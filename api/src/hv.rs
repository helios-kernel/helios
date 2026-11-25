//! Typed, zero-`dyn` hardware virtualization interface over `helios:hv/virtualization`.
//!
//! Guest RAM lives in kernel-owned user-domain frames outside Wasm linear
//! memory. [`GuestPhysAddr`], [`GuestRange`], and [`GuestRegion`] enforce
//! page alignment and bounds before crossing the component boundary, expose
//! POD/slice accessors and bounded streaming loaders, and keep cache
//! publication ([`GuestRegion::publish`]) explicit. [`Aarch64Regs`] and
//! [`X86Regs`] assemble validated register snapshots, [`MmioBus`] and
//! [`PioBus`] compose device routing statically with generics and associated
//! types, and [`IoEvent`] wraps kernel-completed MMIO write notifications.

use core::fmt;
use core::future::Future;
use std::collections::BTreeMap;
use std::vec::Vec;

use thiserror::Error;
pub use zerocopy::{FromBytes, FromZeros, Immutable, IntoBytes, KnownLayout};

pub use crate::bindings::helios::hv::virtualization as raw;
pub use crate::bindings::helios::hv::virtualization::{
    HvError, IoAccess, IoWidth, IoWrite, IrqLevel, MemoryFault, MmioExit, Permissions, PortExit,
    RegisterExit, RegisterId, RegisterValue, VmExit,
};
use crate::bindings::wasi::filesystem::{
    preopens,
    types::{Descriptor, DescriptorFlags, ErrorCode as FsErrorCode, OpenFlags, PathFlags},
};

/// Architectural Stage-2 page granule in bytes (4 KiB).
pub const PAGE_SIZE: u64 = 4096;

/// Bounded per-call byte transfer size for streaming guest RAM copies.
pub const TRANSFER_CHUNK_BYTES: usize = 64 * 1024;

/// Maximum valid AArch64 general-purpose register index (`X0..=X30`).
pub const AARCH64_MAX_X: u8 = 30;

/// Maximum valid x86-64 general-purpose register index (`RAX..=R15`).
pub const X86_MAX_GPR: u8 = 15;

/// Errors returned by typed virtualization operations.
#[derive(Debug, Error)]
pub enum Error {
    #[error("hypervisor: {0}")]
    Hv(#[from] HvError),
    #[error("guest address {address:#x} is not aligned to {alignment:#x} bytes")]
    UnalignedAddress { address: u64, alignment: u64 },
    #[error("guest range {address:#x}+{length:#x} is empty, unaligned, or overflows")]
    InvalidRange { address: u64, length: u64 },
    #[error(
        "guest access {address}+{length:#x} lies outside region {region_base}+{region_size:#x}"
    )]
    OutOfBounds {
        address: GuestPhysAddr,
        length: u64,
        region_base: GuestPhysAddr,
        region_size: u64,
    },
    #[error("transfer length {length} does not match expected size {expected}")]
    LengthMismatch { expected: usize, length: usize },
    #[error("register {register} index {index} exceeds maximum {max}")]
    InvalidRegisterIndex {
        register: &'static str,
        index: u8,
        max: u8,
    },
    #[error("register {0:?} does not belong to the requested architecture")]
    UnexpectedRegister(RegisterId),
    #[error("streaming source error: {0}")]
    Filesystem(#[from] FsErrorCode),
    #[error("root filesystem preopen '/' is not available")]
    MissingRootPreopen,
    #[error("streaming load ended early: expected {expected} bytes, read {actual}")]
    ShortRead { expected: u64, actual: u64 },
    #[error("streaming load exceeded {limit} bytes")]
    StreamOverflow { limit: u64 },
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = core::result::Result<T, Error>;

/// A byte address in a guest's physical address space.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GuestPhysAddr(u64);

impl GuestPhysAddr {
    /// Wraps a raw 64-bit guest physical address.
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    /// Constructs a page-aligned (4 KiB) guest physical address.
    pub const fn page_aligned(raw: u64) -> Result<Self> {
        if raw.is_multiple_of(PAGE_SIZE) {
            Ok(Self(raw))
        } else {
            Err(Error::UnalignedAddress {
                address: raw,
                alignment: PAGE_SIZE,
            })
        }
    }

    /// Returns the raw integer value.
    pub const fn raw(self) -> u64 {
        self.0
    }

    /// Whether the address is aligned to [`PAGE_SIZE`].
    pub const fn is_page_aligned(self) -> bool {
        self.0.is_multiple_of(PAGE_SIZE)
    }

    /// Whether the address is aligned to a power-of-two `alignment`.
    pub const fn is_aligned(self, alignment: u64) -> bool {
        alignment.is_power_of_two() && (self.0 & (alignment - 1)) == 0
    }

    /// Rounds down to the nearest `PAGE_SIZE` boundary.
    pub const fn page_align_down(self) -> Self {
        Self(self.0 & !(PAGE_SIZE - 1))
    }

    /// Rounds up to the nearest `PAGE_SIZE` boundary, returning `None` on overflow.
    pub const fn page_align_up(self) -> Option<Self> {
        match self.0.checked_next_multiple_of(PAGE_SIZE) {
            Some(aligned) => Some(Self(aligned)),
            None => None,
        }
    }

    /// Checked addition of a byte offset.
    pub const fn checked_add(self, bytes: u64) -> Option<Self> {
        match self.0.checked_add(bytes) {
            Some(next) => Some(Self(next)),
            None => None,
        }
    }

    /// Checked subtraction of a byte offset.
    pub const fn checked_sub(self, bytes: u64) -> Option<Self> {
        match self.0.checked_sub(bytes) {
            Some(prev) => Some(Self(prev)),
            None => None,
        }
    }

    /// Byte distance from `base` to `self`, or `None` if `self < base`.
    pub const fn offset_from(self, base: Self) -> Option<u64> {
        self.0.checked_sub(base.0)
    }
}

impl From<GuestPhysAddr> for u64 {
    fn from(value: GuestPhysAddr) -> Self {
        value.0
    }
}

impl fmt::Display for GuestPhysAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

/// Non-empty, page-aligned, non-wrapping guest physical address range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GuestRange {
    base: GuestPhysAddr,
    size: u64,
}

impl GuestRange {
    /// Validates that `base` and `size` are page-aligned, `size > 0`, and
    /// `base + size` does not overflow `u64`.
    pub const fn new(base: GuestPhysAddr, size: u64) -> Result<Self> {
        if size == 0
            || !base.is_page_aligned()
            || !size.is_multiple_of(PAGE_SIZE)
            || base.raw().checked_add(size).is_none()
        {
            return Err(Error::InvalidRange {
                address: base.raw(),
                length: size,
            });
        }
        Ok(Self { base, size })
    }

    pub const fn base(self) -> GuestPhysAddr {
        self.base
    }

    pub const fn size(self) -> u64 {
        self.size
    }

    pub const fn end(self) -> GuestPhysAddr {
        GuestPhysAddr(self.base.0 + self.size)
    }

    pub const fn page_count(self) -> u64 {
        self.size / PAGE_SIZE
    }

    /// Returns the byte offset of `[address, address + length)` inside this
    /// range, or [`Error::OutOfBounds`].
    pub const fn offset_of(self, address: GuestPhysAddr, length: u64) -> Result<u64> {
        let Some(offset) = address.offset_from(self.base) else {
            return Err(Error::OutOfBounds {
                address,
                length,
                region_base: self.base,
                region_size: self.size,
            });
        };
        let Some(end) = offset.checked_add(length) else {
            return Err(Error::OutOfBounds {
                address,
                length,
                region_base: self.base,
                region_size: self.size,
            });
        };
        if end > self.size {
            return Err(Error::OutOfBounds {
                address,
                length,
                region_base: self.base,
                region_size: self.size,
            });
        }
        Ok(offset)
    }

    /// Whether `self` and `other` share at least one guest physical byte.
    pub const fn overlaps(self, other: Self) -> bool {
        self.base.0 < other.end().0 && other.base.0 < self.end().0
    }
}

/// Low-level backing store for a [`GuestRegion`].
///
/// Production code uses [`raw::MemoryRegion`]; tests can supply an in-memory
/// backing without dynamic dispatch.
pub trait MemoryBackend {
    fn read_offset(&self, offset: u64, length: u32) -> Result<Vec<u8>>;
    fn write_offset(&self, offset: u64, bytes: &[u8]) -> Result<()>;
    fn publish_offset(&self, offset: u64, length: u64) -> Result<()>;
}

impl MemoryBackend for raw::MemoryRegion {
    fn read_offset(&self, offset: u64, length: u32) -> Result<Vec<u8>> {
        Ok(self.read(offset, length)?)
    }

    fn write_offset(&self, offset: u64, bytes: &[u8]) -> Result<()> {
        Ok(self.write(offset, bytes)?)
    }

    fn publish_offset(&self, offset: u64, length: u64) -> Result<()> {
        Ok(self.publish(offset, length)?)
    }
}

/// Async byte-chunk producer for streaming loads into [`GuestRegion`].
pub trait AsyncChunkSource {
    type Error: Into<Error>;

    /// Reads the next chunk into `buffer`, returning `(bytes, eof)`.
    ///
    /// Callers pass an empty `Vec` with preallocated capacity to avoid
    /// per-chunk heap allocation.
    fn read_chunk(
        &mut self,
        buffer: Vec<u8>,
    ) -> impl Future<Output = core::result::Result<(Vec<u8>, bool), Self::Error>> + '_;
}

/// Static guest-memory access contract used by device models and loaders.
pub trait GuestMemory {
    fn range(&self) -> GuestRange;
    fn validate_range(&self, address: GuestPhysAddr, length: u64) -> Result<u64>;
    fn read_slice(&self, address: GuestPhysAddr, dst: &mut [u8]) -> Result<()>;
    fn write_slice(&self, address: GuestPhysAddr, src: &[u8]) -> Result<()>;
    fn publish(&self, address: GuestPhysAddr, length: u64) -> Result<()>;

    fn read_bytes(&self, address: GuestPhysAddr, length: usize) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; length];
        self.read_slice(address, &mut buf)?;
        Ok(buf)
    }

    fn read_pod<T: FromBytes + IntoBytes + Immutable>(&self, address: GuestPhysAddr) -> Result<T> {
        let mut value = T::new_zeroed();
        self.read_slice(address, value.as_mut_bytes())?;
        Ok(value)
    }

    fn write_pod<T: IntoBytes + Immutable>(&self, address: GuestPhysAddr, value: &T) -> Result<()> {
        self.write_slice(address, value.as_bytes())
    }

    fn read_u8(&self, address: GuestPhysAddr) -> Result<u8> {
        self.read_pod(address)
    }

    fn read_u16(&self, address: GuestPhysAddr) -> Result<u16> {
        Ok(u16::from_le_bytes(self.read_pod(address)?))
    }

    fn read_u32(&self, address: GuestPhysAddr) -> Result<u32> {
        Ok(u32::from_le_bytes(self.read_pod(address)?))
    }

    fn read_u64(&self, address: GuestPhysAddr) -> Result<u64> {
        Ok(u64::from_le_bytes(self.read_pod(address)?))
    }

    fn write_u8(&self, address: GuestPhysAddr, value: u8) -> Result<()> {
        self.write_pod(address, &value)
    }

    fn write_u16(&self, address: GuestPhysAddr, value: u16) -> Result<()> {
        self.write_pod(address, &value.to_le_bytes())
    }

    fn write_u32(&self, address: GuestPhysAddr, value: u32) -> Result<()> {
        self.write_pod(address, &value.to_le_bytes())
    }

    fn write_u64(&self, address: GuestPhysAddr, value: u64) -> Result<()> {
        self.write_pod(address, &value.to_le_bytes())
    }
}

/// A page-aligned, bounds-checked guest RAM region.
///
/// Writes are **not** automatically published for guest instruction fetch;
/// call [`GuestRegion::publish`] or [`GuestRegion::publish_all`] explicitly
/// after loading executable code or restoring memory images.
pub struct GuestRegion<B: MemoryBackend = raw::MemoryRegion> {
    range: GuestRange,
    backend: B,
}

impl<B: MemoryBackend> GuestRegion<B> {
    /// Wraps an already-mapped backing over a validated page-aligned `range`.
    pub const fn from_backend(range: GuestRange, backend: B) -> Self {
        Self { range, backend }
    }

    pub const fn range(&self) -> GuestRange {
        self.range
    }

    pub const fn base(&self) -> GuestPhysAddr {
        self.range.base()
    }

    pub const fn size(&self) -> u64 {
        self.range.size()
    }

    pub const fn end(&self) -> GuestPhysAddr {
        self.range.end()
    }

    pub const fn backend(&self) -> &B {
        &self.backend
    }

    /// Validates `[address, address + length)` and returns its offset from
    /// [`Self::base`].
    pub const fn offset_of(&self, address: GuestPhysAddr, length: u64) -> Result<u64> {
        self.range.offset_of(address, length)
    }

    /// Reads `dst.len()` bytes starting at `address` in bounded transfers.
    pub fn read_slice(&self, address: GuestPhysAddr, dst: &mut [u8]) -> Result<()> {
        let base_offset = self.offset_of(address, dst.len() as u64)?;
        let mut copied = 0usize;
        while copied < dst.len() {
            let chunk_len = (dst.len() - copied).min(TRANSFER_CHUNK_BYTES);
            let bytes = self
                .backend
                .read_offset(base_offset + copied as u64, chunk_len as u32)?;
            if bytes.len() != chunk_len {
                return Err(Error::LengthMismatch {
                    expected: chunk_len,
                    length: bytes.len(),
                });
            }
            dst[copied..copied + chunk_len].copy_from_slice(&bytes);
            copied += chunk_len;
        }
        Ok(())
    }

    /// Allocates a `Vec<u8>` and reads `length` bytes from `address`.
    pub fn read_bytes(&self, address: GuestPhysAddr, length: usize) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; length];
        self.read_slice(address, &mut buf)?;
        Ok(buf)
    }

    /// Writes `src` starting at `address` in bounded transfers.
    pub fn write_slice(&self, address: GuestPhysAddr, src: &[u8]) -> Result<()> {
        let base_offset = self.offset_of(address, src.len() as u64)?;
        let mut copied = 0usize;
        while copied < src.len() {
            let chunk_len = (src.len() - copied).min(TRANSFER_CHUNK_BYTES);
            self.backend.write_offset(
                base_offset + copied as u64,
                &src[copied..copied + chunk_len],
            )?;
            copied += chunk_len;
        }
        Ok(())
    }

    /// Reads a plain-old-data value of type `T` from `address`.
    pub fn read_pod<T: FromBytes + IntoBytes + Immutable>(
        &self,
        address: GuestPhysAddr,
    ) -> Result<T> {
        <Self as GuestMemory>::read_pod(self, address)
    }

    /// Writes a plain-old-data value of type `T` to `address`.
    pub fn write_pod<T: IntoBytes + Immutable>(
        &self,
        address: GuestPhysAddr,
        value: &T,
    ) -> Result<()> {
        <Self as GuestMemory>::write_pod(self, address, value)
    }

    /// Publishes completed writes in `[address, address + length)` for guest
    /// data and instruction fetch across all processors.
    pub fn publish(&self, address: GuestPhysAddr, length: u64) -> Result<()> {
        let offset = self.offset_of(address, length)?;
        self.backend.publish_offset(offset, length)
    }

    /// Publishes the entire region for guest data and instruction fetch.
    pub fn publish_all(&self) -> Result<()> {
        self.backend.publish_offset(0, self.range.size())
    }

    /// Streams bytes from `source` into guest memory starting at `address`
    /// using a single bounded 64 KiB transfer buffer.
    ///
    /// If `expected_size` is `Some(n)`, validates up front that `[address, address + n)`
    /// fits in the region and fails with [`Error::ShortRead`] or
    /// [`Error::StreamOverflow`] if the stream produces a different count.
    /// Does **not** call [`Self::publish`]; callers publish explicitly once
    /// all writes are complete.
    pub async fn load_stream<S: AsyncChunkSource>(
        &self,
        address: GuestPhysAddr,
        expected_size: Option<u64>,
        source: &mut S,
    ) -> Result<u64> {
        let base_offset = if let Some(expected) = expected_size {
            self.offset_of(address, expected)?
        } else {
            self.offset_of(address, 0)?
        };
        let max_bytes = expected_size.unwrap_or(self.range.size() - base_offset);
        let mut buffer = Vec::with_capacity(TRANSFER_CHUNK_BYTES);
        let mut written = 0u64;
        loop {
            buffer.clear();
            let (chunk, eof) = source.read_chunk(buffer).await.map_err(Into::into)?;
            let chunk_len = chunk.len() as u64;
            if written.checked_add(chunk_len).is_none_or(|n| n > max_bytes) {
                return Err(Error::StreamOverflow { limit: max_bytes });
            }
            if !chunk.is_empty() {
                let target = address
                    .checked_add(written)
                    .ok_or(Error::StreamOverflow { limit: max_bytes })?;
                self.write_slice(target, &chunk)?;
                written += chunk_len;
            }
            buffer = chunk;
            if eof {
                break;
            }
        }
        if let Some(expected) = expected_size
            && written != expected
        {
            return Err(Error::ShortRead {
                expected,
                actual: written,
            });
        }
        Ok(written)
    }

    /// Streams an open WASI 0.3 file `descriptor` of `expected_size` bytes
    /// into guest memory at `address`. Call [`Self::publish`] explicitly
    /// afterward before running vCPUs.
    pub async fn load_wasi_descriptor(
        &self,
        address: GuestPhysAddr,
        descriptor: &Descriptor,
        expected_size: u64,
    ) -> Result<u64> {
        let (stream, completion) = descriptor.read_via_stream(0);
        let mut source = WasiStreamSource { stream };
        let loaded = self
            .load_stream(address, Some(expected_size), &mut source)
            .await?;
        drop(source);
        completion.await?;
        Ok(loaded)
    }

    /// Opens `path` relative to the `/` WASI preopen and streams its full
    /// contents into guest memory at `address`. Call [`Self::publish`]
    /// explicitly afterward before running vCPUs.
    pub async fn load_wasi_file(&self, address: GuestPhysAddr, path: &str) -> Result<u64> {
        let (root, _) = preopens::get_directories()
            .into_iter()
            .find(|(_, name)| name == "/")
            .ok_or(Error::MissingRootPreopen)?;
        let descriptor = root
            .open_at(
                PathFlags::SYMLINK_FOLLOW,
                path.trim_start_matches('/').to_owned(),
                OpenFlags::empty(),
                DescriptorFlags::READ,
            )
            .await?;
        let size = descriptor.stat().await?.size;
        self.load_wasi_descriptor(address, &descriptor, size).await
    }
}

impl<B: MemoryBackend> GuestMemory for GuestRegion<B> {
    fn range(&self) -> GuestRange {
        self.range
    }

    fn validate_range(&self, address: GuestPhysAddr, length: u64) -> Result<u64> {
        self.offset_of(address, length)
    }

    fn read_slice(&self, address: GuestPhysAddr, dst: &mut [u8]) -> Result<()> {
        GuestRegion::read_slice(self, address, dst)
    }

    fn write_slice(&self, address: GuestPhysAddr, src: &[u8]) -> Result<()> {
        GuestRegion::write_slice(self, address, src)
    }

    fn publish(&self, address: GuestPhysAddr, length: u64) -> Result<()> {
        GuestRegion::publish(self, address, length)
    }
}

struct WasiStreamSource {
    stream: crate::wit_bindgen::rt::async_support::StreamReader<u8>,
}

impl AsyncChunkSource for WasiStreamSource {
    type Error = Error;

    async fn read_chunk(&mut self, buffer: Vec<u8>) -> Result<(Vec<u8>, bool)> {
        let (status, bytes) = self.stream.read(buffer).await;
        Ok((bytes, crate::stream_closed(status)))
    }
}

/// Typed AArch64 vCPU register snapshot builder.
///
/// Only registers explicitly populated are emitted by
/// [`Aarch64Regs::to_register_values`], preserving partial updates.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Aarch64Regs {
    x: [Option<u64>; 31],
    sp: Option<u64>,
    pc: Option<u64>,
    pstate: Option<u64>,
}

impl Aarch64Regs {
    /// AArch64 EL1h PSTATE with D, A, I, F interrupts masked (Linux boot protocol).
    pub const EL1H_DAIF_MASKED: u64 = 0x3c5;

    pub const fn new() -> Self {
        Self {
            x: [None; 31],
            sp: None,
            pc: None,
            pstate: None,
        }
    }

    /// Standard Linux ARM64 boot protocol entry state (`PC = entry`,
    /// `PSTATE = EL1h/DAIF masked`, `X0 = dtb`, `X1..=X3 = 0`).
    pub const fn linux_boot(entry: GuestPhysAddr, dtb: GuestPhysAddr) -> Self {
        Self::new()
            .pc(entry.raw())
            .pstate(Self::EL1H_DAIF_MASKED)
            .x0(dtb.raw())
            .x1(0)
            .x2(0)
            .x3(0)
    }

    /// Sets general-purpose register `X{index}` (`0..=30`).
    pub fn try_x(mut self, index: u8, value: u64) -> Result<Self> {
        if index > AARCH64_MAX_X {
            return Err(Error::InvalidRegisterIndex {
                register: "aarch64 X",
                index,
                max: AARCH64_MAX_X,
            });
        }
        self.x[usize::from(index)] = Some(value);
        Ok(self)
    }

    pub const fn x0(mut self, value: u64) -> Self {
        self.x[0] = Some(value);
        self
    }

    pub const fn x1(mut self, value: u64) -> Self {
        self.x[1] = Some(value);
        self
    }

    pub const fn x2(mut self, value: u64) -> Self {
        self.x[2] = Some(value);
        self
    }

    pub const fn x3(mut self, value: u64) -> Self {
        self.x[3] = Some(value);
        self
    }

    pub const fn lr(mut self, value: u64) -> Self {
        self.x[30] = Some(value);
        self
    }

    pub const fn sp(mut self, value: u64) -> Self {
        self.sp = Some(value);
        self
    }

    pub const fn pc(mut self, value: u64) -> Self {
        self.pc = Some(value);
        self
    }

    pub const fn pstate(mut self, value: u64) -> Self {
        self.pstate = Some(value);
        self
    }

    pub fn get_x(&self, index: u8) -> Result<Option<u64>> {
        if index > AARCH64_MAX_X {
            return Err(Error::InvalidRegisterIndex {
                register: "aarch64 X",
                index,
                max: AARCH64_MAX_X,
            });
        }
        Ok(self.x[usize::from(index)])
    }

    pub const fn get_sp(&self) -> Option<u64> {
        self.sp
    }

    pub const fn get_pc(&self) -> Option<u64> {
        self.pc
    }

    pub const fn get_pstate(&self) -> Option<u64> {
        self.pstate
    }

    /// All 34 architectural AArch64 register identifiers (`X0..=X30`, `SP`, `PC`, `PSTATE`).
    pub fn all_ids() -> [RegisterId; 34] {
        let mut ids = [RegisterId::Aarch64Sp; 34];
        let mut i = 0u8;
        while i <= AARCH64_MAX_X {
            ids[usize::from(i)] = RegisterId::Aarch64X(i);
            i += 1;
        }
        ids[31] = RegisterId::Aarch64Sp;
        ids[32] = RegisterId::Aarch64Pc;
        ids[33] = RegisterId::Aarch64Pstate;
        ids
    }

    /// Serializes populated registers into a deterministic WIT batch.
    pub fn to_register_values(&self) -> Vec<RegisterValue> {
        let mut values = Vec::new();
        for (index, slot) in self.x.iter().enumerate() {
            if let Some(value) = *slot {
                values.push(RegisterValue {
                    id: RegisterId::Aarch64X(index as u8),
                    value,
                });
            }
        }
        if let Some(value) = self.sp {
            values.push(RegisterValue {
                id: RegisterId::Aarch64Sp,
                value,
            });
        }
        if let Some(value) = self.pc {
            values.push(RegisterValue {
                id: RegisterId::Aarch64Pc,
                value,
            });
        }
        if let Some(value) = self.pstate {
            values.push(RegisterValue {
                id: RegisterId::Aarch64Pstate,
                value,
            });
        }
        values
    }

    /// Parses a WIT register batch into a typed AArch64 snapshot.
    pub fn from_register_values(values: &[RegisterValue]) -> Result<Self> {
        let mut regs = Self::new();
        for entry in values {
            match entry.id {
                RegisterId::Aarch64X(index) => {
                    regs = regs.try_x(index, entry.value)?;
                }
                RegisterId::Aarch64Sp => regs.sp = Some(entry.value),
                RegisterId::Aarch64Pc => regs.pc = Some(entry.value),
                RegisterId::Aarch64Pstate => regs.pstate = Some(entry.value),
                other => return Err(Error::UnexpectedRegister(other)),
            }
        }
        Ok(regs)
    }
}

/// x86-64 64-bit general-purpose register encoding (Intel SDM Vol. 2, Table 2-2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum X86Gpr {
    Rax = 0,
    Rcx = 1,
    Rdx = 2,
    Rbx = 3,
    Rsp = 4,
    Rbp = 5,
    Rsi = 6,
    Rdi = 7,
    R8 = 8,
    R9 = 9,
    R10 = 10,
    R11 = 11,
    R12 = 12,
    R13 = 13,
    R14 = 14,
    R15 = 15,
}

impl X86Gpr {
    pub const fn index(self) -> u8 {
        self as u8
    }

    pub const fn from_index(index: u8) -> Result<Self> {
        match index {
            0 => Ok(Self::Rax),
            1 => Ok(Self::Rcx),
            2 => Ok(Self::Rdx),
            3 => Ok(Self::Rbx),
            4 => Ok(Self::Rsp),
            5 => Ok(Self::Rbp),
            6 => Ok(Self::Rsi),
            7 => Ok(Self::Rdi),
            8 => Ok(Self::R8),
            9 => Ok(Self::R9),
            10 => Ok(Self::R10),
            11 => Ok(Self::R11),
            12 => Ok(Self::R12),
            13 => Ok(Self::R13),
            14 => Ok(Self::R14),
            15 => Ok(Self::R15),
            _ => Err(Error::InvalidRegisterIndex {
                register: "x86 GPR",
                index,
                max: X86_MAX_GPR,
            }),
        }
    }
}

/// Typed x86-64 vCPU register snapshot builder.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct X86Regs {
    gprs: [Option<u64>; 16],
    rip: Option<u64>,
    rflags: Option<u64>,
    controls: BTreeMap<u8, u64>,
    msrs: BTreeMap<u32, u64>,
}

impl X86Regs {
    /// Architectural x86 RFLAGS reserved bit 1 (always set).
    pub const RFLAGS_FIXED: u64 = 1 << 1;

    pub fn new() -> Self {
        Self::default()
    }

    pub fn gpr(mut self, register: X86Gpr, value: u64) -> Self {
        self.gprs[usize::from(register.index())] = Some(value);
        self
    }

    pub fn rax(self, value: u64) -> Self {
        self.gpr(X86Gpr::Rax, value)
    }

    pub fn rcx(self, value: u64) -> Self {
        self.gpr(X86Gpr::Rcx, value)
    }

    pub fn rdx(self, value: u64) -> Self {
        self.gpr(X86Gpr::Rdx, value)
    }

    pub fn rbx(self, value: u64) -> Self {
        self.gpr(X86Gpr::Rbx, value)
    }

    pub fn rsp(self, value: u64) -> Self {
        self.gpr(X86Gpr::Rsp, value)
    }

    pub fn rbp(self, value: u64) -> Self {
        self.gpr(X86Gpr::Rbp, value)
    }

    pub fn rsi(self, value: u64) -> Self {
        self.gpr(X86Gpr::Rsi, value)
    }

    pub fn rdi(self, value: u64) -> Self {
        self.gpr(X86Gpr::Rdi, value)
    }

    pub fn r8(self, value: u64) -> Self {
        self.gpr(X86Gpr::R8, value)
    }

    pub fn r9(self, value: u64) -> Self {
        self.gpr(X86Gpr::R9, value)
    }

    pub fn r10(self, value: u64) -> Self {
        self.gpr(X86Gpr::R10, value)
    }

    pub fn r11(self, value: u64) -> Self {
        self.gpr(X86Gpr::R11, value)
    }

    pub fn r12(self, value: u64) -> Self {
        self.gpr(X86Gpr::R12, value)
    }

    pub fn r13(self, value: u64) -> Self {
        self.gpr(X86Gpr::R13, value)
    }

    pub fn r14(self, value: u64) -> Self {
        self.gpr(X86Gpr::R14, value)
    }

    pub fn r15(self, value: u64) -> Self {
        self.gpr(X86Gpr::R15, value)
    }

    pub fn rip(mut self, value: u64) -> Self {
        self.rip = Some(value);
        self
    }

    pub fn rflags(mut self, value: u64) -> Self {
        self.rflags = Some(value);
        self
    }

    pub fn control(mut self, index: u8, value: u64) -> Self {
        self.controls.insert(index, value);
        self
    }

    pub fn cr0(self, value: u64) -> Self {
        self.control(0, value)
    }

    pub fn cr2(self, value: u64) -> Self {
        self.control(2, value)
    }

    pub fn cr3(self, value: u64) -> Self {
        self.control(3, value)
    }

    pub fn cr4(self, value: u64) -> Self {
        self.control(4, value)
    }

    pub fn cr8(self, value: u64) -> Self {
        self.control(8, value)
    }

    pub fn msr(mut self, index: u32, value: u64) -> Self {
        self.msrs.insert(index, value);
        self
    }

    pub fn get_gpr(&self, register: X86Gpr) -> Option<u64> {
        self.gprs[usize::from(register.index())]
    }

    pub fn get_rip(&self) -> Option<u64> {
        self.rip
    }

    pub fn get_rflags(&self) -> Option<u64> {
        self.rflags
    }

    pub fn get_control(&self, index: u8) -> Option<u64> {
        self.controls.get(&index).copied()
    }

    pub fn get_msr(&self, index: u32) -> Option<u64> {
        self.msrs.get(&index).copied()
    }

    /// Serializes populated registers into a deterministic WIT batch.
    pub fn to_register_values(&self) -> Vec<RegisterValue> {
        let mut values = Vec::new();
        for (index, slot) in self.gprs.iter().enumerate() {
            if let Some(value) = *slot {
                values.push(RegisterValue {
                    id: RegisterId::X86Gpr(index as u8),
                    value,
                });
            }
        }
        if let Some(value) = self.rip {
            values.push(RegisterValue {
                id: RegisterId::X86Rip,
                value,
            });
        }
        if let Some(value) = self.rflags {
            values.push(RegisterValue {
                id: RegisterId::X86Rflags,
                value,
            });
        }
        for (&index, &value) in &self.controls {
            values.push(RegisterValue {
                id: RegisterId::X86Control(index),
                value,
            });
        }
        for (&index, &value) in &self.msrs {
            values.push(RegisterValue {
                id: RegisterId::X86Msr(index),
                value,
            });
        }
        values
    }

    /// Parses a WIT register batch into a typed x86-64 snapshot.
    pub fn from_register_values(values: &[RegisterValue]) -> Result<Self> {
        let mut regs = Self::new();
        for entry in values {
            match entry.id {
                RegisterId::X86Gpr(index) => {
                    let gpr = X86Gpr::from_index(index)?;
                    regs.gprs[usize::from(gpr.index())] = Some(entry.value);
                }
                RegisterId::X86Rip => regs.rip = Some(entry.value),
                RegisterId::X86Rflags => regs.rflags = Some(entry.value),
                RegisterId::X86Control(index) => {
                    regs.controls.insert(index, entry.value);
                }
                RegisterId::X86Msr(index) => {
                    regs.msrs.insert(index, entry.value);
                }
                other => return Err(Error::UnexpectedRegister(other)),
            }
        }
        Ok(regs)
    }
}

/// Non-empty, non-wrapping guest MMIO address window `[base, base + size)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MmioRange {
    base: GuestPhysAddr,
    size: u64,
}

impl MmioRange {
    pub const fn new(base: GuestPhysAddr, size: u64) -> Result<Self> {
        if size == 0 || base.raw().checked_add(size).is_none() {
            return Err(Error::InvalidRange {
                address: base.raw(),
                length: size,
            });
        }
        Ok(Self { base, size })
    }

    pub const fn base(self) -> GuestPhysAddr {
        self.base
    }

    pub const fn size(self) -> u64 {
        self.size
    }

    pub const fn end(self) -> GuestPhysAddr {
        GuestPhysAddr(self.base.0 + self.size)
    }

    pub const fn offset(self, address: GuestPhysAddr) -> Option<u64> {
        let Some(offset) = address.offset_from(self.base) else {
            return None;
        };
        if offset < self.size {
            Some(offset)
        } else {
            None
        }
    }

    pub const fn contains(self, address: GuestPhysAddr) -> bool {
        self.offset(address).is_some()
    }

    pub const fn overlaps(self, other: Self) -> bool {
        self.base.0 < other.end().0 && other.base.0 < self.end().0
    }
}

/// A single MMIO-mapped device with compile-time dispatch.
pub trait MmioDevice<Ctx = ()> {
    type Error;

    fn range(&self) -> MmioRange;
    fn access(
        &mut self,
        offset: u64,
        access: IoAccess,
        ctx: &Ctx,
    ) -> core::result::Result<u64, Self::Error>;
}

/// Static MMIO bus composed via generics and associated types (zero `dyn`).
pub trait MmioBus<Ctx = ()> {
    type Error;

    fn dispatch(
        &mut self,
        address: GuestPhysAddr,
        access: IoAccess,
        ctx: &Ctx,
    ) -> core::result::Result<Option<u64>, Self::Error>;
}

/// Non-empty, non-wrapping x86 port I/O range `[base, base + count)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PioRange {
    base: u16,
    count: u16,
}

impl PioRange {
    pub const fn new(base: u16, count: u16) -> Result<Self> {
        if count == 0 || (base as u32) + (count as u32) > (u16::MAX as u32) + 1 {
            return Err(Error::InvalidRange {
                address: base as u64,
                length: count as u64,
            });
        }
        Ok(Self { base, count })
    }

    pub const fn base(self) -> u16 {
        self.base
    }

    pub const fn count(self) -> u16 {
        self.count
    }

    pub const fn offset(self, port: u16) -> Option<u16> {
        let Some(offset) = port.checked_sub(self.base) else {
            return None;
        };
        if offset < self.count {
            Some(offset)
        } else {
            None
        }
    }

    pub const fn contains(self, port: u16) -> bool {
        self.offset(port).is_some()
    }
}

/// A single port-I/O device with compile-time dispatch.
pub trait PioDevice<Ctx = ()> {
    type Error;

    fn range(&self) -> PioRange;
    fn access(
        &mut self,
        offset: u16,
        access: IoAccess,
        ctx: &Ctx,
    ) -> core::result::Result<u64, Self::Error>;
}

/// Static port-I/O bus composed via generics and associated types (zero `dyn`).
pub trait PioBus<Ctx = ()> {
    type Error;

    fn dispatch(
        &mut self,
        port: u16,
        access: IoAccess,
        ctx: &Ctx,
    ) -> core::result::Result<Option<u64>, Self::Error>;
}

/// Terminal empty bus that matches no MMIO or PIO address.
#[derive(Clone, Copy, Debug)]
pub struct EmptyBus<E> {
    _error: core::marker::PhantomData<fn() -> E>,
}

impl<E> Default for EmptyBus<E> {
    fn default() -> Self {
        Self::new()
    }
}

impl<E> EmptyBus<E> {
    pub const fn new() -> Self {
        Self {
            _error: core::marker::PhantomData,
        }
    }
}

impl<Ctx, E> MmioBus<Ctx> for EmptyBus<E> {
    type Error = E;

    fn dispatch(
        &mut self,
        _address: GuestPhysAddr,
        _access: IoAccess,
        _ctx: &Ctx,
    ) -> core::result::Result<Option<u64>, E> {
        Ok(None)
    }
}

impl<Ctx, E> PioBus<Ctx> for EmptyBus<E> {
    type Error = E;

    fn dispatch(
        &mut self,
        _port: u16,
        _access: IoAccess,
        _ctx: &Ctx,
    ) -> core::result::Result<Option<u64>, E> {
        Ok(None)
    }
}

/// Adapts a single [`MmioDevice`] into an [`MmioBus`].
#[derive(Debug)]
pub struct MmioEntry<D>(pub D);

impl<Ctx, D: MmioDevice<Ctx>> MmioBus<Ctx> for MmioEntry<D> {
    type Error = D::Error;

    fn dispatch(
        &mut self,
        address: GuestPhysAddr,
        access: IoAccess,
        ctx: &Ctx,
    ) -> core::result::Result<Option<u64>, D::Error> {
        let Some(offset) = self.0.range().offset(address) else {
            return Ok(None);
        };
        self.0.access(offset, access, ctx).map(Some)
    }
}

/// Adapts a single [`PioDevice`] into a [`PioBus`].
#[derive(Debug)]
pub struct PioEntry<D>(pub D);

impl<Ctx, D: PioDevice<Ctx>> PioBus<Ctx> for PioEntry<D> {
    type Error = D::Error;

    fn dispatch(
        &mut self,
        port: u16,
        access: IoAccess,
        ctx: &Ctx,
    ) -> core::result::Result<Option<u64>, D::Error> {
        let Some(offset) = self.0.range().offset(port) else {
            return Ok(None);
        };
        self.0.access(offset, access, ctx).map(Some)
    }
}

/// Static two-stage MMIO bus combinator: checks `head` first, then `tail`.
#[derive(Debug)]
pub struct MmioChain<Head, Tail> {
    pub head: Head,
    pub tail: Tail,
}

impl<Ctx, E, Head, Tail> MmioBus<Ctx> for MmioChain<Head, Tail>
where
    Head: MmioBus<Ctx, Error = E>,
    Tail: MmioBus<Ctx, Error = E>,
{
    type Error = E;

    fn dispatch(
        &mut self,
        address: GuestPhysAddr,
        access: IoAccess,
        ctx: &Ctx,
    ) -> core::result::Result<Option<u64>, E> {
        if let Some(value) = self.head.dispatch(address, access, ctx)? {
            return Ok(Some(value));
        }
        self.tail.dispatch(address, access, ctx)
    }
}

/// Static two-stage PIO bus combinator: checks `head` first, then `tail`.
#[derive(Debug)]
pub struct PioChain<Head, Tail> {
    pub head: Head,
    pub tail: Tail,
}

impl<Ctx, E, Head, Tail> PioBus<Ctx> for PioChain<Head, Tail>
where
    Head: PioBus<Ctx, Error = E>,
    Tail: PioBus<Ctx, Error = E>,
{
    type Error = E;

    fn dispatch(
        &mut self,
        port: u16,
        access: IoAccess,
        ctx: &Ctx,
    ) -> core::result::Result<Option<u64>, E> {
        if let Some(value) = self.head.dispatch(port, access, ctx)? {
            return Ok(Some(value));
        }
        self.tail.dispatch(port, access, ctx)
    }
}

/// Optional MMIO device or sub-bus on a static bus.
impl<Ctx, B: MmioBus<Ctx>> MmioBus<Ctx> for Option<B> {
    type Error = B::Error;

    fn dispatch(
        &mut self,
        address: GuestPhysAddr,
        access: IoAccess,
        ctx: &Ctx,
    ) -> core::result::Result<Option<u64>, B::Error> {
        match self {
            Some(bus) => bus.dispatch(address, access, ctx),
            None => Ok(None),
        }
    }
}

/// Optional PIO device or sub-bus on a static bus.
impl<Ctx, B: PioBus<Ctx>> PioBus<Ctx> for Option<B> {
    type Error = B::Error;

    fn dispatch(
        &mut self,
        port: u16,
        access: IoAccess,
        ctx: &Ctx,
    ) -> core::result::Result<Option<u64>, B::Error> {
        match self {
            Some(bus) => bus.dispatch(port, access, ctx),
            None => Ok(None),
        }
    }
}

/// Homogeneous slice of MMIO devices (for example, multiple `virtio-fs` shares)
/// without dynamic dispatch.
impl<Ctx, D: MmioDevice<Ctx>> MmioBus<Ctx> for &mut [D] {
    type Error = D::Error;

    fn dispatch(
        &mut self,
        address: GuestPhysAddr,
        access: IoAccess,
        ctx: &Ctx,
    ) -> core::result::Result<Option<u64>, D::Error> {
        for device in self.iter_mut() {
            if let Some(offset) = device.range().offset(address) {
                return device.access(offset, access, ctx).map(Some);
            }
        }
        Ok(None)
    }
}

/// Homogeneous slice of PIO devices without dynamic dispatch.
impl<Ctx, D: PioDevice<Ctx>> PioBus<Ctx> for &mut [D] {
    type Error = D::Error;

    fn dispatch(
        &mut self,
        port: u16,
        access: IoAccess,
        ctx: &Ctx,
    ) -> core::result::Result<Option<u64>, D::Error> {
        for device in self.iter_mut() {
            if let Some(offset) = device.range().offset(port) {
                return device.access(offset, access, ctx).map(Some);
            }
        }
        Ok(None)
    }
}

/// Mutable borrow of any [`MmioDevice`] dispatches directly as an [`MmioBus`].
impl<Ctx, D: MmioDevice<Ctx>> MmioBus<Ctx> for &mut D {
    type Error = D::Error;

    fn dispatch(
        &mut self,
        address: GuestPhysAddr,
        access: IoAccess,
        ctx: &Ctx,
    ) -> core::result::Result<Option<u64>, D::Error> {
        let Some(offset) = (**self).range().offset(address) else {
            return Ok(None);
        };
        (**self).access(offset, access, ctx).map(Some)
    }
}

/// Mutable borrow of any [`PioDevice`] dispatches directly as a [`PioBus`].
impl<Ctx, D: PioDevice<Ctx>> PioBus<Ctx> for &mut D {
    type Error = D::Error;

    fn dispatch(
        &mut self,
        port: u16,
        access: IoAccess,
        ctx: &Ctx,
    ) -> core::result::Result<Option<u64>, D::Error> {
        let Some(offset) = (**self).range().offset(port) else {
            return Ok(None);
        };
        (**self).access(offset, access, ctx).map(Some)
    }
}

/// Ergonomic builder for chaining static [`MmioBus`] stages.
#[derive(Debug)]
pub struct MmioRouter<B>(B);

impl<E> MmioRouter<EmptyBus<E>> {
    pub const fn new() -> Self {
        Self(EmptyBus::new())
    }
}

impl<E> Default for MmioRouter<EmptyBus<E>> {
    fn default() -> Self {
        Self::new()
    }
}

impl<B> MmioRouter<B> {
    /// Prepends a bus stage to be checked before existing stages.
    pub fn with_bus<H>(self, head: H) -> MmioRouter<MmioChain<H, B>> {
        MmioRouter(MmioChain { head, tail: self.0 })
    }

    /// Prepends a single [`MmioDevice`] to be checked before existing stages.
    pub fn with_device<D>(self, device: D) -> MmioRouter<MmioChain<MmioEntry<D>, B>> {
        self.with_bus(MmioEntry(device))
    }

    pub fn dispatch<Ctx>(
        &mut self,
        address: GuestPhysAddr,
        access: IoAccess,
        ctx: &Ctx,
    ) -> core::result::Result<Option<u64>, B::Error>
    where
        B: MmioBus<Ctx>,
    {
        self.0.dispatch(address, access, ctx)
    }
}

/// Ergonomic builder for chaining static [`PioBus`] stages.
#[derive(Debug)]
pub struct PioRouter<B>(B);

impl<E> PioRouter<EmptyBus<E>> {
    pub const fn new() -> Self {
        Self(EmptyBus::new())
    }
}

impl<E> Default for PioRouter<EmptyBus<E>> {
    fn default() -> Self {
        Self::new()
    }
}

impl<B> PioRouter<B> {
    pub fn with_bus<H>(self, head: H) -> PioRouter<PioChain<H, B>> {
        PioRouter(PioChain { head, tail: self.0 })
    }

    pub fn with_device<D>(self, device: D) -> PioRouter<PioChain<PioEntry<D>, B>> {
        self.with_bus(PioEntry(device))
    }

    pub fn dispatch<Ctx>(
        &mut self,
        port: u16,
        access: IoAccess,
        ctx: &Ctx,
    ) -> core::result::Result<Option<u64>, B::Error>
    where
        B: PioBus<Ctx>,
    {
        self.0.dispatch(port, access, ctx)
    }
}

/// Backing contract for [`IoEvent`], enabling host tests without `dyn`.
pub trait IoEventBackend {
    fn wait(&self) -> impl Future<Output = Result<()>> + '_;
}

impl IoEventBackend for raw::Ioevent {
    async fn wait(&self) -> Result<()> {
        Ok(raw::Ioevent::wait(self).await?)
    }
}

/// Kernel-completed MMIO write notification handle.
///
/// Dropping an [`IoEvent`] unregisters its kernel fast path. Cancellation of
/// [`IoEvent::wait`] preserves unconsumed completions in the kernel.
pub struct IoEvent<B: IoEventBackend = raw::Ioevent> {
    address: GuestPhysAddr,
    width: IoWidth,
    match_value: Option<u64>,
    backend: B,
}

impl<B: IoEventBackend> IoEvent<B> {
    pub const fn from_backend(
        address: GuestPhysAddr,
        width: IoWidth,
        match_value: Option<u64>,
        backend: B,
    ) -> Self {
        Self {
            address,
            width,
            match_value,
            backend,
        }
    }

    pub const fn address(&self) -> GuestPhysAddr {
        self.address
    }

    pub const fn width(&self) -> IoWidth {
        self.width
    }

    pub const fn match_value(&self) -> Option<u64> {
        self.match_value
    }

    /// Awaits the next matching guest MMIO write.
    pub async fn wait(&self) -> Result<()> {
        self.backend.wait().await
    }
}

/// Typed wrapper over `helios:hv/virtualization.vm`.
pub struct Vm {
    raw: raw::Vm,
}

impl Vm {
    /// Creates a new hardware virtual machine with a guest RAM budget of
    /// `memory_limit` bytes.
    pub fn create(memory_limit: u64) -> Result<Self> {
        Ok(Self {
            raw: raw::Vm::create(memory_limit)?,
        })
    }

    /// Allocates and maps a page-aligned guest RAM region.
    pub fn allocate_memory(
        &self,
        base: GuestPhysAddr,
        size: u64,
        permissions: Permissions,
    ) -> Result<GuestRegion> {
        let range = GuestRange::new(base, size)?;
        let region = self
            .raw
            .allocate_memory(range.base().raw(), range.size(), permissions)?;
        Ok(GuestRegion::from_backend(range, region))
    }

    /// Unmaps a previously mapped guest range, awaiting Stage-2 shootdowns.
    pub async fn unmap_memory(&self, range: GuestRange) -> Result<()> {
        Ok(self
            .raw
            .unmap_memory(range.base().raw(), range.size())
            .await?)
    }

    /// Updates Stage-2 permissions for a mapped guest range.
    pub async fn protect_memory(&self, range: GuestRange, permissions: Permissions) -> Result<()> {
        Ok(self
            .raw
            .protect_memory(range.base().raw(), range.size(), permissions)
            .await?)
    }

    /// Creates vCPU `id` with a pending-interrupt queue capacity of
    /// `pending_interrupts`.
    pub fn create_vcpu(&self, id: u32, pending_interrupts: u32) -> Result<Vcpu> {
        Ok(Vcpu {
            id,
            raw: self.raw.create_vcpu(id, pending_interrupts)?,
        })
    }

    /// Drives a virtual interrupt line on `vcpu_id`.
    pub fn set_irq_line(&self, vcpu_id: u32, number: u32, level: IrqLevel) -> Result<()> {
        Ok(self.raw.set_irq_line(vcpu_id, number, level)?)
    }

    /// Registers a kernel-completed MMIO write fast path at `address`.
    pub fn register_ioevent(
        &self,
        address: GuestPhysAddr,
        width: IoWidth,
        match_value: Option<u64>,
    ) -> Result<IoEvent> {
        let raw = self
            .raw
            .register_ioevent(address.raw(), width, match_value)?;
        Ok(IoEvent::from_backend(address, width, match_value, raw))
    }

    pub fn raw(&self) -> &raw::Vm {
        &self.raw
    }
}

/// Typed wrapper over `helios:hv/virtualization.vcpu`.
pub struct Vcpu {
    id: u32,
    raw: raw::Vcpu,
}

impl Vcpu {
    pub const fn id(&self) -> u32 {
        self.id
    }

    pub async fn run(&self) -> Result<VmExit> {
        Ok(self.raw.run().await?)
    }

    pub fn reset(&self) -> Result<()> {
        Ok(self.raw.reset()?)
    }

    pub fn get_regs(&self, ids: &[RegisterId]) -> Result<Vec<RegisterValue>> {
        Ok(self.raw.get_regs(ids)?)
    }

    pub fn set_regs(&self, values: &[RegisterValue]) -> Result<()> {
        Ok(self.raw.set_regs(values)?)
    }

    pub fn set_aarch64_regs(&self, regs: &Aarch64Regs) -> Result<()> {
        let values = regs.to_register_values();
        self.set_regs(&values)
    }

    pub fn get_aarch64_regs(&self, ids: &[RegisterId]) -> Result<Aarch64Regs> {
        let values = self.get_regs(ids)?;
        Aarch64Regs::from_register_values(&values)
    }

    pub fn set_x86_regs(&self, regs: &X86Regs) -> Result<()> {
        let values = regs.to_register_values();
        self.set_regs(&values)
    }

    pub fn get_x86_regs(&self, ids: &[RegisterId]) -> Result<X86Regs> {
        let values = self.get_regs(ids)?;
        X86Regs::from_register_values(&values)
    }

    pub fn complete_exit(&self, value: u64) -> Result<()> {
        Ok(self.raw.complete_exit(value)?)
    }

    pub fn kick(&self) {
        self.raw.kick();
    }

    pub fn raw(&self) -> &raw::Vcpu {
        &self.raw
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::VecDeque;

    struct VecMemory {
        bytes: RefCell<Vec<u8>>,
        published: RefCell<Vec<(u64, u64)>>,
    }

    impl VecMemory {
        fn new(size: usize) -> Self {
            Self {
                bytes: RefCell::new(vec![0; size]),
                published: RefCell::new(Vec::new()),
            }
        }
    }

    impl MemoryBackend for VecMemory {
        fn read_offset(&self, offset: u64, length: u32) -> Result<Vec<u8>> {
            let start = offset as usize;
            let end = start + length as usize;
            Ok(self.bytes.borrow()[start..end].to_vec())
        }

        fn write_offset(&self, offset: u64, bytes: &[u8]) -> Result<()> {
            let start = offset as usize;
            let end = start + bytes.len();
            self.bytes.borrow_mut()[start..end].copy_from_slice(bytes);
            Ok(())
        }

        fn publish_offset(&self, offset: u64, length: u64) -> Result<()> {
            self.published.borrow_mut().push((offset, length));
            Ok(())
        }
    }

    struct ChunkList {
        chunks: VecDeque<Vec<u8>>,
    }

    impl AsyncChunkSource for ChunkList {
        type Error = Error;

        async fn read_chunk(&mut self, mut buffer: Vec<u8>) -> Result<(Vec<u8>, bool)> {
            match self.chunks.pop_front() {
                Some(chunk) => {
                    buffer.extend_from_slice(&chunk);
                    Ok((buffer, self.chunks.is_empty()))
                }
                None => Ok((buffer, true)),
            }
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout)]
    #[repr(C)]
    struct TestHeader {
        magic: u32,
        flags: u16,
        reserved: u16,
        entry: u64,
    }

    #[test]
    fn guest_phys_addr_and_range_enforce_page_alignment_and_bounds() {
        assert!(GuestPhysAddr::page_aligned(0x4000_0000).is_ok());
        assert!(matches!(
            GuestPhysAddr::page_aligned(0x4000_0001),
            Err(Error::UnalignedAddress {
                address: 0x4000_0001,
                alignment: PAGE_SIZE,
            })
        ));
        assert_eq!(
            GuestPhysAddr::new(0x4000_1234).page_align_down(),
            GuestPhysAddr::new(0x4000_1000)
        );
        assert_eq!(
            GuestPhysAddr::new(0x4000_1234).page_align_up(),
            Some(GuestPhysAddr::new(0x4000_2000))
        );
        assert!(GuestRange::new(GuestPhysAddr::new(0x4000_0000), 0).is_err());
        assert!(GuestRange::new(GuestPhysAddr::new(0x4000_0001), PAGE_SIZE).is_err());
        assert!(GuestRange::new(GuestPhysAddr::new(0x4000_0000), PAGE_SIZE + 1).is_err());
        assert!(GuestRange::new(GuestPhysAddr::new(u64::MAX - PAGE_SIZE + 1), PAGE_SIZE).is_err());

        let range = GuestRange::new(GuestPhysAddr::new(0x4000_0000), 2 * PAGE_SIZE).unwrap();
        assert_eq!(range.page_count(), 2);
        assert_eq!(
            range
                .offset_of(GuestPhysAddr::new(0x4000_1000), PAGE_SIZE)
                .unwrap(),
            PAGE_SIZE
        );
        assert!(matches!(
            range.offset_of(GuestPhysAddr::new(0x3fff_f000), 4),
            Err(Error::OutOfBounds { .. })
        ));
        assert!(matches!(
            range.offset_of(GuestPhysAddr::new(0x4000_1ff0), 32),
            Err(Error::OutOfBounds { .. })
        ));
    }

    #[test]
    fn guest_region_pod_slice_streaming_and_explicit_publish() {
        let range = GuestRange::new(GuestPhysAddr::new(0x4000_0000), 4 * PAGE_SIZE).unwrap();
        let region = GuestRegion::from_backend(range, VecMemory::new(4 * PAGE_SIZE as usize));

        let header = TestHeader {
            magic: 0x644d_5241,
            flags: 3,
            reserved: 0,
            entry: 0x4008_0000,
        };
        let addr = GuestPhysAddr::new(0x4000_0100);
        region.write_pod(addr, &header).unwrap();
        assert_eq!(region.read_pod::<TestHeader>(addr).unwrap(), header);
        region
            .write_u8(GuestPhysAddr::new(0x4000_0200), 0xab)
            .unwrap();
        assert_eq!(
            region.read_u8(GuestPhysAddr::new(0x4000_0200)).unwrap(),
            0xab
        );
        region
            .write_u16(GuestPhysAddr::new(0x4000_0202), 0x1234)
            .unwrap();
        assert_eq!(
            region.read_u16(GuestPhysAddr::new(0x4000_0202)).unwrap(),
            0x1234
        );
        region
            .write_u32(GuestPhysAddr::new(0x4000_0204), 0xdead_beef)
            .unwrap();
        assert_eq!(
            region.read_u32(GuestPhysAddr::new(0x4000_0204)).unwrap(),
            0xdead_beef
        );
        region
            .write_u64(GuestPhysAddr::new(0x4000_0208), 0x0123_4567_89ab_cdef)
            .unwrap();
        assert_eq!(
            region.read_u64(GuestPhysAddr::new(0x4000_0208)).unwrap(),
            0x0123_4567_89ab_cdef
        );
        assert!(matches!(
            region.read_pod::<TestHeader>(GuestPhysAddr::new(0x4000_3ff8)),
            Err(Error::OutOfBounds { .. })
        ));

        // Streaming load does NOT implicitly publish.
        let mut source = ChunkList {
            chunks: VecDeque::from([b"helios-".to_vec(), b"kernel-".to_vec(), b"image".to_vec()]),
        };
        let load_addr = GuestPhysAddr::new(0x4000_1000);
        let loaded =
            futures_lite::future::block_on(region.load_stream(load_addr, Some(19), &mut source))
                .unwrap();
        assert_eq!(loaded, 19);
        assert_eq!(
            region.read_bytes(load_addr, 19).unwrap(),
            b"helios-kernel-image"
        );
        assert!(region.backend().published.borrow().is_empty());

        // Explicit publish records the exact byte window.
        region.publish(load_addr, loaded).unwrap();
        assert_eq!(*region.backend().published.borrow(), vec![(PAGE_SIZE, 19)]);

        // Short read and overflow fail fast.
        let mut short = ChunkList {
            chunks: VecDeque::from([b"abc".to_vec()]),
        };
        assert!(matches!(
            futures_lite::future::block_on(region.load_stream(load_addr, Some(10), &mut short)),
            Err(Error::ShortRead {
                expected: 10,
                actual: 3
            })
        ));
        let mut overflow = ChunkList {
            chunks: VecDeque::from([b"0123456789".to_vec()]),
        };
        assert!(matches!(
            futures_lite::future::block_on(region.load_stream(load_addr, Some(4), &mut overflow)),
            Err(Error::StreamOverflow { limit: 4 })
        ));
    }

    #[test]
    fn aarch64_and_x86_reg_builders_validate_and_round_trip() {
        let arm = Aarch64Regs::linux_boot(
            GuestPhysAddr::new(0x4008_0000),
            GuestPhysAddr::new(0x47e0_0000),
        )
        .sp(0x4001_0000)
        .lr(0x4008_0004)
        .try_x(7, 0xdead_beef)
        .unwrap();
        let batch = arm.to_register_values();
        let parsed = Aarch64Regs::from_register_values(&batch).unwrap();
        assert_eq!(parsed, arm);
        assert_eq!(parsed.get_x(0).unwrap(), Some(0x47e0_0000));
        assert_eq!(parsed.get_x(7).unwrap(), Some(0xdead_beef));
        assert_eq!(parsed.get_x(30).unwrap(), Some(0x4008_0004));
        assert_eq!(parsed.get_pc(), Some(0x4008_0000));
        assert_eq!(parsed.get_pstate(), Some(Aarch64Regs::EL1H_DAIF_MASKED));
        assert!(matches!(
            Aarch64Regs::new().try_x(31, 0),
            Err(Error::InvalidRegisterIndex { index: 31, .. })
        ));
        assert!(matches!(
            Aarch64Regs::from_register_values(&[RegisterValue {
                id: RegisterId::X86Rip,
                value: 0,
            }]),
            Err(Error::UnexpectedRegister(RegisterId::X86Rip))
        ));

        let x86 = X86Regs::new()
            .rip(0x1000_0000)
            .rflags(X86Regs::RFLAGS_FIXED)
            .rsi(0x7000)
            .rsp(0x9000)
            .r15(0x1234)
            .cr0(0x8005_0033)
            .cr3(0x2000)
            .msr(0xc000_0080, 0x500);
        let x86_batch = x86.to_register_values();
        let x86_parsed = X86Regs::from_register_values(&x86_batch).unwrap();
        assert_eq!(x86_parsed, x86);
        assert_eq!(x86_parsed.get_gpr(X86Gpr::Rsi), Some(0x7000));
        assert_eq!(x86_parsed.get_gpr(X86Gpr::R15), Some(0x1234));
        assert_eq!(x86_parsed.get_control(3), Some(0x2000));
        assert_eq!(x86_parsed.get_msr(0xc000_0080), Some(0x500));
        assert!(matches!(
            X86Regs::from_register_values(&[RegisterValue {
                id: RegisterId::X86Gpr(16),
                value: 0,
            }]),
            Err(Error::InvalidRegisterIndex { index: 16, .. })
        ));
    }

    #[test]
    fn static_mmio_and_pio_buses_dispatch_without_dyn() {
        struct RegDevice {
            range: MmioRange,
            value: u64,
        }
        impl MmioDevice for RegDevice {
            type Error = Error;
            fn range(&self) -> MmioRange {
                self.range
            }
            fn access(&mut self, offset: u64, access: IoAccess, _: &()) -> Result<u64> {
                match access {
                    IoAccess::Read(_) => Ok(self.value ^ offset),
                    IoAccess::Write(w) => {
                        self.value = w.value;
                        Ok(0)
                    }
                }
            }
        }

        let mut router = MmioRouter::new()
            .with_device(RegDevice {
                range: MmioRange::new(GuestPhysAddr::new(0x1000), 0x100).unwrap(),
                value: 0x11,
            })
            .with_device(RegDevice {
                range: MmioRange::new(GuestPhysAddr::new(0x2000), 0x100).unwrap(),
                value: 0x22,
            });

        assert_eq!(
            router
                .dispatch(
                    GuestPhysAddr::new(0x1004),
                    IoAccess::Read(IoWidth::Dword),
                    &()
                )
                .unwrap(),
            Some(0x11 ^ 4)
        );
        assert_eq!(
            router
                .dispatch(
                    GuestPhysAddr::new(0x2000),
                    IoAccess::Write(IoWrite {
                        width: IoWidth::Dword,
                        value: 0x99,
                    }),
                    &(),
                )
                .unwrap(),
            Some(0)
        );
        assert_eq!(
            router
                .dispatch(
                    GuestPhysAddr::new(0x2000),
                    IoAccess::Read(IoWidth::Dword),
                    &()
                )
                .unwrap(),
            Some(0x99)
        );
        assert_eq!(
            router
                .dispatch(
                    GuestPhysAddr::new(0x3000),
                    IoAccess::Read(IoWidth::Dword),
                    &()
                )
                .unwrap(),
            None
        );

        struct SerialPort {
            range: PioRange,
            last: u8,
        }
        impl PioDevice for SerialPort {
            type Error = Error;
            fn range(&self) -> PioRange {
                self.range
            }
            fn access(&mut self, offset: u16, access: IoAccess, _: &()) -> Result<u64> {
                match (offset, access) {
                    (0, IoAccess::Write(w)) => {
                        self.last = w.value as u8;
                        Ok(0)
                    }
                    (0, IoAccess::Read(_)) => Ok(u64::from(self.last)),
                    _ => Ok(0xff),
                }
            }
        }

        let mut pio = PioRouter::new().with_device(SerialPort {
            range: PioRange::new(0x3f8, 8).unwrap(),
            last: 0,
        });
        assert_eq!(
            pio.dispatch(
                0x3f8,
                IoAccess::Write(IoWrite {
                    width: IoWidth::Byte,
                    value: b'H' as u64,
                }),
                &(),
            )
            .unwrap(),
            Some(0)
        );
        assert_eq!(
            pio.dispatch(0x3f8, IoAccess::Read(IoWidth::Byte), &())
                .unwrap(),
            Some(b'H' as u64)
        );
        assert_eq!(
            pio.dispatch(0x2f8, IoAccess::Read(IoWidth::Byte), &())
                .unwrap(),
            None
        );
    }

    #[test]
    fn ioevent_wrapper_awaits_backend_completions() {
        struct MockEvent {
            remaining: RefCell<usize>,
        }
        impl IoEventBackend for MockEvent {
            async fn wait(&self) -> Result<()> {
                let mut count = self.remaining.borrow_mut();
                if *count == 0 {
                    return Err(Error::Hv(HvError::Stopped));
                }
                *count -= 1;
                Ok(())
            }
        }

        let event = IoEvent::from_backend(
            GuestPhysAddr::new(0x0a00_0050),
            IoWidth::Dword,
            Some(1),
            MockEvent {
                remaining: RefCell::new(2),
            },
        );
        assert_eq!(event.address(), GuestPhysAddr::new(0x0a00_0050));
        assert_eq!(event.width(), IoWidth::Dword);
        assert_eq!(event.match_value(), Some(1));
        futures_lite::future::block_on(async {
            event.wait().await.unwrap();
            event.wait().await.unwrap();
            assert!(matches!(
                event.wait().await,
                Err(Error::Hv(HvError::Stopped))
            ));
        });
    }
}
