use alloc::vec::Vec;
use core::alloc::Layout;
use core::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use crossbeam_utils::CachePadded;
use helios_hal::hv::GuestRange;
use helios_hal::pmm::{PhysFrame, PhysFrameAllocator, PhysFrameRange};
use thiserror::Error;
use triomphe::Arc;

use crate::ProgramOutOfMemory;
use crate::memory::UserMemoryPool;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum GuestMemoryError {
    #[error("guest memory budget exceeded: requested {requested} bytes, available {available}")]
    Budget { requested: usize, available: usize },
    #[error(transparent)]
    Frames(#[from] ProgramOutOfMemory),
    #[error("guest memory access is outside the region or overflows")]
    Bounds,
    #[error("scatter/gather byte count does not match the buffer")]
    Length,
}

/// Per-VM accounting, independent of Wasm linear memory and pooling slots.
/// Producers on any processor reserve/release through one shared atomic;
/// the padded block shares no cache line with unrelated state. A retained
/// memory-region handle continues to own its charge after unmapping.
pub struct GuestMemoryAccount {
    limit: usize,
    used: CachePadded<AtomicUsize>,
}

impl GuestMemoryAccount {
    pub fn new(limit: usize) -> Self {
        Self {
            limit,
            used: CachePadded::new(AtomicUsize::new(0)),
        }
    }
    pub fn allocated_bytes(&self) -> usize {
        self.used.load(Ordering::Acquire)
    }
    pub fn limit(&self) -> usize {
        self.limit
    }
    fn reserve(account: &Arc<Self>, bytes: usize) -> Result<MemoryCharge, GuestMemoryError> {
        account
            .used
            .try_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_add(bytes)
                    .filter(|next| *next <= account.limit)
            })
            .map_err(|used| GuestMemoryError::Budget {
                requested: bytes,
                available: account.limit - used,
            })?;
        Ok(MemoryCharge {
            account: account.clone(),
            bytes,
        })
    }
}

struct MemoryCharge {
    account: Arc<GuestMemoryAccount>,
    bytes: usize,
}
impl Drop for MemoryCharge {
    fn drop(&mut self) {
        self.account.used.fetch_sub(self.bytes, Ordering::AcqRel);
    }
}

/// Owned user-domain frames. The VM retains this owner across mapping,
/// revocation and cancellation; frames are never put in a Wasm allocation.
pub(super) struct GuestPages {
    pool: &'static UserMemoryPool,
    frames: Vec<PhysFrame>,
    // Released after frames have gone back to the user pool.
    _charge: MemoryCharge,
}

impl GuestPages {
    pub(super) fn allocate(
        pool: &'static UserMemoryPool,
        account: &Arc<GuestMemoryAccount>,
        bytes: usize,
    ) -> Result<Arc<Self>, GuestMemoryError> {
        let charge = GuestMemoryAccount::reserve(account, bytes)?;
        let mut pages = Self {
            pool,
            frames: Vec::with_capacity(bytes / PhysFrame::SIZE),
            _charge: charge,
        };
        // Individual frames avoid imposing physical contiguity on guest RAM.
        // A failed allocation drops every frame already acquired and its charge.
        for _ in 0..bytes / PhysFrame::SIZE {
            let layout = Layout::from_size_align(PhysFrame::SIZE, PhysFrame::SIZE)
                .expect("frame size and alignment form a valid layout");
            let ptr = pool.allocate_zeroed(layout)?;
            pages
                .frames
                .push(PhysFrame::from_phys_addr(ptr.as_ptr().expose_provenance()));
        }
        Ok(Arc::new(pages))
    }
    pub(super) fn frames(&self) -> &[PhysFrame] {
        &self.frames
    }
    fn byte(&self, offset: usize) -> &AtomicU8 {
        let frame = self.frames[offset / PhysFrame::SIZE];
        let address = frame.phys_addr() + offset % PhysFrame::SIZE;
        // SAFETY: these initialized frames remain owned by self. Atomic byte
        // accesses permit concurrent host access without manufacturing slices
        // or exclusive references over RAM a guest can modify concurrently.
        unsafe { AtomicU8::from_ptr(core::ptr::with_exposed_provenance_mut(address)) }
    }
}

impl Drop for GuestPages {
    fn drop(&mut self) {
        for &frame in &self.frames {
            self.pool.deallocate(PhysFrameRange::single(frame));
        }
    }
}

/// Explicit byte-copy view of kernel-managed guest RAM. Cloning retains the
/// allocation, not a host pointer or Wasm linear-memory mapping. Reads/writes
/// are byte-atomic, not a coherent snapshot against running guest processors;
/// device protocols must provide their own publication/synchronization rules.
#[derive(Clone)]
pub struct GuestMemoryRegion {
    pub(super) range: GuestRange,
    pub(super) pages: Arc<GuestPages>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GuestSlice {
    pub offset: usize,
    pub len: usize,
}

impl GuestMemoryRegion {
    pub fn range(&self) -> GuestRange {
        self.range
    }
    fn validate(&self, offset: usize, len: usize) -> Result<(), GuestMemoryError> {
        if offset
            .checked_add(len)
            .is_none_or(|end| end > self.range.byte_len())
        {
            return Err(GuestMemoryError::Bounds);
        }
        Ok(())
    }
    pub fn read(&self, offset: usize, destination: &mut [u8]) -> Result<(), GuestMemoryError> {
        self.validate(offset, destination.len())?;
        for (index, byte) in destination.iter_mut().enumerate() {
            *byte = self.pages.byte(offset + index).load(Ordering::Relaxed);
        }
        Ok(())
    }
    pub fn write(&self, offset: usize, source: &[u8]) -> Result<(), GuestMemoryError> {
        self.validate(offset, source.len())?;
        for (index, byte) in source.iter().enumerate() {
            self.pages
                .byte(offset + index)
                .store(*byte, Ordering::Relaxed);
        }
        Ok(())
    }
    fn validate_scatter(
        &self,
        slices: &[GuestSlice],
        bytes: usize,
    ) -> Result<(), GuestMemoryError> {
        let mut total = 0usize;
        for slice in slices {
            self.validate(slice.offset, slice.len)?;
            total = total
                .checked_add(slice.len)
                .ok_or(GuestMemoryError::Length)?;
        }
        if total != bytes {
            return Err(GuestMemoryError::Length);
        }
        Ok(())
    }
    pub fn read_scattered(
        &self,
        slices: &[GuestSlice],
        destination: &mut [u8],
    ) -> Result<(), GuestMemoryError> {
        self.validate_scatter(slices, destination.len())?;
        let mut offset = 0;
        for slice in slices {
            self.read(slice.offset, &mut destination[offset..offset + slice.len])?;
            offset += slice.len;
        }
        Ok(())
    }
    pub fn write_scattered(
        &self,
        slices: &[GuestSlice],
        source: &[u8],
    ) -> Result<(), GuestMemoryError> {
        self.validate_scatter(slices, source.len())?;
        let mut offset = 0;
        for slice in slices {
            self.write(slice.offset, &source[offset..offset + slice.len])?;
            offset += slice.len;
        }
        Ok(())
    }
}
