use alloc::vec::Vec;
use core::alloc::Layout;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use crossbeam_utils::CachePadded;
use helios_hal::hv::{GuestRange, Hypervisor};
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
    #[error("guest memory partial-word write raced with another writer")]
    Contended,
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
    fn word(&self, offset: usize) -> &AtomicU64 {
        let frame = self.frames[offset / PhysFrame::SIZE];
        let address = frame.phys_addr() + ((offset % PhysFrame::SIZE) & !7);
        // SAFETY: frames are initialized, page-aligned and retained by self.
        // Every host access uses this same atomic width. No Rust slice or
        // exclusive reference is manufactured over concurrently running RAM.
        unsafe { AtomicU64::from_ptr(core::ptr::with_exposed_provenance_mut(address)) }
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
/// use aligned 64-bit atomic cells with acquire/release publication. Naturally
/// aligned 1/2/4/8-byte accesses are atomic; larger or unaligned transfers are
/// not snapshots. Device protocols still own synchronization with guest CPUs.
/// Partial-cell writes attempt one compare-exchange and return `Contended`
/// on interference; a prefix of the transfer may already have been written.
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
    pub fn publish(
        &self,
        hardware: &impl Hypervisor,
        offset: usize,
        len: usize,
    ) -> Result<(), GuestMemoryError> {
        self.validate(offset, len)?;
        if len == 0 {
            return Ok(());
        }
        let first = offset / PhysFrame::SIZE;
        let end = (offset + len).div_ceil(PhysFrame::SIZE);
        // SAFETY: this handle retains initialized user-domain pages. The
        // caller's preceding copies have finished; no Rust reference aliases
        // guest access. Cache maintenance includes whole boundary pages.
        unsafe {
            hardware.synchronize_memory(&self.pages.frames[first..end]);
        }
        Ok(())
    }
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
        let mut copied = 0;
        while copied < destination.len() {
            let position = offset + copied;
            let lane = position % 8;
            let count = (8 - lane).min(destination.len() - copied);
            let bytes = self
                .pages
                .word(position)
                .load(Ordering::Acquire)
                .to_ne_bytes();
            destination[copied..copied + count].copy_from_slice(&bytes[lane..lane + count]);
            copied += count;
        }
        Ok(())
    }
    pub fn write(&self, offset: usize, source: &[u8]) -> Result<(), GuestMemoryError> {
        self.validate(offset, source.len())?;
        let mut copied = 0;
        while copied < source.len() {
            let position = offset + copied;
            let lane = position % 8;
            let count = (8 - lane).min(source.len() - copied);
            let word = self.pages.word(position);
            if count == 8 {
                word.store(
                    u64::from_ne_bytes(source[copied..copied + 8].try_into().unwrap()),
                    Ordering::Release,
                );
            } else {
                let previous = word.load(Ordering::Acquire);
                let mut bytes = previous.to_ne_bytes();
                bytes[lane..lane + count].copy_from_slice(&source[copied..copied + count]);
                word.compare_exchange(
                    previous,
                    u64::from_ne_bytes(bytes),
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .map_err(|_| GuestMemoryError::Contended)?;
            }
            copied += count;
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
