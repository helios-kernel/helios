//! The page index a native user address space keeps beside its hardware
//! translation tables, shared by every backend that implements
//! `helios_hal::native`.
//!
//! The index maps each mapped user range to its access flags and tracks the
//! backing user-memory frame only for pages that have been committed (leaving
//! newly reserved and discarded pages without a frame until first touched). It
//! answers the lookups the contract's operations need, the copies of
//! [`helios_hal::native::UserSpace`] and the fault path, in `O(log n)` per
//! range rather than a scan of every page, and copies each run of physically
//! adjacent frames in one copy.
//!
//! # Concurrency
//!
//! The index is single-owner: a space holds it under the lock that also
//! serialises its page-table writes, and every method runs with that lock
//! held. Frames are reached through the kernel's direct map, never through a
//! user address.
//!
//! [`NativeSpace`] keeps the slice count `helios_hal::native` describes in
//! a cache line of its own: every processor entering or leaving a slice of
//! the space writes it and every removal reads it, so it shares no line
//! with the lock word removals and copies spin on. A removal holds the lock
//! from its first table write through its shootdown, so no copy, fault
//! resolution or other change of the space sees a page whose translation
//! is gone from the tables but not yet from every processor.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering, fence};

use crossbeam_utils::CachePadded;
use helios_hal::native::{Mapping, NativeError, RegionKind, SharedFrame, UserSpace};
use helios_hal::pmm::PhysFrame;
use helios_hal::vmm::{PageFlags, SwapToken, VirtAddr, VirtRange};
use spin::Mutex;

use crate::memory::{
    AGE_BATCH_PAGES, allocate_user_frame_uninit_on, allocate_user_frame_zeroed_on,
    deallocate_user_frame_on,
};

const PAGE: u64 = PhysFrame::SIZE as u64;

fn deallocate_user_frame_current(frame: NonNull<u8>) {
    deallocate_user_frame_on(helios_hal::cpu::current_processor(), frame);
}

fn allocate_shared_frame() -> Result<SharedFrame, NativeError> {
    let processor = helios_hal::cpu::current_processor();
    let ptr = allocate_user_frame_zeroed_on(processor).map_err(|_| NativeError::OutOfMemory)?;
    // SAFETY: `ptr` is a freshly allocated, page-aligned 4 KiB user frame from
    // the user memory pool released by `deallocate_user_frame_current`.
    Ok(unsafe { SharedFrame::new(ptr, deallocate_user_frame_current) })
}

/// The hardware translation tables of one native user address space: the
/// part of [`NativeSpace`] each backend supplies.
///
/// # Safety
///
/// `install` maps exactly the frame it is given at the page it is given,
/// reachable from user mode with no more access than `flags`, `protect`
/// grants no more than its `flags`, and neither touches the kernel's half
/// of the address space. `invalidate` returns only once no processor holds
/// a translation of the range older than the call.
pub unsafe trait UserTranslation: Send + 'static {
    /// Maps page `base`, which is not mapped, to the frame at `physical`.
    /// The page goes from not present to present, so no processor holds a
    /// translation of it and no invalidation is needed.
    fn install(&mut self, base: u64, physical: u64, flags: PageFlags) -> Result<(), NativeError>;

    /// Removes the translation of present page `base`. Processors may still
    /// hold it: the caller runs [`Self::invalidate`] over the page, when a
    /// slice may hold it, before the frame is freed, mapped elsewhere alone,
    /// or the removal is reported done.
    fn uninstall(&mut self, base: u64);

    /// Replaces the access of present page `base` with `flags`, keeping its
    /// frame. A narrowing is invalidated by the caller as `uninstall` is.
    fn protect(&mut self, base: u64, flags: PageFlags);

    /// Invalidates every translation of `[first, last)` on this processor
    /// and every other, and returns once each has acknowledged: the
    /// backend's TLB shootdown. Runs in task context with interrupts
    /// enabled.
    fn invalidate(&self, first: u64, last: u64);

    /// The physical address of a user frame, from its direct-map address.
    fn physical(&self, frame: NonNull<u8>) -> u64;

    /// Allocates a fresh, empty translation-table root matching this space's
    /// kernel half and direct-map offset, for [`UserSpace::clone_cow`].
    fn new_empty(&self) -> Result<Self, NativeError>
    where
        Self: Sized;

    /// Synchronizes data and instruction caches for the 4 KiB user frame at
    /// kernel direct-map pointer `frame` before user mode fetches instructions
    /// from it. Architectures whose hardware keeps I-cache coherent with
    /// D-cache (x86-64) leave the default no-op; AArch64 cleans D-cache to PoU
    /// and invalidates I-cache whenever `CTR_EL0.{IDC,DIC}` require it.
    fn sync_executable_frame(&self, _frame: NonNull<u8>) {}

    /// Tests and clears the hardware accessed flag (`ACCESSED` on x86-64,
    /// `AF` on AArch64) on the present leaf for page `base`. Returns `true`
    /// when the bit was set (the page was accessed since the previous pass)
    /// and `false` when it was already clear or not present.
    fn test_and_clear_accessed(&mut self, _base: u64) -> bool {
        false
    }
}

/// A native user address space: the page index and the backend's
/// translation tables behind one spin lock, held for a table write, a
/// copy, or a removal and its shootdown, never across a slice or an
/// `.await`, and the count of slices running it. It is the [`UserSpace`]
/// every backend publishes; see `helios_hal::native` for the concurrency
/// contract it keeps.
///
/// Both live in one block the space owns, so the space itself has the
/// alignment of a pointer wherever it is held: the padded counter's
/// cache-line alignment (128 bytes on x86-64 and AArch64) would otherwise
/// pass to every future that holds a space, past what the executor's task
/// arena places.
pub struct NativeSpace<Tables> {
    shared: Box<Shared<Tables>>,
}

const _: () = assert!(align_of::<NativeSpace<()>>() == align_of::<usize>());

struct Shared<Tables> {
    state: Mutex<SpaceState<Tables>>,
    /// Slices of this space running now, on any processor. Every processor
    /// that enters or leaves a slice of the space writes it.
    slices: CachePadded<AtomicUsize>,
}

struct SpaceState<Tables> {
    pages: NativePages,
    tables: Tables,
}

/// One running slice of a [`NativeSpace`], counted from before it reads
/// the space's root until it is dropped. A backend drops it only once the
/// slice's exit has left no translation of the space on its processor.
pub struct NativeSlice<'a, Tables> {
    space: &'a NativeSpace<Tables>,
}

impl<Tables: UserTranslation> NativeSlice<'_, Tables> {
    /// Runs `operation` on the translation tables under the space's lock,
    /// as a slice's entry does to read the root it loads.
    pub fn with_tables<Output>(&self, operation: impl FnOnce(&mut Tables) -> Output) -> Output {
        operation(&mut self.space.shared.state.lock().tables)
    }
}

impl<Tables> Drop for NativeSlice<'_, Tables> {
    fn drop(&mut self) {
        self.space.shared.slices.fetch_sub(1, Ordering::SeqCst);
    }
}

struct SharedObjectPage {
    frame: Arc<SharedFrame>,
    /// Clean 4 KiB baseline frame allocated from the user memory pool for
    /// file-backed `MAP_SHARED` objects so writeback emits only modified byte
    /// ranges and never clobbers concurrent `write(2)` updates or untouched
    /// bytes. `None` for anonymous shared objects.
    clean: Option<SharedFrame>,
}

struct SharedObjectState {
    pages: BTreeMap<u64, SharedObjectPage>,
    track_dirty: bool,
}

/// A page-indexed shared memory object holding reference-counted 4 KiB user
/// frames (`Arc<SharedFrame>`), shared coherently across multiple mappings in
/// one address space, across `fork(2)` (`UserSpace::clone_cow`), across
/// distinct processes inside a container, and for `memfd` / SysV shared memory.
///
/// # Concurrency contract
///
/// Guarded by a non-awaiting `spin::Mutex` (never held across `.await`, never
/// touched from interrupt context). When both a [`NativeSpace`] lock and a
/// [`SharedPageObject`] lock are held, the order is strictly **`NativeSpace`
/// -> `SharedPageObject`**.
#[derive(Clone)]
pub struct SharedPageObject {
    inner: Arc<Mutex<SharedObjectState>>,
}

impl core::fmt::Debug for SharedPageObject {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("SharedPageObject")
            .finish_non_exhaustive()
    }
}

impl SharedPageObject {
    /// Allocates a single zeroed user-pool [`SharedFrame`] and copies up to
    /// one page of `bytes` into its start, for demand-loading a private file
    /// page via [`UserSpace::install_private_frame`].
    pub fn allocate_frame_from_bytes(bytes: &[u8]) -> Result<SharedFrame, NativeError> {
        let frame = allocate_shared_frame()?;
        let n = bytes.len().min(PhysFrame::SIZE);
        if n > 0 {
            // SAFETY: `frame` owns a valid 4 KiB page and `n <= PhysFrame::SIZE`.
            unsafe {
                core::ptr::copy_nonoverlapping(bytes.as_ptr(), frame.as_ptr().as_ptr(), n);
            }
        }
        Ok(frame)
    }

    /// Creates an anonymous shared memory object (`MAP_SHARED | MAP_ANONYMOUS`,
    /// `memfd`, SysV `shm`) without file dirty-baseline tracking.
    pub fn new_anonymous() -> Self {
        Self {
            inner: Arc::new(Mutex::new(SharedObjectState {
                pages: BTreeMap::new(),
                track_dirty: false,
            })),
        }
    }

    /// Creates a file-backed shared memory object that tracks clean baselines
    /// in user-pool frames for exact dirty-byte writeback.
    pub fn new_file_backed() -> Self {
        Self {
            inner: Arc::new(Mutex::new(SharedObjectState {
                pages: BTreeMap::new(),
                track_dirty: true,
            })),
        }
    }

    /// Returns a weak handle to the internal state so container caches drop
    /// entries automatically once the last mapping releases the object.
    pub fn downgrade(&self) -> WeakSharedPageObject {
        WeakSharedPageObject {
            inner: Arc::downgrade(&self.inner),
        }
    }

    /// Returns the resident frame at `page_index`, if already allocated.
    pub fn get_frame(&self, page_index: u64) -> Option<Arc<SharedFrame>> {
        self.inner
            .lock()
            .pages
            .get(&page_index)
            .map(|slot| Arc::clone(&slot.frame))
    }

    /// Returns the resident frame at `page_index`, allocating a zeroed frame
    /// (and clean baseline frame when `track_dirty`) from the user pool if absent.
    pub fn get_or_alloc_frame(&self, page_index: u64) -> Result<Arc<SharedFrame>, NativeError> {
        let mut state = self.inner.lock();
        if let Some(slot) = state.pages.get(&page_index) {
            return Ok(Arc::clone(&slot.frame));
        }
        let frame = Arc::new(allocate_shared_frame()?);
        let clean = if state.track_dirty {
            Some(allocate_shared_frame()?)
        } else {
            None
        };
        let cloned = Arc::clone(&frame);
        state
            .pages
            .insert(page_index, SharedObjectPage { frame, clean });
        Ok(cloned)
    }

    /// Populates `page_index` with initial file `bytes` (at most 4 KiB) if that
    /// page is not yet resident, preserving any already-resident (potentially
    /// dirty) frame untouched.
    pub fn load_file_page(
        &self,
        page_index: u64,
        bytes: &[u8],
    ) -> Result<Arc<SharedFrame>, NativeError> {
        assert!(bytes.len() <= PAGE as usize, "page load exceeds 4 KiB");
        let mut state = self.inner.lock();
        if let Some(slot) = state.pages.get(&page_index) {
            return Ok(Arc::clone(&slot.frame));
        }
        let frame = allocate_shared_frame()?;
        if !bytes.is_empty() {
            // SAFETY: `frame` is a newly allocated, unshared 4 KiB user frame
            // and `bytes.len() <= PAGE`.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    bytes.as_ptr(),
                    frame.as_ptr().as_ptr(),
                    bytes.len(),
                );
            }
        }
        let clean = if state.track_dirty {
            let clean_frame = allocate_shared_frame()?;
            if !bytes.is_empty() {
                // SAFETY: `clean_frame` is a newly allocated, unshared 4 KiB
                // user frame and `bytes.len() <= PAGE`.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        bytes.as_ptr(),
                        clean_frame.as_ptr().as_ptr(),
                        bytes.len(),
                    );
                }
            }
            Some(clean_frame)
        } else {
            None
        };
        let frame = Arc::new(frame);
        let cloned = Arc::clone(&frame);
        state
            .pages
            .insert(page_index, SharedObjectPage { frame, clean });
        Ok(cloned)
    }

    /// Extracts all resident frames as uniquely owned `SharedFrame`s when this
    /// object was used as a private staging buffer (sole owner).
    pub fn drain_unique_frames(&self) -> Vec<(u64, SharedFrame)> {
        let mut state = self.inner.lock();
        let drained = core::mem::take(&mut state.pages);
        drained
            .into_iter()
            .filter_map(|(idx, slot)| Arc::try_unwrap(slot.frame).ok().map(|f| (idx, f)))
            .collect()
    }

    /// Applies a `write(2)` / `pwrite(2)` update to every already-resident page
    /// overlapping `[file_offset, file_offset + bytes.len())`, updating both
    /// the live shared frame (immediately visible in every mapped space) and
    /// the clean baseline (so writeback does not clobber the write).
    pub fn apply_file_write(&self, file_offset: u64, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        let state = self.inner.lock();
        let mut done = 0usize;
        while done < bytes.len() {
            let pos = file_offset.saturating_add(done as u64);
            let page_index = pos / PAGE;
            let into_page = (pos % PAGE) as usize;
            let step = (bytes.len() - done).min(PAGE as usize - into_page);
            if let Some(slot) = state.pages.get(&page_index) {
                let src = &bytes[done..done + step];
                // SAFETY: `into_page <= PAGE`, keeping `dst` within the 4 KiB frame.
                let dst = unsafe { slot.frame.as_ptr().as_ptr().add(into_page) };
                // SAFETY: `into_page + step <= PAGE`, and `slot.frame` stays
                // live while `state` is locked.
                unsafe {
                    core::ptr::copy_nonoverlapping(src.as_ptr(), dst, step);
                }
                if let Some(clean) = &slot.clean {
                    // SAFETY: `into_page <= PAGE`, keeping `clean_dst` within `clean`.
                    let clean_dst = unsafe { clean.as_ptr().as_ptr().add(into_page) };
                    // SAFETY: `into_page + step <= PAGE`, and `clean` is owned
                    // exclusively under `state`.
                    unsafe {
                        core::ptr::copy_nonoverlapping(src.as_ptr(), clean_dst, step);
                    }
                }
            }
            done += step;
        }
    }

    /// Overlays live resident shared bytes onto a buffer read from the backing
    /// file at `file_offset`, ensuring `read(2)` observes unflushed `MAP_SHARED`
    /// writes across all processes in a container.
    pub fn overlay_file_read(&self, file_offset: u64, out: &mut [u8]) {
        if out.is_empty() {
            return;
        }
        let state = self.inner.lock();
        let mut done = 0usize;
        while done < out.len() {
            let pos = file_offset.saturating_add(done as u64);
            let page_index = pos / PAGE;
            let into_page = (pos % PAGE) as usize;
            let step = (out.len() - done).min(PAGE as usize - into_page);
            if let Some(slot) = state.pages.get(&page_index) {
                // SAFETY: `into_page <= PAGE`, keeping `src_ptr` within the 4 KiB frame.
                let src_ptr = unsafe { slot.frame.as_ptr().as_ptr().add(into_page) };
                // SAFETY: `into_page + step <= PAGE` and `slot.frame` is a live
                // 4 KiB direct-mapped frame while `state` is locked.
                let src = unsafe { core::slice::from_raw_parts(src_ptr, step) };
                out[done..done + step].copy_from_slice(src);
            }
            done += step;
        }
    }

    /// Reflects a file truncation to `new_size`: zeroes the tail of the
    /// partial EOF page in both `frame` and `clean`, and drops pages strictly
    /// beyond `page_align(new_size)`.
    pub fn truncate(&self, new_size: u64) {
        let mut state = self.inner.lock();
        let eof_page = new_size.div_ceil(PAGE);
        let tail_offset = (new_size % PAGE) as usize;
        if tail_offset != 0
            && let Some(slot) = state.pages.get_mut(&(eof_page - 1))
        {
            let zero_len = PAGE as usize - tail_offset;
            // SAFETY: `tail_offset < PAGE` within the live 4 KiB frame.
            let dst = unsafe { slot.frame.as_ptr().as_ptr().add(tail_offset) };
            // SAFETY: `tail_offset + zero_len == PAGE` within the live 4 KiB frame.
            unsafe {
                core::ptr::write_bytes(dst, 0, zero_len);
            }
            if let Some(clean) = &slot.clean {
                // SAFETY: `tail_offset < PAGE` within `clean`'s 4 KiB frame.
                let clean_dst = unsafe { clean.as_ptr().as_ptr().add(tail_offset) };
                // SAFETY: `tail_offset + zero_len == PAGE` within `clean`'s 4 KiB frame.
                unsafe {
                    core::ptr::write_bytes(clean_dst, 0, zero_len);
                }
            }
        }
        let _removed = state.pages.split_off(&eof_page);
    }

    /// Collects only the contiguous modified `(file_offset, bytes)` runs across
    /// `[file_offset, file_offset + valid_len)` by comparing each resident
    /// frame directly through the kernel direct map against its clean baseline
    /// (preserving dirty data even across `mprotect(PROT_NONE)`).
    pub fn collect_dirty_runs(&self, file_offset: u64, valid_len: u64) -> Vec<(u64, Vec<u8>)> {
        if valid_len == 0 {
            return Vec::new();
        }
        let state = self.inner.lock();
        if !state.track_dirty {
            return Vec::new();
        }
        let mut runs = Vec::new();
        let mut done = 0u64;
        while done < valid_len {
            let pos = file_offset.saturating_add(done);
            let page_index = pos / PAGE;
            let into_page = (pos % PAGE) as usize;
            let step = (valid_len - done).min(PAGE - into_page as u64) as usize;
            if let Some(slot) = state.pages.get(&page_index)
                && let Some(clean) = &slot.clean
            {
                // SAFETY: `into_page <= PAGE` inside the live 4 KiB frame.
                let live_ptr = unsafe { slot.frame.as_ptr().as_ptr().add(into_page) };
                // SAFETY: `into_page + step <= PAGE` inside the live 4 KiB frame.
                let live_slice = unsafe { core::slice::from_raw_parts(live_ptr, step) };
                // SAFETY: `into_page <= PAGE` inside `clean`'s 4 KiB frame.
                let clean_ptr = unsafe { clean.as_ptr().as_ptr().add(into_page) };
                // SAFETY: `into_page + step <= PAGE` inside `clean`'s 4 KiB frame.
                let clean_slice = unsafe { core::slice::from_raw_parts(clean_ptr, step) };
                let mut idx = 0usize;
                while idx < step {
                    if live_slice[idx] == clean_slice[idx] {
                        idx += 1;
                        continue;
                    }
                    let run_start = idx;
                    while idx < step && live_slice[idx] != clean_slice[idx] {
                        idx += 1;
                    }
                    runs.push((pos + run_start as u64, live_slice[run_start..idx].to_vec()));
                }
            }
            done += step as u64;
        }
        runs
    }

    /// Updates the clean baseline for `[file_offset, file_offset + bytes.len())`
    /// after those bytes have been written back to the backing file.
    pub fn mark_clean(&self, file_offset: u64, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        let state = self.inner.lock();
        let mut done = 0usize;
        while done < bytes.len() {
            let pos = file_offset.saturating_add(done as u64);
            let page_index = pos / PAGE;
            let into_page = (pos % PAGE) as usize;
            let step = (bytes.len() - done).min(PAGE as usize - into_page);
            if let Some(slot) = state.pages.get(&page_index)
                && let Some(clean) = &slot.clean
            {
                let src = &bytes[done..done + step];
                // SAFETY: `into_page <= PAGE` inside `clean`'s 4 KiB frame.
                let clean_dst = unsafe { clean.as_ptr().as_ptr().add(into_page) };
                // SAFETY: `into_page + step <= PAGE` inside `clean`'s 4 KiB frame.
                unsafe {
                    core::ptr::copy_nonoverlapping(src.as_ptr(), clean_dst, step);
                }
            }
            done += step;
        }
    }
}

/// Weak reference to a [`SharedPageObject`], used by container-wide file page
/// caches so entries expire automatically when the last mapping drops.
#[derive(Clone)]
pub struct WeakSharedPageObject {
    inner: alloc::sync::Weak<Mutex<SharedObjectState>>,
}

impl WeakSharedPageObject {
    pub fn upgrade(&self) -> Option<SharedPageObject> {
        self.inner.upgrade().map(|inner| SharedPageObject { inner })
    }
}

/// Ownership of one tracked 4 KiB user page inside [`NativePages`].
///
/// - [`Self::Unique`]: privately owned resident frame with no refcount traffic.
/// - [`Self::Cow`]: copy-on-write resident frame produced by [`NativeSpace::clone_cow`]
///   on private mappings; mapped read-only in hardware and copied on write.
/// - [`Self::SharedWritable`]: true shared-memory resident frame (`MAP_SHARED`,
///   `memfd`, SysV `shm`); mapped writable in hardware when `PageFlags::WRITE`
///   is set and kept shared (never CoW-copied) across `clone_cow`, `mprotect`,
///   and `remap`.
/// - [`Self::Swapped`]: private page evicted to the swap backend under a
///   [`SwapToken`]; its hardware PTE is unmapped until faulted back in.
#[derive(Debug)]
enum FrameRef {
    Unique(NonNull<u8>),
    Cow(Arc<SharedFrame>),
    SharedWritable(Arc<SharedFrame>),
    Swapped(SwapToken),
}

impl FrameRef {
    fn resident_ptr(&self) -> Option<NonNull<u8>> {
        match self {
            Self::Unique(ptr) => Some(*ptr),
            Self::Cow(shared) | Self::SharedWritable(shared) => Some(shared.as_ptr()),
            Self::Swapped(_) => None,
        }
    }

    fn is_cow(&self) -> bool {
        matches!(self, Self::Cow(_))
    }

    fn is_swapped(&self) -> bool {
        matches!(self, Self::Swapped(_))
    }

    fn swapped_token(&self) -> Option<SwapToken> {
        match self {
            Self::Swapped(token) => Some(*token),
            Self::Unique(_) | Self::Cow(_) | Self::SharedWritable(_) => None,
        }
    }

    /// Clones this frame reference for `clone_cow` (`fork`), returning
    /// `(child_ref, narrowed_parent)` where `narrowed_parent` is `true` only
    /// when a previously unique writable private frame was promoted to CoW and
    /// requires narrowing its parent PTE.
    fn clone_for_fork(&mut self) -> (Self, bool) {
        match self {
            Self::Unique(ptr) => {
                // SAFETY: `ptr` is a valid 4 KiB user frame owned by this slot.
                let shared =
                    Arc::new(unsafe { SharedFrame::new(*ptr, deallocate_user_frame_current) });
                let clone = Arc::clone(&shared);
                *self = Self::Cow(shared);
                (Self::Cow(clone), true)
            }
            Self::Cow(shared) => (Self::Cow(Arc::clone(shared)), false),
            Self::SharedWritable(shared) => (Self::SharedWritable(Arc::clone(shared)), false),
            Self::Swapped(_) => {
                panic!("clone_cow must pre-fault all swapped pages before sharing frames")
            }
        }
    }

    fn release(self, processor: helios_hal::cpu::ProcessorId) {
        match self {
            Self::Unique(ptr) => deallocate_user_frame_on(processor, ptr),
            Self::Cow(shared) | Self::SharedWritable(shared) => drop(shared),
            Self::Swapped(_) => {
                panic!("swapped tokens must be queued onto orphan_tokens rather than released")
            }
        }
    }
}

fn hardware_flags(flags: PageFlags, is_cow: bool) -> PageFlags {
    if is_cow {
        flags - PageFlags::WRITE
    } else {
        flags
    }
}

/// What a change took out of the tables: the frames to free once its
/// shootdown is done, and the page span `[first, last)` it removed or
/// narrowed translations in, empty when it touched none.
struct Removed {
    frames: Vec<FrameRef>,
    first: u64,
    last: u64,
}

impl Removed {
    fn new() -> Self {
        Self {
            frames: Vec::new(),
            first: u64::MAX,
            last: 0,
        }
    }

    fn touch(&mut self, base: u64) {
        self.first = self.first.min(base);
        self.last = self.last.max(base + PAGE);
    }
}

/// An installation that ran out of memory or tables part way, with the
/// pages it had installed already taken back out.
struct Failed {
    error: NativeError,
    removed: Removed,
}

impl<Tables: UserTranslation> NativeSpace<Tables> {
    /// An empty space whose user range is `[start, end)`.
    pub fn new(tables: Tables, start: u64, end: u64) -> Self {
        Self {
            shared: Box::new(Shared {
                state: Mutex::new(SpaceState {
                    pages: NativePages::new(start, end),
                    tables,
                }),
                slices: CachePadded::new(AtomicUsize::new(0)),
            }),
        }
    }

    /// Counts a slice of this space as running. The caller takes it before
    /// it reads the root it loads, so a removal that misses the count wrote
    /// its tables before that slice walks them.
    pub fn begin_slice(&self) -> NativeSlice<'_, Tables> {
        self.shared.slices.fetch_add(1, Ordering::SeqCst);
        NativeSlice { space: self }
    }

    /// Runs a TLB shootdown over `[first, last)` whenever any slice of this
    /// space may be executing on another processor.
    fn invalidate_if_active(&self, tables: &Tables, first: u64, last: u64) {
        if first < last {
            // Pairs with `begin_slice`: either this load sees a slice that
            // is starting, or that slice counts itself after it and the root
            // it loads walks the tables as written above. A slice that has
            // ended left nothing behind on its processor.
            fence(Ordering::SeqCst);
            if self.shared.slices.load(Ordering::SeqCst) != 0 {
                tables.invalidate(first, last);
            }
        }
    }

    /// Completes a change: invalidates what it removed or narrowed wherever
    /// a slice may hold it, then frees the frames it took out.
    fn complete(&self, tables: &Tables, removed: Removed) {
        self.invalidate_if_active(tables, removed.first, removed.last);
        let processor = helios_hal::cpu::current_processor();
        for frame in removed.frames {
            frame.release(processor);
        }
    }
}

impl<Tables: UserTranslation> SpaceState<Tables> {
    /// Installs zero-filled pages over `[first, last)`, which has no
    /// mapping. A failure takes back what it installed.
    fn install(&mut self, first: u64, last: u64, flags: PageFlags) -> Result<(), Failed> {
        let processor = helios_hal::cpu::current_processor();
        for base in (first..last).step_by(PAGE as usize) {
            let Ok(frame) = allocate_user_frame_zeroed_on(processor) else {
                return Err(self.fail(first, base, NativeError::OutOfMemory));
            };
            let physical = self.tables.physical(frame);
            if let Err(error) = self.tables.install(base, physical, flags) {
                deallocate_user_frame_on(processor, frame);
                return Err(self.fail(first, base, error));
            }
            self.pages.insert_region_with_kind(
                base,
                base + PAGE,
                flags,
                RegionKind::PrivateAnonymous,
            );
            self.pages.insert_frame(base, frame);
        }
        Ok(())
    }

    /// Takes the pages of `[first, last)` out of the index and the tables.
    /// Another thread's slice may have reached any committed page, so their
    /// frames wait for the shootdown. Swapped-out pages have no hardware PTE
    /// and queue their tokens onto `orphan_tokens`.
    fn take(&mut self, first: u64, last: u64) -> Removed {
        let mut removed = Removed::new();
        for (base, frame) in self.pages.remove_range_refs(first, last) {
            if let FrameRef::Swapped(token) = frame {
                self.pages.orphan_tokens.push(token);
                continue;
            }
            self.tables.uninstall(base);
            removed.touch(base);
            removed.frames.push(frame);
        }
        removed
    }

    fn fail(&mut self, first: u64, last: u64, error: NativeError) -> Failed {
        Failed {
            error,
            removed: self.take(first, last),
        }
    }

    /// Gives uncommitted page `base` a zero-filled frame (private `Unique` for
    /// private regions, `SharedWritable` for shared regions).
    fn commit(&mut self, base: u64, flags: PageFlags, kind: RegionKind) -> Result<(), NativeError> {
        let processor = helios_hal::cpu::current_processor();
        let frame =
            allocate_user_frame_zeroed_on(processor).map_err(|_| NativeError::OutOfMemory)?;
        if flags.contains(PageFlags::EXECUTE) {
            self.tables.sync_executable_frame(frame);
        }
        if let Err(error) = self
            .tables
            .install(base, self.tables.physical(frame), flags)
        {
            deallocate_user_frame_on(processor, frame);
            return Err(error);
        }
        let frame_ref = if kind == RegionKind::Shared {
            // SAFETY: `frame` is a newly allocated 4 KiB user frame.
            FrameRef::SharedWritable(Arc::new(unsafe {
                SharedFrame::new(frame, deallocate_user_frame_current)
            }))
        } else {
            FrameRef::Unique(frame)
        };
        self.pages.insert_frame_ref(base, frame_ref);
        Ok(())
    }

    /// Synchronizes instruction caches for every resident committed frame in
    /// `[first, last)` whose mapped region carries [`PageFlags::EXECUTE`].
    fn sync_executable_range(&self, first: u64, last: u64) {
        for (&base, frame) in self.pages.frames.range(first..last) {
            let Some(ptr) = frame.resident_ptr() else {
                continue;
            };
            if self
                .pages
                .region_at(base)
                .is_some_and(|(_, region)| region.flags.contains(PageFlags::EXECUTE))
            {
                self.tables.sync_executable_frame(ptr);
            }
        }
    }

    /// Ensures committed page `base` is writable in hardware (`flags`):
    /// upgrades `FrameRef::Cow` in place when this space is the sole surviving
    /// owner or performs a break-before-make copy onto a fresh private frame.
    /// Leaves `FrameRef::Unique` and `FrameRef::SharedWritable` untouched so
    /// true shared mappings remain coherent across all sharers.
    fn break_cow_page(
        &mut self,
        space: &NativeSpace<Tables>,
        base: u64,
        flags: PageFlags,
    ) -> Result<(), NativeError> {
        if !self.pages.frames.get(&base).is_some_and(FrameRef::is_cow) {
            return Ok(());
        }
        let FrameRef::Cow(shared) = self
            .pages
            .remove_frame_ref(base)
            .expect("checked CoW frame exists")
        else {
            unreachable!("checked is_cow above");
        };
        match Arc::try_unwrap(shared) {
            Ok(sole) => {
                // Sole surviving owner: upgrade back to `Unique` in place and
                // widen the hardware PTE (widening needs no shootdown).
                self.pages
                    .insert_frame_ref(base, FrameRef::Unique(sole.into_raw()));
                self.tables.protect(base, flags);
                Ok(())
            }
            Err(shared) => {
                let processor = helios_hal::cpu::current_processor();
                let Ok(new_frame) = allocate_user_frame_zeroed_on(processor) else {
                    self.pages.insert_frame_ref(base, FrameRef::Cow(shared));
                    return Err(NativeError::OutOfMemory);
                };
                // SAFETY: both `shared.as_ptr()` and `new_frame` are valid 4 KiB
                // direct-mapped user frames; `shared` is read-only in hardware
                // and remains alive until dropped below.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        shared.as_ptr().as_ptr(),
                        new_frame.as_ptr(),
                        PAGE as usize,
                    );
                }
                if flags.contains(PageFlags::EXECUTE) {
                    self.tables.sync_executable_frame(new_frame);
                }
                let old_phys = self.tables.physical(shared.as_ptr());
                let new_phys = self.tables.physical(new_frame);
                // Break-before-make (Arm ARM D8.14.1): uninstall the shared
                // translation and shoot down active slices before installing
                // the private physical frame.
                self.tables.uninstall(base);
                space.invalidate_if_active(&self.tables, base, base + PAGE);
                if let Err(error) = self.tables.install(base, new_phys, flags) {
                    let _ = self
                        .tables
                        .install(base, old_phys, hardware_flags(flags, true));
                    deallocate_user_frame_on(processor, new_frame);
                    self.pages.insert_frame_ref(base, FrameRef::Cow(shared));
                    return Err(error);
                }
                self.pages
                    .insert_frame_ref(base, FrameRef::Unique(new_frame));
                drop(shared);
                Ok(())
            }
        }
    }

    /// Gives every uncommitted page of `[first, last)` a frame with its mapped
    /// flags and breaks copy-on-write on any `FrameRef::Cow` page so a kernel
    /// write never mutates another space's private CoW frame (while preserving
    /// `FrameRef::SharedWritable` sharing). Refuses with [`NativeError::Swapped`]
    /// without mutating any page if any page in `[first, last)` is swapped out.
    fn ensure_writable_range(
        &mut self,
        space: &NativeSpace<Tables>,
        first: u64,
        last: u64,
    ) -> Result<(), NativeError> {
        if self.pages.first_swapped_in_span(first, last).is_some() {
            return Err(NativeError::Swapped);
        }
        for base in (first..last).step_by(PAGE as usize) {
            let (_, region) = self
                .pages
                .region_at(base)
                .expect("write checks every page is mapped first");
            if !self.pages.frames.contains_key(&base) {
                self.commit(base, region.flags, region.kind)?;
            } else {
                self.break_cow_page(space, base, region.flags)?;
            }
        }
        Ok(())
    }
}

fn page_span(range: VirtRange) -> Result<(u64, u64), NativeError> {
    if !range.is_page_aligned() || range.byte_len == 0 {
        return Err(NativeError::Address);
    }
    let first = range.start.raw() as u64;
    let last = first
        .checked_add(range.byte_len as u64)
        .ok_or(NativeError::Address)?;
    Ok((first, last))
}

// SAFETY: every user page maps a frame this space allocated, with the flags
// it was mapped with, through a translation that keeps `UserTranslation`'s
// contract; a frame leaves the space only after `complete` has shot down
// every translation of it.
unsafe impl<Tables: UserTranslation> UserSpace for NativeSpace<Tables> {
    fn map(&self, range: VirtRange, contents: &[u8], flags: PageFlags) -> Result<(), NativeError> {
        if contents.len() > range.byte_len {
            return Err(NativeError::Address);
        }
        let start = range.start.raw() as u64;
        let mut state = self.shared.state.lock();
        let (first, last) = state.pages.span(start, range.byte_len as u64)?;
        if state.pages.overlaps(first, last) {
            return Err(NativeError::Overlap);
        }
        if contents.is_empty() {
            state.pages.insert_region(first, last, flags);
            return Ok(());
        }
        let (_, contents_last) = state.pages.span(start, contents.len() as u64)?;
        if let Err(failed) = state.install(first, contents_last, flags) {
            self.complete(&state.tables, failed.removed);
            return Err(failed.error);
        }
        if contents_last < last {
            state.pages.insert_region(contents_last, last, flags);
        }
        state
            .pages
            .write(start, contents, PageFlags::empty())
            .expect("installed pages cover contents");
        if flags.contains(PageFlags::EXECUTE) {
            state.sync_executable_range(first, contents_last);
        }
        Ok(())
    }

    fn map_anywhere(
        &self,
        hint: VirtAddr,
        byte_len: usize,
        flags: PageFlags,
    ) -> Result<VirtRange, NativeError> {
        self.map_region_anywhere(hint, byte_len, flags, RegionKind::PrivateAnonymous)
    }

    fn read(&self, address: VirtAddr, output: &mut [u8]) -> Result<(), NativeError> {
        self.shared
            .state
            .lock()
            .pages
            .read(address.raw() as u64, output)
    }

    fn read_unrestricted(&self, address: VirtAddr, output: &mut [u8]) -> Result<(), NativeError> {
        self.shared.state.lock().pages.read_with_access(
            address.raw() as u64,
            output,
            PageFlags::empty(),
        )
    }

    fn check_writable(&self, address: VirtAddr, byte_len: usize) -> Result<(), NativeError> {
        self.shared
            .state
            .lock()
            .pages
            .check(address.raw() as u64, byte_len, PageFlags::WRITE)
    }

    fn write(&self, address: VirtAddr, bytes: &[u8]) -> Result<(), NativeError> {
        let address = address.raw() as u64;
        let mut state = self.shared.state.lock();
        state.pages.check(address, bytes.len(), PageFlags::WRITE)?;
        if bytes.is_empty() {
            return Ok(());
        }
        let (first, last) = state.pages.span(address, bytes.len() as u64)?;
        state.ensure_writable_range(self, first, last)?;
        state.pages.write(address, bytes, PageFlags::WRITE)?;
        state.sync_executable_range(first, last);
        Ok(())
    }

    fn populate(&self, address: VirtAddr, bytes: &[u8]) -> Result<(), NativeError> {
        let address = address.raw() as u64;
        let mut state = self.shared.state.lock();
        state
            .pages
            .check(address, bytes.len(), PageFlags::empty())?;
        if bytes.is_empty() {
            return Ok(());
        }
        let (first, last) = state.pages.span(address, bytes.len() as u64)?;
        state.ensure_writable_range(self, first, last)?;
        state.pages.write(address, bytes, PageFlags::empty())?;
        state.sync_executable_range(first, last);
        Ok(())
    }

    fn atomic_load_u32(&self, address: VirtAddr) -> Result<u32, NativeError> {
        let address = address.raw() as u64;
        if address & 3 != 0 {
            return Err(NativeError::Address);
        }
        let state = self.shared.state.lock();
        let (first, _) = state.pages.span(address, 4)?;
        let (_, region) = state.pages.region_at(first).ok_or(NativeError::NotMapped)?;
        if !region.flags.contains(PageFlags::READ) {
            return Err(NativeError::NotMapped);
        }
        let frame = match state.pages.frames.get(&first) {
            Some(FrameRef::Swapped(_)) => return Err(NativeError::Swapped),
            Some(frame_ref) => frame_ref
                .resident_ptr()
                .expect("non-swapped FrameRef carries a resident pointer"),
            None => return Ok(0),
        };
        let offset = (address - first) as usize;
        // SAFETY: `offset < PAGE`, so the offset stays within `first`'s 4 KiB frame.
        let ptr = unsafe { frame.as_ptr().add(offset) }.cast::<AtomicU32>();
        // SAFETY: `address` is 4-byte aligned and `frame` stays allocated while
        // `state` is locked.
        let word = unsafe { &*ptr };
        Ok(u32::from_le(word.load(Ordering::SeqCst)))
    }

    fn atomic_store_u32(&self, address: VirtAddr, value: u32) -> Result<(), NativeError> {
        let address = address.raw() as u64;
        if address & 3 != 0 {
            return Err(NativeError::Address);
        }
        let mut state = self.shared.state.lock();
        let (first, _) = state.pages.span(address, 4)?;
        let (_, region) = state.pages.region_at(first).ok_or(NativeError::NotMapped)?;
        if !region.flags.contains(PageFlags::WRITE) {
            return Err(NativeError::NotMapped);
        }
        match state.pages.frames.get(&first) {
            Some(FrameRef::Swapped(_)) => return Err(NativeError::Swapped),
            None => state.commit(first, region.flags, region.kind)?,
            Some(_) => state.break_cow_page(self, first, region.flags)?,
        }
        let frame = state
            .pages
            .get(first)
            .and_then(|page| page.frame)
            .expect("atomic store commits a discarded page first");
        let offset = (address - first) as usize;
        // SAFETY: `offset < PAGE`, so the offset stays within `first`'s 4 KiB frame.
        let ptr = unsafe { frame.as_ptr().add(offset) }.cast::<AtomicU32>();
        // SAFETY: `address` is 4-byte aligned and `frame` stays allocated while
        // `state` is locked.
        let word = unsafe { &*ptr };
        word.store(value.to_le(), Ordering::SeqCst);
        if region.flags.contains(PageFlags::EXECUTE) {
            state.tables.sync_executable_frame(frame);
        }
        Ok(())
    }

    fn atomic_compare_exchange_u32(
        &self,
        address: VirtAddr,
        expected: u32,
        desired: u32,
    ) -> Result<Result<u32, u32>, NativeError> {
        let address = address.raw() as u64;
        if address & 3 != 0 {
            return Err(NativeError::Address);
        }
        let mut state = self.shared.state.lock();
        let (first, _) = state.pages.span(address, 4)?;
        let (_, region) = state.pages.region_at(first).ok_or(NativeError::NotMapped)?;
        if !region.flags.contains(PageFlags::READ | PageFlags::WRITE) {
            return Err(NativeError::NotMapped);
        }
        match state.pages.frames.get(&first) {
            Some(FrameRef::Swapped(_)) => return Err(NativeError::Swapped),
            None => state.commit(first, region.flags, region.kind)?,
            Some(_) => state.break_cow_page(self, first, region.flags)?,
        }
        let frame = state
            .pages
            .get(first)
            .and_then(|page| page.frame)
            .expect("atomic compare-exchange commits a discarded page first");
        let offset = (address - first) as usize;
        // SAFETY: `offset < PAGE`, so the offset stays within `first`'s 4 KiB frame.
        let ptr = unsafe { frame.as_ptr().add(offset) }.cast::<AtomicU32>();
        // SAFETY: `address` is 4-byte aligned and `frame` stays allocated while
        // `state` is locked.
        let word = unsafe { &*ptr };
        let res = word
            .compare_exchange(
                expected.to_le(),
                desired.to_le(),
                Ordering::SeqCst,
                Ordering::SeqCst,
            )
            .map(u32::from_le)
            .map_err(u32::from_le);
        if res.is_ok() && region.flags.contains(PageFlags::EXECUTE) {
            state.tables.sync_executable_frame(frame);
        }
        Ok(res)
    }

    fn unmap(&self, range: VirtRange) -> Result<(), NativeError> {
        let (first, last) = page_span(range)?;
        let mut state = self.shared.state.lock();
        state.pages.span(first, last - first)?;
        let removed = state.take(first, last);
        self.complete(&state.tables, removed);
        Ok(())
    }

    fn protect(&self, range: VirtRange, flags: PageFlags) -> Result<(), NativeError> {
        let (first, last) = page_span(range)?;
        let mut state = self.shared.state.lock();
        state.pages.span(first, last - first)?;
        if !state.pages.covers(first, last) {
            return Err(NativeError::NotMapped);
        }
        let SpaceState { pages, tables } = &mut *state;
        let mut narrowed = Removed::new();
        pages.protect_range_with_sharing(first, last, flags, |base, frame, old_flags, is_cow| {
            let old_hw = hardware_flags(old_flags, is_cow);
            let new_hw = hardware_flags(flags, is_cow);
            if old_hw != new_hw {
                if new_hw.contains(PageFlags::EXECUTE) && !old_hw.contains(PageFlags::EXECUTE) {
                    tables.sync_executable_frame(frame);
                }
                tables.protect(base, new_hw);
                if !new_hw.contains(old_hw) {
                    narrowed.touch(base);
                }
            }
        });
        self.complete(&state.tables, narrowed);
        Ok(())
    }

    fn discard(&self, range: VirtRange) -> Result<(), NativeError> {
        let (first, last) = page_span(range)?;
        let mut state = self.shared.state.lock();
        state.pages.span(first, last - first)?;
        let SpaceState { pages, tables } = &mut *state;
        let mut removed = Removed::new();
        for (base, frame) in pages.discard_range_refs(first, last) {
            if let FrameRef::Swapped(token) = frame {
                pages.orphan_tokens.push(token);
                continue;
            }
            tables.uninstall(base);
            removed.touch(base);
            removed.frames.push(frame);
        }
        self.complete(&state.tables, removed);
        Ok(())
    }

    fn remap(&self, from: VirtRange, to: VirtRange) -> Result<(), NativeError> {
        let (from_first, from_last) = page_span(from)?;
        let (to_first, to_last) = page_span(to)?;
        if to.byte_len < from.byte_len {
            return Err(NativeError::Address);
        }
        if from_first < to_last && to_first < from_last {
            return Err(NativeError::Overlap);
        }
        let mut state = self.shared.state.lock();
        state.pages.span(from_first, from_last - from_first)?;
        state.pages.span(to_first, to_last - to_first)?;
        if state.pages.overlaps(to_first, to_last) {
            return Err(NativeError::Overlap);
        }
        let (flags, kind) = state
            .pages
            .uniform_with_kind(from_first, from_last)
            .ok_or(NativeError::NotMapped)?;
        // Each moved resident frame is reachable at both addresses until the
        // source goes, so a slice racing the move reaches one frame, never two.
        // Swapped-out pages carry no hardware PTE and move in `NativePages`
        // alone. The growth tail takes no frames until touched.
        let committed = state.pages.committed_in_with_cow(from_first, from_last);
        for (index, (base, ptr, is_cow)) in committed.iter().enumerate() {
            let target = to_first + (base - from_first);
            let physical = state.tables.physical(*ptr);
            let hw = hardware_flags(flags, *is_cow);
            if let Err(error) = state.tables.install(target, physical, hw) {
                // Unwind the destination. Its moved translations alias frames
                // the source still owns, so none are freed here.
                let mut unwound = Removed::new();
                for (base, _, _) in &committed[..index] {
                    let target = to_first + (base - from_first);
                    state.tables.uninstall(target);
                    unwound.touch(target);
                }
                self.complete(&state.tables, unwound);
                return Err(error);
            }
        }
        let SpaceState { pages, tables } = &mut *state;
        let mut source = Removed::new();
        let moved = pages.remove_range_refs(from_first, from_last);
        pages.insert_region_with_kind(to_first, to_last, flags, kind);
        for (base, frame) in moved {
            if !frame.is_swapped() {
                tables.uninstall(base);
                source.touch(base);
            }
            pages.insert_frame_ref(to_first + (base - from_first), frame);
        }
        self.complete(&state.tables, source);
        Ok(())
    }

    fn resolve_fault(&self, address: VirtAddr, access: PageFlags) -> Result<(), NativeError> {
        let base = address.page_floor().raw() as u64;
        let mut state = self.shared.state.lock();
        let (_, region) = state.pages.region_at(base).ok_or(NativeError::NotMapped)?;
        if !region.flags.contains(access) {
            return Err(NativeError::NotMapped);
        }
        match state.pages.frames.get(&base) {
            None => match region.kind {
                RegionKind::PrivateAnonymous => state.commit(base, region.flags, region.kind),
                RegionKind::PrivateFile | RegionKind::Shared => Err(NativeError::BackingFault),
            },
            Some(FrameRef::Swapped(_)) => Err(NativeError::Swapped),
            Some(FrameRef::Cow(_)) if access.contains(PageFlags::WRITE) => {
                state.break_cow_page(self, base, region.flags)
            }
            Some(FrameRef::Cow(_)) => {
                // Restore the hardware accessed flag (e.g. AArch64 Access Flag
                // fault after `test_and_clear_accessed`) while preserving CoW
                // read-only hardware permissions.
                state
                    .tables
                    .protect(base, hardware_flags(region.flags, true));
                Ok(())
            }
            Some(FrameRef::Unique(_) | FrameRef::SharedWritable(_)) => {
                // Re-publish current hardware permissions and accessed flag
                // (`AF` on AArch64, `ACCESSED` on x86-64) for access-flag
                // faults and stale-TLB retries.
                state.tables.protect(base, region.flags);
                Ok(())
            }
        }
    }

    fn mapping(&self, range: VirtRange) -> Option<Mapping> {
        let (first, last) = page_span(range)
            .unwrap_or_else(|_| panic!("a mapping query names a page-aligned range: {range:?}"));
        self.shared.state.lock().pages.first_run(first, last)
    }

    fn free_range(&self, hint: VirtAddr, byte_len: usize) -> Option<VirtAddr> {
        assert!(
            byte_len != 0 && (byte_len as u64).is_multiple_of(PAGE),
            "a free-range query names a nonzero page multiple, not {byte_len:#x} bytes"
        );
        self.shared
            .state
            .lock()
            .pages
            .free_range(hint.raw() as u64, byte_len as u64)
            .map(|start| VirtAddr::new(start as usize))
    }

    fn clone_cow(&self) -> Result<Self, NativeError> {
        let mut state = self.shared.state.lock();
        if state.pages.swapped_pages != 0 {
            return Err(NativeError::Swapped);
        }
        let mut child_tables = state.tables.new_empty()?;
        let mut child_pages = NativePages {
            regions: state.pages.regions.clone(),
            frames: BTreeMap::new(),
            orphan_tokens: Vec::new(),
            resident_pages: 0,
            swapped_pages: 0,
            age_cursor: 0,
            torn_down: false,
            start: state.pages.start,
            end: state.pages.end,
        };
        let mut narrowed = Removed::new();
        let SpaceState { pages, tables } = &mut *state;
        let keys: Vec<u64> = pages.frames.keys().copied().collect();
        for base in keys {
            let flags = pages
                .region_at(base)
                .expect("every committed frame lies inside a mapped region")
                .1
                .flags;
            let frame_ref = pages
                .frames
                .get_mut(&base)
                .expect("key came from pages.frames");
            let physical = tables.physical(
                frame_ref
                    .resident_ptr()
                    .expect("clone_cow checked swapped_pages == 0"),
            );
            let is_shared_writable = matches!(frame_ref, FrameRef::SharedWritable(_));
            let child_hw_flags = hardware_flags(flags, !is_shared_writable);
            if let Err(error) = child_tables.install(base, physical, child_hw_flags) {
                // Shoot down any parent pages already narrowed before dropping
                // `child_pages` (which decrements its `Arc<SharedFrame>` refs).
                self.complete(tables, narrowed);
                return Err(error);
            }
            let (child_ref, narrowed_parent) = frame_ref.clone_for_fork();
            child_pages.insert_frame_ref(base, child_ref);
            if narrowed_parent && flags.contains(PageFlags::WRITE) {
                tables.protect(base, child_hw_flags);
                narrowed.touch(base);
            }
        }
        // Shoot down every narrowed parent PTE before exposing the child space
        // so no sibling thread in the parent can write through a stale writable
        // TLB entry into a newly CoW-shared frame.
        self.complete(tables, narrowed);
        Ok(Self {
            shared: Box::new(Shared {
                state: Mutex::new(SpaceState {
                    pages: child_pages,
                    tables: child_tables,
                }),
                slices: CachePadded::new(AtomicUsize::new(0)),
            }),
        })
    }

    fn is_page_shared(&self, address: VirtAddr) -> bool {
        let base = address.page_floor().raw() as u64;
        self.shared
            .state
            .lock()
            .pages
            .frames
            .get(&base)
            .is_some_and(FrameRef::is_cow)
    }

    fn map_region(
        &self,
        range: VirtRange,
        flags: PageFlags,
        kind: RegionKind,
    ) -> Result<(), NativeError> {
        let (first, last) = page_span(range)?;
        let mut state = self.shared.state.lock();
        state.pages.span(first, last - first)?;
        if state.pages.overlaps(first, last) {
            return Err(NativeError::Overlap);
        }
        state
            .pages
            .insert_region_with_kind(first, last, flags, kind);
        Ok(())
    }

    fn map_region_anywhere(
        &self,
        hint: VirtAddr,
        byte_len: usize,
        flags: PageFlags,
        kind: RegionKind,
    ) -> Result<VirtRange, NativeError> {
        if byte_len == 0 || !(byte_len as u64).is_multiple_of(PAGE) {
            return Err(NativeError::Address);
        }
        let mut state = self.shared.state.lock();
        let start = state
            .pages
            .free_range(hint.raw() as u64, byte_len as u64)
            .ok_or(NativeError::OutOfMemory)?;
        state
            .pages
            .insert_region_with_kind(start, start + byte_len as u64, flags, kind);
        Ok(VirtRange::new(VirtAddr::new(start as usize), byte_len))
    }

    fn attach_shared_frame(
        &self,
        base: VirtAddr,
        frame: Arc<SharedFrame>,
    ) -> Result<(), NativeError> {
        let base = base.raw() as u64;
        if !base.is_multiple_of(PAGE) {
            return Err(NativeError::Address);
        }
        let mut state = self.shared.state.lock();
        let (_, region) = state.pages.region_at(base).ok_or(NativeError::NotMapped)?;
        let flags = region.flags;
        if let Some(existing) = state.pages.frames.get(&base)
            && existing.resident_ptr() == Some(frame.as_ptr())
            && matches!(existing, FrameRef::SharedWritable(_))
        {
            if flags.contains(PageFlags::EXECUTE) {
                state.tables.sync_executable_frame(frame.as_ptr());
            }
            return Ok(());
        }
        if flags.contains(PageFlags::EXECUTE) {
            state.tables.sync_executable_frame(frame.as_ptr());
        }
        let new_phys = state.tables.physical(frame.as_ptr());
        if let Some(old_ref) = state.pages.remove_frame_ref(base) {
            if let FrameRef::Swapped(token) = old_ref {
                if let Err(error) = state.tables.install(base, new_phys, flags) {
                    state.pages.insert_frame_ref(base, FrameRef::Swapped(token));
                    return Err(error);
                }
                state.pages.orphan_tokens.push(token);
                state
                    .pages
                    .insert_frame_ref(base, FrameRef::SharedWritable(frame));
                return Ok(());
            }
            let old_phys = state.tables.physical(
                old_ref
                    .resident_ptr()
                    .expect("non-swapped FrameRef carries a resident pointer"),
            );
            let old_is_cow = old_ref.is_cow();
            state.tables.uninstall(base);
            self.invalidate_if_active(&state.tables, base, base + PAGE);
            if let Err(error) = state.tables.install(base, new_phys, flags) {
                let _ = state
                    .tables
                    .install(base, old_phys, hardware_flags(flags, old_is_cow));
                state.pages.insert_frame_ref(base, old_ref);
                return Err(error);
            }
            state
                .pages
                .insert_frame_ref(base, FrameRef::SharedWritable(frame));
            old_ref.release(helios_hal::cpu::current_processor());
        } else {
            state.tables.install(base, new_phys, flags)?;
            state
                .pages
                .insert_frame_ref(base, FrameRef::SharedWritable(frame));
        }
        Ok(())
    }

    fn install_private_frame(&self, base: VirtAddr, frame: SharedFrame) -> Result<(), NativeError> {
        let base = base.raw() as u64;
        if !base.is_multiple_of(PAGE) {
            return Err(NativeError::Address);
        }
        let mut state = self.shared.state.lock();
        let (_, region) = state.pages.region_at(base).ok_or(NativeError::NotMapped)?;
        if state.pages.frames.contains_key(&base) {
            return Err(NativeError::Overlap);
        }
        let flags = region.flags;
        if flags.contains(PageFlags::EXECUTE) {
            state.tables.sync_executable_frame(frame.as_ptr());
        }
        let phys = state.tables.physical(frame.as_ptr());
        state.tables.install(base, phys, flags)?;
        state
            .pages
            .insert_frame_ref(base, FrameRef::Unique(frame.into_raw()));
        Ok(())
    }

    fn swapped_token(&self, base: VirtAddr) -> Option<SwapToken> {
        let base = base.page_floor().raw() as u64;
        self.shared
            .state
            .lock()
            .pages
            .frames
            .get(&base)
            .and_then(FrameRef::swapped_token)
    }

    fn first_swapped_in(&self, range: VirtRange) -> Option<VirtAddr> {
        if range.byte_len == 0 {
            return None;
        }
        let start = range.start.raw() as u64;
        let state = self.shared.state.lock();
        let Ok((first, last)) = state.pages.span(start, range.byte_len as u64) else {
            return None;
        };
        state
            .pages
            .first_swapped_in_span(first, last)
            .map(|base| VirtAddr::new(base as usize))
    }

    fn first_swapped_page(&self) -> Option<VirtAddr> {
        let state = self.shared.state.lock();
        if state.pages.swapped_pages == 0 {
            return None;
        }
        state
            .pages
            .frames
            .iter()
            .find_map(|(&base, frame)| frame.is_swapped().then_some(VirtAddr::new(base as usize)))
    }

    fn swapped_bytes(&self) -> u64 {
        self.shared.state.lock().pages.swapped_pages * PAGE
    }

    fn resident_bytes(&self) -> u64 {
        self.shared.state.lock().pages.resident_pages * PAGE
    }

    fn scan_private_pages_for_swap(
        &self,
        max_visits: usize,
        cold_only: bool,
        max_pages: usize,
        out: &mut Vec<VirtAddr>,
    ) -> usize {
        if max_visits == 0 || max_pages == 0 {
            return 0;
        }
        let mut state = self.shared.state.lock();
        if state.pages.torn_down || state.pages.resident_pages == 0 {
            return 0;
        }
        let start_cursor = state.pages.age_cursor;
        let mut unique_bases = Vec::new();
        for (&base, frame) in state.pages.frames.range(start_cursor..) {
            if matches!(frame, FrameRef::Unique(_)) {
                unique_bases.push(base);
                if unique_bases.len() >= max_visits {
                    break;
                }
            }
        }
        if unique_bases.len() < max_visits && start_cursor != 0 {
            for (&base, frame) in state.pages.frames.range(..start_cursor) {
                if matches!(frame, FrameRef::Unique(_)) {
                    unique_bases.push(base);
                    if unique_bases.len() >= max_visits {
                        break;
                    }
                }
            }
        }
        let initial_len = out.len();
        let mut visited = 0usize;
        let mut cleared_start = 0u64;
        let mut cleared_pages = 0usize;
        let mut last_base = None;
        for base in unique_bases {
            if out.len() - initial_len >= max_pages || visited >= max_visits {
                break;
            }
            visited += 1;
            last_base = Some(base);
            if cold_only {
                let accessed = state.tables.test_and_clear_accessed(base);
                if accessed {
                    let contiguous =
                        cleared_pages != 0 && base == cleared_start + (cleared_pages as u64) * PAGE;
                    if cleared_pages != 0 && !contiguous {
                        self.invalidate_if_active(
                            &state.tables,
                            cleared_start,
                            cleared_start + (cleared_pages as u64) * PAGE,
                        );
                        cleared_pages = 0;
                    }
                    if cleared_pages == 0 {
                        cleared_start = base;
                    }
                    cleared_pages += 1;
                    if cleared_pages == AGE_BATCH_PAGES {
                        self.invalidate_if_active(
                            &state.tables,
                            cleared_start,
                            cleared_start + (cleared_pages as u64) * PAGE,
                        );
                        cleared_pages = 0;
                    }
                } else {
                    out.push(VirtAddr::new(base as usize));
                }
            } else {
                out.push(VirtAddr::new(base as usize));
            }
        }
        if cleared_pages != 0 {
            self.invalidate_if_active(
                &state.tables,
                cleared_start,
                cleared_start + (cleared_pages as u64) * PAGE,
            );
        }
        state.pages.age_cursor = last_base.map_or(0, |base| base.saturating_add(PAGE));
        visited
    }

    fn swap_out_private_page(
        &self,
        base: VirtAddr,
        token: SwapToken,
        out: &mut [u8],
    ) -> Result<(), NativeError> {
        if !base.is_page_aligned() || out.len() != PhysFrame::SIZE {
            return Err(NativeError::Address);
        }
        let base = base.raw() as u64;
        let mut state = self.shared.state.lock();
        if state.pages.torn_down {
            return Err(NativeError::NotMapped);
        }
        // Only detach a page when no user slice is running on this space.
        fence(Ordering::SeqCst);
        if self.shared.slices.load(Ordering::SeqCst) != 0 {
            return Err(NativeError::Overlap);
        }
        if !matches!(state.pages.frames.get(&base), Some(FrameRef::Unique(_))) {
            return Err(NativeError::NotMapped);
        }
        let Some(FrameRef::Unique(frame)) = state
            .pages
            .replace_frame_ref(base, FrameRef::Swapped(token))
        else {
            unreachable!("checked Unique frame above");
        };
        // Unmap the hardware translation and complete any TLB shootdown before
        // copying the bytes and returning the frame to the user memory pool.
        state.tables.uninstall(base);
        self.invalidate_if_active(&state.tables, base, base + PAGE);
        // SAFETY: `frame` is an exclusively owned 4 KiB direct-mapped user
        // frame whose PTE was unmapped and shot down above; `out` is exactly
        // one page long and disjoint from the user pool.
        unsafe {
            core::ptr::copy_nonoverlapping(frame.as_ptr(), out.as_mut_ptr(), PhysFrame::SIZE);
        }
        deallocate_user_frame_on(helios_hal::cpu::current_processor(), frame);
        Ok(())
    }

    fn swap_in_private_page(&self, base: VirtAddr, bytes: &[u8]) -> Result<SwapToken, NativeError> {
        if !base.is_page_aligned() || bytes.len() != PhysFrame::SIZE {
            return Err(NativeError::Address);
        }
        let base = base.raw() as u64;
        let mut state = self.shared.state.lock();
        let (_, region) = state.pages.region_at(base).ok_or(NativeError::NotMapped)?;
        let Some(&FrameRef::Swapped(token)) = state.pages.frames.get(&base) else {
            return Err(NativeError::NotMapped);
        };
        let processor = helios_hal::cpu::current_processor();
        let frame =
            allocate_user_frame_uninit_on(processor).map_err(|_| NativeError::OutOfMemory)?;
        // SAFETY: `frame` is a newly allocated, exclusively owned 4 KiB user
        // frame and `bytes` is exactly one page long.
        unsafe {
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), frame.as_ptr(), PhysFrame::SIZE);
        }
        let flags = region.flags;
        if flags.contains(PageFlags::EXECUTE) {
            state.tables.sync_executable_frame(frame);
        }
        let phys = state.tables.physical(frame);
        if let Err(error) = state.tables.install(base, phys, flags) {
            deallocate_user_frame_on(processor, frame);
            return Err(error);
        }
        let replaced = state.pages.replace_frame_ref(base, FrameRef::Unique(frame));
        debug_assert!(matches!(replaced, Some(FrameRef::Swapped(prev)) if prev == token));
        Ok(token)
    }

    fn drain_orphan_swap_tokens(&self, out: &mut Vec<SwapToken>) {
        let mut state = self.shared.state.lock();
        out.append(&mut state.pages.orphan_tokens);
    }

    fn drain_all_swap_tokens_for_teardown(&self, out: &mut Vec<SwapToken>) {
        let mut state = self.shared.state.lock();
        state.pages.torn_down = true;
        out.append(&mut state.pages.orphan_tokens);
        if state.pages.swapped_pages == 0 {
            return;
        }
        let swapped_bases: Vec<u64> = state
            .pages
            .frames
            .iter()
            .filter_map(|(&base, frame)| frame.is_swapped().then_some(base))
            .collect();
        for base in swapped_bases {
            if let Some(FrameRef::Swapped(token)) = state.pages.remove_frame_ref(base) {
                out.push(token);
            }
        }
    }
}

impl<Tables> Drop for NativeSpace<Tables> {
    fn drop(&mut self) {
        // No slice outlives the borrow of this space, and every slice's exit
        // left no translation of it usable on its processor.
        let processor = helios_hal::cpu::current_processor();
        let pages = &mut self.shared.state.get_mut().pages;
        for frame in pages.drain_frame_refs() {
            match frame {
                FrameRef::Swapped(token) => pages.orphan_tokens.push(token),
                resident => resident.release(processor),
            }
        }
    }
}

/// A mapped user page: its frame's direct-map address, `None` when no
/// frame has been committed, and its access.
#[derive(Clone, Copy, Debug)]
pub struct NativePage {
    pub frame: Option<NonNull<u8>>,
    pub flags: PageFlags,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct MappedRegion {
    end: u64,
    flags: PageFlags,
    kind: RegionKind,
}

/// Every mapped page of one user address space: contiguous mapped ranges
/// with uniform access, and only the pages that currently hold a user frame
/// or a swap token.
pub struct NativePages {
    /// Non-overlapping, non-empty, page-aligned mapped ranges keyed by start
    /// address; adjacent ranges with identical `flags` are merged.
    regions: BTreeMap<u64, MappedRegion>,
    /// Committed backing frames or swap tokens keyed by page base inside `regions`.
    frames: BTreeMap<u64, FrameRef>,
    /// Tokens of swapped-out pages unmapped, discarded, or overwritten before
    /// fault-in, awaiting release by `SwapService`.
    orphan_tokens: Vec<SwapToken>,
    /// Count of resident frames (`Unique`, `Cow`, `SharedWritable`) in `frames`.
    resident_pages: u64,
    /// Count of swapped pages (`Swapped`) in `frames`.
    swapped_pages: u64,
    /// Next page base for round-robin hardware aging scans.
    age_cursor: u64,
    /// Set once teardown drains all swap tokens so concurrent eviction cannot
    /// detach new pages from a dying space.
    torn_down: bool,
    /// The lowest mappable address: page zero stays unmapped.
    start: u64,
    /// The end of the user range.
    end: u64,
}

// SAFETY: the index owns the frames it names; they are reached only through
// `&mut self` or under the owner's lock.
unsafe impl Send for NativePages {}
// SAFETY: as above; shared references only read the map.
unsafe impl Sync for NativePages {}

impl NativePages {
    pub fn new(start: u64, end: u64) -> Self {
        Self {
            regions: BTreeMap::new(),
            frames: BTreeMap::new(),
            orphan_tokens: Vec::new(),
            resident_pages: 0,
            swapped_pages: 0,
            age_cursor: 0,
            torn_down: false,
            start,
            end,
        }
    }

    fn first_swapped_in_span(&self, first: u64, last: u64) -> Option<u64> {
        if self.swapped_pages == 0 || first >= last {
            return None;
        }
        self.frames
            .range(first..last)
            .find_map(|(&base, frame)| frame.is_swapped().then_some(base))
    }

    /// The page-aligned span `[address, address + length)` touches, refused
    /// when it is empty, wraps, or leaves the user range.
    pub fn span(&self, address: u64, length: u64) -> Result<(u64, u64), NativeError> {
        let end = address.checked_add(length).ok_or(NativeError::Address)?;
        if length == 0 || address < self.start || end > self.end {
            return Err(NativeError::Address);
        }
        Ok((address & !(PAGE - 1), end.next_multiple_of(PAGE)))
    }

    fn region_at(&self, base: u64) -> Option<(u64, MappedRegion)> {
        let (&start, &region) = self.regions.range(..=base).next_back()?;
        (base < region.end).then_some((start, region))
    }

    pub fn overlaps(&self, first: u64, last: u64) -> bool {
        if first >= last {
            return false;
        }
        self.regions
            .range(..last)
            .next_back()
            .is_some_and(|(_, region)| region.end > first)
    }

    /// Whether every page of the page span `[first, last)` is mapped.
    pub fn covers(&self, first: u64, last: u64) -> bool {
        if first >= last {
            return true;
        }
        let Some((_, region)) = self.region_at(first) else {
            return false;
        };
        if region.end >= last {
            return true;
        }
        let mut cursor = region.end;
        for (&start, &region) in self.regions.range(cursor..last) {
            if start != cursor {
                return false;
            }
            if region.end >= last {
                return true;
            }
            cursor = region.end;
        }
        false
    }

    /// The access every page of `[first, last)` is mapped with, `None` when
    /// a page is not mapped or two differ.
    pub fn uniform(&self, first: u64, last: u64) -> Option<PageFlags> {
        self.uniform_with_kind(first, last).map(|(flags, _)| flags)
    }

    fn uniform_with_kind(&self, first: u64, last: u64) -> Option<(PageFlags, RegionKind)> {
        if first >= last {
            return None;
        }
        let (_, region) = self.region_at(first)?;
        (region.end >= last).then_some((region.flags, region.kind))
    }

    /// The first run of `[first, last)` mapped contiguously with one access.
    pub fn first_run(&self, first: u64, last: u64) -> Option<Mapping> {
        if first >= last {
            return None;
        }
        let (start, region) = self.region_at(first).or_else(|| {
            self.regions
                .range(first..last)
                .next()
                .map(|(&s, &r)| (s, r))
        })?;
        let clipped_start = start.max(first);
        let mut clipped_end = region.end.min(last);
        // Adjacent regions with identical `flags` but distinct `RegionKind`
        // still form one logical access run for `UserSpace::mapping`.
        while clipped_end < last {
            let Some(&next) = self.regions.get(&clipped_end) else {
                break;
            };
            if next.flags != region.flags {
                break;
            }
            clipped_end = next.end.min(last);
        }
        Some(Mapping {
            range: VirtRange::new(
                VirtAddr::new(clipped_start as usize),
                (clipped_end - clipped_start) as usize,
            ),
            flags: region.flags,
        })
    }

    pub fn get(&self, base: u64) -> Option<NativePage> {
        let (_, region) = self.region_at(base)?;
        Some(NativePage {
            frame: self.frames.get(&base).and_then(FrameRef::resident_ptr),
            flags: region.flags,
        })
    }

    /// Inserts an unmapped contiguous page-aligned range `[first, last)` as a
    /// private anonymous region, coalescing with adjacent neighbors that carry
    /// the same `flags` and `kind`.
    pub fn insert_region(&mut self, first: u64, last: u64, flags: PageFlags) {
        self.insert_region_with_kind(first, last, flags, RegionKind::PrivateAnonymous);
    }

    fn insert_region_with_kind(
        &mut self,
        mut first: u64,
        mut last: u64,
        flags: PageFlags,
        kind: RegionKind,
    ) {
        assert!(first < last && first.is_multiple_of(PAGE) && last.is_multiple_of(PAGE));
        if let Some((&left_start, &left)) = self.regions.range(..first).next_back()
            && left.end == first
            && left.flags == flags
            && left.kind == kind
        {
            self.regions.remove(&left_start);
            first = left_start;
        }
        if let Some(&right) = self.regions.get(&last)
            && right.flags == flags
            && right.kind == kind
        {
            self.regions.remove(&last);
            last = right.end;
        }
        let previous = self.regions.insert(
            first,
            MappedRegion {
                end: last,
                flags,
                kind,
            },
        );
        assert!(
            previous.is_none(),
            "user range {first:#x}..{last:#x} mapped twice"
        );
    }

    pub fn insert_frame(&mut self, base: u64, frame: NonNull<u8>) {
        self.insert_frame_ref(base, FrameRef::Unique(frame));
    }

    fn insert_frame_ref(&mut self, base: u64, frame: FrameRef) {
        let is_swapped = frame.is_swapped();
        let previous = self.frames.insert(base, frame);
        assert!(previous.is_none(), "user page {base:#x} framed twice");
        if is_swapped {
            self.swapped_pages += 1;
        } else {
            self.resident_pages += 1;
        }
    }

    fn remove_frame_ref(&mut self, base: u64) -> Option<FrameRef> {
        let removed = self.frames.remove(&base)?;
        if removed.is_swapped() {
            self.swapped_pages -= 1;
        } else {
            self.resident_pages -= 1;
        }
        Some(removed)
    }

    fn replace_frame_ref(&mut self, base: u64, frame: FrameRef) -> Option<FrameRef> {
        let new_swapped = frame.is_swapped();
        let previous = self.frames.insert(base, frame);
        if let Some(ref prev) = previous {
            if prev.is_swapped() {
                self.swapped_pages -= 1;
            } else {
                self.resident_pages -= 1;
            }
        }
        if new_swapped {
            self.swapped_pages += 1;
        } else {
            self.resident_pages += 1;
        }
        previous
    }

    pub fn insert(&mut self, base: u64, page: NativePage) {
        assert!(
            !self.overlaps(base, base + PAGE),
            "user page {base:#x} mapped twice"
        );
        self.insert_region(base, base + PAGE, page.flags);
        if let Some(frame) = page.frame {
            self.insert_frame(base, frame);
        }
    }

    /// Gives uncommitted page `base` the frame `frame`.
    pub fn commit(&mut self, base: u64, frame: NonNull<u8>) {
        assert!(
            self.region_at(base).is_some(),
            "committing unmapped user page {base:#x}"
        );
        self.insert_frame_ref(base, FrameRef::Unique(frame));
    }

    fn split_at(&mut self, boundary: u64) {
        let Some((start, region)) = self.region_at(boundary) else {
            return;
        };
        if start < boundary {
            self.regions.get_mut(&start).expect("region exists").end = boundary;
            self.regions.insert(
                boundary,
                MappedRegion {
                    end: region.end,
                    flags: region.flags,
                    kind: region.kind,
                },
            );
        }
    }

    fn drain_frames_in_range(&mut self, first: u64, last: u64) -> Vec<(u64, FrameRef)> {
        let mut tail = self.frames.split_off(&first);
        let mut rest = tail.split_off(&last);
        self.frames.append(&mut rest);
        let removed: Vec<(u64, FrameRef)> = tail.into_iter().collect();
        for (_, frame) in &removed {
            if frame.is_swapped() {
                self.swapped_pages -= 1;
            } else {
                self.resident_pages -= 1;
            }
        }
        removed
    }

    /// Replaces the access of `[first, last)` (which must be covered) with
    /// `flags`, invoking `on_committed(base, old_flags)` for each committed
    /// frame whose region's access changed.
    pub fn protect_range(
        &mut self,
        first: u64,
        last: u64,
        flags: PageFlags,
        mut on_committed: impl FnMut(u64, PageFlags),
    ) {
        self.protect_range_with_sharing(first, last, flags, |base, _, old_flags, _| {
            on_committed(base, old_flags);
        });
    }

    fn protect_range_with_sharing(
        &mut self,
        first: u64,
        last: u64,
        flags: PageFlags,
        mut on_committed: impl FnMut(u64, NonNull<u8>, PageFlags, bool),
    ) {
        if first >= last {
            return;
        }
        self.split_at(first);
        self.split_at(last);
        let keys: Vec<(u64, MappedRegion)> = self
            .regions
            .range(first..last)
            .map(|(&start, &region)| (start, region))
            .collect();
        for (start, region) in &keys {
            if region.flags != flags {
                for (&base, frame) in self.frames.range(*start..region.end) {
                    if let Some(ptr) = frame.resident_ptr() {
                        on_committed(base, ptr, region.flags, frame.is_cow());
                    }
                }
            }
            self.regions.remove(start);
        }
        for (start, region) in keys {
            self.insert_region_with_kind(start, region.end, flags, region.kind);
        }
    }

    /// Drops the backing frames of `[first, last)` while keeping the mapped
    /// ranges and their access intact, returning the `(base, frame)` pairs
    /// removed.
    pub fn discard_range(&mut self, first: u64, last: u64) -> Vec<(u64, NonNull<u8>)> {
        self.discard_range_refs(first, last)
            .into_iter()
            .filter_map(|(base, frame)| frame.resident_ptr().map(|ptr| (base, ptr)))
            .collect()
    }

    fn discard_range_refs(&mut self, first: u64, last: u64) -> Vec<(u64, FrameRef)> {
        if first >= last {
            return Vec::new();
        }
        self.drain_frames_in_range(first, last)
    }

    pub fn committed_in(&self, first: u64, last: u64) -> Vec<(u64, NonNull<u8>)> {
        self.frames
            .range(first..last)
            .filter_map(|(&base, frame)| frame.resident_ptr().map(|ptr| (base, ptr)))
            .collect()
    }

    fn committed_in_with_cow(&self, first: u64, last: u64) -> Vec<(u64, NonNull<u8>, bool)> {
        self.frames
            .range(first..last)
            .filter_map(|(&base, frame)| {
                frame.resident_ptr().map(|ptr| (base, ptr, frame.is_cow()))
            })
            .collect()
    }

    /// Takes every page of `[first, last)` out of the index, returning the
    /// committed `(base, frame)` pairs that were mapped there.
    pub fn remove_range(&mut self, first: u64, last: u64) -> Vec<(u64, NonNull<u8>)> {
        self.remove_range_refs(first, last)
            .into_iter()
            .filter_map(|(base, frame)| frame.resident_ptr().map(|ptr| (base, ptr)))
            .collect()
    }

    fn remove_range_refs(&mut self, first: u64, last: u64) -> Vec<(u64, FrameRef)> {
        if first >= last {
            return Vec::new();
        }
        self.split_at(first);
        self.split_at(last);
        let keys: Vec<u64> = self.regions.range(first..last).map(|(&s, _)| s).collect();
        for key in keys {
            self.regions.remove(&key);
        }
        self.drain_frames_in_range(first, last)
    }

    /// Takes every committed frame out of the index.
    pub fn drain_frames(&mut self) -> impl Iterator<Item = NonNull<u8>> {
        self.drain_frame_refs()
            .filter_map(|frame| frame.resident_ptr())
    }

    fn drain_frame_refs(&mut self) -> impl Iterator<Item = FrameRef> + use<> {
        self.regions.clear();
        self.resident_pages = 0;
        self.swapped_pages = 0;
        core::mem::take(&mut self.frames).into_values()
    }

    /// The first free page-aligned range of `length` bytes at or above
    /// `hint`, else at or above the start of the user range.
    pub fn free_range(&self, hint: u64, length: u64) -> Option<u64> {
        self.find(hint, length)
            .or_else(|| self.find(self.start, length))
    }

    fn find(&self, from: u64, length: u64) -> Option<u64> {
        let mut candidate = (from & !(PAGE - 1)).max(self.start);
        if let Some((_, region)) = self.region_at(candidate) {
            candidate = region.end;
        }
        loop {
            let end = candidate
                .checked_add(length)
                .filter(|end| *end <= self.end)?;
            match self.regions.range(candidate..end).next() {
                Some((_, region)) => candidate = region.end,
                None => return Some(candidate),
            }
        }
    }

    /// Whether every page `[address, address + length)` touches is mapped
    /// with `access`.
    pub fn check(&self, address: u64, length: usize, access: PageFlags) -> Result<(), NativeError> {
        if length == 0 {
            return Ok(());
        }
        let (first, last) = self.span(address, length as u64)?;
        let Some((_, region)) = self.region_at(first) else {
            return Err(NativeError::NotMapped);
        };
        if !region.flags.contains(access) {
            return Err(NativeError::NotMapped);
        }
        if region.end >= last {
            return Ok(());
        }
        let mut cursor = region.end;
        for (&start, &region) in self.regions.range(cursor..last) {
            if start != cursor || !region.flags.contains(access) {
                return Err(NativeError::NotMapped);
            }
            if region.end >= last {
                return Ok(());
            }
            cursor = region.end;
        }
        Err(NativeError::NotMapped)
    }

    /// Visits `[address, address + length)` as runs of physically adjacent
    /// frames, after checking that every page is mapped with `access`:
    /// `visit(run, bytes, offset)` receives the run's bytes through the
    /// direct map, or `None` for a run of uncommitted pages, and the run's
    /// offset within the range. Nothing is visited when any page fails the
    /// check.
    pub fn runs(
        &self,
        address: u64,
        length: usize,
        access: PageFlags,
        mut visit: impl FnMut(Option<NonNull<u8>>, usize, usize),
    ) -> Result<(), NativeError> {
        self.check(address, length, access)?;
        if length == 0 {
            return Ok(());
        }
        let (first, last) = self.span(address, length as u64)?;
        if self.first_swapped_in_span(first, last).is_some() {
            return Err(NativeError::Swapped);
        }
        let end_addr = address + length as u64;
        let mut done = 0usize;
        let mut run: Option<(Option<NonNull<u8>>, usize)> = None;
        let mut emit = |start: Option<NonNull<u8>>, bytes: usize| {
            run = match (run.take(), start) {
                (Some((Some(head), prev)), Some(next))
                    if head.as_ptr().wrapping_add(prev) == next.as_ptr() =>
                {
                    Some((Some(head), prev + bytes))
                }
                (Some((None, prev)), None) => Some((None, prev + bytes)),
                (Some((head, prev)), next) => {
                    visit(head, prev, done);
                    done += prev;
                    Some((next, bytes))
                }
                (None, next) => Some((next, bytes)),
            };
        };

        let mut cursor = first;
        for (&base, frame) in self.frames.range(first..last) {
            if cursor < base {
                let gap = (base.min(end_addr) - cursor.max(address)) as usize;
                emit(None, gap);
            }
            let skip = address.saturating_sub(base) as usize;
            let take = ((base + PAGE).min(end_addr) - base.max(address)) as usize;
            let ptr = frame
                .resident_ptr()
                .expect("runs checked no swapped pages in span");
            // SAFETY: `skip < PAGE`, so `ptr.add(skip)` stays inside this page's frame.
            let start = unsafe { ptr.add(skip) };
            emit(Some(start), take);
            cursor = base + PAGE;
        }
        if cursor < last {
            let tail = (last.min(end_addr) - cursor.max(address)) as usize;
            emit(None, tail);
        }
        if let Some((head, bytes)) = run {
            visit(head, bytes, done);
        }
        Ok(())
    }

    /// Copies `output.len()` readable bytes from `address`; a discarded page
    /// reads as zeros.
    pub fn read(&self, address: u64, output: &mut [u8]) -> Result<(), NativeError> {
        self.read_with_access(address, output, PageFlags::READ)
    }

    /// Copies `output.len()` bytes from mapped pages at `address` requiring
    /// `access` (pass [`PageFlags::empty()`] to read `PROT_NONE` pages through
    /// the kernel direct map).
    pub fn read_with_access(
        &self,
        address: u64,
        output: &mut [u8],
        access: PageFlags,
    ) -> Result<(), NativeError> {
        let length = output.len();
        self.runs(address, length, access, |run, bytes, offset| {
            let target = &mut output[offset..offset + bytes];
            match run {
                Some(run) => {
                    // SAFETY: the run lies inside frames this index owns, which
                    // stay allocated while the owner's lock is held.
                    let src = unsafe { core::slice::from_raw_parts(run.as_ptr(), bytes) };
                    target.copy_from_slice(src);
                }
                None => target.fill(0),
            }
        })
    }

    /// Copies `bytes` to `address`, every page of which must be writable
    /// and committed; `access` is the access the copy requires, empty for
    /// the initial contents a fresh mapping receives.
    pub fn write(
        &mut self,
        address: u64,
        bytes: &[u8],
        access: PageFlags,
    ) -> Result<(), NativeError> {
        self.runs(address, bytes.len(), access, |run, length, offset| {
            let run = run.expect("a write commits every discarded page first");
            // SAFETY: `self` is borrowed mutably and the run lies inside frames
            // this index owns exclusively for the call.
            let target = unsafe { core::slice::from_raw_parts_mut(run.as_ptr(), length) };
            target.copy_from_slice(&bytes[offset..offset + length]);
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::boxed::Box;
    use alloc::vec;

    #[repr(C, align(4096))]
    struct Frames([u8; 4 * PAGE as usize]);

    fn frame(frames: &mut Frames, index: usize) -> NonNull<u8> {
        NonNull::new(frames.0[index * PAGE as usize..].as_mut_ptr()).unwrap()
    }

    fn page(frame: NonNull<u8>, flags: PageFlags) -> NativePage {
        NativePage {
            frame: Some(frame),
            flags,
        }
    }

    #[test]
    fn copies_cross_pages_in_one_run_per_adjacent_frame_group() {
        let mut frames = Box::new(Frames([0; 4 * PAGE as usize]));
        let mut pages = NativePages::new(PAGE, 1 << 47);
        let rw = PageFlags::READ | PageFlags::WRITE;
        // Pages 0x10000 and 0x11000 are frames 0 and 1, adjacent; 0x12000
        // is frame 3, apart from them.
        pages.insert(0x10000, page(frame(&mut frames, 0), rw));
        pages.insert(0x11000, page(frame(&mut frames, 1), rw));
        pages.insert(0x12000, page(frame(&mut frames, 3), rw));
        // 27 bytes a repeat, so 500 cover the three pages.
        let text = "中文 日本語 한국어 ".repeat(500).into_bytes();
        let start = 0x10000 + 100;
        let length = 3 * PAGE as usize - 200;
        let mut runs = Vec::new();
        pages
            .runs(start, length, PageFlags::WRITE, |_, bytes, offset| {
                runs.push((offset, bytes))
            })
            .unwrap();
        assert_eq!(
            runs,
            vec![
                (0, 2 * PAGE as usize - 100),
                (2 * PAGE as usize - 100, PAGE as usize - 100)
            ]
        );
        pages
            .write(start, &text[..length], PageFlags::WRITE)
            .unwrap();
        let mut back = vec![0; length];
        pages.read(start, &mut back).unwrap();
        assert_eq!(back, &text[..length]);
        assert_eq!(
            &frames.0[3 * PAGE as usize..3 * PAGE as usize + 10],
            &text[2 * PAGE as usize - 100..2 * PAGE as usize - 90]
        );
    }

    #[test]
    fn a_gap_or_a_missing_access_refuses_the_whole_copy() {
        let mut frames = Box::new(Frames([0; 4 * PAGE as usize]));
        let mut pages = NativePages::new(PAGE, 1 << 47);
        pages.insert(
            0x10000,
            page(frame(&mut frames, 0), PageFlags::READ | PageFlags::WRITE),
        );
        pages.insert(
            0x12000,
            page(frame(&mut frames, 1), PageFlags::READ | PageFlags::WRITE),
        );
        pages.insert(0x13000, page(frame(&mut frames, 2), PageFlags::READ));
        assert_eq!(
            pages.write(0x10ff0, &[1; 32], PageFlags::WRITE),
            Err(NativeError::NotMapped)
        );
        assert_eq!(
            pages.write(0x12ff0, &[1; 32], PageFlags::WRITE),
            Err(NativeError::NotMapped)
        );
        assert!(frames.0.iter().all(|byte| *byte == 0));
        assert_eq!(pages.read(0, &mut [0; 1]), Err(NativeError::Address));
        assert_eq!(pages.read(u64::MAX, &mut [0; 2]), Err(NativeError::Address));
    }

    #[test]
    fn free_ranges_skip_mapped_pages_and_fall_back_below_the_hint() {
        let mut frames = Box::new(Frames([0; 4 * PAGE as usize]));
        let mut pages = NativePages::new(PAGE, 0x20000);
        pages.insert(0x10000, page(frame(&mut frames, 0), PageFlags::READ));
        assert_eq!(pages.free_range(0x10000, 2 * PAGE), Some(0x11000));
        assert_eq!(pages.free_range(0x1f000, 2 * PAGE), Some(PAGE));
        assert_eq!(pages.free_range(0, 0x20000), None);
    }

    #[test]
    fn discarded_pages_read_as_zeros_between_committed_runs() {
        let mut frames = Box::new(Frames([0; 4 * PAGE as usize]));
        frames.0.fill(0x5a);
        let mut pages = NativePages::new(PAGE, 1 << 47);
        let rw = PageFlags::READ | PageFlags::WRITE;
        pages.insert(0x10000, page(frame(&mut frames, 0), rw));
        pages.insert(
            0x11000,
            NativePage {
                frame: None,
                flags: rw,
            },
        );
        pages.insert(0x12000, page(frame(&mut frames, 2), rw));
        let mut runs = Vec::new();
        pages
            .runs(
                0x10000,
                3 * PAGE as usize,
                PageFlags::READ,
                |run, bytes, offset| runs.push((run.is_some(), offset, bytes)),
            )
            .unwrap();
        let page = PAGE as usize;
        assert_eq!(
            runs,
            vec![(true, 0, page), (false, page, page), (true, 2 * page, page)]
        );
        let mut back = vec![1; 3 * page];
        pages.read(0x10000, &mut back).unwrap();
        assert!(back[..page].iter().all(|byte| *byte == 0x5a));
        assert!(back[page..2 * page].iter().all(|byte| *byte == 0));
        assert!(back[2 * page..].iter().all(|byte| *byte == 0x5a));
    }

    #[test]
    fn runs_report_the_first_uniform_stretch_and_ranges_split_cleanly() {
        let mut frames = Box::new(Frames([0; 4 * PAGE as usize]));
        let mut pages = NativePages::new(PAGE, 1 << 47);
        let rw = PageFlags::READ | PageFlags::WRITE;
        pages.insert(0x10000, page(frame(&mut frames, 0), rw));
        pages.insert(0x11000, page(frame(&mut frames, 1), rw));
        pages.insert(0x12000, page(frame(&mut frames, 2), PageFlags::READ));
        pages.insert(0x14000, page(frame(&mut frames, 3), PageFlags::READ));
        let run = |first, last| {
            pages
                .first_run(first, last)
                .map(|run| (run.range, run.flags))
        };
        let range = |start: usize, count: usize| {
            VirtRange::new(VirtAddr::new(start), count * PAGE as usize)
        };
        assert_eq!(run(0xf000, 0x15000), Some((range(0x10000, 2), rw)));
        assert_eq!(run(0x11000, 0x15000), Some((range(0x11000, 1), rw)));
        assert_eq!(
            run(0x12000, 0x15000),
            Some((range(0x12000, 1), PageFlags::READ))
        );
        assert_eq!(run(0x13000, 0x14000), None);
        assert_eq!(pages.uniform(0x10000, 0x12000), Some(rw));
        assert_eq!(pages.uniform(0x10000, 0x13000), None);
        assert_eq!(pages.uniform(0x12000, 0x15000), None);
        assert!(pages.covers(0x10000, 0x13000) && !pages.covers(0x10000, 0x14000));
        let taken: Vec<u64> = pages
            .remove_range(0x11000, 0x14000)
            .into_iter()
            .map(|(base, _)| base)
            .collect();
        assert_eq!(taken, vec![0x11000, 0x12000]);
        assert!(pages.get(0x10000).is_some() && pages.get(0x14000).is_some());
        assert!(!pages.overlaps(0x11000, 0x14000));
    }

    struct ShootdownLog {
        events: Mutex<Vec<(u64, u64, usize)>>,
    }

    // SAFETY: test model records invalidations and checks that removed frames
    // are still allocated when `invalidate` runs.
    unsafe impl UserTranslation for alloc::sync::Arc<ShootdownLog> {
        fn install(&mut self, _: u64, _: u64, _: PageFlags) -> Result<(), NativeError> {
            Ok(())
        }

        fn uninstall(&mut self, _: u64) {}

        fn protect(&mut self, _: u64, _: PageFlags) {}

        fn invalidate(&self, first: u64, last: u64) {
            self.events.lock().push((
                first,
                last,
                crate::memory::user_heap_stats().allocated_bytes,
            ));
        }

        fn physical(&self, frame: NonNull<u8>) -> u64 {
            frame.as_ptr() as u64
        }

        fn new_empty(&self) -> Result<Self, NativeError> {
            Ok(alloc::sync::Arc::new(ShootdownLog {
                events: Mutex::new(Vec::new()),
            }))
        }
    }

    fn ensure_pool() {
        const POOL_BYTES: usize = 4 * 1024 * 1024;
        if crate::memory::installed_user_memory_pool().is_some() {
            return;
        }
        let layout =
            alloc::alloc::Layout::from_size_align(POOL_BYTES, PAGE as usize).expect("pool layout");
        // SAFETY: nonzero size, leaked for the process lifetime of the test pool.
        let base = unsafe { alloc::alloc::alloc_zeroed(layout) } as usize;
        assert!(base != 0, "pool backing");
        crate::memory::install_user_memory_pool(crate::memory::UserMemoryPool::single_node(
            1,
            &[(base, base + POOL_BYTES)],
        ));
    }

    #[test]
    fn shootdown_runs_when_slices_are_active_and_before_frames_reclaim() {
        ensure_pool();
        let log = alloc::sync::Arc::new(ShootdownLog {
            events: Mutex::new(Vec::new()),
        });
        let space = NativeSpace::new(log.clone(), PAGE, 1 << 47);
        let rw = PageFlags::READ | PageFlags::WRITE;
        let range = |start: usize, pages: usize| {
            VirtRange::new(VirtAddr::new(start), pages * PAGE as usize)
        };

        // Without a running slice, removals skip remote invalidation.
        space.map(range(0x10000, 1), b"solo", rw).unwrap();
        space.unmap(range(0x10000, 1)).unwrap();
        assert!(log.events.lock().is_empty());

        // With a sibling slice running, map and widening protect need no
        // shootdown, while narrowing protect, discard, remap and unmap shoot
        // down before freeing removed frames.
        let slice = space.begin_slice();
        space
            .map(range(0x20000, 2), b"shared", PageFlags::READ)
            .unwrap();
        space.protect(range(0x20000, 2), rw).unwrap();
        assert!(log.events.lock().is_empty());

        space.protect(range(0x20000, 1), PageFlags::READ).unwrap();
        assert_eq!(log.events.lock().len(), 1);
        assert_eq!(log.events.lock()[0].0, 0x20000);
        assert_eq!(log.events.lock()[0].1, 0x21000);

        // Commit the trailing page first so `discard` has a frame to shoot
        // down and free.
        space
            .resolve_fault(VirtAddr::new(0x21000), PageFlags::WRITE)
            .unwrap();
        let before_discard = crate::memory::user_heap_stats().allocated_bytes;
        space.discard(range(0x21000, 1)).unwrap();
        let after_discard = crate::memory::user_heap_stats().allocated_bytes;
        let (_, _, during_discard) = *log.events.lock().last().unwrap();
        assert_eq!(during_discard, before_discard);
        assert!(after_discard < before_discard);

        // Atomic 32-bit operations read zeros from discarded pages, commit on
        // write/CAS, and enforce alignment and access flags.
        assert_eq!(space.atomic_load_u32(VirtAddr::new(0x21000)), Ok(0));
        assert_eq!(
            space.atomic_load_u32(VirtAddr::new(0x21002)),
            Err(NativeError::Address)
        );
        assert_eq!(
            space.atomic_store_u32(VirtAddr::new(0x20000), 9),
            Err(NativeError::NotMapped)
        );
        assert_eq!(
            space.atomic_compare_exchange_u32(VirtAddr::new(0x21004), 0, 0x1234_5678),
            Ok(Ok(0))
        );
        assert_eq!(
            space.atomic_load_u32(VirtAddr::new(0x21004)),
            Ok(0x1234_5678)
        );
        assert_eq!(
            space.atomic_compare_exchange_u32(VirtAddr::new(0x21004), 0, 7),
            Ok(Err(0x1234_5678))
        );

        space.protect(range(0x20000, 2), rw).unwrap();
        space.remap(range(0x20000, 2), range(0x30000, 2)).unwrap();
        assert_eq!(log.events.lock().last().unwrap().0, 0x20000);
        assert_eq!(log.events.lock().last().unwrap().1, 0x22000);

        let before_unmap = crate::memory::user_heap_stats().allocated_bytes;
        space.unmap(range(0x30000, 2)).unwrap();
        let after_unmap = crate::memory::user_heap_stats().allocated_bytes;
        let (first, last, during_unmap) = *log.events.lock().last().unwrap();
        assert_eq!((first, last), (0x30000, 0x32000));
        assert_eq!(during_unmap, before_unmap);
        assert!(after_unmap < before_unmap);

        drop(slice);
    }

    #[test]
    fn large_reservations_merge_split_and_skip_uncommitted_scans() {
        let mut pages = NativePages::new(PAGE, 1 << 47);
        let rw = PageFlags::READ | PageFlags::WRITE;
        let rwx = rw | PageFlags::EXECUTE;
        let gib = 1024 * 1024 * 1024;
        // A 4 GiB reservation takes one region entry and zero frames.
        pages.insert_region(gib, 5 * gib, rw);
        assert_eq!(pages.regions.len(), 1);
        assert!(pages.frames.is_empty());
        assert_eq!(pages.free_range(gib, PAGE), Some(5 * gib));

        // Splitting with different flags produces three regions; restoring
        // the original flags coalesces them back into one.
        let mut touched = Vec::new();
        pages.protect_range(2 * gib, 2 * gib + 2 * PAGE, rwx, |b, f| {
            touched.push((b, f));
        });
        assert!(touched.is_empty());
        assert_eq!(pages.regions.len(), 3);
        assert_eq!(pages.uniform(2 * gib, 2 * gib + 2 * PAGE), Some(rwx));
        pages.protect_range(2 * gib, 2 * gib + 2 * PAGE, rw, |_, _| {});
        assert_eq!(pages.regions.len(), 1);

        // Removing a hole inside the 4 GiB reservation splits into two regions.
        assert!(pages.remove_range(3 * gib, 3 * gib + 0x1_0000).is_empty());
        assert_eq!(pages.regions.len(), 2);
        assert_eq!(pages.free_range(2 * gib, 0x1_0000), Some(3 * gib));
    }

    struct InstallLog(alloc::sync::Arc<Mutex<Vec<u64>>>);

    // SAFETY: host test counts `install` calls and never runs hardware slices.
    unsafe impl UserTranslation for InstallLog {
        fn install(&mut self, base: u64, _: u64, _: PageFlags) -> Result<(), NativeError> {
            self.0.lock().push(base);
            Ok(())
        }
        fn uninstall(&mut self, _: u64) {}
        fn protect(&mut self, _: u64, _: PageFlags) {}
        fn invalidate(&self, _: u64, _: u64) {}
        fn physical(&self, frame: NonNull<u8>) -> u64 {
            frame.as_ptr() as u64
        }

        fn new_empty(&self) -> Result<Self, NativeError> {
            Ok(InstallLog(alloc::sync::Arc::new(Mutex::new(Vec::new()))))
        }
    }

    #[test]
    fn anonymous_mappings_commit_only_touched_pages_until_fault_or_write() {
        ensure_pool();
        let tables = alloc::sync::Arc::new(Mutex::new(Vec::new()));
        let space = NativeSpace::new(InstallLog(tables.clone()), PAGE, 1 << 47);
        let rw = PageFlags::READ | PageFlags::WRITE;
        let range = |start: usize, pages: usize| {
            VirtRange::new(VirtAddr::new(start), pages * PAGE as usize)
        };

        let baseline = crate::memory::user_heap_stats().allocated_bytes;

        // Mapping more bytes than the entire 4 MiB test pool succeeds with 0
        // frames and 0 table installs.
        let huge = space
            .map_anywhere(VirtAddr::new(0x100_0000), 64 * 1024 * 1024, rw)
            .unwrap();
        assert_eq!(huge.byte_len, 64 * 1024 * 1024);
        assert_eq!(crate::memory::user_heap_stats().allocated_bytes, baseline);
        assert!(tables.lock().is_empty());

        // Fixed anonymous map (brk growth / MAP_FIXED) also takes 0 frames.
        space.map(range(0x10_000, 8), &[], rw).unwrap();
        assert_eq!(crate::memory::user_heap_stats().allocated_bytes, baseline);
        assert!(tables.lock().is_empty());

        // Reading or atomic-loading untouched pages yields zeros and commits nothing.
        let mut zeros = [0xffu8; 64];
        space.read(VirtAddr::new(0x12_080), &mut zeros).unwrap();
        assert!(zeros.iter().all(|b| *b == 0));
        assert_eq!(space.atomic_load_u32(VirtAddr::new(0x13_000)), Ok(0));
        assert_eq!(crate::memory::user_heap_stats().allocated_bytes, baseline);
        assert!(tables.lock().is_empty());

        // First touch on two pages commits exactly two frames.
        space
            .resolve_fault(VirtAddr::new(huge.start.raw() + 0x200), PageFlags::READ)
            .unwrap();
        space
            .resolve_fault(
                VirtAddr::new(huge.start.raw() + 64 * 1024 * 1024 - 16),
                PageFlags::WRITE,
            )
            .unwrap();
        assert_eq!(
            crate::memory::user_heap_stats().allocated_bytes,
            baseline + 2 * PAGE as usize
        );
        assert_eq!(tables.lock().len(), 2);

        // Writing a partial-contents segment (.data + .bss tail) commits only
        // the pages covered by `contents`.
        space.map(range(0x40_000, 4), b"data", rw).unwrap();
        assert_eq!(
            crate::memory::user_heap_stats().allocated_bytes,
            baseline + 3 * PAGE as usize
        );
        assert_eq!(tables.lock().len(), 3);

        // Growing via `remap` keeps the existing committed frame and takes 0
        // frames for the newly appended pages until touched.
        space.write(VirtAddr::new(0x10_000), b"head").unwrap();
        assert_eq!(
            crate::memory::user_heap_stats().allocated_bytes,
            baseline + 4 * PAGE as usize
        );
        space
            .remap(range(0x10_000, 8), range(0x80_000, 32))
            .unwrap();
        assert_eq!(
            crate::memory::user_heap_stats().allocated_bytes,
            baseline + 4 * PAGE as usize
        );
        let mut back = [0u8; 4];
        space.read(VirtAddr::new(0x80_000), &mut back).unwrap();
        assert_eq!(&back, b"head");

        // Touching a page in the grown tail commits that single page.
        space
            .resolve_fault(
                VirtAddr::new(0x80_000 + 20 * PAGE as usize),
                PageFlags::WRITE,
            )
            .unwrap();
        assert_eq!(
            crate::memory::user_heap_stats().allocated_bytes,
            baseline + 5 * PAGE as usize
        );

        // Unmapping frees only the committed frames and returns to baseline.
        space.unmap(huge).unwrap();
        space.unmap(range(0x40_000, 4)).unwrap();
        space.unmap(range(0x80_000, 32)).unwrap();
        assert_eq!(crate::memory::user_heap_stats().allocated_bytes, baseline);
    }

    #[derive(Clone, Copy)]
    struct TrackingPte {
        physical: u64,
        flags: PageFlags,
        accessed: bool,
    }

    /// Hardware PTE model for copy-on-write and aging tests: records every
    /// installed `(physical, flags, accessed)` entry and every shootdown span.
    #[derive(Clone)]
    struct TrackingTables {
        ptes: Arc<Mutex<BTreeMap<u64, TrackingPte>>>,
        shootdowns: Arc<Mutex<Vec<(u64, u64)>>>,
        icache_syncs: Arc<Mutex<Vec<usize>>>,
    }

    impl TrackingTables {
        fn new() -> Self {
            Self {
                ptes: Arc::new(Mutex::new(BTreeMap::new())),
                shootdowns: Arc::new(Mutex::new(Vec::new())),
                icache_syncs: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn pte(&self, base: u64) -> Option<(u64, PageFlags)> {
            self.ptes
                .lock()
                .get(&base)
                .map(|entry| (entry.physical, entry.flags))
        }

        fn is_accessed(&self, base: u64) -> Option<bool> {
            self.ptes.lock().get(&base).map(|entry| entry.accessed)
        }
    }

    // SAFETY: host test model tracking hardware translations without running
    // hardware slices.
    unsafe impl UserTranslation for TrackingTables {
        fn install(
            &mut self,
            base: u64,
            physical: u64,
            flags: PageFlags,
        ) -> Result<(), NativeError> {
            let prev = self.ptes.lock().insert(
                base,
                TrackingPte {
                    physical,
                    flags,
                    accessed: true,
                },
            );
            assert!(
                prev.is_none(),
                "install must obey break-before-make on {base:#x}"
            );
            Ok(())
        }

        fn uninstall(&mut self, base: u64) {
            let prev = self.ptes.lock().remove(&base);
            assert!(prev.is_some(), "uninstall on unmapped page {base:#x}");
        }

        fn protect(&mut self, base: u64, flags: PageFlags) {
            let mut ptes = self.ptes.lock();
            let entry = ptes.get_mut(&base).expect("protect on mapped page");
            entry.flags = flags;
            entry.accessed = true;
        }

        fn invalidate(&self, first: u64, last: u64) {
            self.shootdowns.lock().push((first, last));
        }

        fn physical(&self, frame: NonNull<u8>) -> u64 {
            frame.as_ptr() as u64
        }

        fn new_empty(&self) -> Result<Self, NativeError> {
            Ok(Self::new())
        }

        fn sync_executable_frame(&self, frame: NonNull<u8>) {
            self.icache_syncs.lock().push(frame.as_ptr() as usize);
        }

        fn test_and_clear_accessed(&mut self, base: u64) -> bool {
            let mut ptes = self.ptes.lock();
            let Some(entry) = ptes.get_mut(&base) else {
                return false;
            };
            let was_accessed = entry.accessed;
            entry.accessed = false;
            was_accessed
        }
    }

    #[test]
    fn cow_clone_shares_frames_shoots_down_parent_and_copies_on_write_fault() {
        ensure_pool();
        let parent_tables = TrackingTables::new();
        let parent = NativeSpace::new(parent_tables.clone(), PAGE, 1 << 47);
        let rw = PageFlags::READ | PageFlags::WRITE;
        let range = |start: usize, pages: usize| {
            VirtRange::new(VirtAddr::new(start), pages * PAGE as usize)
        };

        let baseline = crate::memory::user_heap_stats().allocated_bytes;
        parent.map(range(0x10_000, 2), b"hello-cow", rw).unwrap();
        // Page 0x10_000 is committed; 0x11_000 is uncommitted zero-fill.
        assert_eq!(
            crate::memory::user_heap_stats().allocated_bytes,
            baseline + PAGE as usize
        );
        let (orig_phys, orig_flags) = parent_tables.pte(0x10_000).unwrap();
        assert_eq!(orig_flags, rw);

        // Hold an active slice on parent to verify clone_cow shoots down narrowed PTEs.
        let slice = parent.begin_slice();
        let child = parent.clone_cow().unwrap();
        drop(slice);

        // Zero additional frames allocated by clone_cow!
        assert_eq!(
            crate::memory::user_heap_stats().allocated_bytes,
            baseline + PAGE as usize
        );
        assert!(parent.is_page_shared(VirtAddr::new(0x10_000)));
        assert!(child.is_page_shared(VirtAddr::new(0x10_000)));
        assert!(!parent.is_page_shared(VirtAddr::new(0x11_000)));
        // Parent's hardware PTE lost WRITE and was shot down.
        assert_eq!(
            parent_tables.pte(0x10_000),
            Some((orig_phys, PageFlags::READ))
        );
        assert_eq!(*parent_tables.shootdowns.lock(), vec![(0x10_000, 0x11_000)]);
        // Logical mapping still reports READ | WRITE in both spaces.
        assert_eq!(
            parent.mapping(range(0x10_000, 2)).map(|m| m.flags),
            Some(rw)
        );
        assert_eq!(child.mapping(range(0x10_000, 2)).map(|m| m.flags), Some(rw));

        // Child write fault copies the frame privately without touching parent.
        let child_slice = child.begin_slice();
        child
            .resolve_fault(VirtAddr::new(0x10_000), PageFlags::WRITE)
            .unwrap();
        drop(child_slice);
        assert_eq!(
            crate::memory::user_heap_stats().allocated_bytes,
            baseline + 2 * PAGE as usize
        );
        assert!(!child.is_page_shared(VirtAddr::new(0x10_000)));
        assert!(parent.is_page_shared(VirtAddr::new(0x10_000)));
        child.write(VirtAddr::new(0x10_000), b"child-val").unwrap();

        let mut parent_bytes = [0u8; 9];
        let mut child_bytes = [0u8; 9];
        parent
            .read(VirtAddr::new(0x10_000), &mut parent_bytes)
            .unwrap();
        child
            .read(VirtAddr::new(0x10_000), &mut child_bytes)
            .unwrap();
        assert_eq!(&parent_bytes, b"hello-cow");
        assert_eq!(&child_bytes, b"child-val");

        // Parent is now the sole surviving owner of `orig_phys`: a write fault
        // on parent upgrades in place without allocating a third frame!
        parent
            .resolve_fault(VirtAddr::new(0x10_000), PageFlags::WRITE)
            .unwrap();
        assert_eq!(
            crate::memory::user_heap_stats().allocated_bytes,
            baseline + 2 * PAGE as usize
        );
        assert_eq!(parent_tables.pte(0x10_000), Some((orig_phys, rw)));
        assert!(!parent.is_page_shared(VirtAddr::new(0x10_000)));

        drop(child);
        drop(parent);
        assert_eq!(crate::memory::user_heap_stats().allocated_bytes, baseline);
    }

    #[test]
    fn cow_kernel_write_atomics_mprotect_and_mremap_preserve_isolation() {
        ensure_pool();
        let parent_tables = TrackingTables::new();
        let parent = NativeSpace::new(parent_tables.clone(), PAGE, 1 << 47);
        let rw = PageFlags::READ | PageFlags::WRITE;
        let range = |start: usize, pages: usize| {
            VirtRange::new(VirtAddr::new(start), pages * PAGE as usize)
        };

        let baseline = crate::memory::user_heap_stats().allocated_bytes;
        parent.map(range(0x20_000, 1), b"orig", rw).unwrap();
        parent
            .map(range(0x30_000, 1), b"prot", PageFlags::READ)
            .unwrap();
        parent.map(range(0x40_000, 1), b"move", rw).unwrap();

        let child = parent.clone_cow().unwrap();

        // 1. Kernel write / atomic store / atomic CAS break CoW without mutating peer.
        child
            .atomic_store_u32(VirtAddr::new(0x20_004), 0xdead_beef)
            .unwrap();
        assert_eq!(parent.atomic_load_u32(VirtAddr::new(0x20_004)), Ok(0));
        assert_eq!(
            child.atomic_compare_exchange_u32(VirtAddr::new(0x20_004), 0xdead_beef, 42),
            Ok(Ok(0xdead_beef))
        );
        assert_eq!(parent.atomic_load_u32(VirtAddr::new(0x20_004)), Ok(0));

        // 2. Widening a shared RO page via `protect(RW)` keeps hardware PTE RO
        //    so CoW still fires on write instead of corrupting the peer.
        parent.protect(range(0x30_000, 1), rw).unwrap();
        assert_eq!(
            parent_tables.pte(0x30_000).map(|(_, flags)| flags),
            Some(PageFlags::READ)
        );
        parent.write(VirtAddr::new(0x30_000), b"edit").unwrap();
        let mut child_prot = [0u8; 4];
        child
            .read(VirtAddr::new(0x30_000), &mut child_prot)
            .unwrap();
        assert_eq!(&child_prot, b"prot");

        // 3. Remapping (`mremap`) a CoW page keeps hardware PTE RO until write.
        parent
            .remap(range(0x40_000, 1), range(0x50_000, 1))
            .unwrap();
        assert_eq!(
            parent_tables.pte(0x50_000).map(|(_, flags)| flags),
            Some(PageFlags::READ)
        );
        parent.write(VirtAddr::new(0x50_000), b"mut!").unwrap();
        let mut child_move = [0u8; 4];
        child
            .read(VirtAddr::new(0x40_000), &mut child_move)
            .unwrap();
        assert_eq!(&child_move, b"move");

        drop(child);
        drop(parent);
        assert_eq!(crate::memory::user_heap_stats().allocated_bytes, baseline);
    }

    #[test]
    fn populate_writes_readonly_and_exec_pages_without_widening_ptes_and_breaks_cow() {
        ensure_pool();
        let parent_tables = TrackingTables::new();
        let parent = NativeSpace::new(parent_tables.clone(), PAGE, 1 << 47);
        let rx = PageFlags::READ | PageFlags::EXECUTE;
        let range = |start: usize, pages: usize| {
            VirtRange::new(VirtAddr::new(start), pages * PAGE as usize)
        };
        let baseline = crate::memory::user_heap_stats().allocated_bytes;

        // Reserve 2 RX pages and 1 PROT_NONE page (0 frames committed yet).
        parent.map(range(0x10_000, 2), &[], rx).unwrap();
        parent
            .map(range(0x20_000, 1), &[], PageFlags::empty())
            .unwrap();
        assert_eq!(crate::memory::user_heap_stats().allocated_bytes, baseline);

        // Populate only page 0 of RX and page 0 of PROT_NONE: PTEs keep exact
        // non-writable flags and untouched EOF tail page commits 0 frames.
        parent
            .populate(VirtAddr::new(0x10_000), b"exec-bytes")
            .unwrap();
        parent
            .populate(VirtAddr::new(0x20_000), b"hidden-bytes")
            .unwrap();
        assert_eq!(
            crate::memory::user_heap_stats().allocated_bytes,
            baseline + 2 * PAGE as usize
        );
        assert_eq!(parent_tables.pte(0x10_000).map(|(_, f)| f), Some(rx));
        assert_eq!(parent_tables.pte(0x11_000), None);
        assert_eq!(
            parent_tables.pte(0x20_000).map(|(_, f)| f),
            Some(PageFlags::empty())
        );

        // Reveal PROT_NONE via protect(READ) and verify populated bytes + zero tail.
        parent.protect(range(0x20_000, 1), PageFlags::READ).unwrap();
        let mut out = [0xffu8; 32];
        parent.read(VirtAddr::new(0x20_000), &mut out).unwrap();
        assert_eq!(&out[..12], b"hidden-bytes");
        assert!(out[12..].iter().all(|&b| b == 0));

        // CoW clone shares both frames (0 new frames); populating parent's
        // read-only page breaks CoW privately without mutating child or
        // granting WRITE in hardware.
        let child = parent.clone_cow().unwrap();
        assert_eq!(
            crate::memory::user_heap_stats().allocated_bytes,
            baseline + 2 * PAGE as usize
        );
        parent
            .populate(VirtAddr::new(0x20_000), b"PARENT-SYNC!")
            .unwrap();
        assert_eq!(
            crate::memory::user_heap_stats().allocated_bytes,
            baseline + 3 * PAGE as usize
        );
        assert_eq!(
            parent_tables.pte(0x20_000).map(|(_, f)| f),
            Some(PageFlags::READ)
        );
        let mut p_seen = [0u8; 12];
        let mut c_seen = [0u8; 12];
        parent.read(VirtAddr::new(0x20_000), &mut p_seen).unwrap();
        child.read(VirtAddr::new(0x20_000), &mut c_seen).unwrap();
        assert_eq!(&p_seen, b"PARENT-SYNC!");
        assert_eq!(&c_seen, b"hidden-bytes");

        drop(child);
        drop(parent);
        assert_eq!(crate::memory::user_heap_stats().allocated_bytes, baseline);
    }

    #[test]
    fn shared_writable_frames_preserve_coherence_dirty_tracking_and_icache_sync() {
        ensure_pool();
        let parent_tables = TrackingTables::new();
        let parent = NativeSpace::new(parent_tables.clone(), PAGE, 1 << 47);
        let rw = PageFlags::READ | PageFlags::WRITE;
        let rx = PageFlags::READ | PageFlags::EXECUTE;
        let range = |start: usize, pages: usize| {
            VirtRange::new(VirtAddr::new(start), pages * PAGE as usize)
        };
        let baseline = crate::memory::user_heap_stats().allocated_bytes;

        // 1. SharedWritable frames stay writable across clone_cow (NOT CoW-narrowed),
        //    so writes from parent and child see the exact same SharedFrame immediately.
        let obj = SharedPageObject::new_file_backed();
        let frame = obj.load_file_page(0, b"initial-file-content").unwrap();
        parent
            .map_region(range(0x10_000, 2), rw, RegionKind::Shared)
            .unwrap();
        parent
            .attach_shared_frame(VirtAddr::new(0x10_000), Arc::clone(&frame))
            .unwrap();
        // Uncommitted shared page 0x11_000 triggers BackingFault for demand-load / SIGBUS.
        assert_eq!(
            parent.resolve_fault(VirtAddr::new(0x11_000), PageFlags::READ),
            Err(NativeError::BackingFault)
        );
        // Second mapping of the same object in the same address space shares the frame.
        parent
            .map_region(range(0x20_000, 1), rw, RegionKind::Shared)
            .unwrap();
        parent
            .attach_shared_frame(VirtAddr::new(0x20_000), Arc::clone(&frame))
            .unwrap();
        assert_eq!(
            parent_tables.pte(0x10_000),
            parent_tables.pte(0x20_000),
            "duplicate MAP_SHARED shares the exact physical frame"
        );

        let child = parent.clone_cow().unwrap();
        // Parent's SharedWritable PTE stays RW (not narrowed to READ).
        assert_eq!(parent_tables.pte(0x10_000).map(|(_, f)| f), Some(rw));
        // Child writes bytes 0..7; parent sees them immediately through both mappings.
        child.write(VirtAddr::new(0x10_000), b"CHILD!!").unwrap();
        let mut seen = [0u8; 20];
        parent.read(VirtAddr::new(0x20_000), &mut seen).unwrap();
        assert_eq!(&seen, b"CHILD!!-file-content");

        // Concurrent write(2) updates bytes 13..20 without clobbering child's dirty bytes 0..7.
        obj.apply_file_write(13, b"WRITTEN");
        parent.read(VirtAddr::new(0x10_000), &mut seen).unwrap();
        assert_eq!(&seen, b"CHILD!!-file-WRITTEN");

        // mprotect(PROT_NONE) denies user reads, while read_unrestricted and
        // collect_dirty_runs still observe ONLY modified bytes 0..7!
        parent
            .protect(range(0x10_000, 1), PageFlags::empty())
            .unwrap();
        assert_eq!(
            parent.read(VirtAddr::new(0x10_000), &mut seen),
            Err(NativeError::NotMapped)
        );
        parent
            .read_unrestricted(VirtAddr::new(0x10_000), &mut seen)
            .unwrap();
        assert_eq!(&seen, b"CHILD!!-file-WRITTEN");
        let dirty = obj.collect_dirty_runs(0, 20);
        assert_eq!(dirty, vec![(0, b"CHILD!!".to_vec())]);
        obj.mark_clean(0, b"CHILD!!");
        assert!(obj.collect_dirty_runs(0, 20).is_empty());

        // 2. PrivateFile uncommitted page returns BackingFault.
        parent
            .map_region(range(0x30_000, 1), PageFlags::READ, RegionKind::PrivateFile)
            .unwrap();
        assert_eq!(
            parent.resolve_fault(VirtAddr::new(0x30_000), PageFlags::READ),
            Err(NativeError::BackingFault)
        );
        let priv_frame = SharedPageObject::allocate_frame_from_bytes(b"priv").unwrap();
        parent
            .install_private_frame(VirtAddr::new(0x30_000), priv_frame)
            .unwrap();
        let mut pbuf = [0u8; 4];
        parent.read(VirtAddr::new(0x30_000), &mut pbuf).unwrap();
        assert_eq!(&pbuf, b"priv");

        // 3. Executable page maintenance invokes sync_executable_frame on map/write/protect.
        parent_tables.icache_syncs.lock().clear();
        parent.map(range(0x40_000, 1), b"data", rw).unwrap();
        assert!(
            parent_tables.icache_syncs.lock().is_empty(),
            "RW mapping needs no icache sync"
        );
        parent.protect(range(0x40_000, 1), rx).unwrap();
        assert_eq!(
            parent_tables.icache_syncs.lock().len(),
            1,
            "widening RW -> RX must sync icache"
        );
        parent.map(range(0x50_000, 1), b"code", rx).unwrap();
        assert_eq!(
            parent_tables.icache_syncs.lock().len(),
            2,
            "mapping executable code must sync icache"
        );

        drop(frame);
        drop(obj);
        drop(child);
        drop(parent);
        assert_eq!(crate::memory::user_heap_stats().allocated_bytes, baseline);
    }

    #[test]
    fn hardware_aging_access_flag_fault_restoration_and_swap_lifecycle() {
        ensure_pool();
        let tables = TrackingTables::new();
        let space = NativeSpace::new(tables.clone(), PAGE, 1 << 47);
        let rw = PageFlags::READ | PageFlags::WRITE;
        let rx = PageFlags::READ | PageFlags::EXECUTE;
        let range = |start: usize, pages: usize| {
            VirtRange::new(VirtAddr::new(start), pages * PAGE as usize)
        };
        let baseline = crate::memory::user_heap_stats().allocated_bytes;

        let cjk = "中文 日本語 한국어 native swap payload".as_bytes();
        space.map(range(0x10_000, 3), &[], rw).unwrap();
        space.write(VirtAddr::new(0x10_000), cjk).unwrap();
        space.write(VirtAddr::new(0x11_000), b"cold-page").unwrap();
        space.write(VirtAddr::new(0x12_000), b"discard-me").unwrap();
        assert_eq!(space.resident_bytes(), 3 * PAGE);
        assert_eq!(space.swapped_bytes(), 0);

        // Freshly installed pages start accessed (Hot).
        assert_eq!(tables.is_accessed(0x10_000), Some(true));
        assert_eq!(tables.is_accessed(0x11_000), Some(true));

        // First Red (cold-only) scan clears AF/ACCESSED on all 3 pages and
        // selects 0 candidates because all 3 were Hot.
        let mut candidates = Vec::new();
        let visited = space.scan_private_pages_for_swap(16, true, 16, &mut candidates);
        assert_eq!(visited, 3);
        assert!(candidates.is_empty());
        assert_eq!(tables.is_accessed(0x10_000), Some(false));
        assert_eq!(tables.is_accessed(0x11_000), Some(false));
        assert_eq!(tables.is_accessed(0x12_000), Some(false));

        // Simulate AArch64 Access Flag Fault on 0x10_000 (READ): `resolve_fault`
        // must re-publish hardware AF (`accessed = true`) so EL0 does not loop!
        space
            .resolve_fault(VirtAddr::new(0x10_000), PageFlags::READ)
            .unwrap();
        assert_eq!(tables.is_accessed(0x10_000), Some(true));

        // Second Red scan sees 0x10_000 Hot (clears it again) and 0x11_000 / 0x12_000 Cold!
        candidates.clear();
        space.scan_private_pages_for_swap(16, true, 16, &mut candidates);
        assert_eq!(
            candidates,
            vec![VirtAddr::new(0x11_000), VirtAddr::new(0x12_000)]
        );

        // Active slice refuses `swap_out_private_page` without detaching.
        let tok1 = SwapToken::new(10).unwrap();
        let tok2 = SwapToken::new(11).unwrap();
        let tok3 = SwapToken::new(12).unwrap();
        let mut buf1 = vec![0u8; PAGE as usize];
        let mut buf2 = vec![0u8; PAGE as usize];
        let slice = space.begin_slice();
        assert_eq!(
            space.swap_out_private_page(VirtAddr::new(0x11_000), tok1, &mut buf1),
            Err(NativeError::Overlap)
        );
        drop(slice);

        // With slices == 0, private pages swap out cleanly and free their frames.
        space
            .swap_out_private_page(VirtAddr::new(0x11_000), tok1, &mut buf1)
            .unwrap();
        space
            .swap_out_private_page(VirtAddr::new(0x12_000), tok2, &mut buf2)
            .unwrap();
        assert_eq!(&buf1[..9], b"cold-page");
        assert_eq!(tables.pte(0x11_000), None);
        assert_eq!(space.resident_bytes(), PAGE);
        assert_eq!(space.swapped_bytes(), 2 * PAGE);
        assert_eq!(space.swapped_token(VirtAddr::new(0x11_000)), Some(tok1));
        assert_eq!(
            space.first_swapped_in(range(0x10_000, 3)),
            Some(VirtAddr::new(0x11_000))
        );
        assert_eq!(space.first_swapped_page(), Some(VirtAddr::new(0x11_000)));
        assert_eq!(
            crate::memory::user_heap_stats().allocated_bytes,
            baseline + PAGE as usize
        );

        // User fault, kernel read/write/populate/atomics, and clone_cow all
        // report `NativeError::Swapped` without partial mutation.
        assert_eq!(
            space.resolve_fault(VirtAddr::new(0x11_000), PageFlags::READ),
            Err(NativeError::Swapped)
        );
        let mut probe = [0u8; 8];
        assert_eq!(
            space.read(VirtAddr::new(0x11_000), &mut probe),
            Err(NativeError::Swapped)
        );
        assert_eq!(
            space.write(VirtAddr::new(0x11_000), b"nope"),
            Err(NativeError::Swapped)
        );
        assert_eq!(
            space.populate(VirtAddr::new(0x11_000), b"nope"),
            Err(NativeError::Swapped)
        );
        assert_eq!(
            space.atomic_load_u32(VirtAddr::new(0x11_000)),
            Err(NativeError::Swapped)
        );
        assert_eq!(
            space.atomic_store_u32(VirtAddr::new(0x11_000), 1),
            Err(NativeError::Swapped)
        );
        assert_eq!(
            space.atomic_compare_exchange_u32(VirtAddr::new(0x11_000), 0, 1),
            Err(NativeError::Swapped)
        );
        assert!(matches!(space.clone_cow(), Err(NativeError::Swapped)));

        // `mprotect` to RX and `mremap` while swapped preserve token and flags,
        // and swap-in installs with RX + icache sync + accessed=true.
        space.protect(range(0x11_000, 1), rx).unwrap();
        space.remap(range(0x11_000, 1), range(0x21_000, 1)).unwrap();
        assert_eq!(space.swapped_token(VirtAddr::new(0x11_000)), None);
        assert_eq!(space.swapped_token(VirtAddr::new(0x21_000)), Some(tok1));
        tables.icache_syncs.lock().clear();
        assert_eq!(
            space
                .swap_in_private_page(VirtAddr::new(0x21_000), &buf1)
                .unwrap(),
            tok1
        );
        assert_eq!(tables.pte(0x21_000).map(|(_, f)| f), Some(rx));
        assert_eq!(tables.is_accessed(0x21_000), Some(true));
        assert_eq!(tables.icache_syncs.lock().len(), 1);
        let mut back = [0u8; 9];
        space.read(VirtAddr::new(0x21_000), &mut back).unwrap();
        assert_eq!(&back, b"cold-page");

        // `discard` on swapped page 0x12_000 orphans tok2; `unmap` on swapped
        // page 0x10_000 orphans tok3.
        space.discard(range(0x12_000, 1)).unwrap();
        let mut orphans = Vec::new();
        space.drain_orphan_swap_tokens(&mut orphans);
        assert_eq!(orphans, vec![tok2]);

        let mut buf0 = vec![0u8; PAGE as usize];
        space
            .swap_out_private_page(VirtAddr::new(0x10_000), tok3, &mut buf0)
            .unwrap();
        assert_eq!(&buf0[..cjk.len()], cjk);
        space.unmap(range(0x10_000, 1)).unwrap();
        orphans.clear();
        space.drain_orphan_swap_tokens(&mut orphans);
        assert_eq!(orphans, vec![tok3]);
        assert_eq!(space.swapped_bytes(), 0);

        // CoW and SharedWritable pages are NEVER scanned or evicted.
        let shared_obj = SharedPageObject::new_anonymous();
        let sh_frame = shared_obj.get_or_alloc_frame(0).unwrap();
        space
            .map_region(range(0x30_000, 1), rw, RegionKind::Shared)
            .unwrap();
        space
            .attach_shared_frame(VirtAddr::new(0x30_000), sh_frame)
            .unwrap();
        let child = space.clone_cow().unwrap();
        // 0x21_000 is now CoW, 0x30_000 is SharedWritable -> 0 evictable Unique pages!
        candidates.clear();
        assert_eq!(
            space.scan_private_pages_for_swap(16, false, 16, &mut candidates),
            0
        );
        assert!(candidates.is_empty());
        assert_eq!(
            space.swap_out_private_page(
                VirtAddr::new(0x21_000),
                SwapToken::new(99).unwrap(),
                &mut buf0
            ),
            Err(NativeError::NotMapped)
        );
        assert_eq!(
            space.swap_out_private_page(
                VirtAddr::new(0x30_000),
                SwapToken::new(99).unwrap(),
                &mut buf0
            ),
            Err(NativeError::NotMapped)
        );

        drop(child);
        drop(shared_obj);
        drop(space);
        assert_eq!(crate::memory::user_heap_stats().allocated_bytes, baseline);
    }
}
