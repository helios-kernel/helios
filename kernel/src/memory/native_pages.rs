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
use helios_hal::native::{Mapping, NativeError, UserSpace};
use helios_hal::pmm::PhysFrame;
use helios_hal::vmm::{PageFlags, VirtAddr, VirtRange};
use spin::Mutex;

use crate::memory::{allocate_user_frame_zeroed_on, deallocate_user_frame_on};

const PAGE: u64 = PhysFrame::SIZE as u64;

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

/// A reference-counted copy-on-write user frame. Dropping the last `Arc`
/// returns the frame to the user memory pool on the executing processor.
#[derive(Debug)]
struct SharedFrame(NonNull<u8>);

// SAFETY: a user frame is a 4 KiB direct-mapped allocation managed by the user
// memory pool; shared frames stay read-only in hardware until copied or
// unwrapped by the sole surviving owner.
unsafe impl Send for SharedFrame {}
// SAFETY: `SharedFrame` only holds an immutable `NonNull<u8>` pointing to a
// read-only shared frame whose drop frees the frame once the last `Arc` ends.
unsafe impl Sync for SharedFrame {}

impl SharedFrame {
    fn into_raw(self) -> NonNull<u8> {
        let ptr = self.0;
        core::mem::forget(self);
        ptr
    }
}

impl Drop for SharedFrame {
    fn drop(&mut self) {
        deallocate_user_frame_on(helios_hal::cpu::current_processor(), self.0);
    }
}

/// Ownership of one committed 4 KiB user frame inside [`NativePages`].
///
/// Non-forked pages stay [`Self::Unique`] with no heap allocation or atomic
/// refcount traffic; [`NativeSpace::clone_cow`] promotes committed frames to
/// [`Self::Shared`] so parent and child share them read-only until either
/// writes.
#[derive(Debug)]
enum FrameRef {
    Unique(NonNull<u8>),
    Shared(Arc<SharedFrame>),
}

impl FrameRef {
    fn ptr(&self) -> NonNull<u8> {
        match self {
            Self::Unique(ptr) => *ptr,
            Self::Shared(shared) => shared.0,
        }
    }

    fn is_shared(&self) -> bool {
        matches!(self, Self::Shared(_))
    }

    fn share(&mut self) -> Self {
        match self {
            Self::Unique(ptr) => {
                let shared = Arc::new(SharedFrame(*ptr));
                let clone = Arc::clone(&shared);
                *self = Self::Shared(shared);
                Self::Shared(clone)
            }
            Self::Shared(shared) => Self::Shared(Arc::clone(shared)),
        }
    }

    fn release(self, processor: helios_hal::cpu::ProcessorId) {
        match self {
            Self::Unique(ptr) => deallocate_user_frame_on(processor, ptr),
            Self::Shared(shared) => drop(shared),
        }
    }
}

fn hardware_flags(flags: PageFlags, shared: bool) -> PageFlags {
    if shared {
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
            self.pages.insert_region(base, base + PAGE, flags);
            self.pages.insert_frame(base, frame);
        }
        Ok(())
    }

    /// Takes the pages of `[first, last)` out of the index and the tables.
    /// Another thread's slice may have reached any committed page, so their
    /// frames wait for the shootdown.
    fn take(&mut self, first: u64, last: u64) -> Removed {
        let mut removed = Removed::new();
        for (base, frame) in self.pages.remove_range_refs(first, last) {
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

    /// Gives uncommitted page `base` a zero-filled frame.
    fn commit(&mut self, base: u64, flags: PageFlags) -> Result<(), NativeError> {
        let processor = helios_hal::cpu::current_processor();
        let frame =
            allocate_user_frame_zeroed_on(processor).map_err(|_| NativeError::OutOfMemory)?;
        if let Err(error) = self
            .tables
            .install(base, self.tables.physical(frame), flags)
        {
            deallocate_user_frame_on(processor, frame);
            return Err(error);
        }
        self.pages.commit(base, frame);
        Ok(())
    }

    /// Ensures committed page `base` is privately owned (`FrameRef::Unique`)
    /// and writable in hardware (`flags`). Upgrades in place when this space
    /// is the sole surviving owner, or performs a break-before-make copy onto
    /// a fresh frame when another space still references the frame.
    fn break_cow_page(
        &mut self,
        space: &NativeSpace<Tables>,
        base: u64,
        flags: PageFlags,
    ) -> Result<(), NativeError> {
        if !self
            .pages
            .frames
            .get(&base)
            .is_some_and(FrameRef::is_shared)
        {
            return Ok(());
        }
        let FrameRef::Shared(shared) = self
            .pages
            .frames
            .remove(&base)
            .expect("checked shared frame exists")
        else {
            unreachable!("checked is_shared above");
        };
        match Arc::try_unwrap(shared) {
            Ok(sole) => {
                // Sole surviving owner: upgrade back to `Unique` in place and
                // widen the hardware PTE (widening needs no shootdown).
                self.pages
                    .frames
                    .insert(base, FrameRef::Unique(sole.into_raw()));
                self.tables.protect(base, flags);
                Ok(())
            }
            Err(shared) => {
                let processor = helios_hal::cpu::current_processor();
                let Ok(new_frame) = allocate_user_frame_zeroed_on(processor) else {
                    self.pages.frames.insert(base, FrameRef::Shared(shared));
                    return Err(NativeError::OutOfMemory);
                };
                // SAFETY: both `shared.0` and `new_frame` are valid 4 KiB
                // direct-mapped user frames; `shared` is read-only in hardware
                // and remains alive until dropped below.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        shared.0.as_ptr(),
                        new_frame.as_ptr(),
                        PAGE as usize,
                    );
                }
                let old_phys = self.tables.physical(shared.0);
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
                    self.pages.frames.insert(base, FrameRef::Shared(shared));
                    return Err(error);
                }
                self.pages.frames.insert(base, FrameRef::Unique(new_frame));
                drop(shared);
                Ok(())
            }
        }
    }

    /// Gives every uncommitted page of `[first, last)` a private frame and
    /// breaks copy-on-write on any shared page so a kernel write never mutates
    /// another space's frame.
    fn ensure_writable_private_range(
        &mut self,
        space: &NativeSpace<Tables>,
        first: u64,
        last: u64,
    ) -> Result<(), NativeError> {
        for base in (first..last).step_by(PAGE as usize) {
            let page = self
                .pages
                .get(base)
                .expect("write checks every page is mapped first");
            match page.frame {
                None => self.commit(base, page.flags)?,
                Some(_) => self.break_cow_page(space, base, page.flags)?,
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
        Ok(())
    }

    fn map_anywhere(
        &self,
        hint: VirtAddr,
        byte_len: usize,
        flags: PageFlags,
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
            .insert_region(start, start + byte_len as u64, flags);
        Ok(VirtRange::new(VirtAddr::new(start as usize), byte_len))
    }

    fn read(&self, address: VirtAddr, output: &mut [u8]) -> Result<(), NativeError> {
        self.shared
            .state
            .lock()
            .pages
            .read(address.raw() as u64, output)
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
        state.ensure_writable_private_range(self, first, last)?;
        state.pages.write(address, bytes, PageFlags::WRITE)
    }

    fn atomic_load_u32(&self, address: VirtAddr) -> Result<u32, NativeError> {
        let address = address.raw() as u64;
        if address & 3 != 0 {
            return Err(NativeError::Address);
        }
        let state = self.shared.state.lock();
        let (first, _) = state.pages.span(address, 4)?;
        let page = state.pages.get(first).ok_or(NativeError::NotMapped)?;
        if !page.flags.contains(PageFlags::READ) {
            return Err(NativeError::NotMapped);
        }
        let Some(frame) = page.frame else {
            return Ok(0);
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
        let page = state.pages.get(first).ok_or(NativeError::NotMapped)?;
        if !page.flags.contains(PageFlags::WRITE) {
            return Err(NativeError::NotMapped);
        }
        if page.frame.is_none() {
            state.commit(first, page.flags)?;
        } else {
            state.break_cow_page(self, first, page.flags)?;
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
        let page = state.pages.get(first).ok_or(NativeError::NotMapped)?;
        if !page.flags.contains(PageFlags::READ | PageFlags::WRITE) {
            return Err(NativeError::NotMapped);
        }
        if page.frame.is_none() {
            state.commit(first, page.flags)?;
        } else {
            state.break_cow_page(self, first, page.flags)?;
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
        Ok(word
            .compare_exchange(
                expected.to_le(),
                desired.to_le(),
                Ordering::SeqCst,
                Ordering::SeqCst,
            )
            .map(u32::from_le)
            .map_err(u32::from_le))
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
        pages.protect_range_with_sharing(first, last, flags, |base, old_flags, shared| {
            let old_hw = hardware_flags(old_flags, shared);
            let new_hw = hardware_flags(flags, shared);
            if old_hw != new_hw {
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
        let flags = state
            .pages
            .uniform(from_first, from_last)
            .ok_or(NativeError::NotMapped)?;
        // Each moved frame is reachable at both addresses until the source
        // goes, so a slice racing the move reaches one frame, never two. The
        // growth tail takes no frames until touched.
        let committed = state.pages.committed_in_with_sharing(from_first, from_last);
        for (index, (base, ptr, shared)) in committed.iter().enumerate() {
            let target = to_first + (base - from_first);
            let physical = state.tables.physical(*ptr);
            let hw = hardware_flags(flags, *shared);
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
        pages.insert_region(to_first, to_last, flags);
        for (base, frame) in moved {
            tables.uninstall(base);
            source.touch(base);
            pages.insert_frame_ref(to_first + (base - from_first), frame);
        }
        self.complete(&state.tables, source);
        Ok(())
    }

    fn resolve_fault(&self, address: VirtAddr, access: PageFlags) -> Result<(), NativeError> {
        let base = address.page_floor().raw() as u64;
        let mut state = self.shared.state.lock();
        let page = state.pages.get(base).ok_or(NativeError::NotMapped)?;
        if !page.flags.contains(access) {
            return Err(NativeError::NotMapped);
        }
        match page.frame {
            None => state.commit(base, page.flags),
            Some(_) if access.contains(PageFlags::WRITE) => {
                state.break_cow_page(self, base, page.flags)
            }
            // A translation older than the page's current access, left on
            // the faulting processor: walking the tables again succeeds.
            Some(_) => Ok(()),
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
        let mut child_tables = state.tables.new_empty()?;
        let mut child_pages = NativePages {
            regions: state.pages.regions.clone(),
            frames: BTreeMap::new(),
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
            let hw_flags = hardware_flags(flags, true);
            let frame_ref = pages
                .frames
                .get_mut(&base)
                .expect("key came from pages.frames");
            let physical = tables.physical(frame_ref.ptr());
            let was_shared = frame_ref.is_shared();
            if let Err(error) = child_tables.install(base, physical, hw_flags) {
                // Shoot down any parent pages already narrowed before dropping
                // `child_pages` (which decrements its `Arc<SharedFrame>` refs).
                self.complete(tables, narrowed);
                return Err(error);
            }
            let child_ref = frame_ref.share();
            child_pages.frames.insert(base, child_ref);
            if !was_shared && flags.contains(PageFlags::WRITE) {
                tables.protect(base, hw_flags);
                narrowed.touch(base);
            }
        }
        // Shoot down every narrowed parent PTE before exposing the child space
        // so no sibling thread in the parent can write through a stale writable
        // TLB entry into a newly shared frame.
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
            .is_some_and(FrameRef::is_shared)
    }
}

impl<Tables> Drop for NativeSpace<Tables> {
    fn drop(&mut self) {
        // No slice outlives the borrow of this space, and every slice's exit
        // left no translation of it usable on its processor.
        let processor = helios_hal::cpu::current_processor();
        for frame in self.shared.state.get_mut().pages.drain_frame_refs() {
            frame.release(processor);
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
}

/// Every mapped page of one user address space: contiguous mapped ranges
/// with uniform access, and only the pages that currently hold a user frame.
pub struct NativePages {
    /// Non-overlapping, non-empty, page-aligned mapped ranges keyed by start
    /// address; adjacent ranges with identical `flags` are merged.
    regions: BTreeMap<u64, MappedRegion>,
    /// Committed backing frames keyed by page base inside `regions`.
    frames: BTreeMap<u64, FrameRef>,
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
            start,
            end,
        }
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
        if first >= last {
            return None;
        }
        let (_, region) = self.region_at(first)?;
        (region.end >= last).then_some(region.flags)
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
        let clipped_end = region.end.min(last);
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
            frame: self.frames.get(&base).map(FrameRef::ptr),
            flags: region.flags,
        })
    }

    /// Inserts an unmapped contiguous page-aligned range `[first, last)`,
    /// coalescing with adjacent neighbors that carry the same `flags`.
    pub fn insert_region(&mut self, mut first: u64, mut last: u64, flags: PageFlags) {
        assert!(first < last && first.is_multiple_of(PAGE) && last.is_multiple_of(PAGE));
        if let Some((&left_start, &left)) = self.regions.range(..first).next_back()
            && left.end == first
            && left.flags == flags
        {
            self.regions.remove(&left_start);
            first = left_start;
        }
        if let Some(&right) = self.regions.get(&last)
            && right.flags == flags
        {
            self.regions.remove(&last);
            last = right.end;
        }
        let previous = self
            .regions
            .insert(first, MappedRegion { end: last, flags });
        assert!(
            previous.is_none(),
            "user range {first:#x}..{last:#x} mapped twice"
        );
    }

    pub fn insert_frame(&mut self, base: u64, frame: NonNull<u8>) {
        self.insert_frame_ref(base, FrameRef::Unique(frame));
    }

    fn insert_frame_ref(&mut self, base: u64, frame: FrameRef) {
        let previous = self.frames.insert(base, frame);
        assert!(previous.is_none(), "user page {base:#x} framed twice");
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
        let previous = self.frames.insert(base, FrameRef::Unique(frame));
        assert!(previous.is_none(), "user page {base:#x} committed twice");
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
                },
            );
        }
    }

    fn drain_frames_in_range(&mut self, first: u64, last: u64) -> Vec<(u64, FrameRef)> {
        let mut tail = self.frames.split_off(&first);
        let mut rest = tail.split_off(&last);
        self.frames.append(&mut rest);
        tail.into_iter().collect()
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
        self.protect_range_with_sharing(first, last, flags, |base, old_flags, _| {
            on_committed(base, old_flags);
        });
    }

    fn protect_range_with_sharing(
        &mut self,
        first: u64,
        last: u64,
        flags: PageFlags,
        mut on_committed: impl FnMut(u64, PageFlags, bool),
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
                    on_committed(base, region.flags, frame.is_shared());
                }
            }
            self.regions.remove(start);
        }
        self.insert_region(first, last, flags);
    }

    /// Drops the backing frames of `[first, last)` while keeping the mapped
    /// ranges and their access intact, returning the `(base, frame)` pairs
    /// removed.
    pub fn discard_range(&mut self, first: u64, last: u64) -> Vec<(u64, NonNull<u8>)> {
        self.discard_range_refs(first, last)
            .into_iter()
            .map(|(base, frame)| (base, frame.ptr()))
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
            .map(|(&base, frame)| (base, frame.ptr()))
            .collect()
    }

    fn committed_in_with_sharing(&self, first: u64, last: u64) -> Vec<(u64, NonNull<u8>, bool)> {
        self.frames
            .range(first..last)
            .map(|(&base, frame)| (base, frame.ptr(), frame.is_shared()))
            .collect()
    }

    /// Takes every page of `[first, last)` out of the index, returning the
    /// committed `(base, frame)` pairs that were mapped there.
    pub fn remove_range(&mut self, first: u64, last: u64) -> Vec<(u64, NonNull<u8>)> {
        self.remove_range_refs(first, last)
            .into_iter()
            .map(|(base, frame)| (base, frame.ptr()))
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
        self.drain_frame_refs().map(|frame| frame.ptr())
    }

    fn drain_frame_refs(&mut self) -> impl Iterator<Item = FrameRef> {
        self.regions.clear();
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
            // SAFETY: `skip < PAGE`, so `frame.ptr().add(skip)` stays inside this page's frame.
            let start = unsafe { frame.ptr().add(skip) };
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
        let length = output.len();
        self.runs(address, length, PageFlags::READ, |run, bytes, offset| {
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

    /// Hardware PTE model for copy-on-write tests: records every installed
    /// `(physical, flags)` entry and every shootdown span.
    #[derive(Clone)]
    struct TrackingTables {
        ptes: Arc<Mutex<BTreeMap<u64, (u64, PageFlags)>>>,
        shootdowns: Arc<Mutex<Vec<(u64, u64)>>>,
    }

    impl TrackingTables {
        fn new() -> Self {
            Self {
                ptes: Arc::new(Mutex::new(BTreeMap::new())),
                shootdowns: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn pte(&self, base: u64) -> Option<(u64, PageFlags)> {
            self.ptes.lock().get(&base).copied()
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
            let prev = self.ptes.lock().insert(base, (physical, flags));
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
            entry.1 = flags;
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
}
