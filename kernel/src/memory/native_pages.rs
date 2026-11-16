//! The page index a native user address space keeps beside its hardware
//! translation tables, shared by every backend that implements
//! `helios_hal::native`.
//!
//! The index maps each mapped user page to the user-memory frame behind it
//! and the access it was mapped with. It answers the lookups the contract's
//! operations need, the copies of [`helios_hal::native::UserSpace`] and the
//! fault path, in `O(log n)` per range rather than a scan of every page, and
//! copies each run of physically adjacent frames in one copy.
//!
//! # Concurrency
//!
//! The index is single-owner: a space holds it under the lock that also
//! serialises its page-table writes, and every method runs with that lock
//! held. Frames are reached through the kernel's direct map, never through a
//! user address.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::ptr::NonNull;

use helios_hal::native::{NativeError, UserSpace};
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
/// reachable from user mode with no more access than `flags`, and never
/// touches the kernel's half of the address space.
pub unsafe trait UserTranslation: Send + 'static {
    /// Maps page `base`, which is not mapped, to the frame at `physical`.
    /// The page goes from not present to present, so no processor holds a
    /// translation of it and no invalidation is needed.
    fn install(&mut self, base: u64, physical: u64, flags: PageFlags) -> Result<(), NativeError>;

    /// Removes page `base`, which a `map` that failed installed and no
    /// slice can have run.
    fn uninstall(&mut self, base: u64);

    /// The physical address of a user frame, from its direct-map address.
    fn physical(&self, frame: NonNull<u8>) -> u64;
}

/// A native user address space: the page index and the backend's
/// translation tables behind one spin lock, held for a table write or a
/// copy and never across a slice or an `.await`. It is the
/// [`UserSpace`] every backend publishes; see `helios_hal::native` for
/// the concurrency contract it keeps.
pub struct NativeSpace<Tables> {
    state: Mutex<SpaceState<Tables>>,
}

struct SpaceState<Tables> {
    pages: NativePages,
    tables: Tables,
}

impl<Tables: UserTranslation> NativeSpace<Tables> {
    /// An empty space whose user range is `[start, end)`.
    pub fn new(tables: Tables, start: u64, end: u64) -> Self {
        Self {
            state: Mutex::new(SpaceState {
                pages: NativePages::new(start, end),
                tables,
            }),
        }
    }

    /// Runs `operation` on the translation tables under the space's lock,
    /// as a slice's entry does to read the root it loads.
    pub fn with_tables<Output>(&self, operation: impl FnOnce(&mut Tables) -> Output) -> Output {
        operation(&mut self.state.lock().tables)
    }
}

impl<Tables: UserTranslation> SpaceState<Tables> {
    fn install(&mut self, first: u64, last: u64, flags: PageFlags) -> Result<(), NativeError> {
        let processor = helios_hal::cpu::current_processor();
        for base in (first..last).step_by(PAGE as usize) {
            let Ok(frame) = allocate_user_frame_zeroed_on(processor) else {
                self.remove(first, base);
                return Err(NativeError::OutOfMemory);
            };
            let physical = self.tables.physical(frame);
            if let Err(error) = self.tables.install(base, physical, flags) {
                deallocate_user_frame_on(processor, frame);
                self.remove(first, base);
                return Err(error);
            }
            self.pages.insert(base, NativePage { frame, flags });
        }
        Ok(())
    }

    fn remove(&mut self, first: u64, last: u64) {
        let processor = helios_hal::cpu::current_processor();
        for (base, page) in self.pages.remove_range(first, last) {
            self.tables.uninstall(base);
            deallocate_user_frame_on(processor, page.frame);
        }
    }
}

// SAFETY: every user page maps a frame this space allocated, with the flags
// it was mapped with, through a translation that keeps `UserTranslation`'s
// contract.
unsafe impl<Tables: UserTranslation> UserSpace for NativeSpace<Tables> {
    fn map(&self, range: VirtRange, contents: &[u8], flags: PageFlags) -> Result<(), NativeError> {
        if contents.len() > range.byte_len {
            return Err(NativeError::Address);
        }
        if flags.contains(PageFlags::WRITE | PageFlags::EXECUTE) {
            return Err(NativeError::Permissions);
        }
        let start = range.start.raw() as u64;
        let mut state = self.state.lock();
        let (first, last) = state.pages.span(start, range.byte_len as u64)?;
        if state.pages.overlaps(first, last) {
            return Err(NativeError::Overlap);
        }
        state.install(first, last, flags)?;
        state
            .pages
            .write(start, contents, PageFlags::empty())
            .expect("installed pages cover the range");
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
        if flags.contains(PageFlags::WRITE | PageFlags::EXECUTE) {
            return Err(NativeError::Permissions);
        }
        let mut state = self.state.lock();
        let start = state
            .pages
            .free_range(hint.raw() as u64, byte_len as u64)
            .ok_or(NativeError::OutOfMemory)?;
        state.install(start, start + byte_len as u64, flags)?;
        Ok(VirtRange::new(VirtAddr::new(start as usize), byte_len))
    }

    fn read(&self, address: VirtAddr, output: &mut [u8]) -> Result<(), NativeError> {
        self.state.lock().pages.read(address.raw() as u64, output)
    }

    fn check_writable(&self, address: VirtAddr, byte_len: usize) -> Result<(), NativeError> {
        self.state.lock().pages.runs(
            address.raw() as u64,
            byte_len,
            PageFlags::WRITE,
            |_, _, _| {},
        )
    }

    fn write(&self, address: VirtAddr, bytes: &[u8]) -> Result<(), NativeError> {
        self.state
            .lock()
            .pages
            .write(address.raw() as u64, bytes, PageFlags::WRITE)
    }
}

impl<Tables> Drop for NativeSpace<Tables> {
    fn drop(&mut self) {
        // No slice outlives the borrow of this space, and every slice's exit
        // left no translation of it usable on its processor.
        let processor = helios_hal::cpu::current_processor();
        for page in self.state.get_mut().pages.drain() {
            deallocate_user_frame_on(processor, page.frame);
        }
    }
}

/// A mapped user page: its frame's direct-map address and its access.
#[derive(Clone, Copy, Debug)]
pub struct NativePage {
    pub frame: NonNull<u8>,
    pub flags: PageFlags,
}

/// Every mapped page of one user address space, by page address.
pub struct NativePages {
    pages: BTreeMap<u64, NativePage>,
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
            pages: BTreeMap::new(),
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

    pub fn overlaps(&self, first: u64, last: u64) -> bool {
        self.pages.range(first..last).next().is_some()
    }

    pub fn get(&self, base: u64) -> Option<NativePage> {
        self.pages.get(&base).copied()
    }

    pub fn insert(&mut self, base: u64, page: NativePage) {
        let previous = self.pages.insert(base, page);
        assert!(previous.is_none(), "user page {base:#x} mapped twice");
    }

    /// Takes every page of `[first, last)` out of the index.
    pub fn remove_range(&mut self, first: u64, last: u64) -> Vec<(u64, NativePage)> {
        let bases: Vec<u64> = self
            .pages
            .range(first..last)
            .map(|(base, _)| *base)
            .collect();
        bases
            .into_iter()
            .map(|base| (base, self.pages.remove(&base).expect("collected page")))
            .collect()
    }

    /// Takes every page out of the index.
    pub fn drain(&mut self) -> impl Iterator<Item = NativePage> {
        core::mem::take(&mut self.pages).into_values()
    }

    /// The first free page-aligned range of `length` bytes at or above
    /// `hint`, else at or above the start of the user range.
    pub fn free_range(&self, hint: u64, length: u64) -> Option<u64> {
        self.find(hint, length)
            .or_else(|| self.find(self.start, length))
    }

    fn find(&self, from: u64, length: u64) -> Option<u64> {
        let mut candidate = (from & !(PAGE - 1)).max(self.start);
        loop {
            let end = candidate
                .checked_add(length)
                .filter(|end| *end <= self.end)?;
            match self.pages.range(candidate..end).next_back() {
                Some((base, _)) => candidate = base + PAGE,
                None => return Some(candidate),
            }
        }
    }

    /// Visits `[address, address + length)` as runs of physically adjacent
    /// frames, after checking that every page is mapped with `access`:
    /// `visit(run, offset)` receives the run's bytes through the direct map
    /// and the run's offset within the range. Nothing is visited when any
    /// page fails the check.
    pub fn runs(
        &self,
        address: u64,
        length: usize,
        access: PageFlags,
        mut visit: impl FnMut(NonNull<u8>, usize, usize),
    ) -> Result<(), NativeError> {
        if length == 0 {
            return Ok(());
        }
        let (first, last) = self.span(address, length as u64)?;
        let pages = self.pages.range(first..last);
        let mut expected = first;
        for (base, page) in pages.clone() {
            if *base != expected || !page.flags.contains(access) {
                return Err(NativeError::NotMapped);
            }
            expected += PAGE;
        }
        if expected != last {
            return Err(NativeError::NotMapped);
        }
        let mut done = 0usize;
        let mut run: Option<(NonNull<u8>, usize)> = None;
        for (base, page) in pages {
            let skip = if *base < address {
                (address - base) as usize
            } else {
                0
            };
            let take = (PAGE as usize - skip).min(length - done - run.map_or(0, |(_, n)| n));
            // SAFETY: `skip` lies inside this page's frame.
            let start = unsafe { NonNull::new_unchecked(page.frame.as_ptr().add(skip)) };
            run = match run {
                Some((head, bytes))
                    // SAFETY: one past the run's last byte, inside or at the
                    // end of the run's last frame.
                    if unsafe { head.as_ptr().add(bytes) } == start.as_ptr() =>
                {
                    Some((head, bytes + take))
                }
                Some((head, bytes)) => {
                    visit(head, bytes, done);
                    done += bytes;
                    Some((start, take))
                }
                None => Some((start, take)),
            };
        }
        if let Some((head, bytes)) = run {
            visit(head, bytes, done);
        }
        Ok(())
    }

    /// Copies `output.len()` readable bytes from `address`.
    pub fn read(&self, address: u64, output: &mut [u8]) -> Result<(), NativeError> {
        let length = output.len();
        self.runs(address, length, PageFlags::READ, |run, bytes, offset| {
            // SAFETY: the run lies inside frames this index owns, which stay
            // allocated while the owner's lock is held.
            let source = unsafe { core::slice::from_raw_parts(run.as_ptr(), bytes) };
            output[offset..offset + bytes].copy_from_slice(source);
        })
    }

    /// Copies `bytes` to `address`, every page of which must be writable;
    /// `access` is the access the copy requires, empty for the initial
    /// contents a fresh mapping receives.
    pub fn write(&self, address: u64, bytes: &[u8], access: PageFlags) -> Result<(), NativeError> {
        self.runs(address, bytes.len(), access, |run, length, offset| {
            // SAFETY: as in `read`.
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
        NativePage { frame, flags }
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
}
