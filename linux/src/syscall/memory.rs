//! The memory-map system calls: `mmap`, `munmap`, `mprotect`, `mremap`,
//! `madvise` and `brk` on anonymous private memory.
//!
//! Each follows the order in which Linux checks its arguments and walks
//! its mappings, so a caller sees the same errno and the same partial
//! effect. Linux's unit of mapping is the VMA; here it is a [`Region`], a
//! run of pages mapped contiguously with one access, which is what Linux's
//! VMAs of anonymous private memory merge into. Source references are to
//! the Linux kernel's mm/ directory.

use super::*;

// include/uapi/asm-generic/mman-common.h, which both ABIs use.
const PROT_READ: u64 = 0x1;
const PROT_WRITE: u64 = 0x2;
const PROT_EXEC: u64 = 0x4;
const PROT_SEM: u64 = 0x8;
const PROT_GROWSDOWN: u64 = 0x0100_0000;
const PROT_GROWSUP: u64 = 0x0200_0000;
const MAP_TYPE: u64 = 0x0f;
const MAP_PRIVATE: u64 = 0x02;
const MAP_FIXED: u64 = 0x10;
const MAP_ANONYMOUS: u64 = 0x20;
const MAP_FIXED_NOREPLACE: u64 = 0x10_0000;
const MADV_DONTNEED: u64 = 4;
const MADV_FREE: u64 = 8;
// include/uapi/linux/mman.h.
const MREMAP_MAYMOVE: u64 = 1;
const MREMAP_FIXED: u64 = 2;
const MREMAP_DONTUNMAP: u64 = 4;
// Linux uapi/asm-generic/errno-base.h.
const EEXIST: u64 = 17;
const EOVERFLOW: u64 = 75;

/// Both ABIs' Linux page size: x86-64 always, arm64 in its 4 KiB
/// configuration, which Helios's TTBR0 translation granule is.
const PAGE: u64 = 4096;

/// `PAGE_ALIGN`: rounds up to a page, wrapping as Linux's unsigned
/// arithmetic does.
fn page_align(length: u64) -> u64 {
    length.wrapping_add(PAGE - 1) & !(PAGE - 1)
}

/// The access `prot` grants. Both ISAs read from writable or executable
/// pages, as Linux's `protection_map` makes them.
fn access(prot: u64) -> PageFlags {
    let mut flags = PageFlags::empty();
    flags.set(
        PageFlags::READ,
        prot & (PROT_READ | PROT_WRITE | PROT_EXEC) != 0,
    );
    flags.set(PageFlags::WRITE, prot & PROT_WRITE != 0);
    flags.set(PageFlags::EXECUTE, prot & PROT_EXEC != 0);
    flags
}

fn map_errno(error: MapError) -> u64 {
    errno(match error {
        MapError::OutOfMemory => ENOMEM,
        // The native W^X policy, refused as a security module refuses a
        // mapping.
        MapError::Permission => EPERM,
        // Below the lowest mappable address: `security_mmap_addr`'s
        // `mmap_min_addr` refusal.
        MapError::Address => EPERM,
        MapError::Occupied => EEXIST,
    })
}

/// Removes `[start, end)` from the space, after clipping it to the
/// addresses the space maps; Linux's `do_vmi_munmap` accepts any page
/// range below `TASK_SIZE`.
fn unmap_clipped<M: VirtualMemory>(start: u64, end: u64, memory: &mut M) {
    let start = start.max(memory.lowest_address());
    if start < end {
        memory.unmap(start, end - start);
    }
}

/// `do_vmi_munmap`'s checks, then the removal.
fn unmap_checked<M: VirtualMemory>(abi: Abi, start: u64, length: u64, memory: &mut M) -> u64 {
    let task = abi.task_size();
    if start & (PAGE - 1) != 0 || start > task || length > task - start {
        return errno(EINVAL);
    }
    let length = page_align(length);
    if length == 0 {
        return errno(EINVAL);
    }
    unmap_clipped(start, start + length, memory);
    0
}

/// `mmap(addr, length, prot, flags, fd, offset)` for anonymous private
/// memory (mm/mmap.c `do_mmap`).
pub(super) fn mmap<M: VirtualMemory>(abi: Abi, args: [u64; 6], memory: &mut M) -> u64 {
    let [hint, length, prot, flags, fd, offset] = args;
    if length == 0 || prot & !(PROT_READ | PROT_WRITE | PROT_EXEC) != 0 {
        return errno(EINVAL);
    }
    if flags & MAP_TYPE != MAP_PRIVATE || offset & (PAGE - 1) != 0 {
        return errno(EINVAL);
    }
    if flags & MAP_ANONYMOUS == 0 {
        // Output streams are valid descriptors but cannot back a mapping.
        return errno(if matches!(fd as u32, 1 | 2) {
            ENODEV
        } else {
            EBADF
        });
    }
    if flags & !(MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED | MAP_FIXED_NOREPLACE) != 0 {
        return errno(EOPNOTSUPP);
    }
    // The native W^X policy.
    if prot & (PROT_WRITE | PROT_EXEC) == PROT_WRITE | PROT_EXEC {
        return errno(EPERM);
    }
    let length = page_align(length);
    if length == 0 {
        return errno(ENOMEM);
    }
    if (offset / PAGE).checked_add(length / PAGE).is_none() {
        return errno(EOVERFLOW);
    }
    let access = access(prot);
    let task = abi.task_size();
    if flags & (MAP_FIXED | MAP_FIXED_NOREPLACE) == 0 {
        if length > task {
            return errno(ENOMEM);
        }
        return memory
            .map_anywhere(hint & !(PAGE - 1), length, access)
            .unwrap_or_else(map_errno);
    }
    // `__get_unmapped_area` with MAP_FIXED.
    if length > task || hint > task - length {
        return errno(ENOMEM);
    }
    if hint & (PAGE - 1) != 0 {
        return errno(EINVAL);
    }
    if hint < memory.lowest_address() {
        return map_errno(MapError::Address);
    }
    if flags & MAP_FIXED_NOREPLACE != 0 {
        if memory.region(hint, hint + length).is_some() {
            return errno(EEXIST);
        }
    } else {
        // `mmap_region` unmaps what the new mapping replaces; a failure
        // after this leaves the range unmapped, as Linux's does.
        memory.unmap(hint, length);
    }
    match memory.map_at(hint, length, access) {
        Ok(()) => hint,
        Err(error) => map_errno(error),
    }
}

/// `munmap(addr, length)` (mm/mmap.c `__vm_munmap`).
pub(super) fn munmap<M: VirtualMemory>(abi: Abi, args: [u64; 6], memory: &mut M) -> u64 {
    unmap_checked(abi, args[0], args[1], memory)
}

/// `mprotect(addr, length, prot)` (mm/mprotect.c `do_mprotect_pkey`).
/// Regions are changed in address order; a hole after the first ends the
/// walk with `ENOMEM` and leaves the regions before it changed.
pub(super) fn mprotect<M: VirtualMemory>(abi: Abi, args: [u64; 6], memory: &mut M) -> u64 {
    let [start, length, prot, ..] = args;
    let grows = prot & (PROT_GROWSDOWN | PROT_GROWSUP);
    let prot = prot & !grows;
    if grows == PROT_GROWSDOWN | PROT_GROWSUP || start & (PAGE - 1) != 0 {
        return errno(EINVAL);
    }
    if length == 0 {
        return 0;
    }
    let length = page_align(length);
    let Some(end) = start.checked_add(length).filter(|end| *end > start) else {
        return errno(ENOMEM);
    };
    // `arch_validate_prot`: x86-64 and arm64 both accept the generic bits;
    // arm64's PROT_BTI and PROT_MTE need hardware features Helios does not
    // enable for user mode, so they are refused as on hardware without
    // them.
    if prot & !(PROT_READ | PROT_WRITE | PROT_EXEC | PROT_SEM) != 0 {
        return errno(EINVAL);
    }
    let Some(first) = memory.region(start, end.min(abi.task_size())) else {
        return errno(ENOMEM);
    };
    if grows != 0 {
        // No mapping of a Helios process grows: PROT_GROWSDOWN needs a
        // VM_GROWSDOWN mapping, PROT_GROWSUP a VM_GROWSUP one.
        return errno(EINVAL);
    }
    if first.start > start {
        return errno(ENOMEM);
    }
    if prot & (PROT_WRITE | PROT_EXEC) == PROT_WRITE | PROT_EXEC {
        return errno(EPERM);
    }
    let access = access(prot);
    let mut position = start;
    let mut region = Some(first);
    while let Some(Region {
        start, end: run, ..
    }) = region
    {
        if start != position {
            return errno(ENOMEM);
        }
        if let Err(error) = memory.protect(start, run - start, access) {
            return map_errno(error);
        }
        position = run;
        if position == end {
            return 0;
        }
        region = memory.region(position, end);
    }
    errno(ENOMEM)
}

/// `madvise(addr, length, advice)` for the advice that frees memory
/// (mm/madvise.c). Every mapped part of the range is advised; a hole
/// anywhere in it makes the result `ENOMEM` (`madvise_walk_vmas`).
///
/// `MADV_DONTNEED` and `MADV_FREE` drop the pages now: Linux may keep
/// `MADV_FREE` pages until memory is short, and reading zeros is one of
/// the two outcomes it allows. Other advice is refused with `EINVAL`, the
/// answer of a kernel built without it (`madvise_behavior_valid`).
pub(super) fn madvise<M: VirtualMemory>(args: [u64; 6], memory: &mut M) -> u64 {
    let [start, requested, advice, ..] = args;
    if !matches!(advice, MADV_DONTNEED | MADV_FREE) || start & (PAGE - 1) != 0 {
        return errno(EINVAL);
    }
    let length = page_align(requested);
    if requested != 0 && length == 0 {
        return errno(EINVAL);
    }
    let Some(end) = start.checked_add(length) else {
        return errno(EINVAL);
    };
    let mut position = start;
    let mut hole = false;
    while position < end {
        let Some(region) = memory.region(position, end) else {
            hole = true;
            break;
        };
        hole |= region.start != position;
        memory.discard(region.start, region.end - region.start);
        position = region.end;
    }
    if hole { errno(ENOMEM) } else { 0 }
}

/// `mremap(addr, old_length, new_length, flags, new_addr)` (mm/mremap.c).
pub(super) fn mremap<M: VirtualMemory>(abi: Abi, args: [u64; 6], memory: &mut M) -> u64 {
    let [address, old_length, new_length, flags, new_address, _] = args;
    if flags & !(MREMAP_MAYMOVE | MREMAP_FIXED | MREMAP_DONTUNMAP) != 0
        || (flags & MREMAP_FIXED != 0 && flags & MREMAP_MAYMOVE == 0)
        || (flags & MREMAP_DONTUNMAP != 0
            && (flags & MREMAP_MAYMOVE == 0 || old_length != new_length))
        || address & (PAGE - 1) != 0
    {
        return errno(EINVAL);
    }
    let (old_length, new_length) = (page_align(old_length), page_align(new_length));
    if new_length == 0 {
        return errno(EINVAL);
    }
    let task = abi.task_size();
    // `vma_lookup`: the region holding `address`, to its end.
    let region = match memory.region(address, task) {
        Some(region) if region.start == address => region,
        _ => return errno(EFAULT),
    };
    if flags & (MREMAP_FIXED | MREMAP_DONTUNMAP) != 0 {
        return mremap_to(
            abi,
            address,
            old_length,
            new_length,
            flags,
            new_address,
            memory,
        );
    }
    // A shrink only unmaps the tail. The sum wraps as Linux's unsigned one
    // does, and `do_vmi_munmap` then refuses it.
    if old_length >= new_length {
        if old_length != new_length {
            let tail = address.wrapping_add(new_length);
            let unmapped = unmap_checked(abi, tail, old_length - new_length, memory);
            if unmapped != 0 {
                return unmapped;
            }
        }
        return address;
    }
    if let Err(result) = resizable(address, old_length, region) {
        return result;
    }
    // In place, when the range ends the region and the pages after it are
    // free (`vma_expandable`).
    if old_length == region.end - address {
        let delta = new_length - old_length;
        if region
            .end
            .checked_add(delta)
            .is_some_and(|end| end <= task && memory.region(region.end, end).is_none())
        {
            return match memory.map_at(region.end, delta, region.access) {
                Ok(()) => address,
                Err(error) => map_errno(error),
            };
        }
    }
    if flags & MREMAP_MAYMOVE == 0 {
        return errno(ENOMEM);
    }
    let Some(target) = (new_length <= task)
        .then(|| memory.free_range(0, new_length))
        .flatten()
    else {
        return errno(ENOMEM);
    };
    match memory.remap(address, old_length, target, new_length) {
        Ok(()) => target,
        Err(error) => map_errno(error),
    }
}

/// `vma_to_resize`'s checks on a private region, `Err` holding the result.
fn resizable(address: u64, old_length: u64, region: Region) -> Result<(), u64> {
    // A zero old length duplicates a shared mapping only.
    if old_length == 0 {
        return Err(errno(EINVAL));
    }
    // A move never crosses a region boundary.
    if old_length > region.end - address {
        return Err(errno(EFAULT));
    }
    Ok(())
}

/// `mremap_to`: a move to `new_address`, or near it for
/// `MREMAP_DONTUNMAP` alone, which then leaves the old range mapped and
/// empty.
fn mremap_to<M: VirtualMemory>(
    abi: Abi,
    address: u64,
    mut old_length: u64,
    new_length: u64,
    flags: u64,
    new_address: u64,
    memory: &mut M,
) -> u64 {
    let task = abi.task_size();
    if new_address & (PAGE - 1) != 0 || new_length > task || new_address > task - new_length {
        return errno(EINVAL);
    }
    // Linux's unsigned sums wrap; `new_address + new_length` cannot, by the
    // check above.
    if address.wrapping_add(old_length) > new_address && new_address + new_length > address {
        return errno(EINVAL);
    }
    if flags & MREMAP_FIXED != 0 {
        let unmapped = unmap_checked(abi, new_address, new_length, memory);
        if unmapped != 0 {
            return unmapped;
        }
    }
    if old_length > new_length {
        let tail = address.wrapping_add(new_length);
        let unmapped = unmap_checked(abi, tail, old_length - new_length, memory);
        if unmapped != 0 {
            return unmapped;
        }
        old_length = new_length;
    }
    // The region again: the unmaps above may have shortened it.
    let region = match memory.region(address, task) {
        Some(region) if region.start == address => region,
        _ => return errno(EFAULT),
    };
    if let Err(result) = resizable(address, old_length, region) {
        return result;
    }
    let target = if flags & MREMAP_FIXED != 0 {
        if new_address < memory.lowest_address() {
            return map_errno(MapError::Address);
        }
        new_address
    } else {
        match memory.free_range(new_address, new_length) {
            Some(target) => target,
            None => return errno(ENOMEM),
        }
    };
    if let Err(error) = memory.remap(address, old_length, target, new_length) {
        return map_errno(error);
    }
    if flags & MREMAP_DONTUNMAP != 0 {
        // The old range stays mapped with its access and reads as zeros.
        if let Err(error) = memory.map_at(address, old_length, region.access) {
            return map_errno(error);
        }
        memory.discard(address, old_length);
    }
    target
}

/// The program break: where it started and where the process last set it.
pub(super) struct ProgramBreak {
    start: u64,
    current: u64,
}

impl ProgramBreak {
    pub(super) fn new(start: u64) -> Self {
        Self {
            start,
            current: start,
        }
    }

    /// `brk(requested)` (mm/mmap.c): the new break, or the unchanged one
    /// when it cannot move there. The pages between the page-aligned old
    /// and new breaks are mapped or unmapped; one free page must stay above
    /// a grown break.
    pub(super) fn set<M: VirtualMemory>(
        &mut self,
        abi: Abi,
        requested: u64,
        memory: &mut M,
    ) -> u64 {
        if requested < self.start {
            return self.current;
        }
        let new_end = page_align(requested);
        let old_end = page_align(self.current);
        if new_end == old_end {
            self.current = requested;
            return requested;
        }
        if requested <= self.current {
            if memory.region(new_end, old_end).is_none() {
                return self.current;
            }
            unmap_clipped(new_end, old_end, memory);
            self.current = requested;
            return requested;
        }
        // `check_brk_limits`, then the free page above the new break. A
        // request within a page of 2^64 wraps to a zero `new_end`.
        let task = abi.task_size();
        if new_end < requested || new_end > task {
            return self.current;
        }
        if memory.region(old_end, (new_end + PAGE).min(task)).is_some() {
            return self.current;
        }
        match memory.map_at(old_end, new_end - old_end, access(PROT_READ | PROT_WRITE)) {
            Ok(()) => {
                self.current = requested;
                requested
            }
            Err(_) => self.current,
        }
    }
}
