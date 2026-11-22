//! The memory-map system calls: `mmap`, `munmap`, `mprotect`, `mremap`,
//! `madvise`, `msync` and `brk` on anonymous and file-backed mappings.
//!
//! Each follows the order in which Linux checks its arguments and walks
//! its mappings, so a caller sees the same errno and the same partial
//! effect. Linux's unit of mapping is the VMA; here it is a [`Region`], a
//! run of pages mapped contiguously with one access. Source references are
//! to the Linux kernel's mm/ directory.

use super::*;
use alloc::vec::Vec;
use helios_hal::fs::{NodeKind, WritePosition};
use helios_unix::FDFLAG_PATH;

// include/uapi/asm-generic/mman-common.h, which both ABIs use.
const PROT_READ: u64 = 0x1;
const PROT_WRITE: u64 = 0x2;
const PROT_EXEC: u64 = 0x4;
const PROT_SEM: u64 = 0x8;
const PROT_GROWSDOWN: u64 = 0x0100_0000;
const PROT_GROWSUP: u64 = 0x0200_0000;
const MAP_TYPE: u64 = 0x0f;
const MAP_SHARED: u64 = 0x01;
const MAP_PRIVATE: u64 = 0x02;
const MAP_SHARED_VALIDATE: u64 = 0x03;
const MAP_FIXED: u64 = 0x10;
const MAP_ANONYMOUS: u64 = 0x20;
const MAP_DENYWRITE: u64 = 0x0800;
const MAP_EXECUTABLE: u64 = 0x1000;
const MAP_LOCKED: u64 = 0x2000;
const MAP_NORESERVE: u64 = 0x4000;
const MAP_POPULATE: u64 = 0x8000;
const MAP_NONBLOCK: u64 = 0x1_0000;
const MAP_STACK: u64 = 0x2_0000;
const MAP_FIXED_NOREPLACE: u64 = 0x10_0000;
const KNOWN_MAP_FLAGS: u64 = MAP_TYPE
    | MAP_FIXED
    | MAP_ANONYMOUS
    | MAP_DENYWRITE
    | MAP_EXECUTABLE
    | MAP_LOCKED
    | MAP_NORESERVE
    | MAP_POPULATE
    | MAP_NONBLOCK
    | MAP_STACK
    | MAP_FIXED_NOREPLACE;

// include/uapi/asm-generic/mman-common.h: msync(2) flags.
const MS_ASYNC: u64 = 1;
const MS_INVALIDATE: u64 = 2;
const MS_SYNC: u64 = 4;

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

/// One active `MAP_SHARED` file-backed range tracked by a process so writes
/// through the mapping are flushed back to the backing file on `msync`,
/// `munmap`, `mremap`, `read`, `fsync`, and process exit, and `write(2)`
/// updates to the same file are reflected back into the mapping.
#[derive(Clone)]
pub(super) struct SharedFileMapping<F> {
    pub start: u64,
    pub len: u64,
    pub file: F,
    pub file_offset: u64,
    /// Whether the mapping's descriptor permitted writing (`VM_MAYWRITE`).
    pub may_write: bool,
    /// Whether the mapping is currently (or was ever) writable.
    pub writable: bool,
}

impl<F> SharedFileMapping<F> {
    fn end(&self) -> u64 {
        self.start.saturating_add(self.len)
    }
}

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

/// Flushes a single `(start, len, file, file_offset)` range back to `file`,
/// clamped to the file's current size (POSIX/Linux `mmap` never extends a file
/// via writes past EOF).
async fn flush_one_range<R: Resources, M: UserMemory, F: fs::Filesystem<R>>(
    start: u64,
    len: u64,
    file: &R::File,
    file_offset: u64,
    creds: &Credentials,
    memory: &M,
    fs: &mut F,
) {
    let Ok(stat) = fs.stat_file(file).await else {
        return;
    };
    if file_offset >= stat.size {
        return;
    }
    let valid_len = len.min(stat.size - file_offset);
    let mut buf = [0u8; 4096];
    let mut done = 0u64;
    while done < valid_len {
        let addr = start + done;
        let page_base = addr & !4095;
        let into_page = (addr - page_base) as usize;
        let page_rem = (4096 - into_page) as u64;
        let step = (valid_len - done).min(page_rem) as usize;
        // Skip copy-on-write shared pages untouched since `fork(2)` so an
        // exiting or execing child never clobbers post-fork writes to the
        // backing file with its stale pre-fork snapshot.
        if !memory.is_page_shared(page_base) && memory.read(addr, &mut buf[..step]).is_ok() {
            let _ = fs
                .write_at(
                    file,
                    WritePosition::At(file_offset + done),
                    &buf[..step],
                    creds,
                )
                .await;
        }
        done += step as u64;
    }
}

/// Collects clipped writable shared-mapping segments overlapping `[start, end)`.
fn snapshot_overlapping<R: Resources>(
    process: &Process<R>,
    start: u64,
    end: u64,
    writable_only: bool,
) -> Vec<(u64, u64, R::File, u64)> {
    let guard = process.shared.shared_mappings.lock();
    let mut out = Vec::new();
    for m in guard.iter() {
        if writable_only && !m.writable {
            continue;
        }
        let ov_start = m.start.max(start);
        let ov_end = m.end().min(end);
        if ov_start < ov_end {
            let delta = ov_start - m.start;
            out.push((
                ov_start,
                ov_end - ov_start,
                m.file.clone(),
                m.file_offset + delta,
            ));
        }
    }
    out
}

/// Removes or splits any `SharedFileMapping` overlapping `[start, end)`.
fn remove_shared_range<R: Resources>(process: &Process<R>, start: u64, end: u64) {
    let mut guard = process.shared.shared_mappings.lock();
    let mut next = Vec::with_capacity(guard.len());
    for m in guard.drain(..) {
        let m_end = m.end();
        if m_end <= start || m.start >= end {
            next.push(m);
            continue;
        }
        if m.start < start {
            next.push(SharedFileMapping {
                start: m.start,
                len: start - m.start,
                file: m.file.clone(),
                file_offset: m.file_offset,
                may_write: m.may_write,
                writable: m.writable,
            });
        }
        if m_end > end {
            let delta = end - m.start;
            next.push(SharedFileMapping {
                start: end,
                len: m_end - end,
                file: m.file,
                file_offset: m.file_offset + delta,
                may_write: m.may_write,
                writable: m.writable,
            });
        }
    }
    *guard = next;
}

/// Flushes every writable `MAP_SHARED` mapping overlapping `[start, end)`.
async fn flush_shared_range<R: Resources, M: UserMemory, F: fs::Filesystem<R>>(
    process: &Process<R>,
    start: u64,
    end: u64,
    memory: &M,
    fs: &mut F,
) {
    let segments = snapshot_overlapping(process, start, end, true);
    let creds = process.shared.credentials.lock().clone();
    for (seg_start, seg_len, file, file_off) in segments {
        flush_one_range(seg_start, seg_len, &file, file_off, &creds, memory, fs).await;
    }
}

/// Flushes all writable `MAP_SHARED` mappings backed by `file`.
pub(super) async fn flush_file_shared_mappings<
    R: Resources,
    M: UserMemory,
    F: fs::Filesystem<R>,
>(
    process: &Process<R>,
    file: &R::File,
    memory: &M,
    fs: &mut F,
) {
    let segments: Vec<_> = {
        let guard = process.shared.shared_mappings.lock();
        guard
            .iter()
            .filter(|m| m.writable && fs.same_file(&m.file, file))
            .map(|m| (m.start, m.len, m.file.clone(), m.file_offset))
            .collect()
    };
    let creds = process.shared.credentials.lock().clone();
    for (seg_start, seg_len, f, file_off) in segments {
        flush_one_range(seg_start, seg_len, &f, file_off, &creds, memory, fs).await;
    }
}

/// Flushes every active writable `MAP_SHARED` mapping in `process`.
pub(super) async fn flush_all_shared_mappings<R: Resources, M: UserMemory, F: fs::Filesystem<R>>(
    process: &Process<R>,
    memory: &M,
    fs: &mut F,
) {
    let segments: Vec<_> = {
        let guard = process.shared.shared_mappings.lock();
        guard
            .iter()
            .filter(|m| m.writable)
            .map(|m| (m.start, m.len, m.file.clone(), m.file_offset))
            .collect()
    };
    let creds = process.shared.credentials.lock().clone();
    for (seg_start, seg_len, f, file_off) in segments {
        flush_one_range(seg_start, seg_len, &f, file_off, &creds, memory, fs).await;
    }
}

/// Propagates bytes written to `file` at `offset` into any active `MAP_SHARED`
/// mappings of the same file in `process`, temporarily granting write access
/// to read-only `MAP_SHARED` pages while copying.
pub(super) fn sync_write_to_shared_mappings<
    R: Resources,
    M: VirtualMemory,
    F: fs::Filesystem<R>,
>(
    process: &Process<R>,
    file: &R::File,
    offset: u64,
    bytes: &[u8],
    memory: &mut M,
    fs: &F,
) {
    if bytes.is_empty() {
        return;
    }
    let write_end = offset.saturating_add(bytes.len() as u64);
    let targets: Vec<(u64, u64, u64)> = {
        let guard = process.shared.shared_mappings.lock();
        guard
            .iter()
            .filter(|m| fs.same_file(&m.file, file))
            .filter_map(|m| {
                let map_file_end = m.file_offset.saturating_add(m.len);
                let ov_start = offset.max(m.file_offset);
                let ov_end = write_end.min(map_file_end);
                (ov_start < ov_end).then_some((
                    m.start + (ov_start - m.file_offset),
                    ov_start - offset,
                    ov_end - ov_start,
                ))
            })
            .collect()
    };
    if targets.is_empty() {
        return;
    }
    let _mm = process.shared.program_break.lock();
    for (addr, src_off, len) in targets {
        let end = addr.saturating_add(len);
        let query_end = page_align(end);
        let mut pos = addr;
        while pos < end {
            let query_start = pos & !(PAGE - 1);
            let Some(region) = memory.region(query_start, query_end) else {
                break;
            };
            if region.start >= end {
                break;
            }
            let copy_start = region.start.max(pos);
            let copy_end = region.end.min(end);
            if copy_start < copy_end {
                let slice_start = (src_off + (copy_start - addr)) as usize;
                let slice_end = slice_start + (copy_end - copy_start) as usize;
                if region.access.contains(PageFlags::WRITE) {
                    let _ = memory.write(copy_start, &bytes[slice_start..slice_end]);
                } else {
                    let p_start = copy_start & !(PAGE - 1);
                    let p_end = page_align(copy_end);
                    let p_len = p_end - p_start;
                    if p_len > 0
                        && memory
                            .protect(
                                p_start,
                                p_len,
                                region.access | PageFlags::READ | PageFlags::WRITE,
                            )
                            .is_ok()
                    {
                        let _ = memory.write(copy_start, &bytes[slice_start..slice_end]);
                        let _ = memory.protect(p_start, p_len, region.access);
                    }
                }
            }
            pos = copy_end.max(region.end);
        }
    }
}

/// `do_vmi_munmap`'s checks, then flush and removal.
async fn unmap_checked<R: Resources, M: VirtualMemory, F: fs::Filesystem<R>>(
    process: &Process<R>,
    abi: Abi,
    start: u64,
    length: u64,
    memory: &mut M,
    fs: &mut F,
) -> u64 {
    let task = abi.task_size();
    if start & (PAGE - 1) != 0 || start > task || length > task - start {
        return errno(EINVAL);
    }
    let length = page_align(length);
    if length == 0 {
        return errno(EINVAL);
    }
    let end = start + length;
    flush_shared_range(process, start, end, memory, fs).await;
    let _mm = process.shared.program_break.lock();
    remove_shared_range(process, start, end);
    unmap_clipped(start, end, memory);
    0
}

/// `mmap(addr, length, prot, flags, fd, offset)` for anonymous and file-backed
/// private/shared mappings (mm/mmap.c `do_mmap`).
pub(super) async fn mmap<R: Resources, M: VirtualMemory, F: fs::Filesystem<R>>(
    process: &Process<R>,
    abi: Abi,
    args: [u64; 6],
    memory: &mut M,
    fs: &mut F,
) -> u64 {
    let [hint, length, prot, flags, fd_raw, offset] = args;
    if length == 0 || prot & !(PROT_READ | PROT_WRITE | PROT_EXEC) != 0 {
        return errno(EINVAL);
    }
    let map_type = flags & MAP_TYPE;
    if !matches!(map_type, MAP_PRIVATE | MAP_SHARED | MAP_SHARED_VALIDATE)
        || offset & (PAGE - 1) != 0
    {
        return errno(EINVAL);
    }
    if flags & !KNOWN_MAP_FLAGS != 0 {
        return errno(EOPNOTSUPP);
    }
    let length = page_align(length);
    if length == 0 {
        return errno(ENOMEM);
    }
    if (offset / PAGE).checked_add(length / PAGE).is_none() {
        return errno(EOVERFLOW);
    }
    let is_shared = matches!(map_type, MAP_SHARED | MAP_SHARED_VALIDATE);
    let is_anon = flags & MAP_ANONYMOUS != 0;
    let access = access(prot);

    let file_backing: Option<(R::File, bool, u64)> = if is_anon {
        None
    } else {
        let fd = fd_raw as u32 as i32;
        let Some(entry) = process.shared.descriptors.lock().get_entry(fd).cloned() else {
            return errno(EBADF);
        };
        if entry.fdflags() & FDFLAG_PATH != 0 {
            return errno(EBADF);
        }
        let file = match &entry.descriptor {
            FileDescriptor::File(open) => open.node().clone(),
            FileDescriptor::Preopen { descriptor, .. } => descriptor.clone(),
            _ => return errno(ENODEV),
        };
        let file_access = fs.file_access(&file);
        if !file_access.readable() {
            return errno(EACCES);
        }
        if is_shared && (prot & PROT_WRITE != 0) && !file_access.writable() {
            return errno(EACCES);
        }
        if (prot & PROT_EXEC != 0) && !fs.can_exec_file(&file) {
            return errno(EPERM);
        }
        // Flush any dirty MAP_SHARED pages of this file first so the new mapping
        // starts with up-to-date contents.
        flush_file_shared_mappings(process, &file, memory, fs).await;
        let stat = match fs.stat_file(&file).await {
            Ok(stat) => stat,
            Err(error) => return fs::fs_errno(error),
        };
        if stat.kind != NodeKind::File {
            return errno(ENODEV);
        }
        Some((file, file_access.writable(), stat.size))
    };

    let task = abi.task_size();
    let is_fixed = flags & (MAP_FIXED | MAP_FIXED_NOREPLACE) != 0;
    if is_fixed {
        if length > task || hint > task - length {
            return errno(ENOMEM);
        }
        if hint & (PAGE - 1) != 0 {
            return errno(EINVAL);
        }
        if hint < memory.lowest_address() {
            return map_errno(MapError::Address);
        }
        if flags & MAP_FIXED_NOREPLACE == 0 {
            // Flush any shared mappings replaced by `MAP_FIXED` before unmapping.
            flush_shared_range(process, hint, hint + length, memory, fs).await;
        }
    } else if length > task {
        return errno(ENOMEM);
    }

    // Install the virtual range (temporarily writable if we need to copy file
    // contents into a read-only or PROT_NONE mapping).
    let initial_access = if file_backing.is_some() {
        PageFlags::READ | PageFlags::WRITE
    } else {
        access
    };

    let mapped_addr = {
        let _mm = process.shared.program_break.lock();
        if !is_fixed {
            match memory.map_anywhere(hint & !(PAGE - 1), length, initial_access) {
                Ok(addr) => addr,
                Err(error) => return map_errno(error),
            }
        } else {
            if flags & MAP_FIXED_NOREPLACE != 0 {
                if memory.region(hint, hint + length).is_some() {
                    return errno(EEXIST);
                }
            } else {
                remove_shared_range(process, hint, hint + length);
                memory.unmap(hint, length);
            }
            match memory.map_at(hint, length, initial_access) {
                Ok(()) => hint,
                Err(error) => return map_errno(error),
            }
        }
    };

    if let Some((file, may_write, file_size)) = file_backing {
        if offset < file_size {
            let to_load = length.min(file_size - offset);
            const CHUNK: usize = 64 * 1024;
            let mut filled = 0u64;
            while filled < to_load {
                let want = (to_load - filled).min(CHUNK as u64) as usize;
                let bytes = match fs.read_at(&file, offset + filled, want).await {
                    Ok(bytes) => bytes,
                    Err(error) => {
                        let _mm = process.shared.program_break.lock();
                        memory.unmap(mapped_addr, length);
                        return fs::fs_errno(error);
                    }
                };
                if bytes.is_empty() {
                    break;
                }
                if memory.write(mapped_addr + filled, &bytes).is_err() {
                    let _mm = process.shared.program_break.lock();
                    memory.unmap(mapped_addr, length);
                    return errno(EFAULT);
                }
                filled += bytes.len() as u64;
                if bytes.len() < want {
                    break;
                }
            }
        }
        if initial_access != access {
            let _mm = process.shared.program_break.lock();
            if let Err(error) = memory.protect(mapped_addr, length, access) {
                memory.unmap(mapped_addr, length);
                return map_errno(error);
            }
        }
        if is_shared {
            process
                .shared
                .shared_mappings
                .lock()
                .push(SharedFileMapping {
                    start: mapped_addr,
                    len: length,
                    file,
                    file_offset: offset,
                    may_write,
                    writable: access.contains(PageFlags::WRITE),
                });
        }
    }

    mapped_addr
}

/// `munmap(addr, length)` (mm/mmap.c `__vm_munmap`).
pub(super) async fn munmap<R: Resources, M: VirtualMemory, F: fs::Filesystem<R>>(
    process: &Process<R>,
    abi: Abi,
    args: [u64; 6],
    memory: &mut M,
    fs: &mut F,
) -> u64 {
    unmap_checked(process, abi, args[0], args[1], memory, fs).await
}

/// `msync(addr, length, flags)` (mm/msync.c).
pub(super) async fn msync<R: Resources, M: VirtualMemory, F: fs::Filesystem<R>>(
    process: &Process<R>,
    abi: Abi,
    args: [u64; 6],
    memory: &M,
    fs: &mut F,
) -> u64 {
    let [start, requested, flags, ..] = args;
    if flags & !(MS_ASYNC | MS_INVALIDATE | MS_SYNC) != 0 {
        return errno(EINVAL);
    }
    if (flags & MS_ASYNC != 0) && (flags & MS_SYNC != 0) {
        return errno(EINVAL);
    }
    if start & (PAGE - 1) != 0 {
        return errno(EINVAL);
    }
    if requested == 0 {
        return 0;
    }
    let length = page_align(requested);
    let Some(end) = start.checked_add(length).filter(|end| *end > start) else {
        return errno(ENOMEM);
    };
    let task = abi.task_size();
    let mut hole = end > task;
    let clamped_end = end.min(task);
    let mut position = start;
    while position < clamped_end {
        let Some(region) = memory.region(position, clamped_end) else {
            hole = true;
            break;
        };
        if region.start != position {
            hole = true;
        }
        position = region.end;
    }

    let segments = snapshot_overlapping(process, start, clamped_end, true);
    let creds = process.shared.credentials.lock().clone();
    for (seg_start, seg_len, file, file_off) in segments {
        flush_one_range(seg_start, seg_len, &file, file_off, &creds, memory, fs).await;
        if flags & MS_SYNC != 0
            && let Err(error) = fs.sync(&file, false).await
        {
            return fs::fs_errno(error);
        }
    }

    if hole { errno(ENOMEM) } else { 0 }
}

fn mark_shared_writable<R: Resources>(process: &Process<R>, start: u64, end: u64) {
    if start >= end {
        return;
    }
    let mut shared = process.shared.shared_mappings.lock();
    for m in shared.iter_mut() {
        if m.start < end && m.end() > start {
            m.writable = true;
        }
    }
}

/// `mprotect(addr, length, prot)` (mm/mprotect.c `do_mprotect_pkey`).
/// Regions are changed in address order; a hole after the first ends the
/// walk with `ENOMEM` and leaves the regions before it changed.
pub(super) fn mprotect<R: Resources, M: VirtualMemory>(
    process: &Process<R>,
    abi: Abi,
    args: [u64; 6],
    memory: &mut M,
) -> u64 {
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
    if prot & !(PROT_READ | PROT_WRITE | PROT_EXEC | PROT_SEM) != 0 {
        return errno(EINVAL);
    }
    let _mm = process.shared.program_break.lock();
    let Some(first) = memory.region(start, end.min(abi.task_size())) else {
        return errno(ENOMEM);
    };
    if grows != 0 {
        return errno(EINVAL);
    }
    if first.start > start {
        return errno(ENOMEM);
    }
    // Check `VM_MAYWRITE` for any overlapping `MAP_SHARED` file mapping.
    if prot & PROT_WRITE != 0 {
        let shared = process.shared.shared_mappings.lock();
        for m in shared.iter() {
            if m.start < end && m.end() > start && !m.may_write {
                return errno(EACCES);
            }
        }
    }
    let access = access(prot);
    let mut position = start;
    let mut region = Some(first);
    let result = loop {
        let Some(Region {
            start: r_start,
            end: run,
            ..
        }) = region
        else {
            break errno(ENOMEM);
        };
        if r_start != position {
            break errno(ENOMEM);
        }
        if let Err(error) = memory.protect(r_start, run - r_start, access) {
            break map_errno(error);
        }
        position = run;
        if position == end {
            break 0;
        }
        region = memory.region(position, end);
    };
    if prot & PROT_WRITE != 0 {
        mark_shared_writable(process, start, position);
    }
    result
}

/// `madvise(addr, length, advice)` for the advice that frees memory
/// (mm/madvise.c).
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

struct GrownSharedTail<F> {
    mapping_start: u64,
    old_len: u64,
    new_len: u64,
    tail_addr: u64,
    tail_len: u64,
    file: F,
    tail_file_offset: u64,
}

/// Relocates any `SharedFileMapping` contained in `[from, from + old_len)` to
/// `to`. When a full mapping grew (`new_len > old_len`), keeps `m.len == old_len`
/// and returns a `GrownSharedTail` so the caller populates the newly exposed
/// file pages before expanding `m.len`.
fn move_shared_range<R: Resources>(
    process: &Process<R>,
    from: u64,
    old_len: u64,
    to: u64,
    new_len: u64,
) -> Option<GrownSharedTail<R::File>> {
    let from_end = from.saturating_add(old_len);
    let mut guard = process.shared.shared_mappings.lock();
    let mut grown_tail = None;
    for m in guard.iter_mut() {
        if m.start >= from && m.end() <= from_end {
            let offset_in_old = m.start - from;
            m.start = to + offset_in_old;
            if offset_in_old == 0 && m.len == old_len && new_len > old_len {
                grown_tail = Some(GrownSharedTail {
                    mapping_start: to,
                    old_len,
                    new_len,
                    tail_addr: to + old_len,
                    tail_len: new_len - old_len,
                    file: m.file.clone(),
                    tail_file_offset: m.file_offset.saturating_add(old_len),
                });
            }
        }
    }
    grown_tail
}

/// Populates the newly grown tail of a `MAP_SHARED` file mapping from its
/// backing file and then expands the tracked mapping length to `new_len`.
async fn populate_grown_shared_tail<R: Resources, M: VirtualMemory, F: fs::Filesystem<R>>(
    process: &Process<R>,
    tail: GrownSharedTail<R::File>,
    region_access: PageFlags,
    memory: &mut M,
    fs: &mut F,
) {
    let Ok(stat) = fs.stat_file(&tail.file).await else {
        return;
    };
    if tail.tail_file_offset < stat.size {
        let to_load = tail.tail_len.min(stat.size - tail.tail_file_offset);
        let need_temp_write = !region_access.contains(PageFlags::WRITE);
        if need_temp_write {
            let _mm = process.shared.program_break.lock();
            if memory
                .protect(
                    tail.tail_addr,
                    tail.tail_len,
                    PageFlags::READ | PageFlags::WRITE,
                )
                .is_err()
            {
                return;
            }
        }
        const CHUNK: usize = 64 * 1024;
        let mut filled = 0u64;
        let mut ok = true;
        while filled < to_load {
            let want = (to_load - filled).min(CHUNK as u64) as usize;
            let Ok(bytes) = fs
                .read_at(&tail.file, tail.tail_file_offset + filled, want)
                .await
            else {
                ok = false;
                break;
            };
            if bytes.is_empty() {
                break;
            }
            if memory.write(tail.tail_addr + filled, &bytes).is_err() {
                ok = false;
                break;
            }
            filled += bytes.len() as u64;
            if bytes.len() < want {
                break;
            }
        }
        if need_temp_write {
            let _mm = process.shared.program_break.lock();
            let _ = memory.protect(tail.tail_addr, tail.tail_len, region_access);
        }
        if !ok {
            return;
        }
    }
    let mut guard = process.shared.shared_mappings.lock();
    for m in guard.iter_mut() {
        if m.start == tail.mapping_start && m.len == tail.old_len {
            m.len = tail.new_len;
            break;
        }
    }
}

/// `mremap(addr, old_length, new_length, flags, new_addr)` (mm/mremap.c).
pub(super) async fn mremap<R: Resources, M: VirtualMemory, F: fs::Filesystem<R>>(
    process: &Process<R>,
    abi: Abi,
    args: [u64; 6],
    memory: &mut M,
    fs: &mut F,
) -> u64 {
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
    let region = {
        let _mm = process.shared.program_break.lock();
        match memory.region(address, task) {
            Some(region) if region.start == address => region,
            _ => return errno(EFAULT),
        }
    };
    if flags & (MREMAP_FIXED | MREMAP_DONTUNMAP) != 0 {
        return mremap_to(
            process,
            abi,
            address,
            old_length,
            new_length,
            flags,
            new_address,
            memory,
            fs,
        )
        .await;
    }
    if old_length >= new_length {
        if old_length != new_length {
            let tail = address.wrapping_add(new_length);
            let unmapped =
                unmap_checked(process, abi, tail, old_length - new_length, memory, fs).await;
            if unmapped != 0 {
                return unmapped;
            }
        }
        return address;
    }
    if let Err(result) = resizable(address, old_length, region) {
        return result;
    }
    let (result_addr, grown_tail) = {
        let _mm = process.shared.program_break.lock();
        if old_length == region.end - address {
            let delta = new_length - old_length;
            if region
                .end
                .checked_add(delta)
                .is_some_and(|end| end <= task && memory.region(region.end, end).is_none())
            {
                match memory.map_at(region.end, delta, region.access) {
                    Ok(()) => {
                        let tail =
                            move_shared_range(process, address, old_length, address, new_length);
                        (Ok(address), tail)
                    }
                    Err(error) => (Err(map_errno(error)), None),
                }
            } else if flags & MREMAP_MAYMOVE == 0 {
                (Err(errno(ENOMEM)), None)
            } else if let Some(target) = (new_length <= task)
                .then(|| memory.free_range(0, new_length))
                .flatten()
            {
                match memory.remap(address, old_length, target, new_length) {
                    Ok(()) => {
                        let tail =
                            move_shared_range(process, address, old_length, target, new_length);
                        (Ok(target), tail)
                    }
                    Err(error) => (Err(map_errno(error)), None),
                }
            } else {
                (Err(errno(ENOMEM)), None)
            }
        } else if flags & MREMAP_MAYMOVE == 0 {
            (Err(errno(ENOMEM)), None)
        } else if let Some(target) = (new_length <= task)
            .then(|| memory.free_range(0, new_length))
            .flatten()
        {
            match memory.remap(address, old_length, target, new_length) {
                Ok(()) => {
                    let tail = move_shared_range(process, address, old_length, target, new_length);
                    (Ok(target), tail)
                }
                Err(error) => (Err(map_errno(error)), None),
            }
        } else {
            (Err(errno(ENOMEM)), None)
        }
    };
    let target = match result_addr {
        Ok(addr) => addr,
        Err(err) => return err,
    };
    if let Some(tail) = grown_tail {
        populate_grown_shared_tail(process, tail, region.access, memory, fs).await;
    }
    target
}

/// `vma_to_resize`'s checks on a region, `Err` holding the result.
fn resizable(address: u64, old_length: u64, region: Region) -> Result<(), u64> {
    if old_length == 0 {
        return Err(errno(EINVAL));
    }
    if old_length > region.end - address {
        return Err(errno(EFAULT));
    }
    Ok(())
}

/// `mremap_to`: a move to `new_address`, or near it for `MREMAP_DONTUNMAP`.
#[allow(clippy::too_many_arguments)]
async fn mremap_to<R: Resources, M: VirtualMemory, F: fs::Filesystem<R>>(
    process: &Process<R>,
    abi: Abi,
    address: u64,
    mut old_length: u64,
    new_length: u64,
    flags: u64,
    new_address: u64,
    memory: &mut M,
    fs: &mut F,
) -> u64 {
    let task = abi.task_size();
    if new_address & (PAGE - 1) != 0 || new_length > task || new_address > task - new_length {
        return errno(EINVAL);
    }
    if address.wrapping_add(old_length) > new_address && new_address + new_length > address {
        return errno(EINVAL);
    }
    if flags & MREMAP_FIXED != 0 {
        let unmapped = unmap_checked(process, abi, new_address, new_length, memory, fs).await;
        if unmapped != 0 {
            return unmapped;
        }
    }
    if old_length > new_length {
        let tail = address.wrapping_add(new_length);
        let unmapped = unmap_checked(process, abi, tail, old_length - new_length, memory, fs).await;
        if unmapped != 0 {
            return unmapped;
        }
        old_length = new_length;
    }
    let (target, region_access, grown_tail) = {
        let _mm = process.shared.program_break.lock();
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
        let tail = move_shared_range(process, address, old_length, target, new_length);
        if flags & MREMAP_DONTUNMAP != 0 {
            if let Err(error) = memory.map_at(address, old_length, region.access) {
                return map_errno(error);
            }
            memory.discard(address, old_length);
        }
        (target, region.access, tail)
    };
    if let Some(tail) = grown_tail {
        populate_grown_shared_tail(process, tail, region_access, memory, fs).await;
    }
    target
}

/// The program break: where it started and where the process last set it.
#[derive(Clone)]
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

    /// `brk(requested)` (mm/mmap.c).
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
