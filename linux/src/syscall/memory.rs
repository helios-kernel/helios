//! The memory-map system calls: `mmap`, `munmap`, `mprotect`, `mremap`,
//! `madvise`, `msync` and `brk` on anonymous and file-backed mappings.
//!
//! Each follows the order in which Linux checks its arguments and walks
//! its mappings, so a caller sees the same errno and the same partial
//! effect. Linux's unit of mapping is the VMA; here it is a [`Region`], a
//! run of pages mapped contiguously with one access, paired with tracked
//! [`SharedFileMapping`] descriptors carrying file backing, shared-object IDs,
//! `VM_MAYWRITE`, and `VM_MAYEXEC`. Source references are to the Linux
//! kernel's `mm/` directory.

use super::*;
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
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

/// Backing descriptor of a tracked VMA (file-backed, `MAP_SHARED` anonymous,
/// or SysV shared memory).
#[derive(Clone)]
pub(super) enum MappingBacking<F> {
    SharedFile {
        file: F,
        file_offset: u64,
        object_id: u64,
    },
    PrivateFile {
        file: F,
        file_offset: u64,
    },
    SharedAnon {
        object_id: u64,
        object_offset: u64,
    },
    SysvShm {
        shmid: i32,
        attach_id: u64,
        object_id: u64,
        object_offset: u64,
    },
}

impl<F: Clone> MappingBacking<F> {
    fn advance(&self, delta: u64) -> Self {
        match self {
            Self::SharedFile {
                file,
                file_offset,
                object_id,
            } => Self::SharedFile {
                file: file.clone(),
                file_offset: file_offset.saturating_add(delta),
                object_id: *object_id,
            },
            Self::PrivateFile { file, file_offset } => Self::PrivateFile {
                file: file.clone(),
                file_offset: file_offset.saturating_add(delta),
            },
            Self::SharedAnon {
                object_id,
                object_offset,
            } => Self::SharedAnon {
                object_id: *object_id,
                object_offset: object_offset.saturating_add(delta),
            },
            Self::SysvShm {
                shmid,
                attach_id,
                object_id,
                object_offset,
            } => Self::SysvShm {
                shmid: *shmid,
                attach_id: *attach_id,
                object_id: *object_id,
                object_offset: object_offset.saturating_add(delta),
            },
        }
    }

    fn is_shared(&self) -> bool {
        matches!(
            self,
            Self::SharedFile { .. } | Self::SharedAnon { .. } | Self::SysvShm { .. }
        )
    }
}

/// Public lookup record returned by [`Process::lookup_vma`] for demand-fault
/// resolution (`SIGBUS` beyond EOF or lazy file/shared frame attachment).
#[derive(Clone, Debug)]
pub struct FileVmaLookup<F> {
    pub start: u64,
    pub len: u64,
    pub file: F,
    pub file_offset: u64,
    pub is_shared: bool,
    pub shared_object: u64,
}

/// Result of looking up the tracked VMA backing a faulting address.
#[derive(Clone, Debug)]
pub enum VmaBacking<F> {
    SharedAnon {
        start: u64,
        object_id: u64,
        object_offset: u64,
    },
    File(FileVmaLookup<F>),
}

/// One tracked VMA (file-backed `MAP_SHARED` / `MAP_PRIVATE`, anonymous
/// `MAP_SHARED`, or SysV shared memory) recording its backing, `VM_MAYWRITE`,
/// `VM_MAYEXEC`, dirty-writeback eligibility, and `memfd` lifecycle holds.
#[derive(Clone)]
pub(super) struct SharedFileMapping<F> {
    pub start: u64,
    pub len: u64,
    pub backing: MappingBacking<F>,
    /// Whether the mapping's descriptor permitted writing (`VM_MAYWRITE`).
    pub may_write: bool,
    /// Whether the mapping's mount/backing permitted execution (`VM_MAYEXEC`).
    pub may_exec: bool,
    /// Whether this range is currently or was ever writable (preserved across
    /// `mprotect(PROT_NONE)` so prior dirty writes are still flushed).
    pub writable: bool,
    /// RAII hold keeping a `memfd_create(2)` inode alive while mapped.
    pub memfd_hold: Option<helios_unix::MemfdHold>,
    /// RAII hold tracking an active `MAP_SHARED` VMA with `VM_MAYWRITE` on a
    /// `memfd_create(2)` inode so `F_ADD_SEALS(F_SEAL_WRITE)` fails with `EBUSY`.
    pub memfd_write_hold: Option<helios_unix::MemfdWritableMapHold>,
}

impl<F> SharedFileMapping<F> {
    fn end(&self) -> u64 {
        self.start.saturating_add(self.len)
    }

    fn shared_file(&self) -> Option<(&F, u64, u64)> {
        match &self.backing {
            MappingBacking::SharedFile {
                file,
                file_offset,
                object_id,
            } => Some((file, *file_offset, *object_id)),
            MappingBacking::PrivateFile { .. }
            | MappingBacking::SharedAnon { .. }
            | MappingBacking::SysvShm { .. } => None,
        }
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

/// Looks up the tracked VMA containing `address`, if any.
pub(super) fn lookup_vma<R: Resources>(
    process: &Process<R>,
    address: u64,
) -> Option<VmaBacking<R::File>> {
    let guard = process.shared.shared_mappings.lock();
    for m in guard.iter() {
        if address >= m.start && address < m.end() {
            return Some(match &m.backing {
                MappingBacking::SharedFile {
                    file,
                    file_offset,
                    object_id,
                } => VmaBacking::File(FileVmaLookup {
                    start: m.start,
                    len: m.len,
                    file: file.clone(),
                    file_offset: *file_offset,
                    is_shared: true,
                    shared_object: *object_id,
                }),
                MappingBacking::PrivateFile { file, file_offset } => {
                    VmaBacking::File(FileVmaLookup {
                        start: m.start,
                        len: m.len,
                        file: file.clone(),
                        file_offset: *file_offset,
                        is_shared: false,
                        shared_object: 0,
                    })
                }
                MappingBacking::SharedAnon {
                    object_id,
                    object_offset,
                }
                | MappingBacking::SysvShm {
                    object_id,
                    object_offset,
                    ..
                } => VmaBacking::SharedAnon {
                    start: m.start,
                    object_id: *object_id,
                    object_offset: *object_offset,
                },
            });
        }
    }
    None
}

/// Flushes a single `(start, len, file, file_offset, object_id)` range back
/// to `file`, clamped to the file's current size (POSIX/Linux `mmap` never
/// extends a file via writes past EOF).
///
/// When backed by a kernel `SharedPageObject` (`object_id != 0`), writes back
/// ONLY modified byte runs compared directly against the clean baseline via
/// kernel direct-map frames (preserving dirty data across `mprotect(PROT_NONE)`
/// and never clobbering concurrent `write(2)` updates).
#[expect(
    clippy::too_many_arguments,
    reason = "flushes a single tracked range against its backing file, shared object, credentials, memory view, and filesystem"
)]
async fn flush_one_range<R: Resources, M: UserMemory, F: fs::Filesystem<R>>(
    start: u64,
    len: u64,
    file: &R::File,
    file_offset: u64,
    object_id: u64,
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
    if object_id != 0
        && let Some(dirty_runs) = memory.collect_shared_dirty(object_id, file_offset, valid_len)
    {
        for (write_off, data) in dirty_runs {
            if fs
                .write_at(file, WritePosition::At(write_off), &data, creds)
                .await
                .is_ok()
            {
                memory.mark_shared_clean(object_id, write_off, &data);
            }
        }
        return;
    }

    // Fallback for lightweight unit-test mocks without `SharedPageObject`.
    let mut buf = alloc::vec![0u8; 4096];
    let mut done = 0u64;
    while done < valid_len {
        let addr = start + done;
        let page_base = addr & !4095;
        let into_page = (addr - page_base) as usize;
        let page_rem = (4096 - into_page) as u64;
        let step = (valid_len - done).min(page_rem) as usize;
        if !memory.is_page_shared(page_base)
            && memory.read_unrestricted(addr, &mut buf[..step]).is_ok()
        {
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

/// Collects clipped writable `MAP_SHARED` file-mapping segments overlapping
/// `[start, end)`.
fn snapshot_overlapping<R: Resources>(
    process: &Process<R>,
    start: u64,
    end: u64,
    writable_only: bool,
) -> Vec<(u64, u64, R::File, u64, u64)> {
    let guard = process.shared.shared_mappings.lock();
    let mut out = Vec::new();
    for m in guard.iter() {
        if writable_only && !m.writable {
            continue;
        }
        let Some((file, file_offset, object_id)) = m.shared_file() else {
            continue;
        };
        let ov_start = m.start.max(start);
        let ov_end = m.end().min(end);
        if ov_start < ov_end {
            let delta = ov_start - m.start;
            out.push((
                ov_start,
                ov_end - ov_start,
                file.clone(),
                file_offset + delta,
                object_id,
            ));
        }
    }
    out
}

/// Removes or splits any tracked VMA overlapping `[start, end)`, returning
/// `(detached_shmids, dropped_memfd)` where `detached_shmids` lists every SysV
/// shared memory attachment whose last VMA just dropped.
fn remove_shared_range<R: Resources>(
    process: &Process<R>,
    start: u64,
    end: u64,
) -> (Vec<i32>, bool) {
    let mut guard = process.shared.shared_mappings.lock();
    let mut next = Vec::with_capacity(guard.len());
    let mut touched_shm: Vec<(u64, i32)> = Vec::new();
    let mut dropped_memfd = false;
    for m in guard.drain(..) {
        let m_end = m.end();
        if m_end <= start || m.start >= end {
            next.push(m);
            continue;
        }
        if m.memfd_hold.is_some() {
            dropped_memfd = true;
        }
        if let MappingBacking::SysvShm {
            shmid, attach_id, ..
        } = m.backing
            && !touched_shm.iter().any(|(id, _)| *id == attach_id)
        {
            touched_shm.push((attach_id, shmid));
        }
        if m.start < start {
            next.push(SharedFileMapping {
                start: m.start,
                len: start - m.start,
                backing: m.backing.clone(),
                may_write: m.may_write,
                may_exec: m.may_exec,
                writable: m.writable,
                memfd_hold: m.memfd_hold.clone(),
                memfd_write_hold: m.memfd_write_hold.clone(),
            });
        }
        if m_end > end {
            let delta = end - m.start;
            next.push(SharedFileMapping {
                start: end,
                len: m_end - end,
                backing: m.backing.advance(delta),
                may_write: m.may_write,
                may_exec: m.may_exec,
                writable: m.writable,
                memfd_hold: m.memfd_hold.clone(),
                memfd_write_hold: m.memfd_write_hold.clone(),
            });
        }
    }
    let mut detached_shmids = Vec::new();
    for (attach_id, shmid) in touched_shm {
        let still_mapped = next.iter().any(|m| {
            matches!(
                m.backing,
                MappingBacking::SysvShm {
                    attach_id: existing,
                    ..
                } if existing == attach_id
            )
        });
        if !still_mapped {
            detached_shmids.push(shmid);
        }
    }
    *guard = next;
    (detached_shmids, dropped_memfd)
}

/// Splits tracked VMAs at `start` and `end`, and marks only the `[start, end)`
/// portion `writable = true` when `set_writable` is set (preserving prior
/// `writable` on pages narrowed to read-only or `PROT_NONE`).
fn split_vmas_for_mprotect<R: Resources>(
    process: &Process<R>,
    start: u64,
    end: u64,
    set_writable: bool,
) {
    if start >= end {
        return;
    }
    let mut guard = process.shared.shared_mappings.lock();
    let mut next = Vec::with_capacity(guard.len() + 2);
    for m in guard.drain(..) {
        let m_end = m.end();
        if m_end <= start || m.start >= end {
            next.push(m);
            continue;
        }
        let ov_start = m.start.max(start);
        let ov_end = m_end.min(end);
        if m.start < ov_start {
            next.push(SharedFileMapping {
                start: m.start,
                len: ov_start - m.start,
                backing: m.backing.clone(),
                may_write: m.may_write,
                may_exec: m.may_exec,
                writable: m.writable,
                memfd_hold: m.memfd_hold.clone(),
                memfd_write_hold: m.memfd_write_hold.clone(),
            });
        }
        next.push(SharedFileMapping {
            start: ov_start,
            len: ov_end - ov_start,
            backing: m.backing.advance(ov_start - m.start),
            may_write: m.may_write,
            may_exec: m.may_exec,
            writable: m.writable || set_writable,
            memfd_hold: m.memfd_hold.clone(),
            memfd_write_hold: m.memfd_write_hold.clone(),
        });
        if ov_end < m_end {
            next.push(SharedFileMapping {
                start: ov_end,
                len: m_end - ov_end,
                backing: m.backing.advance(ov_end - m.start),
                may_write: m.may_write,
                may_exec: m.may_exec,
                writable: m.writable,
                memfd_hold: m.memfd_hold,
                memfd_write_hold: m.memfd_write_hold,
            });
        }
    }
    *guard = next;
}

/// Flushes every writable `MAP_SHARED` file mapping overlapping `[start, end)`.
async fn flush_shared_range<R: Resources, M: UserMemory, F: fs::Filesystem<R>>(
    process: &Process<R>,
    start: u64,
    end: u64,
    memory: &M,
    fs: &mut F,
) {
    let segments = snapshot_overlapping(process, start, end, true);
    let creds = process.credentials.lock().clone();
    for (seg_start, seg_len, file, file_off, object_id) in segments {
        flush_one_range(
            seg_start, seg_len, &file, file_off, object_id, &creds, memory, fs,
        )
        .await;
    }
}

/// Flushes all writable `MAP_SHARED` file mappings backed by `file`.
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
            .filter_map(|m| {
                let (m_file, file_offset, object_id) = m.shared_file()?;
                (m.writable && fs.same_file(m_file, file))
                    .then(|| (m.start, m.len, m_file.clone(), file_offset, object_id))
            })
            .collect()
    };
    let creds = process.credentials.lock().clone();
    for (seg_start, seg_len, f, file_off, object_id) in segments {
        flush_one_range(
            seg_start, seg_len, &f, file_off, object_id, &creds, memory, fs,
        )
        .await;
    }
}

/// Flushes every active writable `MAP_SHARED` file mapping in `process`.
pub(super) async fn flush_all_shared_mappings<R: Resources, M: UserMemory, F: fs::Filesystem<R>>(
    process: &Process<R>,
    memory: &M,
    fs: &mut F,
) {
    let segments: Vec<_> = {
        let guard = process.shared.shared_mappings.lock();
        guard
            .iter()
            .filter_map(|m| {
                let (m_file, file_offset, object_id) = m.shared_file()?;
                m.writable
                    .then(|| (m.start, m.len, m_file.clone(), file_offset, object_id))
            })
            .collect()
    };
    let creds = process.credentials.lock().clone();
    for (seg_start, seg_len, f, file_off, object_id) in segments {
        flush_one_range(
            seg_start, seg_len, &f, file_off, object_id, &creds, memory, fs,
        )
        .await;
    }
}

/// Propagates bytes written to `file` at `offset` into any active `MAP_SHARED`
/// mappings of the same file in `process`.
///
/// When backed by a kernel `SharedPageObject` (`object_id != 0`), updates both
/// the live shared frame (visible across all mappings and processes) and the
/// clean baseline once per object; falls back to per-mapping `populate` for
/// lightweight test mocks.
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
    let mut object_ids: Vec<u64> = Vec::new();
    let mut fallback_targets: Vec<(u64, u64, u64)> = Vec::new();
    {
        let guard = process.shared.shared_mappings.lock();
        for m in guard.iter() {
            let Some((m_file, file_offset, object_id)) = m.shared_file() else {
                continue;
            };
            if !fs.same_file(m_file, file) {
                continue;
            }
            if object_id != 0 {
                if !object_ids.contains(&object_id) {
                    object_ids.push(object_id);
                }
                continue;
            }
            let map_file_end = file_offset.saturating_add(m.len);
            let ov_start = offset.max(file_offset);
            let ov_end = write_end.min(map_file_end);
            if ov_start < ov_end {
                fallback_targets.push((
                    m.start + (ov_start - file_offset),
                    ov_start - offset,
                    ov_end - ov_start,
                ));
            }
        }
    }
    for object_id in object_ids {
        let _ = memory.apply_shared_file_write(object_id, offset, bytes);
    }
    if fallback_targets.is_empty() {
        return;
    }
    let _mm = process.shared.program_break.lock();
    for (addr, src_off, len) in fallback_targets {
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
                let _ = memory.populate(copy_start, &bytes[slice_start..slice_end]);
            }
            pos = copy_end.max(region.end);
        }
    }
}

/// `do_vmi_munmap`'s checks, then flush and removal.
async fn unmap_checked<R: Resources, M: VirtualMemory, O: System + fs::Filesystem<R>>(
    process: &Process<R>,
    abi: Abi,
    start: u64,
    length: u64,
    memory: &mut M,
    fs: &mut O,
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
    let (detached_shmids, dropped_memfd) = {
        let _mm = process.shared.program_break.lock();
        let removed = remove_shared_range(process, start, end);
        memory.unmap_shared_vma(start, end);
        unmap_clipped(start, end, memory);
        removed
    };
    if !detached_shmids.is_empty() {
        let now_secs = (fs.realtime_nanos() / 1_000_000_000) as i64;
        let pid = process.pid().get();
        for shmid in detached_shmids {
            fs.shm_detach(shmid, pid, now_secs);
        }
    }
    if dropped_memfd {
        fs.reap_memfds();
    }
    0
}

/// Reads `[file_offset, file_offset + to_load)` from `file` into shared object
/// `object_id` (using `base_page_index` as the page index of `file_offset`)
/// BEFORE acquiring any address-space lock so a read or OOM failure never
/// races a sibling thread's `MAP_FIXED`.
async fn stage_file_into_shared_object<R: Resources, M: VirtualMemory, F: fs::Filesystem<R>>(
    file: &R::File,
    file_offset: u64,
    to_load: u64,
    object_id: u64,
    base_page_index: u64,
    memory: &mut M,
    fs: &F,
) -> Result<u64, u64> {
    let mut filled = 0u64;
    while filled < to_load {
        let want = (to_load - filled).min(PAGE) as usize;
        let bytes = fs
            .read_at(file, file_offset + filled, want)
            .await
            .map_err(fs::fs_errno)?;
        if bytes.is_empty() {
            break;
        }
        let page_index = base_page_index + (filled / PAGE);
        memory
            .load_shared_page(object_id, page_index, &bytes)
            .map_err(map_errno)?;
        filled += bytes.len() as u64;
        if bytes.len() < want {
            break;
        }
    }
    Ok(filled)
}

/// Fallback staging into a byte buffer for lightweight unit-test mocks that do
/// not back mappings with `SharedPageObject` (`object_id == 0`).
async fn stage_file_into_vec<R: Resources, F: fs::Filesystem<R>>(
    file: &R::File,
    file_offset: u64,
    to_load: u64,
    fs: &F,
) -> Result<Vec<u8>, u64> {
    const CHUNK: usize = 64 * 1024;
    let mut staged = Vec::new();
    let mut filled = 0u64;
    while filled < to_load {
        let want = (to_load - filled).min(CHUNK as u64) as usize;
        let bytes = fs
            .read_at(file, file_offset + filled, want)
            .await
            .map_err(fs::fs_errno)?;
        if bytes.is_empty() {
            break;
        }
        staged.extend_from_slice(&bytes);
        filled += bytes.len() as u64;
        if bytes.len() < want {
            break;
        }
    }
    Ok(staged)
}

/// Concrete heap-pinned wrappers for the cold async memory-map syscalls.
/// Keeping each construction inside a non-inlined frame prevents debug builds
/// from reserving stack slots for every VM future simultaneously inside
/// `syscall::dispatch`.
#[inline(never)]
pub(super) fn mmap_boxed<'a, R: Resources, M: VirtualMemory, F: System + fs::Filesystem<R>>(
    process: &'a Process<R>,
    abi: Abi,
    args: [u64; 6],
    memory: &'a mut M,
    fs: &'a mut F,
) -> Pin<Box<impl Future<Output = u64> + use<'a, R, M, F>>> {
    Box::pin(mmap(process, abi, args, memory, fs))
}

#[inline(never)]
pub(super) fn munmap_boxed<'a, R: Resources, M: VirtualMemory, F: System + fs::Filesystem<R>>(
    process: &'a Process<R>,
    abi: Abi,
    args: [u64; 6],
    memory: &'a mut M,
    fs: &'a mut F,
) -> Pin<Box<impl Future<Output = u64> + use<'a, R, M, F>>> {
    Box::pin(munmap(process, abi, args, memory, fs))
}

#[inline(never)]
pub(super) fn msync_boxed<'a, R: Resources, M: VirtualMemory, F: fs::Filesystem<R>>(
    process: &'a Process<R>,
    abi: Abi,
    args: [u64; 6],
    memory: &'a M,
    fs: &'a mut F,
) -> Pin<Box<impl Future<Output = u64> + use<'a, R, M, F>>> {
    Box::pin(msync(process, abi, args, memory, fs))
}

#[inline(never)]
pub(super) fn mremap_boxed<'a, R: Resources, M: VirtualMemory, F: System + fs::Filesystem<R>>(
    process: &'a Process<R>,
    abi: Abi,
    args: [u64; 6],
    memory: &'a mut M,
    fs: &'a mut F,
) -> Pin<Box<impl Future<Output = u64> + use<'a, R, M, F>>> {
    Box::pin(mremap(process, abi, args, memory, fs))
}

#[inline(never)]
pub(super) fn madvise_boxed<'a, R: Resources, M: VirtualMemory, F: fs::Filesystem<R>>(
    process: &'a Process<R>,
    args: [u64; 6],
    memory: &'a mut M,
    fs: &'a F,
) -> Pin<Box<impl Future<Output = u64> + use<'a, R, M, F>>> {
    Box::pin(madvise(process, args, memory, fs))
}

/// `mmap(addr, length, prot, flags, fd, offset)` for anonymous and file-backed
/// private/shared mappings (mm/mmap.c `do_mmap`).
pub(super) async fn mmap<R: Resources, M: VirtualMemory, O: System + fs::Filesystem<R>>(
    process: &Process<R>,
    abi: Abi,
    args: [u64; 6],
    memory: &mut M,
    fs: &mut O,
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

    struct FileBacking<F> {
        file: F,
        may_write: bool,
        may_exec: bool,
        stat: FileStat,
        memfd_hold: Option<helios_unix::MemfdHold>,
        memfd_write_hold: Option<helios_unix::MemfdWritableMapHold>,
    }

    let file_backing: Option<FileBacking<R::File>> = if is_anon {
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
        let can_exec = fs.can_exec_file(&file);
        if (prot & PROT_EXEC != 0) && !can_exec {
            return errno(EPERM);
        }
        // Enforce `memfd_create(2)` write seals (`mm/shmem.c` `shmem_mmap`):
        // - `MAP_SHARED | PROT_WRITE` fails with `EPERM` under `F_SEAL_WRITE`
        //   or `F_SEAL_FUTURE_WRITE`.
        // - `MAP_SHARED` without `PROT_WRITE` on a writable fd clears
        //   `VM_MAYWRITE` (`may_write = false`) under `F_SEAL_WRITE` or
        //   `F_SEAL_FUTURE_WRITE` so a later `mprotect(PROT_WRITE)` fails
        //   with `EACCES`.
        let mut may_write = file_access.writable();
        let memfd_hold = fs.memfd_handle(&file).map(|h| h.acquire_hold());
        let mut memfd_write_hold = None;
        if is_shared && memfd_hold.is_some() && may_write {
            match fs.memfd_acquire_writable_map(&file) {
                Ok(Some(write_hold)) => memfd_write_hold = Some(write_hold),
                Ok(None) => {}
                Err(FsOpError::PermissionDenied) => {
                    if prot & PROT_WRITE != 0 {
                        return errno(EPERM);
                    }
                    may_write = false;
                }
                Err(error) => return fs::fs_errno(error),
            }
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
        Some(FileBacking {
            file,
            may_write,
            may_exec: can_exec,
            stat,
            memfd_hold,
            memfd_write_hold,
        })
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

    // `CONFIG_DEFAULT_MMAP_MIN_ADDR` (64 KiB, `security/min_addr.c`): keep
    // unfixed mappings above the low null-pointer guard range.
    const MMAP_MIN_ADDR: u64 = 65_536;
    let unfixed_hint = (hint & !(PAGE - 1)).max(MMAP_MIN_ADDR);

    // Stage file bytes BEFORE acquiring `program_break.lock()` and before
    // mapping any virtual address so async file reads never race sibling
    // `MAP_FIXED` operations and an error never unmaps another thread's range.
    enum StagedPlan<F> {
        PrivateAnon,
        SharedAnon {
            object_id: u64,
        },
        SharedFile {
            file: F,
            may_write: bool,
            may_exec: bool,
            object_id: u64,
            attach_len: u64,
            fallback_bytes: Vec<u8>,
            memfd_hold: Option<helios_unix::MemfdHold>,
            memfd_write_hold: Option<helios_unix::MemfdWritableMapHold>,
        },
        PrivateFile {
            file: F,
            may_exec: bool,
            stage_id: u64,
            staged_len: u64,
            fallback_bytes: Vec<u8>,
            memfd_hold: Option<helios_unix::MemfdHold>,
        },
    }

    let plan = match file_backing {
        None if is_shared => StagedPlan::SharedAnon {
            object_id: memory.create_shared_anonymous(),
        },
        None => StagedPlan::PrivateAnon,
        Some(FileBacking {
            file,
            may_write,
            may_exec,
            stat,
            memfd_hold,
            memfd_write_hold,
        }) if is_shared => {
            let object_id = memory.acquire_shared_file(stat.dev, stat.ino);
            let to_load = if offset < stat.size {
                length.min(stat.size - offset)
            } else {
                0
            };
            if object_id != 0 {
                // Memfd pages already live directly inside the `SharedPageObject`
                // returned by `acquire_shared_file`; skip redundant staging so
                // sparse memfds stay demand-paged without extra frame allocations.
                let attach_len = if memfd_hold.is_some() {
                    to_load
                } else {
                    match stage_file_into_shared_object(
                        &file,
                        offset,
                        to_load,
                        object_id,
                        offset / PAGE,
                        memory,
                        fs,
                    )
                    .await
                    {
                        Ok(loaded) => loaded,
                        Err(err) => {
                            memory.release_shared_object(object_id);
                            return err;
                        }
                    }
                };
                StagedPlan::SharedFile {
                    file,
                    may_write,
                    may_exec,
                    object_id,
                    attach_len,
                    fallback_bytes: Vec::new(),
                    memfd_hold,
                    memfd_write_hold,
                }
            } else {
                let fallback_bytes = match stage_file_into_vec(&file, offset, to_load, fs).await {
                    Ok(bytes) => bytes,
                    Err(err) => return err,
                };
                StagedPlan::SharedFile {
                    file,
                    may_write,
                    may_exec,
                    object_id: 0,
                    attach_len: fallback_bytes.len() as u64,
                    fallback_bytes,
                    memfd_hold,
                    memfd_write_hold,
                }
            }
        }
        Some(FileBacking {
            file,
            may_exec,
            stat,
            memfd_hold,
            ..
        }) => {
            let to_load = if offset < stat.size {
                length.min(stat.size - offset)
            } else {
                0
            };
            let stage_id = if to_load > 0 {
                memory.create_shared_anonymous()
            } else {
                0
            };
            if stage_id != 0 {
                let staged_len = match stage_file_into_shared_object(
                    &file, offset, to_load, stage_id, 0, memory, fs,
                )
                .await
                {
                    Ok(loaded) => loaded,
                    Err(err) => {
                        memory.release_shared_object(stage_id);
                        return err;
                    }
                };
                StagedPlan::PrivateFile {
                    file,
                    may_exec,
                    stage_id,
                    staged_len,
                    fallback_bytes: Vec::new(),
                    memfd_hold,
                }
            } else {
                let fallback_bytes = match stage_file_into_vec(&file, offset, to_load, fs).await {
                    Ok(bytes) => bytes,
                    Err(err) => return err,
                };
                StagedPlan::PrivateFile {
                    file,
                    may_exec,
                    stage_id: 0,
                    staged_len: fallback_bytes.len() as u64,
                    fallback_bytes,
                    memfd_hold,
                }
            }
        }
    };

    // Perform the entire VA reservation, replacement, frame installation, and
    // VMA registration atomically under `program_break.lock()`.
    let (result, detached_shmids, dropped_memfd) = {
        let _mm = process.shared.program_break.lock();
        let mut detached_shmids = Vec::new();
        let mut dropped_memfd = false;
        if is_fixed {
            if flags & MAP_FIXED_NOREPLACE != 0 {
                if memory.region(hint, hint + length).is_some() {
                    match &plan {
                        StagedPlan::SharedAnon { object_id }
                        | StagedPlan::SharedFile { object_id, .. }
                            if *object_id != 0 =>
                        {
                            memory.release_shared_object(*object_id);
                        }
                        StagedPlan::PrivateFile { stage_id, .. } if *stage_id != 0 => {
                            memory.release_shared_object(*stage_id);
                        }
                        _ => {}
                    }
                    return errno(EEXIST);
                }
            } else {
                let (shmids, memfd) = remove_shared_range(process, hint, hint + length);
                detached_shmids = shmids;
                dropped_memfd = memfd;
                memory.unmap_shared_vma(hint, hint + length);
                memory.unmap(hint, length);
            }
        }

        let res = match plan {
            StagedPlan::PrivateAnon => {
                let mapped = if is_fixed {
                    memory.map_at(hint, length, access).map(|()| hint)
                } else {
                    memory.map_anywhere(unfixed_hint, length, access)
                };
                match mapped {
                    Ok(addr) => addr,
                    Err(error) => map_errno(error),
                }
            }
            StagedPlan::SharedAnon { object_id } => {
                let mapped = if is_fixed {
                    memory
                        .map_shared_at(hint, length, access, object_id, 0, 0)
                        .map(|()| hint)
                } else {
                    memory.map_shared_anywhere(unfixed_hint, length, access, object_id, 0, 0)
                };
                match mapped {
                    Ok(mapped_addr) => {
                        process
                            .shared
                            .shared_mappings
                            .lock()
                            .push(SharedFileMapping {
                                start: mapped_addr,
                                len: length,
                                backing: MappingBacking::SharedAnon {
                                    object_id,
                                    object_offset: 0,
                                },
                                may_write: true,
                                may_exec: true,
                                writable: access.contains(PageFlags::WRITE),
                                memfd_hold: None,
                                memfd_write_hold: None,
                            });
                        mapped_addr
                    }
                    Err(error) => {
                        if object_id != 0 {
                            memory.release_shared_object(object_id);
                        }
                        map_errno(error)
                    }
                }
            }
            StagedPlan::SharedFile {
                file,
                may_write,
                may_exec,
                object_id,
                attach_len,
                fallback_bytes,
                memfd_hold,
                memfd_write_hold,
            } => {
                let mapped = if is_fixed {
                    memory
                        .map_shared_at(hint, length, access, object_id, offset, attach_len)
                        .map(|()| hint)
                } else {
                    memory.map_shared_anywhere(
                        unfixed_hint,
                        length,
                        access,
                        object_id,
                        offset,
                        attach_len,
                    )
                };
                match mapped {
                    Ok(mapped_addr) => {
                        if object_id == 0
                            && !fallback_bytes.is_empty()
                            && let Err(error) = memory.populate(mapped_addr, &fallback_bytes)
                        {
                            memory.unmap(mapped_addr, length);
                            match error {
                                MapError::OutOfMemory => errno(ENOMEM),
                                MapError::Address | MapError::Occupied => errno(EFAULT),
                            }
                        } else {
                            process
                                .shared
                                .shared_mappings
                                .lock()
                                .push(SharedFileMapping {
                                    start: mapped_addr,
                                    len: length,
                                    backing: MappingBacking::SharedFile {
                                        file,
                                        file_offset: offset,
                                        object_id,
                                    },
                                    may_write,
                                    may_exec,
                                    writable: access.contains(PageFlags::WRITE),
                                    memfd_hold,
                                    memfd_write_hold,
                                });
                            mapped_addr
                        }
                    }
                    Err(error) => {
                        if object_id != 0 {
                            memory.release_shared_object(object_id);
                        }
                        map_errno(error)
                    }
                }
            }
            StagedPlan::PrivateFile {
                file,
                may_exec,
                stage_id,
                staged_len,
                fallback_bytes,
                memfd_hold,
            } => {
                let mapped = if is_fixed {
                    memory
                        .map_private_file_at(hint, length, access, stage_id, staged_len)
                        .map(|()| hint)
                } else {
                    memory.map_private_file_anywhere(
                        unfixed_hint,
                        length,
                        access,
                        stage_id,
                        staged_len,
                    )
                };
                match mapped {
                    Ok(mapped_addr) => {
                        if stage_id == 0
                            && !fallback_bytes.is_empty()
                            && let Err(error) = memory.populate(mapped_addr, &fallback_bytes)
                        {
                            memory.unmap(mapped_addr, length);
                            match error {
                                MapError::OutOfMemory => errno(ENOMEM),
                                MapError::Address | MapError::Occupied => errno(EFAULT),
                            }
                        } else {
                            process
                                .shared
                                .shared_mappings
                                .lock()
                                .push(SharedFileMapping {
                                    start: mapped_addr,
                                    len: length,
                                    backing: MappingBacking::PrivateFile {
                                        file,
                                        file_offset: offset,
                                    },
                                    may_write: true,
                                    may_exec,
                                    writable: access.contains(PageFlags::WRITE),
                                    memfd_hold,
                                    memfd_write_hold: None,
                                });
                            mapped_addr
                        }
                    }
                    Err(error) => {
                        if stage_id != 0 {
                            memory.release_shared_object(stage_id);
                        }
                        map_errno(error)
                    }
                }
            }
        };
        (res, detached_shmids, dropped_memfd)
    };
    if !detached_shmids.is_empty() {
        let now_secs = (fs.realtime_nanos() / 1_000_000_000) as i64;
        let pid = process.pid().get();
        for shmid in detached_shmids {
            fs.shm_detach(shmid, pid, now_secs);
        }
    }
    if dropped_memfd {
        fs.reap_memfds();
    }
    result
}

/// `munmap(addr, length)` (mm/mmap.c `__vm_munmap`).
pub(super) async fn munmap<R: Resources, M: VirtualMemory, O: System + fs::Filesystem<R>>(
    process: &Process<R>,
    abi: Abi,
    args: [u64; 6],
    memory: &mut M,
    fs: &mut O,
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
    let creds = process.credentials.lock().clone();
    for (seg_start, seg_len, file, file_off, object_id) in segments {
        flush_one_range(
            seg_start, seg_len, &file, file_off, object_id, &creds, memory, fs,
        )
        .await;
        if flags & MS_SYNC != 0
            && let Err(error) = fs.sync(&file, false).await
        {
            return fs::fs_errno(error);
        }
    }

    if hole { errno(ENOMEM) } else { 0 }
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
    // Enforce `VM_MAYWRITE` and `VM_MAYEXEC` across overlapping VMAs
    // (`mm/mprotect.c` `mprotect_fixup`).
    {
        let vmas = process.shared.shared_mappings.lock();
        for m in vmas.iter() {
            if m.start < end && m.end() > start {
                if prot & PROT_WRITE != 0 && !m.may_write {
                    return errno(EACCES);
                }
                if prot & PROT_EXEC != 0 && !m.may_exec {
                    return errno(EACCES);
                }
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
    split_vmas_for_mprotect(process, start, position, prot & PROT_WRITE != 0);
    result
}

/// `madvise(addr, length, advice)` for the advice that frees memory
/// (mm/madvise.c).
///
/// - `MADV_DONTNEED` on anonymous private mappings discards pages to zero.
/// - `MADV_DONTNEED` on file-backed `MAP_PRIVATE` mappings discards modified
///   private copies and reloads the backing file's contents (leaving whole
///   pages beyond EOF uncommitted so accesses still raise `SIGBUS`).
/// - `MADV_DONTNEED` on `MAP_SHARED` mappings preserves shared contents.
/// - `MADV_FREE` is permitted only on anonymous private mappings (`EINVAL`
///   on shared or file-backed mappings, matching `madvise_free_single_vma`).
pub(super) async fn madvise<R: Resources, M: VirtualMemory, F: fs::Filesystem<R>>(
    process: &Process<R>,
    args: [u64; 6],
    memory: &mut M,
    fs: &F,
) -> u64 {
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
    if start == end {
        return 0;
    }

    enum AdviceStep<File> {
        DiscardPrivateAnon {
            start: u64,
            len: u64,
        },
        ReloadPrivateFile {
            start: u64,
            len: u64,
            file: File,
            file_offset: u64,
        },
        PreserveShared,
    }

    let (steps, hole) = {
        let _mm = process.shared.program_break.lock();
        let vmas = process.shared.shared_mappings.lock();
        let mut steps = Vec::new();
        let mut position = start;
        let mut hole = false;
        while position < end {
            let Some(region) = memory.region(position, end) else {
                hole = true;
                break;
            };
            hole |= region.start != position;
            let mut cursor = region.start;
            while cursor < region.end {
                // Find the VMA containing `cursor`, or the next VMA boundary inside `region`.
                let containing = vmas.iter().find(|m| cursor >= m.start && cursor < m.end());
                if let Some(vma) = containing {
                    let seg_end = region.end.min(vma.end());
                    let seg_len = seg_end - cursor;
                    match &vma.backing {
                        MappingBacking::SharedFile { .. }
                        | MappingBacking::SharedAnon { .. }
                        | MappingBacking::SysvShm { .. } => {
                            if advice == MADV_FREE {
                                return errno(EINVAL);
                            }
                            steps.push(AdviceStep::PreserveShared);
                        }
                        MappingBacking::PrivateFile { file, file_offset } => {
                            if advice == MADV_FREE {
                                return errno(EINVAL);
                            }
                            steps.push(AdviceStep::ReloadPrivateFile {
                                start: cursor,
                                len: seg_len,
                                file: file.clone(),
                                file_offset: file_offset.saturating_add(cursor - vma.start),
                            });
                        }
                    }
                    cursor = seg_end;
                } else {
                    let next_vma_start = vmas
                        .iter()
                        .filter(|m| m.start > cursor && m.start < region.end)
                        .map(|m| m.start)
                        .min()
                        .unwrap_or(region.end);
                    steps.push(AdviceStep::DiscardPrivateAnon {
                        start: cursor,
                        len: next_vma_start - cursor,
                    });
                    cursor = next_vma_start;
                }
            }
            position = region.end;
        }
        (steps, hole)
    };

    for step in steps {
        match step {
            AdviceStep::PreserveShared => {}
            AdviceStep::DiscardPrivateAnon { start, len } => {
                let _mm = process.shared.program_break.lock();
                memory.discard(start, len);
            }
            AdviceStep::ReloadPrivateFile {
                start,
                len,
                file,
                file_offset,
            } => {
                let reloaded = match fs.stat_file(&file).await {
                    Ok(stat) if file_offset < stat.size => {
                        let to_load = len.min(stat.size - file_offset);
                        stage_file_into_vec(&file, file_offset, to_load, fs)
                            .await
                            .ok()
                    }
                    _ => None,
                };
                let _mm = process.shared.program_break.lock();
                memory.discard(start, len);
                if let Some(bytes) = reloaded
                    && !bytes.is_empty()
                {
                    let _ = memory.populate(start, &bytes);
                }
            }
        }
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
    object_id: u64,
}

/// Relocates any tracked VMA overlapping `[from, from + old_len)` to `to`
/// (splitting first at `from` and `from + old_len` when partial). When a full
/// file-backed mapping grew (`new_len > old_len`), keeps `m.len == old_len`
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
    let mut next = Vec::with_capacity(guard.len() + 2);
    let mut grown_tail = None;
    for m in guard.drain(..) {
        let m_end = m.end();
        if m_end <= from || m.start >= from_end {
            next.push(m);
            continue;
        }
        if m.start < from {
            next.push(SharedFileMapping {
                start: m.start,
                len: from - m.start,
                backing: m.backing.clone(),
                may_write: m.may_write,
                may_exec: m.may_exec,
                writable: m.writable,
                memfd_hold: m.memfd_hold.clone(),
                memfd_write_hold: m.memfd_write_hold.clone(),
            });
        }
        let ov_start = m.start.max(from);
        let ov_end = m_end.min(from_end);
        let ov_len = ov_end - ov_start;
        let moved_start = to + (ov_start - from);
        let moved_backing = m.backing.advance(ov_start - m.start);
        let mut moved_len = ov_len;
        if ov_end == from_end && new_len > old_len {
            let growth = new_len - old_len;
            match &moved_backing {
                MappingBacking::SharedFile {
                    file,
                    file_offset,
                    object_id,
                } => {
                    grown_tail = Some(GrownSharedTail {
                        mapping_start: moved_start,
                        old_len: ov_len,
                        new_len: ov_len + growth,
                        tail_addr: to + old_len,
                        tail_len: growth,
                        file: file.clone(),
                        tail_file_offset: file_offset.saturating_add(ov_len),
                        object_id: *object_id,
                    });
                }
                MappingBacking::PrivateFile { file, file_offset } => {
                    grown_tail = Some(GrownSharedTail {
                        mapping_start: moved_start,
                        old_len: ov_len,
                        new_len: ov_len + growth,
                        tail_addr: to + old_len,
                        tail_len: growth,
                        file: file.clone(),
                        tail_file_offset: file_offset.saturating_add(ov_len),
                        object_id: 0,
                    });
                }
                MappingBacking::SharedAnon { .. } | MappingBacking::SysvShm { .. } => {
                    moved_len += growth;
                }
            }
        }
        next.push(SharedFileMapping {
            start: moved_start,
            len: moved_len,
            backing: moved_backing,
            may_write: m.may_write,
            may_exec: m.may_exec,
            writable: m.writable,
            memfd_hold: m.memfd_hold.clone(),
            memfd_write_hold: m.memfd_write_hold.clone(),
        });
        if m_end > from_end {
            next.push(SharedFileMapping {
                start: from_end,
                len: m_end - from_end,
                backing: m.backing.advance(from_end - m.start),
                may_write: m.may_write,
                may_exec: m.may_exec,
                writable: m.writable,
                memfd_hold: m.memfd_hold,
                memfd_write_hold: m.memfd_write_hold,
            });
        }
    }
    *guard = next;
    grown_tail
}

/// Populates the newly grown tail of a file-backed mapping from its backing
/// file and then expands the tracked mapping length to `new_len`.
async fn populate_grown_shared_tail<R: Resources, M: VirtualMemory, F: fs::Filesystem<R>>(
    process: &Process<R>,
    tail: GrownSharedTail<R::File>,
    memory: &mut M,
    fs: &mut F,
) {
    let Ok(stat) = fs.stat_file(&tail.file).await else {
        return;
    };
    if tail.tail_file_offset < stat.size {
        let to_load = tail.tail_len.min(stat.size - tail.tail_file_offset);
        if tail.object_id != 0 {
            let loaded = if fs.memfd_handle(&tail.file).is_some() {
                Ok(to_load)
            } else {
                stage_file_into_shared_object(
                    &tail.file,
                    tail.tail_file_offset,
                    to_load,
                    tail.object_id,
                    tail.tail_file_offset / PAGE,
                    memory,
                    fs,
                )
                .await
            };
            if let Ok(loaded) = loaded {
                let _mm = process.shared.program_break.lock();
                let _ = memory.attach_shared_tail(
                    tail.tail_addr,
                    tail.object_id,
                    tail.tail_file_offset,
                    loaded,
                );
            }
        } else if let Ok(bytes) =
            stage_file_into_vec(&tail.file, tail.tail_file_offset, to_load, fs).await
            && !bytes.is_empty()
        {
            let _mm = process.shared.program_break.lock();
            let _ = memory.populate(tail.tail_addr, &bytes);
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
pub(super) async fn mremap<R: Resources, M: VirtualMemory, O: System + fs::Filesystem<R>>(
    process: &Process<R>,
    abi: Abi,
    args: [u64; 6],
    memory: &mut M,
    fs: &mut O,
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
                let in_place = {
                    let vmas = process.shared.shared_mappings.lock();
                    vmas.iter()
                        .find(|m| m.start <= address && m.end() >= address + old_length)
                        .map(|m| (m.backing.is_shared(), m.start, m.backing.clone()))
                };
                let map_res = match in_place {
                    Some((
                        true,
                        vma_start,
                        MappingBacking::SharedFile {
                            file_offset,
                            object_id,
                            ..
                        },
                    )) => {
                        let tail_off = file_offset.saturating_add(region.end - vma_start);
                        memory.map_shared_at(
                            region.end,
                            delta,
                            region.access,
                            object_id,
                            tail_off,
                            0,
                        )
                    }
                    Some((
                        true,
                        vma_start,
                        MappingBacking::SharedAnon {
                            object_id,
                            object_offset,
                        }
                        | MappingBacking::SysvShm {
                            object_id,
                            object_offset,
                            ..
                        },
                    )) => {
                        let tail_off = object_offset.saturating_add(region.end - vma_start);
                        memory.map_shared_at(
                            region.end,
                            delta,
                            region.access,
                            object_id,
                            tail_off,
                            0,
                        )
                    }
                    Some((false, _, MappingBacking::PrivateFile { .. })) => {
                        memory.map_private_file_at(region.end, delta, region.access, 0, 0)
                    }
                    _ => memory.map_at(region.end, delta, region.access),
                };
                match map_res {
                    Ok(()) => {
                        memory.remap_shared_vma(address, old_length, address, new_length);
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
                        memory.remap_shared_vma(address, old_length, target, new_length);
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
                    memory.remap_shared_vma(address, old_length, target, new_length);
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
        populate_grown_shared_tail(process, tail, memory, fs).await;
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
#[expect(
    clippy::too_many_arguments,
    reason = "mirrors Linux mm/mremap.c mremap_to arguments plus process, memory, and filesystem handles"
)]
async fn mremap_to<R: Resources, M: VirtualMemory, O: System + fs::Filesystem<R>>(
    process: &Process<R>,
    abi: Abi,
    address: u64,
    mut old_length: u64,
    new_length: u64,
    flags: u64,
    new_address: u64,
    memory: &mut M,
    fs: &mut O,
) -> u64 {
    let task = abi.task_size();
    if new_address & (PAGE - 1) != 0 || new_length > task || new_address > task - new_length {
        return errno(EINVAL);
    }
    if address.wrapping_add(old_length) > new_address && new_address + new_length > address {
        return errno(EINVAL);
    }
    if flags & MREMAP_DONTUNMAP != 0 {
        // Linux `mm/mremap.c`: `MREMAP_DONTUNMAP` rejects `VM_SHARED`.
        let overlaps_shared = {
            let vmas = process.shared.shared_mappings.lock();
            vmas.iter().any(|m| {
                m.backing.is_shared()
                    && m.start < address.saturating_add(old_length)
                    && m.end() > address
            })
        };
        if overlaps_shared {
            return errno(EINVAL);
        }
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
    let (target, grown_tail) = {
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
        memory.remap_shared_vma(address, old_length, target, new_length);
        let tail = move_shared_range(process, address, old_length, target, new_length);
        if flags & MREMAP_DONTUNMAP != 0 {
            if let Err(error) = memory.map_at(address, old_length, region.access) {
                return map_errno(error);
            }
            memory.discard(address, old_length);
        }
        (target, tail)
    };
    if let Some(tail) = grown_tail {
        populate_grown_shared_tail(process, tail, memory, fs).await;
    }
    target
}

/// Maps a SysV shared memory segment into `process`'s address space for
/// `shmat(2)` (`ipc/shm.c` `do_shmat`).
#[expect(
    clippy::too_many_arguments,
    reason = "maps a validated shmat request against the process, ABI, segment, permissions, memory, and host"
)]
pub(super) async fn shmat_map<R: Resources, M: VirtualMemory, O: System + fs::Filesystem<R>>(
    process: &Process<R>,
    abi: Abi,
    shmid: i32,
    seg_size: u64,
    fixed_addr: Option<u64>,
    remap: bool,
    access: PageFlags,
    may_write: bool,
    now_secs: i64,
    memory: &mut M,
    fs: &mut O,
) -> Result<u64, u64> {
    let map_len = page_align(seg_size);
    if map_len == 0 {
        return Err(ENOMEM);
    }
    let task = abi.task_size();
    if let Some(addr) = fixed_addr {
        if map_len > task || addr > task - map_len {
            return Err(ENOMEM);
        }
        if addr < memory.lowest_address() {
            return Err(EINVAL);
        }
        if remap {
            flush_shared_range(process, addr, addr + map_len, memory, fs).await;
        }
    } else if map_len > task {
        return Err(ENOMEM);
    }

    const MMAP_MIN_ADDR: u64 = 65_536;
    let object_id = memory.acquire_sysv_shm(shmid);

    let (mapped_result, detached_shmids, dropped_memfd) = {
        let _mm = process.shared.program_break.lock();
        let mut detached_shmids = Vec::new();
        let mut dropped_memfd = false;
        if let Some(addr) = fixed_addr {
            if !remap {
                if memory.region(addr, addr + map_len).is_some() {
                    if object_id != 0 {
                        memory.release_shared_object(object_id);
                    }
                    return Err(EINVAL);
                }
            } else {
                let (shmids, memfd) = remove_shared_range(process, addr, addr + map_len);
                detached_shmids = shmids;
                dropped_memfd = memfd;
                memory.unmap_shared_vma(addr, addr + map_len);
                memory.unmap(addr, map_len);
            }
        }
        let mapped = match fixed_addr {
            Some(addr) => memory
                .map_shared_at(addr, map_len, access, object_id, 0, map_len)
                .map(|()| addr),
            None => {
                memory.map_shared_anywhere(MMAP_MIN_ADDR, map_len, access, object_id, 0, map_len)
            }
        };
        let res = match mapped {
            Ok(mapped_addr) => {
                let attach_id = process
                    .shared
                    .next_shm_attach_id
                    .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                process
                    .shared
                    .shared_mappings
                    .lock()
                    .push(SharedFileMapping {
                        start: mapped_addr,
                        len: map_len,
                        backing: MappingBacking::SysvShm {
                            shmid,
                            attach_id,
                            object_id,
                            object_offset: 0,
                        },
                        may_write,
                        may_exec: true,
                        writable: access.contains(PageFlags::WRITE),
                        memfd_hold: None,
                        memfd_write_hold: None,
                    });
                Ok(mapped_addr)
            }
            Err(error) => {
                if object_id != 0 {
                    memory.release_shared_object(object_id);
                }
                Err(match error {
                    MapError::OutOfMemory => ENOMEM,
                    MapError::Address => EINVAL,
                    MapError::Occupied => EINVAL,
                })
            }
        };
        (res, detached_shmids, dropped_memfd)
    };
    if !detached_shmids.is_empty() {
        let pid = process.pid().get();
        for old_shmid in detached_shmids {
            fs.shm_detach(old_shmid, pid, now_secs);
        }
    }
    if dropped_memfd {
        fs.reap_memfds();
    }
    mapped_result
}

/// Detaches the SysV shared memory segment whose attached base equals `shmaddr`
/// (`ipc/shm.c` `ksys_shmdt`).
pub(super) fn shmdt_unmap<R: Resources, M: VirtualMemory, F: fs::Filesystem<R>>(
    process: &Process<R>,
    shmaddr: u64,
    now_secs: i64,
    memory: &mut M,
    fs: &mut F,
) -> u64 {
    let detached = {
        let _mm = process.shared.program_break.lock();
        let mut guard = process.shared.shared_mappings.lock();
        let found = guard.iter().find_map(|m| match m.backing {
            MappingBacking::SysvShm {
                shmid,
                attach_id,
                object_offset: 0,
                ..
            } if m.start == shmaddr => Some((shmid, attach_id)),
            _ => None,
        });
        let Some((shmid, target_attach_id)) = found else {
            return errno(EINVAL);
        };
        let mut to_unmap = Vec::new();
        let mut remaining = Vec::with_capacity(guard.len());
        for m in guard.drain(..) {
            if matches!(
                m.backing,
                MappingBacking::SysvShm { attach_id, .. } if attach_id == target_attach_id
            ) {
                to_unmap.push((m.start, m.end()));
            } else {
                remaining.push(m);
            }
        }
        *guard = remaining;
        drop(guard);
        for (start, end) in to_unmap {
            memory.unmap_shared_vma(start, end);
            unmap_clipped(start, end, memory);
        }
        shmid
    };
    fs.shm_detach(detached, process.pid().get(), now_secs);
    0
}

/// Clones `process`'s tracked VMAs for `fork(2)`, assigning fresh attachment
/// IDs to each inherited SysV shared memory attachment and returning the list
/// of inherited `shmid`s (one entry per distinct attachment).
pub(super) fn clone_vmas_for_fork<R: Resources>(
    process: &Process<R>,
) -> (Vec<SharedFileMapping<R::File>>, Vec<i32>) {
    let guard = process.shared.shared_mappings.lock();
    let mut id_map: Vec<(u64, u64, i32)> = Vec::new();
    let mut next_child_id = 1u64;
    let mut cloned = Vec::with_capacity(guard.len());
    for m in guard.iter() {
        let mut copy = m.clone();
        if let MappingBacking::SysvShm {
            shmid,
            ref mut attach_id,
            ..
        } = copy.backing
        {
            if let Some(&(_, mapped_id, _)) = id_map.iter().find(|(old, _, _)| *old == *attach_id) {
                *attach_id = mapped_id;
            } else {
                let fresh = next_child_id;
                next_child_id += 1;
                id_map.push((*attach_id, fresh, shmid));
                *attach_id = fresh;
            }
        }
        cloned.push(copy);
    }
    let inherited_shmids = id_map.into_iter().map(|(_, _, shmid)| shmid).collect();
    (cloned, inherited_shmids)
}

/// Drains all remaining SysV shared memory attachments from `process` when its
/// address space is solely owned (on `execve` or final process exit), returning
/// one `shmid` per distinct attachment to detach.
pub(super) fn drain_sysv_shm_for_detach<R: Resources>(process: &Process<R>) -> Vec<i32> {
    if Arc::strong_count(&process.shared.shared_mappings) != 1 {
        return Vec::new();
    }
    let mut guard = process.shared.shared_mappings.lock();
    let mut seen: Vec<(u64, i32)> = Vec::new();
    let mut kept = Vec::with_capacity(guard.len());
    for m in guard.drain(..) {
        if let MappingBacking::SysvShm {
            shmid, attach_id, ..
        } = m.backing
        {
            if !seen.iter().any(|(id, _)| *id == attach_id) {
                seen.push((attach_id, shmid));
            }
        } else {
            kept.push(m);
        }
    }
    *guard = kept;
    seen.into_iter().map(|(_, shmid)| shmid).collect()
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
