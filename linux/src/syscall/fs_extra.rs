//! Extended filesystem, advisory locking, zero-copy I/O, and chroot syscalls:
//! `statfs`, `fstatfs`, `flock`, `fcntl` record locks (`F_GETLK`/`F_SETLK`/
//! `F_SETLKW`), `fallocate`, `sync`, `syncfs`, `chroot`, `copy_file_range`,
//! `splice`, `tee`, and `readahead`.
//!
//! Layouts, argument validation, and errno precedence follow Linux v6.12
//! (`fs/statfs.c`, `fs/locks.c`, `fs/open.c`, `fs/sync.c`, `fs/read_write.c`,
//! `fs/splice.c`, `mm/readahead.c`).

use bytes::Bytes;
use core::future::poll_fn;
use helios_hal::fs::{NodeKind, WritePosition};
use helios_sync::{TryRead, TryWrite};
use helios_unix::{
    ByteRange, FDFLAG_APPEND, FDFLAG_NONBLOCK, FDFLAG_PATH, FileDescriptor, FileLockKey, FlockKind,
    OpenFile, PosixLockKind, Signal,
};

use super::fs::{
    ANON_INODE_FS_MAGIC, AccessCheck, FsStat, PIPEFS_MAGIC, SOCKFS_MAGIC, ST_NODEV, ST_NOSUID,
    ST_RDONLY, ST_VALID, TMPFS_MAGIC, entry_file, fs_errno, process_creds, read_user_path,
    resolve_in_chroot,
};
use super::signal::WaitOutcome;
use super::socket::{Network, SocketContext, socket_recv, socket_send};
use super::{
    CAP_SYS_CHROOT, Descriptor, EACCES, EAGAIN, EBADF, EFAULT, EINTR, EINVAL, EIO, ENODEV,
    EOPNOTSUPP, EPERM, Entry, Filesystem, MAX_RW_COUNT, Process, Resources, Stream, SyscallOutcome,
    UserMemory, VirtualMemory, errno,
};
use crate::signal_frame::SigInfo;

// Linux UAPI constants (`include/uapi/asm-generic/errno-base.h`, `fcntl.h`, `falloc.h`).
const ENOENT: u64 = 2;
const ENOTDIR: u64 = 20;
const EISDIR: u64 = 21;
const EFBIG: u64 = 27;
const ESPIPE: u64 = 29;
const EPIPE: u64 = 32;
const EOVERFLOW: u64 = 75;

// `flock(2)` operations (`include/uapi/asm-generic/fcntl.h`).
const LOCK_SH: u32 = 1;
const LOCK_EX: u32 = 2;
const LOCK_NB: u32 = 4;
const LOCK_UN: u32 = 8;

// POSIX `fcntl(2)` advisory record lock commands & types.
pub(super) const F_GETLK: u32 = 5;
pub(super) const F_SETLK: u32 = 6;
pub(super) const F_SETLKW: u32 = 7;
const F_RDLCK: i16 = 0;
const F_WRLCK: i16 = 1;
const F_UNLCK: i16 = 2;
const SEEK_SET: i16 = 0;
const SEEK_CUR: i16 = 1;
const SEEK_END: i16 = 2;

// `fallocate(2)` mode bits (`include/uapi/linux/falloc.h`).
const FALLOC_FL_KEEP_SIZE: u32 = 0x01;
const FALLOC_FL_PUNCH_HOLE: u32 = 0x02;

// `splice(2)` / `tee(2)` flags (`include/linux/splice.h`).
const SPLICE_F_NONBLOCK: u32 = 0x02;

const COPY_CHUNK_BYTES: usize = 65_536;
const ZERO_CHUNK_BYTES: usize = 4096;

/// Derives a stable [`FileLockKey`] for an open file node, preferring
/// [`Filesystem::file_lock_key`] and falling back to [`Filesystem::stat_file`].
async fn resolve_file_lock_key<R: Resources, F: Filesystem<R>>(
    file: &R::File,
    fs: &F,
) -> Option<FileLockKey> {
    if let Some(key) = fs.file_lock_key(file) {
        return Some(key);
    }
    fs.stat_file(file)
        .await
        .ok()
        .map(|stat| FileLockKey::new(stat.dev, stat.ino))
}

/// Releases every POSIX record lock held by `process` on the underlying file of
/// `entry` (called whenever `process` closes a descriptor, per POSIX `fcntl(2)`).
pub(super) fn release_posix_locks_for_entry<R: Resources, F: Filesystem<R>>(
    process: &Process<R>,
    entry: &Entry<R>,
    fs: &F,
) {
    let Some(open) = entry_file::<R>(entry) else {
        return;
    };
    if let Some(key) = fs.file_lock_key(open.node()) {
        process
            .shared
            .pids
            .file_locks()
            .release_posix_for_file(key, process.shared.identity);
    }
}

/// `statfs(path, buf)` (`fs/statfs.c`, x86-64: 137, aarch64: 43).
pub(super) async fn statfs<R: Resources, M: UserMemory, F: Filesystem<R>>(
    process: &Process<R>,
    args: [u64; 6],
    memory: &mut M,
    fs: &F,
) -> u64 {
    let path = match read_user_path(memory, args[0]).await {
        Ok(path) => path,
        Err(err) => return err,
    };
    if path.is_empty() {
        return errno(ENOENT);
    }
    let creds = process_creds(process);
    let (cwd, resolved_path) = match resolve_in_chroot(process, None, &path, true, &creds, fs).await
    {
        Ok(pair) => pair,
        Err(err) => return err,
    };
    let stat = match fs.statfs_path(None, &cwd, &resolved_path, &creds).await {
        Ok(stat) => stat,
        Err(error) => return fs_errno(error),
    };
    match memory.write(args[1], &stat.write_statfs()).await {
        Ok(()) => 0,
        Err(_) => errno(EFAULT),
    }
}

/// `fstatfs(fd, buf)` (`fs/statfs.c`, x86-64: 138, aarch64: 44).
pub(super) async fn fstatfs<R: Resources, M: UserMemory, F: Filesystem<R>>(
    process: &Process<R>,
    args: [u64; 6],
    memory: &mut M,
    fs: &F,
) -> u64 {
    let fd = args[0] as u32 as i32;
    let Some(entry) = process.shared.descriptors.lock().get_entry(fd).cloned() else {
        return errno(EBADF);
    };
    let stat = match &entry.descriptor {
        FileDescriptor::File(open) => match fs.statfs_file(open.node()).await {
            Ok(stat) => stat,
            Err(error) => return fs_errno(error),
        },
        FileDescriptor::Preopen { descriptor, .. } => match fs.statfs_file(descriptor).await {
            Ok(stat) => stat,
            Err(error) => return fs_errno(error),
        },
        FileDescriptor::PipeRead { .. }
        | FileDescriptor::PipeWrite { .. }
        | FileDescriptor::FifoRead(_)
        | FileDescriptor::FifoWrite(_)
        | FileDescriptor::FifoReadWrite(_) => FsStat {
            f_type: PIPEFS_MAGIC,
            f_flags: ST_VALID | ST_NOSUID | ST_NODEV,
            ..FsStat::synthetic_virtual(PIPEFS_MAGIC)
        },
        FileDescriptor::Socket(_) => FsStat::synthetic_virtual(SOCKFS_MAGIC),
        FileDescriptor::Event(_) | FileDescriptor::Epoll(_) => {
            FsStat::synthetic_virtual(ANON_INODE_FS_MAGIC)
        }
        FileDescriptor::NullDevice
        | FileDescriptor::PseudoDevice(_)
        | FileDescriptor::PtyMaster(_)
        | FileDescriptor::PtySlave(_)
        | FileDescriptor::Stdin { .. }
        | FileDescriptor::Stdout
        | FileDescriptor::Stderr => FsStat {
            f_type: TMPFS_MAGIC,
            f_flags: ST_VALID | ST_NOSUID | ST_NODEV,
            ..FsStat::synthetic_virtual(TMPFS_MAGIC)
        },
    };
    match memory.write(args[1], &stat.write_statfs()).await {
        Ok(()) => 0,
        Err(_) => errno(EFAULT),
    }
}

/// `flock(fd, operation)` (`fs/locks.c`, x86-64: 73, aarch64: 32).
pub(super) async fn flock<R: Resources, F: Filesystem<R>>(
    process: &Process<R>,
    args: [u64; 6],
    fs: &F,
) -> SyscallOutcome {
    let fd = args[0] as u32 as i32;
    let op = args[1] as u32;
    let Some(entry) = process.shared.descriptors.lock().get_entry(fd).cloned() else {
        return SyscallOutcome::Return(errno(EBADF));
    };
    if entry.fdflags() & FDFLAG_PATH != 0 {
        return SyscallOutcome::Return(errno(EBADF));
    }
    let nonblocking = op & LOCK_NB != 0;
    let base = op & !LOCK_NB;
    let action = match base {
        LOCK_SH => Some(FlockKind::Shared),
        LOCK_EX => Some(FlockKind::Exclusive),
        LOCK_UN => None,
        _ => return SyscallOutcome::Return(errno(EINVAL)),
    };
    let Some(open) = entry_file::<R>(&entry) else {
        // Non-filesystem descriptors (pipes, sockets, /dev/null) carry no
        // shared inode across unrelated opens; accept valid operations.
        return SyscallOutcome::Return(0);
    };
    let Some(key) = resolve_file_lock_key(open.node(), fs).await else {
        return SyscallOutcome::Return(0);
    };
    let locks = process.shared.pids.file_locks();
    let owner = open.id();
    let Some(kind) = action else {
        locks.unlock_flock(key, owner);
        return SyscallOutcome::Return(0);
    };
    open.attach_flock_table(&locks);
    loop {
        let mut waiter = locks.waiter();
        if locks.try_flock(key, owner, kind, !nonblocking) {
            return SyscallOutcome::Return(0);
        }
        if nonblocking {
            return SyscallOutcome::Return(errno(EAGAIN));
        }
        if matches!(
            process
                .signals
                .interruptible(poll_fn(|cx| locks.poll_changed(cx, &mut waiter)))
                .await,
            WaitOutcome::Interrupted
        ) {
            return SyscallOutcome::RestartSys;
        }
    }
}

/// Decoded LP64 `struct flock` (`include/uapi/asm-generic/fcntl.h`, 32 bytes).
#[derive(Clone, Copy, Debug)]
struct LinuxFlock {
    l_type: i16,
    l_whence: i16,
    l_start: i64,
    l_len: i64,
    l_pid: i32,
}

impl LinuxFlock {
    async fn read<M: UserMemory>(memory: &M, addr: u64) -> Result<Self, u64> {
        let mut raw = [0u8; 32];
        memory.read(addr, &mut raw).await.map_err(|_| EFAULT)?;
        Ok(Self {
            l_type: i16::from_le_bytes(raw[0..2].try_into().unwrap()),
            l_whence: i16::from_le_bytes(raw[2..4].try_into().unwrap()),
            l_start: i64::from_le_bytes(raw[8..16].try_into().unwrap()),
            l_len: i64::from_le_bytes(raw[16..24].try_into().unwrap()),
            l_pid: i32::from_le_bytes(raw[24..28].try_into().unwrap()),
        })
    }

    async fn write<M: UserMemory>(self, memory: &mut M, addr: u64) -> Result<(), u64> {
        let mut raw = [0u8; 32];
        raw[0..2].copy_from_slice(&self.l_type.to_le_bytes());
        raw[2..4].copy_from_slice(&self.l_whence.to_le_bytes());
        raw[8..16].copy_from_slice(&self.l_start.to_le_bytes());
        raw[16..24].copy_from_slice(&self.l_len.to_le_bytes());
        raw[24..28].copy_from_slice(&self.l_pid.to_le_bytes());
        memory.write(addr, &raw).await.map_err(|_| EFAULT)
    }
}

async fn resolve_posix_range<R: Resources, F: Filesystem<R>>(
    fl: LinuxFlock,
    open: &OpenFile<R::File>,
    fs: &F,
) -> Result<ByteRange, u64> {
    let base: i64 = match fl.l_whence {
        SEEK_SET => 0,
        SEEK_CUR => i64::try_from(open.lock_position().await.get()).map_err(|_| EOVERFLOW)?,
        SEEK_END => {
            let size = fs.stat_file(open.node()).await.map_err(|_| EINVAL)?.size;
            i64::try_from(size).map_err(|_| EOVERFLOW)?
        }
        _ => return Err(EINVAL),
    };
    let origin = base.checked_add(fl.l_start).ok_or(EOVERFLOW)?;
    if fl.l_len > 0 {
        if origin < 0 {
            return Err(EINVAL);
        }
        let end = origin.checked_add(fl.l_len - 1).ok_or(EOVERFLOW)?;
        Ok(ByteRange::new(origin as u64, end as u64))
    } else if fl.l_len == 0 {
        if origin < 0 {
            return Err(EINVAL);
        }
        Ok(ByteRange::new(origin as u64, ByteRange::MAX_END))
    } else {
        // Negative `l_len`: locks `[origin + l_len, origin - 1]`.
        let start = origin.checked_add(fl.l_len).ok_or(EOVERFLOW)?;
        let end = origin.checked_sub(1).ok_or(EINVAL)?;
        if start < 0 || end < start {
            return Err(EINVAL);
        }
        Ok(ByteRange::new(start as u64, end as u64))
    }
}

/// `fcntl(fd, F_GETLK | F_SETLK | F_SETLKW, &flock)` (`fs/locks.c`).
pub(super) async fn fcntl_lock<R: Resources, M: UserMemory, F: Filesystem<R>>(
    process: &Process<R>,
    fd: i32,
    cmd: u32,
    flock_ptr: u64,
    memory: &mut M,
    fs: &F,
) -> SyscallOutcome {
    let Some(entry) = process.shared.descriptors.lock().get_entry(fd).cloned() else {
        return SyscallOutcome::Return(errno(EBADF));
    };
    if entry.fdflags() & FDFLAG_PATH != 0 {
        return SyscallOutcome::Return(errno(EBADF));
    }
    let fl = match LinuxFlock::read(memory, flock_ptr).await {
        Ok(fl) => fl,
        Err(err) => return SyscallOutcome::Return(errno(err)),
    };
    let Some(open) = entry_file::<R>(&entry) else {
        return SyscallOutcome::Return(errno(EBADF));
    };
    let access = fs.file_access(open.node());
    let range = match resolve_posix_range(fl, &open, fs).await {
        Ok(range) => range,
        Err(err) => return SyscallOutcome::Return(errno(err)),
    };
    let Some(key) = resolve_file_lock_key(open.node(), fs).await else {
        return SyscallOutcome::Return(errno(EBADF));
    };
    let locks = process.shared.pids.file_locks();
    let owner = process.shared.identity;

    match cmd {
        F_GETLK => {
            let kind = match fl.l_type {
                F_RDLCK => PosixLockKind::Read,
                F_WRLCK => PosixLockKind::Write,
                _ => return SyscallOutcome::Return(errno(EINVAL)),
            };
            let out = match locks.test_posix_lock(key, owner, kind, range) {
                Some(conflict) => LinuxFlock {
                    l_type: match conflict.kind {
                        PosixLockKind::Read => F_RDLCK,
                        PosixLockKind::Write => F_WRLCK,
                    },
                    l_whence: SEEK_SET,
                    l_start: conflict.range.start as i64,
                    l_len: if conflict.range.end == ByteRange::MAX_END {
                        0
                    } else {
                        (conflict.range.end - conflict.range.start + 1) as i64
                    },
                    l_pid: conflict.owner.id().get() as i32,
                },
                None => LinuxFlock {
                    l_type: F_UNLCK,
                    ..fl
                },
            };
            match out.write(memory, flock_ptr).await {
                Ok(()) => SyscallOutcome::Return(0),
                Err(err) => SyscallOutcome::Return(errno(err)),
            }
        }
        F_SETLK | F_SETLKW => {
            let blocking = cmd == F_SETLKW;
            match fl.l_type {
                F_UNLCK => {
                    locks.unlock_posix_range(key, owner, range);
                    SyscallOutcome::Return(0)
                }
                F_RDLCK | F_WRLCK => {
                    let kind = if fl.l_type == F_RDLCK {
                        if !access.readable() {
                            return SyscallOutcome::Return(errno(EBADF));
                        }
                        PosixLockKind::Read
                    } else {
                        if !access.writable() {
                            return SyscallOutcome::Return(errno(EBADF));
                        }
                        PosixLockKind::Write
                    };
                    loop {
                        let mut waiter = locks.waiter();
                        if locks.try_set_posix_lock(key, owner, kind, range) {
                            return SyscallOutcome::Return(0);
                        }
                        if !blocking {
                            return SyscallOutcome::Return(errno(EAGAIN));
                        }
                        if matches!(
                            process
                                .signals
                                .interruptible(poll_fn(|cx| locks.poll_changed(cx, &mut waiter)))
                                .await,
                            WaitOutcome::Interrupted
                        ) {
                            return SyscallOutcome::RestartSys;
                        }
                    }
                }
                _ => SyscallOutcome::Return(errno(EINVAL)),
            }
        }
        _ => SyscallOutcome::Return(errno(EINVAL)),
    }
}

/// `fallocate(fd, mode, offset, len)` (`fs/open.c` `vfs_fallocate`, x86-64: 285, aarch64: 47).
pub(super) async fn fallocate<R: Resources, M: VirtualMemory, F: Filesystem<R>>(
    process: &Process<R>,
    args: [u64; 6],
    memory: &mut M,
    fs: &mut F,
) -> u64 {
    let fd = args[0] as u32 as i32;
    let mode = args[1] as u32;
    let offset = args[2] as i64;
    let len = args[3] as i64;

    let Some(entry) = process.shared.descriptors.lock().get_entry(fd).cloned() else {
        return errno(EBADF);
    };
    if entry.fdflags() & FDFLAG_PATH != 0 {
        return errno(EBADF);
    }
    if offset < 0 || len <= 0 {
        return errno(EINVAL);
    }
    let supported = match mode {
        0 => true,
        FALLOC_FL_KEEP_SIZE => true,
        m if m == (FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE) => true,
        _ => false,
    };
    if !supported {
        return errno(EOPNOTSUPP);
    }
    match &entry.descriptor {
        FileDescriptor::PipeRead { .. }
        | FileDescriptor::PipeWrite { .. }
        | FileDescriptor::FifoRead(_)
        | FileDescriptor::FifoWrite(_)
        | FileDescriptor::FifoReadWrite(_) => errno(ESPIPE),
        FileDescriptor::File(open) => {
            if !fs.file_access(open.node()).writable() {
                return errno(EBADF);
            }
            if fs.file_is_directory(open.node()) {
                return errno(EISDIR);
            }
            let Some(end) = offset.checked_add(len) else {
                return errno(EFBIG);
            };
            let creds = process_creds(process);
            let stat = match fs.stat_file(open.node()).await {
                Ok(stat) => stat,
                Err(error) => return fs_errno(error),
            };
            if mode == 0 {
                let target = end as u64;
                let fsize = process.limit(super::Resource::Fsize).current;
                if target > fsize {
                    process
                        .shared
                        .signals
                        .raise_thread(&process.signals, SigInfo::from_kernel(Signal::SIGXFSZ));
                    return errno(EFBIG);
                }
                if target > stat.size
                    && let Err(error) = fs.set_size_file(open.node(), target, &creds).await
                {
                    return fs_errno(error);
                }
                0
            } else if mode == FALLOC_FL_KEEP_SIZE {
                // Preallocation without changing `st_size`.
                0
            } else {
                // `FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE`: zero `[offset, min(end, size))`
                // without altering `st_size`. On a sealed memfd (`F_SEAL_WRITE` or
                // `F_SEAL_FUTURE_WRITE`), Linux `mm/shmem.c` `shmem_fallocate` refuses
                // hole punching with `EPERM` even beyond EOF.
                if let Some(seals) = fs.memfd_get_seals(open.node())
                    && seals & (helios_unix::F_SEAL_WRITE | helios_unix::F_SEAL_FUTURE_WRITE) != 0
                {
                    return errno(EPERM);
                }
                let start = offset as u64;
                let limit = (end as u64).min(stat.size);
                if start >= limit {
                    return 0;
                }
                let zeros = [0u8; ZERO_CHUNK_BYTES];
                let mut cursor = start;
                while cursor < limit {
                    let step = ((limit - cursor) as usize).min(ZERO_CHUNK_BYTES);
                    match fs
                        .write_at(
                            open.node(),
                            WritePosition::At(cursor),
                            &zeros[..step],
                            &creds,
                        )
                        .await
                    {
                        Ok(landed) => {
                            if landed.len > 0 {
                                super::memory::sync_write_to_shared_mappings(
                                    process,
                                    open.node(),
                                    landed.offset,
                                    &zeros[..landed.len],
                                    memory,
                                    fs,
                                )
                                .await;
                            }
                            cursor = cursor.saturating_add(step as u64);
                        }
                        Err(error) => return fs_errno(error),
                    }
                }
                0
            }
        }
        FileDescriptor::Preopen { descriptor, .. } => {
            if !fs.file_access(descriptor).writable() {
                return errno(EBADF);
            }
            if fs.file_is_directory(descriptor) {
                return errno(EISDIR);
            }
            errno(ENODEV)
        }
        _ => errno(ENODEV),
    }
}

/// `sync()` (`fs/sync.c`, x86-64: 162, aarch64: 81).
pub(super) async fn sync<R: Resources, M: UserMemory, F: Filesystem<R>>(
    process: &Process<R>,
    memory: &M,
    fs: &mut F,
) -> u64 {
    super::memory::flush_all_shared_mappings(process, memory, fs).await;
    let _ = fs.sync_all().await;
    0
}

/// `syncfs(fd)` (`fs/sync.c`, x86-64: 306, aarch64: 267).
pub(super) async fn syncfs<R: Resources, M: UserMemory, F: Filesystem<R>>(
    process: &Process<R>,
    args: [u64; 6],
    memory: &M,
    fs: &mut F,
) -> u64 {
    let fd = args[0] as u32 as i32;
    let Some(entry) = process.shared.descriptors.lock().get_entry(fd).cloned() else {
        return errno(EBADF);
    };
    if entry.fdflags() & FDFLAG_PATH != 0 {
        return errno(EBADF);
    }
    if let Some(open) = entry_file::<R>(&entry) {
        super::memory::flush_file_shared_mappings(process, open.node(), memory, fs).await;
        if let Err(error) = fs.sync_fs(open.node()).await {
            return fs_errno(error);
        }
    }
    0
}

/// `chroot(path)` (`fs/open.c` `ksys_chroot`, x86-64: 161, aarch64: 51).
///
/// Requires `CAP_SYS_CHROOT`, verifies the target is a searchable directory
/// inside the container, and updates the `CLONE_FS`-shared root prefix strictly
/// within the container's filesystem.
pub(super) async fn chroot<R: Resources, M: UserMemory, F: Filesystem<R>>(
    process: &Process<R>,
    args: [u64; 6],
    memory: &M,
    fs: &F,
) -> u64 {
    let path = match read_user_path(memory, args[0]).await {
        Ok(path) => path,
        Err(err) => return err,
    };
    if path.is_empty() {
        return errno(ENOENT);
    }
    let creds = process_creds(process);
    let (cwd, resolved_path) = match resolve_in_chroot(process, None, &path, true, &creds, fs).await
    {
        Ok(pair) => pair,
        Err(err) => return err,
    };
    let (stat, canonical) = match fs.stat_path(None, &cwd, &resolved_path, true, &creds).await {
        Ok(pair) => pair,
        Err(error) => return fs_errno(error),
    };
    if stat.kind != NodeKind::Directory {
        return errno(ENOTDIR);
    }
    if let Err(error) = fs
        .access_path(
            None,
            &cwd,
            &resolved_path,
            AccessCheck {
                read: false,
                write: false,
                exec: true,
                follow: true,
                use_effective: true,
            },
            &creds,
        )
        .await
    {
        return fs_errno(error);
    }
    if !creds.capabilities.has_effective(CAP_SYS_CHROOT) {
        return errno(EPERM);
    }
    *process.shared.root.lock() = canonical;
    0
}

async fn read_optional_offset<M: UserMemory>(memory: &M, ptr: u64) -> Result<Option<u64>, u64> {
    if ptr == 0 {
        return Ok(None);
    }
    if memory.check_writable(ptr, 8).await.is_err() {
        return Err(EFAULT);
    }
    let mut raw = [0u8; 8];
    memory.read(ptr, &mut raw).await.map_err(|_| EFAULT)?;
    let off = i64::from_le_bytes(raw);
    if off < 0 {
        return Err(EINVAL);
    }
    Ok(Some(off as u64))
}

async fn write_optional_offset<M: UserMemory>(
    memory: &mut M,
    ptr: u64,
    value: u64,
) -> Result<(), u64> {
    if ptr == 0 {
        return Ok(());
    }
    memory
        .write(ptr, &(value as i64).to_le_bytes())
        .await
        .map_err(|_| EFAULT)
}

/// `copy_file_range(fd_in, off_in, fd_out, off_out, len, flags)`
/// (`fs/read_write.c` `vfs_copy_file_range`, x86-64: 326, aarch64: 285).
pub(super) async fn copy_file_range<R: Resources, M: VirtualMemory, F: Filesystem<R>>(
    process: &Process<R>,
    args: [u64; 6],
    memory: &mut M,
    fs: &mut F,
) -> u64 {
    let fd_in = args[0] as u32 as i32;
    let off_in_ptr = args[1];
    let fd_out = args[2] as u32 as i32;
    let off_out_ptr = args[3];
    let len = args[4].min(MAX_RW_COUNT) as usize;
    let flags = args[5] as u32;

    if flags != 0 {
        return errno(EINVAL);
    }
    let (in_entry, out_entry) = {
        let table = process.shared.descriptors.lock();
        let Some(in_e) = table.get_entry(fd_in).cloned() else {
            return errno(EBADF);
        };
        let Some(out_e) = table.get_entry(fd_out).cloned() else {
            return errno(EBADF);
        };
        (in_e, out_e)
    };
    if in_entry.fdflags() & FDFLAG_PATH != 0 || out_entry.fdflags() & FDFLAG_PATH != 0 {
        return errno(EBADF);
    }
    let in_open = match &in_entry.descriptor {
        FileDescriptor::File(open) => open.clone(),
        _ => return errno(EINVAL),
    };
    let out_open = match &out_entry.descriptor {
        FileDescriptor::File(open) => open.clone(),
        _ => return errno(EINVAL),
    };
    if !fs.file_access(in_open.node()).readable() || !fs.file_access(out_open.node()).writable() {
        return errno(EBADF);
    }
    if out_entry.fdflags() & FDFLAG_APPEND != 0 {
        return errno(EBADF);
    }
    if fs.file_is_directory(in_open.node()) || fs.file_is_directory(out_open.node()) {
        return errno(EISDIR);
    }
    let explicit_in = match read_optional_offset(memory, off_in_ptr).await {
        Ok(v) => v,
        Err(err) => return errno(err),
    };
    let explicit_out = match read_optional_offset(memory, off_out_ptr).await {
        Ok(v) => v,
        Err(err) => return errno(err),
    };

    let start_in = match explicit_in {
        Some(off) => off,
        None => in_open.lock_position().await.get(),
    };
    let start_out = match explicit_out {
        Some(off) => off,
        None => out_open.lock_position().await.get(),
    };
    if len > 0 && fs.same_file(in_open.node(), out_open.node()) {
        let end_in = start_in.saturating_add(len as u64);
        let end_out = start_out.saturating_add(len as u64);
        if start_in < end_out && start_out < end_in {
            return errno(EINVAL);
        }
    }
    if len == 0 {
        return 0;
    }

    super::memory::flush_file_shared_mappings(process, in_open.node(), memory, fs).await;
    let creds = process_creds(process);
    let mut total = 0usize;
    while total < len {
        let step = (len - total).min(COPY_CHUNK_BYTES);
        let read_pos = start_in.saturating_add(total as u64);
        let write_pos = start_out.saturating_add(total as u64);
        let chunk = match fs.read_at(in_open.node(), read_pos, step).await {
            Ok(bytes) => bytes,
            Err(error) => {
                if total > 0 {
                    break;
                }
                return fs_errno(error);
            }
        };
        if chunk.is_empty() {
            break;
        }
        let landed = match fs
            .write_at(
                out_open.node(),
                WritePosition::At(write_pos),
                &chunk,
                &creds,
            )
            .await
        {
            Ok(landed) => landed,
            Err(error) => {
                if total > 0 {
                    break;
                }
                return fs_errno(error);
            }
        };
        if landed.len > 0 {
            super::memory::sync_write_to_shared_mappings(
                process,
                out_open.node(),
                landed.offset,
                &chunk[..landed.len],
                memory,
                fs,
            )
            .await;
        }
        total += landed.len;
        if landed.len < chunk.len() {
            break;
        }
    }

    let next_in = start_in.saturating_add(total as u64);
    let next_out = start_out.saturating_add(total as u64);
    if explicit_in.is_some() {
        if let Err(err) = write_optional_offset(memory, off_in_ptr, next_in).await {
            return errno(err);
        }
    } else if total > 0 {
        in_open.lock_position().await.set(next_in);
    }
    if explicit_out.is_some() {
        if let Err(err) = write_optional_offset(memory, off_out_ptr, next_out).await {
            return errno(err);
        }
    } else if total > 0 {
        out_open.lock_position().await.set(next_out);
    }
    total as u64
}

/// `splice(fd_in, off_in, fd_out, off_out, len, flags)`
/// (`fs/splice.c` `do_splice`, x86-64: 275, aarch64: 76).
pub(super) async fn splice<
    R: Resources,
    M: VirtualMemory,
    O: super::Stdio + Filesystem<R> + Network<R::Network>,
>(
    process: &Process<R>,
    args: [u64; 6],
    memory: &mut M,
    output: &mut O,
) -> SyscallOutcome {
    let fd_in = args[0] as u32 as i32;
    let off_in_ptr = args[1];
    let fd_out = args[2] as u32 as i32;
    let off_out_ptr = args[3];
    let len = args[4].min(MAX_RW_COUNT) as usize;
    let flags = args[5] as u32;

    let (in_entry, out_entry) = {
        let table = process.shared.descriptors.lock();
        let Some(in_e) = table.get_entry(fd_in).cloned() else {
            return SyscallOutcome::Return(errno(EBADF));
        };
        let Some(out_e) = table.get_entry(fd_out).cloned() else {
            return SyscallOutcome::Return(errno(EBADF));
        };
        (in_e, out_e)
    };
    if in_entry.fdflags() & FDFLAG_PATH != 0 || out_entry.fdflags() & FDFLAG_PATH != 0 {
        return SyscallOutcome::Return(errno(EBADF));
    }

    let in_is_pipe = matches!(in_entry.descriptor, FileDescriptor::PipeRead { .. });
    let out_is_pipe = matches!(out_entry.descriptor, FileDescriptor::PipeWrite { .. });
    if matches!(in_entry.descriptor, FileDescriptor::PipeWrite { .. })
        || matches!(out_entry.descriptor, FileDescriptor::PipeRead { .. })
    {
        return SyscallOutcome::Return(errno(EBADF));
    }
    if !in_is_pipe && !out_is_pipe {
        return SyscallOutcome::Return(errno(EINVAL));
    }
    if let (
        FileDescriptor::PipeRead { inode: in_ino, .. },
        FileDescriptor::PipeWrite { inode: out_ino, .. },
    ) = (&in_entry.descriptor, &out_entry.descriptor)
        && in_ino.same_pipe(out_ino)
    {
        return SyscallOutcome::Return(errno(EINVAL));
    }
    if in_is_pipe && off_in_ptr != 0 {
        return SyscallOutcome::Return(errno(ESPIPE));
    }
    if out_is_pipe && off_out_ptr != 0 {
        return SyscallOutcome::Return(errno(ESPIPE));
    }

    // Validate non-pipe ends and optional offsets.
    match &in_entry.descriptor {
        FileDescriptor::PipeRead { .. } => {}
        FileDescriptor::File(open) => {
            if !output.file_access(open.node()).readable() {
                return SyscallOutcome::Return(errno(EBADF));
            }
            if output.file_is_directory(open.node()) {
                return SyscallOutcome::Return(errno(EINVAL));
            }
        }
        FileDescriptor::Socket(_) | FileDescriptor::Stdin { .. } | FileDescriptor::NullDevice => {
            if off_in_ptr != 0 {
                return SyscallOutcome::Return(errno(ESPIPE));
            }
        }
        _ => return SyscallOutcome::Return(errno(EBADF)),
    }
    match &out_entry.descriptor {
        FileDescriptor::PipeWrite { .. } => {}
        FileDescriptor::File(open) => {
            if !output.file_access(open.node()).writable() {
                return SyscallOutcome::Return(errno(EBADF));
            }
            if output.file_is_directory(open.node()) {
                return SyscallOutcome::Return(errno(EINVAL));
            }
            if out_entry.fdflags() & FDFLAG_APPEND != 0 {
                return SyscallOutcome::Return(errno(EINVAL));
            }
        }
        FileDescriptor::Socket(_)
        | FileDescriptor::Stdout
        | FileDescriptor::Stderr
        | FileDescriptor::NullDevice => {
            if off_out_ptr != 0 {
                return SyscallOutcome::Return(errno(ESPIPE));
            }
        }
        _ => return SyscallOutcome::Return(errno(EBADF)),
    }

    let explicit_in = match read_optional_offset(memory, off_in_ptr).await {
        Ok(v) => v,
        Err(err) => return SyscallOutcome::Return(errno(err)),
    };
    let explicit_out = match read_optional_offset(memory, off_out_ptr).await {
        Ok(v) => v,
        Err(err) => return SyscallOutcome::Return(errno(err)),
    };

    if len == 0 {
        return SyscallOutcome::Return(0);
    }

    let nonblock_flag = flags & SPLICE_F_NONBLOCK != 0;
    let in_nonblock = nonblock_flag || (in_entry.fdflags() & FDFLAG_NONBLOCK != 0);
    let out_nonblock = nonblock_flag || (out_entry.fdflags() & FDFLAG_NONBLOCK != 0);
    let max_step = len.min(COPY_CHUNK_BYTES);

    // Read one chunk from `fd_in`.
    let (data, in_read_pos): (Bytes, Option<u64>) = match &in_entry.descriptor {
        FileDescriptor::PipeRead { reader, .. } => {
            if in_nonblock {
                match reader.try_read_limit(max_step) {
                    TryRead::Ready(bytes) => (bytes, None),
                    TryRead::Eof => return SyscallOutcome::Return(0),
                    TryRead::Pending => return SyscallOutcome::Return(errno(EAGAIN)),
                }
            } else {
                match process
                    .signals
                    .interruptible(reader.read_limit(max_step))
                    .await
                {
                    WaitOutcome::Ready(Some(bytes)) => (bytes, None),
                    WaitOutcome::Ready(None) => return SyscallOutcome::Return(0),
                    WaitOutcome::Interrupted => return SyscallOutcome::RestartSys,
                }
            }
        }
        FileDescriptor::File(open) => {
            super::memory::flush_file_shared_mappings(process, open.node(), memory, output).await;
            let pos = match explicit_in {
                Some(off) => off,
                None => open.lock_position().await.get(),
            };
            match output.read_at(open.node(), pos, max_step).await {
                Ok(bytes) if bytes.is_empty() => return SyscallOutcome::Return(0),
                Ok(bytes) => (bytes, Some(pos)),
                Err(error) => return SyscallOutcome::Return(fs_errno(error)),
            }
        }
        FileDescriptor::Socket(sock) => {
            let msg_flags = if in_nonblock {
                super::socket::MSG_DONTWAIT
            } else {
                0
            };
            match socket_recv(sock, max_step, msg_flags, output).await {
                Ok(result) if result.data.is_empty() => return SyscallOutcome::Return(0),
                Ok(result) => (result.data, None),
                Err(err) => return SyscallOutcome::Return(errno(err)),
            }
        }
        FileDescriptor::NullDevice => return SyscallOutcome::Return(0),
        FileDescriptor::Stdin { .. } => {
            let _lock = process.shared.stdin_lock.lock().await;
            match output.read_input(max_step).await {
                Ok(bytes) if bytes.is_empty() => return SyscallOutcome::Return(0),
                Ok(bytes) => (bytes, None),
                Err(_) => return SyscallOutcome::Return(errno(EACCES)),
            }
        }
        _ => unreachable!(),
    };

    // Write `data` to `fd_out`.
    let written: usize = match &out_entry.descriptor {
        FileDescriptor::PipeWrite { writer, .. } => {
            let n = data.len();
            let res = if out_nonblock {
                match writer.try_write(data) {
                    TryWrite::Written => Ok(n),
                    TryWrite::Full(_) => Err(Some(EAGAIN)),
                    TryWrite::Closed => Err(Some(EPIPE)),
                }
            } else {
                match process.signals.interruptible(writer.write(data)).await {
                    WaitOutcome::Ready(Ok(())) => Ok(n),
                    WaitOutcome::Ready(Err(_)) => Err(Some(EPIPE)),
                    WaitOutcome::Interrupted => Err(None),
                }
            };
            match res {
                Ok(n) => n,
                Err(Some(EPIPE)) => {
                    process
                        .shared
                        .signals
                        .raise_thread(&process.signals, SigInfo::from_kernel(Signal::SIGPIPE));
                    return SyscallOutcome::Return(errno(EPIPE));
                }
                Err(Some(err)) => return SyscallOutcome::Return(errno(err)),
                Err(None) => return SyscallOutcome::RestartSys,
            }
        }
        FileDescriptor::File(open) => {
            let creds = process_creds(process);
            let out_pos = match explicit_out {
                Some(off) => off,
                None => open.lock_position().await.get(),
            };
            let landed = match output
                .write_at(open.node(), WritePosition::At(out_pos), &data, &creds)
                .await
            {
                Ok(landed) => landed,
                Err(error) => return SyscallOutcome::Return(fs_errno(error)),
            };
            if landed.len > 0 {
                super::memory::sync_write_to_shared_mappings(
                    process,
                    open.node(),
                    landed.offset,
                    &data[..landed.len],
                    memory,
                    output,
                )
                .await;
            }
            let next_out = out_pos.saturating_add(landed.len as u64);
            if explicit_out.is_some() {
                if let Err(err) = write_optional_offset(memory, off_out_ptr, next_out).await {
                    return SyscallOutcome::Return(errno(err));
                }
            } else if landed.len > 0 {
                open.lock_position().await.set(next_out);
            }
            landed.len
        }
        FileDescriptor::Socket(sock) => {
            let msg_flags = if out_nonblock {
                super::socket::MSG_DONTWAIT
            } else {
                0
            };
            match socket_send(
                sock,
                data.to_vec(),
                msg_flags,
                None,
                SocketContext::default(),
                output,
            )
            .await
            {
                Ok(n) => n,
                Err(err) => return SyscallOutcome::Return(errno(err)),
            }
        }
        FileDescriptor::Stdout | FileDescriptor::Stderr => {
            let stream = if matches!(out_entry.descriptor, FileDescriptor::Stdout) {
                Stream::Stdout
            } else {
                Stream::Stderr
            };
            match output.write(stream, &data).await {
                Ok(n) => n,
                Err(err) => {
                    return SyscallOutcome::Return(errno(match err {
                        super::WriteError::Denied => EACCES,
                        super::WriteError::Io => EPIPE,
                        super::WriteError::Interrupted => EINTR,
                        super::WriteError::WouldBlock => EAGAIN,
                    }));
                }
            }
        }
        FileDescriptor::NullDevice => data.len(),
        _ => unreachable!(),
    };

    if let (Descriptor::<R>::File(in_open), Some(pos)) = (&in_entry.descriptor, in_read_pos) {
        let next_in = pos.saturating_add(written as u64);
        if explicit_in.is_some() {
            if let Err(err) = write_optional_offset(memory, off_in_ptr, next_in).await {
                return SyscallOutcome::Return(errno(err));
            }
        } else if written > 0 {
            in_open.lock_position().await.set(next_in);
        }
    }

    SyscallOutcome::Return(written as u64)
}

/// `tee(fd_in, fd_out, len, flags)` (`fs/splice.c` `do_tee`, x86-64: 276, aarch64: 77).
///
/// Duplicates up to `len` bytes from pipe `fd_in` to pipe `fd_out` without
/// consuming the bytes from `fd_in`.
pub(super) async fn tee<R: Resources>(process: &Process<R>, args: [u64; 6]) -> SyscallOutcome {
    let fd_in = args[0] as u32 as i32;
    let fd_out = args[1] as u32 as i32;
    let len = args[2].min(MAX_RW_COUNT) as usize;
    let flags = args[3] as u32;

    let (in_entry, out_entry) = {
        let table = process.shared.descriptors.lock();
        let Some(in_e) = table.get_entry(fd_in).cloned() else {
            return SyscallOutcome::Return(errno(EBADF));
        };
        let Some(out_e) = table.get_entry(fd_out).cloned() else {
            return SyscallOutcome::Return(errno(EBADF));
        };
        (in_e, out_e)
    };
    if in_entry.fdflags() & FDFLAG_PATH != 0 || out_entry.fdflags() & FDFLAG_PATH != 0 {
        return SyscallOutcome::Return(errno(EBADF));
    }

    let (reader, in_inode) = match &in_entry.descriptor {
        FileDescriptor::PipeRead { reader, inode } => (reader.clone(), inode.clone()),
        _ => return SyscallOutcome::Return(errno(EINVAL)),
    };
    let (writer, out_inode) = match &out_entry.descriptor {
        FileDescriptor::PipeWrite { writer, inode } => (writer.clone(), inode.clone()),
        _ => return SyscallOutcome::Return(errno(EINVAL)),
    };
    if in_inode.same_pipe(&out_inode) {
        return SyscallOutcome::Return(errno(EINVAL));
    }
    if len == 0 {
        return SyscallOutcome::Return(0);
    }

    let nonblock_flag = flags & SPLICE_F_NONBLOCK != 0;
    let in_nonblock = nonblock_flag || (in_entry.fdflags() & FDFLAG_NONBLOCK != 0);
    let out_nonblock = nonblock_flag || (out_entry.fdflags() & FDFLAG_NONBLOCK != 0);

    let peeked = if in_nonblock {
        match reader.try_peek_limit(len) {
            TryRead::Ready(bytes) => bytes,
            TryRead::Eof => return SyscallOutcome::Return(0),
            TryRead::Pending => return SyscallOutcome::Return(errno(EAGAIN)),
        }
    } else {
        match process.signals.interruptible(reader.peek_limit(len)).await {
            WaitOutcome::Ready(Some(bytes)) => bytes,
            WaitOutcome::Ready(None) => return SyscallOutcome::Return(0),
            WaitOutcome::Interrupted => return SyscallOutcome::RestartSys,
        }
    };

    let n = peeked.len();
    if out_nonblock {
        match writer.try_write(peeked) {
            TryWrite::Written => SyscallOutcome::Return(n as u64),
            TryWrite::Full(_) => SyscallOutcome::Return(errno(EAGAIN)),
            TryWrite::Closed => {
                process
                    .shared
                    .signals
                    .raise_thread(&process.signals, SigInfo::from_kernel(Signal::SIGPIPE));
                SyscallOutcome::Return(errno(EPIPE))
            }
        }
    } else {
        match process.signals.interruptible(writer.write(peeked)).await {
            WaitOutcome::Ready(Ok(())) => SyscallOutcome::Return(n as u64),
            WaitOutcome::Ready(Err(_)) => {
                process
                    .shared
                    .signals
                    .raise_thread(&process.signals, SigInfo::from_kernel(Signal::SIGPIPE));
                SyscallOutcome::Return(errno(EPIPE))
            }
            WaitOutcome::Interrupted => SyscallOutcome::RestartSys,
        }
    }
}

/// `readahead(fd, offset, count)` (`mm/readahead.c` `ksys_readahead`, x86-64: 187, aarch64: 213).
pub(super) fn readahead<R: Resources, F: Filesystem<R>>(
    process: &Process<R>,
    args: [u64; 6],
    fs: &F,
) -> u64 {
    let fd = args[0] as u32 as i32;
    let offset = args[1] as i64;
    let Some(entry) = process.shared.descriptors.lock().get_entry(fd).cloned() else {
        return errno(EBADF);
    };
    if entry.fdflags() & FDFLAG_PATH != 0 {
        return errno(EBADF);
    }
    let FileDescriptor::File(open) = &entry.descriptor else {
        return errno(EINVAL);
    };
    if !fs.file_access(open.node()).readable() {
        return errno(EBADF);
    }
    if fs.file_is_directory(open.node()) {
        return errno(EINVAL);
    }
    if offset < 0 {
        return errno(EINVAL);
    }
    0
}

// Keep `ST_RDONLY` and `EIO` imports clean if unused in direct helper bodies.
const _: (i64, u64) = (ST_RDONLY, EIO);
