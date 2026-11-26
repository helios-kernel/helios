//! `memfd_create(2)`, `fcntl(2)` file sealing (`F_ADD_SEALS` / `F_GET_SEALS`),
//! and System V shared memory (`shmget`, `shmat`, `shmdt`, `shmctl`).
//!
//! Behaviour, flag validation, permission checks, and LP64 structure layouts
//! follow Linux v6.12 (`mm/memfd.c`, `mm/shmem.c`, `ipc/shm.c`, `ipc/util.c`,
//! `include/uapi/linux/memfd.h`, `include/uapi/linux/ipc.h`,
//! `include/uapi/linux/shm.h`, `include/uapi/asm-generic/shmbuf.h`).

use alloc::string::String;
use alloc::vec::Vec;
use helios_hal::vmm::PageFlags;
use helios_unix::{F_ALL_SEALS, FDFLAG_PATH, FileDescriptor, OpenFile};

use super::fs::{entry_file, fs_errno, process_creds};
use super::{
    Abi, CAP_SYS_ADMIN, Credentials, EACCES, EBADF, EFAULT, EINVAL, EPERM, Entry, Filesystem,
    Process, Resources, System, UserMemory, VirtualMemory, errno, io, memory,
};

// Linux UAPI `include/uapi/linux/capability.h`.
pub const CAP_IPC_LOCK: u32 = 14;
pub const CAP_IPC_OWNER: u32 = 15;

// Linux UAPI `include/uapi/linux/memfd.h`.
pub const MFD_CLOEXEC: u32 = 0x0001;
pub const MFD_ALLOW_SEALING: u32 = 0x0002;
pub const MFD_HUGETLB: u32 = 0x0004;
pub const MFD_NOEXEC_SEAL: u32 = 0x0008;
pub const MFD_EXEC: u32 = 0x0010;
const MFD_SUPPORTED_FLAGS: u32 = MFD_CLOEXEC | MFD_ALLOW_SEALING | MFD_NOEXEC_SEAL | MFD_EXEC;
/// `NAME_MAX (255) - strlen("memfd:") (6)` (`mm/memfd.c` `MFD_NAME_MAX_LEN`).
const MFD_NAME_MAX_LEN: usize = 249;

// Linux UAPI `include/uapi/linux/fcntl.h` sealing commands.
pub(super) const F_ADD_SEALS: u32 = 1033;
pub(super) const F_GET_SEALS: u32 = 1034;

// Linux UAPI `include/uapi/linux/ipc.h` and `include/uapi/linux/shm.h`.
pub const IPC_PRIVATE: i32 = 0;
pub const IPC_CREAT: u32 = 0o0001000;
pub const IPC_EXCL: u32 = 0o0002000;
pub const IPC_NOWAIT: u32 = 0o0004000;

pub const IPC_RMID: u32 = 0;
pub const IPC_SET: u32 = 1;
pub const IPC_STAT: u32 = 2;
pub const IPC_INFO: u32 = 3;
pub const IPC_64: u32 = 0x0100;

pub const SHM_LOCK: u32 = 11;
pub const SHM_UNLOCK: u32 = 12;
pub const SHM_STAT: u32 = 13;
pub const SHM_INFO: u32 = 14;
pub const SHM_STAT_ANY: u32 = 15;

pub const SHM_RDONLY: u32 = 0o010000;
pub const SHM_RND: u32 = 0o020000;
pub const SHM_REMAP: u32 = 0o040000;
pub const SHM_EXEC: u32 = 0o100000;

pub const SHM_DEST: u32 = 0o001000;
pub const SHM_LOCKED: u32 = 0o002000;
pub const SHM_HUGETLB: u32 = 0o004000;
pub const SHM_NORESERVE: u32 = 0o010000;

/// Segment attach alignment (`SHMLBA == PAGE_SIZE` on x86-64 and aarch64).
pub const SHMLBA: u64 = 4096;

/// Default Linux LP64 SysV shared memory limits (`include/uapi/linux/shm.h`).
pub const SHMMIN: u64 = 1;
pub const SHMMAX: u64 = u64::MAX - (1 << 24);
pub const SHMALL: u64 = u64::MAX - (1 << 24);
pub const SHMMNI: u64 = 4096;
pub const SHMSEG: u64 = 4096;

/// Size of LP64 `struct shmid64_ds` (`include/uapi/asm-generic/shmbuf.h`,
/// identical on x86-64 and aarch64).
pub const SHMID64_DS_BYTES: usize = 112;
/// Size of LP64 `struct shminfo64` (`include/uapi/asm-generic/shmbuf.h`).
pub const SHMINFO64_BYTES: usize = 72;
/// Size of LP64 `struct shm_info` (`include/uapi/linux/shm.h`).
pub const SHM_INFO_BYTES: usize = 48;

// Additional errnos (`include/uapi/asm-generic/errno-base.h`).
pub const ENOENT: u64 = 2;
pub const EEXIST: u64 = 17;
pub const ENOSPC: u64 = 28;

/// Permissions and ownership metadata of one SysV IPC segment (`struct ipc64_perm`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShmPerm {
    pub key: i32,
    pub uid: u32,
    pub gid: u32,
    pub cuid: u32,
    pub cgid: u32,
    pub mode: u32,
    pub seq: u16,
}

/// Snapshot of one SysV shared memory segment (`struct shmid64_ds`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShmStat {
    pub perm: ShmPerm,
    pub segsz: u64,
    pub atime: i64,
    pub dtime: i64,
    pub ctime: i64,
    pub cpid: u32,
    pub lpid: u32,
    pub nattch: u64,
}

impl ShmStat {
    /// Encodes LP64 `struct shmid64_ds` (112 bytes, identical layout on both
    /// x86-64 and aarch64 per `include/uapi/asm-generic/shmbuf.h`).
    pub fn encode_shmid64_ds(self) -> [u8; SHMID64_DS_BYTES] {
        let mut out = [0u8; SHMID64_DS_BYTES];
        // `struct ipc64_perm` (48 bytes: offset 0..48):
        out[0..4].copy_from_slice(&self.perm.key.to_le_bytes());
        out[4..8].copy_from_slice(&self.perm.uid.to_le_bytes());
        out[8..12].copy_from_slice(&self.perm.gid.to_le_bytes());
        out[12..16].copy_from_slice(&self.perm.cuid.to_le_bytes());
        out[16..20].copy_from_slice(&self.perm.cgid.to_le_bytes());
        // Write low 16 bits in little-endian `[20..24]` with upper 16 bits zeroed
        // so both glibc (`u16 mode + u16 __pad1`) and musl (`u32 mode`) agree.
        out[20..24].copy_from_slice(&(self.perm.mode & 0xffff).to_le_bytes());
        out[24..26].copy_from_slice(&self.perm.seq.to_le_bytes());
        // `[26..48]` pad / `__unused1` / `__unused2` stay zeroed.

        // Remaining `struct shmid64_ds` fields (offset 48..112):
        out[48..56].copy_from_slice(&self.segsz.to_le_bytes());
        out[56..64].copy_from_slice(&self.atime.to_le_bytes());
        out[64..72].copy_from_slice(&self.dtime.to_le_bytes());
        out[72..80].copy_from_slice(&self.ctime.to_le_bytes());
        out[80..84].copy_from_slice(&(self.cpid as i32).to_le_bytes());
        out[84..88].copy_from_slice(&(self.lpid as i32).to_le_bytes());
        out[88..96].copy_from_slice(&self.nattch.to_le_bytes());
        // `[96..112]` `__unused4` / `__unused5` stay zeroed.
        out
    }

    /// Decodes `(uid, gid, mode & 0o777)` from a user-supplied `struct shmid64_ds`
    /// for `shmctl(..., IPC_SET, buf)`.
    pub fn decode_ipc_set(raw: &[u8; SHMID64_DS_BYTES]) -> (u32, u32, u32) {
        let uid = u32::from_le_bytes(raw[4..8].try_into().unwrap());
        let gid = u32::from_le_bytes(raw[8..12].try_into().unwrap());
        let mode = u32::from(u16::from_le_bytes(raw[20..22].try_into().unwrap())) & 0o777;
        (uid, gid, mode)
    }
}

/// Container-wide SysV shared memory usage statistics (`struct shm_info`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ShmUsageInfo {
    pub used_ids: i32,
    pub shm_tot: u64,
    pub shm_rss: u64,
    pub shm_swp: u64,
    pub swap_attempts: u64,
    pub swap_successes: u64,
}

impl ShmUsageInfo {
    /// Encodes LP64 `struct shm_info` (48 bytes, `include/uapi/linux/shm.h`).
    pub fn encode_shm_info(self) -> [u8; SHM_INFO_BYTES] {
        let mut out = [0u8; SHM_INFO_BYTES];
        out[0..4].copy_from_slice(&self.used_ids.to_le_bytes());
        // `[4..8]` alignment padding stays zeroed.
        out[8..16].copy_from_slice(&self.shm_tot.to_le_bytes());
        out[16..24].copy_from_slice(&self.shm_rss.to_le_bytes());
        out[24..32].copy_from_slice(&self.shm_swp.to_le_bytes());
        out[32..40].copy_from_slice(&self.swap_attempts.to_le_bytes());
        out[40..48].copy_from_slice(&self.swap_successes.to_le_bytes());
        out
    }
}

/// Encodes LP64 `struct shminfo64` (72 bytes, `include/uapi/asm-generic/shmbuf.h`).
pub fn encode_shminfo64() -> [u8; SHMINFO64_BYTES] {
    let mut out = [0u8; SHMINFO64_BYTES];
    out[0..8].copy_from_slice(&SHMMAX.to_le_bytes());
    out[8..16].copy_from_slice(&SHMMIN.to_le_bytes());
    out[16..24].copy_from_slice(&SHMMNI.to_le_bytes());
    out[24..32].copy_from_slice(&SHMSEG.to_le_bytes());
    out[32..40].copy_from_slice(&SHMALL.to_le_bytes());
    out
}

/// Checks Linux SysV IPC DAC permissions (`ipc/util.c` `ipcperms`), honouring
/// `CAP_IPC_OWNER` override.
///
/// `required` holds Linux mode bits in the owner position (`0o400` read,
/// `0o200` write, `0o100` exec) or low 9 bits from `shmget(shmflg)`.
pub fn check_ipc_perms(creds: &Credentials, perm: ShmPerm, required_rwx: u32) -> Result<(), u64> {
    let req = required_rwx & 0o7;
    if req == 0 {
        return Ok(());
    }
    let euid = creds.user.effective;
    let granted = if euid == perm.uid || euid == perm.cuid {
        (perm.mode >> 6) & 0o7
    } else if creds.in_group(perm.gid) || creds.in_group(perm.cgid) {
        (perm.mode >> 3) & 0o7
    } else {
        perm.mode & 0o7
    };
    if (granted & req) == req || creds.capabilities.has_effective(CAP_IPC_OWNER) {
        Ok(())
    } else {
        Err(EACCES)
    }
}

/// Checks owner/creator or `CAP_SYS_ADMIN` privilege for `shmctl(IPC_SET | IPC_RMID)`
/// (`ipc/shm.c` `shmctl_down`).
pub fn check_ipc_owner_or_admin(creds: &Credentials, perm: ShmPerm) -> Result<(), u64> {
    let euid = creds.user.effective;
    if euid == perm.uid || euid == perm.cuid || creds.capabilities.has_effective(CAP_SYS_ADMIN) {
        Ok(())
    } else {
        Err(EPERM)
    }
}

/// Synchronizes `process`'s currently open `memfd` descriptors into the host
/// container so other processes can inspect and reopen `/proc/<pid>/fd/<n>`.
pub(super) fn sync_process_memfds<R: Resources, F: Filesystem<R>>(process: &Process<R>, fs: &F) {
    let entries: Vec<(i32, R::File)> = {
        let table = process.shared.descriptors.lock();
        table
            .entries
            .iter()
            .enumerate()
            .filter_map(|(idx, slot)| {
                let entry = slot.as_ref()?;
                let FileDescriptor::File(open) = &entry.descriptor else {
                    return None;
                };
                fs.memfd_handle(open.node())
                    .map(|_| (idx as i32, open.node().clone()))
            })
            .collect()
    };
    fs.sync_process_memfds(process.pid().get(), &entries);
}

/// Reads a NUL-terminated `memfd_create` name (at most 249 bytes excluding NUL)
/// from user memory (`mm/memfd.c` `SYSCALL_DEFINE2(memfd_create)`).
fn read_memfd_name<M: UserMemory>(memory: &M, mut ptr: u64) -> Result<String, u64> {
    if ptr == 0 {
        return Err(EFAULT);
    }
    let mut bytes = Vec::new();
    let mut chunk = [0u8; 64];
    loop {
        let remaining = (MFD_NAME_MAX_LEN + 1).saturating_sub(bytes.len());
        if remaining == 0 {
            return Err(EINVAL);
        }
        let to_read = chunk.len().min(remaining);
        let slice = if memory.read(ptr, &mut chunk[..to_read]).is_ok() {
            &chunk[..to_read]
        } else {
            let mut byte = [0u8; 1];
            memory.read(ptr, &mut byte).map_err(|_| EFAULT)?;
            chunk[0] = byte[0];
            &chunk[..1]
        };
        if let Some(nul) = slice.iter().position(|&b| b == 0) {
            bytes.extend_from_slice(&slice[..nul]);
            return Ok(String::from_utf8(bytes)
                .unwrap_or_else(|err| String::from_utf8_lossy(err.as_bytes()).into_owned()));
        }
        bytes.extend_from_slice(slice);
        if bytes.len() > MFD_NAME_MAX_LEN {
            return Err(EINVAL);
        }
        ptr = ptr.checked_add(slice.len() as u64).ok_or(EFAULT)?;
    }
}

/// `memfd_create(name, flags)` (`mm/memfd.c`, x86-64: 319, aarch64: 279).
pub(super) fn memfd_create<R: Resources, M: UserMemory, F: Filesystem<R>>(
    process: &Process<R>,
    args: [u64; 6],
    memory: &M,
    fs: &mut F,
) -> u64 {
    let flags = args[1] as u32;
    if (flags & MFD_HUGETLB != 0)
        || (flags & !MFD_SUPPORTED_FLAGS != 0)
        || (flags & (MFD_NOEXEC_SEAL | MFD_EXEC) == (MFD_NOEXEC_SEAL | MFD_EXEC))
    {
        return errno(EINVAL);
    }
    let name = match read_memfd_name(memory, args[0]) {
        Ok(name) => name,
        Err(err) => return errno(err),
    };
    let creds = process_creds(process);
    let (file, handle) = match fs.create_memfd(&name, flags, &creds) {
        Ok(pair) => pair,
        Err(err) => return fs_errno(err),
    };
    let cloexec = flags & MFD_CLOEXEC != 0;
    let entry = Entry::<R>::new(
        FileDescriptor::File(OpenFile::with_memfd_hold(file, handle.acquire_hold())),
        cloexec,
    );
    let inserted = process.shared.descriptors.lock().insert_entry(entry);
    match inserted {
        Ok(fd) => {
            sync_process_memfds(process, fs);
            u64::from(fd)
        }
        Err(err) => {
            fs.reap_memfds();
            io::descriptor_errno(err)
        }
    }
}

/// `fcntl(fd, F_ADD_SEALS | F_GET_SEALS, arg)` (`mm/memfd.c` `memfd_fcntl`).
pub(super) fn fcntl_seals<R: Resources, F: Filesystem<R>>(
    process: &Process<R>,
    fd: i32,
    cmd: u32,
    arg: u64,
    fs: &mut F,
) -> u64 {
    let Some(entry) = process.shared.descriptors.lock().get_entry(fd).cloned() else {
        return errno(EBADF);
    };
    if entry.fdflags() & FDFLAG_PATH != 0 {
        return errno(EBADF);
    }
    let Some(open) = entry_file::<R>(&entry) else {
        return errno(EINVAL);
    };
    match cmd {
        F_GET_SEALS => match fs.memfd_get_seals(open.node()) {
            Some(seals) => u64::from(seals),
            None => errno(EINVAL),
        },
        F_ADD_SEALS => {
            if fs.memfd_get_seals(open.node()).is_none() {
                return errno(EINVAL);
            }
            if !fs.file_access(open.node()).writable() {
                return errno(EPERM);
            }
            let seals = arg as u32;
            if (arg & !u64::from(F_ALL_SEALS)) != 0 || (seals & !F_ALL_SEALS) != 0 {
                return errno(EINVAL);
            }
            match fs.memfd_add_seals(open.node(), seals) {
                Ok(()) => 0,
                Err(err) => fs_errno(err),
            }
        }
        _ => errno(EINVAL),
    }
}

/// `shmget(key, size, shmflg)` (`ipc/shm.c` `ksys_shmget`, x86-64: 29, aarch64: 194).
pub(super) fn shmget<R: Resources, O: System + Filesystem<R>>(
    process: &Process<R>,
    args: [u64; 6],
    output: &mut O,
) -> u64 {
    let key = args[0] as i32;
    let size = args[1];
    let shmflg = args[2] as u32;
    if shmflg & SHM_HUGETLB != 0 {
        return errno(EINVAL);
    }
    let creds = process_creds(process);
    let now_secs = (output.realtime_nanos() / 1_000_000_000) as i64;
    match output.shm_get(key, size, shmflg, process.pid().get(), &creds, now_secs) {
        Ok(shmid) => shmid as u64,
        Err(err) => errno(err),
    }
}

/// `shmat(shmid, shmaddr, shmflg)` (`ipc/shm.c` `do_shmat`, x86-64: 30, aarch64: 196).
pub(super) async fn shmat<R: Resources, M: VirtualMemory, O: System + Filesystem<R>>(
    process: &Process<R>,
    abi: Abi,
    args: [u64; 6],
    memory: &mut M,
    output: &mut O,
) -> u64 {
    let shmid = args[0] as i32;
    let shmaddr = args[1];
    let shmflg = args[2] as u32;

    if shmid < 0 {
        return errno(EINVAL);
    }
    let remap = shmflg & SHM_REMAP != 0;
    let fixed_addr = if shmaddr != 0 {
        if shmaddr & (SHMLBA - 1) != 0 {
            if shmflg & SHM_RND != 0 {
                let rounded = shmaddr & !(SHMLBA - 1);
                if rounded == 0 {
                    return errno(EINVAL);
                }
                Some(rounded)
            } else {
                return errno(EINVAL);
            }
        } else {
            Some(shmaddr)
        }
    } else {
        if remap {
            return errno(EINVAL);
        }
        None
    };

    let read_only = shmflg & SHM_RDONLY != 0;
    let exec = shmflg & SHM_EXEC != 0;
    let creds = process_creds(process);
    let seg_size = match output.shm_prepare_attach(shmid, read_only, exec, &creds) {
        Ok(size) => size,
        Err(err) => return errno(err),
    };
    if seg_size == 0 {
        return errno(EINVAL);
    }
    let mut access = PageFlags::READ;
    if !read_only {
        access |= PageFlags::WRITE;
    }
    if exec {
        access |= PageFlags::EXECUTE;
    }

    let now_secs = (output.realtime_nanos() / 1_000_000_000) as i64;
    let mapped = memory::shmat_map(
        process, abi, shmid, seg_size, fixed_addr, remap, access, !read_only, now_secs, memory,
        output,
    )
    .await;
    match mapped {
        Ok(addr) => {
            output.shm_commit_attach(shmid, process.pid().get(), now_secs);
            addr
        }
        Err(err) => errno(err),
    }
}

/// `shmdt(shmaddr)` (`ipc/shm.c` `ksys_shmdt`, x86-64: 67, aarch64: 197).
pub(super) fn shmdt<R: Resources, M: VirtualMemory, O: System + Filesystem<R>>(
    process: &Process<R>,
    args: [u64; 6],
    memory: &mut M,
    output: &mut O,
) -> u64 {
    let shmaddr = args[0];
    let now_secs = (output.realtime_nanos() / 1_000_000_000) as i64;
    memory::shmdt_unmap(process, shmaddr, now_secs, memory, output)
}

/// `shmctl(shmid, cmd, buf)` (`ipc/shm.c` `ksys_shmctl`, x86-64: 31, aarch64: 195).
pub(super) fn shmctl<R: Resources, M: UserMemory, O: System + Filesystem<R>>(
    process: &Process<R>,
    args: [u64; 6],
    memory: &mut M,
    output: &mut O,
) -> u64 {
    let shmid = args[0] as i32;
    let cmd = (args[1] as u32) & !IPC_64;
    let buf = args[2];
    let creds = process_creds(process);
    let now_secs = (output.realtime_nanos() / 1_000_000_000) as i64;

    match cmd {
        IPC_INFO => {
            if buf == 0 {
                return errno(EFAULT);
            }
            let (max_idx, _) = output.shm_ctl_info();
            let raw = encode_shminfo64();
            if memory.write(buf, &raw).is_err() {
                return errno(EFAULT);
            }
            max_idx as u64
        }
        SHM_INFO => {
            if buf == 0 {
                return errno(EFAULT);
            }
            let (max_idx, info) = output.shm_ctl_info();
            let raw = info.encode_shm_info();
            if memory.write(buf, &raw).is_err() {
                return errno(EFAULT);
            }
            max_idx as u64
        }
        IPC_STAT | SHM_STAT | SHM_STAT_ANY => {
            if buf == 0 {
                return errno(EFAULT);
            }
            let by_index = matches!(cmd, SHM_STAT | SHM_STAT_ANY);
            let check_perms = cmd != SHM_STAT_ANY;
            let (resolved_id, stat) =
                match output.shm_ctl_stat(shmid, by_index, check_perms, &creds) {
                    Ok(pair) => pair,
                    Err(err) => return errno(err),
                };
            let raw = stat.encode_shmid64_ds();
            if memory.write(buf, &raw).is_err() {
                return errno(EFAULT);
            }
            if by_index { resolved_id as u64 } else { 0 }
        }
        IPC_SET => {
            if buf == 0 {
                return errno(EFAULT);
            }
            let mut raw = [0u8; SHMID64_DS_BYTES];
            if memory.read(buf, &mut raw).is_err() {
                return errno(EFAULT);
            }
            let (uid, gid, mode) = ShmStat::decode_ipc_set(&raw);
            match output.shm_ctl_set(shmid, uid, gid, mode, &creds, now_secs) {
                Ok(()) => 0,
                Err(err) => errno(err),
            }
        }
        IPC_RMID => match output.shm_ctl_rmid(shmid, &creds, now_secs) {
            Ok(()) => 0,
            Err(err) => errno(err),
        },
        SHM_LOCK | SHM_UNLOCK => match output.shm_ctl_lock(shmid, cmd == SHM_LOCK, &creds) {
            Ok(()) => 0,
            Err(err) => errno(err),
        },
        _ => errno(EINVAL),
    }
}
