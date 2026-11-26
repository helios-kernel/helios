#![cfg(feature = "runtime")]
//! Dual-architecture (`x86-64` and `aarch64`) Linux v6.12 ABI tests for issue
//! `#1260`: `statfs`/`fstatfs`, `flock`, `fcntl` byte-range locks, `fallocate`,
//! `sync`/`syncfs`, `chroot`, `copy_file_range`, `splice`, `tee`, `readahead`,
//! `times`, `getrusage`, `wait4`/`waitid` `rusage`, `sched_*`, `ioprio_*`,
//! `personality`, extended `prctl` (including `PR_SET_PDEATHSIG` and
//! `PR_SET_CHILD_SUBREAPER`), `syslog`, and `IPPROTO_ICMP` / `IPPROTO_ICMPV6`
//! echo sockets.

use bytes::Bytes;
use core::num::NonZeroU32;
use core::ops::ControlFlow;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use core::task::{Context, Poll, Waker};
use helios_hal::fs::{FsError, Landed, NodeKind, WritePosition};
use helios_hal::vmm::PageFlags;
use helios_linux::abi::{Abi, Operation};
use helios_linux::syscall::{
    AccessCheck, BTRFS_SUPER_MAGIC, CAP_NET_RAW, CAP_SETPCAP, CAP_SYS_ADMIN, CAP_SYS_CHROOT,
    CAP_SYS_NICE, CAP_SYSLOG, Call, Clock, CpuUsage, Credentials, Denied, EAGAIN, FileAccess,
    FileStat, Filesystem, FsOpError, FsStat, IPPROTO_ICMP, IPPROTO_ICMPV6, IcmpDatagram, IpAddr,
    LinuxCapabilities, MapError, MemoryFault, MemoryTotals, Network, OpenRequest, PIPEFS_MAGIC,
    PidNamespace, Process, Region, Resources, SOCKFS_MAGIC, ST_NODEV, ST_NOSUID, ST_RDONLY,
    ST_VALID, SocketReady, SpawnError, SpawnedProcess, SpawnedThread, Start, Stdio, Stream,
    SyscallOutcome, System, TMPFS_MAGIC, Thread, Tty, UserMemory, VirtualMemory, WriteError,
    dispatch, standard_streams,
};
use helios_unix::{
    ChildTermination, FileLockKey, OwnedIcmpSocket, Signal, SocketFamily, SocketLimits,
    SocketNetwork,
};
use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex};

const ABIS: [Abi; 2] = [Abi::X86_64, Abi::Aarch64];
const PROGRAM_BREAK: u64 = 0x40_0000;

const EPERM: u64 = 1;
const ENOENT: u64 = 2;
const ESRCH: u64 = 3;
const EBADF: u64 = 9;
const ENOTDIR: u64 = 20;
const EINVAL: u64 = 22;
const ESPIPE: u64 = 29;
const EOPNOTSUPP: u64 = 95;
const EFAULT: u64 = 14;

const AT_FDCWD: u64 = (-100i64) as u64;
const O_RDONLY: u64 = 0;
const O_RDWR: u64 = 2;
const O_CREAT: u64 = 0x40;

const LOCK_SH: u64 = 1;
const LOCK_EX: u64 = 2;
const LOCK_NB: u64 = 4;
const LOCK_UN: u64 = 8;

const F_GETLK: u64 = 5;
const F_SETLK: u64 = 6;
const F_SETLKW: u64 = 7;
const F_RDLCK: i16 = 0;
const F_WRLCK: i16 = 1;
const F_UNLCK: i16 = 2;

const FALLOC_FL_KEEP_SIZE: u64 = 0x01;
const FALLOC_FL_PUNCH_HOLE: u64 = 0x02;

const SPLICE_F_NONBLOCK: u64 = 0x02;

const RUSAGE_SELF: u64 = 0;
const RUSAGE_CHILDREN: u64 = (-1i32) as u32 as u64;
const RUSAGE_THREAD: u64 = 1;

const SCHED_OTHER: i32 = 0;
const SCHED_FIFO: i32 = 1;
const SCHED_RR: i32 = 2;
const SCHED_BATCH: i32 = 3;
const SCHED_IDLE: i32 = 5;
const SCHED_RESET_ON_FORK: u32 = 0x4000_0000;

const IOPRIO_WHO_PROCESS: u64 = 1;
const IOPRIO_WHO_PGRP: u64 = 2;
const IOPRIO_WHO_USER: u64 = 3;
const IOPRIO_CLASS_RT: u16 = 1;
const IOPRIO_CLASS_BE: u16 = 2;
const IOPRIO_CLASS_IDLE: u16 = 3;

const PR_SET_PDEATHSIG: u64 = 1;
const PR_GET_PDEATHSIG: u64 = 2;
const PR_GET_DUMPABLE: u64 = 3;
const PR_SET_DUMPABLE: u64 = 4;
const PR_SET_NAME: u64 = 15;
const PR_GET_NAME: u64 = 16;
const PR_CAPBSET_READ: u64 = 23;
const PR_CAPBSET_DROP: u64 = 24;
const PR_SET_CHILD_SUBREAPER: u64 = 36;
const PR_GET_CHILD_SUBREAPER: u64 = 37;
const PR_CAP_AMBIENT: u64 = 47;
const PR_CAP_AMBIENT_IS_SET: u64 = 1;
const PR_CAP_AMBIENT_RAISE: u64 = 2;
const PR_CAP_AMBIENT_LOWER: u64 = 3;
const PR_CAP_AMBIENT_CLEAR_ALL: u64 = 4;

const SYSLOG_ACTION_READ: u64 = 2;
const SYSLOG_ACTION_READ_ALL: u64 = 3;
const SYSLOG_ACTION_READ_CLEAR: u64 = 4;
const SYSLOG_ACTION_CLEAR: u64 = 5;
const SYSLOG_ACTION_SIZE_UNREAD: u64 = 9;
const SYSLOG_ACTION_SIZE_BUFFER: u64 = 10;

const AF_INET: u64 = 2;
const AF_INET6: u64 = 10;
const SOCK_DGRAM: u64 = 2;
const SOCK_RAW: u64 = 3;
const SOL_SOCKET: u64 = 1;
const SO_PROTOCOL: u64 = 38;
const IPPROTO_IP: u64 = 0;
const IP_TTL: i32 = 2;
const IP_RECVTTL: u64 = 12;
const IPPROTO_IPV6: u64 = 41;
const IPV6_RECVHOPLIMIT: u64 = 51;
const IPV6_HOPLIMIT: i32 = 52;

fn err(code: u64) -> u64 {
    code.wrapping_neg()
}

fn number(abi: Abi, op: Operation) -> u64 {
    for n in 0..=450 {
        if abi.operation(n) == op {
            return n;
        }
    }
    panic!("no syscall number for {op:?} on {abi:?}");
}

fn block_on<F: core::future::Future>(future: F) -> F::Output {
    let mut cx = Context::from_waker(Waker::noop());
    let mut pinned = core::pin::pin!(future);
    match pinned.as_mut().poll(&mut cx) {
        Poll::Ready(out) => out,
        Poll::Pending => panic!("unexpected Pending in synchronous test"),
    }
}

#[derive(Clone)]
struct Mem {
    base: u64,
    bytes: Arc<Mutex<Vec<u8>>>,
}

impl Mem {
    fn new() -> Self {
        Self {
            base: 0x10_0000,
            bytes: Arc::new(Mutex::new(vec![0u8; 65_536])),
        }
    }

    fn write_cstr(&mut self, addr: u64, s: &str) {
        let mut buf = s.as_bytes().to_vec();
        buf.push(0);
        self.write(addr, &buf).unwrap();
    }

    fn read_bytes(&self, addr: u64, len: usize) -> Vec<u8> {
        let mut out = vec![0u8; len];
        self.read(addr, &mut out).unwrap();
        out
    }

    fn read_cstr(&self, addr: u64, max: usize) -> String {
        let raw = self.read_bytes(addr, max);
        let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
        String::from_utf8(raw[..end].to_vec()).unwrap()
    }
}

impl UserMemory for Mem {
    fn check_writable(&self, address: u64, length: usize) -> Result<(), MemoryFault> {
        let off = address.checked_sub(self.base).ok_or(MemoryFault)? as usize;
        let end = off.checked_add(length).ok_or(MemoryFault)?;
        if end <= self.bytes.lock().unwrap().len() {
            Ok(())
        } else {
            Err(MemoryFault)
        }
    }

    fn read(&self, address: u64, output: &mut [u8]) -> Result<(), MemoryFault> {
        let off = address.checked_sub(self.base).ok_or(MemoryFault)? as usize;
        let end = off.checked_add(output.len()).ok_or(MemoryFault)?;
        let guard = self.bytes.lock().unwrap();
        if end > guard.len() {
            return Err(MemoryFault);
        }
        output.copy_from_slice(&guard[off..end]);
        Ok(())
    }

    fn write(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryFault> {
        let off = address.checked_sub(self.base).ok_or(MemoryFault)? as usize;
        let end = off.checked_add(bytes.len()).ok_or(MemoryFault)?;
        let mut guard = self.bytes.lock().unwrap();
        if end > guard.len() {
            return Err(MemoryFault);
        }
        guard[off..end].copy_from_slice(bytes);
        Ok(())
    }

    fn atomic_load_u32(&self, address: u64) -> Result<u32, MemoryFault> {
        let mut raw = [0u8; 4];
        self.read(address, &mut raw)?;
        Ok(u32::from_le_bytes(raw))
    }

    fn atomic_store_u32(&mut self, address: u64, value: u32) -> Result<(), MemoryFault> {
        self.write(address, &value.to_le_bytes())
    }

    fn atomic_compare_exchange_u32(
        &mut self,
        address: u64,
        expected: u32,
        desired: u32,
    ) -> Result<Result<u32, u32>, MemoryFault> {
        let cur = self.atomic_load_u32(address)?;
        if cur == expected {
            self.atomic_store_u32(address, desired)?;
            Ok(Ok(cur))
        } else {
            Ok(Err(cur))
        }
    }
}

impl VirtualMemory for Mem {
    fn lowest_address(&self) -> u64 {
        self.base
    }
    fn map_anywhere(&mut self, _: u64, _: u64, _: PageFlags) -> Result<u64, MapError> {
        Err(MapError::OutOfMemory)
    }
    fn map_at(&mut self, _: u64, _: u64, _: PageFlags) -> Result<(), MapError> {
        Err(MapError::OutOfMemory)
    }
    fn unmap(&mut self, _: u64, _: u64) {}
    fn protect(&mut self, _: u64, _: u64, _: PageFlags) -> Result<(), MapError> {
        Ok(())
    }
    fn discard(&mut self, _: u64, _: u64) {}
    fn remap(&mut self, _: u64, _: u64, _: u64, _: u64) -> Result<(), MapError> {
        Err(MapError::OutOfMemory)
    }
    fn region(&self, _: u64, _: u64) -> Option<Region> {
        None
    }
    fn free_range(&self, _: u64, _: u64) -> Option<u64> {
        None
    }
}

#[derive(Clone)]
struct TestNet {
    closed_icmp: Arc<Mutex<Vec<u64>>>,
}

impl Default for TestNet {
    fn default() -> Self {
        Self {
            closed_icmp: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

impl SocketNetwork for TestNet {
    type Address = IpAddr;
    type TcpStream = u64;
    type TcpListener = u64;
    type UdpSocket = u64;
    type PacketSocket = u64;

    const LIMITS: SocketLimits = SocketLimits {
        receive_buffer_bytes: 65_536,
        send_buffer_bytes: 65_536,
        default_hop_limit: 64,
    };

    fn tcp_close(&self, _: u64) {}
    fn tcp_listener_close(&self, _: u64) {}
    fn udp_close(&self, _: u64) {}
    fn packet_close(&self, _: u64) {}
    fn icmp_close(&self, socket: u64) {
        self.closed_icmp.lock().unwrap().push(socket);
    }
}

#[derive(Clone)]
struct TestFile {
    ino: u64,
    path: String,
    access: FileAccess,
    is_dir: bool,
}

struct TestRes;
impl Resources for TestRes {
    type File = TestFile;
    type Network = TestNet;
    type Data = u64;
}

#[derive(Clone)]
enum FsEntry {
    Dir,
    File { ino: u64, data: Vec<u8> },
    Symlink { target: String },
}

struct IcmpSlot {
    family: SocketFamily,
    is_raw: bool,
    local_id: u16,
    queue: VecDeque<IcmpDatagram>,
}

struct TestHost {
    entries: Arc<Mutex<BTreeMap<String, FsEntry>>>,
    next_ino: Arc<AtomicU64>,
    fs_type: i64,
    sync_all_count: Arc<AtomicUsize>,
    sync_fs_count: Arc<AtomicUsize>,
    now_ns: u64,
    user_ns: u64,
    sys_ns: u64,
    thread_user_ns: u64,
    thread_sys_ns: u64,
    max_rss_kib: u64,
    processors: u32,
    syslog_read_cap: bool,
    syslog_clear_cap: bool,
    syslog_buf: Vec<u8>,
    syslog_cursor: usize,
    net: TestNet,
    icmp_next: Arc<AtomicU64>,
    icmp_slots: Arc<Mutex<BTreeMap<u64, IcmpSlot>>>,
    icmp_allow_dgram: bool,
    icmp_allow_raw: bool,
}

impl Default for TestHost {
    fn default() -> Self {
        let mut map = BTreeMap::new();
        map.insert(String::from("/"), FsEntry::Dir);
        Self {
            entries: Arc::new(Mutex::new(map)),
            next_ino: Arc::new(AtomicU64::new(10)),
            fs_type: BTRFS_SUPER_MAGIC,
            sync_all_count: Arc::new(AtomicUsize::new(0)),
            sync_fs_count: Arc::new(AtomicUsize::new(0)),
            now_ns: 2_500_000_000,
            user_ns: 1_200_000_000,
            sys_ns: 350_000_000,
            thread_user_ns: 400_000_000,
            thread_sys_ns: 120_000_000,
            max_rss_kib: 4096,
            processors: 4,
            syslog_read_cap: true,
            syslog_clear_cap: true,
            syslog_buf: b"<6>[0.000001] kernel: boot ok\n".to_vec(),
            syslog_cursor: 0,
            net: TestNet::default(),
            icmp_next: Arc::new(AtomicU64::new(1)),
            icmp_slots: Arc::new(Mutex::new(BTreeMap::new())),
            icmp_allow_dgram: true,
            icmp_allow_raw: true,
        }
    }
}

impl TestHost {
    fn add_dir(&self, path: &str) {
        self.entries
            .lock()
            .unwrap()
            .insert(normalize(path), FsEntry::Dir);
    }

    fn add_file(&self, path: &str, data: &[u8]) -> u64 {
        let ino = self.next_ino.fetch_add(1, Ordering::Relaxed);
        self.entries.lock().unwrap().insert(
            normalize(path),
            FsEntry::File {
                ino,
                data: data.to_vec(),
            },
        );
        ino
    }

    fn add_symlink(&self, path: &str, target: &str) {
        self.entries.lock().unwrap().insert(
            normalize(path),
            FsEntry::Symlink {
                target: String::from(target),
            },
        );
    }

    fn file_bytes(&self, path: &str) -> Vec<u8> {
        match self.entries.lock().unwrap().get(&normalize(path)) {
            Some(FsEntry::File { data, .. }) => data.clone(),
            _ => panic!("missing file {path}"),
        }
    }
}

fn normalize(path: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for seg in path.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                let _ = parts.pop();
            }
            p => parts.push(p),
        }
    }
    if parts.is_empty() {
        String::from("/")
    } else {
        format!("/{}", parts.join("/"))
    }
}

fn join_norm(cwd: &str, path: &str) -> String {
    if path.starts_with('/') {
        normalize(path)
    } else if cwd.ends_with('/') {
        normalize(&format!("{cwd}{path}"))
    } else {
        normalize(&format!("{cwd}/{path}"))
    }
}

impl Clock for TestHost {
    fn now_nanos(&self) -> u64 {
        self.now_ns
    }
    async fn sleep_until(&self, _: u64) {}
}

impl Stdio for TestHost {
    async fn write(&mut self, _: Stream, bytes: &[u8]) -> Result<usize, WriteError> {
        Ok(bytes.len())
    }
    async fn read_input(&mut self, _: usize) -> Result<Bytes, Denied> {
        Ok(Bytes::new())
    }
}

impl Tty for TestHost {}

impl System for TestHost {
    fn realtime_nanos(&self) -> u64 {
        self.now_ns
    }
    fn set_realtime_nanos(&mut self, _: u64) -> Result<(), Denied> {
        Ok(())
    }
    fn cpu_nanos(&self) -> u64 {
        self.thread_user_ns
    }
    fn process_cpu_nanos(&self) -> u64 {
        self.user_ns
    }
    fn thread_sys_nanos(&self) -> u64 {
        self.thread_sys_ns
    }
    fn process_sys_nanos(&self) -> u64 {
        self.sys_ns
    }
    fn max_rss_kib(&self) -> u64 {
        self.max_rss_kib
    }
    fn processor_count(&self) -> u32 {
        self.processors
    }
    fn fill_random(&mut self, out: &mut [u8]) {
        out.fill(0x5a);
    }
    fn memory(&self) -> MemoryTotals {
        MemoryTotals {
            total_bytes: 1 << 30,
            free_bytes: 1 << 29,
        }
    }
    fn process_count(&self) -> u32 {
        1
    }
    fn kernel_version(&self) -> &str {
        "#1 Helios test"
    }
    fn syslog_check_authority(&self) -> Result<(), Denied> {
        if self.syslog_read_cap || self.syslog_clear_cap {
            Ok(())
        } else {
            Err(Denied)
        }
    }
    fn syslog_buffer_size(&self) -> usize {
        65_536
    }
    fn syslog_unread_size(&self) -> usize {
        self.syslog_buf.len().saturating_sub(self.syslog_cursor)
    }
    fn syslog_read(&mut self, all: bool, clear: bool, max_bytes: usize) -> Result<Vec<u8>, Denied> {
        if clear {
            if !self.syslog_clear_cap {
                return Err(Denied);
            }
        } else {
            self.syslog_check_authority()?;
        }
        let start = if all { 0 } else { self.syslog_cursor };
        let avail = &self.syslog_buf[start..];
        let take = avail.len().min(max_bytes);
        let out = avail[..take].to_vec();
        if !all {
            self.syslog_cursor += take;
        }
        if clear {
            self.syslog_buf.clear();
            self.syslog_cursor = 0;
        }
        Ok(out)
    }
    fn syslog_clear(&mut self) -> Result<(), Denied> {
        if !self.syslog_clear_cap {
            return Err(Denied);
        }
        self.syslog_buf.clear();
        self.syslog_cursor = 0;
        Ok(())
    }
}

impl Filesystem<TestRes> for TestHost {
    fn file_access(&self, file: &TestFile) -> FileAccess {
        file.access
    }
    fn file_is_directory(&self, file: &TestFile) -> bool {
        file.is_dir
    }
    fn file_path<'a>(&self, file: &'a TestFile) -> Option<&'a str> {
        Some(&file.path)
    }
    fn same_file(&self, a: &TestFile, b: &TestFile) -> bool {
        a.ino == b.ino
    }
    fn file_lock_key(&self, file: &TestFile) -> Option<FileLockKey> {
        Some(FileLockKey {
            dev: 1,
            ino: file.ino,
        })
    }
    async fn statfs_path(
        &self,
        base: Option<&TestFile>,
        cwd: &str,
        path: &str,
        _: &Credentials,
    ) -> Result<FsStat, FsOpError> {
        let effective_cwd = base.map_or(cwd, |b| b.path.as_str());
        let full = join_norm(effective_cwd, path);
        if !self.entries.lock().unwrap().contains_key(&full) {
            return Err(FsOpError::Fs(FsError::NoEntry));
        }
        Ok(FsStat {
            f_type: self.fs_type,
            f_bsize: 4096,
            f_blocks: 1000,
            f_bfree: 600,
            f_bavail: 550,
            f_files: 500,
            f_ffree: 400,
            f_fsid: [0x1122_3344, 0x5566_7788],
            f_namelen: 255,
            f_frsize: 4096,
            f_flags: ST_VALID | ST_NOSUID | ST_NODEV,
        })
    }
    async fn statfs_file(&self, _: &TestFile) -> Result<FsStat, FsOpError> {
        Ok(FsStat {
            f_type: self.fs_type,
            f_bsize: 4096,
            f_blocks: 1000,
            f_bfree: 600,
            f_bavail: 550,
            f_files: 500,
            f_ffree: 400,
            f_fsid: [0x1122_3344, 0x5566_7788],
            f_namelen: 255,
            f_frsize: 4096,
            f_flags: ST_VALID | ST_RDONLY,
        })
    }
    async fn sync_all(&self) -> Result<(), FsOpError> {
        self.sync_all_count.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
    async fn sync_fs(&self, _: &TestFile) -> Result<(), FsOpError> {
        self.sync_fs_count.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
    async fn open(
        &mut self,
        base: Option<&TestFile>,
        cwd: &str,
        path: &str,
        request: OpenRequest,
        _: &Credentials,
    ) -> Result<TestFile, FsOpError> {
        let effective_cwd = base.map_or(cwd, |b| b.path.as_str());
        let full = join_norm(effective_cwd, path);
        let mut guard = self.entries.lock().unwrap();
        let entry = match guard.get(&full) {
            Some(e) => e.clone(),
            None if request.create => {
                let ino = self.next_ino.fetch_add(1, Ordering::Relaxed);
                let created = FsEntry::File {
                    ino,
                    data: Vec::new(),
                };
                guard.insert(full.clone(), created.clone());
                created
            }
            None => return Err(FsOpError::Fs(FsError::NoEntry)),
        };
        let access = match (request.read, request.write) {
            (true, true) => FileAccess::ReadWrite,
            (true, false) => FileAccess::ReadOnly,
            (false, true) => FileAccess::WriteOnly,
            (false, false) => FileAccess::PathOnly,
        };
        match entry {
            FsEntry::Dir => Ok(TestFile {
                ino: 1,
                path: full,
                access,
                is_dir: true,
            }),
            FsEntry::File { ino, .. } => {
                if request.directory {
                    return Err(FsOpError::Fs(FsError::NotDirectory));
                }
                Ok(TestFile {
                    ino,
                    path: full,
                    access,
                    is_dir: false,
                })
            }
            FsEntry::Symlink { .. } => Err(FsOpError::Fs(FsError::Loop)),
        }
    }
    async fn stat_path(
        &self,
        base: Option<&TestFile>,
        cwd: &str,
        path: &str,
        follow: bool,
        _: &Credentials,
    ) -> Result<(FileStat, String), FsOpError> {
        let effective_cwd = base.map_or(cwd, |b| b.path.as_str());
        let mut full = join_norm(effective_cwd, path);
        let guard = self.entries.lock().unwrap();
        for _ in 0..8 {
            match guard.get(&full) {
                Some(FsEntry::Dir) => {
                    return Ok((
                        FileStat {
                            dev: 1,
                            ino: 1,
                            kind: NodeKind::Directory,
                            permissions: 0o755,
                            nlink: 2,
                            uid: 0,
                            gid: 0,
                            rdev: 0,
                            size: 0,
                            access_nanos: 0,
                            modified_nanos: 0,
                            status_nanos: 0,
                        },
                        full,
                    ));
                }
                Some(FsEntry::File { ino, data }) => {
                    return Ok((
                        FileStat {
                            dev: 1,
                            ino: *ino,
                            kind: NodeKind::File,
                            permissions: 0o644,
                            nlink: 1,
                            uid: 0,
                            gid: 0,
                            rdev: 0,
                            size: data.len() as u64,
                            access_nanos: 0,
                            modified_nanos: 0,
                            status_nanos: 0,
                        },
                        full,
                    ));
                }
                Some(FsEntry::Symlink { target }) => {
                    if !follow {
                        return Ok((
                            FileStat {
                                dev: 1,
                                ino: 2,
                                kind: NodeKind::Symlink,
                                permissions: 0o777,
                                nlink: 1,
                                uid: 0,
                                gid: 0,
                                rdev: 0,
                                size: target.len() as u64,
                                access_nanos: 0,
                                modified_nanos: 0,
                                status_nanos: 0,
                            },
                            full,
                        ));
                    }
                    full = join_norm(full.rsplit_once('/').map_or("/", |(p, _)| p), target);
                }
                None => return Err(FsOpError::Fs(FsError::NoEntry)),
            }
        }
        Err(FsOpError::Fs(FsError::Loop))
    }
    async fn stat_file(&self, file: &TestFile) -> Result<FileStat, FsOpError> {
        let guard = self.entries.lock().unwrap();
        match guard.get(&file.path) {
            Some(FsEntry::File { ino, data }) => Ok(FileStat {
                dev: 1,
                ino: *ino,
                kind: NodeKind::File,
                permissions: 0o644,
                nlink: 1,
                uid: 0,
                gid: 0,
                rdev: 0,
                size: data.len() as u64,
                access_nanos: 0,
                modified_nanos: 0,
                status_nanos: 0,
            }),
            Some(FsEntry::Dir) => Ok(FileStat {
                dev: 1,
                ino: 1,
                kind: NodeKind::Directory,
                permissions: 0o755,
                nlink: 2,
                uid: 0,
                gid: 0,
                rdev: 0,
                size: 0,
                access_nanos: 0,
                modified_nanos: 0,
                status_nanos: 0,
            }),
            _ => Err(FsOpError::Fs(FsError::NoEntry)),
        }
    }
    async fn read_link(
        &self,
        base: Option<&TestFile>,
        cwd: &str,
        path: &str,
        _: &Credentials,
    ) -> Result<String, FsOpError> {
        let effective_cwd = base.map_or(cwd, |b| b.path.as_str());
        let full = join_norm(effective_cwd, path);
        match self.entries.lock().unwrap().get(&full) {
            Some(FsEntry::Symlink { target }) => Ok(target.clone()),
            Some(_) => Err(FsOpError::Fs(FsError::Unsupported)),
            None => Err(FsOpError::Fs(FsError::NoEntry)),
        }
    }
    async fn access_path(
        &self,
        base: Option<&TestFile>,
        cwd: &str,
        path: &str,
        _: AccessCheck,
        _: &Credentials,
    ) -> Result<(), FsOpError> {
        let effective_cwd = base.map_or(cwd, |b| b.path.as_str());
        let full = join_norm(effective_cwd, path);
        if self.entries.lock().unwrap().contains_key(&full) {
            Ok(())
        } else {
            Err(FsOpError::Fs(FsError::NoEntry))
        }
    }
    async fn read_at(&self, file: &TestFile, offset: u64, len: usize) -> Result<Bytes, FsOpError> {
        let guard = self.entries.lock().unwrap();
        let Some(FsEntry::File { data, .. }) = guard.get(&file.path) else {
            return Err(FsOpError::Fs(FsError::IsDirectory));
        };
        let start = (offset as usize).min(data.len());
        let end = start.saturating_add(len).min(data.len());
        Ok(Bytes::copy_from_slice(&data[start..end]))
    }
    async fn write_at(
        &mut self,
        file: &TestFile,
        position: WritePosition,
        bytes: &[u8],
        _: &Credentials,
    ) -> Result<Landed, FsOpError> {
        let mut guard = self.entries.lock().unwrap();
        let Some(FsEntry::File { data, .. }) = guard.get_mut(&file.path) else {
            return Err(FsOpError::Fs(FsError::IsDirectory));
        };
        let off = match position {
            WritePosition::At(pos) => pos as usize,
            WritePosition::End => data.len(),
        };
        let end = off + bytes.len();
        if end > data.len() {
            data.resize(end, 0);
        }
        data[off..end].copy_from_slice(bytes);
        Ok(Landed {
            offset: off as u64,
            len: bytes.len(),
        })
    }
    async fn set_size_file(
        &mut self,
        file: &TestFile,
        size: u64,
        _: &Credentials,
    ) -> Result<(), FsOpError> {
        let mut guard = self.entries.lock().unwrap();
        let Some(FsEntry::File { data, .. }) = guard.get_mut(&file.path) else {
            return Err(FsOpError::Fs(FsError::IsDirectory));
        };
        data.resize(size as usize, 0);
        Ok(())
    }
}

impl Network<TestNet> for TestHost {
    fn to_ip(&self, address: IpAddr) -> IpAddr {
        address
    }
    fn encode_ip(&self, ip: IpAddr) -> IpAddr {
        ip
    }
    fn check_icmp_open(&self, is_raw: bool) -> Result<(), u64> {
        if is_raw {
            if self.icmp_allow_raw {
                Ok(())
            } else {
                Err(EPERM)
            }
        } else if self.icmp_allow_dgram {
            Ok(())
        } else {
            Err(13) // EACCES
        }
    }
    fn icmp_open(
        &self,
        family: SocketFamily,
        is_raw: bool,
    ) -> Result<(Arc<OwnedIcmpSocket<TestNet>>, u16), u64> {
        let id = self.icmp_next.fetch_add(1, Ordering::Relaxed);
        let local_id = if is_raw { 0 } else { (0x2000 + id) as u16 };
        self.icmp_slots.lock().unwrap().insert(
            id,
            IcmpSlot {
                family,
                is_raw,
                local_id,
                queue: VecDeque::new(),
            },
        );
        Ok((OwnedIcmpSocket::new(self.net.clone(), id), local_id))
    }
    fn icmp_bind(&self, socket: u64, requested_id: u16) -> Result<u16, u64> {
        let mut slots = self.icmp_slots.lock().unwrap();
        let slot = slots.get_mut(&socket).ok_or(EBADF)?;
        if !slot.is_raw && requested_id != 0 {
            slot.local_id = requested_id;
        }
        Ok(slot.local_id)
    }
    async fn icmp_send<'a>(
        &'a self,
        socket: u64,
        destination: IpAddr,
        identifier: u16,
        sequence: u16,
        payload: &'a [u8],
        hop_limit: u8,
    ) -> Result<(), u64> {
        let mut slots = self.icmp_slots.lock().unwrap();
        let slot = slots.get_mut(&socket).ok_or(EBADF)?;
        let mut reply = vec![0u8; 8 + payload.len()];
        reply[0] = match slot.family {
            SocketFamily::Ipv4 => 0,   // Echo Reply
            SocketFamily::Ipv6 => 129, // ICMPv6 Echo Reply
        };
        reply[4..6].copy_from_slice(&identifier.to_be_bytes());
        reply[6..8].copy_from_slice(&sequence.to_be_bytes());
        reply[8..].copy_from_slice(payload);
        slot.queue.push_back(IcmpDatagram {
            source: destination,
            destination,
            ttl: if hop_limit == 0 { 64 } else { hop_limit },
            payload: Bytes::from(reply),
        });
        Ok(())
    }
    async fn icmp_receive(
        &self,
        socket: u64,
        _timeout_nanos: u64,
        peek: bool,
    ) -> Result<Option<IcmpDatagram>, u64> {
        let mut slots = self.icmp_slots.lock().unwrap();
        let slot = slots.get_mut(&socket).ok_or(EBADF)?;
        Ok(if peek {
            slot.queue.front().cloned()
        } else {
            slot.queue.pop_front()
        })
    }
    async fn icmp_readiness(&self, socket: u64) -> Result<SocketReady, u64> {
        let slots = self.icmp_slots.lock().unwrap();
        let slot = slots.get(&socket).ok_or(EBADF)?;
        Ok(SocketReady {
            readable: !slot.queue.is_empty(),
            writable: true,
            hangup: false,
        })
    }
}

#[derive(Default)]
struct TestThread {
    spawned_threads: Vec<Process<TestRes>>,
    spawned_processes: Vec<SpawnedProcess<TestRes>>,
}

impl Thread<TestRes> for TestThread {
    fn thread_pointer(&self) -> u64 {
        0
    }
    fn set_thread_pointer(&mut self, _: u64) -> Result<(), Denied> {
        Ok(())
    }
    fn spawn_thread(
        &mut self,
        child: Process<TestRes>,
        _: SpawnedThread,
    ) -> Result<(), SpawnError> {
        self.spawned_threads.push(child);
        Ok(())
    }
    fn spawn_process(&mut self, child: SpawnedProcess<TestRes>) -> Result<(), SpawnError> {
        self.spawned_processes.push(child);
        Ok(())
    }
}

fn new_proc(
    abi: Abi,
    pid: u32,
    pids: Option<PidNamespace>,
    creds: Credentials,
) -> Process<TestRes> {
    let start = Start {
        pids,
        credentials: creds,
        ..Start::default()
    };
    Process::with_descriptors(
        abi,
        NonZeroU32::new(pid).unwrap(),
        PROGRAM_BREAK,
        standard_streams::<TestRes>(),
        start,
    )
}

fn call(
    proc: &mut Process<TestRes>,
    abi: Abi,
    op: Operation,
    args: [u64; 6],
    mem: &mut Mem,
    thread: &mut TestThread,
    host: &mut TestHost,
) -> SyscallOutcome {
    match block_on(dispatch(
        proc,
        Call {
            number: number(abi, op),
            arguments: args,
        },
        mem,
        thread,
        host,
    )) {
        ControlFlow::Continue(outcome) => outcome,
        ControlFlow::Break(exit) => panic!("unexpected exit {exit:?}"),
    }
}

fn call_ret(
    proc: &mut Process<TestRes>,
    abi: Abi,
    op: Operation,
    args: [u64; 6],
    mem: &mut Mem,
    thread: &mut TestThread,
    host: &mut TestHost,
) -> u64 {
    match call(proc, abi, op, args, mem, thread, host) {
        SyscallOutcome::Return(v) => v,
        other => panic!("expected Return for {op:?}, got {other:?}"),
    }
}

fn open_file(
    proc: &mut Process<TestRes>,
    abi: Abi,
    path: &str,
    flags: u64,
    mem: &mut Mem,
    thread: &mut TestThread,
    host: &mut TestHost,
) -> u64 {
    let addr = mem.base + 0x100;
    mem.write_cstr(addr, path);
    call_ret(
        proc,
        abi,
        Operation::Openat,
        [AT_FDCWD, addr, flags, 0o644, 0, 0],
        mem,
        thread,
        host,
    )
}

fn make_pipe(
    proc: &mut Process<TestRes>,
    abi: Abi,
    mem: &mut Mem,
    thread: &mut TestThread,
    host: &mut TestHost,
) -> (u64, u64) {
    let fds_addr = mem.base + 0x200;
    let ret = call_ret(
        proc,
        abi,
        Operation::Pipe2,
        [fds_addr, 0, 0, 0, 0, 0],
        mem,
        thread,
        host,
    );
    assert_eq!(ret, 0);
    let raw = mem.read_bytes(fds_addr, 8);
    let r = i32::from_le_bytes(raw[0..4].try_into().unwrap()) as u64;
    let w = i32::from_le_bytes(raw[4..8].try_into().unwrap()) as u64;
    (r, w)
}

#[test]
fn statfs_and_fstatfs_write_120_byte_lp64_layout_on_both_abis() {
    for abi in ABIS {
        let mut host = TestHost::default();
        host.add_file("/data.bin", b"hello");
        let mut mem = Mem::new();
        let mut thread = TestThread::default();
        let mut proc = new_proc(abi, 1, None, Credentials::root());

        let path_addr = mem.base + 0x10;
        let buf_addr = mem.base + 0x1000;
        mem.write_cstr(path_addr, "/data.bin");
        let ret = call_ret(
            &mut proc,
            abi,
            Operation::Statfs,
            [path_addr, buf_addr, 0, 0, 0, 0],
            &mut mem,
            &mut thread,
            &mut host,
        );
        assert_eq!(ret, 0);
        let raw = mem.read_bytes(buf_addr, 120);
        assert_eq!(
            i64::from_le_bytes(raw[0..8].try_into().unwrap()),
            BTRFS_SUPER_MAGIC
        );
        assert_eq!(i64::from_le_bytes(raw[8..16].try_into().unwrap()), 4096);
        assert_eq!(u64::from_le_bytes(raw[16..24].try_into().unwrap()), 1000);
        assert_eq!(u64::from_le_bytes(raw[24..32].try_into().unwrap()), 600);
        assert_eq!(u64::from_le_bytes(raw[32..40].try_into().unwrap()), 550);
        assert_eq!(u64::from_le_bytes(raw[40..48].try_into().unwrap()), 500);
        assert_eq!(u64::from_le_bytes(raw[48..56].try_into().unwrap()), 400);
        assert_eq!(
            i32::from_le_bytes(raw[56..60].try_into().unwrap()),
            0x1122_3344
        );
        assert_eq!(
            i32::from_le_bytes(raw[60..64].try_into().unwrap()),
            0x5566_7788
        );
        assert_eq!(i64::from_le_bytes(raw[64..72].try_into().unwrap()), 255);
        assert_eq!(i64::from_le_bytes(raw[72..80].try_into().unwrap()), 4096);
        assert_eq!(
            i64::from_le_bytes(raw[80..88].try_into().unwrap()),
            ST_VALID | ST_NOSUID | ST_NODEV
        );

        // Pipe reports PIPEFS_MAGIC via fstatfs.
        let (rfd, _) = make_pipe(&mut proc, abi, &mut mem, &mut thread, &mut host);
        assert_eq!(
            call_ret(
                &mut proc,
                abi,
                Operation::Fstatfs,
                [rfd, buf_addr, 0, 0, 0, 0],
                &mut mem,
                &mut thread,
                &mut host,
            ),
            0
        );
        let pipe_raw = mem.read_bytes(buf_addr, 120);
        assert_eq!(
            i64::from_le_bytes(pipe_raw[0..8].try_into().unwrap()),
            PIPEFS_MAGIC
        );

        // Socket reports SOCKFS_MAGIC via fstatfs.
        let sock = call_ret(
            &mut proc,
            abi,
            Operation::Socket,
            [AF_INET, SOCK_DGRAM, IPPROTO_ICMP as u64, 0, 0, 0],
            &mut mem,
            &mut thread,
            &mut host,
        );
        assert!(sock < 100);
        assert_eq!(
            call_ret(
                &mut proc,
                abi,
                Operation::Fstatfs,
                [sock, buf_addr, 0, 0, 0, 0],
                &mut mem,
                &mut thread,
                &mut host,
            ),
            0
        );
        let sock_raw = mem.read_bytes(buf_addr, 120);
        assert_eq!(
            i64::from_le_bytes(sock_raw[0..8].try_into().unwrap()),
            SOCKFS_MAGIC
        );

        // Bad fd returns EBADF, missing path returns ENOENT.
        assert_eq!(
            call_ret(
                &mut proc,
                abi,
                Operation::Fstatfs,
                [99, buf_addr, 0, 0, 0, 0],
                &mut mem,
                &mut thread,
                &mut host,
            ),
            err(EBADF)
        );
        mem.write_cstr(path_addr, "/nope");
        assert_eq!(
            call_ret(
                &mut proc,
                abi,
                Operation::Statfs,
                [path_addr, buf_addr, 0, 0, 0, 0],
                &mut mem,
                &mut thread,
                &mut host,
            ),
            err(ENOENT)
        );
        let _ = TMPFS_MAGIC;
    }
}

#[test]
fn flock_shared_exclusive_dup_async_wakeup_and_eintr() {
    for abi in ABIS {
        let mut host = TestHost::default();
        host.add_file("/lockfile", b"abc");
        let pids = PidNamespace::new();
        let mut mem = Mem::new();
        let mut thread = TestThread::default();
        let mut p1 = new_proc(abi, 1, Some(pids.clone()), Credentials::root());
        let mut p2 = new_proc(abi, 2, Some(pids), Credentials::root());

        let fd1 = open_file(
            &mut p1,
            abi,
            "/lockfile",
            O_RDWR,
            &mut mem,
            &mut thread,
            &mut host,
        );
        let fd1_dup = call_ret(
            &mut p1,
            abi,
            Operation::Dup,
            [fd1, 0, 0, 0, 0, 0],
            &mut mem,
            &mut thread,
            &mut host,
        );
        let fd2 = open_file(
            &mut p2,
            abi,
            "/lockfile",
            O_RDWR,
            &mut mem,
            &mut thread,
            &mut host,
        );

        // Acquire LOCK_EX on fd1.
        assert_eq!(
            call_ret(
                &mut p1,
                abi,
                Operation::Flock,
                [fd1, LOCK_EX, 0, 0, 0, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            0
        );
        // Same open file description via dup can downgrade to LOCK_SH.
        assert_eq!(
            call_ret(
                &mut p1,
                abi,
                Operation::Flock,
                [fd1_dup, LOCK_SH | LOCK_NB, 0, 0, 0, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            0
        );
        // Separate open file description fd2 can also take LOCK_SH.
        assert_eq!(
            call_ret(
                &mut p2,
                abi,
                Operation::Flock,
                [fd2, LOCK_SH | LOCK_NB, 0, 0, 0, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            0
        );
        // Exclusive LOCK_NB on fd1 conflicts with fd2's LOCK_SH.
        assert_eq!(
            call_ret(
                &mut p1,
                abi,
                Operation::Flock,
                [fd1, LOCK_EX | LOCK_NB, 0, 0, 0, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            err(EAGAIN)
        );
        // Release fd2's lock by closing fd2; now fd1 acquires LOCK_EX!
        assert_eq!(
            call_ret(
                &mut p2,
                abi,
                Operation::Close,
                [fd2, 0, 0, 0, 0, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            0
        );
        assert_eq!(
            call_ret(
                &mut p1,
                abi,
                Operation::Flock,
                [fd1, LOCK_EX | LOCK_NB, 0, 0, 0, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            0
        );

        // Blocking flock on fd2b suspends until signal interrupts -> RestartSys.
        let fd2b = open_file(
            &mut p2,
            abi,
            "/lockfile",
            O_RDWR,
            &mut mem,
            &mut thread,
            &mut host,
        );
        let mut cx = Context::from_waker(Waker::noop());
        let sig_handle = p2.process_signals();
        {
            let mut fut = core::pin::pin!(dispatch(
                &mut p2,
                Call {
                    number: number(abi, Operation::Flock),
                    arguments: [fd2b, LOCK_EX, 0, 0, 0, 0],
                },
                &mut mem,
                &mut thread,
                &mut host,
            ));
            assert!(matches!(fut.as_mut().poll(&mut cx), Poll::Pending));
            sig_handle.raise_external(Signal::SIGUSR1);
            assert_eq!(
                fut.as_mut().poll(&mut cx),
                Poll::Ready(ControlFlow::Continue(SyscallOutcome::RestartSys))
            );
        }

        // Closing fd1 alone keeps lock alive via fd1_dup; closing fd1_dup releases it.
        assert_eq!(
            call_ret(
                &mut p1,
                abi,
                Operation::Close,
                [fd1, 0, 0, 0, 0, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            0
        );
        assert_eq!(
            call_ret(
                &mut p2,
                abi,
                Operation::Flock,
                [fd2b, LOCK_EX | LOCK_NB, 0, 0, 0, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            err(EAGAIN)
        );
        assert_eq!(
            call_ret(
                &mut p1,
                abi,
                Operation::Close,
                [fd1_dup, 0, 0, 0, 0, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            0
        );
        assert_eq!(
            call_ret(
                &mut p2,
                abi,
                Operation::Flock,
                [fd2b, LOCK_EX | LOCK_NB, 0, 0, 0, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            0
        );
        assert_eq!(
            call_ret(
                &mut p2,
                abi,
                Operation::Flock,
                [fd2b, LOCK_UN, 0, 0, 0, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            0
        );
        assert_eq!(
            call_ret(
                &mut p2,
                abi,
                Operation::Flock,
                [fd2b, 0x99, 0, 0, 0, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            err(EINVAL)
        );
    }
}

fn write_flock_struct(
    mem: &mut Mem,
    addr: u64,
    l_type: i16,
    l_whence: i16,
    l_start: i64,
    l_len: i64,
) {
    let mut raw = [0u8; 32];
    raw[0..2].copy_from_slice(&l_type.to_le_bytes());
    raw[2..4].copy_from_slice(&l_whence.to_le_bytes());
    raw[8..16].copy_from_slice(&l_start.to_le_bytes());
    raw[16..24].copy_from_slice(&l_len.to_le_bytes());
    mem.write(addr, &raw).unwrap();
}

#[test]
fn fcntl_posix_byte_range_locks_and_close_release() {
    for abi in ABIS {
        let mut host = TestHost::default();
        host.add_file("/rec", b"0123456789abcdef");
        let pids = PidNamespace::new();
        let mut mem = Mem::new();
        let mut thread = TestThread::default();
        let mut p1 = new_proc(abi, 10, Some(pids.clone()), Credentials::root());
        let mut p2 = new_proc(abi, 20, Some(pids), Credentials::root());

        let fd1a = open_file(
            &mut p1,
            abi,
            "/rec",
            O_RDWR,
            &mut mem,
            &mut thread,
            &mut host,
        );
        let fd1b = open_file(
            &mut p1,
            abi,
            "/rec",
            O_RDONLY,
            &mut mem,
            &mut thread,
            &mut host,
        );
        let fd2 = open_file(
            &mut p2,
            abi,
            "/rec",
            O_RDWR,
            &mut mem,
            &mut thread,
            &mut host,
        );

        let flk = mem.base + 0x500;
        // WRLCK on read-only fd returns EBADF.
        write_flock_struct(&mut mem, flk, F_WRLCK, 0, 0, 10);
        assert_eq!(
            call_ret(
                &mut p1,
                abi,
                Operation::Fcntl,
                [fd1b, F_SETLK, flk, 0, 0, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            err(EBADF)
        );

        // p1 locks [0, 10) exclusively.
        write_flock_struct(&mut mem, flk, F_WRLCK, 0, 0, 10);
        assert_eq!(
            call_ret(
                &mut p1,
                abi,
                Operation::Fcntl,
                [fd1a, F_SETLK, flk, 0, 0, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            0
        );
        // p2 probes via F_GETLK on [4, 8): sees conflict owned by pid 10.
        write_flock_struct(&mut mem, flk, F_RDLCK, 0, 4, 4);
        assert_eq!(
            call_ret(
                &mut p2,
                abi,
                Operation::Fcntl,
                [fd2, F_GETLK, flk, 0, 0, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            0
        );
        let out = mem.read_bytes(flk, 32);
        assert_eq!(i16::from_le_bytes(out[0..2].try_into().unwrap()), F_WRLCK);
        assert_eq!(i64::from_le_bytes(out[8..16].try_into().unwrap()), 0);
        assert_eq!(i64::from_le_bytes(out[16..24].try_into().unwrap()), 10);
        assert_eq!(i32::from_le_bytes(out[24..28].try_into().unwrap()), 10);

        // p1 unlocks middle [3, 6), splitting [0, 10) into [0, 3) and [6, 10).
        write_flock_struct(&mut mem, flk, F_UNLCK, 0, 3, 3);
        assert_eq!(
            call_ret(
                &mut p1,
                abi,
                Operation::Fcntl,
                [fd1a, F_SETLK, flk, 0, 0, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            0
        );
        // p2 can now lock [3, 6) cleanly.
        write_flock_struct(&mut mem, flk, F_WRLCK, 0, 3, 3);
        assert_eq!(
            call_ret(
                &mut p2,
                abi,
                Operation::Fcntl,
                [fd2, F_SETLK, flk, 0, 0, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            0
        );

        // POSIX semantics: closing ANY fd referencing the same file in p1 (fd1b)
        // releases ALL POSIX locks held by p1 on that file!
        assert_eq!(
            call_ret(
                &mut p1,
                abi,
                Operation::Close,
                [fd1b, 0, 0, 0, 0, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            0
        );
        write_flock_struct(&mut mem, flk, F_WRLCK, 0, 0, 10);
        assert_eq!(
            call_ret(
                &mut p2,
                abi,
                Operation::Fcntl,
                [fd2, F_SETLKW, flk, 0, 0, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            0
        );
    }
}

#[test]
fn fallocate_sync_and_syncfs_semantics() {
    for abi in ABIS {
        let mut host = TestHost::default();
        host.add_file("/alloc", b"hello");
        let mut mem = Mem::new();
        let mut thread = TestThread::default();
        let mut proc = new_proc(abi, 1, None, Credentials::root());

        let fd = open_file(
            &mut proc,
            abi,
            "/alloc",
            O_RDWR,
            &mut mem,
            &mut thread,
            &mut host,
        );
        let ro_fd = open_file(
            &mut proc,
            abi,
            "/alloc",
            O_RDONLY,
            &mut mem,
            &mut thread,
            &mut host,
        );

        // mode == 0 extends file with zeros.
        assert_eq!(
            call_ret(
                &mut proc,
                abi,
                Operation::Fallocate,
                [fd, 0, 5, 5, 0, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            0
        );
        assert_eq!(host.file_bytes("/alloc"), b"hello\0\0\0\0\0");

        // FALLOC_FL_KEEP_SIZE keeps apparent size unchanged.
        assert_eq!(
            call_ret(
                &mut proc,
                abi,
                Operation::Fallocate,
                [fd, FALLOC_FL_KEEP_SIZE, 8, 10, 0, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            0
        );
        assert_eq!(host.file_bytes("/alloc").len(), 10);

        // FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE zeroes range without changing size.
        assert_eq!(
            call_ret(
                &mut proc,
                abi,
                Operation::Fallocate,
                [fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, 1, 3, 0, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            0
        );
        assert_eq!(host.file_bytes("/alloc"), b"h\0\0\0o\0\0\0\0\0");

        // Error precedence: punch hole without KEEP_SIZE -> EOPNOTSUPP, bad len -> EINVAL, RO -> EBADF.
        assert_eq!(
            call_ret(
                &mut proc,
                abi,
                Operation::Fallocate,
                [fd, FALLOC_FL_PUNCH_HOLE, 0, 2, 0, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            err(EOPNOTSUPP)
        );
        assert_eq!(
            call_ret(
                &mut proc,
                abi,
                Operation::Fallocate,
                [fd, 0, 0, 0, 0, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            err(EINVAL)
        );
        assert_eq!(
            call_ret(
                &mut proc,
                abi,
                Operation::Fallocate,
                [ro_fd, 0, 0, 4, 0, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            err(EBADF)
        );

        // Pipe returns ESPIPE.
        let (rfd, _) = make_pipe(&mut proc, abi, &mut mem, &mut thread, &mut host);
        assert_eq!(
            call_ret(
                &mut proc,
                abi,
                Operation::Fallocate,
                [rfd, 0, 0, 4, 0, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            err(ESPIPE)
        );

        // sync and syncfs.
        assert_eq!(
            call_ret(
                &mut proc,
                abi,
                Operation::Sync,
                [0; 6],
                &mut mem,
                &mut thread,
                &mut host
            ),
            0
        );
        assert_eq!(host.sync_all_count.load(Ordering::Relaxed), 1);
        assert_eq!(
            call_ret(
                &mut proc,
                abi,
                Operation::Syncfs,
                [fd, 0, 0, 0, 0, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            0
        );
        assert_eq!(host.sync_fs_count.load(Ordering::Relaxed), 1);
        assert_eq!(
            call_ret(
                &mut proc,
                abi,
                Operation::Syncfs,
                [99, 0, 0, 0, 0, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            err(EBADF)
        );
    }
}

#[test]
fn chroot_clamps_paths_symlinks_and_getcwd_and_enforces_cap() {
    for abi in ABIS {
        let mut host = TestHost::default();
        host.add_dir("/outside");
        host.add_file("/outside/secret", b"top-secret");
        host.add_dir("/jail");
        host.add_dir("/jail/sub");
        host.add_file("/jail/hello", b"inside-jail");
        host.add_symlink("/jail/escape", "/outside/secret");

        let mut mem = Mem::new();
        let mut thread = TestThread::default();

        // Without CAP_SYS_CHROOT -> EPERM.
        let mut unpriv_creds = Credentials::root();
        unpriv_creds.capabilities = LinuxCapabilities::for_uid(1000);
        let mut unpriv = new_proc(abi, 1, None, unpriv_creds);
        let paddr = mem.base + 0x10;
        mem.write_cstr(paddr, "/jail");
        assert_eq!(
            call_ret(
                &mut unpriv,
                abi,
                Operation::Chroot,
                [paddr, 0, 0, 0, 0, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            err(EPERM)
        );

        // Privileged process chroots into /jail while cwd is /outside.
        let mut proc = new_proc(abi, 2, None, Credentials::root());
        mem.write_cstr(paddr, "/outside");
        assert_eq!(
            call_ret(
                &mut proc,
                abi,
                Operation::Chdir,
                [paddr, 0, 0, 0, 0, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            0
        );
        // Non-directory fails ENOTDIR.
        mem.write_cstr(paddr, "/outside/secret");
        assert_eq!(
            call_ret(
                &mut proc,
                abi,
                Operation::Chroot,
                [paddr, 0, 0, 0, 0, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            err(ENOTDIR)
        );
        // Valid chroot.
        mem.write_cstr(paddr, "/jail");
        assert_eq!(
            call_ret(
                &mut proc,
                abi,
                Operation::Chroot,
                [paddr, 0, 0, 0, 0, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            0
        );

        // getcwd reports (unreachable)/outside while cwd is outside root!
        let cwd_buf = mem.base + 0x400;
        assert!(
            call_ret(
                &mut proc,
                abi,
                Operation::Getcwd,
                [cwd_buf, 128, 0, 0, 0, 0],
                &mut mem,
                &mut thread,
                &mut host
            ) < 128
        );
        assert_eq!(mem.read_cstr(cwd_buf, 128), "(unreachable)/outside");

        // chdir("/") moves into /jail and getcwd reports "/".
        mem.write_cstr(paddr, "/");
        assert_eq!(
            call_ret(
                &mut proc,
                abi,
                Operation::Chdir,
                [paddr, 0, 0, 0, 0, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            0
        );
        assert!(
            call_ret(
                &mut proc,
                abi,
                Operation::Getcwd,
                [cwd_buf, 128, 0, 0, 0, 0],
                &mut mem,
                &mut thread,
                &mut host
            ) < 128
        );
        assert_eq!(mem.read_cstr(cwd_buf, 128), "/");

        // Absolute path "/hello" opens "/jail/hello".
        let fd = open_file(
            &mut proc,
            abi,
            "/hello",
            O_RDONLY,
            &mut mem,
            &mut thread,
            &mut host,
        );
        assert!(fd < 100);
        let rbuf = mem.base + 0x600;
        let n = call_ret(
            &mut proc,
            abi,
            Operation::Read,
            [fd, rbuf, 64, 0, 0, 0],
            &mut mem,
            &mut thread,
            &mut host,
        );
        assert_eq!(&mem.read_bytes(rbuf, n as usize), b"inside-jail");

        // ".." traversal clamps at /jail and cannot reach /outside/secret.
        assert_eq!(
            open_file(
                &mut proc,
                abi,
                "/../../../outside/secret",
                O_RDONLY,
                &mut mem,
                &mut thread,
                &mut host
            ),
            err(ENOENT)
        );
        // Symlink pointing to "/outside/secret" resolves inside /jail -> ENOENT!
        assert_eq!(
            open_file(
                &mut proc,
                abi,
                "/escape",
                O_RDONLY,
                &mut mem,
                &mut thread,
                &mut host
            ),
            err(ENOENT)
        );
        let _ = CAP_SYS_CHROOT;
    }
}

#[test]
fn copy_file_range_splice_tee_and_readahead() {
    for abi in ABIS {
        let mut host = TestHost::default();
        host.add_file("/src", b"0123456789ABCDEF");
        host.add_file("/dst", b"");
        let mut mem = Mem::new();
        let mut thread = TestThread::default();
        let mut proc = new_proc(abi, 1, None, Credentials::root());

        let src = open_file(
            &mut proc,
            abi,
            "/src",
            O_RDWR,
            &mut mem,
            &mut thread,
            &mut host,
        );
        let dst = open_file(
            &mut proc,
            abi,
            "/dst",
            O_RDWR,
            &mut mem,
            &mut thread,
            &mut host,
        );

        // copy_file_range with explicit offsets.
        let off_in = mem.base + 0x300;
        let off_out = mem.base + 0x308;
        mem.write(off_in, &4i64.to_le_bytes()).unwrap();
        mem.write(off_out, &2i64.to_le_bytes()).unwrap();
        assert_eq!(
            call_ret(
                &mut proc,
                abi,
                Operation::CopyFileRange,
                [src, off_in, dst, off_out, 6, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            6
        );
        assert_eq!(host.file_bytes("/dst"), b"\x00\x00456789");
        assert_eq!(
            i64::from_le_bytes(mem.read_bytes(off_in, 8).try_into().unwrap()),
            10
        );
        assert_eq!(
            i64::from_le_bytes(mem.read_bytes(off_out, 8).try_into().unwrap()),
            8
        );
        // Same-file overlapping copy_file_range -> EINVAL.
        mem.write(off_in, &0i64.to_le_bytes()).unwrap();
        mem.write(off_out, &2i64.to_le_bytes()).unwrap();
        assert_eq!(
            call_ret(
                &mut proc,
                abi,
                Operation::CopyFileRange,
                [src, off_in, src, off_out, 4, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            err(EINVAL)
        );

        // splice file -> pipe1, tee pipe1 -> pipe2 (non-consuming!), splice pipe2 -> /dst2.
        let (p1r, p1w) = make_pipe(&mut proc, abi, &mut mem, &mut thread, &mut host);
        let (p2r, p2w) = make_pipe(&mut proc, abi, &mut mem, &mut thread, &mut host);
        mem.write(off_in, &0i64.to_le_bytes()).unwrap();
        assert_eq!(
            call_ret(
                &mut proc,
                abi,
                Operation::Splice,
                [src, off_in, p1w, 0, 10, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            10
        );
        // tee duplicates p1r -> p2w without draining p1r!
        assert_eq!(
            call_ret(
                &mut proc,
                abi,
                Operation::Tee,
                [p1r, p2w, 10, 0, 0, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            10
        );
        // Same pipe tee -> EINVAL.
        assert_eq!(
            call_ret(
                &mut proc,
                abi,
                Operation::Tee,
                [p1r, p1w, 4, 0, 0, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            err(EINVAL)
        );
        // Read both pipes: both yield "0123456789".
        let rbuf = mem.base + 0x700;
        let n1 = call_ret(
            &mut proc,
            abi,
            Operation::Read,
            [p1r, rbuf, 16, 0, 0, 0],
            &mut mem,
            &mut thread,
            &mut host,
        );
        assert_eq!(&mem.read_bytes(rbuf, n1 as usize), b"0123456789");
        let dst2 = open_file(
            &mut proc,
            abi,
            "/dst2",
            O_RDWR | O_CREAT,
            &mut mem,
            &mut thread,
            &mut host,
        );
        assert_eq!(
            call_ret(
                &mut proc,
                abi,
                Operation::Splice,
                [p2r, 0, dst2, 0, 10, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            10
        );
        assert_eq!(host.file_bytes("/dst2"), b"0123456789");
        // Empty pipe tee with SPLICE_F_NONBLOCK -> EAGAIN.
        assert_eq!(
            call_ret(
                &mut proc,
                abi,
                Operation::Tee,
                [p1r, p2w, 4, SPLICE_F_NONBLOCK, 0, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            err(EAGAIN)
        );
        // Offset on pipe in splice -> ESPIPE.
        assert_eq!(
            call_ret(
                &mut proc,
                abi,
                Operation::Splice,
                [p1r, off_in, dst2, 0, 4, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            err(ESPIPE)
        );

        // readahead on regular file succeeds, pipe fails EINVAL.
        assert_eq!(
            call_ret(
                &mut proc,
                abi,
                Operation::Readahead,
                [src, 0, 4096, 0, 0, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            0
        );
        assert_eq!(
            call_ret(
                &mut proc,
                abi,
                Operation::Readahead,
                [p1r, 0, 4096, 0, 0, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            err(EINVAL)
        );
    }
}

#[test]
fn times_getrusage_and_wait4_rusage_accounting() {
    for abi in ABIS {
        let mut host = TestHost::default();
        let pids = PidNamespace::new();
        let mut mem = Mem::new();
        let mut thread = TestThread::default();
        let mut parent = new_proc(abi, 1, Some(pids), Credentials::root());

        // Fork a child (via clone(SIGCHLD) so both x86-64 and AArch64 work),
        // record child usage, exit child, and reap via wait4 with rusage ptr!
        let child_pid = call_ret(
            &mut parent,
            abi,
            Operation::Clone,
            [17, 0, 0, 0, 0, 0],
            &mut mem,
            &mut thread,
            &mut host,
        );
        assert!(child_pid > 1);
        let child = thread.spawned_processes.pop().unwrap().child;
        child.record_usage(CpuUsage {
            user_nanos: 500_000_000,
            sys_nanos: 250_000_000,
            max_rss_kib: 8192,
        });
        child.mark_exited(ChildTermination::Exited(0));

        let status_ptr = mem.base + 0x100;
        let ru_ptr = mem.base + 0x200;
        assert_eq!(
            call_ret(
                &mut parent,
                abi,
                Operation::Wait4,
                [child_pid, status_ptr, 0, ru_ptr, 0, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            child_pid
        );
        let child_ru = mem.read_bytes(ru_ptr, 144);
        assert_eq!(i64::from_le_bytes(child_ru[0..8].try_into().unwrap()), 0); // utime tv_sec
        assert_eq!(
            i64::from_le_bytes(child_ru[8..16].try_into().unwrap()),
            500_000
        ); // utime tv_usec
        assert_eq!(i64::from_le_bytes(child_ru[16..24].try_into().unwrap()), 0); // stime tv_sec
        assert_eq!(
            i64::from_le_bytes(child_ru[24..32].try_into().unwrap()),
            250_000
        ); // stime tv_usec
        assert_eq!(
            i64::from_le_bytes(child_ru[32..40].try_into().unwrap()),
            8192
        ); // ru_maxrss

        // getrusage(RUSAGE_SELF), RUSAGE_CHILDREN, RUSAGE_THREAD.
        assert_eq!(
            call_ret(
                &mut parent,
                abi,
                Operation::Getrusage,
                [RUSAGE_SELF, ru_ptr, 0, 0, 0, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            0
        );
        let self_ru = mem.read_bytes(ru_ptr, 144);
        assert_eq!(i64::from_le_bytes(self_ru[0..8].try_into().unwrap()), 1);
        assert_eq!(
            i64::from_le_bytes(self_ru[8..16].try_into().unwrap()),
            200_000
        );
        assert_eq!(
            i64::from_le_bytes(self_ru[24..32].try_into().unwrap()),
            350_000
        );
        assert_eq!(
            i64::from_le_bytes(self_ru[32..40].try_into().unwrap()),
            4096
        );

        assert_eq!(
            call_ret(
                &mut parent,
                abi,
                Operation::Getrusage,
                [RUSAGE_CHILDREN, ru_ptr, 0, 0, 0, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            0
        );
        let children_ru = mem.read_bytes(ru_ptr, 144);
        assert_eq!(
            i64::from_le_bytes(children_ru[8..16].try_into().unwrap()),
            500_000
        );
        assert_eq!(
            i64::from_le_bytes(children_ru[32..40].try_into().unwrap()),
            8192
        );

        assert_eq!(
            call_ret(
                &mut parent,
                abi,
                Operation::Getrusage,
                [RUSAGE_THREAD, ru_ptr, 0, 0, 0, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            0
        );
        let thr_ru = mem.read_bytes(ru_ptr, 144);
        assert_eq!(
            i64::from_le_bytes(thr_ru[8..16].try_into().unwrap()),
            400_000
        );
        assert_eq!(
            i64::from_le_bytes(thr_ru[24..32].try_into().unwrap()),
            120_000
        );

        assert_eq!(
            call_ret(
                &mut parent,
                abi,
                Operation::Getrusage,
                [99, ru_ptr, 0, 0, 0, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            err(EINVAL)
        );

        // times(2): USER_HZ = 100 ticks (10ms per tick).
        let tms_ptr = mem.base + 0x400;
        let ticks = call_ret(
            &mut parent,
            abi,
            Operation::Times,
            [tms_ptr, 0, 0, 0, 0, 0],
            &mut mem,
            &mut thread,
            &mut host,
        );
        assert_eq!(ticks, 250); // 2.5s * 100
        let tms = mem.read_bytes(tms_ptr, 32);
        assert_eq!(i64::from_le_bytes(tms[0..8].try_into().unwrap()), 120); // 1.2s
        assert_eq!(i64::from_le_bytes(tms[8..16].try_into().unwrap()), 35); // 0.35s
        assert_eq!(i64::from_le_bytes(tms[16..24].try_into().unwrap()), 50); // 0.5s
        assert_eq!(i64::from_le_bytes(tms[24..32].try_into().unwrap()), 25); // 0.25s
    }
}

#[test]
fn sched_and_ioprio_syscalls_on_both_abis() {
    for abi in ABIS {
        let mut host = TestHost::default();
        let pids = PidNamespace::new();
        let mut mem = Mem::new();
        let mut thread = TestThread::default();
        let mut proc = new_proc(abi, 1, Some(pids), Credentials::root());

        // Priority bounds.
        assert_eq!(
            call_ret(
                &mut proc,
                abi,
                Operation::SchedGetPriorityMax,
                [SCHED_OTHER as u64, 0, 0, 0, 0, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            0
        );
        assert_eq!(
            call_ret(
                &mut proc,
                abi,
                Operation::SchedGetPriorityMin,
                [SCHED_OTHER as u64, 0, 0, 0, 0, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            0
        );
        assert_eq!(
            call_ret(
                &mut proc,
                abi,
                Operation::SchedGetPriorityMax,
                [SCHED_FIFO as u64, 0, 0, 0, 0, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            99
        );
        assert_eq!(
            call_ret(
                &mut proc,
                abi,
                Operation::SchedGetPriorityMin,
                [SCHED_FIFO as u64, 0, 0, 0, 0, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            1
        );
        assert_eq!(
            call_ret(
                &mut proc,
                abi,
                Operation::SchedGetPriorityMax,
                [SCHED_RR as u64, 0, 0, 0, 0, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            99
        );
        assert_eq!(
            call_ret(
                &mut proc,
                abi,
                Operation::SchedGetPriorityMax,
                [99, 0, 0, 0, 0, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            err(EINVAL)
        );

        // sched_getscheduler / sched_setscheduler / sched_getparam / sched_setparam.
        assert_eq!(
            call_ret(
                &mut proc,
                abi,
                Operation::SchedGetscheduler,
                [0; 6],
                &mut mem,
                &mut thread,
                &mut host
            ),
            SCHED_OTHER as u64
        );
        let param_ptr = mem.base + 0x100;
        mem.write(param_ptr, &20i32.to_le_bytes()).unwrap();
        assert_eq!(
            call_ret(
                &mut proc,
                abi,
                Operation::SchedSetscheduler,
                [
                    0,
                    (SCHED_RR as u64) | u64::from(SCHED_RESET_ON_FORK),
                    param_ptr,
                    0,
                    0,
                    0
                ],
                &mut mem,
                &mut thread,
                &mut host,
            ),
            0
        );
        assert_eq!(
            call_ret(
                &mut proc,
                abi,
                Operation::SchedGetscheduler,
                [0; 6],
                &mut mem,
                &mut thread,
                &mut host
            ),
            (SCHED_RR as u64) | u64::from(SCHED_RESET_ON_FORK)
        );
        mem.write(param_ptr, &0i32.to_le_bytes()).unwrap();
        assert_eq!(
            call_ret(
                &mut proc,
                abi,
                Operation::SchedGetparam,
                [0, param_ptr, 0, 0, 0, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            0
        );
        assert_eq!(
            i32::from_le_bytes(mem.read_bytes(param_ptr, 4).try_into().unwrap()),
            20
        );
        mem.write(param_ptr, &35i32.to_le_bytes()).unwrap();
        assert_eq!(
            call_ret(
                &mut proc,
                abi,
                Operation::SchedSetparam,
                [0, param_ptr, 0, 0, 0, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            0
        );
        assert_eq!(
            call_ret(
                &mut proc,
                abi,
                Operation::SchedGetparam,
                [0, param_ptr, 0, 0, 0, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            0
        );
        assert_eq!(
            i32::from_le_bytes(mem.read_bytes(param_ptr, 4).try_into().unwrap()),
            35
        );

        // Fork resets SCHED_RESET_ON_FORK child back to SCHED_OTHER.
        let child_pid = call_ret(
            &mut proc,
            abi,
            Operation::Clone,
            [17, 0, 0, 0, 0, 0],
            &mut mem,
            &mut thread,
            &mut host,
        );
        assert!(child_pid > 1);
        let mut child = thread.spawned_processes.pop().unwrap().child;
        assert_eq!(
            call_ret(
                &mut child,
                abi,
                Operation::SchedGetscheduler,
                [0; 6],
                &mut mem,
                &mut thread,
                &mut host
            ),
            SCHED_OTHER as u64
        );

        // sched_setaffinity / sched_getaffinity.
        let mask_ptr = mem.base + 0x200;
        mem.write(mask_ptr, &0b1010u64.to_le_bytes()).unwrap();
        assert_eq!(
            call_ret(
                &mut proc,
                abi,
                Operation::SchedSetaffinity,
                [0, 8, mask_ptr, 0, 0, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            0
        );
        mem.write(mask_ptr, &0u64.to_le_bytes()).unwrap();
        assert_eq!(
            call_ret(
                &mut proc,
                abi,
                Operation::SchedGetaffinity,
                [0, 8, mask_ptr, 0, 0, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            8
        );
        assert_eq!(
            u64::from_le_bytes(mem.read_bytes(mask_ptr, 8).try_into().unwrap()),
            0b1010
        );
        // Empty intersection with online CPUs (0..4) fails EINVAL.
        mem.write(mask_ptr, &0b1_0000u64.to_le_bytes()).unwrap();
        assert_eq!(
            call_ret(
                &mut proc,
                abi,
                Operation::SchedSetaffinity,
                [0, 8, mask_ptr, 0, 0, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            err(EINVAL)
        );
        // Unknown pid fails ESRCH.
        assert_eq!(
            call_ret(
                &mut proc,
                abi,
                Operation::SchedGetscheduler,
                [999, 0, 0, 0, 0, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            err(ESRCH)
        );

        // ioprio_set / ioprio_get.
        let be2 = u64::from((IOPRIO_CLASS_BE << 13) | 2);
        assert_eq!(
            call_ret(
                &mut proc,
                abi,
                Operation::IoprioSet,
                [IOPRIO_WHO_PROCESS, 0, be2, 0, 0, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            0
        );
        assert_eq!(
            call_ret(
                &mut proc,
                abi,
                Operation::IoprioGet,
                [IOPRIO_WHO_PROCESS, 0, 0, 0, 0, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            be2
        );
        let idle = u64::from(IOPRIO_CLASS_IDLE << 13);
        assert_eq!(
            call_ret(
                &mut proc,
                abi,
                Operation::IoprioSet,
                [IOPRIO_WHO_PGRP, 0, idle, 0, 0, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            0
        );
        assert_eq!(
            call_ret(
                &mut proc,
                abi,
                Operation::IoprioGet,
                [IOPRIO_WHO_USER, 0, 0, 0, 0, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            idle
        );
        let rt1 = u64::from((IOPRIO_CLASS_RT << 13) | 1);
        assert_eq!(
            call_ret(
                &mut proc,
                abi,
                Operation::IoprioSet,
                [IOPRIO_WHO_PROCESS, 0, rt1, 0, 0, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            0
        );

        // Unprivileged cannot set RT ioprio or SCHED_FIFO without CAP_SYS_NICE.
        let mut unpriv_creds = Credentials::root();
        unpriv_creds.capabilities = LinuxCapabilities::for_uid(1000);
        let mut unpriv = new_proc(abi, 50, None, unpriv_creds);
        assert_eq!(
            call_ret(
                &mut unpriv,
                abi,
                Operation::IoprioSet,
                [IOPRIO_WHO_PROCESS, 0, rt1, 0, 0, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            err(EPERM)
        );
        mem.write(param_ptr, &10i32.to_le_bytes()).unwrap();
        assert_eq!(
            call_ret(
                &mut unpriv,
                abi,
                Operation::SchedSetscheduler,
                [0, SCHED_FIFO as u64, param_ptr, 0, 0, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            err(EPERM)
        );
        let _ = (SCHED_BATCH, SCHED_IDLE, CAP_SYS_NICE);
    }
}

#[test]
fn personality_extended_prctl_pdeathsig_subreaper_and_syslog() {
    for abi in ABIS {
        let mut host = TestHost::default();
        let pids = PidNamespace::new();
        let mut mem = Mem::new();
        let mut thread = TestThread::default();
        let mut proc = new_proc(abi, 1, Some(pids.clone()), Credentials::root());

        // personality(2).
        assert_eq!(
            call_ret(
                &mut proc,
                abi,
                Operation::Personality,
                [0xffff_ffff, 0, 0, 0, 0, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            0
        );
        assert_eq!(
            call_ret(
                &mut proc,
                abi,
                Operation::Personality,
                [0x0040_0000, 0, 0, 0, 0, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            0
        );
        assert_eq!(
            call_ret(
                &mut proc,
                abi,
                Operation::Personality,
                [0xffff_ffff, 0, 0, 0, 0, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            0x0040_0000
        );
        assert_eq!(
            call_ret(
                &mut proc,
                abi,
                Operation::Personality,
                [5, 0, 0, 0, 0, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            err(EINVAL)
        );

        // PR_SET_NAME / PR_GET_NAME (truncates at 15 chars + NUL).
        let name_ptr = mem.base + 0x100;
        let out_ptr = mem.base + 0x200;
        mem.write_cstr(name_ptr, "busybox-long-process-name");
        assert_eq!(
            call_ret(
                &mut proc,
                abi,
                Operation::Prctl,
                [PR_SET_NAME, name_ptr, 0, 0, 0, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            0
        );
        assert_eq!(
            call_ret(
                &mut proc,
                abi,
                Operation::Prctl,
                [PR_GET_NAME, out_ptr, 0, 0, 0, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            0
        );
        assert_eq!(mem.read_cstr(out_ptr, 16), "busybox-long-pr");

        // PR_GET_DUMPABLE / PR_SET_DUMPABLE.
        assert_eq!(
            call_ret(
                &mut proc,
                abi,
                Operation::Prctl,
                [PR_GET_DUMPABLE, 0, 0, 0, 0, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            1
        );
        assert_eq!(
            call_ret(
                &mut proc,
                abi,
                Operation::Prctl,
                [PR_SET_DUMPABLE, 0, 0, 0, 0, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            0
        );
        assert_eq!(
            call_ret(
                &mut proc,
                abi,
                Operation::Prctl,
                [PR_GET_DUMPABLE, 0, 0, 0, 0, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            0
        );
        assert_eq!(
            call_ret(
                &mut proc,
                abi,
                Operation::Prctl,
                [PR_SET_DUMPABLE, 9, 0, 0, 0, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            err(EINVAL)
        );

        // PR_CAPBSET_READ / PR_CAPBSET_DROP & PR_CAP_AMBIENT.
        assert_eq!(
            call_ret(
                &mut proc,
                abi,
                Operation::Prctl,
                [PR_CAPBSET_READ, u64::from(CAP_SYS_ADMIN), 0, 0, 0, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            1
        );
        assert_eq!(
            call_ret(
                &mut proc,
                abi,
                Operation::Prctl,
                [PR_CAPBSET_DROP, u64::from(CAP_SYS_ADMIN), 0, 0, 0, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            0
        );
        assert_eq!(
            call_ret(
                &mut proc,
                abi,
                Operation::Prctl,
                [PR_CAPBSET_READ, u64::from(CAP_SYS_ADMIN), 0, 0, 0, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            0
        );
        // Ambient raise fails EPERM when inheritable doesn't hold cap.
        assert_eq!(
            call_ret(
                &mut proc,
                abi,
                Operation::Prctl,
                [
                    PR_CAP_AMBIENT,
                    PR_CAP_AMBIENT_RAISE,
                    u64::from(CAP_NET_RAW),
                    0,
                    0,
                    0
                ],
                &mut mem,
                &mut thread,
                &mut host
            ),
            err(EPERM)
        );
        // With inheritable set, RAISE / IS_SET / LOWER / CLEAR_ALL all work.
        let mut amb_creds = Credentials::root();
        amb_creds.capabilities.inheritable = amb_creds.capabilities.permitted;
        let mut amb_proc = new_proc(abi, 3, None, amb_creds);
        assert_eq!(
            call_ret(
                &mut amb_proc,
                abi,
                Operation::Prctl,
                [
                    PR_CAP_AMBIENT,
                    PR_CAP_AMBIENT_RAISE,
                    u64::from(CAP_NET_RAW),
                    0,
                    0,
                    0
                ],
                &mut mem,
                &mut thread,
                &mut host
            ),
            0
        );
        assert_eq!(
            call_ret(
                &mut amb_proc,
                abi,
                Operation::Prctl,
                [
                    PR_CAP_AMBIENT,
                    PR_CAP_AMBIENT_IS_SET,
                    u64::from(CAP_NET_RAW),
                    0,
                    0,
                    0
                ],
                &mut mem,
                &mut thread,
                &mut host
            ),
            1
        );
        assert_eq!(
            call_ret(
                &mut amb_proc,
                abi,
                Operation::Prctl,
                [
                    PR_CAP_AMBIENT,
                    PR_CAP_AMBIENT_LOWER,
                    u64::from(CAP_NET_RAW),
                    0,
                    0,
                    0
                ],
                &mut mem,
                &mut thread,
                &mut host
            ),
            0
        );
        assert_eq!(
            call_ret(
                &mut amb_proc,
                abi,
                Operation::Prctl,
                [
                    PR_CAP_AMBIENT,
                    PR_CAP_AMBIENT_IS_SET,
                    u64::from(CAP_NET_RAW),
                    0,
                    0,
                    0
                ],
                &mut mem,
                &mut thread,
                &mut host
            ),
            0
        );
        assert_eq!(
            call_ret(
                &mut amb_proc,
                abi,
                Operation::Prctl,
                [
                    PR_CAP_AMBIENT,
                    PR_CAP_AMBIENT_RAISE,
                    u64::from(CAP_NET_RAW),
                    0,
                    0,
                    0
                ],
                &mut mem,
                &mut thread,
                &mut host
            ),
            0
        );
        assert_eq!(
            call_ret(
                &mut amb_proc,
                abi,
                Operation::Prctl,
                [PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            0
        );
        assert_eq!(
            call_ret(
                &mut amb_proc,
                abi,
                Operation::Prctl,
                [
                    PR_CAP_AMBIENT,
                    PR_CAP_AMBIENT_IS_SET,
                    u64::from(CAP_NET_RAW),
                    0,
                    0,
                    0
                ],
                &mut mem,
                &mut thread,
                &mut host
            ),
            0
        );

        // PR_SET_CHILD_SUBREAPER + PR_SET_PDEATHSIG!
        let reaper_pid = call_ret(
            &mut proc,
            abi,
            Operation::Clone,
            [17, 0, 0, 0, 0, 0],
            &mut mem,
            &mut thread,
            &mut host,
        );
        let mut reaper = thread.spawned_processes.pop().unwrap().child;
        assert_eq!(
            call_ret(
                &mut reaper,
                abi,
                Operation::Prctl,
                [PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            0
        );
        assert_eq!(
            call_ret(
                &mut reaper,
                abi,
                Operation::Prctl,
                [PR_GET_CHILD_SUBREAPER, out_ptr, 0, 0, 0, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            0
        );
        assert_eq!(
            i32::from_le_bytes(mem.read_bytes(out_ptr, 4).try_into().unwrap()),
            1
        );

        let mid_pid = call_ret(
            &mut reaper,
            abi,
            Operation::Clone,
            [17, 0, 0, 0, 0, 0],
            &mut mem,
            &mut thread,
            &mut host,
        );
        let mut mid = thread.spawned_processes.pop().unwrap().child;
        let _grand_pid = call_ret(
            &mut mid,
            abi,
            Operation::Clone,
            [17, 0, 0, 0, 0, 0],
            &mut mem,
            &mut thread,
            &mut host,
        );
        let mut grand = thread.spawned_processes.pop().unwrap().child;
        assert_eq!(
            call_ret(
                &mut grand,
                abi,
                Operation::Prctl,
                [
                    PR_SET_PDEATHSIG,
                    u64::from(Signal::SIGTERM.raw()),
                    0,
                    0,
                    0,
                    0
                ],
                &mut mem,
                &mut thread,
                &mut host
            ),
            0
        );
        assert_eq!(
            call_ret(
                &mut grand,
                abi,
                Operation::Prctl,
                [PR_GET_PDEATHSIG, out_ptr, 0, 0, 0, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            0
        );
        assert_eq!(
            i32::from_le_bytes(mem.read_bytes(out_ptr, 4).try_into().unwrap()),
            i32::from(Signal::SIGTERM.raw())
        );

        // When `mid` exits: `grand` receives SIGTERM (pdeathsig) AND reparents to `reaper`!
        let _ = mid_pid;
        mid.mark_exited(ChildTermination::Exited(0));
        assert_eq!(
            call_ret(
                &mut grand,
                abi,
                Operation::Getppid,
                [0; 6],
                &mut mem,
                &mut thread,
                &mut host
            ),
            reaper_pid
        );
        assert_eq!(
            grand.thread_signals().take_pending_signal(),
            Some(Signal::SIGTERM)
        );

        // syslog(2).
        let mut unpriv_creds = Credentials::root();
        unpriv_creds.capabilities = LinuxCapabilities::for_uid(1000);
        let mut unpriv = new_proc(abi, 60, None, unpriv_creds);
        let log_buf = mem.base + 0x500;
        assert_eq!(
            call_ret(
                &mut unpriv,
                abi,
                Operation::Syslog,
                [SYSLOG_ACTION_SIZE_BUFFER, 0, 0, 0, 0, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            err(EPERM)
        );

        let mut priv_proc = new_proc(abi, 61, None, Credentials::root());
        assert_eq!(
            call_ret(
                &mut priv_proc,
                abi,
                Operation::Syslog,
                [SYSLOG_ACTION_SIZE_BUFFER, 0, 0, 0, 0, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            65_536
        );
        let unread = call_ret(
            &mut priv_proc,
            abi,
            Operation::Syslog,
            [SYSLOG_ACTION_SIZE_UNREAD, 0, 0, 0, 0, 0],
            &mut mem,
            &mut thread,
            &mut host,
        );
        assert_eq!(unread as usize, b"<6>[0.000001] kernel: boot ok\n".len());
        let n = call_ret(
            &mut priv_proc,
            abi,
            Operation::Syslog,
            [SYSLOG_ACTION_READ_ALL, log_buf, 128, 0, 0, 0],
            &mut mem,
            &mut thread,
            &mut host,
        );
        assert_eq!(n, unread);
        assert_eq!(
            &mem.read_bytes(log_buf, n as usize),
            b"<6>[0.000001] kernel: boot ok\n"
        );
        let n2 = call_ret(
            &mut priv_proc,
            abi,
            Operation::Syslog,
            [SYSLOG_ACTION_READ, log_buf, 128, 0, 0, 0],
            &mut mem,
            &mut thread,
            &mut host,
        );
        assert_eq!(n2, unread);
        assert_eq!(
            call_ret(
                &mut priv_proc,
                abi,
                Operation::Syslog,
                [SYSLOG_ACTION_SIZE_UNREAD, 0, 0, 0, 0, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            0
        );
        assert_eq!(
            call_ret(
                &mut priv_proc,
                abi,
                Operation::Syslog,
                [SYSLOG_ACTION_READ_CLEAR, log_buf, 128, 0, 0, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            unread
        );
        assert_eq!(
            call_ret(
                &mut priv_proc,
                abi,
                Operation::Syslog,
                [SYSLOG_ACTION_CLEAR, 0, 0, 0, 0, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            0
        );
        assert_eq!(
            call_ret(
                &mut priv_proc,
                abi,
                Operation::Syslog,
                [SYSLOG_ACTION_READ_ALL, 0, 16, 0, 0, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            err(EINVAL)
        );
        assert_eq!(
            call_ret(
                &mut priv_proc,
                abi,
                Operation::Syslog,
                [SYSLOG_ACTION_READ_ALL, 0xdead_beef, 16, 0, 0, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            err(EFAULT)
        );
        let _ = (CAP_SETPCAP, CAP_SYSLOG);
    }
}

#[test]
fn icmp_and_icmpv6_dgram_and_raw_sockets_with_ttl_cmsg() {
    for abi in ABIS {
        let mut host = TestHost::default();
        let mut mem = Mem::new();
        let mut thread = TestThread::default();

        // Unprivileged process can open SOCK_DGRAM IPPROTO_ICMP, cannot open SOCK_RAW.
        let mut unpriv_creds = Credentials::root();
        unpriv_creds.capabilities = LinuxCapabilities::for_uid(1000);
        let mut unpriv = new_proc(abi, 1, None, unpriv_creds);
        assert_eq!(
            call_ret(
                &mut unpriv,
                abi,
                Operation::Socket,
                [AF_INET, SOCK_RAW, IPPROTO_ICMP as u64, 0, 0, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            err(EPERM)
        );
        let dgram_fd = call_ret(
            &mut unpriv,
            abi,
            Operation::Socket,
            [AF_INET, SOCK_DGRAM, IPPROTO_ICMP as u64, 0, 0, 0],
            &mut mem,
            &mut thread,
            &mut host,
        );
        assert!(dgram_fd < 100);

        // Enable IP_RECVTTL and check SO_PROTOCOL.
        let opt_ptr = mem.base + 0x50;
        let optlen_ptr = mem.base + 0x58;
        mem.write(opt_ptr, &1i32.to_le_bytes()).unwrap();
        assert_eq!(
            call_ret(
                &mut unpriv,
                abi,
                Operation::Setsockopt,
                [dgram_fd, IPPROTO_IP, IP_RECVTTL, opt_ptr, 4, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            0
        );
        mem.write(optlen_ptr, &4i32.to_le_bytes()).unwrap();
        assert_eq!(
            call_ret(
                &mut unpriv,
                abi,
                Operation::Getsockopt,
                [dgram_fd, SOL_SOCKET, SO_PROTOCOL, opt_ptr, optlen_ptr, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            0
        );
        assert_eq!(
            i32::from_le_bytes(mem.read_bytes(opt_ptr, 4).try_into().unwrap()),
            IPPROTO_ICMP
        );

        // Send ICMPv4 Echo Request to 127.0.0.1.
        let dst_ptr = mem.base + 0x100;
        let mut sa = [0u8; 16];
        sa[0..2].copy_from_slice(&(AF_INET as u16).to_le_bytes());
        sa[4..8].copy_from_slice(&[127, 0, 0, 1]);
        mem.write(dst_ptr, &sa).unwrap();
        let req_ptr = mem.base + 0x200;
        let mut req = [0u8; 12];
        req[0] = 8; // Echo Request
        req[6..8].copy_from_slice(&42u16.to_be_bytes());
        req[8..12].copy_from_slice(b"ping");
        mem.write(req_ptr, &req).unwrap();
        assert_eq!(
            call_ret(
                &mut unpriv,
                abi,
                Operation::Sendto,
                [dgram_fd, req_ptr, 12, 0, dst_ptr, 16],
                &mut mem,
                &mut thread,
                &mut host
            ),
            12
        );

        // Receive via recvmsg with control buffer -> receives ICMP reply + IP_TTL cmsg!
        let rbuf = mem.base + 0x300;
        let iov = mem.base + 0x400;
        mem.write(iov, &rbuf.to_le_bytes()).unwrap();
        mem.write(iov + 8, &64u64.to_le_bytes()).unwrap();
        let cbuf = mem.base + 0x500;
        let msg = mem.base + 0x600;
        let mut mh = [0u8; 56];
        mh[16..24].copy_from_slice(&iov.to_le_bytes());
        mh[24..32].copy_from_slice(&1u64.to_le_bytes());
        mh[32..40].copy_from_slice(&cbuf.to_le_bytes());
        mh[40..48].copy_from_slice(&32u64.to_le_bytes());
        mem.write(msg, &mh).unwrap();
        let got = call_ret(
            &mut unpriv,
            abi,
            Operation::Recvmsg,
            [dgram_fd, msg, 0, 0, 0, 0],
            &mut mem,
            &mut thread,
            &mut host,
        );
        assert_eq!(got, 12);
        let reply = mem.read_bytes(rbuf, 12);
        assert_eq!(reply[0], 0); // Echo Reply
        assert_eq!(u16::from_be_bytes([reply[6], reply[7]]), 42);
        assert_eq!(&reply[8..12], b"ping");
        let controllen = u64::from_le_bytes(mem.read_bytes(msg + 40, 8).try_into().unwrap());
        assert_eq!(controllen, 24);
        let cmsg = mem.read_bytes(cbuf, 24);
        assert_eq!(
            i32::from_le_bytes(cmsg[8..12].try_into().unwrap()),
            IPPROTO_IP as i32
        );
        assert_eq!(i32::from_le_bytes(cmsg[12..16].try_into().unwrap()), IP_TTL);
        assert_eq!(i32::from_le_bytes(cmsg[16..20].try_into().unwrap()), 64);

        // Privileged SOCK_RAW IPPROTO_ICMP prepends 20-byte IPv4 header on receive!
        let mut priv_proc = new_proc(abi, 2, None, Credentials::root());
        let raw_fd = call_ret(
            &mut priv_proc,
            abi,
            Operation::Socket,
            [AF_INET, SOCK_RAW, IPPROTO_ICMP as u64, 0, 0, 0],
            &mut mem,
            &mut thread,
            &mut host,
        );
        assert!(raw_fd < 100);
        assert_eq!(
            call_ret(
                &mut priv_proc,
                abi,
                Operation::Sendto,
                [raw_fd, req_ptr, 12, 0, dst_ptr, 16],
                &mut mem,
                &mut thread,
                &mut host
            ),
            12
        );
        let raw_got = call_ret(
            &mut priv_proc,
            abi,
            Operation::Recvfrom,
            [raw_fd, rbuf, 64, 0, 0, 0],
            &mut mem,
            &mut thread,
            &mut host,
        );
        assert_eq!(raw_got, 32); // 20-byte IPv4 header + 12-byte ICMP reply
        let raw_pkt = mem.read_bytes(rbuf, 32);
        assert_eq!(raw_pkt[0], 0x45);
        assert_eq!(raw_pkt[9], IPPROTO_ICMP as u8);
        assert_eq!(raw_pkt[20], 0); // ICMP Echo Reply after IPv4 header
        assert_eq!(&raw_pkt[28..32], b"ping");

        // IPv6 SOCK_DGRAM IPPROTO_ICMPV6 + IPV6_RECVHOPLIMIT cmsg.
        let v6_fd = call_ret(
            &mut unpriv,
            abi,
            Operation::Socket,
            [AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6 as u64, 0, 0, 0],
            &mut mem,
            &mut thread,
            &mut host,
        );
        assert!(v6_fd < 100);
        mem.write(opt_ptr, &1i32.to_le_bytes()).unwrap();
        assert_eq!(
            call_ret(
                &mut unpriv,
                abi,
                Operation::Setsockopt,
                [v6_fd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, opt_ptr, 4, 0],
                &mut mem,
                &mut thread,
                &mut host
            ),
            0
        );
        let mut sa6 = [0u8; 28];
        sa6[0..2].copy_from_slice(&(AF_INET6 as u16).to_le_bytes());
        sa6[23] = 1; // ::1
        mem.write(dst_ptr, &sa6).unwrap();
        req[0] = 128; // ICMPv6 Echo Request
        mem.write(req_ptr, &req).unwrap();
        assert_eq!(
            call_ret(
                &mut unpriv,
                abi,
                Operation::Sendto,
                [v6_fd, req_ptr, 12, 0, dst_ptr, 28],
                &mut mem,
                &mut thread,
                &mut host
            ),
            12
        );
        mem.write(msg, &mh).unwrap();
        let v6_got = call_ret(
            &mut unpriv,
            abi,
            Operation::Recvmsg,
            [v6_fd, msg, 0, 0, 0, 0],
            &mut mem,
            &mut thread,
            &mut host,
        );
        assert_eq!(v6_got, 12);
        let v6_reply = mem.read_bytes(rbuf, 12);
        assert_eq!(v6_reply[0], 129); // ICMPv6 Echo Reply
        let cmsg6 = mem.read_bytes(cbuf, 24);
        assert_eq!(
            i32::from_le_bytes(cmsg6[8..12].try_into().unwrap()),
            IPPROTO_IPV6 as i32
        );
        assert_eq!(
            i32::from_le_bytes(cmsg6[12..16].try_into().unwrap()),
            IPV6_HOPLIMIT
        );
        assert_eq!(i32::from_le_bytes(cmsg6[16..20].try_into().unwrap()), 64);
    }
}
