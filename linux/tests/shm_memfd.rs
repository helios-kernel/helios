#![cfg(feature = "runtime")]
//! Dual-architecture (`x86-64` and `aarch64`) ABI and semantics tests for
//! `memfd_create(2)`, `fcntl(2)` file sealing (`F_ADD_SEALS` / `F_GET_SEALS`),
//! and System V shared memory (`shmget`, `shmat`, `shmdt`, `shmctl`).

use core::future::Future;
use core::num::NonZeroU32;
use core::ops::ControlFlow;
use core::task::{Context, Poll, Waker};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use helios_hal::fs::{FsError, Landed, NodeKind, WritePosition};
use helios_hal::vmm::PageFlags;
use helios_linux::abi::Abi;
use helios_linux::syscall::{
    CAP_IPC_OWNER, CAP_SYS_ADMIN, Call, Clock, Credentials, Denied, Descriptor, FileAccess,
    FileStat, Filesystem, FsOpError, FsStat, IPC_64, IPC_CREAT, IPC_EXCL, IPC_INFO, IPC_PRIVATE,
    IPC_RMID, IPC_SET, IPC_STAT, MFD_ALLOW_SEALING, MFD_CLOEXEC, MFD_EXEC, MFD_HUGETLB,
    MFD_NOEXEC_SEAL, MapError, MemoryFault, MemoryTotals, Network, OpenOutcome, OpenRequest,
    PidNamespace, Process, Region, Resources, SHM_DEST, SHM_EXEC, SHM_HUGETLB, SHM_INFO,
    SHM_INFO_BYTES, SHM_LOCK, SHM_LOCKED, SHM_RDONLY, SHM_REMAP, SHM_RND, SHM_STAT, SHM_UNLOCK,
    SHMID64_DS_BYTES, SHMINFO64_BYTES, SHMMIN, SHMMNI, ShmPerm, ShmStat, ShmUsageInfo, SpawnError,
    SpawnedProcess, SpawnedThread, Start, Stdio, Stream, SyscallOutcome, System, TMPFS_MAGIC,
    Thread, Tty, UserMemory, VirtualMemory, WriteError, check_ipc_owner_or_admin, check_ipc_perms,
    dispatch, standard_streams,
};
use helios_unix::{
    F_SEAL_EXEC, F_SEAL_FUTURE_WRITE, F_SEAL_GROW, F_SEAL_SEAL, F_SEAL_SHRINK, F_SEAL_WRITE,
    MemfdHandle, NoNetwork, OpenFile,
};

const PAGE: u64 = 4096;
const LOWEST: u64 = PAGE;
const BREAK: u64 = 0x50_0000;

// Linux errno values (`include/uapi/asm-generic/errno-base.h`).
const EPERM: u64 = 1;
const ENOENT: u64 = 2;
const EACCES: u64 = 13;
const EFAULT: u64 = 14;
const EBUSY: u64 = 16;
const EEXIST: u64 = 17;
const EINVAL: u64 = 22;

// Linux `fcntl(2)` commands.
const F_GETFD: u64 = 1;
const F_ADD_SEALS: u64 = 1033;
const F_GET_SEALS: u64 = 1034;

// Linux `mmap(2)` flags / prot.
const PROT_READ: u64 = 1;
const PROT_WRITE: u64 = 2;
const MAP_SHARED: u64 = 0x01;
const MAP_PRIVATE: u64 = 0x02;
const MAP_FIXED: u64 = 0x10;
const MAP_ANONYMOUS: u64 = 0x20;

// Linux `fallocate(2)` flags.
const FALLOC_FL_KEEP_SIZE: u64 = 0x01;
const FALLOC_FL_PUNCH_HOLE: u64 = 0x02;

// Linux `openat(2)` flags.
const AT_FDCWD: u64 = (-100i64) as u64;
const O_RDONLY: u64 = 0;
const O_RDWR: u64 = 2;
const O_TRUNC: u64 = 0o1000;

const SIGCHLD: u64 = 17;

#[derive(Clone, Copy)]
struct AbiNums {
    abi: Abi,
    read: u64,
    write: u64,
    close: u64,
    fstat: u64,
    lseek: u64,
    mmap: u64,
    mprotect: u64,
    munmap: u64,
    pread64: u64,
    pwrite64: u64,
    writev: u64,
    shmget: u64,
    shmat: u64,
    shmctl: u64,
    shmdt: u64,
    clone: u64,
    fcntl: u64,
    ftruncate: u64,
    fchmod: u64,
    fstatfs: u64,
    exit_group: u64,
    openat: u64,
    fallocate: u64,
    memfd_create: u64,
    copy_file_range: u64,
}

impl AbiNums {
    const X86_64: Self = Self {
        abi: Abi::X86_64,
        read: 0,
        write: 1,
        close: 3,
        fstat: 5,
        lseek: 8,
        mmap: 9,
        mprotect: 10,
        munmap: 11,
        pread64: 17,
        pwrite64: 18,
        writev: 20,
        shmget: 29,
        shmat: 30,
        shmctl: 31,
        shmdt: 67,
        clone: 56,
        fcntl: 72,
        ftruncate: 77,
        fchmod: 91,
        fstatfs: 138,
        exit_group: 231,
        openat: 257,
        fallocate: 285,
        memfd_create: 319,
        copy_file_range: 326,
    };

    const AARCH64: Self = Self {
        abi: Abi::Aarch64,
        read: 63,
        write: 64,
        close: 57,
        fstat: 80,
        lseek: 62,
        mmap: 222,
        mprotect: 226,
        munmap: 215,
        pread64: 67,
        pwrite64: 68,
        writev: 66,
        shmget: 194,
        shmat: 196,
        shmctl: 195,
        shmdt: 197,
        clone: 220,
        fcntl: 25,
        ftruncate: 46,
        fchmod: 52,
        fstatfs: 44,
        exit_group: 94,
        openat: 56,
        fallocate: 47,
        memfd_create: 279,
        copy_file_range: 285,
    };

    const ALL: [Self; 2] = [Self::X86_64, Self::AARCH64];
}

#[derive(Clone, Debug)]
struct MockFile {
    id: u64,
    path: String,
    access: FileAccess,
    is_memfd: bool,
}

struct MockResources;
impl Resources for MockResources {
    type File = MockFile;
    type Network = NoNetwork;
    type Data = u64;
}

struct MockMemfdInode {
    id: u64,
    path: String,
    mode: u32,
    uid: u32,
    gid: u32,
    seals: u32,
    handle: MemfdHandle,
    data: Arc<Mutex<Vec<u8>>>,
}

struct MockShmSeg {
    shmid: i32,
    perm: ShmPerm,
    size: u64,
    atime: i64,
    dtime: i64,
    ctime: i64,
    cpid: u32,
    lpid: u32,
    nattch: u64,
    destroyed: bool,
    data: Arc<Mutex<Vec<u8>>>,
}

impl MockShmSeg {
    fn to_stat(&self) -> ShmStat {
        ShmStat {
            perm: self.perm,
            segsz: self.size,
            atime: self.atime,
            dtime: self.dtime,
            ctime: self.ctime,
            cpid: self.cpid,
            lpid: self.lpid,
            nattch: self.nattch,
        }
    }
}

struct MockBackingInner {
    next_id: u64,
    now_secs: i64,
    memfds: BTreeMap<u64, MockMemfdInode>,
    proc_memfds: BTreeMap<u32, Vec<(i32, u64)>>,
    regular_files: BTreeMap<u64, Arc<Mutex<Vec<u8>>>>,
    shm_slots: Vec<Option<MockShmSeg>>,
    shm_keys: BTreeMap<i32, usize>,
    next_shm_seq: u16,
}

#[derive(Clone)]
struct MockBacking {
    inner: Arc<Mutex<MockBackingInner>>,
}

impl MockBacking {
    fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(MockBackingInner {
                next_id: 1,
                now_secs: 1_700_000_000,
                memfds: BTreeMap::new(),
                proc_memfds: BTreeMap::new(),
                regular_files: BTreeMap::new(),
                shm_slots: Vec::new(),
                shm_keys: BTreeMap::new(),
                next_shm_seq: 0,
            })),
        }
    }

    fn advance_time(&self, secs: i64) {
        self.inner.lock().unwrap().now_secs += secs;
    }

    fn active_memfds(&self) -> usize {
        self.inner.lock().unwrap().memfds.len()
    }

    fn active_shm_segments(&self) -> usize {
        self.inner
            .lock()
            .unwrap()
            .shm_slots
            .iter()
            .flatten()
            .count()
    }

    fn shared_buffer_for_file(&self, file_id: u64) -> Option<Arc<Mutex<Vec<u8>>>> {
        let guard = self.inner.lock().unwrap();
        if let Some(m) = guard.memfds.get(&file_id) {
            return Some(m.data.clone());
        }
        guard.regular_files.get(&file_id).cloned()
    }

    fn shared_buffer_for_shm(&self, shmid: i32) -> Option<Arc<Mutex<Vec<u8>>>> {
        let guard = self.inner.lock().unwrap();
        let idx = (shmid & 0x7fff) as usize;
        let seg = guard.shm_slots.get(idx)?.as_ref()?;
        (seg.shmid == shmid).then(|| seg.data.clone())
    }
}

#[derive(Clone)]
struct MockPage {
    access: PageFlags,
    bytes: Box<[u8; PAGE as usize]>,
    shared: Option<(Arc<Mutex<Vec<u8>>>, usize)>,
}

#[derive(Clone)]
struct MockMemory {
    pages: BTreeMap<u64, MockPage>,
    backing: MockBacking,
    next_object_id: u64,
    objects: BTreeMap<u64, Arc<Mutex<Vec<u8>>>>,
}

impl MockMemory {
    fn new(backing: MockBacking) -> Self {
        Self {
            pages: BTreeMap::new(),
            backing,
            next_object_id: 1,
            objects: BTreeMap::new(),
        }
    }

    fn pages_in(start: u64, length: u64) -> impl Iterator<Item = u64> {
        (start..start + length).step_by(PAGE as usize)
    }

    fn fork_clone(&self) -> Self {
        let mut pages = BTreeMap::new();
        for (&base, page) in &self.pages {
            pages.insert(base, page.clone());
        }
        Self {
            pages,
            backing: self.backing.clone(),
            next_object_id: self.next_object_id,
            objects: self.objects.clone(),
        }
    }

    fn put_cstr(&mut self, addr: u64, s: &[u8]) {
        let mut buf = s.to_vec();
        buf.push(0);
        self.write(addr, &buf).unwrap();
    }

    fn bind_shared_pages(&mut self, start: u64, length: u64, object_id: u64, object_offset: u64) {
        let Some(buf) = self.objects.get(&object_id).cloned() else {
            return;
        };
        for base in Self::pages_in(start, length) {
            if let Some(page) = self.pages.get_mut(&base) {
                let off = (object_offset + (base - start)) as usize;
                page.shared = Some((buf.clone(), off));
            }
        }
    }
    fn read(&self, address: u64, output: &mut [u8]) -> Result<(), MemoryFault> {
        for (i, byte) in output.iter_mut().enumerate() {
            let a = address + i as u64;
            let base = a & !(PAGE - 1);
            let off = (a % PAGE) as usize;
            let page = self.pages.get(&base).ok_or(MemoryFault)?;
            if !page.access.contains(PageFlags::READ) {
                return Err(MemoryFault);
            }
            *byte = if let Some((buf, buf_off)) = &page.shared {
                let guard = buf.lock().unwrap();
                guard.get(buf_off + off).copied().unwrap_or(0)
            } else {
                page.bytes[off]
            };
        }
        Ok(())
    }

    fn check_writable(&self, address: u64, length: usize) -> Result<(), MemoryFault> {
        for i in 0..length {
            let a = address + i as u64;
            let page = self.pages.get(&(a & !(PAGE - 1))).ok_or(MemoryFault)?;
            if !page.access.contains(PageFlags::WRITE) {
                return Err(MemoryFault);
            }
        }
        Ok(())
    }

    fn write(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryFault> {
        self.check_writable(address, bytes.len())?;
        for (i, &b) in bytes.iter().enumerate() {
            let a = address + i as u64;
            let base = a & !(PAGE - 1);
            let off = (a % PAGE) as usize;
            let page = self.pages.get_mut(&base).ok_or(MemoryFault)?;
            if let Some((buf, buf_off)) = &page.shared {
                let mut guard = buf.lock().unwrap();
                let pos = buf_off + off;
                if pos >= guard.len() {
                    guard.resize(pos + 1, 0);
                }
                guard[pos] = b;
            } else {
                page.bytes[off] = b;
            }
        }
        Ok(())
    }
}

impl UserMemory for MockMemory {
    async fn read(&self, address: u64, output: &mut [u8]) -> Result<(), MemoryFault> {
        Self::read(self, address, output)
    }

    async fn check_writable(&self, address: u64, length: usize) -> Result<(), MemoryFault> {
        Self::check_writable(self, address, length)
    }

    async fn write(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryFault> {
        Self::write(self, address, bytes)
    }

    async fn atomic_load_u32(&self, address: u64) -> Result<u32, MemoryFault> {
        self.try_atomic_load_u32(address)?.ok_or(MemoryFault)
    }

    fn try_atomic_load_u32(&self, address: u64) -> Result<Option<u32>, MemoryFault> {
        let mut raw = [0u8; 4];
        Self::read(self, address, &mut raw)?;
        Ok(Some(u32::from_le_bytes(raw)))
    }

    async fn atomic_store_u32(&mut self, address: u64, value: u32) -> Result<(), MemoryFault> {
        Self::write(self, address, &value.to_le_bytes())
    }

    async fn atomic_compare_exchange_u32(
        &mut self,
        address: u64,
        expected: u32,
        desired: u32,
    ) -> Result<Result<u32, u32>, MemoryFault> {
        let cur = self.atomic_load_u32(address).await?;
        if cur == expected {
            self.atomic_store_u32(address, desired).await?;
            Ok(Ok(cur))
        } else {
            Ok(Err(cur))
        }
    }
}

impl VirtualMemory for MockMemory {
    fn lowest_address(&self) -> u64 {
        LOWEST
    }

    fn map_anywhere(&mut self, hint: u64, length: u64, access: PageFlags) -> Result<u64, MapError> {
        let start = self.free_range(hint, length).ok_or(MapError::OutOfMemory)?;
        self.map_at(start, length, access)?;
        Ok(start)
    }

    fn map_at(&mut self, address: u64, length: u64, access: PageFlags) -> Result<(), MapError> {
        if address < LOWEST {
            return Err(MapError::Address);
        }
        if self.region(address, address + length).is_some() {
            return Err(MapError::Occupied);
        }
        for base in Self::pages_in(address, length) {
            self.pages.insert(
                base,
                MockPage {
                    access,
                    bytes: Box::new([0u8; PAGE as usize]),
                    shared: None,
                },
            );
        }
        Ok(())
    }

    fn unmap(&mut self, address: u64, length: u64) {
        for base in Self::pages_in(address, length) {
            self.pages.remove(&base);
        }
    }

    fn protect(&mut self, address: u64, length: u64, access: PageFlags) -> Result<(), MapError> {
        for base in Self::pages_in(address, length) {
            self.pages.get_mut(&base).ok_or(MapError::Address)?.access = access;
        }
        Ok(())
    }

    fn discard(&mut self, address: u64, length: u64) {
        for base in Self::pages_in(address, length) {
            if let Some(p) = self.pages.get_mut(&base)
                && p.shared.is_none()
            {
                p.bytes.fill(0);
            }
        }
    }

    fn remap(&mut self, from: u64, length: u64, to: u64, new_length: u64) -> Result<(), MapError> {
        let access = self.pages.get(&from).ok_or(MapError::Address)?.access;
        for base in Self::pages_in(from, length) {
            let page = self.pages.remove(&base).ok_or(MapError::Address)?;
            self.pages.insert(to + (base - from), page);
        }
        for base in Self::pages_in(to + length, new_length.saturating_sub(length)) {
            self.pages.insert(
                base,
                MockPage {
                    access,
                    bytes: Box::new([0u8; PAGE as usize]),
                    shared: None,
                },
            );
        }
        Ok(())
    }

    fn region(&self, start: u64, end: u64) -> Option<Region> {
        let mut iter = self.pages.range(start..end);
        let (&first, head) = iter.next()?;
        let mut last = first + PAGE;
        for (&base, page) in iter {
            if base != last || page.access != head.access {
                break;
            }
            last += PAGE;
        }
        Some(Region {
            start: first,
            end: last,
            access: head.access,
        })
    }

    fn free_range(&self, hint: u64, length: u64) -> Option<u64> {
        let mut candidate = hint.max(LOWEST);
        while let Some(r) = self.region(candidate, candidate + length) {
            candidate = r.end;
        }
        Some(candidate)
    }

    async fn populate(&mut self, address: u64, bytes: &[u8]) -> Result<(), MapError> {
        for (i, &b) in bytes.iter().enumerate() {
            let a = address + i as u64;
            let page = self
                .pages
                .get_mut(&(a & !(PAGE - 1)))
                .ok_or(MapError::Address)?;
            if page.shared.is_none() {
                page.bytes[(a % PAGE) as usize] = b;
            }
        }
        Ok(())
    }

    fn acquire_shared_file(&mut self, _dev: u64, ino: u64) -> u64 {
        let Some(buf) = self.backing.shared_buffer_for_file(ino) else {
            return 0;
        };
        let id = self.next_object_id;
        self.next_object_id += 1;
        self.objects.insert(id, buf);
        id
    }

    fn acquire_sysv_shm(&mut self, shmid: i32) -> u64 {
        let Some(buf) = self.backing.shared_buffer_for_shm(shmid) else {
            return 0;
        };
        let id = self.next_object_id;
        self.next_object_id += 1;
        self.objects.insert(id, buf);
        id
    }

    fn map_shared_at(
        &mut self,
        address: u64,
        length: u64,
        access: PageFlags,
        object_id: u64,
        object_offset: u64,
        _attach_len: u64,
    ) -> Result<(), MapError> {
        self.map_at(address, length, access)?;
        self.bind_shared_pages(address, length, object_id, object_offset);
        Ok(())
    }

    fn map_shared_anywhere(
        &mut self,
        hint: u64,
        length: u64,
        access: PageFlags,
        object_id: u64,
        object_offset: u64,
        _attach_len: u64,
    ) -> Result<u64, MapError> {
        let start = self.map_anywhere(hint, length, access)?;
        self.bind_shared_pages(start, length, object_id, object_offset);
        Ok(start)
    }

    fn unmap_shared_vma(&mut self, start: u64, end: u64) {
        if end <= start {
            return;
        }
        for base in Self::pages_in(start, end - start) {
            if let Some(page) = self.pages.get_mut(&base) {
                page.shared = None;
            }
        }
    }
}

struct MockThread {
    forked_child: Option<Process<MockResources>>,
}

impl MockThread {
    fn new() -> Self {
        Self { forked_child: None }
    }
}

impl Thread<MockResources> for MockThread {
    fn thread_pointer(&self) -> u64 {
        0
    }
    fn set_thread_pointer(&mut self, _: u64) -> Result<(), Denied> {
        Err(Denied)
    }
    fn spawn_thread(
        &mut self,
        _: Process<MockResources>,
        _: SpawnedThread,
    ) -> Result<(), SpawnError> {
        Err(SpawnError::Busy)
    }
    async fn spawn_process(
        &mut self,
        spawned: SpawnedProcess<MockResources>,
    ) -> Result<(), SpawnError> {
        self.forked_child = Some(spawned.child);
        Ok(())
    }
}

impl Stdio for MockBacking {
    async fn write(&mut self, _: Stream, data: &[u8]) -> Result<usize, WriteError> {
        Ok(data.len())
    }
    async fn read_input(&mut self, _: usize) -> Result<Bytes, Denied> {
        Err(Denied)
    }
}

impl Clock for MockBacking {
    fn now_nanos(&self) -> u64 {
        (self.inner.lock().unwrap().now_secs as u64) * 1_000_000_000
    }
    async fn sleep_until(&self, _: u64) {}
}

impl Network<NoNetwork> for MockBacking {
    fn to_ip(&self, address: core::convert::Infallible) -> helios_linux::syscall::IpAddr {
        match address {}
    }
    fn encode_ip(&self, _: helios_linux::syscall::IpAddr) -> core::convert::Infallible {
        unreachable!()
    }
}

impl System for MockBacking {
    fn realtime_nanos(&self) -> u64 {
        (self.inner.lock().unwrap().now_secs as u64) * 1_000_000_000
    }
    fn set_realtime_nanos(&mut self, _: u64) -> Result<(), Denied> {
        Err(Denied)
    }
    fn cpu_nanos(&self) -> u64 {
        0
    }
    fn fill_random(&mut self, buf: &mut [u8]) {
        buf.fill(0x5a);
    }
    fn memory(&self) -> MemoryTotals {
        MemoryTotals {
            total_bytes: 64 << 20,
            free_bytes: 32 << 20,
        }
    }
    fn process_count(&self) -> u32 {
        1
    }
    fn kernel_version(&self) -> &str {
        "6.12.0-helios"
    }
}

impl Tty for MockBacking {}

impl Filesystem<MockResources> for MockBacking {
    fn file_access(&self, file: &MockFile) -> FileAccess {
        file.access
    }

    fn file_path<'a>(&self, file: &'a MockFile) -> Option<&'a str> {
        Some(&file.path)
    }

    async fn open_descriptor(
        &mut self,
        _base: Option<&MockFile>,
        _cwd: &str,
        path: &str,
        request: OpenRequest,
        _creds: &Credentials,
    ) -> Result<Option<OpenOutcome<MockResources>>, FsOpError> {
        if let Some(rest) = path.strip_prefix("/proc/") {
            let parts: Vec<&str> = rest.split('/').collect();
            if parts.len() == 3 && parts[1] == "fd" {
                let fd: i32 = parts[2]
                    .parse()
                    .map_err(|_| FsOpError::Fs(FsError::NoEntry))?;
                if parts[0] == "self" {
                    return Ok(Some(OpenOutcome::ReopenFd { fd }));
                }
                let pid: u32 = parts[0]
                    .parse()
                    .map_err(|_| FsOpError::Fs(FsError::NoEntry))?;
                let guard = self.inner.lock().unwrap();
                let memfd_id = guard
                    .proc_memfds
                    .get(&pid)
                    .and_then(|list| {
                        list.iter()
                            .find_map(|&(slot, id)| (slot == fd).then_some(id))
                    })
                    .ok_or(FsOpError::Fs(FsError::NoEntry))?;
                let inode = guard
                    .memfds
                    .get(&memfd_id)
                    .ok_or(FsOpError::Fs(FsError::NoEntry))?;
                let access = match (request.read, request.write) {
                    (true, true) => FileAccess::ReadWrite,
                    (false, true) => FileAccess::WriteOnly,
                    _ => FileAccess::ReadOnly,
                };
                if request.truncate
                    && (inode.seals & F_SEAL_SHRINK != 0)
                    && !inode.data.lock().unwrap().is_empty()
                {
                    return Err(FsOpError::PermissionDenied);
                }
                if request.truncate {
                    inode.data.lock().unwrap().clear();
                }
                let file = MockFile {
                    id: inode.id,
                    path: inode.path.clone(),
                    access,
                    is_memfd: true,
                };
                return Ok(Some(OpenOutcome::Descriptor(
                    Descriptor::<MockResources>::File(OpenFile::with_memfd_hold(
                        file,
                        inode.handle.acquire_hold(),
                    )),
                )));
            }
        }
        if path == "/regular" {
            let mut guard = self.inner.lock().unwrap();
            let id = guard.next_id;
            guard.next_id += 1;
            guard
                .regular_files
                .insert(id, Arc::new(Mutex::new(Vec::new())));
            return Ok(Some(OpenOutcome::Descriptor(
                Descriptor::<MockResources>::File(OpenFile::new(MockFile {
                    id,
                    path: String::from("/regular"),
                    access: FileAccess::ReadWrite,
                    is_memfd: false,
                })),
            )));
        }
        Err(FsOpError::Fs(FsError::NoEntry))
    }

    async fn stat_file(&self, file: &MockFile) -> Result<FileStat, FsOpError> {
        let guard = self.inner.lock().unwrap();
        if let Some(inode) = guard.memfds.get(&file.id) {
            let size = inode.data.lock().unwrap().len() as u64;
            return Ok(FileStat {
                dev: 1,
                ino: inode.id,
                kind: NodeKind::File,
                permissions: inode.mode,
                nlink: 1,
                uid: inode.uid,
                gid: inode.gid,
                rdev: 0,
                size,
                access_nanos: 0,
                modified_nanos: 0,
                status_nanos: 0,
            });
        }
        if let Some(buf) = guard.regular_files.get(&file.id) {
            return Ok(FileStat {
                dev: 2,
                ino: file.id,
                kind: NodeKind::File,
                permissions: 0o644,
                nlink: 1,
                uid: 0,
                gid: 0,
                rdev: 0,
                size: buf.lock().unwrap().len() as u64,
                access_nanos: 0,
                modified_nanos: 0,
                status_nanos: 0,
            });
        }
        Err(FsOpError::Fs(FsError::NoEntry))
    }

    async fn statfs_file(&self, file: &MockFile) -> Result<FsStat, FsOpError> {
        if file.is_memfd {
            return Ok(FsStat::synthetic_virtual(TMPFS_MAGIC));
        }
        Err(FsOpError::Fs(FsError::NoEntry))
    }

    async fn read_at(
        &self,
        file: &MockFile,
        offset: u64,
        max_bytes: usize,
    ) -> Result<Bytes, FsOpError> {
        let buf = self
            .shared_buffer_for_file(file.id)
            .ok_or(FsOpError::Fs(FsError::NoEntry))?;
        let data = buf.lock().unwrap();
        let off = offset as usize;
        if off >= data.len() {
            return Ok(Bytes::new());
        }
        let end = off.saturating_add(max_bytes).min(data.len());
        Ok(Bytes::copy_from_slice(&data[off..end]))
    }

    async fn write_at(
        &mut self,
        file: &MockFile,
        position: WritePosition,
        bytes: &[u8],
        _creds: &Credentials,
    ) -> Result<Landed, FsOpError> {
        let (buf, seals) = {
            let guard = self.inner.lock().unwrap();
            if let Some(inode) = guard.memfds.get(&file.id) {
                (inode.data.clone(), inode.seals)
            } else if let Some(reg) = guard.regular_files.get(&file.id) {
                (reg.clone(), 0)
            } else {
                return Err(FsOpError::Fs(FsError::NoEntry));
            }
        };
        if seals & (F_SEAL_WRITE | F_SEAL_FUTURE_WRITE) != 0 {
            return Err(FsOpError::PermissionDenied);
        }
        let mut data = buf.lock().unwrap();
        let off = match position {
            WritePosition::At(o) => o as usize,
            WritePosition::End => data.len(),
        };
        let end = off + bytes.len();
        if end > data.len() && (seals & F_SEAL_GROW != 0) {
            return Err(FsOpError::PermissionDenied);
        }
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
        file: &MockFile,
        size: u64,
        _creds: &Credentials,
    ) -> Result<(), FsOpError> {
        let (buf, seals) = {
            let guard = self.inner.lock().unwrap();
            if let Some(inode) = guard.memfds.get(&file.id) {
                (inode.data.clone(), inode.seals)
            } else if let Some(reg) = guard.regular_files.get(&file.id) {
                (reg.clone(), 0)
            } else {
                return Err(FsOpError::Fs(FsError::NoEntry));
            }
        };
        let mut data = buf.lock().unwrap();
        let cur = data.len() as u64;
        if size < cur && (seals & F_SEAL_SHRINK != 0) {
            return Err(FsOpError::PermissionDenied);
        }
        if size > cur && (seals & F_SEAL_GROW != 0) {
            return Err(FsOpError::PermissionDenied);
        }
        data.resize(size as usize, 0);
        Ok(())
    }

    async fn chmod_file(
        &mut self,
        file: &MockFile,
        mode: u32,
        _creds: &Credentials,
    ) -> Result<(), FsOpError> {
        let mut guard = self.inner.lock().unwrap();
        let inode = guard
            .memfds
            .get_mut(&file.id)
            .ok_or(FsOpError::Fs(FsError::NoEntry))?;
        let new_mode = mode & 0o7777;
        if (inode.seals & F_SEAL_EXEC != 0) && ((new_mode & 0o111) != (inode.mode & 0o111)) {
            return Err(FsOpError::PermissionDenied);
        }
        inode.mode = new_mode;
        Ok(())
    }

    fn create_memfd(
        &mut self,
        name: &str,
        flags: u32,
        creds: &Credentials,
    ) -> Result<(MockFile, MemfdHandle), FsOpError> {
        let mut guard = self.inner.lock().unwrap();
        let id = guard.next_id;
        guard.next_id += 1;
        let mut initial_seals = 0u32;
        if flags & MFD_ALLOW_SEALING == 0 {
            initial_seals |= F_SEAL_SEAL;
        }
        let mode = if flags & MFD_NOEXEC_SEAL != 0 {
            initial_seals |= F_SEAL_EXEC;
            0o666
        } else {
            0o777
        };
        let path = format!("/memfd:{name} (deleted)");
        let handle = MemfdHandle::new();
        guard.memfds.insert(
            id,
            MockMemfdInode {
                id,
                path: path.clone(),
                mode,
                uid: creds.user.effective,
                gid: creds.group.effective,
                seals: initial_seals,
                handle: handle.clone(),
                data: Arc::new(Mutex::new(Vec::new())),
            },
        );
        Ok((
            MockFile {
                id,
                path,
                access: FileAccess::ReadWrite,
                is_memfd: true,
            },
            handle,
        ))
    }

    fn reopen_memfd(
        &mut self,
        file: &MockFile,
        request: OpenRequest,
        _creds: &Credentials,
    ) -> Result<Option<(MockFile, MemfdHandle)>, FsOpError> {
        if !file.is_memfd {
            return Ok(None);
        }
        let guard = self.inner.lock().unwrap();
        let inode = guard
            .memfds
            .get(&file.id)
            .ok_or(FsOpError::Fs(FsError::NoEntry))?;
        if request.truncate
            && (inode.seals & F_SEAL_SHRINK != 0)
            && !inode.data.lock().unwrap().is_empty()
        {
            return Err(FsOpError::PermissionDenied);
        }
        if request.truncate {
            inode.data.lock().unwrap().clear();
        }
        let access = match (request.read, request.write) {
            (true, true) => FileAccess::ReadWrite,
            (false, true) => FileAccess::WriteOnly,
            _ => FileAccess::ReadOnly,
        };
        Ok(Some((
            MockFile {
                id: inode.id,
                path: inode.path.clone(),
                access,
                is_memfd: true,
            },
            inode.handle.clone(),
        )))
    }

    fn memfd_handle(&self, file: &MockFile) -> Option<MemfdHandle> {
        if !file.is_memfd {
            return None;
        }
        self.inner
            .lock()
            .unwrap()
            .memfds
            .get(&file.id)
            .map(|m| m.handle.clone())
    }

    fn memfd_acquire_writable_map(
        &self,
        file: &MockFile,
    ) -> Result<Option<helios_unix::MemfdWritableMapHold>, FsOpError> {
        if !file.is_memfd {
            return Ok(None);
        }
        let guard = self.inner.lock().unwrap();
        let Some(inode) = guard.memfds.get(&file.id) else {
            return Ok(None);
        };
        if inode.seals & (F_SEAL_WRITE | F_SEAL_FUTURE_WRITE) != 0 {
            return Err(FsOpError::PermissionDenied);
        }
        Ok(Some(inode.handle.acquire_writable_map()))
    }

    fn memfd_get_seals(&self, file: &MockFile) -> Option<u32> {
        if !file.is_memfd {
            return None;
        }
        self.inner
            .lock()
            .unwrap()
            .memfds
            .get(&file.id)
            .map(|m| m.seals)
    }

    fn memfd_add_seals(&mut self, file: &MockFile, seals: u32) -> Result<(), FsOpError> {
        let mut guard = self.inner.lock().unwrap();
        let inode = guard
            .memfds
            .get_mut(&file.id)
            .ok_or(FsOpError::Fs(FsError::Invalid))?;
        let current = inode.seals;
        if current & F_SEAL_SEAL != 0 {
            return Err(FsOpError::PermissionDenied);
        }
        let mut effective = seals;
        if (seals & F_SEAL_EXEC != 0) && (inode.mode & 0o111 != 0) {
            effective |= F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE | F_SEAL_FUTURE_WRITE;
        }
        if (effective & F_SEAL_WRITE != 0)
            && (current & F_SEAL_WRITE == 0)
            && inode.handle.writable_shared_maps() > 0
        {
            return Err(FsOpError::Fs(FsError::Busy));
        }
        inode.seals |= effective;
        Ok(())
    }

    fn sync_process_memfds(&self, pid: u32, fds: &[(i32, MockFile)]) {
        let mut guard = self.inner.lock().unwrap();
        if fds.is_empty() {
            guard.proc_memfds.remove(&pid);
        } else {
            guard
                .proc_memfds
                .insert(pid, fds.iter().map(|(fd, f)| (*fd, f.id)).collect());
        }
    }

    fn reap_memfds(&self) {
        let mut guard = self.inner.lock().unwrap();
        let dead: Vec<u64> = guard
            .memfds
            .iter()
            .filter_map(|(&id, inode)| (inode.handle.live_holds() == 0).then_some(id))
            .collect();
        for id in dead {
            guard.memfds.remove(&id);
        }
    }

    fn shm_get(
        &mut self,
        key: i32,
        size: u64,
        shmflg: u32,
        pid: u32,
        creds: &Credentials,
        now_secs: i64,
    ) -> Result<i32, u64> {
        let mut guard = self.inner.lock().unwrap();
        if key != IPC_PRIVATE
            && let Some(&idx) = guard.shm_keys.get(&key)
            && let Some(existing) = guard.shm_slots.get(idx).and_then(Option::as_ref)
        {
            if (shmflg & (IPC_CREAT | IPC_EXCL)) == (IPC_CREAT | IPC_EXCL) {
                return Err(EEXIST);
            }
            if size > existing.size {
                return Err(EINVAL);
            }
            check_ipc_perms(creds, existing.perm, shmflg & 0o777)?;
            return Ok(existing.shmid);
        }
        if key != IPC_PRIVATE && (shmflg & IPC_CREAT) == 0 {
            return Err(ENOENT);
        }
        if size < SHMMIN {
            return Err(EINVAL);
        }
        let used = guard.shm_slots.iter().flatten().count() as u64;
        if used >= SHMMNI {
            return Err(28);
        }
        let idx = guard
            .shm_slots
            .iter()
            .position(Option::is_none)
            .unwrap_or_else(|| {
                guard.shm_slots.push(None);
                guard.shm_slots.len() - 1
            });
        let seq = guard.next_shm_seq & 0x7fff;
        guard.next_shm_seq = guard.next_shm_seq.wrapping_add(1) & 0x7fff;
        let shmid = (i32::from(seq) << 15) | (idx as i32);
        let aligned = size.div_ceil(PAGE) * PAGE;
        guard.shm_slots[idx] = Some(MockShmSeg {
            shmid,
            perm: ShmPerm {
                key,
                uid: creds.user.effective,
                gid: creds.group.effective,
                cuid: creds.user.effective,
                cgid: creds.group.effective,
                mode: shmflg & 0o777,
                seq,
            },
            size,
            atime: 0,
            dtime: 0,
            ctime: now_secs,
            cpid: pid,
            lpid: 0,
            nattch: 0,
            destroyed: false,
            data: Arc::new(Mutex::new(vec![0u8; aligned as usize])),
        });
        if key != IPC_PRIVATE {
            guard.shm_keys.insert(key, idx);
        }
        Ok(shmid)
    }

    fn shm_prepare_attach(
        &mut self,
        shmid: i32,
        read_only: bool,
        exec: bool,
        creds: &Credentials,
    ) -> Result<u64, u64> {
        let guard = self.inner.lock().unwrap();
        let idx = (shmid & 0x7fff) as usize;
        let seg = guard
            .shm_slots
            .get(idx)
            .and_then(Option::as_ref)
            .filter(|s| s.shmid == shmid)
            .ok_or(EINVAL)?;
        let mut req = 0o4;
        if !read_only {
            req |= 0o2;
        }
        if exec {
            req |= 0o1;
        }
        check_ipc_perms(creds, seg.perm, req)?;
        Ok(seg.size)
    }

    fn shm_commit_attach(&mut self, shmid: i32, pid: u32, now_secs: i64) {
        let mut guard = self.inner.lock().unwrap();
        let idx = (shmid & 0x7fff) as usize;
        if let Some(seg) = guard.shm_slots.get_mut(idx).and_then(Option::as_mut)
            && seg.shmid == shmid
        {
            seg.nattch += 1;
            seg.atime = now_secs;
            seg.lpid = pid;
        }
    }

    fn shm_fork_attach(&mut self, shmid: i32) {
        let mut guard = self.inner.lock().unwrap();
        let idx = (shmid & 0x7fff) as usize;
        if let Some(seg) = guard.shm_slots.get_mut(idx).and_then(Option::as_mut)
            && seg.shmid == shmid
        {
            seg.nattch += 1;
        }
    }

    fn shm_fork_rollback(&mut self, shmid: i32) {
        let mut guard = self.inner.lock().unwrap();
        let idx = (shmid & 0x7fff) as usize;
        if let Some(seg) = guard.shm_slots.get_mut(idx).and_then(Option::as_mut)
            && seg.shmid == shmid
        {
            seg.nattch = seg.nattch.saturating_sub(1);
            if seg.destroyed && seg.nattch == 0 {
                guard.shm_slots[idx] = None;
            }
        }
    }

    fn shm_detach(&mut self, shmid: i32, pid: u32, now_secs: i64) {
        let mut guard = self.inner.lock().unwrap();
        let idx = (shmid & 0x7fff) as usize;
        if let Some(seg) = guard.shm_slots.get_mut(idx).and_then(Option::as_mut)
            && seg.shmid == shmid
        {
            seg.nattch = seg.nattch.saturating_sub(1);
            seg.dtime = now_secs;
            seg.lpid = pid;
            if seg.destroyed && seg.nattch == 0 {
                guard.shm_slots[idx] = None;
            }
        }
    }

    fn shm_ctl_stat(
        &self,
        id_or_idx: i32,
        by_index: bool,
        check_perms: bool,
        creds: &Credentials,
    ) -> Result<(i32, ShmStat), u64> {
        let guard = self.inner.lock().unwrap();
        let seg = if by_index {
            if id_or_idx < 0 {
                return Err(EINVAL);
            }
            guard
                .shm_slots
                .get(id_or_idx as usize)
                .and_then(Option::as_ref)
                .ok_or(EINVAL)?
        } else {
            if id_or_idx < 0 {
                return Err(EINVAL);
            }
            let idx = (id_or_idx & 0x7fff) as usize;
            guard
                .shm_slots
                .get(idx)
                .and_then(Option::as_ref)
                .filter(|s| s.shmid == id_or_idx)
                .ok_or(EINVAL)?
        };
        if check_perms {
            check_ipc_perms(creds, seg.perm, 0o4)?;
        }
        Ok((seg.shmid, seg.to_stat()))
    }

    fn shm_ctl_set(
        &mut self,
        shmid: i32,
        uid: u32,
        gid: u32,
        mode: u32,
        creds: &Credentials,
        now_secs: i64,
    ) -> Result<(), u64> {
        let mut guard = self.inner.lock().unwrap();
        let idx = (shmid & 0x7fff) as usize;
        let seg = guard
            .shm_slots
            .get_mut(idx)
            .and_then(Option::as_mut)
            .filter(|s| s.shmid == shmid)
            .ok_or(EINVAL)?;
        check_ipc_owner_or_admin(creds, seg.perm)?;
        seg.perm.uid = uid;
        seg.perm.gid = gid;
        seg.perm.mode = (seg.perm.mode & !0o777) | (mode & 0o777);
        seg.ctime = now_secs;
        Ok(())
    }

    fn shm_ctl_rmid(&mut self, shmid: i32, creds: &Credentials, now_secs: i64) -> Result<(), u64> {
        let mut guard = self.inner.lock().unwrap();
        let idx = (shmid & 0x7fff) as usize;
        let (key, drop_now) = {
            let seg = guard
                .shm_slots
                .get_mut(idx)
                .and_then(Option::as_mut)
                .filter(|s| s.shmid == shmid)
                .ok_or(EINVAL)?;
            check_ipc_owner_or_admin(creds, seg.perm)?;
            seg.destroyed = true;
            seg.perm.mode |= SHM_DEST;
            seg.ctime = now_secs;
            (seg.perm.key, seg.nattch == 0)
        };
        if key != IPC_PRIVATE && guard.shm_keys.get(&key) == Some(&idx) {
            guard.shm_keys.remove(&key);
        }
        if drop_now {
            guard.shm_slots[idx] = None;
        }
        Ok(())
    }

    fn shm_ctl_lock(&mut self, shmid: i32, lock: bool, creds: &Credentials) -> Result<(), u64> {
        let mut guard = self.inner.lock().unwrap();
        let idx = (shmid & 0x7fff) as usize;
        let seg = guard
            .shm_slots
            .get_mut(idx)
            .and_then(Option::as_mut)
            .filter(|s| s.shmid == shmid)
            .ok_or(EINVAL)?;
        check_ipc_owner_or_admin(creds, seg.perm)?;
        if lock {
            seg.perm.mode |= SHM_LOCKED;
        } else {
            seg.perm.mode &= !SHM_LOCKED;
        }
        Ok(())
    }

    fn shm_ctl_info(&self) -> (i32, ShmUsageInfo) {
        let guard = self.inner.lock().unwrap();
        let mut max_idx = 0i32;
        let mut used_ids = 0i32;
        let mut shm_tot = 0u64;
        for (idx, slot) in guard.shm_slots.iter().enumerate() {
            if let Some(seg) = slot {
                max_idx = idx as i32;
                used_ids += 1;
                shm_tot += seg.size.div_ceil(PAGE);
            }
        }
        (
            max_idx,
            ShmUsageInfo {
                used_ids,
                shm_tot,
                shm_rss: shm_tot,
                shm_swp: 0,
                swap_attempts: 0,
                swap_successes: 0,
            },
        )
    }
}

struct Guest {
    nums: AbiNums,
    process: Process<MockResources>,
    memory: MockMemory,
    backing: MockBacking,
    scratch: u64,
}

impl Guest {
    fn new(
        nums: AbiNums,
        backing: MockBacking,
        pids: PidNamespace,
        pid: u32,
        credentials: Credentials,
    ) -> Self {
        let process = Process::with_descriptors(
            nums.abi,
            NonZeroU32::new(pid).unwrap(),
            BREAK,
            standard_streams::<MockResources>(),
            Start {
                pids: Some(pids),
                credentials,
                ..Start::default()
            },
        );
        let mut memory = MockMemory::new(backing.clone());
        let scratch = memory
            .map_anywhere(0x10_0000, 4 * PAGE, PageFlags::READ | PageFlags::WRITE)
            .unwrap();
        Self {
            nums,
            process,
            memory,
            backing,
            scratch,
        }
    }

    fn call_full(
        &mut self,
        number: u64,
        arguments: [u64; 6],
    ) -> (
        ControlFlow<helios_linux::syscall::Exit, SyscallOutcome>,
        Option<Process<MockResources>>,
    ) {
        let mut thread = MockThread::new();
        let res = {
            let fut = dispatch(
                &mut self.process,
                Call { number, arguments },
                &mut self.memory,
                &mut thread,
                &mut self.backing,
            );
            let mut fut = core::pin::pin!(fut);
            match fut.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
                Poll::Ready(v) => v,
                Poll::Pending => panic!("unexpected Pending in synchronous mock syscall"),
            }
        };
        (res, thread.forked_child)
    }

    fn call(&mut self, number: u64, arguments: [u64; 6]) -> i64 {
        match self.call_full(number, arguments).0 {
            ControlFlow::Continue(SyscallOutcome::Return(val)) => val as i64,
            other => panic!("unexpected syscall outcome: {other:?}"),
        }
    }

    fn fork(&mut self) -> Self {
        let (flow, child_proc) = self.call_full(self.nums.clone, [SIGCHLD, 0, 0, 0, 0, 0]);
        let child_pid = match flow {
            ControlFlow::Continue(SyscallOutcome::Return(pid)) => pid as i64,
            other => panic!("unexpected clone outcome: {other:?}"),
        };
        assert!(child_pid > 0, "fork failed: {child_pid}");
        Self {
            nums: self.nums,
            process: child_proc.expect("fork produced child process"),
            memory: self.memory.fork_clone(),
            backing: self.backing.clone(),
            scratch: self.scratch,
        }
    }

    fn exit(&mut self, code: u64) {
        let (flow, _) = self.call_full(self.nums.exit_group, [code, 0, 0, 0, 0, 0]);
        assert!(matches!(flow, ControlFlow::Break(_)));
    }
}

fn neg(e: u64) -> i64 {
    -(e as i64)
}

#[test]
fn memfd_create_flags_name_validation_and_io_both_arches() {
    for nums in AbiNums::ALL {
        let backing = MockBacking::new();
        let pids = PidNamespace::new();
        let mut g = Guest::new(nums, backing.clone(), pids, 1, Credentials::root());

        // Bad pointer -> EFAULT.
        assert_eq!(g.call(nums.memfd_create, [0, 0, 0, 0, 0, 0]), neg(EFAULT));
        assert_eq!(
            g.call(nums.memfd_create, [0xdead_0000, 0, 0, 0, 0, 0]),
            neg(EFAULT)
        );

        // Name > 249 bytes -> EINVAL; exact 249 bytes -> OK.
        let too_long = vec![b'a'; 250];
        g.memory.put_cstr(g.scratch, &too_long);
        assert_eq!(
            g.call(nums.memfd_create, [g.scratch, 0, 0, 0, 0, 0]),
            neg(EINVAL)
        );
        let max_len = vec![b'b'; 249];
        g.memory.put_cstr(g.scratch, &max_len);
        let fd_max = g.call(
            nums.memfd_create,
            [g.scratch, u64::from(MFD_CLOEXEC), 0, 0, 0, 0],
        );
        assert!(fd_max >= 3);
        assert_eq!(g.call(nums.fcntl, [fd_max as u64, F_GETFD, 0, 0, 0, 0]), 1);
        assert_eq!(g.call(nums.close, [fd_max as u64, 0, 0, 0, 0, 0]), 0);
        assert_eq!(backing.active_memfds(), 0);

        // Flag validation.
        g.memory.put_cstr(g.scratch, b"flags");
        assert_eq!(
            g.call(
                nums.memfd_create,
                [g.scratch, u64::from(MFD_HUGETLB), 0, 0, 0, 0]
            ),
            neg(EINVAL)
        );
        assert_eq!(
            g.call(
                nums.memfd_create,
                [g.scratch, u64::from(MFD_NOEXEC_SEAL | MFD_EXEC), 0, 0, 0, 0]
            ),
            neg(EINVAL)
        );
        assert_eq!(
            g.call(nums.memfd_create, [g.scratch, 0x2000, 0, 0, 0, 0]),
            neg(EINVAL)
        );

        // CJK name covering Chinese, Japanese, and Korean.
        g.memory
            .put_cstr(g.scratch, "中文 日本語 한국어".as_bytes());
        let fd = g.call(
            nums.memfd_create,
            [
                g.scratch,
                u64::from(MFD_ALLOW_SEALING | MFD_NOEXEC_SEAL),
                0,
                0,
                0,
                0,
            ],
        );
        assert!(fd >= 3);
        assert_eq!(g.call(nums.fcntl, [fd as u64, F_GETFD, 0, 0, 0, 0]), 0);
        assert_eq!(
            g.call(nums.fcntl, [fd as u64, F_GET_SEALS, 0, 0, 0, 0]),
            i64::from(F_SEAL_EXEC)
        );

        // write / lseek / read / pwrite64 / pread64 / ftruncate / fallocate.
        let msg = b"hello memfd";
        g.memory.write(g.scratch, msg).unwrap();
        assert_eq!(
            g.call(
                nums.write,
                [fd as u64, g.scratch, msg.len() as u64, 0, 0, 0]
            ),
            msg.len() as i64
        );
        assert_eq!(g.call(nums.lseek, [fd as u64, 0, 0, 0, 0, 0]), 0);
        assert_eq!(
            g.call(
                nums.read,
                [fd as u64, g.scratch + 64, msg.len() as u64, 0, 0, 0]
            ),
            msg.len() as i64
        );
        let mut out = [0u8; 11];
        g.memory.read(g.scratch + 64, &mut out).unwrap();
        assert_eq!(&out, msg);

        g.memory.write(g.scratch, b"WORLD").unwrap();
        assert_eq!(g.call(nums.pwrite64, [fd as u64, g.scratch, 5, 6, 0, 0]), 5);
        let mut pbuf = [0u8; 5];
        assert_eq!(
            g.call(nums.pread64, [fd as u64, g.scratch + 128, 5, 6, 0, 0]),
            5
        );
        g.memory.read(g.scratch + 128, &mut pbuf).unwrap();
        assert_eq!(&pbuf, b"WORLD");

        // fstatfs reports TMPFS_MAGIC at offset 0 of struct statfs.
        assert_eq!(
            g.call(nums.fstatfs, [fd as u64, g.scratch + 256, 0, 0, 0, 0]),
            0
        );
        let mut fs_type_raw = [0u8; 8];
        g.memory.read(g.scratch + 256, &mut fs_type_raw).unwrap();
        assert_eq!(i64::from_le_bytes(fs_type_raw), TMPFS_MAGIC);

        // fstat succeeds.
        assert_eq!(
            g.call(nums.fstat, [fd as u64, g.scratch + 512, 0, 0, 0, 0]),
            0
        );

        // ftruncate grows and fallocate extends.
        assert_eq!(g.call(nums.ftruncate, [fd as u64, 4096, 0, 0, 0, 0]), 0);
        assert_eq!(g.call(nums.fallocate, [fd as u64, 0, 4096, 4096, 0, 0]), 0);

        // copy_file_range into a second memfd works coherently.
        g.memory.put_cstr(g.scratch, b"dst");
        let dst = g.call(
            nums.memfd_create,
            [g.scratch, u64::from(MFD_ALLOW_SEALING), 0, 0, 0, 0],
        );
        assert!(dst >= 3);
        assert_eq!(g.call(nums.lseek, [fd as u64, 0, 0, 0, 0, 0]), 0);
        assert_eq!(
            g.call(nums.copy_file_range, [fd as u64, 0, dst as u64, 0, 11, 0]),
            11
        );
        assert_eq!(
            g.call(nums.pread64, [dst as u64, g.scratch + 128, 11, 0, 0, 0]),
            11
        );
        let mut copied = [0u8; 11];
        g.memory.read(g.scratch + 128, &mut copied).unwrap();
        assert_eq!(&copied, b"hello WORLD");

        // Closing both fds reclaims both memfds immediately.
        assert_eq!(g.call(nums.close, [fd as u64, 0, 0, 0, 0, 0]), 0);
        assert_eq!(g.call(nums.close, [dst as u64, 0, 0, 0, 0, 0]), 0);
        assert_eq!(backing.active_memfds(), 0);
    }
}

#[test]
fn memfd_sealing_mmap_coherence_and_fork_both_arches() {
    for nums in AbiNums::ALL {
        let backing = MockBacking::new();
        let pids = PidNamespace::new();
        let mut parent = Guest::new(nums, backing.clone(), pids, 1, Credentials::root());

        // Non-memfd (regular file and stdout) returns EINVAL on F_GET_SEALS / F_ADD_SEALS.
        assert_eq!(
            parent.call(nums.fcntl, [1, F_GET_SEALS, 0, 0, 0, 0]),
            neg(EINVAL)
        );
        parent.memory.put_cstr(parent.scratch, b"/regular");
        let reg = parent.call(nums.openat, [AT_FDCWD, parent.scratch, O_RDWR, 0, 0, 0]);
        assert!(reg >= 3);
        assert_eq!(
            parent.call(nums.fcntl, [reg as u64, F_GET_SEALS, 0, 0, 0, 0]),
            neg(EINVAL)
        );
        assert_eq!(
            parent.call(
                nums.fcntl,
                [reg as u64, F_ADD_SEALS, u64::from(F_SEAL_WRITE), 0, 0, 0]
            ),
            neg(EINVAL)
        );
        assert_eq!(parent.call(nums.close, [reg as u64, 0, 0, 0, 0, 0]), 0);

        // Without MFD_ALLOW_SEALING, memfd starts with F_SEAL_SEAL set.
        parent.memory.put_cstr(parent.scratch, b"noseal");
        let noseal = parent.call(nums.memfd_create, [parent.scratch, 0, 0, 0, 0, 0]);
        assert_eq!(
            parent.call(nums.fcntl, [noseal as u64, F_GET_SEALS, 0, 0, 0, 0]),
            i64::from(F_SEAL_SEAL)
        );
        assert_eq!(
            parent.call(
                nums.fcntl,
                [noseal as u64, F_ADD_SEALS, u64::from(F_SEAL_WRITE), 0, 0, 0]
            ),
            neg(EPERM)
        );
        assert_eq!(parent.call(nums.close, [noseal as u64, 0, 0, 0, 0, 0]), 0);

        // Sealable memfd with MFD_NOEXEC_SEAL.
        parent.memory.put_cstr(parent.scratch, b"sealed");
        let fd = parent.call(
            nums.memfd_create,
            [
                parent.scratch,
                u64::from(MFD_ALLOW_SEALING | MFD_NOEXEC_SEAL),
                0,
                0,
                0,
                0,
            ],
        );
        assert_eq!(
            parent.call(nums.ftruncate, [fd as u64, PAGE, 0, 0, 0, 0]),
            0
        );

        // Unknown seal bits -> EINVAL.
        assert_eq!(
            parent.call(nums.fcntl, [fd as u64, F_ADD_SEALS, 0x8000, 0, 0, 0]),
            neg(EINVAL)
        );

        // Reopen read-only via /proc/self/fd/<fd>: F_ADD_SEALS requires writable fd -> EPERM.
        let proc_fd_path = format!("/proc/self/fd/{fd}");
        parent
            .memory
            .put_cstr(parent.scratch, proc_fd_path.as_bytes());
        let ro_fd = parent.call(nums.openat, [AT_FDCWD, parent.scratch, O_RDONLY, 0, 0, 0]);
        assert!(ro_fd >= 3);
        assert_eq!(
            parent.call(
                nums.fcntl,
                [ro_fd as u64, F_ADD_SEALS, u64::from(F_SEAL_GROW), 0, 0, 0]
            ),
            neg(EPERM)
        );

        // MAP_SHARED | PROT_WRITE in parent, then fork child -> coherent writes & EBUSY on F_SEAL_WRITE.
        let map_addr = parent.call(
            nums.mmap,
            [0, PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, fd as u64, 0],
        ) as u64;
        assert!(map_addr >= LOWEST);
        parent.memory.write(map_addr, b"PARENT").unwrap();

        let mut child = parent.fork();
        let mut seen_in_child = [0u8; 6];
        child.memory.read(map_addr, &mut seen_in_child).unwrap();
        assert_eq!(&seen_in_child, b"PARENT");
        child.memory.write(map_addr + 6, b"_CHILD").unwrap();

        // Visible via parent MAP_SHARED and via pread64!
        let mut seen_in_parent = [0u8; 12];
        parent.memory.read(map_addr, &mut seen_in_parent).unwrap();
        assert_eq!(&seen_in_parent, b"PARENT_CHILD");
        assert_eq!(
            parent.call(nums.pread64, [fd as u64, parent.scratch, 12, 0, 0, 0]),
            12
        );
        let mut pread_buf = [0u8; 12];
        parent.memory.read(parent.scratch, &mut pread_buf).unwrap();
        assert_eq!(&pread_buf, b"PARENT_CHILD");

        // F_SEAL_WRITE fails with EBUSY while parent or child holds writable MAP_SHARED.
        assert_eq!(
            parent.call(
                nums.fcntl,
                [fd as u64, F_ADD_SEALS, u64::from(F_SEAL_WRITE), 0, 0, 0]
            ),
            neg(EBUSY)
        );
        assert_eq!(parent.call(nums.munmap, [map_addr, PAGE, 0, 0, 0, 0]), 0);
        // Child STILL holds the writable MAP_SHARED mapping -> STILL EBUSY!
        assert_eq!(
            parent.call(
                nums.fcntl,
                [fd as u64, F_ADD_SEALS, u64::from(F_SEAL_WRITE), 0, 0, 0]
            ),
            neg(EBUSY)
        );

        // F_SEAL_FUTURE_WRITE succeeds even while child holds its existing writable MAP_SHARED!
        assert_eq!(
            parent.call(
                nums.fcntl,
                [
                    fd as u64,
                    F_ADD_SEALS,
                    u64::from(F_SEAL_FUTURE_WRITE),
                    0,
                    0,
                    0
                ]
            ),
            0
        );
        // Existing child mapping still writes, while new write/MAP_SHARED|PROT_WRITE fail with EPERM.
        child.memory.write(map_addr, b"FUTWRT").unwrap();
        assert_eq!(
            parent.call(nums.write, [fd as u64, parent.scratch, 4, 0, 0, 0]),
            neg(EPERM)
        );
        assert_eq!(
            parent.call(
                nums.mmap,
                [0, PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, fd as u64, 0]
            ),
            neg(EPERM)
        );

        // MAP_SHARED | PROT_READ on a writable fd clears VM_MAYWRITE under F_SEAL_FUTURE_WRITE,
        // so mprotect(PROT_WRITE) fails with EACCES!
        let ro_map = parent.call(nums.mmap, [0, PAGE, PROT_READ, MAP_SHARED, fd as u64, 0]) as u64;
        assert!(ro_map >= LOWEST);
        assert_eq!(
            parent.call(
                nums.mprotect,
                [ro_map, PAGE, PROT_READ | PROT_WRITE, 0, 0, 0]
            ),
            neg(EACCES)
        );

        // Child exits -> releases its writable MAP_SHARED hold -> F_SEAL_WRITE now succeeds!
        child.exit(0);
        assert_eq!(
            parent.call(
                nums.fcntl,
                [fd as u64, F_ADD_SEALS, u64::from(F_SEAL_WRITE), 0, 0, 0]
            ),
            0
        );

        // Zero-length write, pwrite64, writev, fallocate(PUNCH_HOLE) all fail with EPERM.
        assert_eq!(
            parent.call(nums.write, [fd as u64, parent.scratch, 0, 0, 0, 0]),
            neg(EPERM)
        );
        assert_eq!(
            parent.call(nums.pwrite64, [fd as u64, parent.scratch, 4, 0, 0, 0]),
            neg(EPERM)
        );
        let iov = parent.scratch + 256;
        parent
            .memory
            .write(iov, &parent.scratch.to_le_bytes())
            .unwrap();
        parent.memory.write(iov + 8, &4u64.to_le_bytes()).unwrap();
        assert_eq!(
            parent.call(nums.writev, [fd as u64, iov, 1, 0, 0, 0]),
            neg(EPERM)
        );
        assert_eq!(
            parent.call(
                nums.fallocate,
                [
                    fd as u64,
                    FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
                    0,
                    64,
                    0,
                    0
                ]
            ),
            neg(EPERM)
        );

        // MAP_PRIVATE | PROT_WRITE still succeeds when write-sealed.
        let priv_map = parent.call(
            nums.mmap,
            [0, PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd as u64, 0],
        ) as u64;
        assert!(priv_map >= LOWEST);
        assert_eq!(parent.call(nums.munmap, [priv_map, PAGE, 0, 0, 0, 0]), 0);

        // F_SEAL_SHRINK & F_SEAL_GROW on ftruncate and fallocate.
        assert_eq!(
            parent.call(
                nums.fcntl,
                [fd as u64, F_ADD_SEALS, u64::from(F_SEAL_SHRINK), 0, 0, 0]
            ),
            0
        );
        assert_eq!(
            parent.call(nums.ftruncate, [fd as u64, 16, 0, 0, 0, 0]),
            neg(EPERM)
        );
        // O_TRUNC reopen fails with EPERM under F_SEAL_SHRINK.
        parent
            .memory
            .put_cstr(parent.scratch, proc_fd_path.as_bytes());
        assert_eq!(
            parent.call(
                nums.openat,
                [AT_FDCWD, parent.scratch, O_RDWR | O_TRUNC, 0, 0, 0]
            ),
            neg(EPERM)
        );
        assert_eq!(
            parent.call(nums.ftruncate, [fd as u64, 2 * PAGE, 0, 0, 0, 0]),
            0
        );
        assert_eq!(
            parent.call(
                nums.fcntl,
                [fd as u64, F_ADD_SEALS, u64::from(F_SEAL_GROW), 0, 0, 0]
            ),
            0
        );
        assert_eq!(
            parent.call(nums.ftruncate, [fd as u64, 3 * PAGE, 0, 0, 0, 0]),
            neg(EPERM)
        );
        assert_eq!(
            parent.call(nums.fallocate, [fd as u64, 0, 2 * PAGE, PAGE, 0, 0]),
            neg(EPERM)
        );

        // F_SEAL_EXEC blocks changing exec bits via fchmod, allows non-exec changes.
        assert_eq!(
            parent.call(nums.fchmod, [fd as u64, 0o755, 0, 0, 0, 0]),
            neg(EPERM)
        );
        assert_eq!(parent.call(nums.fchmod, [fd as u64, 0o640, 0, 0, 0, 0]), 0);

        // F_SEAL_SEAL freezes the seal mask permanently.
        assert_eq!(
            parent.call(
                nums.fcntl,
                [fd as u64, F_ADD_SEALS, u64::from(F_SEAL_SEAL), 0, 0, 0]
            ),
            0
        );
        assert_eq!(
            parent.call(
                nums.fcntl,
                [fd as u64, F_ADD_SEALS, u64::from(F_SEAL_EXEC), 0, 0, 0]
            ),
            neg(EPERM)
        );

        // Memfd stays alive while ro_map exists even after fds close, then reaps
        // immediately once ro_map is unmapped.
        assert_eq!(parent.call(nums.close, [fd as u64, 0, 0, 0, 0, 0]), 0);
        assert_eq!(parent.call(nums.close, [ro_fd as u64, 0, 0, 0, 0, 0]), 0);
        assert_eq!(backing.active_memfds(), 1);
        assert_eq!(parent.call(nums.munmap, [ro_map, PAGE, 0, 0, 0, 0]), 0);
        assert_eq!(backing.active_memfds(), 0);
    }
}

#[test]
fn sysv_shm_lifecycle_lp64_layout_and_fork_exec_exit_both_arches() {
    for nums in AbiNums::ALL {
        let backing = MockBacking::new();
        let pids = PidNamespace::new();
        let owner_creds = Credentials::for_ids(1000, 1000, Vec::new());
        let mut parent = Guest::new(nums, backing.clone(), pids.clone(), 1, owner_creds);

        let key: u64 = 0x4242;
        // Lookup without IPC_CREAT -> ENOENT.
        assert_eq!(
            parent.call(nums.shmget, [key, PAGE, 0o600, 0, 0, 0]),
            neg(ENOENT)
        );
        // Size 0 or SHM_HUGETLB -> EINVAL.
        assert_eq!(
            parent.call(nums.shmget, [key, 0, u64::from(IPC_CREAT) | 0o600, 0, 0, 0]),
            neg(EINVAL)
        );
        assert_eq!(
            parent.call(
                nums.shmget,
                [
                    key,
                    PAGE,
                    u64::from(IPC_CREAT | SHM_HUGETLB) | 0o600,
                    0,
                    0,
                    0
                ]
            ),
            neg(EINVAL)
        );

        // Create segment with IPC_CREAT | IPC_EXCL.
        let shmid = parent.call(
            nums.shmget,
            [key, 5000, u64::from(IPC_CREAT | IPC_EXCL) | 0o640, 0, 0, 0],
        );
        assert!(shmid >= 0);
        assert_eq!(
            parent.call(
                nums.shmget,
                [key, 5000, u64::from(IPC_CREAT | IPC_EXCL) | 0o640, 0, 0, 0]
            ),
            neg(EEXIST)
        );
        // Oversize lookup on existing key -> EINVAL.
        assert_eq!(
            parent.call(nums.shmget, [key, 9000, 0o600, 0, 0, 0]),
            neg(EINVAL)
        );
        // Existing lookup with smaller size returns same shmid.
        assert_eq!(parent.call(nums.shmget, [key, 4096, 0o600, 0, 0, 0]), shmid);

        // Unprivileged foreign UID is denied attach/stat; CAP_IPC_OWNER overrides DAC.
        let other_creds = Credentials::for_ids(2000, 2000, Vec::new());
        let mut other = Guest::new(nums, backing.clone(), pids.clone(), 2, other_creds);
        assert_eq!(
            other.call(nums.shmat, [shmid as u64, 0, 0, 0, 0, 0]),
            neg(EACCES)
        );
        assert_eq!(
            other.call(
                nums.shmctl,
                [shmid as u64, u64::from(IPC_STAT), other.scratch, 0, 0, 0]
            ),
            neg(EACCES)
        );
        let mut ipc_owner_creds = Credentials::for_ids(2000, 2000, Vec::new());
        ipc_owner_creds.capabilities.effective |= 1u64 << CAP_IPC_OWNER;
        let mut ipc_owner = Guest::new(nums, backing.clone(), pids.clone(), 3, ipc_owner_creds);
        assert_eq!(
            ipc_owner.call(
                nums.shmctl,
                [
                    shmid as u64,
                    u64::from(IPC_STAT | IPC_64),
                    ipc_owner.scratch,
                    0,
                    0,
                    0
                ]
            ),
            0
        );

        // shmat validation: unaligned without SHM_RND -> EINVAL; SHM_REMAP with 0 -> EINVAL.
        assert_eq!(
            parent.call(nums.shmat, [shmid as u64, 0x20_0001, 0, 0, 0, 0]),
            neg(EINVAL)
        );
        assert_eq!(
            parent.call(nums.shmat, [shmid as u64, 0, u64::from(SHM_REMAP), 0, 0, 0]),
            neg(EINVAL)
        );

        // Attach with SHM_RND rounds down to SHMLBA (4096).
        backing.advance_time(10);
        let addr_rw = parent.call(
            nums.shmat,
            [shmid as u64, 0x30_0123, u64::from(SHM_RND), 0, 0, 0],
        ) as u64;
        assert_eq!(addr_rw, 0x30_0000);
        parent.memory.write(addr_rw, b"SYSV_SHM").unwrap();

        // Attach read-only: mprotect(PROT_WRITE) fails with EACCES.
        let addr_ro = parent.call(
            nums.shmat,
            [shmid as u64, 0, u64::from(SHM_RDONLY), 0, 0, 0],
        ) as u64;
        assert!(addr_ro >= LOWEST);
        let mut ro_bytes = [0u8; 8];
        parent.memory.read(addr_ro, &mut ro_bytes).unwrap();
        assert_eq!(&ro_bytes, b"SYSV_SHM");
        assert_eq!(
            parent.call(
                nums.mprotect,
                [addr_ro, 2 * PAGE, PROT_READ | PROT_WRITE, 0, 0, 0]
            ),
            neg(EACCES)
        );

        // Verify exact 112-byte LP64 struct shmid64_ds via IPC_STAT & SHM_STAT.
        let stat_buf = parent.scratch;
        assert_eq!(
            parent.call(
                nums.shmctl,
                [shmid as u64, u64::from(IPC_STAT), stat_buf, 0, 0, 0]
            ),
            0
        );
        let mut ds = [0u8; SHMID64_DS_BYTES];
        parent.memory.read(stat_buf, &mut ds).unwrap();
        assert_eq!(i32::from_le_bytes(ds[0..4].try_into().unwrap()), key as i32);
        assert_eq!(u32::from_le_bytes(ds[4..8].try_into().unwrap()), 1000);
        assert_eq!(u32::from_le_bytes(ds[8..12].try_into().unwrap()), 1000);
        assert_eq!(
            u32::from_le_bytes(ds[20..24].try_into().unwrap()) & 0o777,
            0o640
        );
        assert_eq!(u64::from_le_bytes(ds[48..56].try_into().unwrap()), 5000);
        assert_eq!(
            i64::from_le_bytes(ds[56..64].try_into().unwrap()),
            1_700_000_010
        );
        assert_eq!(i64::from_le_bytes(ds[64..72].try_into().unwrap()), 0);
        assert_eq!(i32::from_le_bytes(ds[80..84].try_into().unwrap()), 1);
        assert_eq!(i32::from_le_bytes(ds[84..88].try_into().unwrap()), 1);
        assert_eq!(u64::from_le_bytes(ds[88..96].try_into().unwrap()), 2);

        // SHM_STAT by slot index 0 returns resolved shmid.
        assert_eq!(
            parent.call(nums.shmctl, [0, u64::from(SHM_STAT), stat_buf, 0, 0, 0]),
            shmid
        );

        // IPC_INFO (72 B) and SHM_INFO (48 B).
        assert_eq!(
            parent.call(nums.shmctl, [0, u64::from(IPC_INFO), stat_buf, 0, 0, 0]),
            0
        );
        let mut info64 = [0u8; SHMINFO64_BYTES];
        parent.memory.read(stat_buf, &mut info64).unwrap();
        assert_eq!(
            u64::from_le_bytes(info64[8..16].try_into().unwrap()),
            SHMMIN
        );

        assert_eq!(
            parent.call(nums.shmctl, [0, u64::from(SHM_INFO), stat_buf, 0, 0, 0]),
            0
        );
        let mut shm_info = [0u8; SHM_INFO_BYTES];
        parent.memory.read(stat_buf, &mut shm_info).unwrap();
        assert_eq!(i32::from_le_bytes(shm_info[0..4].try_into().unwrap()), 1);
        assert_eq!(u64::from_le_bytes(shm_info[8..16].try_into().unwrap()), 2);

        // IPC_SET updates mode (denied to non-owner without CAP_SYS_ADMIN).
        ds[20..24].copy_from_slice(&0o660u32.to_le_bytes());
        other.memory.write(other.scratch, &ds).unwrap();
        assert_eq!(
            other.call(
                nums.shmctl,
                [shmid as u64, u64::from(IPC_SET), other.scratch, 0, 0, 0]
            ),
            neg(EPERM)
        );
        parent.memory.write(stat_buf, &ds).unwrap();
        assert_eq!(
            parent.call(
                nums.shmctl,
                [shmid as u64, u64::from(IPC_SET), stat_buf, 0, 0, 0]
            ),
            0
        );

        // SHM_LOCK / SHM_UNLOCK toggle SHM_LOCKED bit.
        assert_eq!(
            parent.call(nums.shmctl, [shmid as u64, u64::from(SHM_LOCK), 0, 0, 0, 0]),
            0
        );
        assert_eq!(
            parent.call(
                nums.shmctl,
                [shmid as u64, u64::from(IPC_STAT), stat_buf, 0, 0, 0]
            ),
            0
        );
        parent.memory.read(stat_buf, &mut ds).unwrap();
        assert_ne!(
            u32::from_le_bytes(ds[20..24].try_into().unwrap()) & SHM_LOCKED,
            0
        );
        assert_eq!(
            parent.call(
                nums.shmctl,
                [shmid as u64, u64::from(SHM_UNLOCK), 0, 0, 0, 0]
            ),
            0
        );

        // SHM_REMAP replaces an existing anonymous mapping at a fixed address.
        let victim = parent.call(
            nums.mmap,
            [
                0x40_0000,
                2 * PAGE,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
                u64::MAX,
                0,
            ],
        ) as u64;
        assert_eq!(victim, 0x40_0000);
        // SHM_EXEC requires execute permission (0o660 -> EACCES; 0o760 -> OK).
        assert_eq!(
            parent.call(
                nums.shmat,
                [
                    shmid as u64,
                    0x40_0000,
                    u64::from(SHM_REMAP | SHM_EXEC),
                    0,
                    0,
                    0,
                ]
            ),
            neg(EACCES)
        );
        ds[20..24].copy_from_slice(&0o760u32.to_le_bytes());
        parent.memory.write(stat_buf, &ds).unwrap();
        assert_eq!(
            parent.call(
                nums.shmctl,
                [shmid as u64, u64::from(IPC_SET), stat_buf, 0, 0, 0]
            ),
            0
        );
        let remapped = parent.call(
            nums.shmat,
            [
                shmid as u64,
                0x40_0000,
                u64::from(SHM_REMAP | SHM_EXEC),
                0,
                0,
                0,
            ],
        ) as u64;
        assert_eq!(remapped, 0x40_0000);
        // Now nattch == 3. Detach via munmap drops it to 2.
        assert_eq!(
            parent.call(nums.munmap, [remapped, 2 * PAGE, 0, 0, 0, 0]),
            0
        );

        // Fork increments nattch from 2 to 4 (2 parent + 2 child); child writes visible in parent.
        let mut child = parent.fork();
        child.memory.write(addr_rw + 4, b"_FORK").unwrap();
        let mut merged = [0u8; 9];
        parent.memory.read(addr_ro, &mut merged).unwrap();
        assert_eq!(&merged, b"SYSV_FORK");
        assert_eq!(
            parent.call(
                nums.shmctl,
                [shmid as u64, u64::from(IPC_STAT), stat_buf, 0, 0, 0]
            ),
            0
        );
        parent.memory.read(stat_buf, &mut ds).unwrap();
        assert_eq!(u64::from_le_bytes(ds[88..96].try_into().unwrap()), 4);

        // shmdt rejects non-base / unmapped addresses with EINVAL.
        assert_eq!(
            parent.call(nums.shmdt, [addr_rw + PAGE, 0, 0, 0, 0, 0]),
            neg(EINVAL)
        );
        assert_eq!(
            parent.call(nums.shmdt, [0x90_0000, 0, 0, 0, 0, 0]),
            neg(EINVAL)
        );

        // IPC_RMID unlinks key immediately while keeping segment alive until nattch == 0.
        backing.advance_time(5);
        assert_eq!(
            parent.call(nums.shmctl, [shmid as u64, u64::from(IPC_RMID), 0, 0, 0, 0]),
            0
        );
        assert_eq!(
            parent.call(nums.shmget, [key, PAGE, 0o600, 0, 0, 0]),
            neg(ENOENT)
        );

        // Child exit detaches child's 2 attachments (nattch: 4 -> 2).
        child.exit(0);
        assert_eq!(
            parent.call(
                nums.shmctl,
                [shmid as u64, u64::from(IPC_STAT), stat_buf, 0, 0, 0]
            ),
            0
        );
        parent.memory.read(stat_buf, &mut ds).unwrap();
        assert_eq!(u64::from_le_bytes(ds[88..96].try_into().unwrap()), 2);

        // Parent detaches addr_rw (nattch -> 1), then simulates execve detach (nattch -> 0 -> destroyed!).
        backing.advance_time(5);
        assert_eq!(parent.call(nums.shmdt, [addr_rw, 0, 0, 0, 0, 0]), 0);
        assert_eq!(backing.active_shm_segments(), 1);
        parent
            .process
            .detach_sysv_shm(1_700_000_030, &mut parent.backing);
        assert_eq!(backing.active_shm_segments(), 0);
        assert_eq!(
            parent.call(
                nums.shmctl,
                [shmid as u64, u64::from(IPC_STAT), stat_buf, 0, 0, 0]
            ),
            neg(EINVAL)
        );

        // IPC_PRIVATE with immediate IPC_RMID while nattch == 0 destroys immediately.
        let mut admin_creds = Credentials::for_ids(3000, 3000, Vec::new());
        admin_creds.capabilities.effective |= 1u64 << CAP_SYS_ADMIN;
        let mut admin = Guest::new(nums, backing.clone(), pids, 4, admin_creds);
        let priv_id = parent.call(nums.shmget, [IPC_PRIVATE as u64, PAGE, 0o600, 0, 0, 0]);
        assert!(priv_id >= 0);
        assert_eq!(backing.active_shm_segments(), 1);
        assert_eq!(
            admin.call(
                nums.shmctl,
                [priv_id as u64, u64::from(IPC_RMID), 0, 0, 0, 0]
            ),
            0
        );
        assert_eq!(backing.active_shm_segments(), 0);
    }
}
