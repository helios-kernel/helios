//! Unit tests for `#1028`: stdin `epoll_ctl` & `O_NONBLOCK`, `poll`/`ppoll`/
//! `select`/`pselect6`, `tty` ioctls, `fcntl` shared status flags, and
//! file-backed `MAP_PRIVATE`/`MAP_SHARED` `mmap` + `msync`.

use bytes::Bytes;
use core::future::Future;
use core::num::NonZeroU32;
use core::ops::ControlFlow;
use core::sync::atomic::{AtomicUsize, Ordering};
use core::task::{Context, Poll, Waker};
use helios_hal::fs::{FsError, Landed, NodeKind, WritePosition};
use helios_hal::vmm::PageFlags;
use helios_linux::abi::{Abi, Operation};
use helios_linux::syscall::{
    Call, Clock, Denied, FileAccess, FileStat, Filesystem, MapError, MemoryFault, MemoryTotals,
    OpenRequest, Process, READY_IN, Region, Resources, SpawnError, SpawnedThread, StdinTryRead,
    Stdio, Stream, SyscallOutcome, System, Termios, TermiosAction, Thread, Tty, TtyError,
    TtyStream, UserMemory, VirtualMemory, Winsize, WriteError, dispatch,
};
use helios_sync::Notify;
use helios_unix::{NoNetwork, OpenFile};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::task::Wake;

const PAGE: u64 = 4096;
const EPERM: u64 = 1;
const ENOENT: u64 = 2;
const EBADF: u64 = 9;
const EAGAIN: u64 = 11;
const ENOMEM: u64 = 12;
const EACCES: u64 = 13;
const EFAULT: u64 = 14;
const EINVAL: u64 = 22;
const ENOTTY: u64 = 25;

fn err(code: u64) -> u64 {
    code.wrapping_neg()
}

fn syscall_num(abi: Abi, op: Operation) -> u64 {
    for n in 0..512 {
        if abi.operation(n) == op {
            return n;
        }
    }
    panic!("operation {op:?} has no syscall number on {abi:?}");
}

#[derive(Clone)]
struct MemFile {
    id: u64,
    access: FileAccess,
}

struct MemRes;
impl Resources for MemRes {
    type File = MemFile;
    type Network = NoNetwork;
    type Data = u64;
}

struct PageMem {
    pages: BTreeMap<u64, (PageFlags, [u8; PAGE as usize])>,
    next_addr: u64,
}

impl Default for PageMem {
    fn default() -> Self {
        let mut mem = Self {
            pages: BTreeMap::new(),
            next_addr: 0x20_0000,
        };
        // Scratch page at 0x10_0000 for syscall buffers.
        mem.pages
            .insert(0x10_0000, (PageFlags::READ | PageFlags::WRITE, [0; 4096]));
        mem
    }
}

impl UserMemory for PageMem {
    fn read(&self, address: u64, output: &mut [u8]) -> Result<(), MemoryFault> {
        for (i, byte) in output.iter_mut().enumerate() {
            let a = address.checked_add(i as u64).ok_or(MemoryFault)?;
            let base = a & !(PAGE - 1);
            let (flags, data) = self.pages.get(&base).ok_or(MemoryFault)?;
            if !flags.contains(PageFlags::READ) {
                return Err(MemoryFault);
            }
            *byte = data[(a % PAGE) as usize];
        }
        Ok(())
    }
    fn check_writable(&self, address: u64, length: usize) -> Result<(), MemoryFault> {
        for i in 0..length {
            let a = address.checked_add(i as u64).ok_or(MemoryFault)?;
            let base = a & !(PAGE - 1);
            let (flags, _) = self.pages.get(&base).ok_or(MemoryFault)?;
            if !flags.contains(PageFlags::WRITE) {
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
            let (_, data) = self.pages.get_mut(&base).unwrap();
            data[(a % PAGE) as usize] = b;
        }
        Ok(())
    }
    fn atomic_load_u32(&self, address: u64) -> Result<u32, MemoryFault> {
        let mut raw = [0; 4];
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

impl VirtualMemory for PageMem {
    fn lowest_address(&self) -> u64 {
        PAGE
    }
    fn map_anywhere(
        &mut self,
        _hint: u64,
        length: u64,
        access: PageFlags,
    ) -> Result<u64, MapError> {
        let addr = self.next_addr;
        self.next_addr += length + PAGE;
        self.map_at(addr, length, access)?;
        Ok(addr)
    }
    fn map_at(&mut self, address: u64, length: u64, access: PageFlags) -> Result<(), MapError> {
        let mut cur = address;
        while cur < address + length {
            if self.pages.contains_key(&cur) {
                return Err(MapError::Occupied);
            }
            cur += PAGE;
        }
        let mut cur = address;
        while cur < address + length {
            self.pages.insert(cur, (access, [0; PAGE as usize]));
            cur += PAGE;
        }
        Ok(())
    }
    fn unmap(&mut self, address: u64, length: u64) {
        let mut cur = address;
        while cur < address + length {
            self.pages.remove(&cur);
            cur += PAGE;
        }
    }
    fn protect(&mut self, address: u64, length: u64, access: PageFlags) -> Result<(), MapError> {
        let mut cur = address;
        while cur < address + length {
            let entry = self.pages.get_mut(&cur).ok_or(MapError::Address)?;
            entry.0 = access;
            cur += PAGE;
        }
        Ok(())
    }
    fn discard(&mut self, address: u64, length: u64) {
        let mut cur = address;
        while cur < address + length {
            if let Some(entry) = self.pages.get_mut(&cur) {
                entry.1.fill(0);
            }
            cur += PAGE;
        }
    }
    fn remap(&mut self, from: u64, length: u64, to: u64, new_length: u64) -> Result<(), MapError> {
        let mut moved = Vec::new();
        let mut cur = from;
        while cur < from + length {
            moved.push(self.pages.remove(&cur).ok_or(MapError::Address)?);
            cur += PAGE;
        }
        let access = moved[0].0;
        for (i, page) in moved.into_iter().enumerate() {
            self.pages.insert(to + (i as u64) * PAGE, page);
        }
        let mut cur = to + length;
        while cur < to + new_length {
            self.pages.insert(cur, (access, [0; PAGE as usize]));
            cur += PAGE;
        }
        Ok(())
    }
    fn region(&self, start: u64, end: u64) -> Option<Region> {
        let (&first, &(access, _)) = self.pages.range(start..end).next()?;
        let mut run_end = first + PAGE;
        while run_end < end {
            match self.pages.get(&run_end) {
                Some(&(a, _)) if a == access => run_end += PAGE,
                _ => break,
            }
        }
        Some(Region {
            start: first,
            end: run_end.min(end),
            access,
        })
    }
    fn free_range(&self, hint: u64, length: u64) -> Option<u64> {
        let candidate = hint.max(self.next_addr);
        if self.region(candidate, candidate + length).is_none() {
            Some(candidate)
        } else {
            None
        }
    }
}

struct DummyThread;
impl Thread<MemRes> for DummyThread {
    fn thread_pointer(&self) -> u64 {
        0
    }
    fn set_thread_pointer(&mut self, _: u64) -> Result<(), Denied> {
        Ok(())
    }
    fn spawn_thread(&mut self, _: Process<MemRes>, _: SpawnedThread) -> Result<(), SpawnError> {
        Err(SpawnError::Busy)
    }
}

struct MockHost {
    stdin: Arc<Mutex<Vec<u8>>>,
    stdin_notify: Arc<Notify>,
    stdin_eof: bool,
    stdin_return_whole_chunk: bool,
    tty_attached: bool,
    tty_control: bool,
    termios: Termios,
    winsize: Winsize,
    files: Arc<Mutex<BTreeMap<u64, Vec<u8>>>>,
    now: u64,
}

impl Default for MockHost {
    fn default() -> Self {
        Self {
            stdin: Arc::new(Mutex::new(Vec::new())),
            stdin_notify: Arc::new(Notify::new()),
            stdin_eof: false,
            stdin_return_whole_chunk: false,
            tty_attached: true,
            tty_control: true,
            termios: Termios::from_flags(true, true, true),
            winsize: Winsize::DEFAULT,
            files: Arc::new(Mutex::new(BTreeMap::new())),
            now: 0,
        }
    }
}

impl Stdio for MockHost {
    async fn write(&mut self, _: Stream, bytes: &[u8]) -> Result<usize, WriteError> {
        Ok(bytes.len())
    }
    async fn read_input(&mut self, limit: usize) -> Result<Bytes, Denied> {
        let mut guard = self.stdin.lock().unwrap();
        let take = if self.stdin_return_whole_chunk {
            guard.len()
        } else {
            guard.len().min(limit)
        };
        let out = Bytes::copy_from_slice(&guard[..take]);
        guard.drain(..take);
        Ok(out)
    }
    fn try_read_input(&mut self, limit: usize) -> StdinTryRead {
        let mut guard = self.stdin.lock().unwrap();
        if !guard.is_empty() {
            let take = guard.len().min(limit);
            let out = Bytes::copy_from_slice(&guard[..take]);
            guard.drain(..take);
            StdinTryRead::Ready(out)
        } else if self.stdin_eof {
            StdinTryRead::Eof
        } else {
            StdinTryRead::WouldBlock
        }
    }
    fn stdin_ready_mask(&self) -> u32 {
        if !self.stdin.lock().unwrap().is_empty() || self.stdin_eof {
            READY_IN
        } else {
            0
        }
    }
    async fn wait_stdin_ready(&self) {
        loop {
            let mut waiter = self.stdin_notify.waiter();
            if self.stdin_ready_mask() != 0 {
                return;
            }
            core::future::poll_fn(|cx| self.stdin_notify.poll_notified(cx, &mut waiter)).await;
        }
    }
}

impl Clock for MockHost {
    fn now_nanos(&self) -> u64 {
        self.now
    }
    async fn sleep_until(&self, _deadline: u64) {}
}

impl System for MockHost {
    fn realtime_nanos(&self) -> u64 {
        self.now
    }
    fn set_realtime_nanos(&mut self, _: u64) -> Result<(), Denied> {
        Err(Denied)
    }
    fn cpu_nanos(&self) -> u64 {
        0
    }
    fn fill_random(&mut self, out: &mut [u8]) {
        out.fill(0);
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
        "#1 test"
    }
}

impl Tty for MockHost {
    fn is_tty(&self, _stream: TtyStream) -> bool {
        self.tty_attached
    }
    fn get_termios(&self, _stream: TtyStream) -> Result<Termios, TtyError> {
        if !self.tty_attached {
            return Err(TtyError::NotTty);
        }
        Ok(self.termios)
    }
    fn set_termios(
        &mut self,
        _stream: TtyStream,
        termios: Termios,
        _action: TermiosAction,
    ) -> Result<(), TtyError> {
        if !self.tty_attached {
            return Err(TtyError::NotTty);
        }
        if !self.tty_control {
            return Err(TtyError::Denied);
        }
        self.termios = termios;
        Ok(())
    }
    fn get_winsize(&self, _stream: TtyStream) -> Result<Winsize, TtyError> {
        if !self.tty_attached {
            return Err(TtyError::NotTty);
        }
        Ok(self.winsize)
    }
    fn set_winsize(&mut self, _stream: TtyStream, winsize: Winsize) -> Result<(), TtyError> {
        if !self.tty_attached {
            return Err(TtyError::NotTty);
        }
        if !self.tty_control {
            return Err(TtyError::Denied);
        }
        self.winsize = winsize;
        Ok(())
    }
}

impl Filesystem<MemRes> for MockHost {
    fn file_access(&self, file: &MemFile) -> FileAccess {
        file.access
    }
    fn same_file(&self, a: &MemFile, b: &MemFile) -> bool {
        a.id == b.id
    }
    async fn open(
        &mut self,
        _base: Option<&MemFile>,
        _cwd: &str,
        path: &str,
        request: OpenRequest,
    ) -> Result<MemFile, FsError> {
        let id = match path {
            "/mapped" | "mapped" => 1,
            "/sym" | "sym" => 2,
            _ => return Err(FsError::NoEntry),
        };
        let access = match (request.read, request.write) {
            (true, true) => FileAccess::ReadWrite,
            (true, false) => FileAccess::ReadOnly,
            (false, true) => FileAccess::WriteOnly,
            (false, false) => FileAccess::PathOnly,
        };
        Ok(MemFile { id, access })
    }
    async fn stat_file(&self, file: &MemFile) -> Result<FileStat, FsError> {
        let files = self.files.lock().unwrap();
        let data = files.get(&file.id).ok_or(FsError::NoEntry)?;
        Ok(FileStat {
            dev: 1,
            ino: file.id,
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
        })
    }
    async fn read_at(
        &self,
        file: &MemFile,
        offset: u64,
        max_bytes: usize,
    ) -> Result<Bytes, FsError> {
        let files = self.files.lock().unwrap();
        let data = files.get(&file.id).ok_or(FsError::NoEntry)?;
        let off = offset as usize;
        if off >= data.len() {
            return Ok(Bytes::new());
        }
        let end = (off + max_bytes).min(data.len());
        Ok(Bytes::copy_from_slice(&data[off..end]))
    }
    async fn write_at(
        &mut self,
        file: &MemFile,
        position: WritePosition,
        bytes: &[u8],
    ) -> Result<Landed, FsError> {
        let mut files = self.files.lock().unwrap();
        let data = files.get_mut(&file.id).ok_or(FsError::NoEntry)?;
        let off = match position {
            WritePosition::At(o) => o as usize,
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
    async fn sync(&self, _file: &MemFile, _data_only: bool) -> Result<(), FsError> {
        Ok(())
    }
    async fn read_link(
        &self,
        base: Option<&MemFile>,
        _cwd: &str,
        path: &str,
    ) -> Result<String, FsError> {
        if path.is_empty() {
            return match base {
                Some(file) if file.id == 2 => Ok(String::from("target-from-fd")),
                _ => Err(FsError::Invalid),
            };
        }
        match path {
            "/sym" | "sym" => Ok(String::from("target-from-path")),
            _ => Err(FsError::NoEntry),
        }
    }
}

fn run_call(
    process: &mut Process<MemRes>,
    abi: Abi,
    op: Operation,
    args: [u64; 6],
    mem: &mut PageMem,
    host: &mut MockHost,
) -> u64 {
    let mut thread = DummyThread;
    let call = Call {
        number: syscall_num(abi, op),
        arguments: args,
    };
    let mut fut = core::pin::pin!(dispatch(process, call, mem, &mut thread, host));
    match fut.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(ControlFlow::Continue(SyscallOutcome::Return(res))) => res,
        other => panic!("unexpected poll result for {op:?}: {other:?}"),
    }
}

struct WakeCount(AtomicUsize);
impl Wake for WakeCount {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

#[test]
fn stdin_supports_epoll_ctl_async_wakeup_and_nonblocking_eagain() {
    let abi = Abi::X86_64;
    let mut process = Process::<MemRes>::new(abi, NonZeroU32::new(1).unwrap(), 0x40_0000);
    let mut mem = PageMem::default();
    let mut host = MockHost::default();
    let buf = 0x10_0000;

    // Set O_NONBLOCK on stdin (fd 0) via fcntl(F_SETFL) and verify EAGAIN while empty.
    assert_eq!(
        run_call(
            &mut process,
            abi,
            Operation::Fcntl,
            [0, 4, 0x800, 0, 0, 0],
            &mut mem,
            &mut host
        ),
        0
    );
    assert_eq!(
        run_call(
            &mut process,
            abi,
            Operation::Fcntl,
            [0, 3, 0, 0, 0, 0],
            &mut mem,
            &mut host
        ),
        0x800
    );
    assert_eq!(
        run_call(
            &mut process,
            abi,
            Operation::Read,
            [0, buf, 4, 0, 0, 0],
            &mut mem,
            &mut host
        ),
        err(EAGAIN)
    );

    // epoll_ctl on stdin (fd 0) must succeed (never EPERM).
    let ep = run_call(
        &mut process,
        abi,
        Operation::EpollCreate1,
        [0, 0, 0, 0, 0, 0],
        &mut mem,
        &mut host,
    );
    mem.write(buf, &1u32.to_le_bytes()).unwrap();
    mem.write(buf + 4, &0x1234u64.to_le_bytes()).unwrap();
    assert_eq!(
        run_call(
            &mut process,
            abi,
            Operation::EpollCtl,
            [ep, 1, 0, buf, 0, 0],
            &mut mem,
            &mut host
        ),
        0
    );

    // epoll_wait suspends while stdin is quiet, then wakes as soon as input arrives.
    let stdin_buf = host.stdin.clone();
    let stdin_notify = host.stdin_notify.clone();
    let wakes = Arc::new(WakeCount(AtomicUsize::new(0)));
    let waker = Waker::from(wakes.clone());
    let mut cx = Context::from_waker(&waker);
    let mut thread = DummyThread;
    let call = Call {
        number: syscall_num(abi, Operation::EpollWait),
        arguments: [ep, buf + 64, 2, u64::MAX, 0, 0],
    };
    {
        let mut fut = core::pin::pin!(dispatch(
            &mut process,
            call,
            &mut mem,
            &mut thread,
            &mut host
        ));
        assert!(fut.as_mut().poll(&mut cx).is_pending());
        stdin_buf.lock().unwrap().extend_from_slice(b"hi");
        stdin_notify.notify_all();
        assert!(wakes.0.load(Ordering::Relaxed) > 0);
        assert_eq!(
            fut.as_mut().poll(&mut cx),
            Poll::Ready(ControlFlow::Continue(SyscallOutcome::Return(1)))
        );
    }
    let mut out = [0u8; 12];
    mem.read(buf + 64, &mut out).unwrap();
    assert_eq!(u32::from_le_bytes(out[0..4].try_into().unwrap()), 1);
    assert_eq!(u64::from_le_bytes(out[4..12].try_into().unwrap()), 0x1234);

    // Nonblocking read now succeeds with "hi" and returns EAGAIN again afterwards.
    assert_eq!(
        run_call(
            &mut process,
            abi,
            Operation::Read,
            [0, buf + 128, 8, 0, 0, 0],
            &mut mem,
            &mut host
        ),
        2
    );
    let mut read_back = [0u8; 2];
    mem.read(buf + 128, &mut read_back).unwrap();
    assert_eq!(&read_back, b"hi");
    assert_eq!(
        run_call(
            &mut process,
            abi,
            Operation::Read,
            [0, buf + 128, 8, 0, 0, 0],
            &mut mem,
            &mut host
        ),
        err(EAGAIN)
    );
}

#[test]
fn tty_ioctls_enforce_tty_status_control_authority_and_faults() {
    let abi = Abi::X86_64;
    let mut process = Process::<MemRes>::new(abi, NonZeroU32::new(1).unwrap(), 0x40_0000);
    let mut mem = PageMem::default();
    let mut host = MockHost::default();
    let buf = 0x10_0000;

    // TCGETS + TCSETS + TIOCGWINSZ + TIOCSWINSZ succeed on attached TTY.
    assert_eq!(
        run_call(
            &mut process,
            abi,
            Operation::Ioctl,
            [1, 0x5401, buf, 0, 0, 0],
            &mut mem,
            &mut host
        ),
        0
    );
    let mut tio = [0u8; 36];
    mem.read(buf, &mut tio).unwrap();
    tio[12..16].copy_from_slice(&0u32.to_le_bytes()); // clear c_lflag
    mem.write(buf, &tio).unwrap();
    assert_eq!(
        run_call(
            &mut process,
            abi,
            Operation::Ioctl,
            [1, 0x5402, buf, 0, 0, 0],
            &mut mem,
            &mut host
        ),
        0
    );
    assert_eq!(host.termios.lflag, 0);

    // Without CONTROL right, TCSETS / TIOCSWINSZ return EPERM.
    host.tty_control = false;
    assert_eq!(
        run_call(
            &mut process,
            abi,
            Operation::Ioctl,
            [1, 0x5402, buf, 0, 0, 0],
            &mut mem,
            &mut host
        ),
        err(EPERM)
    );
    assert_eq!(
        run_call(
            &mut process,
            abi,
            Operation::Ioctl,
            [1, 0x5414, buf, 0, 0, 0],
            &mut mem,
            &mut host
        ),
        err(EPERM)
    );

    // Bad pointer -> EFAULT; closed fd -> EBADF; detached TTY -> ENOTTY.
    assert_eq!(
        run_call(
            &mut process,
            abi,
            Operation::Ioctl,
            [1, 0x5401, 1, 0, 0, 0],
            &mut mem,
            &mut host
        ),
        err(EFAULT)
    );
    assert_eq!(
        run_call(
            &mut process,
            abi,
            Operation::Ioctl,
            [99, 0x5401, buf, 0, 0, 0],
            &mut mem,
            &mut host
        ),
        err(EBADF)
    );
    host.tty_attached = false;
    assert_eq!(
        run_call(
            &mut process,
            abi,
            Operation::Ioctl,
            [1, 0x5401, buf, 0, 0, 0],
            &mut mem,
            &mut host
        ),
        err(ENOTTY)
    );
}

#[test]
fn file_backed_shared_and_private_mmap_and_msync_round_trip() {
    let abi = Abi::X86_64;
    let mut process = Process::<MemRes>::new(abi, NonZeroU32::new(1).unwrap(), 0x40_0000);
    let mut mem = PageMem::default();
    let mut host = MockHost::default();
    host.files
        .lock()
        .unwrap()
        .insert(1, b"hello shared map".to_vec());

    let buf = 0x10_0000;
    mem.write(buf, b"/mapped\0").unwrap();
    let fd = run_call(
        &mut process,
        abi,
        Operation::Openat,
        [(-100i32) as u32 as u64, buf, 2 /* O_RDWR */, 0, 0, 0],
        &mut mem,
        &mut host,
    );
    assert!(fd >= 3);

    // MAP_SHARED | PROT_READ | PROT_WRITE
    let shared_addr = run_call(
        &mut process,
        abi,
        Operation::Mmap,
        [0, PAGE, 3, 0x01 /* MAP_SHARED */, fd, 0],
        &mut mem,
        &mut host,
    );
    assert!(shared_addr >= PAGE);
    let mut seen = [0u8; 16];
    mem.read(shared_addr, &mut seen).unwrap();
    assert_eq!(&seen, b"hello shared map");

    // Mutate mapping and msync(MS_SYNC) -> persisted in backing file.
    mem.write(shared_addr, b"HELLO").unwrap();
    assert_eq!(
        run_call(
            &mut process,
            abi,
            Operation::Msync,
            [shared_addr, PAGE, 4, 0, 0, 0],
            &mut mem,
            &mut host
        ),
        0
    );
    assert_eq!(&host.files.lock().unwrap()[&1], b"HELLO shared map");

    // Write via pwrite64 propagates into active MAP_SHARED mapping.
    mem.write(buf + 64, b"DIRECT").unwrap();
    assert_eq!(
        run_call(
            &mut process,
            abi,
            Operation::Pwrite64,
            [fd, buf + 64, 6, 6, 0, 0],
            &mut mem,
            &mut host
        ),
        6
    );
    mem.read(shared_addr, &mut seen).unwrap();
    assert_eq!(&seen, b"HELLO DIRECT map");

    // Unmap flushes latest bytes.
    mem.write(shared_addr + 13, b"MAP").unwrap();
    assert_eq!(
        run_call(
            &mut process,
            abi,
            Operation::Munmap,
            [shared_addr, PAGE, 0, 0, 0, 0],
            &mut mem,
            &mut host
        ),
        0
    );
    assert_eq!(&host.files.lock().unwrap()[&1], b"HELLO DIRECT MAP");

    // Read-only fd refuses MAP_SHARED|PROT_WRITE and mprotect(PROT_WRITE) with EACCES.
    let ro_fd = run_call(
        &mut process,
        abi,
        Operation::Openat,
        [(-100i32) as u32 as u64, buf, 0 /* O_RDONLY */, 0, 0, 0],
        &mut mem,
        &mut host,
    );
    assert_eq!(
        run_call(
            &mut process,
            abi,
            Operation::Mmap,
            [0, PAGE, 3, 0x01, ro_fd, 0],
            &mut mem,
            &mut host
        ),
        err(EACCES)
    );
    let ro_map = run_call(
        &mut process,
        abi,
        Operation::Mmap,
        [0, PAGE, 1 /* PROT_READ */, 0x01, ro_fd, 0],
        &mut mem,
        &mut host,
    );
    assert!(ro_map >= PAGE);
    assert_eq!(
        run_call(
            &mut process,
            abi,
            Operation::Mprotect,
            [ro_map, PAGE, 3, 0, 0, 0],
            &mut mem,
            &mut host
        ),
        err(EACCES)
    );
    assert_eq!(
        run_call(
            &mut process,
            abi,
            Operation::Msync,
            [ro_map + 1, PAGE, 4, 0, 0, 0],
            &mut mem,
            &mut host
        ),
        err(EINVAL)
    );
}

#[test]
fn poll_and_select_cover_pipes_invalid_fds_and_timeout_writeback() {
    let abi = Abi::X86_64;
    let mut process = Process::<MemRes>::new(abi, NonZeroU32::new(1).unwrap(), 0x40_0000);
    let mut mem = PageMem::default();
    let mut host = MockHost::default();
    let buf = 0x10_0000;

    assert_eq!(
        run_call(
            &mut process,
            abi,
            Operation::Pipe2,
            [buf, 0, 0, 0, 0, 0],
            &mut mem,
            &mut host
        ),
        0
    );
    let mut raw = [0u8; 8];
    mem.read(buf, &mut raw).unwrap();
    let rfd = i32::from_le_bytes(raw[0..4].try_into().unwrap());
    let wfd = i32::from_le_bytes(raw[4..8].try_into().unwrap());

    // pollfd[0] = rfd (POLLIN), pollfd[1] = wfd (POLLOUT), pollfd[2] = closed 99 (POLLNVAL)
    let pfds_addr = buf + 64;
    let entries: [(i32, u16); 3] = [(rfd, 1), (wfd, 4), (99, 1)];
    for (i, (fd, ev)) in entries.iter().enumerate() {
        let a = pfds_addr + (i as u64) * 8;
        mem.write(a, &fd.to_le_bytes()).unwrap();
        mem.write(a + 4, &ev.to_le_bytes()).unwrap();
        mem.write(a + 6, &0u16.to_le_bytes()).unwrap();
    }
    assert_eq!(
        run_call(
            &mut process,
            abi,
            Operation::Poll,
            [pfds_addr, 3, 0, 0, 0, 0],
            &mut mem,
            &mut host
        ),
        2
    );
    let mut rev = [0u8; 2];
    mem.read(pfds_addr + 6, &mut rev).unwrap();
    assert_eq!(u16::from_le_bytes(rev), 0);
    mem.read(pfds_addr + 14, &mut rev).unwrap();
    assert_eq!(u16::from_le_bytes(rev), 4);
    mem.read(pfds_addr + 22, &mut rev).unwrap();
    assert_eq!(u16::from_le_bytes(rev), 0x20 /* POLLNVAL */);

    // select with closed fd returns EBADF.
    let set_addr = buf + 256;
    mem.write(set_addr, &(1u64 << 20).to_le_bytes()).unwrap();
    assert_eq!(
        run_call(
            &mut process,
            abi,
            Operation::Select,
            [21, set_addr, 0, 0, 0, 0],
            &mut mem,
            &mut host
        ),
        err(EBADF)
    );
}

#[test]
fn fcntl_dupfd_and_status_flags_match_both_abis() {
    for abi in [Abi::X86_64, Abi::Aarch64] {
        let mut process = Process::<MemRes>::new(abi, NonZeroU32::new(1).unwrap(), 0x40_0000);
        let mut mem = PageMem::default();
        let mut host = MockHost::default();
        let buf = 0x10_0000;
        let _ = OpenFile::new(MemFile {
            id: 1,
            access: FileAccess::ReadWrite,
        });

        assert_eq!(
            run_call(
                &mut process,
                abi,
                Operation::Pipe2,
                [buf, 0, 0, 0, 0, 0],
                &mut mem,
                &mut host
            ),
            0
        );
        let mut raw = [0u8; 8];
        mem.read(buf, &mut raw).unwrap();
        let rfd = u32::from_le_bytes(raw[0..4].try_into().unwrap()) as u64;

        let d1 = run_call(
            &mut process,
            abi,
            Operation::Fcntl,
            [rfd, 0 /* F_DUPFD */, 10, 0, 0, 0],
            &mut mem,
            &mut host,
        );
        assert_eq!(d1, 10);
        assert_eq!(
            run_call(
                &mut process,
                abi,
                Operation::Fcntl,
                [d1, 1 /* F_GETFD */, 0, 0, 0, 0],
                &mut mem,
                &mut host
            ),
            0
        );
        let d2 = run_call(
            &mut process,
            abi,
            Operation::Fcntl,
            [rfd, 1030 /* F_DUPFD_CLOEXEC */, 10, 0, 0, 0],
            &mut mem,
            &mut host,
        );
        assert_eq!(d2, 11);
        assert_eq!(
            run_call(
                &mut process,
                abi,
                Operation::Fcntl,
                [d2, 1 /* F_GETFD */, 0, 0, 0, 0],
                &mut mem,
                &mut host
            ),
            1
        );
        // Setting O_NONBLOCK | O_APPEND on d1 is visible via F_GETFL on rfd.
        assert_eq!(
            run_call(
                &mut process,
                abi,
                Operation::Fcntl,
                [d1, 4, 0x400 | 0x800, 0, 0, 0],
                &mut mem,
                &mut host
            ),
            0
        );
        assert_eq!(
            run_call(
                &mut process,
                abi,
                Operation::Fcntl,
                [rfd, 3, 0, 0, 0, 0],
                &mut mem,
                &mut host
            ),
            0x400 | 0x800
        );
    }
}

#[test]
fn mremap_growth_populates_shared_tail_and_preserves_backing_file() {
    let abi = Abi::X86_64;
    let mut process = Process::<MemRes>::new(abi, NonZeroU32::new(1).unwrap(), 0x40_0000);
    let mut mem = PageMem::default();
    let mut host = MockHost::default();
    let mut data = vec![b'A'; PAGE as usize];
    data.extend(core::iter::repeat_n(b'B', PAGE as usize));
    host.files.lock().unwrap().insert(1, data);

    let buf = 0x10_0000;
    mem.write(buf, b"/mapped\0").unwrap();
    let fd = run_call(
        &mut process,
        abi,
        Operation::Openat,
        [(-100i32) as u32 as u64, buf, 2 /* O_RDWR */, 0, 0, 0],
        &mut mem,
        &mut host,
    );
    assert!(fd >= 3);

    // 1. In-place growth of writable MAP_SHARED populates page 2 from file and
    // preserves page 2 across msync + munmap.
    let m1 = run_call(
        &mut process,
        abi,
        Operation::Mmap,
        [
            0, PAGE, 3,    /* PROT_READ|PROT_WRITE */
            0x01, /* MAP_SHARED */
            fd, 0,
        ],
        &mut mem,
        &mut host,
    );
    assert!(m1 >= PAGE);
    let grown = run_call(
        &mut process,
        abi,
        Operation::Mremap,
        [m1, PAGE, 2 * PAGE, 0, 0, 0],
        &mut mem,
        &mut host,
    );
    assert_eq!(grown, m1);
    let mut page1 = [0u8; 4];
    let mut page2 = [0u8; 4];
    mem.read(grown, &mut page1).unwrap();
    mem.read(grown + PAGE, &mut page2).unwrap();
    assert_eq!(&page1, b"AAAA");
    assert_eq!(&page2, b"BBBB");

    mem.write(grown, b"CCCC").unwrap();
    assert_eq!(
        run_call(
            &mut process,
            abi,
            Operation::Msync,
            [grown, 2 * PAGE, 4 /* MS_SYNC */, 0, 0, 0],
            &mut mem,
            &mut host
        ),
        0
    );
    assert_eq!(
        run_call(
            &mut process,
            abi,
            Operation::Munmap,
            [grown, 2 * PAGE, 0, 0, 0, 0],
            &mut mem,
            &mut host
        ),
        0
    );
    {
        let files = host.files.lock().unwrap();
        let file_bytes = &files[&1];
        assert_eq!(&file_bytes[..4], b"CCCC");
        assert_eq!(&file_bytes[PAGE as usize..PAGE as usize + 4], b"BBBB");
    }

    // 2. Relocated growth (MREMAP_MAYMOVE) of PROT_READ MAP_SHARED populates
    // page 2 from file and keeps page 2 read-only.
    let m2 = run_call(
        &mut process,
        abi,
        Operation::Mmap,
        [
            0, PAGE, 1,    /* PROT_READ */
            0x01, /* MAP_SHARED */
            fd, 0,
        ],
        &mut mem,
        &mut host,
    );
    assert!(m2 >= PAGE);
    // Occupy m2 + PAGE so mremap must relocate.
    mem.map_at(m2 + PAGE, PAGE, PageFlags::READ).unwrap();
    let moved = run_call(
        &mut process,
        abi,
        Operation::Mremap,
        [m2, PAGE, 2 * PAGE, 1 /* MREMAP_MAYMOVE */, 0, 0],
        &mut mem,
        &mut host,
    );
    assert_ne!(moved, m2);
    assert!(moved >= PAGE);
    mem.read(moved, &mut page1).unwrap();
    mem.read(moved + PAGE, &mut page2).unwrap();
    assert_eq!(&page1, b"CCCC");
    assert_eq!(&page2, b"BBBB");
    assert!(mem.check_writable(moved + PAGE, 1).is_err());
}

#[test]
fn shared_mapping_syncs_write_into_readonly_pages_and_partial_mprotect_flushes() {
    let abi = Abi::X86_64;
    let mut process = Process::<MemRes>::new(abi, NonZeroU32::new(1).unwrap(), 0x40_0000);
    let mut mem = PageMem::default();
    let mut host = MockHost::default();
    host.files
        .lock()
        .unwrap()
        .insert(1, b"initial-data".to_vec());

    let buf = 0x10_0000;
    mem.write(buf, b"/mapped\0").unwrap();
    let fd = run_call(
        &mut process,
        abi,
        Operation::Openat,
        [(-100i32) as u32 as u64, buf, 2 /* O_RDWR */, 0, 0, 0],
        &mut mem,
        &mut host,
    );
    assert!(fd >= 3);

    // Map PROT_READ | MAP_SHARED from an O_RDWR fd.
    let addr = run_call(
        &mut process,
        abi,
        Operation::Mmap,
        [
            0, PAGE, 1,    /* PROT_READ */
            0x01, /* MAP_SHARED */
            fd, 0,
        ],
        &mut mem,
        &mut host,
    );
    assert!(addr >= PAGE);
    assert!(mem.check_writable(addr, 1).is_err());

    // pwrite64 into the file updates the read-only MAP_SHARED page while keeping
    // the page read-only.
    mem.write(buf + 64, b"UPDATED").unwrap();
    assert_eq!(
        run_call(
            &mut process,
            abi,
            Operation::Pwrite64,
            [fd, buf + 64, 7, 0, 0, 0],
            &mut mem,
            &mut host
        ),
        7
    );
    let mut seen = [0u8; 12];
    mem.read(addr, &mut seen).unwrap();
    assert_eq!(&seen, b"UPDATED-data");
    assert!(mem.check_writable(addr, 1).is_err());

    // Partial mprotect across [addr, addr + 2*PAGE) (second page is a hole)
    // returns ENOMEM, leaves page 0 writable, and marks the mapping writable so
    // msync / munmap flush mutations back to the file.
    assert_eq!(
        run_call(
            &mut process,
            abi,
            Operation::Mprotect,
            [addr, 2 * PAGE, 3 /* PROT_READ|PROT_WRITE */, 0, 0, 0],
            &mut mem,
            &mut host
        ),
        err(ENOMEM)
    );
    mem.write(addr, b"PARTIAL").unwrap();
    assert_eq!(
        run_call(
            &mut process,
            abi,
            Operation::Msync,
            [addr, PAGE, 4 /* MS_SYNC */, 0, 0, 0],
            &mut mem,
            &mut host
        ),
        0
    );
    assert_eq!(&host.files.lock().unwrap()[&1], b"PARTIAL-data");
}

#[test]
fn readlinkat_empty_path_rejects_at_fdcwd_and_resolves_open_fd() {
    let abi = Abi::X86_64;
    let mut process = Process::<MemRes>::new(abi, NonZeroU32::new(1).unwrap(), 0x40_0000);
    let mut mem = PageMem::default();
    let mut host = MockHost::default();
    let buf = 0x10_0000;

    // Empty path relative to AT_FDCWD must fail with ENOENT.
    mem.write(buf, b"\0").unwrap();
    assert_eq!(
        run_call(
            &mut process,
            abi,
            Operation::Readlinkat,
            [(-100i32) as u32 as u64, buf, buf + 64, 64, 0, 0],
            &mut mem,
            &mut host
        ),
        err(ENOENT)
    );

    // Open /sym with O_PATH | O_NOFOLLOW and readlinkat(sym_fd, "", ...).
    mem.write(buf + 16, b"/sym\0").unwrap();
    let sym_fd = run_call(
        &mut process,
        abi,
        Operation::Openat,
        [
            (-100i32) as u32 as u64,
            buf + 16,
            0x20_0000 | 0x2_0000, /* O_PATH | O_NOFOLLOW (x86_64) */
            0,
            0,
            0,
        ],
        &mut mem,
        &mut host,
    );
    assert!(sym_fd >= 3);
    let n = run_call(
        &mut process,
        abi,
        Operation::Readlinkat,
        [sym_fd, buf, buf + 64, 64, 0, 0],
        &mut mem,
        &mut host,
    );
    assert_eq!(n, b"target-from-fd".len() as u64);
    let mut out = [0u8; 14];
    mem.read(buf + 64, &mut out).unwrap();
    assert_eq!(&out, b"target-from-fd");
}

#[test]
fn tcsetsf_does_not_flush_stdin_when_denied_and_flushes_when_allowed() {
    let abi = Abi::X86_64;
    let mut process = Process::<MemRes>::new(abi, NonZeroU32::new(1).unwrap(), 0x40_0000);
    let mut mem = PageMem::default();
    let mut host = MockHost {
        stdin_return_whole_chunk: true,
        ..Default::default()
    };
    host.stdin.lock().unwrap().extend_from_slice(b"abcdef");
    let buf = 0x10_0000;

    // Seed stdin_carry with "cdef" by reading 2 bytes from a 6-byte chunk.
    assert_eq!(
        run_call(
            &mut process,
            abi,
            Operation::Read,
            [0, buf, 2, 0, 0, 0],
            &mut mem,
            &mut host
        ),
        2
    );
    let mut got = [0u8; 2];
    mem.read(buf, &mut got).unwrap();
    assert_eq!(&got, b"ab");

    // Fetch current termios into buf + 64.
    assert_eq!(
        run_call(
            &mut process,
            abi,
            Operation::Ioctl,
            [0, 0x5401 /* TCGETS */, buf + 64, 0, 0, 0],
            &mut mem,
            &mut host
        ),
        0
    );

    // Without TTY control authority, TCSETSF fails with EPERM and must NOT
    // discard unread stdin_carry bytes.
    host.tty_control = false;
    assert_eq!(
        run_call(
            &mut process,
            abi,
            Operation::Ioctl,
            [0, 0x5404 /* TCSETSF */, buf + 64, 0, 0, 0],
            &mut mem,
            &mut host
        ),
        err(EPERM)
    );
    assert_eq!(
        run_call(
            &mut process,
            abi,
            Operation::Read,
            [0, buf, 2, 0, 0, 0],
            &mut mem,
            &mut host
        ),
        2
    );
    mem.read(buf, &mut got).unwrap();
    assert_eq!(&got, b"cd");

    // With TTY control authority, TCSETSF succeeds and flushes the remaining
    // "ef" in stdin_carry so a nonblocking read returns EAGAIN.
    host.tty_control = true;
    assert_eq!(
        run_call(
            &mut process,
            abi,
            Operation::Ioctl,
            [0, 0x5404 /* TCSETSF */, buf + 64, 0, 0, 0],
            &mut mem,
            &mut host
        ),
        0
    );
    assert_eq!(
        run_call(
            &mut process,
            abi,
            Operation::Fcntl,
            [
                0, 4,     /* F_SETFL */
                0x800, /* O_NONBLOCK */
                0, 0, 0
            ],
            &mut mem,
            &mut host
        ),
        0
    );
    assert_eq!(
        run_call(
            &mut process,
            abi,
            Operation::Read,
            [0, buf, 4, 0, 0, 0],
            &mut mem,
            &mut host
        ),
        err(EAGAIN)
    );
}
