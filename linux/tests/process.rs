#![cfg(feature = "runtime")]
//! Linux process lifecycle tests: `fork`, `vfork`, `clone`/`clone3` without
//! `CLONE_THREAD`, `execve`/`execveat`, `wait4`/`waitid` (`WNOHANG`,
//! `WUNTRACED`, `WCONTINUED`, `WNOWAIT`, `SIGCHLD`, auto-reap, reparenting),
//! `getppid`, `getpgid`/`getpgrp`/`setpgid`, `getsid`/`setsid`, on both
//! x86-64 and AArch64.

use core::future::Future;
use core::ops::ControlFlow;
use core::task::{Context, Poll, Waker};
use std::sync::{Arc, Mutex};

use helios_hal::vmm::PageFlags;
use helios_linux::abi::{Abi, Operation};
use helios_linux::signal_frame::{
    CLD_CONTINUED, CLD_EXITED, CLD_KILLED, CLD_STOPPED, SA_NOCLDWAIT,
};
use helios_linux::syscall::{
    AT_EMPTY_PATH, AT_SYMLINK_NOFOLLOW, Call, Clock, Denied, ExecError, ExecSpec, MapError,
    MemoryFault, MemoryTotals, NoBacking, PidNamespace, Process, Region, SpawnError,
    SpawnedProcess, SpawnedThread, Start, Stdio, Stream, SyscallOutcome, System, Thread,
    UserMemory, VirtualMemory, WriteError, dispatch, standard_streams,
};
use helios_unix::{ChildTermination, Signal, SignalTermination};

const ABIS: [Abi; 2] = [Abi::X86_64, Abi::Aarch64];
const PROGRAM_BREAK: u64 = 0x40_0000;

const EPERM: u64 = 1;
const ENOENT: u64 = 2;
const ESRCH: u64 = 3;
const ECHILD: u64 = 10;
const EACCES: u64 = 13;
const EFAULT: u64 = 14;
const EINVAL: u64 = 22;

const WNOHANG: u64 = 1;
const WUNTRACED: u64 = 2;
const WSTOPPED: u64 = 2;
const WEXITED: u64 = 4;
const WCONTINUED: u64 = 8;
const WNOWAIT: u64 = 0x0100_0000;

const P_ALL: u64 = 0;
const P_PID: u64 = 1;
const P_PGID: u64 = 2;

const CLONE_VM: u64 = 0x0100;
const CLONE_VFORK: u64 = 0x4000;
const CLONE_CHILD_SETTID: u64 = 0x0100_0000;
const CLONE_CLEAR_SIGHAND: u64 = 1 << 32;

const O_CLOEXEC: u64 = 0x8_0000;

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

#[derive(Clone)]
struct Mem {
    base: u64,
    bytes: Arc<Mutex<Vec<u8>>>,
}

impl Mem {
    fn new(base: u64, size: usize) -> Self {
        Self {
            base,
            bytes: Arc::new(Mutex::new(vec![0; size])),
        }
    }

    fn range(&self, addr: u64, len: usize) -> Result<core::ops::Range<usize>, MemoryFault> {
        let off = addr.checked_sub(self.base).ok_or(MemoryFault)? as usize;
        let end = off.checked_add(len).ok_or(MemoryFault)?;
        let guard = self.bytes.lock().unwrap();
        if end <= guard.len() {
            Ok(off..end)
        } else {
            Err(MemoryFault)
        }
    }

    fn write_bytes(&self, addr: u64, data: &[u8]) {
        let r = self.range(addr, data.len()).unwrap();
        self.bytes.lock().unwrap()[r].copy_from_slice(data);
    }

    fn write_cstr(&self, addr: u64, s: &str) {
        self.write_bytes(addr, s.as_bytes());
        self.write_bytes(addr + s.len() as u64, &[0]);
    }

    fn write_u64(&self, addr: u64, val: u64) {
        self.write_bytes(addr, &val.to_le_bytes());
    }

    fn read_bytes(&self, addr: u64, len: usize) -> Vec<u8> {
        let r = self.range(addr, len).unwrap();
        self.bytes.lock().unwrap()[r].to_vec()
    }

    fn read_i32(&self, addr: u64) -> i32 {
        i32::from_le_bytes(self.read_bytes(addr, 4).try_into().unwrap())
    }

    fn read_u32(&self, addr: u64) -> u32 {
        u32::from_le_bytes(self.read_bytes(addr, 4).try_into().unwrap())
    }

    fn read_u64(&self, addr: u64) -> u64 {
        u64::from_le_bytes(self.read_bytes(addr, 8).try_into().unwrap())
    }
}

impl UserMemory for Mem {
    fn read(&self, addr: u64, out: &mut [u8]) -> Result<(), MemoryFault> {
        let r = self.range(addr, out.len())?;
        out.copy_from_slice(&self.bytes.lock().unwrap()[r]);
        Ok(())
    }

    fn check_writable(&self, addr: u64, len: usize) -> Result<(), MemoryFault> {
        let _ = self.range(addr, len)?;
        Ok(())
    }

    fn write(&mut self, addr: u64, data: &[u8]) -> Result<(), MemoryFault> {
        let r = self.range(addr, data.len())?;
        self.bytes.lock().unwrap()[r].copy_from_slice(data);
        Ok(())
    }

    fn atomic_load_u32(&self, addr: u64) -> Result<u32, MemoryFault> {
        let mut buf = [0u8; 4];
        self.read(addr, &mut buf)?;
        Ok(u32::from_le_bytes(buf))
    }

    fn atomic_store_u32(&mut self, addr: u64, value: u32) -> Result<(), MemoryFault> {
        self.write(addr, &value.to_le_bytes())
    }

    fn atomic_compare_exchange_u32(
        &mut self,
        addr: u64,
        expected: u32,
        desired: u32,
    ) -> Result<Result<u32, u32>, MemoryFault> {
        let cur = self.atomic_load_u32(addr)?;
        if cur == expected {
            self.atomic_store_u32(addr, desired)?;
            Ok(Ok(cur))
        } else {
            Ok(Err(cur))
        }
    }
}

impl VirtualMemory for Mem {
    fn lowest_address(&self) -> u64 {
        0x1000
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

struct MockHost {
    spawned: Arc<Mutex<Vec<SpawnedProcess<NoBacking>>>>,
    last_exec: Option<ExecSpec>,
    exec_result: Result<(), ExecError>,
}

impl MockHost {
    fn new() -> Self {
        Self {
            spawned: Arc::new(Mutex::new(Vec::new())),
            last_exec: None,
            exec_result: Ok(()),
        }
    }

    fn pop_spawned(&self) -> SpawnedProcess<NoBacking> {
        self.spawned.lock().unwrap().pop().unwrap()
    }
}

impl Thread<NoBacking> for MockHost {
    fn thread_pointer(&self) -> u64 {
        0
    }
    fn set_thread_pointer(&mut self, _: u64) -> Result<(), Denied> {
        Ok(())
    }
    fn spawn_thread(&mut self, _: Process<NoBacking>, _: SpawnedThread) -> Result<(), SpawnError> {
        Err(SpawnError::Busy)
    }
    fn spawn_process(&mut self, process: SpawnedProcess<NoBacking>) -> Result<(), SpawnError> {
        self.spawned.lock().unwrap().push(process);
        Ok(())
    }
    async fn prepare_exec(&mut self, spec: ExecSpec) -> Result<(), ExecError> {
        self.last_exec = Some(spec);
        self.exec_result
    }
}

struct MockPlatform;
impl helios_linux::syscall::Filesystem<NoBacking> for MockPlatform {}
impl helios_linux::syscall::Tty for MockPlatform {}
impl helios_linux::syscall::Network<helios_unix::NoNetwork> for MockPlatform {
    fn to_ip(&self, address: core::convert::Infallible) -> helios_linux::syscall::IpAddr {
        match address {}
    }
    fn encode_ip(&self, _: helios_linux::syscall::IpAddr) -> core::convert::Infallible {
        unreachable!()
    }
}
impl Stdio for MockPlatform {
    async fn write(&mut self, _: Stream, bytes: &[u8]) -> Result<usize, WriteError> {
        Ok(bytes.len())
    }
    async fn read_input(&mut self, _: usize) -> Result<bytes::Bytes, Denied> {
        Ok(bytes::Bytes::new())
    }
}
impl Clock for MockPlatform {
    fn now_nanos(&self) -> u64 {
        0
    }
    async fn sleep_until(&self, _: u64) {}
}
impl System for MockPlatform {
    fn realtime_nanos(&self) -> u64 {
        0
    }
    fn set_realtime_nanos(&mut self, _: u64) -> Result<(), Denied> {
        Err(Denied)
    }
    fn cpu_nanos(&self) -> u64 {
        0
    }
    fn fill_random(&mut self, _: &mut [u8]) {}
    fn memory(&self) -> MemoryTotals {
        MemoryTotals {
            total_bytes: 0,
            free_bytes: 0,
        }
    }
    fn process_count(&self) -> u32 {
        1
    }
    fn kernel_version(&self) -> &str {
        "test"
    }
}

fn call_now(
    process: &mut Process<NoBacking>,
    abi: Abi,
    op: Operation,
    arguments: [u64; 6],
    memory: &mut Mem,
    host: &mut MockHost,
) -> SyscallOutcome {
    let mut platform = MockPlatform;
    let mut fut = core::pin::pin!(dispatch(
        process,
        Call {
            number: number(abi, op),
            arguments,
        },
        memory,
        host,
        &mut platform,
    ));
    match fut.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(ControlFlow::Continue(outcome)) => outcome,
        other => panic!("unexpected dispatch result for {op:?}: {other:?}"),
    }
}

fn call_ret(
    process: &mut Process<NoBacking>,
    abi: Abi,
    op: Operation,
    arguments: [u64; 6],
    memory: &mut Mem,
    host: &mut MockHost,
) -> u64 {
    match call_now(process, abi, op, arguments, memory, host) {
        SyscallOutcome::Return(val) => val,
        other => panic!("expected Return for {op:?}, got {other:?}"),
    }
}

fn make_root(abi: Abi, pids: &PidNamespace) -> Process<NoBacking> {
    let pid = pids.allocate_process().unwrap();
    Process::with_descriptors(
        abi,
        pid,
        PROGRAM_BREAK,
        standard_streams::<NoBacking>(),
        Start {
            pids: Some(pids.clone()),
            ..Start::default()
        },
    )
}

#[test]
fn fork_clone_wait4_waitid_sigchld_and_stop_continue_both_abis() {
    for abi in ABIS {
        let pids = PidNamespace::new();
        let mut parent = make_root(abi, &pids);
        let mut mem = Mem::new(0x1_0000, 0x1_0000);
        let mut host = MockHost::new();

        assert_eq!(
            call_ret(
                &mut parent,
                abi,
                Operation::Getppid,
                [0; 6],
                &mut mem,
                &mut host
            ),
            0
        );
        // No children -> ECHILD.
        assert_eq!(
            call_ret(
                &mut parent,
                abi,
                Operation::Wait4,
                [(-1i32) as u32 as u64, 0, WNOHANG, 0, 0, 0],
                &mut mem,
                &mut host,
            ),
            err(ECHILD)
        );

        // Fork via `clone(SIGCHLD, 0, ...)` (works on both x86-64 and AArch64).
        let child_pid = call_ret(
            &mut parent,
            abi,
            Operation::Clone,
            [u64::from(Signal::SIGCHLD.raw()), 0, 0, 0, 0, 0],
            &mut mem,
            &mut host,
        );
        assert_eq!(child_pid, 2);
        assert_eq!(host.spawned.lock().unwrap().len(), 1);
        let spawned = host.pop_spawned();
        assert!(!spawned.share_vm);
        let mut child = spawned.child;

        assert_eq!(
            call_ret(
                &mut child,
                abi,
                Operation::Getppid,
                [0; 6],
                &mut mem,
                &mut host
            ),
            1
        );

        // Running child -> WNOHANG returns 0.
        assert_eq!(
            call_ret(
                &mut parent,
                abi,
                Operation::Wait4,
                [child_pid, 0x1_0100, WNOHANG, 0, 0, 0],
                &mut mem,
                &mut host,
            ),
            0
        );

        // Stop child with SIGSTOP -> WUNTRACED reports ((SIGSTOP << 8) | 0x7f) once.
        child.mark_stopped(Signal::SIGSTOP);
        assert_eq!(
            call_ret(
                &mut parent,
                abi,
                Operation::Wait4,
                [child_pid, 0x1_0100, WNOHANG | WUNTRACED, 0, 0, 0],
                &mut mem,
                &mut host,
            ),
            child_pid
        );
        assert_eq!(
            mem.read_i32(0x1_0100),
            ((i32::from(Signal::SIGSTOP.raw())) << 8) | 0x7f
        );
        // Already reported -> WNOHANG returns 0.
        assert_eq!(
            call_ret(
                &mut parent,
                abi,
                Operation::Wait4,
                [child_pid, 0x1_0100, WNOHANG | WUNTRACED, 0, 0, 0],
                &mut mem,
                &mut host,
            ),
            0
        );

        // Continue child -> waitid(WCONTINUED | WNOWAIT) peeks CLD_CONTINUED,
        // then wait4(WCONTINUED) consumes 0xffff.
        pids.mark_continued(child.pid());
        assert_eq!(
            call_ret(
                &mut parent,
                abi,
                Operation::Waitid,
                [
                    P_PID,
                    child_pid,
                    0x1_0200,
                    WCONTINUED | WNOWAIT | WNOHANG,
                    0,
                    0
                ],
                &mut mem,
                &mut host,
            ),
            0
        );
        assert_eq!(mem.read_i32(0x1_0200), i32::from(Signal::SIGCHLD.raw()));
        assert_eq!(mem.read_i32(0x1_0208), CLD_CONTINUED);
        assert_eq!(mem.read_u32(0x1_0210), 2);
        assert_eq!(
            call_ret(
                &mut parent,
                abi,
                Operation::Wait4,
                [child_pid, 0x1_0100, WNOHANG | WCONTINUED, 0, 0, 0],
                &mut mem,
                &mut host,
            ),
            child_pid
        );
        assert_eq!(mem.read_i32(0x1_0100), 0xffff);

        // Child exits with code 42 -> SIGCHLD queued on parent, waitid(WNOWAIT)
        // peeks CLD_EXITED, wait4 reaps (42 << 8) and releases PID.
        child.mark_exited(ChildTermination::Exited(42));
        assert!(pids.contains(2));
        assert_eq!(
            call_ret(
                &mut parent,
                abi,
                Operation::Waitid,
                [P_ALL, 0, 0x1_0300, WEXITED | WNOWAIT, 0, 0],
                &mut mem,
                &mut host,
            ),
            0
        );
        assert_eq!(mem.read_i32(0x1_0308), CLD_EXITED);
        assert_eq!(mem.read_i32(0x1_0318), 42);
        // EFAULT on bad wstatus must NOT reap the zombie!
        assert_eq!(
            call_ret(
                &mut parent,
                abi,
                Operation::Wait4,
                [child_pid, 0xDEAD_0000, WNOHANG, 0, 0, 0],
                &mut mem,
                &mut host,
            ),
            err(EFAULT)
        );
        assert_eq!(
            call_ret(
                &mut parent,
                abi,
                Operation::Wait4,
                [child_pid, 0x1_0100, 0, 0x1_0400, 0, 0],
                &mut mem,
                &mut host,
            ),
            child_pid
        );
        assert_eq!(mem.read_i32(0x1_0100), 42 << 8);
        assert!(!pids.contains(2));

        // Signal-terminated child encodes signal + core_dumped bit.
        let child2_pid = call_ret(
            &mut parent,
            abi,
            Operation::Clone,
            [u64::from(Signal::SIGCHLD.raw()), 0, 0, 0, 0, 0],
            &mut mem,
            &mut host,
        );
        let child2 = host.pop_spawned().child;
        child2.mark_exited(ChildTermination::Signaled(SignalTermination {
            signal: Signal::SIGSEGV.raw(),
            core_dumped: true,
        }));
        assert_eq!(
            call_ret(
                &mut parent,
                abi,
                Operation::Waitid,
                [P_PID, child2_pid, 0x1_0300, WEXITED | WNOWAIT, 0, 0],
                &mut mem,
                &mut host,
            ),
            0
        );
        assert_eq!(mem.read_i32(0x1_0308), 3); // CLD_DUMPED
        assert_eq!(
            call_ret(
                &mut parent,
                abi,
                Operation::Wait4,
                [child2_pid, 0x1_0100, 0, 0, 0, 0],
                &mut mem,
                &mut host,
            ),
            child2_pid
        );
        assert_eq!(
            mem.read_i32(0x1_0100),
            i32::from(Signal::SIGSEGV.raw()) | 0x80
        );
        let _ = (CLD_KILLED, CLD_STOPPED, WSTOPPED);
    }
}

#[test]
fn vfork_suspends_parent_until_child_execs_or_exits() {
    let pids = PidNamespace::new();
    let mut parent = make_root(Abi::X86_64, &pids);
    let mut mem = Mem::new(0x1_0000, 0x1_0000);
    let mut host = MockHost::new();
    let spawned_queue = Arc::clone(&host.spawned);
    let mut platform = MockPlatform;

    let mut fut = core::pin::pin!(dispatch(
        &mut parent,
        Call {
            number: number(Abi::X86_64, Operation::Vfork),
            arguments: [0; 6],
        },
        &mut mem,
        &mut host,
        &mut platform,
    ));

    // First poll spawns child with share_vm=true and suspends parent!
    assert!(
        fut.as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    let spawned = {
        let mut queue = spawned_queue.lock().unwrap();
        assert_eq!(queue.len(), 1);
        queue.pop().unwrap()
    };
    assert!(spawned.share_vm);
    let mut child = spawned.child;
    let child_pid = child.pid().get();

    // Child calls commit_linux_exec -> immediately unblocks parent!
    child.commit_linux_exec(0x50_0000);
    match fut.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(ControlFlow::Continue(SyscallOutcome::Return(ret))) => {
            assert_eq!(ret, u64::from(child_pid));
        }
        other => panic!("expected vfork to return child pid, got {other:?}"),
    }
    child.mark_exited(ChildTermination::Exited(0));
}

#[test]
fn pgid_sid_setsid_and_exec_resets_cloexec_and_handlers() {
    for abi in ABIS {
        let pids = PidNamespace::new();
        let mut parent = make_root(abi, &pids);
        let mut mem = Mem::new(0x1_0000, 0x1_0000);
        let mut host = MockHost::new();

        // Install caught handler on SIGUSR1 and SIG_IGN on SIGUSR2 in parent.
        let mut sa_catch = [0u8; 32];
        sa_catch[0..8].copy_from_slice(&0x40_1234u64.to_le_bytes());
        mem.write_bytes(0x1_0000, &sa_catch);
        assert_eq!(
            call_ret(
                &mut parent,
                abi,
                Operation::RtSigaction,
                [u64::from(Signal::SIGUSR1.raw()), 0x1_0000, 0, 8, 0, 0],
                &mut mem,
                &mut host,
            ),
            0
        );
        let mut sa_ign = [0u8; 32];
        sa_ign[0..8].copy_from_slice(&1u64.to_le_bytes()); // SIG_IGN
        mem.write_bytes(0x1_0040, &sa_ign);
        assert_eq!(
            call_ret(
                &mut parent,
                abi,
                Operation::RtSigaction,
                [u64::from(Signal::SIGUSR2.raw()), 0x1_0040, 0, 8, 0, 0],
                &mut mem,
                &mut host,
            ),
            0
        );

        // Open a CLOEXEC pipe and a non-CLOEXEC pipe.
        assert_eq!(
            call_ret(
                &mut parent,
                abi,
                Operation::Pipe2,
                [0x1_0100, O_CLOEXEC, 0, 0, 0, 0],
                &mut mem,
                &mut host,
            ),
            0
        );
        let cloexec_fd = mem.read_i32(0x1_0100);
        assert_eq!(
            call_ret(
                &mut parent,
                abi,
                Operation::Pipe2,
                [0x1_0108, 0, 0, 0, 0, 0],
                &mut mem,
                &mut host,
            ),
            0
        );
        let kept_fd = mem.read_i32(0x1_0108);

        // Negative pid / pgid validation matches Linux kernel/sys.c
        // (pgid defaults to pid before pgid < 0 -> EINVAL is checked).
        assert_eq!(
            call_ret(
                &mut parent,
                abi,
                Operation::Setpgid,
                [(-1i32) as u32 as u64, 0, 0, 0, 0, 0],
                &mut mem,
                &mut host,
            ),
            err(EINVAL)
        );
        assert_eq!(
            call_ret(
                &mut parent,
                abi,
                Operation::Setpgid,
                [0, (-1i32) as u32 as u64, 0, 0, 0, 0],
                &mut mem,
                &mut host,
            ),
            err(EINVAL)
        );
        assert_eq!(
            call_ret(
                &mut parent,
                abi,
                Operation::Setpgid,
                [(-1i32) as u32 as u64, 1, 0, 0, 0, 0],
                &mut mem,
                &mut host,
            ),
            err(ESRCH)
        );

        // Session leader cannot setsid or setpgid.
        assert_eq!(
            call_ret(
                &mut parent,
                abi,
                Operation::Setsid,
                [0; 6],
                &mut mem,
                &mut host
            ),
            err(EPERM)
        );

        // Fork child.
        let child_pid = call_ret(
            &mut parent,
            abi,
            Operation::Clone,
            [u64::from(Signal::SIGCHLD.raw()), 0, 0, 0, 0, 0],
            &mut mem,
            &mut host,
        );
        let mut child = host.pop_spawned().child;

        // Parent can move child to its own process group before exec.
        assert_eq!(
            call_ret(
                &mut parent,
                abi,
                Operation::Setpgid,
                [child_pid, child_pid, 0, 0, 0, 0],
                &mut mem,
                &mut host,
            ),
            0
        );
        assert_eq!(
            call_ret(
                &mut parent,
                abi,
                Operation::Getpgid,
                [child_pid, 0, 0, 0, 0, 0],
                &mut mem,
                &mut host,
            ),
            child_pid
        );
        assert_eq!(
            call_ret(
                &mut parent,
                abi,
                Operation::Getsid,
                [child_pid, 0, 0, 0, 0, 0],
                &mut mem,
                &mut host,
            ),
            1
        );

        // Wait by P_PGID matches child in its new pgid.
        assert_eq!(
            call_ret(
                &mut parent,
                abi,
                Operation::Waitid,
                [P_PGID, child_pid, 0x1_0200, WEXITED | WNOHANG, 0, 0],
                &mut mem,
                &mut host,
            ),
            0
        );

        // Child calls execve with valid path -> SyscallOutcome::Exec.
        mem.write_cstr(0x1_1000, "/linux/hello");
        mem.write_cstr(0x1_1040, "arg0");
        mem.write_cstr(0x1_1060, "K=V");
        mem.write_u64(0x1_1100, 0x1_1040);
        mem.write_u64(0x1_1108, 0);
        mem.write_u64(0x1_1120, 0x1_1060);
        mem.write_u64(0x1_1128, 0);
        assert_eq!(
            call_now(
                &mut child,
                abi,
                Operation::Execve,
                [0x1_1000, 0x1_1100, 0x1_1120, 0, 0, 0],
                &mut mem,
                &mut host,
            ),
            SyscallOutcome::Exec
        );
        let spec = host.last_exec.take().unwrap();
        assert_eq!(spec.path, "/linux/hello");
        assert_eq!(spec.argv, vec!["arg0"]);
        assert_eq!(spec.envp, vec!["K=V"]);

        // Commit exec on child: CLOEXEC fd closed, kept fd open, SIGUSR1 reset
        // to SIG_DFL, SIGUSR2 still SIG_IGN, and parent setpgid now returns EACCES.
        child.commit_linux_exec(0x60_0000);
        assert!(child.descriptor_entry(cloexec_fd).is_none());
        assert!(child.descriptor_entry(kept_fd).is_some());
        assert_eq!(
            call_ret(
                &mut child,
                abi,
                Operation::RtSigaction,
                [u64::from(Signal::SIGUSR1.raw()), 0, 0x1_0500, 8, 0, 0],
                &mut mem,
                &mut host,
            ),
            0
        );
        assert_eq!(mem.read_u64(0x1_0500), 0); // SIG_DFL
        assert_eq!(
            call_ret(
                &mut child,
                abi,
                Operation::RtSigaction,
                [u64::from(Signal::SIGUSR2.raw()), 0, 0x1_0520, 8, 0, 0],
                &mut mem,
                &mut host,
            ),
            0
        );
        assert_eq!(mem.read_u64(0x1_0520), 1); // SIG_IGN preserved
        assert_eq!(
            call_ret(
                &mut parent,
                abi,
                Operation::Setpgid,
                [child_pid, 1, 0, 0, 0, 0],
                &mut mem,
                &mut host,
            ),
            err(EACCES)
        );

        // Non-leader child in parent's pgid can create a new session with setsid().
        let child2_pid = call_ret(
            &mut parent,
            abi,
            Operation::Clone,
            [u64::from(Signal::SIGCHLD.raw()), 0, 0, 0, 0, 0],
            &mut mem,
            &mut host,
        );
        let mut child2 = host.pop_spawned().child;
        assert_eq!(
            call_ret(
                &mut child2,
                abi,
                Operation::Setsid,
                [0; 6],
                &mut mem,
                &mut host
            ),
            child2_pid
        );
        assert_eq!(
            call_ret(
                &mut child2,
                abi,
                Operation::Getsid,
                [0; 6],
                &mut mem,
                &mut host
            ),
            child2_pid
        );
        assert_eq!(
            call_ret(
                &mut child2,
                abi,
                Operation::Getpgid,
                [0; 6],
                &mut mem,
                &mut host
            ),
            child2_pid
        );

        // execveat flag validation & empty path checks.
        mem.write_cstr(0x1_1200, "");
        assert_eq!(
            call_ret(
                &mut child,
                abi,
                Operation::Execveat,
                [(-100i32) as u32 as u64, 0x1_1200, 0, 0, 0, 0],
                &mut mem,
                &mut host,
            ),
            err(ENOENT)
        );
        assert_eq!(
            call_ret(
                &mut child,
                abi,
                Operation::Execveat,
                [(-100i32) as u32 as u64, 0x1_1200, 0, 0, 0xdead, 0],
                &mut mem,
                &mut host,
            ),
            err(EINVAL)
        );
        assert_eq!(
            call_now(
                &mut child,
                abi,
                Operation::Execveat,
                [
                    5,
                    0x1_1200,
                    0,
                    0,
                    u64::from(AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW),
                    0,
                ],
                &mut mem,
                &mut host,
            ),
            SyscallOutcome::Exec
        );
        let _ = (
            ESRCH,
            CLONE_VM,
            CLONE_VFORK,
            CLONE_CHILD_SETTID,
            CLONE_CLEAR_SIGHAND,
        );
    }
}

#[test]
fn sigchld_auto_reap_and_orphan_reparenting_to_pid_1() {
    let pids = PidNamespace::new();
    let mut init = make_root(Abi::Aarch64, &pids);
    let mut mem = Mem::new(0x1_0000, 0x1_0000);
    let mut host = MockHost::new();

    // Fork middle child (pid 2) and grandchild (pid 3).
    let mid_pid = call_ret(
        &mut init,
        Abi::Aarch64,
        Operation::Clone,
        [u64::from(Signal::SIGCHLD.raw()), 0, 0, 0, 0, 0],
        &mut mem,
        &mut host,
    );
    let mut mid = host.pop_spawned().child;
    let grand_pid = call_ret(
        &mut mid,
        Abi::Aarch64,
        Operation::Clone,
        [u64::from(Signal::SIGCHLD.raw()), 0, 0, 0, 0, 0],
        &mut mem,
        &mut host,
    );
    let mut grand = host.pop_spawned().child;
    assert_eq!(
        call_ret(
            &mut grand,
            Abi::Aarch64,
            Operation::Getppid,
            [0; 6],
            &mut mem,
            &mut host,
        ),
        mid_pid
    );

    // Middle child exits while grandchild is still alive -> grandchild reparented to PID 1.
    mid.mark_exited(ChildTermination::Exited(0));
    assert_eq!(
        call_ret(
            &mut grand,
            Abi::Aarch64,
            Operation::Getppid,
            [0; 6],
            &mut mem,
            &mut host,
        ),
        1
    );
    grand.mark_exited(ChildTermination::Exited(7));
    assert_eq!(
        call_ret(
            &mut init,
            Abi::Aarch64,
            Operation::Wait4,
            [grand_pid, 0x1_0100, 0, 0, 0, 0],
            &mut mem,
            &mut host,
        ),
        grand_pid
    );
    assert_eq!(mem.read_i32(0x1_0100), 7 << 8);
    assert_eq!(
        call_ret(
            &mut init,
            Abi::Aarch64,
            Operation::Wait4,
            [mid_pid, 0x1_0100, 0, 0, 0, 0],
            &mut mem,
            &mut host,
        ),
        mid_pid
    );

    // Setting SA_NOCLDWAIT auto-reaps exiting children without creating zombies.
    let mut sa = [0u8; 32];
    sa[8..16].copy_from_slice(&SA_NOCLDWAIT.to_le_bytes());
    mem.write_bytes(0x1_0000, &sa);
    assert_eq!(
        call_ret(
            &mut init,
            Abi::Aarch64,
            Operation::RtSigaction,
            [u64::from(Signal::SIGCHLD.raw()), 0x1_0000, 0, 8, 0, 0],
            &mut mem,
            &mut host,
        ),
        0
    );
    let ephemeral_pid = call_ret(
        &mut init,
        Abi::Aarch64,
        Operation::Clone,
        [u64::from(Signal::SIGCHLD.raw()), 0, 0, 0, 0, 0],
        &mut mem,
        &mut host,
    );
    let ephemeral = host.pop_spawned().child;
    ephemeral.mark_exited(ChildTermination::Exited(0));
    assert!(!pids.contains(ephemeral_pid as u32));
    assert_eq!(
        call_ret(
            &mut init,
            Abi::Aarch64,
            Operation::Wait4,
            [(-1i32) as u32 as u64, 0, WNOHANG, 0, 0, 0],
            &mut mem,
            &mut host,
        ),
        err(ECHILD)
    );
}

#[test]
fn fork_cow_map_shared_untouched_child_does_not_clobber_post_fork_writes() {
    use helios_hal::fs::{FsError, Landed, NodeKind, WritePosition};
    use helios_linux::syscall::{
        Credentials, FileAccess, FileStat, Filesystem, FsOpError, OpenRequest, Resources, Tty,
        VirtualMemory,
    };

    struct FileBacking;
    impl Resources for FileBacking {
        type File = u32;
        type Network = helios_unix::NoNetwork;
        type Data = u64;
    }

    struct CowMem {
        base: u64,
        bytes: Vec<u8>,
        shared_pages: std::collections::BTreeSet<u64>,
    }

    impl CowMem {
        fn new(base: u64, len: usize) -> Self {
            Self {
                base,
                bytes: vec![0; len],
                shared_pages: std::collections::BTreeSet::new(),
            }
        }

        fn clone_cow(&mut self) -> Self {
            let mut shared = std::collections::BTreeSet::new();
            for offset in (0..self.bytes.len()).step_by(4096) {
                shared.insert(self.base + offset as u64);
            }
            self.shared_pages = shared.clone();
            Self {
                base: self.base,
                bytes: self.bytes.clone(),
                shared_pages: shared,
            }
        }

        fn slice(&self, address: u64, len: usize) -> Result<core::ops::Range<usize>, MemoryFault> {
            let start = usize::try_from(address.checked_sub(self.base).ok_or(MemoryFault)?)
                .map_err(|_| MemoryFault)?;
            let end = start.checked_add(len).ok_or(MemoryFault)?;
            if end > self.bytes.len() {
                return Err(MemoryFault);
            }
            Ok(start..end)
        }
    }

    impl UserMemory for CowMem {
        fn read(&self, address: u64, output: &mut [u8]) -> Result<(), MemoryFault> {
            let range = self.slice(address, output.len())?;
            output.copy_from_slice(&self.bytes[range]);
            Ok(())
        }
        fn check_writable(&self, address: u64, length: usize) -> Result<(), MemoryFault> {
            self.slice(address, length).map(|_| ())
        }
        fn write(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryFault> {
            let range = self.slice(address, bytes.len())?;
            self.bytes[range].copy_from_slice(bytes);
            let first_page = address & !4095;
            let last_page = (address + bytes.len().saturating_sub(1) as u64) & !4095;
            let mut p = first_page;
            while p <= last_page {
                self.shared_pages.remove(&p);
                p += 4096;
            }
            Ok(())
        }
        fn atomic_load_u32(&self, address: u64) -> Result<u32, MemoryFault> {
            let mut buf = [0u8; 4];
            self.read(address, &mut buf)?;
            Ok(u32::from_le_bytes(buf))
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
        fn is_page_shared(&self, address: u64) -> bool {
            self.shared_pages.contains(&(address & !4095))
        }
    }

    impl VirtualMemory for CowMem {
        fn lowest_address(&self) -> u64 {
            self.base
        }
        fn map_anywhere(&mut self, _: u64, _: u64, _: PageFlags) -> Result<u64, MapError> {
            Ok(self.base + 0x2000)
        }
        fn map_at(&mut self, _: u64, _: u64, _: PageFlags) -> Result<(), MapError> {
            Ok(())
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

    struct SharedFileHost {
        spawned: Vec<SpawnedProcess<FileBacking>>,
    }
    impl Thread<FileBacking> for SharedFileHost {
        fn thread_pointer(&self) -> u64 {
            0
        }
        fn set_thread_pointer(&mut self, _: u64) -> Result<(), Denied> {
            Ok(())
        }
        fn spawn_thread(
            &mut self,
            _: Process<FileBacking>,
            _: SpawnedThread,
        ) -> Result<(), SpawnError> {
            Err(SpawnError::Busy)
        }
        fn spawn_process(&mut self, p: SpawnedProcess<FileBacking>) -> Result<(), SpawnError> {
            self.spawned.push(p);
            Ok(())
        }
    }

    struct SharedFilePlatform {
        data: Arc<Mutex<Vec<u8>>>,
    }
    impl Stdio for SharedFilePlatform {
        async fn write(&mut self, _: Stream, bytes: &[u8]) -> Result<usize, WriteError> {
            Ok(bytes.len())
        }
        async fn read_input(&mut self, _: usize) -> Result<bytes::Bytes, Denied> {
            Ok(bytes::Bytes::new())
        }
    }
    impl Clock for SharedFilePlatform {
        fn now_nanos(&self) -> u64 {
            0
        }
        async fn sleep_until(&self, _: u64) {}
    }
    impl System for SharedFilePlatform {
        fn realtime_nanos(&self) -> u64 {
            0
        }
        fn set_realtime_nanos(&mut self, _: u64) -> Result<(), Denied> {
            Err(Denied)
        }
        fn cpu_nanos(&self) -> u64 {
            0
        }
        fn fill_random(&mut self, _: &mut [u8]) {}
        fn memory(&self) -> MemoryTotals {
            MemoryTotals {
                total_bytes: 0,
                free_bytes: 0,
            }
        }
        fn process_count(&self) -> u32 {
            1
        }
        fn kernel_version(&self) -> &str {
            "test"
        }
    }
    impl helios_linux::syscall::Network<helios_unix::NoNetwork> for SharedFilePlatform {
        fn to_ip(&self, address: core::convert::Infallible) -> helios_linux::syscall::IpAddr {
            match address {}
        }
        fn encode_ip(&self, _: helios_linux::syscall::IpAddr) -> core::convert::Infallible {
            unreachable!()
        }
    }
    impl Tty for SharedFilePlatform {}
    impl Filesystem<FileBacking> for SharedFilePlatform {
        fn file_access(&self, _: &u32) -> FileAccess {
            FileAccess::ReadWrite
        }
        fn same_file(&self, a: &u32, b: &u32) -> bool {
            a == b
        }
        async fn open(
            &mut self,
            _: Option<&u32>,
            _: &str,
            path: &str,
            _: OpenRequest,
            _: &Credentials,
        ) -> Result<u32, FsOpError> {
            if path == "/shared.bin" {
                Ok(1)
            } else {
                Err(FsOpError::Fs(FsError::NoEntry))
            }
        }
        async fn stat_file(&self, _: &u32) -> Result<FileStat, FsOpError> {
            let size = self.data.lock().unwrap().len() as u64;
            Ok(FileStat {
                dev: 1,
                ino: 1,
                kind: NodeKind::File,
                permissions: 0o644,
                nlink: 1,
                uid: 0,
                gid: 0,
                rdev: 0,
                size,
                access_nanos: 0,
                modified_nanos: 0,
                status_nanos: 0,
            })
        }
        async fn read_at(
            &self,
            _: &u32,
            offset: u64,
            max_bytes: usize,
        ) -> Result<bytes::Bytes, FsOpError> {
            let data = self.data.lock().unwrap();
            let off = (offset as usize).min(data.len());
            let n = max_bytes.min(data.len() - off);
            Ok(bytes::Bytes::copy_from_slice(&data[off..off + n]))
        }
        async fn write_at(
            &mut self,
            _: &u32,
            pos: WritePosition,
            bytes: &[u8],
            _: &Credentials,
        ) -> Result<Landed, FsOpError> {
            let mut data = self.data.lock().unwrap();
            let off = match pos {
                WritePosition::At(o) => o as usize,
                WritePosition::End => data.len(),
            };
            if off + bytes.len() > data.len() {
                data.resize(off + bytes.len(), 0);
            }
            data[off..off + bytes.len()].copy_from_slice(bytes);
            Ok(Landed {
                offset: off as u64,
                len: bytes.len(),
            })
        }
    }

    let run = |process: &mut Process<FileBacking>,
               op: Operation,
               args: [u64; 6],
               mem: &mut CowMem,
               host: &mut SharedFileHost,
               plat: &mut SharedFilePlatform| {
        let mut fut = core::pin::pin!(dispatch(
            process,
            Call {
                number: number(Abi::X86_64, op),
                arguments: args,
            },
            mem,
            host,
            plat,
        ));
        match fut.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(res) => res,
            Poll::Pending => panic!("unexpected pending"),
        }
    };

    let pids = PidNamespace::new();
    let pid = pids.allocate_process().unwrap();
    let mut parent = Process::<FileBacking>::with_descriptors(
        Abi::X86_64,
        pid,
        PROGRAM_BREAK,
        standard_streams::<FileBacking>(),
        Start {
            pids: Some(pids),
            ..Start::default()
        },
    );
    let mut parent_mem = CowMem::new(0x1_0000, 0x4000);
    let mut host = SharedFileHost {
        spawned: Vec::new(),
    };
    let backing = Arc::new(Mutex::new(b"INITIAL!".to_vec()));
    let mut plat = SharedFilePlatform {
        data: Arc::clone(&backing),
    };

    // Open `/shared.bin` O_RDWR (2) and map it MAP_SHARED (1) | PROT_READ|PROT_WRITE (3).
    parent_mem.write(0x1_0000, b"/shared.bin\0").unwrap();
    let ControlFlow::Continue(SyscallOutcome::Return(fd)) = run(
        &mut parent,
        Operation::Openat,
        [(-100i32) as u32 as u64, 0x1_0000, 2, 0, 0, 0],
        &mut parent_mem,
        &mut host,
        &mut plat,
    ) else {
        panic!("openat failed");
    };
    assert_eq!(fd, 3);

    let ControlFlow::Continue(SyscallOutcome::Return(mapped)) = run(
        &mut parent,
        Operation::Mmap,
        [0, 4096, 3, 1, fd, 0],
        &mut parent_mem,
        &mut host,
        &mut plat,
    ) else {
        panic!("mmap failed");
    };
    assert_eq!(mapped, 0x1_2000);

    // Parent mutates mapping before fork: fork must flush "PRE-FORK" before CoW.
    parent_mem.write(mapped, b"PRE-FORK").unwrap();
    let ControlFlow::Continue(SyscallOutcome::Return(child1_pid)) = run(
        &mut parent,
        Operation::Fork,
        [0; 6],
        &mut parent_mem,
        &mut host,
        &mut plat,
    ) else {
        panic!("fork 1 failed");
    };
    assert!(child1_pid > 1);
    assert_eq!(&*backing.lock().unwrap(), b"PRE-FORK");
    let mut child1_mem = parent_mem.clone_cow();
    let mut child1 = host.spawned.pop().unwrap().child;

    // Parent writes "POSTFORK" after fork and flushes via pwrite64.
    parent_mem.write(0x1_0100, b"POSTFORK").unwrap();
    let ControlFlow::Continue(SyscallOutcome::Return(written)) = run(
        &mut parent,
        Operation::Pwrite64,
        [fd, 0x1_0100, 8, 0, 0, 0],
        &mut parent_mem,
        &mut host,
        &mut plat,
    ) else {
        panic!("pwrite64 failed");
    };
    assert_eq!(written, 8);
    assert_eq!(&*backing.lock().unwrap(), b"POSTFORK");

    // Child 1 exits WITHOUT touching `mapped`: its untouched CoW page must NOT
    // overwrite the file with "PRE-FORK".
    let ControlFlow::Break(_) = run(
        &mut child1,
        Operation::ExitGroup,
        [0, 0, 0, 0, 0, 0],
        &mut child1_mem,
        &mut host,
        &mut plat,
    ) else {
        panic!("child1 exit_group failed");
    };
    assert_eq!(&*backing.lock().unwrap(), b"POSTFORK");

    // Child 2 forks, leaves `mapped` untouched, flushes on execve -> still "POSTFORK".
    let ControlFlow::Continue(SyscallOutcome::Return(_)) = run(
        &mut parent,
        Operation::Fork,
        [0; 6],
        &mut parent_mem,
        &mut host,
        &mut plat,
    ) else {
        panic!("fork 2 failed");
    };
    let child2_mem = parent_mem.clone_cow();
    let mut child2 = host.spawned.pop().unwrap().child;
    {
        let mut fut = core::pin::pin!(child2.flush_shared_mappings(&child2_mem, &mut plat));
        assert!(
            fut.as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_ready()
        );
    }
    child2.commit_linux_exec(PROGRAM_BREAK);
    assert_eq!(&*backing.lock().unwrap(), b"POSTFORK");

    // Child 3 forks and DOES dirty `mapped` (breaking CoW) -> flushes "CHILDWRT".
    let ControlFlow::Continue(SyscallOutcome::Return(_)) = run(
        &mut parent,
        Operation::Fork,
        [0; 6],
        &mut parent_mem,
        &mut host,
        &mut plat,
    ) else {
        panic!("fork 3 failed");
    };
    let mut child3_mem = parent_mem.clone_cow();
    let mut child3 = host.spawned.pop().unwrap().child;
    child3_mem.write(mapped, b"CHILDWRT").unwrap();
    assert!(!child3_mem.is_page_shared(mapped));
    let ControlFlow::Break(_) = run(
        &mut child3,
        Operation::ExitGroup,
        [0, 0, 0, 0, 0, 0],
        &mut child3_mem,
        &mut host,
        &mut plat,
    ) else {
        panic!("child3 exit_group failed");
    };
    assert_eq!(&*backing.lock().unwrap(), b"CHILDWRT");
}

#[test]
fn clone_sighand_without_clone_thread_keeps_distinct_tgid_and_unshares_on_exec() {
    const CLONE_VM: u64 = 0x0000_0100;
    const CLONE_FS: u64 = 0x0000_0200;
    const CLONE_FILES: u64 = 0x0000_0400;
    const CLONE_SIGHAND: u64 = 0x0000_0800;
    const CLONE_THREAD: u64 = 0x0001_0000;

    let pids = PidNamespace::new();
    let mut parent = make_root(Abi::X86_64, &pids);
    let mut mem = Mem::new(0x1_0000, 0x1_0000);
    let mut host = MockHost::new();

    // Parent installs SIGUSR1 handler = 0x40_1000.
    let mut sa = [0u8; 32];
    sa[0..8].copy_from_slice(&0x40_1000u64.to_le_bytes());
    mem.write_bytes(0x1_0000, &sa);
    assert_eq!(
        call_ret(
            &mut parent,
            Abi::X86_64,
            Operation::RtSigaction,
            [u64::from(Signal::SIGUSR1.raw()), 0x1_0000, 0, 8, 0, 0],
            &mut mem,
            &mut host,
        ),
        0
    );

    // Clone a separate process sharing only dispositions (`CLONE_VM | CLONE_SIGHAND`).
    let child_pid = call_ret(
        &mut parent,
        Abi::X86_64,
        Operation::Clone,
        [
            CLONE_VM | CLONE_SIGHAND | u64::from(Signal::SIGCHLD.raw()),
            0,
            0,
            0,
            0,
            0,
        ],
        &mut mem,
        &mut host,
    );
    let mut child = host.pop_spawned().child;
    assert_eq!(child.pid().get(), child_pid as u32);
    assert_ne!(
        child.process_signals().tgid(),
        parent.process_signals().tgid()
    );
    assert_eq!(child.process_signals().tgid(), child.pid());

    // Signalling `child_pid` delivers to child's mailbox, NOT parent's.
    assert_eq!(
        call_ret(
            &mut parent,
            Abi::X86_64,
            Operation::Kill,
            [child_pid, u64::from(Signal::SIGUSR2.raw()), 0, 0, 0, 0],
            &mut mem,
            &mut host,
        ),
        0
    );
    assert!(child.thread_signals().take_pending_signal() == Some(Signal::SIGUSR2));
    assert!(parent.thread_signals().take_pending_signal().is_none());

    // Child mutating SIGUSR2 disposition is visible in parent (shared table).
    sa[0..8].copy_from_slice(&0x40_2000u64.to_le_bytes());
    mem.write_bytes(0x1_0000, &sa);
    assert_eq!(
        call_ret(
            &mut child,
            Abi::X86_64,
            Operation::RtSigaction,
            [u64::from(Signal::SIGUSR2.raw()), 0x1_0000, 0, 8, 0, 0],
            &mut mem,
            &mut host,
        ),
        0
    );
    assert_eq!(
        call_ret(
            &mut parent,
            Abi::X86_64,
            Operation::RtSigaction,
            [u64::from(Signal::SIGUSR2.raw()), 0, 0x1_0040, 8, 0, 0],
            &mut mem,
            &mut host,
        ),
        0
    );
    assert_eq!(mem.read_u64(0x1_0040), 0x40_2000);

    // Child calling `commit_linux_exec` unshares sighand and resets child's
    // SIGUSR1 to SIG_DFL while preserving parent's SIGUSR1 handler (0x40_1000).
    child.commit_linux_exec(PROGRAM_BREAK);
    assert_eq!(
        call_ret(
            &mut child,
            Abi::X86_64,
            Operation::RtSigaction,
            [u64::from(Signal::SIGUSR1.raw()), 0, 0x1_0040, 8, 0, 0],
            &mut mem,
            &mut host,
        ),
        0
    );
    assert_eq!(mem.read_u64(0x1_0040), 0);
    assert_eq!(
        call_ret(
            &mut parent,
            Abi::X86_64,
            Operation::RtSigaction,
            [u64::from(Signal::SIGUSR1.raw()), 0, 0x1_0040, 8, 0, 0],
            &mut mem,
            &mut host,
        ),
        0
    );
    assert_eq!(mem.read_u64(0x1_0040), 0x40_1000);

    // Verify `commit_wasm_exec` called from a non-leader thread normalizes
    // `tid == pid` and releases the old thread ID (`de_thread`).
    struct ThreadCaptureHost {
        thread: Option<Process<NoBacking>>,
    }
    impl Thread<NoBacking> for ThreadCaptureHost {
        fn thread_pointer(&self) -> u64 {
            0
        }
        fn set_thread_pointer(&mut self, _: u64) -> Result<(), Denied> {
            Ok(())
        }
        fn spawn_thread(
            &mut self,
            child: Process<NoBacking>,
            _: SpawnedThread,
        ) -> Result<(), SpawnError> {
            self.thread = Some(child);
            Ok(())
        }
    }
    let mut th_host = ThreadCaptureHost { thread: None };
    let mut plat = MockPlatform;
    let worker_tid = {
        let mut fut = core::pin::pin!(dispatch(
            &mut child,
            Call {
                number: number(Abi::X86_64, Operation::Clone),
                arguments: [
                    CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD,
                    0x20_0000,
                    0,
                    0,
                    0,
                    0
                ],
            },
            &mut mem,
            &mut th_host,
            &mut plat,
        ));
        match fut.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(ControlFlow::Continue(SyscallOutcome::Return(tid))) => tid as u32,
            other => panic!("expected clone thread tid, got {other:?}"),
        }
    };
    let mut worker = th_host.thread.take().unwrap();
    assert_eq!(worker.tid().get(), worker_tid);
    assert_ne!(worker.tid(), worker.pid());
    let (_, _) = worker.commit_wasm_exec();
    assert_eq!(worker.tid(), worker.pid());
    assert!(!pids.contains(worker_tid));
    child.mark_exited(ChildTermination::Exited(0));
}

#[test]
fn dev_null_fallback_rejects_dotdot_traversal() {
    use helios_hal::fs::FsError;
    use helios_linux::syscall::{Credentials, Filesystem, FsOpError, OpenRequest, Tty};

    struct EmptyFsPlatform;
    impl Stdio for EmptyFsPlatform {
        async fn write(&mut self, _: Stream, bytes: &[u8]) -> Result<usize, WriteError> {
            Ok(bytes.len())
        }
        async fn read_input(&mut self, _: usize) -> Result<bytes::Bytes, Denied> {
            Ok(bytes::Bytes::new())
        }
    }
    impl Clock for EmptyFsPlatform {
        fn now_nanos(&self) -> u64 {
            0
        }
        async fn sleep_until(&self, _: u64) {}
    }
    impl System for EmptyFsPlatform {
        fn realtime_nanos(&self) -> u64 {
            0
        }
        fn set_realtime_nanos(&mut self, _: u64) -> Result<(), Denied> {
            Err(Denied)
        }
        fn cpu_nanos(&self) -> u64 {
            0
        }
        fn fill_random(&mut self, _: &mut [u8]) {}
        fn memory(&self) -> MemoryTotals {
            MemoryTotals {
                total_bytes: 0,
                free_bytes: 0,
            }
        }
        fn process_count(&self) -> u32 {
            1
        }
        fn kernel_version(&self) -> &str {
            "test"
        }
    }
    impl helios_linux::syscall::Network<helios_unix::NoNetwork> for EmptyFsPlatform {
        fn to_ip(&self, address: core::convert::Infallible) -> helios_linux::syscall::IpAddr {
            match address {}
        }
        fn encode_ip(&self, _: helios_linux::syscall::IpAddr) -> core::convert::Infallible {
            unreachable!()
        }
    }
    impl Tty for EmptyFsPlatform {}
    impl Filesystem<NoBacking> for EmptyFsPlatform {
        async fn open(
            &mut self,
            _: Option<&core::convert::Infallible>,
            _: &str,
            _: &str,
            _: OpenRequest,
            _: &Credentials,
        ) -> Result<core::convert::Infallible, FsOpError> {
            Err(FsOpError::Fs(FsError::NoEntry))
        }
    }

    let pids = PidNamespace::new();
    let mut proc = make_root(Abi::X86_64, &pids);
    let mut mem = Mem::new(0x1_0000, 0x1_0000);
    let mut host = MockHost::new();
    let mut plat = EmptyFsPlatform;

    let open_path = |proc: &mut Process<NoBacking>,
                     mem: &mut Mem,
                     host: &mut MockHost,
                     plat: &mut EmptyFsPlatform,
                     addr: u64,
                     path: &[u8]| {
        mem.write_bytes(addr, path);
        let mut fut = core::pin::pin!(dispatch(
            proc,
            Call {
                number: number(Abi::X86_64, Operation::Openat),
                arguments: [(-100i32) as u32 as u64, addr, 0, 0, 0, 0],
            },
            mem,
            host,
            plat,
        ));
        match fut.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(ControlFlow::Continue(SyscallOutcome::Return(ret))) => ret,
            other => panic!("unexpected openat outcome: {other:?}"),
        }
    };

    // Clean `/dev/null` opens synthetic NullDevice.
    assert_eq!(
        open_path(
            &mut proc,
            &mut mem,
            &mut host,
            &mut plat,
            0x1_0000,
            b"/dev/null\0"
        ),
        3
    );

    // `/nonexistent/../dev/null` must NOT collapse `..` over a missing directory.
    assert_eq!(
        open_path(
            &mut proc,
            &mut mem,
            &mut host,
            &mut plat,
            0x1_0040,
            b"/nonexistent/../dev/null\0",
        ),
        err(ENOENT)
    );
}
