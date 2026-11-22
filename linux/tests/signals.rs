#![cfg(feature = "runtime")]
//! Linux signal handling, delivery, restart/EINTR, alternate stack, container
//! PID namespace isolation, and interval timer tests on both x86-64 and AArch64.

use core::convert::Infallible;
use core::future::Future;
use core::num::NonZeroU32;
use core::ops::ControlFlow;
use core::sync::atomic::{AtomicU64, Ordering};
use core::task::{Context, Poll, Waker};
use std::sync::{Arc, Mutex};

use helios_hal::hv::RegisterId;
use helios_hal::native::{
    Aarch64FpSimd, ExtendedState, FaultKind, NativeError, Stop, UserContext, UserFault,
};
use helios_hal::vmm::{PageFlags, VirtAddr};
use helios_linux::abi::{Abi, Operation};
use helios_linux::signal_frame::{
    SA_NODEFER, SA_ONSTACK, SA_RESETHAND, SA_RESTART, SA_RESTORER, SA_SIGINFO, SEGV_ACCERR,
    SS_AUTODISARM, SS_DISABLE, SS_ONSTACK,
};
use helios_linux::syscall::{
    Call, Clock, Credentials, Denied, Filesystem, MapError, MemoryFault, MemoryTotals, NoBacking,
    PidNamespace, Process, Region, SignalDelivery, SpawnError, SpawnedThread, Start, Stdio, Stream,
    SyscallOutcome, SyscallRestart, System, Thread, Tty, UserMemory, VirtualMemory, WriteError,
    dispatch, standard_streams,
};
use helios_unix::{Signal, SignalSet};

const ABIS: [Abi; 2] = [Abi::X86_64, Abi::Aarch64];
const PROGRAM_BREAK: u64 = 0x40_0000;
const EINVAL: u64 = 22;
const EPERM: u64 = 1;
const ESRCH: u64 = 3;
const EINTR: u64 = 4;
const EAGAIN: u64 = 11;
const ENOMEM: u64 = 12;
const EFAULT: u64 = 14;
const EPIPE: u64 = 32;

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
    fn read_bytes(&self, addr: u64, len: usize) -> Vec<u8> {
        let r = self.range(addr, len).unwrap();
        self.bytes.lock().unwrap()[r].to_vec()
    }
    fn read_u64(&self, addr: u64) -> u64 {
        u64::from_le_bytes(self.read_bytes(addr, 8).try_into().unwrap())
    }
    fn read_i32(&self, addr: u64) -> i32 {
        i32::from_le_bytes(self.read_bytes(addr, 4).try_into().unwrap())
    }
    fn write_u64(&self, addr: u64, val: u64) {
        self.write_bytes(addr, &val.to_le_bytes());
    }
}

impl UserMemory for Mem {
    fn read(&self, address: u64, output: &mut [u8]) -> Result<(), MemoryFault> {
        let r = self.range(address, output.len())?;
        output.copy_from_slice(&self.bytes.lock().unwrap()[r]);
        Ok(())
    }
    fn check_writable(&self, address: u64, length: usize) -> Result<(), MemoryFault> {
        self.range(address, length).map(|_| ())
    }
    fn write(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryFault> {
        let r = self.range(address, bytes.len())?;
        self.bytes.lock().unwrap()[r].copy_from_slice(bytes);
        Ok(())
    }
    fn atomic_load_u32(&self, address: u64) -> Result<u32, MemoryFault> {
        let mut b = [0; 4];
        self.read(address, &mut b)?;
        Ok(u32::from_le_bytes(b))
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

struct TestPlatform {
    now_ns: Arc<AtomicU64>,
}

impl TestPlatform {
    fn new(now: u64) -> Self {
        Self {
            now_ns: Arc::new(AtomicU64::new(now)),
        }
    }
}

impl Stdio for TestPlatform {
    async fn write(&mut self, _: Stream, bytes: &[u8]) -> Result<usize, WriteError> {
        Ok(bytes.len())
    }
    async fn read_input(&mut self, _: usize) -> Result<bytes::Bytes, Denied> {
        core::future::pending().await
    }
}

impl Filesystem<NoBacking> for TestPlatform {}
impl Tty for TestPlatform {}

impl Clock for TestPlatform {
    fn now_nanos(&self) -> u64 {
        self.now_ns.load(Ordering::Relaxed)
    }
    async fn sleep_until(&self, _: u64) {
        core::future::pending().await
    }
}

impl System for TestPlatform {
    fn realtime_nanos(&self) -> u64 {
        self.now_ns.load(Ordering::Relaxed)
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
            total_bytes: 64 << 20,
            free_bytes: 32 << 20,
        }
    }
    fn process_count(&self) -> u32 {
        1
    }
    fn kernel_version(&self) -> &str {
        "test"
    }
}

struct TestThread {
    sp: u64,
    spawned: Vec<Process<NoBacking>>,
}

impl TestThread {
    fn new(sp: u64) -> Self {
        Self {
            sp,
            spawned: Vec::new(),
        }
    }
}

impl Thread<NoBacking> for TestThread {
    fn thread_pointer(&self) -> u64 {
        0
    }
    fn set_thread_pointer(&mut self, _: u64) -> Result<(), Denied> {
        Ok(())
    }
    fn stack_pointer(&self) -> u64 {
        self.sp
    }
    fn spawn_thread(
        &mut self,
        child: Process<NoBacking>,
        _: SpawnedThread,
    ) -> Result<(), SpawnError> {
        self.spawned.push(child);
        Ok(())
    }
}

#[derive(Clone)]
struct FakeContext {
    abi: Abi,
    gprs: [u64; 31],
    sp: u64,
    pc: u64,
    flags: u64,
    ext: ExtendedState,
}

impl FakeContext {
    fn new(abi: Abi, sp: u64, pc: u64) -> Self {
        let mut gprs = [0u64; 31];
        if abi == Abi::X86_64 {
            gprs[4] = sp;
        }
        let ext = match abi {
            Abi::X86_64 => ExtendedState::X86Xsave(vec![0; 576]),
            Abi::Aarch64 => ExtendedState::Aarch64FpSimd(Box::new(Aarch64FpSimd {
                vregs: [0; 32],
                fpsr: 0,
                fpcr: 0,
            })),
        };
        Self {
            abi,
            gprs,
            sp,
            pc,
            flags: 0x202,
            ext,
        }
    }
}

unsafe impl UserContext for FakeContext {
    type Space = Infallible;
    fn register(&self, register: RegisterId) -> Result<u64, NativeError> {
        match (self.abi, register) {
            (Abi::X86_64, RegisterId::X86Gpr(i)) if i < 16 => Ok(self.gprs[i as usize]),
            (Abi::X86_64, RegisterId::X86Rip) => Ok(self.pc),
            (Abi::X86_64, RegisterId::X86Rflags) => Ok(self.flags),
            (Abi::Aarch64, RegisterId::Aarch64X(i)) if i < 31 => Ok(self.gprs[i as usize]),
            (Abi::Aarch64, RegisterId::Aarch64Sp) => Ok(self.sp),
            (Abi::Aarch64, RegisterId::Aarch64Pc) => Ok(self.pc),
            (Abi::Aarch64, RegisterId::Aarch64Pstate) => Ok(self.flags),
            _ => Err(NativeError::Register),
        }
    }
    fn set_register(&mut self, register: RegisterId, value: u64) -> Result<(), NativeError> {
        match (self.abi, register) {
            (Abi::X86_64, RegisterId::X86Gpr(i)) if i < 16 => {
                self.gprs[i as usize] = value;
                if i == 4 {
                    self.sp = value;
                }
                Ok(())
            }
            (Abi::X86_64, RegisterId::X86Rip) => {
                self.pc = value;
                Ok(())
            }
            (Abi::X86_64, RegisterId::X86Rflags) => {
                self.flags = value;
                Ok(())
            }
            (Abi::Aarch64, RegisterId::Aarch64X(i)) if i < 31 => {
                self.gprs[i as usize] = value;
                Ok(())
            }
            (Abi::Aarch64, RegisterId::Aarch64Sp) => {
                self.sp = value;
                Ok(())
            }
            (Abi::Aarch64, RegisterId::Aarch64Pc) => {
                self.pc = value;
                Ok(())
            }
            (Abi::Aarch64, RegisterId::Aarch64Pstate) => {
                self.flags = value;
                Ok(())
            }
            _ => Err(NativeError::Register),
        }
    }
    fn thread_pointer(&self) -> VirtAddr {
        VirtAddr::new(0)
    }
    fn set_thread_pointer(&mut self, _: VirtAddr) -> Result<(), NativeError> {
        Ok(())
    }
    fn extended_state(&self) -> ExtendedState {
        self.ext.clone()
    }
    fn set_extended_state(&mut self, state: &ExtendedState) -> Result<(), NativeError> {
        self.ext = state.clone();
        Ok(())
    }
    fn try_clone(&self) -> Result<Self, NativeError> {
        Ok(self.clone())
    }
    fn resume(&mut self, _: &Self::Space) -> Stop {
        unreachable!()
    }
}

fn poll_once<F: Future>(fut: &mut core::pin::Pin<&mut F>) -> Poll<F::Output> {
    fut.as_mut().poll(&mut Context::from_waker(Waker::noop()))
}

fn call_now(
    process: &mut Process<NoBacking>,
    abi: Abi,
    op: Operation,
    arguments: [u64; 6],
    memory: &mut Mem,
    thread: &mut TestThread,
    platform: &mut TestPlatform,
) -> SyscallOutcome {
    let mut fut = core::pin::pin!(dispatch(
        process,
        Call {
            number: number(abi, op),
            arguments,
        },
        memory,
        thread,
        platform,
    ));
    match poll_once(&mut fut) {
        Poll::Ready(ControlFlow::Continue(out)) => out,
        other => panic!("expected Ready(Continue), got {other:?}"),
    }
}

fn write_sigaction(mem: &Mem, addr: u64, handler: u64, flags: u64, restorer: u64, mask: u64) {
    mem.write_u64(addr, handler);
    mem.write_u64(addr + 8, flags);
    mem.write_u64(addr + 16, restorer);
    mem.write_u64(addr + 24, mask);
}

#[test]
fn sigaction_sigprocmask_sigpending_and_sigaltstack_both_abis() {
    for abi in ABIS {
        let mut mem = Mem::new(0x10_0000, 0x2_0000);
        let mut platform = TestPlatform::new(1_000_000_000);
        let mut thread = TestThread::new(0x10_8000);
        let mut proc = Process::<NoBacking>::new(abi, NonZeroU32::new(1).unwrap(), PROGRAM_BREAK);

        // SIGKILL/SIGSTOP refused on write, allowed on read-only query.
        write_sigaction(&mem, 0x10_0100, 0x40_1000, SA_RESTORER, 0x40_2000, 0);
        assert_eq!(
            call_now(
                &mut proc,
                abi,
                Operation::RtSigaction,
                [9, 0x10_0100, 0, 8, 0, 0],
                &mut mem,
                &mut thread,
                &mut platform
            ),
            SyscallOutcome::Return(err(EINVAL))
        );
        assert_eq!(
            call_now(
                &mut proc,
                abi,
                Operation::RtSigaction,
                [19, 0, 0x10_0200, 8, 0, 0],
                &mut mem,
                &mut thread,
                &mut platform
            ),
            SyscallOutcome::Return(0)
        );
        assert_eq!(mem.read_u64(0x10_0200), 0);

        // Install handler on SIGUSR1 with SIGKILL|SIGSTOP|SIGUSR2 in sa_mask:
        // uncatchable bits must be stripped on readback.
        let mask_in = Signal::SIGKILL.bit() | Signal::SIGSTOP.bit() | Signal::SIGUSR2.bit();
        write_sigaction(
            &mem,
            0x10_0100,
            0x40_1000,
            SA_SIGINFO | SA_RESTART | SA_RESTORER,
            0x40_2000,
            mask_in,
        );
        assert_eq!(
            call_now(
                &mut proc,
                abi,
                Operation::RtSigaction,
                [10, 0x10_0100, 0x10_0200, 8, 0, 0],
                &mut mem,
                &mut thread,
                &mut platform
            ),
            SyscallOutcome::Return(0)
        );
        assert_eq!(
            call_now(
                &mut proc,
                abi,
                Operation::RtSigaction,
                [10, 0, 0x10_0200, 8, 0, 0],
                &mut mem,
                &mut thread,
                &mut platform
            ),
            SyscallOutcome::Return(0)
        );
        assert_eq!(mem.read_u64(0x10_0200), 0x40_1000);
        assert_eq!(
            mem.read_u64(0x10_0208),
            SA_SIGINFO | SA_RESTART | SA_RESTORER
        );
        assert_eq!(mem.read_u64(0x10_0210), 0x40_2000);
        assert_eq!(mem.read_u64(0x10_0218), Signal::SIGUSR2.bit());

        // Block SIGUSR1 + SIGKILL -> SIGKILL stripped, SIGUSR1 pending visible.
        mem.write_u64(0x10_0300, Signal::SIGUSR1.bit() | Signal::SIGKILL.bit());
        assert_eq!(
            call_now(
                &mut proc,
                abi,
                Operation::RtSigprocmask,
                [0, 0x10_0300, 0x10_0308, 8, 0, 0],
                &mut mem,
                &mut thread,
                &mut platform
            ),
            SyscallOutcome::Return(0)
        );
        assert_eq!(mem.read_u64(0x10_0308), 0);
        assert_eq!(
            call_now(
                &mut proc,
                abi,
                Operation::Kill,
                [1, 10, 0, 0, 0, 0],
                &mut mem,
                &mut thread,
                &mut platform
            ),
            SyscallOutcome::Return(0)
        );
        assert_eq!(
            call_now(
                &mut proc,
                abi,
                Operation::RtSigpending,
                [0x10_0310, 8, 0, 0, 0, 0],
                &mut mem,
                &mut thread,
                &mut platform
            ),
            SyscallOutcome::Return(0)
        );
        assert_eq!(mem.read_u64(0x10_0310), Signal::SIGUSR1.bit());

        // sigaltstack rejects < MINSIGSTKSZ with ENOMEM, accepts valid + SS_AUTODISARM,
        // and rejects modification while on stack with EPERM.
        mem.write_u64(0x10_0400, 0x11_0000);
        mem.write_bytes(0x10_0408, &0u32.to_le_bytes());
        mem.write_u64(0x10_0410, abi.min_sigstksz() - 1);
        assert_eq!(
            call_now(
                &mut proc,
                abi,
                Operation::Sigaltstack,
                [0x10_0400, 0, 0, 0, 0, 0],
                &mut mem,
                &mut thread,
                &mut platform
            ),
            SyscallOutcome::Return(err(ENOMEM))
        );

        mem.write_u64(0x10_0400, 0x11_0000);
        mem.write_bytes(0x10_0408, &SS_AUTODISARM.to_le_bytes());
        mem.write_u64(0x10_0410, 0x4000);
        assert_eq!(
            call_now(
                &mut proc,
                abi,
                Operation::Sigaltstack,
                [0x10_0400, 0x10_0420, 0, 0, 0, 0],
                &mut mem,
                &mut thread,
                &mut platform
            ),
            SyscallOutcome::Return(0)
        );
        assert_eq!(mem.read_i32(0x10_0428) as u32, SS_DISABLE);

        // Pretend SP is inside the altstack -> query shows SS_ONSTACK | SS_AUTODISARM,
        // update returns EPERM.
        thread.sp = 0x11_2000;
        assert_eq!(
            call_now(
                &mut proc,
                abi,
                Operation::Sigaltstack,
                [0, 0x10_0420, 0, 0, 0, 0],
                &mut mem,
                &mut thread,
                &mut platform
            ),
            SyscallOutcome::Return(0)
        );
        assert_eq!(mem.read_i32(0x10_0428) as u32, SS_ONSTACK | SS_AUTODISARM);
        assert_eq!(
            call_now(
                &mut proc,
                abi,
                Operation::Sigaltstack,
                [0x10_0400, 0, 0, 0, 0, 0],
                &mut mem,
                &mut thread,
                &mut platform
            ),
            SyscallOutcome::Return(err(EPERM))
        );
    }
}

#[test]
fn container_pid_namespace_isolation_and_kill_permissions() {
    let ns_a = PidNamespace::new();
    let ns_b = PidNamespace::new();
    let pid_a1 = ns_a.allocate_process().unwrap();
    let pid_a2 = ns_a.allocate_process().unwrap();
    let pid_b1 = ns_b.allocate_process().unwrap();
    assert_eq!(pid_a1.get(), 1);
    assert_eq!(pid_a2.get(), 2);
    assert_eq!(pid_b1.get(), 1);

    let mut proc_a1 = Process::<NoBacking>::with_descriptors(
        Abi::X86_64,
        pid_a1,
        PROGRAM_BREAK,
        standard_streams::<NoBacking>(),
        Start {
            credentials: Credentials::try_for_ids(1000, 1000, Vec::new()).unwrap(),
            pids: Some(ns_a.clone()),
            ..Start::default()
        },
    );
    let proc_a2 = Process::<NoBacking>::with_descriptors(
        Abi::X86_64,
        pid_a2,
        PROGRAM_BREAK,
        standard_streams::<NoBacking>(),
        Start {
            credentials: Credentials::try_for_ids(2000, 2000, Vec::new()).unwrap(),
            pids: Some(ns_a.clone()),
            ..Start::default()
        },
    );
    let mut proc_b1 = Process::<NoBacking>::with_descriptors(
        Abi::X86_64,
        pid_b1,
        PROGRAM_BREAK,
        standard_streams::<NoBacking>(),
        Start {
            credentials: Credentials::root(),
            pids: Some(ns_b.clone()),
            ..Start::default()
        },
    );

    let mut mem = Mem::new(0x10_0000, 0x1_0000);
    let mut platform = TestPlatform::new(0);
    let mut thread = TestThread::new(0x10_8000);

    // Unprivileged proc_a1 (uid 1000) cannot kill proc_a2 (uid 2000) -> EPERM.
    assert_eq!(
        call_now(
            &mut proc_a1,
            Abi::X86_64,
            Operation::Kill,
            [2, 10, 0, 0, 0, 0],
            &mut mem,
            &mut thread,
            &mut platform
        ),
        SyscallOutcome::Return(err(EPERM))
    );
    assert!(proc_a2.thread_signals().pending_set().is_empty());

    // Root proc_b1 in container B cannot see PID 2 (which only exists in container A) -> ESRCH.
    assert_eq!(
        call_now(
            &mut proc_b1,
            Abi::X86_64,
            Operation::Kill,
            [2, 0, 0, 0, 0, 0],
            &mut mem,
            &mut thread,
            &mut platform
        ),
        SyscallOutcome::Return(err(ESRCH))
    );
    // Root proc_b1 killing PID 1 signals ONLY itself, never container A's PID 1.
    proc_b1
        .thread_signals()
        .set_mask(SignalSet::EMPTY.with(Signal::SIGUSR1));
    assert_eq!(
        call_now(
            &mut proc_b1,
            Abi::X86_64,
            Operation::Kill,
            [1, 10, 0, 0, 0, 0],
            &mut mem,
            &mut thread,
            &mut platform
        ),
        SyscallOutcome::Return(0)
    );
    assert!(
        proc_b1
            .thread_signals()
            .pending_set()
            .contains(Signal::SIGUSR1)
    );
    assert!(proc_a1.thread_signals().pending_set().is_empty());
}

#[test]
fn restart_vs_eintr_sigsuspend_and_fault_delivery_both_abis() {
    for abi in ABIS {
        let mut mem = Mem::new(0x10_0000, 0x2_0000);
        let mut platform = TestPlatform::new(1_000_000);
        let mut thread = TestThread::new(0x10_8000);
        let mut proc = Process::<NoBacking>::new(abi, NonZeroU32::new(1).unwrap(), PROGRAM_BREAK);

        // Install SA_RESTART handler on SIGUSR1 and non-restart handler on SIGUSR2.
        write_sigaction(
            &mem,
            0x10_0100,
            0x40_5000,
            SA_RESTART | SA_RESTORER,
            0x40_6000,
            0,
        );
        call_now(
            &mut proc,
            abi,
            Operation::RtSigaction,
            [10, 0x10_0100, 0, 8, 0, 0],
            &mut mem,
            &mut thread,
            &mut platform,
        );
        write_sigaction(&mem, 0x10_0100, 0x40_7000, SA_RESTORER, 0x40_6000, 0);
        call_now(
            &mut proc,
            abi,
            Operation::RtSigaction,
            [12, 0x10_0100, 0, 8, 0, 0],
            &mut mem,
            &mut thread,
            &mut platform,
        );

        // 1. RestartSys with SA_RESTART handler rolls back PC and restores orig_reg.
        let mut ctx = FakeContext::new(abi, 0x10_8000, 0x40_1004);
        proc.raise_external_signal(Signal::SIGUSR1);
        assert_eq!(
            proc.deliver_pending_signals(
                &mut ctx,
                &mut mem,
                Some(SyscallRestart::RestartSys { orig_reg: 99 }),
                0x70_0000
            ),
            SignalDelivery::Delivered
        );
        // Simulate handler returning via rt_sigreturn.
        if abi == Abi::X86_64 {
            let sp = ctx.register(RegisterId::X86Gpr(4)).unwrap();
            ctx.set_register(RegisterId::X86Gpr(4), sp + 8).unwrap();
        }
        proc.restore_signal_frame(&mut ctx, &mem).unwrap();
        assert_eq!(
            ctx.register(abi.program_counter_register()).unwrap(),
            0x40_1004 - abi.syscall_instruction_bytes()
        );
        assert_eq!(
            ctx.register(abi.system_call_registers().result).unwrap(),
            99
        );

        // 2. RestartSys without SA_RESTART writes -EINTR and leaves PC untouched.
        let mut ctx = FakeContext::new(abi, 0x10_8000, 0x40_2004);
        proc.raise_external_signal(Signal::SIGUSR2);
        assert_eq!(
            proc.deliver_pending_signals(
                &mut ctx,
                &mut mem,
                Some(SyscallRestart::RestartSys { orig_reg: 77 }),
                0x70_0000
            ),
            SignalDelivery::Delivered
        );
        if abi == Abi::X86_64 {
            let sp = ctx.register(RegisterId::X86Gpr(4)).unwrap();
            ctx.set_register(RegisterId::X86Gpr(4), sp + 8).unwrap();
        }
        proc.restore_signal_frame(&mut ctx, &mem).unwrap();
        assert_eq!(
            ctx.register(abi.program_counter_register()).unwrap(),
            0x40_2004
        );
        assert_eq!(
            ctx.register(abi.system_call_registers().result).unwrap(),
            err(EINTR)
        );

        // 3. RestartNoHand (pause / sigsuspend / epoll_pwait) writes -EINTR EVEN with SA_RESTART.
        let mut ctx = FakeContext::new(abi, 0x10_8000, 0x40_3004);
        proc.raise_external_signal(Signal::SIGUSR1);
        assert_eq!(
            proc.deliver_pending_signals(
                &mut ctx,
                &mut mem,
                Some(SyscallRestart::RestartNoHand { orig_reg: 34 }),
                0x70_0000
            ),
            SignalDelivery::Delivered
        );
        if abi == Abi::X86_64 {
            let sp = ctx.register(RegisterId::X86Gpr(4)).unwrap();
            ctx.set_register(RegisterId::X86Gpr(4), sp + 8).unwrap();
        }
        proc.restore_signal_frame(&mut ctx, &mem).unwrap();
        assert_eq!(
            ctx.register(abi.system_call_registers().result).unwrap(),
            err(EINTR)
        );

        // 4. Fault delivery: caught SIGSEGV delivers handler frame; masked SIGSEGV
        // forces default termination (`force_sig_fault`).
        write_sigaction(
            &mem,
            0x10_0100,
            0x40_8000,
            SA_SIGINFO | SA_RESTORER | SA_ONSTACK | SA_NODEFER | SA_RESETHAND,
            0x40_6000,
            0,
        );
        call_now(
            &mut proc,
            abi,
            Operation::RtSigaction,
            [11, 0x10_0100, 0, 8, 0, 0],
            &mut mem,
            &mut thread,
            &mut platform,
        );
        let fault = UserFault {
            kind: FaultKind::Page {
                address: VirtAddr::new(0x12_3456),
                access: PageFlags::WRITE,
                present: true,
            },
            instruction: VirtAddr::new(0x40_4000),
        };
        let mut ctx = FakeContext::new(abi, 0x10_8000, 0x40_4000);
        assert_eq!(
            proc.deliver_fault_signal(fault, &mut ctx, &mut mem, 0x70_0000),
            SignalDelivery::Delivered
        );
        // Check `siginfo_t` carries `SEGV_ACCERR` and `si_addr = 0x12_3456`.
        let info_addr = match abi {
            Abi::X86_64 => ctx.register(RegisterId::X86Gpr(6)).unwrap(),
            Abi::Aarch64 => ctx.register(RegisterId::Aarch64X(1)).unwrap(),
        };
        assert_eq!(mem.read_i32(info_addr), 11);
        assert_eq!(mem.read_i32(info_addr + 8), SEGV_ACCERR);
        assert_eq!(mem.read_u64(info_addr + 16), 0x12_3456);

        // SA_RESETHAND reset SIGSEGV to SIG_DFL -> second fault terminates!
        assert_eq!(
            proc.deliver_fault_signal(fault, &mut ctx, &mut mem, 0x70_0000),
            SignalDelivery::Terminated {
                signal: Signal::SIGSEGV,
                core_dumped: true,
            }
        );
    }
}

#[test]
fn timers_alarm_itimer_and_pipe_sigpipe() {
    let mut mem = Mem::new(0x10_0000, 0x1_0000);
    let mut platform = TestPlatform::new(1_000_000_000);
    let mut thread = TestThread::new(0x10_8000);
    let mut proc =
        Process::<NoBacking>::new(Abi::X86_64, NonZeroU32::new(1).unwrap(), PROGRAM_BREAK);

    // Block SIGALRM, SIGVTALRM, SIGPROF so we can observe pending bits deterministically.
    let all_timers = Signal::SIGALRM.bit() | Signal::SIGVTALRM.bit() | Signal::SIGPROF.bit();
    proc.thread_signals()
        .set_mask(SignalSet::from_bits(all_timers));

    // alarm(3) -> 0; advance 1.2s -> alarm(0) returns 2 (rounded from 1.8s).
    assert_eq!(
        call_now(
            &mut proc,
            Abi::X86_64,
            Operation::Alarm,
            [3, 0, 0, 0, 0, 0],
            &mut mem,
            &mut thread,
            &mut platform
        ),
        SyscallOutcome::Return(0)
    );
    platform.now_ns.store(2_200_000_000, Ordering::Relaxed);
    assert_eq!(
        call_now(
            &mut proc,
            Abi::X86_64,
            Operation::Alarm,
            [0, 0, 0, 0, 0, 0],
            &mut mem,
            &mut thread,
            &mut platform
        ),
        SyscallOutcome::Return(2)
    );

    // ITIMER_REAL fires at deadline and reloads interval.
    mem.write_u64(0x10_0100, 0);
    mem.write_u64(0x10_0108, 50_000); // interval = 50ms
    mem.write_u64(0x10_0110, 0);
    mem.write_u64(0x10_0118, 20_000); // value = 20ms
    assert_eq!(
        call_now(
            &mut proc,
            Abi::X86_64,
            Operation::Setitimer,
            [0, 0x10_0100, 0, 0, 0, 0],
            &mut mem,
            &mut thread,
            &mut platform
        ),
        SyscallOutcome::Return(0)
    );
    assert!(!proc.process_signals().fire_real_timer_if_due(2_210_000_000));
    assert!(proc.process_signals().fire_real_timer_if_due(2_220_000_000));
    assert!(
        proc.thread_signals()
            .pending_set()
            .contains(Signal::SIGALRM)
    );
    // Reloaded for +50ms.
    let (next_deadline, _) = proc.process_signals().next_real_timer_deadline().unwrap();
    assert_eq!(next_deadline, 2_270_000_000);

    // Unwritable `old_value` must fail with EFAULT without mutating the armed timer.
    let before_fault = proc.process_signals().next_real_timer_deadline().unwrap();
    mem.write_u64(0x10_0108, 0);
    mem.write_u64(0x10_0118, 0);
    assert_eq!(
        call_now(
            &mut proc,
            Abi::X86_64,
            Operation::Setitimer,
            [0, 0x10_0100, 0x1, 0, 0, 0],
            &mut mem,
            &mut thread,
            &mut platform
        ),
        SyscallOutcome::Return(err(EFAULT))
    );
    assert_eq!(
        proc.process_signals().next_real_timer_deadline(),
        Some(before_fault)
    );

    // ITIMER_VIRTUAL and ITIMER_PROF fire when CPU time is accounted.
    mem.write_u64(0x10_0108, 0);
    mem.write_u64(0x10_0118, 10_000); // 10ms
    assert_eq!(
        call_now(
            &mut proc,
            Abi::X86_64,
            Operation::Setitimer,
            [1, 0x10_0100, 0, 0, 0, 0],
            &mut mem,
            &mut thread,
            &mut platform
        ),
        SyscallOutcome::Return(0)
    );
    assert_eq!(
        call_now(
            &mut proc,
            Abi::X86_64,
            Operation::Setitimer,
            [2, 0x10_0100, 0, 0, 0, 0],
            &mut mem,
            &mut thread,
            &mut platform
        ),
        SyscallOutcome::Return(0)
    );
    // Kernel-only time (0 user, 10ms total) fires SIGPROF but not SIGVTALRM.
    proc.account_cpu_timers(0, 10_000_000);
    assert!(
        proc.thread_signals()
            .pending_set()
            .contains(Signal::SIGPROF)
    );
    assert!(
        !proc
            .thread_signals()
            .pending_set()
            .contains(Signal::SIGVTALRM)
    );
    // User time (10ms) fires SIGVTALRM.
    proc.account_cpu_timers(10_000_000, 10_000_000);
    assert!(
        proc.thread_signals()
            .pending_set()
            .contains(Signal::SIGVTALRM)
    );

    // Pipe write with closed reader raises SIGPIPE and returns -EPIPE.
    proc.thread_signals()
        .set_mask(SignalSet::EMPTY.with(Signal::SIGPIPE));
    assert_eq!(
        call_now(
            &mut proc,
            Abi::X86_64,
            Operation::Pipe2,
            [0x10_0200, 0, 0, 0, 0, 0],
            &mut mem,
            &mut thread,
            &mut platform
        ),
        SyscallOutcome::Return(0)
    );
    let rfd = mem.read_i32(0x10_0200) as u64;
    let wfd = mem.read_i32(0x10_0204) as u64;
    assert_eq!(
        call_now(
            &mut proc,
            Abi::X86_64,
            Operation::Close,
            [rfd, 0, 0, 0, 0, 0],
            &mut mem,
            &mut thread,
            &mut platform
        ),
        SyscallOutcome::Return(0)
    );
    assert_eq!(
        call_now(
            &mut proc,
            Abi::X86_64,
            Operation::Write,
            [wfd, 0x10_0200, 1, 0, 0, 0],
            &mut mem,
            &mut thread,
            &mut platform
        ),
        SyscallOutcome::Return(err(EPIPE))
    );
    assert!(
        proc.thread_signals()
            .pending_set()
            .contains(Signal::SIGPIPE)
    );

    // rt_sigtimedwait zero-timeout consumes pending SIGPIPE immediately, then EAGAIN.
    mem.write_u64(0x10_0300, Signal::SIGPIPE.bit());
    mem.write_u64(0x10_0310, 0);
    mem.write_u64(0x10_0318, 0);
    assert_eq!(
        call_now(
            &mut proc,
            Abi::X86_64,
            Operation::RtSigtimedwait,
            [0x10_0300, 0x10_0320, 0x10_0310, 8, 0, 0],
            &mut mem,
            &mut thread,
            &mut platform
        ),
        SyscallOutcome::Return(13)
    );
    assert_eq!(mem.read_i32(0x10_0320), 13);
    assert_eq!(
        call_now(
            &mut proc,
            Abi::X86_64,
            Operation::RtSigtimedwait,
            [0x10_0300, 0x10_0320, 0x10_0310, 8, 0, 0],
            &mut mem,
            &mut thread,
            &mut platform
        ),
        SyscallOutcome::Return(err(EAGAIN))
    );
}
