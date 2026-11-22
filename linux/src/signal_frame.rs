//! Architecture-specific Linux `rt_sigframe` construction and `rt_sigreturn`
//! restoration for x86-64 and AArch64.
//!
//! Layouts and constants follow Linux v6.12:
//! - Common `siginfo_t` (`include/uapi/asm-generic/siginfo.h`) and `stack_t`
//!   (`include/uapi/asm-generic/signal.h`).
//! - x86-64 `struct rt_sigframe`, `struct ucontext`, `struct sigcontext`, and
//!   `struct _fpx_sw_bytes` (`arch/x86/include/asm/sigframe.h`,
//!   `arch/x86/include/uapi/asm/ucontext.h`,
//!   `arch/x86/include/uapi/asm/sigcontext.h`, `arch/x86/kernel/signal_64.c`).
//! - AArch64 `struct rt_sigframe`, `struct ucontext`, `struct sigcontext`, and
//!   `struct fpsimd_context` (`arch/arm64/include/uapi/asm/ucontext.h`,
//!   `arch/arm64/include/uapi/asm/sigcontext.h`, `arch/arm64/kernel/signal.c`).
//!
//! All reads and writes go through [`UserMemory`]; this module never
//! dereferences guest addresses directly.

use alloc::boxed::Box;
use alloc::vec;
use helios_hal::hv::RegisterId;
use helios_hal::native::{Aarch64FpSimd, ExtendedState, FaultKind, UserContext, UserFault};
use helios_unix::{Signal, SignalSet};
use thiserror::Error;

use crate::abi::Abi;
use crate::syscall::UserMemory;

/// Linux `sigaction` flags (`include/uapi/asm-generic/signal-defs.h`,
/// `arch/x86/include/uapi/asm/signal.h`, `arch/arm64/include/uapi/asm/signal.h`).
pub const SA_NOCLDSTOP: u64 = 0x0000_0001;
pub const SA_NOCLDWAIT: u64 = 0x0000_0002;
pub const SA_SIGINFO: u64 = 0x0000_0004;
pub const SA_RESTORER: u64 = 0x0400_0000;
pub const SA_ONSTACK: u64 = 0x0800_0000;
pub const SA_RESTART: u64 = 0x1000_0000;
pub const SA_NODEFER: u64 = 0x4000_0000;
pub const SA_RESETHAND: u64 = 0x8000_0000;

/// Linux `sigaltstack` flags (`include/uapi/asm-generic/signal.h`).
pub const SS_ONSTACK: u32 = 1;
pub const SS_DISABLE: u32 = 2;
pub const SS_AUTODISARM: u32 = 1 << 31;

/// Linux `siginfo_t` `si_code` values (`include/uapi/asm-generic/siginfo.h`).
pub const SI_USER: i32 = 0;
pub const SI_KERNEL: i32 = 0x80;
pub const SI_TIMER: i32 = -2;
pub const SI_TKILL: i32 = -6;
pub const ILL_ILLOPC: i32 = 1;
pub const FPE_INTDIV: i32 = 1;
pub const SEGV_MAPERR: i32 = 1;
pub const SEGV_ACCERR: i32 = 2;
pub const BUS_ADRALN: i32 = 1;
pub const BUS_ADRERR: i32 = 2;
pub const TRAP_BRKPT: i32 = 1;

/// Size of Linux `siginfo_t` (`SI_MAX_SIZE`, `include/uapi/asm-generic/siginfo.h`).
pub const SIGINFO_SIZE: usize = 128;
/// Size of Linux LP64 `stack_t` (`include/uapi/asm-generic/signal.h`).
pub const STACK_T_SIZE: usize = 24;

// x86-64 signal frame layout constants (`arch/x86/include/uapi/asm/ucontext.h`,
// `arch/x86/include/uapi/asm/sigcontext.h`, `arch/x86/kernel/signal_64.c`).
const X86_RED_ZONE: u64 = 128;
const X86_UC_FP_XSTATE: u64 = 1;
const X86_FP_XSTATE_MAGIC1: u32 = 0x4650_5853;
const X86_FP_XSTATE_MAGIC2: u32 = 0x4650_5845;
const X86_FXSAVE_SIZE: usize = 512;
const X86_SW_RESERVED_OFFSET: usize = 464;
const X86_UC_FLAGS_OFFSET: usize = 0;
const X86_UC_LINK_OFFSET: usize = 8;
const X86_UC_STACK_OFFSET: usize = 16;
const X86_UC_MCONTEXT_OFFSET: usize = 40;
const X86_UC_SIGMASK_OFFSET: usize = 296;
/// Space reserved for `ucontext_t` inside `rt_sigframe`: covers the full
/// 128-byte musl/glibc `sigset_t` at `uc_sigmask` (`296 + 128 = 424`) so
/// `sigemptyset(&uc->uc_sigmask)` cannot overwrite the following `siginfo_t`.
const X86_UCONTEXT_ALLOC_SIZE: usize = 424;
const X86_FRAME_UC_OFFSET: usize = 8;
const X86_FRAME_INFO_OFFSET: usize = X86_FRAME_UC_OFFSET + X86_UCONTEXT_ALLOC_SIZE;
const X86_RT_SIGFRAME_SIZE: usize = X86_FRAME_INFO_OFFSET + SIGINFO_SIZE;
// User code/data selectors matching `helios-x86` (`USER_CODE = 0x2b`/`0x33`,
// standard ring-3 Linux CS=0x33, SS=0x2b).
const X86_USER_CS: u16 = 0x33;
const X86_USER_SS: u16 = 0x2b;
const X86_RFLAGS_TF: u64 = 1 << 8;
const X86_RFLAGS_DF: u64 = 1 << 10;
const X86_RFLAGS_FIXED: u64 = 0x202;

// AArch64 signal frame layout constants (`arch/arm64/include/uapi/asm/ucontext.h`,
// `arch/arm64/include/uapi/asm/sigcontext.h`, `arch/arm64/kernel/signal.c`).
const AARCH64_FPSIMD_MAGIC: u32 = 0x4650_8001;
const AARCH64_FPSIMD_SIZE: u32 = 0x210;
const AARCH64_RESERVED_SIZE: usize = 4096;
const AARCH64_UC_FLAGS_OFFSET: usize = 0;
const AARCH64_UC_LINK_OFFSET: usize = 8;
const AARCH64_UC_STACK_OFFSET: usize = 16;
const AARCH64_UC_SIGMASK_OFFSET: usize = 40;
const AARCH64_UC_MCONTEXT_OFFSET: usize = 176;
const AARCH64_MCONTEXT_FAULT_ADDR: usize = 0;
const AARCH64_MCONTEXT_REGS: usize = 8;
const AARCH64_MCONTEXT_SP: usize = 256;
const AARCH64_MCONTEXT_PC: usize = 264;
const AARCH64_MCONTEXT_PSTATE: usize = 272;
const AARCH64_MCONTEXT_RESERVED: usize = 288;
const AARCH64_UCONTEXT_SIZE: usize =
    AARCH64_UC_MCONTEXT_OFFSET + AARCH64_MCONTEXT_RESERVED + AARCH64_RESERVED_SIZE;
const AARCH64_FRAME_INFO_OFFSET: usize = 0;
const AARCH64_FRAME_UC_OFFSET: usize = SIGINFO_SIZE;
const AARCH64_RT_SIGFRAME_SIZE: usize = AARCH64_FRAME_UC_OFFSET + AARCH64_UCONTEXT_SIZE;

/// Why building or restoring a signal frame failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum SignalFrameError {
    #[error("user memory fault while reading or writing signal frame")]
    MemoryFault,
    #[error("signal frame contains an invalid register or address value")]
    InvalidContext,
    #[error("signal frame contains invalid floating-point or vector state")]
    InvalidExtendedState,
}

/// Signal payload fields carried by Linux `siginfo_t`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigInfoPayload {
    /// Sender PID and real UID (`SI_USER`, `SI_TKILL`).
    Kill { pid: u32, uid: u32 },
    /// Faulting memory or instruction address (`SIGSEGV`, `SIGBUS`, `SIGILL`,
    /// `SIGFPE`, `SIGTRAP`).
    Fault { addr: u64 },
    /// Kernel-originated signal with no extra fields (`SI_KERNEL`, `SI_TIMER`).
    None,
}

/// Structured Linux `siginfo_t` (`include/uapi/asm-generic/siginfo.h`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SigInfo {
    pub signo: Signal,
    pub errno: i32,
    pub code: i32,
    pub payload: SigInfoPayload,
}

impl SigInfo {
    pub const fn from_kill(signo: Signal, pid: u32, uid: u32) -> Self {
        Self {
            signo,
            errno: 0,
            code: SI_USER,
            payload: SigInfoPayload::Kill { pid, uid },
        }
    }

    pub const fn from_tkill(signo: Signal, pid: u32, uid: u32) -> Self {
        Self {
            signo,
            errno: 0,
            code: SI_TKILL,
            payload: SigInfoPayload::Kill { pid, uid },
        }
    }

    pub const fn from_kernel(signo: Signal) -> Self {
        Self {
            signo,
            errno: 0,
            code: SI_KERNEL,
            payload: SigInfoPayload::None,
        }
    }

    pub const fn from_timer(signo: Signal) -> Self {
        Self {
            signo,
            errno: 0,
            code: SI_TIMER,
            payload: SigInfoPayload::None,
        }
    }

    /// Translates a hardware [`UserFault`] into the Linux signal and `siginfo_t`
    /// (`arch/x86/kernel/traps.c`, `arch/x86/mm/fault.c`,
    /// `arch/arm64/kernel/traps.c`, `arch/arm64/mm/fault.c`).
    pub fn from_fault(fault: UserFault) -> (Self, u64) {
        let instruction = fault.instruction.raw() as u64;
        match fault.kind {
            FaultKind::Page {
                address, present, ..
            } => {
                let addr = address.raw() as u64;
                let code = if present { SEGV_ACCERR } else { SEGV_MAPERR };
                (
                    Self {
                        signo: Signal::SIGSEGV,
                        errno: 0,
                        code,
                        payload: SigInfoPayload::Fault { addr },
                    },
                    addr,
                )
            }
            FaultKind::Protection => (Self::from_kernel(Signal::SIGSEGV), 0),
            FaultKind::InvalidInstruction => (
                Self {
                    signo: Signal::SIGILL,
                    errno: 0,
                    code: ILL_ILLOPC,
                    payload: SigInfoPayload::Fault { addr: instruction },
                },
                instruction,
            ),
            FaultKind::Arithmetic => (
                Self {
                    signo: Signal::SIGFPE,
                    errno: 0,
                    code: FPE_INTDIV,
                    payload: SigInfoPayload::Fault { addr: instruction },
                },
                instruction,
            ),
            FaultKind::Alignment => (
                Self {
                    signo: Signal::SIGBUS,
                    errno: 0,
                    code: BUS_ADRALN,
                    payload: SigInfoPayload::Fault { addr: instruction },
                },
                instruction,
            ),
            FaultKind::Bus => (
                Self {
                    signo: Signal::SIGBUS,
                    errno: 0,
                    code: BUS_ADRERR,
                    payload: SigInfoPayload::Fault { addr: instruction },
                },
                instruction,
            ),
            FaultKind::Breakpoint => (
                Self {
                    signo: Signal::SIGTRAP,
                    errno: 0,
                    code: TRAP_BRKPT,
                    payload: SigInfoPayload::Fault { addr: instruction },
                },
                instruction,
            ),
        }
    }

    /// Encodes the 128-byte Linux LP64 `siginfo_t`.
    pub fn encode(self) -> [u8; SIGINFO_SIZE] {
        let mut bytes = [0u8; SIGINFO_SIZE];
        write_i32(&mut bytes, 0, i32::from(self.signo.raw()));
        write_i32(&mut bytes, 4, self.errno);
        write_i32(&mut bytes, 8, self.code);
        match self.payload {
            SigInfoPayload::Kill { pid, uid } => {
                write_u32(&mut bytes, 16, pid);
                write_u32(&mut bytes, 20, uid);
            }
            SigInfoPayload::Fault { addr } => {
                write_u64(&mut bytes, 16, addr);
            }
            SigInfoPayload::None => {}
        }
        bytes
    }
}

/// Per-thread alternate signal stack (`sigaltstack(2)`, `kernel/signal.c`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SigAltStack {
    pub sp: u64,
    pub size: u64,
    /// `SS_DISABLE` when disabled, otherwise `0` or `SS_AUTODISARM`.
    pub flags: u32,
}

impl Default for SigAltStack {
    fn default() -> Self {
        Self::disabled()
    }
}

impl SigAltStack {
    pub const fn disabled() -> Self {
        Self {
            sp: 0,
            size: 0,
            flags: SS_DISABLE,
        }
    }

    pub const fn is_disabled(self) -> bool {
        self.flags & SS_DISABLE != 0 || self.size == 0
    }

    /// Whether `stack_pointer` lies inside this alternate stack
    /// (`include/linux/sched/signal.h` `on_sig_stack`).
    pub const fn on_stack(self, stack_pointer: u64) -> bool {
        if self.is_disabled() {
            return false;
        }
        stack_pointer > self.sp && stack_pointer.saturating_sub(self.sp) <= self.size
    }

    /// Reports the current `ss_flags` value (`kernel/signal.c` `sas_ss_flags`
    /// plus `SS_AUTODISARM`).
    pub const fn reported_flags(self, stack_pointer: u64) -> u32 {
        if self.is_disabled() {
            SS_DISABLE
        } else {
            let active = if self.on_stack(stack_pointer) {
                SS_ONSTACK
            } else {
                0
            };
            active | (self.flags & SS_AUTODISARM)
        }
    }

    /// Encodes Linux LP64 `stack_t` (24 bytes).
    pub fn encode_stack_t(self, stack_pointer: u64) -> [u8; STACK_T_SIZE] {
        let mut bytes = [0u8; STACK_T_SIZE];
        write_u64(&mut bytes, 0, self.sp);
        write_u32(&mut bytes, 8, self.reported_flags(stack_pointer));
        write_u64(&mut bytes, 16, self.size);
        bytes
    }

    /// Decodes Linux LP64 `stack_t` into `(ss_sp, ss_flags, ss_size)`.
    pub fn decode_stack_t(bytes: &[u8; STACK_T_SIZE]) -> (u64, u32, u64) {
        let sp = read_u64(bytes, 0);
        let flags = read_u32(bytes, 8);
        let size = read_u64(bytes, 16);
        (sp, flags, size)
    }

    /// Top of the alternate stack (`ss_sp + ss_size`, checked for overflow).
    pub fn top(self) -> Option<u64> {
        self.sp.checked_add(self.size)
    }
}

/// Inputs required to construct a signal delivery frame on the user stack.
#[derive(Clone, Copy, Debug)]
pub struct FrameDeliveryInput {
    pub abi: Abi,
    pub info: SigInfo,
    pub handler: u64,
    pub restorer: u64,
    pub flags: u64,
    pub saved_mask: SignalSet,
    pub altstack: SigAltStack,
    pub sigreturn_trampoline: u64,
    pub fault_address: u64,
}

/// State recovered from `ucontext_t` by `rt_sigreturn`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RestoredFrame {
    pub sigmask: SignalSet,
    pub uc_stack_sp: u64,
    pub uc_stack_flags: u32,
    pub uc_stack_size: u64,
}

/// Builds a signal frame on the user stack (or alternate stack when
/// `SA_ONSTACK` applies) and updates `context` to enter the signal handler.
///
/// Returns `true` if delivery switched onto the alternate stack (so the caller
/// can apply `SS_AUTODISARM` when set).
pub fn setup_signal_frame<C: UserContext, M: UserMemory>(
    context: &mut C,
    memory: &mut M,
    input: FrameDeliveryInput,
) -> Result<bool, SignalFrameError> {
    match input.abi {
        Abi::X86_64 => setup_x86_64_frame(context, memory, input),
        Abi::Aarch64 => setup_aarch64_frame(context, memory, input),
    }
}

/// Restores `context`'s general and extended registers from the signal frame
/// currently on the user stack (`rt_sigreturn`), returning the saved signal
/// mask and `uc_stack` for the caller to reinstall.
pub fn restore_signal_frame<C: UserContext, M: UserMemory>(
    abi: Abi,
    context: &mut C,
    memory: &M,
) -> Result<RestoredFrame, SignalFrameError> {
    match abi {
        Abi::X86_64 => restore_x86_64_frame(context, memory),
        Abi::Aarch64 => restore_aarch64_frame(context, memory),
    }
}

fn choose_stack(current_sp: u64, flags: u64, altstack: SigAltStack) -> (u64, bool) {
    if flags & SA_ONSTACK != 0
        && !altstack.is_disabled()
        && !altstack.on_stack(current_sp)
        && let Some(top) = altstack.top()
    {
        return (top, true);
    }
    (current_sp, false)
}

fn setup_x86_64_frame<C: UserContext, M: UserMemory>(
    context: &mut C,
    memory: &mut M,
    input: FrameDeliveryInput,
) -> Result<bool, SignalFrameError> {
    let reg = |id| {
        context
            .register(id)
            .map_err(|_| SignalFrameError::InvalidContext)
    };
    let old_rax = reg(RegisterId::X86Gpr(0))?;
    let old_rcx = reg(RegisterId::X86Gpr(1))?;
    let old_rdx = reg(RegisterId::X86Gpr(2))?;
    let old_rbx = reg(RegisterId::X86Gpr(3))?;
    let old_rsp = reg(RegisterId::X86Gpr(4))?;
    let old_rbp = reg(RegisterId::X86Gpr(5))?;
    let old_rsi = reg(RegisterId::X86Gpr(6))?;
    let old_rdi = reg(RegisterId::X86Gpr(7))?;
    let old_r8 = reg(RegisterId::X86Gpr(8))?;
    let old_r9 = reg(RegisterId::X86Gpr(9))?;
    let old_r10 = reg(RegisterId::X86Gpr(10))?;
    let old_r11 = reg(RegisterId::X86Gpr(11))?;
    let old_r12 = reg(RegisterId::X86Gpr(12))?;
    let old_r13 = reg(RegisterId::X86Gpr(13))?;
    let old_r14 = reg(RegisterId::X86Gpr(14))?;
    let old_r15 = reg(RegisterId::X86Gpr(15))?;
    let old_rip = reg(RegisterId::X86Rip)?;
    let old_rflags = reg(RegisterId::X86Rflags)?;

    let ExtendedState::X86Xsave(mut xstate) = context.extended_state() else {
        return Err(SignalFrameError::InvalidExtendedState);
    };
    if xstate.len() < X86_FXSAVE_SIZE {
        xstate.resize(X86_FXSAVE_SIZE, 0);
    }

    let (mut sp, used_altstack) = choose_stack(old_rsp, input.flags, input.altstack);
    if !used_altstack {
        // SysV x86-64 ABI 128-byte red zone (`arch/x86/kernel/signal.c`).
        sp = sp
            .checked_sub(X86_RED_ZONE)
            .ok_or(SignalFrameError::MemoryFault)?;
    }

    // Reserve the 64-byte-aligned XSAVE area plus the 4-byte `FP_XSTATE_MAGIC2`
    // trailer (`arch/x86/kernel/fpu/signal.c` `fpu__alloc_mathframe`).
    let xstate_size = xstate.len();
    let extended_size = xstate_size + 4;
    let fpstate_addr = align_down(
        sp.checked_sub(extended_size as u64)
            .ok_or(SignalFrameError::MemoryFault)?,
        64,
    );

    // Populate `struct _fpx_sw_bytes` in software-usable bytes 464..512.
    let xfeatures = if xstate_size >= 520 {
        read_u64(&xstate, 512) | 0x3
    } else {
        0x3
    };
    let mut fp_buf = vec![0u8; extended_size];
    fp_buf[..xstate_size].copy_from_slice(&xstate);
    write_u32(&mut fp_buf, X86_SW_RESERVED_OFFSET, X86_FP_XSTATE_MAGIC1);
    write_u32(
        &mut fp_buf,
        X86_SW_RESERVED_OFFSET + 4,
        extended_size as u32,
    );
    write_u64(&mut fp_buf, X86_SW_RESERVED_OFFSET + 8, xfeatures);
    write_u32(&mut fp_buf, X86_SW_RESERVED_OFFSET + 16, xstate_size as u32);
    fp_buf[X86_SW_RESERVED_OFFSET + 20..X86_FXSAVE_SIZE].fill(0);
    write_u32(&mut fp_buf, xstate_size, X86_FP_XSTATE_MAGIC2);

    // Align `frame_sp` so `frame_sp % 16 == 8` (matching a `call` entry with
    // `pretcode` at `[rsp]` and 16-byte-aligned `ucontext` at `[rsp + 8]`).
    let frame_sp = align_down(
        fpstate_addr
            .checked_sub(X86_RT_SIGFRAME_SIZE as u64)
            .ok_or(SignalFrameError::MemoryFault)?,
        16,
    )
    .checked_sub(8)
    .ok_or(SignalFrameError::MemoryFault)?;

    let mut frame = [0u8; X86_RT_SIGFRAME_SIZE];
    let pretcode = if input.flags & SA_RESTORER != 0 {
        input.restorer
    } else {
        0
    };
    write_u64(&mut frame, 0, pretcode);

    let uc = &mut frame[X86_FRAME_UC_OFFSET..X86_FRAME_INFO_OFFSET];
    write_u64(uc, X86_UC_FLAGS_OFFSET, X86_UC_FP_XSTATE);
    write_u64(uc, X86_UC_LINK_OFFSET, 0);
    uc[X86_UC_STACK_OFFSET..X86_UC_STACK_OFFSET + STACK_T_SIZE]
        .copy_from_slice(&input.altstack.encode_stack_t(old_rsp));

    // `struct sigcontext` (`arch/x86/include/uapi/asm/sigcontext.h`).
    let mc = &mut uc[X86_UC_MCONTEXT_OFFSET..X86_UC_SIGMASK_OFFSET];
    let gregs = [
        old_r8,
        old_r9,
        old_r10,
        old_r11,
        old_r12,
        old_r13,
        old_r14,
        old_r15,
        old_rdi,
        old_rsi,
        old_rbp,
        old_rbx,
        old_rdx,
        old_rax,
        old_rcx,
        old_rsp,
        old_rip,
        old_rflags,
        u64::from(X86_USER_CS) | (u64::from(X86_USER_SS) << 48),
        0, // err
        0, // trapno
        input.saved_mask.bits(),
        input.fault_address,
        fpstate_addr,
    ];
    for (index, value) in gregs.into_iter().enumerate() {
        write_u64(mc, index * 8, value);
    }
    write_u64(uc, X86_UC_SIGMASK_OFFSET, input.saved_mask.bits());

    frame[X86_FRAME_INFO_OFFSET..X86_FRAME_INFO_OFFSET + SIGINFO_SIZE]
        .copy_from_slice(&input.info.encode());

    memory
        .write(fpstate_addr, &fp_buf)
        .map_err(|_| SignalFrameError::MemoryFault)?;
    memory
        .write(frame_sp, &frame)
        .map_err(|_| SignalFrameError::MemoryFault)?;

    let uc_addr = frame_sp + X86_FRAME_UC_OFFSET as u64;
    let info_addr = frame_sp + X86_FRAME_INFO_OFFSET as u64;
    let set = |ctx: &mut C, id, val| {
        ctx.set_register(id, val)
            .map_err(|_| SignalFrameError::InvalidContext)
    };
    set(
        context,
        RegisterId::X86Gpr(7),
        u64::from(input.info.signo.raw()),
    )?;
    set(context, RegisterId::X86Gpr(6), info_addr)?;
    set(context, RegisterId::X86Gpr(2), uc_addr)?;
    set(context, RegisterId::X86Gpr(0), 0)?;
    set(context, RegisterId::X86Gpr(4), frame_sp)?;
    set(context, RegisterId::X86Rip, input.handler)?;
    set(
        context,
        RegisterId::X86Rflags,
        (old_rflags & !(X86_RFLAGS_DF | X86_RFLAGS_TF)) | X86_RFLAGS_FIXED,
    )?;

    Ok(used_altstack)
}

fn restore_x86_64_frame<C: UserContext, M: UserMemory>(
    context: &mut C,
    memory: &M,
) -> Result<RestoredFrame, SignalFrameError> {
    // `ret` from the signal handler popped `pretcode`, leaving `rsp` pointing
    // directly at `rt_sigframe.uc` (`arch/x86/kernel/signal_64.c`).
    let uc_addr = context
        .register(RegisterId::X86Gpr(4))
        .map_err(|_| SignalFrameError::InvalidContext)?;
    let mut uc = [0u8; X86_UCONTEXT_ALLOC_SIZE];
    memory
        .read(uc_addr, &mut uc)
        .map_err(|_| SignalFrameError::MemoryFault)?;

    let stack_bytes: [u8; STACK_T_SIZE] = uc
        [X86_UC_STACK_OFFSET..X86_UC_STACK_OFFSET + STACK_T_SIZE]
        .try_into()
        .unwrap();
    let (uc_stack_sp, uc_stack_flags, uc_stack_size) = SigAltStack::decode_stack_t(&stack_bytes);
    let sigmask = SignalSet::from_bits(read_u64(&uc, X86_UC_SIGMASK_OFFSET)).without_uncatchable();

    let mc = &uc[X86_UC_MCONTEXT_OFFSET..X86_UC_SIGMASK_OFFSET];
    let r8 = read_u64(mc, 0);
    let r9 = read_u64(mc, 8);
    let r10 = read_u64(mc, 16);
    let r11 = read_u64(mc, 24);
    let r12 = read_u64(mc, 32);
    let r13 = read_u64(mc, 40);
    let r14 = read_u64(mc, 48);
    let r15 = read_u64(mc, 56);
    let rdi = read_u64(mc, 64);
    let rsi = read_u64(mc, 72);
    let rbp = read_u64(mc, 80);
    let rbx = read_u64(mc, 88);
    let rdx = read_u64(mc, 96);
    let rax = read_u64(mc, 104);
    let rcx = read_u64(mc, 112);
    let rsp = read_u64(mc, 120);
    let rip = read_u64(mc, 128);
    let rflags = read_u64(mc, 136);
    let fpstate_addr = read_u64(mc, 23 * 8);

    let limit = Abi::X86_64.task_size();
    if rip >= limit || rsp >= limit {
        return Err(SignalFrameError::InvalidContext);
    }

    if fpstate_addr != 0 {
        let mut legacy = [0u8; X86_FXSAVE_SIZE];
        memory
            .read(fpstate_addr, &mut legacy)
            .map_err(|_| SignalFrameError::MemoryFault)?;
        let magic1 = read_u32(&legacy, X86_SW_RESERVED_OFFSET);
        let xstate_bytes = if magic1 == X86_FP_XSTATE_MAGIC1 {
            let xstate_size = read_u32(&legacy, X86_SW_RESERVED_OFFSET + 16) as usize;
            let extended_size = read_u32(&legacy, X86_SW_RESERVED_OFFSET + 4) as usize;
            if xstate_size < X86_FXSAVE_SIZE
                || extended_size < xstate_size + 4
                || xstate_size > 16384
            {
                return Err(SignalFrameError::InvalidExtendedState);
            }
            let mut full = vec![0u8; xstate_size];
            memory
                .read(fpstate_addr, &mut full)
                .map_err(|_| SignalFrameError::MemoryFault)?;
            let mut magic2_bytes = [0u8; 4];
            memory
                .read(
                    fpstate_addr
                        .checked_add(xstate_size as u64)
                        .ok_or(SignalFrameError::MemoryFault)?,
                    &mut magic2_bytes,
                )
                .map_err(|_| SignalFrameError::MemoryFault)?;
            if u32::from_le_bytes(magic2_bytes) != X86_FP_XSTATE_MAGIC2 {
                return Err(SignalFrameError::InvalidExtendedState);
            }
            full[X86_SW_RESERVED_OFFSET..X86_FXSAVE_SIZE].fill(0);
            full
        } else {
            let mut buf = legacy.to_vec();
            buf[X86_SW_RESERVED_OFFSET..X86_FXSAVE_SIZE].fill(0);
            buf
        };
        context
            .set_extended_state(&ExtendedState::X86Xsave(xstate_bytes))
            .map_err(|_| SignalFrameError::InvalidExtendedState)?;
    }

    let set = |ctx: &mut C, id, val| {
        ctx.set_register(id, val)
            .map_err(|_| SignalFrameError::InvalidContext)
    };
    set(context, RegisterId::X86Gpr(0), rax)?;
    set(context, RegisterId::X86Gpr(1), rcx)?;
    set(context, RegisterId::X86Gpr(2), rdx)?;
    set(context, RegisterId::X86Gpr(3), rbx)?;
    set(context, RegisterId::X86Gpr(4), rsp)?;
    set(context, RegisterId::X86Gpr(5), rbp)?;
    set(context, RegisterId::X86Gpr(6), rsi)?;
    set(context, RegisterId::X86Gpr(7), rdi)?;
    set(context, RegisterId::X86Gpr(8), r8)?;
    set(context, RegisterId::X86Gpr(9), r9)?;
    set(context, RegisterId::X86Gpr(10), r10)?;
    set(context, RegisterId::X86Gpr(11), r11)?;
    set(context, RegisterId::X86Gpr(12), r12)?;
    set(context, RegisterId::X86Gpr(13), r13)?;
    set(context, RegisterId::X86Gpr(14), r14)?;
    set(context, RegisterId::X86Gpr(15), r15)?;
    set(context, RegisterId::X86Rip, rip)?;
    set(context, RegisterId::X86Rflags, rflags)?;

    Ok(RestoredFrame {
        sigmask,
        uc_stack_sp,
        uc_stack_flags,
        uc_stack_size,
    })
}

fn setup_aarch64_frame<C: UserContext, M: UserMemory>(
    context: &mut C,
    memory: &mut M,
    input: FrameDeliveryInput,
) -> Result<bool, SignalFrameError> {
    let mut regs = [0u64; 31];
    for (index, slot) in regs.iter_mut().enumerate() {
        *slot = context
            .register(RegisterId::Aarch64X(index as u8))
            .map_err(|_| SignalFrameError::InvalidContext)?;
    }
    let old_sp = context
        .register(RegisterId::Aarch64Sp)
        .map_err(|_| SignalFrameError::InvalidContext)?;
    let old_pc = context
        .register(RegisterId::Aarch64Pc)
        .map_err(|_| SignalFrameError::InvalidContext)?;
    let old_pstate = context
        .register(RegisterId::Aarch64Pstate)
        .map_err(|_| SignalFrameError::InvalidContext)?;

    let ExtendedState::Aarch64FpSimd(fp) = context.extended_state() else {
        return Err(SignalFrameError::InvalidExtendedState);
    };
    let Aarch64FpSimd { vregs, fpsr, fpcr } = *fp;

    let (base_sp, used_altstack) = choose_stack(old_sp, input.flags, input.altstack);
    let frame_sp = align_down(
        base_sp
            .checked_sub(AARCH64_RT_SIGFRAME_SIZE as u64)
            .ok_or(SignalFrameError::MemoryFault)?,
        16,
    );

    let mut frame = vec![0u8; AARCH64_RT_SIGFRAME_SIZE];
    frame[AARCH64_FRAME_INFO_OFFSET..AARCH64_FRAME_INFO_OFFSET + SIGINFO_SIZE]
        .copy_from_slice(&input.info.encode());

    let uc = &mut frame[AARCH64_FRAME_UC_OFFSET..AARCH64_FRAME_UC_OFFSET + AARCH64_UCONTEXT_SIZE];
    write_u64(uc, AARCH64_UC_FLAGS_OFFSET, 0);
    write_u64(uc, AARCH64_UC_LINK_OFFSET, 0);
    uc[AARCH64_UC_STACK_OFFSET..AARCH64_UC_STACK_OFFSET + STACK_T_SIZE]
        .copy_from_slice(&input.altstack.encode_stack_t(old_sp));
    write_u64(uc, AARCH64_UC_SIGMASK_OFFSET, input.saved_mask.bits());

    let mc = &mut uc[AARCH64_UC_MCONTEXT_OFFSET..];
    write_u64(mc, AARCH64_MCONTEXT_FAULT_ADDR, input.fault_address);
    for (index, value) in regs.into_iter().enumerate() {
        write_u64(mc, AARCH64_MCONTEXT_REGS + index * 8, value);
    }
    write_u64(mc, AARCH64_MCONTEXT_SP, old_sp);
    write_u64(mc, AARCH64_MCONTEXT_PC, old_pc);
    write_u64(mc, AARCH64_MCONTEXT_PSTATE, old_pstate);

    // `struct fpsimd_context` followed by `{ magic = 0, size = 0 }` end record
    // (`arch/arm64/include/uapi/asm/sigcontext.h`).
    let reserved = &mut mc[AARCH64_MCONTEXT_RESERVED..];
    write_u32(reserved, 0, AARCH64_FPSIMD_MAGIC);
    write_u32(reserved, 4, AARCH64_FPSIMD_SIZE);
    write_u32(reserved, 8, fpsr);
    write_u32(reserved, 12, fpcr);
    for (index, vreg) in vregs.into_iter().enumerate() {
        let offset = 16 + index * 16;
        reserved[offset..offset + 16].copy_from_slice(&vreg.to_le_bytes());
    }
    // End record at offset 0x210 is already zero-initialized.

    memory
        .write(frame_sp, &frame)
        .map_err(|_| SignalFrameError::MemoryFault)?;

    let info_addr = frame_sp + AARCH64_FRAME_INFO_OFFSET as u64;
    let uc_addr = frame_sp + AARCH64_FRAME_UC_OFFSET as u64;
    let restorer = if input.flags & SA_RESTORER != 0 && input.restorer != 0 {
        input.restorer
    } else {
        input.sigreturn_trampoline
    };

    let set = |ctx: &mut C, id, val| {
        ctx.set_register(id, val)
            .map_err(|_| SignalFrameError::InvalidContext)
    };
    set(
        context,
        RegisterId::Aarch64X(0),
        u64::from(input.info.signo.raw()),
    )?;
    set(context, RegisterId::Aarch64X(1), info_addr)?;
    set(context, RegisterId::Aarch64X(2), uc_addr)?;
    set(context, RegisterId::Aarch64X(29), 0)?;
    set(context, RegisterId::Aarch64X(30), restorer)?;
    set(context, RegisterId::Aarch64Sp, frame_sp)?;
    set(context, RegisterId::Aarch64Pc, input.handler)?;
    set(context, RegisterId::Aarch64Pstate, 0)?;

    Ok(used_altstack)
}

fn restore_aarch64_frame<C: UserContext, M: UserMemory>(
    context: &mut C,
    memory: &M,
) -> Result<RestoredFrame, SignalFrameError> {
    let frame_sp = context
        .register(RegisterId::Aarch64Sp)
        .map_err(|_| SignalFrameError::InvalidContext)?;
    if frame_sp & 0xf != 0 {
        return Err(SignalFrameError::InvalidContext);
    }
    let uc_addr = frame_sp
        .checked_add(AARCH64_FRAME_UC_OFFSET as u64)
        .ok_or(SignalFrameError::MemoryFault)?;
    let mut uc = vec![0u8; AARCH64_UCONTEXT_SIZE];
    memory
        .read(uc_addr, &mut uc)
        .map_err(|_| SignalFrameError::MemoryFault)?;

    let stack_bytes: [u8; STACK_T_SIZE] = uc
        [AARCH64_UC_STACK_OFFSET..AARCH64_UC_STACK_OFFSET + STACK_T_SIZE]
        .try_into()
        .unwrap();
    let (uc_stack_sp, uc_stack_flags, uc_stack_size) = SigAltStack::decode_stack_t(&stack_bytes);
    let sigmask =
        SignalSet::from_bits(read_u64(&uc, AARCH64_UC_SIGMASK_OFFSET)).without_uncatchable();

    let mc = &uc[AARCH64_UC_MCONTEXT_OFFSET..];
    let mut regs = [0u64; 31];
    for (index, slot) in regs.iter_mut().enumerate() {
        *slot = read_u64(mc, AARCH64_MCONTEXT_REGS + index * 8);
    }
    let sp = read_u64(mc, AARCH64_MCONTEXT_SP);
    let pc = read_u64(mc, AARCH64_MCONTEXT_PC);
    let pstate = read_u64(mc, AARCH64_MCONTEXT_PSTATE);

    let limit = Abi::Aarch64.task_size();
    if pc >= limit || sp >= limit {
        return Err(SignalFrameError::InvalidContext);
    }

    // Parse `__reserved` record list (`arch/arm64/kernel/signal.c`
    // `parse_user_sigframe`).
    let reserved = &mc[AARCH64_MCONTEXT_RESERVED..];
    let mut offset = 0usize;
    let mut fpsimd = None;
    loop {
        if offset + 8 > reserved.len() {
            return Err(SignalFrameError::InvalidExtendedState);
        }
        let magic = read_u32(reserved, offset);
        let size = read_u32(reserved, offset + 4);
        if magic == 0 && size == 0 {
            break;
        }
        let size = size as usize;
        if size < 8 || size % 16 != 0 || offset + size > reserved.len() {
            return Err(SignalFrameError::InvalidExtendedState);
        }
        if magic == AARCH64_FPSIMD_MAGIC {
            if size != AARCH64_FPSIMD_SIZE as usize || fpsimd.is_some() {
                return Err(SignalFrameError::InvalidExtendedState);
            }
            let fpsr = read_u32(reserved, offset + 8);
            let fpcr = read_u32(reserved, offset + 12);
            let mut vregs = [0u128; 32];
            for (index, slot) in vregs.iter_mut().enumerate() {
                let v_off = offset + 16 + index * 16;
                *slot = u128::from_le_bytes(reserved[v_off..v_off + 16].try_into().unwrap());
            }
            fpsimd = Some(ExtendedState::Aarch64FpSimd(Box::new(Aarch64FpSimd {
                vregs,
                fpsr,
                fpcr,
            })));
        }
        offset += size;
    }

    if let Some(state) = fpsimd {
        context
            .set_extended_state(&state)
            .map_err(|_| SignalFrameError::InvalidExtendedState)?;
    }

    let set = |ctx: &mut C, id, val| {
        ctx.set_register(id, val)
            .map_err(|_| SignalFrameError::InvalidContext)
    };
    for (index, value) in regs.into_iter().enumerate() {
        set(context, RegisterId::Aarch64X(index as u8), value)?;
    }
    set(context, RegisterId::Aarch64Sp, sp)?;
    set(context, RegisterId::Aarch64Pc, pc)?;
    set(context, RegisterId::Aarch64Pstate, pstate)?;

    Ok(RestoredFrame {
        sigmask,
        uc_stack_sp,
        uc_stack_flags,
        uc_stack_size,
    })
}

const fn align_down(value: u64, align: u64) -> u64 {
    value & !(align - 1)
}

fn write_i32(buf: &mut [u8], offset: usize, value: i32) {
    buf[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u32(buf: &mut [u8], offset: usize, value: u32) {
    buf[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64(buf: &mut [u8], offset: usize, value: u64) {
    buf[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn read_u32(buf: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(buf[offset..offset + 4].try_into().unwrap())
}

fn read_u64(buf: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(buf[offset..offset + 8].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::syscall::MemoryFault;
    use alloc::vec::Vec;
    use core::convert::Infallible;
    use helios_hal::native::{NativeError, Stop};
    use helios_hal::vmm::VirtAddr;

    struct FlatMemory {
        base: u64,
        bytes: Vec<u8>,
    }

    impl FlatMemory {
        fn new(base: u64, size: usize) -> Self {
            Self {
                base,
                bytes: vec![0; size],
            }
        }
        fn range(&self, address: u64, len: usize) -> Result<core::ops::Range<usize>, MemoryFault> {
            let offset = address.checked_sub(self.base).ok_or(MemoryFault)? as usize;
            let end = offset.checked_add(len).ok_or(MemoryFault)?;
            if end <= self.bytes.len() {
                Ok(offset..end)
            } else {
                Err(MemoryFault)
            }
        }
    }

    impl UserMemory for FlatMemory {
        fn check_writable(&self, address: u64, length: usize) -> Result<(), MemoryFault> {
            self.range(address, length).map(|_| ())
        }
        fn read(&self, address: u64, output: &mut [u8]) -> Result<(), MemoryFault> {
            let r = self.range(address, output.len())?;
            output.copy_from_slice(&self.bytes[r]);
            Ok(())
        }
        fn write(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryFault> {
            let r = self.range(address, bytes.len())?;
            self.bytes[r].copy_from_slice(bytes);
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
            let current = self.atomic_load_u32(address)?;
            if current == expected {
                self.atomic_store_u32(address, desired)?;
                Ok(Ok(current))
            } else {
                Ok(Err(current))
            }
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
        fn new_x86(sp: u64, rip: u64) -> Self {
            let mut xsave = vec![0u8; 832];
            xsave[24..28].copy_from_slice(&0x1f80_u32.to_le_bytes());
            xsave[160..176]
                .copy_from_slice(&0x1122_3344_5566_7788_99aa_bbcc_ddee_ff00_u128.to_le_bytes());
            xsave[512..520].copy_from_slice(&0x7_u64.to_le_bytes());
            xsave[576..592]
                .copy_from_slice(&0xdead_beef_cafe_babe_0123_4567_89ab_cdef_u128.to_le_bytes());
            let mut gprs = [0u64; 31];
            for (i, slot) in gprs[..16].iter_mut().enumerate() {
                *slot = 0x1000 + i as u64 * 0x11;
            }
            gprs[4] = sp;
            Self {
                abi: Abi::X86_64,
                gprs,
                sp,
                pc: rip,
                flags: 0x246 | X86_RFLAGS_DF,
                ext: ExtendedState::X86Xsave(xsave),
            }
        }

        fn new_aarch64(sp: u64, pc: u64) -> Self {
            let mut gprs = [0u64; 31];
            for (i, slot) in gprs.iter_mut().enumerate() {
                *slot = 0x2000 + i as u64 * 0x13;
            }
            let mut vregs = [0u128; 32];
            for (i, slot) in vregs.iter_mut().enumerate() {
                *slot = ((i as u128 + 1) << 64) | (0xa5a5_0000 + i as u128);
            }
            Self {
                abi: Abi::Aarch64,
                gprs,
                sp,
                pc,
                flags: 0x6000_0000,
                ext: ExtendedState::Aarch64FpSimd(Box::new(Aarch64FpSimd {
                    vregs,
                    fpsr: 0x1234_5678,
                    fpcr: 0x0000_0040,
                })),
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

    #[test]
    fn x86_64_signal_frame_preserves_gprs_xsave_red_zone_and_roundtrips() {
        let mut memory = FlatMemory::new(0x10_0000, 0x1_0000);
        let initial_sp = 0x10_8000;
        let initial_rip = 0x40_1234;
        // Fill the 128-byte red zone with a sentinel to prove delivery never touches it.
        let red_sentinel = [0xabu8; 128];
        memory.write(initial_sp - 128, &red_sentinel).unwrap();

        let original = FakeContext::new_x86(initial_sp, initial_rip);
        let mut ctx = original.clone();
        let saved_mask = SignalSet::EMPTY.with(Signal::SIGUSR2);

        let used_alt = setup_signal_frame(
            &mut ctx,
            &mut memory,
            FrameDeliveryInput {
                abi: Abi::X86_64,
                info: SigInfo::from_kill(Signal::SIGUSR1, 42, 1000),
                handler: 0x40_5000,
                restorer: 0x40_6000,
                flags: SA_SIGINFO | SA_RESTORER,
                saved_mask,
                altstack: SigAltStack::disabled(),
                sigreturn_trampoline: 0,
                fault_address: 0,
            },
        )
        .unwrap();
        assert!(!used_alt);

        // Red zone untouched.
        let mut red_after = [0u8; 128];
        memory.read(initial_sp - 128, &mut red_after).unwrap();
        assert_eq!(red_after, red_sentinel);

        // Handler entry ABI: RSP % 16 == 8, RDI = signo, RSI = &info, RDX = &uc, DF cleared.
        let frame_sp = ctx.register(RegisterId::X86Gpr(4)).unwrap();
        assert_eq!(frame_sp % 16, 8);
        assert_eq!(ctx.register(RegisterId::X86Rip).unwrap(), 0x40_5000);
        assert_eq!(ctx.register(RegisterId::X86Gpr(7)).unwrap(), 10);
        assert_eq!(
            ctx.register(RegisterId::X86Rflags).unwrap() & X86_RFLAGS_DF,
            0
        );

        // Pretcode sits at [RSP].
        let mut pretcode = [0u8; 8];
        memory.read(frame_sp, &mut pretcode).unwrap();
        assert_eq!(u64::from_le_bytes(pretcode), 0x40_6000);

        // Simulate handler clobbering every GPR and XSAVE, then `ret` popping pretcode.
        for i in 0..16 {
            ctx.set_register(RegisterId::X86Gpr(i), 0xbad0 + u64::from(i))
                .unwrap();
        }
        ctx.set_extended_state(&ExtendedState::X86Xsave(vec![0; 832]))
            .unwrap();
        ctx.set_register(RegisterId::X86Gpr(4), frame_sp + 8)
            .unwrap();

        let restored = restore_signal_frame(Abi::X86_64, &mut ctx, &memory).unwrap();
        assert_eq!(restored.sigmask, saved_mask);
        assert_eq!(ctx.gprs[..16], original.gprs[..16]);
        assert_eq!(ctx.pc, original.pc);
        assert_eq!(ctx.flags, original.flags);
        assert_eq!(ctx.ext, original.ext);
    }

    #[test]
    fn aarch64_signal_frame_preserves_gprs_neon_altstack_and_trampoline() {
        let mut memory = FlatMemory::new(0x20_0000, 0x2_0000);
        let initial_sp = 0x20_8000;
        let initial_pc = 0x40_2000;
        let altstack = SigAltStack {
            sp: 0x21_0000,
            size: 0x4000,
            flags: SS_AUTODISARM,
        };
        let original = FakeContext::new_aarch64(initial_sp, initial_pc);
        let mut ctx = original.clone();
        let saved_mask = SignalSet::EMPTY.with(Signal::SIGALRM);

        let used_alt = setup_signal_frame(
            &mut ctx,
            &mut memory,
            FrameDeliveryInput {
                abi: Abi::Aarch64,
                info: SigInfo::from_timer(Signal::SIGALRM),
                handler: 0x40_7000,
                restorer: 0,
                flags: SA_SIGINFO | SA_ONSTACK,
                saved_mask,
                altstack,
                sigreturn_trampoline: 0x70_0000,
                fault_address: 0xdead_0000,
            },
        )
        .unwrap();
        assert!(used_alt);

        let frame_sp = ctx.register(RegisterId::Aarch64Sp).unwrap();
        assert_eq!(frame_sp % 16, 0);
        assert!(altstack.on_stack(frame_sp));
        assert_eq!(ctx.register(RegisterId::Aarch64Pc).unwrap(), 0x40_7000);
        assert_eq!(ctx.register(RegisterId::Aarch64X(0)).unwrap(), 14);
        assert_eq!(ctx.register(RegisterId::Aarch64X(30)).unwrap(), 0x70_0000);

        // Clobber every register and NEON vector, keeping SP at frame_sp as `ret` does.
        for i in 0..31 {
            ctx.set_register(RegisterId::Aarch64X(i), 0xbad0 + u64::from(i))
                .unwrap();
        }
        ctx.set_extended_state(&ExtendedState::Aarch64FpSimd(Box::new(Aarch64FpSimd {
            vregs: [0; 32],
            fpsr: 0,
            fpcr: 0,
        })))
        .unwrap();

        let restored = restore_signal_frame(Abi::Aarch64, &mut ctx, &memory).unwrap();
        assert_eq!(restored.sigmask, saved_mask);
        assert_eq!(restored.uc_stack_sp, altstack.sp);
        assert_eq!(restored.uc_stack_size, altstack.size);
        assert_eq!(restored.uc_stack_flags, SS_AUTODISARM);
        assert_eq!(ctx.gprs, original.gprs);
        assert_eq!(ctx.sp, original.sp);
        assert_eq!(ctx.pc, original.pc);
        assert_eq!(ctx.flags, original.flags);
        assert_eq!(ctx.ext, original.ext);
    }
}
