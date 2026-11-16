//! Where the Linux ABI keeps its values in the architectural registers and
//! which signal a processor fault becomes, per instruction set.

use helios_hal::hv::RegisterId;
use helios_hal::native::{FaultKind, InstructionSet};

/// A Linux ABI this crate decodes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Abi {
    X86_64,
    Aarch64,
}

/// The system calls the decoder serves, independent of their numbers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation {
    Read,
    Write,
    Close,
    Pipe,
    Pipe2,
    Dup,
    Dup2,
    Dup3,
    Fcntl,
    Eventfd,
    Eventfd2,
    EpollCreate,
    EpollCreate1,
    EpollCtl,
    EpollWait,
    EpollPwait,
    Mmap,
    Ioctl,
    Writev,
    Getpid,
    Gettid,
    SetTidAddress,
    ArchPrctl,
    Exit,
    ExitGroup,
    Unknown,
}

impl Abi {
    /// The Linux ABI of `isa`, or `None` where this crate decodes none.
    pub fn for_instruction_set(isa: InstructionSet) -> Option<Self> {
        match isa {
            InstructionSet::X86_64 => Some(Self::X86_64),
            InstructionSet::Aarch64 => Some(Self::Aarch64),
            InstructionSet::Riscv64 => None,
        }
    }

    /// The operation system call `number` names.
    pub fn operation(self, number: u64) -> Operation {
        match self {
            // arch/x86/entry/syscalls/syscall_64.tbl
            Self::X86_64 => match number {
                0 => Operation::Read,
                1 => Operation::Write,
                3 => Operation::Close,
                9 => Operation::Mmap,
                16 => Operation::Ioctl,
                20 => Operation::Writev,
                22 => Operation::Pipe,
                32 => Operation::Dup,
                33 => Operation::Dup2,
                39 => Operation::Getpid,
                60 => Operation::Exit,
                72 => Operation::Fcntl,
                158 => Operation::ArchPrctl,
                186 => Operation::Gettid,
                213 => Operation::EpollCreate,
                218 => Operation::SetTidAddress,
                231 => Operation::ExitGroup,
                232 => Operation::EpollWait,
                233 => Operation::EpollCtl,
                281 => Operation::EpollPwait,
                284 => Operation::Eventfd,
                290 => Operation::Eventfd2,
                291 => Operation::EpollCreate1,
                292 => Operation::Dup3,
                293 => Operation::Pipe2,
                _ => Operation::Unknown,
            },
            // include/uapi/asm-generic/unistd.h, which has none of the
            // legacy calls (pipe, dup2, epoll_create, epoll_wait, eventfd)
            // and no arch_prctl: user code writes TPIDR_EL0 itself.
            Self::Aarch64 => match number {
                19 => Operation::Eventfd2,
                20 => Operation::EpollCreate1,
                21 => Operation::EpollCtl,
                22 => Operation::EpollPwait,
                23 => Operation::Dup,
                24 => Operation::Dup3,
                25 => Operation::Fcntl,
                29 => Operation::Ioctl,
                57 => Operation::Close,
                59 => Operation::Pipe2,
                63 => Operation::Read,
                64 => Operation::Write,
                66 => Operation::Writev,
                93 => Operation::Exit,
                94 => Operation::ExitGroup,
                96 => Operation::SetTidAddress,
                172 => Operation::Getpid,
                178 => Operation::Gettid,
                222 => Operation::Mmap,
                _ => Operation::Unknown,
            },
        }
    }

    /// The registers a system call is read from and answered in.
    pub fn system_call_registers(self) -> SystemCallRegisters {
        match self {
            // arch/x86/entry/entry_64.S: RAX holds the number and the
            // result, RDI, RSI, RDX, R10, R8 and R9 the arguments
            // (encodings 0, 7, 6, 2, 10, 8, 9).
            Self::X86_64 => SystemCallRegisters {
                number: RegisterId::X86Gpr(0),
                arguments: [
                    RegisterId::X86Gpr(7),
                    RegisterId::X86Gpr(6),
                    RegisterId::X86Gpr(2),
                    RegisterId::X86Gpr(10),
                    RegisterId::X86Gpr(8),
                    RegisterId::X86Gpr(9),
                ],
                result: RegisterId::X86Gpr(0),
            },
            // arch/arm64/kernel/syscall.c: x8 holds the number, x0 to x5
            // the arguments, x0 the result.
            Self::Aarch64 => SystemCallRegisters {
                number: RegisterId::Aarch64X(8),
                arguments: [
                    RegisterId::Aarch64X(0),
                    RegisterId::Aarch64X(1),
                    RegisterId::Aarch64X(2),
                    RegisterId::Aarch64X(3),
                    RegisterId::Aarch64X(4),
                    RegisterId::Aarch64X(5),
                ],
                result: RegisterId::Aarch64X(0),
            },
        }
    }

    /// Where `struct epoll_event`'s 64-bit data sits after its 32-bit
    /// events: x86-64 packs the struct (uapi/linux/eventpoll.h,
    /// `EPOLL_PACKED`), every other ABI aligns the data to 8. The struct
    /// is the offset plus 8 bytes long.
    pub fn epoll_data_offset(self) -> usize {
        match self {
            Self::X86_64 => 4,
            Self::Aarch64 => 8,
        }
    }

    /// The ELF `e_machine` of this ABI's executables (System V gABI).
    pub fn elf_machine(self) -> u16 {
        match self {
            Self::X86_64 => 62,
            Self::Aarch64 => 183,
        }
    }
}

/// The registers a system call is read from and answered in.
#[derive(Clone, Copy, Debug)]
pub struct SystemCallRegisters {
    pub number: RegisterId,
    pub arguments: [RegisterId; 6],
    pub result: RegisterId,
}

// Linux uapi/asm-generic/signal.h numbers, shared by x86-64.
pub const SIGILL: u8 = 4;
pub const SIGTRAP: u8 = 5;
pub const SIGBUS: u8 = 7;
pub const SIGFPE: u8 = 8;
pub const SIGSEGV: u8 = 11;

/// The signal Linux raises for a user fault of `kind`
/// (arch/x86/kernel/traps.c and arch/x86/mm/fault.c).
pub fn fault_signal(kind: FaultKind) -> u8 {
    match kind {
        FaultKind::Page { .. } | FaultKind::Protection => SIGSEGV,
        FaultKind::InvalidInstruction => SIGILL,
        FaultKind::Arithmetic => SIGFPE,
        FaultKind::Breakpoint => SIGTRAP,
        FaultKind::Alignment => SIGBUS,
    }
}

/// The exit status a parent reads for a process a signal ended, as a POSIX
/// shell reports it: 128 plus the signal number.
pub fn signal_exit_status(signal: u32) -> u32 {
    128 + signal
}
