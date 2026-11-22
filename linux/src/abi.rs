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
    Open,
    Close,
    Stat,
    Fstat,
    Lstat,
    Poll,
    Lseek,
    Pread64,
    Pwrite64,
    Readv,
    Writev,
    Access,
    Pipe,
    Select,
    Pipe2,
    Dup,
    Dup2,
    Dup3,
    Fcntl,
    Fsync,
    Fdatasync,
    Truncate,
    Ftruncate,
    Getdents64,
    Getcwd,
    Chdir,
    Fchdir,
    Rename,
    Mkdir,
    Rmdir,
    Creat,
    Link,
    Unlink,
    Symlink,
    Readlink,
    Chmod,
    Fchmod,
    Chown,
    Fchown,
    Lchown,
    Mknod,
    Setxattr,
    Lsetxattr,
    Fsetxattr,
    Getxattr,
    Lgetxattr,
    Fgetxattr,
    Listxattr,
    Llistxattr,
    Flistxattr,
    Removexattr,
    Lremovexattr,
    Fremovexattr,
    Openat,
    Mkdirat,
    Mknodat,
    Fchownat,
    Newfstatat,
    Unlinkat,
    Renameat,
    Linkat,
    Symlinkat,
    Readlinkat,
    Fchmodat,
    Fchmodat2,
    Faccessat,
    Faccessat2,
    Pselect6,
    Ppoll,
    Utimensat,
    Preadv,
    Pwritev,
    Renameat2,
    Preadv2,
    Pwritev2,
    Statx,
    CloseRange,
    Eventfd,
    Eventfd2,
    EpollCreate,
    EpollCreate1,
    EpollCtl,
    EpollWait,
    EpollPwait,
    Mmap,
    Munmap,
    Mprotect,
    Mremap,
    Msync,
    Madvise,
    Brk,
    RtSigaction,
    RtSigprocmask,
    RtSigreturn,
    RtSigpending,
    RtSigtimedwait,
    RtSigsuspend,
    Sigaltstack,
    Kill,
    Tkill,
    Tgkill,
    /// x86-64 only: aarch64's asm-generic table has no `pause` (musl uses `ppoll`).
    Pause,
    /// x86-64 only: aarch64's asm-generic table has no `alarm` (musl uses `setitimer`).
    Alarm,
    Getitimer,
    Setitimer,
    Ioctl,
    SchedYield,
    SchedGetaffinity,
    Nanosleep,
    ClockNanosleep,
    Clone,
    Clone3,
    Futex,
    SetRobustList,
    GetRobustList,
    Getpid,
    Gettid,
    SetTidAddress,
    ArchPrctl,
    Exit,
    ExitGroup,
    ClockGettime,
    ClockGetres,
    ClockSettime,
    Gettimeofday,
    /// x86-64 only: aarch64's asm-generic table has no `time`.
    Time,
    Getrandom,
    Uname,
    Sethostname,
    Setdomainname,
    Sysinfo,
    Getuid,
    Geteuid,
    Getgid,
    Getegid,
    Getgroups,
    Getresuid,
    Getresgid,
    Setuid,
    Setgid,
    Setreuid,
    Setregid,
    Setresuid,
    Setresgid,
    Setgroups,
    Capget,
    Capset,
    Prlimit64,
    Getrlimit,
    Setrlimit,
    Umask,
    Getpriority,
    Setpriority,
    Sendfile,
    Socket,
    Socketpair,
    Bind,
    Listen,
    Accept,
    Accept4,
    Connect,
    Getsockname,
    Getpeername,
    Sendto,
    Recvfrom,
    Sendmsg,
    Recvmsg,
    Sendmmsg,
    Recvmmsg,
    Shutdown,
    Setsockopt,
    Getsockopt,
    Unknown,
}

/// Decoded arguments of the legacy `clone` system call, whose `tls` and
/// `child_tid` positions differ between x86-64 and `CONFIG_CLONE_BACKWARDS`
/// architectures such as AArch64 (`kernel/fork.c` `SYSCALL_DEFINE5(clone)`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CloneRegisters {
    pub flags: u64,
    pub stack: u64,
    pub parent_tid: u64,
    pub child_tid: u64,
    pub tls: u64,
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
            // arch/x86/entry/syscalls/syscall_64.tbl, Linux v6.12.
            Self::X86_64 => match number {
                0 => Operation::Read,
                1 => Operation::Write,
                2 => Operation::Open,
                3 => Operation::Close,
                4 => Operation::Stat,
                5 => Operation::Fstat,
                6 => Operation::Lstat,
                7 => Operation::Poll,
                8 => Operation::Lseek,
                9 => Operation::Mmap,
                10 => Operation::Mprotect,
                11 => Operation::Munmap,
                12 => Operation::Brk,
                13 => Operation::RtSigaction,
                14 => Operation::RtSigprocmask,
                15 => Operation::RtSigreturn,
                16 => Operation::Ioctl,
                17 => Operation::Pread64,
                18 => Operation::Pwrite64,
                19 => Operation::Readv,
                20 => Operation::Writev,
                21 => Operation::Access,
                22 => Operation::Pipe,
                23 => Operation::Select,
                24 => Operation::SchedYield,
                25 => Operation::Mremap,
                26 => Operation::Msync,
                28 => Operation::Madvise,
                32 => Operation::Dup,
                33 => Operation::Dup2,
                34 => Operation::Pause,
                35 => Operation::Nanosleep,
                36 => Operation::Getitimer,
                37 => Operation::Alarm,
                38 => Operation::Setitimer,
                39 => Operation::Getpid,
                40 => Operation::Sendfile,
                41 => Operation::Socket,
                42 => Operation::Connect,
                43 => Operation::Accept,
                44 => Operation::Sendto,
                45 => Operation::Recvfrom,
                46 => Operation::Sendmsg,
                47 => Operation::Recvmsg,
                48 => Operation::Shutdown,
                49 => Operation::Bind,
                50 => Operation::Listen,
                51 => Operation::Getsockname,
                52 => Operation::Getpeername,
                53 => Operation::Socketpair,
                54 => Operation::Setsockopt,
                55 => Operation::Getsockopt,
                56 => Operation::Clone,
                60 => Operation::Exit,
                62 => Operation::Kill,
                63 => Operation::Uname,
                72 => Operation::Fcntl,
                74 => Operation::Fsync,
                75 => Operation::Fdatasync,
                76 => Operation::Truncate,
                77 => Operation::Ftruncate,
                79 => Operation::Getcwd,
                80 => Operation::Chdir,
                81 => Operation::Fchdir,
                82 => Operation::Rename,
                83 => Operation::Mkdir,
                84 => Operation::Rmdir,
                85 => Operation::Creat,
                86 => Operation::Link,
                87 => Operation::Unlink,
                88 => Operation::Symlink,
                89 => Operation::Readlink,
                90 => Operation::Chmod,
                91 => Operation::Fchmod,
                92 => Operation::Chown,
                93 => Operation::Fchown,
                94 => Operation::Lchown,
                95 => Operation::Umask,
                96 => Operation::Gettimeofday,
                97 => Operation::Getrlimit,
                99 => Operation::Sysinfo,
                102 => Operation::Getuid,
                104 => Operation::Getgid,
                105 => Operation::Setuid,
                106 => Operation::Setgid,
                107 => Operation::Geteuid,
                108 => Operation::Getegid,
                113 => Operation::Setreuid,
                114 => Operation::Setregid,
                115 => Operation::Getgroups,
                116 => Operation::Setgroups,
                117 => Operation::Setresuid,
                118 => Operation::Getresuid,
                119 => Operation::Setresgid,
                120 => Operation::Getresgid,
                125 => Operation::Capget,
                126 => Operation::Capset,
                127 => Operation::RtSigpending,
                128 => Operation::RtSigtimedwait,
                130 => Operation::RtSigsuspend,
                131 => Operation::Sigaltstack,
                133 => Operation::Mknod,
                140 => Operation::Getpriority,
                141 => Operation::Setpriority,
                158 => Operation::ArchPrctl,
                160 => Operation::Setrlimit,
                170 => Operation::Sethostname,
                171 => Operation::Setdomainname,
                186 => Operation::Gettid,
                188 => Operation::Setxattr,
                189 => Operation::Lsetxattr,
                190 => Operation::Fsetxattr,
                191 => Operation::Getxattr,
                192 => Operation::Lgetxattr,
                193 => Operation::Fgetxattr,
                194 => Operation::Listxattr,
                195 => Operation::Llistxattr,
                196 => Operation::Flistxattr,
                197 => Operation::Removexattr,
                198 => Operation::Lremovexattr,
                199 => Operation::Fremovexattr,
                200 => Operation::Tkill,
                201 => Operation::Time,
                202 => Operation::Futex,
                204 => Operation::SchedGetaffinity,
                213 => Operation::EpollCreate,
                217 => Operation::Getdents64,
                218 => Operation::SetTidAddress,
                227 => Operation::ClockSettime,
                228 => Operation::ClockGettime,
                229 => Operation::ClockGetres,
                230 => Operation::ClockNanosleep,
                231 => Operation::ExitGroup,
                232 => Operation::EpollWait,
                233 => Operation::EpollCtl,
                234 => Operation::Tgkill,
                257 => Operation::Openat,
                258 => Operation::Mkdirat,
                259 => Operation::Mknodat,
                260 => Operation::Fchownat,
                262 => Operation::Newfstatat,
                263 => Operation::Unlinkat,
                264 => Operation::Renameat,
                265 => Operation::Linkat,
                266 => Operation::Symlinkat,
                267 => Operation::Readlinkat,
                268 => Operation::Fchmodat,
                269 => Operation::Faccessat,
                270 => Operation::Pselect6,
                271 => Operation::Ppoll,
                273 => Operation::SetRobustList,
                274 => Operation::GetRobustList,
                280 => Operation::Utimensat,
                281 => Operation::EpollPwait,
                284 => Operation::Eventfd,
                288 => Operation::Accept4,
                290 => Operation::Eventfd2,
                291 => Operation::EpollCreate1,
                292 => Operation::Dup3,
                293 => Operation::Pipe2,
                295 => Operation::Preadv,
                296 => Operation::Pwritev,
                299 => Operation::Recvmmsg,
                302 => Operation::Prlimit64,
                307 => Operation::Sendmmsg,
                316 => Operation::Renameat2,
                318 => Operation::Getrandom,
                327 => Operation::Preadv2,
                328 => Operation::Pwritev2,
                332 => Operation::Statx,
                435 => Operation::Clone3,
                436 => Operation::CloseRange,
                439 => Operation::Faccessat2,
                452 => Operation::Fchmodat2,
                _ => Operation::Unknown,
            },
            // include/uapi/asm-generic/unistd.h, which has none of the
            // legacy calls (pipe, dup2, epoll_create, epoll_wait, eventfd,
            // open, stat, lstat, poll, select, access, mkdir, rmdir, creat,
            // link, unlink, symlink, readlink, rename, chmod, chown, lchown,
            // mknod, time) and no arch_prctl.
            Self::Aarch64 => match number {
                5 => Operation::Setxattr,
                6 => Operation::Lsetxattr,
                7 => Operation::Fsetxattr,
                8 => Operation::Getxattr,
                9 => Operation::Lgetxattr,
                10 => Operation::Fgetxattr,
                11 => Operation::Listxattr,
                12 => Operation::Llistxattr,
                13 => Operation::Flistxattr,
                14 => Operation::Removexattr,
                15 => Operation::Lremovexattr,
                16 => Operation::Fremovexattr,
                17 => Operation::Getcwd,
                19 => Operation::Eventfd2,
                20 => Operation::EpollCreate1,
                21 => Operation::EpollCtl,
                22 => Operation::EpollPwait,
                23 => Operation::Dup,
                24 => Operation::Dup3,
                25 => Operation::Fcntl,
                29 => Operation::Ioctl,
                33 => Operation::Mknodat,
                34 => Operation::Mkdirat,
                35 => Operation::Unlinkat,
                36 => Operation::Symlinkat,
                37 => Operation::Linkat,
                38 => Operation::Renameat,
                45 => Operation::Truncate,
                46 => Operation::Ftruncate,
                48 => Operation::Faccessat,
                49 => Operation::Chdir,
                50 => Operation::Fchdir,
                52 => Operation::Fchmod,
                53 => Operation::Fchmodat,
                54 => Operation::Fchownat,
                55 => Operation::Fchown,
                56 => Operation::Openat,
                57 => Operation::Close,
                59 => Operation::Pipe2,
                61 => Operation::Getdents64,
                62 => Operation::Lseek,
                63 => Operation::Read,
                64 => Operation::Write,
                65 => Operation::Readv,
                66 => Operation::Writev,
                67 => Operation::Pread64,
                68 => Operation::Pwrite64,
                69 => Operation::Preadv,
                70 => Operation::Pwritev,
                71 => Operation::Sendfile,
                72 => Operation::Pselect6,
                73 => Operation::Ppoll,
                78 => Operation::Readlinkat,
                79 => Operation::Newfstatat,
                80 => Operation::Fstat,
                82 => Operation::Fsync,
                83 => Operation::Fdatasync,
                88 => Operation::Utimensat,
                90 => Operation::Capget,
                91 => Operation::Capset,
                93 => Operation::Exit,
                94 => Operation::ExitGroup,
                96 => Operation::SetTidAddress,
                98 => Operation::Futex,
                99 => Operation::SetRobustList,
                100 => Operation::GetRobustList,
                101 => Operation::Nanosleep,
                102 => Operation::Getitimer,
                103 => Operation::Setitimer,
                112 => Operation::ClockSettime,
                113 => Operation::ClockGettime,
                114 => Operation::ClockGetres,
                115 => Operation::ClockNanosleep,
                123 => Operation::SchedGetaffinity,
                124 => Operation::SchedYield,
                129 => Operation::Kill,
                130 => Operation::Tkill,
                131 => Operation::Tgkill,
                132 => Operation::Sigaltstack,
                133 => Operation::RtSigsuspend,
                134 => Operation::RtSigaction,
                135 => Operation::RtSigprocmask,
                136 => Operation::RtSigpending,
                137 => Operation::RtSigtimedwait,
                139 => Operation::RtSigreturn,
                140 => Operation::Setpriority,
                141 => Operation::Getpriority,
                143 => Operation::Setregid,
                144 => Operation::Setgid,
                145 => Operation::Setreuid,
                146 => Operation::Setuid,
                147 => Operation::Setresuid,
                148 => Operation::Getresuid,
                149 => Operation::Setresgid,
                150 => Operation::Getresgid,
                158 => Operation::Getgroups,
                159 => Operation::Setgroups,
                160 => Operation::Uname,
                161 => Operation::Sethostname,
                162 => Operation::Setdomainname,
                163 => Operation::Getrlimit,
                164 => Operation::Setrlimit,
                166 => Operation::Umask,
                169 => Operation::Gettimeofday,
                172 => Operation::Getpid,
                174 => Operation::Getuid,
                175 => Operation::Geteuid,
                176 => Operation::Getgid,
                177 => Operation::Getegid,
                178 => Operation::Gettid,
                179 => Operation::Sysinfo,
                198 => Operation::Socket,
                199 => Operation::Socketpair,
                200 => Operation::Bind,
                201 => Operation::Listen,
                202 => Operation::Accept,
                203 => Operation::Connect,
                204 => Operation::Getsockname,
                205 => Operation::Getpeername,
                206 => Operation::Sendto,
                207 => Operation::Recvfrom,
                208 => Operation::Setsockopt,
                209 => Operation::Getsockopt,
                210 => Operation::Shutdown,
                211 => Operation::Sendmsg,
                212 => Operation::Recvmsg,
                214 => Operation::Brk,
                215 => Operation::Munmap,
                216 => Operation::Mremap,
                220 => Operation::Clone,
                222 => Operation::Mmap,
                226 => Operation::Mprotect,
                227 => Operation::Msync,
                233 => Operation::Madvise,
                242 => Operation::Accept4,
                243 => Operation::Recvmmsg,
                261 => Operation::Prlimit64,
                269 => Operation::Sendmmsg,
                276 => Operation::Renameat2,
                278 => Operation::Getrandom,
                286 => Operation::Preadv2,
                287 => Operation::Pwritev2,
                291 => Operation::Statx,
                435 => Operation::Clone3,
                436 => Operation::CloseRange,
                439 => Operation::Faccessat2,
                452 => Operation::Fchmodat2,
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

    /// The user stack-pointer register of this ABI.
    pub fn stack_pointer_register(self) -> RegisterId {
        match self {
            Self::X86_64 => RegisterId::X86Gpr(4),
            Self::Aarch64 => RegisterId::Aarch64Sp,
        }
    }

    /// The user program-counter register of this ABI.
    pub fn program_counter_register(self) -> RegisterId {
        match self {
            Self::X86_64 => RegisterId::X86Rip,
            Self::Aarch64 => RegisterId::Aarch64Pc,
        }
    }

    /// Width in bytes of the system-call instruction (`syscall` = 2 bytes on
    /// x86-64; `svc #0` = 4 bytes on AArch64), subtracted from the saved PC
    /// when restarting an interrupted system call (`arch/x86/kernel/signal.c`,
    /// `arch/arm64/kernel/signal.c`).
    pub const fn syscall_instruction_bytes(self) -> u64 {
        match self {
            Self::X86_64 => 2,
            Self::Aarch64 => 4,
        }
    }

    /// Minimum alternate signal stack size (`MINSIGSTKSZ` in Linux v6.12
    /// `arch/x86/include/uapi/asm/signal.h` and
    /// `arch/arm64/include/uapi/asm/signal.h`).
    pub const fn min_sigstksz(self) -> u64 {
        match self {
            Self::X86_64 => 2048,
            Self::Aarch64 => 5120,
        }
    }

    /// Kernel-provided `rt_sigreturn` trampoline instructions when the ABI
    /// supplies one in a user-executable page for handlers registered without
    /// `SA_RESTORER` (`arch/arm64/kernel/vdso/sigreturn.S`: `mov x8, #139;
    /// svc #0`). x86-64 supplies none and requires `SA_RESTORER`.
    pub const fn sigreturn_trampoline_code(self) -> Option<&'static [u8]> {
        match self {
            Self::X86_64 => None,
            // `mov x8, #139` (0xd280_1168) ; `svc #0` (0xd400_0001)
            Self::Aarch64 => Some(&[0x68, 0x11, 0x80, 0xd2, 0x01, 0x00, 0x00, 0xd4]),
        }
    }

    /// Decodes the register order of `clone(2)` (`kernel/fork.c`
    /// `SYSCALL_DEFINE5(clone)`): `CONFIG_CLONE_BACKWARDS` on arm64 swaps
    /// `tls` and `child_tid` relative to x86-64.
    pub fn clone_registers(self, args: [u64; 6]) -> CloneRegisters {
        match self {
            Self::X86_64 => CloneRegisters {
                flags: args[0],
                stack: args[1],
                parent_tid: args[2],
                child_tid: args[3],
                tls: args[4],
            },
            Self::Aarch64 => CloneRegisters {
                flags: args[0],
                stack: args[1],
                parent_tid: args[2],
                tls: args[3],
                child_tid: args[4],
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

    /// Linux's `TASK_SIZE` for this ABI's processes: the end of the
    /// addresses a mapping may reach. x86-64 keeps the last page below the
    /// canonical hole unmappable (`TASK_SIZE_MAX`, (1 << 47) - PAGE_SIZE in
    /// arch/x86/include/asm/page_64_types.h); arm64 ends at 1 << VA_BITS
    /// (`TASK_SIZE_64`, arch/arm64/include/asm/processor.h) with the 48-bit
    /// user range Helios's TTBR0 provides.
    pub fn task_size(self) -> u64 {
        match self {
            Self::X86_64 => (1 << 47) - 4096,
            Self::Aarch64 => 1 << 48,
        }
    }

    /// The ELF `e_machine` of this ABI's executables (System V gABI).
    pub fn elf_machine(self) -> u16 {
        match self {
            Self::X86_64 => 62,
            Self::Aarch64 => 183,
        }
    }

    /// `O_DIRECTORY` bit for this ABI (`arch/arm64/include/uapi/asm/fcntl.h`
    /// swaps bits 14..17 relative to `include/uapi/asm-generic/fcntl.h`).
    pub const fn o_directory(self) -> u64 {
        match self {
            Self::X86_64 => 1 << 16,
            Self::Aarch64 => 1 << 14,
        }
    }

    /// `O_NOFOLLOW` bit for this ABI.
    pub const fn o_nofollow(self) -> u64 {
        match self {
            Self::X86_64 => 1 << 17,
            Self::Aarch64 => 1 << 15,
        }
    }

    /// `O_DIRECT` bit for this ABI.
    pub const fn o_direct(self) -> u64 {
        match self {
            Self::X86_64 => 1 << 14,
            Self::Aarch64 => 1 << 16,
        }
    }

    /// `O_LARGEFILE` bit for this ABI.
    pub const fn o_largefile(self) -> u64 {
        match self {
            Self::X86_64 => 1 << 15,
            Self::Aarch64 => 1 << 17,
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
pub const SIGABRT: u8 = 6;
pub const SIGBUS: u8 = 7;
pub const SIGFPE: u8 = 8;
pub const SIGKILL: u8 = 9;
pub const SIGSEGV: u8 = 11;

/// The signal Linux raises for a user fault of `kind`
/// (arch/x86/kernel/traps.c and arch/x86/mm/fault.c).
pub fn fault_signal(kind: FaultKind) -> u8 {
    match kind {
        FaultKind::Page { .. } | FaultKind::Protection => SIGSEGV,
        FaultKind::InvalidInstruction => SIGILL,
        FaultKind::Arithmetic => SIGFPE,
        FaultKind::Breakpoint => SIGTRAP,
        // arch/arm64/kernel/traps.c and arch/arm64/mm/fault.c (`do_sea`).
        FaultKind::Alignment | FaultKind::Bus => SIGBUS,
    }
}

/// Encodes `termination` into the 16-bit status word `wait4(2)` writes
/// (`kernel/exit.c` `wait_task_zombie`, `include/uapi/linux/wait.h`):
/// `(code & 0xff) << 8` on exit, `(signal & 0x7f) | (core_dumped << 7)`
/// on signal death, `SIGABRT` on a trap, and `SIGKILL` on an owner kill.
pub fn wait_status(termination: helios_unix::ChildTermination) -> i32 {
    match termination {
        helios_unix::ChildTermination::Exited(code) => ((code & 0xff) as i32) << 8,
        helios_unix::ChildTermination::Signaled(helios_unix::SignalTermination {
            signal,
            core_dumped,
        }) => i32::from(signal & 0x7f) | (i32::from(core_dumped) << 7),
        helios_unix::ChildTermination::Trapped => i32::from(SIGABRT),
        helios_unix::ChildTermination::Killed => i32::from(SIGKILL),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use helios_unix::{ChildTermination, SignalTermination};

    #[test]
    fn wait_status_encodes_each_termination_kind() {
        assert_eq!(wait_status(ChildTermination::Exited(0)), 0);
        assert_eq!(wait_status(ChildTermination::Exited(42)), 42 << 8);
        assert_eq!(wait_status(ChildTermination::Exited(0x1ff)), 0xff << 8);
        assert_eq!(
            wait_status(ChildTermination::Signaled(SignalTermination {
                signal: SIGSEGV,
                core_dumped: false,
            })),
            i32::from(SIGSEGV),
        );
        assert_eq!(
            wait_status(ChildTermination::Signaled(SignalTermination {
                signal: SIGSEGV,
                core_dumped: true,
            })),
            i32::from(SIGSEGV) | 0x80,
        );
        assert_eq!(wait_status(ChildTermination::Trapped), i32::from(SIGABRT));
        assert_eq!(wait_status(ChildTermination::Killed), i32::from(SIGKILL));
    }
}
