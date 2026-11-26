//! Process creation (`fork`, `vfork`, `clone`/`clone3` without `CLONE_THREAD`),
//! image replacement (`execve`, `execveat`), child waiting (`wait4`, `waitid`),
//! and process-group / session management (`getppid`, `getpgid`, `getpgrp`,
//! `setpgid`, `getsid`, `setsid`).
//!
//! Semantics and error precedence follow Linux v6.12 (`kernel/fork.c`,
//! `kernel/exit.c`, `kernel/sys.c`, `fs/exec.c`).
//!
//! # Concurrency contract
//!
//! - Process-tree relationships, zombie records, and process-group/session IDs
//!   live inside [`PidNamespace`] behind its short synchronous `spin::Mutex`,
//!   never held across an `.await`.
//! - Blocking `wait4` / `waitid` and `vfork` waits park on lock-free
//!   [`Notify`] waiters armed before releasing any spin lock, so child exits,
//!   stops, continues, `vfork` completions, and signals never lose wakeups.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::future::poll_fn;
use core::num::NonZeroU32;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use core::task::Poll;

use helios_sync::Notify;
use helios_unix::{ChildTermination, Signal};

use super::signal::ProcessSignals;
use super::system::Credentials;
use super::thread::{
    CLONE_CHILD_CLEARTID, CLONE_CHILD_SETTID, CLONE_CLEAR_SIGHAND, CLONE_DETACHED, CLONE_FILES,
    CLONE_FS, CLONE_IO, CLONE_PARENT, CLONE_PARENT_SETTID, CLONE_SETTLS, CLONE_SIGHAND,
    CLONE_SYSVSEM, CLONE_UNTRACED, CLONE_VFORK, CLONE_VM, ParsedClone, write_tid,
};
use super::{
    EFAULT, EINVAL, ENOMEM, EPERM, ESRCH, GroupLifecycle, Process, ProcessShared, Resources,
    SpawnError, SyscallOutcome, Thread, UserMemory, errno,
};
use crate::signal_frame::{
    CLD_CONTINUED, CLD_DUMPED, CLD_EXITED, CLD_KILLED, CLD_STOPPED, SIGINFO_SIZE, SigInfo,
    SigInfoPayload,
};

// Linux UAPI constants (`include/uapi/linux/wait.h`, `include/uapi/linux/fcntl.h`,
// `include/uapi/asm-generic/errno-base.h`).
const E2BIG: u64 = 7;
const ENOEXEC: u64 = 8;
const EBADF: u64 = 9;
const ECHILD: u64 = 10;
const EAGAIN: u64 = 11;
const EACCES: u64 = 13;
const ENOTDIR: u64 = 20;
const EISDIR: u64 = 21;
const ENAMETOOLONG: u64 = 36;
const ELOOP: u64 = 40;
const ENOENT: u64 = 2;
const EIO: u64 = 5;
const ENOSYS: u64 = 38;

const WNOHANG: u32 = 1;
const WUNTRACED: u32 = 2;
const WSTOPPED: u32 = 2;
const WEXITED: u32 = 4;
const WCONTINUED: u32 = 8;
const WNOWAIT: u32 = 0x0100_0000;
const __WNOTHREAD: u32 = 0x2000_0000;
const __WALL: u32 = 0x4000_0000;
const __WCLONE: u32 = 0x8000_0000;

const P_ALL: u32 = 0;
const P_PID: u32 = 1;
const P_PGID: u32 = 2;

const AT_FDCWD: i32 = -100;
pub const AT_SYMLINK_NOFOLLOW: u32 = 0x100;
pub const AT_EMPTY_PATH: u32 = 0x1000;

/// Size of LP64 `struct rusage` (`include/uapi/linux/resource.h`).
const RUSAGE_BYTES: usize = 144;
/// Maximum executable pathname length (`PATH_MAX`).
const PATH_MAX: usize = 4096;
/// Maximum argument / environment entries and combined byte budget.
const MAX_EXEC_STRINGS: usize = 4096;
const MAX_EXEC_BYTES: usize = 2 * 1024 * 1024;

const ALLOWED_PROCESS_CLONE_FLAGS: u64 = CLONE_VM
    | CLONE_FS
    | CLONE_FILES
    | CLONE_SIGHAND
    | CLONE_VFORK
    | CLONE_PARENT
    | CLONE_SYSVSEM
    | CLONE_SETTLS
    | CLONE_PARENT_SETTID
    | CLONE_CHILD_CLEARTID
    | CLONE_DETACHED
    | CLONE_UNTRACED
    | CLONE_CHILD_SETTID
    | CLONE_IO
    | CLONE_CLEAR_SIGHAND;

/// One-shot completion latch shared between a `vfork`/`CLONE_VFORK` parent
/// and child so the parent stays suspended until the child calls `execve` or
/// exits (`kernel/fork.c` `wait_for_vfork_done`).
pub struct VforkDone {
    done: AtomicBool,
    notify: Notify,
}

impl VforkDone {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            done: AtomicBool::new(false),
            notify: Notify::new(),
        })
    }

    pub fn complete(&self) {
        if !self.done.swap(true, Ordering::AcqRel) {
            self.notify.notify_all();
        }
    }

    pub async fn wait(&self) {
        loop {
            let mut waiter = self.notify.waiter();
            if self.done.load(Ordering::Acquire) {
                return;
            }
            poll_fn(|cx| self.notify.poll_notified(cx, &mut waiter)).await;
        }
    }
}

/// A newly created child process handed to [`Thread::spawn_process`].
pub struct SpawnedProcess<R: Resources> {
    pub child: Process<R>,
    /// True for `vfork` / `CLONE_VM` (share parent's `UserSpace` directly);
    /// false for `fork` (duplicate parent's `UserSpace` copy-on-write).
    pub share_vm: bool,
    /// Optional stack pointer override (`clone`/`clone3`).
    pub stack: Option<u64>,
    /// Optional TLS override (`CLONE_SETTLS`).
    pub tls: Option<u64>,
    /// When `CLONE_CHILD_SETTID` is set, write the child's PID to this address
    /// in the child's address space after cloning it.
    pub child_tid_addr: Option<u64>,
}

/// Decoded arguments of `execve` / `execveat` handed to [`Thread::prepare_exec`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecSpec {
    pub dirfd: i32,
    pub path: String,
    pub argv: Vec<String>,
    pub envp: Vec<String>,
    pub flags: u32,
}

/// Typed refusal from loading or validating an `execve` / `execveat` target.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ExecError {
    #[error("executable not found")]
    NoEntry,
    #[error("permission denied")]
    Access,
    #[error("path component is not a directory")]
    NotDir,
    #[error("cannot execute a directory")]
    IsDir,
    #[error("too many levels of symbolic links")]
    Loop,
    #[error("pathname too long")]
    NameTooLong,
    #[error("unrecognized or malformed executable format")]
    InvalidFormat,
    #[error("out of memory")]
    OutOfMemory,
    #[error("bad file descriptor")]
    BadFd,
    #[error("invalid argument")]
    InvalidArg,
    #[error("I/O error reading executable")]
    Io,
}

impl ExecError {
    pub const fn to_errno(self) -> u64 {
        match self {
            Self::NoEntry => ENOENT,
            Self::Access => EACCES,
            Self::NotDir => ENOTDIR,
            Self::IsDir => EISDIR,
            Self::Loop => ELOOP,
            Self::NameTooLong => ENAMETOOLONG,
            Self::InvalidFormat => ENOEXEC,
            Self::OutOfMemory => ENOMEM,
            Self::BadFd => EBADF,
            Self::InvalidArg => EINVAL,
            Self::Io => EIO,
        }
    }
}

/// Lifecycle state of one process as visible to its parent's `wait4`/`waitid`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ChildWaitState {
    Running,
    Stopped { signal: Signal, reported: bool },
    Continued { reported: bool },
    Exited(ChildTermination),
}

/// One reportable child event extracted by `PidNamespace::try_wait`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct WaitEvent {
    pub pid: u32,
    pub uid: u32,
    pub kind: WaitEventKind,
    pub usage: super::system::CpuUsage,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum WaitEventKind {
    Exited(ChildTermination),
    Stopped(Signal),
    Continued,
}

impl WaitEvent {
    /// Linux `wstatus` encoding (`include/uapi/linux/wait.h`).
    pub fn encode_wstatus(self) -> i32 {
        match self.kind {
            WaitEventKind::Exited(ChildTermination::Exited(code)) => ((code & 0xff) << 8) as i32,
            WaitEventKind::Exited(ChildTermination::Signaled(sig)) => {
                let core_bit = if sig.core_dumped { 0x80 } else { 0 };
                ((u32::from(sig.signal) & 0x7f) | core_bit) as i32
            }
            WaitEventKind::Exited(ChildTermination::Trapped) => i32::from(Signal::SIGABRT.raw()),
            WaitEventKind::Exited(ChildTermination::Killed) => i32::from(Signal::SIGKILL.raw()),
            WaitEventKind::Stopped(sig) => ((i32::from(sig.raw()) & 0xff) << 8) | 0x7f,
            WaitEventKind::Continued => 0xffff,
        }
    }

    /// Linux `waitid` `siginfo_t` encoding (`kernel/exit.c` `wait_task_zombie`,
    /// `wait_task_stopped`, `wait_task_continued`).
    pub fn encode_siginfo(self) -> SigInfo {
        let (code, status) = match self.kind {
            WaitEventKind::Exited(ChildTermination::Exited(exit)) => {
                (CLD_EXITED, (exit & 0xff) as i32)
            }
            WaitEventKind::Exited(ChildTermination::Signaled(sig)) => (
                if sig.core_dumped {
                    CLD_DUMPED
                } else {
                    CLD_KILLED
                },
                i32::from(sig.signal),
            ),
            WaitEventKind::Exited(ChildTermination::Trapped) => {
                (CLD_KILLED, i32::from(Signal::SIGABRT.raw()))
            }
            WaitEventKind::Exited(ChildTermination::Killed) => {
                (CLD_KILLED, i32::from(Signal::SIGKILL.raw()))
            }
            WaitEventKind::Stopped(sig) => (CLD_STOPPED, i32::from(sig.raw())),
            WaitEventKind::Continued => (CLD_CONTINUED, i32::from(Signal::SIGCONT.raw())),
        };
        SigInfo {
            signo: Signal::SIGCHLD,
            errno: 0,
            code,
            payload: SigInfoPayload::Child {
                pid: self.pid,
                uid: self.uid,
                status,
            },
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum WaitTarget {
    Any,
    Pid(u32),
    Pgid(u32),
}

/// Which children `wait4`/`waitid` considers based on `__WALL` / `__WCLONE`
/// (`kernel/exit.c` `eligible_child`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum WaitCloneFilter {
    /// Neither `__WALL` nor `__WCLONE`: only children whose exit signal is `SIGCHLD`.
    Standard,
    /// `__WCLONE` without `__WALL`: only children whose exit signal is not `SIGCHLD`.
    CloneOnly,
    /// `__WALL`: all children regardless of exit signal.
    All,
}

impl WaitCloneFilter {
    pub(super) const fn from_options(options: u32) -> Self {
        if options & __WALL != 0 {
            Self::All
        } else if options & __WCLONE != 0 {
            Self::CloneOnly
        } else {
            Self::Standard
        }
    }

    pub(super) fn matches(self, exit_signal: Option<Signal>) -> bool {
        let is_clone = exit_signal != Some(Signal::SIGCHLD);
        match self {
            Self::Standard => !is_clone,
            Self::CloneOnly => is_clone,
            Self::All => true,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum TryWaitResult {
    Event(WaitEvent),
    Pending,
    NoChildren,
}

/// Metadata stored per process in [`PidNamespace`] for parent/child tracking,
/// job control (`pgid`/`sid`), `wait4`/`waitid`, `PR_SET_PDEATHSIG`,
/// `PR_SET_CHILD_SUBREAPER`, and child resource usage accounting.
pub(super) struct ProcessTreeRecord {
    pub ppid: u32,
    /// TID of the parent thread that forked/cloned this process (for `PR_SET_PDEATHSIG`).
    pub parent_tid: u32,
    pub pgid: NonZeroU32,
    pub sid: NonZeroU32,
    pub exit_signal: Option<Signal>,
    pub has_execed: bool,
    pub is_child_subreaper: bool,
    pub pdeathsig: Option<Signal>,
    pub usage: super::system::CpuUsage,
    pub state: ChildWaitState,
    pub signals: Arc<ProcessSignals>,
    pub credentials: Arc<spin::Mutex<Credentials>>,
    pub sched: Arc<spin::Mutex<super::thread::ThreadSchedState>>,
}

impl ProcessTreeRecord {
    pub fn new_root(
        pid: NonZeroU32,
        signals: Arc<ProcessSignals>,
        credentials: Arc<spin::Mutex<Credentials>>,
        sched: Arc<spin::Mutex<super::thread::ThreadSchedState>>,
    ) -> Self {
        Self {
            ppid: 0,
            parent_tid: 0,
            pgid: pid,
            sid: pid,
            exit_signal: Some(Signal::SIGCHLD),
            has_execed: false,
            is_child_subreaper: false,
            pdeathsig: None,
            usage: super::system::CpuUsage::default(),
            state: ChildWaitState::Running,
            signals,
            credentials,
            sched,
        }
    }

    pub fn is_live(&self) -> bool {
        !matches!(self.state, ChildWaitState::Exited(_))
    }

    pub fn real_uid(&self) -> u32 {
        self.credentials.lock().user.real
    }
}

/// Validates flags for a non-`CLONE_THREAD` process clone (`kernel/fork.c`).
pub(super) fn validate_process_clone_flags(
    flags: u64,
    exit_signal_raw: u64,
) -> Result<Option<Signal>, u64> {
    if flags & CLONE_SIGHAND != 0 && flags & CLONE_VM == 0 {
        return Err(EINVAL);
    }
    if flags & CLONE_SIGHAND != 0 && flags & CLONE_CLEAR_SIGHAND != 0 {
        return Err(EINVAL);
    }
    if flags & !ALLOWED_PROCESS_CLONE_FLAGS != 0 {
        return Err(ENOSYS);
    }
    let exit_signal = if exit_signal_raw == 0 {
        None
    } else {
        match u8::try_from(exit_signal_raw).ok().and_then(Signal::new) {
            Some(sig) => Some(sig),
            None => return Err(EINVAL),
        }
    };
    Ok(exit_signal)
}

/// `fork()` (x86-64 syscall 57).
pub(super) async fn fork<R: Resources, M: UserMemory, T: Thread<R>, F: super::fs::Filesystem<R>>(
    process: &Process<R>,
    memory: &mut M,
    thread: &mut T,
    fs: &mut F,
) -> u64 {
    clone_process(
        process,
        ParsedClone {
            flags: 0,
            stack: None,
            parent_tid: 0,
            child_tid: 0,
            tls: 0,
        },
        Some(Signal::SIGCHLD),
        memory,
        thread,
        fs,
    )
    .await
}

/// `vfork()` (x86-64 syscall 58).
pub(super) async fn vfork<
    R: Resources,
    M: UserMemory,
    T: Thread<R>,
    F: super::fs::Filesystem<R>,
>(
    process: &Process<R>,
    memory: &mut M,
    thread: &mut T,
    fs: &mut F,
) -> u64 {
    clone_process(
        process,
        ParsedClone {
            flags: CLONE_VM | CLONE_VFORK,
            stack: None,
            parent_tid: 0,
            child_tid: 0,
            tls: 0,
        },
        Some(Signal::SIGCHLD),
        memory,
        thread,
        fs,
    )
    .await
}

/// Creates a new child process (`fork`, `vfork`, or `clone`/`clone3` without
/// `CLONE_THREAD`) inside the parent's container [`PidNamespace`].
pub(super) async fn clone_process<
    R: Resources,
    M: UserMemory,
    T: Thread<R>,
    F: super::fs::Filesystem<R>,
>(
    process: &Process<R>,
    parsed: ParsedClone,
    exit_signal: Option<Signal>,
    memory: &mut M,
    thread: &mut T,
    fs: &mut F,
) -> u64 {
    let tls = if parsed.flags & CLONE_SETTLS != 0 {
        if parsed.tls >= process.shared.abi.task_size() {
            return errno(EPERM);
        }
        Some(parsed.tls)
    } else {
        None
    };

    let parent_pid = process.pid();
    let (ppid, pgid, sid) = if parsed.flags & CLONE_PARENT != 0 {
        if parent_pid.get() == 1 {
            return errno(EINVAL);
        }
        let parent_ppid = process.shared.pids.ppid(parent_pid.get());
        let pgid = process
            .shared
            .pids
            .pgid(parent_pid.get())
            .unwrap_or(parent_pid);
        let sid = process
            .shared
            .pids
            .sid(parent_pid.get())
            .unwrap_or(parent_pid);
        (parent_ppid, pgid, sid)
    } else {
        let pgid = process
            .shared
            .pids
            .pgid(parent_pid.get())
            .unwrap_or(parent_pid);
        let sid = process
            .shared
            .pids
            .sid(parent_pid.get())
            .unwrap_or(parent_pid);
        (parent_pid.get(), pgid, sid)
    };

    // Enforce container `RLIMIT_NPROC`.
    let nproc = process.limit(super::Resource::Nproc).current;
    if u64::from(process.shared.pids.process_count()) >= nproc {
        return errno(EAGAIN);
    }

    let child_pid = match process.shared.pids.allocate_process() {
        Ok(pid) => pid,
        Err(err) => return errno(err),
    };

    if parsed.flags & CLONE_PARENT_SETTID != 0
        && write_tid(parsed.parent_tid, child_pid.get(), memory)
            .await
            .is_err()
    {
        process.shared.pids.release_process(child_pid);
        return errno(EFAULT);
    }

    let share_vm = parsed.flags & CLONE_VM != 0;
    if !share_vm {
        // Flush any dirty writable `MAP_SHARED` pages before `clone_cow` marks
        // them shared so neither parent nor child loses pre-fork writes while
        // untouched CoW pages are skipped on subsequent flushes.
        super::memory::flush_all_shared_mappings(process, memory, fs).await;
    }
    let vfork_done = (parsed.flags & CLONE_VFORK != 0).then(VforkDone::new);

    let child_descriptors = if parsed.flags & CLONE_FILES != 0 {
        process.shared.descriptors.clone()
    } else {
        Arc::new(spin::Mutex::new(process.shared.descriptors.lock().clone()))
    };
    let child_program_break = if share_vm {
        process.shared.program_break.clone()
    } else {
        Arc::new(spin::Mutex::new(
            process.shared.program_break.lock().clone(),
        ))
    };
    let child_memory_id = if share_vm {
        process.shared.memory_id
    } else {
        helios_unix::ProcessMemoryIdentity::new(
            (process
                .shared
                .memory_id
                .raw()
                .wrapping_mul(0x9e37_79b9_7f4a_7c15))
                ^ u64::from(child_pid.get()),
        )
    };

    let child_creds = Arc::new(spin::Mutex::new(process.credentials.lock().clone()));
    let child_sched = Arc::new(spin::Mutex::new(process.sched.lock().clone_for_fork()));
    let child_attrs = process.shared.attributes.lock().clone();
    let child_stdin_carry = process.shared.stdin_carry.lock().clone();
    let share_sighand = parsed.flags & CLONE_SIGHAND != 0;
    let clear_sighand = parsed.flags & CLONE_CLEAR_SIGHAND != 0;
    let child_signals =
        process
            .shared
            .signals
            .clone_for_fork(child_pid, share_sighand, clear_sighand);
    child_signals.set_pgid(pgid.get());
    let child_thread_signals =
        child_signals.register_thread(child_pid, process.signals.current_mask());
    child_thread_signals.set_altstack(process.signals.clone_altstack());

    let parent_tid_val = if parsed.flags & CLONE_PARENT != 0 {
        ppid
    } else {
        process.tid.get()
    };
    process.shared.pids.register_child_process(
        child_pid,
        ppid,
        parent_tid_val,
        pgid,
        sid,
        exit_signal,
        child_signals.clone(),
        child_creds.clone(),
        child_sched.clone(),
    );
    process.shared.pids.register_thread(
        child_pid,
        child_thread_signals.clone(),
        child_creds.clone(),
        child_sched.clone(),
    );

    let robust_list = Arc::new(AtomicU64::new(0));
    let lifecycle = Arc::new(GroupLifecycle {
        threads: spin::Mutex::new(super::thread::ThreadGroup::new(
            child_pid,
            process.shared.pids.clone(),
            robust_list.clone(),
        )),
        changed: Notify::new(),
    });

    let (child_cwd, child_root) = if parsed.flags & CLONE_FS != 0 {
        (process.shared.cwd.clone(), process.shared.root.clone())
    } else {
        (
            Arc::new(spin::Mutex::new(process.shared.cwd.lock().clone())),
            Arc::new(spin::Mutex::new(process.shared.root.lock().clone())),
        )
    };
    let (child_shared_mappings, inherited_shmids) = if share_vm {
        (process.shared.shared_mappings.clone(), Vec::new())
    } else {
        let (cloned, shmids) = super::memory::clone_vmas_for_fork(process);
        for &shmid in &shmids {
            fs.shm_fork_attach(shmid);
        }
        (Arc::new(spin::Mutex::new(cloned)), shmids)
    };
    let child_memfds: Vec<(i32, R::File)> = {
        let table = child_descriptors.lock();
        table
            .entries
            .iter()
            .enumerate()
            .filter_map(|(idx, slot)| {
                let entry = slot.as_ref()?;
                let helios_unix::FileDescriptor::File(open) = &entry.descriptor else {
                    return None;
                };
                fs.memfd_handle(open.node())
                    .map(|_| (idx as i32, open.node().clone()))
            })
            .collect()
    };

    let child = Process {
        shared: Arc::new(ProcessShared {
            abi: process.shared.abi,
            identity: helios_unix::ProcessIdentity::new(child_pid.into()),
            memory_id: child_memory_id,
            pids: process.shared.pids.clone(),
            futex: process.shared.futex.clone(),
            descriptors: child_descriptors,
            cwd: child_cwd,
            root: child_root,
            shared_mappings: child_shared_mappings,
            next_shm_attach_id: AtomicU64::new(
                process
                    .shared
                    .next_shm_attach_id
                    .load(Ordering::Relaxed)
                    .max(1),
            ),
            stdin_lock: helios_sync::RawMutex::new(),
            stdin_carry: spin::Mutex::new(child_stdin_carry),
            attributes: spin::Mutex::new(child_attrs),
            children_usage: spin::Mutex::new(super::system::CpuUsage::default()),
            program_break: child_program_break,
            signals: child_signals,
            threads: lifecycle,
            vfork_done: spin::Mutex::new(vfork_done.clone()),
        }),
        tid: child_pid,
        signals: child_thread_signals,
        credentials: child_creds,
        sched: child_sched,
        clear_child_tid: if parsed.flags & CLONE_CHILD_CLEARTID != 0 {
            parsed.child_tid
        } else {
            0
        },
        robust_list,
        exited: false,
    };

    let child_tid_addr = (parsed.flags & CLONE_CHILD_SETTID != 0).then_some(parsed.child_tid);
    match thread
        .spawn_process(SpawnedProcess {
            child,
            share_vm,
            stack: parsed.stack,
            tls,
            child_tid_addr,
        })
        .await
    {
        Ok(()) => {
            if !child_memfds.is_empty() {
                fs.sync_process_memfds(child_pid.get(), &child_memfds);
            }
            if let Some(done) = vfork_done {
                done.wait().await;
            }
            u64::from(child_pid.get())
        }
        Err(error) => {
            for shmid in inherited_shmids {
                fs.shm_fork_rollback(shmid);
            }
            process.shared.pids.release_process(child_pid);
            errno(match error {
                SpawnError::OutOfMemory => ENOMEM,
                SpawnError::Busy => EAGAIN,
                SpawnError::InvalidTls => EPERM,
            })
        }
    }
}

/// Reads a NUL-terminated UTF-8 string up to `max_bytes` from user memory.
async fn read_c_string<M: UserMemory>(
    memory: &M,
    mut ptr: u64,
    max_bytes: usize,
    too_long_err: u64,
) -> Result<String, u64> {
    if ptr == 0 {
        return Err(EFAULT);
    }
    let mut bytes = Vec::new();
    let mut chunk = [0u8; 64];
    loop {
        let remaining = max_bytes.saturating_sub(bytes.len()) + 1;
        let to_read = chunk.len().min(remaining);
        // Try reading a chunk; if the tail straddles an unmapped page boundary,
        // fall back to byte-by-byte until the NUL terminator or fault.
        let slice = if memory.read(ptr, &mut chunk[..to_read]).await.is_ok() {
            &chunk[..to_read]
        } else {
            let mut byte = [0u8; 1];
            memory.read(ptr, &mut byte).await.map_err(|_| EFAULT)?;
            chunk[0] = byte[0];
            &chunk[..1]
        };
        if let Some(nul) = slice.iter().position(|&b| b == 0) {
            bytes.extend_from_slice(&slice[..nul]);
            return String::from_utf8(bytes).map_err(|_| EINVAL);
        }
        bytes.extend_from_slice(slice);
        if bytes.len() > max_bytes {
            return Err(too_long_err);
        }
        ptr = ptr.checked_add(slice.len() as u64).ok_or(EFAULT)?;
    }
}

/// Reads a NULL-terminated array of C-string pointers (`argv` or `envp`).
async fn read_c_string_array<M: UserMemory>(
    memory: &M,
    mut array_ptr: u64,
    total_bytes: &mut usize,
) -> Result<Vec<String>, u64> {
    if array_ptr == 0 {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    let mut raw = [0u8; 8];
    loop {
        memory.read(array_ptr, &mut raw).await.map_err(|_| EFAULT)?;
        let item_ptr = u64::from_le_bytes(raw);
        if item_ptr == 0 {
            return Ok(out);
        }
        if out.len() >= MAX_EXEC_STRINGS {
            return Err(E2BIG);
        }
        let budget = MAX_EXEC_BYTES.saturating_sub(*total_bytes);
        let value = read_c_string(memory, item_ptr, budget, E2BIG).await?;
        *total_bytes = total_bytes.saturating_add(value.len() + 1);
        if *total_bytes > MAX_EXEC_BYTES {
            return Err(E2BIG);
        }
        out.push(value);
        array_ptr = array_ptr.checked_add(8).ok_or(EFAULT)?;
    }
}

/// `execve(pathname, argv, envp)` (`fs/exec.c`).
pub(super) async fn execve<R: Resources, M: UserMemory, T: Thread<R>>(
    args: [u64; 6],
    memory: &M,
    thread: &mut T,
) -> SyscallOutcome {
    execve_common(
        AT_FDCWD, args[0], args[1], args[2], 0, false, memory, thread,
    )
    .await
}

/// `execveat(dirfd, pathname, argv, envp, flags)` (`fs/exec.c`).
pub(super) async fn execveat<R: Resources, M: UserMemory, T: Thread<R>>(
    args: [u64; 6],
    memory: &M,
    thread: &mut T,
) -> SyscallOutcome {
    execve_common(
        args[0] as u32 as i32,
        args[1],
        args[2],
        args[3],
        args[4] as u32,
        true,
        memory,
        thread,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn execve_common<R: Resources, M: UserMemory, T: Thread<R>>(
    dirfd: i32,
    path_ptr: u64,
    argv_ptr: u64,
    envp_ptr: u64,
    flags: u32,
    is_execveat: bool,
    memory: &M,
    thread: &mut T,
) -> SyscallOutcome {
    if flags & !(AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW) != 0 {
        return SyscallOutcome::Return(errno(EINVAL));
    }
    let path = match read_c_string(memory, path_ptr, PATH_MAX, ENAMETOOLONG).await {
        Ok(path) => path,
        Err(err) => return SyscallOutcome::Return(errno(err)),
    };
    if path.is_empty() && (!is_execveat || flags & AT_EMPTY_PATH == 0) {
        return SyscallOutcome::Return(errno(ENOENT));
    }
    let mut total_bytes = 0usize;
    let argv = match read_c_string_array(memory, argv_ptr, &mut total_bytes).await {
        Ok(argv) => argv,
        Err(err) => return SyscallOutcome::Return(errno(err)),
    };
    let envp = match read_c_string_array(memory, envp_ptr, &mut total_bytes).await {
        Ok(envp) => envp,
        Err(err) => return SyscallOutcome::Return(errno(err)),
    };

    match thread
        .prepare_exec(ExecSpec {
            dirfd,
            path,
            argv,
            envp,
            flags,
        })
        .await
    {
        Ok(()) => SyscallOutcome::Exec,
        Err(err) => SyscallOutcome::Return(errno(err.to_errno())),
    }
}

/// `wait4(pid, wstatus, options, rusage)` (`kernel/exit.c` `do_wait`).
pub(super) async fn wait4<R: Resources, M: UserMemory>(
    process: &Process<R>,
    args: [u64; 6],
    memory: &mut M,
) -> SyscallOutcome {
    let raw_pid = args[0] as u32 as i32;
    let wstatus_ptr = args[1];
    let options = args[2] as u32;
    let rusage_ptr = args[3];

    let allowed = WNOHANG | WUNTRACED | WCONTINUED | __WALL | __WCLONE | __WNOTHREAD;
    if options & !allowed != 0 {
        return SyscallOutcome::Return(errno(EINVAL));
    }
    if wstatus_ptr != 0 && memory.check_writable(wstatus_ptr, 4).await.is_err() {
        return SyscallOutcome::Return(errno(EFAULT));
    }
    if rusage_ptr != 0
        && memory
            .check_writable(rusage_ptr, RUSAGE_BYTES)
            .await
            .is_err()
    {
        return SyscallOutcome::Return(errno(EFAULT));
    }

    let caller_pid = process.pid();
    let target = if raw_pid > 0 {
        WaitTarget::Pid(raw_pid as u32)
    } else if raw_pid == -1 {
        WaitTarget::Any
    } else if raw_pid == 0 {
        let pgid = process
            .shared
            .pids
            .pgid(caller_pid.get())
            .unwrap_or(caller_pid);
        WaitTarget::Pgid(pgid.get())
    } else if raw_pid == i32::MIN {
        return SyscallOutcome::Return(errno(ECHILD));
    } else {
        WaitTarget::Pgid((-raw_pid) as u32)
    };

    let want_exited = true;
    let want_stopped = options & WUNTRACED != 0;
    let want_continued = options & WCONTINUED != 0;
    let nohang = options & WNOHANG != 0;
    let clone_filter = WaitCloneFilter::from_options(options);

    loop {
        let mut wait_notify = process.shared.pids.wait_waiter();
        let mut sig_notify = process.signals.signal_waiter();

        match process.shared.pids.try_wait(
            caller_pid,
            target,
            clone_filter,
            want_exited,
            want_stopped,
            want_continued,
            false,
        ) {
            TryWaitResult::Event(event) => {
                if matches!(event.kind, WaitEventKind::Exited(_)) {
                    process.shared.children_usage.lock().accumulate(event.usage);
                }
                if wstatus_ptr != 0
                    && memory
                        .write(wstatus_ptr, &event.encode_wstatus().to_le_bytes())
                        .await
                        .is_err()
                {
                    return SyscallOutcome::Return(errno(EFAULT));
                }
                if rusage_ptr != 0
                    && memory
                        .write(rusage_ptr, &event.usage.encode_rusage())
                        .await
                        .is_err()
                {
                    return SyscallOutcome::Return(errno(EFAULT));
                }
                return SyscallOutcome::Return(u64::from(event.pid));
            }
            TryWaitResult::NoChildren => return SyscallOutcome::Return(errno(ECHILD)),
            TryWaitResult::Pending if nohang => return SyscallOutcome::Return(0),
            TryWaitResult::Pending => {}
        }

        if process.signals.has_deliverable_signal() {
            return SyscallOutcome::RestartSys;
        }

        poll_fn(|cx| {
            if process
                .shared
                .pids
                .poll_wait_changed(cx, &mut wait_notify)
                .is_ready()
                || process
                    .signals
                    .poll_signal_waiter(cx, &mut sig_notify)
                    .is_ready()
            {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await;
    }
}

/// `waitid(idtype, id, infop, options, rusage)` (`kernel/exit.c` `kernel_waitid`).
pub(super) async fn waitid<R: Resources, M: UserMemory>(
    process: &Process<R>,
    args: [u64; 6],
    memory: &mut M,
) -> SyscallOutcome {
    let idtype = args[0] as u32;
    let id = args[1] as u32;
    let infop = args[2];
    let options = args[3] as u32;
    let rusage_ptr = args[4];

    let allowed =
        WNOHANG | WSTOPPED | WEXITED | WCONTINUED | WNOWAIT | __WALL | __WCLONE | __WNOTHREAD;
    if options & !allowed != 0 || options & (WEXITED | WSTOPPED | WCONTINUED) == 0 {
        return SyscallOutcome::Return(errno(EINVAL));
    }

    let target = match idtype {
        P_ALL => WaitTarget::Any,
        P_PID => {
            if id == 0 {
                return SyscallOutcome::Return(errno(EINVAL));
            }
            WaitTarget::Pid(id)
        }
        P_PGID => {
            let pgid = if id == 0 {
                process
                    .shared
                    .pids
                    .pgid(process.pid().get())
                    .unwrap_or_else(|| process.pid())
                    .get()
            } else {
                id
            };
            WaitTarget::Pgid(pgid)
        }
        _ => return SyscallOutcome::Return(errno(EINVAL)),
    };

    if infop != 0 && memory.check_writable(infop, SIGINFO_SIZE).await.is_err() {
        return SyscallOutcome::Return(errno(EFAULT));
    }
    if rusage_ptr != 0
        && memory
            .check_writable(rusage_ptr, RUSAGE_BYTES)
            .await
            .is_err()
    {
        return SyscallOutcome::Return(errno(EFAULT));
    }

    let caller_pid = process.pid();
    let want_exited = options & WEXITED != 0;
    let want_stopped = options & WSTOPPED != 0;
    let want_continued = options & WCONTINUED != 0;
    let nowait = options & WNOWAIT != 0;
    let nohang = options & WNOHANG != 0;
    let clone_filter = WaitCloneFilter::from_options(options);

    loop {
        let mut wait_notify = process.shared.pids.wait_waiter();
        let mut sig_notify = process.signals.signal_waiter();

        match process.shared.pids.try_wait(
            caller_pid,
            target,
            clone_filter,
            want_exited,
            want_stopped,
            want_continued,
            nowait,
        ) {
            TryWaitResult::Event(event) => {
                if !nowait && matches!(event.kind, WaitEventKind::Exited(_)) {
                    process.shared.children_usage.lock().accumulate(event.usage);
                }
                if infop != 0 {
                    let encoded = event.encode_siginfo().encode();
                    if memory.write(infop, &encoded).await.is_err() {
                        return SyscallOutcome::Return(errno(EFAULT));
                    }
                }
                if rusage_ptr != 0
                    && memory
                        .write(rusage_ptr, &event.usage.encode_rusage())
                        .await
                        .is_err()
                {
                    return SyscallOutcome::Return(errno(EFAULT));
                }
                return SyscallOutcome::Return(0);
            }
            TryWaitResult::NoChildren => return SyscallOutcome::Return(errno(ECHILD)),
            TryWaitResult::Pending if nohang => {
                if infop != 0 && memory.write(infop, &[0u8; SIGINFO_SIZE]).await.is_err() {
                    return SyscallOutcome::Return(errno(EFAULT));
                }
                return SyscallOutcome::Return(0);
            }
            TryWaitResult::Pending => {}
        }

        if process.signals.has_deliverable_signal() {
            return SyscallOutcome::RestartSys;
        }

        poll_fn(|cx| {
            if process
                .shared
                .pids
                .poll_wait_changed(cx, &mut wait_notify)
                .is_ready()
                || process
                    .signals
                    .poll_signal_waiter(cx, &mut sig_notify)
                    .is_ready()
            {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await;
    }
}

/// `getppid()` (`kernel/sys.c`).
pub(super) fn getppid<R: Resources>(process: &Process<R>) -> u64 {
    u64::from(process.shared.pids.ppid(process.pid().get()))
}

/// `getpgid(pid)` (`kernel/sys.c`).
pub(super) fn getpgid<R: Resources>(process: &Process<R>, args: [u64; 6]) -> u64 {
    let pid = args[0] as u32 as i32;
    if pid < 0 {
        return errno(ESRCH);
    }
    let query = if pid == 0 {
        process.pid().get()
    } else {
        pid as u32
    };
    match process.shared.pids.pgid(query) {
        Some(pgid) => u64::from(pgid.get()),
        None => errno(ESRCH),
    }
}

/// `getpgrp()` (x86-64 syscall 111, equivalent to `getpgid(0)`).
pub(super) fn getpgrp<R: Resources>(process: &Process<R>) -> u64 {
    getpgid(process, [0; 6])
}

/// `setpgid(pid, pgid)` (`kernel/sys.c`).
pub(super) fn setpgid<R: Resources>(process: &Process<R>, args: [u64; 6]) -> u64 {
    let raw_pid = args[0] as u32 as i32;
    let raw_pgid = args[1] as u32 as i32;
    let pid = if raw_pid == 0 {
        process.pid().get() as i32
    } else {
        raw_pid
    };
    let pgid = if raw_pgid == 0 { pid } else { raw_pgid };
    if pgid < 0 {
        return errno(EINVAL);
    }
    if pid < 0 {
        return errno(ESRCH);
    }
    match process
        .shared
        .pids
        .setpgid(process.pid(), pid as u32, pgid as u32)
    {
        Ok(()) => 0,
        Err(err) => errno(err),
    }
}

/// `getsid(pid)` (`kernel/sys.c`).
pub(super) fn getsid<R: Resources>(process: &Process<R>, args: [u64; 6]) -> u64 {
    let pid = args[0] as u32 as i32;
    if pid < 0 {
        return errno(ESRCH);
    }
    let query = if pid == 0 {
        process.pid().get()
    } else {
        pid as u32
    };
    match process.shared.pids.sid(query) {
        Some(sid) => u64::from(sid.get()),
        None => errno(ESRCH),
    }
}

/// `setsid()` (`kernel/sys.c`).
pub(super) fn setsid<R: Resources>(process: &Process<R>) -> u64 {
    match process.shared.pids.setsid(process.pid()) {
        Ok(sid) => u64::from(sid.get()),
        Err(err) => errno(err),
    }
}
