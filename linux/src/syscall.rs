use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use bytes::Bytes;
use core::convert::Infallible;
use core::future::Future;
use core::num::NonZeroU32;
use core::ops::ControlFlow;
use core::sync::atomic::AtomicU64;
use core::task::{Context, Poll};
use helios_hal::native::{UserContext, UserFault};
use helios_hal::vmm::PageFlags;
use helios_sync::{Notify, NotifyWaiter, RawMutex};
use helios_unix::{
    ChildTermination, DescriptorSlots, FDFLAG_NONBLOCK, FileDescriptor, FileDescriptorEntry,
    FutexTable, NoNetwork, ProcessIdentity, ProcessMemoryIdentity, Signal, SignalSet,
    SocketNetwork,
};

mod fs;
mod fs_extra;
mod futex;
mod icmp;
mod io;
mod memory;
mod netlink;
mod packet;
pub mod permissions;
mod poll;
mod process;
pub mod shm;
mod signal;
mod socket;
mod system;
mod thread;
mod tty;

pub use crate::abi::{Abi, Operation};
pub use crate::signal_frame::SignalFrameError;
pub use fs::{
    ANON_INODE_FS_MAGIC, AccessCheck, BTRFS_SUPER_MAGIC, DirListEntry, EROFS_SUPER_MAGIC_V1,
    FileAccess, FileStat, Filesystem, FsOpError, FsStat, LinkOptions, OVERLAYFS_SUPER_MAGIC,
    OpenOutcome, OpenRequest, PIPEFS_MAGIC, PROC_SUPER_MAGIC, SOCKFS_MAGIC, ST_NODEV, ST_NOEXEC,
    ST_NOSUID, ST_RDONLY, ST_VALID, SYSFS_MAGIC, TMPFS_MAGIC, TimeUpdate, V9FS_MAGIC, XattrSetMode,
};
pub use icmp::{IPPROTO_ICMP, IPPROTO_ICMPV6, IcmpDatagram};
pub use io::Clock;
pub use memory::{FileVmaLookup, VmaBacking};
pub use netlink::{AF_NETLINK, NETLINK_ROUTE};
pub use packet::AF_PACKET;
pub use process::{
    AT_EMPTY_PATH, AT_SYMLINK_NOFOLLOW, ExecError, ExecSpec, SpawnedProcess, VforkDone,
};
pub use shm::{
    CAP_IPC_LOCK, CAP_IPC_OWNER, IPC_64, IPC_CREAT, IPC_EXCL, IPC_INFO, IPC_NOWAIT, IPC_PRIVATE,
    IPC_RMID, IPC_SET, IPC_STAT, MFD_ALLOW_SEALING, MFD_CLOEXEC, MFD_EXEC, MFD_HUGETLB,
    MFD_NOEXEC_SEAL, SHM_DEST, SHM_EXEC, SHM_HUGETLB, SHM_INFO, SHM_INFO_BYTES, SHM_LOCK,
    SHM_LOCKED, SHM_NORESERVE, SHM_RDONLY, SHM_REMAP, SHM_RND, SHM_STAT, SHM_STAT_ANY, SHM_UNLOCK,
    SHMALL, SHMID64_DS_BYTES, SHMINFO64_BYTES, SHMLBA, SHMMAX, SHMMIN, SHMMNI, SHMSEG, ShmPerm,
    ShmStat, ShmUsageInfo, check_ipc_owner_or_admin, check_ipc_perms, encode_shminfo64,
};
pub use signal::{ProcessSignals, SignalDelivery, SyscallRestart, ThreadSignalSlot};
pub use socket::{
    AcceptedVsockStream, ConnectProgress, EADDRINUSE, EADDRNOTAVAIL, EAFNOSUPPORT, EAGAIN,
    EALREADY, ECONNABORTED, ECONNREFUSED, ECONNRESET, EDESTADDRREQ, EHOSTUNREACH, EINPROGRESS,
    EISCONN, EMSGSIZE, ENETDOWN, ENETUNREACH, ENOPROTOOPT, ENOTCONN, ENOTSOCK, EPIPE,
    EPROTONOSUPPORT, EPROTOTYPE, ETIMEDOUT, IpAddr, Ipv4InterfaceAddress, Ipv4RouteEntry, Network,
    PacketFrameData, SocketAddr, SocketReady,
};
pub use system::{
    CAP_CHOWN, CAP_DAC_OVERRIDE, CAP_DAC_READ_SEARCH, CAP_FOWNER, CAP_FSETID, CAP_FULL_SET,
    CAP_KILL, CAP_LAST_CAP, CAP_MKNOD, CAP_NET_ADMIN, CAP_NET_BIND_SERVICE, CAP_NET_BROADCAST,
    CAP_NET_RAW, CAP_SETFCAP, CAP_SETGID, CAP_SETPCAP, CAP_SETUID, CAP_SYS_ADMIN, CAP_SYS_CHROOT,
    CAP_SYS_NICE, CAP_SYS_RESOURCE, CAP_SYS_TIME, CAP_SYSLOG, CpuUsage, Credentials,
    CredentialsError, Ids, LinuxCapabilities, MemoryTotals, NGROUPS_MAX, NR_OPEN_DEFAULT, RELEASE,
    RLIM_INFINITY, Resource, Rlimit, Start, System, UTS_FIELD_MAX, UtsField, UtsNameError,
};
pub use thread::{PidNamespace, PidNamespaceTelemetry};
pub use tty::{Termios, TermiosAction, Tty, TtyError, TtyStream, Winsize};

/// The platform objects a process's descriptors can hold besides the UNIX
/// objects `helios-unix` owns (pipes, eventfds, epoll sets, sockets): the
/// host's files, the network its sockets live on, and the user data its
/// epoll interests carry. A process shares descriptors with programs of
/// another ABI by naming the same resource set they use.
pub trait Resources: 'static {
    type File: Clone + Send + Sync;
    type Network: SocketNetwork;
    type Data: EpollData + Send + Sync;
}

/// User data an epoll interest carries, as Linux's 64-bit `epoll_data`.
pub trait EpollData: Clone {
    fn from_linux(data: u64) -> Self;
    fn to_linux(&self) -> u64;
}

impl EpollData for u64 {
    fn from_linux(data: u64) -> Self {
        data
    }
    fn to_linux(&self) -> u64 {
        *self
    }
}

/// A resource set with no files and no network: its only sockets are
/// socket pairs.
pub struct NoBacking;
impl Resources for NoBacking {
    type File = Infallible;
    type Network = NoNetwork;
    type Data = u64;
}

pub type Descriptor<R> =
    FileDescriptor<<R as Resources>::File, <R as Resources>::Network, <R as Resources>::Data>;
pub type Entry<R> =
    FileDescriptorEntry<<R as Resources>::File, <R as Resources>::Network, <R as Resources>::Data>;
pub type Descriptors<R> = DescriptorSlots<Entry<R>>;

/// The descriptor table a process started by no other process holds:
/// standard input, output and error at 0, 1 and 2.
pub fn standard_streams<R: Resources>() -> Descriptors<R> {
    DescriptorSlots::from_entries(alloc::vec![
        Some(Entry::<R>::new(
            Descriptor::<R>::Stdin {
                carry: Bytes::new()
            },
            false
        )),
        Some(Entry::<R>::new(Descriptor::<R>::Stdout, false)),
        Some(Entry::<R>::new(Descriptor::<R>::Stderr, false)),
    ])
}

/// A fault reported by the address-space owner, before any bytes are exposed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("inaccessible user address")]
pub struct MemoryFault;

pub trait UserMemory: Send + Sync {
    /// Copies exactly `output.len()` readable bytes. The implementation owns
    /// mapping synchronization and faults in swapped pages asynchronously; no
    /// user reference may escape this operation.
    fn read<'a>(
        &'a self,
        address: u64,
        output: &'a mut [u8],
    ) -> impl Future<Output = Result<(), MemoryFault>> + Send + 'a;
    /// Validates a writable range without modifying it.
    fn check_writable(
        &self,
        address: u64,
        length: usize,
    ) -> impl Future<Output = Result<(), MemoryFault>> + Send + '_;
    /// Copies bytes only into writable user mappings, faulting in swapped
    /// pages asynchronously.
    fn write<'a>(
        &'a mut self,
        address: u64,
        bytes: &'a [u8],
    ) -> impl Future<Output = Result<(), MemoryFault>> + Send + 'a;
    /// Atomically loads a 4-byte-aligned 32-bit word from readable user memory.
    fn atomic_load_u32(
        &self,
        address: u64,
    ) -> impl Future<Output = Result<u32, MemoryFault>> + Send + '_;
    /// Non-blocking atomic 32-bit load for spin-locked callers such as
    /// `FUTEX_CMP_REQUEUE`. Returns `Ok(Some(value))` when resident, `Ok(None)`
    /// when the page is swapped out (caller must drop its lock, await
    /// [`Self::atomic_load_u32`], and retry), or `Err(MemoryFault)` when
    /// inaccessible.
    fn try_atomic_load_u32(&self, address: u64) -> Result<Option<u32>, MemoryFault>;
    /// Atomically stores a 4-byte-aligned 32-bit word into writable user memory.
    fn atomic_store_u32(
        &mut self,
        address: u64,
        value: u32,
    ) -> impl Future<Output = Result<(), MemoryFault>> + Send + '_;
    /// Atomically compares and replaces a 4-byte-aligned 32-bit word in
    /// readable and writable user memory.
    fn atomic_compare_exchange_u32(
        &mut self,
        address: u64,
        expected: u32,
        desired: u32,
    ) -> impl Future<Output = Result<Result<u32, u32>, MemoryFault>> + Send + '_;
    /// Whether the page containing `address` is still shared copy-on-write
    /// with another address space (untouched since `fork(2)`).
    fn is_page_shared(&self, _address: u64) -> bool {
        false
    }
    /// Reads mapped bytes regardless of user `PageFlags::READ` permission
    /// (e.g. after `mprotect(PROT_NONE)`), defaulting to [`Self::read`].
    fn read_unrestricted<'a>(
        &'a self,
        address: u64,
        output: &'a mut [u8],
    ) -> impl Future<Output = Result<(), MemoryFault>> + Send + 'a {
        self.read(address, output)
    }
    /// Collects dirty `(file_offset, bytes)` runs from a file-backed
    /// `MAP_SHARED` object over `[file_offset, file_offset + valid_len)`.
    /// Returns `None` when the backing memory does not track shared objects.
    fn collect_shared_dirty(
        &self,
        _object_id: u64,
        _file_offset: u64,
        _valid_len: u64,
    ) -> Option<Vec<(u64, Vec<u8>)>> {
        None
    }
    /// Updates the clean baseline of shared object `object_id` after `bytes`
    /// at `file_offset` have been written back to the backing file.
    fn mark_shared_clean(&self, _object_id: u64, _file_offset: u64, _bytes: &[u8]) {}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MapError {
    #[error("user memory exhausted")]
    OutOfMemory,
    #[error("the range lies outside the mappable user range")]
    Address,
    #[error("the range is already mapped")]
    Occupied,
}

/// A run of pages mapped contiguously with one access, `[start, end)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Region {
    pub start: u64,
    pub end: u64,
    pub access: PageFlags,
}

/// The process's address space as its memory-map system calls change it.
/// Every range is page aligned, nonempty and below the ABI's `TASK_SIZE`;
/// the caller has validated it with Linux's errors. The process's shared
/// address-space lock serialises multi-step compositions across threads.
pub trait VirtualMemory: UserMemory {
    /// The lowest address the space maps.
    fn lowest_address(&self) -> u64;

    /// Installs zero-filled private pages at the first free range at or
    /// above `hint`, else anywhere, and returns where.
    fn map_anywhere(&mut self, hint: u64, length: u64, access: PageFlags) -> Result<u64, MapError>;

    /// Installs zero-filled private pages at `address`, which must have no
    /// mapping. Failure leaves the space unchanged.
    fn map_at(&mut self, address: u64, length: u64, access: PageFlags) -> Result<(), MapError>;

    /// Removes every mapping of the range; unmapped pages are skipped.
    fn unmap(&mut self, address: u64, length: u64);

    /// Replaces the access of the range, every page of which is mapped.
    fn protect(&mut self, address: u64, length: u64, access: PageFlags) -> Result<(), MapError>;

    /// Drops the contents of every mapped page of the range, which reads as
    /// zeros afterwards and holds no memory until it is touched.
    fn discard(&mut self, address: u64, length: u64);

    /// Moves `[from, from + length)`, one region, to `to`, which has no
    /// mapping, extending it with zero-filled pages of the same access to
    /// `new_length`. Failure leaves the space unchanged.
    fn remap(&mut self, from: u64, length: u64, to: u64, new_length: u64) -> Result<(), MapError>;

    /// The first region of `[start, end)`, clipped to it.
    fn region(&self, start: u64, end: u64) -> Option<Region>;

    /// The first free range of `length` bytes at or above `hint`, else
    /// anywhere.
    fn free_range(&self, hint: u64, length: u64) -> Option<u64>;

    /// Populates already-mapped pages starting at `address` with `bytes`
    /// regardless of their user write permission, committing frames from the
    /// user memory pool on demand and returning [`MapError::OutOfMemory`] on
    /// exhaustion.
    fn populate<'a>(
        &'a mut self,
        address: u64,
        bytes: &'a [u8],
    ) -> impl Future<Output = Result<(), MapError>> + Send + 'a {
        async move {
            self.write(address, bytes)
                .await
                .map_err(|_| MapError::Address)
        }
    }

    /// Creates a fresh anonymous shared memory object and returns its
    /// process-local ID (`0` when unsupported by a lightweight test mock).
    fn create_shared_anonymous(&mut self) -> u64 {
        0
    }

    /// Acquires or creates the container-wide shared memory object for a
    /// regular file identified by `(dev, ino)` (`0` when unsupported).
    fn acquire_shared_file(&mut self, _dev: u64, _ino: u64) -> u64 {
        0
    }

    /// Acquires the container-wide shared memory object for SysV shared memory
    /// segment `shmid` (`0` when unsupported by a lightweight test mock).
    fn acquire_sysv_shm(&mut self, _shmid: i32) -> u64 {
        0
    }

    /// Populates `page_index` inside shared object `object_id` with initial
    /// file `bytes` if absent, preserving any existing resident frame.
    fn load_shared_page(
        &mut self,
        _object_id: u64,
        _page_index: u64,
        _bytes: &[u8],
    ) -> Result<(), MapError> {
        Ok(())
    }

    /// Releases an unused temporary shared object (e.g. when staging fails).
    fn release_shared_object(&mut self, _object_id: u64) {}

    /// Maps `[address, address + length)` backed by shared object `object_id`
    /// starting at `object_offset`, attaching resident pages covering
    /// `attach_len` bytes.
    fn map_shared_at(
        &mut self,
        address: u64,
        length: u64,
        access: PageFlags,
        _object_id: u64,
        _object_offset: u64,
        _attach_len: u64,
    ) -> Result<(), MapError> {
        self.map_at(address, length, access)
    }

    /// Same as [`Self::map_shared_at`] at the first free range at or above `hint`.
    fn map_shared_anywhere(
        &mut self,
        hint: u64,
        length: u64,
        access: PageFlags,
        _object_id: u64,
        _object_offset: u64,
        _attach_len: u64,
    ) -> Result<u64, MapError> {
        self.map_anywhere(hint, length, access)
    }

    /// Maps a file-backed `MAP_PRIVATE` range at `address` and transfers any
    /// staged frames from `stage_id` (consuming `stage_id`), leaving pages
    /// beyond `staged_len` uncommitted so beyond-EOF touches raise `SIGBUS`.
    fn map_private_file_at(
        &mut self,
        address: u64,
        length: u64,
        access: PageFlags,
        _stage_id: u64,
        _staged_len: u64,
    ) -> Result<(), MapError> {
        self.map_at(address, length, access)
    }

    /// Same as [`Self::map_private_file_at`] at the first free range at or above `hint`.
    fn map_private_file_anywhere(
        &mut self,
        hint: u64,
        length: u64,
        access: PageFlags,
        _stage_id: u64,
        _staged_len: u64,
    ) -> Result<u64, MapError> {
        self.map_anywhere(hint, length, access)
    }

    /// Applies a `write(2)` / `pwrite(2)` update to shared object `object_id`
    /// (updating live shared frames and clean baselines). Returns `true` when
    /// handled through the shared object.
    fn apply_shared_file_write(
        &mut self,
        _object_id: u64,
        _file_offset: u64,
        _bytes: &[u8],
    ) -> bool {
        false
    }

    /// Notifies the address space that `[start, end)` was unmapped so shared
    /// VMA metadata stays synchronized.
    fn unmap_shared_vma(&mut self, _start: u64, _end: u64) {}

    /// Notifies the address space that `[from, from + old_len)` was remapped
    /// to `[to, to + new_len)` so shared VMA metadata stays synchronized.
    fn remap_shared_vma(&mut self, _from: u64, _old_len: u64, _to: u64, _new_len: u64) {}

    /// Attaches resident pages from `object_id` covering `[address, address + attach_len)`
    /// starting at `object_offset` (used when `mremap` grows a `MAP_SHARED` mapping).
    fn attach_shared_tail(
        &mut self,
        _address: u64,
        _object_id: u64,
        _object_offset: u64,
        _attach_len: u64,
    ) -> Result<(), MapError> {
        Ok(())
    }
}

/// Initial stack and TLS overrides for a cloned thread.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpawnedThread {
    /// Initial user stack pointer (`Some(sp)`), or `None` to inherit the
    /// calling thread's stack pointer.
    pub stack: Option<u64>,
    /// Initial thread pointer when `CLONE_SETTLS` is set, or `None` to
    /// inherit the calling thread's thread pointer.
    pub tls: Option<u64>,
}

/// Why the execution host could not start a cloned thread.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SpawnError {
    #[error("user or kernel memory exhausted")]
    OutOfMemory,
    #[error("thread task capacity exhausted")]
    Busy,
    #[error("invalid thread-pointer address")]
    InvalidTls,
}

/// The calling thread's execution context: its thread pointer (`arch_prctl`),
/// user stack pointer (`sigaltstack`), and spawning a sibling thread sharing
/// this process (`clone` / `clone3`).
pub trait Thread<R: Resources = NoBacking> {
    fn thread_pointer(&self) -> u64;
    /// Refused for an address outside the user range.
    fn set_thread_pointer(&mut self, address: u64) -> Result<(), Denied>;
    /// Current user stack pointer, used by `sigaltstack` to report `SS_ONSTACK`
    /// and refuse changes while executing on the alternate stack.
    fn stack_pointer(&self) -> u64 {
        0
    }
    /// Duplicates the calling thread's user context with `state` and starts
    /// `child` on its own task with syscall result `0`.
    fn spawn_thread(&mut self, child: Process<R>, state: SpawnedThread) -> Result<(), SpawnError>;

    /// Duplicates the calling process (`fork`, `vfork`, or `clone`/`clone3`
    /// without `CLONE_THREAD`) and starts the child process with syscall
    /// result `0`.
    fn spawn_process(
        &mut self,
        _process: SpawnedProcess<R>,
    ) -> impl Future<Output = Result<(), SpawnError>> + Send {
        async { Err(SpawnError::Busy) }
    }

    /// Loads and validates the target executable for `execve`/`execveat`,
    /// stashing the prepared image on the host so returning
    /// [`SyscallOutcome::Exec`] replaces the process atomically.
    fn prepare_exec(
        &mut self,
        _spec: ExecSpec,
    ) -> impl Future<Output = Result<(), ExecError>> + Send {
        async { Err(ExecError::NoEntry) }
    }
}

/// Outcome of a non-exiting system call returned by [`dispatch`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyscallOutcome {
    /// Normal return value to write into the ABI's result register.
    Return(u64),
    /// Interrupted syscall eligible for `SA_RESTART` (Linux `-ERESTARTSYS`).
    RestartSys,
    /// Interrupted syscall that returns `-EINTR` if any handler runs and
    /// restarts only if no handler runs (Linux `-ERESTARTNOHAND`).
    RestartNoHand,
    /// `rt_sigreturn`: the driver must restore the thread context from the
    /// user signal frame and must not overwrite the restored result register.
    SigReturn,
    /// `execve` / `execveat`: the host prepared the replacement image via
    /// [`Thread::prepare_exec`] and must now commit the exec transition.
    Exec,
}

/// How an `exit` or `exit_group` system call ends execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exit {
    /// `exit(2)`: ends the calling thread alone; ends the process with this
    /// status only when no sibling thread remains.
    Thread(u8),
    /// `exit_group(2)`: condemns every thread of the process with this status.
    Group(u8),
}

impl Exit {
    pub const fn status(self) -> u8 {
        match self {
            Self::Thread(status) | Self::Group(status) => status,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stream {
    Stdout,
    Stderr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum WriteError {
    #[error("output interrupted")]
    Interrupted,
    #[error("output failed")]
    Io,
    #[error("the process's authority does not reach this output")]
    Denied,
    #[error("non-blocking output would block")]
    WouldBlock,
}

/// Non-blocking standard-input read outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StdinTryRead {
    Ready(Bytes),
    Eof,
    WouldBlock,
    Denied,
}

/// Readiness event mask bits (matching Linux `POLLIN`/`POLLOUT`/`POLLERR`/`POLLHUP`).
pub const READY_IN: u32 = poll::POLLIN;
pub const READY_OUT: u32 = poll::POLLOUT;
pub const READY_ERR: u32 = poll::POLLERR;
pub const READY_HUP: u32 = poll::POLLHUP;

/// A refusal by the process's authority, or of an address it may not use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("refused")]
pub struct Denied;

/// Where the standard-stream descriptors lead: the terminal, a parent's
/// channel, or a log, as the process's host routes them. The host refuses
/// a stream its process's authority does not reach.
pub trait Stdio {
    /// Writes up to the supplied length, including short writes. The buffer
    /// belongs to the caller and remains stable across suspension.
    fn write(
        &mut self,
        stream: Stream,
        bytes: &[u8],
    ) -> impl Future<Output = Result<usize, WriteError>> + Send;

    /// Non-blocking write for `O_NONBLOCK` stdout/stderr descriptors.
    fn try_write(&mut self, _stream: Stream, _bytes: &[u8]) -> Result<usize, WriteError> {
        Err(WriteError::WouldBlock)
    }

    /// Waits for standard input and returns what arrived, at most `limit`
    /// bytes; empty at the end of input.
    fn read_input(&mut self, limit: usize) -> impl Future<Output = Result<Bytes, Denied>> + Send;

    /// Non-blocking read for `O_NONBLOCK` stdin descriptors.
    fn try_read_input(&mut self, _limit: usize) -> StdinTryRead {
        StdinTryRead::WouldBlock
    }

    /// Current readiness mask (`READY_IN`, `READY_HUP`, `READY_ERR`) for standard input.
    fn stdin_ready_mask(&self) -> u32 {
        0
    }

    /// Waits until standard input readiness may have changed (data arrived or EOF).
    fn wait_stdin_ready(&self) -> impl Future<Output = ()> + Send {
        core::future::pending()
    }

    /// Current readiness mask (`READY_OUT`, `READY_ERR`) for stdout/stderr.
    fn stdout_ready_mask(&self, _stream: Stream) -> u32 {
        READY_OUT
    }
}

/// A system call as its ABI's registers carry it.
#[derive(Debug, Clone, Copy)]
pub struct Call {
    pub number: u64,
    pub arguments: [u64; 6],
}

// Linux uapi/asm-generic/errno-base.h and errno.h.
const EPERM: u64 = 1;
const ESRCH: u64 = 3;
const EINTR: u64 = 4;
const EIO: u64 = 5;
const EBADF: u64 = 9;
const ENOMEM: u64 = 12;
const EACCES: u64 = 13;
const EFAULT: u64 = 14;
pub const ENODEV: u64 = 19;
const EINVAL: u64 = 22;
const ENOTTY: u64 = 25;
const ENOSYS: u64 = 38;
const EOPNOTSUPP: u64 = 95;
const MAX_RW_COUNT: u64 = 0x7fff_f000; // Linux INT_MAX rounded down to a page.

struct GroupLifecycle {
    threads: spin::Mutex<thread::ThreadGroup>,
    /// Broadcast whenever the group is condemned (`exit_group`, fatal signal,
    /// fault) or when the last live thread withdraws.
    changed: Notify,
}

/// Handle for observing and condemning a thread group's lifecycle without
/// retaining its descriptor table or other process resources.
#[derive(Clone)]
pub struct ProcessObserver {
    lifecycle: Arc<GroupLifecycle>,
}

impl ProcessObserver {
    pub fn group_ended(&self) -> bool {
        self.lifecycle.threads.lock().group_ended()
    }

    pub fn all_threads_exited(&self) -> bool {
        self.lifecycle.threads.lock().all_exited()
    }

    pub fn termination(&self) -> ChildTermination {
        self.lifecycle.threads.lock().termination()
    }

    pub fn waiter(&self) -> NotifyWaiter {
        self.lifecycle.changed.waiter()
    }

    pub fn poll_changed(&self, cx: &mut Context<'_>, waiter: &mut NotifyWaiter) -> Poll<()> {
        self.lifecycle.changed.poll_notified(cx, waiter)
    }

    pub fn terminate_group(&self, termination: ChildTermination) {
        let broadcast = self
            .lifecycle
            .threads
            .lock()
            .terminate_group(None, termination);
        if broadcast {
            self.lifecycle.changed.notify_all();
        }
    }
}

struct ProcessShared<R: Resources> {
    abi: Abi,
    identity: ProcessIdentity,
    memory_id: ProcessMemoryIdentity,
    pids: PidNamespace,
    futex: FutexTable,
    descriptors: Arc<spin::Mutex<Descriptors<R>>>,
    cwd: Arc<spin::Mutex<String>>,
    root: Arc<spin::Mutex<String>>,
    shared_mappings: Arc<spin::Mutex<Vec<memory::SharedFileMapping<R::File>>>>,
    next_shm_attach_id: AtomicU64,
    stdin_lock: RawMutex,
    stdin_carry: spin::Mutex<Bytes>,
    attributes: spin::Mutex<system::Attributes>,
    children_usage: spin::Mutex<system::CpuUsage>,
    program_break: Arc<spin::Mutex<memory::ProgramBreak>>,
    signals: Arc<ProcessSignals>,
    threads: Arc<GroupLifecycle>,
    vfork_done: spin::Mutex<Option<Arc<VforkDone>>>,
}

impl core::ops::Deref for GroupLifecycle {
    type Target = spin::Mutex<thread::ThreadGroup>;
    fn deref(&self) -> &Self::Target {
        &self.threads
    }
}

/// One thread's handle to a Linux process (`CLONE_THREAD` shares the
/// underlying descriptor table, futex queues, program break and attributes,
/// while each thread holds its own credentials per Linux `kernel/cred.c`).
///
/// # Concurrency
///
/// Each thread task exclusively owns its `Process<R>` handle while
/// dispatching a syscall. Shared process structures synchronize internally
/// with bounded non-awaiting critical sections (`descriptors`, `cwd`, `root`,
/// `shared_mappings`, `attributes`, `children_usage`, `program_break`,
/// `signals`, `threads`, `futex`) or an async mutex (`stdin_carry`); no spin
/// lock is ever held across an `.await`.
pub struct Process<R: Resources> {
    shared: Arc<ProcessShared<R>>,
    tid: NonZeroU32,
    signals: Arc<ThreadSignalSlot>,
    credentials: Arc<spin::Mutex<Credentials>>,
    sched: Arc<spin::Mutex<thread::ThreadSchedState>>,
    clear_child_tid: u64,
    robust_list: Arc<AtomicU64>,
    exited: bool,
}

impl<R: Resources> Process<R> {
    /// A single-threaded process holding the standard streams only, whose
    /// program break starts at `program_break` (`Image::program_break`).
    pub fn new(abi: Abi, id: NonZeroU32, program_break: u64) -> Self {
        Self::with_descriptors(
            abi,
            id,
            program_break,
            standard_streams::<R>(),
            Start::default(),
        )
    }

    /// A process holding the descriptors its parent handed it, whose
    /// table's limit is its `RLIMIT_NOFILE`.
    pub fn with_descriptors(
        abi: Abi,
        id: NonZeroU32,
        program_break: u64,
        mut descriptors: Descriptors<R>,
        mut start: Start,
    ) -> Self {
        let open_files = descriptors.limit;
        let futex = start.futex.clone();
        let pids = start
            .pids
            .clone()
            .unwrap_or_else(|| PidNamespace::standalone(id));
        let credentials = Arc::new(spin::Mutex::new(start.credentials.clone()));
        let memory_id = ProcessMemoryIdentity::new(start.memory_id.unwrap_or(u64::from(id.get())));
        let initial_cwd = start
            .cwd
            .take()
            .filter(|p| p.starts_with('/'))
            .unwrap_or_else(|| String::from("/"));
        let mut initial_stdin_carry = Bytes::new();
        for slot in descriptors.entries.iter_mut().flatten() {
            if let Descriptor::<R>::Stdin { carry } = &mut slot.descriptor
                && !carry.is_empty()
            {
                initial_stdin_carry = core::mem::take(carry);
                break;
            }
        }
        let robust_list = Arc::new(AtomicU64::new(0));
        let process_signals = ProcessSignals::new(id);
        let thread_signals = process_signals.register_thread(id, SignalSet::EMPTY);
        let sched = Arc::new(spin::Mutex::new(thread::ThreadSchedState::default()));
        pids.register_process(
            id,
            process_signals.clone(),
            credentials.clone(),
            sched.clone(),
        );
        pids.register_thread(
            id,
            thread_signals.clone(),
            credentials.clone(),
            sched.clone(),
        );
        let lifecycle = Arc::new(GroupLifecycle {
            threads: spin::Mutex::new(thread::ThreadGroup::new(
                id,
                pids.clone(),
                robust_list.clone(),
            )),
            changed: Notify::new(),
        });
        Self {
            shared: Arc::new(ProcessShared {
                abi,
                identity: ProcessIdentity::new(id.into()),
                memory_id,
                pids,
                futex,
                descriptors: Arc::new(spin::Mutex::new(descriptors)),
                cwd: Arc::new(spin::Mutex::new(initial_cwd)),
                root: Arc::new(spin::Mutex::new(String::from("/"))),
                shared_mappings: Arc::new(spin::Mutex::new(Vec::new())),
                next_shm_attach_id: AtomicU64::new(1),
                stdin_lock: RawMutex::new(),
                stdin_carry: spin::Mutex::new(initial_stdin_carry),
                attributes: spin::Mutex::new(system::Attributes::new(start, open_files)),
                children_usage: spin::Mutex::new(system::CpuUsage::default()),
                program_break: Arc::new(spin::Mutex::new(memory::ProgramBreak::new(program_break))),
                signals: process_signals,
                threads: lifecycle,
                vfork_done: spin::Mutex::new(None),
            }),
            tid: id,
            signals: thread_signals,
            credentials,
            sched,
            clear_child_tid: 0,
            robust_list,
            exited: false,
        }
    }

    /// Flushes every active writable `MAP_SHARED` file mapping back to its
    /// backing file (used on process teardown after non-syscall exits).
    pub async fn flush_shared_mappings<M: UserMemory, F: Filesystem<R>>(
        &self,
        memory: &M,
        fs: &mut F,
    ) {
        memory::flush_all_shared_mappings(self, memory, fs).await;
    }

    /// Detaches all remaining SysV shared memory segments and drops any sole-
    /// owner `memfd` mappings/descriptors on `execve` or final process exit.
    pub fn detach_sysv_shm<F: Filesystem<R>>(&self, now_secs: i64, fs: &mut F) {
        let shmids = memory::drain_sysv_shm_for_detach(self);
        let pid = self.pid().get();
        for shmid in shmids {
            fs.shm_detach(shmid, pid, now_secs);
        }
    }

    /// Releases sole-owner VMAs, SysV shared memory attachments, and `memfd`
    /// descriptors on final process exit (called after the last thread ends).
    pub fn cleanup_ipc_on_exit<F: Filesystem<R>>(&self, now_secs: i64, fs: &mut F) {
        self.detach_sysv_shm(now_secs, fs);
        if Arc::strong_count(&self.shared.shared_mappings) == 1 {
            self.shared.shared_mappings.lock().clear();
        }
        if Arc::strong_count(&self.shared.descriptors) == 1 {
            *self.shared.descriptors.lock() = DescriptorSlots::from_entries(Vec::new());
        }
        fs.sync_process_memfds(self.pid().get(), &[]);
        fs.reap_memfds();
    }

    /// Synchronises this process's live `memfd` descriptor slots with `fs`
    /// (for cross-process `/proc/<pid>/fd/<n>` reopen after `execve`).
    pub fn sync_memfds<F: Filesystem<R>>(&self, fs: &F) {
        shm::sync_process_memfds(self, fs);
    }

    /// Process-wide signal and interval-timer state shared across all threads
    /// of this thread group.
    pub fn process_signals(&self) -> Arc<ProcessSignals> {
        self.shared.signals.clone()
    }

    /// Per-thread signal mask, private pending queue, and alternate stack.
    pub fn thread_signals(&self) -> &Arc<ThreadSignalSlot> {
        &self.signals
    }

    /// Forwards an external signal (such as a parent WASIX signal or owner
    /// kill) into this Linux process's signal state.
    pub fn raise_external_signal(&self, signal: Signal) {
        self.shared.signals.raise_external(signal);
    }

    /// Advances `ITIMER_VIRTUAL` (`user_ns`) and `ITIMER_PROF` (`total_ns`).
    pub fn account_cpu_timers(&self, user_ns: u64, total_ns: u64) {
        self.shared.signals.account_cpu_timers(user_ns, total_ns);
    }

    /// Whether this process is currently stopped (`SIGSTOP`/`SIGTSTP`/etc.).
    pub fn is_stopped(&self) -> bool {
        self.shared.signals.is_stopped()
    }

    /// Delivers pending unmasked signals on return to user mode.
    pub async fn deliver_pending_signals<C: UserContext, M: UserMemory>(
        &self,
        context: &mut C,
        memory: &mut M,
        restart: Option<SyscallRestart>,
        sigreturn_trampoline: u64,
    ) -> SignalDelivery {
        signal::deliver_pending_signals(
            self.shared.abi,
            &self.signals,
            context,
            memory,
            restart,
            sigreturn_trampoline,
        )
        .await
    }

    /// Delivers a synchronous hardware fault signal with Linux
    /// `force_sig_fault` semantics.
    pub async fn deliver_fault_signal<C: UserContext, M: UserMemory>(
        &self,
        fault: UserFault,
        context: &mut C,
        memory: &mut M,
        sigreturn_trampoline: u64,
    ) -> SignalDelivery {
        signal::deliver_fault_signal(
            self.shared.abi,
            &self.signals,
            fault,
            context,
            memory,
            sigreturn_trampoline,
        )
        .await
    }

    /// Delivers a synchronous `SIGBUS` (`BUS_ADRERR`) fault with `si_addr =
    /// fault_address` (e.g. accessing a page beyond a mapped file's end).
    pub async fn deliver_bus_fault<C: UserContext, M: UserMemory>(
        &self,
        fault_address: u64,
        context: &mut C,
        memory: &mut M,
        sigreturn_trampoline: u64,
    ) -> SignalDelivery {
        signal::deliver_bus_fault_signal(
            self.shared.abi,
            &self.signals,
            fault_address,
            context,
            memory,
            sigreturn_trampoline,
        )
        .await
    }

    /// Looks up the tracked file or shared-anonymous VMA covering `address`,
    /// used on demand page faults (`NativeError::BackingFault`) to check file
    /// EOF (`SIGBUS`) or load/attach the backing page.
    pub fn lookup_vma(&self, address: u64) -> Option<VmaBacking<R::File>> {
        memory::lookup_vma(self, address)
    }

    /// Restores user registers, extended state, signal mask, and alternate
    /// stack from the signal frame on `rt_sigreturn`.
    pub async fn restore_signal_frame<C: UserContext, M: UserMemory>(
        &self,
        context: &mut C,
        memory: &M,
    ) -> Result<(), SignalFrameError> {
        signal::restore_from_sigreturn(self.shared.abi, &self.signals, context, memory).await
    }

    /// The thread-group ID (`getpid`).
    pub fn pid(&self) -> NonZeroU32 {
        NonZeroU32::try_from(self.shared.identity.id())
            .expect("process identity is created from NonZeroU32")
    }

    /// This thread's ID (`gettid`).
    pub fn tid(&self) -> NonZeroU32 {
        self.tid
    }

    /// Observer handle for the thread group's lifecycle, independent of the
    /// descriptor table's reference count.
    pub fn observer(&self) -> ProcessObserver {
        ProcessObserver {
            lifecycle: self.shared.threads.clone(),
        }
    }

    /// Whether the thread group has been condemned (`exit_group`, fatal
    /// signal or fault).
    pub fn group_ended(&self) -> bool {
        self.shared.threads.lock().group_ended()
    }

    /// Arms a wait on thread-group condemnation.
    pub fn group_end_waiter(&self) -> NotifyWaiter {
        self.shared.threads.changed.waiter()
    }

    /// Polls a thread-group condemnation wait.
    pub fn poll_group_ended(&self, cx: &mut Context<'_>, waiter: &mut NotifyWaiter) -> Poll<()> {
        self.shared.threads.changed.poll_notified(cx, waiter)
    }

    /// Records that this process stopped on `signal` (`SIGSTOP`/`SIGTSTP`/etc.)
    /// so its parent's `wait4`/`waitid` (`WUNTRACED`/`WSTOPPED`) observes it.
    pub fn mark_stopped(&self, signal: Signal) {
        self.shared.pids.mark_stopped(self.pid(), signal);
    }

    /// Signals a waiting `vfork`/`CLONE_VFORK` parent (if any) that this child
    /// has completed `execve` or exited.
    pub fn signal_vfork_done(&self) {
        if let Some(done) = self.shared.vfork_done.lock().take() {
            done.complete();
        }
    }

    /// Records final CPU/memory usage for this process so its parent's
    /// `wait4`/`waitid` and `getrusage(RUSAGE_CHILDREN)` observe it.
    pub fn record_usage(&self, usage: system::CpuUsage) {
        self.shared.pids.record_usage(self.pid(), usage);
    }

    /// Transitions this process into exited/zombie state inside its container's
    /// [`PidNamespace`], waking any parent blocked in `wait4`/`waitid` and
    /// raising its exit signal (`SIGCHLD`), and unblocks any `vfork` parent.
    pub fn mark_exited(&self, termination: ChildTermination) {
        self.shared
            .pids
            .file_locks()
            .release_posix_for_process(self.shared.identity);
        self.signal_vfork_done();
        self.shared.pids.mark_exited(self.pid(), termination);
    }

    /// Closes every descriptor marked `FD_CLOEXEC`, leaving all other open
    /// descriptors intact.
    pub fn close_on_exec(&self) {
        let mut table = self.shared.descriptors.lock();
        let len = table.entries.len();
        for index in 0..len {
            if table.entries[index]
                .as_ref()
                .is_some_and(|entry| entry.close_on_exec)
            {
                let _ = table.close(index as i32);
            }
        }
    }

    /// Signals currently set to `SIG_IGN` (carried into a WASIX/Wasm image on
    /// `execve`).
    pub fn ignored_signals(&self) -> alloc::vec::Vec<Signal> {
        self.shared.signals.ignored_signals()
    }

    /// Returns a cloned copy of the open file entry at `fd` (used by
    /// `execveat` to resolve `dirfd` / `AT_EMPTY_PATH`).
    pub fn descriptor_entry(&self, fd: i32) -> Option<Entry<R>> {
        self.shared.descriptors.lock().get_entry(fd).cloned()
    }

    /// Shared handle to this process's descriptor table (for host `execveat`
    /// `dirfd` lookup without holding a borrow on `Process`).
    pub fn descriptors_handle(&self) -> Arc<spin::Mutex<Descriptors<R>>> {
        self.shared.descriptors.clone()
    }

    /// Shared handle to this process's current working directory (for host
    /// `execve`/`execveat` relative path resolution without holding a borrow on
    /// `Process`).
    pub fn cwd_handle(&self) -> Arc<spin::Mutex<String>> {
        self.shared.cwd.clone()
    }

    /// Shared handle to this process's chroot root directory (for host
    /// `execve`/`execveat` path resolution).
    pub fn root_handle(&self) -> Arc<spin::Mutex<String>> {
        self.shared.root.clone()
    }

    /// Shared handle to this thread's credentials (for host `execve`/`execveat`
    /// permission checks and set-id / file-capability transitions without
    /// holding a borrow on `Process`).
    pub fn credentials_handle(&self) -> Arc<spin::Mutex<system::Credentials>> {
        self.credentials.clone()
    }

    /// If a non-leader thread called `execve`, transitions its thread ID to
    /// the thread-group leader (`tid == pid`), matching Linux `de_thread`.
    fn normalize_exec_leader(&mut self) {
        let pid = self.pid();
        if self.tid != pid {
            let old_mask = self.signals.current_mask();
            self.shared.signals.unregister_thread(self.tid);
            self.shared.pids.release_tid(self.tid);
            self.tid = pid;
            self.signals = self.shared.signals.register_thread(pid, old_mask);
            self.shared.pids.register_thread(
                pid,
                self.signals.clone(),
                self.credentials.clone(),
                self.sched.clone(),
            );
            self.shared
                .pids
                .update_process_credentials(pid, self.credentials.clone());
        }
    }

    /// Commits an in-place Linux-to-Linux `execve`/`execveat`:
    /// - detaches from any `vfork`/`CLONE_VM`/`CLONE_FILES` parent state,
    /// - closes `FD_CLOEXEC` descriptors,
    /// - applies the post-`execve` `new_credentials` (visible to both the new
    ///   image and `PidNamespace` signal checks),
    /// - resets caught signal handlers to `SIG_DFL` while preserving `SIG_IGN`
    ///   and the calling thread's signal mask,
    /// - marks `has_execed` in [`PidNamespace`] and wakes any `vfork` parent,
    /// - resets the thread group to a single thread (`tid == pid`) with
    ///   `new_program_break`.
    pub fn commit_linux_exec(
        &mut self,
        new_program_break: u64,
        new_credentials: system::Credentials,
    ) {
        let pid = self.pid();
        *self.credentials.lock() = new_credentials;
        let mut surviving = self.shared.descriptors.lock().clone();
        let len = surviving.entries.len();
        for index in 0..len {
            if surviving.entries[index]
                .as_ref()
                .is_some_and(|entry| entry.close_on_exec)
            {
                let _ = surviving.close(index as i32);
            }
        }
        // Clear `FD_CLOEXEC` in-place when we were the sole owner of the table
        // so closed descriptors drop immediately before the new image starts.
        if Arc::strong_count(&self.shared.descriptors) == 1 {
            *self.shared.descriptors.lock() = surviving.clone();
        }

        self.shared.signals.reset_for_exec();
        self.signals.reset_for_exec();
        self.normalize_exec_leader();

        self.shared.pids.mark_execed(pid);
        self.signal_vfork_done();

        let robust_list = Arc::new(AtomicU64::new(0));
        let lifecycle = Arc::new(GroupLifecycle {
            threads: spin::Mutex::new(thread::ThreadGroup::new(
                pid,
                self.shared.pids.clone(),
                robust_list.clone(),
            )),
            changed: Notify::new(),
        });
        let fresh_memory_id = helios_unix::ProcessMemoryIdentity::new(
            self.shared
                .memory_id
                .raw()
                .wrapping_add(0x9e37_79b9_7f4a_7c15),
        );
        let new_shared = Arc::new(ProcessShared {
            abi: self.shared.abi,
            identity: self.shared.identity,
            memory_id: fresh_memory_id,
            pids: self.shared.pids.clone(),
            futex: self.shared.futex.clone(),
            descriptors: Arc::new(spin::Mutex::new(surviving)),
            cwd: Arc::new(spin::Mutex::new(self.shared.cwd.lock().clone())),
            root: Arc::new(spin::Mutex::new(self.shared.root.lock().clone())),
            shared_mappings: Arc::new(spin::Mutex::new(Vec::new())),
            next_shm_attach_id: AtomicU64::new(1),
            stdin_lock: RawMutex::new(),
            stdin_carry: spin::Mutex::new(self.shared.stdin_carry.lock().clone()),
            attributes: spin::Mutex::new(self.shared.attributes.lock().clone()),
            children_usage: spin::Mutex::new(*self.shared.children_usage.lock()),
            program_break: Arc::new(spin::Mutex::new(memory::ProgramBreak::new(
                new_program_break,
            ))),
            signals: self.shared.signals.clone(),
            threads: lifecycle,
            vfork_done: spin::Mutex::new(None),
        });
        // Mark the old thread handle withdrawn from the old lifecycle without
        // unregistering the process from `PidNamespace`.
        self.shared = new_shared;
        self.clear_child_tid = 0;
        self.robust_list = robust_list;
        self.exited = false;
    }

    /// Commits a Linux-to-Wasm/WASIX `execve`/`execveat`, returning the
    /// surviving post-`FD_CLOEXEC` descriptor table and preserved `SIG_IGN`
    /// signals while keeping the process registered in [`PidNamespace`] until
    /// the Wasm program finishes and calls [`PidNamespace::mark_exited`].
    pub fn commit_wasm_exec(&mut self) -> (Descriptors<R>, alloc::vec::Vec<Signal>) {
        let pid = self.pid();
        let mut surviving = self.shared.descriptors.lock().clone();
        let len = surviving.entries.len();
        for index in 0..len {
            if surviving.entries[index]
                .as_ref()
                .is_some_and(|entry| entry.close_on_exec)
            {
                let _ = surviving.close(index as i32);
            }
        }
        if Arc::strong_count(&self.shared.descriptors) == 1 {
            // Release the Linux table's descriptor references immediately so
            // pipe EOFs depend solely on the Wasm image's table.
            *self.shared.descriptors.lock() = DescriptorSlots::from_entries(alloc::vec::Vec::new());
        }
        self.shared.signals.reset_for_exec();
        self.signals.reset_for_exec();
        self.normalize_exec_leader();
        let ignored = self.shared.signals.ignored_signals();
        self.shared.pids.mark_execed(pid);
        self.signal_vfork_done();
        // Suppress `Process::drop` withdrawal so `PidNamespace` keeps this
        // process live while the Wasm image runs.
        self.exited = true;
        (surviving, ignored)
    }

    /// Condemns the entire thread group from this thread (for a fatal signal,
    /// unhandled fault or owner kill) and withdraws this thread from the live
    /// set.
    pub fn terminate_group(&mut self, termination: ChildTermination) {
        let tid = (!self.exited).then_some(self.tid);
        self.exited = true;
        if let Some(tid) = tid {
            self.shared.signals.unregister_thread(tid);
        }
        let broadcast = self.shared.threads.lock().terminate_group(tid, termination);
        if broadcast {
            self.shared.threads.changed.notify_all();
        }
        if self.shared.threads.lock().all_exited() {
            self.shared
                .pids
                .file_locks()
                .release_posix_for_process(self.shared.identity);
            self.signal_vfork_done();
        }
    }

    fn finish_syscall_exit(&mut self, exit: Exit) -> bool {
        if self.exited {
            return false;
        }
        self.exited = true;
        self.shared.signals.unregister_thread(self.tid);
        let (broadcast, all_exited) = self.shared.threads.lock().finish(self.tid, exit);
        if broadcast || all_exited {
            self.shared.threads.changed.notify_all();
        }
        if all_exited {
            self.shared
                .pids
                .file_locks()
                .release_posix_for_process(self.shared.identity);
            self.signal_vfork_done();
        }
        all_exited
    }
}

impl<R: Resources> Drop for Process<R> {
    fn drop(&mut self) {
        if !self.exited {
            self.exited = true;
            self.shared.signals.unregister_thread(self.tid);
            let all_exited = self.shared.threads.lock().withdraw(self.tid);
            if all_exited {
                self.shared.threads.changed.notify_all();
                self.shared
                    .pids
                    .file_locks()
                    .release_posix_for_process(self.shared.identity);
                self.signal_vfork_done();
            }
        }
    }
}

fn errno(value: u64) -> u64 {
    value.wrapping_neg()
}

/// Dispatches one Linux system call on `process`'s thread. `Exit` and
/// `ExitGroup` consume the thread's execution loop through `Break`.
pub async fn dispatch<
    R: Resources,
    M: VirtualMemory,
    T: Thread<R>,
    O: Stdio + Clock + System + Filesystem<R> + Tty + Network<R::Network>,
>(
    process: &mut Process<R>,
    call: Call,
    memory: &mut M,
    thread: &mut T,
    output: &mut O,
) -> ControlFlow<Exit, SyscallOutcome> {
    let abi = process.shared.abi;
    let arguments = call.arguments;
    let operation = abi.operation(call.number);
    let outcome = match operation {
        Operation::Exit
        | Operation::ExitGroup
        | Operation::Mmap
        | Operation::Munmap
        | Operation::Msync
        | Operation::Mremap
        | Operation::Madvise
        | Operation::Shmat
        | Operation::SchedYield
        | Operation::Clone
        | Operation::Clone3
        | Operation::Fork
        | Operation::Vfork
        | Operation::Execve
        | Operation::Execveat
        | Operation::Wait4
        | Operation::Waitid
        | Operation::Getrandom => {
            return dispatch_proc_mem(operation, process, abi, arguments, memory, thread, output)
                .await;
        }
        Operation::RtSigsuspend
        | Operation::RtSigtimedwait
        | Operation::Pause
        | Operation::EpollWait
        | Operation::EpollPwait
        | Operation::Poll
        | Operation::Ppoll
        | Operation::Select
        | Operation::Pselect6
        | Operation::Nanosleep
        | Operation::ClockNanosleep
        | Operation::Futex => {
            dispatch_wait_signal(operation, process, abi, arguments, memory, output).await
        }
        Operation::Read
        | Operation::Write
        | Operation::Readv
        | Operation::Writev
        | Operation::Pread64
        | Operation::Pwrite64
        | Operation::Preadv
        | Operation::Pwritev
        | Operation::Preadv2
        | Operation::Pwritev2
        | Operation::Openat
        | Operation::Open
        | Operation::Creat
        | Operation::Lseek
        | Operation::Getdents64
        | Operation::Ftruncate
        | Operation::Truncate
        | Operation::Fsync
        | Operation::Fdatasync => {
            dispatch_fs_io(operation, process, arguments, memory, output).await
        }
        Operation::Statfs
        | Operation::Fstatfs
        | Operation::Flock
        | Operation::Fallocate
        | Operation::Sync
        | Operation::Syncfs
        | Operation::Chroot
        | Operation::CopyFileRange
        | Operation::Splice
        | Operation::Tee => dispatch_fs_extra(operation, process, arguments, memory, output).await,
        Operation::Fstat
        | Operation::Newfstatat
        | Operation::Stat
        | Operation::Lstat
        | Operation::Statx
        | Operation::Faccessat
        | Operation::Faccessat2
        | Operation::Access
        | Operation::Readlinkat
        | Operation::Readlink
        | Operation::Mkdirat
        | Operation::Mkdir
        | Operation::Mknodat
        | Operation::Mknod
        | Operation::Chmod
        | Operation::Fchmod
        | Operation::Fchmodat
        | Operation::Fchmodat2
        | Operation::Chown
        | Operation::Lchown
        | Operation::Fchown
        | Operation::Fchownat => {
            dispatch_fs_meta(operation, process, arguments, memory, output).await
        }
        Operation::Setxattr
        | Operation::Lsetxattr
        | Operation::Fsetxattr
        | Operation::Getxattr
        | Operation::Lgetxattr
        | Operation::Fgetxattr
        | Operation::Listxattr
        | Operation::Llistxattr
        | Operation::Flistxattr
        | Operation::Removexattr
        | Operation::Lremovexattr
        | Operation::Fremovexattr
        | Operation::Unlinkat
        | Operation::Unlink
        | Operation::Rmdir
        | Operation::Renameat2
        | Operation::Renameat
        | Operation::Rename
        | Operation::Linkat
        | Operation::Link
        | Operation::Symlinkat
        | Operation::Symlink
        | Operation::Utimensat
        | Operation::Chdir
        | Operation::Fchdir => {
            dispatch_fs_xattr_links(operation, process, arguments, memory, output).await
        }
        Operation::Bind
        | Operation::Listen
        | Operation::Accept
        | Operation::Accept4
        | Operation::Connect
        | Operation::Getsockname
        | Operation::Getpeername
        | Operation::Sendto
        | Operation::Recvfrom
        | Operation::Sendmsg
        | Operation::Recvmsg
        | Operation::Sendmmsg
        | Operation::Recvmmsg
        | Operation::Shutdown
        | Operation::Sendfile
        | Operation::Setsockopt
        | Operation::Getsockopt => {
            dispatch_socket(operation, process, arguments, memory, output).await
        }
        Operation::RtSigreturn => SyscallOutcome::SigReturn,
        Operation::RtSigaction
        | Operation::RtSigprocmask
        | Operation::RtSigpending
        | Operation::Sigaltstack
        | Operation::Getitimer
        | Operation::Setitimer
        | Operation::Getcwd
        | Operation::Pipe
        | Operation::Pipe2
        | Operation::EpollCtl
        | Operation::MemfdCreate
        | Operation::Shmctl
        | Operation::GetRobustList
        | Operation::Socketpair => {
            dispatch_signal_ipc(operation, process, abi, arguments, memory, thread, output).await
        }
        Operation::SchedGetaffinity
        | Operation::SchedSetaffinity
        | Operation::SchedSetscheduler
        | Operation::SchedGetparam
        | Operation::SchedSetparam
        | Operation::Times
        | Operation::Getrusage
        | Operation::Syslog
        | Operation::Prctl
        | Operation::ArchPrctl
        | Operation::ClockGettime
        | Operation::ClockGetres
        | Operation::ClockSettime
        | Operation::Gettimeofday
        | Operation::Time
        | Operation::Uname
        | Operation::Sethostname
        | Operation::Setdomainname
        | Operation::Sysinfo
        | Operation::Getgroups
        | Operation::Getresuid
        | Operation::Getresgid
        | Operation::Setgroups
        | Operation::Capget
        | Operation::Capset
        | Operation::Prlimit64
        | Operation::Getrlimit
        | Operation::Setrlimit => {
            dispatch_system_sched(operation, process, abi, arguments, memory, thread, output).await
        }
        Operation::Kill => {
            let creds = process.credentials.lock().clone();
            SyscallOutcome::Return(signal::kill(
                &process.shared.pids,
                process.pid(),
                process.shared.signals.pgid(),
                &creds,
                arguments,
            ))
        }
        Operation::Tkill => {
            let creds = process.credentials.lock().clone();
            SyscallOutcome::Return(signal::tkill(
                &process.shared.pids,
                process.pid(),
                &creds,
                arguments,
            ))
        }
        Operation::Tgkill => {
            let creds = process.credentials.lock().clone();
            SyscallOutcome::Return(signal::tgkill(
                &process.shared.pids,
                process.pid(),
                &creds,
                arguments,
            ))
        }
        Operation::Alarm => {
            SyscallOutcome::Return(signal::alarm(&process.shared.signals, arguments, output))
        }
        Operation::Close => {
            let fd = arguments[0] as u32 as i32;
            let (result, closed) = match process.shared.descriptors.lock().close(fd) {
                Ok(entry) => (0, Some(entry)),
                Err(err) => (io::descriptor_errno(err), None),
            };
            if let Some(entry) = closed {
                let is_memfd = matches!(&entry.descriptor, Descriptor::<R>::File(open) if output.memfd_handle(open.node()).is_some());
                fs_extra::release_posix_locks_for_entry(process, &entry, output);
                drop(entry);
                if is_memfd {
                    output.reap_memfds();
                    shm::sync_process_memfds(process, output);
                }
            }
            SyscallOutcome::Return(result)
        }
        Operation::CloseRange => {
            SyscallOutcome::Return(fs::close_range::<R, _>(process, arguments, output))
        }
        Operation::Readahead => {
            SyscallOutcome::Return(fs_extra::readahead::<R, _>(process, arguments, output))
        }
        Operation::Dup | Operation::Dup2 | Operation::Dup3 => {
            let (result, overwritten, src_is_memfd) = {
                let mut table = process.shared.descriptors.lock();
                let src_memfd = table
                    .get_entry(arguments[0] as u32 as i32)
                    .is_some_and(|e| {
                        matches!(&e.descriptor, Descriptor::<R>::File(open) if output.memfd_handle(open.node()).is_some())
                    });
                let prev = if matches!(operation, Operation::Dup2 | Operation::Dup3)
                    && arguments[0] as u32 != arguments[1] as u32
                {
                    table.get_entry(arguments[1] as u32 as i32).cloned()
                } else {
                    None
                };
                let res = io::duplicate::<R, _>(abi, &mut table, operation, arguments, output);
                (res, prev, src_memfd)
            };
            let mut touched_memfd = src_is_memfd && result <= i32::MAX as u64;
            if result <= i32::MAX as u64
                && let Some(entry) = overwritten
            {
                if matches!(&entry.descriptor, Descriptor::<R>::File(open) if output.memfd_handle(open.node()).is_some())
                {
                    touched_memfd = true;
                }
                fs_extra::release_posix_locks_for_entry(process, &entry, output);
                drop(entry);
            }
            if touched_memfd {
                output.reap_memfds();
                shm::sync_process_memfds(process, output);
            }
            SyscallOutcome::Return(result)
        }
        Operation::Fcntl => {
            let cmd = arguments[1] as u32;
            if matches!(cmd, 5..=7) {
                dispatch_fs_extra(operation, process, arguments, memory, output).await
            } else if matches!(cmd, shm::F_ADD_SEALS | shm::F_GET_SEALS) {
                SyscallOutcome::Return(shm::fcntl_seals(
                    process,
                    arguments[0] as u32 as i32,
                    cmd,
                    arguments[2],
                    output,
                ))
            } else {
                let res = io::duplicate::<R, _>(
                    abi,
                    &mut process.shared.descriptors.lock(),
                    Operation::Fcntl,
                    arguments,
                    output,
                );
                if matches!(cmd, 0 | 1030) && res <= i32::MAX as u64 {
                    let is_memfd = process
                        .shared
                        .descriptors
                        .lock()
                        .get_entry(res as i32)
                        .is_some_and(|e| {
                            matches!(&e.descriptor, Descriptor::<R>::File(open) if output.memfd_handle(open.node()).is_some())
                        });
                    if is_memfd {
                        shm::sync_process_memfds(process, output);
                    }
                }
                SyscallOutcome::Return(res)
            }
        }
        Operation::Eventfd | Operation::Eventfd2 => SyscallOutcome::Return(io::event::<R>(
            &mut process.shared.descriptors.lock(),
            arguments,
            operation == Operation::Eventfd2,
        )),
        Operation::EpollCreate | Operation::EpollCreate1 => {
            SyscallOutcome::Return(io::epoll_create::<R>(
                &mut process.shared.descriptors.lock(),
                arguments,
                operation == Operation::EpollCreate1,
            ))
        }
        Operation::Mprotect => {
            SyscallOutcome::Return(memory::mprotect(process, abi, arguments, memory))
        }
        Operation::Brk => SyscallOutcome::Return(process.shared.program_break.lock().set(
            abi,
            arguments[0],
            memory,
        )),
        Operation::Shmget => SyscallOutcome::Return(shm::shmget(process, arguments, output)),
        Operation::Shmdt => SyscallOutcome::Return(shm::shmdt(process, arguments, memory, output)),
        Operation::SchedGetscheduler => {
            SyscallOutcome::Return(thread::sched_getscheduler(process, arguments))
        }
        Operation::SchedGetPriorityMax => {
            SyscallOutcome::Return(thread::sched_get_priority_max(arguments))
        }
        Operation::SchedGetPriorityMin => {
            SyscallOutcome::Return(thread::sched_get_priority_min(arguments))
        }
        Operation::IoprioSet => SyscallOutcome::Return(thread::ioprio_set(process, arguments)),
        Operation::IoprioGet => SyscallOutcome::Return(thread::ioprio_get(process, arguments)),
        Operation::Personality => SyscallOutcome::Return(process.personality(arguments)),
        Operation::SetRobustList => {
            SyscallOutcome::Return(futex::set_robust_list(process, arguments))
        }
        Operation::Getpid => SyscallOutcome::Return(process.shared.identity.id().get()),
        Operation::Getppid => SyscallOutcome::Return(process::getppid(process)),
        Operation::Getpgid => SyscallOutcome::Return(process::getpgid(process, arguments)),
        Operation::Setpgid => SyscallOutcome::Return(process::setpgid(process, arguments)),
        Operation::Getpgrp => SyscallOutcome::Return(process::getpgrp(process)),
        Operation::Getsid => SyscallOutcome::Return(process::getsid(process, arguments)),
        Operation::Setsid => {
            let res = process::setsid(process);
            if (res as i64) >= 0 {
                output.set_controlling_pty(None);
            }
            SyscallOutcome::Return(res)
        }
        Operation::Gettid => SyscallOutcome::Return(u64::from(process.tid.get())),
        Operation::SetTidAddress => {
            process.clear_child_tid = arguments[0];
            SyscallOutcome::Return(u64::from(process.tid.get()))
        }
        Operation::Ioctl => {
            let is_socket = process
                .shared
                .descriptors
                .lock()
                .get_entry(arguments[0] as u32 as i32)
                .is_some_and(|e| matches!(e.descriptor, Descriptor::<R>::Socket(_)));
            if is_socket {
                dispatch_socket(operation, process, arguments, memory, output).await
            } else {
                dispatch_system_sched(operation, process, abi, arguments, memory, thread, output)
                    .await
            }
        }
        Operation::Getuid | Operation::Geteuid | Operation::Getgid | Operation::Getegid => {
            SyscallOutcome::Return(process.credentials.lock().id(operation))
        }
        Operation::Setuid => SyscallOutcome::Return(process.credentials.lock().setuid(arguments)),
        Operation::Setgid => SyscallOutcome::Return(process.credentials.lock().setgid(arguments)),
        Operation::Setreuid => {
            SyscallOutcome::Return(process.credentials.lock().setreuid(arguments))
        }
        Operation::Setregid => {
            SyscallOutcome::Return(process.credentials.lock().setregid(arguments))
        }
        Operation::Setresuid => {
            SyscallOutcome::Return(process.credentials.lock().setresuid(arguments))
        }
        Operation::Setresgid => {
            SyscallOutcome::Return(process.credentials.lock().setresgid(arguments))
        }
        Operation::Umask => SyscallOutcome::Return(process.umask(arguments)),
        Operation::Getpriority => SyscallOutcome::Return(process.getpriority(arguments)),
        Operation::Setpriority => SyscallOutcome::Return(process.setpriority(arguments)),
        Operation::Socket => SyscallOutcome::Return(socket::socket::<R, _>(
            &process.shared.descriptors,
            arguments,
            socket_context(process),
            output,
        )),
        Operation::Unknown => SyscallOutcome::Return(errno(ENOSYS)),
    };
    ControlFlow::Continue(outcome)
}

#[inline(never)]
async fn dispatch_signal_ipc<
    R: Resources,
    M: VirtualMemory,
    T: Thread<R>,
    O: Stdio + Clock + System + Filesystem<R> + Tty + Network<R::Network>,
>(
    operation: Operation,
    process: &mut Process<R>,
    abi: Abi,
    arguments: [u64; 6],
    memory: &mut M,
    thread: &mut T,
    output: &mut O,
) -> SyscallOutcome {
    match operation {
        Operation::RtSigaction => SyscallOutcome::Return(
            signal::rt_sigaction(&process.shared.signals, arguments, memory).await,
        ),
        Operation::RtSigprocmask => SyscallOutcome::Return(
            signal::rt_sigprocmask(&process.signals, arguments, memory).await,
        ),
        Operation::RtSigpending => {
            SyscallOutcome::Return(signal::rt_sigpending(&process.signals, arguments, memory).await)
        }
        Operation::Sigaltstack => SyscallOutcome::Return(
            signal::sigaltstack(
                abi,
                &process.signals,
                thread.stack_pointer(),
                arguments,
                memory,
            )
            .await,
        ),
        Operation::Getitimer => SyscallOutcome::Return(
            signal::getitimer(&process.shared.signals, arguments, memory, output).await,
        ),
        Operation::Setitimer => SyscallOutcome::Return(
            signal::setitimer(&process.shared.signals, arguments, memory, output).await,
        ),
        Operation::Getcwd => {
            SyscallOutcome::Return(fs::getcwd::<R, _>(process, arguments, memory).await)
        }
        Operation::Pipe | Operation::Pipe2 => {
            let (uid, gid) = {
                let creds = process.credentials.lock();
                (creds.user.effective, creds.group.effective)
            };
            SyscallOutcome::Return(
                io::pipe::<R, _>(
                    &process.shared.descriptors,
                    arguments,
                    memory,
                    operation == Operation::Pipe2,
                    uid,
                    gid,
                )
                .await,
            )
        }
        Operation::EpollCtl => SyscallOutcome::Return(
            io::epoll_ctl::<R, _>(abi, &process.shared.descriptors, arguments, memory).await,
        ),
        Operation::MemfdCreate => {
            SyscallOutcome::Return(shm::memfd_create(process, arguments, memory, output).await)
        }
        Operation::Shmctl => {
            SyscallOutcome::Return(shm::shmctl(process, arguments, memory, output).await)
        }
        Operation::GetRobustList => {
            SyscallOutcome::Return(futex::get_robust_list(process, arguments, memory).await)
        }
        Operation::Socketpair => SyscallOutcome::Return(
            socket::socketpair::<R, _>(&process.shared.descriptors, arguments, memory).await,
        ),
        _ => unreachable!("dispatched non-signal/ipc operation"),
    }
}

#[inline(never)]
async fn dispatch_system_sched<
    R: Resources,
    M: VirtualMemory,
    T: Thread<R>,
    O: Stdio + Clock + System + Filesystem<R> + Tty + Network<R::Network>,
>(
    operation: Operation,
    process: &mut Process<R>,
    abi: Abi,
    arguments: [u64; 6],
    memory: &mut M,
    thread: &mut T,
    output: &mut O,
) -> SyscallOutcome {
    match operation {
        Operation::SchedGetaffinity => SyscallOutcome::Return(
            thread::sched_getaffinity(process, arguments, memory, output).await,
        ),
        Operation::SchedSetaffinity => SyscallOutcome::Return(
            thread::sched_setaffinity(process, arguments, memory, output).await,
        ),
        Operation::SchedSetscheduler => {
            SyscallOutcome::Return(thread::sched_setscheduler(process, arguments, memory).await)
        }
        Operation::SchedGetparam => {
            SyscallOutcome::Return(thread::sched_getparam(process, arguments, memory).await)
        }
        Operation::SchedSetparam => {
            SyscallOutcome::Return(thread::sched_setparam(process, arguments, memory).await)
        }
        Operation::Times => SyscallOutcome::Return(
            system::times::<R, _, _>(process, arguments, memory, output).await,
        ),
        Operation::Getrusage => SyscallOutcome::Return(
            system::getrusage::<R, _, _>(process, arguments, memory, output).await,
        ),
        Operation::Syslog => SyscallOutcome::Return(
            system::syslog::<R, _, _>(process, arguments, memory, output).await,
        ),
        Operation::Prctl => SyscallOutcome::Return(process.prctl(arguments, memory).await),
        Operation::ArchPrctl => {
            SyscallOutcome::Return(arch_prctl(abi, arguments, memory, thread).await)
        }
        Operation::Ioctl => {
            SyscallOutcome::Return(tty::ioctl::<R, _, _>(process, arguments, memory, output).await)
        }
        Operation::ClockGettime => {
            SyscallOutcome::Return(system::clock_gettime(arguments, memory, output).await)
        }
        Operation::ClockGetres => {
            SyscallOutcome::Return(system::clock_getres(arguments, memory).await)
        }
        Operation::ClockSettime => {
            let has_cap = process
                .credentials
                .lock()
                .capabilities
                .has_effective(CAP_SYS_TIME);
            SyscallOutcome::Return(system::clock_settime(arguments, has_cap, memory, output).await)
        }
        Operation::Gettimeofday => {
            SyscallOutcome::Return(system::gettimeofday(arguments, memory, output).await)
        }
        Operation::Time => SyscallOutcome::Return(system::time(arguments, memory, output).await),
        Operation::Uname => {
            SyscallOutcome::Return(system::uname(abi, arguments, memory, output).await)
        }
        Operation::Sethostname | Operation::Setdomainname => {
            let has_cap = process
                .credentials
                .lock()
                .capabilities
                .has_effective(CAP_SYS_ADMIN);
            SyscallOutcome::Return(
                system::set_uts_name(operation, has_cap, arguments, memory, output).await,
            )
        }
        Operation::Sysinfo => {
            SyscallOutcome::Return(system::sysinfo(arguments, memory, output).await)
        }
        Operation::Getgroups => {
            let creds = process.credentials.lock().clone();
            SyscallOutcome::Return(creds.getgroups(arguments, memory).await)
        }
        Operation::Getresuid | Operation::Getresgid => {
            let credentials = process.credentials.lock().clone();
            SyscallOutcome::Return(credentials.resolve(operation, arguments, memory).await)
        }
        Operation::Setgroups => {
            SyscallOutcome::Return(system::setgroups(&process.credentials, arguments, memory).await)
        }
        Operation::Capget => SyscallOutcome::Return(process.capget(arguments, memory).await),
        Operation::Capset => SyscallOutcome::Return(process.capset(arguments, memory).await),
        Operation::Prlimit64 | Operation::Getrlimit | Operation::Setrlimit => {
            SyscallOutcome::Return(process.rlimit(operation, arguments, memory).await)
        }
        _ => unreachable!("dispatched non-system/sched operation"),
    }
}

#[inline(never)]
async fn dispatch_proc_mem<
    R: Resources,
    M: VirtualMemory,
    T: Thread<R>,
    O: Stdio + Clock + System + Filesystem<R> + Tty + Network<R::Network>,
>(
    operation: Operation,
    process: &mut Process<R>,
    abi: Abi,
    arguments: [u64; 6],
    memory: &mut M,
    thread: &mut T,
    output: &mut O,
) -> ControlFlow<Exit, SyscallOutcome> {
    let outcome = match operation {
        Operation::Exit | Operation::ExitGroup => {
            memory::flush_all_shared_mappings(process, memory, output).await;
            futex::exit_thread(process, memory).await;
            let status = arguments[0] as u8;
            let exit = if operation == Operation::ExitGroup {
                Exit::Group(status)
            } else {
                Exit::Thread(status)
            };
            if process.finish_syscall_exit(exit) {
                let now_secs = (output.realtime_nanos() / 1_000_000_000) as i64;
                process.cleanup_ipc_on_exit(now_secs, output);
            }
            return ControlFlow::Break(exit);
        }
        Operation::Mmap => match fs::prepare_mmap_pseudo_zero(process, arguments) {
            Ok(mmap_args) => SyscallOutcome::Return(
                memory::mmap_boxed(process, abi, mmap_args, memory, output).await,
            ),
            Err(err) => SyscallOutcome::Return(err),
        },
        Operation::Munmap => SyscallOutcome::Return(
            memory::munmap_boxed(process, abi, arguments, memory, output).await,
        ),
        Operation::Msync => SyscallOutcome::Return(
            memory::msync_boxed(process, abi, arguments, memory, output).await,
        ),
        Operation::Mremap => SyscallOutcome::Return(
            memory::mremap_boxed(process, abi, arguments, memory, output).await,
        ),
        Operation::Madvise => {
            SyscallOutcome::Return(memory::madvise_boxed(process, arguments, memory, output).await)
        }
        Operation::Shmat => {
            SyscallOutcome::Return(shm::shmat(process, abi, arguments, memory, output).await)
        }
        Operation::SchedYield => SyscallOutcome::Return(thread::sched_yield().await),
        Operation::Clone => {
            SyscallOutcome::Return(thread::clone(process, arguments, memory, thread, output).await)
        }
        Operation::Clone3 => {
            SyscallOutcome::Return(thread::clone3(process, arguments, memory, thread, output).await)
        }
        Operation::Fork => {
            SyscallOutcome::Return(process::fork(process, memory, thread, output).await)
        }
        Operation::Vfork => {
            SyscallOutcome::Return(process::vfork(process, memory, thread, output).await)
        }
        Operation::Execve => process::execve(arguments, memory, thread).await,
        Operation::Execveat => process::execveat(arguments, memory, thread).await,
        Operation::Wait4 => process::wait4(process, arguments, memory).await,
        Operation::Waitid => process::waitid(process, arguments, memory).await,
        Operation::Getrandom => {
            SyscallOutcome::Return(system::getrandom(arguments, memory, output).await)
        }
        _ => unreachable!("dispatched non-proc-mem operation"),
    };
    ControlFlow::Continue(outcome)
}

#[inline(never)]
async fn dispatch_wait_signal<
    R: Resources,
    M: VirtualMemory,
    O: Stdio + Clock + System + Filesystem<R> + Tty + Network<R::Network>,
>(
    operation: Operation,
    process: &mut Process<R>,
    abi: Abi,
    arguments: [u64; 6],
    memory: &mut M,
    output: &mut O,
) -> SyscallOutcome {
    match operation {
        Operation::RtSigsuspend => signal::rt_sigsuspend(&process.signals, arguments, memory).await,
        Operation::RtSigtimedwait => {
            signal::rt_sigtimedwait(&process.signals, arguments, memory, output).await
        }
        Operation::Pause => signal::pause(&process.signals).await,
        Operation::EpollWait | Operation::EpollPwait => {
            io::epoll_wait::<R, _, _>(
                abi,
                process,
                arguments,
                memory,
                output,
                operation == Operation::EpollPwait,
            )
            .await
        }
        Operation::Poll => poll::poll::<R, _, _>(process, arguments, memory, output).await,
        Operation::Ppoll => poll::ppoll::<R, _, _>(process, arguments, memory, output).await,
        Operation::Select => poll::select::<R, _, _>(process, arguments, memory, output).await,
        Operation::Pselect6 => poll::pselect6::<R, _, _>(process, arguments, memory, output).await,
        Operation::Nanosleep => SyscallOutcome::Return(
            thread::nanosleep(&process.signals, arguments, memory, output).await,
        ),
        Operation::ClockNanosleep => SyscallOutcome::Return(
            thread::clock_nanosleep(&process.signals, arguments, memory, output).await,
        ),
        Operation::Futex => futex::futex(process, arguments, memory, output).await,
        _ => unreachable!("dispatched non-wait-signal operation"),
    }
}

#[inline(never)]
async fn dispatch_fs_io<
    R: Resources,
    M: VirtualMemory,
    O: Stdio + Clock + System + Filesystem<R> + Tty + Network<R::Network>,
>(
    operation: Operation,
    process: &mut Process<R>,
    arguments: [u64; 6],
    memory: &mut M,
    output: &mut O,
) -> SyscallOutcome {
    match operation {
        Operation::Read => read::<R, _, _>(process, arguments, memory, output).await,
        Operation::Write => write::<R, _, _>(process, arguments, memory, output).await,
        Operation::Readv => {
            fs::readv_common::<R, _, _>(process, arguments, None, 0, memory, output).await
        }
        Operation::Writev => {
            fs::writev_common::<R, _, _>(process, arguments, None, 0, memory, output).await
        }
        Operation::Pread64 => {
            SyscallOutcome::Return(fs::pread64::<R, _, _>(process, arguments, memory, output).await)
        }
        Operation::Pwrite64 => SyscallOutcome::Return(
            fs::pwrite64::<R, _, _>(process, arguments, memory, output).await,
        ),
        Operation::Preadv => {
            fs::readv_common::<R, _, _>(
                process,
                arguments,
                Some(arguments[3] as i64),
                0,
                memory,
                output,
            )
            .await
        }
        Operation::Pwritev => {
            fs::writev_common::<R, _, _>(
                process,
                arguments,
                Some(arguments[3] as i64),
                0,
                memory,
                output,
            )
            .await
        }
        Operation::Preadv2 => {
            let off = arguments[3] as i64;
            fs::readv_common::<R, _, _>(
                process,
                arguments,
                (off != -1).then_some(off),
                arguments[5],
                memory,
                output,
            )
            .await
        }
        Operation::Pwritev2 => {
            let off = arguments[3] as i64;
            fs::writev_common::<R, _, _>(
                process,
                arguments,
                (off != -1).then_some(off),
                arguments[5],
                memory,
                output,
            )
            .await
        }
        op @ (Operation::Openat | Operation::Open | Operation::Creat) => {
            let openat_args = match op {
                Operation::Openat => arguments,
                Operation::Open => fs::open_to_openat_args(arguments),
                Operation::Creat => fs::creat_to_openat_args(arguments),
                _ => unreachable!("matched Openat | Open | Creat"),
            };
            fs::openat::<R, _, _>(process, openat_args, memory, output).await
        }
        Operation::Lseek => {
            SyscallOutcome::Return(fs::lseek::<R, _>(process, arguments, output).await)
        }
        Operation::Getdents64 => SyscallOutcome::Return(
            fs::getdents64::<R, _, _>(process, arguments, memory, output).await,
        ),
        Operation::Ftruncate => {
            SyscallOutcome::Return(fs::ftruncate::<R, _>(process, arguments, output).await)
        }
        Operation::Truncate => SyscallOutcome::Return(
            fs::truncate::<R, _, _>(process, arguments, memory, output).await,
        ),
        Operation::Fsync => SyscallOutcome::Return(
            fs::fsync::<R, _, _>(process, arguments, false, memory, output).await,
        ),
        Operation::Fdatasync => SyscallOutcome::Return(
            fs::fsync::<R, _, _>(process, arguments, true, memory, output).await,
        ),
        _ => unreachable!("dispatched non-fs-io operation"),
    }
}

#[inline(never)]
async fn dispatch_fs_extra<
    R: Resources,
    M: VirtualMemory,
    O: Stdio + Clock + System + Filesystem<R> + Tty + Network<R::Network>,
>(
    operation: Operation,
    process: &mut Process<R>,
    arguments: [u64; 6],
    memory: &mut M,
    output: &mut O,
) -> SyscallOutcome {
    match operation {
        Operation::Statfs => SyscallOutcome::Return(
            fs_extra::statfs::<R, _, _>(process, arguments, memory, output).await,
        ),
        Operation::Fstatfs => SyscallOutcome::Return(
            fs_extra::fstatfs::<R, _, _>(process, arguments, memory, output).await,
        ),
        Operation::Flock => fs_extra::flock::<R, _>(process, arguments, output).await,
        Operation::Fallocate => SyscallOutcome::Return(
            fs_extra::fallocate::<R, _, _>(process, arguments, memory, output).await,
        ),
        Operation::Sync => {
            SyscallOutcome::Return(fs_extra::sync::<R, _, _>(process, memory, output).await)
        }
        Operation::Syncfs => SyscallOutcome::Return(
            fs_extra::syncfs::<R, _, _>(process, arguments, memory, output).await,
        ),
        Operation::Chroot => SyscallOutcome::Return(
            fs_extra::chroot::<R, _, _>(process, arguments, memory, output).await,
        ),
        Operation::CopyFileRange => SyscallOutcome::Return(
            fs_extra::copy_file_range::<R, _, _>(process, arguments, memory, output).await,
        ),
        Operation::Splice => fs_extra::splice::<R, _, _>(process, arguments, memory, output).await,
        Operation::Tee => fs_extra::tee::<R>(process, arguments).await,
        Operation::Fcntl => {
            let cmd = arguments[1] as u32;
            fs_extra::fcntl_lock::<R, _, _>(
                process,
                arguments[0] as u32 as i32,
                cmd,
                arguments[2],
                memory,
                output,
            )
            .await
        }
        _ => unreachable!("dispatched non-fs-extra operation"),
    }
}

#[inline(never)]
async fn dispatch_fs_meta<
    R: Resources,
    M: VirtualMemory,
    O: Stdio + Clock + System + Filesystem<R> + Tty + Network<R::Network>,
>(
    operation: Operation,
    process: &mut Process<R>,
    arguments: [u64; 6],
    memory: &mut M,
    output: &mut O,
) -> SyscallOutcome {
    match operation {
        Operation::Fstat => SyscallOutcome::Return(
            fs::fstat::<R, _, _, _>(process, arguments, memory, output, output).await,
        ),
        Operation::Newfstatat => SyscallOutcome::Return(
            fs::newfstatat::<R, _, _, _>(process, arguments, memory, output, output).await,
        ),
        Operation::Stat => SyscallOutcome::Return(
            fs::stat::<R, _, _, _>(process, arguments, true, memory, output, output).await,
        ),
        Operation::Lstat => SyscallOutcome::Return(
            fs::stat::<R, _, _, _>(process, arguments, false, memory, output, output).await,
        ),
        Operation::Statx => SyscallOutcome::Return(
            fs::statx::<R, _, _, _>(process, arguments, memory, output, output).await,
        ),
        Operation::Faccessat => SyscallOutcome::Return(
            fs::faccessat::<R, _, _>(process, arguments, false, memory, output).await,
        ),
        Operation::Faccessat2 => SyscallOutcome::Return(
            fs::faccessat::<R, _, _>(process, arguments, true, memory, output).await,
        ),
        Operation::Access => {
            SyscallOutcome::Return(fs::access::<R, _, _>(process, arguments, memory, output).await)
        }
        Operation::Readlinkat => SyscallOutcome::Return(
            fs::readlinkat::<R, _, _>(process, arguments, memory, output).await,
        ),
        Operation::Readlink => SyscallOutcome::Return(
            fs::readlink::<R, _, _>(process, arguments, memory, output).await,
        ),
        Operation::Mkdirat => {
            SyscallOutcome::Return(fs::mkdirat::<R, _, _>(process, arguments, memory, output).await)
        }
        Operation::Mkdir => {
            SyscallOutcome::Return(fs::mkdir::<R, _, _>(process, arguments, memory, output).await)
        }
        Operation::Mknodat => {
            SyscallOutcome::Return(fs::mknodat::<R, _, _>(process, arguments, memory, output).await)
        }
        Operation::Mknod => {
            SyscallOutcome::Return(fs::mknod::<R, _, _>(process, arguments, memory, output).await)
        }
        Operation::Chmod => {
            SyscallOutcome::Return(fs::chmod::<R, _, _>(process, arguments, memory, output).await)
        }
        Operation::Fchmod => {
            SyscallOutcome::Return(fs::fchmod::<R, _>(process, arguments, output).await)
        }
        Operation::Fchmodat => SyscallOutcome::Return(
            fs::fchmodat2::<R, _, _>(process, arguments, false, memory, output).await,
        ),
        Operation::Fchmodat2 => SyscallOutcome::Return(
            fs::fchmodat2::<R, _, _>(process, arguments, true, memory, output).await,
        ),
        Operation::Chown => SyscallOutcome::Return(
            fs::chown::<R, _, _>(process, arguments, true, memory, output).await,
        ),
        Operation::Lchown => SyscallOutcome::Return(
            fs::chown::<R, _, _>(process, arguments, false, memory, output).await,
        ),
        Operation::Fchown => {
            SyscallOutcome::Return(fs::fchown::<R, _>(process, arguments, output).await)
        }
        Operation::Fchownat => SyscallOutcome::Return(
            fs::fchownat::<R, _, _>(process, arguments, memory, output).await,
        ),
        _ => unreachable!("dispatched non-fs-meta operation"),
    }
}

#[inline(never)]
async fn dispatch_fs_xattr_links<
    R: Resources,
    M: VirtualMemory,
    O: Stdio + Clock + System + Filesystem<R> + Tty + Network<R::Network>,
>(
    operation: Operation,
    process: &mut Process<R>,
    arguments: [u64; 6],
    memory: &mut M,
    output: &mut O,
) -> SyscallOutcome {
    match operation {
        Operation::Setxattr => SyscallOutcome::Return(
            fs::setxattr_path::<R, _, _>(process, arguments, true, memory, output).await,
        ),
        Operation::Lsetxattr => SyscallOutcome::Return(
            fs::setxattr_path::<R, _, _>(process, arguments, false, memory, output).await,
        ),
        Operation::Fsetxattr => SyscallOutcome::Return(
            fs::fsetxattr::<R, _, _>(process, arguments, memory, output).await,
        ),
        Operation::Getxattr => SyscallOutcome::Return(
            fs::getxattr_path::<R, _, _>(process, arguments, true, memory, output).await,
        ),
        Operation::Lgetxattr => SyscallOutcome::Return(
            fs::getxattr_path::<R, _, _>(process, arguments, false, memory, output).await,
        ),
        Operation::Fgetxattr => SyscallOutcome::Return(
            fs::fgetxattr::<R, _, _>(process, arguments, memory, output).await,
        ),
        Operation::Listxattr => SyscallOutcome::Return(
            fs::listxattr_path::<R, _, _>(process, arguments, true, memory, output).await,
        ),
        Operation::Llistxattr => SyscallOutcome::Return(
            fs::listxattr_path::<R, _, _>(process, arguments, false, memory, output).await,
        ),
        Operation::Flistxattr => SyscallOutcome::Return(
            fs::flistxattr::<R, _, _>(process, arguments, memory, output).await,
        ),
        Operation::Removexattr => SyscallOutcome::Return(
            fs::removexattr_path::<R, _, _>(process, arguments, true, memory, output).await,
        ),
        Operation::Lremovexattr => SyscallOutcome::Return(
            fs::removexattr_path::<R, _, _>(process, arguments, false, memory, output).await,
        ),
        Operation::Fremovexattr => SyscallOutcome::Return(
            fs::fremovexattr::<R, _, _>(process, arguments, memory, output).await,
        ),
        Operation::Unlinkat => SyscallOutcome::Return(
            fs::unlinkat::<R, _, _>(process, arguments, memory, output).await,
        ),
        Operation::Unlink => SyscallOutcome::Return(
            fs::unlink::<R, _, _>(process, arguments, false, memory, output).await,
        ),
        Operation::Rmdir => SyscallOutcome::Return(
            fs::unlink::<R, _, _>(process, arguments, true, memory, output).await,
        ),
        Operation::Renameat2 => SyscallOutcome::Return(
            fs::renameat2::<R, _, _>(process, arguments, true, memory, output).await,
        ),
        Operation::Renameat => SyscallOutcome::Return(
            fs::renameat2::<R, _, _>(process, arguments, false, memory, output).await,
        ),
        Operation::Rename => {
            SyscallOutcome::Return(fs::rename::<R, _, _>(process, arguments, memory, output).await)
        }
        Operation::Linkat => {
            SyscallOutcome::Return(fs::linkat::<R, _, _>(process, arguments, memory, output).await)
        }
        Operation::Link => {
            SyscallOutcome::Return(fs::link::<R, _, _>(process, arguments, memory, output).await)
        }
        Operation::Symlinkat => SyscallOutcome::Return(
            fs::symlinkat::<R, _, _>(process, arguments, memory, output).await,
        ),
        Operation::Symlink => {
            SyscallOutcome::Return(fs::symlink::<R, _, _>(process, arguments, memory, output).await)
        }
        Operation::Utimensat => SyscallOutcome::Return(
            fs::utimensat::<R, _, _>(process, arguments, memory, output).await,
        ),
        Operation::Chdir => {
            SyscallOutcome::Return(fs::chdir::<R, _, _>(process, arguments, memory, output).await)
        }
        Operation::Fchdir => {
            SyscallOutcome::Return(fs::fchdir::<R, _>(process, arguments, output).await)
        }
        _ => unreachable!("dispatched non-fs-xattr-links operation"),
    }
}

#[inline(never)]
async fn dispatch_socket<
    R: Resources,
    M: VirtualMemory,
    O: Stdio + Clock + System + Filesystem<R> + Tty + Network<R::Network>,
>(
    operation: Operation,
    process: &mut Process<R>,
    arguments: [u64; 6],
    memory: &mut M,
    output: &mut O,
) -> SyscallOutcome {
    match operation {
        Operation::Bind => SyscallOutcome::Return(
            socket::bind::<R, _, _>(
                &process.shared.descriptors,
                arguments,
                socket_context(process),
                memory,
                output,
            )
            .await,
        ),
        Operation::Listen => SyscallOutcome::Return(
            socket::listen::<R, _>(&process.shared.descriptors, arguments, output).await,
        ),
        Operation::Accept | Operation::Accept4 => SyscallOutcome::Return(
            socket::accept::<R, _, _>(
                &process.shared.descriptors,
                arguments,
                memory,
                output,
                operation == Operation::Accept4,
            )
            .await,
        ),
        Operation::Connect => SyscallOutcome::Return(
            socket::connect::<R, _, _>(&process.shared.descriptors, arguments, memory, output)
                .await,
        ),
        Operation::Getsockname => SyscallOutcome::Return(
            socket::getsockname::<R, _, _>(&process.shared.descriptors, arguments, memory, output)
                .await,
        ),
        Operation::Getpeername => SyscallOutcome::Return(
            socket::getpeername::<R, _, _>(&process.shared.descriptors, arguments, memory, output)
                .await,
        ),
        Operation::Sendto => SyscallOutcome::Return(
            socket::sendto::<R, _, _>(
                &process.shared.descriptors,
                arguments,
                socket_context(process),
                memory,
                output,
            )
            .await,
        ),
        Operation::Recvfrom => SyscallOutcome::Return(
            socket::recvfrom::<R, _, _>(&process.shared.descriptors, arguments, memory, output)
                .await,
        ),
        Operation::Sendmsg => SyscallOutcome::Return(
            socket::sendmsg::<R, _, _>(
                &process.shared.descriptors,
                arguments,
                socket_context(process),
                memory,
                output,
            )
            .await,
        ),
        Operation::Recvmsg => SyscallOutcome::Return(
            socket::recvmsg::<R, _, _>(&process.shared.descriptors, arguments, memory, output)
                .await,
        ),
        Operation::Sendmmsg => SyscallOutcome::Return(
            socket::sendmmsg::<R, _, _>(
                &process.shared.descriptors,
                arguments,
                socket_context(process),
                memory,
                output,
            )
            .await,
        ),
        Operation::Recvmmsg => SyscallOutcome::Return(
            socket::recvmmsg::<R, _, _>(&process.shared.descriptors, arguments, memory, output)
                .await,
        ),
        Operation::Shutdown => SyscallOutcome::Return(
            socket::shutdown::<R, _>(&process.shared.descriptors, arguments, output).await,
        ),
        Operation::Sendfile => SyscallOutcome::Return(
            socket::sendfile::<R, _, _>(process, arguments, memory, output).await,
        ),
        Operation::Setsockopt => SyscallOutcome::Return(
            socket::setsockopt::<R, _, _>(&process.shared.descriptors, arguments, memory, output)
                .await,
        ),
        Operation::Getsockopt => SyscallOutcome::Return(
            socket::getsockopt::<R, _, _>(&process.shared.descriptors, arguments, memory, output)
                .await,
        ),
        Operation::Ioctl => SyscallOutcome::Return({
            let ctx = socket_context(process);
            match netlink::socket_ioctl::<R::Network, _, _>(
                arguments[1] as u32,
                arguments[2],
                ctx,
                memory,
                output,
            )
            .await
            {
                Ok(Some(ret)) => ret,
                Ok(None) => tty::ioctl::<R, _, _>(process, arguments, memory, output).await,
                Err(err) => errno(err),
            }
        }),
        _ => unreachable!("dispatched non-socket operation"),
    }
}

async fn read<
    R: Resources,
    M: UserMemory,
    O: Stdio + System + Filesystem<R> + Network<R::Network>,
>(
    process: &Process<R>,
    args: [u64; 6],
    memory: &mut M,
    output: &mut O,
) -> SyscallOutcome {
    let Some(entry) = process
        .shared
        .descriptors
        .lock()
        .get_entry(args[0] as u32 as i32)
        .cloned()
    else {
        return SyscallOutcome::Return(errno(EBADF));
    };
    if matches!(
        entry.descriptor,
        Descriptor::<R>::File(_) | Descriptor::<R>::Preopen { .. }
    ) {
        return SyscallOutcome::Return(
            fs::read_file(process, &entry, args[1], args[2], None, memory, output).await,
        );
    }
    if let Descriptor::<R>::Socket(sock) = &entry.descriptor {
        let limit = args[2].min(MAX_RW_COUNT) as usize;
        if limit == 0 {
            return SyscallOutcome::Return(0);
        }
        if memory.check_writable(args[1], limit).await.is_err() {
            return SyscallOutcome::Return(errno(EFAULT));
        }
        return SyscallOutcome::Return(match socket::socket_recv(sock, limit, 0, output).await {
            Ok(recv) => {
                if !recv.data.is_empty() && memory.write(args[1], &recv.data).await.is_err() {
                    return SyscallOutcome::Return(errno(EFAULT));
                }
                recv.data.len() as u64
            }
            Err(err) => errno(err),
        });
    }
    if matches!(entry.descriptor, Descriptor::<R>::Stdin { .. }) {
        let limit = args[2].min(MAX_RW_COUNT) as usize;
        if limit == 0 {
            return SyscallOutcome::Return(0);
        }
        if memory.check_writable(args[1], limit).await.is_err() {
            return SyscallOutcome::Return(errno(EFAULT));
        }
        let nonblock = entry.fdflags() & FDFLAG_NONBLOCK != 0;
        let stdin_guard = match process
            .signals
            .interruptible(process.shared.stdin_lock.lock())
            .await
        {
            signal::WaitOutcome::Ready(guard) => guard,
            signal::WaitOutcome::Interrupted => return SyscallOutcome::RestartSys,
        };
        if process.shared.stdin_carry.lock().is_empty() {
            if nonblock {
                match output.try_read_input(limit) {
                    StdinTryRead::Ready(bytes) => *process.shared.stdin_carry.lock() = bytes,
                    StdinTryRead::Eof => return SyscallOutcome::Return(0),
                    StdinTryRead::WouldBlock => return SyscallOutcome::Return(errno(EAGAIN)),
                    StdinTryRead::Denied => return SyscallOutcome::Return(errno(EACCES)),
                }
            } else {
                match process
                    .signals
                    .interruptible(output.read_input(limit))
                    .await
                {
                    signal::WaitOutcome::Ready(Ok(bytes)) => {
                        *process.shared.stdin_carry.lock() = bytes;
                    }
                    signal::WaitOutcome::Ready(Err(Denied)) => {
                        return SyscallOutcome::Return(errno(EACCES));
                    }
                    signal::WaitOutcome::Interrupted => return SyscallOutcome::RestartSys,
                }
            }
        }
        let bytes = {
            let mut carry = process.shared.stdin_carry.lock();
            let take = carry.len().min(limit);
            carry.split_to(take)
        };
        drop(stdin_guard);
        if memory.write(args[1], &bytes).await.is_err() {
            return SyscallOutcome::Return(errno(EFAULT));
        }
        return SyscallOutcome::Return(bytes.len() as u64);
    }
    io::read_resource::<R, M, O>(process, &entry, args, memory, output).await
}

fn socket_context<R: Resources>(process: &Process<R>) -> socket::SocketContext {
    let creds = process.credentials.lock();
    socket::SocketContext {
        pid: process.shared.identity.id().get() as u32,
        cap_net_admin: creds.capabilities.has_effective(CAP_NET_ADMIN),
        cap_net_raw: creds.capabilities.has_effective(CAP_NET_RAW),
    }
}

async fn write<
    R: Resources,
    M: VirtualMemory,
    O: Stdio + System + Filesystem<R> + Network<R::Network>,
>(
    process: &Process<R>,
    args: [u64; 6],
    memory: &mut M,
    output: &mut O,
) -> SyscallOutcome {
    // Linux takes fd as an unsigned int, discarding the register's upper bits.
    let Some(entry) = process
        .shared
        .descriptors
        .lock()
        .get_entry(args[0] as u32 as i32)
        .cloned()
    else {
        return SyscallOutcome::Return(errno(EBADF));
    };
    if matches!(
        entry.descriptor,
        Descriptor::<R>::File(_) | Descriptor::<R>::Preopen { .. }
    ) {
        return SyscallOutcome::Return(
            fs::write_file(process, &entry, args[1], args[2], None, 0, memory, output).await,
        );
    }
    if let Descriptor::<R>::Socket(sock) = &entry.descriptor {
        let count = args[2].min(MAX_RW_COUNT) as usize;
        let mut data = alloc::vec![0u8; count];
        if count > 0 && memory.read(args[1], &mut data).await.is_err() {
            return SyscallOutcome::Return(errno(EFAULT));
        }
        let ctx = socket_context(process);
        return SyscallOutcome::Return(
            match socket::socket_send(sock, data, 0, None, ctx, output).await {
                Ok(written) => written as u64,
                Err(err) => errno(err),
            },
        );
    }
    let stream = match &entry.descriptor {
        Descriptor::<R>::Stdout => Stream::Stdout,
        Descriptor::<R>::Stderr => Stream::Stderr,
        _ => return io::write_resource::<R, M, O>(process, &entry, args, memory, output).await,
    };
    let nonblock = entry.fdflags() & FDFLAG_NONBLOCK != 0;
    // Linux MAX_RW_COUNT is INT_MAX rounded down to PAGE_SIZE (x86-64: 4096).
    let count = args[2].min(MAX_RW_COUNT);
    if args[1].checked_add(count).is_none() {
        return SyscallOutcome::Return(errno(EFAULT));
    }
    // One page bounds kernel stack use independently of the guest's count.
    let mut buffer = [0; 4096];
    let mut written = 0_u64;
    while written < count {
        let address = args[1] + written;
        // Stop at a user-page boundary so a fault on the next page preserves
        // the bytes already written, including an unaligned first buffer.
        let page_remaining = buffer.len() - (address as usize & (buffer.len() - 1));
        let size = (count - written).min(page_remaining as u64) as usize;
        if memory.read(address, &mut buffer[..size]).await.is_err() {
            return SyscallOutcome::Return(if written == 0 { errno(EFAULT) } else { written });
        }
        let step = if nonblock {
            output.try_write(stream, &buffer[..size])
        } else {
            output.write(stream, &buffer[..size]).await
        };
        match step {
            Ok(n) => {
                assert!(n <= size, "output returned more bytes than supplied");
                written += n as u64;
                if n < size {
                    break;
                }
            }
            Err(error) => {
                return SyscallOutcome::Return(if written != 0 {
                    written
                } else {
                    errno(match error {
                        WriteError::Interrupted => EINTR,
                        WriteError::Io => EIO,
                        WriteError::Denied => EACCES,
                        WriteError::WouldBlock => EAGAIN,
                    })
                });
            }
        }
    }
    SyscallOutcome::Return(written)
}

async fn arch_prctl<R: Resources, M: UserMemory, T: Thread<R>>(
    abi: Abi,
    args: [u64; 6],
    memory: &mut M,
    thread: &mut T,
) -> u64 {
    // Linux UAPI asm/prctl.h: ARCH_SET_FS and ARCH_GET_FS.
    match args[0] as u32 {
        0x1002 => {
            // arch/x86/kernel/process_64.c refuses a base at or above
            // TASK_SIZE_MAX.
            if args[1] >= abi.task_size() || thread.set_thread_pointer(args[1]).is_err() {
                return errno(EPERM);
            }
            0
        }
        0x1003 => match memory
            .write(args[1], &thread.thread_pointer().to_le_bytes())
            .await
        {
            Ok(()) => 0,
            Err(_) => errno(EFAULT),
        },
        _ => errno(EINVAL),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use helios_unix::OpenFile;

    // fcntl.h: O_CLOEXEC.
    const O_CLOEXEC: u64 = 0x80000;

    /// A node handle as the platform would supply one; only its identity
    /// matters here.
    #[derive(Clone)]
    struct Node;

    struct Files;
    impl Resources for Files {
        type File = Node;
        type Network = NoNetwork;
        type Data = u64;
    }

    struct NoFs;
    impl Filesystem<Files> for NoFs {}

    fn open_file(descriptors: &Descriptors<Files>, fd: i32) -> &OpenFile<Node> {
        match descriptors.get_entry(fd).map(|entry| &entry.descriptor) {
            Some(Descriptor::<Files>::File(file)) => file,
            _ => panic!("descriptor {fd} must name the file"),
        }
    }

    #[test]
    fn duplicated_file_descriptors_share_one_open_file_description() {
        let process = Process::<Files>::new(Abi::X86_64, NonZeroU32::new(1).unwrap(), 0x40_0000);
        let mut descriptors = process.shared.descriptors.lock();
        let fd = descriptors
            .insert_entry(Entry::<Files>::new(
                Descriptor::<Files>::File(OpenFile::new(Node)),
                false,
            ))
            .expect("the table has room");
        let duplicate = io::duplicate::<Files, _>(
            Abi::X86_64,
            &mut descriptors,
            Operation::Dup,
            [u64::from(fd), 0, 0, 0, 0, 0],
            &NoFs,
        );
        let target = io::duplicate::<Files, _>(
            Abi::X86_64,
            &mut descriptors,
            Operation::Dup3,
            [u64::from(fd), 9, O_CLOEXEC, 0, 0, 0],
            &NoFs,
        );
        assert_eq!(target, 9);

        let original = open_file(&descriptors, fd as i32);
        original
            .try_lock_position()
            .expect("the position lock is free")
            .set(7);
        for copy in [duplicate as i32, 9] {
            let shared = open_file(&descriptors, copy);
            assert!(shared.same_description(original));
            assert_eq!(
                shared
                    .try_lock_position()
                    .expect("the position lock is free")
                    .get(),
                7
            );
        }
        // Only close-on-exec belongs to the slot.
        assert!(descriptors.get_entry(9).unwrap().close_on_exec);
        assert!(!descriptors.get_entry(fd as i32).unwrap().close_on_exec);
    }
}
