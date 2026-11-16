use bytes::Bytes;
use core::convert::Infallible;
use core::future::Future;
use core::num::NonZeroU32;
use core::ops::ControlFlow;
use helios_unix::{DescriptorSlots, FileDescriptor, FileDescriptorEntry, ProcessIdentity};
mod io;
pub use crate::abi::{Abi, Operation};
pub use io::Clock;

/// The platform objects a process's descriptors can hold besides the UNIX
/// objects `helios-unix` owns (pipes, eventfds, epoll sets): the host's
/// files and sockets, and the user data its epoll interests carry. A
/// process shares descriptors with programs of another ABI by naming the
/// same resource set they use.
pub trait Resources: 'static {
    type File: Clone;
    type Socket: Clone;
    type Data: EpollData;
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

/// A resource set with no files and no sockets.
pub struct NoBacking;
impl Resources for NoBacking {
    type File = Infallible;
    type Socket = Infallible;
    type Data = u64;
}

pub type Descriptor<R> =
    FileDescriptor<<R as Resources>::File, <R as Resources>::Socket, <R as Resources>::Data>;
pub type Entry<R> =
    FileDescriptorEntry<<R as Resources>::File, <R as Resources>::Socket, <R as Resources>::Data>;
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

pub trait UserMemory {
    /// Copies exactly `output.len()` readable bytes. The implementation owns
    /// mapping synchronization; no user reference may escape this operation.
    fn read(&self, address: u64, output: &mut [u8]) -> Result<(), MemoryFault>;
    /// Validates a writable range without modifying it. The exclusive memory
    /// borrow keeps its mappings stable until the syscall completes.
    fn check_writable(&self, address: u64, length: usize) -> Result<(), MemoryFault>;
    /// Copies bytes only into writable user mappings.
    fn write(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryFault>;
}

#[derive(Debug, thiserror::Error)]
pub enum MapError {
    #[error("user memory exhausted")]
    OutOfMemory,
    #[error("mapping permissions refused")]
    Permission,
    #[error("invalid mapping")]
    Invalid,
}

pub trait VirtualMemory: UserMemory {
    /// Installs zero-filled private pages. `hint` is advisory. Failure
    /// leaves the address space's mappings unchanged.
    fn map_anonymous(
        &mut self,
        hint: u64,
        length: u64,
        readable: bool,
        writable: bool,
        executable: bool,
    ) -> Result<u64, MapError>;
}

/// The calling thread's thread pointer, which x86-64's `arch_prctl` sets
/// and reads. aarch64 user code writes `TPIDR_EL0` itself.
pub trait Thread {
    fn thread_pointer(&self) -> u64;
    /// Refused for an address outside the user range.
    fn set_thread_pointer(&mut self, address: u64) -> Result<(), Denied>;
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
}

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

    /// Waits for standard input and returns what arrived, at most `limit`
    /// bytes; empty at the end of input.
    fn read_input(&mut self, limit: usize) -> impl Future<Output = Result<Bytes, Denied>> + Send;
}

/// A system call as its ABI's registers carry it.
#[derive(Debug, Clone, Copy)]
pub struct Call {
    pub number: u64,
    pub arguments: [u64; 6],
}

// Linux uapi/asm-generic/errno-base.h and errno.h.
const EPERM: u64 = 1;
const EINTR: u64 = 4;
const EIO: u64 = 5;
const EBADF: u64 = 9;
const ENOMEM: u64 = 12;
const EACCES: u64 = 13;
const EFAULT: u64 = 14;
const ENODEV: u64 = 19;
const EINVAL: u64 = 22;
const ENOTTY: u64 = 25;
const ENOSYS: u64 = 38;
const EOPNOTSUPP: u64 = 95;
const MAX_RW_COUNT: u64 = 0x7fff_f000; // Linux INT_MAX rounded down to a page.
// x86-64 TASK_SIZE_MAX with four-level paging: the end of the user half.
const X86_64_USER_END: u64 = 1 << 47;

/// State of a single-threaded Linux process, exclusively owned by its task.
/// No syscall or user-memory mutation runs concurrently with guest execution.
/// The execution owner supplies a unique nonzero ID for each live process.
pub struct Process<R: Resources> {
    abi: Abi,
    identity: ProcessIdentity,
    descriptors: Descriptors<R>,
    clear_child_tid: u64,
}
impl<R: Resources> Process<R> {
    /// A process holding the standard streams only.
    pub fn new(abi: Abi, id: NonZeroU32) -> Self {
        Self::with_descriptors(abi, id, standard_streams::<R>())
    }
    /// A process holding the descriptors its parent handed it.
    pub fn with_descriptors(abi: Abi, id: NonZeroU32, descriptors: Descriptors<R>) -> Self {
        Self {
            abi,
            identity: ProcessIdentity::new(id.into()),
            descriptors,
            clear_child_tid: 0,
        }
    }
}

fn errno(value: u64) -> u64 {
    value.wrapping_neg()
}

/// A single-threaded process's initial ABI surface. Exit consumes the execution
/// loop through `Break`; it is never returned to the guest as a syscall result.
pub async fn dispatch<R: Resources, M: VirtualMemory, T: Thread, O: Stdio + Clock>(
    process: &mut Process<R>,
    call: Call,
    memory: &mut M,
    thread: &mut T,
    output: &mut O,
) -> ControlFlow<u8, u64> {
    let arguments = call.arguments;
    let result = match process.abi.operation(call.number) {
        Operation::Exit | Operation::ExitGroup => {
            // Linux ignores a fault clearing this address. There are no sibling
            // threads/futex waiters in this single-threaded process model.
            if process.clear_child_tid != 0 {
                let _ = memory.write(process.clear_child_tid, &0u32.to_le_bytes());
            }
            return ControlFlow::Break(arguments[0] as u8);
        }
        Operation::Read => {
            io::read::<R, _, _>(&mut process.descriptors, arguments, memory, output).await
        }
        Operation::Close => process
            .descriptors
            .close(arguments[0] as u32 as i32)
            .map_or_else(io::descriptor_errno, |_| 0),
        operation @ (Operation::Pipe | Operation::Pipe2) => io::pipe::<R, _>(
            &mut process.descriptors,
            arguments,
            memory,
            operation == Operation::Pipe2,
        ),
        operation @ (Operation::Dup | Operation::Dup2 | Operation::Dup3 | Operation::Fcntl) => {
            io::duplicate::<R>(&mut process.descriptors, operation, arguments)
        }
        operation @ (Operation::Eventfd | Operation::Eventfd2) => io::event::<R>(
            &mut process.descriptors,
            arguments,
            operation == Operation::Eventfd2,
        ),
        operation @ (Operation::EpollCreate | Operation::EpollCreate1) => io::epoll_create::<R>(
            &mut process.descriptors,
            arguments,
            operation == Operation::EpollCreate1,
        ),
        Operation::EpollCtl => {
            io::epoll_ctl::<R, _>(process.abi, &mut process.descriptors, arguments, memory)
        }
        operation @ (Operation::EpollWait | Operation::EpollPwait) => {
            io::epoll_wait::<R, _, _>(
                process.abi,
                &process.descriptors,
                arguments,
                memory,
                output,
                operation == Operation::EpollPwait,
            )
            .await
        }
        Operation::Mmap => mmap(arguments, memory),
        Operation::Getpid | Operation::Gettid => process.identity.id().get(),
        Operation::SetTidAddress => {
            process.clear_child_tid = arguments[0];
            process.identity.id().get()
        }
        Operation::ArchPrctl => arch_prctl(arguments, memory, thread),
        Operation::Writev => {
            writev::<R, _, _>(&process.descriptors, arguments, memory, output).await
        }
        Operation::Ioctl => match process.descriptors.get_entry(arguments[0] as u32 as i32) {
            Some(_) => errno(ENOTTY),
            None => errno(EBADF),
        },
        Operation::Write => write::<R, _, _>(&process.descriptors, arguments, memory, output).await,
        Operation::Unknown => errno(ENOSYS),
    };
    ControlFlow::Continue(result)
}

async fn write<R: Resources, M: UserMemory, O: Stdio>(
    descriptors: &Descriptors<R>,
    args: [u64; 6],
    memory: &M,
    output: &mut O,
) -> u64 {
    // Linux takes fd as an unsigned int, discarding the register's upper bits.
    let Some(entry) = descriptors.get_entry(args[0] as u32 as i32) else {
        return errno(EBADF);
    };
    let stream = match &entry.descriptor {
        Descriptor::<R>::Stdout => Stream::Stdout,
        Descriptor::<R>::Stderr => Stream::Stderr,
        _ => return io::write_resource::<R, M>(entry, args, memory).await,
    };
    // Linux MAX_RW_COUNT is INT_MAX rounded down to PAGE_SIZE (x86-64: 4096).
    let count = args[2].min(MAX_RW_COUNT);
    if args[1].checked_add(count).is_none() {
        return errno(EFAULT);
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
        if memory.read(address, &mut buffer[..size]).is_err() {
            return if written == 0 { errno(EFAULT) } else { written };
        }
        match output.write(stream, &buffer[..size]).await {
            Ok(n) => {
                assert!(n <= size, "output returned more bytes than supplied");
                written += n as u64;
                if n < size {
                    break;
                }
            }
            Err(error) => {
                return if written != 0 {
                    written
                } else {
                    errno(match error {
                        WriteError::Interrupted => EINTR,
                        WriteError::Io => EIO,
                        WriteError::Denied => EACCES,
                    })
                };
            }
        }
    }
    written
}

fn arch_prctl<M: UserMemory, T: Thread>(args: [u64; 6], memory: &mut M, thread: &mut T) -> u64 {
    // Linux UAPI asm/prctl.h: ARCH_SET_FS and ARCH_GET_FS.
    match args[0] as u32 {
        0x1002 => {
            if args[1] >= X86_64_USER_END || thread.set_thread_pointer(args[1]).is_err() {
                return errno(EPERM);
            }
            0
        }
        0x1003 => match memory.write(args[1], &thread.thread_pointer().to_le_bytes()) {
            Ok(()) => 0,
            Err(_) => errno(EFAULT),
        },
        _ => errno(EINVAL),
    }
}

async fn writev<R: Resources, M: UserMemory, O: Stdio>(
    descriptors: &Descriptors<R>,
    args: [u64; 6],
    memory: &M,
    output: &mut O,
) -> u64 {
    if descriptors.get_entry(args[0] as u32 as i32).is_none() {
        return errno(EBADF);
    }
    let count = args[2] as u32;
    // Linux UIO_MAXIOV; negative int values also fail this unsigned comparison.
    if count > 1024 {
        return errno(EINVAL);
    }
    if count == 0 {
        return 0;
    }
    if args[1].checked_add(u64::from(count) * 16).is_none() {
        return errno(EFAULT);
    }
    let mut vector = [0; 16];
    // Import/validate all lengths before emitting bytes, as Linux import_iovec
    // does. The stopped private process cannot mutate the descriptors meanwhile.
    for index in 0..count {
        if memory
            .read(args[1] + u64::from(index) * 16, &mut vector)
            .is_err()
        {
            return errno(EFAULT);
        }
        let length = u64::from_le_bytes(vector[8..].try_into().unwrap());
        if length > i64::MAX as u64 {
            return errno(EINVAL);
        }
    }
    let mut done = 0;
    for index in 0..count {
        if done == MAX_RW_COUNT {
            break;
        }
        memory
            .read(args[1] + u64::from(index) * 16, &mut vector)
            .expect("validated immutable iovec");
        let base = u64::from_le_bytes(vector[..8].try_into().unwrap());
        let length = u64::from_le_bytes(vector[8..].try_into().unwrap()).min(MAX_RW_COUNT - done);
        if length == 0 {
            continue;
        }
        let result = write::<R, _, _>(
            descriptors,
            [args[0], base, length, 0, 0, 0],
            memory,
            output,
        )
        .await;
        if (result as i64) < 0 {
            return if done == 0 { result } else { done };
        }
        done += result;
        if result < length {
            break;
        }
    }
    done
}

fn mmap<M: VirtualMemory>(args: [u64; 6], memory: &mut M) -> u64 {
    // Linux mmap: MAP_PRIVATE | MAP_ANONYMOUS, PROT_{READ,WRITE,EXEC}, whose
    // values asm-generic/mman-common.h gives both ABIs.
    if args[1] == 0 || args[2] & !7 != 0 || args[3] & 3 != 2 || args[5] & 4095 != 0 {
        return errno(EINVAL);
    }
    if args[3] & 0x20 == 0 {
        // Output streams are valid descriptors but cannot back a mapping.
        return errno(if matches!(args[4] as u32, 1 | 2) {
            ENODEV
        } else {
            EBADF
        });
    }
    if args[3] & !0x22 != 0 {
        return errno(EOPNOTSUPP);
    } // Unsupported mapping operations.
    if args[2] & 6 == 6 {
        return errno(EPERM);
    } // Enforce the native W^X policy.
    let Some(length) = args[1].checked_add(4095).map(|n| n & !4095) else {
        return errno(ENOMEM);
    };
    // Both ISAs permit reads from writable or executable mappings as well.
    match memory.map_anonymous(
        args[0] & !4095,
        length,
        args[2] != 0,
        args[2] & 2 != 0,
        args[2] & 4 != 0,
    ) {
        Ok(address) => address,
        Err(MapError::OutOfMemory) => errno(ENOMEM),
        Err(MapError::Permission) => errno(EPERM),
        Err(MapError::Invalid) => errno(EINVAL),
    }
}
