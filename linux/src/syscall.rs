use core::future::Future;
use core::num::NonZeroU32;
use core::ops::ControlFlow;

/// A fault reported by the address-space owner, before any bytes are exposed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("inaccessible user address")]
pub struct MemoryFault;

pub trait UserMemory {
    /// Copies exactly `output.len()` readable bytes. The implementation owns
    /// mapping synchronization; no user reference may escape this operation.
    fn read(&self, address: u64, output: &mut [u8]) -> Result<(), MemoryFault>;
    /// Copies bytes only into writable user mappings while execution is stopped.
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
    /// Installs zero-filled private pages in an inactive address space. `hint`
    /// is advisory. Failure leaves the address space's mappings unchanged.
    fn map_anonymous(
        &mut self,
        hint: u64,
        length: u64,
        readable: bool,
        writable: bool,
        executable: bool,
    ) -> Result<u64, MapError>;
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
}

pub trait Output {
    /// Writes up to the supplied length, including short writes. The buffer
    /// belongs to the caller and remains stable across suspension.
    fn write(
        &mut self,
        stream: Stream,
        bytes: &[u8],
    ) -> impl Future<Output = Result<usize, WriteError>> + Send;
}

/// The x86-64 Linux syscall register ABI: RAX and RDI, RSI, RDX, R10, R8, R9.
#[derive(Debug, Clone, Copy)]
pub struct Call {
    pub number: u64,
    pub arguments: [u64; 6],
}

// Linux UAPI arch/x86/entry/syscalls/syscall_64.tbl and asm-generic/errno-base.h.
const SYS_WRITE: u64 = 1;
const SYS_MMAP: u64 = 9;
const SYS_IOCTL: u64 = 16;
const SYS_WRITEV: u64 = 20;
const SYS_GETPID: u64 = 39;
const SYS_ARCH_PRCTL: u64 = 158;
const SYS_GETTID: u64 = 186;
const SYS_SET_TID_ADDRESS: u64 = 218;
const ENOMEM: u64 = 12;
const ENODEV: u64 = 19;
const EOPNOTSUPP: u64 = 95;
const EINVAL: u64 = 22;
const ENOTTY: u64 = 25;
const EPERM: u64 = 1;
const MAX_RW_COUNT: u64 = 0x7fff_f000; // Linux INT_MAX rounded down to a page.

/// State of a single-threaded Linux process, exclusively owned by its task.
/// No syscall or user-memory mutation runs concurrently with guest execution.
/// The execution owner supplies a unique nonzero ID for each live process.
pub struct Process {
    id: NonZeroU32,
    fs_base: u64,
    clear_child_tid: u64,
}
impl Process {
    pub fn new(id: NonZeroU32) -> Self {
        Self {
            id,
            fs_base: 0,
            clear_child_tid: 0,
        }
    }
    pub fn fs_base(&self) -> u64 {
        self.fs_base
    }
}

const SYS_EXIT: u64 = 60;
const SYS_EXIT_GROUP: u64 = 231;
const EINTR: u64 = 4;
const EIO: u64 = 5;
const EBADF: u64 = 9;
const EFAULT: u64 = 14;
const ENOSYS: u64 = 38;

fn errno(value: u64) -> u64 {
    value.wrapping_neg()
}

/// A single-threaded process's initial ABI surface. Exit consumes the execution
/// loop through `Break`; it is never returned to the guest as a syscall result.
pub async fn dispatch<M: VirtualMemory, O: Output>(
    process: &mut Process,
    call: Call,
    memory: &mut M,
    output: &mut O,
) -> ControlFlow<u8, u64> {
    match call.number {
        SYS_EXIT | SYS_EXIT_GROUP => {
            // Linux ignores a fault clearing this address. There are no sibling
            // threads/futex waiters in this single-threaded process model.
            if process.clear_child_tid != 0 {
                let _ = memory.write(process.clear_child_tid, &0u32.to_le_bytes());
            }
            ControlFlow::Break(call.arguments[0] as u8)
        }
        SYS_MMAP => ControlFlow::Continue(mmap(call.arguments, memory)),
        SYS_GETPID | SYS_GETTID => ControlFlow::Continue(process.id.get().into()),
        SYS_SET_TID_ADDRESS => {
            process.clear_child_tid = call.arguments[0];
            ControlFlow::Continue(process.id.get().into())
        }
        SYS_ARCH_PRCTL => ControlFlow::Continue(arch_prctl(process, call.arguments, memory)),
        SYS_WRITEV => ControlFlow::Continue(writev(call.arguments, memory, output).await),
        SYS_IOCTL => ControlFlow::Continue(match call.arguments[0] as u32 {
            // The inherited output descriptors are byte streams, not terminals.
            1 | 2 => errno(ENOTTY),
            _ => errno(EBADF),
        }),
        SYS_WRITE => ControlFlow::Continue(write(call.arguments, memory, output).await),
        _ => ControlFlow::Continue(errno(ENOSYS)),
    }
}

async fn write<M: UserMemory, O: Output>(args: [u64; 6], memory: &M, output: &mut O) -> u64 {
    // Linux takes fd as an unsigned int, discarding the register's upper bits.
    let stream = match args[0] as u32 {
        1 => Stream::Stdout,
        2 => Stream::Stderr,
        _ => return errno(EBADF),
    };
    // Linux MAX_RW_COUNT is INT_MAX rounded down to PAGE_SIZE (x86-64: 4096).
    let count = args[2].min(MAX_RW_COUNT);
    let Some(end) = args[1].checked_add(count) else {
        return errno(EFAULT);
    };
    // Four-level x86-64 userspace ends at the canonical lower-half boundary.
    if args[1] >= 1 << 47 || end > 1 << 47 {
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
                    })
                };
            }
        }
    }
    written
}

fn arch_prctl<M: UserMemory>(process: &mut Process, args: [u64; 6], memory: &mut M) -> u64 {
    // Linux UAPI asm/prctl.h: ARCH_SET_FS and ARCH_GET_FS.
    match args[0] as u32 {
        0x1002 => {
            if args[1] >= 1 << 47 {
                return errno(EPERM);
            }
            process.fs_base = args[1];
            0
        }
        0x1003 => match memory.write(args[1], &process.fs_base.to_le_bytes()) {
            Ok(()) => 0,
            Err(_) => errno(EFAULT),
        },
        _ => errno(EINVAL),
    }
}

async fn writev<M: UserMemory, O: Output>(args: [u64; 6], memory: &M, output: &mut O) -> u64 {
    if !matches!(args[0] as u32, 1 | 2) {
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
    let Some(end) = args[1].checked_add(u64::from(count) * 16) else {
        return errno(EFAULT);
    };
    if end > 1 << 47 {
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
        let result = write([args[0], base, length, 0, 0, 0], memory, output).await;
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
    // Linux x86-64 mmap: MAP_PRIVATE | MAP_ANONYMOUS, PROT_{READ,WRITE,EXEC}.
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
    let Some(length) = args[1]
        .checked_add(4095)
        .map(|n| n & !4095)
        .filter(|n| *n < 1 << 47)
    else {
        return errno(ENOMEM);
    };
    // x86 permits reads from writable or executable mappings as well.
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
