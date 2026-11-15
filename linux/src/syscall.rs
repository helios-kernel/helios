use core::future::Future;
use core::ops::ControlFlow;

/// A fault reported by the address-space owner, before any bytes are exposed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("unreadable user address")]
pub struct MemoryFault;

pub trait UserMemory {
    /// Copies exactly `output.len()` readable bytes. The implementation owns
    /// mapping synchronization; no user reference may escape this operation.
    fn read(&self, address: u64, output: &mut [u8]) -> Result<(), MemoryFault>;
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
pub async fn dispatch<M: UserMemory, O: Output>(
    call: Call,
    memory: &M,
    output: &mut O,
) -> ControlFlow<u8, u64> {
    match call.number {
        SYS_EXIT | SYS_EXIT_GROUP => ControlFlow::Break(call.arguments[0] as u8),
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
    let count = args[2].min(0x7fff_f000);
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
        let size = (count - written).min(buffer.len() as u64) as usize;
        if memory.read(args[1] + written, &mut buffer[..size]).is_err() {
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
