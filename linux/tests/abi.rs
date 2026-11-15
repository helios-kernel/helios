#![cfg(feature = "runtime")]

use core::future::Future;
use core::ops::ControlFlow;
use core::task::{Context, Poll, Waker};
use helios_linux::elf::{Error, Image};
use helios_linux::syscall::{Call, MemoryFault, Output, Stream, UserMemory, WriteError, dispatch};

struct Memory(Vec<u8>);
impl UserMemory for Memory {
    fn read(&self, address: u64, output: &mut [u8]) -> Result<(), MemoryFault> {
        let start = usize::try_from(address).map_err(|_| MemoryFault)?;
        let end = start.checked_add(output.len()).ok_or(MemoryFault)?;
        output.copy_from_slice(self.0.get(start..end).ok_or(MemoryFault)?);
        Ok(())
    }
}
#[derive(Default)]
struct Sink {
    bytes: Vec<u8>,
    short: Option<usize>,
    error: Option<WriteError>,
}
impl Output for Sink {
    async fn write(&mut self, _: Stream, bytes: &[u8]) -> Result<usize, WriteError> {
        if let Some(error) = self.error {
            return Err(error);
        }
        let n = self.short.unwrap_or(bytes.len()).min(bytes.len());
        self.bytes.extend_from_slice(&bytes[..n]);
        Ok(n)
    }
}
fn ready<T>(future: impl Future<Output = T>) -> T {
    let mut future = std::pin::pin!(future);
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("test adapters complete immediately"),
    }
}
fn write(fd: u64, address: u64, count: u64) -> Call {
    Call {
        number: 1,
        arguments: [fd, address, count, 0, 0, 0],
    }
}
#[test]
fn writes_real_bytes_across_chunks() {
    let bytes = "Linux: 中文 日本語 한국어\n".repeat(300).into_bytes();
    let mut sink = Sink::default();
    let result = ready(dispatch(
        write(1, 0, bytes.len() as u64),
        &Memory(bytes.clone()),
        &mut sink,
    ));
    assert_eq!(result, ControlFlow::Continue(bytes.len() as u64));
    assert_eq!(sink.bytes, bytes);
}
#[test]
fn errors_are_negative_linux_errno_and_do_not_emit_bytes() {
    let memory = Memory(vec![42]);
    let mut sink = Sink::default();
    for (call, errno) in [
        (write(5, 0, 1), 9_u64),
        (write(1, 2, 1), 14),
        (write(1, u64::MAX, 2), 14),
        (
            Call {
                number: 9999,
                arguments: [0; 6],
            },
            38,
        ),
    ] {
        assert_eq!(
            ready(dispatch(call, &memory, &mut sink)),
            ControlFlow::Continue(errno.wrapping_neg())
        );
    }
    assert!(sink.bytes.is_empty());
}
#[test]
fn preserves_short_writes_partial_faults_and_interrupts() {
    let memory = Memory(vec![42; 4096]);
    let mut sink = Sink {
        short: Some(3),
        ..Sink::default()
    };
    assert_eq!(
        ready(dispatch(write(1, 0, 12), &memory, &mut sink)),
        ControlFlow::Continue(3)
    );
    let mut sink = Sink::default();
    assert_eq!(
        ready(dispatch(write(2, 0, 8192), &memory, &mut sink)),
        ControlFlow::Continue(4096)
    );
    let mut sink = Sink {
        error: Some(WriteError::Interrupted),
        ..Sink::default()
    };
    assert_eq!(
        ready(dispatch(write(1, 0, 1), &memory, &mut sink)),
        ControlFlow::Continue(4_u64.wrapping_neg())
    );
}
#[test]
fn zero_length_and_fd_register_width_follow_linux() {
    let mut sink = Sink::default();
    assert_eq!(
        ready(dispatch(write(1, 0, 0), &Memory(vec![]), &mut sink)),
        ControlFlow::Continue(0)
    );
    assert_eq!(
        ready(dispatch(
            write(0x1_0000_0001, 0, 1),
            &Memory(vec![7]),
            &mut sink
        )),
        ControlFlow::Continue(1)
    );
}
#[test]
fn exit_never_resumes_and_truncates_status_to_eight_bits() {
    for number in [60, 231] {
        assert_eq!(
            ready(dispatch(
                Call {
                    number,
                    arguments: [0x123, 0, 0, 0, 0, 0]
                },
                &Memory(vec![]),
                &mut Sink::default()
            )),
            ControlFlow::Break(0x23)
        );
    }
}

fn image() -> Vec<u8> {
    let mut bytes = vec![0; 4096];
    bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    bytes[16..18].copy_from_slice(&2_u16.to_le_bytes());
    bytes[18..20].copy_from_slice(&62_u16.to_le_bytes());
    bytes[20..24].copy_from_slice(&1_u32.to_le_bytes());
    bytes[24..32].copy_from_slice(&0x400100_u64.to_le_bytes());
    bytes[32..40].copy_from_slice(&64_u64.to_le_bytes());
    bytes[52..54].copy_from_slice(&64_u16.to_le_bytes());
    bytes[54..56].copy_from_slice(&56_u16.to_le_bytes());
    bytes[56..58].copy_from_slice(&1_u16.to_le_bytes());
    bytes[64..68].copy_from_slice(&1_u32.to_le_bytes());
    bytes[68..72].copy_from_slice(&5_u32.to_le_bytes());
    bytes[80..88].copy_from_slice(&0x400000_u64.to_le_bytes());
    bytes[96..104].copy_from_slice(&4096_u64.to_le_bytes());
    bytes[104..112].copy_from_slice(&8192_u64.to_le_bytes());
    bytes[112..120].copy_from_slice(&4096_u64.to_le_bytes());
    bytes
}
#[test]
fn validates_static_elf_and_retains_bss_extent() {
    let bytes = image();
    let parsed = Image::parse(&bytes).unwrap();
    assert_eq!(parsed.entry(), 0x400100);
    let segment = parsed.segments().next().unwrap();
    assert_eq!(segment.bytes.len(), 4096);
    assert_eq!(segment.memory_size, 8192);
    assert!(segment.executable);
    assert!(!segment.writable);
}
#[test]
fn refuses_truncated_dynamic_writable_code_and_kernel_addresses() {
    assert!(Image::parse(&image()[..40]).is_err());
    let mut bytes = image();
    bytes[16..18].copy_from_slice(&3_u16.to_le_bytes());
    assert!(matches!(Image::parse(&bytes), Err(Error::UnsupportedImage)));
    let mut bytes = image();
    bytes[68..72].copy_from_slice(&7_u32.to_le_bytes());
    assert!(matches!(Image::parse(&bytes), Err(Error::InvalidSegment)));
    let mut bytes = image();
    bytes[80..88].copy_from_slice(&0xffff800000000000_u64.to_le_bytes());
    assert!(matches!(Image::parse(&bytes), Err(Error::InvalidSegment)));
    let mut bytes = image();
    bytes[24..32].copy_from_slice(&0x401100_u64.to_le_bytes());
    assert!(matches!(Image::parse(&bytes), Err(Error::InvalidEntry)));
}

#[test]
fn initial_stack_is_aligned_and_contains_linux_arguments() {
    let mut bytes = [0xff; 256];
    let base = 0x10003;
    let rsp = helios_linux::stack::initialize(&mut bytes, base, b"hello", 0x401000, 4096).unwrap();
    assert_eq!(rsp % 16, 0);
    let offset = (rsp - base) as usize;
    let words: Vec<u64> = bytes[offset..offset + 80]
        .as_chunks::<8>()
        .0
        .iter()
        .map(|word| u64::from_le_bytes(*word))
        .collect();
    assert_eq!(words[0], 1);
    assert_eq!(&words[2..], &[0, 0, 6, 4096, 9, 0x401000, 0, 0]);
    let argument = (words[1] - base) as usize;
    assert_eq!(&bytes[argument..argument + 6], b"hello\0");
    assert!(helios_linux::stack::initialize(&mut [0; 8], base, b"hello", 0, 4096).is_err());
    assert!(helios_linux::stack::initialize(&mut bytes, base, b"bad\0arg", 0, 4096).is_err());
}
