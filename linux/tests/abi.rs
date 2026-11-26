#![cfg(feature = "runtime")]

use core::future::Future;
use core::ops::ControlFlow;
use core::task::{Context, Poll, Waker};
use helios_hal::vmm::PageFlags;
use helios_linux::abi::Abi;
use helios_linux::abi::Operation;
use helios_linux::elf::{Error, Image};
use helios_linux::syscall::{
    Call, Credentials, Denied, Exit, Ids, MapError, MemoryFault, MemoryTotals, NoBacking, Process,
    Region, SpawnError, SpawnedThread, Start, Stdio, Stream, System, Thread, UserMemory,
    WriteError, dispatch as linux_dispatch,
};

// The crate root is not `mod.rs`, so the submodule names its directory.
#[path = "abi/files_poll_tty.rs"]
mod files_poll_tty;
#[path = "abi/permissions.rs"]
mod permissions;
#[path = "abi/system.rs"]
mod system;

// x86-64's four-level user half.
const USER_END: u64 = 1 << 47;

fn parse(bytes: &[u8]) -> Result<Image<'_>, Error> {
    Image::parse(bytes, Abi::X86_64, USER_END)
}

/// Where these tests' processes start their break, past any memory a test
/// reads.
const PROGRAM_BREAK: u64 = 0x40_0000;

fn new_process(id: u32) -> Process<NoBacking> {
    Process::new(
        Abi::X86_64,
        core::num::NonZeroU32::new(id).unwrap(),
        PROGRAM_BREAK,
    )
}

/// The calling thread's thread pointer, which the sink keeps so a test
/// reads back what `arch_prctl` set.
struct TestThread(std::sync::Arc<std::sync::atomic::AtomicU64>);
impl Thread for TestThread {
    fn thread_pointer(&self) -> u64 {
        self.0.load(std::sync::atomic::Ordering::Relaxed)
    }
    fn set_thread_pointer(&mut self, address: u64) -> Result<(), Denied> {
        self.0.store(address, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }
    fn spawn_thread(&mut self, _: Process<NoBacking>, _: SpawnedThread) -> Result<(), SpawnError> {
        Err(SpawnError::Busy)
    }
}

async fn process_dispatch(
    process: &mut Process<NoBacking>,
    call: Call,
    memory: &mut Memory,
    sink: &mut Sink,
) -> ControlFlow<Exit, u64> {
    let mut thread = TestThread(sink.thread.clone());
    match linux_dispatch(process, call, memory, &mut thread, sink).await {
        ControlFlow::Continue(helios_linux::syscall::SyscallOutcome::Return(value)) => {
            ControlFlow::Continue(value)
        }
        ControlFlow::Continue(other) => panic!("unexpected syscall outcome: {other:?}"),
        ControlFlow::Break(exit) => ControlFlow::Break(exit),
    }
}

#[derive(Clone)]
struct Memory(Vec<u8>);
impl UserMemory for Memory {
    async fn check_writable(&self, address: u64, length: usize) -> Result<(), MemoryFault> {
        let start = usize::try_from(address).map_err(|_| MemoryFault)?;
        let end = start.checked_add(length).ok_or(MemoryFault)?;
        self.0.get(start..end).map(|_| ()).ok_or(MemoryFault)
    }
    async fn write(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryFault> {
        let start = usize::try_from(address).map_err(|_| MemoryFault)?;
        let end = start.checked_add(bytes.len()).ok_or(MemoryFault)?;
        self.0
            .get_mut(start..end)
            .ok_or(MemoryFault)?
            .copy_from_slice(bytes);
        Ok(())
    }
    async fn read(&self, address: u64, output: &mut [u8]) -> Result<(), MemoryFault> {
        let start = usize::try_from(address).map_err(|_| MemoryFault)?;
        let end = start.checked_add(output.len()).ok_or(MemoryFault)?;
        output.copy_from_slice(self.0.get(start..end).ok_or(MemoryFault)?);
        Ok(())
    }
    async fn atomic_load_u32(&self, address: u64) -> Result<u32, MemoryFault> {
        self.try_atomic_load_u32(address)?.ok_or(MemoryFault)
    }
    fn try_atomic_load_u32(&self, address: u64) -> Result<Option<u32>, MemoryFault> {
        if address & 3 != 0 {
            return Err(MemoryFault);
        }
        let start = usize::try_from(address).map_err(|_| MemoryFault)?;
        let end = start.checked_add(4).ok_or(MemoryFault)?;
        let bytes: [u8; 4] = self
            .0
            .get(start..end)
            .ok_or(MemoryFault)?
            .try_into()
            .unwrap();
        Ok(Some(u32::from_le_bytes(bytes)))
    }
    async fn atomic_store_u32(&mut self, address: u64, value: u32) -> Result<(), MemoryFault> {
        if address & 3 != 0 {
            return Err(MemoryFault);
        }
        self.write(address, &value.to_le_bytes()).await
    }
    async fn atomic_compare_exchange_u32(
        &mut self,
        address: u64,
        expected: u32,
        desired: u32,
    ) -> Result<Result<u32, u32>, MemoryFault> {
        let current = self.atomic_load_u32(address).await?;
        if current == expected {
            self.atomic_store_u32(address, desired).await?;
            Ok(Ok(current))
        } else {
            Ok(Err(current))
        }
    }
}
/// The flat memory maps by growing; the calls that change mappings have
/// their own tests over a page map (`tests/memory.rs`).
impl helios_linux::syscall::VirtualMemory for Memory {
    fn lowest_address(&self) -> u64 {
        4096
    }
    fn map_anywhere(
        &mut self,
        hint: u64,
        length: u64,
        _: PageFlags,
    ) -> Result<u64, helios_linux::syscall::MapError> {
        let base = hint.max((self.0.len() as u64 + 4095) & !4095).max(4096);
        self.0.resize((base + length) as usize, 0);
        Ok(base)
    }
    fn map_at(&mut self, _: u64, _: u64, _: PageFlags) -> Result<(), MapError> {
        unreachable!("the flat test memory maps by growing only")
    }
    fn unmap(&mut self, _: u64, _: u64) {
        unreachable!("the flat test memory maps by growing only")
    }
    fn protect(&mut self, _: u64, _: u64, _: PageFlags) -> Result<(), MapError> {
        unreachable!("the flat test memory maps by growing only")
    }
    fn discard(&mut self, _: u64, _: u64) {
        unreachable!("the flat test memory maps by growing only")
    }
    fn remap(&mut self, _: u64, _: u64, _: u64, _: u64) -> Result<(), MapError> {
        unreachable!("the flat test memory maps by growing only")
    }
    fn region(&self, _: u64, _: u64) -> Option<Region> {
        None
    }
    fn free_range(&self, _: u64, _: u64) -> Option<u64> {
        unreachable!("the flat test memory maps by growing only")
    }
}
async fn dispatch(call: Call, memory: &Memory, sink: &mut Sink) -> ControlFlow<Exit, u64> {
    process_dispatch(&mut new_process(1), call, &mut memory.clone(), sink).await
}
#[derive(Default)]
struct Sink {
    time: core::sync::atomic::AtomicU64,
    bytes: Vec<u8>,
    short: Option<usize>,
    error: Option<WriteError>,
    input: bytes::Bytes,
    thread: std::sync::Arc<std::sync::atomic::AtomicU64>,
    wall_nanos: u64,
    may_set_wall_clock: bool,
    cpu_nanos: u64,
    entropy: u8,
    processes: u32,
    hostname: helios_linux::syscall::UtsField,
    domainname: helios_linux::syscall::UtsField,
}
impl helios_linux::syscall::Network<helios_unix::NoNetwork> for Sink {
    fn to_ip(&self, address: core::convert::Infallible) -> helios_linux::syscall::IpAddr {
        match address {}
    }
    fn encode_ip(&self, _: helios_linux::syscall::IpAddr) -> core::convert::Infallible {
        unreachable!()
    }
}

impl System for Sink {
    fn realtime_nanos(&self) -> u64 {
        self.wall_nanos
    }
    fn set_realtime_nanos(&mut self, nanos: u64) -> Result<(), Denied> {
        if !self.may_set_wall_clock {
            return Err(Denied);
        }
        self.wall_nanos = nanos;
        Ok(())
    }
    fn cpu_nanos(&self) -> u64 {
        self.cpu_nanos
    }
    /// A counting sequence, so a test sees exactly which bytes were drawn.
    fn fill_random(&mut self, output: &mut [u8]) {
        for byte in output {
            *byte = self.entropy;
            self.entropy = self.entropy.wrapping_add(1);
        }
    }
    fn memory(&self) -> MemoryTotals {
        MemoryTotals {
            total_bytes: 8 << 30,
            free_bytes: 3 << 30,
        }
    }
    fn process_count(&self) -> u32 {
        self.processes
    }
    fn kernel_version(&self) -> &str {
        "Helios test build"
    }
    fn hostname(&self) -> helios_linux::syscall::UtsField {
        self.hostname
    }
    fn domainname(&self) -> helios_linux::syscall::UtsField {
        self.domainname
    }
    fn set_hostname(&mut self, name: helios_linux::syscall::UtsField) -> Result<(), Denied> {
        self.hostname = name;
        Ok(())
    }
    fn set_domainname(&mut self, name: helios_linux::syscall::UtsField) -> Result<(), Denied> {
        self.domainname = name;
        Ok(())
    }
}
impl helios_linux::syscall::Filesystem<NoBacking> for Sink {}
impl helios_linux::syscall::Tty for Sink {}
impl Stdio for Sink {
    async fn write(&mut self, _: Stream, bytes: &[u8]) -> Result<usize, WriteError> {
        if let Some(error) = self.error {
            return Err(error);
        }
        let n = self.short.unwrap_or(bytes.len()).min(bytes.len());
        self.bytes.extend_from_slice(&bytes[..n]);
        Ok(n)
    }
    async fn read_input(&mut self, limit: usize) -> Result<bytes::Bytes, Denied> {
        if self.error == Some(WriteError::Denied) {
            return Err(Denied);
        }
        let n = limit.min(self.input.len());
        Ok(self.input.split_to(n))
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
    let mut sink = Sink::default();
    assert_eq!(
        ready(dispatch(write(1, 4090, 32), &memory, &mut sink)),
        ControlFlow::Continue(6)
    );
    assert_eq!(sink.bytes, vec![42; 6]);
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
    for (number, expected) in [(60, Exit::Thread(0x23)), (231, Exit::Group(0x23))] {
        assert_eq!(
            ready(dispatch(
                Call {
                    number,
                    arguments: [0x123, 0, 0, 0, 0, 0]
                },
                &Memory(vec![]),
                &mut Sink::default()
            )),
            ControlFlow::Break(expected)
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
    let parsed = parse(&bytes).unwrap();
    assert_eq!(parsed.entry(), 0x400100);
    let segment = parsed.segments().next().unwrap();
    assert_eq!(segment.bytes.len(), 4096);
    assert_eq!(segment.memory_size, 8192);
    assert!(segment.executable);
    assert!(!segment.writable);
}
#[test]
fn a_writable_executable_segment_loads_writable_and_executable() {
    // fs/binfmt_elf.c `load_elf_binary` maps a PF_R | PF_W | PF_X segment
    // through `elf_map` with `make_prot(p_flags)`: PROT_READ, PROT_WRITE and
    // PROT_EXEC together.
    let mut bytes = image();
    bytes[68..72].copy_from_slice(&7_u32.to_le_bytes());
    let parsed = parse(&bytes).expect("an RWX load segment is a valid image");
    let segment = parsed.segments().next().expect("the image's load segment");
    assert!(segment.writable && segment.executable);
}

#[test]
fn refuses_truncated_relocatable_unknown_flags_and_kernel_addresses() {
    assert!(parse(&image()[..40]).is_err());
    // ET_REL (1) is not a loadable executable or PIE image.
    let mut bytes = image();
    bytes[16..18].copy_from_slice(&1_u16.to_le_bytes());
    assert!(matches!(parse(&bytes), Err(Error::UnsupportedImage)));
    // A p_flags bit beyond PF_R, PF_W and PF_X.
    let mut bytes = image();
    bytes[68..72].copy_from_slice(&0x0d_u32.to_le_bytes());
    assert!(matches!(parse(&bytes), Err(Error::InvalidSegment)));
    let mut bytes = image();
    bytes[80..88].copy_from_slice(&0xffff800000000000_u64.to_le_bytes());
    assert!(matches!(parse(&bytes), Err(Error::InvalidSegment)));
    let mut bytes = image();
    bytes[24..32].copy_from_slice(&0x401100_u64.to_le_bytes());
    assert!(matches!(parse(&bytes), Err(Error::InvalidEntry)));
}

#[test]
fn initial_stack_is_aligned_and_contains_linux_arguments() {
    let arguments: [&[u8]; 4] = [
        b"/bin/args",
        "中文".as_bytes(),
        "日本語".as_bytes(),
        "한국어".as_bytes(),
    ];
    let environment: [&[u8]; 1] = [b"LANG=ko_KR.UTF-8"];
    let startup = helios_linux::stack::Startup {
        entry: 0x401000,
        page_size: 4096,
        headers: helios_linux::elf::ProgramHeaders {
            address: 0x400040,
            count: 3,
        },
        interpreter_base: 0x7fff_f7dd_0000,
        flags: 0,
        random: [7; 16],
        arguments: &arguments,
        environment: &environment,
        executable: b"/bin/args",
        uid: 1000,
        euid: 0,
        gid: 100,
        egid: 200,
        secure: true,
    };
    let top = 0x7fff_0000_0000;
    let stack = helios_linux::stack::build(&startup, top).unwrap();
    assert_eq!(stack.pointer % 16, 0);
    assert_eq!(stack.bytes.len() % 4096, 0);
    assert_eq!(stack.base + stack.bytes.len() as u64, top);
    let at = |address: u64| (address - stack.base) as usize;
    let words: Vec<u64> = stack.bytes[at(stack.pointer)..]
        .as_chunks::<8>()
        .0
        .iter()
        .take(38)
        .map(|word| u64::from_le_bytes(*word))
        .collect();
    let string = |address: u64| {
        let start = at(address);
        let end = start + stack.bytes[start..].iter().position(|b| *b == 0).unwrap();
        &stack.bytes[start..end]
    };
    assert_eq!(words[0], 4);
    for (index, argument) in arguments.iter().enumerate() {
        assert_eq!(string(words[1 + index]), *argument);
    }
    assert_eq!(words[5], 0);
    assert_eq!(string(words[6]), environment[0]);
    assert_eq!(words[7], 0);
    assert_eq!(
        &words[8..32],
        &[
            3,
            0x400040,
            4,
            56,
            5,
            3,
            6,
            4096,
            7,
            0x7fff_f7dd_0000,
            8,
            0,
            9,
            0x401000,
            11,
            1000,
            12,
            0,
            13,
            100,
            14,
            200,
            23,
            1,
        ]
    );
    assert_eq!(words[32], 25);
    assert_eq!(&stack.bytes[at(words[33])..at(words[33]) + 16], &[7; 16]);
    assert_eq!(words[34], 31);
    assert_eq!(string(words[35]), b"/bin/args");
    assert_eq!(&words[36..38], &[0, 0]);
    let bad: [&[u8]; 1] = [b"bad\0arg"];
    let refused = helios_linux::stack::Startup {
        arguments: &bad,
        ..startup
    };
    assert!(helios_linux::stack::build(&refused, top).is_err());
}

#[test]
fn aarch64_numbers_reach_the_same_operations_and_legacy_numbers_do_not() {
    let mut process = Process::<NoBacking>::new(
        Abi::Aarch64,
        core::num::NonZeroU32::new(5).unwrap(),
        PROGRAM_BREAK,
    );
    let mut memory = Memory(vec![0; 64]);
    memory.0[..10].copy_from_slice("中文日\n".as_bytes());
    let mut sink = Sink::default();
    // asm-generic numbers write 64 and getpid 172.
    assert_eq!(
        unix_call(
            &mut process,
            64,
            [1, 0, 10, 0, 0, 0],
            &mut memory,
            &mut sink
        ),
        10
    );
    assert_eq!(&sink.bytes, "中文日\n".as_bytes());
    assert_eq!(
        unix_call(&mut process, 172, [0; 6], &mut memory, &mut sink),
        5
    );
    // x86-64's write (1), open (2) and eventfd (284) are no aarch64 calls this
    // decoder serves (1 is io_destroy, 2 io_submit, 284 seccomp).
    for number in [1, 2, 284] {
        assert_eq!(
            unix_call(&mut process, number, [0; 6], &mut memory, &mut sink),
            38u64.wrapping_neg()
        );
    }
    // pipe2 is 59.
    assert_eq!(
        unix_call(
            &mut process,
            59,
            [16, 0, 0, 0, 0, 0],
            &mut memory,
            &mut sink
        ),
        0
    );
    // aarch64's epoll_event is not packed: the data sits at offset 8 of a
    // 16-byte record (eventfd2 19, epoll_create1 20, epoll_ctl 21,
    // epoll_pwait 22).
    let event = unix_call(&mut process, 19, [1, 0, 0, 0, 0, 0], &mut memory, &mut sink);
    let epoll = unix_call(&mut process, 20, [0; 6], &mut memory, &mut sink);
    memory.0[24..28].copy_from_slice(&1u32.to_le_bytes());
    memory.0[32..40].copy_from_slice(&0x1122334455667788u64.to_le_bytes());
    assert_eq!(
        unix_call(
            &mut process,
            21,
            [epoll, 1, event, 24, 0, 0],
            &mut memory,
            &mut sink
        ),
        0
    );
    assert_eq!(
        unix_call(
            &mut process,
            22,
            [epoll, 40, 1, 0, 0, 0],
            &mut memory,
            &mut sink
        ),
        1
    );
    assert_eq!(&memory.0[40..44], &1u32.to_le_bytes());
    assert_eq!(&memory.0[48..56], &0x1122334455667788u64.to_le_bytes());
    assert_eq!(
        ready(process_dispatch(
            &mut process,
            call(93, [9, 0, 0, 0, 0, 0]),
            &mut memory,
            &mut sink
        )),
        ControlFlow::Break(Exit::Thread(9))
    );
}

#[test]
fn a_stream_the_authority_does_not_reach_is_refused_with_eacces() {
    let mut process = new_process(1);
    let mut memory = Memory(vec![7; 16]);
    let mut sink = Sink {
        error: Some(WriteError::Denied),
        ..Sink::default()
    };
    assert_eq!(
        unix_call(&mut process, 1, [1, 0, 4, 0, 0, 0], &mut memory, &mut sink),
        13u64.wrapping_neg()
    );
    assert_eq!(
        unix_call(&mut process, 0, [0, 0, 4, 0, 0, 0], &mut memory, &mut sink),
        13u64.wrapping_neg()
    );
    assert!(sink.bytes.is_empty());
}

#[test]
fn an_image_at_an_unaligned_offset_parses() {
    // A boot payload stores files back to back, so a file's first byte
    // need not be aligned for the ELF header's fields.
    let mut storage = vec![0; 1];
    storage.extend_from_slice(&image());
    let parsed = parse(&storage[1..]).unwrap();
    assert_eq!(parsed.entry(), 0x400100);
}

#[test]
fn standard_input_reads_through_the_hosts_stream_until_its_end() {
    let mut process = new_process(1);
    let mut memory = Memory(vec![0; 64]);
    let mut sink = Sink {
        input: bytes::Bytes::from("한국어 日本語\n".as_bytes()),
        ..Sink::default()
    };
    assert_eq!(
        unix_call(&mut process, 0, [0, 0, 6, 0, 0, 0], &mut memory, &mut sink),
        6
    );
    assert_eq!(&memory.0[..6], "한국".as_bytes());
    assert_eq!(
        unix_call(&mut process, 0, [0, 8, 56, 0, 0, 0], &mut memory, &mut sink),
        14
    );
    assert_eq!(&memory.0[8..22], "어 日本語\n".as_bytes());
    assert_eq!(
        unix_call(&mut process, 0, [0, 0, 8, 0, 0, 0], &mut memory, &mut sink),
        0
    );
}

fn call(number: u64, arguments: [u64; 6]) -> Call {
    Call { number, arguments }
}

#[test]
fn thread_state_round_trips_and_exit_clears_registered_tid() {
    let mut process = new_process(73);
    let mut memory = Memory(vec![0xff; 64]);
    let mut sink = Sink::default();
    for number in [39, 186] {
        assert_eq!(
            ready(process_dispatch(
                &mut process,
                call(number, [0; 6]),
                &mut memory,
                &mut sink
            )),
            ControlFlow::Continue(73)
        );
    }
    assert_eq!(
        ready(process_dispatch(
            &mut process,
            call(158, [0x1002, 0x12345000, 0, 0, 0, 0]),
            &mut memory,
            &mut sink
        )),
        ControlFlow::Continue(0)
    );
    assert_eq!(
        sink.thread.load(std::sync::atomic::Ordering::Relaxed),
        0x12345000
    );
    assert_eq!(
        ready(process_dispatch(
            &mut process,
            call(158, [0x1003, 8, 0, 0, 0, 0]),
            &mut memory,
            &mut sink
        )),
        ControlFlow::Continue(0)
    );
    assert_eq!(&memory.0[8..16], &0x12345000u64.to_le_bytes());
    assert_eq!(
        ready(process_dispatch(
            &mut process,
            call(158, [0x1002, 1 << 47, 0, 0, 0, 0]),
            &mut memory,
            &mut sink
        )),
        ControlFlow::Continue(1u64.wrapping_neg())
    );
    assert_eq!(
        sink.thread.load(std::sync::atomic::Ordering::Relaxed),
        0x12345000
    );
    assert_eq!(
        ready(process_dispatch(
            &mut process,
            call(158, [0x1003, 60, 0, 0, 0, 0]),
            &mut memory,
            &mut sink
        )),
        ControlFlow::Continue(14u64.wrapping_neg())
    );
    assert_eq!(
        ready(process_dispatch(
            &mut process,
            call(218, [4, 0, 0, 0, 0, 0]),
            &mut memory,
            &mut sink
        )),
        ControlFlow::Continue(73)
    );
    assert_eq!(
        ready(process_dispatch(
            &mut process,
            call(60, [0; 6]),
            &mut memory,
            &mut sink
        )),
        ControlFlow::Break(Exit::Thread(0))
    );
    assert_eq!(&memory.0[4..8], &[0; 4]);
}

#[test]
fn vectored_output_validates_descriptors_and_preserves_partial_writes() {
    let mut memory = Memory(vec![0; 4096]);
    memory.0[0..8].copy_from_slice(&128u64.to_le_bytes());
    memory.0[8..16].copy_from_slice(&3u64.to_le_bytes());
    memory.0[16..24].copy_from_slice(&4094u64.to_le_bytes());
    memory.0[24..32].copy_from_slice(&8u64.to_le_bytes());
    memory.0[128..131].copy_from_slice(b"abc");
    memory.0[4094..].copy_from_slice(b"de");
    let mut sink = Sink::default();
    assert_eq!(
        ready(dispatch(call(20, [1, 0, 2, 0, 0, 0]), &memory, &mut sink)),
        ControlFlow::Continue(5)
    );
    assert_eq!(&sink.bytes, b"abcde");
    memory.0[24..32].copy_from_slice(&u64::MAX.to_le_bytes());
    sink.bytes.clear();
    assert_eq!(
        ready(dispatch(call(20, [1, 0, 2, 0, 0, 0]), &memory, &mut sink)),
        ControlFlow::Continue(22u64.wrapping_neg())
    );
    assert!(sink.bytes.is_empty());
    assert_eq!(
        ready(dispatch(
            call(20, [1, 4090, 1, 0, 0, 0]),
            &memory,
            &mut sink
        )),
        ControlFlow::Continue(14u64.wrapping_neg())
    );
    assert_eq!(
        ready(dispatch(
            call(20, [1, 0, 1025, 0, 0, 0]),
            &memory,
            &mut sink
        )),
        ControlFlow::Continue(22u64.wrapping_neg())
    );
    assert_eq!(
        ready(dispatch(
            call(16, [1, 0x5413, 0, 0, 0, 0]),
            &memory,
            &mut sink
        )),
        ControlFlow::Continue(25u64.wrapping_neg())
    );
    assert_eq!(
        ready(dispatch(
            call(16, [9, 0x5413, 0, 0, 0, 0]),
            &memory,
            &mut sink
        )),
        ControlFlow::Continue(9u64.wrapping_neg())
    );
}

#[test]
fn elf_exposes_mapped_headers_and_validates_tls_initialization_bytes() {
    let mut bytes = image();
    bytes[56..58].copy_from_slice(&2u16.to_le_bytes());
    // Second ELF64 program header describes a four-byte template plus TLS BSS.
    bytes[120..124].copy_from_slice(&7u32.to_le_bytes());
    bytes[124..128].copy_from_slice(&4u32.to_le_bytes());
    bytes[128..136].copy_from_slice(&512u64.to_le_bytes());
    bytes[136..144].copy_from_slice(&0x400200u64.to_le_bytes());
    bytes[152..160].copy_from_slice(&4u64.to_le_bytes());
    bytes[160..168].copy_from_slice(&8u64.to_le_bytes());
    bytes[168..176].copy_from_slice(&4u64.to_le_bytes());
    let parsed = parse(&bytes).unwrap();
    let headers = parsed.program_headers().unwrap();
    assert_eq!(headers.address, 0x400040);
    assert_eq!(headers.count, 2);
    bytes[160..168].copy_from_slice(&2u64.to_le_bytes());
    assert!(matches!(parse(&bytes), Err(Error::InvalidSegment)));
    bytes[160..168].copy_from_slice(&8u64.to_le_bytes());
    bytes[136..144].copy_from_slice(&0x900200u64.to_le_bytes());
    assert!(matches!(parse(&bytes), Err(Error::InvalidSegment)));
}

#[test]
fn anonymous_mmap_allocates_zeroed_memory_and_rejects_invalid_requests() {
    let mut process = new_process(1);
    let mut memory = Memory(vec![1; 4096]);
    let mut sink = Sink::default();
    let result = ready(process_dispatch(
        &mut process,
        call(9, [0, 17, 3, 0x22, u64::MAX, 0]),
        &mut memory,
        &mut sink,
    ));
    // Unfixed `mmap(0, ...)` starts at `CONFIG_DEFAULT_MMAP_MIN_ADDR` (64 KiB)
    // so low invalid user pointers never alias live mappings.
    assert_eq!(result, ControlFlow::Continue(65_536));
    assert_eq!(&memory.0[65_536..], &[0; 4096]);
    for (arguments, error) in [
        ([0, 0, 3, 0x22, u64::MAX, 0], 22u64),
        // MAP_FIXED below the lowest mappable address.
        ([0, 4096, 3, 0x32, u64::MAX, 0], 1),
        // MAP_HUGETLB (0x40000), which no mapping here supports.
        ([0, 4096, 3, 0x22 | 0x40000, u64::MAX, 0], 95),
        ([0, 4096, 3, 0x22, u64::MAX, 1], 22),
        ([0, u64::MAX, 3, 0x22, u64::MAX, 0], 12),
    ] {
        assert_eq!(
            ready(process_dispatch(
                &mut process,
                call(9, arguments),
                &mut memory,
                &mut sink
            )),
            ControlFlow::Continue(error.wrapping_neg())
        );
    }
}

impl helios_linux::syscall::Clock for Sink {
    fn now_nanos(&self) -> u64 {
        self.time.load(core::sync::atomic::Ordering::Relaxed)
    }
    async fn sleep_until(&self, deadline: u64) {
        self.time
            .store(deadline, core::sync::atomic::Ordering::Relaxed);
    }
}

fn unix_call(
    process: &mut Process<NoBacking>,
    number: u64,
    arguments: [u64; 6],
    memory: &mut Memory,
    sink: &mut Sink,
) -> u64 {
    match ready(process_dispatch(
        process,
        Call { number, arguments },
        memory,
        sink,
    )) {
        ControlFlow::Continue(result) => result,
        ControlFlow::Break(_) => panic!("I/O syscall terminated the process"),
    }
}

#[test]
fn eventfd_epoll_uses_linux_layout_and_a_shared_counter_after_dup() {
    let mut process = new_process(1);
    let mut memory = Memory(vec![0; 256]);
    let mut sink = Sink::default();
    let event = unix_call(
        &mut process,
        290,
        [0, 0x800, 0, 0, 0, 0],
        &mut memory,
        &mut sink,
    );
    let epoll = unix_call(
        &mut process,
        291,
        [0, 0, 0, 0, 0, 0],
        &mut memory,
        &mut sink,
    );
    memory.0[16..20].copy_from_slice(&1u32.to_le_bytes());
    memory.0[20..28].copy_from_slice(&0x1122334455667788u64.to_le_bytes());
    assert_eq!(
        unix_call(
            &mut process,
            233,
            [epoll, 1, event, 16, 0, 0],
            &mut memory,
            &mut sink
        ),
        0
    );
    assert_eq!(
        unix_call(
            &mut process,
            232,
            [epoll, 64, 4, 0, 0, 0],
            &mut memory,
            &mut sink
        ),
        0
    );
    let dup = unix_call(
        &mut process,
        32,
        [event, 0, 0, 0, 0, 0],
        &mut memory,
        &mut sink,
    );
    memory.0[0..8].copy_from_slice(&7u64.to_le_bytes());
    assert_eq!(
        unix_call(
            &mut process,
            1,
            [dup, 0, 8, 0, 0, 0],
            &mut memory,
            &mut sink
        ),
        8
    );
    assert_eq!(
        unix_call(
            &mut process,
            232,
            [epoll, 64, 4, 0, 0, 0],
            &mut memory,
            &mut sink
        ),
        1
    );
    assert_eq!(&memory.0[64..76], &memory.0[16..28]);
    assert_eq!(
        unix_call(
            &mut process,
            0,
            [event, 32, 8, 0, 0, 0],
            &mut memory,
            &mut sink
        ),
        8
    );
    assert_eq!(u64::from_le_bytes(memory.0[32..40].try_into().unwrap()), 7);
    assert_eq!(
        unix_call(
            &mut process,
            0,
            [dup, 32, 8, 0, 0, 0],
            &mut memory,
            &mut sink
        ),
        (-11i64) as u64
    );
    assert_eq!(
        unix_call(
            &mut process,
            233,
            [epoll, 2, event, u64::MAX, 0, 0],
            &mut memory,
            &mut sink
        ),
        0
    );
}

#[test]
fn epoll_errors_timeout_and_pipe_readiness_are_real() {
    let mut process = new_process(1);
    let mut memory = Memory(vec![0; 256]);
    let mut sink = Sink::default();
    assert_eq!(
        unix_call(
            &mut process,
            293,
            [0, 0x800, 0, 0, 0, 0],
            &mut memory,
            &mut sink
        ),
        0
    );
    let reader = u32::from_le_bytes(memory.0[..4].try_into().unwrap()) as u64;
    let writer = u32::from_le_bytes(memory.0[4..8].try_into().unwrap()) as u64;
    let epoll = unix_call(
        &mut process,
        291,
        [0, 0, 0, 0, 0, 0],
        &mut memory,
        &mut sink,
    );
    memory.0[16..20].copy_from_slice(&1u32.to_le_bytes());
    memory.0[20..28].copy_from_slice(&99u64.to_le_bytes());
    assert_eq!(
        unix_call(
            &mut process,
            233,
            [epoll, 1, reader, 16, 0, 0],
            &mut memory,
            &mut sink
        ),
        0
    );
    assert_eq!(
        unix_call(
            &mut process,
            233,
            [epoll, 1, reader, 16, 0, 0],
            &mut memory,
            &mut sink
        ),
        (-17i64) as u64
    );
    assert_eq!(
        unix_call(
            &mut process,
            232,
            [epoll, 64, 4, 7, 0, 0],
            &mut memory,
            &mut sink
        ),
        0
    );
    assert_eq!(helios_linux::syscall::Clock::now_nanos(&sink), 7_000_000);
    memory.0[32..38].copy_from_slice(b"abcdef");
    assert_eq!(
        unix_call(
            &mut process,
            1,
            [writer, 32, 6, 0, 0, 0],
            &mut memory,
            &mut sink
        ),
        6
    );
    assert_eq!(
        unix_call(
            &mut process,
            232,
            [epoll, 64, 4, 0, 0, 0],
            &mut memory,
            &mut sink
        ),
        1
    );
    assert_eq!(
        unix_call(
            &mut process,
            0,
            [reader, 40, 3, 0, 0, 0],
            &mut memory,
            &mut sink
        ),
        3
    );
    assert_eq!(
        unix_call(
            &mut process,
            0,
            [reader, 43, 3, 0, 0, 0],
            &mut memory,
            &mut sink
        ),
        3
    );
    assert_eq!(&memory.0[40..46], b"abcdef");
    assert_eq!(
        unix_call(
            &mut process,
            0,
            [reader, 40, 3, 0, 0, 0],
            &mut memory,
            &mut sink
        ),
        (-11i64) as u64
    );
    assert_eq!(
        unix_call(
            &mut process,
            3,
            [writer, 0, 0, 0, 0, 0],
            &mut memory,
            &mut sink
        ),
        0
    );
    assert_eq!(
        unix_call(
            &mut process,
            0,
            [reader, 40, 3, 0, 0, 0],
            &mut memory,
            &mut sink
        ),
        0
    );
}

#[test]
fn epoll_rejects_cycles_and_duplicate_self_registration() {
    let mut process = new_process(1);
    let mut memory = Memory(vec![0; 64]);
    let mut sink = Sink::default();
    let first = unix_call(&mut process, 291, [0; 6], &mut memory, &mut sink);
    let second = unix_call(&mut process, 291, [0; 6], &mut memory, &mut sink);
    memory.0[..4].copy_from_slice(&(1u32 | (1 << 30)).to_le_bytes());
    assert_eq!(
        unix_call(
            &mut process,
            233,
            [first, 1, second, 0, 0, 0],
            &mut memory,
            &mut sink
        ),
        0
    );
    assert_eq!(
        unix_call(
            &mut process,
            233,
            [second, 1, first, 0, 0, 0],
            &mut memory,
            &mut sink
        ),
        (-40i64) as u64
    );
    let duplicate = unix_call(
        &mut process,
        32,
        [first, 0, 0, 0, 0, 0],
        &mut memory,
        &mut sink,
    );
    assert_eq!(
        unix_call(
            &mut process,
            233,
            [first, 1, duplicate, 0, 0, 0],
            &mut memory,
            &mut sink
        ),
        (-22i64) as u64
    );
}

#[test]
fn invalid_pipe_destination_does_not_consume_data_and_dup_shares_nonblocking() {
    let mut process = new_process(1);
    let mut memory = Memory(vec![0; 64]);
    let mut sink = Sink::default();
    assert_eq!(
        unix_call(&mut process, 293, [0; 6], &mut memory, &mut sink),
        0
    );
    let reader = u32::from_le_bytes(memory.0[..4].try_into().unwrap()) as u64;
    let writer = u32::from_le_bytes(memory.0[4..8].try_into().unwrap()) as u64;
    let duplicate = unix_call(
        &mut process,
        32,
        [reader, 0, 0, 0, 0, 0],
        &mut memory,
        &mut sink,
    );
    assert_eq!(
        unix_call(
            &mut process,
            72,
            [duplicate, 4, 0x800, 0, 0, 0],
            &mut memory,
            &mut sink
        ),
        0
    );
    assert_eq!(
        unix_call(
            &mut process,
            72,
            [reader, 3, 0, 0, 0, 0],
            &mut memory,
            &mut sink
        ) & 0x800,
        0x800
    );
    memory.0[16..19].copy_from_slice(b"abc");
    assert_eq!(
        unix_call(
            &mut process,
            1,
            [writer, 16, 3, 0, 0, 0],
            &mut memory,
            &mut sink
        ),
        3
    );
    assert_eq!(
        unix_call(
            &mut process,
            0,
            [reader, u64::MAX, 3, 0, 0, 0],
            &mut memory,
            &mut sink
        ),
        (-14i64) as u64
    );
    assert_eq!(
        unix_call(
            &mut process,
            0,
            [duplicate, 32, 3, 0, 0, 0],
            &mut memory,
            &mut sink
        ),
        3
    );
    assert_eq!(&memory.0[32..35], b"abc");
}

fn build_elf_image(
    abi: Abi,
    e_type: u16,
    base_vaddr: u64,
    interp: Option<&[u8]>,
    with_dynamic: bool,
    with_tbss_tls: bool,
) -> Vec<u8> {
    // 3 pages of file content:
    // - page 0 (0x0000..0x1000): ELF header, phdrs, optional PT_INTERP string
    // - page 1 (0x1000..0x2000): executable text segment (entry at +0x1040)
    // - page 2 (0x2000..0x3000): data file backing for a mid-page PT_LOAD at
    //   p_vaddr = base_vaddr + 0x2dc0, p_offset = 0x1dc0 (matching page offset).
    let mut bytes = vec![0u8; 3 * 4096];
    // Tag page 1 leading bytes before 0x1dc0 and data bytes at 0x1dc0..0x20c0
    // so mid-page elf_map leading bytes and segment bytes are observable.
    bytes[0x1000..0x1008].copy_from_slice(b"CODEHEAD");
    bytes[0x1040..0x1044].copy_from_slice(&[0x90, 0x90, 0x90, 0xc3]);
    bytes[0x1d00..0x1d08].copy_from_slice(b"PRELOAD!");
    bytes[0x1dc0..0x1dc8].copy_from_slice(b"DATAINIT");

    let mut phdrs: Vec<[u8; 56]> = Vec::new();
    let push_phdr = |phdrs: &mut Vec<[u8; 56]>,
                     p_type: u32,
                     p_flags: u32,
                     p_offset: u64,
                     p_vaddr: u64,
                     p_filesz: u64,
                     p_memsz: u64,
                     p_align: u64| {
        let mut h = [0u8; 56];
        h[0..4].copy_from_slice(&p_type.to_le_bytes());
        h[4..8].copy_from_slice(&p_flags.to_le_bytes());
        h[8..16].copy_from_slice(&p_offset.to_le_bytes());
        h[16..24].copy_from_slice(&p_vaddr.to_le_bytes());
        h[24..32].copy_from_slice(&p_vaddr.to_le_bytes());
        h[32..40].copy_from_slice(&p_filesz.to_le_bytes());
        h[40..48].copy_from_slice(&p_memsz.to_le_bytes());
        h[48..56].copy_from_slice(&p_align.to_le_bytes());
        phdrs.push(h);
    };

    if let Some(path) = interp {
        let off = 0x300u64;
        bytes[off as usize..off as usize + path.len()].copy_from_slice(path);
        push_phdr(
            &mut phdrs,
            3, /* PT_INTERP */
            4,
            off,
            base_vaddr + off,
            path.len() as u64,
            path.len() as u64,
            1,
        );
    }
    // PT_LOAD 0: RO headers + interp string
    push_phdr(
        &mut phdrs, 1, /* PT_LOAD */
        4, /* PF_R */
        0, base_vaddr, 0x600, 0x600, 4096,
    );
    // PT_LOAD 1: RX code
    push_phdr(
        &mut phdrs,
        1, /* PT_LOAD */
        5, /* PF_R | PF_X */
        0x1000,
        base_vaddr + 0x1000,
        0x400,
        0x400,
        4096,
    );
    // PT_LOAD 2: RW mid-page data + BSS tail spanning into next page
    push_phdr(
        &mut phdrs,
        1, /* PT_LOAD */
        6, /* PF_R | PF_W */
        0x1dc0,
        base_vaddr + 0x2dc0,
        0x300,
        0x1500,
        4096,
    );
    if with_dynamic {
        push_phdr(
            &mut phdrs,
            2, /* PT_DYNAMIC */
            6,
            0x1dc0,
            base_vaddr + 0x2dc0,
            0x80,
            0x80,
            8,
        );
    }
    if with_tbss_tls {
        // .tbss-only PT_TLS (p_filesz == 0, p_memsz == 64, p_align == 64)
        push_phdr(
            &mut phdrs,
            7, /* PT_TLS */
            4,
            0x20c0,
            base_vaddr + 0x30c0,
            0,
            64,
            64,
        );
    }

    bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    bytes[16..18].copy_from_slice(&e_type.to_le_bytes());
    bytes[18..20].copy_from_slice(&abi.elf_machine().to_le_bytes());
    bytes[20..24].copy_from_slice(&1_u32.to_le_bytes());
    bytes[24..32].copy_from_slice(&(base_vaddr + 0x1040).to_le_bytes());
    bytes[32..40].copy_from_slice(&64_u64.to_le_bytes());
    bytes[52..54].copy_from_slice(&64_u16.to_le_bytes());
    bytes[54..56].copy_from_slice(&56_u16.to_le_bytes());
    bytes[56..58].copy_from_slice(&(phdrs.len() as u16).to_le_bytes());
    for (i, h) in phdrs.iter().enumerate() {
        let start = 64 + i * 56;
        bytes[start..start + 56].copy_from_slice(h);
    }
    bytes
}

#[test]
fn et_dyn_pie_and_pt_interp_placement_and_auxv_for_x86_64_and_aarch64() {
    use helios_linux::elf::{ImageKind, plan_placement};

    for (abi, interp_str) in [
        (Abi::X86_64, "/lib/ld-musl-x86_64.so.1"),
        (Abi::Aarch64, "/lib/ld-musl-aarch64.so.1"),
    ] {
        let user_end = abi.task_size();
        let stack_top = user_end - 8192;

        // 1. Static PIE (ET_DYN with PT_DYNAMIC + .tbss-only PT_TLS, no PT_INTERP).
        let static_pie_bytes = build_elf_image(abi, 3 /* ET_DYN */, 0, None, true, true);
        let static_pie = Image::parse(&static_pie_bytes, abi, user_end).unwrap();
        assert_eq!(static_pie.kind(), ImageKind::Dynamic);
        assert!(static_pie.is_dynamic());
        assert_eq!(static_pie.interpreter(), None);

        let static_place = plan_placement(&static_pie, None, 4096, stack_top, 4096).unwrap();
        assert!(static_place.main_bias >= 65_536);
        assert_eq!(static_place.main_bias % 4096, 0);
        assert_eq!(static_place.interpreter_bias, None);
        assert_eq!(static_place.at_base, 0);
        assert_eq!(static_place.main_entry, static_place.main_bias + 0x1040);
        assert_eq!(static_place.initial_pc, static_place.main_entry);
        assert_eq!(
            static_place.program_headers.address,
            static_place.main_bias + 64
        );
        assert_eq!(static_place.program_headers.count, 5);
        assert_eq!(
            static_place.program_break,
            (static_place.main_bias + 0x2dc0 + 0x1500).next_multiple_of(4096)
        );
        // Verify mid-page PT_LOAD includes leading page bytes from ELF_PAGESTART(p_offset).
        let data_seg = static_pie
            .segments_at(static_place.main_bias)
            .nth(2)
            .unwrap();
        assert_eq!(data_seg.address, static_place.main_bias + 0x2000);
        assert_eq!(data_seg.memory_size, 0xdc0 + 0x1500);
        assert_eq!(&data_seg.bytes[0xd00..0xd08], b"PRELOAD!");
        assert_eq!(&data_seg.bytes[0xdc0..0xdc8], b"DATAINIT");

        // 2. Dynamic PIE (ET_DYN + PT_INTERP) paired with ET_DYN interpreter.
        let mut interp_cstr = interp_str.as_bytes().to_vec();
        interp_cstr.push(0);
        let dyn_pie_bytes =
            build_elf_image(abi, 3 /* ET_DYN */, 0, Some(&interp_cstr), true, true);
        let interp_bytes = build_elf_image(abi, 3 /* ET_DYN */, 0, None, true, false);
        let dyn_pie = Image::parse(&dyn_pie_bytes, abi, user_end).unwrap();
        let interp = Image::parse_interpreter(&interp_bytes, abi, user_end).unwrap();
        assert_eq!(dyn_pie.interpreter(), Some(interp_str));

        let dyn_place = plan_placement(&dyn_pie, Some(&interp), 4096, stack_top, 4096).unwrap();
        let interp_bias = dyn_place.interpreter_bias.expect("interpreter placed");
        assert!(dyn_place.main_bias >= 65_536);
        assert_eq!(dyn_place.at_base, interp_bias);
        assert_ne!(dyn_place.at_base, 0);
        assert_eq!(dyn_place.main_entry, dyn_place.main_bias + 0x1040);
        assert_eq!(dyn_place.initial_pc, interp_bias + 0x1040);
        assert_ne!(dyn_place.initial_pc, dyn_place.main_entry);
        // Main and interpreter segments must be strictly non-overlapping.
        for m in dyn_pie.segments_at(dyn_place.main_bias) {
            let m_start = m.address & !4095;
            let m_end = (m.address + m.memory_size).next_multiple_of(4096);
            for i in interp.segments_at(interp_bias) {
                let i_start = i.address & !4095;
                let i_end = (i.address + i.memory_size).next_multiple_of(4096);
                assert!(
                    m_end <= i_start || i_end <= m_start,
                    "main [{m_start:#x}, {m_end:#x}) overlaps interp [{i_start:#x}, {i_end:#x})"
                );
            }
        }
        // program_break is strictly at main's end, leaving room for brk below interp.
        assert!(dyn_place.program_break < interp_bias);
        assert!(dyn_place.image_end < stack_top);

        // Build initial stack and verify every required auxv entry.
        let execfn = "/usr/bin/dyn-中文-日本語-한국어".as_bytes();
        let args: [&[u8]; 2] = [execfn, b"--check"];
        let env: [&[u8]; 1] = [b"LD_DEBUG=1"];
        let stack = helios_linux::stack::build(
            &helios_linux::stack::Startup {
                entry: dyn_place.main_entry,
                page_size: 4096,
                headers: dyn_place.program_headers,
                interpreter_base: dyn_place.at_base,
                flags: 0,
                random: [0x5a; 16],
                arguments: &args,
                environment: &env,
                executable: execfn,
                uid: 1000,
                euid: 1000,
                gid: 1000,
                egid: 1000,
                secure: false,
            },
            stack_top,
        )
        .unwrap();
        assert!(stack.base > dyn_place.image_end);
        let at = |addr: u64| (addr - stack.base) as usize;
        let read_u64 = |addr: u64| {
            let o = at(addr);
            u64::from_le_bytes(stack.bytes[o..o + 8].try_into().unwrap())
        };
        let mut cursor = stack.pointer;
        let argc = read_u64(cursor);
        assert_eq!(argc, 2);
        cursor += 8 + (argc + 1) * 8;
        while read_u64(cursor) != 0 {
            cursor += 8;
        }
        cursor += 8;
        let mut auxv = std::collections::BTreeMap::new();
        loop {
            let tag = read_u64(cursor);
            let val = read_u64(cursor + 8);
            cursor += 16;
            if tag == 0 {
                break;
            }
            auxv.insert(tag, val);
        }
        assert_eq!(auxv.get(&3), Some(&dyn_place.program_headers.address)); // AT_PHDR
        assert_eq!(auxv.get(&4), Some(&56)); // AT_PHENT
        assert_eq!(auxv.get(&5), Some(&dyn_place.program_headers.count)); // AT_PHNUM
        assert_eq!(auxv.get(&6), Some(&4096)); // AT_PAGESZ
        assert_eq!(auxv.get(&7), Some(&dyn_place.at_base)); // AT_BASE
        assert_eq!(auxv.get(&8), Some(&0)); // AT_FLAGS
        assert_eq!(auxv.get(&9), Some(&dyn_place.main_entry)); // AT_ENTRY
        let execfn_ptr = *auxv.get(&31).expect("AT_EXECFN");
        let start = at(execfn_ptr);
        let end = start + stack.bytes[start..].iter().position(|&b| b == 0).unwrap();
        assert_eq!(&stack.bytes[start..end], execfn);

        // 3. Dynamic non-PIE (ET_EXEC + PT_INTERP) paired with ET_DYN interpreter.
        let dyn_exec_bytes = build_elf_image(
            abi,
            2, /* ET_EXEC */
            0x40_0000,
            Some(&interp_cstr),
            true,
            false,
        );
        let dyn_exec = Image::parse(&dyn_exec_bytes, abi, user_end).unwrap();
        assert_eq!(dyn_exec.kind(), ImageKind::Executable);
        let exec_place = plan_placement(&dyn_exec, Some(&interp), 4096, stack_top, 4096).unwrap();
        assert_eq!(exec_place.main_bias, 0);
        assert_eq!(exec_place.main_entry, 0x40_1040);
        assert_ne!(exec_place.at_base, 0);
        assert_eq!(
            exec_place.initial_pc,
            exec_place.interpreter_bias.unwrap() + 0x1040
        );
        assert_eq!(
            exec_place.program_break,
            (0x40_2dc0u64 + 0x1500).next_multiple_of(4096)
        );
        assert!(exec_place.program_break < exec_place.interpreter_bias.unwrap());
    }
}

#[test]
fn pt_interp_validation_refuses_malformed_duplicate_and_recursive_interpreters() {
    // Missing trailing NUL in PT_INTERP -> InvalidInterpreter.
    let no_nul = build_elf_image(Abi::X86_64, 3, 0, Some(b"/lib/ld.so"), true, false);
    assert!(matches!(
        Image::parse(&no_nul, Abi::X86_64, USER_END),
        Err(Error::InvalidInterpreter)
    ));

    // Empty interpreter string ("\0") -> InvalidInterpreter.
    let empty_interp = build_elf_image(Abi::X86_64, 3, 0, Some(b"\0"), true, false);
    assert!(matches!(
        Image::parse(&empty_interp, Abi::X86_64, USER_END),
        Err(Error::InvalidInterpreter)
    ));

    // Recursive PT_INTERP inside an interpreter image -> InvalidInterpreter.
    let interp_with_interp = build_elf_image(Abi::X86_64, 3, 0, Some(b"/lib/ld.so\0"), true, false);
    assert!(matches!(
        Image::parse_interpreter(&interp_with_interp, Abi::X86_64, USER_END),
        Err(Error::InvalidInterpreter)
    ));

    // Cross-architecture refusal.
    let arm_pie = build_elf_image(Abi::Aarch64, 3, 0, None, true, false);
    assert!(matches!(
        Image::parse(&arm_pie, Abi::X86_64, USER_END),
        Err(Error::UnsupportedImage)
    ));
}
