//! Optional boot-time integration test of the native Linux subsystem.

use alloc::vec;
use core::num::NonZeroU32;
use core::ops::ControlFlow;
use helios_kernel::{BootPayload, DebugSerialWriter, Spawner, yield_now};
use helios_linux::elf::Image;
use helios_linux::syscall::{self, Call, MemoryFault, Output, Stream, UserMemory, WriteError};
use helios_x86::native::{AddressSpace, Context, Stop};
use helios_x86::{BootHook, X86Cpu};

pub struct Prototype;
impl BootHook for Prototype {
    fn start(
        _: X86Cpu,
        spawner: Spawner<X86Cpu>,
        payload: BootPayload,
        entropy: helios_kernel::RootEntropyHandle,
    ) {
        spawner.spawn_detached(async move {
            for (index, (path, expected)) in [
                ("linux-prototype/hello", Expected::Exit(b"native Linux syscall: ok\n")),
                ("linux-prototype/hello-libc", Expected::Exit(b"Hello, World!\n")),
                ("linux-prototype/fault", Expected::Fault),
                ("linux-prototype/spin", Expected::Preempt),
            ].into_iter().enumerate() {
                run(payload, path, expected, NonZeroU32::new(index as u32 + 1).unwrap(), &entropy).await;
            }
            tracing::info!(
                "native Linux prototype passed: write exit ENOSYS EBADF EFAULT isolation preemption libc TLS writev"
            );
        });
    }
}

#[derive(Clone, Copy)]
enum Expected {
    Exit(&'static [u8]),
    Fault,
    Preempt,
}
struct Memory(AddressSpace);
impl UserMemory for Memory {
    fn write(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryFault> {
        self.0.write(address, bytes).map_err(|_| MemoryFault)
    }
    fn read(&self, address: u64, output: &mut [u8]) -> Result<(), MemoryFault> {
        self.0.read(address, output).map_err(|_| MemoryFault)
    }
}
impl syscall::VirtualMemory for Memory {
    fn map_anonymous(
        &mut self,
        hint: u64,
        length: u64,
        readable: bool,
        writable: bool,
        executable: bool,
    ) -> Result<u64, syscall::MapError> {
        self.0
            .map_anonymous(hint, length, readable, writable, executable)
            .map_err(|error| match error {
                helios_x86::native::Error::OutOfMemory => syscall::MapError::OutOfMemory,
                helios_x86::native::Error::Address | helios_x86::native::Error::Mapping => {
                    syscall::MapError::Invalid
                }
            })
    }
}
struct Console {
    writer: DebugSerialWriter,
    written: usize,
    expected: &'static [u8],
}
impl Output for Console {
    async fn write(&mut self, _: Stream, bytes: &[u8]) -> Result<usize, WriteError> {
        loop {
            let ready = self.writer.wait_for_debug_serial_output_ready();
            let written = self.writer.write_stream(bytes);
            if written != 0 || bytes.is_empty() {
                assert_eq!(
                    &bytes[..written],
                    &self.expected[self.written..self.written + written],
                    "Linux output differs"
                );
                self.written += written;
                return Ok(written);
            }
            ready.await;
        }
    }
}

async fn run(
    payload: BootPayload,
    path: &str,
    expected: Expected,
    id: NonZeroU32,
    entropy: &helios_kernel::RootEntropy,
) {
    let bytes = payload
        .bootfs()
        .files()
        .iter()
        .find(|file| file.path() == path)
        .unwrap_or_else(|| panic!("native prototype bootfs lacks {path}"))
        .contents();
    let image = Image::parse(bytes).unwrap_or_else(|error| panic!("{path}: {error}"));
    let mut memory = Memory(AddressSpace::new());
    for segment in image.segments() {
        memory
            .0
            .map(
                segment.address,
                segment.memory_size,
                segment.bytes,
                true,
                segment.writable,
                segment.executable,
            )
            .unwrap_or_else(|error| panic!("{path}: map: {error}"));
    }
    // Test layout: a four-page stack below the canonical user boundary, with
    // unmapped guards. These fixtures use no libc or recursive stack frames.
    let stack_base = 0x7fff_ff00_0000;
    let mut stack = vec![0; 4 * 4096];
    let mut random = [0; 16];
    entropy.fill(&mut random);
    let startup = helios_linux::stack::Startup {
        entry: image.entry(),
        page_size: 4096,
        headers: image.program_headers().expect("mapped ELF program headers"),
        random,
    };
    let stack_pointer =
        helios_linux::stack::initialize(&mut stack, stack_base, path.as_bytes(), &startup)
            .expect("Linux initial stack");
    memory
        .0
        .map(stack_base, stack.len() as u64, &stack, true, true, false)
        .expect("map user stack");
    let mut context = Context::new(image.entry(), stack_pointer).expect("native context");
    let mut console = Console {
        writer: helios_x86::debug_serial_writer(),
        written: 0,
        expected: match expected {
            Expected::Exit(bytes) => bytes,
            _ => &[],
        },
    };
    let mut process = syscall::Process::new(id);
    loop {
        context
            .set_thread_pointer(process.fs_base())
            .expect("validated user FS base");
        match context.resume(&mut memory.0) {
            Stop::SystemCall => {
                let registers = context.registers();
                let call = Call {
                    number: registers.rax,
                    arguments: [
                        registers.rdi,
                        registers.rsi,
                        registers.rdx,
                        registers.r10,
                        registers.r8,
                        registers.r9,
                    ],
                };
                match syscall::dispatch(&mut process, call, &mut memory, &mut console).await {
                    ControlFlow::Continue(result) => context.return_value(result),
                    ControlFlow::Break(status) => {
                        assert!(
                            matches!(expected, Expected::Exit(_)),
                            "{path}: unexpected exit"
                        );
                        assert_eq!(status, 0, "{path}: syscall fixture failed");
                        assert_eq!(console.written, console.expected.len());
                        tracing::info!(path, status, "native Linux process exited");
                        break;
                    }
                }
            }
            Stop::Preempted if matches!(expected, Expected::Preempt) => {
                tracing::info!(path, "native CPU loop preempted");
                break;
            }
            Stop::Interrupted | Stop::Preempted => {}
            Stop::Fault {
                vector,
                error,
                instruction,
            } => {
                assert!(
                    matches!(expected, Expected::Fault),
                    "{path}: vector={vector} error={error:#x} rip={instruction:#x}"
                );
                assert_eq!(vector, 14, "expected isolated user page fault");
                assert_ne!(error & 4, 0, "page fault must originate in user mode");
                assert_ne!(
                    error & 1,
                    0,
                    "kernel mapping must be present but inaccessible"
                );
                tracing::info!(path, vector, "native user fault isolated");
                break;
            }
        }
        yield_now().await;
    }
}
