//! Optional boot-time integration test of the native Linux subsystem.

use alloc::vec;
use core::ops::ControlFlow;
use helios_kernel::{BootPayload, DebugSerialWriter, Spawner, yield_now};
use helios_linux::elf::Image;
use helios_linux::syscall::{self, Call, MemoryFault, Output, Stream, UserMemory, WriteError};
use helios_x86::native::{AddressSpace, Context, Stop};
use helios_x86::{BootHook, X86Cpu};

pub struct Prototype;
impl BootHook for Prototype {
    fn start(_: X86Cpu, spawner: Spawner<X86Cpu>, payload: BootPayload) {
        spawner.spawn_detached(async move {
            run(payload, "linux-prototype/hello", Expected::Exit).await;
            run(payload, "linux-prototype/fault", Expected::Fault).await;
            run(payload, "linux-prototype/spin", Expected::Preempt).await;
            tracing::info!(
                "native Linux prototype passed: write exit ENOSYS EBADF EFAULT isolation preemption"
            );
        });
    }
}

enum Expected {
    Exit,
    Fault,
    Preempt,
}
struct Memory(AddressSpace);
impl UserMemory for Memory {
    fn read(&self, address: u64, output: &mut [u8]) -> Result<(), MemoryFault> {
        self.0.read(address, output).map_err(|_| MemoryFault)
    }
}
struct Console {
    writer: DebugSerialWriter,
    written: usize,
}
impl Output for Console {
    async fn write(&mut self, _: Stream, bytes: &[u8]) -> Result<usize, WriteError> {
        loop {
            let ready = self.writer.wait_for_debug_serial_output_ready();
            let written = self.writer.write_stream(bytes);
            if written != 0 || bytes.is_empty() {
                self.written += written;
                return Ok(written);
            }
            ready.await;
        }
    }
}

async fn run(payload: BootPayload, path: &str, expected: Expected) {
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
                segment.writable,
                segment.executable,
            )
            .unwrap_or_else(|error| panic!("{path}: map: {error}"));
    }
    // Test layout: a four-page stack below the canonical user boundary, with
    // unmapped guards. These fixtures use no libc or recursive stack frames.
    let stack_base = 0x7fff_ff00_0000;
    let mut stack = vec![0; 4 * 4096];
    let stack_pointer = helios_linux::stack::initialize(
        &mut stack,
        stack_base,
        path.as_bytes(),
        image.entry(),
        4096,
    )
    .expect("Linux initial stack");
    memory
        .0
        .map(stack_base, stack.len() as u64, &stack, true, false)
        .expect("map user stack");
    let mut context = Context::new(image.entry(), stack_pointer).expect("native context");
    let mut console = Console {
        writer: helios_x86::debug_serial_writer(),
        written: 0,
    };
    loop {
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
                match syscall::dispatch(call, &memory, &mut console).await {
                    ControlFlow::Continue(result) => context.return_value(result),
                    ControlFlow::Break(status) => {
                        assert!(
                            matches!(expected, Expected::Exit),
                            "{path}: unexpected exit"
                        );
                        assert_eq!(status, 0, "{path}: syscall fixture failed");
                        assert_eq!(console.written, b"native Linux syscall: ok\n".len());
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
