//! ARM64 Linux VMM. vCPU tasks own their execution calls. A single device
//! task serializes emulated device state and file I/O; all waits are async.
use crate::memory::GuestMemory;
mod boot;
mod file;
mod gic;
mod memory;
mod virtio;

use async_channel::{Receiver, Sender};
use clap::Parser;
use helios_api::{
    bindings::wasi::filesystem::types::ErrorCode,
    hv::{self, IoAccess, RegisterId, RegisterValue, Vcpu, Vm, VmExit},
};
use memory::Memory;
use std::{collections::VecDeque, rc::Rc};
use thiserror::Error;

#[derive(Debug, Error)]
enum Error {
    #[error("virtualization: {0}")]
    Hv(#[from] hv::HvError),
    #[error("filesystem: {0}")]
    Fs(#[from] ErrorCode),
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("device tree: {0}")]
    Fdt(#[from] vm_fdt::Error),
    #[error("root filesystem preopen missing")]
    Root,
    #[error("guest memory range {0:#x}+{1:#x} outside RAM")]
    Memory(u64, u64),
    #[error("invalid file transfer {0:#x}+{1:#x}")]
    FileRange(u64, usize),
    #[error("unexpected file EOF")]
    ShortRead,
    #[error("file output stream closed early")]
    ShortWrite,
    #[error("invalid Linux image: {0}")]
    Image(&'static str),
    #[error("virtio: {0}")]
    Queue(&'static str),
    #[error("GICv3: {0}")]
    Gic(&'static str),
    #[error("unexpected vCPU {0} exit: {1:?}")]
    Exit(u32, VmExit),
    #[error("unsupported device address {0:#x}")]
    Device(u64),
    #[error("unsupported system register {0:#x}")]
    Register(u32),
    #[error("configuration: {0}")]
    Config(&'static str),
    #[error("vCPU event channel closed")]
    Channel,
}
type Result<T> = std::result::Result<T, Error>;

#[derive(Parser)]
#[command(about = "Boot an ARM64 Linux virtual machine through helios:hv")]
struct Config {
    #[arg(long)]
    kernel: String,
    #[arg(long)]
    initramfs: String,
    #[arg(long)]
    disk: Option<String>,
    #[arg(long, default_value_t = 128)]
    memory_mib: u64,
    #[arg(long, default_value_t = 1)]
    cpus: u32,
    #[arg(
        long,
        default_value = "console=hvc0 earlycon=pl011,0x9000000 rdinit=/init panic=-1"
    )]
    cmdline: String,
}

enum Action {
    Run,
    Start { entry: u64, context: u64 },
    Park,
    Stop,
}
enum Event {
    Exit { cpu: u32, exit: VmExit },
    Failed(Error),
    Input(Vec<u8>),
}

fn registers(entry: u64, context: u64) -> [RegisterValue; 5] {
    [
        RegisterValue {
            id: RegisterId::Aarch64Pc,
            value: entry,
        },
        RegisterValue {
            id: RegisterId::Aarch64Pstate,
            value: 0x3c5,
        },
        RegisterValue {
            id: RegisterId::Aarch64X(0),
            value: context,
        },
        RegisterValue {
            id: RegisterId::Aarch64X(1),
            value: 0,
        },
        RegisterValue {
            id: RegisterId::Aarch64X(2),
            value: 0,
        },
    ]
}

async fn run_cpu(
    id: u32,
    vcpu: Rc<Vcpu>,
    commands: Receiver<Action>,
    events: Sender<Event>,
) -> Result<()> {
    let mut running = false;
    loop {
        match commands.recv().await.map_err(|_| Error::Channel)? {
            Action::Start { entry, context } => {
                vcpu.reset()?;
                vcpu.set_regs(&registers(entry, context))?;
                running = true;
            }
            Action::Run if running => {}
            Action::Park => {
                running = false;
                continue;
            }
            Action::Stop => return Ok(()),
            Action::Run => return Err(Error::Config("running an offline CPU")),
        }
        let exit = vcpu.run().await?;
        events
            .send(Event::Exit { cpu: id, exit })
            .await
            .map_err(|_| Error::Channel)?;
    }
}

#[helios_api::main]
async fn main() -> Result<()> {
    let config = Config::parse();
    // VMPIDR and the DTB currently describe one cluster with 8-bit Aff0.
    if config.cpus == 0 || config.cpus > 256 {
        return Err(Error::Config(
            "cpus must fit the ARM Aff0 topology (1..256)",
        ));
    }
    let size = config
        .memory_mib
        .checked_mul(1024 * 1024)
        .ok_or(Error::Config("memory size overflow"))?;
    let vm = Vm::create(size)?;
    let memory = Memory::new(&vm, size)?;
    if size < 2 * 1024 * 1024 {
        return Err(Error::Config(
            "RAM must contain the 2 MiB DTB placement region",
        ));
    }
    let boot = boot::load(&config, &memory).await?;
    let disk = if let Some(path) = &config.disk {
        let file = file::File::open(path, true).await?;
        if file.size % 512 != 0 {
            return Err(Error::Config("disk size must be a multiple of 512 bytes"));
        }
        Some(file)
    } else {
        None
    };
    let (events, receiver) = async_channel::bounded(config.cpus as usize + 1);
    let mut cpus = Vec::new();
    let mut commands = Vec::new();
    let mut online = vec![false; config.cpus as usize];
    for id in 0..config.cpus {
        // One pending slot per architecturally usable non-LPI INTID.
        let cpu = Rc::new(vm.create_vcpu(id, 1020)?);
        let (tx, rx) = async_channel::bounded(1);
        commands.push(tx);
        cpus.push(cpu.clone());
        let output = events.clone();
        helios_api::task::spawn(async move {
            if let Err(error) = run_cpu(id, cpu, rx, output.clone()).await {
                let _ = output.send(Event::Failed(error)).await;
            }
        });
    }
    let (input_done, input_ack) = async_channel::bounded(1);
    let output = events.clone();
    helios_api::task::spawn(async move {
        let (mut input, completion) = helios_api::bindings::wasi::cli::stdin::read_via_stream();
        loop {
            let (status, bytes) = input.read(Vec::with_capacity(memory::TRANSFER)).await;
            let closed = helios_api::stream_closed(status);
            if !bytes.is_empty()
                && (output.send(Event::Input(bytes)).await.is_err()
                    || input_ack.recv().await.is_err())
            {
                return;
            }
            if closed {
                break;
            }
        }
        if let Err(error) = completion.await {
            let _ = output
                .send(Event::Failed(Error::Io(std::io::Error::other(format!(
                    "stdin: {error:?}"
                )))))
                .await;
        }
    });
    online[0] = true;
    commands[0]
        .send(Action::Start {
            entry: boot.entry,
            context: boot.dtb,
        })
        .await
        .map_err(|_| Error::Channel)?;
    let mut gic = gic::Gic::new(config.cpus);
    let mut console = virtio::Device::console();
    let mut block = virtio::Device::block();
    let mut input = VecDeque::new();
    let mut input_waiting = false;
    let mut early_console = Vec::new();
    let outcome: Result<()> = async {
        while let Ok(event) = receiver.recv().await {
            let mut response = None;
            match event {
                Event::Failed(error) => return Err(error),
                Event::Input(bytes) => {
                    input.extend(bytes);
                    input_waiting = true;
                }
                Event::Exit { cpu, exit } => {
                    let vcpu = &cpus[cpu as usize];
                    let mut action = Action::Run;
                    match exit {
                        VmExit::Preempted | VmExit::IrqWindow => {}
                        VmExit::Hypercall(function) => {
                            let args = vcpu.get_regs(&[
                                RegisterId::Aarch64X(1),
                                RegisterId::Aarch64X(2),
                                RegisterId::Aarch64X(3),
                            ])?;
                            let a = args[0].value;
                            let b = args[1].value;
                            let c = args[2].value;
                            let result = match function as u32 {
                                0x8400_0000 => 0x0001_0001, // PSCI_VERSION: 1.1.

                                0x8400_0002 => {
                                    online[cpu as usize] = false;
                                    action = Action::Park;
                                    0
                                }
                                0x8400_0003 | 0xc400_0003 => {
                                    if a >= u64::from(config.cpus) {
                                        -2i64 as u64
                                    } else if online[a as usize] {
                                        -4i64 as u64
                                    } else {
                                        memory.offset(b, 4)?;
                                        online[a as usize] = true;
                                        commands[a as usize]
                                            .send(Action::Start {
                                                entry: b,
                                                context: c,
                                            })
                                            .await
                                            .map_err(|_| Error::Channel)?;
                                        0
                                    }
                                }
                                0x8400_0004 | 0xc400_0004 => {
                                    if b != 0 || a >= u64::from(config.cpus) {
                                        -2i64 as u64
                                    } else {
                                        u64::from(!online[a as usize])
                                    }
                                }
                                0x8400_0008 | 0x8400_0009 => {
                                    println!("vmm: guest requested shutdown");
                                    break;
                                }
                                0x8400_000a => match a as u32 {
                                    0x8400_0000 | 0x8400_0002 | 0x8400_0003 | 0xc400_0003
                                    | 0x8400_0004 | 0xc400_0004 | 0x8400_0008 | 0x8400_0009
                                    | 0x8400_000a => 0,
                                    _ => -1i64 as u64,
                                },
                                _ => -1i64 as u64,
                            };
                            vcpu.set_regs(&[RegisterValue {
                                id: RegisterId::Aarch64X(0),
                                value: result,
                            }])?;
                        }
                        VmExit::Mmio(mmio) => {
                            let value = if (boot::UART..boot::UART + 0x1000).contains(&mmio.address)
                            {
                                match (mmio.address - boot::UART, mmio.access) {
                                    (0, IoAccess::Write(write)) => {
                                        let byte = write.value as u8;
                                        early_console.push(byte);
                                        // PL011 is the early boot log console. Coalesce
                                        // complete lines instead of awaiting a component
                                        // stream transfer for every trapped character.
                                        if byte == b'\n' || early_console.len() == memory::TRANSFER
                                        {
                                            helios_api::io::stdout()
                                                .write_all(std::mem::take(&mut early_console))
                                                .await?;
                                        }
                                        0
                                    }
                                    (0x18, IoAccess::Read(_)) => 0x90, // TXFE | RXFE.
                                    (0xfe0, IoAccess::Read(_)) => 0x11,
                                    (0xfe4, IoAccess::Read(_)) => 0x10,
                                    (0xfe8, IoAccess::Read(_)) => 0x14,
                                    (0xfec, IoAccess::Read(_)) => 0,
                                    (0xff0, IoAccess::Read(_)) => 0x0d,
                                    (0xff4, IoAccess::Read(_)) => 0xf0,
                                    (0xff8, IoAccess::Read(_)) => 0x05,
                                    (0xffc, IoAccess::Read(_)) => 0xb1,
                                    _ => 0,
                                }
                            } else if (boot::CONSOLE..boot::CONSOLE + 0x1000)
                                .contains(&mmio.address)
                            {
                                console.access(
                                    mmio.address - boot::CONSOLE,
                                    mmio.access,
                                    0,
                                    &memory,
                                )?
                            } else if let Some(file) = disk.as_ref()
                                && (boot::BLOCK..boot::BLOCK + 0x1000).contains(&mmio.address)
                            {
                                block.access(
                                    mmio.address - boot::BLOCK,
                                    mmio.access,
                                    file.size / 512,
                                    &memory,
                                )?
                            } else if (boot::GICD..boot::GICD + 0x10000).contains(&mmio.address)
                                || (boot::GICR..boot::GICR + u64::from(config.cpus) * 0x20000)
                                    .contains(&mmio.address)
                            {
                                gic.access(mmio.address, mmio.access)?
                            } else {
                                return Err(Error::Device(mmio.address));
                            };
                            vcpu.complete_exit(value)?;
                        }
                        VmExit::SystemRegister(register) => {
                            // Architectural op0:op1:CRn:CRm:op2 encodings.
                            let value = match (register.register, register.access) {
                                (0xc65d, IoAccess::Write(write)) => {
                                    gic.sgi(cpu, write.value);
                                    0
                                } // ICC_SGI1R_EL1.
                                _ => return Err(Error::Register(register.register)),
                            };
                            vcpu.complete_exit(value)?;
                        }
                        VmExit::Shutdown => break,
                        other => return Err(Error::Exit(cpu, other)),
                    }
                    response = Some((cpu, action));
                }
            }
            console.console_output(&memory).await?;
            console.console_input(&memory, &mut input)?;
            if input_waiting && input.is_empty() {
                input_done.send(()).await.map_err(|_| Error::Channel)?;
                input_waiting = false;
            }
            if let Some(file) = &disk {
                block.block_requests(&memory, file).await?;
            }
            gic.line(boot::CONSOLE_IRQ, console.interrupt != 0);
            gic.line(boot::BLOCK_IRQ, block.interrupt != 0);
            gic.sync(&vm)?;
            if let Some((cpu, action)) = response {
                commands[cpu as usize]
                    .send(action)
                    .await
                    .map_err(|_| Error::Channel)?;
            }
        }
        Ok(())
    }
    .await;
    if !early_console.is_empty() {
        helios_api::io::stdout().write_all(early_console).await?;
    }
    for (cpu, command) in cpus.iter().zip(commands) {
        cpu.kick();
        let _ = command.try_send(Action::Stop);
    }
    outcome
}
