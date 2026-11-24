//! Reusable async `MicroVm` builder and execution engine.
//!
//! Each vCPU runs on its own cooperative task, `virtio-mmio` `QueueNotify`
//! writes complete inside the kernel via `ioevent` watchers without blocking
//! vCPU tasks, and a single device task owns the static zero-`dyn` MMIO bus
//! and async device I/O.

use std::collections::{BTreeSet, VecDeque};
use std::rc::Rc;

use async_channel::{Receiver, Sender};
use futures_lite::future::or;
use helios_api::hv::{
    Aarch64Regs, GuestMemory, GuestPhysAddr, HvError, IoAccess, IoEvent, IoEventBackend,
    MmioRouter, Permissions, RegisterId, Vcpu, Vm, VmExit,
};
use tracing::{debug, info};

use crate::boot::{self, RAM_BASE, VirtioSlot};
use crate::error::{Error, Result};
use crate::file::{BlockBackend, WasiFile};
use crate::gic::{Gic, GicBus};
use crate::hv_backend::{IoEventRegistrar, IrqTarget};
use crate::uart::Pl011;
use crate::virtio::block::VirtioBlock;
use crate::virtio::console::{ConsoleSink, StdoutConsoleSink, VirtioConsole};
use crate::virtio::fs::backend::{FsBackend, WasiFsBackend};
use crate::virtio::fs::{ROOTFS_TAG, VirtioFs, VirtioFsShareConfig};
use crate::virtio::net::{ChannelNetBackend, NetBackend, VirtioNet, VirtioNetConfig};
use crate::virtio::vsock::{ChannelVsockBackend, VirtioVsock, VirtioVsockConfig, VsockBackend};

/// Default Linux kernel command line when booting an initramfs.
pub const DEFAULT_INITRAMFS_CMDLINE: &str =
    "console=hvc0 earlycon=pl011,0x9000000 rdinit=/init panic=-1";

/// Default Linux kernel command line when booting a `virtio-fs` rootfs directory directly.
pub const DEFAULT_ROOTFS_CMDLINE: &str =
    "console=hvc0 earlycon=pl011,0x9000000 root=rootfs rootfstype=virtiofs rw panic=-1";

/// Configuration for the `virtio-blk` device.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VirtioBlkConfig {
    pub path: String,
    pub read_only: bool,
}

impl VirtioBlkConfig {
    pub fn new(path: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            read_only: false,
        }
    }

    pub fn read_only(mut self, read_only: bool) -> Self {
        self.read_only = read_only;
        self
    }
}

/// Configuration for the `virtio-console` device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VirtioConsoleConfig {
    pub cols: u16,
    pub rows: u16,
}

impl Default for VirtioConsoleConfig {
    fn default() -> Self {
        Self { cols: 80, rows: 25 }
    }
}

/// Validated custom-VM configuration produced by [`MicroVmBuilder::build`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MicroVmConfig {
    pub cpus: u32,
    pub memory_bytes: u64,
    pub kernel: String,
    pub initramfs: Option<String>,
    pub cmdline: String,
    pub console: Option<VirtioConsoleConfig>,
    pub block: Option<VirtioBlkConfig>,
    pub net: Option<VirtioNetConfig>,
    pub vsock: Option<VirtioVsockConfig>,
    pub fs_shares: Vec<VirtioFsShareConfig>,
}

/// Pure custom-VM builder with no built-in container policy.
#[derive(Clone, Debug)]
pub struct MicroVmBuilder {
    cpus: u32,
    memory_bytes: u64,
    kernel: Option<String>,
    initramfs: Option<String>,
    cmdline: Option<String>,
    console: Option<VirtioConsoleConfig>,
    block: Option<VirtioBlkConfig>,
    net: Option<VirtioNetConfig>,
    vsock: Option<VirtioVsockConfig>,
    rootfs_dir: Option<VirtioFsShareConfig>,
    fs_shares: Vec<VirtioFsShareConfig>,
}

impl Default for MicroVmBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl MicroVmBuilder {
    pub fn new() -> Self {
        Self {
            cpus: 1,
            memory_bytes: 128 * 1024 * 1024,
            kernel: None,
            initramfs: None,
            cmdline: None,
            console: Some(VirtioConsoleConfig::default()),
            block: None,
            net: None,
            vsock: None,
            rootfs_dir: None,
            fs_shares: Vec::new(),
        }
    }

    pub fn cpus(mut self, cpus: u32) -> Self {
        self.cpus = cpus;
        self
    }

    pub fn memory_bytes(mut self, bytes: u64) -> Self {
        self.memory_bytes = bytes;
        self
    }

    pub fn memory_mib(mut self, mib: u64) -> Result<Self> {
        self.memory_bytes = mib
            .checked_mul(1024 * 1024)
            .ok_or(Error::Config("memory size overflow"))?;
        Ok(self)
    }

    pub fn kernel(mut self, path: impl Into<String>) -> Self {
        self.kernel = Some(path.into());
        self
    }

    pub fn initramfs(mut self, path: impl Into<String>) -> Self {
        self.initramfs = Some(path.into());
        self
    }

    pub fn cmdline(mut self, cmdline: impl Into<String>) -> Self {
        self.cmdline = Some(cmdline.into());
        self
    }

    pub fn virtio_console(mut self, config: Option<VirtioConsoleConfig>) -> Self {
        self.console = config;
        self
    }

    pub fn virtio_blk(mut self, config: VirtioBlkConfig) -> Self {
        self.block = Some(config);
        self
    }

    pub fn disk(self, path: impl Into<String>) -> Self {
        self.virtio_blk(VirtioBlkConfig::new(path))
    }

    pub fn virtio_net(mut self, config: VirtioNetConfig) -> Self {
        self.net = Some(config);
        self
    }

    pub fn virtio_vsock(mut self, config: VirtioVsockConfig) -> Self {
        self.vsock = Some(config);
        self
    }

    pub fn virtio_fs(mut self, share: VirtioFsShareConfig) -> Self {
        self.fs_shares.push(share);
        self
    }

    pub fn share_dir(mut self, tag: impl Into<String>, path: impl Into<String>) -> Result<Self> {
        let share = VirtioFsShareConfig::new(tag, path)?;
        self.fs_shares.push(share);
        Ok(self)
    }

    pub fn rootfs_dir(mut self, path: impl Into<String>) -> Result<Self> {
        self.rootfs_dir = Some(VirtioFsShareConfig::new(ROOTFS_TAG, path)?);
        Ok(self)
    }

    pub fn build(self) -> Result<MicroVmConfig> {
        // VMPIDR and the DTB describe one cluster with 8-bit Aff0.
        if self.cpus == 0 || self.cpus > 256 {
            return Err(Error::Config(
                "cpus must fit the ARM Aff0 topology (1..256)",
            ));
        }
        if !self.memory_bytes.is_multiple_of(helios_api::hv::PAGE_SIZE) {
            return Err(Error::Config("memory size must be 4 KiB page-aligned"));
        }
        if self.memory_bytes < boot::DTB_RESERVATION_BYTES {
            return Err(Error::Config(
                "RAM must contain the 2 MiB DTB placement region",
            ));
        }
        let kernel = self
            .kernel
            .filter(|s| !s.is_empty())
            .ok_or(Error::Config("kernel path is required"))?;
        if self.initramfs.is_none() && self.rootfs_dir.is_none() {
            return Err(Error::Config(
                "either initramfs or rootfs_dir must be specified",
            ));
        }

        let mut fs_shares =
            Vec::with_capacity(self.fs_shares.len() + usize::from(self.rootfs_dir.is_some()));
        let mut seen_tags = BTreeSet::new();
        if let Some(rootfs) = self.rootfs_dir {
            seen_tags.insert(rootfs.tag.clone());
            fs_shares.push(rootfs);
        }
        for share in self.fs_shares {
            crate::virtio::fs::validate_tag(&share.tag)?;
            if !seen_tags.insert(share.tag.clone()) {
                return Err(Error::InvalidShareTag {
                    tag: share.tag,
                    reason: "duplicate virtio-fs share tag",
                });
            }
            fs_shares.push(share);
        }

        let total_virtio = usize::from(self.console.is_some())
            + usize::from(self.block.is_some())
            + usize::from(self.net.is_some())
            + usize::from(self.vsock.is_some())
            + fs_shares.len();
        if total_virtio > boot::MAX_VIRTIO_SLOTS {
            return Err(Error::Config(
                "configured virtio devices exceed GICv3 SPI slot limit (16)",
            ));
        }

        let cmdline = match self.cmdline {
            Some(c) => c,
            None if self.initramfs.is_none() => DEFAULT_ROOTFS_CMDLINE.to_owned(),
            None => DEFAULT_INITRAMFS_CMDLINE.to_owned(),
        };

        Ok(MicroVmConfig {
            cpus: self.cpus,
            memory_bytes: self.memory_bytes,
            kernel,
            initramfs: self.initramfs,
            cmdline,
            console: self.console,
            block: self.block,
            net: self.net,
            vsock: self.vsock,
            fs_shares,
        })
    }

    pub fn build_vm(self) -> Result<MicroVm> {
        Ok(MicroVm {
            config: self.build()?,
        })
    }
}

/// Reason a [`MicroVm::run`] loop terminated cleanly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExitReason {
    /// Guest invoked PSCI SYSTEM_OFF or SYSTEM_RESET.
    GuestShutdown,
    /// Hypervisor reported `VmExit::Shutdown`.
    VmShutdown,
}

/// Identifies a single virtio device queue kicked via `ioevent`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueueKickTarget {
    Console(u16),
    Block(u16),
    Net(u16),
    Vsock(u16),
    Fs { index: usize, queue: u16 },
}

enum Action {
    Run,
    Start {
        entry: GuestPhysAddr,
        context: GuestPhysAddr,
    },
    Park,
    Stop,
}

enum Event {
    Exit { cpu: u32, exit: VmExit },
    QueueKick(QueueKickTarget),
    Failed(Error),
    Input(Vec<u8>),
}

/// Device set owned by the single device task, routed over a static zero-`dyn`
/// [`MmioRouter`] and driven either by `ioevent` kicks or MMIO exits.
pub struct DeviceSet<F: FsBackend> {
    pub gic: Gic,
    pub uart: Pl011,
    pub console: Option<VirtioConsole>,
    pub block: Option<VirtioBlock>,
    pub net: Option<VirtioNet>,
    pub vsock: Option<VirtioVsock>,
    pub fs_devices: Vec<VirtioFs<F>>,
}

/// Borrowed I/O backends supplied to [`DeviceSet::handle_kick`].
pub struct KickContext<'a, G, B, S, N, V, I> {
    pub memory: &'a G,
    pub console_sink: &'a mut S,
    pub console_input: &'a mut VecDeque<u8>,
    pub block_backend: Option<&'a B>,
    pub net_backend: &'a mut N,
    pub vsock_backend: &'a mut V,
    pub irq_target: &'a I,
}

impl<F: FsBackend> DeviceSet<F> {
    /// Dispatches one guest MMIO access through a static zero-`dyn` [`MmioRouter`].
    pub fn dispatch_mmio(
        &mut self,
        address: GuestPhysAddr,
        access: IoAccess,
        memory: &impl GuestMemory,
    ) -> Result<u64> {
        let mut router = MmioRouter::new()
            .with_bus(self.fs_devices.as_mut_slice())
            .with_bus(self.vsock.as_mut())
            .with_bus(self.net.as_mut())
            .with_bus(self.block.as_mut())
            .with_bus(self.console.as_mut())
            .with_bus(GicBus(&mut self.gic))
            .with_bus(&mut self.uart);
        router
            .dispatch(address, access, memory)?
            .ok_or(Error::UnmappedDevice(address))
    }

    /// Registers `ioevent` fast-path watchers for every virtio device's
    /// `QueueNotify` register (`base + 0x050`, 32-bit write matching queue ID).
    pub fn register_all_ioevents<R: IoEventRegistrar>(
        &self,
        registrar: &R,
    ) -> Result<Vec<(QueueKickTarget, IoEvent<R::Backend>)>> {
        let mut out = Vec::new();
        if let Some(console) = &self.console {
            for (q, ev) in console.register_queue_ioevents(registrar)? {
                out.push((QueueKickTarget::Console(q), ev));
            }
        }
        if let Some(block) = &self.block {
            for (q, ev) in block.register_queue_ioevents(registrar)? {
                out.push((QueueKickTarget::Block(q), ev));
            }
        }
        if let Some(net) = &self.net {
            for (q, ev) in net.register_queue_ioevents(registrar)? {
                out.push((QueueKickTarget::Net(q), ev));
            }
        }
        if let Some(vsock) = &self.vsock {
            for (q, ev) in vsock.register_queue_ioevents(registrar)? {
                out.push((QueueKickTarget::Vsock(q), ev));
            }
        }
        for (index, fs) in self.fs_devices.iter().enumerate() {
            for (queue, ev) in fs.register_queue_ioevents(registrar)? {
                out.push((QueueKickTarget::Fs { index, queue }, ev));
            }
        }
        Ok(out)
    }

    /// Drives the targeted virtqueue after an `ioevent` kick and syncs GIC lines.
    pub async fn handle_kick<G, B, S, N, V, I>(
        &mut self,
        target: QueueKickTarget,
        ctx: &mut KickContext<'_, G, B, S, N, V, I>,
    ) -> Result<()>
    where
        G: GuestMemory,
        B: BlockBackend,
        S: ConsoleSink,
        N: NetBackend,
        V: VsockBackend,
        I: IrqTarget,
    {
        match target {
            QueueKickTarget::Console(q) => {
                if let Some(console) = &mut self.console {
                    match q {
                        0 => console.process_input(ctx.memory, ctx.console_input)?,
                        1 => console.process_output(ctx.memory, ctx.console_sink).await?,
                        2 | 3 => console.process_control(ctx.memory)?,
                        _ => {}
                    }
                    self.gic.line(console.irq(), console.irq_asserted());
                }
            }
            QueueKickTarget::Block(_) => {
                if let (Some(block), Some(backend)) = (&mut self.block, ctx.block_backend) {
                    block.process_requests(ctx.memory, backend).await?;
                    self.gic.line(block.irq(), block.irq_asserted());
                }
            }
            QueueKickTarget::Net(q) => {
                if let Some(net) = &mut self.net {
                    if q == 1 {
                        net.process_tx(ctx.memory, ctx.net_backend)?;
                    } else {
                        net.process_rx(ctx.memory, ctx.net_backend)?;
                    }
                    self.gic.line(net.irq(), net.irq_asserted());
                }
            }
            QueueKickTarget::Vsock(q) => {
                if let Some(vsock) = &mut self.vsock {
                    if q == 1 {
                        vsock.process_tx(ctx.memory, ctx.vsock_backend)?;
                        vsock.process_rx(ctx.memory, ctx.vsock_backend)?;
                    } else if q == 0 {
                        vsock.process_rx(ctx.memory, ctx.vsock_backend)?;
                    }
                    self.gic.line(vsock.irq(), vsock.irq_asserted());
                }
            }
            QueueKickTarget::Fs { index, queue } => {
                if let Some(fs) = self.fs_devices.get_mut(index) {
                    fs.process_queue(ctx.memory, usize::from(queue)).await?;
                    self.gic.line(fs.irq(), fs.irq_asserted());
                }
            }
        }
        self.gic.sync(ctx.irq_target)
    }

    /// Refreshes all device IRQ lines in GICv3 and synchronizes pending interrupts.
    pub fn sync_all_irqs(&mut self, irq_target: &impl IrqTarget) -> Result<()> {
        if let Some(console) = &self.console {
            self.gic.line(console.irq(), console.irq_asserted());
        }
        if let Some(block) = &self.block {
            self.gic.line(block.irq(), block.irq_asserted());
        }
        if let Some(net) = &self.net {
            self.gic.line(net.irq(), net.irq_asserted());
        }
        if let Some(vsock) = &self.vsock {
            self.gic.line(vsock.irq(), vsock.irq_asserted());
        }
        for fs in &self.fs_devices {
            self.gic.line(fs.irq(), fs.irq_asserted());
        }
        self.gic.sync(irq_target)
    }
}

/// Reusable async hardware virtual machine built via [`MicroVm::builder`].
pub struct MicroVm {
    config: MicroVmConfig,
}

impl MicroVm {
    pub fn builder() -> MicroVmBuilder {
        MicroVmBuilder::new()
    }

    pub fn from_config(config: MicroVmConfig) -> Self {
        Self { config }
    }

    pub fn config(&self) -> &MicroVmConfig {
        &self.config
    }

    /// Boots and runs the virtual machine until the guest shuts down or an
    /// error occurs.
    pub async fn run(&self) -> Result<ExitReason> {
        let vm = Vm::create(self.config.memory_bytes)?;
        let memory = vm.allocate_memory(
            RAM_BASE,
            self.config.memory_bytes,
            Permissions::READ | Permissions::WRITE | Permissions::EXECUTE,
        )?;

        // Allocate deterministic virtio-mmio slots (console, block, net, vsock, fs...).
        let mut next_slot = 0usize;
        let mut virtio_slots = Vec::new();
        let mut alloc_slot = || -> Result<VirtioSlot> {
            let slot = VirtioSlot::at(next_slot)?;
            next_slot += 1;
            virtio_slots.push(slot);
            Ok(slot)
        };

        let console = match self.config.console {
            Some(cfg) => Some(VirtioConsole::console(alloc_slot()?, cfg.cols, cfg.rows)),
            None => None,
        };
        let (block, disk_file) = match &self.config.block {
            Some(cfg) => {
                let file = WasiFile::open(&cfg.path, !cfg.read_only).await?;
                if !file.size().is_multiple_of(512) {
                    return Err(Error::Config("disk size must be a multiple of 512 bytes"));
                }
                let dev = VirtioBlock::block(alloc_slot()?, file.size() / 512, cfg.read_only);
                (Some(dev), Some(file))
            }
            None => (None, None),
        };
        let net = match self.config.net {
            Some(cfg) => Some(VirtioNet::net(alloc_slot()?, cfg)),
            None => None,
        };
        let vsock = match self.config.vsock {
            Some(cfg) => Some(VirtioVsock::vsock(alloc_slot()?, cfg)),
            None => None,
        };
        let mut fs_devices = Vec::with_capacity(self.config.fs_shares.len());
        for share in &self.config.fs_shares {
            let backend = WasiFsBackend::open_root(&share.host_path, share.read_only).await?;
            fs_devices.push(VirtioFs::fs(alloc_slot()?, &share.tag, backend)?);
        }

        let boot = boot::load(
            &self.config.kernel,
            self.config.initramfs.as_deref(),
            &self.config.cmdline,
            self.config.cpus,
            &virtio_slots,
            &memory,
        )
        .await?;

        let mut devices = DeviceSet {
            gic: Gic::new(self.config.cpus),
            uart: Pl011::new(),
            console,
            block,
            net,
            vsock,
            fs_devices,
        };

        // Register ioevents for every virtio QueueNotify so vCPU tasks complete
        // I/O kicks in the kernel without blocking on synchronous MMIO exits.
        let ioevents = devices.register_all_ioevents(&vm)?;
        let ioevent_count = ioevents.len();
        info!(ioevent_count, "registered virtio-mmio queue ioevents");

        let (events, receiver) =
            async_channel::bounded(self.config.cpus as usize + ioevent_count + 4);
        let (shutdown_tx, shutdown_rx) = async_channel::bounded::<()>(1);

        for (target, event) in ioevents {
            let events = events.clone();
            let shutdown = shutdown_rx.clone();
            helios_api::task::spawn(async move {
                run_ioevent_watcher(target, event, events, shutdown).await;
            });
        }

        let mut cpus = Vec::with_capacity(self.config.cpus as usize);
        let mut commands = Vec::with_capacity(self.config.cpus as usize);
        let mut online = vec![false; self.config.cpus as usize];
        for id in 0..self.config.cpus {
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
        if devices.console.is_some() {
            let output = events.clone();
            helios_api::task::spawn(async move {
                let (mut input, completion) =
                    helios_api::bindings::wasi::cli::stdin::read_via_stream();
                loop {
                    let (status, bytes) = input
                        .read(Vec::with_capacity(helios_api::hv::TRANSFER_CHUNK_BYTES))
                        .await;
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
        }

        online[0] = true;
        commands[0]
            .send(Action::Start {
                entry: boot.entry,
                context: boot.dtb,
            })
            .await
            .map_err(|_| Error::ChannelClosed)?;

        let mut console_sink = StdoutConsoleSink;
        let mut net_backend = ChannelNetBackend::default();
        let mut vsock_backend = ChannelVsockBackend::rejecting_unknown_ports();
        let mut input = VecDeque::new();
        let mut input_waiting = false;

        let outcome: Result<ExitReason> = async {
            while let Ok(event) = receiver.recv().await {
                let mut response = None;
                match event {
                    Event::Failed(error) => return Err(error),
                    Event::Input(bytes) => {
                        input.extend(bytes);
                        input_waiting = true;
                        if let Some(console) = &mut devices.console {
                            console.process_input(&memory, &mut input)?;
                            if input_waiting && input.is_empty() {
                                input_done
                                    .send(())
                                    .await
                                    .map_err(|_| Error::ChannelClosed)?;
                                input_waiting = false;
                            }
                            devices.sync_all_irqs(&vm)?;
                        }
                    }
                    Event::QueueKick(target) => {
                        let mut ctx = KickContext {
                            memory: &memory,
                            console_sink: &mut console_sink,
                            console_input: &mut input,
                            block_backend: disk_file.as_ref(),
                            net_backend: &mut net_backend,
                            vsock_backend: &mut vsock_backend,
                            irq_target: &vm,
                        };
                        devices.handle_kick(target, &mut ctx).await?;
                        if input_waiting && input.is_empty() {
                            input_done
                                .send(())
                                .await
                                .map_err(|_| Error::ChannelClosed)?;
                            input_waiting = false;
                        }
                    }
                    Event::Exit { cpu, exit } => {
                        let vcpu = &cpus[cpu as usize];
                        let mut action = Action::Run;
                        match exit {
                            VmExit::Preempted | VmExit::IrqWindow => {}
                            VmExit::Hypercall(function) => {
                                let args = vcpu.get_aarch64_regs(&[
                                    RegisterId::Aarch64X(1),
                                    RegisterId::Aarch64X(2),
                                    RegisterId::Aarch64X(3),
                                ])?;
                                let a = args.get_x(1)?.unwrap_or(0);
                                let b = args.get_x(2)?.unwrap_or(0);
                                let c = args.get_x(3)?.unwrap_or(0);
                                let result = match function as u32 {
                                    0x8400_0000 => 0x0001_0001, // PSCI_VERSION: 1.1
                                    0x8400_0002 => {
                                        online[cpu as usize] = false;
                                        action = Action::Park;
                                        0
                                    }
                                    0x8400_0003 | 0xc400_0003 => {
                                        if a >= u64::from(self.config.cpus) {
                                            -2i64 as u64
                                        } else if online[a as usize] {
                                            -4i64 as u64
                                        } else {
                                            let entry = GuestPhysAddr::new(b);
                                            memory.validate_range(entry, 4)?;
                                            online[a as usize] = true;
                                            commands[a as usize]
                                                .send(Action::Start {
                                                    entry,
                                                    context: GuestPhysAddr::new(c),
                                                })
                                                .await
                                                .map_err(|_| Error::ChannelClosed)?;
                                            0
                                        }
                                    }
                                    0x8400_0004 | 0xc400_0004 => {
                                        if b != 0 || a >= u64::from(self.config.cpus) {
                                            -2i64 as u64
                                        } else {
                                            u64::from(!online[a as usize])
                                        }
                                    }
                                    0x8400_0008 | 0x8400_0009 => {
                                        info!("guest requested PSCI shutdown");
                                        return Ok(ExitReason::GuestShutdown);
                                    }
                                    0x8400_000a => match a as u32 {
                                        0x8400_0000 | 0x8400_0002 | 0x8400_0003 | 0xc400_0003
                                        | 0x8400_0004 | 0xc400_0004 | 0x8400_0008 | 0x8400_0009
                                        | 0x8400_000a => 0,
                                        _ => -1i64 as u64,
                                    },
                                    _ => -1i64 as u64,
                                };
                                vcpu.set_aarch64_regs(&Aarch64Regs::new().x0(result))?;
                            }
                            VmExit::Mmio(mmio) => {
                                let value = devices.dispatch_mmio(
                                    GuestPhysAddr::new(mmio.address),
                                    mmio.access,
                                    &memory,
                                )?;
                                if let Some(bytes) = devices.uart.take_ready() {
                                    console_sink.write_all(bytes).await?;
                                }
                                vcpu.complete_exit(value)?;
                            }
                            VmExit::SystemRegister(register) => {
                                // Architectural op0:op1:CRn:CRm:op2 encodings.
                                let value = match (register.register, register.access) {
                                    (0xc65d, IoAccess::Write(write)) => {
                                        devices.gic.sgi(cpu, write.value);
                                        0
                                    } // ICC_SGI1R_EL1.
                                    _ => return Err(Error::UnsupportedRegister(register.register)),
                                };
                                vcpu.complete_exit(value)?;
                            }
                            VmExit::Shutdown => return Ok(ExitReason::VmShutdown),
                            other => return Err(Error::UnexpectedExit { cpu, exit: other }),
                        }
                        response = Some((cpu, action));
                    }
                }
                // Catch up any virtio state changed by MMIO writes (e.g. DRIVER_OK or
                // InterruptACK) and deliver pending GIC interrupts.
                if let Some(console) = &mut devices.console {
                    console.process_control(&memory)?;
                    console.process_output(&memory, &mut console_sink).await?;
                    console.process_input(&memory, &mut input)?;
                    if input_waiting && input.is_empty() {
                        input_done
                            .send(())
                            .await
                            .map_err(|_| Error::ChannelClosed)?;
                        input_waiting = false;
                    }
                }
                devices.sync_all_irqs(&vm)?;
                if let Some((cpu, action)) = response {
                    commands[cpu as usize]
                        .send(action)
                        .await
                        .map_err(|_| Error::ChannelClosed)?;
                }
            }
            Ok(ExitReason::VmShutdown)
        }
        .await;

        if let Some(console) = &mut devices.console {
            let _ = console.process_output(&memory, &mut console_sink).await;
        }
        if let Some(bytes) = devices.uart.take_all() {
            let _ = console_sink.write_all(bytes).await;
        }
        shutdown_tx.close();
        for (cpu, command) in cpus.iter().zip(commands) {
            cpu.kick();
            let _ = command.try_send(Action::Stop);
        }
        outcome
    }
}

async fn run_ioevent_watcher<B: IoEventBackend>(
    target: QueueKickTarget,
    event: IoEvent<B>,
    events: Sender<Event>,
    shutdown: Receiver<()>,
) {
    loop {
        let wait_result = or(async { Some(event.wait().await) }, async {
            let _ = shutdown.recv().await;
            None
        })
        .await;
        match wait_result {
            None => return,
            Some(Ok(())) => {
                if events.send(Event::QueueKick(target)).await.is_err() {
                    return;
                }
            }
            Some(Err(helios_api::hv::Error::Hv(HvError::Stopped))) => return,
            Some(Err(error)) => {
                debug!(?target, %error, "ioevent watcher stopped on error");
                let _ = events.send(Event::Failed(Error::Hv(error))).await;
                return;
            }
        }
    }
}

async fn run_cpu(
    id: u32,
    vcpu: Rc<Vcpu>,
    commands: Receiver<Action>,
    events: Sender<Event>,
) -> Result<()> {
    let mut running = false;
    loop {
        match commands.recv().await.map_err(|_| Error::ChannelClosed)? {
            Action::Start { entry, context } => {
                vcpu.reset()?;
                vcpu.set_aarch64_regs(&Aarch64Regs::linux_boot(entry, context))?;
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
            .map_err(|_| Error::ChannelClosed)?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::virtio::fs::backend::HostFsBackend;
    use crate::virtio::fs::fuse::*;
    use crate::virtio::test_support::*;
    use crate::virtio::{DRIVER_OK, VirtioModel};
    use helios_api::hv::{IoWidth, IoWrite, IrqLevel};
    use std::cell::RefCell;
    use zerocopy::{FromBytes, IntoBytes};

    struct RecordingIrqs(RefCell<Vec<(u32, u32, IrqLevel)>>);
    impl IrqTarget for RecordingIrqs {
        fn set_irq_line(&self, vcpu_id: u32, number: u32, level: IrqLevel) -> Result<()> {
            self.0.borrow_mut().push((vcpu_id, number, level));
            Ok(())
        }
    }

    struct VecSink(Vec<u8>);
    impl ConsoleSink for VecSink {
        async fn write_all(&mut self, bytes: Vec<u8>) -> Result<()> {
            self.0.extend_from_slice(&bytes);
            Ok(())
        }
    }

    struct MemBlock(RefCell<Vec<u8>>);
    impl BlockBackend for MemBlock {
        fn size(&self) -> u64 {
            self.0.borrow().len() as u64
        }
        async fn read(&self, offset: u64, length: usize) -> Result<Vec<u8>> {
            let s = offset as usize;
            Ok(self.0.borrow()[s..s + length].to_vec())
        }
        async fn write(&self, offset: u64, bytes: Vec<u8>) -> Result<()> {
            let s = offset as usize;
            self.0.borrow_mut()[s..s + bytes.len()].copy_from_slice(&bytes);
            Ok(())
        }
    }

    #[test]
    fn microvm_builder_validates_pure_custom_vm_config() {
        assert!(MicroVm::builder().build().is_err()); // missing kernel
        assert!(MicroVm::builder().kernel("/Image").build().is_err()); // missing initramfs/rootfs

        let cfg = MicroVm::builder()
            .cpus(4)
            .memory_mib(256)
            .unwrap()
            .kernel("/host/Image")
            .rootfs_dir("/host/rootfs")
            .unwrap()
            .share_dir("work", "/host/work")
            .unwrap()
            .disk("/host/disk.raw")
            .virtio_net(VirtioNetConfig::default())
            .virtio_vsock(VirtioVsockConfig::new(5).unwrap())
            .build()
            .unwrap();
        assert_eq!(cfg.cpus, 4);
        assert_eq!(cfg.memory_bytes, 256 * 1024 * 1024);
        assert_eq!(cfg.cmdline, DEFAULT_ROOTFS_CMDLINE);
        assert_eq!(cfg.fs_shares.len(), 2);
        assert_eq!(cfg.fs_shares[0].tag, ROOTFS_TAG);
        assert_eq!(cfg.fs_shares[1].tag, "work");

        // Duplicate tags rejected.
        assert!(
            MicroVm::builder()
                .kernel("/Image")
                .rootfs_dir("/root")
                .unwrap()
                .share_dir("rootfs", "/other")
                .unwrap()
                .build()
                .is_err()
        );
    }

    #[test]
    fn ioevent_kick_drives_virtio_fs_and_console_without_mmio_exit() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("note.txt"), b"hello-ioevent").unwrap();
        let fs_backend = HostFsBackend::new(dir.path(), false).unwrap();

        let console_slot = VirtioSlot::at(0).unwrap();
        let fs_slot = VirtioSlot::at(1).unwrap();
        let mut devices = DeviceSet {
            gic: Gic::new(1),
            uart: Pl011::new(),
            console: Some(VirtioConsole::console(console_slot, 80, 25)),
            block: None,
            net: None,
            vsock: None,
            fs_devices: vec![VirtioFs::fs(fs_slot, "share", fs_backend).unwrap()],
        };

        let ram = test_ram(32 * 1024);
        // Enable GICv3 distributor + wake CPU 0 + enable SPI 49 (fs_slot.irq) via static MMIO bus!
        devices
            .dispatch_mmio(
                boot::GICD,
                IoAccess::Write(IoWrite {
                    width: IoWidth::Dword,
                    value: 2,
                }),
                &ram,
            )
            .unwrap();
        devices
            .dispatch_mmio(
                boot::GICR.checked_add(0x14).unwrap(),
                IoAccess::Write(IoWrite {
                    width: IoWidth::Dword,
                    value: 0,
                }),
                &ram,
            )
            .unwrap();
        let spi_bit = 1u64 << (fs_slot.irq - 32);
        // Group 1 + Enable for fs SPI.
        devices
            .dispatch_mmio(
                boot::GICD.checked_add(0x84).unwrap(),
                IoAccess::Write(IoWrite {
                    width: IoWidth::Dword,
                    value: spi_bit,
                }),
                &ram,
            )
            .unwrap();
        devices
            .dispatch_mmio(
                boot::GICD.checked_add(0x104).unwrap(),
                IoAccess::Write(IoWrite {
                    width: IoWidth::Dword,
                    value: spi_bit,
                }),
                &ram,
            )
            .unwrap();

        // Register ioevents via an async channel-backed registrar simulating kernel ioevent hits.
        struct ChannelEvent(Receiver<()>);
        impl IoEventBackend for ChannelEvent {
            async fn wait(&self) -> helios_api::hv::Result<()> {
                self.0
                    .recv()
                    .await
                    .map_err(|_| helios_api::hv::Error::Hv(HvError::Stopped))
            }
        }
        type KickRegistration = (GuestPhysAddr, Option<u64>, Sender<()>);
        struct MockRegistrar {
            senders: RefCell<Vec<KickRegistration>>,
        }
        impl IoEventRegistrar for MockRegistrar {
            type Backend = ChannelEvent;
            fn register_ioevent(
                &self,
                address: GuestPhysAddr,
                width: IoWidth,
                match_value: Option<u64>,
            ) -> Result<IoEvent<Self::Backend>> {
                let (tx, rx) = async_channel::bounded(4);
                self.senders.borrow_mut().push((address, match_value, tx));
                Ok(IoEvent::from_backend(
                    address,
                    width,
                    match_value,
                    ChannelEvent(rx),
                ))
            }
        }

        let registrar = MockRegistrar {
            senders: RefCell::new(Vec::new()),
        };
        let registered = devices.register_all_ioevents(&registrar).unwrap();
        assert_eq!(registered.len(), 6); // 4 console queues + 2 fs queues

        // Prepare FUSE_INIT request on virtio-fs queue 1.
        let fs_dev = &mut devices.fs_devices[0];
        fs_dev.status = DRIVER_OK;
        fs_dev.model.queues_mut()[1] = enable_queue(&ram, 0, 8);
        let init_in = FuseInitIn {
            major: 7u32.to_le(),
            minor: 31u32.to_le(),
            max_readahead: 4096u32.to_le(),
            flags: FUSE_DO_READDIRPLUS.to_le(),
        };
        let hdr = FuseInHeader {
            len: 56u32.to_le(),
            opcode: FUSE_INIT.to_le(),
            unique: 77u64.to_le(),
            nodeid: 0,
            uid: 0,
            gid: 0,
            pid: 1,
            padding: 0,
        };
        let mut req_buf = Vec::new();
        req_buf.extend_from_slice(hdr.as_bytes());
        req_buf.extend_from_slice(init_in.as_bytes());
        ram.write_slice(GuestPhysAddr::new(4096), &req_buf).unwrap();
        write_desc(&ram, &fs_dev.model.queues()[1], 0, 4096, 56, 1, 1);
        write_desc(&ram, &fs_dev.model.queues()[1], 1, 8192, 256, 2, 0);
        push_avail(&ram, &fs_dev.model.queues()[1], 0, 0);

        // Simulate kernel completing guest QueueNotify write (queue 1 on fs_slot)
        // -> ioevent wakes watcher -> watcher sends Event::QueueKick -> DeviceSet handles it -> GIC asserts IRQ!
        let fs_notify = fs_slot
            .base
            .checked_add(crate::virtio::QUEUE_NOTIFY_OFFSET)
            .unwrap();
        let (fs_target, fs_event) = registered
            .into_iter()
            .find(|(t, _)| *t == QueueKickTarget::Fs { index: 0, queue: 1 })
            .unwrap();
        let kernel_tx = registrar
            .senders
            .borrow()
            .iter()
            .find(|(addr, val, _)| *addr == fs_notify && *val == Some(1))
            .unwrap()
            .2
            .clone();

        let irqs = RecordingIrqs(RefCell::new(Vec::new()));
        let mut sink = VecSink(Vec::new());
        let mut input = VecDeque::new();
        let mut net = ChannelNetBackend::default();
        let mut vsock = ChannelVsockBackend::default();
        let no_block: Option<&MemBlock> = None;

        futures_lite::future::block_on(async {
            let (ev_tx, ev_rx) = async_channel::bounded(4);
            let (sd_tx, sd_rx) = async_channel::bounded(1);
            // Kernel fires ioevent completion before watcher runs.
            kernel_tx.send(()).await.unwrap();
            // Run watcher until it forwards one kick, then signal shutdown.
            let watcher = run_ioevent_watcher(fs_target, fs_event, ev_tx, sd_rx);
            let consumer = async {
                let Event::QueueKick(target) = ev_rx.recv().await.unwrap() else {
                    panic!("expected QueueKick event");
                };
                assert_eq!(target, QueueKickTarget::Fs { index: 0, queue: 1 });
                let mut ctx = KickContext {
                    memory: &ram,
                    console_sink: &mut sink,
                    console_input: &mut input,
                    block_backend: no_block,
                    net_backend: &mut net,
                    vsock_backend: &mut vsock,
                    irq_target: &irqs,
                };
                devices.handle_kick(target, &mut ctx).await.unwrap();
                sd_tx.close();
            };
            futures_lite::future::zip(watcher, consumer).await;
        });

        let used = used_len(&ram, &devices.fs_devices[0].model.queues()[1], 0) as usize;
        let reply = ram.read_bytes(GuestPhysAddr::new(8192), used).unwrap();
        let (out_hdr, _) = FuseOutHeader::read_from_prefix(&reply).unwrap();
        assert_eq!(i32::from_le(out_hdr.error), 0);
        assert_eq!(u64::from_le(out_hdr.unique), 77);
        assert_eq!(*irqs.0.borrow(), vec![(0, fs_slot.irq, IrqLevel::Assert)]);
    }
}
