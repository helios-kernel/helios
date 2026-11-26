//! RISC-V 64-bit hibernate device registry, early-boot resume probe, and
//! restore trampoline handoff.
//!
//! # Ordering contract
//!
//! - [`RiscvHibernateDevices::quiesce_all`] quiesces every DMA-capable
//!   endpoint device BEFORE quiescing `virtio-iommu`.
//! - [`RiscvHibernateDevices::reinitialize_iommu`] reinitializes
//!   `virtio-iommu` alone (when present) before the hibernate block device
//!   writes the snapshot to disk.
//! - [`RiscvHibernateDevices::reinitialize_all`] MUST reinitialize
//!   `virtio-iommu` FIRST (when present) before any other virtio device calls
//!   `reinitialize()`, so every DMA domain and IOVA mapping is restored before
//!   any endpoint resumes DMA (and records resets for host-share and
//!   memory-balloon devices).

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::arch::global_asm;
use core::mem::{offset_of, size_of};
use core::ops::Range;
use core::time::Duration;

use helios_hal::cpu::{
    Cpu, DisplacedFrameCopy, ResumeHandoff, ResumeHandoffWire, Riscv64SnapshotContext,
};
use helios_hal::fs::BlockDevice as _;
use helios_hal::pmm::PhysFrame;
use helios_hal::rtc::RealTimeClock;
use helios_hal::watchdog::Watchdog;
use helios_kernel::hibernate::{
    DeviceFeatureRecord, HIBERNATE_FREEZE_DEADLINE, HibernateDeviceController,
    HibernateDeviceError, HibernateOutcome, HibernateRequest, HibernateRequestError,
    LoadedHibernateImage, ResumeProbe, VirtioBlockHibernateStorage, build_machine_identity,
    collect_boot_protected_ranges, compute_hibernate_reservation_bytes,
    hibernate_machine_with_handle, probe_and_load_hibernate_image, usable_physical_frame_runs,
};
use helios_kernel::{
    DebugSerialWriter, HIBERNATE_DISK_SERIAL, HibernateHandle, Kernel, MachineGenerationHandle,
    ProviderReceiver, ResetDevice, RootEntropy, UserMemoryPool,
};
use helios_virtio::DeviceType;

use crate::RiscvCpu;
use crate::balloon::RiscvVirtioBalloonDevice;
use crate::block::RiscvVirtioBlockDevice;
use crate::entropy::RiscvVirtioRngDevice;
use crate::gpu::RiscvVirtioGpuDevice;
use crate::host_fs::HostFsTransportService;
use crate::input::RiscvVirtioInputDevice;
use crate::iommu::RiscvVirtioIommuDevice;
use crate::net::RiscvVirtioNetDevice;
use crate::rtc::GoldfishRtc;
use crate::snd::RiscvVirtioSndDevice;
use crate::vsock::RiscvVirtioVsockDevice;

global_asm!(include_str!("restore.S"));

unsafe extern "C" {
    fn __helios_riscv_restore_trampoline(params: *const RiscvRestoreParams) -> !;
}

/// Polled I/O deadline for early-boot hibernate disk discovery, verification,
/// and device quiesce/reinitialization.
const POLLED_TIMEOUT: Duration = Duration::from_secs(30);

/// Polled I/O deadline for writing the compressed hibernate image and
/// invalidating its header on resume (generous for slow emulated targets).
const HIBERNATE_IO_TIMEOUT: Duration = Duration::from_secs(300);

/// Parameter block written at offset `0x000` of the safe 4 KiB trampoline page
/// (`trampoline_phys`, identity-mapped on RISC-V) before entering
/// [`__helios_riscv_restore_trampoline`].
#[repr(C)]
struct RiscvRestoreParams {
    trampoline_satp: u64,
    copy_table_phys: u64,
    copy_count: u64,
    stack_top_phys: u64,
    handoff_phys: u64,
    ctx_phys: u64,
}

const HANDOFF_PAGE_OFFSET: usize = 0x80;
const CTX_PAGE_OFFSET: usize = 0x100;
const STACK_TOP_PAGE_OFFSET: usize = 0xff0;

const _: () = {
    assert!(offset_of!(RiscvRestoreParams, trampoline_satp) == 0x00);
    assert!(offset_of!(RiscvRestoreParams, copy_table_phys) == 0x08);
    assert!(offset_of!(RiscvRestoreParams, copy_count) == 0x10);
    assert!(offset_of!(RiscvRestoreParams, stack_top_phys) == 0x18);
    assert!(offset_of!(RiscvRestoreParams, handoff_phys) == 0x20);
    assert!(offset_of!(RiscvRestoreParams, ctx_phys) == 0x28);
    assert!(size_of::<RiscvRestoreParams>() <= HANDOFF_PAGE_OFFSET);
    assert!(HANDOFF_PAGE_OFFSET + size_of::<ResumeHandoffWire>() <= CTX_PAGE_OFFSET);
    assert!(CTX_PAGE_OFFSET + size_of::<Riscv64SnapshotContext>() <= 0x280);
    assert!(offset_of!(Riscv64SnapshotContext, sscratch) == 0xe8);
    assert!(offset_of!(Riscv64SnapshotContext, sie) == 0xf0);
    assert!(offset_of!(Riscv64SnapshotContext, satp) == 0xf8);
    assert!(offset_of!(Riscv64SnapshotContext, stvec) == 0x100);
    assert!(offset_of!(Riscv64SnapshotContext, sstatus) == 0x108);
};

/// Static-dispatch registry of every live RISC-V virtio device brought up at
/// boot, holding `virtio-iommu` first so [`HibernateDeviceController`] enforces
/// the IOMMU-first reinitialization invariant.
#[derive(Clone)]
pub(crate) struct RiscvHibernateDevices {
    cpu: RiscvCpu,
    generation: MachineGenerationHandle,
    pub(crate) iommu: Option<Arc<RiscvVirtioIommuDevice>>,
    pub(crate) host_fs: Option<HostFsTransportService>,
    pub(crate) network: Option<Arc<RiscvVirtioNetDevice>>,
    pub(crate) entropy: Option<Arc<RiscvVirtioRngDevice>>,
    pub(crate) balloon: Option<Arc<RiscvVirtioBalloonDevice>>,
    pub(crate) vsock: Option<Arc<RiscvVirtioVsockDevice>>,
    pub(crate) display: Option<Arc<RiscvVirtioGpuDevice>>,
    pub(crate) inputs: Vec<Arc<RiscvVirtioInputDevice>>,
    pub(crate) sound: Option<Arc<RiscvVirtioSndDevice>>,
    pub(crate) blocks: Vec<RiscvVirtioBlockDevice>,
    pub(crate) hibernate_block: Option<RiscvVirtioBlockDevice>,
}

impl RiscvHibernateDevices {
    pub(crate) fn new(cpu: RiscvCpu, generation: MachineGenerationHandle) -> Self {
        Self {
            cpu,
            generation,
            iommu: None,
            host_fs: None,
            network: None,
            entropy: None,
            balloon: None,
            vsock: None,
            display: None,
            inputs: Vec::new(),
            sound: None,
            blocks: Vec::new(),
            hibernate_block: None,
        }
    }

    /// Collects canonical sorted [`DeviceFeatureRecord`]s across every live
    /// virtio device for [`helios_kernel::hibernate::HibernateIdentity`].
    pub(crate) fn feature_records(&self) -> Vec<DeviceFeatureRecord> {
        let mut records = Vec::new();
        if let Some(iommu) = &self.iommu {
            records.push(DeviceFeatureRecord {
                device_kind: DeviceType::Iommu as u32,
                instance_index: 0,
                features: iommu.features().bits(),
            });
        }
        if let Some(host_fs) = &self.host_fs {
            records.push(DeviceFeatureRecord {
                device_kind: DeviceType::_9P as u32,
                instance_index: 0,
                features: host_fs.device().features().bits(),
            });
        }
        if let Some(network) = &self.network {
            records.push(DeviceFeatureRecord {
                device_kind: DeviceType::Network as u32,
                instance_index: 0,
                features: network.features().bits(),
            });
        }
        if let Some(entropy) = &self.entropy {
            records.push(DeviceFeatureRecord {
                device_kind: DeviceType::Entropy as u32,
                instance_index: 0,
                features: entropy.features().bits(),
            });
        }
        if let Some(balloon) = &self.balloon {
            records.push(DeviceFeatureRecord {
                device_kind: DeviceType::MemoryBalloon as u32,
                instance_index: 0,
                features: balloon.features().bits(),
            });
        }
        if let Some(vsock) = &self.vsock {
            records.push(DeviceFeatureRecord {
                device_kind: DeviceType::Vsock as u32,
                instance_index: 0,
                features: vsock.features().bits(),
            });
        }
        if let Some(display) = &self.display {
            records.push(DeviceFeatureRecord {
                device_kind: DeviceType::Gpu as u32,
                instance_index: 0,
                features: display.features().bits(),
            });
        }
        for (idx, input) in self.inputs.iter().enumerate() {
            records.push(DeviceFeatureRecord {
                device_kind: DeviceType::Input as u32,
                instance_index: idx as u32,
                features: input.features().bits(),
            });
        }
        if let Some(sound) = &self.sound {
            records.push(DeviceFeatureRecord {
                device_kind: DeviceType::Sound as u32,
                instance_index: 0,
                features: sound.features().bits(),
            });
        }
        for (idx, block) in self.blocks.iter().enumerate() {
            records.push(DeviceFeatureRecord {
                device_kind: DeviceType::Block as u32,
                instance_index: idx as u32,
                features: block.features().bits(),
            });
        }
        records.sort_unstable();
        records
    }

    fn deadline(&self) -> u64 {
        self.cpu
            .now()
            .ticks()
            .saturating_add(self.cpu.timebase().duration_to_ticks(POLLED_TIMEOUT))
    }

    fn expired_fn(&self, deadline: u64) -> impl FnMut() -> bool + '_ {
        move || self.cpu.now().ticks() >= deadline
    }
}

impl HibernateDeviceController for RiscvHibernateDevices {
    fn quiesce_all(&mut self) -> Result<(), HibernateDeviceError> {
        let deadline = self.deadline();
        if let Some(host_fs) = &self.host_fs {
            host_fs
                .device()
                .quiesce(self.expired_fn(deadline))
                .map_err(|_| HibernateDeviceError::Quiesce {
                    device: "virtio-9p",
                    detail: "quiesce failed",
                })?;
        }
        if let Some(network) = &self.network {
            network.quiesce(self.expired_fn(deadline)).map_err(|_| {
                HibernateDeviceError::Quiesce {
                    device: "virtio-net",
                    detail: "quiesce failed",
                }
            })?;
        }
        if let Some(entropy) = &self.entropy {
            entropy.quiesce(self.expired_fn(deadline)).map_err(|_| {
                HibernateDeviceError::Quiesce {
                    device: "virtio-rng",
                    detail: "quiesce failed",
                }
            })?;
        }
        if let Some(balloon) = &self.balloon {
            balloon.quiesce(self.expired_fn(deadline)).map_err(|_| {
                HibernateDeviceError::Quiesce {
                    device: "virtio-balloon",
                    detail: "quiesce failed",
                }
            })?;
        }
        if let Some(vsock) = &self.vsock {
            vsock.quiesce(self.expired_fn(deadline)).map_err(|_| {
                HibernateDeviceError::Quiesce {
                    device: "virtio-vsock",
                    detail: "quiesce failed",
                }
            })?;
        }
        if let Some(display) = &self.display {
            display.quiesce(self.expired_fn(deadline)).map_err(|_| {
                HibernateDeviceError::Quiesce {
                    device: "virtio-gpu",
                    detail: "quiesce failed",
                }
            })?;
        }
        for input in &self.inputs {
            input.quiesce(self.expired_fn(deadline)).map_err(|_| {
                HibernateDeviceError::Quiesce {
                    device: "virtio-input",
                    detail: "quiesce failed",
                }
            })?;
        }
        if let Some(sound) = &self.sound {
            sound.quiesce(self.expired_fn(deadline)).map_err(|_| {
                HibernateDeviceError::Quiesce {
                    device: "virtio-snd",
                    detail: "quiesce failed",
                }
            })?;
        }
        for block in &self.blocks {
            block.quiesce(self.expired_fn(deadline)).map_err(|_| {
                HibernateDeviceError::Quiesce {
                    device: "virtio-blk",
                    detail: "quiesce failed",
                }
            })?;
        }
        // Quiesce virtio-iommu LAST after every confined endpoint has drained DMA.
        if let Some(iommu) = &self.iommu {
            iommu.quiesce(self.expired_fn(deadline)).map_err(|_| {
                HibernateDeviceError::Quiesce {
                    device: "virtio-iommu",
                    detail: "quiesce failed",
                }
            })?;
        }
        Ok(())
    }

    fn reinitialize_iommu(&mut self) -> Result<(), HibernateDeviceError> {
        let deadline = self.deadline();
        if let Some(iommu) = &self.iommu {
            let _reset = iommu.reinitialize(self.expired_fn(deadline)).map_err(|_| {
                HibernateDeviceError::Reinitialize {
                    device: "virtio-iommu",
                    detail: "reinitialize failed",
                }
            })?;
        }
        Ok(())
    }

    fn reinitialize_all(&mut self) -> Result<(), HibernateDeviceError> {
        // STRICT ORDERING CONTRACT: when `virtio-iommu` is present, its
        // `reinitialize()` MUST complete BEFORE any other virtio driver calls
        // `reinitialize()`.
        self.reinitialize_iommu()?;
        let deadline = self.deadline();
        if let Some(host_fs) = &self.host_fs {
            let _reset = host_fs.device().reinitialize().map_err(|_| {
                HibernateDeviceError::Reinitialize {
                    device: "virtio-9p",
                    detail: "reinitialize failed",
                }
            })?;
            self.generation.record_device_reset(ResetDevice::HostShare);
        }
        if let Some(network) = &self.network {
            let _reset = network
                .reinitialize(self.expired_fn(deadline))
                .map_err(|_| HibernateDeviceError::Reinitialize {
                    device: "virtio-net",
                    detail: "reinitialize failed",
                })?;
        }
        if let Some(entropy) = &self.entropy {
            let _reset =
                entropy
                    .reinitialize()
                    .map_err(|_| HibernateDeviceError::Reinitialize {
                        device: "virtio-rng",
                        detail: "reinitialize failed",
                    })?;
        }
        if let Some(balloon) = &self.balloon {
            let _reset =
                balloon
                    .reinitialize()
                    .map_err(|_| HibernateDeviceError::Reinitialize {
                        device: "virtio-balloon",
                        detail: "reinitialize failed",
                    })?;
            self.generation
                .record_device_reset(ResetDevice::MemoryBalloon);
        }
        if let Some(vsock) = &self.vsock {
            let _reset = vsock
                .reinitialize()
                .map_err(|_| HibernateDeviceError::Reinitialize {
                    device: "virtio-vsock",
                    detail: "reinitialize failed",
                })?;
        }
        if let Some(display) = &self.display {
            let _reset = display
                .reinitialize(self.expired_fn(deadline))
                .map_err(|_| HibernateDeviceError::Reinitialize {
                    device: "virtio-gpu",
                    detail: "reinitialize failed",
                })?;
        }
        for input in &self.inputs {
            let _reset = input
                .reinitialize()
                .map_err(|_| HibernateDeviceError::Reinitialize {
                    device: "virtio-input",
                    detail: "reinitialize failed",
                })?;
        }
        if let Some(sound) = &self.sound {
            let _reset = sound.reinitialize(self.expired_fn(deadline)).map_err(|_| {
                HibernateDeviceError::Reinitialize {
                    device: "virtio-snd",
                    detail: "reinitialize failed",
                }
            })?;
        }
        for block in &self.blocks {
            let _reset = block
                .reinitialize()
                .map_err(|_| HibernateDeviceError::Reinitialize {
                    device: "virtio-blk",
                    detail: "reinitialize failed",
                })?;
        }
        Ok(())
    }
}

/// Probes the `"helios-hibernate"` block device during early BSP bring-up
/// (with interrupts disabled, before starting secondary harts or launching
/// `init`).
#[expect(
    clippy::too_many_arguments,
    reason = "early-boot resume probe receives explicit static-dispatch boot dependencies"
)]
pub(crate) fn probe_and_resume_if_present<WatchdogImpl, MeasuredBootImpl>(
    cpu: &RiscvCpu,
    kernel: &Kernel<RiscvCpu, WatchdogImpl, MeasuredBootImpl>,
    watchdog: &WatchdogImpl,
    debug_state: &crate::debug_state::RuntimeState,
    pool: &UserMemoryPool,
    root_entropy: &RootEntropy,
    rtc: Option<&GoldfishRtc>,
    devices: &mut RiscvHibernateDevices,
    extra_protected: &[Range<u64>],
) where
    WatchdogImpl: Watchdog + Clone,
    MeasuredBootImpl: helios_hal::measured_boot::MeasuredBoot,
{
    let Some(boot_memory) = kernel.boot_memory() else {
        return;
    };
    let Some(hibernate_blk) = find_hibernate_block_device(cpu, &devices.blocks) else {
        return;
    };
    devices.hibernate_block = Some(hibernate_blk.clone());

    let feature_records = devices.feature_records();
    // SAFETY: `boot_memory.kernel_sections.text` and `rodata` describe the
    // immutable identity-mapped `.text` and `.rodata` sections of this kernel.
    let expected_identity = match unsafe {
        build_machine_identity(
            boot_memory,
            cpu.processor_count() as u32,
            kernel.devices(),
            kernel.dma_model(),
            &feature_records,
        )
    } {
        Ok(id) => id,
        Err(error) => {
            tracing::warn!(%error, "unable to build machine identity for hibernate resume probe");
            return;
        }
    };

    let max_phys = boot_memory.max_physical_address();
    let machine_max_frames = max_phys.div_ceil(PhysFrame::SIZE as u64);
    let usable_frames = usable_physical_frame_runs(boot_memory);
    let protected_ranges = collect_boot_protected_ranges(boot_memory, pool, extra_protected);
    // 1 frame: Sv48 root table whose entry 0 is a 512 GiB RWX identity leaf.
    let table_pages = 1_usize;

    let cpu_for_storage = cpu.clone();
    let deadline = cpu
        .now()
        .ticks()
        .saturating_add(cpu.timebase().duration_to_ticks(POLLED_TIMEOUT));
    let mut storage = VirtioBlockHibernateStorage::new(hibernate_blk, move || {
        cpu_for_storage.now().ticks() >= deadline
    });

    let probe = probe_and_load_hibernate_image(
        &mut storage,
        debug_state.hibernate_auth_key(),
        &expected_identity,
        machine_max_frames,
        &usable_frames,
        &protected_ranges,
        table_pages,
        |dst_phys, frame_bytes| {
            // SAFETY: RISC-V identity-maps all physical RAM; `dst_phys` is
            // either a non-colliding final target frame or a safe displaced
            // frame outside every boot-kernel protected range.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    frame_bytes.as_ptr(),
                    core::ptr::with_exposed_provenance_mut::<u8>(dst_phys as usize),
                    PhysFrame::SIZE,
                );
            }
        },
        || watchdog.pet(),
    );

    let loaded = match probe {
        ResumeProbe::NoImage | ResumeProbe::Refused(_) => return,
        ResumeProbe::Ready(loaded) => loaded,
    };

    // Collect fresh per-boot handoff state BEFORE quiescing devices.
    let mut fresh_entropy = [0_u8; 32];
    root_entropy.fill(&mut fresh_entropy);
    let rtc_unix_nanos = rtc.and_then(|clock| {
        clock
            .read()
            .ok()
            .and_then(|secs| u64::try_from(secs.as_nanos()).ok())
    });
    let handoff = ResumeHandoff {
        image_id: loaded.header.image_id,
        fresh_entropy,
        rtc_unix_nanos,
        boot_monotonic_ticks: cpu.now().ticks(),
    };

    if let Err(error) = devices.quiesce_all() {
        tracing::error!(
            %error,
            "failed to quiesce boot-kernel devices before hibernate restore; continuing cold boot"
        );
        return;
    }

    tracing::info!(
        image_id = format_args!("{:032x}", u128::from_be_bytes(handoff.image_id)),
        direct_frames = loaded.plan.direct_frames,
        displaced_frames = loaded.plan.displaced_copies.len(),
        "entering RISC-V hibernate restore trampoline"
    );

    enter_restore_trampoline(&loaded, handoff)
}

/// BSP-pinned detached task serving guest `helios:system/snapshot.hibernate`
/// requests on RISC-V 64.
#[expect(
    clippy::too_many_arguments,
    reason = "BSP hibernate server takes explicit static-dispatch dependencies"
)]
pub(crate) async fn serve_hibernate_requests<WatchdogImpl>(
    cpu: RiscvCpu,
    handle: HibernateHandle<RiscvCpu, WatchdogImpl>,
    debug_state: crate::debug_state::RuntimeState,
    pool: &'static UserMemoryPool,
    mut devices: RiscvHibernateDevices,
    receiver: ProviderReceiver<HibernateRequest>,
    debug_serial: DebugSerialWriter,
    mirror_to_uart: bool,
) where
    WatchdogImpl: Watchdog + Clone,
{
    while let Some(request) = receiver.recv().await {
        let Some(hibernate_blk) = devices.hibernate_block.clone() else {
            request.respond(Err(HibernateRequestError::NoHibernateDisk));
            continue;
        };
        let feature_records = devices.feature_records();
        let machine = helios_kernel::machine_memory();
        let disk_bytes = hibernate_blk.geometry().capacity_bytes();
        let reservation_bytes = compute_hibernate_reservation_bytes(
            machine.usable_bytes,
            machine.free_bytes,
            disk_bytes,
        );
        let cpu_for_storage = cpu.clone();
        let deadline = cpu
            .now()
            .ticks()
            .saturating_add(cpu.timebase().duration_to_ticks(HIBERNATE_IO_TIMEOUT));
        let mut storage = VirtioBlockHibernateStorage::new(hibernate_blk, move || {
            cpu_for_storage.now().ticks() >= deadline
        });
        let program_service = debug_state.program_service();
        // SAFETY: `handle.boot_memory()` describes the running kernel's
        // immutable identity-mapped `.text` and `.rodata` sections.
        let outcome = unsafe {
            hibernate_machine_with_handle(
                &handle,
                &cpu,
                &debug_state,
                pool,
                &feature_records,
                reservation_bytes,
                HIBERNATE_FREEZE_DEADLINE,
                &mut storage,
                &mut devices,
                || {
                    if let Some(ref service) = program_service {
                        service.interrupt_running_guests();
                    }
                },
            )
            .await
        };
        match outcome {
            Ok(HibernateOutcome::Resumed) => {
                if !mirror_to_uart {
                    let generation = debug_state.machine_generation().current().get();
                    debug_serial.emit_fmt(format_args!(
                        "\nINFO helios_kernel::hibernate::storage: resumed from hibernate image generation={generation}\n"
                    ));
                }
                if request.defer_resume_marker() {
                    debug_state.arm_deferred_resume_marker();
                } else {
                    debug_serial.emit_stage_marker("resume:ok");
                }
                request.respond(Ok(HibernateOutcome::Resumed));
            }
            other => {
                request.respond(other.map_err(HibernateRequestError::from));
            }
        }
    }
}

fn find_hibernate_block_device(
    cpu: &RiscvCpu,
    blocks: &[RiscvVirtioBlockDevice],
) -> Option<RiscvVirtioBlockDevice> {
    let deadline = cpu
        .now()
        .ticks()
        .saturating_add(cpu.timebase().duration_to_ticks(POLLED_TIMEOUT));
    for block in blocks {
        match block.serial_polled(|| cpu.now().ticks() >= deadline) {
            Ok(serial) if serial.as_bytes() == HIBERNATE_DISK_SERIAL.as_bytes() => {
                return Some(block.clone());
            }
            Ok(_) => {}
            Err(error) => {
                tracing::warn!(
                    ?error,
                    "polled serial probe failed on virtio-blk during early-boot hibernate check"
                );
            }
        }
    }
    None
}

fn enter_restore_trampoline(loaded: &LoadedHibernateImage, handoff: ResumeHandoff) -> ! {
    let ctx = loaded
        .header
        .bsp_context
        .as_riscv64()
        .expect("verified hibernate header carries a RISC-V 64 BSP context");
    let plan = &loaded.plan;

    // 1. Copy the `DisplacedFrameCopy` array into its contiguous safe pages.
    let copy_table_phys = if plan.displaced_copies.is_empty() {
        0_u64
    } else {
        // SAFETY: `plan.copy_table_phys` holds `plan.copy_table_pages` contiguous
        // safe frames outside both boot-kernel memory and image targets.
        unsafe {
            core::ptr::copy_nonoverlapping(
                plan.displaced_copies.as_ptr(),
                core::ptr::with_exposed_provenance_mut::<DisplacedFrameCopy>(
                    plan.copy_table_phys as usize,
                ),
                plan.displaced_copies.len(),
            );
        }
        plan.copy_table_phys
    };

    // 2. Build a 1-page Sv48 root table mapping 0..512 GiB as an identity leaf.
    let trampoline_satp = build_trampoline_satp(plan.trampoline_table_frames[0]);

    // 3. Populate the safe trampoline page with `RiscvRestoreParams`,
    //    `ResumeHandoffWire`, and `Riscv64SnapshotContext`.
    let tramp_phys = plan.trampoline_phys as usize;
    // SAFETY: `plan.trampoline_phys` is a dedicated safe 4 KiB identity-mapped frame.
    unsafe {
        core::ptr::write_bytes(
            core::ptr::with_exposed_provenance_mut::<u8>(tramp_phys),
            0,
            PhysFrame::SIZE,
        );
    }

    let handoff_phys = plan.trampoline_phys + HANDOFF_PAGE_OFFSET as u64;
    let ctx_phys = plan.trampoline_phys + CTX_PAGE_OFFSET as u64;
    let stack_top_phys = plan.trampoline_phys + STACK_TOP_PAGE_OFFSET as u64;

    let params = RiscvRestoreParams {
        trampoline_satp,
        copy_table_phys,
        copy_count: plan.displaced_copies.len() as u64,
        stack_top_phys,
        handoff_phys,
        ctx_phys,
    };
    let wire = handoff.to_wire();

    // SAFETY: `tramp_phys` is 4 KiB aligned and exclusively owned on the safe
    // trampoline page; offsets are checked by compile-time assertions above.
    unsafe {
        core::ptr::write(
            core::ptr::with_exposed_provenance_mut::<RiscvRestoreParams>(tramp_phys),
            params,
        );
    }
    // SAFETY: `handoff_phys` lies at `HANDOFF_PAGE_OFFSET` on the safe trampoline page.
    unsafe {
        core::ptr::write(
            core::ptr::with_exposed_provenance_mut::<ResumeHandoffWire>(handoff_phys as usize),
            wire,
        );
    }
    // SAFETY: `ctx_phys` lies at `CTX_PAGE_OFFSET` on the safe trampoline page.
    unsafe {
        core::ptr::write(
            core::ptr::with_exposed_provenance_mut::<Riscv64SnapshotContext>(ctx_phys as usize),
            ctx,
        );
    }

    // SAFETY: all displaced frames are staged in disjoint safe frames, the
    // trampoline Sv48 root table lives in a safe frame, `params` sits on the
    // safe trampoline page, and interrupts are disabled.
    unsafe {
        __helios_riscv_restore_trampoline(core::ptr::with_exposed_provenance::<RiscvRestoreParams>(
            tramp_phys,
        ))
    }
}

/// Builds a 1-page Sv48 root page table in `root_phys` with entry 0 mapping
/// `0..512 GiB` as a RWX identity leaf (matching `riscv/src/vmm.rs`), and
/// returns the `satp` value selecting it.
fn build_trampoline_satp(root_phys: u64) -> u64 {
    const SATP_MODE_SV48: u64 = 9 << 60;
    const PTE_VALID: u64 = 1 << 0;
    const PTE_READ: u64 = 1 << 1;
    const PTE_WRITE: u64 = 1 << 2;
    const PTE_EXECUTE: u64 = 1 << 3;
    const PTE_ACCESSED: u64 = 1 << 6;
    const PTE_DIRTY: u64 = 1 << 7;

    let ptr = core::ptr::with_exposed_provenance_mut::<u64>(root_phys as usize);
    // SAFETY: `root_phys` is an exclusively owned safe 4 KiB frame.
    unsafe {
        core::ptr::write_bytes(ptr.cast::<u8>(), 0, PhysFrame::SIZE);
    }
    // Entry 0: PPN = 0, V | R | W | X | A | D (512 GiB identity superpage).
    let leaf = PTE_VALID | PTE_READ | PTE_WRITE | PTE_EXECUTE | PTE_ACCESSED | PTE_DIRTY;
    // SAFETY: index 0 is within the 512-entry Sv48 root table.
    unsafe {
        ptr.write(leaf);
    }
    SATP_MODE_SV48 | (root_phys >> 12)
}
