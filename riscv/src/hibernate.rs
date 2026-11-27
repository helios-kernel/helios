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
use core::arch::{global_asm, naked_asm};
use core::mem::{offset_of, size_of};
use core::ops::Range;
use core::time::Duration;

use helios_hal::boot::BootMemoryMetadata;
use helios_hal::cpu::{
    Cpu, DisplacedFrameCopy, ProcessorId, ResumeHandoff, ResumeHandoffWire, Riscv64SnapshotContext,
};
use helios_hal::fs::BlockDevice as _;
use helios_hal::pmm::PhysFrame;
use helios_hal::rtc::RealTimeClock;
use helios_hal::watchdog::Watchdog;
use helios_kernel::hibernate::{
    DeviceFeatureRecord, HIBERNATE_FREEZE_DEADLINE, HibernateDeviceController,
    HibernateDeviceError, HibernateOutcome, HibernateRequest, HibernateRequestError,
    LoadedHibernateImage, ResumeProbe, VirtioBlockHibernateStorage, build_machine_identity,
    collect_boot_protected_ranges, compute_hibernate_reservation_bytes, dram_physical_frame_runs,
    hibernate_machine_with_handle, probe_and_load_hibernate_image, usable_physical_frame_runs,
};
use helios_kernel::{
    DebugSerialWriter, HIBERNATE_DISK_SERIAL, HibernateHandle, Kernel, MachineGenerationHandle,
    ProviderReceiver, ResetDevice, RootEntropy, UserMemoryPool,
};
use helios_virtio::DeviceType;
use limine::mp::MpInfo;

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
    static __helios_riscv_restore_trampoline_enter_end: u8;
    fn __helios_riscv_restore_finish() -> !;
    static __helios_riscv_restore_finish_end: u8;
}

/// Polled I/O deadline for early-boot hibernate disk discovery, verification,
/// and device quiesce/reinitialization.
const POLLED_TIMEOUT: Duration = Duration::from_secs(30);

/// Polled I/O deadline for writing the compressed hibernate image and
/// invalidating its header on resume (generous for slow emulated targets).
const HIBERNATE_IO_TIMEOUT: Duration = Duration::from_secs(300);

/// Parameter block written at offset `0x000` of the safe 4 KiB trampoline page
/// (mapped in Boot 2's HHDM) before entering
/// [`__helios_riscv_restore_trampoline`].
#[repr(C)]
struct RiscvRestoreParams {
    trampoline_satp: u64,
    copy_table_virt: u64,
    copy_count: u64,
    direct_map_offset: u64,
    stack_top_virt: u64,
    handoff_phys: u64,
    ctx_virt: u64,
}

const HANDOFF_PAGE_OFFSET: usize = 0x80;
const CTX_PAGE_OFFSET: usize = 0x100;
const STACK_TOP_PAGE_OFFSET: usize = 0xff0;

const _: () = {
    assert!(offset_of!(RiscvRestoreParams, trampoline_satp) == 0x00);
    assert!(offset_of!(RiscvRestoreParams, copy_table_virt) == 0x08);
    assert!(offset_of!(RiscvRestoreParams, copy_count) == 0x10);
    assert!(offset_of!(RiscvRestoreParams, direct_map_offset) == 0x18);
    assert!(offset_of!(RiscvRestoreParams, stack_top_virt) == 0x20);
    assert!(offset_of!(RiscvRestoreParams, handoff_phys) == 0x28);
    assert!(offset_of!(RiscvRestoreParams, ctx_virt) == 0x30);
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
    // immutable higher-half `.text` and `.rodata` sections of this kernel.
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
    let dram_frames = dram_physical_frame_runs(boot_memory);
    let protected_ranges = collect_boot_protected_ranges(boot_memory, pool, extra_protected);
    let physical_memory_offset = crate::vmm::physical_memory_offset();
    // Up to 8 frames: L3 root + L2 HHDM table + L2/L1/L0 tables for `V_enter`
    // and `V_finish` (6 tables worst case if both span distinct L2/L1/L0s).
    let table_pages = 8_usize;

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
        &dram_frames,
        boot_memory.kernel_sections.image,
        &protected_ranges,
        table_pages,
        |src_phys, frame_bytes| {
            let src_virt = (src_phys as usize)
                .checked_add(physical_memory_offset)
                .expect("hibernate source physical frame overflows HHDM");
            // SAFETY: `src_phys` lies in Boot 2's immutable kernel image or
            // boot payload region, mapped readable through HHDM.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    core::ptr::with_exposed_provenance::<u8>(src_virt),
                    frame_bytes.as_mut_ptr(),
                    PhysFrame::SIZE,
                );
            }
        },
        |dst_phys, frame_bytes| {
            let dst_virt = (dst_phys as usize)
                .checked_add(physical_memory_offset)
                .expect("hibernate destination physical frame overflows HHDM");
            // SAFETY: `dst_phys` is either a non-colliding final target frame
            // or a safe displaced frame outside every boot-kernel protected
            // range, mapped writable through HHDM.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    frame_bytes.as_ptr(),
                    core::ptr::with_exposed_provenance_mut::<u8>(dst_virt),
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

    // Limine starts secondary harts and parks them in its bootloader-reclaimable
    // spin loop. Stop every secondary via SBI HSM `hart_stop` before overwriting
    // memory so none executes overwritten Limine pages and post-resume
    // `restart_processor` sees every secondary cleanly `STOPPED`.
    if cpu.processor_count() > 1 {
        stop_limine_secondaries(cpu);
    }

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
        relocated_frames = loaded.plan.relocated_placements.len(),
        "entering RISC-V hibernate restore trampoline"
    );

    enter_restore_trampoline(&loaded, handoff, boot_memory, physical_memory_offset)
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

/// Sends every Limine-parked secondary hart into SBI HSM `hart_stop` and waits
/// until firmware reports each secondary `STOPPED`.
fn stop_limine_secondaries(cpu: &RiscvCpu) {
    let bsp = cpu.bootstrap_processor();
    for id in 0..cpu.processor_count() {
        let hart = ProcessorId::new(id as u16);
        if hart == bsp {
            continue;
        }
        let mp_info = crate::mp_info_for_hart(hart);
        mp_info.bootstrap(limine_secondary_stop_entry, 0);
    }
    for id in 0..cpu.processor_count() {
        let hart = ProcessorId::new(id as u16);
        if hart == bsp {
            continue;
        }
        while crate::hart_status(hart) != sbi_spec::hsm::hart_state::STOPPED {
            core::hint::spin_loop();
        }
    }
}

#[unsafe(naked)]
unsafe extern "C" fn limine_secondary_stop_entry(_mp_info: &MpInfo) -> ! {
    naked_asm!(
        "csrci sstatus, 0x2",
        "csrw sie, zero",
        ".option push",
        ".option norelax",
        "la gp, __global_pointer$",
        ".option pop",
        ".option push",
        ".option arch, +f",
        "li t0, 0x4000",
        "csrc sstatus, t0",
        "li t0, 0x2000",
        "csrs sstatus, t0",
        "fscsr x0",
        ".option pop",
        "tail {stop_main}",
        stop_main = sym limine_secondary_stop_main,
    )
}

extern "C" fn limine_secondary_stop_main() -> ! {
    let ret = sbi_rt::hart_stop();
    panic!(
        "SBI HSM refused to stop Limine secondary hart before hibernate restore: error={} value={}",
        ret.error, ret.value
    );
}

fn enter_restore_trampoline(
    loaded: &LoadedHibernateImage,
    handoff: ResumeHandoff,
    boot_memory: &BootMemoryMetadata,
    physical_memory_offset: usize,
) -> ! {
    let ctx = loaded
        .header
        .bsp_context
        .as_riscv64()
        .expect("verified hibernate header carries a RISC-V 64 BSP context");
    let plan = &loaded.plan;

    // 1. Copy the `DisplacedFrameCopy` array into its contiguous safe pages.
    let copy_table_virt = if plan.displaced_copies.is_empty() {
        0_u64
    } else {
        let virt = (plan.copy_table_phys as usize)
            .checked_add(physical_memory_offset)
            .expect("copy table address overflows HHDM");
        // SAFETY: `plan.copy_table_phys` holds `plan.copy_table_pages` contiguous
        // safe frames outside both boot-kernel memory and image targets.
        unsafe {
            core::ptr::copy_nonoverlapping(
                plan.displaced_copies.as_ptr(),
                core::ptr::with_exposed_provenance_mut::<DisplacedFrameCopy>(virt),
                plan.displaced_copies.len(),
            );
        }
        virt as u64
    };

    // 2. Stage a safe copy of `V_enter` into `plan.trampoline_enter_copy_phys`
    //    and build the self-contained Sv48 trampoline table mapping HHDM,
    //    `V_enter -> enter_copy_phys`, and `V_finish -> image_finish_phys`.
    let enter_virt = __helios_riscv_restore_trampoline as *const () as usize;
    let enter_end = &raw const __helios_riscv_restore_trampoline_enter_end as usize;
    let finish_virt = __helios_riscv_restore_finish as *const () as usize;
    let finish_end = &raw const __helios_riscv_restore_finish_end as usize;
    assert!(
        enter_virt.is_multiple_of(PhysFrame::SIZE),
        "RISC-V restore trampoline entry is not page-aligned"
    );
    assert!(
        finish_virt.is_multiple_of(PhysFrame::SIZE),
        "RISC-V restore trampoline finish is not page-aligned"
    );
    assert!(
        enter_end > enter_virt && enter_end - enter_virt <= PhysFrame::SIZE,
        "RISC-V restore trampoline entry exceeds one 4 KiB page"
    );
    assert!(
        finish_end > finish_virt && finish_end - finish_virt <= PhysFrame::SIZE,
        "RISC-V restore trampoline finish exceeds one 4 KiB page"
    );
    assert_ne!(
        enter_virt, finish_virt,
        "RISC-V restore trampoline entry and finish must occupy distinct pages"
    );

    let enter_copy_virt = (plan.trampoline_enter_copy_phys as usize)
        .checked_add(physical_memory_offset)
        .expect("trampoline entry copy address overflows HHDM");
    // SAFETY: `enter_virt` is a mapped readable 4 KiB `.text` page of the
    // running kernel and `enter_copy_virt` is an exclusively owned safe 4 KiB
    // frame mapped writable in HHDM.
    unsafe {
        core::ptr::copy_nonoverlapping(
            core::ptr::with_exposed_provenance::<u8>(enter_virt),
            core::ptr::with_exposed_provenance_mut::<u8>(enter_copy_virt),
            PhysFrame::SIZE,
        );
    }

    let offset_in_text = (finish_virt as u64)
        .checked_sub(loaded.header.identity.kernel_text_virt_start)
        .expect("RISC-V restore finish lies outside kernel .text");
    let image_finish_phys = loaded.header.identity.kernel_text_phys_start + offset_in_text;
    assert!(
        image_finish_phys.is_multiple_of(PhysFrame::SIZE as u64),
        "image restore finish physical address is not page-aligned"
    );

    let trampoline_satp = build_trampoline_satp(
        &plan.trampoline_table_frames,
        boot_memory,
        physical_memory_offset,
        enter_virt,
        plan.trampoline_enter_copy_phys,
        finish_virt,
        image_finish_phys,
    );

    // 3. Populate the safe trampoline page with `RiscvRestoreParams`,
    //    `ResumeHandoffWire`, and `Riscv64SnapshotContext`.
    let tramp_virt = (plan.trampoline_phys as usize)
        .checked_add(physical_memory_offset)
        .expect("trampoline page address overflows HHDM");
    // SAFETY: `plan.trampoline_phys` is a dedicated safe 4 KiB frame mapped in HHDM.
    unsafe {
        core::ptr::write_bytes(
            core::ptr::with_exposed_provenance_mut::<u8>(tramp_virt),
            0,
            PhysFrame::SIZE,
        );
    }

    let handoff_phys = plan.trampoline_phys + HANDOFF_PAGE_OFFSET as u64;
    let handoff_virt = tramp_virt + HANDOFF_PAGE_OFFSET;
    let ctx_virt = tramp_virt + CTX_PAGE_OFFSET;
    let stack_top_virt = tramp_virt + STACK_TOP_PAGE_OFFSET;

    let params = RiscvRestoreParams {
        trampoline_satp,
        copy_table_virt,
        copy_count: plan.displaced_copies.len() as u64,
        direct_map_offset: physical_memory_offset as u64,
        stack_top_virt: stack_top_virt as u64,
        handoff_phys,
        ctx_virt: ctx_virt as u64,
    };
    let wire = handoff.to_wire();

    // SAFETY: `tramp_virt` is 4 KiB aligned and exclusively owned on the safe
    // trampoline page; offsets are checked by compile-time assertions above.
    unsafe {
        core::ptr::write(
            core::ptr::with_exposed_provenance_mut::<RiscvRestoreParams>(tramp_virt),
            params,
        );
    }
    // SAFETY: `handoff_virt` lies at `HANDOFF_PAGE_OFFSET` on the safe trampoline page.
    unsafe {
        core::ptr::write(
            core::ptr::with_exposed_provenance_mut::<ResumeHandoffWire>(handoff_virt),
            wire,
        );
    }
    // SAFETY: `ctx_virt` lies at `CTX_PAGE_OFFSET` on the safe trampoline page.
    unsafe {
        core::ptr::write(
            core::ptr::with_exposed_provenance_mut::<Riscv64SnapshotContext>(ctx_virt),
            ctx,
        );
    }

    // Order all writes to `trampoline_enter_copy_phys` and page tables before
    // entering the trampoline.
    // SAFETY: `fence rw, rw; fence.i` orders memory stores and instruction fetch.
    unsafe {
        core::arch::asm!("fence rw, rw", "fence.i", options(nostack, preserves_flags));
    }

    // SAFETY: all displaced frames are staged in disjoint safe frames, the
    // trampoline Sv48 page tables live in safe frames, `params` sits on the
    // safe trampoline page, all Limine secondaries are stopped, and interrupts
    // are disabled.
    unsafe {
        __helios_riscv_restore_trampoline(core::ptr::with_exposed_provenance::<RiscvRestoreParams>(
            tramp_virt,
        ))
    }
}

/// Builds a self-contained Sv48 page table in `table_frames` (up to 8 frames)
/// mapping:
/// - `0..max_phys` at `physical_memory_offset + phys` using 1 GiB leaves (RW),
/// - `enter_virt` (`V_enter`) -> `enter_copy_phys` (RX), and
/// - `finish_virt` (`V_finish`) -> `image_finish_phys` (RX, matching Boot 1).
fn build_trampoline_satp(
    table_frames: &[u64],
    boot_memory: &BootMemoryMetadata,
    physical_memory_offset: usize,
    enter_virt: usize,
    enter_copy_phys: u64,
    finish_virt: usize,
    image_finish_phys: u64,
) -> u64 {
    const SATP_MODE_SV48: u64 = 9 << 60;
    const PTE_VALID: u64 = 1 << 0;
    const PTE_READ: u64 = 1 << 1;
    const PTE_WRITE: u64 = 1 << 2;
    const PTE_EXECUTE: u64 = 1 << 3;
    const PTE_ACCESSED: u64 = 1 << 6;
    const PTE_DIRTY: u64 = 1 << 7;
    const PTE_PPN_SHIFT: u32 = 10;
    const GIB: u64 = 1 << 30;

    let mut next_frame = 0_usize;
    let mut alloc_table = || -> u64 {
        let phys = table_frames[next_frame];
        next_frame += 1;
        let virt = (phys as usize)
            .checked_add(physical_memory_offset)
            .expect("trampoline table frame overflows HHDM");
        // SAFETY: `phys` is an exclusively owned safe 4 KiB frame mapped in HHDM.
        unsafe {
            core::ptr::write_bytes(
                core::ptr::with_exposed_provenance_mut::<u8>(virt),
                0,
                PhysFrame::SIZE,
            );
        }
        phys
    };
    let table_at = |phys: u64| -> &mut [u64; 512] {
        let virt = (phys as usize)
            .checked_add(physical_memory_offset)
            .expect("trampoline table frame overflows HHDM");
        // SAFETY: `phys` is one of the disjoint, page-aligned 4 KiB frames in
        // `table_frames`, zero-initialized and exclusively owned by this builder.
        unsafe { &mut *core::ptr::with_exposed_provenance_mut::<[u64; 512]>(virt) }
    };

    let l3_phys = alloc_table();

    // 1. Map all physical RAM at HHDM with 1 GiB RW leaves.
    let max_phys = boot_memory.max_physical_address().max(GIB);
    let gib_count = max_phys.div_ceil(GIB).min(512) as usize;
    let hhdm_l2_phys = alloc_table();
    let hhdm_l3_idx = (physical_memory_offset >> 39) & 0x1ff;
    table_at(l3_phys)[hhdm_l3_idx] = ((hhdm_l2_phys >> 12) << PTE_PPN_SHIFT) | PTE_VALID;
    let hhdm_l2_base = (physical_memory_offset >> 30) & 0x1ff;
    let hhdm_l2 = table_at(hhdm_l2_phys);
    for g in 0..gib_count {
        let l2_idx = hhdm_l2_base + g;
        assert!(l2_idx < 512, "HHDM exceeds one L2 table during restore");
        let phys = (g as u64) * GIB;
        hhdm_l2[l2_idx] = ((phys >> 12) << PTE_PPN_SHIFT)
            | PTE_VALID
            | PTE_READ
            | PTE_WRITE
            | PTE_ACCESSED
            | PTE_DIRTY;
    }

    // 2. Map `V_enter -> enter_copy_phys` and `V_finish -> image_finish_phys` (RX).
    for (virt, phys) in [
        (enter_virt, enter_copy_phys),
        (finish_virt, image_finish_phys),
    ] {
        let i3 = (virt >> 39) & 0x1ff;
        let i2 = (virt >> 30) & 0x1ff;
        let i1 = (virt >> 21) & 0x1ff;
        let i0 = (virt >> 12) & 0x1ff;

        let l3_entry = table_at(l3_phys)[i3];
        let l2_phys = if l3_entry & PTE_VALID != 0 {
            (l3_entry >> PTE_PPN_SHIFT) << 12
        } else {
            let fresh = alloc_table();
            table_at(l3_phys)[i3] = ((fresh >> 12) << PTE_PPN_SHIFT) | PTE_VALID;
            fresh
        };
        let l2_entry = table_at(l2_phys)[i2];
        let l1_phys = if l2_entry & PTE_VALID != 0 {
            (l2_entry >> PTE_PPN_SHIFT) << 12
        } else {
            let fresh = alloc_table();
            table_at(l2_phys)[i2] = ((fresh >> 12) << PTE_PPN_SHIFT) | PTE_VALID;
            fresh
        };
        let l1_entry = table_at(l1_phys)[i1];
        let l0_phys = if l1_entry & PTE_VALID != 0 {
            (l1_entry >> PTE_PPN_SHIFT) << 12
        } else {
            let fresh = alloc_table();
            table_at(l1_phys)[i1] = ((fresh >> 12) << PTE_PPN_SHIFT) | PTE_VALID;
            fresh
        };
        table_at(l0_phys)[i0] =
            ((phys >> 12) << PTE_PPN_SHIFT) | PTE_VALID | PTE_READ | PTE_EXECUTE | PTE_ACCESSED;
    }

    SATP_MODE_SV48 | (l3_phys >> 12)
}
