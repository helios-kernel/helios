//! AArch64 hibernate device registry, early-boot resume probe, and restore
//! trampoline handoff.
//!
//! # Ordering contract
//!
//! - [`Aarch64HibernateDevices::quiesce_all`] quiesces every DMA-capable
//!   endpoint device BEFORE quiescing `virtio-iommu`.
//! - [`Aarch64HibernateDevices::reinitialize_iommu`] reinitializes
//!   `virtio-iommu` alone (when present) before the hibernate block device
//!   writes the snapshot to disk.
//! - [`Aarch64HibernateDevices::reinitialize_all`] MUST reinitialize
//!   `virtio-iommu` FIRST (when present) before any other virtio device calls
//!   `reinitialize()`, so every DMA domain and IOVA mapping is restored before
//!   any endpoint resumes DMA (and records resets for host-share and
//!   memory-balloon devices).

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::arch::{asm, global_asm, naked_asm};
use core::mem::{offset_of, size_of};
use core::ops::Range;
use core::time::Duration;

use helios_hal::boot::BootMemoryMetadata;
use helios_hal::cpu::{
    Aarch64SnapshotContext, Cpu, DisplacedFrameCopy, ProcessorId, ResumeHandoff, ResumeHandoffWire,
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

use crate::Aarch64Cpu;
use crate::balloon::Aarch64VirtioBalloonDevice;
use crate::block::Aarch64VirtioBlockDevice;
use crate::entropy::Aarch64VirtioRngDevice;
use crate::gpu::Aarch64VirtioGpuDevice;
use crate::host_fs::HostFsTransportService;
use crate::input::Aarch64VirtioInputDevice;
use crate::iommu::Aarch64VirtioIommuDevice;
use crate::net::Aarch64VirtioNetDevice;
use crate::platform::PsciConduit;
use crate::rtc::Pl031Rtc;
use crate::snd::Aarch64VirtioSndDevice;
use crate::vsock::Aarch64VirtioVsockDevice;

#[cfg(target_os = "none")]
global_asm!(include_str!("restore.S"));

unsafe extern "C" {
    fn __helios_aarch64_restore_trampoline(params: *const Aarch64RestoreParams) -> !;
    static __helios_aarch64_restore_trampoline_enter_end: u8;
    fn __helios_aarch64_restore_finish() -> !;
    static __helios_aarch64_restore_finish_end: u8;
}

/// Polled I/O deadline for early-boot hibernate disk discovery, verification,
/// and device quiesce/reinitialization.
const POLLED_TIMEOUT: Duration = Duration::from_secs(30);

/// Polled I/O deadline for writing the compressed hibernate image and
/// invalidating its header on resume (generous for slow emulated targets).
const HIBERNATE_IO_TIMEOUT: Duration = Duration::from_secs(300);

/// Parameter block written at offset `0x000` of the safe 4 KiB trampoline page
/// (`trampoline_phys + direct_map_offset`) before entering
/// [`__helios_aarch64_restore_trampoline`].
#[repr(C)]
struct Aarch64RestoreParams {
    trampoline_ttbr1: u64,
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
    assert!(offset_of!(Aarch64RestoreParams, trampoline_ttbr1) == 0x00);
    assert!(offset_of!(Aarch64RestoreParams, copy_table_virt) == 0x08);
    assert!(offset_of!(Aarch64RestoreParams, copy_count) == 0x10);
    assert!(offset_of!(Aarch64RestoreParams, direct_map_offset) == 0x18);
    assert!(offset_of!(Aarch64RestoreParams, stack_top_virt) == 0x20);
    assert!(offset_of!(Aarch64RestoreParams, handoff_phys) == 0x28);
    assert!(offset_of!(Aarch64RestoreParams, ctx_virt) == 0x30);
    assert!(size_of::<Aarch64RestoreParams>() <= HANDOFF_PAGE_OFFSET);
    assert!(HANDOFF_PAGE_OFFSET + size_of::<ResumeHandoffWire>() <= CTX_PAGE_OFFSET);
    assert!(CTX_PAGE_OFFSET + size_of::<Aarch64SnapshotContext>() <= 0x280);
    assert!(offset_of!(Aarch64SnapshotContext, tpidr_el1) == 0xb0);
    assert!(offset_of!(Aarch64SnapshotContext, sp_el0) == 0xb8);
    assert!(offset_of!(Aarch64SnapshotContext, ttbr0_el1) == 0xc0);
    assert!(offset_of!(Aarch64SnapshotContext, ttbr1_el1) == 0xc8);
    assert!(offset_of!(Aarch64SnapshotContext, mair_el1) == 0xd0);
    assert!(offset_of!(Aarch64SnapshotContext, tcr_el1) == 0xd8);
    assert!(offset_of!(Aarch64SnapshotContext, sctlr_el1) == 0xe0);
    assert!(offset_of!(Aarch64SnapshotContext, vbar_el1) == 0xe8);
    assert!(offset_of!(Aarch64SnapshotContext, cpacr_el1) == 0xf0);
    assert!(offset_of!(Aarch64SnapshotContext, daif) == 0xf8);
    assert!(offset_of!(Aarch64SnapshotContext, apia_lo) == 0x100);
    assert!(offset_of!(Aarch64SnapshotContext, apia_hi) == 0x108);
    assert!(offset_of!(Aarch64SnapshotContext, mte_enabled) == 0x110);
    assert!(offset_of!(Aarch64SnapshotContext, gcr_el1) == 0x118);
    assert!(offset_of!(Aarch64SnapshotContext, rgsr_el1) == 0x120);
};

/// Static-dispatch registry of every live AArch64 virtio device brought up at
/// boot, holding `virtio-iommu` first so [`HibernateDeviceController`] enforces
/// the IOMMU-first reinitialization invariant.
#[derive(Clone)]
pub(crate) struct Aarch64HibernateDevices {
    cpu: Aarch64Cpu,
    generation: MachineGenerationHandle,
    pub(crate) iommu: Option<Arc<Aarch64VirtioIommuDevice>>,
    pub(crate) host_fs: Option<HostFsTransportService>,
    pub(crate) network: Option<triomphe::Arc<Aarch64VirtioNetDevice>>,
    pub(crate) entropy: Option<triomphe::Arc<Aarch64VirtioRngDevice>>,
    pub(crate) balloon: Option<Arc<Aarch64VirtioBalloonDevice>>,
    pub(crate) vsock: Option<Arc<Aarch64VirtioVsockDevice>>,
    pub(crate) display: Option<Arc<Aarch64VirtioGpuDevice>>,
    pub(crate) inputs: Vec<Arc<Aarch64VirtioInputDevice>>,
    pub(crate) sound: Option<Arc<Aarch64VirtioSndDevice>>,
    pub(crate) blocks: Vec<Aarch64VirtioBlockDevice>,
    pub(crate) hibernate_block: Option<Aarch64VirtioBlockDevice>,
}

impl Aarch64HibernateDevices {
    pub(crate) fn new(cpu: Aarch64Cpu, generation: MachineGenerationHandle) -> Self {
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

impl HibernateDeviceController for Aarch64HibernateDevices {
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
/// (with interrupts still masked, before starting secondary processors or
/// launching `init`).
#[expect(
    clippy::too_many_arguments,
    reason = "early-boot resume probe receives explicit static-dispatch boot dependencies"
)]
pub(crate) fn probe_and_resume_if_present<WatchdogImpl, MeasuredBootImpl>(
    cpu: &Aarch64Cpu,
    kernel: &Kernel<Aarch64Cpu, WatchdogImpl, MeasuredBootImpl>,
    debug_state: &crate::debug_state::RuntimeState,
    pool: &UserMemoryPool,
    root_entropy: &RootEntropy,
    rtc: Option<&Pl031Rtc>,
    devices: &mut Aarch64HibernateDevices,
    physical_memory_offset: usize,
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
    // immutable mapped `.text` and `.rodata` sections of this running kernel.
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
    // 8 frames: L0 + HHDM L1 (1 GiB blocks up to 512 GiB) + up to 3 tables for
    // `V_enter` + up to 3 tables for `V_finish`.
    let table_pages = 8_usize;

    let cpu_for_storage = *cpu;
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
                .expect("hibernate relocation source overflows HHDM");
            // SAFETY: `src_phys` lies in Boot 2's immutable kernel image or
            // boot payload region, mapped readable in the HHDM.
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
                .expect("hibernate restore destination overflows HHDM");
            // SAFETY: `dst_phys` is either a non-colliding final target frame
            // or a safe displaced frame allocated from `usable_frames` outside
            // every boot-kernel protected range, mapped writable in the HHDM.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    frame_bytes.as_ptr(),
                    core::ptr::with_exposed_provenance_mut::<u8>(dst_virt),
                    PhysFrame::SIZE,
                );
            }
        },
        || {},
    );

    let loaded = match probe {
        ResumeProbe::NoImage | ResumeProbe::Refused(_) => return,
        ResumeProbe::Ready(loaded) => loaded,
    };

    // On AArch64, Limine starts secondary CPUs and parks them in its own
    // bootloader-reclaimable spin loop. Power every secondary off via PSCI
    // before overwriting memory so none executes overwritten Limine pages and
    // post-resume `PSCI CPU_ON` succeeds cleanly.
    if cpu.processor_count() > 1 {
        let Some(psci) = cpu.state.psci_optional() else {
            tracing::error!(
                "cannot resume multi-core AArch64 hibernate image without PSCI; continuing cold boot"
            );
            return;
        };
        power_off_limine_secondaries(cpu, psci);
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
        "entering AArch64 hibernate restore trampoline"
    );

    enter_restore_trampoline(
        &loaded,
        handoff,
        boot_memory,
        physical_memory_offset,
        cpu.state.control_flow_integrity.branch_targets_identified,
    )
}

/// BSP-pinned detached task serving guest `helios:system/snapshot.hibernate`
/// requests on AArch64.
pub(crate) async fn serve_hibernate_requests<WatchdogImpl>(
    cpu: Aarch64Cpu,
    handle: HibernateHandle<Aarch64Cpu, WatchdogImpl>,
    debug_state: crate::debug_state::RuntimeState,
    pool: &'static UserMemoryPool,
    mut devices: Aarch64HibernateDevices,
    receiver: ProviderReceiver<HibernateRequest>,
    debug_serial: DebugSerialWriter,
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
        let cpu_for_storage = cpu;
        let deadline = cpu
            .now()
            .ticks()
            .saturating_add(cpu.timebase().duration_to_ticks(HIBERNATE_IO_TIMEOUT));
        let mut storage = VirtioBlockHibernateStorage::new(hibernate_blk, move || {
            cpu_for_storage.now().ticks() >= deadline
        });
        let program_service = debug_state.program_service();
        // SAFETY: `handle.boot_memory()` describes the running kernel's
        // immutable mapped `.text` and `.rodata` sections.
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
    cpu: &Aarch64Cpu,
    blocks: &[Aarch64VirtioBlockDevice],
) -> Option<Aarch64VirtioBlockDevice> {
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

/// Sends every Limine-parked secondary CPU into `PSCI CPU_OFF` and waits for
/// firmware `AFFINITY_INFO` to report each secondary `Off`.
fn power_off_limine_secondaries(cpu: &Aarch64Cpu, psci: crate::lifecycle::Psci) {
    let conduit = psci.conduit() as u64;
    for id in 1..cpu.processor_count() {
        let slot = cpu.state.processor_slot(ProcessorId::new(id as u16));
        slot.mp_info
            .bootstrap(limine_secondary_power_off_entry, conduit);
    }
    for id in 1..cpu.processor_count() {
        let slot = cpu.state.processor_slot(ProcessorId::new(id as u16));
        psci.wait_affinity_off(slot.mp_info.mpidr, cpu.timebase());
    }
}

#[unsafe(naked)]
unsafe extern "C" fn limine_secondary_power_off_entry(mp_info: &MpInfo) -> ! {
    naked_asm!(
        "hint #38",
        "msr daifset, #0xf",
        "mov x9, sp",
        "msr spsel, #1",
        "mov sp, x9",
        "b {power_off}",
        power_off = sym limine_secondary_power_off_main,
    )
}

unsafe extern "C" fn limine_secondary_power_off_main(mp_info: &MpInfo) -> ! {
    let conduit = if mp_info.extra_argument() == PsciConduit::Hvc as u64 {
        PsciConduit::Hvc
    } else {
        PsciConduit::Smc
    };
    crate::lifecycle::Psci::cpu_off_current(conduit)
}

/// Cleans the data cache to Point of Unification across one 4 KiB page at
/// `virt` so instruction fetches after `ic iallu` observe freshly copied code.
fn clean_dcache_pou_page(virt: usize) {
    let ctr: u64;
    // SAFETY: reading `CTR_EL0` at EL1 has no side effects.
    unsafe {
        asm!("mrs {ctr}, ctr_el0", ctr = out(reg) ctr, options(nomem, nostack, preserves_flags));
    }
    let dminline = 4_usize << ((ctr >> 16) & 0xf);
    let mut addr = virt;
    let end = virt + PhysFrame::SIZE;
    while addr < end {
        // SAFETY: `addr` lies within a mapped Normal WB 4 KiB frame in HHDM.
        unsafe {
            asm!("dc cvau, {addr}", addr = in(reg) addr, options(nostack, preserves_flags));
        }
        addr += dminline;
    }
}

fn enter_restore_trampoline(
    loaded: &LoadedHibernateImage,
    handoff: ResumeHandoff,
    boot_memory: &BootMemoryMetadata,
    physical_memory_offset: usize,
    bti_enabled: bool,
) -> ! {
    let ctx = loaded
        .header
        .bsp_context
        .as_aarch64()
        .expect("verified hibernate header carries an AArch64 BSP context");
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

    // 2. Stage a safe copy of `V_enter` into `plan.trampoline_enter_copy_phys`,
    //    clean D-cache to PoU on `trampoline_enter_copy_phys` and every
    //    direct-placed relocated frame, and build the self-contained TTBR1
    //    table mapping `V_enter -> enter_copy_phys` and
    //    `V_finish -> image_finish_phys`.
    let enter_virt = __helios_aarch64_restore_trampoline as *const () as usize;
    let enter_end = &raw const __helios_aarch64_restore_trampoline_enter_end as usize;
    let finish_virt = __helios_aarch64_restore_finish as *const () as usize;
    let finish_end = &raw const __helios_aarch64_restore_finish_end as usize;
    assert!(
        enter_virt.is_multiple_of(PhysFrame::SIZE),
        "AArch64 restore trampoline entry is not page-aligned"
    );
    assert!(
        finish_virt.is_multiple_of(PhysFrame::SIZE),
        "AArch64 restore trampoline finish is not page-aligned"
    );
    assert!(
        enter_end > enter_virt && enter_end - enter_virt <= PhysFrame::SIZE,
        "AArch64 restore trampoline entry exceeds one 4 KiB page"
    );
    assert!(
        finish_end > finish_virt && finish_end - finish_virt <= PhysFrame::SIZE,
        "AArch64 restore trampoline finish exceeds one 4 KiB page"
    );
    assert_ne!(
        enter_virt, finish_virt,
        "AArch64 restore trampoline entry and finish must occupy distinct pages"
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
    clean_dcache_pou_page(enter_copy_virt);

    for reloc in &plan.relocated_placements {
        if reloc.staging_phys == reloc.dst_phys {
            let dst_virt = (reloc.dst_phys as usize)
                .checked_add(physical_memory_offset)
                .expect("direct relocated frame overflows HHDM");
            clean_dcache_pou_page(dst_virt);
        }
    }

    let offset_in_text = (finish_virt as u64)
        .checked_sub(loaded.header.identity.kernel_text_virt_start)
        .expect("AArch64 restore finish lies outside kernel .text");
    let image_finish_phys = loaded.header.identity.kernel_text_phys_start + offset_in_text;
    assert!(
        image_finish_phys.is_multiple_of(PhysFrame::SIZE as u64),
        "image restore finish physical address is not page-aligned"
    );

    let trampoline_ttbr1 = build_trampoline_page_tables(
        &plan.trampoline_table_frames,
        boot_memory,
        physical_memory_offset,
        bti_enabled,
        enter_virt,
        plan.trampoline_enter_copy_phys,
        finish_virt,
        image_finish_phys,
    );

    // 3. Populate the safe trampoline page with `Aarch64RestoreParams`,
    //    `ResumeHandoffWire`, and `Aarch64SnapshotContext`.
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

    let params = Aarch64RestoreParams {
        trampoline_ttbr1,
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
            core::ptr::with_exposed_provenance_mut::<Aarch64RestoreParams>(tramp_virt),
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
            core::ptr::with_exposed_provenance_mut::<Aarch64SnapshotContext>(ctx_virt),
            ctx,
        );
    }

    // Ensure all direct-placed image frames, `trampoline_enter_copy_phys`, and
    // trampoline structures are coherent with instruction fetch before
    // entering the trampoline.
    // SAFETY: `dsb ish; ic iallu; dsb ish; isb` orders all preceding writes
    // and invalidates any stale I-cache lines for `trampoline_enter_copy_phys`.
    unsafe {
        asm!(
            "dsb ish",
            "ic iallu",
            "dsb ish",
            "isb",
            options(nostack, preserves_flags)
        );
    }

    // SAFETY: all displaced frames are staged in disjoint safe frames, the
    // trampoline page tables live in safe frames, `params` sits on the safe
    // trampoline page, all Limine secondaries are powered off, and interrupts
    // are masked.
    unsafe {
        __helios_aarch64_restore_trampoline(core::ptr::with_exposed_provenance::<
            Aarch64RestoreParams,
        >(tramp_virt))
    }
}

/// Builds a self-contained AArch64 4-level TTBR1 page table in `table_frames`
/// (up to 8 frames) mapping:
/// - `0..max_phys` at `physical_memory_offset + phys` using 1 GiB blocks (RW, PXN, UXN),
/// - `enter_virt` (`V_enter`) -> `enter_copy_phys` (RX, `GP` if BTI), and
/// - `finish_virt` (`V_finish`) -> `image_finish_phys` (RX, `GP` if BTI,
///   matching Boot 1's saved `ctx.ttbr1_el1`).
#[expect(
    clippy::too_many_arguments,
    reason = "page-table builder takes explicit physical/virtual trampoline mappings"
)]
fn build_trampoline_page_tables(
    table_frames: &[u64],
    boot_memory: &BootMemoryMetadata,
    physical_memory_offset: usize,
    bti_enabled: bool,
    enter_virt: usize,
    enter_copy_phys: u64,
    finish_virt: usize,
    image_finish_phys: u64,
) -> u64 {
    const TABLE_DESC: u64 = 0b11;
    const BLOCK_DESC: u64 = 0b01;
    const PAGE_DESC: u64 = 0b11;
    const AF: u64 = 1 << 10;
    const SH_INNER: u64 = 0b11 << 8;
    const AP_KERNEL_RO: u64 = 0b10 << 6;
    const GP: u64 = 1 << 50;
    const PXN: u64 = 1 << 53;
    const UXN: u64 = 1 << 54;
    const ADDR_MASK: u64 = 0x0000_ffff_ffff_f000;
    const GIB: u64 = 1 << 30;

    let mair: u64;
    // SAFETY: reading `MAIR_EL1` at EL1 has no side effects.
    unsafe {
        asm!("mrs {mair}, mair_el1", mair = out(reg) mair, options(nomem, nostack, preserves_flags));
    }
    let wb_attr_idx = (0..8u64)
        .find(|index| (mair >> (index * 8)) & 0xff == 0xff)
        .unwrap_or(0);
    let attr_field = wb_attr_idx << 2;

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

    let l0_phys = alloc_table();

    // 1. Map all physical RAM at HHDM with 1 GiB blocks (Normal WB, RW, PXN, UXN).
    let max_phys = boot_memory.max_physical_address().max(GIB);
    let gib_count = max_phys.div_ceil(GIB).min(512) as usize;
    let hhdm_l1_phys = alloc_table();
    let hhdm_l0_idx = (physical_memory_offset >> 39) & 0x1ff;
    table_at(l0_phys)[hhdm_l0_idx] = hhdm_l1_phys | TABLE_DESC;
    let hhdm_l1_base = (physical_memory_offset >> 30) & 0x1ff;
    let hhdm_l1 = table_at(hhdm_l1_phys);
    for g in 0..gib_count {
        let l1_idx = hhdm_l1_base + g;
        assert!(l1_idx < 512, "HHDM exceeds one L1 table during restore");
        let phys = (g as u64) * GIB;
        hhdm_l1[l1_idx] = phys | BLOCK_DESC | attr_field | SH_INNER | AF | PXN | UXN;
    }

    // 2. Map `V_enter` -> `enter_copy_phys` and `V_finish` ->
    //    `image_finish_phys` (Normal WB, RO, executable, GP if BTI).
    let gp_bit = if bti_enabled { GP } else { 0 };
    for (virt, phys) in [
        (enter_virt, enter_copy_phys),
        (finish_virt, image_finish_phys),
    ] {
        let i0 = (virt >> 39) & 0x1ff;
        let i1 = (virt >> 30) & 0x1ff;
        let i2 = (virt >> 21) & 0x1ff;
        let i3 = (virt >> 12) & 0x1ff;

        let l0_entry = table_at(l0_phys)[i0];
        let l1_phys = if l0_entry & 0b11 == TABLE_DESC {
            l0_entry & ADDR_MASK
        } else {
            let p = alloc_table();
            table_at(l0_phys)[i0] = p | TABLE_DESC;
            p
        };
        let l1_entry = table_at(l1_phys)[i1];
        let l2_phys = if l1_entry & 0b11 == TABLE_DESC {
            l1_entry & ADDR_MASK
        } else {
            let p = alloc_table();
            table_at(l1_phys)[i1] = p | TABLE_DESC;
            p
        };
        let l2_entry = table_at(l2_phys)[i2];
        let l3_phys = if l2_entry & 0b11 == TABLE_DESC {
            l2_entry & ADDR_MASK
        } else {
            let p = alloc_table();
            table_at(l2_phys)[i2] = p | TABLE_DESC;
            p
        };
        table_at(l3_phys)[i3] =
            phys | PAGE_DESC | attr_field | SH_INNER | AF | AP_KERNEL_RO | gp_bit | UXN;
    }

    // SAFETY: `dsb ishst` ensures all new page-table entries are visible before
    // `TTBR1_EL1` is loaded in the trampoline.
    unsafe {
        asm!("dsb ishst", options(nostack, preserves_flags));
    }

    l0_phys
}
