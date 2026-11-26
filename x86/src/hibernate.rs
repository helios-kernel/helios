//! x86-64 hibernate device registry, early-boot resume probe, and restore
//! trampoline handoff.
//!
//! # Ordering contract
//!
//! - [`X86HibernateDevices::quiesce_all`] quiesces every DMA-capable endpoint
//!   device BEFORE quiescing `virtio-iommu`.
//! - [`X86HibernateDevices::reinitialize_all`] MUST reinitialize
//!   `virtio-iommu` FIRST (when present) before any other virtio device calls
//!   `reinitialize()`, so every DMA domain and IOVA mapping is restored before
//!   any endpoint resumes DMA.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::arch::global_asm;
use core::mem::{offset_of, size_of};
use core::ops::Range;
use core::time::Duration;

use helios_hal::boot::BootMemoryMetadata;
use helios_hal::cpu::{
    Cpu, DisplacedFrameCopy, ResumeHandoff, ResumeHandoffWire, X86_64SnapshotContext,
};
use helios_hal::pmm::PhysFrame;
use helios_hal::rtc::RealTimeClock;
use helios_hal::watchdog::Watchdog;
use helios_kernel::hibernate::{
    DeviceFeatureRecord, HibernateDeviceController, HibernateDeviceError, LoadedHibernateImage,
    ResumeProbe, VirtioBlockHibernateStorage, build_machine_identity,
    collect_boot_protected_ranges, probe_and_load_hibernate_image, usable_physical_frame_runs,
};
use helios_kernel::{
    HIBERNATE_DISK_SERIAL, Kernel, MachineGenerationHandle, ResetDevice, RootEntropy,
    UserMemoryPool,
};
use helios_virtio::DeviceType;

use crate::X86Cpu;
use crate::balloon::X86VirtioBalloonDevice;
use crate::block::X86VirtioBlockDevice;
use crate::entropy::X86VirtioRngDevice;
use crate::gpu::X86VirtioGpuDevice;
use crate::host_fs::HostFsTransportService;
use crate::input::X86VirtioInputDevice;
use crate::iommu::X86VirtioIommuDevice;
use crate::net::X86VirtioNetDevice;
use crate::rtc::CmosRtc;
use crate::snd::X86VirtioSndDevice;
use crate::vsock::X86VirtioVsockDevice;

global_asm!(include_str!("restore.S"));

unsafe extern "C" {
    fn helios_x86_restore_trampoline(params: *const X86RestoreParams) -> !;
    static helios_x86_restore_trampoline_end: u8;
}

/// Polled I/O deadline for early-boot hibernate disk discovery, verification,
/// and device quiesce/reinitialization.
const POLLED_TIMEOUT: Duration = Duration::from_secs(30);

/// Parameter block written at offset `0x000` of the safe 4 KiB trampoline page
/// (`trampoline_phys + direct_map_offset`) before entering
/// [`helios_x86_restore_trampoline`].
#[repr(C)]
struct X86RestoreParams {
    trampoline_cr3: u64,
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
    assert!(offset_of!(X86RestoreParams, trampoline_cr3) == 0x00);
    assert!(offset_of!(X86RestoreParams, copy_table_virt) == 0x08);
    assert!(offset_of!(X86RestoreParams, copy_count) == 0x10);
    assert!(offset_of!(X86RestoreParams, direct_map_offset) == 0x18);
    assert!(offset_of!(X86RestoreParams, stack_top_virt) == 0x20);
    assert!(offset_of!(X86RestoreParams, handoff_phys) == 0x28);
    assert!(offset_of!(X86RestoreParams, ctx_virt) == 0x30);
    assert!(size_of::<X86RestoreParams>() <= HANDOFF_PAGE_OFFSET);
    assert!(HANDOFF_PAGE_OFFSET + size_of::<ResumeHandoffWire>() <= CTX_PAGE_OFFSET);
    assert!(CTX_PAGE_OFFSET + size_of::<X86_64SnapshotContext>() <= 0x200);
};

/// Static-dispatch registry of every live x86-64 virtio device brought up at
/// boot, holding `virtio-iommu` first so [`HibernateDeviceController`] enforces
/// the IOMMU-first reinitialization invariant.
#[derive(Clone)]
pub(crate) struct X86HibernateDevices {
    cpu: X86Cpu,
    generation: MachineGenerationHandle,
    pub(crate) iommu: Option<Arc<X86VirtioIommuDevice>>,
    pub(crate) host_fs: Option<HostFsTransportService>,
    pub(crate) network: Option<Arc<X86VirtioNetDevice>>,
    pub(crate) entropy: Option<Arc<X86VirtioRngDevice>>,
    pub(crate) balloon: Option<Arc<X86VirtioBalloonDevice>>,
    pub(crate) vsock: Option<Arc<X86VirtioVsockDevice>>,
    pub(crate) display: Option<Arc<X86VirtioGpuDevice>>,
    pub(crate) inputs: Vec<Arc<X86VirtioInputDevice>>,
    pub(crate) sound: Option<Arc<X86VirtioSndDevice>>,
    pub(crate) blocks: Vec<X86VirtioBlockDevice>,
}

impl X86HibernateDevices {
    pub(crate) fn new(cpu: X86Cpu, generation: MachineGenerationHandle) -> Self {
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

impl HibernateDeviceController for X86HibernateDevices {
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
///
/// If a valid, authenticated hibernate image is loaded, quiesces boot-kernel
/// devices and enters [`helios_x86_restore_trampoline`] (never returning).
/// Otherwise returns normally so cold boot continues.
#[expect(
    clippy::too_many_arguments,
    reason = "early-boot resume probe receives explicit static-dispatch boot dependencies"
)]
pub(crate) fn probe_and_resume_if_present<WatchdogImpl, MeasuredBootImpl>(
    cpu: &X86Cpu,
    kernel: &Kernel<X86Cpu, WatchdogImpl, MeasuredBootImpl>,
    debug_state: &crate::debug_state::RuntimeState,
    pool: &UserMemoryPool,
    root_entropy: &RootEntropy,
    rtc: Option<&CmosRtc>,
    devices: &mut X86HibernateDevices,
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
    let protected_ranges = collect_boot_protected_ranges(boot_memory, pool, extra_protected);
    let table_pages = required_trampoline_table_pages(max_phys);

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
        || cpu.watchdog().pet(),
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

    // Quiesce boot-kernel devices so no boot-kernel DMA runs while the
    // trampoline overwrites memory.
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
        "entering x86-64 hibernate restore trampoline"
    );

    enter_restore_trampoline(&loaded, handoff, boot_memory, physical_memory_offset)
}

fn find_hibernate_block_device(
    cpu: &X86Cpu,
    blocks: &[X86VirtioBlockDevice],
) -> Option<X86VirtioBlockDevice> {
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

/// Number of 4 KiB page-table frames needed to build a self-contained x86-64
/// 4-level page table mapping all physical RAM (`0..max_phys`) at HHDM with
/// 2 MiB huge pages plus the `.text` pages holding `helios_x86_restore_trampoline`.
fn required_trampoline_table_pages(max_phys: u64) -> usize {
    const GIB: u64 = 1 << 30;
    let gib_count = max_phys.div_ceil(GIB).max(1) as usize;
    // 1 PML4 + 1 PDPT (HHDM) + `gib_count` PDs (2 MiB leaves) + up to 4 tables
    // for mapping the trampoline's kernel `.text` page(s).
    1 + 1 + gib_count + 4
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
        .as_x86_64()
        .expect("verified hibernate header carries an x86-64 BSP context");
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

    // 2. Build a self-contained 4-level page table inside
    //    `plan.trampoline_table_frames` so displaced copies overwriting
    //    bootloader-reclaimable page tables cannot fault the copy loop.
    let trampoline_cr3 = build_trampoline_page_tables(
        &plan.trampoline_table_frames,
        boot_memory,
        physical_memory_offset,
    );

    // 3. Populate the safe trampoline page with `X86RestoreParams`,
    //    `ResumeHandoffWire`, and `X86_64SnapshotContext`.
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

    let params = X86RestoreParams {
        trampoline_cr3,
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
            core::ptr::with_exposed_provenance_mut::<X86RestoreParams>(tramp_virt),
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
            core::ptr::with_exposed_provenance_mut::<X86_64SnapshotContext>(ctx_virt),
            ctx,
        );
    }

    // SAFETY: all displaced frames are staged in disjoint safe frames, the
    // trampoline page tables live in safe frames, `params` sits on the safe
    // trampoline page, and interrupts are masked.
    unsafe {
        helios_x86_restore_trampoline(core::ptr::with_exposed_provenance::<X86RestoreParams>(
            tramp_virt,
        ))
    }
}

/// Builds a self-contained x86-64 4-level page table in `table_frames` that
/// maps:
/// - `0..max_phys` at `physical_memory_offset + phys` using 2 MiB RW pages, and
/// - the kernel `.text` page(s) containing [`helios_x86_restore_trampoline`]
///   at their exact linked virtual address (executable, identical across boot
///   and image kernels).
fn build_trampoline_page_tables(
    table_frames: &[u64],
    boot_memory: &BootMemoryMetadata,
    physical_memory_offset: usize,
) -> u64 {
    const PRESENT: u64 = 1 << 0;
    const WRITABLE: u64 = 1 << 1;
    const HUGE: u64 = 1 << 7;
    const NO_EXECUTE: u64 = 1 << 63;
    const ADDR_MASK: u64 = 0x000f_ffff_ffff_f000;
    const MIB_2: u64 = 2 * 1024 * 1024;
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

    let pml4_phys = alloc_table();

    // 1. Map all physical RAM at HHDM with 2 MiB pages (RW, NX).
    let max_phys = boot_memory.max_physical_address().max(MIB_2);
    let gib_count = max_phys.div_ceil(GIB).min(512);
    let hhdm_pdpt_phys = alloc_table();
    let hhdm_pml4_idx = (physical_memory_offset >> 39) & 0x1ff;
    table_at(pml4_phys)[hhdm_pml4_idx] = hhdm_pdpt_phys | PRESENT | WRITABLE;

    let hhdm_pdpt_base = (physical_memory_offset >> 30) & 0x1ff;
    for g in 0..gib_count as usize {
        let pd_phys = alloc_table();
        let pdpt_idx = hhdm_pdpt_base + g;
        assert!(pdpt_idx < 512, "HHDM exceeds one PDPT during restore");
        table_at(hhdm_pdpt_phys)[pdpt_idx] = pd_phys | PRESENT | WRITABLE;
        let pd = table_at(pd_phys);
        for (m, slot) in pd.iter_mut().enumerate() {
            let phys = (g as u64) * GIB + (m as u64) * MIB_2;
            *slot = phys | PRESENT | WRITABLE | HUGE | NO_EXECUTE;
        }
    }

    // 2. Map every 4 KiB page of `helios_x86_restore_trampoline` at its exact
    //    kernel `.text` virtual address (RX).
    let text = boot_memory.kernel_sections.text;
    let stub_start = (helios_x86_restore_trampoline as *const () as usize) & !(PhysFrame::SIZE - 1);
    let stub_end = ((&raw const helios_x86_restore_trampoline_end as usize) + PhysFrame::SIZE - 1)
        & !(PhysFrame::SIZE - 1);
    let mut virt = stub_start;
    while virt < stub_end {
        let offset_in_text = (virt as u64)
            .checked_sub(text.virtual_start)
            .expect("restore trampoline lies outside kernel .text");
        let phys = text.physical_start + offset_in_text;
        let i4 = (virt >> 39) & 0x1ff;
        let i3 = (virt >> 30) & 0x1ff;
        let i2 = (virt >> 21) & 0x1ff;
        let i1 = (virt >> 12) & 0x1ff;

        let pml4_entry = table_at(pml4_phys)[i4];
        let pdpt_phys = if pml4_entry & PRESENT != 0 {
            pml4_entry & ADDR_MASK
        } else {
            let p = alloc_table();
            table_at(pml4_phys)[i4] = p | PRESENT | WRITABLE;
            p
        };
        let pdpt_entry = table_at(pdpt_phys)[i3];
        let pd_phys = if pdpt_entry & PRESENT != 0 {
            pdpt_entry & ADDR_MASK
        } else {
            let p = alloc_table();
            table_at(pdpt_phys)[i3] = p | PRESENT | WRITABLE;
            p
        };
        let pd_entry = table_at(pd_phys)[i2];
        let pt_phys = if pd_entry & PRESENT != 0 {
            pd_entry & ADDR_MASK
        } else {
            let p = alloc_table();
            table_at(pd_phys)[i2] = p | PRESENT | WRITABLE;
            p
        };
        table_at(pt_phys)[i1] = phys | PRESENT;
        virt += PhysFrame::SIZE;
    }

    pml4_phys
}
