//! virtio-balloon over PCI or MMIO for the AArch64 backend.
//!
//! Concurrency contract: the device is discovered and programmed on the
//! bootstrap processor before IRQs are unmasked. Afterwards the kernel's
//! balloon tasks are its only users, and both its completions and its
//! configuration changes arrive on the SPI the firmware names.

extern crate alloc;

use alloc::sync::Arc;

use arm_gic::{IntId, Trigger};
use helios_hal::cpu::Cpu;
use helios_kernel::{BalloonHandle, ExternalInterruptHandler, Kernel};
use helios_virtio::{DeviceType, VirtioBalloonDevice, VirtioBusTransport};

use crate::iommu::{self, Aarch64DmaArenas, Aarch64VirtioTransport, Confinement};
use crate::pci::{PciRoot, VirtioFunctions};
use crate::platform::PlatformDescription;

pub(crate) type Aarch64VirtioBalloonDevice = VirtioBalloonDevice<Aarch64VirtioTransport>;

/// The interrupt half of the balloon: what the GIC dispatches to.
#[derive(Clone)]
pub(crate) struct VirtioBalloonInterrupt {
    device: Arc<Aarch64VirtioBalloonDevice>,
}

impl VirtioBalloonInterrupt {
    pub(crate) fn device(&self) -> &Arc<Aarch64VirtioBalloonDevice> {
        &self.device
    }
}

impl ExternalInterruptHandler for VirtioBalloonInterrupt {
    fn handle_interrupt(&self) {
        self.device.handle_interrupt();
    }
}

/// The balloon the bootstrap processor brought up, together with the
/// interrupt the firmware routes it to.
pub(crate) struct BalloonInterrupt {
    pub(crate) interrupt: IntId,
    pub(crate) trigger: Trigger,
    pub(crate) handler: VirtioBalloonInterrupt,
    pub(crate) handle: BalloonHandle,
}

pub(crate) fn has_balloon_device(
    platform: &PlatformDescription,
    pci_virtio: Option<&VirtioFunctions>,
) -> bool {
    pci_virtio.is_some_and(|v| v.count(DeviceType::MemoryBalloon) != 0)
        || crate::count_virtio_mmio_devices(platform, DeviceType::MemoryBalloon) != 0
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn install<WatchdogImpl, MeasuredBootImpl>(
    cpu: &crate::Aarch64Cpu,
    kernel: &Kernel<crate::Aarch64Cpu, WatchdogImpl, MeasuredBootImpl>,
    platform: &PlatformDescription,
    pci: Option<&PciRoot>,
    pci_virtio: Option<&VirtioFunctions>,
    arenas: &mut Aarch64DmaArenas,
    confinement: Option<&mut Confinement>,
    physical_memory_offset: usize,
    handoff: &crate::LimineBootHandoff,
    generation: helios_kernel::MachineGenerationHandle,
) -> Option<BalloonInterrupt>
where
    WatchdogImpl: helios_hal::watchdog::Watchdog + Clone,
    MeasuredBootImpl: helios_hal::measured_boot::MeasuredBoot,
{
    let (device, interrupt, trigger) = discover_balloon_device(
        cpu,
        platform,
        pci,
        pci_virtio,
        arenas,
        confinement,
        physical_memory_offset,
        handoff,
    )?;
    let device = Arc::new(device);
    let handle = helios_kernel::install_memory_balloon(kernel, device.clone(), generation);
    tracing::info!("virtio balloon online interrupt={interrupt:?}");
    Some(BalloonInterrupt {
        interrupt,
        trigger,
        handler: VirtioBalloonInterrupt { device },
        handle,
    })
}

#[allow(clippy::too_many_arguments)]
fn discover_balloon_device(
    cpu: &crate::Aarch64Cpu,
    platform: &PlatformDescription,
    pci: Option<&PciRoot>,
    pci_virtio: Option<&VirtioFunctions>,
    arenas: &mut Aarch64DmaArenas,
    confinement: Option<&mut Confinement>,
    physical_memory_offset: usize,
    handoff: &crate::LimineBootHandoff,
) -> Option<(Aarch64VirtioBalloonDevice, IntId, Trigger)> {
    if let (Some(pci), Some(function)) = (
        pci,
        pci_virtio.and_then(|v| v.first(DeviceType::MemoryBalloon)),
    ) {
        pci.assign_unassigned_memory_bars(function.address);
        let dma = iommu::dma_pool(
            arenas,
            confinement,
            Some(function.address),
            physical_memory_offset,
            iommu::SMALL_DMA_CHUNK_BYTES,
            cpu.processor_count(),
        );
        let transport = VirtioBusTransport::pci(&pci.access(), function.address, pci, dma, None)
            .unwrap_or_else(|error| {
                panic!(
                    "failed to initialize virtio-balloon PCI transport at {}: {error}",
                    function.address
                )
            });
        let device = VirtioBalloonDevice::new(transport).unwrap_or_else(|error| {
            panic!(
                "failed to initialize virtio-balloon PCI device at {}: {error}",
                function.address
            )
        });
        return Some((device, function.interrupt, function.trigger));
    }

    let candidate = crate::virtio_slots(
        platform,
        physical_memory_offset,
        handoff,
        DeviceType::MemoryBalloon,
    )
    .next()?;
    let (interrupt, trigger) = (candidate.interrupt.intid(), candidate.interrupt.trigger);
    assert!(
        candidate.region.size != 0,
        "AArch64 virtio-balloon node has zero MMIO size"
    );
    crate::map_mmio_range(
        candidate.region.base,
        candidate.region.size,
        physical_memory_offset,
        handoff,
    );
    let virtual_base = crate::mmio_virtual_base(candidate.region.base, physical_memory_offset);
    assert!(
        virtual_base.is_multiple_of(core::mem::align_of::<u32>()),
        "virtio MMIO base {virtual_base:#x} is not 4-byte aligned"
    );
    let header = core::ptr::NonNull::new(virtual_base as *mut u8)
        .unwrap_or_else(|| panic!("virtio MMIO base {virtual_base:#x} was unexpectedly null"));
    let dma = iommu::dma_pool(
        arenas,
        None,
        None,
        physical_memory_offset,
        iommu::SMALL_DMA_CHUNK_BYTES,
        cpu.processor_count(),
    );
    // SAFETY: `map_mmio_range` mapped `header..header + candidate.region.size`
    // as Device-nGnRnE, the device is brought up on the bootstrap processor
    // before IRQs are unmasked with exclusive register access, and `dma`
    // translates using the kernel's direct-map offset.
    let transport = unsafe { VirtioBusTransport::mmio(header, candidate.region.size, dma) }
        .unwrap_or_else(|error| {
            panic!(
                "failed to initialize virtio-balloon MMIO transport at {:#x}: {error}",
                candidate.region.base
            )
        });
    let device = VirtioBalloonDevice::new(transport).unwrap_or_else(|error| {
        panic!(
            "failed to initialize virtio-balloon device at {:#x}: {error}",
            candidate.region.base
        )
    });
    Some((device, interrupt, trigger))
}
