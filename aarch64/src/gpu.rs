//! virtio-gpu over PCI or MMIO for the AArch64 backend.
//!
//! Concurrency contract: the device is discovered and programmed on the
//! bootstrap processor before IRQs are unmasked. Afterwards its completions
//! and its display-change announcements arrive on the SPI the firmware
//! names, delivered to that same processor.

extern crate alloc;

use alloc::sync::Arc;

use arm_gic::{IntId, Trigger};
use helios_hal::cpu::Cpu;
use helios_kernel::ExternalInterruptHandler;
use helios_virtio::{DeviceType, VirtioBusTransport, VirtioGpuDevice};

use crate::iommu::{self, Aarch64DmaArenas, Aarch64VirtioTransport, Confinement};
use crate::pci::{PciRoot, VirtioFunctions};
use crate::platform::PlatformDescription;

type Aarch64VirtioGpuDevice = VirtioGpuDevice<Aarch64VirtioTransport>;

/// The interrupt route's view of the platform's display engine.
#[derive(Clone)]
pub(crate) struct VirtioDisplayDevice {
    device: Arc<Aarch64VirtioGpuDevice>,
}

/// The display device the bootstrap processor brought up, together with
/// the interrupt the firmware routes it to.
pub(crate) struct DisplayInterrupt {
    pub(crate) interrupt: IntId,
    pub(crate) trigger: Trigger,
    pub(crate) device: VirtioDisplayDevice,
}

impl ExternalInterruptHandler for VirtioDisplayDevice {
    fn handle_interrupt(&self) {
        self.device.handle_interrupt();
    }
}

pub(crate) fn has_display_device(
    platform: &PlatformDescription,
    pci_virtio: Option<&VirtioFunctions>,
) -> bool {
    pci_virtio.is_some_and(|v| v.count(DeviceType::Gpu) != 0)
        || crate::count_virtio_mmio_devices(platform, DeviceType::Gpu) != 0
}

/// Brings the platform's display engine up and hands it to the kernel.
#[allow(clippy::too_many_arguments)]
pub(crate) fn install<WatchdogImpl, MeasuredBootImpl>(
    cpu: &crate::Aarch64Cpu,
    kernel: &helios_kernel::Kernel<crate::Aarch64Cpu, WatchdogImpl, MeasuredBootImpl>,
    platform: &PlatformDescription,
    pci: Option<&PciRoot>,
    pci_virtio: Option<&VirtioFunctions>,
    arenas: &mut Aarch64DmaArenas,
    confinement: Option<&mut Confinement>,
    physical_memory_offset: usize,
    handoff: &crate::LimineBootHandoff,
    debug_state: &crate::debug_state::RuntimeState,
) -> Option<DisplayInterrupt>
where
    WatchdogImpl: helios_hal::watchdog::Watchdog + Clone,
    MeasuredBootImpl: helios_hal::measured_boot::MeasuredBoot,
{
    let display = discover_display_device(
        cpu,
        platform,
        pci,
        pci_virtio,
        arenas,
        confinement,
        physical_memory_offset,
        handoff,
    )?;
    let service = helios_kernel::install_display_device(kernel, cpu, display.device.device.clone());
    debug_state.install_display_service(service);
    let service = helios_kernel::install_gpu3d_device(kernel, cpu, display.device.device.clone());
    debug_state.install_gpu3d_service(service);
    Some(display)
}

#[allow(clippy::too_many_arguments)]
fn discover_display_device(
    cpu: &crate::Aarch64Cpu,
    platform: &PlatformDescription,
    pci: Option<&PciRoot>,
    pci_virtio: Option<&VirtioFunctions>,
    arenas: &mut Aarch64DmaArenas,
    confinement: Option<&mut Confinement>,
    physical_memory_offset: usize,
    handoff: &crate::LimineBootHandoff,
) -> Option<DisplayInterrupt> {
    if let (Some(pci), Some(function)) = (pci, pci_virtio.and_then(|v| v.first(DeviceType::Gpu))) {
        pci.assign_unassigned_memory_bars(function.address);
        let dma = iommu::dma_pool(
            arenas,
            confinement,
            Some(function.address),
            physical_memory_offset,
            iommu::LARGE_DMA_CHUNK_BYTES,
            cpu.processor_count(),
        );
        let transport = VirtioBusTransport::pci(&pci.access(), function.address, pci, dma, None)
            .unwrap_or_else(|error| {
                panic!(
                    "failed to initialize virtio-gpu PCI transport at {}: {error}",
                    function.address
                )
            });
        let device = helios_virtio::gpu_from_bus_transport(transport).unwrap_or_else(|error| {
            panic!(
                "failed to initialize virtio-gpu PCI device at {}: {error}",
                function.address
            )
        });
        return Some(DisplayInterrupt {
            interrupt: function.interrupt,
            trigger: function.trigger,
            device: VirtioDisplayDevice {
                device: Arc::new(device),
            },
        });
    }

    let candidate =
        crate::virtio_slots(platform, physical_memory_offset, handoff, DeviceType::Gpu).next()?;
    let (interrupt, trigger) = (candidate.interrupt.intid(), candidate.interrupt.trigger);
    assert!(
        candidate.region.size != 0,
        "AArch64 virtio-gpu node has zero MMIO size"
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
        iommu::LARGE_DMA_CHUNK_BYTES,
        cpu.processor_count(),
    );
    // SAFETY: `map_mmio_range` mapped `header..header + candidate.region.size`
    // as Device-nGnRnE, the device is brought up on the bootstrap processor
    // before IRQs are unmasked with exclusive register access, and `dma`
    // translates using the kernel's direct-map offset.
    let transport = unsafe { VirtioBusTransport::mmio(header, candidate.region.size, dma) }
        .unwrap_or_else(|error| {
            panic!(
                "failed to initialize virtio-gpu MMIO transport at {:#x}: {error}",
                candidate.region.base
            )
        });
    let device = helios_virtio::gpu_from_bus_transport(transport).unwrap_or_else(|error| {
        panic!(
            "failed to initialize virtio-gpu device at {:#x}: {error}",
            candidate.region.base
        )
    });
    Some(DisplayInterrupt {
        interrupt,
        trigger,
        device: VirtioDisplayDevice {
            device: Arc::new(device),
        },
    })
}
