//! virtio-gpu over PCI or MMIO for the RISC-V backend.
//!
//! Concurrency contract: the device is discovered and programmed on the
//! bootstrap hart before external interrupts are unmasked. Afterwards its
//! completions and its display-change announcements arrive on the PLIC line
//! the device tree names, on the hart that takes that PLIC's interrupts.

extern crate alloc;

use alloc::sync::Arc;

use fdt::Fdt;
use helios_hal::cpu::Cpu;
use helios_kernel::ExternalInterruptHandler;
use helios_virtio::{DeviceType, VirtioBusTransport, VirtioGpuDevice};

use crate::iommu::{self, Confinement, RiscvDmaArenas, RiscvVirtioTransport};
use crate::net::PlicInterrupt;
use crate::pci::{PciHostController, VirtioFunctions};

pub(crate) type RiscvVirtioGpuDevice = VirtioGpuDevice<RiscvVirtioTransport>;

/// The interrupt route's view of the platform's display engine.
#[derive(Clone)]
pub(crate) struct VirtioDisplayDevice {
    inner: Arc<RiscvVirtioGpuDevice>,
}

impl VirtioDisplayDevice {
    pub(crate) fn device(&self) -> &Arc<RiscvVirtioGpuDevice> {
        &self.inner
    }
}

/// The display device the bootstrap hart brought up, together with the
/// PLIC line the device tree routes it to.
pub(crate) struct DisplayInterrupt {
    pub(crate) line: PlicInterrupt,
    pub(crate) device: VirtioDisplayDevice,
}

impl ExternalInterruptHandler for VirtioDisplayDevice {
    fn handle_interrupt(&self) {
        self.inner.handle_interrupt();
    }
}

pub(crate) fn has_display_device(fdt: &Fdt<'_>, pci_virtio: Option<&VirtioFunctions>) -> bool {
    pci_virtio.is_some_and(|v| v.count(DeviceType::Gpu) != 0)
        || crate::count_virtio_mmio_devices(fdt, DeviceType::Gpu) != 0
}

/// Brings the platform's display engine up and hands it to the kernel.
#[allow(clippy::too_many_arguments)]
pub(crate) fn install<WatchdogImpl, MeasuredBootImpl>(
    cpu: &crate::RiscvCpu,
    kernel: &helios_kernel::Kernel<crate::RiscvCpu, WatchdogImpl, MeasuredBootImpl>,
    fdt: &Fdt<'_>,
    pci: Option<&PciHostController>,
    pci_virtio: Option<&VirtioFunctions>,
    arenas: &mut RiscvDmaArenas,
    confinement: Option<&mut Confinement>,
    debug_state: &crate::debug_state::RuntimeState,
) -> Option<DisplayInterrupt>
where
    WatchdogImpl: helios_hal::watchdog::Watchdog + Clone,
    MeasuredBootImpl: helios_hal::measured_boot::MeasuredBoot,
{
    let (device, line) = discover_display_device(cpu, fdt, pci, pci_virtio, arenas, confinement)?;
    let service = helios_kernel::install_display_device(kernel, cpu, device.inner.clone());
    debug_state.install_display_service(service);
    let service = helios_kernel::install_gpu3d_device(kernel, cpu, device.inner.clone());
    debug_state.install_gpu3d_service(service);
    Some(DisplayInterrupt { line, device })
}

fn discover_display_device(
    cpu: &crate::RiscvCpu,
    fdt: &Fdt<'_>,
    pci: Option<&PciHostController>,
    pci_virtio: Option<&VirtioFunctions>,
    arenas: &mut RiscvDmaArenas,
    confinement: Option<&mut Confinement>,
) -> Option<(VirtioDisplayDevice, PlicInterrupt)> {
    if let (Some(pci), Some(function)) = (pci, pci_virtio.and_then(|v| v.first(DeviceType::Gpu))) {
        pci.assign_unassigned_memory_bars(function.address);
        let dma = iommu::dma_pool(
            arenas,
            confinement,
            Some(function.address),
            iommu::LARGE_DMA_CHUNK_BYTES,
            cpu.processor_count(),
        );
        let transport =
            VirtioBusTransport::pci(&pci.config_access(), function.address, pci, dma, None)
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
        return Some((
            VirtioDisplayDevice {
                inner: Arc::new(device),
            },
            function.line,
        ));
    }

    let candidate = helios_virtio::mmio_candidates(fdt)
        .find(|candidate| crate::matches_virtio_mmio_device(candidate.base, DeviceType::Gpu))?;
    let base = candidate.base;
    let virt_base = crate::vmm::map_mmio_range(base, candidate.size);
    let header = core::ptr::NonNull::new(virt_base as *mut u8)
        .unwrap_or_else(|| panic!("virtio MMIO base {base:#x} was unexpectedly null"));
    let line = candidate
        .interrupt
        .and_then(PlicInterrupt::from_specifier)
        .unwrap_or_else(|| panic!("virtio-gpu node at {base:#x} has no valid interrupt source"));
    let dma = iommu::dma_pool(
        arenas,
        None,
        None,
        iommu::LARGE_DMA_CHUNK_BYTES,
        cpu.processor_count(),
    );
    // SAFETY: `candidate` comes from `mmio_candidates(fdt)` and matched
    // `DeviceType::Gpu` on the bootstrap hart before interrupts are unmasked,
    // so `header..header + candidate.size` is an identity-mapped VirtIO MMIO
    // GPU register block with exclusive driver access.
    let transport = unsafe { VirtioBusTransport::mmio(header, candidate.size, dma) }
        .unwrap_or_else(|error| {
            panic!("failed to initialize virtio-gpu MMIO transport at {base:#x}: {error}")
        });
    let device = helios_virtio::gpu_from_bus_transport(transport).unwrap_or_else(|error| {
        panic!("failed to initialize virtio-gpu device at {base:#x}: {error}")
    });
    Some((
        VirtioDisplayDevice {
            inner: Arc::new(device),
        },
        line,
    ))
}
