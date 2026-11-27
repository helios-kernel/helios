//! virtio-vsock over PCI or MMIO for the RISC-V backend.
//!
//! Concurrency contract: the device is discovered and programmed on the
//! bootstrap hart before external interrupts are unmasked. Afterwards the
//! kernel's vsock service owns it — one receive pump plus whichever tasks
//! are transmitting — and completions arrive on the PLIC source the device
//! tree names, so every waiter parks on a notification rather than polling.

extern crate alloc;

use alloc::sync::Arc;

use fdt::Fdt;
use helios_hal::cpu::Cpu;
use helios_kernel::ExternalInterruptHandler;
use helios_virtio::{DeviceType, VirtioBusTransport, VirtioVsockDevice as RawVirtioVsockDevice};

use crate::iommu::{self, Confinement, RiscvDmaArenas, RiscvVirtioTransport};
use crate::net::PlicInterrupt;
use crate::pci::{PciHostController, VirtioFunctions};

pub(crate) type RiscvVirtioVsockDevice = RawVirtioVsockDevice<RiscvVirtioTransport>;

/// The interrupt route's view of the platform's vsock device.
#[derive(Clone)]
pub(crate) struct VirtioVsockDevice {
    inner: Arc<RiscvVirtioVsockDevice>,
}

impl VirtioVsockDevice {
    pub(crate) fn device(&self) -> &Arc<RiscvVirtioVsockDevice> {
        &self.inner
    }
}

/// The vsock device the bootstrap hart brought up, together with the
/// PLIC line the device tree routes it to.
pub(crate) struct VsockInterrupt {
    pub(crate) line: PlicInterrupt,
    pub(crate) device: VirtioVsockDevice,
}

impl ExternalInterruptHandler for VirtioVsockDevice {
    fn handle_interrupt(&self) {
        self.inner.handle_interrupt();
    }
}

pub(crate) fn has_vsock_device(fdt: &Fdt<'_>, pci_virtio: Option<&VirtioFunctions>) -> bool {
    pci_virtio.is_some_and(|v| v.count(DeviceType::Vsock) != 0)
        || crate::count_virtio_mmio_devices(fdt, DeviceType::Vsock) != 0
}

/// Brings up the vsock device and publishes it as the machine's host link.
#[allow(clippy::too_many_arguments)]
pub(crate) fn install<WatchdogImpl, MeasuredBootImpl>(
    kernel: &helios_kernel::Kernel<crate::RiscvCpu, WatchdogImpl, MeasuredBootImpl>,
    cpu: &crate::RiscvCpu,
    fdt: &Fdt<'_>,
    pci: Option<&PciHostController>,
    pci_virtio: Option<&VirtioFunctions>,
    arenas: &mut RiscvDmaArenas,
    confinement: Option<&mut Confinement>,
    debug_state: &crate::debug_state::RuntimeState,
) -> Option<VsockInterrupt>
where
    WatchdogImpl: helios_hal::watchdog::Watchdog + Clone,
    MeasuredBootImpl: helios_hal::measured_boot::MeasuredBoot,
{
    let (device, line) = discover_vsock_device(cpu, fdt, pci, pci_virtio, arenas, confinement)?;
    let service = helios_kernel::install_vsock_device(kernel, cpu, device.inner.clone());
    let guest_cid = service.guest_cid();
    debug_state.install_vsock_service(helios_kernel::ComponentHostVsockService::from_service(
        service,
    ));
    tracing::info!(guest_cid, irq = line.number(), "virtio vsock online");
    Some(VsockInterrupt { line, device })
}

fn discover_vsock_device(
    cpu: &crate::RiscvCpu,
    fdt: &Fdt<'_>,
    pci: Option<&PciHostController>,
    pci_virtio: Option<&VirtioFunctions>,
    arenas: &mut RiscvDmaArenas,
    confinement: Option<&mut Confinement>,
) -> Option<(VirtioVsockDevice, PlicInterrupt)> {
    if let (Some(pci), Some(function)) = (pci, pci_virtio.and_then(|v| v.first(DeviceType::Vsock)))
    {
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
                        "failed to initialize virtio-vsock PCI transport at {}: {error}",
                        function.address
                    )
                });
        let device = RawVirtioVsockDevice::new(transport).unwrap_or_else(|error| {
            panic!(
                "failed to initialize virtio-vsock PCI device at {}: {error}",
                function.address
            )
        });
        return Some((
            VirtioVsockDevice {
                inner: Arc::new(device),
            },
            function.line,
        ));
    }

    let candidate = helios_virtio::mmio_candidates(fdt)
        .find(|candidate| crate::matches_virtio_mmio_device(candidate.base, DeviceType::Vsock))?;
    let base = candidate.base;
    let virt_base = crate::vmm::map_mmio_range(base, candidate.size);
    let header = core::ptr::NonNull::new(virt_base as *mut u8)
        .unwrap_or_else(|| panic!("virtio MMIO base {base:#x} was unexpectedly null"));
    let line = candidate
        .interrupt
        .and_then(PlicInterrupt::from_specifier)
        .unwrap_or_else(|| panic!("virtio-vsock node at {base:#x} has no valid interrupt source"));
    let dma = iommu::dma_pool(
        arenas,
        None,
        None,
        iommu::LARGE_DMA_CHUNK_BYTES,
        cpu.processor_count(),
    );
    // SAFETY: `candidate` comes from `mmio_candidates(fdt)` and matched
    // `DeviceType::Vsock` on the bootstrap hart before interrupts are
    // unmasked, so `header..header + candidate.size` is an identity-mapped
    // VirtIO MMIO vsock register block with exclusive driver access.
    let transport = unsafe { VirtioBusTransport::mmio(header, candidate.size, dma) }
        .unwrap_or_else(|error| {
            panic!("failed to initialize virtio-vsock MMIO transport at {base:#x}: {error}")
        });
    let device = RawVirtioVsockDevice::new(transport).unwrap_or_else(|error| {
        panic!("failed to initialize virtio-vsock device at {base:#x}: {error}")
    });
    Some((
        VirtioVsockDevice {
            inner: Arc::new(device),
        },
        line,
    ))
}
