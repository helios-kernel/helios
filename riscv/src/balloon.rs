//! virtio-balloon over PCI or MMIO for the RISC-V backend.
//!
//! Concurrency contract: the device is discovered and programmed on the
//! bootstrap hart before external interrupts are unmasked. Afterwards the
//! kernel's balloon tasks are its only users, and both its completions and
//! its configuration changes arrive on the PLIC source the device tree
//! names.

extern crate alloc;

use alloc::sync::Arc;

use fdt::Fdt;
use helios_hal::cpu::Cpu;
use helios_kernel::{BalloonHandle, ExternalInterruptHandler};
use helios_virtio::{DeviceType, VirtioBalloonDevice, VirtioBusTransport};

use crate::iommu::{self, Confinement, RiscvDmaArenas, RiscvVirtioTransport};
use crate::net::PlicInterrupt;
use crate::pci::{PciHostController, VirtioFunctions};

pub(crate) type RiscvVirtioBalloonDevice = VirtioBalloonDevice<RiscvVirtioTransport>;

/// The interrupt half of the balloon: what the PLIC dispatches to.
#[derive(Clone)]
pub(crate) struct VirtioBalloonInterrupt {
    inner: Arc<RiscvVirtioBalloonDevice>,
}

impl VirtioBalloonInterrupt {
    pub(crate) fn device(&self) -> &Arc<RiscvVirtioBalloonDevice> {
        &self.inner
    }
}

impl ExternalInterruptHandler for VirtioBalloonInterrupt {
    fn handle_interrupt(&self) {
        self.inner.handle_interrupt();
    }
}

/// The balloon the bootstrap hart brought up, together with the PLIC
/// line the device tree routes it to.
pub(crate) struct BalloonInterrupt {
    pub(crate) line: PlicInterrupt,
    pub(crate) handler: VirtioBalloonInterrupt,
    pub(crate) handle: BalloonHandle,
}

pub(crate) fn has_balloon_device(fdt: &Fdt<'_>, pci_virtio: Option<&VirtioFunctions>) -> bool {
    pci_virtio.is_some_and(|v| v.count(DeviceType::MemoryBalloon) != 0)
        || crate::count_virtio_mmio_devices(fdt, DeviceType::MemoryBalloon) != 0
}

/// Brings up the platform's memory balloon and hands it to the kernel's
/// balloon tasks.
#[allow(clippy::too_many_arguments)]
pub(crate) fn install<WatchdogImpl, MeasuredBootImpl>(
    cpu: &crate::RiscvCpu,
    kernel: &helios_kernel::Kernel<crate::RiscvCpu, WatchdogImpl, MeasuredBootImpl>,
    fdt: &Fdt<'_>,
    pci: Option<&PciHostController>,
    pci_virtio: Option<&VirtioFunctions>,
    arenas: &mut RiscvDmaArenas,
    confinement: Option<&mut Confinement>,
    generation: helios_kernel::MachineGenerationHandle,
) -> Option<BalloonInterrupt>
where
    WatchdogImpl: helios_hal::watchdog::Watchdog + Clone,
    MeasuredBootImpl: helios_hal::measured_boot::MeasuredBoot,
{
    let (device, line) = discover_balloon_device(cpu, fdt, pci, pci_virtio, arenas, confinement)?;
    let device = Arc::new(device);
    let handle = helios_kernel::install_memory_balloon(kernel, device.clone(), generation);
    tracing::info!("virtio balloon online irq={}", line.number());
    Some(BalloonInterrupt {
        line,
        handler: VirtioBalloonInterrupt { inner: device },
        handle,
    })
}

fn discover_balloon_device(
    cpu: &crate::RiscvCpu,
    fdt: &Fdt<'_>,
    pci: Option<&PciHostController>,
    pci_virtio: Option<&VirtioFunctions>,
    arenas: &mut RiscvDmaArenas,
    confinement: Option<&mut Confinement>,
) -> Option<(VirtioBalloonDevice<RiscvVirtioTransport>, PlicInterrupt)> {
    if let (Some(pci), Some(function)) = (
        pci,
        pci_virtio.and_then(|v| v.first(DeviceType::MemoryBalloon)),
    ) {
        pci.assign_unassigned_memory_bars(function.address);
        let dma = iommu::dma_pool(
            arenas,
            confinement,
            Some(function.address),
            iommu::SMALL_DMA_CHUNK_BYTES,
            cpu.processor_count(),
        );
        let transport =
            VirtioBusTransport::pci(&pci.config_access(), function.address, pci, dma, None)
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
        return Some((device, function.line));
    }

    let candidate = helios_virtio::mmio_candidates(fdt).find(|candidate| {
        crate::matches_virtio_mmio_device(candidate.base, DeviceType::MemoryBalloon)
    })?;
    let base = candidate.base;
    let virt_base = crate::vmm::map_mmio_range(base, candidate.size);
    let header = core::ptr::NonNull::new(virt_base as *mut u8)
        .unwrap_or_else(|| panic!("virtio MMIO base {base:#x} was unexpectedly null"));
    let line = candidate
        .interrupt
        .and_then(PlicInterrupt::from_specifier)
        .unwrap_or_else(|| {
            panic!("virtio-balloon node at {base:#x} has no valid interrupt source")
        });
    let dma = iommu::dma_pool(
        arenas,
        None,
        None,
        iommu::SMALL_DMA_CHUNK_BYTES,
        cpu.processor_count(),
    );
    // SAFETY: `candidate` comes from `mmio_candidates(fdt)` and matched
    // `DeviceType::MemoryBalloon` on the bootstrap hart before interrupts are
    // unmasked, so `header..header + candidate.size` is an identity-mapped
    // VirtIO MMIO balloon register block with exclusive driver access.
    let transport = unsafe { VirtioBusTransport::mmio(header, candidate.size, dma) }
        .unwrap_or_else(|error| {
            panic!("failed to initialize virtio-balloon MMIO transport at {base:#x}: {error}")
        });
    let device = VirtioBalloonDevice::new(transport).unwrap_or_else(|error| {
        panic!("failed to initialize virtio-balloon device at {base:#x}: {error}")
    });
    Some((device, line))
}
