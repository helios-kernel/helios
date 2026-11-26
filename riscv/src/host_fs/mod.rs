//! virtio-9p host share over PCI or MMIO for the RISC-V backend.
//!
//! Concurrency contract: the device is constructed on the bootstrap hart
//! before interrupts are enabled. Afterwards every caller submits straight
//! to the device, which pipelines requests and routes each completion back
//! to the task that submitted it; completions arrive on the PLIC line the
//! device tree names, so callers await a notification instead of polling
//! the used ring.

use fdt::Fdt;
use helios_hal::cpu::Cpu;
use helios_kernel::Virtio9pTransport;
use helios_virtio::{DeviceType, Virtio9pDevice, VirtioBusTransport};

use crate::iommu::{self, Confinement, RiscvDmaArenas, RiscvVirtioTransport};
use crate::net::PlicInterrupt;
use crate::pci::{PciHostController, VirtioFunctions};

pub(crate) const HOST_MOUNT_TAG: &str = helios_kernel::HOST_SHARE_MOUNT_TAG;

pub(crate) type HostFsTransportService = Virtio9pTransport<RiscvVirtioTransport>;

pub(crate) type HostFileSystemService =
    helios_kernel::HostFsClient<HostFsTransportService, crate::RiscvCpu>;

pub(crate) struct HostFsInterrupt {
    pub(crate) line: PlicInterrupt,
    pub(crate) transport: HostFsTransportService,
}

pub(crate) fn install(
    cpu: &crate::RiscvCpu,
    fdt: &Fdt<'_>,
    pci: Option<&PciHostController>,
    pci_virtio: Option<&VirtioFunctions>,
    arenas: &mut RiscvDmaArenas,
    confinement: Option<&mut Confinement>,
    debug_state: &crate::debug_state::RuntimeState,
) -> Option<HostFsInterrupt> {
    let Some((transport, line)) =
        discover_9p_device(cpu, fdt, pci, pci_virtio, arenas, confinement)
    else {
        tracing::warn!("virtio 9p device was not discovered on the platform bus");
        return None;
    };

    debug_state.install_host_fs_service(HostFileSystemService::new(
        transport.clone(),
        cpu.clone(),
        debug_state.profiles(),
    ));
    tracing::info!(
        "virtio 9p online mount_tag={HOST_MOUNT_TAG} irq={}",
        line.number()
    );

    Some(HostFsInterrupt { line, transport })
}

fn discover_9p_device(
    cpu: &crate::RiscvCpu,
    fdt: &Fdt<'_>,
    pci: Option<&PciHostController>,
    pci_virtio: Option<&VirtioFunctions>,
    arenas: &mut RiscvDmaArenas,
    confinement: Option<&mut Confinement>,
) -> Option<(HostFsTransportService, PlicInterrupt)> {
    if let (Some(pci), Some(function)) = (pci, pci_virtio.and_then(|v| v.first(DeviceType::_9P))) {
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
                        "failed to initialize virtio-9p PCI transport at {}: {error}",
                        function.address
                    )
                });
        let device = Virtio9pDevice::new(transport).unwrap_or_else(|error| {
            panic!(
                "failed to initialize virtio-9p PCI device at {}: {error}",
                function.address
            )
        });
        return Some((Virtio9pTransport::new(device), function.line));
    }

    let candidate = helios_virtio::mmio_candidates(fdt)
        .find(|candidate| crate::matches_virtio_mmio_device(candidate.base, DeviceType::_9P))?;
    let base = candidate.base;
    let header = core::ptr::NonNull::new(base as *mut u8)
        .unwrap_or_else(|| panic!("virtio MMIO base {base:#x} was unexpectedly null"));
    let line = candidate
        .interrupt
        .and_then(PlicInterrupt::from_specifier)
        .unwrap_or_else(|| panic!("virtio-9p node at {base:#x} has no valid interrupt source"));
    let dma = iommu::dma_pool(
        arenas,
        None,
        None,
        iommu::LARGE_DMA_CHUNK_BYTES,
        cpu.processor_count(),
    );
    // SAFETY: `candidate` comes from `mmio_candidates(fdt)` and matched
    // `DeviceType::_9P` on the bootstrap hart before interrupts are unmasked,
    // so `header..header + candidate.size` is an identity-mapped VirtIO MMIO
    // 9P register block with exclusive driver access.
    let transport = unsafe { VirtioBusTransport::mmio(header, candidate.size, dma) }
        .unwrap_or_else(|error| {
            panic!("failed to initialize virtio-9p MMIO transport at {base:#x}: {error}")
        });
    let device = Virtio9pDevice::new(transport).unwrap_or_else(|error| {
        panic!("failed to initialize virtio-9p device at {base:#x}: {error}")
    });
    Some((Virtio9pTransport::new(device), line))
}

pub(crate) fn has_9p_device(fdt: &Fdt<'_>, pci_virtio: Option<&VirtioFunctions>) -> bool {
    pci_virtio.is_some_and(|v| v.count(DeviceType::_9P) != 0)
        || crate::count_virtio_mmio_devices(fdt, DeviceType::_9P) != 0
}
