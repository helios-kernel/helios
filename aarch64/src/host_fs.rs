//! virtio-9p host share over PCI or MMIO for the AArch64 backend.
//!
//! Concurrency contract: the device is constructed on the bootstrap processor
//! before IRQs are unmasked. Afterwards every caller submits straight to the
//! device, which pipelines requests and routes each completion back to the
//! task that submitted it.

use arm_gic::{IntId, Trigger};
use helios_hal::cpu::Cpu;
use helios_kernel::Virtio9pTransport;
use helios_virtio::{DeviceType, Virtio9pDevice, VirtioBusTransport};

use crate::iommu::{self, Aarch64DmaArenas, Aarch64VirtioTransport, Confinement};
use crate::pci::{PciRoot, VirtioFunctions};
use crate::platform::PlatformDescription;

pub(crate) type HostFsTransportService = Virtio9pTransport<Aarch64VirtioTransport>;

pub(crate) type HostFileSystemService =
    helios_kernel::HostFsClient<HostFsTransportService, crate::Aarch64Cpu>;

/// The 9p transport the bootstrap processor brought up, together with
/// the interrupt the firmware routes it to.
pub(crate) struct HostFsInterrupt {
    pub(crate) interrupt: IntId,
    pub(crate) trigger: Trigger,
    pub(crate) transport: HostFsTransportService,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn install(
    cpu: &crate::Aarch64Cpu,
    platform: &PlatformDescription,
    pci: Option<&PciRoot>,
    pci_virtio: Option<&VirtioFunctions>,
    arenas: &mut Aarch64DmaArenas,
    confinement: Option<&mut Confinement>,
    physical_memory_offset: usize,
    handoff: &crate::LimineBootHandoff,
    debug_state: &crate::debug_state::RuntimeState,
) -> Option<HostFsInterrupt> {
    let Some(probe) = discover_9p_device(
        cpu,
        platform,
        pci,
        pci_virtio,
        arenas,
        confinement,
        physical_memory_offset,
        handoff,
    ) else {
        tracing::warn!("virtio 9p device was not discovered on the platform bus");
        return None;
    };
    let service = HostFileSystemService::new(probe.transport.clone(), *cpu, debug_state.profiles());
    debug_state.install_host_fs_service(service);
    tracing::info!(
        "virtio 9p online mount_tag={} interrupt={:?}",
        helios_kernel::HOST_SHARE_MOUNT_TAG,
        probe.interrupt
    );
    Some(probe)
}

pub(crate) fn has_9p_device(
    platform: &PlatformDescription,
    pci_virtio: Option<&VirtioFunctions>,
) -> bool {
    pci_virtio.is_some_and(|v| v.count(DeviceType::_9P) != 0)
        || crate::count_virtio_mmio_devices(platform, DeviceType::_9P) != 0
}

#[allow(clippy::too_many_arguments)]
fn discover_9p_device(
    cpu: &crate::Aarch64Cpu,
    platform: &PlatformDescription,
    pci: Option<&PciRoot>,
    pci_virtio: Option<&VirtioFunctions>,
    arenas: &mut Aarch64DmaArenas,
    confinement: Option<&mut Confinement>,
    physical_memory_offset: usize,
    handoff: &crate::LimineBootHandoff,
) -> Option<HostFsInterrupt> {
    if let (Some(pci), Some(function)) = (pci, pci_virtio.and_then(|v| v.first(DeviceType::_9P))) {
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
        return Some(HostFsInterrupt {
            interrupt: function.interrupt,
            trigger: function.trigger,
            transport: Virtio9pTransport::new(device),
        });
    }

    let candidate =
        crate::virtio_slots(platform, physical_memory_offset, handoff, DeviceType::_9P).next()?;
    let (interrupt, trigger) = (candidate.interrupt.intid(), candidate.interrupt.trigger);
    let physical_base = candidate.region.base;
    let size = candidate.region.size;
    assert!(size != 0, "AArch64 virtio-9p node has zero MMIO size");
    crate::map_mmio_range(physical_base, size, physical_memory_offset, handoff);
    let virtual_base = crate::mmio_virtual_base(physical_base, physical_memory_offset);
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
    // SAFETY: `map_mmio_range` mapped `header..header + size` as Device-nGnRnE,
    // the device is brought up on the bootstrap processor before IRQs are
    // unmasked with exclusive register access, and `dma` translates using the
    // kernel's direct-map offset.
    let transport =
        unsafe { VirtioBusTransport::mmio(header, size, dma) }.unwrap_or_else(|error| {
            panic!("failed to initialize virtio-9p MMIO transport at {physical_base:#x}: {error}")
        });
    let device = Virtio9pDevice::new(transport).unwrap_or_else(|error| {
        panic!("failed to initialize virtio-9p device at {physical_base:#x}: {error}")
    });
    Some(HostFsInterrupt {
        interrupt,
        trigger,
        transport: Virtio9pTransport::new(device),
    })
}
