//! virtio-vsock over PCI or MMIO for the AArch64 backend.
//!
//! Concurrency contract: the device is discovered and programmed on the
//! bootstrap processor before IRQs are unmasked. Afterwards the kernel's
//! vsock service owns it — one receive pump plus whichever tasks are
//! transmitting — and completions arrive on the SPI the firmware names, so
//! every waiter parks on a notification rather than polling.

extern crate alloc;

use alloc::sync::Arc;

use arm_gic::{IntId, Trigger};
use helios_hal::cpu::Cpu;
use helios_kernel::ExternalInterruptHandler;
use helios_virtio::{DeviceType, VirtioBusTransport, VirtioVsockDevice as RawVirtioVsockDevice};

use crate::iommu::{self, Aarch64DmaArenas, Aarch64VirtioTransport, Confinement};
use crate::pci::{PciRoot, VirtioFunctions};
use crate::platform::PlatformDescription;

type Aarch64VirtioVsockDevice = RawVirtioVsockDevice<Aarch64VirtioTransport>;

/// The interrupt route's view of the platform's vsock device.
#[derive(Clone)]
pub(crate) struct VirtioVsockDevice {
    device: Arc<Aarch64VirtioVsockDevice>,
}

/// The vsock device the bootstrap processor brought up, together with
/// the interrupt the firmware routes it to.
pub(crate) struct VsockInterrupt {
    pub(crate) interrupt: IntId,
    pub(crate) trigger: Trigger,
    pub(crate) device: VirtioVsockDevice,
}

impl ExternalInterruptHandler for VirtioVsockDevice {
    fn handle_interrupt(&self) {
        self.device.handle_interrupt();
    }
}

pub(crate) fn has_vsock_device(
    platform: &PlatformDescription,
    pci_virtio: Option<&VirtioFunctions>,
) -> bool {
    pci_virtio.is_some_and(|v| v.count(DeviceType::Vsock) != 0)
        || crate::count_virtio_mmio_devices(platform, DeviceType::Vsock) != 0
}

/// Brings up the vsock device and publishes it as the machine's host link.
#[allow(clippy::too_many_arguments)]
pub(crate) fn install<WatchdogImpl, MeasuredBootImpl>(
    kernel: &helios_kernel::Kernel<crate::Aarch64Cpu, WatchdogImpl, MeasuredBootImpl>,
    cpu: &crate::Aarch64Cpu,
    platform: &PlatformDescription,
    pci: Option<&PciRoot>,
    pci_virtio: Option<&VirtioFunctions>,
    arenas: &mut Aarch64DmaArenas,
    confinement: Option<&mut Confinement>,
    physical_memory_offset: usize,
    handoff: &crate::LimineBootHandoff,
    debug_state: &crate::debug_state::RuntimeState,
) -> Option<VsockInterrupt>
where
    WatchdogImpl: helios_hal::watchdog::Watchdog + Clone,
    MeasuredBootImpl: helios_hal::measured_boot::MeasuredBoot,
{
    let vsock = discover_vsock_device(
        cpu,
        platform,
        pci,
        pci_virtio,
        arenas,
        confinement,
        physical_memory_offset,
        handoff,
    )?;
    let service = helios_kernel::install_vsock_device(kernel, cpu, vsock.device.device.clone());
    let guest_cid = service.guest_cid();
    debug_state.install_vsock_service(helios_kernel::ComponentHostVsockService::from_service(
        service,
    ));
    tracing::info!(
        guest_cid,
        interrupt = ?vsock.interrupt,
        "virtio vsock online"
    );
    Some(vsock)
}

#[allow(clippy::too_many_arguments)]
fn discover_vsock_device(
    cpu: &crate::Aarch64Cpu,
    platform: &PlatformDescription,
    pci: Option<&PciRoot>,
    pci_virtio: Option<&VirtioFunctions>,
    arenas: &mut Aarch64DmaArenas,
    confinement: Option<&mut Confinement>,
    physical_memory_offset: usize,
    handoff: &crate::LimineBootHandoff,
) -> Option<VsockInterrupt> {
    if let (Some(pci), Some(function)) = (pci, pci_virtio.and_then(|v| v.first(DeviceType::Vsock)))
    {
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
        return Some(VsockInterrupt {
            interrupt: function.interrupt,
            trigger: function.trigger,
            device: VirtioVsockDevice {
                device: Arc::new(device),
            },
        });
    }

    let candidate =
        crate::virtio_slots(platform, physical_memory_offset, handoff, DeviceType::Vsock).next()?;
    let (interrupt, trigger) = (candidate.interrupt.intid(), candidate.interrupt.trigger);
    assert!(
        candidate.region.size != 0,
        "AArch64 virtio-vsock node has zero MMIO size"
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
                "failed to initialize virtio-vsock MMIO transport at {:#x}: {error}",
                candidate.region.base
            )
        });
    let device = RawVirtioVsockDevice::new(transport).unwrap_or_else(|error| {
        panic!(
            "failed to initialize virtio-vsock device at {:#x}: {error}",
            candidate.region.base
        )
    });
    Some(VsockInterrupt {
        interrupt,
        trigger,
        device: VirtioVsockDevice {
            device: Arc::new(device),
        },
    })
}
