//! virtio-input over PCI or MMIO for the AArch64 backend.
//!
//! Concurrency contract: the devices are discovered and programmed on the
//! bootstrap processor before IRQs are unmasked. Afterwards each reports on
//! the SPI the firmware names, delivered to that same processor.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;

use arm_gic::{IntId, Trigger};
use helios_hal::cpu::Cpu;
use helios_kernel::ExternalInterruptHandler;
use helios_virtio::{DeviceType, VirtioBusTransport, VirtioInputDevice as RawVirtioInputDevice};

use crate::iommu::{self, Aarch64DmaArenas, Aarch64VirtioTransport, Confinement};
use crate::pci::{PciRoot, VirtioFunctions};
use crate::platform::PlatformDescription;

pub(crate) type Aarch64VirtioInputDevice = RawVirtioInputDevice<Aarch64VirtioTransport>;

/// The interrupt route's view of one input device.
#[derive(Clone)]
pub(crate) struct VirtioInputDevice {
    inner: Arc<Aarch64VirtioInputDevice>,
}

impl VirtioInputDevice {
    pub(crate) fn device(&self) -> &Arc<Aarch64VirtioInputDevice> {
        &self.inner
    }
}

/// One input device the bootstrap processor brought up, together with
/// the interrupt the firmware routes it to.
pub(crate) struct InputInterrupt {
    pub(crate) interrupt: IntId,
    pub(crate) trigger: Trigger,
    pub(crate) device: VirtioInputDevice,
}

impl ExternalInterruptHandler for VirtioInputDevice {
    fn handle_interrupt(&self) {
        self.inner.handle_interrupt();
    }
}

pub(crate) fn count_input_devices(
    platform: &PlatformDescription,
    pci_virtio: Option<&VirtioFunctions>,
) -> usize {
    pci_virtio.map_or(0, |v| v.count(DeviceType::Input))
        + crate::count_virtio_mmio_devices(platform, DeviceType::Input)
}

/// Brings up every input device on the PCI and platform buses, hands them
/// all to the kernel, and publishes `helios:system/input`.
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
) -> Vec<InputInterrupt>
where
    WatchdogImpl: helios_hal::watchdog::Watchdog + Clone,
    MeasuredBootImpl: helios_hal::measured_boot::MeasuredBoot,
{
    let discovered = discover_input_devices(
        cpu,
        platform,
        pci,
        pci_virtio,
        arenas,
        confinement,
        physical_memory_offset,
        handoff,
    );
    let service = helios_kernel::install_input_devices(
        kernel,
        discovered
            .iter()
            .map(|installed| installed.device.inner.clone()),
    );
    debug_state.install_input_service(service);
    discovered
}

#[allow(clippy::too_many_arguments)]
fn discover_input_devices(
    cpu: &crate::Aarch64Cpu,
    platform: &PlatformDescription,
    pci: Option<&PciRoot>,
    pci_virtio: Option<&VirtioFunctions>,
    arenas: &mut Aarch64DmaArenas,
    mut confinement: Option<&mut Confinement>,
    physical_memory_offset: usize,
    handoff: &crate::LimineBootHandoff,
) -> Vec<InputInterrupt> {
    let mut devices = Vec::new();
    if let (Some(pci), Some(pci_virtio)) = (pci, pci_virtio) {
        for function in pci_virtio.of_type(DeviceType::Input) {
            pci.assign_unassigned_memory_bars(function.address);
            let dma = iommu::dma_pool(
                arenas,
                confinement.as_deref_mut(),
                Some(function.address),
                physical_memory_offset,
                iommu::SMALL_DMA_CHUNK_BYTES,
                cpu.processor_count(),
            );
            let transport =
                VirtioBusTransport::pci(&pci.access(), function.address, pci, dma, None)
                    .unwrap_or_else(|error| {
                        panic!(
                            "failed to initialize virtio-input PCI transport at {}: {error}",
                            function.address
                        )
                    });
            let device =
                helios_virtio::input_from_bus_transport(transport).unwrap_or_else(|error| {
                    panic!(
                        "failed to initialize virtio-input PCI device at {}: {error}",
                        function.address
                    )
                });
            devices.push(InputInterrupt {
                interrupt: function.interrupt,
                trigger: function.trigger,
                device: VirtioInputDevice {
                    inner: Arc::new(device),
                },
            });
        }
    }

    for candidate in
        crate::virtio_slots(platform, physical_memory_offset, handoff, DeviceType::Input)
    {
        let (interrupt, trigger) = (candidate.interrupt.intid(), candidate.interrupt.trigger);
        assert!(
            candidate.region.size != 0,
            "AArch64 virtio-input node has zero MMIO size"
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
                    "failed to initialize virtio-input MMIO transport at {:#x}: {error}",
                    candidate.region.base
                )
            });
        let device = helios_virtio::input_from_bus_transport(transport).unwrap_or_else(|error| {
            panic!(
                "failed to initialize virtio-input device at {:#x}: {error}",
                candidate.region.base
            )
        });
        devices.push(InputInterrupt {
            interrupt,
            trigger,
            device: VirtioInputDevice {
                inner: Arc::new(device),
            },
        });
    }

    devices
}
