//! virtio-input over PCI or MMIO for the RISC-V backend.
//!
//! Concurrency contract: the devices are discovered and programmed on the
//! bootstrap hart before external interrupts are unmasked. Afterwards each
//! reports on the PLIC line the device tree names, on the hart that takes
//! that PLIC's interrupts.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;

use fdt::Fdt;
use helios_hal::cpu::Cpu;
use helios_kernel::ExternalInterruptHandler;
use helios_virtio::{DeviceType, VirtioBusTransport, VirtioInputDevice as RawVirtioInputDevice};

use crate::iommu::{self, Confinement, RiscvDmaArenas, RiscvVirtioTransport};
use crate::net::PlicInterrupt;
use crate::pci::{PciHostController, VirtioFunctions};

pub(crate) type RiscvVirtioInputDevice = RawVirtioInputDevice<RiscvVirtioTransport>;

/// The interrupt route's view of one input device.
#[derive(Clone)]
pub(crate) struct VirtioInputDevice {
    inner: Arc<RiscvVirtioInputDevice>,
}

impl VirtioInputDevice {
    pub(crate) fn device(&self) -> &Arc<RiscvVirtioInputDevice> {
        &self.inner
    }
}

/// One input device the bootstrap hart brought up, together with the
/// PLIC line the device tree routes it to.
pub(crate) struct InputInterrupt {
    pub(crate) line: PlicInterrupt,
    pub(crate) device: VirtioInputDevice,
}

impl ExternalInterruptHandler for VirtioInputDevice {
    fn handle_interrupt(&self) {
        self.inner.handle_interrupt();
    }
}

pub(crate) fn count_input_devices(fdt: &Fdt<'_>, pci_virtio: Option<&VirtioFunctions>) -> usize {
    pci_virtio.map_or(0, |v| v.count(DeviceType::Input))
        + crate::count_virtio_mmio_devices(fdt, DeviceType::Input)
}

/// Brings up every input device on the PCI and platform buses, hands them
/// all to the kernel, and publishes `helios:system/input`.
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
) -> Vec<InputInterrupt>
where
    WatchdogImpl: helios_hal::watchdog::Watchdog + Clone,
    MeasuredBootImpl: helios_hal::measured_boot::MeasuredBoot,
{
    let discovered = discover_input_devices(cpu, fdt, pci, pci_virtio, arenas, confinement);
    let service = helios_kernel::install_input_devices(
        kernel,
        discovered
            .iter()
            .map(|installed| installed.device.inner.clone()),
    );
    debug_state.install_input_service(service);
    discovered
}

fn discover_input_devices(
    cpu: &crate::RiscvCpu,
    fdt: &Fdt<'_>,
    pci: Option<&PciHostController>,
    pci_virtio: Option<&VirtioFunctions>,
    arenas: &mut RiscvDmaArenas,
    mut confinement: Option<&mut Confinement>,
) -> Vec<InputInterrupt> {
    let mut devices = Vec::new();
    if let (Some(pci), Some(pci_virtio)) = (pci, pci_virtio) {
        for function in pci_virtio.of_type(DeviceType::Input) {
            pci.assign_unassigned_memory_bars(function.address);
            let dma = iommu::dma_pool(
                arenas,
                confinement.as_deref_mut(),
                Some(function.address),
                iommu::SMALL_DMA_CHUNK_BYTES,
                cpu.processor_count(),
            );
            let transport =
                VirtioBusTransport::pci(&pci.config_access(), function.address, pci, dma, None)
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
                line: function.line,
                device: VirtioInputDevice {
                    inner: Arc::new(device),
                },
            });
        }
    }

    for candidate in helios_virtio::mmio_candidates(fdt)
        .filter(|candidate| crate::matches_virtio_mmio_device(candidate.base, DeviceType::Input))
    {
        let base = candidate.base;
        let virt_base = crate::vmm::map_mmio_range(base, candidate.size);
        let header = core::ptr::NonNull::new(virt_base as *mut u8)
            .unwrap_or_else(|| panic!("virtio MMIO base {base:#x} was unexpectedly null"));
        let line = candidate
            .interrupt
            .and_then(PlicInterrupt::from_specifier)
            .unwrap_or_else(|| {
                panic!("virtio-input node at {base:#x} has no valid interrupt source")
            });
        let dma = iommu::dma_pool(
            arenas,
            None,
            None,
            iommu::SMALL_DMA_CHUNK_BYTES,
            cpu.processor_count(),
        );
        // SAFETY: `candidate` comes from `mmio_candidates(fdt)` and matched
        // `DeviceType::Input` on the bootstrap hart before interrupts are
        // unmasked, so `header..header + candidate.size` is an identity-mapped
        // VirtIO MMIO input register block with exclusive driver access.
        let transport = unsafe { VirtioBusTransport::mmio(header, candidate.size, dma) }
            .unwrap_or_else(|error| {
                panic!("failed to initialize virtio-input MMIO transport at {base:#x}: {error}")
            });
        let device = helios_virtio::input_from_bus_transport(transport).unwrap_or_else(|error| {
            panic!("failed to initialize virtio-input device at {base:#x}: {error}")
        });
        devices.push(InputInterrupt {
            line,
            device: VirtioInputDevice {
                inner: Arc::new(device),
            },
        });
    }

    devices
}
