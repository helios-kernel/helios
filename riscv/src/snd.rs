//! virtio-snd over PCI or MMIO for the RISC-V backend.
//!
//! Concurrency contract: the device is discovered and programmed on the
//! bootstrap hart before external interrupts are unmasked. Afterwards its
//! completions and its event reports arrive on the PLIC line the device
//! tree names, on the hart that takes that PLIC's interrupts.

extern crate alloc;

use alloc::sync::Arc;

use fdt::Fdt;
use helios_hal::cpu::Cpu;
use helios_kernel::ExternalInterruptHandler;
use helios_virtio::{DeviceType, VirtioBusTransport, VirtioSndDevice};

use crate::iommu::{self, Confinement, RiscvDmaArenas, RiscvVirtioTransport};
use crate::net::PlicInterrupt;
use crate::pci::{PciHostController, VirtioFunctions};

/// The interrupt route's view of the machine's sound device.
#[derive(Clone)]
pub(crate) struct VirtioSoundDevice {
    inner: Arc<VirtioSndDevice<RiscvVirtioTransport>>,
}

/// The sound device the bootstrap hart brought up, together with the
/// PLIC line the device tree routes it to.
pub(crate) struct SoundInterrupt {
    pub(crate) line: PlicInterrupt,
    pub(crate) device: VirtioSoundDevice,
}

impl ExternalInterruptHandler for VirtioSoundDevice {
    fn handle_interrupt(&self) {
        self.inner.handle_interrupt();
    }
}

pub(crate) fn has_sound_device(fdt: &Fdt<'_>, pci_virtio: Option<&VirtioFunctions>) -> bool {
    pci_virtio.is_some_and(|v| v.count(DeviceType::Sound) != 0)
        || crate::count_virtio_mmio_devices(fdt, DeviceType::Sound) != 0
}

/// Brings the platform's sound device up and hands it to the kernel.
#[allow(clippy::too_many_arguments)]
pub(crate) fn install<WatchdogImpl>(
    cpu: &crate::RiscvCpu,
    kernel: &helios_kernel::Kernel<crate::RiscvCpu, WatchdogImpl>,
    fdt: &Fdt<'_>,
    pci: Option<&PciHostController>,
    pci_virtio: Option<&VirtioFunctions>,
    arenas: &mut RiscvDmaArenas,
    confinement: Option<&mut Confinement>,
    debug_state: &crate::debug_state::RuntimeState,
) -> Option<SoundInterrupt>
where
    WatchdogImpl: helios_hal::watchdog::Watchdog + Clone,
{
    let (device, line) = discover_sound_device(cpu, fdt, pci, pci_virtio, arenas, confinement)?;
    let service = helios_kernel::install_audio_device(kernel, device.inner.clone());
    debug_state.install_audio_service(service);
    Some(SoundInterrupt { line, device })
}

fn discover_sound_device(
    cpu: &crate::RiscvCpu,
    fdt: &Fdt<'_>,
    pci: Option<&PciHostController>,
    pci_virtio: Option<&VirtioFunctions>,
    arenas: &mut RiscvDmaArenas,
    confinement: Option<&mut Confinement>,
) -> Option<(VirtioSoundDevice, PlicInterrupt)> {
    if let (Some(pci), Some(function)) = (pci, pci_virtio.and_then(|v| v.first(DeviceType::Sound)))
    {
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
                        "failed to initialize virtio-snd PCI transport at {}: {error}",
                        function.address
                    )
                });
        let device = helios_virtio::snd_from_bus_transport(transport).unwrap_or_else(|error| {
            panic!(
                "failed to initialize virtio-snd PCI device at {}: {error}",
                function.address
            )
        });
        return Some((
            VirtioSoundDevice {
                inner: Arc::new(device),
            },
            function.line,
        ));
    }

    let candidate = helios_virtio::mmio_candidates(fdt)
        .find(|candidate| crate::matches_virtio_mmio_device(candidate.base, DeviceType::Sound))?;
    let base = candidate.base;
    let header = core::ptr::NonNull::new(base as *mut u8)
        .unwrap_or_else(|| panic!("virtio MMIO base {base:#x} was unexpectedly null"));
    let line = candidate
        .interrupt
        .and_then(PlicInterrupt::from_specifier)
        .unwrap_or_else(|| panic!("virtio-snd node at {base:#x} has no valid interrupt source"));
    let dma = iommu::dma_pool(
        arenas,
        None,
        None,
        iommu::SMALL_DMA_CHUNK_BYTES,
        cpu.processor_count(),
    );
    // SAFETY: `candidate` comes from `mmio_candidates(fdt)` and matched
    // `DeviceType::Sound` on the bootstrap hart before interrupts are
    // unmasked, so `header..header + candidate.size` is an identity-mapped
    // VirtIO MMIO sound register block with exclusive driver access.
    let transport = unsafe { VirtioBusTransport::mmio(header, candidate.size, dma) }
        .unwrap_or_else(|error| {
            panic!("failed to initialize virtio-snd MMIO transport at {base:#x}: {error}")
        });
    let device = helios_virtio::snd_from_bus_transport(transport).unwrap_or_else(|error| {
        panic!("failed to initialize virtio-snd device at {base:#x}: {error}")
    });
    Some((
        VirtioSoundDevice {
            inner: Arc::new(device),
        },
        line,
    ))
}
