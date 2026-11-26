//! virtio-entropy over PCI or MMIO for the RISC-V backend.
//!
//! Concurrency contract: the device is discovered and programmed on the
//! bootstrap hart before external interrupts are unmasked. Afterwards the
//! kernel's reseed task is its only reader and completions arrive on the
//! PLIC source the device tree names, so the reader parks on a notification
//! rather than polling the used ring.

extern crate alloc;

use alloc::sync::Arc;
use core::future::Future;

use fdt::Fdt;
use helios_hal::io::IoError;
use helios_kernel::{ExternalInterruptHandler, HardwareEntropySource};
use helios_virtio::{DeviceType, VirtioBusTransport, VirtioRngDevice};

use crate::iommu::{self, Confinement, RiscvDmaArenas, RiscvVirtioTransport};
use crate::net::PlicInterrupt;
use crate::pci::{PciHostController, VirtioFunctions};

pub(crate) type RiscvVirtioRngDevice = VirtioRngDevice<RiscvVirtioTransport>;

#[derive(Clone)]
pub(crate) struct VirtioEntropyDevice {
    inner: Arc<RiscvVirtioRngDevice>,
}

impl VirtioEntropyDevice {
    pub(crate) fn device(&self) -> &Arc<RiscvVirtioRngDevice> {
        &self.inner
    }
}

/// The entropy device the bootstrap hart brought up, together with the
/// PLIC line the device tree routes it to.
pub(crate) struct EntropyInterrupt {
    pub(crate) line: PlicInterrupt,
    pub(crate) device: VirtioEntropyDevice,
}

impl ExternalInterruptHandler for VirtioEntropyDevice {
    fn handle_interrupt(&self) {
        self.inner.handle_interrupt();
    }
}

impl HardwareEntropySource for VirtioEntropyDevice {
    fn fill<'a>(
        &'a self,
        buffer: &'a mut [u8],
    ) -> impl Future<Output = Result<(), IoError>> + Send + 'a {
        self.inner.fill(buffer)
    }

    fn drain_completions(&self) {
        self.inner.handle_interrupt();
    }
}

pub(crate) fn has_entropy_device(fdt: &Fdt<'_>, pci_virtio: Option<&VirtioFunctions>) -> bool {
    pci_virtio.is_some_and(|v| v.count(DeviceType::Entropy) != 0)
        || crate::count_virtio_mmio_devices(fdt, DeviceType::Entropy) != 0
}

/// Brings the platform's entropy device up.
///
/// Called after IOMMU confinement so a PCI `virtio-rng` behind
/// `virtio-iommu-pci` is never touched before it has a domain, and before
/// `seed_root_entropy` so a platform whose firmware leaves no
/// `/chosen/rng-seed` still seeds its root DRBG from hardware entropy.
pub(crate) fn bring_up(
    fdt: &Fdt<'_>,
    pci: Option<&PciHostController>,
    pci_virtio: Option<&VirtioFunctions>,
    arenas: &mut RiscvDmaArenas,
    confinement: Option<&mut Confinement>,
    processors: usize,
) -> Option<EntropyInterrupt> {
    let Some((device, line)) =
        discover_entropy_device(fdt, pci, pci_virtio, arenas, confinement, processors)
    else {
        tracing::warn!("virtio entropy device was not discovered on the platform bus");
        return None;
    };
    Some(EntropyInterrupt { line, device })
}

/// Hands the device to the kernel's reseed task.
pub(crate) fn install<WatchdogImpl, MeasuredBootImpl>(
    kernel: &helios_kernel::Kernel<crate::RiscvCpu, WatchdogImpl, MeasuredBootImpl>,
    entropy: &EntropyInterrupt,
    root: helios_kernel::RootEntropyHandle,
) where
    WatchdogImpl: helios_hal::watchdog::Watchdog + Clone,
    MeasuredBootImpl: helios_hal::measured_boot::MeasuredBoot,
{
    helios_kernel::install_entropy_device(kernel, root, entropy.device.clone());
    tracing::info!("virtio entropy online irq={}", entropy.line.number());
}

fn discover_entropy_device(
    fdt: &Fdt<'_>,
    pci: Option<&PciHostController>,
    pci_virtio: Option<&VirtioFunctions>,
    arenas: &mut RiscvDmaArenas,
    confinement: Option<&mut Confinement>,
    processors: usize,
) -> Option<(VirtioEntropyDevice, PlicInterrupt)> {
    if let (Some(pci), Some(function)) =
        (pci, pci_virtio.and_then(|v| v.first(DeviceType::Entropy)))
    {
        pci.assign_unassigned_memory_bars(function.address);
        let dma = iommu::dma_pool(
            arenas,
            confinement,
            Some(function.address),
            iommu::SMALL_DMA_CHUNK_BYTES,
            processors,
        );
        let transport =
            VirtioBusTransport::pci(&pci.config_access(), function.address, pci, dma, None)
                .unwrap_or_else(|error| {
                    panic!(
                        "failed to initialize virtio-rng PCI transport at {}: {error}",
                        function.address
                    )
                });
        let device = VirtioRngDevice::new(transport).unwrap_or_else(|error| {
            panic!(
                "failed to initialize virtio-rng PCI device at {}: {error}",
                function.address
            )
        });
        return Some((
            VirtioEntropyDevice {
                inner: Arc::new(device),
            },
            function.line,
        ));
    }

    let candidate = helios_virtio::mmio_candidates(fdt)
        .find(|candidate| crate::matches_virtio_mmio_device(candidate.base, DeviceType::Entropy))?;
    let base = candidate.base;
    let header = core::ptr::NonNull::new(base as *mut u8)
        .unwrap_or_else(|| panic!("virtio MMIO base {base:#x} was unexpectedly null"));
    let line = candidate
        .interrupt
        .and_then(PlicInterrupt::from_specifier)
        .unwrap_or_else(|| panic!("virtio-rng node at {base:#x} has no valid interrupt source"));
    let dma = iommu::dma_pool(arenas, None, None, iommu::SMALL_DMA_CHUNK_BYTES, processors);
    // SAFETY: `candidate` comes from `mmio_candidates(fdt)` and matched
    // `DeviceType::Entropy` on the bootstrap hart before interrupts are
    // unmasked, so `header..header + candidate.size` is an identity-mapped
    // VirtIO MMIO entropy register block with exclusive driver access.
    let transport = unsafe { VirtioBusTransport::mmio(header, candidate.size, dma) }
        .unwrap_or_else(|error| {
            panic!("failed to initialize virtio-rng MMIO transport at {base:#x}: {error}")
        });
    let device = VirtioRngDevice::new(transport).unwrap_or_else(|error| {
        panic!("failed to initialize virtio-rng device at {base:#x}: {error}")
    });
    Some((
        VirtioEntropyDevice {
            inner: Arc::new(device),
        },
        line,
    ))
}
