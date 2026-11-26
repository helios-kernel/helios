//! virtio-entropy over PCI or MMIO for the AArch64 backend.
//!
//! Concurrency contract: the device is discovered and programmed on the
//! bootstrap processor before IRQs are unmasked. Afterwards the kernel's
//! reseed task is its only reader, and completions arrive on the SPI the
//! firmware names, so the reader parks on a notification rather than polling
//! the used ring.

extern crate alloc;

use core::future::Future;

use arm_gic::{IntId, Trigger};
use helios_hal::io::IoError;
use helios_kernel::{ExternalInterruptHandler, HardwareEntropySource, RootEntropyHandle};
use helios_virtio::{DeviceType, VirtioBusTransport, VirtioRngDevice};
use triomphe::Arc;

use crate::iommu::{self, Aarch64DmaArenas, Aarch64VirtioTransport, Confinement};
use crate::pci::{PciRoot, VirtioFunctions};
use crate::platform::PlatformDescription;

pub(crate) type Aarch64VirtioRngDevice = VirtioRngDevice<Aarch64VirtioTransport>;

#[derive(Clone)]
pub(crate) struct VirtioEntropyDevice {
    device: Arc<Aarch64VirtioRngDevice>,
}

impl VirtioEntropyDevice {
    pub(crate) fn device(&self) -> &Arc<Aarch64VirtioRngDevice> {
        &self.device
    }
}

/// The entropy device the bootstrap processor brought up, together with
/// the interrupt the firmware routes it to.
pub(crate) struct EntropyInterrupt {
    pub(crate) interrupt: IntId,
    pub(crate) trigger: Trigger,
    pub(crate) device: VirtioEntropyDevice,
}

impl ExternalInterruptHandler for VirtioEntropyDevice {
    fn handle_interrupt(&self) {
        self.device.handle_interrupt();
    }
}

impl HardwareEntropySource for VirtioEntropyDevice {
    fn fill<'a>(
        &'a self,
        buffer: &'a mut [u8],
    ) -> impl Future<Output = Result<(), IoError>> + Send + 'a {
        self.device.fill(buffer)
    }

    fn drain_completions(&self) {
        self.device.handle_interrupt();
    }
}

pub(crate) fn has_entropy_device(
    platform: &PlatformDescription,
    pci_virtio: Option<&VirtioFunctions>,
) -> bool {
    pci_virtio.is_some_and(|v| v.count(DeviceType::Entropy) != 0)
        || crate::count_virtio_mmio_devices(platform, DeviceType::Entropy) != 0
}

/// Brings the platform's entropy device up.
///
/// Called after IOMMU confinement so a PCI `virtio-rng` behind
/// `virtio-iommu-pci` is never touched before it has a domain, and before
/// `seed_root_entropy` so an ACPI machine without `FEAT_RNG` still seeds its
/// root DRBG (and MTE/PAC keys) from hardware entropy.
#[allow(clippy::too_many_arguments)]
pub(crate) fn bring_up(
    platform: &PlatformDescription,
    pci: Option<&PciRoot>,
    pci_virtio: Option<&VirtioFunctions>,
    arenas: &mut Aarch64DmaArenas,
    confinement: Option<&mut Confinement>,
    physical_memory_offset: usize,
    handoff: &crate::LimineBootHandoff,
    processors: usize,
) -> Option<EntropyInterrupt> {
    let entropy = discover_entropy_device(
        platform,
        pci,
        pci_virtio,
        arenas,
        confinement,
        physical_memory_offset,
        handoff,
        processors,
    );
    if entropy.is_none() {
        tracing::warn!("virtio entropy device was not discovered on the platform bus");
    }
    entropy
}

/// Hands the device to the kernel's reseed task.
pub(crate) fn install<WatchdogImpl, MeasuredBootImpl>(
    kernel: &helios_kernel::Kernel<crate::Aarch64Cpu, WatchdogImpl, MeasuredBootImpl>,
    entropy: &EntropyInterrupt,
    root: RootEntropyHandle,
) where
    WatchdogImpl: helios_hal::watchdog::Watchdog + Clone,
    MeasuredBootImpl: helios_hal::measured_boot::MeasuredBoot,
{
    helios_kernel::install_entropy_device(kernel, root, entropy.device.clone());
    tracing::info!("virtio entropy online interrupt={:?}", entropy.interrupt);
}

#[allow(clippy::too_many_arguments)]
fn discover_entropy_device(
    platform: &PlatformDescription,
    pci: Option<&PciRoot>,
    pci_virtio: Option<&VirtioFunctions>,
    arenas: &mut Aarch64DmaArenas,
    confinement: Option<&mut Confinement>,
    physical_memory_offset: usize,
    handoff: &crate::LimineBootHandoff,
    processors: usize,
) -> Option<EntropyInterrupt> {
    if let (Some(pci), Some(function)) =
        (pci, pci_virtio.and_then(|v| v.first(DeviceType::Entropy)))
    {
        pci.assign_unassigned_memory_bars(function.address);
        let dma = iommu::dma_pool(
            arenas,
            confinement,
            Some(function.address),
            physical_memory_offset,
            iommu::SMALL_DMA_CHUNK_BYTES,
            processors,
        );
        let transport = VirtioBusTransport::pci(&pci.access(), function.address, pci, dma, None)
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
        return Some(EntropyInterrupt {
            interrupt: function.interrupt,
            trigger: function.trigger,
            device: VirtioEntropyDevice {
                device: Arc::new(device),
            },
        });
    }

    let candidate = crate::virtio_slots(
        platform,
        physical_memory_offset,
        handoff,
        DeviceType::Entropy,
    )
    .next()?;
    let (interrupt, trigger) = (candidate.interrupt.intid(), candidate.interrupt.trigger);
    assert!(
        candidate.region.size != 0,
        "AArch64 virtio-rng node has zero MMIO size"
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
        processors,
    );
    // SAFETY: `map_mmio_range` mapped `header..header + candidate.region.size`
    // as Device-nGnRnE, the device is brought up on the bootstrap processor
    // before IRQs are unmasked with exclusive register access, and `dma`
    // translates using the kernel's direct-map offset.
    let transport = unsafe { VirtioBusTransport::mmio(header, candidate.region.size, dma) }
        .unwrap_or_else(|error| {
            panic!(
                "failed to initialize virtio-rng MMIO transport at {:#x}: {error}",
                candidate.region.base
            )
        });
    let device = VirtioRngDevice::new(transport).unwrap_or_else(|error| {
        panic!(
            "failed to initialize virtio-rng device at {:#x}: {error}",
            candidate.region.base
        )
    });
    Some(EntropyInterrupt {
        interrupt,
        trigger,
        device: VirtioEntropyDevice {
            device: Arc::new(device),
        },
    })
}
