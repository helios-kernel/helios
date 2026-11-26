//! virtio-blk over PCI or MMIO for the AArch64 backend.
//!
//! Every block device discovered on the PCI or platform bus is brought up
//! here, up to the block interrupt routes the kernel's table holds; what
//! each of them is for is the kernel's decision, taken from the serials
//! they report.
//!
//! Concurrency contract: the devices are discovered and programmed on the
//! bootstrap processor before IRQs are unmasked, and their completions
//! arrive on the SPIs the firmware names, so every reader parks on a
//! notification rather than polling a used ring.

extern crate alloc;

use alloc::vec::Vec;
use core::fmt;

use arm_gic::{IntId, Trigger};
use helios_hal::cpu::Cpu;
use helios_hal::fs::BlockDeviceRights;
use helios_kernel::ExternalInterruptHandler;
use helios_virtio::{
    DeviceType, VirtioBlockDevice as RawVirtioBlockDevice, VirtioBlockResource, VirtioBusTransport,
};

use crate::Aarch64Cpu;
use crate::debug_state::RuntimeState;
use crate::iommu::{self, Aarch64DmaArenas, Aarch64VirtioTransport, Confinement};
use crate::pci::{PciRoot, VirtioFunctions, VirtioPciFunction};
use crate::platform::{PlatformDescription, VirtioMmioSlot};

pub(crate) type Aarch64VirtioBlockDevice =
    VirtioBlockResource<Aarch64VirtioTransport, Aarch64Cpu, helios_kernel::BlockPages>;

#[derive(Clone)]
pub(crate) struct VirtioBlockDevice {
    inner: Aarch64VirtioBlockDevice,
}

/// One block device the bootstrap processor brought up, together with
/// the interrupt the firmware routes it to.
pub(crate) struct BlockInterrupt {
    pub(crate) interrupt: IntId,
    pub(crate) trigger: Trigger,
    pub(crate) device: VirtioBlockDevice,
}

impl ExternalInterruptHandler for VirtioBlockDevice {
    fn handle_interrupt(&self) {
        self.inner.handle_interrupt();
    }
}

pub(crate) fn count_block_devices(
    platform: &PlatformDescription,
    pci_virtio: Option<&VirtioFunctions>,
) -> usize {
    pci_virtio.map_or(0, |v| v.count(DeviceType::Block))
        + crate::count_virtio_mmio_devices(platform, DeviceType::Block)
}

enum BlockCandidate {
    Pci(VirtioPciFunction),
    Mmio(VirtioMmioSlot),
}

impl fmt::Display for BlockCandidate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pci(function) => write!(f, "PCI {}", function.address),
            Self::Mmio(slot) => write!(f, "MMIO {:#x}", slot.region.base),
        }
    }
}

/// Brings up every block device on the PCI and platform buses and hands
/// them to the kernel, which gives each the role its serial names and
/// returns the scratch disk for swap.
#[allow(clippy::too_many_arguments)]
pub(crate) fn install<WatchdogImpl, MeasuredBootImpl>(
    cpu: &Aarch64Cpu,
    kernel: &helios_kernel::Kernel<Aarch64Cpu, WatchdogImpl, MeasuredBootImpl>,
    platform: &PlatformDescription,
    pci: Option<&PciRoot>,
    pci_virtio: Option<&VirtioFunctions>,
    arenas: &mut Aarch64DmaArenas,
    confinement: Option<&mut Confinement>,
    physical_memory_offset: usize,
    handoff: &crate::LimineBootHandoff,
    debug_state: &RuntimeState,
    root: helios_kernel::RootEntropyHandle,
) -> Vec<BlockInterrupt>
where
    WatchdogImpl: helios_hal::watchdog::Watchdog + Clone,
    MeasuredBootImpl: helios_hal::measured_boot::MeasuredBoot,
{
    let discovered = discover_block_devices(
        cpu,
        platform,
        pci,
        pci_virtio,
        arenas,
        confinement,
        physical_memory_offset,
        handoff,
    );
    let devices: Vec<_> = discovered
        .iter()
        .map(|interrupt| interrupt.device.inner.clone())
        .collect();
    let state = debug_state.clone();
    let spawner = kernel.spawner();
    let timer = kernel.timer();
    let swap_cpu = *cpu;
    if !devices.is_empty() {
        debug_state.begin_block_discovery();
    }
    helios_kernel::install_block_devices(
        kernel,
        root,
        devices,
        move |service, scratch, mount_sources| {
            state.install_block_service(service);
            if let Some(cache) = mount_sources {
                state.install_mount_sources(cache);
            }
            state.finish_block_discovery();
            if let Some(swap) = helios_kernel::install_scratch_swap(
                state.instance_registry(),
                scratch,
                spawner,
                timer,
                swap_cpu,
                "virtio-blk",
                helios_virtio::VirtioBlockSwapBackend::new,
            ) {
                state.install_swap(swap);
            }
        },
    );
    for interrupt in &discovered {
        tracing::info!(interrupt = ?interrupt.interrupt, "virtio block online");
    }
    discovered
}

#[allow(clippy::too_many_arguments)]
fn discover_block_devices(
    cpu: &Aarch64Cpu,
    platform: &PlatformDescription,
    pci: Option<&PciRoot>,
    pci_virtio: Option<&VirtioFunctions>,
    arenas: &mut Aarch64DmaArenas,
    mut confinement: Option<&mut Confinement>,
    physical_memory_offset: usize,
    handoff: &crate::LimineBootHandoff,
) -> Vec<BlockInterrupt> {
    let mut candidates = Vec::new();
    if let Some(pci_virtio) = pci_virtio {
        candidates.extend(
            pci_virtio
                .of_type(DeviceType::Block)
                .map(BlockCandidate::Pci),
        );
    }
    candidates.extend(
        crate::virtio_slots(platform, physical_memory_offset, handoff, DeviceType::Block)
            .map(BlockCandidate::Mmio),
    );

    helios_kernel::admit_block_devices(candidates)
        .into_iter()
        .map(|candidate| match candidate {
            BlockCandidate::Pci(function) => {
                let pci = pci.expect("PCI virtio-blk candidate requires a PCI root");
                pci.assign_unassigned_memory_bars(function.address);
                let dma = iommu::dma_pool(
                    arenas,
                    confinement.as_deref_mut(),
                    Some(function.address),
                    physical_memory_offset,
                    iommu::LARGE_DMA_CHUNK_BYTES,
                    cpu.processor_count(),
                );
                let transport =
                    VirtioBusTransport::pci(&pci.access(), function.address, pci, dma, None)
                        .unwrap_or_else(|error| {
                            panic!(
                                "failed to initialize virtio-blk PCI transport at {}: {error}",
                                function.address
                            )
                        });
                let device = RawVirtioBlockDevice::new_resource(
                    transport,
                    *cpu,
                    BlockDeviceRights::READ | BlockDeviceRights::WRITE,
                )
                .unwrap_or_else(|error| {
                    panic!(
                        "failed to initialize virtio-blk PCI device at {}: {error}",
                        function.address
                    )
                });
                BlockInterrupt {
                    interrupt: function.interrupt,
                    trigger: function.trigger,
                    device: VirtioBlockDevice { inner: device },
                }
            }
            BlockCandidate::Mmio(candidate) => {
                let (interrupt, trigger) =
                    (candidate.interrupt.intid(), candidate.interrupt.trigger);
                assert!(
                    candidate.region.size != 0,
                    "AArch64 virtio-blk node has zero MMIO size"
                );
                crate::map_mmio_range(
                    candidate.region.base,
                    candidate.region.size,
                    physical_memory_offset,
                    handoff,
                );
                let virtual_base =
                    crate::mmio_virtual_base(candidate.region.base, physical_memory_offset);
                assert!(
                    virtual_base.is_multiple_of(core::mem::align_of::<u32>()),
                    "virtio MMIO base {virtual_base:#x} is not 4-byte aligned"
                );
                let header =
                    core::ptr::NonNull::new(virtual_base as *mut u8).unwrap_or_else(|| {
                        panic!("virtio MMIO base {virtual_base:#x} was unexpectedly null")
                    });
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
                let transport =
                    unsafe { VirtioBusTransport::mmio(header, candidate.region.size, dma) }
                        .unwrap_or_else(|error| {
                            panic!(
                                "failed to initialize virtio-blk MMIO transport at {:#x}: {error}",
                                candidate.region.base
                            )
                        });
                let device = RawVirtioBlockDevice::new_resource(
                    transport,
                    *cpu,
                    BlockDeviceRights::READ | BlockDeviceRights::WRITE,
                )
                .unwrap_or_else(|error| {
                    panic!(
                        "failed to initialize virtio-blk device at {:#x}: {error}",
                        candidate.region.base
                    )
                });
                BlockInterrupt {
                    interrupt,
                    trigger,
                    device: VirtioBlockDevice { inner: device },
                }
            }
        })
        .collect()
}
