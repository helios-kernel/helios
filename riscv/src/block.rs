//! virtio-blk over PCI or MMIO for the RISC-V backend.
//!
//! Every block device discovered on the PCI or platform bus is brought up
//! here, up to the block interrupt routes the kernel's table holds; what
//! each of them is for is the kernel's decision, taken from the serials
//! they report.
//!
//! Concurrency contract: the devices are discovered and programmed on the
//! bootstrap hart before external interrupts are unmasked, and their
//! completions arrive on the PLIC lines the device tree names, so every
//! reader parks on a notification rather than polling a used ring.

extern crate alloc;

use alloc::vec::Vec;
use core::fmt;

use fdt::Fdt;
use helios_hal::cpu::Cpu;
use helios_hal::fs::BlockDeviceRights;
use helios_kernel::ExternalInterruptHandler;
use helios_virtio::{
    DeviceType, MmioCandidate, VirtioBlockDevice as RawVirtioBlockDevice, VirtioBlockResource,
    VirtioBusTransport,
};

use crate::RiscvCpu;
use crate::debug_state::RuntimeState;
use crate::iommu::{self, Confinement, RiscvDmaArenas, RiscvVirtioTransport};
use crate::net::PlicInterrupt;
use crate::pci::{PciHostController, VirtioFunctions, VirtioPciFunction};

pub(crate) type RiscvVirtioBlockDevice =
    VirtioBlockResource<RiscvVirtioTransport, RiscvCpu, helios_kernel::BlockPages>;

#[derive(Clone)]
pub(crate) struct VirtioBlockDevice {
    inner: RiscvVirtioBlockDevice,
}

/// One block device the bootstrap hart brought up, together with the
/// PLIC line the device tree routes it to.
pub(crate) struct BlockInterrupt {
    pub(crate) line: PlicInterrupt,
    pub(crate) device: VirtioBlockDevice,
}

impl ExternalInterruptHandler for VirtioBlockDevice {
    fn handle_interrupt(&self) {
        self.inner.handle_interrupt();
    }
}

pub(crate) fn count_block_devices(fdt: &Fdt<'_>, pci_virtio: Option<&VirtioFunctions>) -> usize {
    pci_virtio.map_or(0, |v| v.count(DeviceType::Block))
        + crate::count_virtio_mmio_devices(fdt, DeviceType::Block)
}

enum BlockCandidate {
    Pci(VirtioPciFunction),
    Mmio(MmioCandidate),
}

impl fmt::Display for BlockCandidate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pci(function) => write!(f, "PCI {}", function.address),
            Self::Mmio(candidate) => write!(f, "MMIO {:#x}", candidate.base),
        }
    }
}

/// Brings up every block device on the PCI and platform buses and hands
/// them to the kernel, which gives each the role its serial names.
#[allow(clippy::too_many_arguments)]
pub(crate) fn install<WatchdogImpl>(
    cpu: &RiscvCpu,
    kernel: &helios_kernel::Kernel<RiscvCpu, WatchdogImpl>,
    fdt: &Fdt<'_>,
    pci: Option<&PciHostController>,
    pci_virtio: Option<&VirtioFunctions>,
    arenas: &mut RiscvDmaArenas,
    confinement: Option<&mut Confinement>,
    debug_state: &RuntimeState,
    root: helios_kernel::RootEntropyHandle,
) -> Vec<BlockInterrupt>
where
    WatchdogImpl: helios_hal::watchdog::Watchdog + Clone,
{
    let discovered = discover_block_devices(cpu, fdt, pci, pci_virtio, arenas, confinement);
    let devices: Vec<_> = discovered
        .iter()
        .map(|interrupt| interrupt.device.inner.clone())
        .collect();
    let state = debug_state.clone();
    if !devices.is_empty() {
        debug_state.begin_block_discovery();
    }
    helios_kernel::install_block_devices(
        kernel,
        root,
        devices,
        move |service, _scratch, mount_sources, hibernate| {
            state.install_block_service(service);
            if let Some(cache) = mount_sources {
                state.install_mount_sources(cache);
            }
            if let Some(hibernate) = hibernate {
                state.install_hibernate_disk(hibernate);
            }
            state.finish_block_discovery();
        },
    );
    for interrupt in &discovered {
        tracing::info!(irq = interrupt.line.number(), "virtio block online");
    }
    discovered
}

fn discover_block_devices(
    cpu: &RiscvCpu,
    fdt: &Fdt<'_>,
    pci: Option<&PciHostController>,
    pci_virtio: Option<&VirtioFunctions>,
    arenas: &mut RiscvDmaArenas,
    mut confinement: Option<&mut Confinement>,
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
        helios_virtio::mmio_candidates(fdt)
            .filter(|candidate| {
                crate::matches_virtio_mmio_device(candidate.base, DeviceType::Block)
            })
            .map(BlockCandidate::Mmio),
    );

    helios_kernel::admit_block_devices(candidates)
        .into_iter()
        .map(|candidate| match candidate {
            BlockCandidate::Pci(function) => {
                let pci = pci.expect("PCI virtio-blk candidate requires a PCI host controller");
                pci.assign_unassigned_memory_bars(function.address);
                let dma = iommu::dma_pool(
                    arenas,
                    confinement.as_deref_mut(),
                    Some(function.address),
                    iommu::LARGE_DMA_CHUNK_BYTES,
                    cpu.processor_count(),
                );
                let transport =
                    VirtioBusTransport::pci(&pci.config_access(), function.address, pci, dma, None)
                        .unwrap_or_else(|error| {
                            panic!(
                                "failed to initialize virtio-blk PCI transport at {}: {error}",
                                function.address
                            )
                        });
                let device = RawVirtioBlockDevice::new_resource(
                    transport,
                    cpu.clone(),
                    BlockDeviceRights::READ | BlockDeviceRights::WRITE,
                )
                .unwrap_or_else(|error| {
                    panic!(
                        "failed to initialize virtio-blk PCI device at {}: {error}",
                        function.address
                    )
                });
                BlockInterrupt {
                    line: function.line,
                    device: VirtioBlockDevice { inner: device },
                }
            }
            BlockCandidate::Mmio(candidate) => {
                let base = candidate.base;
                let header = core::ptr::NonNull::new(base as *mut u8)
                    .unwrap_or_else(|| panic!("virtio MMIO base {base:#x} was unexpectedly null"));
                let line = candidate
                    .interrupt
                    .and_then(PlicInterrupt::from_specifier)
                    .unwrap_or_else(|| {
                        panic!("virtio-blk node at {base:#x} has no valid interrupt source")
                    });
                let dma = iommu::dma_pool(
                    arenas,
                    None,
                    None,
                    iommu::LARGE_DMA_CHUNK_BYTES,
                    cpu.processor_count(),
                );
                // SAFETY: `candidate` comes from `mmio_candidates(fdt)` and matched
                // `DeviceType::Block` on the bootstrap hart before interrupts are
                // unmasked, so `header..header + candidate.size` is an identity-mapped
                // VirtIO MMIO block register block with exclusive driver access.
                let transport = unsafe { VirtioBusTransport::mmio(header, candidate.size, dma) }
                    .unwrap_or_else(|error| {
                        panic!(
                            "failed to initialize virtio-blk MMIO transport at {base:#x}: {error}"
                        )
                    });
                let device = RawVirtioBlockDevice::new_resource(
                    transport,
                    cpu.clone(),
                    BlockDeviceRights::READ | BlockDeviceRights::WRITE,
                )
                .unwrap_or_else(|error| {
                    panic!("failed to initialize virtio-blk device at {base:#x}: {error}")
                });
                BlockInterrupt {
                    line,
                    device: VirtioBlockDevice { inner: device },
                }
            }
        })
        .collect()
}
