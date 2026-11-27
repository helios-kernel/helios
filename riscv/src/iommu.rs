//! `virtio-iommu-pci` bring-up, device confinement, and elastic DMA arenas
//! for the RISC-V backend.
//!
//! Concurrency contract: discovery, unit bring-up, and per-device domain
//! construction all run on the bootstrap hart before external interrupts are
//! unmasked or any secondary hart starts. Afterwards the only background
//! user of the translation unit is [`watch_faults`], which polls reported
//! faults on a timer.

extern crate alloc;

use alloc::sync::Arc;
use core::time::Duration;

use helios_firmware::VirtioIommuTopology;
use helios_hal::cpu::Cpu;
use helios_hal::iommu::PhysicalRange;
use helios_kernel::{
    DeviceChunkDomain, DirectChunkDomain, DmaArenas, Elastic, IommuChunkDomain, IommuDomains,
    IommuReport, MAX_IOMMU_ENDPOINTS, SharedDmaArena, Timer, UserPoolChunks,
};
use helios_virtio::{
    DeviceType, MAX_RESERVED_REGIONS, OffsetDmaPool, ReservedRegion, VirtioBusTransport,
    VirtioIommuDevice, VirtioPciTransport,
};
use pci_types::PciAddress;

use crate::pci::PciHostController;

/// The translation unit the platform exposes, once it has been brought up.
pub(crate) type RiscvVirtioIommuDevice = VirtioIommuDevice<VirtioPciTransport<OffsetDmaPool>>;

/// Per-device chunk domain backing every virtio driver on RISC-V.
pub(crate) type RiscvDmaDomain = DeviceChunkDomain<Arc<RiscvVirtioIommuDevice>>;

/// The DMA pool every virtio driver on this backend publishes addresses from.
pub(crate) type RiscvDmaPool = SharedDmaArena<UserPoolChunks, RiscvDmaDomain, Elastic>;

/// Registry of all RISC-V elastic DMA arenas driven by the background
/// maintenance task.
pub(crate) type RiscvDmaArenas = DmaArenas<UserPoolChunks, RiscvDmaDomain>;

/// Static transport dispatch over either VirtIO MMIO or VirtIO PCI.
pub(crate) type RiscvVirtioTransport = VirtioBusTransport<RiscvDmaPool>;

/// Chunk size (2 MiB) for high-throughput or large-slab devices (network,
/// block, host-fs, vsock, GPU).
pub(crate) const LARGE_DMA_CHUNK_BYTES: usize = 2 << 20;

/// Chunk size (256 KiB = 64 pages, one bitmap word) for control and
/// low-bandwidth devices (entropy, balloon, input, sound).
pub(crate) const SMALL_DMA_CHUNK_BYTES: usize = 256 << 10;

/// How often the platform's translation unit is asked whether it has
/// reported a fault.
const FAULT_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Reads back the faults the unit reported and publishes the running total,
/// so `helios-inspector stats` shows it.
pub(crate) async fn watch_faults<CpuImpl: Cpu + Clone>(
    device: Arc<RiscvVirtioIommuDevice>,
    report: Arc<IommuReport>,
    timer: Timer<CpuImpl>,
) {
    loop {
        timer.sleep_for(FAULT_POLL_INTERVAL).await;
        device.drain_faults();
        report.record_faults(device.fault_count());
    }
}

/// Brings the `virtio-iommu-pci` unit at `address` up.
pub(crate) fn install(pci: &PciHostController, address: PciAddress) -> Arc<RiscvVirtioIommuDevice> {
    pci.assign_unassigned_memory_bars(address);
    let access = pci.config_access();
    assert_eq!(
        helios_virtio::virtio_pci_device_type(&access, address),
        Some(DeviceType::Iommu),
        "the device tree named {address} as the translation unit but it carries no virtio-iommu"
    );
    let device = helios_virtio::iommu_from_pci(
        &access,
        address,
        pci,
        OffsetDmaPool::new(crate::vmm::physical_memory_offset()),
        None,
    )
    .unwrap_or_else(|error| {
        panic!("failed to initialize the virtio-iommu function at {address}: {error}")
    });
    // `VirtioPciTransport::new(..., None)` clears INTERRUPT_DISABLE for
    // INTx-driven devices, but `virtio-iommu-pci` is driven synchronously
    // and polled by `watch_faults`. Mask INTx so it never holds a shared
    // PLIC line asserted.
    pci.disable_intx(address);
    tracing::info!(
        function = %address,
        global_bypass = device.global_bypass(),
        "virtio-iommu online"
    );
    Arc::new(device)
}

type RiscvIommuDomain = IommuChunkDomain<Arc<RiscvVirtioIommuDevice>>;
type ConfinedEntry = (PciAddress, Option<RiscvIommuDomain>);

/// The devices one translation unit confines, and each device's dynamic
/// IOMMU chunk domain.
pub(crate) struct Confinement {
    device: Arc<RiscvVirtioIommuDevice>,
    report: Arc<IommuReport>,
    entries: [Option<ConfinedEntry>; MAX_IOMMU_ENDPOINTS],
}

impl Confinement {
    /// Takes ownership of the dynamic IOMMU domain built for `address`.
    pub(crate) fn take_domain(&mut self, address: PciAddress) -> RiscvIommuDomain {
        self.entries
            .iter_mut()
            .flatten()
            .find_map(|(confined, domain)| (*confined == address).then(|| domain.take()))
            .flatten()
            .unwrap_or_else(|| {
                panic!(
                    "PCI function {address} was never given an IOMMU domain or was claimed twice"
                )
            })
    }

    /// The unit itself, for the task that collects its fault reports.
    pub(crate) fn device(&self) -> Arc<RiscvVirtioIommuDevice> {
        self.device.clone()
    }

    /// What the kernel publishes about this unit.
    pub(crate) fn report(&self) -> Arc<IommuReport> {
        self.report.clone()
    }
}

/// Brings the platform's translation unit up and gives every PCI function in
/// `functions` a private domain of its own.
pub(crate) fn confine_devices(
    pci: &PciHostController,
    topology: VirtioIommuTopology,
    functions: &[PciAddress],
) -> Confinement {
    let device = install(pci, topology.unit());

    let mut doorbells = [PhysicalRange::new(0, 0); MAX_RESERVED_REGIONS];
    let mut doorbell_count = 0;
    let mut probed = [ReservedRegion {
        start: 0,
        bytes: 0,
        doorbell: false,
    }; MAX_RESERVED_REGIONS];
    for address in functions {
        let Some(endpoint) = topology.endpoint_of(*address) else {
            panic!("PCI function {address} is not covered by the device tree `iommu-map`");
        };
        let found = device.probe(endpoint, &mut probed).unwrap_or_else(|error| {
            panic!("virtio-iommu refused to probe endpoint {endpoint}: {error}")
        });
        for region in &probed[..found] {
            assert!(
                region.doorbell,
                "virtio-iommu reserved a range at {:#x} that endpoint {endpoint} may not reach; \
                 helios has no way to keep that endpoint working",
                region.start
            );
            let range = PhysicalRange::new(region.start, region.bytes);
            if doorbells[..doorbell_count].contains(&range) {
                continue;
            }
            doorbells[doorbell_count] = range;
            doorbell_count += 1;
        }
    }

    let mut domains = IommuDomains::new(
        device.clone(),
        &doorbells[..doorbell_count],
        crate::vmm::physical_memory_offset(),
        device.global_bypass(),
    )
    .unwrap_or_else(|error| panic!("the IOMMU domain layout is not buildable: {error}"));
    let mut entries = [const { None }; MAX_IOMMU_ENDPOINTS];
    for (slot, address) in functions.iter().enumerate() {
        let endpoint = topology
            .endpoint_of(*address)
            .unwrap_or_else(|| panic!("PCI function {address} left the `iommu-map` topology"));
        let domain = domains
            .confine(endpoint)
            .unwrap_or_else(|error| panic!("failed to confine {address}: {error}"));
        entries[slot] = Some((*address, Some(domain)));
    }

    Confinement {
        report: domains.report(),
        device,
        entries,
    }
}

/// Builds and registers a per-device DMA arena.
///
/// PCI functions behind an active translation unit map only their own chunks
/// and foreign ranges into their private IOMMU domain; MMIO devices and PCI
/// functions without a translation unit address physical memory directly.
pub(crate) fn dma_pool(
    arenas: &mut RiscvDmaArenas,
    confinement: Option<&mut Confinement>,
    pci_address: Option<PciAddress>,
    chunk_bytes: usize,
    processors: usize,
) -> RiscvDmaPool {
    let domain = match (confinement, pci_address) {
        (Some(confinement), Some(address)) => {
            DeviceChunkDomain::Confined(confinement.take_domain(address))
        }
        _ => {
            DeviceChunkDomain::Direct(DirectChunkDomain::new(crate::vmm::physical_memory_offset()))
        }
    };
    SharedDmaArena::new(arenas.arena(domain, chunk_bytes, processors))
}
