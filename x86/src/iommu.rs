//! virtio-iommu discovery and device confinement for the x86 backend.
//!
//! q35 describes its translation topology in the ACPI VIOT table: one
//! node names the PCI function the virtio-iommu itself sits on, and PCI
//! range nodes map a span of bus/device/function numbers onto the
//! endpoint identities that unit knows them by. This module reads that
//! table, brings the unit up, and hands the kernel the endpoint of every
//! virtio function it is about to drive.
//!
//! Concurrency contract: discovery, bring-up and domain construction all
//! run on the bootstrap processor with interrupts masked, before any
//! device is programmed. Afterwards the only thing that touches the unit
//! is its interrupt handler, which drains reported faults.

extern crate alloc;

use alloc::sync::Arc;
use core::time::Duration;

use helios_firmware::{VIOT_SIGNATURE, VirtioIommuTopology, parse_viot};
use helios_hal::cpu::{Cpu, Timebase};
use helios_hal::iommu::PhysicalRange;
use helios_kernel::{
    DeviceChunkDomain, DirectChunkDomain, DmaArenas, Elastic, IommuChunkDomain, IommuDomains,
    IommuReport, MAX_IOMMU_ENDPOINTS, SharedDmaArena, Timer, UserPoolChunks,
};
use helios_virtio::{
    DeviceType, MAX_RESERVED_REGIONS, OffsetDmaPool, ReservedRegion, VirtioIommuDevice,
    VirtioPciTransport,
};
use pci_types::PciAddress;

use crate::pci::PciRoot;

/// Per-device chunk domain backing every virtio-PCI driver on x86.
pub(crate) type X86DmaDomain = DeviceChunkDomain<Arc<X86VirtioIommuDevice>>;

/// The DMA pool every virtio-PCI driver on this backend publishes
/// addresses from.
///
/// Every device owns its own [`DmaArena`] whose chunks are lent from the
/// user memory pool and dynamically mapped into that device's IOMMU
/// domain (or translated directly when no translation unit is present).
pub(crate) type X86DmaPool = SharedDmaArena<UserPoolChunks, X86DmaDomain, Elastic>;

/// Registry of all x86 elastic DMA arenas driven by the background
/// maintenance task.
pub(crate) type X86DmaArenas = DmaArenas<UserPoolChunks, X86DmaDomain>;

/// Chunk size (2 MiB) for high-throughput or large-slab devices (network,
/// block, host-fs, GPU).
pub(crate) const LARGE_DMA_CHUNK_BYTES: usize = 2 << 20;

/// Chunk size (256 KiB = 64 pages, one bitmap word) for control and
/// low-bandwidth devices (entropy, balloon, vsock, input, sound).
pub(crate) const SMALL_DMA_CHUNK_BYTES: usize = 256 << 10;

/// The translation unit as ACPI VIOT describes it.
pub(crate) type IommuTopology = VirtioIommuTopology;

/// The unit the platform exposes, once it has been brought up.
pub(crate) type X86VirtioIommuDevice = VirtioIommuDevice<VirtioPciTransport<OffsetDmaPool>>;

/// How often the platform's translation unit is asked whether it has
/// reported a fault.
///
/// The unit has no interrupt to report one on. QEMU's
/// `virtio-iommu-pci` function exposes no MSI-X capability at all — it
/// has no `vectors` property to give it one — and this backend routes
/// device interrupts through MSI-X only. A fault is exceptional, so a
/// task that sleeps on the kernel timer between polls costs nothing and
/// never busy-waits; what it must not do is leave a fault unreported.
const FAULT_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Reads back the faults the unit reported and publishes the running
/// total, so `helios-inspector stats` shows it.
pub(crate) async fn watch_faults<CpuImpl: Cpu + Clone>(
    device: Arc<X86VirtioIommuDevice>,
    report: Arc<IommuReport>,
    timer: Timer<CpuImpl>,
) {
    loop {
        timer.sleep_for(FAULT_POLL_INTERVAL).await;
        device.drain_faults();
        report.record_faults(device.fault_count());
    }
}

/// Reads the platform's translation topology out of the ACPI VIOT table.
///
/// A machine with no VIOT has no translation unit its devices can be put
/// behind, which is the ordinary case; the caller then leaves the
/// devices addressing physical memory directly.
pub(crate) fn discover(
    rsdp_address: usize,
    physical_memory_offset: usize,
) -> Option<IommuTopology> {
    let handler = crate::smp::PhysicalOffsetAcpiHandler {
        physical_memory_offset,
        tsc_base: 0,
        timebase: Timebase::new(1),
    };
    // SAFETY: `rsdp_address` comes from the bootloader's Limine handoff and
    // `handler` translates ACPI physical addresses through the bootloader's
    // direct physical map.
    let tables = unsafe { acpi::AcpiTables::from_rsdp(handler, rsdp_address) }
        .unwrap_or_else(|error| panic!("failed to parse ACPI tables for the VIOT: {error:?}"));
    let (physical_address, header) = tables
        .table_headers()
        .find(|(_, header)| header.signature.as_str() == VIOT_SIGNATURE)?;
    // `SdtHeader` is a packed structure, so the field is copied out
    // before anything takes a reference to it.
    let declared_length = header.length;
    let length = usize::try_from(declared_length)
        .unwrap_or_else(|_| panic!("ACPI VIOT length {declared_length} does not fit usize"));
    let virtual_address = physical_address
        .checked_add(physical_memory_offset)
        .unwrap_or_else(|| panic!("ACPI VIOT at {physical_address:#x} overflowed the HHDM"));
    // SAFETY: the address and length come from the RSDT entry the
    // firmware published, and the whole table sits inside the direct
    // physical map the bootloader established.
    let table = unsafe { core::slice::from_raw_parts(virtual_address as *const u8, length) };
    Some(parse_viot(table).unwrap_or_else(|error| panic!("ACPI VIOT table is invalid: {error}")))
}

/// Brings the unit at `address` up.
///
/// It is left on its INTx pin: the function carries no MSI-X capability
/// to bind, and nothing in this backend routes a legacy pin, so the
/// faults it reports are collected by [`watch_faults`] instead.
pub(crate) fn install(
    pci: &PciRoot,
    address: PciAddress,
    physical_memory_offset: usize,
) -> Arc<X86VirtioIommuDevice> {
    assert_eq!(
        helios_virtio::virtio_pci_device_type(&pci.access(), address),
        Some(DeviceType::Iommu),
        "the ACPI VIOT named {address} as the translation unit but it carries no virtio-iommu"
    );
    let device = helios_virtio::iommu_from_pci(
        &pci.access(),
        address,
        pci,
        OffsetDmaPool::new(physical_memory_offset),
        None,
    )
    .unwrap_or_else(|error| {
        panic!("failed to initialize the virtio-iommu function at {address}: {error}")
    });
    tracing::info!(
        function = %address,
        global_bypass = device.global_bypass(),
        "virtio-iommu online"
    );
    Arc::new(device)
}

type X86IommuDomain = IommuChunkDomain<Arc<X86VirtioIommuDevice>>;
type ConfinedEntry = (PciAddress, Option<X86IommuDomain>);

/// The devices one translation unit confines, and each device's dynamic
/// IOMMU chunk domain.
pub(crate) struct Confinement {
    device: Arc<X86VirtioIommuDevice>,
    report: Arc<IommuReport>,
    entries: [Option<ConfinedEntry>; MAX_IOMMU_ENDPOINTS],
}

impl Confinement {
    /// Takes ownership of the dynamic IOMMU domain built for `address`.
    pub(crate) fn take_domain(
        &mut self,
        address: PciAddress,
    ) -> IommuChunkDomain<Arc<X86VirtioIommuDevice>> {
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
    pub(crate) fn device(&self) -> Arc<X86VirtioIommuDevice> {
        self.device.clone()
    }

    /// What the kernel publishes about this unit.
    pub(crate) fn report(&self) -> Arc<IommuReport> {
        self.report.clone()
    }
}

/// Brings the platform's translation unit up and gives every function in
/// `functions` a private domain of its own.
///
/// Only the unit's and platform's interrupt doorbells are mapped here;
/// each device's [`DmaArena`] maps its own chunks and foreign ranges on
/// demand and unmaps them when retired or dropped.
pub(crate) fn confine_devices(
    pci: &PciRoot,
    topology: IommuTopology,
    physical_memory_offset: usize,
    functions: &[PciAddress],
) -> Confinement {
    let device = install(pci, topology.unit(), physical_memory_offset);

    // The unit is authoritative about the ranges its endpoints have to
    // keep reaching; the platform's own message window is the answer
    // when it names none, which is what q35 does.
    let mut doorbells = [MSI_DOORBELL; MAX_RESERVED_REGIONS + 1];
    let mut doorbell_count = 1;
    let mut probed = [ReservedRegion {
        start: 0,
        bytes: 0,
        doorbell: false,
    }; MAX_RESERVED_REGIONS];
    for address in functions {
        let Some(endpoint) = topology.endpoint_of(*address) else {
            panic!("PCI function {address} is not covered by the ACPI VIOT topology");
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
        physical_memory_offset,
        device.global_bypass(),
    )
    .unwrap_or_else(|error| panic!("the IOMMU domain layout is not buildable: {error}"));
    let mut entries = [const { None }; MAX_IOMMU_ENDPOINTS];
    for (slot, address) in functions.iter().enumerate() {
        let endpoint = topology
            .endpoint_of(*address)
            .unwrap_or_else(|| panic!("PCI function {address} left the VIOT topology"));
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

/// Builds and registers a per-device DMA arena for `address`.
///
/// With a translation unit the arena maps only its own chunks and foreign
/// ranges into that device's IOMMU domain; without one it translates
/// direct-map addresses to physical addresses.
pub(crate) fn dma_pool(
    arenas: &mut X86DmaArenas,
    confinement: Option<&mut Confinement>,
    address: PciAddress,
    physical_memory_offset: usize,
    chunk_bytes: usize,
    processors: usize,
) -> X86DmaPool {
    let domain = match confinement {
        Some(confinement) => DeviceChunkDomain::Confined(confinement.take_domain(address)),
        None => DeviceChunkDomain::Direct(DirectChunkDomain::new(physical_memory_offset)),
    };
    SharedDmaArena::new(arenas.arena(domain, chunk_bytes, processors))
}

/// The local-APIC message window every MSI-X capable function writes to.
///
/// A confined device still has to reach it, and the address is fixed by
/// the interrupt controller, so every domain maps it at its own physical
/// address.
pub(crate) const MSI_DOORBELL: PhysicalRange = PhysicalRange::new(0xfee0_0000, 0x10_0000);
