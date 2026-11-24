//! IOMMU domain management.
//!
//! The hardware contract lives in `helios_hal::iommu`; the backends find
//! the translation unit and the endpoint identities their platform
//! publishes. What is left — deciding how many domains exist, where each
//! one's I/O virtual address space starts, and dynamically mapping and
//! unmapping the chunks and foreign buffers each device owns — is
//! hardware-independent, so it lives here.
//!
//! Helios gives every protected device a domain of its own, and every
//! domain a disjoint slot of the I/O virtual address space of its own.
//! At confinement time a domain maps only the platform's identity-mapped
//! interrupt doorbells; no bulk RAM is mapped at boot. Every DMA buffer
//! a driver allocates comes from that device's [`crate::io::DmaArena`],
//! whose [`IommuChunkDomain`] maps each lent chunk on demand with its
//! class's access rights (`READ` only for read-only request chunks,
//! `READ | WRITE` for writable and resident chunks) and unmaps it when
//! the chunk retires. Caller-owned physical ranges (GPU framebuffers,
//! blobs, balloon free-page reports) are mapped on demand through
//! [`ChunkDomain::map_foreign`] and unmapped when their
//! [`IommuForeignMapping`] guard drops.
//!
//! Concurrency contract: [`IommuDomains`] builds domains on the bootstrap
//! processor while devices are brought up. Once built, each
//! [`IommuChunkDomain`] is shared across processors: IOVA allocation and
//! release are serialised by its per-domain [`IovaSpace`] spin mutex, the
//! underlying [`Iommu`] is internally synchronised, and [`IommuReport`]
//! carries only atomics. Domain mapping and unmapping run only in task
//! context, never from an interrupt handler.

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};

use helios_hal::dma::{DeviceAddress, DmaAddressing, DmaError, DmaForeignMapping};
use helios_hal::iommu::{
    DmaAccess, DomainId, EndpointId, IoVirtAddr, Iommu, IommuError, IommuGeometry, MAX_DMA_WINDOWS,
    PhysicalRange,
};
use helios_hal::pmm::PhysFrame;
use spin::Mutex;

use crate::io::dma::{ChunkDomain, LentChunk};

/// How many devices one translation unit can confine.
///
/// A full desktop guest exposes network, host share, entropy, balloon,
/// vsock, display, multiple input functions, sound, and several disks,
/// with room left for plugin-hosted devices.
pub const MAX_IOMMU_ENDPOINTS: usize = 32;

/// What one confined device's domain covers.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IommuEndpointStats {
    /// The endpoint identity the platform gave the device.
    pub endpoint: u32,
    /// The domain the device was attached to.
    pub domain: u32,
    /// Physical bytes the domain currently maps, doorbells included.
    pub mapped_bytes: u64,
}

/// Live atomic record for one confined endpoint inside [`IommuReport`].
#[derive(Debug)]
struct LiveEndpointStats {
    endpoint: AtomicU32,
    domain: AtomicU32,
    mapped_bytes: AtomicU64,
}

impl LiveEndpointStats {
    const fn new() -> Self {
        Self {
            endpoint: AtomicU32::new(0),
            domain: AtomicU32::new(0),
            mapped_bytes: AtomicU64::new(0),
        }
    }

    fn snapshot(&self) -> IommuEndpointStats {
        IommuEndpointStats {
            endpoint: self.endpoint.load(Ordering::Relaxed),
            domain: self.domain.load(Ordering::Relaxed),
            mapped_bytes: self.mapped_bytes.load(Ordering::Relaxed),
        }
    }
}

/// A coherent view of what the platform's translation unit is doing.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IommuStats {
    /// The smallest page the unit maps.
    pub granule_bytes: u64,
    /// Whether endpoints attached to no domain still reach memory.
    /// A confined device is translated either way.
    pub global_bypass: bool,
    /// Translation faults the unit has reported since boot.
    pub faults: u64,
    endpoints: [IommuEndpointStats; MAX_IOMMU_ENDPOINTS],
    endpoint_count: usize,
}

impl IommuStats {
    /// One entry per confined device.
    pub fn endpoints(&self) -> &[IommuEndpointStats] {
        &self.endpoints[..self.endpoint_count]
    }
}

/// The live IOMMU observation the kernel publishes.
///
/// The confined endpoint list is populated during device bring-up; each
/// endpoint's mapped byte count moves live as chunks and foreign ranges
/// are mapped and unmapped, and the fault watcher moves the fault
/// counter.
#[derive(Debug)]
pub struct IommuReport {
    granule_bytes: u64,
    global_bypass: bool,
    endpoints: [LiveEndpointStats; MAX_IOMMU_ENDPOINTS],
    endpoint_count: AtomicUsize,
    faults: AtomicU64,
}

impl IommuReport {
    fn new(granule_bytes: u64, global_bypass: bool) -> Self {
        Self {
            granule_bytes,
            global_bypass,
            endpoints: core::array::from_fn(|_| LiveEndpointStats::new()),
            endpoint_count: AtomicUsize::new(0),
            faults: AtomicU64::new(0),
        }
    }

    fn register_endpoint(
        &self,
        index: usize,
        endpoint: EndpointId,
        domain: DomainId,
        doorbell_bytes: u64,
    ) {
        let entry = &self.endpoints[index];
        entry.endpoint.store(endpoint.get(), Ordering::Relaxed);
        entry.domain.store(domain.get(), Ordering::Relaxed);
        entry.mapped_bytes.store(doorbell_bytes, Ordering::Relaxed);
        self.endpoint_count.store(index + 1, Ordering::Release);
    }

    fn add_mapped_bytes(&self, slot: usize, bytes: u64) {
        self.endpoints[slot]
            .mapped_bytes
            .fetch_add(bytes, Ordering::Relaxed);
    }

    fn sub_mapped_bytes(&self, slot: usize, bytes: u64) {
        self.endpoints[slot]
            .mapped_bytes
            .fetch_sub(bytes, Ordering::Relaxed);
    }

    /// Publishes the total number of faults the unit has reported.
    pub fn record_faults(&self, total: u64) {
        self.faults.store(total, Ordering::Relaxed);
    }

    /// The current observation.
    pub fn snapshot(&self) -> IommuStats {
        let endpoint_count = self.endpoint_count.load(Ordering::Acquire);
        let mut endpoints = [IommuEndpointStats::default(); MAX_IOMMU_ENDPOINTS];
        for (slot, dst) in endpoints[..endpoint_count].iter_mut().enumerate() {
            *dst = self.endpoints[slot].snapshot();
        }
        IommuStats {
            granule_bytes: self.granule_bytes,
            global_bypass: self.global_bypass,
            faults: self.faults.load(Ordering::Relaxed),
            endpoints,
            endpoint_count,
        }
    }
}

/// One free run inside a domain's IOVA slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct IovaRun {
    start: u64,
    bytes: u64,
}

impl IovaRun {
    fn end(self) -> u64 {
        self.start + self.bytes
    }
}

/// Coalescing free-list allocator for one domain's disjoint IOVA slot.
#[derive(Debug)]
struct IovaSpace {
    free: Vec<IovaRun>,
}

impl IovaSpace {
    fn new(start: u64, bytes: u64) -> Self {
        Self {
            free: vec![IovaRun { start, bytes }],
        }
    }

    fn allocate(&mut self, bytes: u64, align: u64) -> Option<IoVirtAddr> {
        debug_assert!(bytes != 0 && align.is_power_of_two());
        for index in 0..self.free.len() {
            let run = self.free[index];
            let aligned = align_up_u64(run.start, align)?;
            let end = aligned.checked_add(bytes)?;
            let run_end = run.end();
            if end > run_end {
                continue;
            }
            let head = aligned - run.start;
            let tail = run_end - end;
            match (head != 0, tail != 0) {
                (false, false) => {
                    self.free.remove(index);
                }
                (true, false) => {
                    self.free[index] = IovaRun {
                        start: run.start,
                        bytes: head,
                    };
                }
                (false, true) => {
                    self.free[index] = IovaRun {
                        start: end,
                        bytes: tail,
                    };
                }
                (true, true) => {
                    self.free[index] = IovaRun {
                        start: run.start,
                        bytes: head,
                    };
                    self.free.insert(
                        index + 1,
                        IovaRun {
                            start: end,
                            bytes: tail,
                        },
                    );
                }
            }
            return Some(IoVirtAddr::new(aligned));
        }
        None
    }

    fn free(&mut self, iova: IoVirtAddr, bytes: u64) {
        if bytes == 0 {
            return;
        }
        let start = iova.get();
        let end = start
            .checked_add(bytes)
            .expect("freed IOVA range overflowed u64");
        let position = self.free.partition_point(|run| run.start < start);
        let merge_left = position > 0 && self.free[position - 1].end() == start;
        let merge_right = position < self.free.len() && end == self.free[position].start;
        match (merge_left, merge_right) {
            (true, true) => {
                let right_bytes = self.free[position].bytes;
                self.free[position - 1].bytes += bytes + right_bytes;
                self.free.remove(position);
            }
            (true, false) => {
                self.free[position - 1].bytes += bytes;
            }
            (false, true) => {
                self.free[position].start = start;
                self.free[position].bytes += bytes;
            }
            (false, false) => {
                self.free.insert(position, IovaRun { start, bytes });
            }
        }
    }
}

fn align_up_u64(value: u64, align: u64) -> Option<u64> {
    let mask = align - 1;
    value.checked_add(mask).map(|raised| raised & !mask)
}

fn physical_from_virtual(
    address: usize,
    bytes: usize,
    physical_memory_offset: usize,
) -> Result<u64, DmaError> {
    let physical = address
        .checked_sub(physical_memory_offset)
        .ok_or(DmaError::Unreachable { address, bytes })?;
    Ok(physical as u64)
}

fn dma_error_from_iommu(error: IommuError, address: usize, bytes: usize) -> DmaError {
    match error {
        IommuError::OutOfResources => DmaError::Exhausted { bytes },
        _ => DmaError::Unreachable { address, bytes },
    }
}

/// Active IOMMU mapping of a caller-owned physical range.
///
/// Dropping the guard unmaps the range from the device's domain and
/// returns its IOVA span to the domain's [`IovaSpace`]. If the IOMMU
/// refuses the unmap, the IOVA span is deliberately retained so the
/// device cannot reach a later unrelated mapping through a stale entry.
pub struct IommuForeignMapping<I: Iommu> {
    iommu: I,
    domain: DomainId,
    iova: Arc<Mutex<IovaSpace>>,
    report: Arc<IommuReport>,
    report_slot: usize,
    mapped_iova: IoVirtAddr,
    mapped_bytes: u64,
    device_address: DeviceAddress,
}

impl<I: Iommu> DmaForeignMapping for IommuForeignMapping<I> {
    fn device_address(&self) -> DeviceAddress {
        self.device_address
    }
}

impl<I: Iommu> Drop for IommuForeignMapping<I> {
    fn drop(&mut self) {
        match self
            .iommu
            .unmap(self.domain, self.mapped_iova, self.mapped_bytes)
        {
            Ok(()) => {
                self.iova.lock().free(self.mapped_iova, self.mapped_bytes);
                self.report
                    .sub_mapped_bytes(self.report_slot, self.mapped_bytes);
            }
            Err(error) => {
                tracing::error!(
                    domain = %self.domain,
                    iova = %self.mapped_iova,
                    bytes = self.mapped_bytes,
                    %error,
                    "IOMMU refused to unmap a dropped foreign mapping; its IOVA span stays quarantined"
                );
            }
        }
    }
}

/// One device's dynamic IOMMU domain, implementing [`ChunkDomain`].
///
/// Each lent chunk and each foreign range is mapped into this domain's
/// private IOVA slot on demand and unmapped when retired or dropped.
pub struct IommuChunkDomain<I: Iommu> {
    iommu: I,
    geometry: IommuGeometry,
    domain: DomainId,
    physical_memory_offset: usize,
    iova: Arc<Mutex<IovaSpace>>,
    report: Arc<IommuReport>,
    report_slot: usize,
}

impl<I: Iommu> IommuChunkDomain<I> {
    /// The IOMMU domain identifier backing this device.
    pub fn domain_id(&self) -> DomainId {
        self.domain
    }
}

impl<I: Iommu + Clone> ChunkDomain for IommuChunkDomain<I> {
    type ForeignMapping = IommuForeignMapping<I>;

    fn map(&self, chunk: LentChunk, access: DmaAccess) -> Result<DeviceAddress, DmaError> {
        let bytes = u64::try_from(chunk.bytes()).map_err(|_| DmaError::TooLarge {
            bytes: chunk.bytes(),
            limit: usize::MAX,
        })?;
        let granule = self.geometry.granule();
        if bytes == 0 || !bytes.is_multiple_of(granule) {
            return Err(DmaError::InvalidLength {
                bytes: chunk.bytes(),
                required_multiple: granule as usize,
            });
        }
        let physical =
            physical_from_virtual(chunk.start(), chunk.bytes(), self.physical_memory_offset)?;
        if !physical.is_multiple_of(granule) {
            return Err(DmaError::Unreachable {
                address: chunk.start(),
                bytes: chunk.bytes(),
            });
        }
        // `ChunkMap` uses bit 0 as the presence tag and requires at least
        // page alignment alongside the IOMMU granule.
        let align = granule.max(PhysFrame::SIZE as u64);
        let iova = self
            .iova
            .lock()
            .allocate(bytes, align)
            .ok_or(DmaError::Exhausted {
                bytes: chunk.bytes(),
            })?;
        if let Err(error) = self.iommu.map(self.domain, iova, physical, bytes, access) {
            self.iova.lock().free(iova, bytes);
            return Err(dma_error_from_iommu(error, chunk.start(), chunk.bytes()));
        }
        self.report.add_mapped_bytes(self.report_slot, bytes);
        Ok(DeviceAddress::new(iova.get()))
    }

    fn unmap(&self, chunk: LentChunk, device: DeviceAddress) -> Result<(), DmaError> {
        let bytes = chunk.bytes() as u64;
        let iova = IoVirtAddr::new(device.get());
        self.iommu
            .unmap(self.domain, iova, bytes)
            .map_err(|error| dma_error_from_iommu(error, chunk.start(), chunk.bytes()))?;
        self.iova.lock().free(iova, bytes);
        self.report.sub_mapped_bytes(self.report_slot, bytes);
        Ok(())
    }

    fn map_foreign(
        &self,
        range: PhysicalRange,
        access: DmaAccess,
    ) -> Result<Self::ForeignMapping, DmaError> {
        if range.bytes == 0 {
            return Err(DmaError::InvalidLength {
                bytes: 0,
                required_multiple: 1,
            });
        }
        let aligned = range.aligned_to(&self.geometry);
        let offset = range.start - aligned.start;
        let granule = self.geometry.granule();
        let iova =
            self.iova
                .lock()
                .allocate(aligned.bytes, granule)
                .ok_or(DmaError::Exhausted {
                    bytes: aligned.bytes as usize,
                })?;
        if let Err(error) = self
            .iommu
            .map(self.domain, iova, aligned.start, aligned.bytes, access)
        {
            self.iova.lock().free(iova, aligned.bytes);
            return Err(dma_error_from_iommu(
                error,
                range.start as usize,
                range.bytes as usize,
            ));
        }
        self.report
            .add_mapped_bytes(self.report_slot, aligned.bytes);
        Ok(IommuForeignMapping {
            iommu: self.iommu.clone(),
            domain: self.domain,
            iova: self.iova.clone(),
            report: self.report.clone(),
            report_slot: self.report_slot,
            mapped_iova: iova,
            mapped_bytes: aligned.bytes,
            device_address: DeviceAddress::new(iova.get() + offset),
        })
    }

    fn physical_address(&self, bytes: &[u8]) -> Result<u64, DmaError> {
        physical_from_virtual(
            bytes.as_ptr() as usize,
            bytes.len(),
            self.physical_memory_offset,
        )
    }

    fn addressing(&self) -> DmaAddressing {
        DmaAddressing::Platform
    }
}

/// Direct (untranslated) chunk domain for platforms or boots without an IOMMU.
///
/// Converts higher-half direct-map kernel addresses straight to physical
/// addresses.
#[derive(Clone, Copy, Debug)]
pub struct DirectChunkDomain {
    physical_memory_offset: usize,
}

impl DirectChunkDomain {
    pub const fn new(physical_memory_offset: usize) -> Self {
        Self {
            physical_memory_offset,
        }
    }
}

impl ChunkDomain for DirectChunkDomain {
    type ForeignMapping = DeviceAddress;

    fn map(&self, chunk: LentChunk, _access: DmaAccess) -> Result<DeviceAddress, DmaError> {
        let physical =
            physical_from_virtual(chunk.start(), chunk.bytes(), self.physical_memory_offset)?;
        Ok(DeviceAddress::new(physical))
    }

    fn unmap(&self, _chunk: LentChunk, _device: DeviceAddress) -> Result<(), DmaError> {
        Ok(())
    }

    fn map_foreign(
        &self,
        range: PhysicalRange,
        _access: DmaAccess,
    ) -> Result<Self::ForeignMapping, DmaError> {
        Ok(DeviceAddress::new(range.start))
    }

    fn physical_address(&self, bytes: &[u8]) -> Result<u64, DmaError> {
        physical_from_virtual(
            bytes.as_ptr() as usize,
            bytes.len(),
            self.physical_memory_offset,
        )
    }

    fn addressing(&self) -> DmaAddressing {
        DmaAddressing::Physical
    }
}

/// Foreign-mapping guard for [`DeviceChunkDomain`].
pub enum DeviceForeignMapping<I: Iommu> {
    Direct(DeviceAddress),
    Confined(IommuForeignMapping<I>),
}

impl<I: Iommu> DmaForeignMapping for DeviceForeignMapping<I> {
    fn device_address(&self) -> DeviceAddress {
        match self {
            Self::Direct(address) => *address,
            Self::Confined(mapping) => mapping.device_address(),
        }
    }
}

/// Unified per-device [`ChunkDomain`] covering boots both with and without an
/// IOMMU without dynamic dispatch.
pub enum DeviceChunkDomain<I: Iommu> {
    Direct(DirectChunkDomain),
    Confined(IommuChunkDomain<I>),
}

impl<I: Iommu + Clone> ChunkDomain for DeviceChunkDomain<I> {
    type ForeignMapping = DeviceForeignMapping<I>;

    fn map(&self, chunk: LentChunk, access: DmaAccess) -> Result<DeviceAddress, DmaError> {
        match self {
            Self::Direct(domain) => domain.map(chunk, access),
            Self::Confined(domain) => domain.map(chunk, access),
        }
    }

    fn unmap(&self, chunk: LentChunk, device: DeviceAddress) -> Result<(), DmaError> {
        match self {
            Self::Direct(domain) => domain.unmap(chunk, device),
            Self::Confined(domain) => domain.unmap(chunk, device),
        }
    }

    fn map_foreign(
        &self,
        range: PhysicalRange,
        access: DmaAccess,
    ) -> Result<Self::ForeignMapping, DmaError> {
        match self {
            Self::Direct(domain) => domain
                .map_foreign(range, access)
                .map(DeviceForeignMapping::Direct),
            Self::Confined(domain) => domain
                .map_foreign(range, access)
                .map(DeviceForeignMapping::Confined),
        }
    }

    fn physical_address(&self, bytes: &[u8]) -> Result<u64, DmaError> {
        match self {
            Self::Direct(domain) => domain.physical_address(bytes),
            Self::Confined(domain) => domain.physical_address(bytes),
        }
    }

    fn addressing(&self) -> DmaAddressing {
        match self {
            Self::Direct(domain) => domain.addressing(),
            Self::Confined(domain) => domain.addressing(),
        }
    }
}

/// Builds and owns the per-device translation domains of one IOMMU.
pub struct IommuDomains<I: Iommu> {
    iommu: I,
    geometry: IommuGeometry,
    physical_memory_offset: usize,
    /// Ranges every domain maps at their own physical address because
    /// the device cannot be told to issue anything else for them —
    /// interrupt doorbells.
    doorbells: [Option<PhysicalRange>; MAX_DMA_WINDOWS],
    /// I/O virtual bytes one domain's private slot occupies.
    slot_span: u64,
    /// Where the first domain's slot starts.
    first_base: u64,
    endpoint_count: usize,
    report: Arc<IommuReport>,
}

impl<I: Iommu> IommuDomains<I> {
    /// Prepares the per-device domain layout for `iommu`.
    ///
    /// `doorbells` are the physical ranges every confined device has to
    /// keep reaching at their own address (interrupt doorbells). No RAM is
    /// mapped here: each confined device gets a private, disjoint IOVA
    /// slot and maps only the chunks and foreign buffers it holds.
    pub fn new(
        iommu: I,
        doorbells: &[PhysicalRange],
        physical_memory_offset: usize,
        global_bypass: bool,
    ) -> Result<Self, IommuError> {
        let geometry = iommu.geometry();
        let doorbells = RangeSet::build(doorbells, &geometry)?;
        if doorbells.len > MAX_DMA_WINDOWS {
            return Err(IommuError::TooManyWindows);
        }
        let doorbells = windows_of(doorbells.as_slice());

        // The domain slots start above every identity-mapped doorbell so
        // a domain address can never collide with one.
        let doorbell_end = doorbells
            .iter()
            .flatten()
            .map(|range| range.last())
            .max()
            .map(|last| last.checked_add(1).ok_or(IommuError::OutOfRange))
            .transpose()?
            .unwrap_or(0);
        let first_base = geometry.align_up(doorbell_end.max(*geometry.input_range.start()));
        let input_end = *geometry.input_range.end();
        if first_base > input_end {
            return Err(IommuError::OutOfRange);
        }
        let available = u128::from(input_end) - u128::from(first_base) + 1;
        let granule = geometry.granule();
        let raw_slot = u64::try_from(available / MAX_IOMMU_ENDPOINTS as u128).unwrap_or(u64::MAX);
        let slot_span = raw_slot & !(granule - 1);
        if slot_span < granule {
            return Err(IommuError::OutOfRange);
        }

        let report = Arc::new(IommuReport::new(granule, global_bypass));
        Ok(Self {
            iommu,
            geometry,
            physical_memory_offset,
            doorbells,
            slot_span,
            first_base,
            endpoint_count: 0,
            report,
        })
    }

    /// The translation unit these domains are built on.
    pub fn iommu(&self) -> &I {
        &self.iommu
    }

    /// The live observation the kernel publishes for these domains.
    pub fn report(&self) -> Arc<IommuReport> {
        self.report.clone()
    }
}

impl<I: Iommu + Clone> IommuDomains<I> {
    /// Puts `endpoint` in a domain of its own, identity-maps only its
    /// doorbells, and returns the dynamic [`IommuChunkDomain`] its DMA
    /// arena maps chunks and foreign buffers through.
    pub fn confine(&mut self, endpoint: EndpointId) -> Result<IommuChunkDomain<I>, IommuError> {
        let index = self.endpoint_count;
        if index >= MAX_IOMMU_ENDPOINTS {
            return Err(IommuError::OutOfResources);
        }
        let domain_id = u32::try_from(index)
            .ok()
            .and_then(|index| self.geometry.domain_range.start().checked_add(index))
            .filter(|domain| self.geometry.domain_range.contains(domain))
            .ok_or(IommuError::OutOfResources)?;
        let domain = DomainId::new(domain_id);

        let base = u64::try_from(index)
            .ok()
            .and_then(|index| index.checked_mul(self.slot_span))
            .and_then(|offset| self.first_base.checked_add(offset))
            .ok_or(IommuError::OutOfRange)?;
        let last = base
            .checked_add(self.slot_span - 1)
            .ok_or(IommuError::OutOfRange)?;
        if !self.geometry.input_range.contains(&last) {
            return Err(IommuError::OutOfRange);
        }

        self.iommu.attach(domain, endpoint)?;

        let mut doorbell_bytes = 0_u64;
        for range in self.doorbells.iter().flatten() {
            // A doorbell is written by the device at an address the
            // interrupt controller fixed, so the only mapping that can
            // work is the identity one.
            if let Err(error) = self.iommu.map(
                domain,
                IoVirtAddr::new(range.start),
                range.start,
                range.bytes,
                DmaAccess::WRITE | DmaAccess::MMIO,
            ) {
                let _ = self.iommu.detach(domain, endpoint);
                return Err(error);
            }
            doorbell_bytes += range.bytes;
        }

        self.report
            .register_endpoint(index, endpoint, domain, doorbell_bytes);
        self.endpoint_count = index + 1;
        tracing::info!(
            endpoint = %endpoint,
            domain = domain_id,
            iova_base = base,
            iova_bytes = self.slot_span,
            doorbell_bytes,
            granule = self.geometry.granule(),
            "virtio device confined to its own IOMMU domain"
        );
        Ok(IommuChunkDomain {
            iommu: self.iommu.clone(),
            geometry: self.geometry.clone(),
            domain,
            physical_memory_offset: self.physical_memory_offset,
            iova: Arc::new(Mutex::new(IovaSpace::new(base, self.slot_span))),
            report: self.report.clone(),
            report_slot: index,
        })
    }
}

/// Ranges a firmware memory map may name before the kernel refuses to
/// look at it at all.
const MAX_INPUT_RANGES: usize = 64;

/// A fixed-capacity, ascending, disjoint set of physical ranges.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RangeSet {
    ranges: [PhysicalRange; MAX_INPUT_RANGES],
    len: usize,
}

impl RangeSet {
    /// Aligns every range outwards to `geometry`'s granule, sorts them,
    /// and merges the ones that touch.
    fn build(ranges: &[PhysicalRange], geometry: &IommuGeometry) -> Result<Self, IommuError> {
        if ranges.len() > MAX_INPUT_RANGES {
            return Err(IommuError::TooManyWindows);
        }
        let mut set = Self {
            ranges: [PhysicalRange::new(0, 0); MAX_INPUT_RANGES],
            len: 0,
        };
        for range in ranges {
            set.ranges[set.len] = range.aligned_to(geometry);
            set.len += 1;
        }
        for index in 1..set.len {
            let mut slot = index;
            while slot > 0 && set.ranges[slot - 1].start > set.ranges[slot].start {
                set.ranges.swap(slot - 1, slot);
                slot -= 1;
            }
        }
        set.merge_touching();
        Ok(set)
    }

    fn as_slice(&self) -> &[PhysicalRange] {
        &self.ranges[..self.len]
    }

    fn merge_touching(&mut self) {
        let mut kept = 0;
        for index in 1..self.len {
            let candidate = self.ranges[index];
            let current = self.ranges[kept];
            if candidate.start <= current.last().saturating_add(1) {
                self.ranges[kept] = merge(current, candidate);
                continue;
            }
            kept += 1;
            self.ranges[kept] = candidate;
        }
        if self.len != 0 {
            self.len = kept + 1;
        }
    }
}

fn merge(first: PhysicalRange, second: PhysicalRange) -> PhysicalRange {
    let start = first.start.min(second.start);
    let last = first.last().max(second.last());
    PhysicalRange::new(start, last - start + 1)
}

fn windows_of(ranges: &[PhysicalRange]) -> [Option<PhysicalRange>; MAX_DMA_WINDOWS] {
    let mut windows = [const { None }; MAX_DMA_WINDOWS];
    for (slot, range) in ranges.iter().enumerate() {
        windows[slot] = Some(*range);
    }
    windows
}

#[cfg(test)]
mod tests {
    use alloc::alloc::{alloc_zeroed, dealloc};
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use core::alloc::Layout;
    use core::future::Future;
    use core::ops::Range;
    use core::ptr;
    use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    use futures_lite::future::block_on;
    use helios_hal::dma::{DmaAddressing, DmaBuffer, DmaForeignMapping, DmaMemory};
    use helios_hal::iommu::{
        DmaAccess, DomainId, EndpointId, IoVirtAddr, Iommu, IommuError, IommuGeometry,
        PhysicalRange,
    };
    use helios_hal::pmm::PhysFrame;
    use spin::Mutex;

    use super::{IommuDomains, IommuReport, MAX_IOMMU_ENDPOINTS};
    use crate::exec::{ProgressMark, ProgressSignal};
    use crate::io::dma::{ChunkDomain, ChunkSource, DmaArenas, LentChunk, SharedDmaArena};

    /// `-(4 * KiB)`: a unit that maps from 4 KiB pages upwards.
    const PAGE_SIZE_MASK: u64 = 0xffff_ffff_ffff_f000;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct MappingEntry {
        domain: DomainId,
        iova_start: u64,
        bytes: u64,
        physical: u64,
        access: DmaAccess,
    }

    #[derive(Default)]
    struct SimState {
        attachments: Vec<(EndpointId, DomainId)>,
        mappings: Vec<MappingEntry>,
    }

    /// A software IOMMU model that enforces per-domain isolation,
    /// access rights, and unmapped-IOVA fault accounting.
    #[derive(Clone)]
    struct SimulatingIommu {
        geometry: IommuGeometry,
        state: Arc<Mutex<SimState>>,
        faults: Arc<AtomicU64>,
    }

    impl SimulatingIommu {
        fn new(domain_last: u32) -> Self {
            Self {
                geometry: IommuGeometry {
                    page_size_mask: PAGE_SIZE_MASK,
                    input_range: 0..=u64::MAX,
                    domain_range: 0..=domain_last,
                },
                state: Arc::new(Mutex::new(SimState::default())),
                faults: Arc::new(AtomicU64::new(0)),
            }
        }

        fn fault_count(&self) -> u64 {
            self.faults.load(Ordering::Relaxed)
        }

        /// Simulates a DMA transaction by `endpoint` at `iova` with
        /// `required` access rights, incrementing the fault counter and
        /// publishing it to `report` on any translation or permission
        /// violation.
        fn dma_access(
            &self,
            endpoint: EndpointId,
            iova: u64,
            required: DmaAccess,
            report: &IommuReport,
        ) -> Result<u64, IommuError> {
            let state = self.state.lock();
            let Some(&(_, domain)) = state.attachments.iter().find(|&&(ep, _)| ep == endpoint)
            else {
                let total = self.faults.fetch_add(1, Ordering::Relaxed) + 1;
                report.record_faults(total);
                return Err(IommuError::Fault);
            };
            for entry in &state.mappings {
                if entry.domain == domain
                    && iova >= entry.iova_start
                    && iova - entry.iova_start < entry.bytes
                    && entry.access.contains(required)
                {
                    return Ok(entry.physical + (iova - entry.iova_start));
                }
            }
            let total = self.faults.fetch_add(1, Ordering::Relaxed) + 1;
            report.record_faults(total);
            Err(IommuError::Fault)
        }
    }

    impl Iommu for SimulatingIommu {
        fn geometry(&self) -> IommuGeometry {
            self.geometry.clone()
        }

        fn attach(&self, domain: DomainId, endpoint: EndpointId) -> Result<(), IommuError> {
            let mut state = self.state.lock();
            state.attachments.retain(|&(ep, _)| ep != endpoint);
            state.attachments.push((endpoint, domain));
            Ok(())
        }

        fn detach(&self, domain: DomainId, endpoint: EndpointId) -> Result<(), IommuError> {
            let mut state = self.state.lock();
            state
                .attachments
                .retain(|&(ep, dom)| !(ep == endpoint && dom == domain));
            Ok(())
        }

        fn map(
            &self,
            domain: DomainId,
            iova: IoVirtAddr,
            physical: u64,
            bytes: u64,
            access: DmaAccess,
        ) -> Result<(), IommuError> {
            let mut state = self.state.lock();
            let start = iova.get();
            let end = start.checked_add(bytes).ok_or(IommuError::OutOfRange)?;
            for existing in &state.mappings {
                if existing.domain == domain {
                    let ex_end = existing.iova_start + existing.bytes;
                    if start < ex_end && existing.iova_start < end {
                        return Err(IommuError::Invalid);
                    }
                }
            }
            state.mappings.push(MappingEntry {
                domain,
                iova_start: start,
                bytes,
                physical,
                access,
            });
            Ok(())
        }

        fn unmap(&self, domain: DomainId, iova: IoVirtAddr, bytes: u64) -> Result<(), IommuError> {
            let mut state = self.state.lock();
            let before = state.mappings.len();
            state.mappings.retain(|entry| {
                !(entry.domain == domain && entry.iova_start == iova.get() && entry.bytes == bytes)
            });
            if state.mappings.len() == before {
                return Err(IommuError::NotFound);
            }
            Ok(())
        }
    }

    struct HostChunkRegion {
        layout: Layout,
        base: usize,
        chunk_bytes: usize,
        lent: Vec<AtomicBool>,
        returned: ProgressSignal,
    }

    impl Drop for HostChunkRegion {
        fn drop(&mut self) {
            // SAFETY: allocated with `self.layout` in `HostChunkSource::new`.
            unsafe { dealloc(ptr::with_exposed_provenance_mut(self.base), self.layout) };
        }
    }

    #[derive(Clone)]
    struct HostChunkSource(Arc<HostChunkRegion>);

    impl HostChunkSource {
        fn new(chunk_bytes: usize, capacity: usize) -> Self {
            let layout =
                Layout::from_size_align(chunk_bytes * capacity, chunk_bytes).expect("chunk layout");
            // SAFETY: non-zero layout.
            let base = unsafe { alloc_zeroed(layout) };
            assert!(!base.is_null());
            Self(Arc::new(HostChunkRegion {
                layout,
                base: base.expose_provenance(),
                chunk_bytes,
                lent: (0..capacity).map(|_| AtomicBool::new(false)).collect(),
                returned: ProgressSignal::new(),
            }))
        }
    }

    impl ChunkSource for HostChunkSource {
        fn lend(&self, bytes: usize) -> Option<LentChunk> {
            assert_eq!(bytes, self.0.chunk_bytes);
            let slot = (0..self.0.lent.len()).find(|&slot| {
                self.0.lent[slot]
                    .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                    .is_ok()
            })?;
            Some(LentChunk::new(self.0.base + slot * bytes, bytes))
        }

        fn take_back(&self, chunk: LentChunk) {
            let slot = (chunk.start() - self.0.base) / self.0.chunk_bytes;
            assert!(self.0.lent[slot].swap(false, Ordering::SeqCst));
            self.0.returned.signal();
        }

        fn span(&self) -> Range<usize> {
            self.0.base..self.0.base + self.0.lent.len() * self.0.chunk_bytes
        }

        fn want_chunk(&self) -> ProgressMark {
            self.0.returned.mark()
        }

        fn chunk_returned(&self, mark: ProgressMark) -> impl Future<Output = ()> + Send + '_ {
            self.0.returned.changed(mark)
        }
    }

    fn doorbells() -> [PhysicalRange; 1] {
        [PhysicalRange::new(0xfee0_0000, 0x10_0000)]
    }

    #[test]
    fn confining_maps_only_doorbells_and_chunks_map_dynamically_with_access_rights() {
        let sim = SimulatingIommu::new(u32::MAX);
        let mut domains =
            IommuDomains::new(sim.clone(), &doorbells(), 0, true).expect("layout builds");
        let ep_a = EndpointId::new(0x18);
        let ep_b = EndpointId::new(0x20);
        let dom_a = domains.confine(ep_a).expect("confine A");
        let dom_b = domains.confine(ep_b).expect("confine B");
        let report = domains.report();

        // Initially only the doorbell is mapped; zero RAM is reachable.
        let initial = report.snapshot();
        assert_eq!(initial.endpoints().len(), 2);
        assert_eq!(initial.endpoints()[0].mapped_bytes, 0x10_0000);
        assert_eq!(initial.endpoints()[1].mapped_bytes, 0x10_0000);
        assert_eq!(
            sim.dma_access(ep_a, 0xfee0_0000, DmaAccess::WRITE, &report),
            Ok(0xfee0_0000)
        );
        // Unmapped IOVA faults and increments the report's fault counter.
        assert_eq!(
            sim.dma_access(ep_a, 0xfef0_0000, DmaAccess::READ, &report),
            Err(IommuError::Fault)
        );
        assert_eq!(report.snapshot().faults, 1);

        let chunk_bytes = 4 * PhysFrame::SIZE;
        let source = HostChunkSource::new(chunk_bytes, 8);
        let mut arenas = DmaArenas::new(source);
        let arena_a = arenas.arena(dom_a, chunk_bytes, 1);
        let arena_b = arenas.arena(dom_b, chunk_bytes, 1);
        let dma_a = SharedDmaArena::new(arena_a.clone());
        let dma_b = SharedDmaArena::new(arena_b.clone());
        assert_eq!(dma_a.addressing(), DmaAddressing::Platform);

        // Allocate a read-only buffer for device A and a read-write buffer for device B.
        let layout = Layout::from_size_align(PhysFrame::SIZE, PhysFrame::SIZE).expect("layout");
        let buf_a_ro = dma_a
            .allocate(layout, DmaAccess::READ)
            .expect("read-only buffer on A");
        let buf_b_rw = dma_b
            .allocate(layout, DmaAccess::READ | DmaAccess::WRITE)
            .expect("read-write buffer on B");

        let iova_a = buf_a_ro.device_address().get();
        let iova_b = buf_b_rw.device_address().get();
        assert_ne!(iova_a, iova_b);

        // Live mapped bytes grew by exactly one chunk per device.
        let after_alloc = report.snapshot();
        assert_eq!(
            after_alloc.endpoints()[0].mapped_bytes,
            0x10_0000 + chunk_bytes as u64
        );
        assert_eq!(
            after_alloc.endpoints()[1].mapped_bytes,
            0x10_0000 + chunk_bytes as u64
        );

        // Device A can read its read-only chunk, but writing to it faults.
        assert_eq!(
            sim.dma_access(ep_a, iova_a, DmaAccess::READ, &report),
            Ok(buf_a_ro.as_ptr() as usize as u64)
        );
        assert_eq!(
            sim.dma_access(ep_a, iova_a, DmaAccess::WRITE, &report),
            Err(IommuError::Fault)
        );
        assert_eq!(report.snapshot().faults, 2);

        // Cross-domain isolation: A cannot access B's IOVA, and B cannot access A's IOVA.
        assert_eq!(
            sim.dma_access(ep_a, iova_b, DmaAccess::READ, &report),
            Err(IommuError::Fault)
        );
        assert_eq!(
            sim.dma_access(ep_b, iova_a, DmaAccess::READ, &report),
            Err(IommuError::Fault)
        );
        assert_eq!(report.snapshot().faults, 4);

        // Device B can both read and write its own writable chunk.
        assert_eq!(
            sim.dma_access(ep_b, iova_b, DmaAccess::READ | DmaAccess::WRITE, &report),
            Ok(buf_b_rw.as_ptr() as usize as u64)
        );

        // Dropping A's buffer and retiring empty chunks unmaps A's chunk;
        // subsequent access to the retired IOVA faults and mapped_bytes drops back.
        drop(buf_a_ro);
        assert_eq!(block_on(arena_a.retire_empty(0)), 1);
        assert_eq!(report.snapshot().endpoints()[0].mapped_bytes, 0x10_0000);
        assert_eq!(
            sim.dma_access(ep_a, iova_a, DmaAccess::READ, &report),
            Err(IommuError::Fault)
        );
        assert_eq!(report.snapshot().faults, 5);

        // Clean teardown of B.
        drop(buf_b_rw);
        assert_eq!(block_on(arena_b.retire_empty(0)), 1);
        assert_eq!(report.snapshot().endpoints()[1].mapped_bytes, 0x10_0000);
        assert_eq!(sim.fault_count(), 5);
    }

    #[test]
    fn foreign_mapping_revokes_access_on_drop_and_reclaims_iova() {
        let sim = SimulatingIommu::new(u32::MAX);
        let mut domains =
            IommuDomains::new(sim.clone(), &doorbells(), 0, false).expect("layout builds");
        let ep = EndpointId::new(0x10);
        let dom = domains.confine(ep).expect("confine");
        let report = domains.report();

        // Unaligned physical range is rounded outwards to granule and preserves offset.
        let mapping = dom
            .map_foreign(PhysicalRange::new(0x4000_0800, 0x1800), DmaAccess::READ)
            .expect("foreign mapping");
        let iova = mapping.device_address().get();
        assert_eq!(iova & 0xfff, 0x800);
        assert_eq!(
            report.snapshot().endpoints()[0].mapped_bytes,
            0x10_0000 + 0x2000
        );
        assert_eq!(
            sim.dma_access(ep, iova, DmaAccess::READ, &report),
            Ok(0x4000_0800)
        );
        // Write to read-only foreign mapping faults.
        assert_eq!(
            sim.dma_access(ep, iova, DmaAccess::WRITE, &report),
            Err(IommuError::Fault)
        );

        drop(mapping);
        assert_eq!(report.snapshot().endpoints()[0].mapped_bytes, 0x10_0000);
        // Access after drop faults.
        assert_eq!(
            sim.dma_access(ep, iova, DmaAccess::READ, &report),
            Err(IommuError::Fault)
        );
        assert_eq!(report.snapshot().faults, 2);

        // IOVA was reclaimed and coalesced, so the next mapping reuses the slot base.
        let again = dom
            .map_foreign(PhysicalRange::new(0x5000_0000, 0x1000), DmaAccess::READ)
            .expect("second foreign mapping");
        assert_eq!(again.device_address().get(), iova & !0xfff);
    }

    #[test]
    fn a_unit_with_too_few_domains_refuses_the_next_device() {
        let mut domains =
            IommuDomains::new(SimulatingIommu::new(0), &[], 0, false).expect("layout builds");

        domains
            .confine(EndpointId::new(0x18))
            .expect("the only domain is available");
        assert_eq!(
            domains.confine(EndpointId::new(0x20)).err(),
            Some(IommuError::OutOfResources)
        );
    }

    #[test]
    fn more_devices_than_the_kernel_tracks_are_refused() {
        let mut domains = IommuDomains::new(SimulatingIommu::new(u32::MAX), &[], 0, false)
            .expect("layout builds");
        for index in 0..MAX_IOMMU_ENDPOINTS {
            domains
                .confine(EndpointId::new(index as u32))
                .expect("every tracked endpoint is confined");
        }

        assert_eq!(
            domains.confine(EndpointId::new(0xffff)).err(),
            Some(IommuError::OutOfResources)
        );
    }
}
