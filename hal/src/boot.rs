use core::ops::Range;
use core::ptr::NonNull;

use arrayvec::ArrayVec;

use crate::memory::MemoryRegion;
use crate::numa::{MemoryAffinity, NumaTopology};

/// How many bootloader-owned ranges a machine may hold back from the
/// usable memory map.
pub const MAX_BOOT_RESERVED_RANGES: usize = 4;

/// How many usable pieces one memory region can be cut into once every
/// reserved range is subtracted from it.
pub const MAX_USABLE_REGION_SEGMENTS: usize = 6;

/// Maximum firmware memory-map entries carried in [`BootMemoryMetadata`].
pub const MAX_FIRMWARE_MEMORY_MAP_ENTRIES: usize = 128;

/// Maximum bootloader-reclaimable ranges carried in [`BootMemoryMetadata`].
pub const MAX_BOOTLOADER_RECLAIMABLE_RANGES: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootMemoryKind {
    Usable,
    /// Memory used by the bootloader (page tables, boot structures) that
    /// remains live until the kernel replaces every reference to it.
    BootloaderReclaimable,
    Reserved,
}

impl BootMemoryKind {
    /// Stable wire discriminant for canonical memory-map hashing.
    pub const fn tag(self) -> u32 {
        match self {
            Self::Usable => 0,
            Self::BootloaderReclaimable => 1,
            Self::Reserved => 2,
        }
    }
}

/// A half-open `[start, end)` physical address range recorded at boot.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BootPhysicalRange {
    pub start: u64,
    pub end: u64,
}

impl BootPhysicalRange {
    pub const fn new(start: u64, end: u64) -> Self {
        Self { start, end }
    }

    pub const fn from_start_len(start: u64, len: u64) -> Self {
        Self {
            start,
            end: start.saturating_add(len),
        }
    }

    pub const fn len(self) -> u64 {
        self.end.saturating_sub(self.start)
    }

    pub const fn is_empty(self) -> bool {
        self.end <= self.start
    }
}

/// Physical and virtual location of one linked kernel section.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct KernelSectionRange {
    pub physical_start: u64,
    pub virtual_start: u64,
    pub len: u64,
}

impl KernelSectionRange {
    pub const fn new(physical_start: u64, virtual_start: u64, len: u64) -> Self {
        Self {
            physical_start,
            virtual_start,
            len,
        }
    }

    pub const fn physical_end(self) -> u64 {
        self.physical_start.saturating_add(self.len)
    }

    pub const fn virtual_end(self) -> u64 {
        self.virtual_start.saturating_add(self.len)
    }

    pub const fn physical_range(self) -> BootPhysicalRange {
        BootPhysicalRange::from_start_len(self.physical_start, self.len)
    }

    pub const fn is_empty(self) -> bool {
        self.len == 0
    }
}

/// Immutable and writable sections of the running kernel image, as laid
/// out by the linker script and placed in physical memory by the loader.
///
/// `text` and `rodata` are immutable after bring-up and identify the
/// kernel image; `data`, `bss`, and optional `uninit`/`stack` ranges hold
/// writable kernel state that a full-memory snapshot must preserve.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct KernelImageSections {
    pub text: KernelSectionRange,
    pub rodata: KernelSectionRange,
    pub data: KernelSectionRange,
    pub bss: KernelSectionRange,
    /// Optional writable `.uninit` section (present on RISC-V).
    pub uninit: Option<KernelSectionRange>,
    /// Optional statically linked kernel stack section (present on RISC-V).
    pub stack: Option<KernelSectionRange>,
}

/// Physical location and SHA-256 digest of the verified boot payload
/// handed to the kernel at bring-up.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BootPayloadMetadata {
    pub physical_address: u64,
    pub len: u64,
    pub sha256: [u8; 32],
}

/// Boot-time memory layout and firmware-owned ranges preserved for full
/// machine identity verification and atomic memory snapshots.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BootMemoryMetadata {
    pub kernel_sections: KernelImageSections,
    pub bootloader_reclaimable: ArrayVec<BootPhysicalRange, MAX_BOOTLOADER_RECLAIMABLE_RANGES>,
    pub device_tree_blob: Option<BootPhysicalRange>,
    pub firmware_memory_map: ArrayVec<BootMemoryRegion, MAX_FIRMWARE_MEMORY_MAP_ENTRIES>,
    pub boot_payload: Option<BootPayloadMetadata>,
    /// Direct-map offset (`virtual = physical + physical_memory_offset`),
    /// `0` on identity-mapped backends.
    pub physical_memory_offset: usize,
}

impl BootMemoryMetadata {
    /// Highest physical address covered by any firmware memory-map entry.
    pub fn max_physical_address(&self) -> u64 {
        self.firmware_memory_map
            .iter()
            .map(|region| region.end)
            .max()
            .unwrap_or(0)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BootMemoryRegion {
    pub start: u64,
    pub end: u64,
    pub kind: BootMemoryKind,
}

impl BootMemoryRegion {
    pub const fn usable(self) -> bool {
        matches!(self.kind, BootMemoryKind::Usable)
    }
}

pub trait BootMemoryMap {
    type Iter: Iterator<Item = BootMemoryRegion>;

    fn regions(&self) -> Self::Iter;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FirmwareKind {
    Uefi32,
    Uefi64,
    Sbi,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BootKernelImage {
    pub physical_base: u64,
    pub virtual_base: u64,
    pub file_address: usize,
    pub size: u64,
}

/// Where the bootloader left the firmware's own descriptions of the
/// machine, for whichever of them this firmware publishes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BootFirmwareTables {
    /// Physical address of the ACPI root pointer.
    ///
    /// Physical rather than mapped, because an ACPI table walk follows
    /// physical addresses out of the tables themselves and has to map
    /// each one the same way; handing it a pre-mapped root would make
    /// the root the one address that is translated differently.
    pub acpi_rsdp: Option<usize>,
    /// Address of the flattened device tree, mapped and readable.
    ///
    /// Unlike ACPI, a device tree is one self-contained blob: nothing
    /// in it is reached by physical address, so the only thing a reader
    /// needs is somewhere to read it from.
    pub device_tree_blob: Option<usize>,
    /// The log of every measurement the chain before the kernel made,
    /// when the firmware kept one and the bootloader handed it over.
    pub measurement_log: Option<MeasurementLog>,
}

/// The firmware's log of the measurements the boot chain extended into
/// its measurement device, mapped and readable.
///
/// Like a device tree it is one self-contained blob, so it is handed
/// over by where it can be read from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MeasurementLog {
    pub format: MeasurementLogFormat,
    pub address: usize,
    pub size: usize,
}

/// How a [`MeasurementLog`]'s records are laid out, by the
/// `EFI_TCG2_EVENT_LOG_FORMAT` bit the firmware produced it under (TCG
/// EFI Protocol Specification, "EFI_TCG2_PROTOCOL.GetEventLog").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MeasurementLogFormat {
    /// `EFI_TCG2_EVENT_LOG_FORMAT_TCG_1_2`: SHA-1 records only.
    Tcg12,
    /// `EFI_TCG2_EVENT_LOG_FORMAT_TCG_2`: the crypto-agile log, one
    /// digest per active bank in every record.
    Tcg2,
    /// A format code this kernel does not know, as the bootloader gave
    /// it.
    Other(u64),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BootModule<'a> {
    pub address: usize,
    pub size: usize,
    pub path: &'a [u8],
    pub command_line: &'a [u8],
}

pub trait BootModules<'a> {
    type Iter: Iterator<Item = BootModule<'a>>;

    fn modules(&self) -> Self::Iter;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NoBootModules;

impl<'a> BootModules<'a> for NoBootModules {
    type Iter = core::iter::Empty<BootModule<'a>>;

    fn modules(&self) -> Self::Iter {
        core::iter::empty()
    }
}

/// Bit-field position and width of one RGB colour channel inside a packed
/// linear framebuffer pixel word.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BootPixelChannel {
    /// Width of the channel field in bits (for example, `8` for 8-bit RGB).
    pub mask_size: u8,
    /// Bit offset of the channel's least-significant bit inside the pixel word.
    pub mask_shift: u8,
}

impl BootPixelChannel {
    pub const fn new(mask_size: u8, mask_shift: u8) -> Self {
        Self {
            mask_size,
            mask_shift,
        }
    }

    /// Packs an 8-bit colour component (`0..=255`) into this channel's
    /// bit-field position using integer arithmetic only.
    pub const fn pack(self, value: u8) -> u32 {
        if self.mask_size == 0 || self.mask_shift >= 32 {
            return 0;
        }
        let scaled = if self.mask_size >= 8 {
            value as u32
        } else {
            (value as u32) >> (8 - self.mask_size)
        };
        let mask = if self.mask_size >= 32 {
            u32::MAX
        } else {
            (1u32 << self.mask_size) - 1
        };
        (scaled & mask) << self.mask_shift
    }
}

/// RGB pixel channel masks and shifts reported by firmware or the bootloader.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BootPixelLayout {
    pub red: BootPixelChannel,
    pub green: BootPixelChannel,
    pub blue: BootPixelChannel,
}

impl BootPixelLayout {
    pub const fn new(
        red: BootPixelChannel,
        green: BootPixelChannel,
        blue: BootPixelChannel,
    ) -> Self {
        Self { red, green, blue }
    }

    /// Standard 32-bit `BGRX8888` (`0x00RRGGBB` in little-endian memory).
    pub const BGRX8888: Self = Self {
        red: BootPixelChannel::new(8, 16),
        green: BootPixelChannel::new(8, 8),
        blue: BootPixelChannel::new(8, 0),
    };

    /// Standard 32-bit `RGBX8888` (`0x00BBGGRR` in little-endian memory).
    pub const RGBX8888: Self = Self {
        red: BootPixelChannel::new(8, 0),
        green: BootPixelChannel::new(8, 8),
        blue: BootPixelChannel::new(8, 16),
    };

    /// Packs 8-bit `(red, green, blue)` components into the framebuffer's
    /// little-endian pixel word.
    pub const fn pack_rgb(self, red: u8, green: u8, blue: u8) -> u32 {
        self.red.pack(red) | self.green.pack(green) | self.blue.pack(blue)
    }
}

/// A firmware-provisioned linear RGB framebuffer handed over at boot.
///
/// The backing memory is mapped writable in the kernel's higher-half direct
/// map and stays untouched across normal bring-up so any bootloader splash
/// remains on screen until the native display driver claims scanout. Only an
/// early fatal panic writes to it before handoff.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BootFramebuffer {
    /// Virtual address of the top-left pixel in the kernel address space.
    pub base: NonNull<u8>,
    /// Visible width in pixels.
    pub width: u32,
    /// Visible height in pixels.
    pub height: u32,
    /// Distance between consecutive scanlines in bytes.
    pub pitch: u32,
    /// Bits per pixel (`16`, `24`, or `32`).
    pub bpp: u16,
    /// RGB channel layout inside each pixel word.
    pub layout: BootPixelLayout,
}

// SAFETY: `BootFramebuffer` describes a firmware-owned linear framebuffer
// mapping at a fixed kernel virtual address that remains valid until detached
// when the native display driver takes over; callers synchronize access.
unsafe impl Send for BootFramebuffer {}
// SAFETY: same as `Send`.
unsafe impl Sync for BootFramebuffer {}

impl BootFramebuffer {
    /// Bytes occupied by one pixel for supported linear RGB formats (`16`,
    /// `24`, or `32` bpp).
    pub const fn bytes_per_pixel(&self) -> Option<usize> {
        match self.bpp {
            16 => Some(2),
            24 => Some(3),
            32 => Some(4),
            _ => None,
        }
    }

    /// Total byte extent of the visible scanlines (`height * pitch`).
    pub const fn byte_len(&self) -> Option<usize> {
        (self.height as usize).checked_mul(self.pitch as usize)
    }

    /// Whether the geometry and pixel stride form a well-formed, addressable
    /// linear RGB framebuffer.
    pub const fn is_valid(&self) -> bool {
        if self.width == 0 || self.height == 0 {
            return false;
        }
        let Some(bytes_per_pixel) = self.bytes_per_pixel() else {
            return false;
        };
        let Some(row_bytes) = (self.width as usize).checked_mul(bytes_per_pixel) else {
            return false;
        };
        if (self.pitch as usize) < row_bytes {
            return false;
        }
        matches!(self.byte_len(), Some(len) if len > 0 && len <= isize::MAX as usize)
    }

    /// Packs 8-bit `(red, green, blue)` components into this framebuffer's
    /// native pixel word.
    pub const fn pack_rgb(&self, red: u8, green: u8, blue: u8) -> u32 {
        self.layout.pack_rgb(red, green, blue)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BootHandoff<'a, MemoryMap, Modules> {
    pub memory_map: MemoryMap,
    pub kernel: BootKernelImage,
    pub command_line: &'a [u8],
    pub modules: Modules,
    pub firmware: FirmwareKind,
    pub tables: BootFirmwareTables,
    pub framebuffer: Option<BootFramebuffer>,
}

/// The bootloader-owned ranges carved out of the usable memory map.
///
/// A bootloader hands the kernel a memory map that still describes the
/// bytes it put the kernel image in as usable, and a machine may need
/// one more range held back for its own bring-up. Each of those is
/// recorded here and subtracted from every usable region before the
/// kernel primes an allocator from it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BootReservedRanges {
    ranges: ArrayVec<Range<usize>, MAX_BOOT_RESERVED_RANGES>,
}

impl BootReservedRanges {
    pub fn new() -> Self {
        Self::default()
    }

    /// Holds `range` back from every usable region.
    ///
    /// Panics past capacity rather than dropping the range: a reserved
    /// range that silently went missing hands the allocator memory the
    /// firmware or the kernel image still owns.
    pub fn reserve(&mut self, range: Range<usize>) {
        self.ranges.try_push(range).unwrap_or_else(|error| {
            panic!(
                "boot reserved ranges exceeded capacity {MAX_BOOT_RESERVED_RANGES}: {:#x?}",
                error.element()
            )
        });
    }

    pub fn iter(&self) -> impl Iterator<Item = &Range<usize>> {
        self.ranges.iter()
    }
}

/// The usable pieces of `region` once every reserved range is subtracted.
///
/// A region that is not usable, or empty, yields nothing. Each reserved
/// range that overlaps a piece splits it in two, so the count is bounded
/// by the reserved-range capacity and returned in a fixed-size array
/// rather than an allocation.
pub fn usable_region_segments(
    region: BootMemoryRegion,
    reserved_ranges: &BootReservedRanges,
) -> [Option<Range<usize>>; MAX_USABLE_REGION_SEGMENTS] {
    if !region.usable() || region.end <= region.start {
        return [const { None }; MAX_USABLE_REGION_SEGMENTS];
    }

    let mut segments = [const { None }; MAX_USABLE_REGION_SEGMENTS];
    segments[0] = Some(region.start as usize..region.end as usize);
    for reserved in reserved_ranges.iter() {
        segments = subtract_reserved_range(segments, reserved);
    }
    segments
}

/// The usable pieces of `region`, reserved ranges removed and each piece
/// split at node boundaries, as kernel-owned regions.
///
/// Panics naming the physical range when a usable byte lies in no
/// affinity range: memory the kernel cannot place is memory it does not
/// understand. (Linux tolerates <1 MiB uncovered and otherwise discards
/// NUMA altogether; neither is a correct answer here.)
///
/// # Safety
///
/// Every usable byte of `region` that is not reserved is memory nothing
/// else owns, it is reachable at its physical address plus
/// `physical_memory_offset`, and it outlives the kernel.
pub unsafe fn usable_node_regions<'n, Numa: NumaTopology>(
    region: BootMemoryRegion,
    reserved: &BootReservedRanges,
    physical_memory_offset: usize,
    numa: &'n Numa,
) -> impl Iterator<Item = MemoryRegion> + use<'n, Numa> {
    NodeRegions {
        segments: usable_region_segments(region, reserved)
            .into_iter()
            .flatten(),
        numa,
        physical_memory_offset,
        current: None,
    }
}

/// The segment being split, the affinity ranges still to intersect with
/// it, and how many of its bytes they have covered so far.
struct SegmentCursor<'n, Numa: NumaTopology + 'n> {
    segment: Range<u64>,
    affinities: Numa::MemoryAffinities<'n>,
    covered: u64,
}

struct NodeRegions<'n, Numa: NumaTopology + 'n> {
    segments: core::iter::Flatten<
        core::array::IntoIter<Option<Range<usize>>, MAX_USABLE_REGION_SEGMENTS>,
    >,
    numa: &'n Numa,
    physical_memory_offset: usize,
    current: Option<SegmentCursor<'n, Numa>>,
}

impl<'n, Numa: NumaTopology + 'n> Iterator for NodeRegions<'n, Numa> {
    type Item = MemoryRegion;

    fn next(&mut self) -> Option<MemoryRegion> {
        loop {
            let cursor = match &mut self.current {
                Some(cursor) => cursor,
                None => {
                    let segment = self.segments.next()?;
                    self.current.insert(SegmentCursor {
                        segment: segment.start as u64..segment.end as u64,
                        affinities: self.numa.memory_affinity(),
                        covered: 0,
                    })
                }
            };
            let Some(MemoryAffinity { physical, node }) = cursor.affinities.next() else {
                assert!(
                    cursor.covered == cursor.segment.end - cursor.segment.start,
                    "usable memory {:#x?} is only partly covered by the NUMA memory affinity \
                     ({:#x} of {:#x} bytes)",
                    cursor.segment,
                    cursor.covered,
                    cursor.segment.end - cursor.segment.start
                );
                self.current = None;
                continue;
            };
            let start = physical.start.max(cursor.segment.start);
            let end = physical.end.min(cursor.segment.end);
            if start >= end {
                continue;
            }
            cursor.covered += end - start;
            let pointer = core::ptr::slice_from_raw_parts_mut(
                (start as usize + self.physical_memory_offset) as *mut u8,
                (end - start) as usize,
            );
            let span = core::ptr::NonNull::new(pointer)
                .unwrap_or_else(|| panic!("usable memory piece {start:#x}..{end:#x} is null"));
            // SAFETY: the caller of `usable_node_regions` promised every
            // usable, unreserved byte, and this piece is one of them.
            return Some(unsafe { MemoryRegion::new(span, node) });
        }
    }
}

fn subtract_reserved_range(
    segments: [Option<Range<usize>>; MAX_USABLE_REGION_SEGMENTS],
    reserved: &Range<usize>,
) -> [Option<Range<usize>>; MAX_USABLE_REGION_SEGMENTS] {
    let mut result = [const { None }; MAX_USABLE_REGION_SEGMENTS];
    let mut next = 0;
    for segment in segments.into_iter().flatten() {
        for piece in split_segment(segment, reserved).into_iter().flatten() {
            assert!(
                next < MAX_USABLE_REGION_SEGMENTS,
                "boot memory segmentation exceeded capacity {MAX_USABLE_REGION_SEGMENTS}"
            );
            result[next] = Some(piece);
            next += 1;
        }
    }
    result
}

/// `segment` with `reserved` taken out of it: the part below it and the
/// part above it, either of which may be empty.
fn split_segment(segment: Range<usize>, reserved: &Range<usize>) -> [Option<Range<usize>>; 2] {
    if reserved.end <= segment.start || reserved.start >= segment.end {
        return [Some(segment), None];
    }
    let below = (reserved.start > segment.start).then_some(segment.start..reserved.start);
    let above = (reserved.end < segment.end).then_some(reserved.end..segment.end);
    [below, above]
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::{
        BootFramebuffer, BootMemoryKind, BootMemoryRegion, BootPixelChannel, BootPixelLayout,
        BootReservedRanges, usable_node_regions, usable_region_segments,
    };
    use crate::cpu::ProcessorId;
    use crate::numa::{MemoryAffinity, NodeDistance, NodeId, NumaTopology};
    use core::ops::Range;
    use core::ptr::NonNull;

    #[test]
    fn pixel_layout_packs_bgrx_rgbx_and_rgb565_using_integers() {
        assert_eq!(
            BootPixelLayout::BGRX8888.pack_rgb(0xFF, 0x6A, 0x00),
            0x00FF_6A00
        );
        assert_eq!(
            BootPixelLayout::RGBX8888.pack_rgb(0xFF, 0x6A, 0x00),
            0x0000_6AFF
        );

        let rgb565 = BootPixelLayout::new(
            BootPixelChannel::new(5, 11),
            BootPixelChannel::new(6, 5),
            BootPixelChannel::new(5, 0),
        );
        // Full red (0x1f << 11), half green (~0x20 << 5), full blue (0x1f).
        assert_eq!(
            rgb565.pack_rgb(0xFF, 0x80, 0xFF),
            (0x1F << 11) | (0x20 << 5) | 0x1F
        );
        assert_eq!(BootPixelChannel::new(0, 0).pack(0xFF), 0);
        assert_eq!(BootPixelChannel::new(8, 32).pack(0xFF), 0);
    }

    #[test]
    fn boot_framebuffer_validates_geometry_and_bpp() {
        let mut backing = [0u8; 64];
        let base = NonNull::new(backing.as_mut_ptr()).expect("stack slice is non-null");
        let valid = BootFramebuffer {
            base,
            width: 4,
            height: 4,
            pitch: 16,
            bpp: 32,
            layout: BootPixelLayout::BGRX8888,
        };
        assert!(valid.is_valid());
        assert_eq!(valid.bytes_per_pixel(), Some(4));
        assert_eq!(valid.byte_len(), Some(64));
        assert_eq!(valid.pack_rgb(0x12, 0x34, 0x56), 0x0012_3456);

        let too_narrow_pitch = BootFramebuffer { pitch: 12, ..valid };
        assert!(!too_narrow_pitch.is_valid());

        let unsupported_bpp = BootFramebuffer { bpp: 8, ..valid };
        assert!(!unsupported_bpp.is_valid());

        let zero_height = BootFramebuffer { height: 0, ..valid };
        assert!(!zero_height.is_valid());
    }

    #[test]
    fn usable_region_without_overlap_stays_single_segment() {
        assert_eq!(
            collect_segments(region(0x1000..0x4000), Some(0x5000..0x6000)),
            alloc::vec![0x1000..0x4000]
        );
    }

    #[test]
    fn excluded_wakeup_page_splits_region_without_heap_growth_path() {
        assert_eq!(
            collect_segments(region(0x1000..0x5000), Some(0x2000..0x3000)),
            alloc::vec![0x1000..0x2000, 0x3000..0x5000]
        );
    }

    #[test]
    fn non_usable_region_yields_no_segments() {
        assert!(
            collect_segments(
                BootMemoryRegion {
                    start: 0x1000,
                    end: 0x4000,
                    kind: BootMemoryKind::Reserved,
                },
                None,
            )
            .is_empty()
        );
    }

    #[test]
    fn every_reserved_range_is_subtracted() {
        let mut reserved = BootReservedRanges::new();
        reserved.reserve(0x2000..0x3000);
        reserved.reserve(0x6000..0x7000);

        assert_eq!(
            usable_region_segments(region(0x1000..0x9000), &reserved)
                .into_iter()
                .flatten()
                .collect::<Vec<_>>(),
            alloc::vec![0x1000..0x2000, 0x3000..0x6000, 0x7000..0x9000]
        );
    }

    struct TwoNodes;

    impl NumaTopology for TwoNodes {
        type MemoryAffinities<'a> = core::array::IntoIter<MemoryAffinity, 2>;

        fn node_count(&self) -> usize {
            2
        }

        fn processor_count(&self) -> usize {
            2
        }

        fn processor_node(&self, processor: ProcessorId) -> NodeId {
            NodeId::new(usize::from(processor.id()))
        }

        fn distance(&self, from: NodeId, to: NodeId) -> NodeDistance {
            if from == to {
                NodeDistance::LOCAL
            } else {
                NodeDistance::UNIFORM_REMOTE
            }
        }

        fn memory_affinity(&self) -> Self::MemoryAffinities<'_> {
            [
                MemoryAffinity {
                    physical: 0x1000..0x3000,
                    node: NodeId::new(0),
                },
                MemoryAffinity {
                    physical: 0x3000..0x6000,
                    node: NodeId::new(1),
                },
            ]
            .into_iter()
        }
    }

    fn tagged(
        region: BootMemoryRegion,
        reserved: &BootReservedRanges,
    ) -> Vec<(usize, usize, usize)> {
        // SAFETY: the pieces are only inspected, never dereferenced.
        unsafe { usable_node_regions(region, reserved, 0, &TwoNodes) }
            .map(|piece| (piece.start(), piece.end(), piece.node().index()))
            .collect()
    }

    #[test]
    fn a_segment_crossing_a_node_boundary_splits_in_two() {
        assert_eq!(
            tagged(region(0x2000..0x5000), &BootReservedRanges::new()),
            alloc::vec![(0x2000, 0x3000, 0), (0x3000, 0x5000, 1)]
        );
    }

    #[test]
    fn reserved_ranges_are_removed_before_tagging() {
        let mut reserved = BootReservedRanges::new();
        reserved.reserve(0x2800..0x3800);
        assert_eq!(
            tagged(region(0x1000..0x6000), &reserved),
            alloc::vec![(0x1000, 0x2800, 0), (0x3800, 0x6000, 1)]
        );
    }

    #[test]
    #[should_panic(expected = "0x5000..0x7000")]
    fn a_byte_outside_every_affinity_range_panics_naming_the_range() {
        tagged(region(0x5000..0x7000), &BootReservedRanges::new());
    }

    fn collect_segments(
        region: BootMemoryRegion,
        excluded: Option<Range<usize>>,
    ) -> Vec<Range<usize>> {
        let mut reserved = BootReservedRanges::new();
        if let Some(excluded) = excluded {
            reserved.reserve(excluded);
        }
        usable_region_segments(region, &reserved)
            .into_iter()
            .flatten()
            .collect()
    }

    fn region(range: Range<usize>) -> BootMemoryRegion {
        BootMemoryRegion {
            start: range.start as u64,
            end: range.end as u64,
            kind: BootMemoryKind::Usable,
        }
    }
}
