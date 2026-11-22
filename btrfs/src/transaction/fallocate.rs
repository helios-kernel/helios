//! `fallocate(2)`: preallocation, hole punching and range zeroing, after
//! Linux's `btrfs_fallocate`, `btrfs_punch_hole`, `btrfs_zero_range` and
//! `__btrfs_prealloc_file_range` (`fs/btrfs/file.c`).
//!
//! Preallocated extents are written as `BTRFS_FILE_EXTENT_PREALLOC` (type `2`)
//! backed by real data allocations in the extent tree with no `EXTENT_CSUM`
//! items, reading back as zeroes until a later write CoWs the written sectors.

use alloc::vec;
use alloc::vec::Vec;
use core::num::NonZeroUsize;
use core::ops::Range;
use zerocopy::{FromZeros, IntoBytes};

use super::Transaction;
use super::file::{FirstExtent, HEAD_BYTES, REGULAR_BYTES, aligned_end};
use super::namespace::{check_flags, time};
use super::reflink::FileId;
use super::reserve::Units;
use crate::allocation::data::DataReference;
use crate::compress::policy::Compressor;
use crate::delalloc::MAX_EXTENT_SIZE;
use crate::items::{ExtentData, FileExtent, INODE_APPEND, INODE_IMMUTABLE, Metadata};
use crate::ondisk::{
    RawFileExtentBody, RawFileExtentHead, RawInodeItem, RawTimespec, item_type, view,
};
use crate::source::BlockSink;
use crate::space::{DATA, SpaceError};
use crate::tree::Cursor;
use crate::tree::write::WriteError;
use crate::{Error, ItemDefect, Key, Timestamp};

/// `BTRFS_FILE_EXTENT_PREALLOC` in `btrfs_tree.h`.
const EXTENT_PREALLOC: u8 = 2;

/// `BTRFS_FEATURE_INCOMPAT_NO_HOLES` in `btrfs_tree.h`.
const INCOMPAT_NO_HOLES: u64 = 1 << 9;

/// The `fallocate(2)` modes Linux's `btrfs_fallocate` (`fs/btrfs/file.c`)
/// implements.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AllocateMode {
    /// Preallocate space and extend `i_size` when `offset + length > i_size`
    /// (`mode == 0`).
    Allocate,
    /// Preallocate space without changing `i_size` (`FALLOC_FL_KEEP_SIZE`).
    KeepSize,
    /// Free whole sectors in the range and zero partial ones without changing
    /// `i_size` (`FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE`).
    PunchHole,
    /// Zero the range, preallocating aligned sectors, and extend `i_size` when
    /// `offset + length > i_size` (`FALLOC_FL_ZERO_RANGE`).
    ZeroRange,
    /// Zero the range, preallocating aligned sectors, without changing
    /// `i_size` (`FALLOC_FL_ZERO_RANGE | FALLOC_FL_KEEP_SIZE`).
    ZeroRangeKeepSize,
}

impl AllocateMode {
    const fn keeps_size(self) -> bool {
        matches!(
            self,
            Self::KeepSize | Self::PunchHole | Self::ZeroRangeKeepSize
        )
    }

    const fn forbidden_flags(self) -> u64 {
        match self {
            Self::Allocate | Self::KeepSize => INODE_IMMUTABLE,
            Self::PunchHole | Self::ZeroRange | Self::ZeroRangeKeepSize => {
                INODE_IMMUTABLE | INODE_APPEND
            }
        }
    }
}

/// What backs one sector-aligned block of a non-inline file.
#[derive(Clone, Copy, PartialEq, Eq)]
enum SectorBacking {
    Dirty,
    Regular,
    Prealloc,
    Hole,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SpanKind {
    Hole,
    Regular,
    Prealloc,
}

struct ExtentSpan {
    range: Range<u64>,
    kind: SpanKind,
}

/// Encodes a `BTRFS_FILE_EXTENT_PREALLOC` item spanning `[0, length)` of its
/// physical extent at `address`.
fn prealloc(generation: u64, address: u64, disk_length: u64, length: u64) -> [u8; REGULAR_BYTES] {
    let mut head = RawFileExtentHead::new_zeroed();
    head.generation.set(generation);
    head.ram_bytes.set(length);
    head.extent_type = EXTENT_PREALLOC;
    let mut body = RawFileExtentBody::new_zeroed();
    body.disk_bytenr.set(address);
    body.disk_num_bytes.set(disk_length);
    body.num_bytes.set(length);
    let mut bytes = [0; REGULAR_BYTES];
    bytes[..HEAD_BYTES].copy_from_slice(head.as_bytes());
    bytes[HEAD_BYTES..].copy_from_slice(body.as_bytes());
    bytes
}

/// Returns the maximal subranges of `range` not covered by any interval in
/// `occupied`.
fn uncovered_gaps(range: Range<u64>, mut occupied: Vec<Range<u64>>) -> Vec<Range<u64>> {
    if range.start >= range.end {
        return Vec::new();
    }
    occupied.sort_unstable_by_key(|span| span.start);
    let mut gaps = Vec::new();
    let mut position = range.start;
    for span in occupied {
        let start = span.start.max(range.start);
        let end = span.end.min(range.end);
        if start >= end {
            continue;
        }
        if start > position {
            gaps.push(position..start);
        }
        position = position.max(end);
        if position >= range.end {
            break;
        }
    }
    if position < range.end {
        gaps.push(position..range.end);
    }
    gaps
}

/// Coalesces sorted non-overlapping ranges that touch end-to-end.
fn coalesce_ranges(ranges: impl IntoIterator<Item = Range<u64>>) -> Vec<Range<u64>> {
    let mut merged: Vec<Range<u64>> = Vec::new();
    for span in ranges {
        if span.start >= span.end {
            continue;
        }
        if let Some(last) = merged.last_mut()
            && last.end >= span.start
        {
            last.end = last.end.max(span.end);
        } else {
            merged.push(span);
        }
    }
    merged
}

impl<S: BlockSink> Transaction<S> {
    /// Validates `fallocate` arguments and inode permissions before reserving
    /// space or modifying any tree.
    async fn validate_fallocate(
        &self,
        file: FileId,
        offset: u64,
        length: u64,
        mode: AllocateMode,
    ) -> Result<(RawInodeItem, Metadata, u64, u64), WriteError> {
        if length == 0 {
            return Err(WriteError::FallocateRange);
        }
        let end = offset.checked_add(length).ok_or(WriteError::FileOverflow)?;
        let sector = u64::from(self.volume.superblock().sectorsize());
        let _ = aligned_end(end, sector)?;
        let (raw, metadata) = self.file_inode(file.tree, file.inode).await?;
        check_flags(
            file.tree,
            file.inode,
            metadata.flags,
            mode.forbidden_flags(),
        )?;
        let _ = self.roots.get(file.tree)?;
        Ok((raw, metadata, end, sector))
    }

    /// Data bytes `fallocate` needs to reserve before mutating the file.
    pub(crate) async fn fallocate_reservation(
        &self,
        file: FileId,
        offset: u64,
        length: u64,
        mode: AllocateMode,
        max_inline: u64,
    ) -> Result<u64, WriteError> {
        let (_, metadata, end, sector) =
            self.validate_fallocate(file, offset, length, mode).await?;
        let FileId { tree, inode } = file;
        let first = self.first_extent(tree, inode).await?;
        let alloc_start = offset - offset % sector;
        let alloc_end = aligned_end(end, sector)?;
        match mode {
            AllocateMode::Allocate | AllocateMode::KeepSize => {
                if matches!(first, FirstExtent::Inline(..)) {
                    let extra = if alloc_start == 0 { 0 } else { sector };
                    return Ok((alloc_end - alloc_start).saturating_add(extra));
                }
                let mut bytes = 0_u64;
                if !mode.keeps_size()
                    && end > metadata.size
                    && !metadata.size.is_multiple_of(sector)
                {
                    let tail_sec = metadata.size - metadata.size % sector;
                    if self.sector_backing(tree, inode, tail_sec).await? == SectorBacking::Regular {
                        bytes = bytes.saturating_add(sector);
                    }
                }
                let gaps = self
                    .unallocated_gaps(tree, inode, alloc_start..alloc_end)
                    .await?;
                for gap in gaps {
                    bytes = bytes.saturating_add(gap.end - gap.start);
                }
                Ok(bytes)
            }
            AllocateMode::PunchHole => {
                if let FirstExtent::Inline(inline_bytes, _) = first {
                    if offset >= inline_bytes || (offset == 0 && end >= sector) {
                        return Ok(0);
                    }
                    if self.may_inline(metadata.size, metadata.size, max_inline) {
                        return Ok(0);
                    }
                    return Ok(sector);
                }
                let punch_start = aligned_end(offset, sector)?;
                let punch_end = end - end % sector;
                let mut bytes = 0_u64;
                if punch_start > punch_end {
                    if self.sector_backing(tree, inode, alloc_start).await?
                        == SectorBacking::Regular
                    {
                        bytes += sector;
                    }
                } else {
                    if offset < punch_start
                        && self.sector_backing(tree, inode, alloc_start).await?
                            == SectorBacking::Regular
                    {
                        bytes += sector;
                    }
                    if punch_end < end
                        && self.sector_backing(tree, inode, punch_end).await?
                            == SectorBacking::Regular
                    {
                        bytes += sector;
                    }
                }
                Ok(bytes)
            }
            AllocateMode::ZeroRange | AllocateMode::ZeroRangeKeepSize => {
                if matches!(first, FirstExtent::Inline(..)) {
                    let extra = if alloc_start == 0 { 0 } else { sector };
                    return Ok((alloc_end - alloc_start).saturating_add(extra));
                }
                let zero_start = aligned_end(offset, sector)?;
                let zero_end = end - end % sector;
                let mut bytes = 0_u64;
                if !mode.keeps_size()
                    && end > metadata.size
                    && !metadata.size.is_multiple_of(sector)
                {
                    let tail_sec = metadata.size - metadata.size % sector;
                    if tail_sec < alloc_start
                        && self.sector_backing(tree, inode, tail_sec).await?
                            == SectorBacking::Regular
                    {
                        bytes = bytes.saturating_add(sector);
                    }
                }
                if zero_start > zero_end {
                    if matches!(
                        self.sector_backing(tree, inode, alloc_start).await?,
                        SectorBacking::Regular | SectorBacking::Hole
                    ) {
                        bytes = bytes.saturating_add(sector);
                    }
                } else {
                    if offset < zero_start
                        && matches!(
                            self.sector_backing(tree, inode, alloc_start).await?,
                            SectorBacking::Regular | SectorBacking::Hole
                        )
                    {
                        bytes = bytes.saturating_add(sector);
                    }
                    if zero_end < end
                        && matches!(
                            self.sector_backing(tree, inode, zero_end).await?,
                            SectorBacking::Regular | SectorBacking::Hole
                        )
                    {
                        bytes = bytes.saturating_add(sector);
                    }
                    if zero_start < zero_end {
                        let spans = self.scan_extents(tree, inode, zero_start..zero_end).await?;
                        let kept_prealloc: u64 = spans
                            .iter()
                            .filter(|span| span.kind == SpanKind::Prealloc)
                            .map(|span| span.range.end - span.range.start)
                            .sum();
                        let dropped_delalloc = self
                            .delalloc
                            .file(tree, inode)
                            .map_or(0, |dirty| dirty.bytes_in(zero_start..zero_end));
                        bytes = bytes.saturating_add(
                            (zero_end - zero_start - kept_prealloc)
                                .saturating_sub(dropped_delalloc),
                        );
                    }
                }
                Ok(bytes)
            }
        }
    }

    /// Metadata units `fallocate` needs for `mode` given its data
    /// `reservation`.
    pub(crate) fn fallocate_units(&self, mode: AllocateMode, reservation: u64) -> Units {
        match mode {
            AllocateMode::PunchHole if reservation == 0 => Units {
                insert: 4,
                update: 1,
                frees: true,
            },
            AllocateMode::PunchHole => Units {
                insert: 8,
                update: 1,
                frees: false,
            },
            AllocateMode::Allocate
            | AllocateMode::KeepSize
            | AllocateMode::ZeroRange
            | AllocateMode::ZeroRangeKeepSize => {
                let extents = reservation.div_ceil(MAX_EXTENT_SIZE);
                Units {
                    insert: extents.saturating_mul(2).saturating_add(6),
                    update: 2,
                    frees: false,
                }
            }
        }
    }

    /// Executes `fallocate(2)` in `mode` on `[offset, offset + length)`.
    #[expect(
        clippy::too_many_arguments,
        reason = "mirrors write_file/clone_range transaction entry points"
    )]
    pub(crate) async fn fallocate(
        &mut self,
        file: FileId,
        offset: u64,
        length: u64,
        mode: AllocateMode,
        when: Timestamp,
        compressor: &mut Compressor,
        concurrency: NonZeroUsize,
        max_inline: u64,
    ) -> Result<(), WriteError> {
        let (raw, metadata, end, sector) =
            self.validate_fallocate(file, offset, length, mode).await?;
        let when = time(file.tree, file.inode, when)?;
        match mode {
            AllocateMode::Allocate | AllocateMode::KeepSize => {
                self.preallocate(
                    file,
                    offset,
                    end,
                    sector,
                    mode.keeps_size(),
                    raw,
                    metadata,
                    when,
                    compressor,
                    concurrency,
                )
                .await
            }
            AllocateMode::PunchHole => {
                self.punch_hole(
                    file, offset, end, sector, raw, metadata, when, compressor, max_inline,
                )
                .await
            }
            AllocateMode::ZeroRange | AllocateMode::ZeroRangeKeepSize => {
                self.zero_range(
                    file,
                    offset,
                    end,
                    sector,
                    mode.keeps_size(),
                    raw,
                    metadata,
                    when,
                )
                .await
            }
        }
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "internal helper carrying validated preallocation state"
    )]
    async fn preallocate(
        &mut self,
        file: FileId,
        offset: u64,
        end: u64,
        sector: u64,
        keep_size: bool,
        mut raw: RawInodeItem,
        metadata: Metadata,
        when: RawTimespec,
        compressor: &mut Compressor,
        concurrency: NonZeroUsize,
    ) -> Result<(), WriteError> {
        let FileId { tree, inode } = file;
        let alloc_start = offset - offset % sector;
        let alloc_end = aligned_end(end, sector)?;
        let first = self.first_extent(tree, inode).await?;
        let promoted_inline = if let FirstExtent::Inline(inline_bytes, _) = first {
            self.promote_inline(tree, inode, inline_bytes, 0..0, &mut raw)
                .await?;
            // Persist the nbytes drop from removing the inline item before
            // writeback reloads the inode item from the tree.
            self.put_inode(tree, inode, raw).await?;
            true
        } else {
            if !keep_size && end > metadata.size && !metadata.size.is_multiple_of(sector) {
                self.zero_tail(tree, inode, metadata.size, &raw).await?;
            }
            false
        };
        let wb_start = if promoted_inline { 0 } else { alloc_start };
        self.writeback_range(tree, inode, wb_start..alloc_end, compressor, concurrency)
            .await?;
        let (mut raw, _) = self.file_inode(tree, inode).await?;
        self.fill_gap_before(tree, inode, alloc_start).await?;
        self.allocate_prealloc_gaps(tree, inode, alloc_start..alloc_end, &mut raw)
            .await?;
        if !keep_size && end > raw.size.get() {
            raw.size.set(end);
            self.store_file_inode(tree, inode, raw, when).await
        } else {
            self.store_inode_ctime(tree, inode, raw, when).await
        }
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "internal helper carrying validated hole-punch state"
    )]
    async fn punch_hole(
        &mut self,
        file: FileId,
        offset: u64,
        end: u64,
        sector: u64,
        mut raw: RawInodeItem,
        metadata: Metadata,
        when: RawTimespec,
        compressor: &mut Compressor,
        max_inline: u64,
    ) -> Result<(), WriteError> {
        let FileId { tree, inode } = file;
        let no_holes = self.volume.superblock().incompat_flags() & INCOMPAT_NO_HOLES != 0;
        if let FirstExtent::Inline(inline_bytes, _) = self.first_extent(tree, inode).await? {
            if offset < inline_bytes {
                if offset == 0 && end >= sector {
                    self.remove_first_item(tree, inode, inline_bytes, &mut raw)
                        .await?;
                    if !no_holes && metadata.size > 0 {
                        self.fill_holes(tree, inode, 0..sector).await?;
                    }
                } else {
                    let mut content = vec![0; metadata.size as usize];
                    self.read_file(tree, inode, 0, &mut content).await?;
                    let zero_end = end.min(metadata.size) as usize;
                    content[offset as usize..zero_end].fill(0);
                    self.store_first_sector(
                        file,
                        content,
                        Some(inline_bytes),
                        &mut raw,
                        compressor,
                        max_inline,
                    )
                    .await?;
                }
            }
            return self.store_file_inode(tree, inode, raw, when).await;
        }

        let head_sector = offset - offset % sector;
        let punch_start = aligned_end(offset, sector)?;
        let punch_end = end - end % sector;
        let flags = raw.flags.get();

        if punch_start > punch_end {
            self.zero_partial_sector(tree, inode, flags, head_sector, offset..end)
                .await?;
        } else {
            if offset < punch_start {
                self.zero_partial_sector(tree, inode, flags, head_sector, offset..punch_start)
                    .await?;
            }
            if punch_start < punch_end {
                self.delalloc
                    .remove_range(tree, inode, punch_start..punch_end);
                let removed = self
                    .remove_regular_range(tree, inode, punch_start..punch_end)
                    .await?;
                raw.nbytes.set(
                    raw.nbytes
                        .get()
                        .checked_sub(removed)
                        .ok_or(WriteError::FileOverflow)?,
                );
                if !no_holes {
                    let root = self.roots.get(tree)?;
                    let has_later = self
                        .trees
                        .ceiling(
                            &self.volume,
                            root,
                            Key::new(inode, item_type::EXTENT_DATA, punch_end),
                        )
                        .await?
                        .is_some_and(|(key, _)| key.is(inode, item_type::EXTENT_DATA));
                    let fill_end = if has_later {
                        punch_end
                    } else {
                        punch_end.min(aligned_end(metadata.size, sector)?)
                    };
                    if punch_start < fill_end {
                        self.fill_holes(tree, inode, punch_start..fill_end).await?;
                    }
                }
            }
            if punch_end < end {
                self.zero_partial_sector(tree, inode, flags, punch_end, punch_end..end)
                    .await?;
            }
        }
        self.store_file_inode(tree, inode, raw, when).await
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "internal helper carrying validated zero-range state"
    )]
    async fn zero_range(
        &mut self,
        file: FileId,
        offset: u64,
        end: u64,
        sector: u64,
        keep_size: bool,
        mut raw: RawInodeItem,
        metadata: Metadata,
        when: RawTimespec,
    ) -> Result<(), WriteError> {
        let FileId { tree, inode } = file;
        let alloc_start = offset - offset % sector;
        let alloc_end = aligned_end(end, sector)?;
        let zero_start = aligned_end(offset, sector)?;
        let zero_end = end - end % sector;

        if let FirstExtent::Inline(inline_bytes, _) = self.first_extent(tree, inode).await? {
            if offset == 0 && end >= sector {
                self.remove_first_item(tree, inode, inline_bytes, &mut raw)
                    .await?;
            } else {
                self.promote_inline(tree, inode, inline_bytes, 0..0, &mut raw)
                    .await?;
            }
        } else if !keep_size && end > metadata.size && !metadata.size.is_multiple_of(sector) {
            self.zero_tail(tree, inode, metadata.size, &raw).await?;
        }

        let flags = raw.flags.get();
        if zero_start > zero_end {
            self.zero_partial_sector(tree, inode, flags, alloc_start, offset..end)
                .await?;
        } else {
            if offset < zero_start {
                self.zero_partial_sector(tree, inode, flags, alloc_start, offset..zero_start)
                    .await?;
            }
            if zero_end < end {
                self.zero_partial_sector(tree, inode, flags, zero_end, zero_end..end)
                    .await?;
            }
            if zero_start < zero_end {
                self.delalloc
                    .remove_range(tree, inode, zero_start..zero_end);
                let removed = self
                    .drop_non_prealloc_range(tree, inode, zero_start..zero_end)
                    .await?;
                raw.nbytes.set(
                    raw.nbytes
                        .get()
                        .checked_sub(removed)
                        .ok_or(WriteError::FileOverflow)?,
                );
            }
        }

        self.fill_gap_before(tree, inode, alloc_start).await?;
        self.allocate_prealloc_gaps(tree, inode, alloc_start..alloc_end, &mut raw)
            .await?;

        if !keep_size && end > raw.size.get() {
            raw.size.set(end);
        }
        self.store_file_inode(tree, inode, raw, when).await
    }

    /// What backs the single sector starting at `sec`.
    async fn sector_backing(
        &self,
        tree: u64,
        inode: u64,
        sec: u64,
    ) -> Result<SectorBacking, WriteError> {
        if self.delalloc.is_dirty(tree, inode, sec) {
            return Ok(SectorBacking::Dirty);
        }
        let sector = u64::from(self.volume.superblock().sectorsize());
        let root = self.roots.get(tree)?;
        let Some((key, bytes)) = self
            .trees
            .floor(
                &self.volume,
                root,
                Key::new(inode, item_type::EXTENT_DATA, sec),
            )
            .await?
            .filter(|(key, _)| key.is(inode, item_type::EXTENT_DATA))
        else {
            return Ok(SectorBacking::Hole);
        };
        let extent = FileExtent::parse(key, &bytes, sector as u32)
            .map_err(|defect| Error::Item { tree, key, defect })?;
        if extent.end <= sec {
            return Ok(SectorBacking::Hole);
        }
        match extent.data {
            ExtentData::Regular { .. } => Ok(SectorBacking::Regular),
            ExtentData::Zero => {
                let head = view::<RawFileExtentHead>(&bytes).expect("validated extent head");
                let body =
                    view::<RawFileExtentBody>(&bytes[HEAD_BYTES..]).expect("validated extent body");
                if head.extent_type == EXTENT_PREALLOC && body.disk_bytenr.get() != 0 {
                    Ok(SectorBacking::Prealloc)
                } else {
                    Ok(SectorBacking::Hole)
                }
            }
            ExtentData::Inline { .. } => Err(WriteError::NotRegularExtent { key }),
        }
    }

    /// Zeroes `range` inside the single sector `sec..sec + sector` when that
    /// sector holds dirty or regular data. Holes and preallocated sectors
    /// already read as zeroes and are left alone.
    async fn zero_partial_sector(
        &mut self,
        tree: u64,
        inode: u64,
        flags: u64,
        sec: u64,
        range: Range<u64>,
    ) -> Result<(), WriteError> {
        let sector = u64::from(self.volume.superblock().sectorsize());
        debug_assert!(sec.is_multiple_of(sector));
        debug_assert!(sec <= range.start && range.start < range.end && range.end <= sec + sector);
        if !matches!(
            self.sector_backing(tree, inode, sec).await?,
            SectorBacking::Dirty | SectorBacking::Regular
        ) {
            return Ok(());
        }
        let mut page = vec![0; sector as usize];
        self.read_file(tree, inode, sec, &mut page).await?;
        let from = (range.start - sec) as usize;
        let to = (range.end - sec) as usize;
        page[from..to].fill(0);
        self.dirty_exact(tree, inode, flags, sec, &page).await
    }

    /// Scans every non-inline `EXTENT_DATA` item overlapping `range`, clipped
    /// to `range`, in file-offset order.
    async fn scan_extents(
        &self,
        tree: u64,
        inode: u64,
        range: Range<u64>,
    ) -> Result<Vec<ExtentSpan>, WriteError> {
        if range.start >= range.end {
            return Ok(Vec::new());
        }
        let sector = self.volume.superblock().sectorsize();
        let root = self.roots.get(tree)?;
        let nodes = self.trees.reader(&self.volume);
        let first = Key::new(inode, item_type::EXTENT_DATA, 0);
        let mut cursor = Cursor::floor(
            &nodes,
            root,
            Key::new(inode, item_type::EXTENT_DATA, range.start),
        )
        .await?;
        let mut spans = Vec::new();
        let mut previous_end = 0;
        while let (Some(key), Some(bytes)) = (cursor.key(), cursor.item()) {
            if key < first {
                cursor.advance(&nodes).await?;
                continue;
            }
            if !key.is(inode, item_type::EXTENT_DATA) || key.offset >= range.end {
                break;
            }
            let extent = FileExtent::parse(key, bytes, sector).map_err(|defect| Error::Item {
                tree,
                key,
                defect,
            })?;
            if extent.start < previous_end {
                return Err(Error::Item {
                    tree,
                    key,
                    defect: ItemDefect::ExtentOverlap(previous_end),
                }
                .into());
            }
            previous_end = extent.end;
            if extent.end > range.start {
                let kind = match extent.data {
                    ExtentData::Inline { .. } => return Err(WriteError::NotRegularExtent { key }),
                    ExtentData::Regular { .. } => SpanKind::Regular,
                    ExtentData::Zero => {
                        let head = view::<RawFileExtentHead>(bytes).expect("validated extent head");
                        let body = view::<RawFileExtentBody>(&bytes[HEAD_BYTES..])
                            .expect("validated extent body");
                        if head.extent_type == EXTENT_PREALLOC && body.disk_bytenr.get() != 0 {
                            SpanKind::Prealloc
                        } else {
                            SpanKind::Hole
                        }
                    }
                };
                spans.push(ExtentSpan {
                    range: extent.start.max(range.start)..extent.end.min(range.end),
                    kind,
                });
            }
            cursor.advance(&nodes).await?;
        }
        Ok(spans)
    }

    /// Maximal subranges of `range` that have neither an allocated extent
    /// (regular or preallocated) nor dirty delalloc pages.
    async fn unallocated_gaps(
        &self,
        tree: u64,
        inode: u64,
        range: Range<u64>,
    ) -> Result<Vec<Range<u64>>, WriteError> {
        let spans = self.scan_extents(tree, inode, range.clone()).await?;
        let mut occupied: Vec<Range<u64>> = spans
            .into_iter()
            .filter(|span| span.kind != SpanKind::Hole)
            .map(|span| span.range)
            .collect();
        if let Some(dirty) = self.delalloc.file(tree, inode) {
            occupied.extend(dirty.runs(range.clone()));
        }
        Ok(uncovered_gaps(range, occupied))
    }

    /// Removes regular extents and explicit holes in `range`, leaving any
    /// existing `PREALLOC` extents intact. Returns logical allocated bytes
    /// removed for `inode.nbytes`.
    async fn drop_non_prealloc_range(
        &mut self,
        tree: u64,
        inode: u64,
        range: Range<u64>,
    ) -> Result<u64, WriteError> {
        let spans = self.scan_extents(tree, inode, range).await?;
        let to_drop = coalesce_ranges(
            spans
                .into_iter()
                .filter(|span| span.kind != SpanKind::Prealloc)
                .map(|span| span.range),
        );
        let mut removed = 0_u64;
        for drop_range in to_drop {
            removed = removed
                .checked_add(self.remove_regular_range(tree, inode, drop_range).await?)
                .ok_or(WriteError::FileOverflow)?;
        }
        Ok(removed)
    }

    /// Allocates `BTRFS_FILE_EXTENT_PREALLOC` extents for every unallocated
    /// gap in `range`, removing any explicit hole items in those gaps first.
    async fn allocate_prealloc_gaps(
        &mut self,
        tree: u64,
        inode: u64,
        range: Range<u64>,
        raw: &mut RawInodeItem,
    ) -> Result<(), WriteError> {
        let gaps = self.unallocated_gaps(tree, inode, range).await?;
        if gaps.is_empty() {
            return Ok(());
        }
        let sector = u64::from(self.volume.superblock().sectorsize());
        let total_gap: u64 = gaps.iter().map(|gap| gap.end - gap.start).sum();
        if total_gap > self.data_budget() {
            return Err(SpaceError::Exhausted {
                bytes: total_gap,
                flags: DATA,
            }
            .into());
        }
        self.check_quota_limit(tree, total_gap)?;
        for gap in gaps {
            // Clear any explicit hole items spanning this gap (slicing any
            // explicit hole that extends past the gap boundaries).
            let removed = self.remove_regular_range(tree, inode, gap.clone()).await?;
            debug_assert_eq!(removed, 0, "unallocated gaps contain only holes");
            let mut position = gap.start;
            while position < gap.end {
                if !self.reserves(Units::items(2)) {
                    self.force_metadata_chunk().await?;
                }
                let available = self.data_budget();
                if available < sector {
                    return Err(SpaceError::Exhausted {
                        bytes: gap.end - position,
                        flags: DATA,
                    }
                    .into());
                }
                let want = (gap.end - position).min(MAX_EXTENT_SIZE).min(available);
                let length = self.extent_length(want).await?;
                let allocation = self
                    .accounting
                    .allocate_data(
                        &self.volume,
                        &mut self.trees,
                        &mut self.space,
                        length,
                        DataReference {
                            root: tree,
                            inode,
                            offset: position,
                        },
                    )
                    .await?;
                let root = self.roots.get(tree)?;
                let root = self
                    .trees
                    .apply(
                        &self.volume,
                        root,
                        Key::new(inode, item_type::EXTENT_DATA, position),
                        Some(&prealloc(
                            self.trees.generation(),
                            allocation.objectid,
                            allocation.offset,
                            length,
                        )),
                        &mut self.space,
                    )
                    .await?;
                self.roots.set(root)?;
                raw.nbytes.set(
                    raw.nbytes
                        .get()
                        .checked_add(length)
                        .ok_or(WriteError::FileOverflow)?,
                );
                position += length;
            }
        }
        Ok(())
    }

    /// On filesystems without `NO_HOLES`, `btrfs check` flags any unmapped gap
    /// preceding an `EXTENT_DATA` item (`I_ERR_FILE_EXTENT_DISCOUNT`). Fill
    /// any gap immediately before `target`.
    async fn fill_gap_before(
        &mut self,
        tree: u64,
        inode: u64,
        target: u64,
    ) -> Result<(), WriteError> {
        if target == 0 || self.volume.superblock().incompat_flags() & INCOMPAT_NO_HOLES != 0 {
            return Ok(());
        }
        let sector = u64::from(self.volume.superblock().sectorsize());
        let root = self.roots.get(tree)?;
        let prev_end = match self
            .trees
            .floor(
                &self.volume,
                root,
                Key::new(inode, item_type::EXTENT_DATA, target),
            )
            .await?
            .filter(|(key, _)| key.is(inode, item_type::EXTENT_DATA))
        {
            Some((key, bytes)) => {
                FileExtent::parse(key, &bytes, sector as u32)
                    .map_err(|defect| Error::Item { tree, key, defect })?
                    .end
            }
            None => 0,
        };
        if prev_end < target {
            self.fill_holes(tree, inode, prev_end..target).await?;
        }
        Ok(())
    }

    async fn store_inode_ctime(
        &mut self,
        tree: u64,
        inode: u64,
        mut raw: RawInodeItem,
        when: RawTimespec,
    ) -> Result<(), WriteError> {
        raw.transid.set(self.trees.generation());
        raw.sequence.set(raw.sequence.get().wrapping_add(1));
        raw.ctime = when;
        self.put_inode(tree, inode, raw).await
    }
}
