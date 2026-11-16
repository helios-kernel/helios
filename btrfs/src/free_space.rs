//! Free-space-tree records. Logical free space includes superblock stripes;
//! allocation policy excludes those stripes separately from this disk format.

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;
use core::ops::Range;

use rpds::RedBlackTreeMapSync;
use thiserror::Error;
use zerocopy::little_endian::U32;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::Key;
use crate::ondisk::{RawItem, item_type, view};
use crate::source::BlockSource;
use crate::space::Space;
use crate::tree::write::{Trees, WriteError};
use crate::tree::{Cursor, TreeRoot};
use crate::volume::Volume;

// New bitmap payload size in Linux's free-space-tree.h. Existing images may
// have other sizes; their key length and payload determine the represented bits.
const BITMAP_BYTES: u64 = 256;
const BITS_PER_BITMAP: u64 = BITMAP_BYTES * 8;
// Linux's extent/bitmap hysteresis prevents repeated representation changes.
const BITMAP_HYSTERESIS: u64 = 100;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum FreeSpaceDefect {
    #[error("free-space records disagree with allocated extents")]
    AllocationMismatch,
    #[error("invalid free-space info key, size, or flags")]
    Info,
    #[error(
        "free-space range {start}..{end} is empty, unaligned, overflowing, or out of its group"
    )]
    Range { start: u64, end: u64 },
    #[error("overlapping free-space records")]
    Overlap,
    #[error("free-space item type does not match the group's representation")]
    Representation,
    #[error("free-space extent has a payload")]
    ExtentPayload,
    #[error("bitmap payload length or padding does not match its key")]
    BitmapPayload,
    #[error("bitmaps do not cover the whole block group in order")]
    BitmapCoverage,
    #[error("free-space info reports {declared} extents but records contain {found}")]
    Count { declared: u32, found: usize },
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Intervals(RedBlackTreeMapSync<u64, u64>);

impl Intervals {
    pub(crate) fn whole(range: Range<u64>) -> Self {
        Self([(range.start, range.end)].into_iter().collect())
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = Range<u64>> + '_ {
        self.0.iter().map(|(&start, &end)| start..end)
    }

    /// Removes only wholly free ranges; an overlapping allocation is an error.
    pub(crate) fn occupy(&mut self, range: Range<u64>) -> bool {
        let Some((&start, &end)) = self.0.range(..=range.start).next_back() else {
            return false;
        };
        if range.start >= range.end || range.end > end {
            return false;
        }
        self.0.remove_mut(&start);
        if start < range.start {
            self.0.insert_mut(start, range.start);
        }
        if range.end < end {
            self.0.insert_mut(range.end, end);
        }
        true
    }

    /// Inserts a disjoint range and coalesces its adjacent neighbours.
    pub(crate) fn release(&mut self, mut range: Range<u64>) -> Result<(), FreeSpaceDefect> {
        if range.start >= range.end {
            return Err(FreeSpaceDefect::Range {
                start: range.start,
                end: range.end,
            });
        }
        let before = self
            .0
            .range(..=range.start)
            .next_back()
            .map(|(&start, &end)| (start, end));
        let after = self
            .0
            .range(range.start..)
            .next()
            .map(|(&start, &end)| (start, end));
        if before.is_some_and(|(_, end)| end > range.start)
            || after.is_some_and(|(start, _)| start < range.end)
        {
            return Err(FreeSpaceDefect::Overlap);
        }
        if let Some((start, end)) = before
            && end == range.start
        {
            self.0.remove_mut(&start);
            range.start = start;
        }
        if let Some((start, end)) = after
            && start == range.end
        {
            self.0.remove_mut(&start);
            range.end = end;
        }
        self.0.insert_mut(range.start, range.end);
        Ok(())
    }
}

#[derive(FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned)]
#[repr(C)]
struct RawInfo {
    extent_count: U32,
    flags: U32,
}

pub(crate) struct FreeGroup {
    pub(crate) range: Range<u64>,
    pub(crate) free: Intervals,
    bitmaps: bool,
}

impl FreeGroup {
    pub(crate) fn new(range: Range<u64>, free: Intervals) -> Self {
        Self {
            range,
            free,
            bitmaps: false,
        }
    }

    pub(crate) fn decode(
        key: Key,
        bytes: &[u8],
        records: &BTreeMap<Key, Vec<u8>>,
        sector: u64,
    ) -> Result<Self, FreeSpaceDefect> {
        let info: &RawInfo = view(bytes).ok_or(FreeSpaceDefect::Info)?;
        if key.item_type != item_type::FREE_SPACE_INFO
            || bytes.len() != size_of::<RawInfo>()
            || info.flags.get() > 1
        {
            return Err(FreeSpaceDefect::Info);
        }
        let end = key
            .objectid
            .checked_add(key.offset)
            .ok_or(FreeSpaceDefect::Range {
                start: key.objectid,
                end: u64::MAX,
            })?;
        let range = key.objectid..end;
        validate_range(&range, &range, sector)?;
        let bitmaps = info.flags.get() == 1;
        let mut free = Intervals::default();
        let mut bitmap_end = range.start;
        for (&item, payload) in
            records.range(Key::new(range.start, 0, 0)..Key::new(range.end, 0, 0))
        {
            if item == key {
                continue;
            }
            let end = item
                .objectid
                .checked_add(item.offset)
                .ok_or(FreeSpaceDefect::Range {
                    start: item.objectid,
                    end: u64::MAX,
                })?;
            let extent = item.objectid..end;
            validate_range(&extent, &range, sector)?;
            if !bitmaps && item.item_type == item_type::FREE_SPACE_EXTENT {
                if !payload.is_empty() {
                    return Err(FreeSpaceDefect::ExtentPayload);
                }
                free.release(extent)?;
            } else if bitmaps && item.item_type == item_type::FREE_SPACE_BITMAP {
                if extent.start != bitmap_end {
                    return Err(FreeSpaceDefect::BitmapCoverage);
                }
                let bits = item.offset / sector;
                if payload.len() as u64 != bits.div_ceil(8)
                    || (!bits.is_multiple_of(8)
                        && payload.last().is_some_and(|byte| byte >> (bits % 8) != 0))
                {
                    return Err(FreeSpaceDefect::BitmapPayload);
                }
                let mut start = None;
                for bit in 0..bits {
                    let address = extent.start + bit * sector;
                    if payload[(bit / 8) as usize] & (1 << (bit % 8)) != 0 {
                        start.get_or_insert(address);
                    } else if let Some(start) = start.take() {
                        free.release(start..address)?;
                    }
                }
                if let Some(start) = start {
                    free.release(start..extent.end)?;
                }
                bitmap_end = extent.end;
            } else {
                return Err(FreeSpaceDefect::Representation);
            }
        }
        if bitmaps && bitmap_end != range.end {
            return Err(FreeSpaceDefect::BitmapCoverage);
        }
        if free.0.size() != info.extent_count.get() as usize {
            return Err(FreeSpaceDefect::Count {
                declared: info.extent_count.get(),
                found: free.0.size(),
            });
        }
        Ok(Self {
            range,
            free,
            bitmaps,
        })
    }

    pub(crate) fn encode(
        &mut self,
        sector: u64,
    ) -> Result<BTreeMap<Key, Vec<u8>>, FreeSpaceDefect> {
        validate_range(&self.range, &self.range, sector)?;
        let bitmap_span = sector * BITS_PER_BITMAP;
        let count = (self.range.end - self.range.start).div_ceil(bitmap_span);
        let high =
            count * (BITMAP_BYTES + size_of::<RawItem>() as u64) / size_of::<RawItem>() as u64;
        let low = high.saturating_sub(BITMAP_HYSTERESIS);
        let extents = self.free.0.size() as u64;
        self.bitmaps = if self.bitmaps {
            extents >= low
        } else {
            extents > high
        };
        let count = u32::try_from(extents).map_err(|_| FreeSpaceDefect::Count {
            declared: u32::MAX,
            found: self.free.0.size(),
        })?;
        let mut records = BTreeMap::new();
        records.insert(
            Key::new(
                self.range.start,
                item_type::FREE_SPACE_INFO,
                self.range.end - self.range.start,
            ),
            RawInfo {
                extent_count: count.into(),
                flags: u32::from(self.bitmaps).into(),
            }
            .as_bytes()
            .to_vec(),
        );
        if self.bitmaps {
            let mut address = self.range.start;
            while address < self.range.end {
                let length = (self.range.end - address).min(bitmap_span);
                records.insert(
                    Key::new(address, item_type::FREE_SPACE_BITMAP, length),
                    vec![0; (length / sector).div_ceil(8) as usize],
                );
                address += length;
            }
        }
        for range in self.free.iter() {
            validate_range(&range, &self.range, sector)?;
            if !self.bitmaps {
                records.insert(
                    Key::new(
                        range.start,
                        item_type::FREE_SPACE_EXTENT,
                        range.end - range.start,
                    ),
                    Vec::new(),
                );
                continue;
            }
            // Each bitmap is at most 256 bytes, regardless of group size.
            let mut address = range.start;
            while address < range.end {
                let base =
                    self.range.start + (address - self.range.start) / bitmap_span * bitmap_span;
                let length = (self.range.end - base).min(bitmap_span);
                let key = Key::new(base, item_type::FREE_SPACE_BITMAP, length);
                let bitmap = records.get_mut(&key).expect("bitmap covers the group");
                let end = range.end.min(base + length);
                set_bitmap_range(
                    bitmap,
                    ((address - base) / sector) as usize..((end - base) / sector) as usize,
                );
                address = end;
            }
        }
        Ok(records)
    }
}

/// Set a nonempty bit range, preserving both boundary bytes outside the range.
fn set_bitmap_range(bytes: &mut [u8], range: Range<usize>) {
    let first = range.start / 8;
    let last = (range.end - 1) / 8;
    let head = u8::MAX << (range.start % 8);
    let tail = u8::MAX >> (7 - (range.end - 1) % 8);
    if first == last {
        bytes[first] |= head & tail;
    } else {
        bytes[first] |= head;
        bytes[first + 1..last].fill(u8::MAX);
        bytes[last] |= tail;
    }
}

fn validate_range(
    range: &Range<u64>,
    group: &Range<u64>,
    sector: u64,
) -> Result<(), FreeSpaceDefect> {
    if sector == 0
        || range.start >= range.end
        || range.start < group.start
        || range.end > group.end
        || !range.start.is_multiple_of(sector)
        || !range.end.is_multiple_of(sector)
    {
        return Err(FreeSpaceDefect::Range {
            start: range.start,
            end: range.end,
        });
    }
    Ok(())
}

/// The transaction's free-space tree and its last encoded record set. Tree edits
/// can allocate more metadata, so the enclosing accounting loop calls `sync`
/// until allocation, usage, and free-space records all stop changing.
#[derive(Clone)]
pub(crate) struct FreeTree {
    pub(crate) root: TreeRoot,
    records: BTreeMap<Key, Vec<u8>>,
    bitmap_modes: BTreeMap<u64, bool>,
}

impl FreeTree {
    pub(crate) async fn load<S: BlockSource>(
        volume: &Volume<S>,
        root: TreeRoot,
        expected: &[FreeGroup],
    ) -> Result<Self, WriteError> {
        let mut records = BTreeMap::new();
        let mut cursor = Cursor::ceiling(volume, root, Key::new(0, 0, 0)).await?;
        while let Some(key) = cursor.key() {
            records.insert(key, cursor.item().expect("cursor key has an item").to_vec());
            cursor.advance(volume).await?;
        }
        let mut bitmap_modes = BTreeMap::new();
        // FREE_SPACE_TREE_VALID: a cleared bit asks the writer to rebuild from
        // allocation metadata. Stale free-space payloads must not guide reuse.
        if volume.superblock().compat_ro_flags() & (1 << 1) != 0 {
            for group in expected {
                let key = Key::new(
                    group.range.start,
                    item_type::FREE_SPACE_INFO,
                    group.range.end - group.range.start,
                );
                let defect = |defect| WriteError::FreeSpace { key, defect };
                let bytes = records
                    .get(&key)
                    .ok_or_else(|| defect(FreeSpaceDefect::Info))?;
                let decoded = FreeGroup::decode(
                    key,
                    bytes,
                    &records,
                    u64::from(volume.superblock().sectorsize()),
                )
                .map_err(defect)?;
                if decoded.free != group.free {
                    return Err(defect(FreeSpaceDefect::AllocationMismatch));
                }
                bitmap_modes.insert(group.range.start, decoded.bitmaps);
            }
            // A record inside a group was validated by that group's decode. One
            // wholly outside every group is the residue of a removed block group:
            // btrfs-progs before commit 3fc9f1ed ("remove block group free
            // space") never deleted it, so every mkfs image of those releases
            // carries one for its temporary 1 MiB chunk. Linux never reads it;
            // `sync` deletes it with the first commit. A record that reaches
            // into a group from outside is corruption.
            for &key in records.keys() {
                let end = key.objectid.checked_add(key.offset);
                let inside = expected
                    .iter()
                    .any(|group| group.range.contains(&key.objectid));
                let reaches = end.is_none_or(|end| {
                    expected
                        .iter()
                        .any(|group| key.objectid < group.range.end && group.range.start < end)
                });
                if !inside && reaches {
                    return Err(WriteError::FreeSpace {
                        key,
                        defect: FreeSpaceDefect::Range {
                            start: key.objectid,
                            end: end.unwrap_or(u64::MAX),
                        },
                    });
                }
            }
        }
        Ok(Self {
            root,
            records,
            bitmap_modes,
        })
    }

    pub(crate) async fn sync<S: BlockSource>(
        &mut self,
        volume: &Volume<S>,
        trees: &mut Trees,
        space: &mut Space,
        retired: &RedBlackTreeMapSync<u64, u64>,
    ) -> Result<bool, WriteError> {
        let mut desired = BTreeMap::new();
        for mut group in space.committed_free(retired)? {
            group.bitmaps = self
                .bitmap_modes
                .get(&group.range.start)
                .copied()
                .unwrap_or(false);
            let key = Key::new(
                group.range.start,
                item_type::FREE_SPACE_INFO,
                group.range.end - group.range.start,
            );
            desired.extend(
                group
                    .encode(u64::from(volume.superblock().sectorsize()))
                    .map_err(|defect| WriteError::FreeSpace { key, defect })?,
            );
            self.bitmap_modes.insert(group.range.start, group.bitmaps);
        }
        if desired == self.records {
            return Ok(false);
        }
        for &key in self.records.keys().filter(|key| !desired.contains_key(key)) {
            self.root = trees.apply(volume, self.root, key, None, space).await?;
        }
        for (&key, bytes) in &desired {
            if self.records.get(&key) != Some(bytes) {
                self.root = trees
                    .apply(volume, self.root, key, Some(bytes), space)
                    .await?;
            }
        }
        self.records = desired;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bitmap_range_updates_preserve_all_boundary_bits() {
        for start in 0..32 {
            for end in start + 1..=32 {
                let mut bytes = [0x55; 4];
                set_bitmap_range(&mut bytes, start..end);
                for bit in 0..32 {
                    assert_eq!(
                        bytes[bit / 8] & (1 << (bit % 8)) != 0,
                        bit % 2 == 0 || (start..end).contains(&bit)
                    );
                }
            }
        }
    }

    #[test]
    fn fragmented_space_converts_to_bitmaps_and_back_with_correct_bits() {
        let sector = 4096;
        let bits = 12 * BITS_PER_BITMAP + 3;
        let range = (1 << 20)..(1 << 20) + bits * sector;
        let mut free = Intervals::default();
        for bit in (0..bits).step_by(2) {
            let start = range.start + bit * sector;
            free.release(start..start + sector).unwrap();
        }
        let mut group = FreeGroup::new(range.clone(), free.clone());
        let records = group.encode(sector).unwrap();
        let key = Key::new(
            range.start,
            item_type::FREE_SPACE_INFO,
            range.end - range.start,
        );
        let info = btrfs_disk::items::FreeSpaceInfo::parse(&records[&key]).unwrap();
        assert_eq!(u64::from(info.extent_count), bits.div_ceil(2));
        assert_eq!(info.flags.bits(), 1);
        for (key, bytes) in &records {
            if key.item_type != item_type::FREE_SPACE_BITMAP {
                continue;
            }
            for bit in 0..key.offset / sector {
                let global = (key.objectid - range.start) / sector + bit;
                assert_eq!(
                    bytes[(bit / 8) as usize] & (1 << (bit % 8)) != 0,
                    global % 2 == 0
                );
            }
            assert!(bytes.len() <= BITMAP_BYTES as usize);
        }
        let decoded = FreeGroup::decode(key, &records[&key], &records, sector).unwrap();
        assert_eq!(decoded.free, free);
        group.free = Intervals::whole(range.clone());
        let records = group.encode(sector).unwrap();
        let info = btrfs_disk::items::FreeSpaceInfo::parse(&records[&key]).unwrap();
        assert_eq!(info.extent_count, 1);
        assert_eq!(info.flags.bits(), 0);
        assert_eq!(records.len(), 2);
        assert_eq!(
            FreeGroup::decode(key, &records[&key], &records, sector)
                .unwrap()
                .free,
            group.free
        );
    }

    #[test]
    fn bitmap_decoder_handles_nondefault_lengths_and_cross_item_runs() {
        let sector = 4096;
        let start = 1 << 20;
        let key = Key::new(start, item_type::FREE_SPACE_INFO, 22 * sector);
        let mut records = BTreeMap::new();
        records.insert(
            key,
            RawInfo {
                extent_count: 1.into(),
                flags: 1.into(),
            }
            .as_bytes()
            .to_vec(),
        );
        // One free interval spans bit 7 through bit 12, crossing two bitmap
        // items whose lengths deliberately differ from the writer's default.
        let first = Key::new(start, item_type::FREE_SPACE_BITMAP, 9 * sector);
        let second = Key::new(
            start + 9 * sector,
            item_type::FREE_SPACE_BITMAP,
            13 * sector,
        );
        records.insert(first, vec![0x80, 0x01]);
        records.insert(second, vec![0x0f, 0]);
        let decoded = FreeGroup::decode(key, &records[&key], &records, sector).unwrap();
        assert_eq!(
            decoded.free.iter().collect::<Vec<_>>(),
            vec![start + 7 * sector..start + 13 * sector]
        );
        records.get_mut(&second).unwrap()[1] = 0x80;
        assert!(matches!(
            FreeGroup::decode(key, &records[&key], &records, sector),
            Err(FreeSpaceDefect::BitmapPayload)
        ));
        records.insert(second, vec![0x0f, 0]);
        records.remove(&first);
        assert!(matches!(
            FreeGroup::decode(key, &records[&key], &records, sector),
            Err(FreeSpaceDefect::BitmapCoverage)
        ));
    }
}
