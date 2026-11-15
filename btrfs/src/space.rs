//! Transaction-owned space reservations derived from allocation metadata.
//! Mount walks immutable trees. A transaction then owns its free-range map
//! exclusively; it never holds a lock across I/O and never returns retired
//! committed extents to this map before publication/read-side retirement.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::ops::Range;

use thiserror::Error;

use crate::fs::find_root;
use crate::ondisk::{item_type, objectid};
use crate::source::BlockSource;
use crate::tree::write::{MetadataAllocator, WriteError};
use crate::tree::{Cursor, TreeRoot};
use crate::volume::Volume;
use crate::{Error, Key};

// BTRFS_BLOCK_GROUP_{DATA,SYSTEM,METADATA}, from btrfs_tree.h.
const DATA: u64 = 1;
const SYSTEM: u64 = 2;
const METADATA: u64 = 4;
// BTRFS_FEATURE_COMPAT_RO_BLOCK_GROUP_TREE, from btrfs.h.
const BLOCK_GROUP_TREE: u64 = 1 << 3;

#[derive(Debug, Error)]
pub(crate) enum SpaceError {
    #[error(transparent)]
    Read(#[from] Error),
    #[error("allocation tree {tree}, item {key}: {defect}")]
    Corrupt {
        tree: u64,
        key: Key,
        defect: SpaceDefect,
    },
    #[error("no free block-group range can hold {bytes} bytes with flags {flags:#x}")]
    Exhausted { bytes: u64, flags: u64 },
}

#[derive(Debug, Error)]
pub(crate) enum SpaceDefect {
    #[error("truncated allocation record")]
    Truncated,
    #[error("unaligned, empty, or overflowing extent range")]
    Range,
    #[error("block group does not match its chunk")]
    ChunkMismatch,
    #[error("allocated extent is outside a block group or overlaps another extent")]
    ExtentOverlap,
    #[error("extent has no references or inconsistent flags")]
    ExtentHeader,
    #[error(
        "block group reports {declared} allocated bytes but the extent tree accounts for {found}"
    )]
    UsedBytes { declared: u64, found: u64 },
}

struct Group {
    start: u64,
    length: u64,
    flags: u64,
    declared_used: u64,
    found_used: u64,
    free: BTreeMap<u64, u64>,
}

impl Group {
    fn contains(&self, range: &Range<u64>) -> bool {
        self.start <= range.start && range.end <= self.start + self.length
    }

    /// Removes an allocated range only when it was wholly free. Overlapping
    /// allocation records are corruption, not ranges that can be silently merged.
    fn occupy(&mut self, range: Range<u64>) -> bool {
        let Some((&start, &end)) = self.free.range(..=range.start).next_back() else {
            return false;
        };
        if range.end > end {
            return false;
        }
        self.free.remove(&start);
        if start < range.start {
            self.free.insert(start, range.start);
        }
        if range.end < end {
            self.free.insert(range.end, end);
        }
        true
    }

    fn release(&mut self, mut range: Range<u64>) {
        if let Some((&start, &end)) = self.free.range(..range.start).next_back()
            && end == range.start
        {
            self.free.remove(&start);
            range.start = start;
        }
        if let Some(end) = self.free.remove(&range.end) {
            range.end = end;
        }
        self.free.insert(range.start, range.end);
    }

    /// A reserved mirror stripe may already contain an extent-tree reservation.
    /// Remove only its intersections with the remaining free intervals.
    fn exclude(&mut self, range: &Range<u64>) {
        let overlaps: Vec<_> = self
            .free
            .range(..range.end)
            .filter(|(_, end)| **end > range.start)
            .map(|(&start, &end)| start.max(range.start)..end.min(range.end))
            .collect();
        for overlap in overlaps {
            assert!(self.occupy(overlap));
        }
    }
}

/// The extent item/back-reference changes the transaction must publish for a
/// newly reserved metadata block. No record is written by the allocator alone.
#[derive(Clone, Copy, Debug)]
pub(crate) struct MetadataReservation {
    pub(crate) tree: u64,
    pub(crate) level: u8,
    pub(crate) first: Key,
}

pub(crate) struct Space {
    groups: Vec<Group>,
    nodesize: u64,
    sector: u64,
    metadata: BTreeMap<u64, MetadataReservation>,
}

impl Space {
    pub(crate) async fn load<S: BlockSource>(
        volume: &Volume<S>,
        roots: TreeRoot,
    ) -> Result<Self, SpaceError> {
        let sb = volume.superblock();
        let extent_root = find_root(volume, roots, objectid::EXTENT_TREE).await?.root;
        let group_root = if sb.compat_ro_flags() & BLOCK_GROUP_TREE != 0 {
            find_root(volume, roots, objectid::BLOCK_GROUP_TREE)
                .await?
                .root
        } else {
            extent_root
        };
        let mut groups = Vec::new();
        let mut cursor = Cursor::ceiling(volume, group_root, Key::new(0, 0, 0)).await?;
        while let (Some(key), Some(item)) = (cursor.key(), cursor.item()) {
            if key.item_type == item_type::BLOCK_GROUP_ITEM {
                let defect = |defect| SpaceError::Corrupt {
                    tree: group_root.tree,
                    key,
                    defect,
                };
                if item.len() < 24 {
                    return Err(defect(SpaceDefect::Truncated));
                }
                let used = u64::from_le_bytes(item[..8].try_into().unwrap());
                let flags = u64::from_le_bytes(item[16..24].try_into().unwrap());
                if !volume
                    .chunks()
                    .matches_group(key.objectid, key.offset, flags)
                {
                    return Err(defect(SpaceDefect::ChunkMismatch));
                }
                groups.push(Group {
                    start: key.objectid,
                    length: key.offset,
                    flags,
                    declared_used: used,
                    found_used: 0,
                    free: BTreeMap::from([(key.objectid, key.objectid + key.offset)]),
                });
            }
            cursor.advance(volume).await?;
        }
        let mut space = Self {
            groups,
            nodesize: u64::from(sb.nodesize()),
            sector: u64::from(sb.sectorsize()),
            metadata: BTreeMap::new(),
        };
        let mut cursor = Cursor::ceiling(volume, extent_root, Key::new(0, 0, 0)).await?;
        while let (Some(key), Some(item)) = (cursor.key(), cursor.item()) {
            if key.item_type == item_type::EXTENT_ITEM || key.item_type == item_type::METADATA_ITEM
            {
                let defect = |defect| SpaceError::Corrupt {
                    tree: extent_root.tree,
                    key,
                    defect,
                };
                if item.len() < 24 {
                    return Err(defect(SpaceDefect::Truncated));
                }
                let refs = u64::from_le_bytes(item[..8].try_into().unwrap());
                let flags = u64::from_le_bytes(item[16..24].try_into().unwrap());
                // BTRFS_EXTENT_FLAG_DATA=1 and TREE_BLOCK=2 are mutually exclusive.
                if refs == 0
                    || !matches!(flags & 3, 1 | 2)
                    || (key.item_type == item_type::METADATA_ITEM && flags & 3 != 2)
                {
                    return Err(defect(SpaceDefect::ExtentHeader));
                }
                let length = if key.item_type == item_type::METADATA_ITEM {
                    space.nodesize
                } else {
                    key.offset
                };
                let end = key
                    .objectid
                    .checked_add(length)
                    .ok_or_else(|| defect(SpaceDefect::Range))?;
                if length == 0
                    || !key.objectid.is_multiple_of(space.sector)
                    || !length.is_multiple_of(space.sector)
                {
                    return Err(defect(SpaceDefect::Range));
                }
                let range = key.objectid..end;
                let group = space
                    .groups
                    .iter_mut()
                    .find(|group| group.contains(&range))
                    .ok_or_else(|| defect(SpaceDefect::ExtentOverlap))?;
                if !group.occupy(range) {
                    return Err(defect(SpaceDefect::ExtentOverlap));
                }
                group.found_used += length;
            }
            cursor.advance(volume).await?;
        }
        let excluded = volume.chunks().superblock_stripes();
        for group in &mut space.groups {
            if group.declared_used != group.found_used {
                return Err(SpaceError::Corrupt {
                    tree: group_root.tree,
                    key: Key::new(group.start, item_type::BLOCK_GROUP_ITEM, group.length),
                    defect: SpaceDefect::UsedBytes {
                        declared: group.declared_used,
                        found: group.found_used,
                    },
                });
            }
            for range in &excluded {
                group.exclude(range);
            }
        }
        Ok(space)
    }

    fn reserve(&mut self, length: u64, flags: u64) -> Result<u64, SpaceError> {
        for group in &mut self.groups {
            if group.flags & flags == 0 {
                continue;
            }
            let found = group
                .free
                .iter()
                .find(|(start, end)| **end - **start >= length)
                .map(|(&start, _)| start);
            if let Some(start) = found {
                assert!(group.occupy(start..start + length));
                return Ok(start);
            }
        }
        Err(SpaceError::Exhausted {
            bytes: length,
            flags,
        })
    }

    pub(crate) fn metadata(&self) -> impl Iterator<Item = (u64, MetadataReservation)> + '_ {
        self.metadata
            .iter()
            .map(|(&address, &record)| (address, record))
    }

    /// Cancel only allocations owned by this transaction. Published extents
    /// have no entry here and cannot accidentally become reusable this way.
    pub(crate) fn cancel_metadata(&mut self, address: u64) -> bool {
        if self.metadata.remove(&address).is_none() {
            return false;
        }
        let range = address..address + self.nodesize;
        let group = self
            .groups
            .iter_mut()
            .find(|group| group.contains(&range))
            .expect("reservation belongs to its block group");
        group.release(range);
        true
    }

    pub(crate) fn available_metadata(&self) -> u64 {
        self.groups
            .iter()
            .filter(|group| group.flags & METADATA != 0)
            .flat_map(|group| group.free.iter())
            .map(|(start, end)| end - start)
            .sum()
    }
}

impl MetadataAllocator for Space {
    fn cancel(&mut self, address: u64) {
        assert!(
            self.cancel_metadata(address),
            "overlay block owns a reservation"
        );
    }

    fn allocate(&mut self, tree: u64, level: u8, first: Key) -> Result<u64, WriteError> {
        let flags = if tree == objectid::CHUNK_TREE {
            SYSTEM
        } else {
            METADATA
        };
        let address = self.reserve(self.nodesize, flags)?;
        self.metadata
            .insert(address, MetadataReservation { tree, level, first });
        Ok(address)
    }
}
