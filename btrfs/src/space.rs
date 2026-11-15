//! Transaction-owned space reservations derived from allocation metadata.
//! Mount walks immutable trees. A transaction then owns its free-range map
//! exclusively; it never holds a lock across I/O and never returns retired
//! committed extents to this map before publication/read-side retirement.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::ops::Range;

use thiserror::Error;

use crate::allocation::data::{DataDefect, DataExtent};
use crate::allocation::{AllocationDefect, MetadataExtent};
use crate::free_space::{FreeGroup, FreeSpaceDefect, Intervals};
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
    #[error(transparent)]
    FreeSpace(#[from] FreeSpaceDefect),
    #[error(transparent)]
    Allocation(#[from] AllocationDefect),
    #[error(transparent)]
    Data(#[from] DataDefect),
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
    #[error("block-group used-byte accounting underflows or exceeds its length")]
    Accounting,
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
    free: Intervals,
    excluded_free: Intervals,
}

impl Group {
    fn contains(&self, range: &Range<u64>) -> bool {
        self.start <= range.start && range.end <= self.start + self.length
    }

    /// A reserved mirror stripe may already contain an extent-tree reservation.
    /// Remove only its intersections with the remaining free intervals.
    fn exclude(&mut self, range: &Range<u64>) {
        let overlaps: Vec<_> = self
            .free
            .iter()
            .filter(|free| free.start < range.end && free.end > range.start)
            .map(|free| free.start.max(range.start)..free.end.min(range.end))
            .collect();
        for overlap in overlaps {
            self.excluded_free
                .release(overlap.clone())
                .expect("excluded ranges are disjoint");
            assert!(self.free.occupy(overlap));
        }
    }
}

/// The extent item/back-reference changes the transaction must publish for a
/// newly reserved metadata block. No record is written by the allocator alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct MetadataReservation {
    pub(crate) tree: u64,
    pub(crate) level: u8,
    pub(crate) first: Key,
}

pub(crate) struct Space {
    groups: Vec<Group>,
    group_root: TreeRoot,
    free_root: Option<TreeRoot>,
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
        // BTRFS_FEATURE_COMPAT_RO_FREE_SPACE_TREE.
        let free_root = if sb.compat_ro_flags() & 1 != 0 {
            Some(
                find_root(volume, roots, objectid::FREE_SPACE_TREE)
                    .await?
                    .root,
            )
        } else {
            None
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
                    free: Intervals::whole(key.objectid..key.objectid + key.offset),
                    excluded_free: Intervals::default(),
                });
            }
            cursor.advance(volume).await?;
        }
        let mut space = Self {
            groups,
            group_root,
            free_root,
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
                if flags & 2 != 0 {
                    MetadataExtent::parse(key, item, space.nodesize)
                        .map_err(|error| defect(error.into()))?;
                } else {
                    DataExtent::parse(key, item, sb.sectorsize())
                        .map_err(|error| defect(error.into()))?;
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
                if !group.free.occupy(range) {
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
                .find(|range| range.end - range.start >= length)
                .map(|range| range.start);
            if let Some(start) = found {
                assert!(group.free.occupy(start..start + length));
                return Ok(start);
            }
        }
        Err(SpaceError::Exhausted {
            bytes: length,
            flags,
        })
    }

    /// Free-space-tree state after commit. Unlike allocation availability, this
    /// includes free superblock stripes and extents retired from the old roots.
    pub(crate) fn committed_free(
        &self,
        retired: &BTreeMap<u64, u64>,
    ) -> Result<Vec<FreeGroup>, SpaceError> {
        self.groups
            .iter()
            .map(|group| {
                let range = group.start..group.start + group.length;
                let mut free = group.free.clone();
                for returned in group.excluded_free.iter().chain(
                    retired
                        .range(range.clone())
                        .map(|(&address, &length)| address..address + length),
                ) {
                    free.release(returned)
                        .map_err(|defect| SpaceError::Corrupt {
                            tree: objectid::FREE_SPACE_TREE,
                            key: Key::new(group.start, item_type::FREE_SPACE_INFO, group.length),
                            defect: defect.into(),
                        })?;
                }
                Ok(FreeGroup::new(range, free))
            })
            .collect()
    }

    pub(crate) fn free_root(&self) -> Option<TreeRoot> {
        self.free_root
    }

    pub(crate) fn group_root(&self) -> TreeRoot {
        self.group_root
    }

    /// Usage in the next committed generation. Retired extents reduce disk
    /// accounting but remains absent from the reusable free-range map.
    pub(crate) fn group_usage(
        &self,
        retired: &BTreeMap<u64, u64>,
    ) -> Result<Vec<(Key, u64)>, SpaceError> {
        self.groups
            .iter()
            .map(|group| {
                let range = group.start..group.start + group.length;
                let added = self.metadata.range(range.clone()).count() as u64 * self.nodesize;
                let removed = retired.range(range).map(|(_, &length)| length).sum::<u64>();
                let key = Key::new(group.start, item_type::BLOCK_GROUP_ITEM, group.length);
                let used = group
                    .declared_used
                    .checked_add(added)
                    .and_then(|used| used.checked_sub(removed))
                    .filter(|used| *used <= group.length)
                    .ok_or(SpaceError::Corrupt {
                        tree: self.group_root.tree,
                        key,
                        defect: SpaceDefect::Accounting,
                    })?;
                Ok((key, used))
            })
            .collect()
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
        group
            .free
            .release(range)
            .expect("private reservation is allocated");
        true
    }

    pub(crate) fn available_metadata(&self) -> u64 {
        self.groups
            .iter()
            .filter(|group| group.flags & METADATA != 0)
            .flat_map(|group| group.free.iter())
            .map(|range| range.end - range.start)
            .sum()
    }
}

impl MetadataAllocator for Space {
    fn revise(&mut self, address: u64, first: Key) {
        self.metadata
            .get_mut(&address)
            .expect("overlay block owns a reservation")
            .first = first;
    }

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
