//! Chunk allocation on the single device, following Linux's regular policy
//! (`fs/btrfs/volumes.c`, `fs/btrfs/block-group.c`).
//!
//! A chunk is one CHUNK_ITEM in the chunk tree, one DEV_EXTENT item per copy in
//! the dev tree, the device item's `bytes_used` (the chunk tree's record and the
//! superblock's embedded copy), a BLOCK_GROUP_ITEM, and the new group's
//! free-space-tree records, all inside the allocating transaction. A SYSTEM chunk
//! is also appended to the superblock's `sys_chunk_array`. Readers of older
//! generations keep the chunk map they opened.
//!
//! # When chunks are allocated
//!
//! The commit loop COWs trees and allocates tree blocks itself, so a chunk that
//! commit would need must exist before commit starts. Linux's rule, applied here
//! before every mutation and once before commit:
//!
//! * METADATA: allocate when `used + 2 MiB >= 80% of total`
//!   (`should_alloc_chunk` with `CHUNK_ALLOC_NO_FORCE`), so at least a fifth of
//!   the type stays free unless the device itself is full. When the device is
//!   full, a mutation additionally refuses to start while less than
//!   [`Transaction::metadata_reserve`] is free, leaving that much for the commit
//!   of what is already staged.
//! * SYSTEM: allocating any other chunk first makes room in the chunk tree the
//!   way `check_system_chunk` does: a SYSTEM chunk is allocated when its free
//!   bytes cannot hold one device-item update plus one chunk-item insertion, or
//!   when `total < 2 * used` (`system_space_target`).
//! * DATA: allocate when a reservation finds no free range
//!   (`CHUNK_ALLOC_FORCE_FOR_EXTENT` in `find_free_extent`). With no room on the
//!   device either, a data write uses what is free: the window shrinks to the
//!   largest sector-multiple range, and only a full device reports ENOSPC.

use alloc::vec::Vec;
use core::ops::Range;

use arrayvec::ArrayVec;
use thiserror::Error;
use zerocopy::{FromZeros, IntoBytes};

use super::Transaction;
use crate::Key;
use crate::chunk::{Chunk, MAX_COPIES};
use crate::ondisk::{RawChunk, RawDevItem, RawStripe, STRIPE_LEN, item_type, objectid, view};
use crate::source::BlockSink;
use crate::space::{DATA, METADATA, SYSTEM, SpaceError};
use crate::tree::write::WriteError;

const SZ_1M: u64 = 1 << 20;
const SZ_16M: u64 = 16 << 20;
const SZ_1G: u64 = 1 << 30;
/// `BTRFS_DEVICE_RANGE_RESERVED`: the device's first MiB holds no device extent.
const DEVICE_RANGE_RESERVED: u64 = SZ_1M;
/// `BTRFS_MAX_DATA_CHUNK_SIZE`.
const MAX_DATA_CHUNK_SIZE: u64 = 10 * SZ_1G;
/// `BTRFS_BLOCK_GROUP_DUP`.
const DUP: u64 = 1 << 5;
/// `BTRFS_BLOCK_GROUP_PROFILE_MASK`: RAID0, RAID1, DUP, RAID10, RAID5, RAID6,
/// RAID1C3 and RAID1C4 are bits 3 through 10.
const PROFILE_MASK: u64 = 0xff << 3;
/// `BTRFS_MAX_LEVEL`.
const MAX_LEVEL: u64 = 8;
/// The slack in `should_alloc_chunk`'s `bytes_used + SZ_2M`.
const CHUNK_SLACK: u64 = 2 * SZ_1M;
/// The trees a commit rewrites a path in: root, extent, dev, checksum,
/// free-space, block-group and UUID trees, and the subvolume tree edited.
const COMMITTED_TREES: u64 = 8;
/// `sub_stripes` of every profile a single device carries (`btrfs_raid_array`).
const SUB_STRIPES: u16 = 1;

/// Why a chunk could not be allocated.
#[derive(Debug, Error)]
pub enum ChunkError {
    #[error(
        "block-group flags {flags:#x} select a profile this single-device writer cannot allocate; \
         only single and DUP chunks exist on one device"
    )]
    UnsupportedProfile { flags: u64 },
    #[error(
        "the device has no free range for a chunk with flags {flags:#x}: \
         the largest is {largest} bytes and a chunk needs {needed}"
    )]
    NoDeviceSpace {
        flags: u64,
        largest: u64,
        needed: u64,
    },
    #[error(
        "the superblock's system chunk array holds {used} of {capacity} bytes and cannot take {needed} more"
    )]
    SystemArrayFull {
        used: usize,
        needed: usize,
        capacity: usize,
    },
    #[error("the chunk tree has no device item for device {devid}")]
    MissingDevice { devid: u64 },
    #[error("a device-tree or chunk-tree item of {len} bytes is too short")]
    Truncated { len: usize },
    #[error("the new chunk at {logical:#x} does not fit the chunk map: {defect}")]
    Map {
        logical: u64,
        defect: crate::ChunkDefect,
    },
}

/// The per-profile numbers of Linux's `alloc_chunk_ctl` for one device.
struct Policy {
    dev_stripes: u64,
    ncopies: u64,
    max_stripe_size: u64,
    max_chunk_size: u64,
    dev_extent_min: u64,
}

/// The sizes a chunk gets.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Geometry {
    /// Bytes each stripe occupies on the device.
    pub(crate) stripe_size: u64,
    /// Logical bytes the chunk spans.
    pub(crate) chunk_size: u64,
    /// Stripes on the device: two for DUP, one otherwise.
    pub(crate) stripes: u64,
}

impl Policy {
    /// `init_alloc_chunk_ctl` and `init_alloc_chunk_ctl_policy_regular`, with
    /// `device_bytes` as the filesystem's writable bytes.
    fn new(flags: u64, device_bytes: u64) -> Self {
        let (dev_stripes, ncopies) = if flags & DUP != 0 { (2, 2) } else { (1, 1) };
        // `calc_chunk_size`: the space info's chunk size.
        let chunk_size = if flags & DATA != 0 {
            MAX_DATA_CHUNK_SIZE
        } else if flags & SYSTEM != 0 {
            32 * SZ_1M
        } else if device_bytes > 50 * SZ_1G {
            SZ_1G
        } else {
            256 * SZ_1M
        };
        let max_stripe_size = chunk_size.min(SZ_1G);
        // "We don't want a chunk larger than 10% of writable space."
        let max_chunk_size = (device_bytes * 10 / 100).min(chunk_size);
        Self {
            dev_stripes,
            ncopies,
            max_stripe_size,
            max_chunk_size,
            dev_extent_min: STRIPE_LEN * dev_stripes,
        }
    }

    /// The device bytes `gather_device_info` asks `find_free_dev_extent` for.
    fn want(&self) -> u64 {
        self.max_stripe_size * self.dev_stripes
    }

    /// `decide_stripe_size_regular` for one device whose largest usable hole
    /// is `max_avail` bytes.
    fn decide(&self, max_avail: u64) -> Geometry {
        let stripes = self.dev_stripes;
        let data_stripes = stripes / self.ncopies;
        let mut stripe_size = max_avail / self.dev_stripes;
        if stripe_size * data_stripes > self.max_chunk_size {
            // Reduce the stripe, rounded up to 16 MiB again, unless that ends
            // up bigger than before.
            stripe_size = (self.max_chunk_size / data_stripes)
                .next_multiple_of(SZ_16M)
                .min(stripe_size);
        }
        stripe_size = stripe_size.min(SZ_1G);
        stripe_size -= stripe_size % STRIPE_LEN;
        Geometry {
            stripe_size,
            chunk_size: stripe_size * data_stripes,
            stripes,
        }
    }
}

/// A device range found by `find_free_dev_extent`.
#[derive(Debug, PartialEq, Eq)]
struct Hole {
    start: u64,
    size: u64,
}

/// `find_free_dev_extent` over the device's extents, sorted by start: the
/// first hole of `want` bytes, else the largest hole there is.
fn find_hole(extents: &[Range<u64>], device_bytes: u64, want: u64) -> Hole {
    let mut search_start = DEVICE_RANGE_RESERVED;
    let mut max = Hole {
        start: search_start,
        size: 0,
    };
    if search_start >= device_bytes {
        return max;
    }
    for extent in extents {
        if extent.start > device_bytes {
            break;
        }
        if extent.start > search_start {
            let size = extent.start - search_start;
            if size > max.size {
                max = Hole {
                    start: search_start,
                    size,
                };
            }
            if size >= want {
                return max;
            }
        }
        search_start = search_start.max(extent.end);
    }
    if device_bytes > search_start {
        let size = device_bytes - search_start;
        if size > max.size {
            max = Hole {
                start: search_start,
                size,
            };
        }
    }
    max
}

/// The flags of a new chunk of `kind`: the flags of the filesystem's latest
/// group of that kind, whose profile Linux derives the new chunk's from. A
/// filesystem with none gets the unreplicated profile.
fn chunk_flags(latest: Option<u64>, kind: u64) -> Result<u64, ChunkError> {
    let flags = latest.unwrap_or(kind);
    if flags & PROFILE_MASK & !DUP != 0 {
        return Err(ChunkError::UnsupportedProfile { flags });
    }
    Ok(flags)
}

/// The device a chunk goes on, as the chunk and dev trees describe it.
struct Device {
    item: Vec<u8>,
    extents: Vec<Range<u64>>,
    /// `chunk_tree_uuid` of the dev tree's existing extents.
    chunk_tree_uuid: [u8; 16],
}

impl<S: BlockSink> Transaction<'_, S> {
    /// Free metadata bytes below which a mutation refuses to start once the
    /// device cannot supply another chunk: what a commit may still COW, one
    /// root-to-leaf path with room to split, in each tree it rewrites
    /// (`btrfs_calc_insert_metadata_size` per tree).
    fn metadata_reserve(&self) -> u64 {
        u64::from(self.volume.superblock().nodesize()) * MAX_LEVEL * 2 * COMMITTED_TREES
    }

    /// The preparation every mutation and the commit share: a metadata chunk
    /// when the 80% rule asks for one.
    pub(crate) async fn grow_metadata(&mut self) -> Result<(), WriteError> {
        let (total, free) = self.space.totals(METADATA);
        let used = total - free;
        // `should_alloc_chunk` with `CHUNK_ALLOC_NO_FORCE`.
        if used + CHUNK_SLACK < total / 100 * 80 {
            return Ok(());
        }
        self.allocate_chunk_if_room(METADATA).await
    }

    /// Run before every mutation: grow metadata ahead of need and keep the
    /// commit's reserve.
    pub(crate) async fn prepare_mutation(&mut self) -> Result<(), WriteError> {
        self.grow_metadata().await?;
        let reserve = self.metadata_reserve();
        if self.space.totals(METADATA).1 < reserve {
            return Err(SpaceError::Exhausted {
                bytes: reserve,
                flags: METADATA,
            }
            .into());
        }
        Ok(())
    }

    /// Makes `length` bytes reservable as data, allocating a data chunk when no
    /// free range holds them. A full device is not an error here: the caller's
    /// reservation reports it, or shrinks to what exists.
    pub(super) async fn ensure_data(&mut self, length: u64) -> Result<(), WriteError> {
        if !self.space.can_reserve(length, DATA) {
            self.allocate_chunk_if_room(DATA).await?;
        }
        Ok(())
    }

    /// The window a data write of up to `length` bytes can use: `length` when a
    /// range holds it, else the largest sector multiple that fits
    /// (`find_free_extent` with `min_alloc_size` of one sector). Only a device
    /// with no free sector fails.
    pub(super) async fn fit_data_window(&mut self, length: u64) -> Result<u64, WriteError> {
        self.ensure_data(length).await?;
        let sector = u64::from(self.volume.superblock().sectorsize());
        let largest = self.space.largest_free(DATA);
        let fit = length.min(largest - largest % sector);
        if fit == 0 {
            return Err(SpaceError::Exhausted {
                bytes: sector,
                flags: DATA,
            }
            .into());
        }
        Ok(fit)
    }

    async fn allocate_chunk_if_room(&mut self, kind: u64) -> Result<(), WriteError> {
        match self.allocate_chunk(kind).await {
            Err(WriteError::Chunk(ChunkError::NoDeviceSpace { .. })) => Ok(()),
            result => result,
        }
    }

    /// Allocates one chunk of `kind`, first making room in the chunk tree
    /// unless the chunk is itself a SYSTEM chunk (`check_system_chunk`).
    pub(crate) async fn allocate_chunk(&mut self, kind: u64) -> Result<(), WriteError> {
        if kind != SYSTEM {
            let (total, free) = self.space.totals(SYSTEM);
            let used = total - free;
            let nodesize = u64::from(self.volume.superblock().nodesize());
            // One device item updated and one chunk item inserted.
            let needed = nodesize * MAX_LEVEL + nodesize * MAX_LEVEL * 2;
            if free < needed || total < 2 * used {
                match self.create_chunk(SYSTEM).await {
                    Err(WriteError::Chunk(ChunkError::NoDeviceSpace { .. })) | Ok(()) => {}
                    Err(error) => return Err(error),
                }
            }
        }
        self.create_chunk(kind).await
    }

    async fn device(&self, devid: u64) -> Result<Device, WriteError> {
        let item = self
            .trees
            .get(
                &self.volume,
                self.chunk_root,
                Key::new(objectid::DEV_ITEMS, item_type::DEV_ITEM, devid),
            )
            .await?
            .ok_or(ChunkError::MissingDevice { devid })?;
        let mut extents = Vec::new();
        let mut chunk_tree_uuid = [0; 16];
        let root = self.roots.get(objectid::DEV_TREE)?;
        let mut key = Key::new(devid, item_type::DEV_EXTENT, 0);
        while let Some((found, bytes)) = self.trees.ceiling(&self.volume, root, key).await? {
            if found.objectid != devid || found.item_type != item_type::DEV_EXTENT {
                break;
            }
            let length = bytes
                .get(24..32)
                .ok_or(ChunkError::Truncated { len: bytes.len() })?;
            if extents.is_empty()
                && let Some(uuid) = bytes.get(32..48)
            {
                chunk_tree_uuid.copy_from_slice(uuid);
            }
            let length = u64::from_le_bytes(length.try_into().expect("eight bytes"));
            extents.push(found.offset..found.offset + length);
            let Some(next) = found.offset.checked_add(1) else {
                break;
            };
            key.offset = next;
        }
        Ok(Device {
            item,
            extents,
            chunk_tree_uuid,
        })
    }

    /// `btrfs_create_chunk` and the items `btrfs_create_pending_block_groups`
    /// adds, in this transaction.
    async fn create_chunk(&mut self, kind: u64) -> Result<(), WriteError> {
        let flags = chunk_flags(self.space.latest_flags(kind), kind)?;
        let superblock = self.volume.superblock();
        let devid = superblock.devid();
        let device_bytes = superblock.device_bytes();
        let sector = superblock.sectorsize();
        let device = self.device(devid).await?;
        let dev: RawDevItem = *view(&device.item).ok_or(ChunkError::Truncated {
            len: device.item.len(),
        })?;
        let policy = Policy::new(flags, device_bytes);
        let hole = find_hole(&device.extents, device_bytes, policy.want());
        // `gather_device_info`: a device with less than `dev_extent_min`
        // unallocated, or no hole that large, is skipped.
        let total_avail = device_bytes.saturating_sub(dev.bytes_used.get());
        let max_avail = hole.size.min(policy.want());
        if total_avail < policy.dev_extent_min || max_avail < policy.dev_extent_min {
            return Err(ChunkError::NoDeviceSpace {
                flags,
                largest: hole.size,
                needed: policy.dev_extent_min,
            }
            .into());
        }
        let geometry = policy.decide(max_avail);
        let logical = self.volume.chunks().next_logical();
        let copies: ArrayVec<u64, MAX_COPIES> = (0..geometry.stripes)
            .map(|stripe| hole.start + stripe * geometry.stripe_size)
            .collect();

        let mut item = RawChunk::new_zeroed();
        item.length.set(geometry.chunk_size);
        item.owner.set(objectid::EXTENT_TREE);
        item.stripe_len.set(STRIPE_LEN);
        item.chunk_type.set(flags);
        item.io_align.set(STRIPE_LEN as u32);
        item.io_width.set(STRIPE_LEN as u32);
        item.sector_size.set(sector);
        item.num_stripes.set(geometry.stripes as u16);
        item.sub_stripes.set(SUB_STRIPES);
        let mut chunk_item = item.as_bytes().to_vec();
        for &physical in &copies {
            let mut stripe = RawStripe::new_zeroed();
            stripe.devid.set(devid);
            stripe.offset.set(physical);
            stripe.dev_uuid = dev.uuid;
            chunk_item.extend_from_slice(stripe.as_bytes());
        }
        let chunk_key = Key::new(objectid::FIRST_CHUNK_TREE, item_type::CHUNK_ITEM, logical);

        // The transaction's chunk map and space learn the chunk before any
        // tree edit below can allocate a block from it.
        self.volume
            .add_chunk(Chunk::allocated(
                logical,
                geometry.chunk_size,
                flags,
                copies.clone(),
            ))
            .map_err(|defect| ChunkError::Map { logical, defect })?;
        self.space
            .push_group(logical, geometry.chunk_size, flags, self.volume.chunks());

        let used = geometry.stripe_size * geometry.stripes;
        let mut updated = dev;
        updated.bytes_used.set(dev.bytes_used.get() + used);
        let mut device_item = device.item.clone();
        device_item[..size_of::<RawDevItem>()].copy_from_slice(updated.as_bytes());
        for (key, bytes) in [
            (
                Key::new(objectid::DEV_ITEMS, item_type::DEV_ITEM, devid),
                &device_item,
            ),
            (chunk_key, &chunk_item),
        ] {
            self.chunk_root = self
                .trees
                .apply(
                    &self.volume,
                    self.chunk_root,
                    key,
                    Some(bytes),
                    &mut self.space,
                )
                .await?;
        }

        let mut root = self.roots.get(objectid::DEV_TREE)?;
        for &physical in &copies {
            // `btrfs_dev_extent`: the chunk tree, the chunk's objectid and
            // offset, its length, and the chunk tree's UUID.
            let mut extent = Vec::with_capacity(48);
            extent.extend_from_slice(&objectid::CHUNK_TREE.to_le_bytes());
            extent.extend_from_slice(&objectid::FIRST_CHUNK_TREE.to_le_bytes());
            extent.extend_from_slice(&logical.to_le_bytes());
            extent.extend_from_slice(&geometry.stripe_size.to_le_bytes());
            extent.extend_from_slice(&device.chunk_tree_uuid);
            root = self
                .trees
                .apply(
                    &self.volume,
                    root,
                    Key::new(devid, item_type::DEV_EXTENT, physical),
                    Some(&extent),
                    &mut self.space,
                )
                .await?;
        }
        self.roots.set(root)?;

        // `btrfs_block_group_item`: used, the chunk objectid, the flags.
        let mut group = Vec::with_capacity(24);
        group.extend_from_slice(&0_u64.to_le_bytes());
        group.extend_from_slice(&objectid::FIRST_CHUNK_TREE.to_le_bytes());
        group.extend_from_slice(&flags.to_le_bytes());
        self.accounting
            .set_group_item(
                &self.volume,
                &mut self.trees,
                &mut self.space,
                Key::new(logical, item_type::BLOCK_GROUP_ITEM, geometry.chunk_size),
                Some(&group),
            )
            .await?;

        self.image.add_device_used(used);
        if flags & SYSTEM != 0 {
            self.image.append_system_chunk(chunk_key, &chunk_item)?;
        }
        tracing::debug!(
            logical,
            length = geometry.chunk_size,
            flags,
            physical = ?copies,
            "allocated a chunk"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stripe_sizes_follow_linux_for_single_and_dup() {
        const GIB: u64 = SZ_1G;
        // A 10 GiB device, fresh: the data cap is 10% of the device.
        let data = Policy::new(DATA, 10 * GIB);
        assert_eq!(data.want(), GIB);
        assert_eq!(
            data.decide(data.want()),
            Geometry {
                stripe_size: GIB,
                chunk_size: GIB,
                stripes: 1
            }
        );
        // Metadata DUP is 256 MiB below 50 GiB and takes two stripes.
        let metadata = Policy::new(METADATA | DUP, 10 * GIB);
        assert_eq!(metadata.want(), 512 * SZ_1M);
        assert_eq!(
            metadata.decide(metadata.want()),
            Geometry {
                stripe_size: 256 * SZ_1M,
                chunk_size: 256 * SZ_1M,
                stripes: 2
            }
        );
        // SYSTEM is 32 MiB, capped to a tenth of a small device.
        let system = Policy::new(SYSTEM | DUP, 128 * SZ_1M);
        assert_eq!(system.max_chunk_size, 13_421_772);
        let geometry = system.decide(system.want());
        assert_eq!(geometry.stripe_size % STRIPE_LEN, 0);
        assert_eq!(geometry.chunk_size, geometry.stripe_size);
        // A short hole shrinks the stripe to what is left, 64 KiB aligned.
        let geometry = data.decide(SZ_1M + 5000);
        assert_eq!(geometry.stripe_size, SZ_1M);
        // Metadata above 50 GiB prefers a gibibyte.
        assert_eq!(Policy::new(METADATA, 100 * GIB).max_chunk_size, GIB);
    }

    #[test]
    fn a_new_chunk_takes_the_profile_of_its_kind_and_refuses_what_one_device_cannot_hold() {
        assert_eq!(
            chunk_flags(Some(METADATA | DUP), METADATA).unwrap(),
            METADATA | DUP
        );
        assert_eq!(chunk_flags(Some(DATA), DATA).unwrap(), DATA);
        assert_eq!(chunk_flags(None, DATA).unwrap(), DATA);
        // RAID1, RAID1C3, RAID0, RAID10, RAID5, RAID6 and RAID1C4.
        for profile in [1 << 4, 1 << 9, 1 << 3, 1 << 6, 1 << 7, 1 << 8, 1 << 10] {
            let flags = METADATA | profile;
            assert!(matches!(
                chunk_flags(Some(flags), METADATA),
                Err(ChunkError::UnsupportedProfile { flags: named }) if named == flags
            ));
        }
    }

    #[test]
    fn hole_search_takes_the_first_fit_else_the_largest() {
        let extents = [
            SZ_1M..3 * SZ_1M,
            5 * SZ_1M..6 * SZ_1M,
            9 * SZ_1M..10 * SZ_1M,
        ];
        // The first 2 MiB hole is at 3 MiB.
        assert_eq!(
            find_hole(&extents, 20 * SZ_1M, 2 * SZ_1M),
            Hole {
                start: 3 * SZ_1M,
                size: 2 * SZ_1M
            }
        );
        // Nothing before the tail holds 4 MiB, so the 10 MiB tail does.
        assert_eq!(
            find_hole(&extents, 20 * SZ_1M, 4 * SZ_1M),
            Hole {
                start: 10 * SZ_1M,
                size: 10 * SZ_1M
            }
        );
        // On a 10 MiB device no hole fits, so the largest (3 MiB) is reported.
        assert_eq!(
            find_hole(&extents, 10 * SZ_1M, 4 * SZ_1M),
            Hole {
                start: 6 * SZ_1M,
                size: 3 * SZ_1M
            }
        );
        assert_eq!(
            find_hole(&extents, 20 * SZ_1M, 20 * SZ_1M),
            Hole {
                start: 10 * SZ_1M,
                size: 10 * SZ_1M
            }
        );
        // An empty device offers everything after the reserved first MiB.
        assert_eq!(
            find_hole(&[], 8 * SZ_1M, SZ_1M),
            Hole {
                start: SZ_1M,
                size: 7 * SZ_1M
            }
        );
    }
}
