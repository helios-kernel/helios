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
//!   the type stays free unless the device itself is full. A mutation that
//!   cannot reserve its metadata (`transaction::reserve`) first commits, then
//!   allocates a chunk whatever this rule says, before it is refused.
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
use crate::chunk::{Chunk, MAX_COPIES, Stripe};
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
/// `BTRFS_BLOCK_GROUP_RAID1`.
const RAID1: u64 = 1 << 4;
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
    #[error("the superblock's system chunk array has no entry for the chunk at {logical:#x}")]
    NotInSystemArray { logical: u64 },
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
    if flags & PROFILE_MASK & !(DUP | RAID1) != 0 {
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

impl<S: BlockSink> Transaction<S> {
    /// Free metadata bytes kept for the commit's own work whatever the
    /// mutations reserved, as Linux's global block reserve: one root-to-leaf
    /// path with room to split, in each tree a commit rewrites
    /// (`btrfs_calc_insert_metadata_size` per tree).
    pub(super) fn metadata_reserve(&self) -> u64 {
        u64::from(self.volume.superblock().nodesize()) * MAX_LEVEL * 2 * COMMITTED_TREES
    }

    /// Linux's `ALLOC_CHUNK` flush state: a metadata chunk whatever the 80%
    /// rule says, when the device has room for one.
    pub(crate) async fn force_metadata_chunk(&mut self) -> Result<(), WriteError> {
        self.allocate_chunk_if_room(METADATA).await
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

    /// Run before every mutation: grow metadata ahead of need. The space the
    /// mutation itself needs is its reservation's (`transaction::reserve`).
    pub(crate) async fn prepare_mutation(&mut self) -> Result<(), WriteError> {
        self.grow_metadata().await
    }

    /// Makes `length` bytes reservable as data, allocating a data chunk when no
    /// free range holds them. A full device is not an error here: the caller's
    /// reservation reports it, or shrinks to what exists.
    pub(crate) async fn ensure_data(&mut self, length: u64) -> Result<(), WriteError> {
        if !self.space.can_reserve(length, DATA) {
            self.allocate_chunk_if_room(DATA).await?;
        }
        Ok(())
    }

    /// The length of the next data extent writeback allocates for `length`
    /// bytes, as `btrfs_reserve_extent` (`fs/btrfs/extent-tree.c`) settles
    /// it with a `min_alloc_size` of one sector: `length` when a free range
    /// holds it, after a data chunk when none does; otherwise half of it,
    /// at most the largest free range and at least one sector, rounded down
    /// to a sector, until a range holds it. Only a device with no free
    /// sector fails, which the data reservation of the dirty data rules out.
    pub(super) async fn extent_length(&mut self, length: u64) -> Result<u64, WriteError> {
        self.ensure_data(length).await?;
        let sector = u64::from(self.volume.superblock().sectorsize());
        let largest = self.space.largest_free(DATA);
        if largest < sector {
            return Err(SpaceError::Exhausted {
                bytes: sector,
                flags: DATA,
            }
            .into());
        }
        let mut fit = length;
        while fit > largest {
            fit = ((fit >> 1).min(largest) / sector * sector).max(sector);
        }
        Ok(fit)
    }

    /// Adds a data chunk, as the data space flush's `ALLOC_CHUNK_FORCE`.
    /// Answers false once the device has no room for one.
    pub(crate) async fn grow_data(&mut self) -> Result<bool, WriteError> {
        match self.allocate_chunk(DATA).await {
            Err(WriteError::Chunk(ChunkError::NoDeviceSpace { .. })) => Ok(false),
            result => result.map(|()| true),
        }
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

    /// Every `DEV_ITEM` in the chunk tree, sorted by `devid`.
    pub(crate) async fn all_dev_items(&self) -> Result<Vec<(u64, RawDevItem)>, WriteError> {
        let mut items = Vec::new();
        let mut key = Key::new(objectid::DEV_ITEMS, item_type::DEV_ITEM, 0);
        while let Some((found, bytes)) = self
            .trees
            .ceiling(&self.volume, self.chunk_root, key)
            .await?
        {
            if found.objectid != objectid::DEV_ITEMS || found.item_type != item_type::DEV_ITEM {
                break;
            }
            let dev: RawDevItem =
                *view(&bytes).ok_or(ChunkError::Truncated { len: bytes.len() })?;
            items.push((found.offset, dev));
            let Some(next) = found.offset.checked_add(1) else {
                break;
            };
            key.offset = next;
        }
        Ok(items)
    }

    pub(crate) async fn device_extents(
        &self,
        devid: u64,
    ) -> Result<(Vec<Range<u64>>, [u8; 16]), WriteError> {
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
        // Ranges released by removed chunks stay allocated until publication.
        for (rel_dev, range) in &self.released {
            if *rel_dev == devid {
                extents.push(range.clone());
            }
        }
        extents.sort_unstable_by_key(|extent| extent.start);
        Ok((extents, chunk_tree_uuid))
    }

    /// Reads the `chunk_tree_uuid` recorded in existing device extents, or the
    /// chunk tree root header's `chunk_tree_uuid` if none exist yet.
    pub(crate) async fn chunk_tree_uuid(&self) -> Result<[u8; 16], WriteError> {
        let root = self.roots.get(objectid::DEV_TREE)?;
        let mut key = Key::new(0, 0, 0);
        while let Some((found, bytes)) = self.trees.ceiling(&self.volume, root, key).await? {
            if found.item_type == item_type::DEV_EXTENT
                && let Some(uuid) = bytes.get(32..48)
            {
                let mut out = [0; 16];
                out.copy_from_slice(uuid);
                return Ok(out);
            }
            let Some(next) = found.offset.checked_add(1) else {
                break;
            };
            key = Key::new(found.objectid, found.item_type, next);
        }
        let header = self
            .trees
            .read(
                &self.volume,
                self.chunk_root.bytenr,
                crate::tree::Expected {
                    level: self.chunk_root.level,
                    generation: self.chunk_root.generation,
                    first_key: None,
                },
            )
            .await?;
        Ok(header.chunk_tree_uuid())
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
        let (extents, mut chunk_tree_uuid) = self.device_extents(devid).await?;
        if chunk_tree_uuid == [0; 16] {
            chunk_tree_uuid = self.chunk_tree_uuid().await?;
        }
        Ok(Device {
            item,
            extents,
            chunk_tree_uuid,
        })
    }

    /// Removes every unused block group (`btrfs_delete_unused_bgs`), each as
    /// `btrfs_remove_chunk` does. Returns how many left.
    pub(crate) async fn remove_unused_groups(&mut self) -> Result<usize, WriteError> {
        let unused = self.space.unused_groups(self.volume.chunks());
        for &(logical, length, flags) in &unused {
            self.remove_chunk(logical, length, flags).await?;
        }
        Ok(unused.len())
    }

    /// Removes the chunk at `logical` and its block group, in this transaction:
    /// the group leaves the allocator first, so no tree block this removal COWs
    /// can land in it, then its device extents, device item usage, chunk item
    /// (and bootstrap entry for SYSTEM), block-group item and free-space
    /// records go. `unused_groups` established the group is empty.
    async fn remove_chunk(
        &mut self,
        logical: u64,
        length: u64,
        flags: u64,
    ) -> Result<(), WriteError> {
        self.space.remove_group(logical);
        let chunk = self
            .volume
            .remove_chunk(logical)
            .expect("an unused block group has its chunk in the map");
        let group_key = Key::new(logical, item_type::BLOCK_GROUP_ITEM, length);
        self.accounting
            .set_group_item(
                &self.volume,
                &mut self.trees,
                &mut self.space,
                group_key,
                None,
            )
            .await?;
        self.accounting.forget_group(&group_key);

        // Each copy's device extent is `length` bytes (`create_chunk`).
        let mut root = self.roots.get(objectid::DEV_TREE)?;
        let mut per_dev_used: alloc::collections::BTreeMap<u64, u64> =
            alloc::collections::BTreeMap::new();
        for &stripe in chunk.copies() {
            root = self
                .trees
                .apply(
                    &self.volume,
                    root,
                    Key::new(stripe.devid, item_type::DEV_EXTENT, stripe.offset),
                    None,
                    &mut self.space,
                )
                .await?;
            self.released
                .push((stripe.devid, stripe.offset..stripe.offset + length));
            *per_dev_used.entry(stripe.devid).or_default() += length;
        }
        self.roots.set(root)?;

        let primary_devid = self.volume.superblock().devid();
        for (devid, used) in per_dev_used {
            let device = self.device(devid).await?;
            let dev: RawDevItem = *view(&device.item).ok_or(ChunkError::Truncated {
                len: device.item.len(),
            })?;
            let mut updated = dev;
            updated.bytes_used.set(
                dev.bytes_used
                    .get()
                    .checked_sub(used)
                    .expect("a removed chunk was counted as allocated"),
            );
            let mut device_item = device.item.clone();
            device_item[..size_of::<RawDevItem>()].copy_from_slice(updated.as_bytes());
            self.chunk_root = self
                .trees
                .apply(
                    &self.volume,
                    self.chunk_root,
                    Key::new(objectid::DEV_ITEMS, item_type::DEV_ITEM, devid),
                    Some(&device_item),
                    &mut self.space,
                )
                .await?;
            if devid == primary_devid {
                self.image.sub_device_used(used);
            }
        }
        self.chunk_root = self
            .trees
            .apply(
                &self.volume,
                self.chunk_root,
                Key::new(objectid::FIRST_CHUNK_TREE, item_type::CHUNK_ITEM, logical),
                None,
                &mut self.space,
            )
            .await?;
        if flags & SYSTEM != 0 {
            self.image.remove_system_chunk(logical)?;
        }
        tracing::debug!(logical, length, flags, "removed an unused chunk");
        Ok(())
    }

    /// `btrfs_create_chunk` and the items `btrfs_create_pending_block_groups`
    /// adds, in this transaction. Selects eligible devices across the volume,
    /// respecting `excluded_device` (during device removal) and
    /// `device_size_limit` (during device shrink).
    async fn create_chunk(&mut self, kind: u64) -> Result<(), WriteError> {
        let mut flags = chunk_flags(self.space.latest_flags(kind), kind)?;
        let sector = self.volume.superblock().sectorsize();
        let all_devs = self.all_dev_items().await?;
        let eligible: Vec<(u64, RawDevItem)> = all_devs
            .into_iter()
            .filter(|(id, _)| self.excluded_device != Some(*id))
            .collect();
        if flags & RAID1 != 0 && eligible.len() < 2 {
            // Fall back to DUP/SINGLE only if RAID1 cannot be satisfied on a
            // single remaining device? No: refuse unsupported profile cleanly!
            if self.excluded_device.is_none() {
                return Err(ChunkError::UnsupportedProfile { flags }.into());
            }
            flags = (flags & !RAID1) | DUP;
        }
        if flags & RAID1 != 0 {
            return self.create_raid1_chunk(flags, sector, &eligible).await;
        }

        // Choose the eligible device with the largest usable hole for SINGLE or DUP.
        let mut best: Option<(u64, Device, RawDevItem, Hole, Policy, u64)> = None;
        let mut largest_hole = 0_u64;
        let mut needed_min = STRIPE_LEN;
        for (devid, dev) in eligible {
            let mut device_bytes = dev.total_bytes.get();
            if let Some((lim_dev, lim_bytes)) = self.device_size_limit
                && lim_dev == devid
            {
                device_bytes = device_bytes.min(lim_bytes);
            }
            let device = self.device(devid).await?;
            let policy = Policy::new(flags, device_bytes);
            needed_min = policy.dev_extent_min;
            let hole = find_hole(&device.extents, device_bytes, policy.want());
            largest_hole = largest_hole.max(hole.size);
            let total_avail = device_bytes.saturating_sub(dev.bytes_used.get());
            let max_avail = hole.size.min(policy.want());
            if total_avail < policy.dev_extent_min || max_avail < policy.dev_extent_min {
                continue;
            }
            let take = match &best {
                None => true,
                Some((_, _, _, prev_hole, _, _)) => hole.size > prev_hole.size,
            };
            if take {
                best = Some((devid, device, dev, hole, policy, max_avail));
            }
        }
        let Some((devid, device, dev, hole, policy, max_avail)) = best else {
            return Err(ChunkError::NoDeviceSpace {
                flags,
                largest: largest_hole,
                needed: needed_min,
            }
            .into());
        };
        let geometry = policy.decide(max_avail);
        let logical = self.volume.chunks().next_logical();
        let copies: ArrayVec<Stripe, MAX_COPIES> = (0..geometry.stripes)
            .map(|stripe| Stripe {
                devid,
                offset: hole.start + stripe * geometry.stripe_size,
            })
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
        for &stripe_loc in &copies {
            let mut stripe = RawStripe::new_zeroed();
            stripe.devid.set(stripe_loc.devid);
            stripe.offset.set(stripe_loc.offset);
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
        for &stripe_loc in &copies {
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
                    Key::new(stripe_loc.devid, item_type::DEV_EXTENT, stripe_loc.offset),
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

        if devid == self.volume.superblock().devid() {
            self.image.add_device_used(used);
        }
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

    async fn create_raid1_chunk(
        &mut self,
        flags: u64,
        sector: u32,
        eligible: &[(u64, RawDevItem)],
    ) -> Result<(), WriteError> {
        let mut candidates = Vec::new();
        for &(devid, dev) in eligible {
            let mut device_bytes = dev.total_bytes.get();
            if let Some((lim_dev, lim_bytes)) = self.device_size_limit
                && lim_dev == devid
            {
                device_bytes = device_bytes.min(lim_bytes);
            }
            let device = self.device(devid).await?;
            let policy = Policy::new(flags & !RAID1, device_bytes);
            let hole = find_hole(&device.extents, device_bytes, policy.want());
            let total_avail = device_bytes.saturating_sub(dev.bytes_used.get());
            let avail = hole.size.min(total_avail).min(policy.want());
            if avail >= STRIPE_LEN {
                candidates.push((devid, device, dev, hole, policy, avail));
            }
        }
        candidates.sort_by_key(|a| core::cmp::Reverse(a.5));
        if candidates.len() < 2 {
            let largest = candidates.first().map_or(0, |c| c.3.size);
            return Err(ChunkError::NoDeviceSpace {
                flags,
                largest,
                needed: STRIPE_LEN,
            }
            .into());
        }
        let max_avail = candidates[0].5.min(candidates[1].5);
        let geometry = candidates[0].4.decide(max_avail);
        let chunk_size = geometry.stripe_size;
        let logical = self.volume.chunks().next_logical();
        let copies: ArrayVec<Stripe, MAX_COPIES> = [
            Stripe {
                devid: candidates[0].0,
                offset: candidates[0].3.start,
            },
            Stripe {
                devid: candidates[1].0,
                offset: candidates[1].3.start,
            },
        ]
        .into_iter()
        .collect();

        let mut item = RawChunk::new_zeroed();
        item.length.set(chunk_size);
        item.owner.set(objectid::EXTENT_TREE);
        item.stripe_len.set(STRIPE_LEN);
        item.chunk_type.set(flags);
        item.io_align.set(STRIPE_LEN as u32);
        item.io_width.set(STRIPE_LEN as u32);
        item.sector_size.set(sector);
        item.num_stripes.set(2);
        item.sub_stripes.set(SUB_STRIPES);
        let mut chunk_item = item.as_bytes().to_vec();
        for idx in 0..2 {
            let mut stripe = RawStripe::new_zeroed();
            stripe.devid.set(copies[idx].devid);
            stripe.offset.set(copies[idx].offset);
            stripe.dev_uuid = candidates[idx].2.uuid;
            chunk_item.extend_from_slice(stripe.as_bytes());
        }
        let chunk_key = Key::new(objectid::FIRST_CHUNK_TREE, item_type::CHUNK_ITEM, logical);

        self.volume
            .add_chunk(Chunk::allocated(logical, chunk_size, flags, copies.clone()))
            .map_err(|defect| ChunkError::Map { logical, defect })?;
        self.space
            .push_group(logical, chunk_size, flags, self.volume.chunks());

        let primary_devid = self.volume.superblock().devid();
        for candidate in candidates.iter().take(2) {
            let devid = candidate.0;
            let mut updated = candidate.2;
            updated
                .bytes_used
                .set(updated.bytes_used.get() + chunk_size);
            let mut device_item = candidate.1.item.clone();
            device_item[..size_of::<RawDevItem>()].copy_from_slice(updated.as_bytes());
            self.chunk_root = self
                .trees
                .apply(
                    &self.volume,
                    self.chunk_root,
                    Key::new(objectid::DEV_ITEMS, item_type::DEV_ITEM, devid),
                    Some(&device_item),
                    &mut self.space,
                )
                .await?;
            if devid == primary_devid {
                self.image.add_device_used(chunk_size);
            }
        }
        self.chunk_root = self
            .trees
            .apply(
                &self.volume,
                self.chunk_root,
                chunk_key,
                Some(&chunk_item),
                &mut self.space,
            )
            .await?;

        let mut root = self.roots.get(objectid::DEV_TREE)?;
        for idx in 0..2 {
            let mut extent = Vec::with_capacity(48);
            extent.extend_from_slice(&objectid::CHUNK_TREE.to_le_bytes());
            extent.extend_from_slice(&objectid::FIRST_CHUNK_TREE.to_le_bytes());
            extent.extend_from_slice(&logical.to_le_bytes());
            extent.extend_from_slice(&chunk_size.to_le_bytes());
            extent.extend_from_slice(&candidates[idx].1.chunk_tree_uuid);
            root = self
                .trees
                .apply(
                    &self.volume,
                    root,
                    Key::new(copies[idx].devid, item_type::DEV_EXTENT, copies[idx].offset),
                    Some(&extent),
                    &mut self.space,
                )
                .await?;
        }
        self.roots.set(root)?;

        let mut group = Vec::with_capacity(24);
        group.extend_from_slice(&0_u64.to_le_bytes());
        group.extend_from_slice(&objectid::FIRST_CHUNK_TREE.to_le_bytes());
        group.extend_from_slice(&flags.to_le_bytes());
        self.accounting
            .set_group_item(
                &self.volume,
                &mut self.trees,
                &mut self.space,
                Key::new(logical, item_type::BLOCK_GROUP_ITEM, chunk_size),
                Some(&group),
            )
            .await?;

        if flags & SYSTEM != 0 {
            self.image.append_system_chunk(chunk_key, &chunk_item)?;
        }
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
        // RAID1C3, RAID0, RAID10, RAID5, RAID6 and RAID1C4.
        for profile in [1 << 9, 1 << 3, 1 << 6, 1 << 7, 1 << 8, 1 << 10] {
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
