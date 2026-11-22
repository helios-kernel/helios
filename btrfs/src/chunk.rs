//! The logical address space: chunks, and the device ranges behind them.

use alloc::vec::Vec;

use arrayvec::ArrayVec;

use crate::error::{ChunkDefect, Error};
use crate::key::Key;
use crate::ondisk::{
    RawChunk, RawKey, RawStripe, STRIPE_LEN, SYS_CHUNK_ARRAY_OFFSET, item_type, objectid, view,
};
use crate::superblock::Superblock;

const BLOCK_GROUP_DATA: u64 = 1 << 0;
const BLOCK_GROUP_SYSTEM: u64 = 1 << 1;
const BLOCK_GROUP_METADATA: u64 = 1 << 2;
const BLOCK_GROUP_RAID1: u64 = 1 << 4;
const BLOCK_GROUP_DUP: u64 = 1 << 5;

/// Profiles that spread a chunk over several devices, or remap it, and
/// their names. `dup`, two copies on one device, is supported on one or more
/// devices; `raid1`, two copies across two devices, is supported when more
/// than one device is attached.
const UNSUPPORTED_PROFILES: [(u64, &str); 7] = [
    (1 << 3, "raid0"),
    (1 << 6, "raid10"),
    (1 << 7, "raid5"),
    (1 << 8, "raid6"),
    (1 << 9, "raid1c3"),
    (1 << 10, "raid1c4"),
    (1 << 11, "remapped"),
];

/// Copies a chunk keeps: one for `single`, two for `dup` or `raid1`.
pub(crate) const MAX_COPIES: usize = 2;

/// One physical stripe of a chunk: which device and byte offset hold that copy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Stripe {
    pub(crate) devid: u64,
    pub(crate) offset: u64,
}

/// Why a chunk record was not accepted.
enum ChunkRefusal {
    Defect(ChunkDefect),
    Profile(&'static str),
}

impl From<ChunkDefect> for ChunkRefusal {
    fn from(defect: ChunkDefect) -> Self {
        Self::Defect(defect)
    }
}

/// One chunk: a logical range and the device offsets holding each copy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Chunk {
    logical: u64,
    length: u64,
    flags: u64,
    copies: ArrayVec<Stripe, MAX_COPIES>,
}

impl Chunk {
    /// Parses and validates the chunk at the head of `bytes`, keyed `key`.
    /// Returns the chunk and the bytes it occupied.
    fn parse(
        key: Key,
        bytes: &[u8],
        superblock: &Superblock,
        device_sizes: &[(u64, u64)],
    ) -> Result<(Self, usize), ChunkRefusal> {
        if !key.is(objectid::FIRST_CHUNK_TREE, item_type::CHUNK_ITEM) {
            return Err(ChunkDefect::Key.into());
        }
        let logical = key.offset;
        let raw: &RawChunk = view(bytes).ok_or(ChunkDefect::Truncated)?;
        let stripes = raw.num_stripes.get();
        let consumed = size_of::<RawChunk>() + usize::from(stripes) * size_of::<RawStripe>();
        if bytes.len() < consumed {
            return Err(ChunkDefect::Truncated.into());
        }

        let sector = u64::from(superblock.sectorsize());
        let length = raw.length.get();
        if length == 0 || !length.is_multiple_of(sector) {
            return Err(ChunkDefect::Length(length).into());
        }
        if !logical.is_multiple_of(sector) {
            return Err(ChunkDefect::LogicalAlignment.into());
        }
        if logical.checked_add(length).is_none() {
            return Err(ChunkDefect::Overflow.into());
        }
        if raw.stripe_len.get() != STRIPE_LEN {
            return Err(ChunkDefect::StripeLength(raw.stripe_len.get()).into());
        }

        let chunk_type = raw.chunk_type.get();
        let kinds = chunk_type & (BLOCK_GROUP_DATA | BLOCK_GROUP_SYSTEM | BLOCK_GROUP_METADATA);
        let mixed = BLOCK_GROUP_DATA | BLOCK_GROUP_METADATA;
        let kind_valid = kinds == BLOCK_GROUP_DATA
            || kinds == BLOCK_GROUP_SYSTEM
            || kinds == BLOCK_GROUP_METADATA
            || kinds == mixed;
        if !kind_valid {
            return Err(ChunkDefect::Kind(chunk_type).into());
        }
        if let Some((_, profile)) = UNSUPPORTED_PROFILES
            .iter()
            .find(|(bit, _)| chunk_type & bit != 0)
        {
            return Err(ChunkRefusal::Profile(profile));
        }
        if chunk_type & BLOCK_GROUP_RAID1 != 0 && device_sizes.len() < 2 {
            return Err(ChunkRefusal::Profile("raid1"));
        }
        let copies_expected = if chunk_type & (BLOCK_GROUP_DUP | BLOCK_GROUP_RAID1) != 0 {
            2
        } else {
            1
        };
        if stripes != copies_expected {
            return Err(ChunkDefect::StripeCount {
                chunk_type,
                stripes,
            }
            .into());
        }

        let mut copies = ArrayVec::new();
        let stripe_bytes = &bytes[size_of::<RawChunk>()..consumed];
        for stripe in stripe_bytes.as_chunks::<{ size_of::<RawStripe>() }>().0 {
            let stripe: &RawStripe = view(stripe).ok_or(ChunkDefect::Truncated)?;
            let devid = stripe.devid.get();
            let Some(&(_, dev_bytes)) = device_sizes.iter().find(|&&(id, _)| id == devid) else {
                return Err(ChunkDefect::Device(devid).into());
            };
            let physical = stripe.offset.get();
            let in_device = physical
                .checked_add(length)
                .is_some_and(|end| end <= dev_bytes);
            if !physical.is_multiple_of(sector) || !in_device {
                return Err(ChunkDefect::Stripe(physical).into());
            }
            copies.push(Stripe {
                devid,
                offset: physical,
            });
        }
        Ok((
            Self {
                logical,
                length,
                flags: chunk_type,
                copies,
            },
            consumed,
        ))
    }

    #[cfg(feature = "write")]
    pub(crate) fn logical(&self) -> u64 {
        self.logical
    }

    #[cfg(feature = "write")]
    pub(crate) fn length(&self) -> u64 {
        self.length
    }

    #[cfg(feature = "write")]
    pub(crate) fn flags(&self) -> u64 {
        self.flags
    }

    fn end(&self) -> u64 {
        // `parse` refused a range that overflows.
        self.logical + self.length
    }

    /// Where each copy starts on its device.
    #[cfg(feature = "write")]
    pub(crate) fn copies(&self) -> &[Stripe] {
        &self.copies
    }

    /// A chunk the writer allocated. The caller has placed every copy inside
    /// its device and chosen a length the sector size divides.
    #[cfg(feature = "write")]
    pub(crate) fn allocated(
        logical: u64,
        length: u64,
        flags: u64,
        copies: ArrayVec<Stripe, MAX_COPIES>,
    ) -> Self {
        Self {
            logical,
            length,
            flags,
            copies,
        }
    }
}

/// The whole logical-to-physical map of a single-device filesystem.
///
/// Built once at mount and never changed afterwards, so lookups take no
/// lock and run on any number of processors at once.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct ChunkMap {
    /// Sorted by logical start, non-overlapping.
    chunks: Vec<Chunk>,
}

impl ChunkMap {
    /// The bootstrap map: the chunks the superblock carries so that the
    /// chunk tree itself can be read.
    pub(crate) fn from_sys_chunk_array(
        superblock: &Superblock,
        superblock_bytes: &[u8],
        device_sizes: &[(u64, u64)],
    ) -> Result<Self, Error> {
        let array = &superblock_bytes[SYS_CHUNK_ARRAY_OFFSET..][..superblock.sys_chunk_array_len()];
        let mut map = Self::default();
        let mut offset = 0;
        while offset < array.len() {
            let rest = &array[offset..];
            let refused = |refusal| match refusal {
                ChunkRefusal::Defect(defect) => Error::SysChunkArray { offset, defect },
                ChunkRefusal::Profile(profile) => Error::UnsupportedProfile {
                    logical: view::<RawKey>(rest).map_or(0, |key| key.offset.get()),
                    profile,
                },
            };
            let raw_key: &RawKey = view(rest).ok_or(refused(ChunkDefect::Truncated.into()))?;
            let key = Key::from_raw(raw_key);
            let (chunk, consumed) =
                Chunk::parse(key, &rest[size_of::<RawKey>()..], superblock, device_sizes)
                    .map_err(refused)?;
            map.insert(chunk).map_err(|defect| refused(defect.into()))?;
            offset += size_of::<RawKey>() + consumed;
        }
        Ok(map)
    }

    /// Adds a chunk item from the chunk tree, which presents them in
    /// ascending logical order.
    pub(crate) fn insert_item(
        &mut self,
        key: Key,
        item: &[u8],
        superblock: &Superblock,
        device_sizes: &[(u64, u64)],
    ) -> Result<(), Error> {
        let logical = key.offset;
        let refused = |refusal| match refusal {
            ChunkRefusal::Defect(defect) => Error::Chunk { logical, defect },
            ChunkRefusal::Profile(profile) => Error::UnsupportedProfile { logical, profile },
        };
        let (chunk, _) = Chunk::parse(key, item, superblock, device_sizes).map_err(refused)?;
        self.insert(chunk).map_err(|defect| refused(defect.into()))
    }

    /// Every chunk in ascending logical order.
    #[cfg(feature = "write")]
    pub(crate) fn chunks(&self) -> &[Chunk] {
        &self.chunks
    }

    /// Where the next chunk starts: the end of the last one, as
    /// `find_next_chunk` in Linux's volumes.c.
    #[cfg(feature = "write")]
    pub(crate) fn next_logical(&self) -> u64 {
        self.chunks.last().map_or(0, Chunk::end)
    }

    /// Forgets the chunk starting at `logical` and returns it
    /// (`btrfs_remove_chunk` removes the mapping the same way).
    #[cfg(feature = "write")]
    pub(crate) fn remove(&mut self, logical: u64) -> Option<Chunk> {
        let index = self
            .chunks
            .binary_search_by_key(&logical, |chunk| chunk.logical)
            .ok()?;
        Some(self.chunks.remove(index))
    }

    pub(crate) fn insert(&mut self, chunk: Chunk) -> Result<(), ChunkDefect> {
        if let Some(last) = self.chunks.last()
            && chunk.logical < last.end()
        {
            return Err(ChunkDefect::Overlap);
        }
        self.chunks.push(chunk);
        Ok(())
    }

    /// Checks that every bootstrap chunk appears in this map, the one the
    /// chunk tree describes, with the same range and copies.
    pub(crate) fn check_contains(&self, bootstrap: &Self) -> Result<(), Error> {
        for chunk in &bootstrap.chunks {
            if self.find(chunk.logical) != Some(chunk) {
                return Err(Error::Chunk {
                    logical: chunk.logical,
                    defect: ChunkDefect::Mismatch,
                });
            }
        }
        Ok(())
    }

    fn find(&self, logical: u64) -> Option<&Chunk> {
        let index = self.chunks.partition_point(|chunk| chunk.end() <= logical);
        self.chunks
            .get(index)
            .filter(|chunk| chunk.logical <= logical)
    }

    /// The on-disk block-group geometry must agree with its chunk item.
    #[cfg(feature = "write")]
    pub(crate) fn matches_group(&self, logical: u64, length: u64, flags: u64) -> bool {
        self.find(logical).is_some_and(|chunk| {
            chunk.logical == logical && chunk.length == length && chunk.flags == flags
        })
    }

    /// Logical ranges whose physical copies intersect a superblock stripe.
    /// Btrfs reserves the whole 64 KiB stripe, not just the 4 KiB superblock.
    #[cfg(feature = "write")]
    pub(crate) fn superblock_stripes(&self) -> Vec<core::ops::Range<u64>> {
        let mut ranges = Vec::new();
        for chunk in &self.chunks {
            for &stripe in &chunk.copies {
                let physical = stripe.offset;
                for mirror in crate::superblock::MIRROR_OFFSETS {
                    let start = (mirror / STRIPE_LEN * STRIPE_LEN).max(physical);
                    let end = (mirror / STRIPE_LEN * STRIPE_LEN + STRIPE_LEN)
                        .min(physical + chunk.length);
                    if start < end {
                        ranges
                            .push(chunk.logical + start - physical..chunk.logical + end - physical);
                    }
                }
            }
        }
        ranges
    }

    /// Logical bytes of existing `DATA` chunks masked out by superblock mirror
    /// stripes (`superblock_stripes` restricted to chunks carrying
    /// `BLOCK_GROUP_DATA`).
    #[cfg(feature = "write")]
    pub(crate) fn data_superblock_stripe_bytes(&self) -> u64 {
        let mut excluded = 0_u64;
        for chunk in &self.chunks {
            if chunk.flags & BLOCK_GROUP_DATA == 0 {
                continue;
            }
            for &stripe in &chunk.copies {
                let physical = stripe.offset;
                for mirror in crate::superblock::MIRROR_OFFSETS {
                    let start = (mirror / STRIPE_LEN * STRIPE_LEN).max(physical);
                    let end = (mirror / STRIPE_LEN * STRIPE_LEN + STRIPE_LEN)
                        .min(physical + chunk.length);
                    if start < end {
                        excluded = excluded.saturating_add(end - start);
                    }
                }
            }
        }
        excluded
    }

    /// Unallocated device space available for new data chunks, matching
    /// Linux's `btrfs_calc_avail_data_space` (`fs/btrfs/super.c`): device bytes
    /// past `BTRFS_DEVICE_RANGE_RESERVED` (1 MiB) not claimed by any chunk,
    /// divided by the data profile's copy count and rounded down to
    /// `STRIPE_LEN`, minus any superblock mirror stripe in the unallocated
    /// region.
    #[cfg(feature = "write")]
    pub(crate) fn unallocated_data_bytes(&self, total_bytes: u64, dup: bool) -> u64 {
        const DEVICE_RANGE_RESERVED: u64 = 1 << 20;
        let used_device: u64 = self
            .chunks
            .iter()
            .map(|chunk| chunk.length.saturating_mul(chunk.copies.len() as u64))
            .sum();
        let unallocated = total_bytes
            .saturating_sub(DEVICE_RANGE_RESERVED)
            .saturating_sub(used_device);
        let copies = if dup { 2 } else { 1 };
        let mut available = (unallocated / copies) / STRIPE_LEN * STRIPE_LEN;
        for mirror in crate::superblock::MIRROR_OFFSETS {
            let stripe_start = mirror / STRIPE_LEN * STRIPE_LEN;
            let stripe_end = stripe_start + STRIPE_LEN;
            if stripe_start < DEVICE_RANGE_RESERVED || stripe_end > total_bytes {
                continue;
            }
            let covered = self.chunks.iter().any(|chunk| {
                chunk.copies.iter().any(|stripe| {
                    stripe.offset <= stripe_start && stripe_end <= stripe.offset + chunk.length
                })
            });
            if !covered {
                available = available.saturating_sub(STRIPE_LEN);
            }
        }
        available
    }

    /// The device and byte offset of every copy of `[logical, logical + len)`,
    /// which must lie inside one chunk.
    pub(crate) fn map(
        &self,
        logical: u64,
        len: u64,
    ) -> Result<ArrayVec<Stripe, MAX_COPIES>, Error> {
        let unmapped = Error::Unmapped { logical, len };
        let chunk = self.find(logical).ok_or(unmapped)?;
        let end = logical.checked_add(len).ok_or(unmapped)?;
        if end > chunk.end() {
            return Err(unmapped);
        }
        let delta = logical - chunk.logical;
        Ok(chunk
            .copies
            .iter()
            .map(|stripe| Stripe {
                devid: stripe.devid,
                offset: stripe.offset + delta,
            })
            .collect())
    }
}
