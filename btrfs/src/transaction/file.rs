//! File data mutations. A write dirties the sectors it covers, as Linux's
//! buffered write copies into the page cache; writeback (`writeback`) later
//! gives the dirty runs their extents. Partial sectors keep their other
//! bytes, and all reads resolve against this transaction's dirty pages and
//! its inode, extent and checksum roots.

use alloc::sync::Arc;
use alloc::vec;
use core::{num::NonZeroUsize, ops::Range};
use zerocopy::{FromZeros, IntoBytes};

use super::Transaction;
use super::namespace::{check_flags, time};
use super::reflink::FileId;
use super::reserve::Units;
use crate::accounting::DataWrite;
use crate::allocation::data::DataReference;
use crate::compress::policy::{Compressor, inode_compresses};
use crate::delalloc::Page;
use crate::items::{FileExtent, INODE_APPEND, INODE_IMMUTABLE, INODE_NODATASUM, Metadata};
use crate::ondisk::{
    RawFileExtentBody, RawFileExtentHead, RawHeader, RawInodeItem, RawItem, RawTimespec, item_type,
    view,
};
use crate::source::BlockSink;
use crate::space::{DATA, SpaceError};
use crate::tree::write::WriteError;
use crate::{Compression, Error, FileKind, Key, Timestamp};

const HEAD_BYTES: usize = size_of::<RawFileExtentHead>();
const REGULAR_BYTES: usize = HEAD_BYTES + size_of::<RawFileExtentBody>();

fn compression_code(algorithm: Option<Compression>) -> u8 {
    match algorithm {
        None => 0,
        Some(Compression::Zlib) => 1,
        Some(Compression::Lzo) => 2,
        Some(Compression::Zstd) => 3,
    }
}

fn regular(
    generation: u64,
    address: u64,
    disk_length: u64,
    length: u64,
    algorithm: Option<Compression>,
) -> [u8; REGULAR_BYTES] {
    let mut head = RawFileExtentHead::new_zeroed();
    head.generation.set(generation);
    head.ram_bytes.set(length);
    head.compression = compression_code(algorithm);
    head.extent_type = 1; // BTRFS_FILE_EXTENT_REG.
    let mut body = RawFileExtentBody::new_zeroed();
    body.disk_bytenr.set(address);
    body.disk_num_bytes.set(disk_length);
    body.num_bytes.set(length);
    let mut bytes = [0; REGULAR_BYTES];
    bytes[..HEAD_BYTES].copy_from_slice(head.as_bytes());
    bytes[HEAD_BYTES..].copy_from_slice(body.as_bytes());
    bytes
}

pub(super) fn aligned_end(end: u64, sector: u64) -> Result<u64, WriteError> {
    Ok(end
        .checked_add(sector - 1)
        .ok_or(WriteError::FileOverflow)?
        / sector
        * sector)
}

/// What a file's first extent says about where its data lives.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum FirstExtent {
    /// The file has no extent.
    None,
    /// An inline extent holds the whole file, these many bytes of it.
    Inline(u64),
    /// The file's data is in regular, preallocated or hole extents.
    Regular,
}

/// A new data extent writeback inserts: `stored` lands on disk, and the
/// extent maps `length` bytes of the file at `offset`.
pub(super) struct NewExtent<'a> {
    pub(super) offset: u64,
    pub(super) length: u64,
    pub(super) stored: &'a [&'a [u8]],
    pub(super) algorithm: Option<Compression>,
}

impl<S: BlockSink> Transaction<S> {
    /// Writes `data` at `offset` and returns the bytes stored: fewer than
    /// `data.len()` only when the data space ran out partway, never zero for
    /// a nonempty write, which fails instead. A file small enough to be
    /// inline is written inline at once; any other write dirties pages.
    pub(crate) async fn write_file(
        &mut self,
        tree: u64,
        inode: u64,
        offset: u64,
        data: &[u8],
        when: Timestamp,
        compressor: &mut Compressor,
    ) -> Result<usize, WriteError> {
        let (mut raw, metadata) = self.file_inode(tree, inode).await?;
        check_flags(
            tree,
            inode,
            metadata.flags,
            INODE_IMMUTABLE
                | if offset == metadata.size {
                    0
                } else {
                    INODE_APPEND
                },
        )?;
        let when = time(tree, inode, when)?;
        let root = self.roots.get(tree)?;
        if data.is_empty() {
            return Ok(0);
        }
        let mut end = offset
            .checked_add(data.len() as u64)
            .ok_or(WriteError::FileOverflow)?;
        let mut size = metadata.size.max(end);
        let sector = u64::from(self.volume.superblock().sectorsize());
        let first_key = Key::new(inode, item_type::EXTENT_DATA, 0);
        let first = self.first_extent(tree, inode).await?;
        let inline = match first {
            FirstExtent::Inline(bytes) => Some(bytes),
            FirstExtent::None | FirstExtent::Regular => None,
        };
        if self.writes_inline(first, size) {
            let mut payload = vec![0; HEAD_BYTES + size as usize];
            self.read_file(tree, inode, 0, &mut payload[HEAD_BYTES..])
                .await?;
            payload[HEAD_BYTES + offset as usize..HEAD_BYTES + end as usize].copy_from_slice(data);
            let mut head = RawFileExtentHead::new_zeroed();
            head.generation.set(self.trees.generation());
            head.ram_bytes.set(size);
            if inode_compresses(metadata.flags)
                && let Some(encoded) = compressor.encode(&payload[HEAD_BYTES..], sector as usize)?
                && encoded.bytes.len() < size as usize
            {
                head.compression = compression_code(Some(encoded.algorithm));
                self.image.enable_compression(encoded.algorithm);
                payload.truncate(HEAD_BYTES);
                payload.extend_from_slice(encoded.bytes);
            }
            payload[..HEAD_BYTES].copy_from_slice(head.as_bytes());
            let root = self
                .trees
                .apply(
                    &self.volume,
                    root,
                    first_key,
                    Some(&payload),
                    &mut self.space,
                )
                .await?;
            self.roots.set(root)?;
            // The inline item holds the whole file now, the dirty page it
            // was read from included.
            self.delalloc.remove_file(tree, inode);
            raw.nbytes.set(
                raw.nbytes
                    .get()
                    .checked_sub(inline.unwrap_or(0))
                    .and_then(|bytes| bytes.checked_add(size))
                    .ok_or(WriteError::FileOverflow)?,
            );
        } else {
            if let Some(inline_bytes) = inline {
                self.promote_inline(tree, inode, inline_bytes, offset..end, &mut raw)
                    .await?;
            }
            let start = offset - offset % sector;
            if inline.is_none()
                && offset > metadata.size
                && metadata.size % sector != 0
                && metadata.size - metadata.size % sector < start
            {
                self.zero_tail(tree, inode, metadata.size, &raw).await?;
            }
            end = self
                .dirty_range(tree, inode, raw.flags.get(), offset, data)
                .await?;
            size = metadata.size.max(end);
            // Without NO_HOLES, absent mappings inside i_size need explicit
            // hole items. Existing allocations (including prealloc) stay intact.
            if self.volume.superblock().incompat_flags() & (1 << 9) == 0 && offset > metadata.size {
                self.fill_holes(tree, inode, aligned_end(metadata.size, sector)?..start)
                    .await?;
            }
        }
        raw.size.set(size);
        self.store_file_inode(tree, inode, raw, when).await?;
        Ok((end - offset) as usize)
    }

    /// The file's first extent.
    pub(super) async fn first_extent(
        &self,
        tree: u64,
        inode: u64,
    ) -> Result<FirstExtent, WriteError> {
        let root = self.roots.get(tree)?;
        let first_key = Key::new(inode, item_type::EXTENT_DATA, 0);
        let first = self.trees.ceiling(&self.volume, root, first_key).await?;
        let Some((key, bytes)) = first.filter(|(key, _)| key.is(inode, item_type::EXTENT_DATA))
        else {
            return Ok(FirstExtent::None);
        };
        let sector = self.volume.superblock().sectorsize();
        FileExtent::parse(key, &bytes, sector).map_err(|defect| Error::Item {
            tree,
            key,
            defect,
        })?;
        let head = view::<RawFileExtentHead>(&bytes).expect("validated extent");
        Ok(if head.extent_type == 0 {
            FirstExtent::Inline(head.ram_bytes.get())
        } else {
            FirstExtent::Regular
        })
    }

    /// Whether a write that leaves a file whose first extent is `first` at
    /// `size` bytes stores it inline.
    fn writes_inline(&self, first: FirstExtent, size: u64) -> bool {
        first != FirstExtent::Regular && size <= self.inline_limit()
    }

    /// The data space a write of `length` bytes at `offset` dirties, as the
    /// write decides it: nothing for a file it stores inline, else the
    /// sectors it covers that are not dirty yet, and the pages of a promoted
    /// inline extent or of a zeroed tail.
    pub(crate) async fn write_reservation(
        &self,
        file: FileId,
        offset: u64,
        length: u64,
    ) -> Result<u64, WriteError> {
        if length == 0 {
            return Ok(0);
        }
        let (_, metadata) = self.file_inode(file.tree, file.inode).await?;
        let first = self.first_extent(file.tree, file.inode).await?;
        let end = offset.saturating_add(length);
        if self.writes_inline(first, metadata.size.max(end)) {
            return Ok(0);
        }
        let sector = u64::from(self.volume.superblock().sectorsize());
        let start = offset - offset % sector;
        let rounded = end.saturating_add(sector - 1) / sector * sector;
        let dirty = self
            .delalloc
            .file(file.tree, file.inode)
            .map_or(0, |dirty| dirty.bytes_in(start..rounded));
        let besides = match first {
            FirstExtent::Inline(_) => aligned_end(metadata.size, sector)?,
            _ if offset > metadata.size && !metadata.size.is_multiple_of(sector) => sector,
            _ => 0,
        };
        Ok(rounded - start - dirty + besides)
    }

    /// Metadata units a write of `length` bytes at `offset` needs beyond what
    /// the running transaction's existing dirty data already reserved: the
    /// immediate tree edits of `write_file` plus the growth of `delalloc`'s
    /// extent, checksum-leaf and inode-update reservations.
    pub(crate) async fn write_units(
        &self,
        file: FileId,
        offset: u64,
        length: u64,
    ) -> Result<Units, WriteError> {
        if length == 0 {
            return Ok(Units::default());
        }
        let (_, metadata) = self.file_inode(file.tree, file.inode).await?;
        let first = self.first_extent(file.tree, file.inode).await?;
        let end = offset.saturating_add(length);
        if self.writes_inline(first, metadata.size.max(end)) {
            return Ok(Units {
                insert: 1,
                update: 1,
                frees: false,
            });
        }
        let sector = u64::from(self.volume.superblock().sectorsize());
        let start = offset - offset % sector;
        let rounded = end.saturating_add(sector - 1) / sector * sector;
        let inline = matches!(first, FirstExtent::Inline(_));
        let tail = !inline
            && offset > metadata.size
            && !metadata.size.is_multiple_of(sector)
            && metadata.size - metadata.size % sector < start;
        let holes =
            self.volume.superblock().incompat_flags() & (1 << 9) == 0 && offset > metadata.size;
        let (delta_items, delta_inodes) = self.delalloc.reservation_delta(
            (file.tree, file.inode),
            metadata.flags,
            start..rounded,
            inline || tail,
        );
        Ok(Units {
            insert: u64::from(inline) + u64::from(holes) + delta_items,
            update: 1 + delta_inodes,
            frees: false,
        })
    }

    /// The data space truncating to `size` dirties: the inline data it moves
    /// into pages, or the sector it zeroes past the new or old end.
    pub(crate) async fn truncate_reservation(
        &self,
        file: FileId,
        size: u64,
    ) -> Result<u64, WriteError> {
        let (_, metadata) = self.file_inode(file.tree, file.inode).await?;
        let sector = u64::from(self.volume.superblock().sectorsize());
        Ok(match self.first_extent(file.tree, file.inode).await? {
            FirstExtent::Inline(_) if size == 0 || size <= self.inline_limit() => 0,
            FirstExtent::Inline(_) => aligned_end(size.min(metadata.size), sector)?,
            _ if size != metadata.size && !size.min(metadata.size).is_multiple_of(sector) => sector,
            _ => 0,
        })
    }

    /// The data space cloning into `destination` at `offset` dirties: its
    /// promoted inline data or zeroed tail, and an inline source's
    /// `length` bytes, which the clone copies.
    pub(crate) async fn clone_reservation(
        &self,
        source: FileId,
        destination: FileId,
        offset: u64,
        length: u64,
    ) -> Result<u64, WriteError> {
        let (_, metadata) = self.file_inode(destination.tree, destination.inode).await?;
        let sector = u64::from(self.volume.superblock().sectorsize());
        let mut bytes = match self
            .first_extent(destination.tree, destination.inode)
            .await?
        {
            FirstExtent::Inline(_) => aligned_end(metadata.size, sector)?,
            _ if offset > metadata.size && !metadata.size.is_multiple_of(sector) => sector,
            _ => 0,
        };
        if let FirstExtent::Inline(_) = self.first_extent(source.tree, source.inode).await? {
            bytes += aligned_end(length, sector)?;
        }
        Ok(bytes)
    }

    /// The largest file an inline extent holds: a sector, and what a leaf
    /// has room for beside its header.
    fn inline_limit(&self) -> u64 {
        let sector = u64::from(self.volume.superblock().sectorsize());
        sector.min(
            u64::from(self.volume.superblock().nodesize())
                - (size_of::<RawHeader>() + size_of::<RawItem>() + HEAD_BYTES) as u64,
        )
    }

    /// Dirties the sectors that `data` at `offset` covers, as a buffered
    /// write copies into the page cache (`btrfs_buffered_write`): a sector
    /// `data` covers only partly keeps the rest of its current contents.
    /// Each newly dirty sector takes its data space from
    /// [`Self::data_budget`], as `btrfs_check_data_free_space` reserves it,
    /// so writeback never runs out. Returns where the stored prefix ends:
    /// short when the budget runs out partway, as write(2) reports, and an
    /// error when not even the first sector fits.
    pub(super) async fn dirty_range(
        &mut self,
        tree: u64,
        inode: u64,
        flags: u64,
        offset: u64,
        data: &[u8],
    ) -> Result<u64, WriteError> {
        let sector = u64::from(self.volume.superblock().sectorsize());
        let end = offset + data.len() as u64;
        let free_data = self.space.totals(DATA).1;
        let mixed = self.mixed();
        let mut position = offset - offset % sector;
        while position < end {
            let fresh = !self.delalloc.is_dirty(tree, inode, position);
            if fresh {
                let reserved = self.delalloc.bytes()
                    + sector
                    + if mixed {
                        // Leave room for the inode update that follows, and for
                        // the extra extent and checksum leaf this page may add.
                        self.needed(Units {
                            insert: 2,
                            update: 1,
                            frees: false,
                        })
                    } else {
                        0
                    };
                if reserved > free_data {
                    if position > offset {
                        return Ok(position);
                    }
                    return Err(SpaceError::Exhausted {
                        bytes: sector,
                        flags: DATA,
                    }
                    .into());
                }
            }
            let from = offset.max(position);
            let to = end.min(position + sector);
            let covered = &data[(from - offset) as usize..(to - offset) as usize];
            let page: Page = if covered.len() as u64 == sector {
                Arc::from(covered)
            } else {
                let mut page = vec![0; sector as usize];
                self.read_file(tree, inode, position, &mut page).await?;
                page[(from - position) as usize..(to - position) as usize].copy_from_slice(covered);
                Arc::from(page)
            };
            self.delalloc.insert((tree, inode), flags, position, page);
            position += sector;
        }
        Ok(end)
    }

    async fn dirty_exact(
        &mut self,
        tree: u64,
        inode: u64,
        flags: u64,
        offset: u64,
        data: &[u8],
    ) -> Result<(), WriteError> {
        let stored = self.dirty_range(tree, inode, flags, offset, data).await?;
        if stored < offset + data.len() as u64 {
            return Err(SpaceError::Exhausted {
                bytes: u64::from(self.volume.superblock().sectorsize()),
                flags: DATA,
            }
            .into());
        }
        Ok(())
    }

    pub(crate) async fn truncate_file(
        &mut self,
        tree: u64,
        inode: u64,
        size: u64,
        when: Timestamp,
    ) -> Result<(), WriteError> {
        let (mut raw, metadata) = self.file_inode(tree, inode).await?;
        check_flags(tree, inode, metadata.flags, INODE_IMMUTABLE | INODE_APPEND)?;
        let when = time(tree, inode, when)?;
        let sector = u64::from(self.volume.superblock().sectorsize());
        let end = aligned_end(size, sector)?;
        let root = self.roots.get(tree)?;
        let key = Key::new(inode, item_type::EXTENT_DATA, 0);
        let first = self.trees.get(&self.volume, root, key).await?;
        let inline = if let Some(bytes) = &first {
            FileExtent::parse(key, bytes, sector as u32).map_err(|defect| Error::Item {
                tree,
                key,
                defect,
            })?;
            let head = view::<RawFileExtentHead>(bytes).expect("validated extent");
            (head.extent_type == 0).then_some(head.ram_bytes.get())
        } else {
            None
        };
        if let Some(inline_bytes) = inline {
            let retained = size.min(metadata.size);
            let mut payload = vec![0; retained as usize];
            self.read_file(tree, inode, 0, &mut payload).await?;
            let root = self
                .trees
                .apply(&self.volume, root, key, None, &mut self.space)
                .await?;
            self.roots.set(root)?;
            raw.nbytes.set(
                raw.nbytes
                    .get()
                    .checked_sub(inline_bytes)
                    .ok_or(WriteError::FileOverflow)?,
            );
            if size != 0 && size <= self.inline_limit() {
                let mut bytes = vec![0; HEAD_BYTES + size as usize];
                let mut head = RawFileExtentHead::new_zeroed();
                head.generation.set(self.trees.generation());
                head.ram_bytes.set(size);
                bytes[..HEAD_BYTES].copy_from_slice(head.as_bytes());
                bytes[HEAD_BYTES..HEAD_BYTES + payload.len()].copy_from_slice(&payload);
                let root = self
                    .trees
                    .apply(&self.volume, root, key, Some(&bytes), &mut self.space)
                    .await?;
                self.roots.set(root)?;
                raw.nbytes.set(
                    raw.nbytes
                        .get()
                        .checked_add(size)
                        .ok_or(WriteError::FileOverflow)?,
                );
            } else if !payload.is_empty() {
                payload.resize(aligned_end(retained, sector)? as usize, 0);
                self.dirty_exact(tree, inode, raw.flags.get(), 0, &payload)
                    .await?;
            }
        } else if size != metadata.size && size.min(metadata.size) % sector != 0 {
            self.zero_tail(tree, inode, size.min(metadata.size), &raw)
                .await?;
        }
        if size <= metadata.size {
            // Preallocation can extend beyond i_size. Remove every later mapping,
            // and the dirty pages past the new end, as `truncate_pagecache`.
            let removed = self
                .remove_regular_range(tree, inode, end..u64::MAX - u64::MAX % sector)
                .await?;
            self.delalloc.remove_range(tree, inode, end..u64::MAX);
            raw.nbytes.set(
                raw.nbytes
                    .get()
                    .checked_sub(removed)
                    .ok_or(WriteError::FileOverflow)?,
            );
        } else if self.volume.superblock().incompat_flags() & (1 << 9) == 0
            && (inline.is_none() || size > self.inline_limit())
        {
            self.fill_holes(tree, inode, aligned_end(metadata.size, sector)?..end)
                .await?;
        }
        raw.size.set(size);
        self.store_file_inode(tree, inode, raw, when).await
    }

    pub(super) async fn file_inode(
        &self,
        tree: u64,
        inode: u64,
    ) -> Result<(RawInodeItem, Metadata), WriteError> {
        let (raw, metadata) = self.inode_item(tree, inode).await?;
        if metadata.kind != FileKind::Regular {
            return Err(Error::WrongKind {
                tree,
                inode,
                expected: FileKind::Regular,
                found: metadata.kind,
            }
            .into());
        }
        Ok((raw, metadata))
    }

    /// Remove all records belonging to an unlinked inode, retiring every data
    /// allocation only after the final mapping reference has been removed,
    /// and drop its dirty data, as eviction truncates its page cache.
    pub(super) async fn remove_inode(&mut self, tree: u64, inode: u64) -> Result<(), WriteError> {
        self.delalloc.remove_file(tree, inode);
        loop {
            let root = self.roots.get(tree)?;
            let Some((key, bytes)) = self
                .trees
                .ceiling(&self.volume, root, Key::new(inode, 0, 0))
                .await?
            else {
                break;
            };
            if key.objectid != inode {
                break;
            }
            if key.item_type == item_type::EXTENT_DATA {
                let extent = FileExtent::parse(key, &bytes, self.volume.superblock().sectorsize())
                    .map_err(|defect| Error::Item { tree, key, defect })?;
                if !matches!(extent.data, crate::items::ExtentData::Inline { .. }) {
                    self.cut_regular_extent(tree, key, extent.start..extent.end)
                        .await?;
                    continue;
                }
            }
            let root = self
                .trees
                .apply(&self.volume, root, key, None, &mut self.space)
                .await?;
            self.roots.set(root)?;
        }
        Ok(())
    }

    /// Replaces the inline extent with dirty pages holding its data, unless
    /// `overwritten` covers all of it.
    pub(super) async fn promote_inline(
        &mut self,
        tree: u64,
        inode: u64,
        inline_bytes: u64,
        overwritten: Range<u64>,
        raw: &mut RawInodeItem,
    ) -> Result<(), WriteError> {
        let sector = u64::from(self.volume.superblock().sectorsize());
        // Inline data has no separately reference-counted allocation. Preserve
        // its contents before replacing its sole item with regular mappings.
        let mut preserved = if overwritten.start != 0 || overwritten.end < raw.size.get() {
            vec![0; aligned_end(raw.size.get(), sector)? as usize]
        } else {
            vec![]
        };
        if !preserved.is_empty() {
            self.read_file(tree, inode, 0, &mut preserved).await?;
        }
        let root = self.roots.get(tree)?;
        let root = self
            .trees
            .apply(
                &self.volume,
                root,
                Key::new(inode, item_type::EXTENT_DATA, 0),
                None,
                &mut self.space,
            )
            .await?;
        self.roots.set(root)?;
        raw.nbytes.set(
            raw.nbytes
                .get()
                .checked_sub(inline_bytes)
                .ok_or(WriteError::FileOverflow)?,
        );
        if !preserved.is_empty() {
            self.dirty_exact(tree, inode, raw.flags.get(), 0, &preserved)
                .await?;
        }
        Ok(())
    }

    /// Zeroes the sector holding `boundary` past it, as `btrfs_truncate_block`
    /// does to the folio there: a dirty page is rewritten, and so is a
    /// regular extent's sector, which becomes dirty.
    pub(super) async fn zero_tail(
        &mut self,
        tree: u64,
        inode: u64,
        boundary: u64,
        raw: &RawInodeItem,
    ) -> Result<(), WriteError> {
        let sector = u64::from(self.volume.superblock().sectorsize());
        if boundary.is_multiple_of(sector) {
            return Ok(());
        }
        let start = boundary - boundary % sector;
        let root = self.roots.get(tree)?;
        // Sparse and preallocated tails already read as zeroes.
        let mut stored = self.delalloc.is_dirty(tree, inode, start);
        if !stored
            && let Some((key, bytes)) = self
                .trees
                .floor(
                    &self.volume,
                    root,
                    Key::new(inode, item_type::EXTENT_DATA, start),
                )
                .await?
            && key.is(inode, item_type::EXTENT_DATA)
        {
            let extent = FileExtent::parse(key, &bytes, sector as u32)
                .map_err(|defect| Error::Item { tree, key, defect })?;
            stored = extent.end > start
                && matches!(extent.data, crate::items::ExtentData::Regular { .. });
        }
        if stored {
            let mut payload = vec![0; sector as usize];
            self.read_file(
                tree,
                inode,
                start,
                &mut payload[..(boundary - start) as usize],
            )
            .await?;
            self.dirty_exact(tree, inode, raw.flags.get(), start, &payload)
                .await?;
        }
        Ok(())
    }

    /// Maps `extent.length` bytes at `extent.offset` to a new allocation
    /// holding `extent.stored`, which the caller made room for, replacing
    /// whatever mapped them: Linux's `insert_reserved_file_extent` with the
    /// `btrfs_drop_extents` before it, once an ordered extent completes.
    pub(super) async fn insert_extent(
        &mut self,
        tree: u64,
        inode: u64,
        extent: NewExtent<'_>,
        raw: &mut RawInodeItem,
        concurrency: NonZeroUsize,
    ) -> Result<(), WriteError> {
        let NewExtent {
            offset,
            length,
            stored,
            algorithm,
        } = extent;
        if let Some(algorithm) = algorithm {
            self.image.enable_compression(algorithm);
        }
        let removed = self
            .remove_regular_range(tree, inode, offset..offset + length)
            .await?;
        let allocation = self
            .accounting
            .stage_data(
                &self.volume,
                &mut self.trees,
                &mut self.space,
                DataWrite {
                    pieces: stored,
                    reference: DataReference {
                        root: tree,
                        inode,
                        offset,
                    },
                    checksummed: raw.flags.get() & INODE_NODATASUM == 0,
                },
                concurrency,
            )
            .await?;
        let root = self.roots.get(tree)?;
        let root = self
            .trees
            .apply(
                &self.volume,
                root,
                Key::new(inode, item_type::EXTENT_DATA, offset),
                Some(&regular(
                    self.trees.generation(),
                    allocation.objectid,
                    allocation.offset,
                    length,
                    algorithm,
                )),
                &mut self.space,
            )
            .await?;
        self.roots.set(root)?;
        raw.nbytes.set(
            raw.nbytes
                .get()
                .checked_sub(removed)
                .and_then(|bytes| bytes.checked_add(length))
                .ok_or(WriteError::FileOverflow)?,
        );
        Ok(())
    }

    pub(super) async fn remove_regular_range(
        &mut self,
        tree: u64,
        inode: u64,
        range: Range<u64>,
    ) -> Result<u64, WriteError> {
        let mut next = range.start;
        let mut removed = 0_u64;
        while next < range.end {
            let root = self.roots.get(tree)?;
            let key = Key::new(inode, item_type::EXTENT_DATA, next);
            let floor = self.trees.floor(&self.volume, root, key).await?;
            let candidate = if let Some((found, bytes)) = floor
                && found.is(inode, item_type::EXTENT_DATA)
                && FileExtent::parse(found, &bytes, self.volume.superblock().sectorsize())
                    .map_err(|defect| Error::Item {
                        tree,
                        key: found,
                        defect,
                    })?
                    .end
                    > next
            {
                Some((found, bytes))
            } else {
                self.trees.ceiling(&self.volume, root, key).await?
            };
            let Some((key, bytes)) = candidate else {
                break;
            };
            if !key.is(inode, item_type::EXTENT_DATA) || key.offset >= range.end {
                break;
            }
            let extent = FileExtent::parse(key, &bytes, self.volume.superblock().sectorsize())
                .map_err(|defect| Error::Item { tree, key, defect })?;
            next = extent.end;
            removed = removed
                .checked_add(self.cut_regular_extent(tree, key, range.clone()).await?)
                .ok_or(WriteError::FileOverflow)?;
        }
        Ok(removed)
    }

    pub(super) async fn fill_holes(
        &mut self,
        tree: u64,
        inode: u64,
        range: Range<u64>,
    ) -> Result<(), WriteError> {
        let mut position = range.start;
        while position < range.end {
            let root = self.roots.get(tree)?;
            let key = Key::new(inode, item_type::EXTENT_DATA, position);
            if let Some((found, bytes)) = self.trees.floor(&self.volume, root, key).await?
                && found.is(inode, item_type::EXTENT_DATA)
            {
                let extent =
                    FileExtent::parse(found, &bytes, self.volume.superblock().sectorsize())
                        .map_err(|defect| Error::Item {
                            tree,
                            key: found,
                            defect,
                        })?;
                if extent.end > position {
                    position = extent.end;
                    continue;
                }
            }
            let next = self.trees.ceiling(&self.volume, root, key).await?;
            let end = next
                .filter(|(key, _)| key.is(inode, item_type::EXTENT_DATA))
                .map_or(range.end, |(key, _)| key.offset.min(range.end));
            let root = self
                .trees
                .apply(
                    &self.volume,
                    root,
                    key,
                    Some(&regular(
                        self.trees.generation(),
                        0,
                        0,
                        end - position,
                        None,
                    )),
                    &mut self.space,
                )
                .await?;
            self.roots.set(root)?;
            position = end;
        }
        Ok(())
    }

    pub(super) async fn store_file_inode(
        &mut self,
        tree: u64,
        inode: u64,
        mut raw: RawInodeItem,
        when: RawTimespec,
    ) -> Result<(), WriteError> {
        raw.transid.set(self.trees.generation());
        raw.sequence.set(raw.sequence.get().wrapping_add(1));
        raw.mtime = when;
        raw.ctime = when;
        self.put_inode(tree, inode, raw).await
    }
}
