//! File data mutations. Sector windows preserve partial overwrites, and all
//! reads resolve against this transaction's inode, extent and checksum roots.

use alloc::vec;
use alloc::vec::Vec;
use core::{num::NonZeroUsize, ops::Range};
use zerocopy::{FromZeros, IntoBytes};

use super::Transaction;
use super::namespace::{check_flags, time};
use crate::accounting::DataWrite;
use crate::allocation::data::DataReference;
use crate::compress::write::{Encoder, Plain};
use crate::items::{
    ExtentData, FileExtent, INODE_APPEND, INODE_IMMUTABLE, INODE_NODATASUM, Metadata,
};
use crate::ondisk::{
    MAX_COMPRESSED_EXTENT, RawFileExtentBody, RawFileExtentHead, RawHeader, RawInodeItem, RawItem,
    RawTimespec, item_type, view,
};
use crate::source::BlockSink;
use crate::space::{DATA, SpaceError};
use crate::tree::write::WriteError;
use crate::{Compression, Error, FileKind, Key, Timestamp};

const HEAD_BYTES: usize = size_of::<RawFileExtentHead>();
const REGULAR_BYTES: usize = HEAD_BYTES + size_of::<RawFileExtentBody>();

/// `BTRFS_DEFAULT_MAX_INLINE`, 2048 bytes in `fs/btrfs/fs.h`: the default of
/// Linux's `max_inline` mount option.
pub const DEFAULT_MAX_INLINE: u64 = 2048;

/// What a data mutation is written with: the caller's time, I/O concurrency,
/// encoder and inline limit.
pub struct WriteOptions<E> {
    pub when: Timestamp,
    pub concurrency: NonZeroUsize,
    pub encoder: E,
    /// Linux's `max_inline` mount option: the most bytes a file's data, as
    /// stored (compressed when it compresses), may keep inline in its
    /// metadata item. Zero stores nothing inline.
    pub max_inline: u64,
}

impl WriteOptions<Plain> {
    /// Uncompressed, under Linux's default inline limit.
    pub fn plain(when: Timestamp, concurrency: NonZeroUsize) -> Self {
        Self {
            when,
            concurrency,
            encoder: Plain,
            max_inline: DEFAULT_MAX_INLINE,
        }
    }
}

/// Refuses an encoder that compresses for an inode without checksums: Linux
/// never compresses a `NODATASUM` inode's data.
pub(super) fn check_encoder<E: Encoder>(flags: u64) -> Result<(), WriteError> {
    if flags & INODE_NODATASUM != 0 && E::ALGORITHM.is_some() {
        return Err(WriteError::CompressionWithoutChecksums);
    }
    Ok(())
}

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

/// An inline file extent item: its head, then `data`, which holds `size`
/// bytes of the file, compressed with `algorithm`.
fn inline_item(generation: u64, size: u64, algorithm: Option<Compression>, data: &[u8]) -> Vec<u8> {
    let mut head = RawFileExtentHead::new_zeroed();
    head.generation.set(generation);
    head.ram_bytes.set(size);
    head.compression = compression_code(algorithm);
    let mut item = Vec::with_capacity(HEAD_BYTES + data.len());
    item.extend_from_slice(head.as_bytes());
    item.extend_from_slice(data);
    item
}

/// The ram size of a validated file extent item that is inline.
pub(super) fn inline_ram_bytes(item: &[u8]) -> Option<u64> {
    let head = view::<RawFileExtentHead>(item).expect("validated extent");
    (head.extent_type == 0).then_some(head.ram_bytes.get())
}

pub(super) fn aligned_end(end: u64, sector: u64) -> Result<u64, WriteError> {
    Ok(end
        .checked_add(sector - 1)
        .ok_or(WriteError::FileOverflow)?
        / sector
        * sector)
}

impl<S: BlockSink> Transaction<S> {
    pub(crate) async fn write_file<E: Encoder>(
        &mut self,
        tree: u64,
        inode: u64,
        offset: u64,
        data: &[u8],
        mut options: WriteOptions<E>,
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
        let when = time(tree, inode, options.when)?;
        check_encoder::<E>(metadata.flags)?;
        let root = self.roots.get(tree)?;
        if data.is_empty() {
            return Ok(0);
        }
        let mut end = offset
            .checked_add(data.len() as u64)
            .ok_or(WriteError::FileOverflow)?;
        let mut size = metadata.size.max(end);
        let sector = u64::from(self.volume.superblock().sectorsize());
        let rounded_end = aligned_end(end, sector)?;
        let first_key = Key::new(inode, item_type::EXTENT_DATA, 0);
        let first = self.trees.ceiling(&self.volume, root, first_key).await?;
        let first = first.filter(|(key, _)| key.is(inode, item_type::EXTENT_DATA));
        let inline = if let Some((key, bytes)) = &first {
            FileExtent::parse(*key, bytes, sector as u32).map_err(|defect| Error::Item {
                tree,
                key: *key,
                defect,
            })?;
            inline_ram_bytes(bytes)
        } else {
            None
        };
        // A file whose every byte lies in its first sector, held inline or
        // not yet stored at all, is written as that one sector, as Linux's
        // writeback of block 0 is (`btrfs_run_delalloc_range`).
        if (inline.is_some() || first.is_none()) && size <= sector {
            let mut content = vec![0; size as usize];
            self.read_file(tree, inode, 0, &mut content).await?;
            content[offset as usize..end as usize].copy_from_slice(data);
            self.store_first_sector(tree, inode, content, inline, &mut raw, &mut options)
                .await?;
        } else {
            if let Some(inline_bytes) = inline {
                self.promote_inline(
                    tree,
                    inode,
                    inline_bytes,
                    offset..end,
                    &mut raw,
                    &mut options,
                )
                .await?;
            }
            let start = offset - offset % sector;
            if inline.is_none()
                && offset > metadata.size
                && metadata.size % sector != 0
                && metadata.size - metadata.size % sector < start
            {
                self.zero_tail(tree, inode, metadata.size, &mut raw, &mut options)
                    .await?;
            }
            let mut position = start;
            while position < rounded_end {
                // A window the free ranges cannot hold shrinks to the largest
                // range there is; each pass writes at least one sector.
                let length = match self
                    .fit_data_window((rounded_end - position).min(MAX_COMPRESSED_EXTENT))
                    .await
                {
                    Ok(length) => length,
                    // Out of space after the first window: a short write, as
                    // write(2) reports it. Only a write that stores nothing
                    // fails.
                    Err(WriteError::Space(SpaceError::Exhausted { flags: DATA, .. }))
                        if position > offset =>
                    {
                        end = position;
                        size = metadata.size.max(end);
                        break;
                    }
                    Err(error) => return Err(error),
                };
                let mut window = vec![0; length as usize];
                self.read_file(tree, inode, position, &mut window).await?;
                let from = offset.max(position);
                let to = end.min(position + length);
                window[(from - position) as usize..(to - position) as usize]
                    .copy_from_slice(&data[(from - offset) as usize..(to - offset) as usize]);
                self.replace_chunk(tree, inode, position, &window, &mut raw, &mut options)
                    .await?;
                position += length;
            }
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

    pub(crate) async fn truncate_file<E: Encoder>(
        &mut self,
        tree: u64,
        inode: u64,
        size: u64,
        mut options: WriteOptions<E>,
    ) -> Result<(), WriteError> {
        let (mut raw, metadata) = self.file_inode(tree, inode).await?;
        check_flags(tree, inode, metadata.flags, INODE_IMMUTABLE | INODE_APPEND)?;
        check_encoder::<E>(metadata.flags)?;
        let when = time(tree, inode, options.when)?;
        let sector = u64::from(self.volume.superblock().sectorsize());
        let end = aligned_end(size, sector)?;
        let root = self.roots.get(tree)?;
        let key = Key::new(inode, item_type::EXTENT_DATA, 0);
        let first = self.trees.get(&self.volume, root, key).await?;
        let inline = if let Some(bytes) = &first {
            let extent = FileExtent::parse(key, bytes, sector as u32)
                .map_err(|defect| Error::Item { tree, key, defect })?;
            inline_ram_bytes(bytes).map(|ram_bytes| {
                let compressed = matches!(
                    extent.data,
                    ExtentData::Inline {
                        compression: Some(_),
                        ..
                    }
                );
                (ram_bytes, compressed)
            })
        } else {
            None
        };
        if let Some((inline_bytes, compressed)) = inline
            && size != metadata.size
        {
            let retained = size.min(metadata.size);
            if size == 0 {
                self.remove_first_item(tree, inode, inline_bytes, &mut raw)
                    .await?;
            } else if size < metadata.size && !compressed {
                // `btrfs_truncate_inode_items` shrinks an uncompressed inline
                // item in place.
                let mut item = vec![0; HEAD_BYTES + size as usize];
                self.read_file(tree, inode, 0, &mut item[HEAD_BYTES..])
                    .await?;
                let mut head = RawFileExtentHead::new_zeroed();
                head.generation.set(self.trees.generation());
                head.ram_bytes.set(size);
                item[..HEAD_BYTES].copy_from_slice(head.as_bytes());
                let root = self
                    .trees
                    .apply(&self.volume, root, key, Some(&item), &mut self.space)
                    .await?;
                self.roots.set(root)?;
                raw.nbytes.set(
                    raw.nbytes
                        .get()
                        .checked_sub(inline_bytes)
                        .and_then(|bytes| bytes.checked_add(size))
                        .ok_or(WriteError::FileOverflow)?,
                );
            } else {
                // A compressed item cannot be cut (`BTRFS_NEED_TRUNCATE_BLOCK`),
                // and growth zeroes the old tail (`btrfs_cont_expand`): either
                // way Linux dirties the first sector, and its writeback stores
                // the file's first `size` bytes afresh.
                let stored = if size <= sector {
                    size
                } else {
                    aligned_end(retained, sector)?
                };
                let mut content = vec![0; stored as usize];
                self.read_file(tree, inode, 0, &mut content[..retained as usize])
                    .await?;
                if size <= sector {
                    self.store_first_sector(
                        tree,
                        inode,
                        content,
                        Some(inline_bytes),
                        &mut raw,
                        &mut options,
                    )
                    .await?;
                } else {
                    self.remove_first_item(tree, inode, inline_bytes, &mut raw)
                        .await?;
                    self.replace_chunk(tree, inode, 0, &content, &mut raw, &mut options)
                        .await?;
                }
            }
        } else if inline.is_none() && size != metadata.size && size.min(metadata.size) % sector != 0
        {
            self.zero_tail(tree, inode, size.min(metadata.size), &mut raw, &mut options)
                .await?;
        }
        if size <= metadata.size {
            // Preallocation can extend beyond i_size. Remove every later mapping.
            let removed = self
                .remove_regular_range(tree, inode, end..u64::MAX - u64::MAX % sector)
                .await?;
            raw.nbytes.set(
                raw.nbytes
                    .get()
                    .checked_sub(removed)
                    .ok_or(WriteError::FileOverflow)?,
            );
        } else if self.volume.superblock().incompat_flags() & (1 << 9) == 0
            && (inline.is_none() || size > sector)
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
    /// allocation only after the final mapping reference has been removed.
    pub(super) async fn remove_inode(&mut self, tree: u64, inode: u64) -> Result<(), WriteError> {
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

    pub(super) async fn promote_inline<E: Encoder>(
        &mut self,
        tree: u64,
        inode: u64,
        inline_bytes: u64,
        overwritten: Range<u64>,
        raw: &mut RawInodeItem,
        options: &mut WriteOptions<E>,
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
        self.remove_first_item(tree, inode, inline_bytes, raw)
            .await?;
        if !preserved.is_empty() {
            self.replace_chunk(tree, inode, 0, &preserved, raw, options)
                .await?;
        }
        Ok(())
    }

    /// Removes the inline item holding the file's `inline_bytes` bytes.
    pub(super) async fn remove_first_item(
        &mut self,
        tree: u64,
        inode: u64,
        inline_bytes: u64,
        raw: &mut RawInodeItem,
    ) -> Result<(), WriteError> {
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
        Ok(())
    }

    /// `can_cow_file_range_inline` in Linux's `fs/btrfs/inode.c`: whether a
    /// file of `size` bytes, all of them, may be one inline item that stores
    /// `stored` bytes (their compressed length, or `size` uncompressed) under
    /// `BTRFS_MAX_INLINE_DATA_SIZE` (`fs/btrfs/ctree.h`) and the `max_inline`
    /// mount option. Linux's `PAGE_SIZE` bound is its page cache's, which this
    /// writer does not have.
    pub(super) fn may_inline(&self, size: u64, stored: u64, max_inline: u64) -> bool {
        let superblock = self.volume.superblock();
        let sector = u64::from(superblock.sectorsize());
        // `BTRFS_MAX_INLINE_DATA_SIZE`: a leaf's largest item, less the
        // file extent head the data follows.
        let max_data = u64::from(superblock.nodesize())
            - (size_of::<RawHeader>() + size_of::<RawItem>() + HEAD_BYTES) as u64;
        size <= sector && stored < sector && stored <= max_data && stored <= max_inline
    }

    /// Stores `content`, every byte of a file that ends within its first
    /// sector, as Linux's writeback of that sector does
    /// (`run_delalloc_inline`): compressed when the encoder saves space, inline
    /// when [`Self::may_inline`] allows the stored length, and otherwise as a
    /// one-sector regular extent. `inline` is the ram size of the inline item
    /// it replaces.
    async fn store_first_sector<E: Encoder>(
        &mut self,
        tree: u64,
        inode: u64,
        mut content: Vec<u8>,
        inline: Option<u64>,
        raw: &mut RawInodeItem,
        options: &mut WriteOptions<E>,
    ) -> Result<(), WriteError> {
        let size = content.len() as u64;
        let sector = u64::from(self.volume.superblock().sectorsize());
        let generation = self.trees.generation();
        let max_inline = options.max_inline;
        // Compression that saves space decides alone: a compressed length
        // too large to inline sends the sector to a regular extent, never to
        // an uncompressed inline item.
        let item = if let Some(encoded) = options.encoder.encode(&content, sector as usize)?
            && (encoded.bytes.len() as u64) < size
        {
            self.may_inline(size, encoded.bytes.len() as u64, max_inline)
                .then(|| {
                    self.image.enable_compression(encoded.algorithm);
                    inline_item(generation, size, Some(encoded.algorithm), encoded.bytes)
                })
        } else {
            self.may_inline(size, size, max_inline)
                .then(|| inline_item(generation, size, None, &content))
        };
        if let Some(item) = item {
            let root = self.roots.get(tree)?;
            let root = self
                .trees
                .apply(
                    &self.volume,
                    root,
                    Key::new(inode, item_type::EXTENT_DATA, 0),
                    Some(&item),
                    &mut self.space,
                )
                .await?;
            self.roots.set(root)?;
            raw.nbytes.set(
                raw.nbytes
                    .get()
                    .checked_sub(inline.unwrap_or(0))
                    .and_then(|bytes| bytes.checked_add(size))
                    .ok_or(WriteError::FileOverflow)?,
            );
        } else {
            if let Some(inline_bytes) = inline {
                self.remove_first_item(tree, inode, inline_bytes, raw)
                    .await?;
            }
            content.resize(sector as usize, 0);
            self.replace_chunk(tree, inode, 0, &content, raw, options)
                .await?;
        }
        Ok(())
    }

    pub(super) async fn zero_tail<E: Encoder>(
        &mut self,
        tree: u64,
        inode: u64,
        boundary: u64,
        raw: &mut RawInodeItem,
        options: &mut WriteOptions<E>,
    ) -> Result<(), WriteError> {
        let sector = u64::from(self.volume.superblock().sectorsize());
        if boundary.is_multiple_of(sector) {
            return Ok(());
        }
        let start = boundary - boundary % sector;
        let root = self.roots.get(tree)?;
        // Sparse and preallocated tails already read as zeroes.
        if let Some((key, bytes)) = self
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
            if extent.end > start && matches!(extent.data, crate::items::ExtentData::Regular { .. })
            {
                let mut payload = vec![0; sector as usize];
                self.read_file(
                    tree,
                    inode,
                    start,
                    &mut payload[..(boundary - start) as usize],
                )
                .await?;
                self.replace_chunk(tree, inode, start, &payload, raw, options)
                    .await?;
            }
        }
        Ok(())
    }

    async fn replace_chunk<E: Encoder>(
        &mut self,
        tree: u64,
        inode: u64,
        offset: u64,
        bytes: &[u8],
        raw: &mut RawInodeItem,
        options: &mut WriteOptions<E>,
    ) -> Result<(), WriteError> {
        let length = bytes.len() as u64;
        let sector = u64::from(self.volume.superblock().sectorsize());
        let encoded = options.encoder.encode(bytes, sector as usize)?;
        let (stored, algorithm) = if let Some(encoded) = encoded
            && aligned_end(encoded.bytes.len() as u64, sector)? < length
        {
            encoded
                .bytes
                .resize(aligned_end(encoded.bytes.len() as u64, sector)? as usize, 0);
            self.image.enable_compression(encoded.algorithm);
            (encoded.bytes.as_slice(), Some(encoded.algorithm))
        } else {
            (bytes, None)
        };

        let removed = self
            .remove_regular_range(tree, inode, offset..offset + length)
            .await?;
        self.ensure_data(stored.len() as u64).await?;
        let allocation = self
            .accounting
            .stage_data(
                &self.volume,
                &mut self.trees,
                &mut self.space,
                DataWrite {
                    bytes: stored,
                    reference: DataReference {
                        root: tree,
                        inode,
                        offset,
                    },
                    checksummed: raw.flags.get() & INODE_NODATASUM == 0,
                },
                options.concurrency,
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
