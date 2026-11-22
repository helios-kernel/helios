//! Range cloning retains data allocations and adds counted target references.
//! Capture the source mappings before editing either tree: source and target may
//! be in the same inode or share a CoW leaf, even when their ranges do not overlap.

use alloc::vec;
use alloc::vec::Vec;
use core::num::NonZeroUsize;
use zerocopy::FromBytes;

use super::Transaction;
use super::extents::Mapping;
use super::file::{aligned_end, inline_ram_bytes};
use super::namespace::{check_flags, time};
use crate::accounting::DataChange;
use crate::allocation::data::DataReference;
use crate::compress::policy::Compressor;
use crate::items::{ExtentData, FileExtent, INODE_APPEND, INODE_IMMUTABLE, INODE_NODATASUM};
use crate::ondisk::{MAX_COMPRESSED_EXTENT, RawFileExtentHead, item_type};
use crate::source::BlockSink;
use crate::tree::Cursor;
use crate::tree::write::WriteError;
use crate::{Error, ItemDefect, Key, Timestamp};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FileId {
    pub(crate) tree: u64,
    pub(crate) inode: u64,
}

#[derive(Clone, Copy)]
pub(crate) struct CloneRange {
    pub(crate) source: FileId,
    pub(crate) destination: FileId,
    pub(crate) source_offset: u64,
    pub(crate) destination_offset: u64,
    pub(crate) length: u64,
}

impl<S: BlockSink> Transaction<S> {
    /// Clones `request`, writing back dirty data in the source range first so
    /// its extents can be shared, and using `compressor` and `max_inline` for
    /// an inline source or inline destination data that shared extents replace.
    pub(crate) async fn clone_range(
        &mut self,
        request: CloneRange,
        when: Timestamp,
        compressor: &mut Compressor,
        concurrency: NonZeroUsize,
        max_inline: u64,
    ) -> Result<(), WriteError> {
        let CloneRange {
            source,
            destination,
            source_offset,
            destination_offset,
            length,
        } = request;
        let (_, source_metadata) = self.file_inode(source.tree, source.inode).await?;
        let (_, destination_metadata) =
            self.file_inode(destination.tree, destination.inode).await?;
        check_flags(
            destination.tree,
            destination.inode,
            destination_metadata.flags,
            INODE_IMMUTABLE | INODE_APPEND,
        )?;
        let timestamp = time(destination.tree, destination.inode, when)?;
        let source_end = source_offset
            .checked_add(length)
            .ok_or(WriteError::FileOverflow)?;
        let destination_end = destination_offset
            .checked_add(length)
            .ok_or(WriteError::FileOverflow)?;
        if source_end > source_metadata.size {
            return Err(WriteError::CloneSourceRange);
        }
        if (source_metadata.flags ^ destination_metadata.flags) & INODE_NODATASUM != 0 {
            return Err(WriteError::CloneChecksumPolicy);
        }
        let sector = u64::from(self.volume.superblock().sectorsize());
        if !source_offset.is_multiple_of(sector)
            || !destination_offset.is_multiple_of(sector)
            || (!length.is_multiple_of(sector)
                && (source_end != source_metadata.size
                    || destination_end < destination_metadata.size))
        {
            return Err(WriteError::CloneAlignment);
        }
        if length == 0 {
            return Ok(());
        }
        if source == destination
            && source_offset < destination_end
            && destination_offset < source_end
        {
            return Err(WriteError::CloneOverlap);
        }
        let source_rounded = aligned_end(source_end, sector)?;
        let destination_rounded = aligned_end(destination_end, sector)?;
        // The source range is written back before its extents are read, as
        // `btrfs_remap_file_range_prep` waits for its ordered extents
        // (`fs/btrfs/reflink.c`): dirty data has no extent to share yet.
        // Overwritten dirty pages in the destination range are dropped below
        // without allocating extents that the clone immediately replaces.
        self.writeback_range(
            source.tree,
            source.inode,
            source_offset..source_rounded,
            compressor,
            concurrency,
        )
        .await?;
        let root = self.roots.get(source.tree)?;
        let nodes = self.trees.reader(&self.volume);
        let first = Key::new(source.inode, item_type::EXTENT_DATA, 0);
        let mut cursor = Cursor::floor(
            &nodes,
            root,
            Key::new(source.inode, item_type::EXTENT_DATA, source_offset),
        )
        .await?;
        let mut mappings = Vec::new();
        let mut previous_end = 0;
        while let (Some(key), Some(bytes)) = (cursor.key(), cursor.item()) {
            if key < first {
                cursor.advance(&nodes).await?;
                continue;
            }
            if !key.is(source.inode, item_type::EXTENT_DATA) || key.offset >= source_rounded {
                break;
            }
            let extent =
                FileExtent::parse(key, bytes, sector as u32).map_err(|defect| Error::Item {
                    tree: source.tree,
                    key,
                    defect,
                })?;
            if extent.start < previous_end {
                return Err(Error::Item {
                    tree: source.tree,
                    key,
                    defect: ItemDefect::ExtentOverlap(previous_end),
                }
                .into());
            }
            previous_end = extent.end;
            if extent.end > source_offset {
                if matches!(extent.data, ExtentData::Inline { .. }) {
                    // An inline item has no separate allocation to share.
                    let item = bytes.to_vec();
                    return self
                        .clone_inline_range(request, item, when, compressor, max_inline)
                        .await;
                }
                let mapping = Mapping::parse(source.tree, key, bytes, sector as u32)?
                    .slice(extent.start.max(source_offset)..extent.end.min(source_rounded));
                mappings.push(mapping);
            }
            cursor.advance(&nodes).await?;
        }
        // Acquire target references before destination cleanup or EOF tail
        // zeroing can retire a captured source allocation (same-inode clones).
        self.accounting
            .sync_references(&self.volume, &mut self.trees, &mut self.space)
            .await?;
        for mapping in &mut mappings {
            mapping.key.objectid = destination.inode;
            mapping.key.offset = destination_offset + (mapping.key.offset - source_offset);
            mapping.head.generation.set(self.trees.generation());
            if mapping.body.disk_bytenr.get() != 0 {
                self.accounting
                    .update_data(
                        &self.volume,
                        &mut self.trees,
                        &mut self.space,
                        DataChange {
                            key: Key::new(
                                mapping.body.disk_bytenr.get(),
                                item_type::EXTENT_ITEM,
                                mapping.body.disk_num_bytes.get(),
                            ),
                            reference: DataReference {
                                root: destination.tree,
                                inode: destination.inode,
                                offset: mapping.key.offset.wrapping_sub(mapping.body.offset.get()),
                            },
                            delta: 1,
                        },
                    )
                    .await?;
            }
        }
        // Reload the destination inode after source writeback: a same-inode
        // clone updates `nbytes` on the shared inode item when writing the
        // source range back.
        let (mut raw, destination_metadata) =
            self.file_inode(destination.tree, destination.inode).await?;
        let root = self.roots.get(destination.tree)?;
        let first_key = Key::new(destination.inode, item_type::EXTENT_DATA, 0);
        let first = self.trees.get(&self.volume, root, first_key).await?;
        let inline = if let Some(bytes) = &first {
            let extent = FileExtent::parse(first_key, bytes, sector as u32).map_err(|defect| {
                Error::Item {
                    tree: destination.tree,
                    key: first_key,
                    defect,
                }
            })?;
            matches!(extent.data, ExtentData::Inline { .. }).then_some(extent.end)
        } else {
            None
        };
        if let Some(inline_bytes) = inline {
            self.promote_inline(
                destination.tree,
                destination.inode,
                inline_bytes,
                destination_offset..destination_end,
                &mut raw,
            )
            .await?;
        } else if destination_offset > raw.size.get() {
            self.zero_tail(destination.tree, destination.inode, raw.size.get(), &raw)
                .await?;
        }
        // The cloned extents replace whatever pages the destination range
        // holds, as the page cache is invalidated after the clone.
        self.delalloc.remove_range(
            destination.tree,
            destination.inode,
            destination_offset..destination_rounded,
        );
        let removed = self
            .remove_regular_range(
                destination.tree,
                destination.inode,
                destination_offset..destination_rounded,
            )
            .await?;
        raw.nbytes.set(
            raw.nbytes
                .get()
                .checked_sub(removed)
                .ok_or(WriteError::FileOverflow)?,
        );
        for mapping in mappings {
            let root = self.roots.get(destination.tree)?;
            let root = self
                .trees
                .apply(
                    &self.volume,
                    root,
                    mapping.key,
                    Some(&mapping.encode()),
                    &mut self.space,
                )
                .await?;
            self.roots.set(root)?;
            self.accounting
                .sync_references(&self.volume, &mut self.trees, &mut self.space)
                .await?;
            if mapping.body.disk_bytenr.get() != 0 {
                raw.nbytes.set(
                    raw.nbytes
                        .get()
                        .checked_add(mapping.body.num_bytes.get())
                        .ok_or(WriteError::FileOverflow)?,
                );
            }
        }
        if self.volume.superblock().incompat_flags() & (1 << 9) == 0 {
            self.fill_holes(
                destination.tree,
                destination.inode,
                destination_offset.min(aligned_end(destination_metadata.size, sector)?)
                    ..destination_rounded,
            )
            .await?;
        }
        raw.size.set(raw.size.get().max(destination_end));
        self.store_file_inode(destination.tree, destination.inode, raw, timestamp)
            .await
    }

    /// Clones a range whose source is the inline item `item`, as Linux's
    /// `clone_copy_inline_extent` (`fs/btrfs/reflink.c`): the item itself
    /// when it lands at offset 0 of a destination that holds no more than it
    /// (inline or nothing past its first sector), and otherwise its data,
    /// written into the destination as a write is.
    async fn clone_inline_range(
        &mut self,
        request: CloneRange,
        mut item: Vec<u8>,
        when: Timestamp,
        compressor: &mut Compressor,
        max_inline: u64,
    ) -> Result<(), WriteError> {
        let CloneRange {
            destination,
            destination_offset,
            length,
            ..
        } = request;
        let sector = u64::from(self.volume.superblock().sectorsize());
        let datal = inline_ram_bytes(&item).expect("the caller found an inline item");
        let (mut raw, metadata) = self.file_inode(destination.tree, destination.inode).await?;
        let root = self.roots.get(destination.tree)?;
        let first = self
            .trees
            .ceiling(
                &self.volume,
                root,
                Key::new(destination.inode, item_type::EXTENT_DATA, 0),
            )
            .await?
            .filter(|(key, _)| key.is(destination.inode, item_type::EXTENT_DATA));
        let clean_beyond_first_sector = self
            .delalloc
            .file(destination.tree, destination.inode)
            .is_none_or(|dirty| dirty.runs(sector..u64::MAX).is_empty());
        let replaced = match &first {
            None if clean_beyond_first_sector => Some(None),
            Some((key, bytes)) if key.offset == 0 && clean_beyond_first_sector => {
                FileExtent::parse(*key, bytes, sector as u32).map_err(|defect| Error::Item {
                    tree: destination.tree,
                    key: *key,
                    defect,
                })?;
                inline_ram_bytes(bytes).map(Some)
            }
            _ => None,
        };
        let stored = (item.len() - size_of::<RawFileExtentHead>()) as u64;
        if destination_offset == 0
            && metadata.size <= datal
            && length == datal
            && self.may_inline(datal, stored, max_inline)
            && let Some(replaced) = replaced
        {
            if let Some(inline_bytes) = replaced {
                self.remove_first_item(destination.tree, destination.inode, inline_bytes, &mut raw)
                    .await?;
            }
            self.delalloc
                .remove_file(destination.tree, destination.inode);
            let (head, _) =
                RawFileExtentHead::mut_from_prefix(&mut item).expect("validated extent");
            head.generation.set(self.trees.generation());
            let root = self.roots.get(destination.tree)?;
            let root = self
                .trees
                .apply(
                    &self.volume,
                    root,
                    Key::new(destination.inode, item_type::EXTENT_DATA, 0),
                    Some(&item),
                    &mut self.space,
                )
                .await?;
            self.roots.set(root)?;
            raw.nbytes.set(
                raw.nbytes
                    .get()
                    .checked_add(datal)
                    .ok_or(WriteError::FileOverflow)?,
            );
            raw.size.set(metadata.size.max(destination_offset + length));
            let when = time(destination.tree, destination.inode, when)?;
            return self
                .store_file_inode(destination.tree, destination.inode, raw, when)
                .await;
        }
        let mut position = 0;
        while position < length {
            let window = (length - position).min(MAX_COMPRESSED_EXTENT) as usize;
            let mut bytes = vec![0; window];
            self.read_file(
                request.source.tree,
                request.source.inode,
                request.source_offset + position,
                &mut bytes,
            )
            .await?;
            self.write_file(
                destination,
                destination_offset + position,
                &bytes,
                when,
                compressor,
                max_inline,
            )
            .await?;
            position += window as u64;
        }
        Ok(())
    }
}
