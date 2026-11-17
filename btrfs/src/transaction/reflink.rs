//! Range cloning retains data allocations and adds counted target references.
//! Capture the source mappings before editing either tree: source and target may
//! be in the same inode or share a CoW leaf, even when their ranges do not overlap.

use alloc::vec;
use alloc::vec::Vec;
use core::num::NonZeroUsize;

use super::Transaction;
use super::extents::Mapping;
use super::file::{WriteOptions, aligned_end};
use super::namespace::{check_flags, time};
use crate::accounting::DataChange;
use crate::allocation::data::DataReference;
use crate::items::{ExtentData, FileExtent, INODE_APPEND, INODE_IMMUTABLE, INODE_NODATASUM};
use crate::ondisk::{MAX_COMPRESSED_EXTENT, item_type};
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
    pub(crate) async fn clone_range(
        &mut self,
        request: CloneRange,
        when: Timestamp,
        concurrency: NonZeroUsize,
    ) -> Result<(), WriteError> {
        let CloneRange {
            source,
            destination,
            source_offset,
            destination_offset,
            length,
        } = request;
        let (_, source_metadata) = self.file_inode(source.tree, source.inode).await?;
        let (mut raw, destination_metadata) =
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
                    // An inline item has no separate allocation to share. Copy
                    // bounded windows through the normal destination writer.
                    return self.clone_inline_range(request, when, concurrency).await;
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
        let mut options = WriteOptions::plain(when, concurrency);
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
                &mut options,
            )
            .await?;
        } else if destination_offset > raw.size.get() {
            self.zero_tail(
                destination.tree,
                destination.inode,
                raw.size.get(),
                &mut raw,
                &mut options,
            )
            .await?;
        }
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

    async fn clone_inline_range(
        &mut self,
        request: CloneRange,
        when: Timestamp,
        concurrency: NonZeroUsize,
    ) -> Result<(), WriteError> {
        let mut position = 0;
        while position < request.length {
            let length = (request.length - position).min(MAX_COMPRESSED_EXTENT) as usize;
            let mut bytes = vec![0; length];
            self.read_file(
                request.source.tree,
                request.source.inode,
                request.source_offset + position,
                &mut bytes,
            )
            .await?;
            self.write_file(
                request.destination.tree,
                request.destination.inode,
                request.destination_offset + position,
                &bytes,
                WriteOptions::plain(when, concurrency),
            )
            .await?;
            position += length as u64;
        }
        Ok(())
    }
}
