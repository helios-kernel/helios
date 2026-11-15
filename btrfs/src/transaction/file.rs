//! File data mutations. Sector windows preserve partial overwrites, and all
//! reads resolve against this transaction's inode, extent and checksum roots.

use alloc::vec;
use core::{num::NonZeroUsize, ops::Range};
use zerocopy::{FromZeros, IntoBytes};

use super::Transaction;
use crate::accounting::DataWrite;
use crate::allocation::data::DataReference;
use crate::items::{FileExtent, INODE_NODATASUM, Metadata};
use crate::ondisk::{
    MAX_COMPRESSED_EXTENT, RawFileExtentBody, RawFileExtentHead, RawHeader, RawInodeItem, RawItem,
    RawTimespec, item_type, view,
};
use crate::source::BlockSink;
use crate::tree::write::WriteError;
use crate::{Error, FileKind, ItemDefect, Key, Timestamp};

const HEAD_BYTES: usize = size_of::<RawFileExtentHead>();
const REGULAR_BYTES: usize = HEAD_BYTES + size_of::<RawFileExtentBody>();

fn regular(generation: u64, address: u64, length: u64) -> [u8; REGULAR_BYTES] {
    let mut head = RawFileExtentHead::new_zeroed();
    head.generation.set(generation);
    head.ram_bytes.set(length);
    head.extent_type = 1; // BTRFS_FILE_EXTENT_REG.
    let mut body = RawFileExtentBody::new_zeroed();
    body.disk_bytenr.set(address);
    body.disk_num_bytes
        .set(if address == 0 { 0 } else { length });
    body.num_bytes.set(length);
    let mut bytes = [0; REGULAR_BYTES];
    bytes[..HEAD_BYTES].copy_from_slice(head.as_bytes());
    bytes[HEAD_BYTES..].copy_from_slice(body.as_bytes());
    bytes
}

fn aligned_end(end: u64, sector: u64) -> Result<u64, WriteError> {
    Ok(end
        .checked_add(sector - 1)
        .ok_or(WriteError::FileOverflow)?
        / sector
        * sector)
}

impl<S: BlockSink> Transaction<'_, S> {
    pub(crate) async fn write_file(
        &mut self,
        tree: u64,
        inode: u64,
        offset: u64,
        data: &[u8],
        when: Timestamp,
        concurrency: NonZeroUsize,
    ) -> Result<usize, WriteError> {
        let (mut raw, metadata) = self.file_inode(tree, inode).await?;
        let root = self.roots.get(tree)?;
        if data.is_empty() {
            return Ok(0);
        }
        let end = offset
            .checked_add(data.len() as u64)
            .ok_or(WriteError::FileOverflow)?;
        let size = metadata.size.max(end);
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
            let head = view::<RawFileExtentHead>(bytes).expect("validated extent");
            (head.extent_type == 0).then_some(head.ram_bytes.get())
        } else {
            None
        };
        let inline_limit = sector.min(
            u64::from(self.volume.superblock().nodesize())
                - (size_of::<RawHeader>() + size_of::<RawItem>() + HEAD_BYTES) as u64,
        );
        if (inline.is_some() || first.is_none()) && size <= inline_limit {
            let mut payload = vec![0; HEAD_BYTES + size as usize];
            self.read_file(tree, inode, 0, &mut payload[HEAD_BYTES..])
                .await?;
            payload[HEAD_BYTES + offset as usize..HEAD_BYTES + end as usize].copy_from_slice(data);
            let mut head = RawFileExtentHead::new_zeroed();
            head.generation.set(self.trees.generation());
            head.ram_bytes.set(size);
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
            raw.nbytes.set(
                raw.nbytes
                    .get()
                    .checked_sub(inline.unwrap_or(0))
                    .and_then(|bytes| bytes.checked_add(size))
                    .ok_or(WriteError::FileOverflow)?,
            );
        } else {
            if let Some(inline_bytes) = inline {
                // Preserve the inline payload before deleting its only mapping.
                let mut preserved = if offset != 0 || end < metadata.size {
                    vec![0; aligned_end(metadata.size, sector)? as usize]
                } else {
                    vec![]
                };
                if !preserved.is_empty() {
                    self.read_file(tree, inode, 0, &mut preserved).await?;
                }
                let root = self
                    .trees
                    .apply(&self.volume, root, first_key, None, &mut self.space)
                    .await?;
                self.roots.set(root)?;
                raw.nbytes.set(
                    raw.nbytes
                        .get()
                        .checked_sub(inline_bytes)
                        .ok_or(WriteError::FileOverflow)?,
                );
                if !preserved.is_empty() {
                    self.replace_chunk(tree, inode, 0, &preserved, &mut raw, concurrency)
                        .await?;
                }
            }
            let start = offset - offset % sector;
            if inline.is_none()
                && offset > metadata.size
                && metadata.size % sector != 0
                && metadata.size - metadata.size % sector < start
            {
                let tail = metadata.size - metadata.size % sector;
                let mut preserved = vec![0; sector as usize];
                self.read_file(tree, inode, tail, &mut preserved).await?;
                self.replace_chunk(tree, inode, tail, &preserved, &mut raw, concurrency)
                    .await?;
            }
            let mut position = start;
            while position < rounded_end {
                let length = (rounded_end - position).min(MAX_COMPRESSED_EXTENT);
                let mut window = vec![0; length as usize];
                self.read_file(tree, inode, position, &mut window).await?;
                let from = offset.max(position);
                let to = end.min(position + length);
                window[(from - position) as usize..(to - position) as usize]
                    .copy_from_slice(&data[(from - offset) as usize..(to - offset) as usize]);
                self.replace_chunk(tree, inode, position, &window, &mut raw, concurrency)
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
        Ok(data.len())
    }

    pub(crate) async fn truncate_file(
        &mut self,
        tree: u64,
        inode: u64,
        size: u64,
        when: Timestamp,
        concurrency: NonZeroUsize,
    ) -> Result<(), WriteError> {
        let (mut raw, metadata) = self.file_inode(tree, inode).await?;
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
            let inline_limit = sector.min(
                u64::from(self.volume.superblock().nodesize())
                    - (size_of::<RawHeader>() + size_of::<RawItem>() + HEAD_BYTES) as u64,
            );
            if size != 0 && size <= inline_limit {
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
                self.replace_chunk(tree, inode, 0, &payload, &mut raw, concurrency)
                    .await?;
            }
        } else if size != metadata.size && size.min(metadata.size) % sector != 0 {
            let boundary = size.min(metadata.size);
            let start = boundary - boundary % sector;
            let root = self.roots.get(tree)?;
            // A sparse tail stays sparse; a preallocated tail already reads zero.
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
                if extent.end > start
                    && matches!(extent.data, crate::items::ExtentData::Regular { .. })
                {
                    let mut payload = vec![0; sector as usize];
                    self.read_file(
                        tree,
                        inode,
                        start,
                        &mut payload[..(boundary - start) as usize],
                    )
                    .await?;
                    self.replace_chunk(tree, inode, start, &payload, &mut raw, concurrency)
                        .await?;
                }
            }
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

    async fn file_inode(
        &self,
        tree: u64,
        inode: u64,
    ) -> Result<(RawInodeItem, Metadata), WriteError> {
        let root = self.roots.get(tree)?;
        let inode_key = Key::new(inode, item_type::INODE_ITEM, 0);
        let bytes = self
            .trees
            .get(&self.volume, root, inode_key)
            .await?
            .ok_or(Error::MissingInode { tree, inode })?;
        let metadata = Metadata::parse(&bytes).map_err(|defect| Error::Item {
            tree,
            key: inode_key,
            defect,
        })?;
        if metadata.kind != FileKind::Regular {
            return Err(Error::WrongKind {
                tree,
                inode,
                expected: FileKind::Regular,
                found: metadata.kind,
            }
            .into());
        }
        Ok((
            *view::<RawInodeItem>(&bytes).expect("validated inode"),
            metadata,
        ))
    }

    async fn replace_chunk(
        &mut self,
        tree: u64,
        inode: u64,
        offset: u64,
        bytes: &[u8],
        raw: &mut RawInodeItem,
        concurrency: NonZeroUsize,
    ) -> Result<(), WriteError> {
        let length = bytes.len() as u64;
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
                    bytes,
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
                    length,
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

    async fn remove_regular_range(
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

    async fn fill_holes(
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
                    Some(&regular(self.trees.generation(), 0, end - position)),
                    &mut self.space,
                )
                .await?;
            self.roots.set(root)?;
            position = end;
        }
        Ok(())
    }

    async fn store_file_inode(
        &mut self,
        tree: u64,
        inode: u64,
        mut raw: RawInodeItem,
        when: Timestamp,
    ) -> Result<(), WriteError> {
        let key = Key::new(inode, item_type::INODE_ITEM, 0);
        if when.nanoseconds >= 1_000_000_000 {
            return Err(Error::Item {
                tree,
                key,
                defect: ItemDefect::Nanoseconds(when.nanoseconds),
            }
            .into());
        }
        raw.transid.set(self.trees.generation());
        raw.sequence.set(raw.sequence.get().wrapping_add(1));
        raw.mtime = RawTimespec {
            sec: (when.seconds as u64).into(),
            nsec: when.nanoseconds.into(),
        };
        raw.ctime = raw.mtime;
        let root = self.roots.get(tree)?;
        let root = self
            .trees
            .apply(
                &self.volume,
                root,
                key,
                Some(raw.as_bytes()),
                &mut self.space,
            )
            .await?;
        self.roots.set(root)
    }
}
