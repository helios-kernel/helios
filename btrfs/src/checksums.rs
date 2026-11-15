//! Transaction-owned checksum-tree edits. A checksum item can cover several
//! allocations; deleting one allocation preserves both neighboring ranges.

use alloc::vec::Vec;
use core::ops::Range;

use crate::Key;
use crate::ondisk::{RawHeader, RawItem, item_type, objectid};
use crate::source::BlockSource;
use crate::space::Space;
use crate::tree::TreeRoot;
use crate::tree::write::{Trees, WriteError};
use crate::volume::Volume;

pub(crate) struct Checksums {
    pub(crate) root: TreeRoot,
}

impl Checksums {
    /// Store checksums of complete on-disk sectors, including any compressed
    /// extent padding. The caller stages those same bytes before publication.
    pub(crate) async fn set<S: BlockSource>(
        &mut self,
        volume: &Volume<S>,
        trees: &mut Trees,
        space: &mut Space,
        logical: u64,
        data: &[u8],
    ) -> Result<(), WriteError> {
        let sector = volume.superblock().sectorsize() as usize;
        let algorithm = volume.superblock().csum_type();
        let end = logical
            .checked_add(data.len() as u64)
            .ok_or(WriteError::Checksum { key: key(logical) })?;
        self.remove(volume, trees, space, logical..end).await?;
        let per_item = (volume.superblock().nodesize() as usize
            - size_of::<RawHeader>()
            - size_of::<RawItem>())
            / algorithm.size();
        for (index, chunk) in data.chunks(per_item * sector).enumerate() {
            let mut bytes = Vec::with_capacity(chunk.len() / sector * algorithm.size());
            for sector in chunk.chunks_exact(sector) {
                bytes.extend_from_slice(algorithm.digest(sector).as_bytes());
            }
            let start = logical + (index * per_item * sector) as u64;
            self.root = trees
                .apply(volume, self.root, key(start), Some(&bytes), space)
                .await?;
        }
        Ok(())
    }

    /// Missing checksums are legal for preallocated or NODATASUM extents.
    /// Any failure aborts the transaction, including its earlier tree edits.
    pub(crate) async fn remove<S: BlockSource>(
        &mut self,
        volume: &Volume<S>,
        trees: &mut Trees,
        space: &mut Space,
        range: Range<u64>,
    ) -> Result<(), WriteError> {
        let sector = u64::from(volume.superblock().sectorsize());
        let digest = volume.superblock().csum_type().size();
        let first = key(range.start);
        if range.start >= range.end
            || !range.start.is_multiple_of(sector)
            || !range.end.is_multiple_of(sector)
        {
            return Err(WriteError::Checksum { key: first });
        }
        let mut current = trees
            .floor(volume, self.root, first)
            .await?
            .filter(|(key, _)| key.is(objectid::EXTENT_CSUM, item_type::EXTENT_CSUM));
        if current.is_none() {
            current = trees.ceiling(volume, self.root, first).await?;
        }
        while let Some((item, bytes)) = current {
            if !item.is(objectid::EXTENT_CSUM, item_type::EXTENT_CSUM) || item.offset >= range.end {
                break;
            }
            let error = || WriteError::Checksum { key: item };
            if bytes.is_empty()
                || !bytes.len().is_multiple_of(digest)
                || !item.offset.is_multiple_of(sector)
            {
                return Err(error());
            }
            let length = (bytes.len() / digest) as u64;
            let end = length
                .checked_mul(sector)
                .and_then(|length| item.offset.checked_add(length))
                .ok_or_else(error)?;
            let next = trees
                .ceiling(volume, self.root, key(item.offset + 1))
                .await?;
            if next.as_ref().is_some_and(|(key, _)| {
                key.is(objectid::EXTENT_CSUM, item_type::EXTENT_CSUM) && key.offset < end
            }) {
                return Err(error());
            }
            if end > range.start {
                let start = range.start.max(item.offset);
                let stop = range.end.min(end);
                let prefix = ((start - item.offset) / sector) as usize * digest;
                let suffix = ((stop - item.offset) / sector) as usize * digest;
                self.root = trees
                    .apply(
                        volume,
                        self.root,
                        item,
                        (prefix != 0).then_some(&bytes[..prefix]),
                        space,
                    )
                    .await?;
                if suffix < bytes.len() {
                    self.root = trees
                        .apply(volume, self.root, key(stop), Some(&bytes[suffix..]), space)
                        .await?;
                }
            }
            current = next;
        }
        Ok(())
    }
}

pub(crate) fn key(logical: u64) -> Key {
    Key::new(objectid::EXTENT_CSUM, item_type::EXTENT_CSUM, logical)
}
