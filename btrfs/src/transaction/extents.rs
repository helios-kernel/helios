//! File mapping edits preserve the original allocation when splitting an
//! uncompressed, compressed or preallocated extent. The reference identity
//! uses file offset minus extent offset, so both retained halves share it.

use core::ops::Range;

use arrayvec::ArrayVec;
use zerocopy::IntoBytes;

use super::Transaction;
use crate::accounting::DataChange;
use crate::allocation::data::DataReference;
use crate::items::FileExtent;
use crate::ondisk::{RawFileExtentBody, RawFileExtentHead, item_type, view};
use crate::source::BlockSink;
use crate::tree::write::WriteError;
use crate::{Error, Key};

const HEAD_BYTES: usize = size_of::<RawFileExtentHead>();
const ITEM_BYTES: usize = HEAD_BYTES + size_of::<RawFileExtentBody>();

#[derive(Clone, Copy)]
pub(super) struct Mapping {
    pub(super) key: Key,
    pub(super) head: RawFileExtentHead,
    pub(super) body: RawFileExtentBody,
}

impl Mapping {
    pub(super) fn parse(
        tree: u64,
        key: Key,
        bytes: &[u8],
        sector: u32,
    ) -> Result<Self, WriteError> {
        FileExtent::parse(key, bytes, sector).map_err(|defect| Error::Item {
            tree,
            key,
            defect,
        })?;
        let head = *view::<RawFileExtentHead>(bytes).expect("validated file extent header");
        if key.item_type != item_type::EXTENT_DATA || head.extent_type == 0 {
            return Err(WriteError::NotRegularExtent { key });
        }
        Ok(Self {
            key,
            head,
            body: *view::<RawFileExtentBody>(&bytes[HEAD_BYTES..]).expect("validated extent body"),
        })
    }

    pub(super) fn slice(self, range: Range<u64>) -> Self {
        let mut part = self;
        part.key.offset = range.start;
        let offset = if self.body.disk_bytenr.get() == 0 {
            0
        } else {
            self.body.offset.get() + (range.start - self.key.offset)
        };
        part.body.offset.set(offset);
        part.body.num_bytes.set(range.end - range.start);
        part
    }

    pub(super) fn encode(&self) -> [u8; ITEM_BYTES] {
        let mut bytes = [0; ITEM_BYTES];
        bytes[..HEAD_BYTES].copy_from_slice(self.head.as_bytes());
        bytes[HEAD_BYTES..].copy_from_slice(self.body.as_bytes());
        bytes
    }
}

impl<S: BlockSink> Transaction<'_, S> {
    /// Cut an aligned range from one regular/preallocated file mapping. Returns
    /// the logical allocated bytes removed for the enclosing inode update.
    /// Inline contents are converted by the file writer before this operation.
    pub(crate) async fn cut_regular_extent(
        &mut self,
        tree: u64,
        key: Key,
        range: Range<u64>,
    ) -> Result<u64, WriteError> {
        let sector = u64::from(self.volume.superblock().sectorsize());
        if range.start >= range.end
            || !range.start.is_multiple_of(sector)
            || !range.end.is_multiple_of(sector)
        {
            return Err(WriteError::FileRange {
                start: range.start,
                end: range.end,
                sector,
            });
        }
        let root = self.roots.get(tree)?;
        let bytes = self
            .trees
            .get(&self.volume, root, key)
            .await?
            .ok_or(WriteError::NotRegularExtent { key })?;
        let mapping = Mapping::parse(tree, key, &bytes, sector as u32)?;
        let extent = key.offset..key.offset + mapping.body.num_bytes.get();
        let removed = range.start.max(extent.start)..range.end.min(extent.end);
        if removed.start >= removed.end {
            return Ok(0);
        }
        let mut retained = ArrayVec::<Mapping, 2>::new();
        if extent.start < removed.start {
            retained.push(mapping.slice(extent.start..removed.start));
        }
        if removed.end < extent.end {
            retained.push(mapping.slice(removed.end..extent.end));
        }
        let mut root = self
            .trees
            .apply(&self.volume, root, key, None, &mut self.space)
            .await?;
        for part in &retained {
            root = self
                .trees
                .apply(
                    &self.volume,
                    root,
                    part.key,
                    Some(&part.encode()),
                    &mut self.space,
                )
                .await?;
        }
        self.roots.set(root)?;
        // CoW may acquire this tree's implicit data reference or convert the
        // old shared leaf to parent references. Finish that before changing
        // the number of file items referencing the allocation.
        self.accounting
            .sync_references(&self.volume, &mut self.trees, &mut self.space)
            .await?;
        if mapping.body.disk_bytenr.get() == 0 {
            return Ok(0);
        }
        let change = DataChange {
            key: Key::new(
                mapping.body.disk_bytenr.get(),
                item_type::EXTENT_ITEM,
                mapping.body.disk_num_bytes.get(),
            ),
            reference: DataReference {
                root: tree,
                inode: key.objectid,
                offset: key.offset.wrapping_sub(mapping.body.offset.get()),
            },
            delta: retained.len() as i64 - 1,
        };
        self.accounting
            .update_data(&self.volume, &mut self.trees, &mut self.space, change)
            .await?;
        Ok(removed.end - removed.start)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use btrfs_disk::items::{CompressionType, FileExtentBody, FileExtentItem};

    #[test]
    fn slices_preserve_hole_encoding_and_support_high_file_offsets() {
        // A two-sector extent four sectors below the address-space limit.
        let start = u64::MAX - 16383;
        for (address, length, offset, expected) in [(0, 0, 0, 0), (4096, 65536, 32768, 36864)] {
            let bytes = FileExtentItem::to_bytes_regular(
                1,
                65536,
                CompressionType::None,
                false,
                address,
                length,
                offset,
                8192,
            );
            let key = Key::new(257, item_type::EXTENT_DATA, start);
            FileExtent::parse(key, &bytes, 4096).unwrap();
            let mapping = Mapping {
                key,
                head: *view(&bytes).unwrap(),
                body: *view(&bytes[HEAD_BYTES..]).unwrap(),
            };
            let part = mapping.slice(start + 4096..start + 8192);
            let encoded = part.encode();
            FileExtent::parse(part.key, &encoded, 4096).unwrap();
            let FileExtentBody::Regular {
                disk_bytenr,
                offset,
                num_bytes,
                ..
            } = FileExtentItem::parse(&encoded).unwrap().body
            else {
                panic!("regular mapping")
            };
            assert_eq!((disk_bytenr, offset, num_bytes), (address, expected, 4096));
        }
    }
}
