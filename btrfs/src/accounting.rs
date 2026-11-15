//! Extent-tree edits owned by the enclosing filesystem transaction. These edits
//! change references, never allocator availability: committed blocks stay pinned
//! until publication and the last reader of their generation have completed.

use crate::Key;
use crate::allocation::{AllocationDefect, MetadataExtent, MetadataReference};
use crate::ondisk::item_type;
use crate::source::BlockSource;
use crate::tree::TreeRoot;
use crate::tree::write::{MetadataAllocator, Trees, WriteError};
use crate::volume::Volume;

#[derive(Clone, Copy)]
pub(crate) struct MetadataBlock {
    pub(crate) address: u64,
    pub(crate) level: u8,
}

pub(crate) struct Accounting {
    pub(crate) root: TreeRoot,
    nodesize: u64,
}

impl Accounting {
    pub(crate) fn new(root: TreeRoot, nodesize: u64) -> Self {
        Self { root, nodesize }
    }

    /// Returns true only when the last reference was removed. As with any tree
    /// edit, an error aborts the enclosing transaction, including earlier edits.
    pub(crate) async fn remove_metadata<S: BlockSource, A: MetadataAllocator>(
        &mut self,
        volume: &Volume<S>,
        trees: &mut Trees,
        allocator: &mut A,
        block: MetadataBlock,
        reference: MetadataReference,
    ) -> Result<bool, WriteError> {
        let mut key = Key::new(
            block.address,
            item_type::METADATA_ITEM,
            u64::from(block.level),
        );
        let bytes = if let Some(bytes) = trees.get(volume, self.root, key).await? {
            bytes
        } else {
            // Enabling skinny metadata does not rewrite pre-existing fat items.
            key = Key::new(block.address, item_type::EXTENT_ITEM, self.nodesize);
            trees
                .get(volume, self.root, key)
                .await?
                .ok_or(WriteError::MissingExtent {
                    address: block.address,
                    level: block.level,
                })?
        };
        let defect = |defect| WriteError::Allocation { key, defect };
        let mut extent = MetadataExtent::parse(key, &bytes, self.nodesize).map_err(defect)?;
        if extent.level() != block.level {
            return Err(defect(AllocationDefect::Metadata));
        }
        let reference_key = reference.key(block.address);
        let external = trees.get(volume, self.root, reference_key).await?;
        let last = extent
            .remove(reference, external.as_deref())
            .map_err(defect)?;
        if external.is_some() {
            self.root = trees
                .apply(volume, self.root, reference_key, None, allocator)
                .await?;
        }
        let payload = (!last).then(|| extent.encode());
        self.root = trees
            .apply(volume, self.root, key, payload.as_deref(), allocator)
            .await?;
        Ok(last)
    }
}
