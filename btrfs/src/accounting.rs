//! Extent-tree edits owned by the enclosing filesystem transaction. These edits
//! change references, never allocator availability: committed blocks stay pinned
//! until publication and the last reader of their generation have completed.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::Key;
use crate::allocation::{AllocationDefect, MetadataExtent, MetadataReference};
use crate::ondisk::item_type;
use crate::source::BlockSource;
use crate::space::{MetadataReservation, Space};
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
    registered: BTreeMap<u64, MetadataReservation>,
}

impl Accounting {
    pub(crate) fn new(root: TreeRoot, nodesize: u64) -> Self {
        Self {
            root,
            nodesize,
            registered: BTreeMap::new(),
        }
    }

    /// Reconcile transaction-owned allocations, including blocks allocated by
    /// these extent-tree edits. Private tree blocks keep their addresses, so
    /// further passes are needed only for structural changes and first keys.
    /// An error aborts the enclosing transaction, like any other tree edit.
    pub(crate) async fn sync_metadata<S: BlockSource>(
        &mut self,
        volume: &Volume<S>,
        trees: &mut Trees,
        space: &mut Space,
    ) -> Result<(), WriteError> {
        // BTRFS_FEATURE_INCOMPAT_SKINNY_METADATA, from btrfs.h.
        let skinny = volume.superblock().incompat_flags() & (1 << 8) != 0;
        loop {
            let current: BTreeMap<_, _> = space.metadata().collect();
            let removed: Vec<_> = self
                .registered
                .iter()
                .filter(|(address, _)| !current.contains_key(address))
                .map(|(&address, &record)| (address, record))
                .collect();
            let changed: Vec<_> = current
                .iter()
                .filter(|(address, record)| self.registered.get(address) != Some(record))
                .map(|(&address, &record)| (address, record))
                .collect();
            if removed.is_empty() && changed.is_empty() {
                return Ok(());
            }
            for (address, record) in removed {
                let extent = metadata_extent(trees.generation(), record, skinny);
                self.root = trees
                    .apply(
                        volume,
                        self.root,
                        extent.key(address, self.nodesize),
                        None,
                        space,
                    )
                    .await?;
                self.registered.remove(&address);
            }
            for (address, record) in changed {
                let extent = metadata_extent(trees.generation(), record, skinny);
                let key = extent.key(address, self.nodesize);
                if let Some(&old) = self.registered.get(&address) {
                    let old_key = metadata_extent(trees.generation(), old, skinny)
                        .key(address, self.nodesize);
                    if old_key != key {
                        self.root = trees.apply(volume, self.root, old_key, None, space).await?;
                    }
                }
                self.root = trees
                    .apply(volume, self.root, key, Some(&extent.encode()), space)
                    .await?;
                self.registered.insert(address, record);
            }
        }
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

fn metadata_extent(generation: u64, record: MetadataReservation, skinny: bool) -> MetadataExtent {
    MetadataExtent::new(
        generation,
        record.tree,
        record.level,
        (!skinny).then_some(record.first),
    )
}
