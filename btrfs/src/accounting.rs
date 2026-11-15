//! Extent-tree edits owned by the enclosing filesystem transaction. These edits
//! change references, never allocator availability: committed blocks stay pinned
//! until publication and the last reader of their generation have completed.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use crate::Key;
use crate::allocation::{AllocationDefect, MetadataExtent, MetadataReference};
use crate::ondisk::{item_type, objectid};
use crate::source::BlockSource;
use crate::space::{MetadataReservation, Space, SpaceDefect, SpaceError};
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
    groups: TreeRoot,
    group_used: BTreeMap<Key, u64>,
    retired_metadata: BTreeSet<u64>,
    registered: BTreeMap<u64, MetadataReservation>,
}

impl Accounting {
    pub(crate) fn new(root: TreeRoot, groups: TreeRoot, nodesize: u64) -> Self {
        Self {
            root,
            nodesize,
            groups,
            group_used: BTreeMap::new(),
            retired_metadata: BTreeSet::new(),
            registered: BTreeMap::new(),
        }
    }

    /// Reconcile transaction-owned allocations, including blocks allocated by
    /// these extent-tree edits. Private tree blocks keep their addresses, so
    /// further passes are needed only for structural changes and first keys.
    /// An error aborts the enclosing transaction, like any other tree edit.
    pub(crate) async fn sync_allocations<S: BlockSource>(
        &mut self,
        volume: &Volume<S>,
        trees: &mut Trees,
        space: &mut Space,
    ) -> Result<(), WriteError> {
        // BTRFS_FEATURE_INCOMPAT_SKINNY_METADATA, from btrfs.h.
        let skinny = volume.superblock().incompat_flags() & (1 << 8) != 0;
        loop {
            let groups_changed = self.sync_groups(volume, trees, space).await?;
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
            if removed.is_empty() && changed.is_empty() && !groups_changed {
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

    pub(crate) fn group_root(&self) -> TreeRoot {
        if self.groups.tree == objectid::EXTENT_TREE {
            self.root
        } else {
            self.groups
        }
    }

    async fn sync_groups<S: BlockSource>(
        &mut self,
        volume: &Volume<S>,
        trees: &mut Trees,
        space: &mut Space,
    ) -> Result<bool, WriteError> {
        let mut changed = false;
        for (key, used) in space.group_usage(&self.retired_metadata)? {
            if self.group_used.get(&key) == Some(&used) {
                continue;
            }
            let root = self.group_root();
            let mut bytes = trees
                .get(volume, root, key)
                .await?
                .ok_or(SpaceError::Corrupt {
                    tree: root.tree,
                    key,
                    defect: SpaceDefect::ChunkMismatch,
                })?;
            if bytes.len() < 24 {
                return Err(SpaceError::Corrupt {
                    tree: root.tree,
                    key,
                    defect: SpaceDefect::Truncated,
                }
                .into());
            }
            if u64::from_le_bytes(bytes[..8].try_into().unwrap()) != used {
                bytes[..8].copy_from_slice(&used.to_le_bytes());
                let root = trees.apply(volume, root, key, Some(&bytes), space).await?;
                if root.tree == objectid::EXTENT_TREE {
                    self.root = root;
                } else {
                    self.groups = root;
                }
                changed = true;
            }
            self.group_used.insert(key, used);
        }
        Ok(changed)
    }

    /// Removes a committed block reference. Private allocation cancellation is
    /// handled by `sync_allocations`. Returns true only for its last reference. As with any tree
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
        if last {
            self.retired_metadata.insert(block.address);
        }
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
