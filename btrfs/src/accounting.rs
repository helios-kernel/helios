//! Extent-tree edits owned by the enclosing filesystem transaction. These edits
//! change references, never allocator availability: committed blocks stay pinned
//! until publication and the last reader of their generation have completed.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::Key;
use crate::allocation::data::{DataBackref, DataDefect, DataExtent};
use crate::allocation::{AllocationDefect, MetadataExtent, MetadataReference};
use crate::free_space::FreeTree;
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

pub(crate) struct DataChange<R> {
    pub(crate) key: Key,
    pub(crate) reference: R,
    pub(crate) delta: i64,
}

pub(crate) struct Accounting {
    pub(crate) root: TreeRoot,
    nodesize: u64,
    groups: TreeRoot,
    free_space: Option<FreeTree>,
    group_used: BTreeMap<Key, u64>,
    retired_extents: BTreeMap<u64, u64>,
    registered: BTreeMap<u64, MetadataReservation>,
}

impl Accounting {
    /// Change a counted data reference. The signed delta represents file extent
    /// items, not bytes. A zero result retires the whole physical allocation;
    /// it does not make that range reusable before commit/read-side retirement.
    pub(crate) async fn update_data<S: BlockSource, R: DataBackref>(
        &mut self,
        volume: &Volume<S>,
        trees: &mut Trees,
        space: &mut Space,
        change: DataChange<R>,
    ) -> Result<bool, WriteError> {
        let DataChange {
            key,
            reference,
            delta,
        } = change;
        let defect = |defect| WriteError::Data { key, defect };
        let bytes = trees
            .get(volume, self.root, key)
            .await?
            .ok_or_else(|| defect(DataDefect::Missing))?;
        let mut extent =
            DataExtent::parse(key, &bytes, volume.superblock().sectorsize()).map_err(defect)?;
        let inline = reference.inline(&extent);
        let initial = reference.key(key.objectid);
        let mut search = initial;
        let mut vacant = initial;
        let mut external = None;
        // Deleting a colliding key can leave a hole before another matching
        // reference. Search the remaining suffix rather than stopping at holes.
        while let Some((found, bytes)) = trees.ceiling(volume, self.root, search).await? {
            if found.objectid != initial.objectid || found.item_type != initial.item_type {
                break;
            }
            if initial.item_type == item_type::SHARED_DATA_REF && found != initial {
                break;
            }
            if found == vacant {
                vacant.offset = vacant
                    .offset
                    .checked_add(1)
                    .ok_or_else(|| defect(DataDefect::Count))?;
            }
            if let Some(count) = reference.decode(&bytes).map_err(defect)?
                && external.replace((found, count)).is_some()
            {
                return Err(defect(DataDefect::Duplicate));
            }
            let Some(offset) = found.offset.checked_add(1) else {
                break;
            };
            search.offset = offset;
            if initial.item_type == item_type::SHARED_DATA_REF {
                break;
            }
        }
        if inline.is_some() && external.is_some() {
            return Err(defect(DataDefect::Duplicate));
        }
        let old = inline.or(external.map(|(_, count)| count)).unwrap_or(0);
        let inline_total: u64 = extent
            .roots
            .values()
            .chain(extent.parents.values())
            .map(|&count| u64::from(count))
            .sum();
        if inline_total + u64::from(external.map_or(0, |(_, count)| count)) > extent.refs {
            return Err(defect(DataDefect::Count));
        }
        let count = i64::from(old)
            .checked_add(delta)
            .and_then(|count| u32::try_from(count).ok())
            .ok_or_else(|| defect(DataDefect::Count))?;
        let refs = extent
            .refs
            .checked_add_signed(delta)
            .ok_or_else(|| defect(DataDefect::Count))?;
        if delta == 0 {
            return Ok(false);
        }
        if inline.is_some() {
            reference.set_inline(&mut extent, count);
        } else {
            let reference_key = external.map_or(vacant, |(key, _)| key);
            let payload = (count != 0).then(|| reference.encode(count));
            self.root = trees
                .apply(volume, self.root, reference_key, payload.as_deref(), space)
                .await?;
        }
        extent.refs = refs;
        if refs == 0 {
            let first = Key::new(key.objectid, item_type::TREE_BLOCK_REF, 0);
            if let Some((remaining, _)) = trees.ceiling(volume, self.root, first).await?
                && remaining.objectid == key.objectid
                    && remaining.item_type <= item_type::SHARED_DATA_REF
                {
                    return Err(defect(DataDefect::Count));
                }
        }
        let payload = (refs != 0).then(|| extent.encode());
        self.root = trees
            .apply(volume, self.root, key, payload.as_deref(), space)
            .await?;
        if refs == 0 {
            self.retired_extents.insert(key.objectid, key.offset);
        }
        Ok(refs == 0)
    }

    pub(crate) async fn new<S: BlockSource>(
        volume: &Volume<S>,
        root: TreeRoot,
        space: &Space,
    ) -> Result<Self, WriteError> {
        let free_space = if let Some(root) = space.free_root() {
            Some(FreeTree::load(volume, root, &space.committed_free(&BTreeMap::new())?).await?)
        } else {
            None
        };
        Ok(Self {
            root,
            nodesize: u64::from(volume.superblock().nodesize()),
            groups: space.group_root(),
            free_space,
            group_used: BTreeMap::new(),
            retired_extents: BTreeMap::new(),
            registered: BTreeMap::new(),
        })
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
            let free_changed = if let Some(free) = &mut self.free_space {
                free.sync(volume, trees, space, &self.retired_extents)
                    .await?
            } else {
                false
            };
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
            if removed.is_empty() && changed.is_empty() && !groups_changed && !free_changed {
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

    pub(crate) fn free_root(&self) -> Option<TreeRoot> {
        self.free_space.as_ref().map(|free| free.root)
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
        for (key, used) in space.group_usage(&self.retired_extents)? {
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

    /// Read the current extent record, including earlier reference edits.
    pub(crate) async fn metadata<S: BlockSource>(
        &self,
        volume: &Volume<S>,
        trees: &Trees,
        block: MetadataBlock,
    ) -> Result<(Key, MetadataExtent), WriteError> {
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
        let extent = MetadataExtent::parse(key, &bytes, self.nodesize).map_err(defect)?;
        if extent.level() != block.level {
            return Err(defect(AllocationDefect::Metadata));
        }
        Ok((key, extent))
    }

    /// Add a root or parent reference to an existing committed block. Both the
    /// count and external key live in the overlay; any failure aborts it.
    pub(crate) async fn add_metadata<S: BlockSource, A: MetadataAllocator>(
        &mut self,
        volume: &Volume<S>,
        trees: &mut Trees,
        allocator: &mut A,
        block: MetadataBlock,
        reference: MetadataReference,
    ) -> Result<(), WriteError> {
        let (key, mut extent) = self.metadata(volume, trees, block).await?;
        let reference_key = reference.key(block.address);
        let external = trees.get(volume, self.root, reference_key).await?;
        extent
            .add_external(reference, external.as_deref())
            .map_err(|defect| WriteError::Allocation { key, defect })?;
        self.root = trees
            .apply(volume, self.root, reference_key, Some(&[]), allocator)
            .await?;
        self.root = trees
            .apply(volume, self.root, key, Some(&extent.encode()), allocator)
            .await?;
        Ok(())
    }

    /// Mark a block after its outgoing references have been converted to
    /// parent references. This never edits the committed block's own header.
    pub(crate) async fn set_full_backrefs<S: BlockSource, A: MetadataAllocator>(
        &mut self,
        volume: &Volume<S>,
        trees: &mut Trees,
        allocator: &mut A,
        block: MetadataBlock,
    ) -> Result<(), WriteError> {
        let (key, mut extent) = self.metadata(volume, trees, block).await?;
        if !extent.full_backrefs() {
            extent.set_full_backrefs();
            self.root = trees
                .apply(volume, self.root, key, Some(&extent.encode()), allocator)
                .await?;
        }
        Ok(())
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
        let (key, mut extent) = self.metadata(volume, trees, block).await?;
        let defect = |defect| WriteError::Allocation { key, defect };
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
            self.retired_extents.insert(block.address, self.nodesize);
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
