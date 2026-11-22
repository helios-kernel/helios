//! Subvolume creation, snapshots (read-only and writable), deletion, and
//! subvolume metadata / canonical path resolution.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use zerocopy::{FromZeros, IntoBytes};

use helios_hal::fs_management::SubvolumeInfo;

use super::Transaction;
use super::namespace::{Attributes, Name, check_flags, time, validate_name};
use super::ownership::S_IFDIR;
use crate::accounting::{DataChange, MetadataBlock};
use crate::allocation::MetadataReference;
use crate::allocation::data::{DataReference, SharedDataReference};
use crate::csum::name_hash;
use crate::items::{
    FileExtent, INODE_APPEND, INODE_IMMUTABLE, RecordKind, dir_index_record, dir_records,
};
use crate::ondisk::{
    RawDirItem, RawFileExtentBody, RawFileExtentHead, RawInodeItem, RawInodeRef, RawKey,
    RawRootItem, RawRootRef, RawRootTail, item_type, objectid, view,
};
use crate::source::BlockSink;
use crate::tree::Expected;
use crate::tree::write::WriteError;
use crate::{Error, FileKind, Key, Timestamp};

/// Builds a `DIR_ITEM` / `DIR_INDEX` payload linking to subvolume `tree_id`.
fn subvolume_dir_record(tree_id: u64, transid: u64, name: &[u8]) -> Vec<u8> {
    let record = RawDirItem {
        location: RawKey {
            objectid: tree_id.into(),
            item_type: item_type::ROOT_ITEM,
            offset: u64::MAX.into(),
        },
        transid: transid.into(),
        data_len: 0.into(),
        name_len: (name.len() as u16).into(),
        entry_type: 2, // BTRFS_FT_DIR
    };
    let mut bytes = Vec::from(record.as_bytes());
    bytes.extend_from_slice(name);
    bytes
}

/// Builds a `ROOT_REF` / `ROOT_BACKREF` item payload.
fn root_ref_record(dirid: u64, sequence: u64, name: &[u8]) -> Vec<u8> {
    let record = RawRootRef {
        dirid: dirid.into(),
        sequence: sequence.into(),
        name_len: (name.len() as u16).into(),
    };
    let mut bytes = Vec::from(record.as_bytes());
    bytes.extend_from_slice(name);
    bytes
}

impl<S: BlockSink> Transaction<S> {
    /// Creates a new empty subvolume linked under `parent`.
    pub(crate) async fn create_subvolume(
        &mut self,
        parent: Name<'_>,
        attributes: Attributes,
        when: Timestamp,
        new_uuid: [u8; 16],
    ) -> Result<u64, WriteError> {
        validate_name(parent.bytes)?;
        self.roots.check_writable(parent.tree)?;
        let ts = time(parent.tree, parent.parent, when)?;
        let (mut parent_dir, parent_meta) = self.inode_item(parent.tree, parent.parent).await?;
        check_flags(
            parent.tree,
            parent.parent,
            parent_meta.flags,
            INODE_IMMUTABLE,
        )?;
        if parent_meta.kind != FileKind::Directory {
            return Err(Error::WrongKind {
                tree: parent.tree,
                inode: parent.parent,
                expected: FileKind::Directory,
                found: parent_meta.kind,
            }
            .into());
        }

        let tree_id = self.roots.next_subvolume_id()?;
        let trans_gen = self.trees.generation();
        let nodesize = u64::from(self.volume.superblock().nodesize());

        // Allocate an empty root leaf for the new subvolume and populate its
        // root directory inode (256) and self `INODE_REF` ("..").
        let mut subvol_root = self
            .trees
            .create(&self.volume, self.roots.root, tree_id, &mut self.space)
            .await?;

        let mut root_inode = RawInodeItem::new_zeroed();
        root_inode.generation.set(trans_gen);
        root_inode.transid.set(trans_gen);
        root_inode.size.set(0);
        root_inode.nbytes.set(nodesize);
        root_inode.nlink.set(1);
        root_inode.uid.set(attributes.uid);
        root_inode.gid.set(attributes.gid);
        root_inode.mode.set(S_IFDIR | (attributes.mode & 0o7777));
        root_inode.atime = ts;
        root_inode.ctime = ts;
        root_inode.mtime = ts;
        root_inode.otime = ts;

        subvol_root = self
            .trees
            .apply(
                &self.volume,
                subvol_root,
                Key::new(objectid::FIRST_FREE, item_type::INODE_ITEM, 0),
                Some(root_inode.as_bytes()),
                &mut self.space,
            )
            .await?;

        let mut self_ref = Vec::from(
            RawInodeRef {
                index: 0.into(),
                name_len: 2_u16.into(),
            }
            .as_bytes(),
        );
        self_ref.extend_from_slice(b"..");
        subvol_root = self
            .trees
            .apply(
                &self.volume,
                subvol_root,
                Key::new(
                    objectid::FIRST_FREE,
                    item_type::INODE_REF,
                    objectid::FIRST_FREE,
                ),
                Some(&self_ref),
                &mut self.space,
            )
            .await?;

        // Build the new subvolume's `ROOT_ITEM` (439 bytes).
        let mut head = RawRootItem::new_zeroed();
        head.inode.generation.set(1);
        head.inode.size.set(3);
        head.inode.nlink.set(1);
        head.inode.nbytes.set(nodesize);
        head.inode.mode.set(S_IFDIR | 0o755);
        head.generation.set(trans_gen);
        head.root_dirid.set(objectid::FIRST_FREE);
        head.bytenr.set(subvol_root.bytenr);
        head.bytes_used.set(nodesize);
        head.refs.set(1);
        head.level = subvol_root.level;

        let mut tail = RawRootTail::new_zeroed();
        tail.generation_v2.set(trans_gen);
        tail.uuid = new_uuid;
        tail.ctransid.set(trans_gen);
        tail.otransid.set(trans_gen);
        tail.ctime = ts;
        tail.otime = ts;

        let mut root_bytes =
            Vec::with_capacity(size_of::<RawRootItem>() + size_of::<RawRootTail>());
        root_bytes.extend_from_slice(head.as_bytes());
        root_bytes.extend_from_slice(tail.as_bytes());

        // `initial_used = 0` because the single leaf allocated in this
        // transaction contributes `+nodesize` in `Roots::sync`.
        self.roots.insert_subvolume(
            Key::new(tree_id, item_type::ROOT_ITEM, 0),
            subvol_root,
            0,
            root_bytes,
        );

        self.link_subvolume(parent, &mut parent_dir, tree_id, ts)
            .await?;

        if let Some(quota) = &mut self.quota {
            quota.ensure_subvolume(tree_id, trans_gen);
        }
        Ok(tree_id)
    }

    /// Creates a snapshot of committed subvolume `source_tree` linked at
    /// `dest_parent`.
    ///
    /// Caller must commit any pending edits to `source_tree` before calling
    /// this so that `source_tree`'s root block and its children are accounted
    /// in `EXTENT_TREE` and all delalloc for `source_tree` has been flushed.
    pub(crate) async fn snapshot_subvolume(
        &mut self,
        source_tree: u64,
        dest_parent: Name<'_>,
        read_only: bool,
        when: Timestamp,
        new_uuid: [u8; 16],
    ) -> Result<u64, WriteError> {
        validate_name(dest_parent.bytes)?;
        self.roots.check_writable(dest_parent.tree)?;
        let ts = time(dest_parent.tree, dest_parent.parent, when)?;
        let (mut parent_dir, parent_meta) = self
            .inode_item(dest_parent.tree, dest_parent.parent)
            .await?;
        check_flags(
            dest_parent.tree,
            dest_parent.parent,
            parent_meta.flags,
            INODE_IMMUTABLE,
        )?;
        if parent_meta.kind != FileKind::Directory {
            return Err(Error::WrongKind {
                tree: dest_parent.tree,
                inode: dest_parent.parent,
                expected: FileKind::Directory,
                found: parent_meta.kind,
            }
            .into());
        }

        let source_meta = self.roots.subvolume_meta(source_tree)?;
        let source_root = self.roots.get(source_tree)?;
        let snap_tree = self.roots.next_subvolume_id()?;
        let trans_gen = self.trees.generation();
        let nodesize = u64::from(self.volume.superblock().nodesize());
        let sector = self.volume.superblock().sectorsize();

        // Copy only the root block (`btrfs_copy_root`); all lower subtrees and
        // data extents are shared by bumping their extent-tree refcounts.
        let (snap_root, copied) = self
            .trees
            .copy_root(&self.volume, source_root, snap_tree, &mut self.space)
            .await?;

        if copied.level() > 0 {
            for slot in 0..copied.nritems() {
                let (child_addr, _) = copied.child(slot);
                self.accounting
                    .add_metadata(
                        &self.volume,
                        &mut self.trees,
                        &mut self.space,
                        MetadataBlock {
                            address: child_addr,
                            level: copied.level() - 1,
                        },
                        MetadataReference::root(snap_tree),
                    )
                    .await?;
            }
        } else {
            for slot in 0..copied.nritems() {
                let key = copied.key(slot);
                if key.item_type != item_type::EXTENT_DATA {
                    continue;
                }
                let bytes = copied.item(slot);
                FileExtent::parse(key, bytes, sector).map_err(|defect| Error::Item {
                    tree: source_tree,
                    key,
                    defect,
                })?;
                let head: &RawFileExtentHead = view(bytes).expect("validated extent");
                if head.extent_type == 0 {
                    continue;
                }
                let body: &RawFileExtentBody =
                    view(&bytes[size_of::<RawFileExtentHead>()..]).expect("validated extent body");
                if body.disk_bytenr.get() == 0 {
                    continue;
                }
                let offset = key.offset.wrapping_sub(body.offset.get());
                self.accounting
                    .update_data(
                        &self.volume,
                        &mut self.trees,
                        &mut self.space,
                        DataChange {
                            key: Key::new(
                                body.disk_bytenr.get(),
                                item_type::EXTENT_ITEM,
                                body.disk_num_bytes.get(),
                            ),
                            reference: DataReference {
                                root: snap_tree,
                                inode: key.objectid,
                                offset,
                            },
                            delta: 1,
                        },
                    )
                    .await?;
            }
        }

        self.roots.set_last_snapshot(source_tree, trans_gen)?;

        let mut head = RawRootItem::new_zeroed();
        head.inode.generation.set(1);
        head.inode.size.set(3);
        head.inode.nlink.set(1);
        head.inode.nbytes.set(nodesize);
        head.inode.mode.set(S_IFDIR | 0o755);
        head.generation.set(trans_gen);
        head.root_dirid.set(source_meta.root_dirid);
        head.bytenr.set(snap_root.bytenr);
        head.bytes_used.set(source_meta.bytes_used);
        head.last_snapshot.set(trans_gen);
        head.flags.set(u64::from(read_only));
        head.refs.set(1);
        head.level = snap_root.level;

        let mut tail = RawRootTail::new_zeroed();
        tail.generation_v2.set(trans_gen);
        tail.uuid = new_uuid;
        tail.parent_uuid = source_meta.uuid;
        tail.ctransid.set(trans_gen);
        tail.otransid.set(trans_gen);
        tail.ctime = ts;
        tail.otime = ts;

        let mut root_bytes =
            Vec::with_capacity(size_of::<RawRootItem>() + size_of::<RawRootTail>());
        root_bytes.extend_from_slice(head.as_bytes());
        root_bytes.extend_from_slice(tail.as_bytes());

        // The copied root block adds `+nodesize` in `Roots::sync`, so
        // `initial_used = source_bytes_used - nodesize` lands on `source_bytes_used`.
        let initial_used = source_meta.bytes_used.saturating_sub(nodesize);
        self.roots.insert_subvolume(
            Key::new(snap_tree, item_type::ROOT_ITEM, trans_gen),
            snap_root,
            initial_used,
            root_bytes,
        );

        self.link_subvolume(dest_parent, &mut parent_dir, snap_tree, ts)
            .await?;

        if let Some(quota) = &mut self.quota {
            quota.ensure_subvolume(snap_tree, trans_gen);
        }
        Ok(snap_tree)
    }

    /// Inserts `DIR_ITEM`, `DIR_INDEX`, `ROOT_REF` and `ROOT_BACKREF` for
    /// `child_tree` under `parent`.
    async fn link_subvolume(
        &mut self,
        parent: Name<'_>,
        parent_dir: &mut RawInodeItem,
        child_tree: u64,
        ts: crate::ondisk::RawTimespec,
    ) -> Result<(), WriteError> {
        let Name {
            tree,
            parent: parent_ino,
            bytes: name,
        } = parent;
        let root = self.roots.get(tree)?;
        let hash_key = Key::new(parent_ino, item_type::DIR_ITEM, name_hash(name));
        let mut names = self
            .trees
            .get(&self.volume, root, hash_key)
            .await?
            .unwrap_or_default();
        for record in dir_records(&names, RecordKind::Entry) {
            let record = record.map_err(|defect| Error::Item {
                tree,
                key: hash_key,
                defect,
            })?;
            if record.name == name {
                return Err(WriteError::Exists {
                    tree,
                    parent: parent_ino,
                });
            }
        }
        let dir_index = match self
            .trees
            .floor(
                &self.volume,
                root,
                Key::new(parent_ino, item_type::DIR_INDEX, u64::MAX),
            )
            .await?
        {
            Some((key, _)) if key.is(parent_ino, item_type::DIR_INDEX) => key
                .offset
                .checked_add(1)
                .ok_or(WriteError::IdentifierExhausted { tree })?,
            _ => 2,
        };
        let entry_bytes = subvolume_dir_record(child_tree, self.trees.generation(), name);
        names.extend_from_slice(&entry_bytes);

        let mut root = self
            .trees
            .apply(&self.volume, root, hash_key, Some(&names), &mut self.space)
            .await?;
        root = self
            .trees
            .apply(
                &self.volume,
                root,
                Key::new(parent_ino, item_type::DIR_INDEX, dir_index),
                Some(&entry_bytes),
                &mut self.space,
            )
            .await?;
        self.roots.set(root)?;

        let ref_bytes = root_ref_record(parent_ino, dir_index, name);
        self.roots.root = self
            .trees
            .apply(
                &self.volume,
                self.roots.root,
                Key::new(tree, item_type::ROOT_REF, child_tree),
                Some(&ref_bytes),
                &mut self.space,
            )
            .await?;
        self.roots.root = self
            .trees
            .apply(
                &self.volume,
                self.roots.root,
                Key::new(child_tree, item_type::ROOT_BACKREF, tree),
                Some(&ref_bytes),
                &mut self.space,
            )
            .await?;

        parent_dir.size.set(
            parent_dir
                .size
                .get()
                .checked_add(2 * name.len() as u64)
                .ok_or(WriteError::FileOverflow)?,
        );
        parent_dir.transid.set(self.trees.generation());
        parent_dir
            .sequence
            .set(parent_dir.sequence.get().wrapping_add(1));
        parent_dir.mtime = ts;
        parent_dir.ctime = ts;
        self.put_inode(tree, parent_ino, *parent_dir).await?;
        self.roots
            .update_ctransid(tree, self.trees.generation(), ts);
        Ok(())
    }

    /// Deletes the subvolume linked at `parent`, freeing every tree block and
    /// data extent exclusively owned by it while preserving shared blocks for
    /// surviving snapshots via `FULL_BACKREF` conversion.
    ///
    /// Caller must commit any pending edits before calling this so every block
    /// of the deleted subvolume is accounted in `EXTENT_TREE`.
    pub(crate) async fn delete_subvolume(
        &mut self,
        parent: Name<'_>,
        when: Timestamp,
    ) -> Result<u64, WriteError> {
        validate_name(parent.bytes)?;
        self.roots.check_writable(parent.tree)?;
        let ts = time(parent.tree, parent.parent, when)?;
        let (mut parent_dir, parent_meta) = self.inode_item(parent.tree, parent.parent).await?;
        check_flags(
            parent.tree,
            parent.parent,
            parent_meta.flags,
            INODE_IMMUTABLE | INODE_APPEND,
        )?;
        if parent_meta.kind != FileKind::Directory {
            return Err(Error::WrongKind {
                tree: parent.tree,
                inode: parent.parent,
                expected: FileKind::Directory,
                found: parent_meta.kind,
            }
            .into());
        }

        let root = self.roots.get(parent.tree)?;
        let hash_key = Key::new(parent.parent, item_type::DIR_ITEM, name_hash(parent.bytes));
        let mut dir_bytes =
            self.trees
                .get(&self.volume, root, hash_key)
                .await?
                .ok_or(WriteError::NoEntry {
                    tree: parent.tree,
                    parent: parent.parent,
                })?;
        let mut position = 0;
        let mut found = None;
        for record in dir_records(&dir_bytes, RecordKind::Entry) {
            let record = record.map_err(|defect| Error::Item {
                tree: parent.tree,
                key: hash_key,
                defect,
            })?;
            let end = position + size_of::<RawDirItem>() + record.name.len();
            if record.name == parent.bytes {
                found = Some((position..end, record.location));
            }
            position = end;
        }
        let (range, location) = found.ok_or(WriteError::NoEntry {
            tree: parent.tree,
            parent: parent.parent,
        })?;
        if location.item_type != item_type::ROOT_ITEM {
            return Err(WriteError::NotSubvolume {
                tree: parent.tree,
                inode: location.objectid,
            });
        }
        let target_tree = location.objectid;
        if target_tree == objectid::FS_TREE
            || target_tree == self.base().default_subvolume.root.tree
        {
            return Err(WriteError::DefaultSubvolume { tree: target_tree });
        }

        // Refuse deletion if nested subvolumes exist inside `target_tree`.
        let child_ref_search = Key::new(target_tree, item_type::ROOT_REF, 0);
        if let Some((key, _)) = self
            .trees
            .ceiling(&self.volume, self.roots.root, child_ref_search)
            .await?
            && key.is(target_tree, item_type::ROOT_REF)
        {
            return Err(WriteError::SubvolumeNotEmpty { tree: target_tree });
        }

        // Locate the directory index recorded in `ROOT_REF`.
        let root_ref_key = Key::new(parent.tree, item_type::ROOT_REF, target_tree);
        let root_ref_bytes = self
            .trees
            .get(&self.volume, self.roots.root, root_ref_key)
            .await?
            .ok_or(WriteError::NamespaceMismatch {
                tree: objectid::ROOT_TREE,
                key: root_ref_key,
            })?;
        let raw_ref: &RawRootRef = view(&root_ref_bytes).ok_or(WriteError::NamespaceMismatch {
            tree: objectid::ROOT_TREE,
            key: root_ref_key,
        })?;
        let dir_index = raw_ref.sequence.get();

        // Verify and remove `DIR_INDEX` and `DIR_ITEM`.
        let index_key = Key::new(parent.parent, item_type::DIR_INDEX, dir_index);
        let indexed = self.trees.get(&self.volume, root, index_key).await?.ok_or(
            WriteError::NamespaceMismatch {
                tree: parent.tree,
                key: index_key,
            },
        )?;
        let idx_rec = dir_index_record(&indexed).map_err(|defect| Error::Item {
            tree: parent.tree,
            key: index_key,
            defect,
        })?;
        if idx_rec.name != parent.bytes || idx_rec.location != location {
            return Err(WriteError::NamespaceMismatch {
                tree: parent.tree,
                key: index_key,
            });
        }
        dir_bytes.drain(range);
        let mut root = self
            .trees
            .apply(
                &self.volume,
                root,
                hash_key,
                (!dir_bytes.is_empty()).then_some(dir_bytes.as_slice()),
                &mut self.space,
            )
            .await?;
        root = self
            .trees
            .apply(&self.volume, root, index_key, None, &mut self.space)
            .await?;
        self.roots.set(root)?;

        // Update parent directory inode.
        parent_dir.size.set(
            parent_dir
                .size
                .get()
                .checked_sub(2 * parent.bytes.len() as u64)
                .ok_or(WriteError::FileOverflow)?,
        );
        parent_dir.transid.set(self.trees.generation());
        parent_dir
            .sequence
            .set(parent_dir.sequence.get().wrapping_add(1));
        parent_dir.mtime = ts;
        parent_dir.ctime = ts;
        self.put_inode(parent.tree, parent.parent, parent_dir)
            .await?;

        // Remove `ROOT_REF` and `ROOT_BACKREF`.
        self.roots.root = self
            .trees
            .apply(
                &self.volume,
                self.roots.root,
                root_ref_key,
                None,
                &mut self.space,
            )
            .await?;
        self.roots.root = self
            .trees
            .apply(
                &self.volume,
                self.roots.root,
                Key::new(target_tree, item_type::ROOT_BACKREF, parent.tree),
                None,
                &mut self.space,
            )
            .await?;

        // Drop the subvolume's btree and all unshared extents.
        let target_root = self.roots.get(target_tree)?;
        self.drop_subtree(target_tree, target_root).await?;

        // Remove `ROOT_ITEM` from `ROOT_TREE` and `Roots` (which also cleans `UUID_TREE`).
        self.roots
            .remove_tree(&self.volume, &mut self.trees, &mut self.space, target_tree)
            .await?;

        if let Some(quota) = &mut self.quota {
            quota.remove_subvolume(target_tree);
        }
        self.roots
            .update_ctransid(parent.tree, self.trees.generation(), ts);
        Ok(target_tree)
    }

    /// Recursively drops every tree block and data extent reachable from
    /// `root` on behalf of `tree_id`, preserving blocks still shared by
    /// surviving snapshots via `FULL_BACKREF` conversion.
    pub(crate) async fn drop_subtree(
        &mut self,
        tree_id: u64,
        root: crate::tree::TreeRoot,
    ) -> Result<(), WriteError> {
        let sector = self.volume.superblock().sectorsize();
        // Stack entries: (address, level, generation, parent_full_backref, children_dropped).
        let mut stack = vec![(root.bytenr, root.level, root.generation, None::<u64>, false)];
        while let Some((address, level, generation, parent_full, children_dropped)) = stack.pop() {
            let block = MetadataBlock { address, level };
            let my_ref = match parent_full {
                Some(parent_addr) => MetadataReference::parent(parent_addr),
                None => MetadataReference::root(tree_id),
            };
            if children_dropped {
                self.accounting
                    .remove_metadata(
                        &self.volume,
                        &mut self.trees,
                        &mut self.space,
                        block,
                        my_ref,
                    )
                    .await?;
                continue;
            }
            let (_, extent) = self
                .accounting
                .metadata(&self.volume, &self.trees, block)
                .await?;
            let node = self
                .trees
                .read(
                    &self.volume,
                    address,
                    Expected {
                        level,
                        generation,
                        first_key: None,
                    },
                )
                .await?;
            if extent.references() > 1 {
                if node.owner() == tree_id && !extent.full_backrefs() && parent_full.is_none() {
                    // Convert children to explicit `ParentReferences(address)`
                    // before detaching `tree_id` from `address`.
                    for slot in 0..node.nritems() {
                        if level > 0 {
                            let (child_addr, _) = node.child(slot);
                            self.accounting
                                .add_metadata(
                                    &self.volume,
                                    &mut self.trees,
                                    &mut self.space,
                                    MetadataBlock {
                                        address: child_addr,
                                        level: level - 1,
                                    },
                                    MetadataReference::parent(address),
                                )
                                .await?;
                        } else {
                            let key = node.key(slot);
                            if key.item_type != item_type::EXTENT_DATA {
                                continue;
                            }
                            let bytes = node.item(slot);
                            FileExtent::parse(key, bytes, sector).map_err(|defect| {
                                Error::Item {
                                    tree: node.owner(),
                                    key,
                                    defect,
                                }
                            })?;
                            let head: &RawFileExtentHead = view(bytes).expect("validated extent");
                            if head.extent_type == 0 {
                                continue;
                            }
                            let body: &RawFileExtentBody =
                                view(&bytes[size_of::<RawFileExtentHead>()..])
                                    .expect("validated extent body");
                            if body.disk_bytenr.get() == 0 {
                                continue;
                            }
                            self.accounting
                                .update_data(
                                    &self.volume,
                                    &mut self.trees,
                                    &mut self.space,
                                    DataChange {
                                        key: Key::new(
                                            body.disk_bytenr.get(),
                                            item_type::EXTENT_ITEM,
                                            body.disk_num_bytes.get(),
                                        ),
                                        reference: SharedDataReference(address),
                                        delta: 1,
                                    },
                                )
                                .await?;
                        }
                    }
                    self.accounting
                        .set_full_backrefs(&self.volume, &mut self.trees, &mut self.space, block)
                        .await?;
                }
                self.accounting
                    .remove_metadata(
                        &self.volume,
                        &mut self.trees,
                        &mut self.space,
                        block,
                        my_ref,
                    )
                    .await?;
            } else if level == 0 {
                for slot in 0..node.nritems() {
                    let key = node.key(slot);
                    if key.item_type != item_type::EXTENT_DATA {
                        continue;
                    }
                    let bytes = node.item(slot);
                    FileExtent::parse(key, bytes, sector).map_err(|defect| Error::Item {
                        tree: node.owner(),
                        key,
                        defect,
                    })?;
                    let head: &RawFileExtentHead = view(bytes).expect("validated extent");
                    if head.extent_type == 0 {
                        continue;
                    }
                    let body: &RawFileExtentBody = view(&bytes[size_of::<RawFileExtentHead>()..])
                        .expect("validated extent body");
                    if body.disk_bytenr.get() == 0 {
                        continue;
                    }
                    let ext_key = Key::new(
                        body.disk_bytenr.get(),
                        item_type::EXTENT_ITEM,
                        body.disk_num_bytes.get(),
                    );
                    if extent.full_backrefs() {
                        self.accounting
                            .update_data(
                                &self.volume,
                                &mut self.trees,
                                &mut self.space,
                                DataChange {
                                    key: ext_key,
                                    reference: SharedDataReference(address),
                                    delta: -1,
                                },
                            )
                            .await?;
                    } else {
                        let offset = key.offset.wrapping_sub(body.offset.get());
                        self.accounting
                            .update_data(
                                &self.volume,
                                &mut self.trees,
                                &mut self.space,
                                DataChange {
                                    key: ext_key,
                                    reference: DataReference {
                                        root: node.owner(),
                                        inode: key.objectid,
                                        offset,
                                    },
                                    delta: -1,
                                },
                            )
                            .await?;
                    }
                }
                self.accounting
                    .remove_metadata(
                        &self.volume,
                        &mut self.trees,
                        &mut self.space,
                        block,
                        my_ref,
                    )
                    .await?;
            } else {
                stack.push((address, level, generation, parent_full, true));
                let child_parent = extent.full_backrefs().then_some(address);
                for slot in 0..node.nritems() {
                    let (child_addr, child_gen) = node.child(slot);
                    stack.push((child_addr, level - 1, child_gen, child_parent, false));
                }
            }
        }
        Ok(())
    }

    /// Reconstructs the canonical path of `tree` relative to the default
    /// subvolume root (`""` for the default subvolume itself), along with its
    /// direct parent subvolume tree id if any.
    pub(crate) async fn subvolume_path(
        &self,
        tree: u64,
    ) -> Result<(Option<u64>, String), WriteError> {
        let default_tree = self.base().default_subvolume.root.tree;
        if tree == default_tree {
            return Ok((None, String::new()));
        }
        let mut segments: Vec<String> = Vec::new();
        let mut current = tree;
        let mut direct_parent = None;
        let mut hops = 0;
        while current != default_tree {
            hops += 1;
            if hops > 64 {
                return Err(WriteError::DirectoryCycle);
            }
            let search = Key::new(current, item_type::ROOT_BACKREF, 0);
            let Some((found, bytes)) = self
                .trees
                .ceiling(&self.volume, self.roots.root, search)
                .await?
            else {
                return Ok((direct_parent, String::new()));
            };
            if !found.is(current, item_type::ROOT_BACKREF) {
                return Ok((direct_parent, String::new()));
            }
            let parent_tree = found.offset;
            direct_parent.get_or_insert(parent_tree);
            let raw: &RawRootRef = view(&bytes).ok_or(WriteError::NamespaceMismatch {
                tree: objectid::ROOT_TREE,
                key: found,
            })?;
            let name_len = usize::from(raw.name_len.get());
            let name = bytes
                .get(size_of::<RawRootRef>()..size_of::<RawRootRef>() + name_len)
                .ok_or(WriteError::NamespaceMismatch {
                    tree: objectid::ROOT_TREE,
                    key: found,
                })?;
            segments.push(String::from_utf8_lossy(name).into_owned());

            // Walk `INODE_REF`s from `raw.dirid` up to `parent_tree`'s root dir.
            let parent_root_dir = self.roots.root_directory(parent_tree)?;
            let parent_root = self.roots.get(parent_tree)?;
            let mut dir = raw.dirid.get();
            while dir != parent_root_dir {
                let ref_search = Key::new(dir, item_type::INODE_REF, 0);
                let Some((ref_key, ref_bytes)) = self
                    .trees
                    .ceiling(&self.volume, parent_root, ref_search)
                    .await?
                else {
                    break;
                };
                if !ref_key.is(dir, item_type::INODE_REF) || ref_key.offset == dir {
                    break;
                }
                let iref: &RawInodeRef = view(&ref_bytes).ok_or(WriteError::NamespaceMismatch {
                    tree: parent_tree,
                    key: ref_key,
                })?;
                let len = usize::from(iref.name_len.get());
                let seg = ref_bytes
                    .get(size_of::<RawInodeRef>()..size_of::<RawInodeRef>() + len)
                    .ok_or(WriteError::NamespaceMismatch {
                        tree: parent_tree,
                        key: ref_key,
                    })?;
                segments.push(String::from_utf8_lossy(seg).into_owned());
                dir = ref_key.offset;
            }
            current = parent_tree;
        }
        segments.reverse();
        Ok((direct_parent, segments.join("/")))
    }

    /// Builds a [`SubvolumeInfo`] describing `tree`.
    pub(crate) async fn subvolume_info(&self, tree: u64) -> Result<SubvolumeInfo, WriteError> {
        let meta = self.roots.subvolume_meta(tree)?;
        let (parent_id, path) = self.subvolume_path(tree).await?;
        Ok(SubvolumeInfo {
            id: meta.id,
            parent_id,
            path,
            uuid: meta.uuid,
            parent_uuid: meta.parent_uuid,
            received_uuid: meta.received_uuid,
            generation: meta.root.generation,
            ctransid: meta.ctransid,
            otransid: meta.otransid,
            stransid: meta.stransid,
            rtransid: meta.rtransid,
            read_only: meta.read_only,
        })
    }
}
