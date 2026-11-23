//! Quota groups (`BTRFS_QUOTA_TREE_OBJECTID = 8`), following Linux's
//! `fs/btrfs/qgroup.c` and `include/uapi/linux/btrfs_tree.h`.
//!
//! When quotas are enabled, the writer loads the quota tree at mount, enforces
//! `max_rfer` and `max_excl` limits on allocations, and updates every qgroup's
//! `rfer`, `rfer_cmpr`, `excl`, and `excl_cmpr` counts on commit so Linux's
//! `btrfs check --readonly` verifies the quota tree with zero discrepancies.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use helios_hal::fs_management::{QgroupId, QgroupInfo, QgroupLimit, QuotaStatus};
use zerocopy::{FromZeros, IntoBytes};

use crate::items::FileExtent;
use crate::ondisk::{
    RawFileExtentBody, RawFileExtentHead, RawQgroupInfo, RawQgroupLimit, RawQgroupStatus,
    item_type, objectid, view,
};
use crate::roots::Roots;
use crate::source::BlockSource;
use crate::space::Space;
use crate::tree::write::{Trees, WriteError};
use crate::tree::{Cursor, Expected, TreeRoot};
use crate::volume::Volume;
use crate::{Error, Key};

/// `BTRFS_QGROUP_STATUS_VERSION`.
pub(crate) const QGROUP_STATUS_VERSION: u64 = 1;
/// `BTRFS_QGROUP_STATUS_FLAG_ON`.
pub(crate) const QGROUP_STATUS_FLAG_ON: u64 = 1 << 0;
/// `BTRFS_QGROUP_STATUS_FLAG_RESCAN`.
pub(crate) const QGROUP_STATUS_FLAG_RESCAN: u64 = 1 << 1;
/// `BTRFS_QGROUP_STATUS_FLAG_INCONSISTENT`.
pub(crate) const QGROUP_STATUS_FLAG_INCONSISTENT: u64 = 1 << 2;

/// `BTRFS_QGROUP_LIMIT_MAX_RFER`.
pub(crate) const QGROUP_LIMIT_MAX_RFER: u64 = 1 << 0;
/// `BTRFS_QGROUP_LIMIT_MAX_EXCL`.
pub(crate) const QGROUP_LIMIT_MAX_EXCL: u64 = 1 << 1;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct QgroupRecord {
    pub(crate) generation: u64,
    pub(crate) rfer: u64,
    pub(crate) rfer_cmpr: u64,
    pub(crate) excl: u64,
    pub(crate) excl_cmpr: u64,
    pub(crate) limit_flags: u64,
    pub(crate) max_rfer: u64,
    pub(crate) max_excl: u64,
    pub(crate) rsv_rfer: u64,
    pub(crate) rsv_excl: u64,
}

impl QgroupRecord {
    pub(crate) fn limit(&self) -> QgroupLimit {
        QgroupLimit {
            max_referenced: (self.limit_flags & QGROUP_LIMIT_MAX_RFER != 0)
                .then_some(self.max_rfer),
            max_exclusive: (self.limit_flags & QGROUP_LIMIT_MAX_EXCL != 0).then_some(self.max_excl),
        }
    }

    pub(crate) fn set_limit(&mut self, limit: QgroupLimit) {
        self.limit_flags &= !(QGROUP_LIMIT_MAX_RFER | QGROUP_LIMIT_MAX_EXCL);
        if let Some(max_rfer) = limit.max_referenced {
            self.limit_flags |= QGROUP_LIMIT_MAX_RFER;
            self.max_rfer = max_rfer;
        } else {
            self.max_rfer = 0;
        }
        if let Some(max_excl) = limit.max_exclusive {
            self.limit_flags |= QGROUP_LIMIT_MAX_EXCL;
            self.max_excl = max_excl;
        } else {
            self.max_excl = 0;
        }
    }
}

/// In-memory view of the quota tree owned by a running transaction.
#[derive(Clone)]
pub(crate) struct QuotaTree {
    pub(crate) root: TreeRoot,
    pub(crate) status_flags: u64,
    pub(crate) status_generation: u64,
    pub(crate) rescan_progress: u64,
    pub(crate) groups: BTreeMap<u64, QgroupRecord>,
    /// Directed membership edges `(member_raw, parent_raw)` where
    /// `level(member) < level(parent)`.
    pub(crate) relations: BTreeSet<(u64, u64)>,
    /// Keys currently present in the on-disk/overlay quota tree so `sync`
    /// deletes removed items cleanly.
    persisted: BTreeMap<Key, Vec<u8>>,
    pub(crate) dirty: bool,
}

impl QuotaTree {
    /// Creates a brand-new enabled quota tree whose root block is `root`.
    pub(crate) fn new_enabled(root: TreeRoot, generation: u64) -> Self {
        Self {
            root,
            status_flags: QGROUP_STATUS_FLAG_ON,
            status_generation: generation,
            rescan_progress: 0,
            groups: BTreeMap::new(),
            relations: BTreeSet::new(),
            persisted: BTreeMap::new(),
            dirty: true,
        }
    }

    /// Loads an existing quota tree from `volume` at `root`.
    pub(crate) async fn load<S: BlockSource>(
        volume: &Volume<S>,
        root: TreeRoot,
    ) -> Result<Self, WriteError> {
        let mut status_flags = QGROUP_STATUS_FLAG_ON;
        let mut status_generation = root.generation;
        let mut rescan_progress = 0;
        let mut groups = BTreeMap::<u64, QgroupRecord>::new();
        let mut relations = BTreeSet::<(u64, u64)>::new();
        let mut persisted = BTreeMap::<Key, Vec<u8>>::new();

        let mut cursor = Cursor::ceiling(volume, root, Key::new(0, 0, 0)).await?;
        while let (Some(key), Some(bytes)) = (cursor.key(), cursor.item()) {
            persisted.insert(key, bytes.to_vec());
            match key.item_type {
                item_type::QGROUP_STATUS => {
                    if let Some(raw) = view::<RawQgroupStatus>(bytes) {
                        status_generation = raw.generation.get();
                        status_flags = raw.flags.get();
                        rescan_progress = raw.rescan.get();
                    }
                }
                item_type::QGROUP_INFO => {
                    if let Some(raw) = view::<RawQgroupInfo>(bytes) {
                        let entry = groups.entry(key.offset).or_default();
                        entry.generation = raw.generation.get();
                        entry.rfer = raw.rfer.get();
                        entry.rfer_cmpr = raw.rfer_cmpr.get();
                        entry.excl = raw.excl.get();
                        entry.excl_cmpr = raw.excl_cmpr.get();
                    }
                }
                item_type::QGROUP_LIMIT => {
                    if let Some(raw) = view::<RawQgroupLimit>(bytes) {
                        let entry = groups.entry(key.offset).or_default();
                        entry.limit_flags = raw.flags.get();
                        entry.max_rfer = raw.max_rfer.get();
                        entry.max_excl = raw.max_excl.get();
                        entry.rsv_rfer = raw.rsv_rfer.get();
                        entry.rsv_excl = raw.rsv_excl.get();
                    }
                }
                item_type::QGROUP_RELATION => {
                    let src_level = key.objectid >> 48;
                    let dst_level = key.offset >> 48;
                    if src_level < dst_level {
                        relations.insert((key.objectid, key.offset));
                    }
                }
                _ => {}
            }
            cursor.advance(volume).await?;
        }

        Ok(Self {
            root,
            status_flags,
            status_generation,
            rescan_progress,
            groups,
            relations,
            persisted,
            dirty: false,
        })
    }

    pub(crate) fn status(&self) -> QuotaStatus {
        QuotaStatus {
            enabled: self.status_flags & QGROUP_STATUS_FLAG_ON != 0,
            rescanning: self.status_flags & QGROUP_STATUS_FLAG_RESCAN != 0,
            inconsistent: self.status_flags & QGROUP_STATUS_FLAG_INCONSISTENT != 0,
            generation: self.status_generation,
        }
    }

    pub(crate) fn list(&self) -> Vec<QgroupInfo> {
        self.groups
            .iter()
            .map(|(&raw_id, rec)| {
                let parents = self
                    .relations
                    .iter()
                    .filter(|&&(member, _)| member == raw_id)
                    .map(|&(_, parent)| QgroupId::from_raw(parent))
                    .collect();
                QgroupInfo {
                    id: QgroupId::from_raw(raw_id),
                    referenced_bytes: rec.rfer,
                    referenced_compressed_bytes: rec.rfer_cmpr,
                    exclusive_bytes: rec.excl,
                    exclusive_compressed_bytes: rec.excl_cmpr,
                    limit: rec.limit(),
                    parents,
                }
            })
            .collect()
    }

    /// Ensures a level-0 qgroup exists for every live subvolume.
    pub(crate) fn ensure_subvolume(&mut self, tree: u64, generation: u64) {
        self.groups.entry(tree).or_insert_with(|| QgroupRecord {
            generation,
            ..QgroupRecord::default()
        });
        self.dirty = true;
    }

    /// Removes the level-0 qgroup and any relations naming `tree`.
    pub(crate) fn remove_subvolume(&mut self, tree: u64) {
        self.groups.remove(&tree);
        self.relations
            .retain(|&(member, parent)| member != tree && parent != tree);
        self.dirty = true;
    }

    pub(crate) fn create_group(&mut self, id: QgroupId, generation: u64) -> Result<(), WriteError> {
        let raw = id.to_raw();
        if self.groups.contains_key(&raw) {
            return Err(WriteError::QgroupExists { id });
        }
        self.groups.insert(
            raw,
            QgroupRecord {
                generation,
                ..QgroupRecord::default()
            },
        );
        self.dirty = true;
        Ok(())
    }

    pub(crate) fn destroy_group(
        &mut self,
        id: QgroupId,
        live_subvols: &BTreeSet<u64>,
    ) -> Result<(), WriteError> {
        let raw = id.to_raw();
        if !self.groups.contains_key(&raw) {
            return Err(WriteError::QgroupNotFound { id });
        }
        if id.level == 0 && live_subvols.contains(&id.id) {
            return Err(WriteError::QgroupInvalidRelation);
        }
        if self
            .relations
            .iter()
            .any(|&(member, parent)| member == raw || parent == raw)
        {
            return Err(WriteError::QgroupInvalidRelation);
        }
        self.groups.remove(&raw);
        self.dirty = true;
        Ok(())
    }

    pub(crate) fn assign(&mut self, member: QgroupId, parent: QgroupId) -> Result<(), WriteError> {
        if parent.level <= member.level {
            return Err(WriteError::QgroupInvalidRelation);
        }
        let m_raw = member.to_raw();
        let p_raw = parent.to_raw();
        if !self.groups.contains_key(&m_raw) {
            return Err(WriteError::QgroupNotFound { id: member });
        }
        if !self.groups.contains_key(&p_raw) {
            return Err(WriteError::QgroupNotFound { id: parent });
        }
        self.relations.insert((m_raw, p_raw));
        self.dirty = true;
        Ok(())
    }

    pub(crate) fn remove_relation(
        &mut self,
        member: QgroupId,
        parent: QgroupId,
    ) -> Result<(), WriteError> {
        let m_raw = member.to_raw();
        let p_raw = parent.to_raw();
        if !self.relations.remove(&(m_raw, p_raw)) {
            return Err(WriteError::QgroupInvalidRelation);
        }
        self.dirty = true;
        Ok(())
    }

    pub(crate) fn set_limit(&mut self, id: QgroupId, limit: QgroupLimit) -> Result<(), WriteError> {
        let raw = id.to_raw();
        let Some(rec) = self.groups.get_mut(&raw) else {
            return Err(WriteError::QgroupNotFound { id });
        };
        rec.set_limit(limit);
        self.dirty = true;
        Ok(())
    }

    /// Checks whether adding `additional_bytes` of data/metadata to subvolume
    /// `tree` (on top of `pending_tree_bytes` already dirtied in this
    /// transaction) would exceed any configured `max_rfer` or `max_excl` limit
    /// on `0/tree` or any of its ancestor qgroups.
    pub(crate) fn check_limit(
        &self,
        tree: u64,
        pending_tree_bytes: u64,
        additional_bytes: u64,
    ) -> Result<(), WriteError> {
        if self.status_flags & QGROUP_STATUS_FLAG_ON == 0 || additional_bytes == 0 {
            return Ok(());
        }
        // Gather 0/tree and all transitive ancestor qgroups.
        let mut affected = BTreeSet::new();
        let mut stack = alloc::vec![tree];
        while let Some(current) = stack.pop() {
            if !affected.insert(current) {
                continue;
            }
            for &(member, parent) in &self.relations {
                if member == current {
                    stack.push(parent);
                }
            }
        }
        let delta = pending_tree_bytes.saturating_add(additional_bytes);
        for qid in affected {
            let Some(rec) = self.groups.get(&qid) else {
                continue;
            };
            if rec.limit_flags & QGROUP_LIMIT_MAX_RFER != 0
                && rec.rfer.saturating_add(delta) > rec.max_rfer
            {
                return Err(WriteError::QuotaExceeded);
            }
            if rec.limit_flags & QGROUP_LIMIT_MAX_EXCL != 0
                && rec.excl.saturating_add(delta) > rec.max_excl
            {
                return Err(WriteError::QuotaExceeded);
            }
        }
        Ok(())
    }

    /// Recomputes exact `rfer`, `rfer_cmpr`, `excl`, and `excl_cmpr` counters
    /// for every qgroup by walking all live subvolume trees.
    pub(crate) async fn recompute<S: BlockSource>(
        &mut self,
        volume: &Volume<S>,
        trees: &Trees,
        roots: &Roots,
    ) -> Result<(), WriteError> {
        let nodesize = u64::from(volume.superblock().nodesize());
        let sector = volume.superblock().sectorsize();
        let generation = trees.generation();

        // Collect all live subvolumes and ensure level-0 qgroups exist for each.
        let live_subvols: Vec<(u64, TreeRoot)> = roots.live_subvolume_roots();
        for &(tree, _) in &live_subvols {
            self.groups.entry(tree).or_insert_with(|| QgroupRecord {
                generation,
                ..QgroupRecord::default()
            });
        }

        struct CachedNode {
            children: Vec<(u64, u8, u64)>,
            data: Vec<(u64, u64)>,
        }

        // Cache per tree block so shared subtrees across snapshots are read
        // from disk at most once.
        let mut node_cache: BTreeMap<u64, CachedNode> = BTreeMap::new();
        // Map each extent (metadata block or data extent) bytenr -> (size, owning subvol set).
        let mut extent_owners: BTreeMap<u64, (u64, BTreeSet<u64>)> = BTreeMap::new();

        for (subvol_id, root) in &live_subvols {
            let mut visited_nodes = BTreeSet::new();
            let mut stack = alloc::vec![(root.bytenr, root.level, root.generation)];
            while let Some((bytenr, level, node_gen)) = stack.pop() {
                if !visited_nodes.insert(bytenr) {
                    continue;
                }
                extent_owners
                    .entry(bytenr)
                    .or_insert_with(|| (nodesize, BTreeSet::new()))
                    .1
                    .insert(*subvol_id);

                if let alloc::collections::btree_map::Entry::Vacant(entry) =
                    node_cache.entry(bytenr)
                {
                    let node = trees
                        .read(
                            volume,
                            bytenr,
                            Expected {
                                level,
                                generation: node_gen,
                                first_key: None,
                            },
                        )
                        .await?;
                    let mut children = Vec::new();
                    let mut data = Vec::new();
                    if node.level() > 0 {
                        for slot in 0..node.nritems() {
                            let (child_addr, child_gen) = node.child(slot);
                            children.push((child_addr, node.level() - 1, child_gen));
                        }
                    } else {
                        for slot in 0..node.nritems() {
                            let key = node.key(slot);
                            if key.item_type != item_type::EXTENT_DATA {
                                continue;
                            }
                            let bytes = node.item(slot);
                            FileExtent::parse(key, bytes, sector).map_err(|defect| {
                                Error::Item {
                                    tree: *subvol_id,
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
                            let disk_bytenr = body.disk_bytenr.get();
                            let disk_num_bytes = body.disk_num_bytes.get();
                            if disk_bytenr != 0 && disk_num_bytes != 0 {
                                data.push((disk_bytenr, disk_num_bytes));
                            }
                        }
                    }
                    entry.insert(CachedNode { children, data });
                }

                let cached = &node_cache[&bytenr];
                for &(child_addr, child_level, child_gen) in &cached.children {
                    if !visited_nodes.contains(&child_addr) {
                        stack.push((child_addr, child_level, child_gen));
                    }
                }
                for &(disk_bytenr, disk_num_bytes) in &cached.data {
                    extent_owners
                        .entry(disk_bytenr)
                        .or_insert_with(|| (disk_num_bytes, BTreeSet::new()))
                        .1
                        .insert(*subvol_id);
                }
            }
        }

        // Compute transitive level-0 member subvolumes for every qgroup in
        // ascending level order.
        let mut ordered_qids: Vec<u64> = self.groups.keys().copied().collect();
        ordered_qids.sort_unstable_by_key(|&raw| (raw >> 48, raw));
        let mut members: BTreeMap<u64, BTreeSet<u64>> = BTreeMap::new();
        for &qid in &ordered_qids {
            let mut set = BTreeSet::new();
            if qid >> 48 == 0 {
                set.insert(qid);
            } else {
                for &(member, parent) in &self.relations {
                    if parent == qid
                        && let Some(child_members) = members.get(&member)
                    {
                        set.extend(child_members.iter().copied());
                    }
                }
            }
            members.insert(qid, set);
        }

        // Reset counters and accumulate across every unique extent.
        for rec in self.groups.values_mut() {
            rec.generation = generation;
            rec.rfer = 0;
            rec.rfer_cmpr = 0;
            rec.excl = 0;
            rec.excl_cmpr = 0;
        }
        for (size, owners) in extent_owners.values() {
            if owners.is_empty() {
                continue;
            }
            for (&qid, rec) in &mut self.groups {
                let m = &members[&qid];
                if owners.iter().any(|t| m.contains(t)) {
                    rec.rfer = rec.rfer.saturating_add(*size);
                    rec.rfer_cmpr = rec.rfer_cmpr.saturating_add(*size);
                }
                if owners.iter().all(|t| m.contains(t)) {
                    rec.excl = rec.excl.saturating_add(*size);
                    rec.excl_cmpr = rec.excl_cmpr.saturating_add(*size);
                }
            }
        }

        self.status_generation = generation;
        self.status_flags = QGROUP_STATUS_FLAG_ON;
        self.rescan_progress = 0;
        self.dirty = true;
        Ok(())
    }

    /// Writes the current in-memory quota state to the quota btree, updating
    /// only keys that changed.
    pub(crate) async fn sync<S: BlockSource>(
        &mut self,
        volume: &Volume<S>,
        trees: &mut Trees,
        space: &mut Space,
    ) -> Result<bool, WriteError> {
        let mut desired = BTreeMap::<Key, Vec<u8>>::new();

        let mut status = RawQgroupStatus::new_zeroed();
        status.version.set(QGROUP_STATUS_VERSION);
        status.generation.set(self.status_generation);
        status.flags.set(self.status_flags);
        status.rescan.set(self.rescan_progress);
        desired.insert(
            Key::new(0, item_type::QGROUP_STATUS, 0),
            status.as_bytes().to_vec(),
        );

        for (&qid, rec) in &self.groups {
            let mut info = RawQgroupInfo::new_zeroed();
            info.generation.set(rec.generation);
            info.rfer.set(rec.rfer);
            info.rfer_cmpr.set(rec.rfer_cmpr);
            info.excl.set(rec.excl);
            info.excl_cmpr.set(rec.excl_cmpr);
            desired.insert(
                Key::new(0, item_type::QGROUP_INFO, qid),
                info.as_bytes().to_vec(),
            );

            let mut limit = RawQgroupLimit::new_zeroed();
            limit.flags.set(rec.limit_flags);
            limit.max_rfer.set(rec.max_rfer);
            limit.max_excl.set(rec.max_excl);
            limit.rsv_rfer.set(rec.rsv_rfer);
            limit.rsv_excl.set(rec.rsv_excl);
            desired.insert(
                Key::new(0, item_type::QGROUP_LIMIT, qid),
                limit.as_bytes().to_vec(),
            );
        }

        for &(member, parent) in &self.relations {
            // Both forward (member -> parent) and reverse (parent -> member)
            // relation items are stored with empty payloads.
            desired.insert(
                Key::new(member, item_type::QGROUP_RELATION, parent),
                Vec::new(),
            );
            desired.insert(
                Key::new(parent, item_type::QGROUP_RELATION, member),
                Vec::new(),
            );
        }

        let mut changed = false;
        let removed: Vec<Key> = self
            .persisted
            .keys()
            .filter(|k| !desired.contains_key(k))
            .copied()
            .collect();
        for key in removed {
            self.root = trees.apply(volume, self.root, key, None, space).await?;
            self.persisted.remove(&key);
            changed = true;
        }
        for (key, value) in desired {
            if self.persisted.get(&key) == Some(&value) {
                continue;
            }
            self.root = trees
                .apply(volume, self.root, key, Some(&value), space)
                .await?;
            self.persisted.insert(key, value);
            changed = true;
        }
        self.dirty = false;
        Ok(changed)
    }

    /// Reads the quota status and qgroup list directly from a read-only view
    /// without starting a transaction.
    pub(crate) async fn inspect<S: BlockSource>(
        volume: &Volume<S>,
        root_tree: TreeRoot,
    ) -> Result<(QuotaStatus, Vec<QgroupInfo>), Error> {
        match crate::fs::find_root(volume, root_tree, objectid::QUOTA_TREE).await {
            Ok(record) => {
                let mut status = QuotaStatus::default();
                let mut groups = BTreeMap::<u64, QgroupRecord>::new();
                let mut relations = BTreeSet::<(u64, u64)>::new();
                let mut cursor = Cursor::ceiling(volume, record.root, Key::new(0, 0, 0)).await?;
                while let (Some(key), Some(bytes)) = (cursor.key(), cursor.item()) {
                    match key.item_type {
                        item_type::QGROUP_STATUS => {
                            if let Some(raw) = view::<RawQgroupStatus>(bytes) {
                                let flags = raw.flags.get();
                                status = QuotaStatus {
                                    enabled: flags & QGROUP_STATUS_FLAG_ON != 0,
                                    rescanning: flags & QGROUP_STATUS_FLAG_RESCAN != 0,
                                    inconsistent: flags & QGROUP_STATUS_FLAG_INCONSISTENT != 0,
                                    generation: raw.generation.get(),
                                };
                            }
                        }
                        item_type::QGROUP_INFO => {
                            if let Some(raw) = view::<RawQgroupInfo>(bytes) {
                                let entry = groups.entry(key.offset).or_default();
                                entry.generation = raw.generation.get();
                                entry.rfer = raw.rfer.get();
                                entry.rfer_cmpr = raw.rfer_cmpr.get();
                                entry.excl = raw.excl.get();
                                entry.excl_cmpr = raw.excl_cmpr.get();
                            }
                        }
                        item_type::QGROUP_LIMIT => {
                            if let Some(raw) = view::<RawQgroupLimit>(bytes) {
                                let entry = groups.entry(key.offset).or_default();
                                entry.limit_flags = raw.flags.get();
                                entry.max_rfer = raw.max_rfer.get();
                                entry.max_excl = raw.max_excl.get();
                                entry.rsv_rfer = raw.rsv_rfer.get();
                                entry.rsv_excl = raw.rsv_excl.get();
                            }
                        }
                        item_type::QGROUP_RELATION if (key.objectid >> 48) < (key.offset >> 48) => {
                            relations.insert((key.objectid, key.offset));
                        }
                        _ => {}
                    }
                    cursor.advance(volume).await?;
                }
                let list = groups
                    .iter()
                    .map(|(&raw_id, rec)| {
                        let parents = relations
                            .iter()
                            .filter(|&&(member, _)| member == raw_id)
                            .map(|&(_, parent)| QgroupId::from_raw(parent))
                            .collect();
                        QgroupInfo {
                            id: QgroupId::from_raw(raw_id),
                            referenced_bytes: rec.rfer,
                            referenced_compressed_bytes: rec.rfer_cmpr,
                            exclusive_bytes: rec.excl,
                            exclusive_compressed_bytes: rec.excl_cmpr,
                            limit: rec.limit(),
                            parents,
                        }
                    })
                    .collect();
                Ok((status, list))
            }
            Err(Error::MissingRoot { .. }) => Ok((QuotaStatus::default(), Vec::new())),
            Err(error) => Err(error),
        }
    }
}
