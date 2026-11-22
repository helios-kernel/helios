//! A single-owner transaction. Its owner serializes writers and retains the
//! mounted generation's reader pins; this module never reuses retired extents.
//!
//! The transaction runs across many mutations: each one applies to it and
//! is visible through [`Transaction::view`] at once, and a commit writes them
//! all durably as one generation.

pub(crate) mod acl;
pub(crate) mod chunks;
pub(crate) mod dedupe;
pub(crate) mod devices;
mod extents;
pub(crate) mod file;
pub(crate) mod namespace;
pub(crate) mod orphan;
pub(crate) mod ownership;
pub(crate) mod reflink;
pub(crate) mod relocate;
pub(crate) mod replay;
pub(crate) mod reserve;
pub(crate) mod subvolume;
mod writeback;
pub(crate) mod xattr;

use core::num::NonZeroUsize;
use futures::future;

use self::namespace::Name;
use self::orphan::OpenInodes;
use self::reflink::FileId;
use crate::accounting::{Accounting, Allocation};
use crate::commit::CommitImage;
use crate::compress::policy::Compressor;
use crate::data::{File, Reader};
use crate::delalloc::Delalloc;
use crate::fs::Snapshot;
use crate::ondisk::objectid;
use crate::qgroup::QuotaTree;
use crate::retirement::Retirements;
use crate::roots::Roots;
use crate::source::{BlockSink, PendingWrites, READ_ALIGNMENT};
use crate::space::Space;
use crate::tree::TreeRoot;
use crate::tree::write::{Trees, WriteError};
use crate::volume::{Mapping, Volume};
use crate::{EntryTarget, Metadata};
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;

/// Produced only once the new roots are durable, or for an unchanged view.
pub(crate) struct Committed<S> {
    pub(crate) snapshot: Arc<Snapshot>,
    /// The live devices after this commit (reflecting any add/remove/replace).
    pub(crate) devices: Arc<Vec<(u64, Arc<S>)>>,
    /// The allocation state of `snapshot`'s generation; `None` for an unchanged
    /// view, whose state is the one the transaction started from.
    pub(crate) allocation: Option<Allocation>,
}

pub(crate) struct Transaction<S> {
    generation: Arc<Snapshot>,
    // Inode generations distinguish reuse across commits. Within one commit,
    // keep allocated numbers monotonic even after an inode is deleted again.
    inode_high_water: BTreeMap<u64, u64>,
    pub(crate) volume: Volume<S>,
    pub(crate) image: CommitImage,
    pub(crate) roots: Roots,
    /// The chunk tree's root. The superblock, not the root tree, records it.
    pub(crate) chunk_root: TreeRoot,
    /// Device ranges of chunks this transaction removed (`(devid, range)`).
    /// They stay out of reach of chunk allocation until the transaction
    /// publishes (`btrfs_dev_extent_hole` skips `pending_chunks`).
    pub(crate) released: Vec<(u64, core::ops::Range<u64>)>,
    /// Optional device excluded from chunk allocation during device removal.
    pub(crate) excluded_device: Option<u64>,
    /// Optional per-device ceiling in bytes during device shrink.
    pub(crate) device_size_limit: Option<(u64, u64)>,
    pub(crate) trees: Trees,
    pub(crate) space: Space,
    pub(crate) accounting: Accounting,
    /// Quota tree when quotas are enabled on this filesystem.
    pub(crate) quota: Option<QuotaTree>,
    /// File data written but not yet given extents.
    pub(crate) delalloc: Delalloc,
    /// When true, `commit` publishes a new generation even if no tree blocks
    /// changed (for example after changing superblock device metadata).
    pub(crate) force_commit: bool,
    /// Open-handle accounting mirrored from the owning [`crate::write::Writer`],
    /// checkpointed and rolled back alongside tree edits.
    pub(crate) open: OpenInodes,
}

/// Private operation state. Inode allocation high-water marks deliberately
/// remain outside rollback: a discarded creation cannot lend its identity to
/// another inode in the same transaction generation.
pub(crate) struct Checkpoint {
    image: CommitImage,
    roots: Roots,
    chunk_root: TreeRoot,
    mapping: Arc<Mapping>,
    trees: Trees,
    space: Space,
    accounting: Accounting,
    quota: Option<QuotaTree>,
    delalloc: Delalloc,
    force_commit: bool,
    open: OpenInodes,
}

impl<S: BlockSink> Transaction<S> {
    /// The committed generation this transaction started from.
    pub(crate) fn base(&self) -> &Arc<Snapshot> {
        &self.generation
    }

    /// Bytes of private tree blocks this transaction holds in memory, every
    /// one of which its commit writes.
    pub(crate) fn dirty_metadata_bytes(&self) -> u64 {
        self.trees.block_count() as u64 * u64::from(self.volume.superblock().nodesize())
    }

    /// Bytes of file data written but not yet given extents, every one of
    /// which writeback, and so the commit, writes.
    pub(crate) fn dirty_data_bytes(&self) -> u64 {
        self.delalloc.bytes()
    }

    /// A reader's view of this transaction as it stands: its private tree
    /// blocks, its moved roots and the private data they reach. The writer
    /// keeps that data from reuse while the view lives.
    pub(crate) fn view(&self) -> Result<Arc<Snapshot>, WriteError> {
        Snapshot::running(
            &self.generation,
            self.volume.mapping(),
            &self.roots,
            self.accounting.checksum_root(),
            &self.trees,
            self.space.private_data(),
            &self.delalloc,
        )
    }

    pub(crate) fn checkpoint(&mut self) -> Checkpoint {
        let saved = Checkpoint {
            image: self.image.clone(),
            roots: self.roots.clone(),
            chunk_root: self.chunk_root,
            mapping: self.volume.mapping(),
            trees: self.trees.clone(),
            space: self.space.clone(),
            accounting: self.accounting.clone(),
            quota: self.quota.clone(),
            delalloc: self.delalloc.clone(),
            force_commit: self.force_commit,
            open: self.open.clone(),
        };
        self.space.begin_operation();
        saved
    }

    pub(crate) fn restore(&mut self, saved: Checkpoint) {
        self.image = saved.image;
        self.roots = saved.roots;
        self.chunk_root = saved.chunk_root;
        self.volume.install(saved.mapping);
        self.trees = saved.trees;
        self.space = saved.space;
        self.accounting = saved.accounting;
        self.quota = saved.quota;
        self.delalloc = saved.delalloc;
        self.force_commit = saved.force_commit;
        self.open = saved.open;
    }

    /// Checks quota limits on subvolume `tree` before allocating
    /// `additional_bytes` of data/metadata.
    pub(crate) fn check_quota_limit(
        &self,
        tree: u64,
        additional_bytes: u64,
    ) -> Result<(), WriteError> {
        let Some(quota) = &self.quota else {
            return Ok(());
        };
        let pending = self.delalloc.tree_bytes(tree);
        quota.check_limit(tree, pending, additional_bytes)
    }

    /// Enables quota groups by creating `QUOTA_TREE` and scanning all live
    /// subvolumes.
    pub(crate) async fn quota_enable(&mut self) -> Result<(), WriteError> {
        if self.quota.is_some() {
            return Err(WriteError::QuotaAlreadyEnabled);
        }
        let qroot = self
            .trees
            .create(
                &self.volume,
                self.roots.root,
                objectid::QUOTA_TREE,
                &mut self.space,
            )
            .await?;
        self.roots.insert_internal(qroot);
        let mut quota = QuotaTree::new_enabled(qroot, self.trees.generation());
        quota
            .recompute(&self.volume, &self.trees, &self.roots)
            .await?;
        self.quota = Some(quota);
        self.force_commit = true;
        Ok(())
    }

    /// Disables quota groups by dropping `QUOTA_TREE` and removing its root
    /// item from `ROOT_TREE`.
    pub(crate) async fn quota_disable(&mut self) -> Result<(), WriteError> {
        let Some(quota) = self.quota.take() else {
            return Err(WriteError::QuotaNotEnabled);
        };
        // Commit/sync ensures `QUOTA_TREE` blocks are accounted before dropping;
        // caller runs this on a clean transaction so `quota.root` is committed.
        self.drop_subtree(objectid::QUOTA_TREE, quota.root).await?;
        self.roots
            .remove_tree(
                &self.volume,
                &mut self.trees,
                &mut self.space,
                objectid::QUOTA_TREE,
            )
            .await?;
        self.force_commit = true;
        Ok(())
    }

    /// Recomputes every qgroup's referenced and exclusive byte counters from
    /// scratch.
    pub(crate) async fn quota_rescan(&mut self) -> Result<(), WriteError> {
        let Some(quota) = &mut self.quota else {
            return Err(WriteError::QuotaNotEnabled);
        };
        quota
            .recompute(&self.volume, &self.trees, &self.roots)
            .await?;
        self.force_commit = true;
        Ok(())
    }

    pub(crate) fn qgroup_create(
        &mut self,
        id: helios_hal::fs_management::QgroupId,
    ) -> Result<(), WriteError> {
        let generation = self.trees.generation();
        let Some(quota) = &mut self.quota else {
            return Err(WriteError::QuotaNotEnabled);
        };
        quota.create_group(id, generation)?;
        self.force_commit = true;
        Ok(())
    }

    pub(crate) fn qgroup_destroy(
        &mut self,
        id: helios_hal::fs_management::QgroupId,
    ) -> Result<(), WriteError> {
        let live: alloc::collections::BTreeSet<u64> = self
            .roots
            .live_subvolume_roots()
            .into_iter()
            .map(|(tree, _)| tree)
            .collect();
        let Some(quota) = &mut self.quota else {
            return Err(WriteError::QuotaNotEnabled);
        };
        quota.destroy_group(id, &live)?;
        self.force_commit = true;
        Ok(())
    }

    pub(crate) fn qgroup_assign(
        &mut self,
        member: helios_hal::fs_management::QgroupId,
        parent: helios_hal::fs_management::QgroupId,
    ) -> Result<(), WriteError> {
        let Some(quota) = &mut self.quota else {
            return Err(WriteError::QuotaNotEnabled);
        };
        quota.assign(member, parent)?;
        self.force_commit = true;
        Ok(())
    }

    pub(crate) fn qgroup_remove(
        &mut self,
        member: helios_hal::fs_management::QgroupId,
        parent: helios_hal::fs_management::QgroupId,
    ) -> Result<(), WriteError> {
        let Some(quota) = &mut self.quota else {
            return Err(WriteError::QuotaNotEnabled);
        };
        quota.remove_relation(member, parent)?;
        self.force_commit = true;
        Ok(())
    }

    pub(crate) fn qgroup_limit(
        &mut self,
        id: helios_hal::fs_management::QgroupId,
        limit: helios_hal::fs_management::QgroupLimit,
    ) -> Result<(), WriteError> {
        let Some(quota) = &mut self.quota else {
            return Err(WriteError::QuotaNotEnabled);
        };
        quota.set_limit(id, limit)?;
        self.force_commit = true;
        Ok(())
    }

    pub(crate) async fn inode_metadata(&self, file: FileId) -> Result<Metadata, WriteError> {
        let (_, mut metadata) = self.inode_item(file.tree, file.inode).await?;
        metadata.nbytes = metadata
            .nbytes
            .saturating_add(self.delalloc.file_bytes(file.tree, file.inode));
        Ok(metadata)
    }

    pub(crate) async fn lookup_file(&self, name: Name<'_>) -> Result<Option<FileId>, WriteError> {
        Ok(match self.lookup_target(name).await? {
            Some((EntryTarget::Inode(inode), _)) => Some(FileId {
                tree: name.tree,
                inode,
            }),
            Some((EntryTarget::Subvolume(tree), _)) => Some(FileId {
                tree,
                inode: self.roots.root_directory(tree)?,
            }),
            None => None,
        })
    }

    /// Read the transaction's current inode and data: its dirty pages, and
    /// its extents, staged data and unpublished checksum items included.
    pub(crate) async fn read_file(
        &self,
        tree: u64,
        inode: u64,
        offset: u64,
        output: &mut [u8],
    ) -> Result<usize, WriteError> {
        let root = self.roots.get(tree)?;
        let (_, metadata) = self.file_inode(tree, inode).await?;
        let nodes = self.trees.reader(&self.volume);
        Ok(
            Reader::new(&self.volume, &nodes, self.accounting.checksum_root())
                .read(
                    File {
                        root,
                        number: inode,
                        metadata: &metadata,
                        dirty: self.delalloc.file(tree, inode),
                    },
                    offset,
                    output,
                )
                .await?,
        )
    }

    /// Starts from the writer's committed allocation state for `pin`'s
    /// generation. Only the roots are read from disk; the per-transaction
    /// exclusions (mirror stripes, reader pins) are applied to a clone.
    /// `compresses` says whether the mount compresses new data.
    pub(crate) async fn new(
        volume: Volume<S>,
        pin: Arc<Snapshot>,
        retirements: &mut Retirements,
        committed: &Allocation,
        compresses: bool,
    ) -> Result<Self, WriteError> {
        let root = pin.root_tree;
        let (image, roots) =
            future::try_join(volume.commit_image(), Roots::load(&volume, root)).await?;
        let generation = volume
            .superblock()
            .generation()
            .checked_add(1)
            .ok_or(WriteError::GenerationOverflow)?;
        let mut space = committed.space.clone();
        space.rebind(&roots)?;
        space.exclude_superblock_stripes(volume.chunks());
        retirements.protect(&pin, &mut space);
        let mut free = committed.free.clone();
        if let Some(free) = &mut free {
            free.rebind(roots.get(objectid::FREE_SPACE_TREE)?);
        }
        let accounting = Accounting::with_free(
            &volume,
            roots.get(objectid::EXTENT_TREE)?,
            &space,
            roots.get(objectid::CSUM_TREE)?,
            free,
        );
        let quota = if let Ok(qroot) = roots.get(objectid::QUOTA_TREE) {
            Some(QuotaTree::load(&volume, qroot).await?)
        } else {
            None
        };
        let trees = Trees::new(generation, volume.superblock().csum_type());
        let delalloc = Delalloc::new(
            u64::from(volume.superblock().sectorsize()),
            reserve::csums_per_leaf(volume.superblock()),
            compresses,
        );
        let chunk = volume.superblock().chunk_tree();
        Ok(Self {
            generation: pin,
            inode_high_water: BTreeMap::new(),
            volume,
            image,
            roots,
            released: Vec::new(),
            excluded_device: None,
            device_size_limit: None,
            chunk_root: TreeRoot {
                tree: objectid::CHUNK_TREE,
                bytenr: chunk.bytenr,
                level: chunk.level,
                generation: chunk.generation,
            },
            space,
            accounting,
            quota,
            trees,
            delalloc,
            force_commit: false,
            open: OpenInodes::new(),
        })
    }

    /// Bytes used once this transaction commits, as the superblock's
    /// `bytes_used` will record them.
    pub(crate) fn bytes_used(&self) -> Result<u64, WriteError> {
        self.accounting.bytes_used(&self.space)
    }

    /// Consume the overlay. Any failure/cancellation prevents in-memory root
    /// publication; BlockSink's commit contract poisons failed durable commits.
    /// Blocks this transaction retired, and private data it released while a
    /// view still reached it, are recorded in `retirements` against the
    /// generation it started from.
    pub(crate) async fn commit(
        mut self,
        retirements: &mut Retirements,
        mut uuid: impl FnMut() -> [u8; 16],
        compressor: &mut Compressor,
        concurrency: NonZeroUsize,
    ) -> Result<Committed<S>, WriteError> {
        // The dirty data gets its extents before anything is written, so
        // the generation holds every change readers saw.
        self.writeback_all(compressor, concurrency).await?;
        // Block groups nothing uses leave first, as the cleaner does after a
        // commit; what they free is out of reach of this commit's chunks.
        self.remove_unused_groups().await?;
        // A metadata chunk the commit may need exists before it starts.
        if self.trees.blocks().next().is_some() || self.quota.is_some() {
            self.grow_metadata().await?;
        }
        // When quotas are enabled and anything changed (or quota state itself
        // was edited), recompute exact qgroup counts over all live subvolumes
        // before the root/extent convergence loop writes `QUOTA_TREE`.
        if let Some(quota) = &mut self.quota
            && (quota.dirty || self.force_commit || self.trees.blocks().next().is_some())
        {
            quota
                .recompute(&self.volume, &self.trees, &self.roots)
                .await?;
        }
        loop {
            let mut quota_changed = false;
            if let Some(quota) = &mut self.quota {
                quota_changed = quota
                    .sync(&self.volume, &mut self.trees, &mut self.space)
                    .await?;
                self.roots.set(quota.root)?;
            }
            self.accounting
                .sync_allocations(&self.volume, &mut self.trees, &mut self.space)
                .await?;
            self.roots.set(self.accounting.root)?;
            self.roots.set(self.accounting.group_root())?;
            self.roots.set(self.accounting.checksum_root())?;
            if let Some(root) = self.accounting.free_root() {
                self.roots.set(root)?;
            }
            let roots_changed = self
                .roots
                .sync(&self.volume, &mut self.trees, &mut self.space, &mut uuid)
                .await?;
            if !roots_changed && !quota_changed {
                break;
            }
        }
        if !self.force_commit && self.trees.blocks().next().is_none() {
            return Ok(Committed {
                snapshot: self.generation.clone(),
                devices: self.volume.shared_devices(),
                allocation: None,
            });
        }
        let dev_items = self.all_dev_items().await?;
        if let Some((_, primary)) = dev_items
            .iter()
            .find(|(id, _)| *id == self.volume.superblock().devid())
            .or_else(|| dev_items.first())
        {
            self.image.set_dev_item(*primary);
        }
        let total_bytes: u64 = dev_items
            .iter()
            .map(|(_, item)| item.total_bytes.get())
            .sum();
        self.image
            .set_device_totals(dev_items.len() as u64, total_bytes);
        let allocation = self.accounting.committed(&self.space)?;
        self.image.prepare(
            &self.roots,
            self.chunk_root,
            self.accounting.bytes_used(&self.space)?,
        )?;
        let superblock = self
            .image
            .superblock(self.volume.superblock().csum_type())?;
        let snapshot =
            self.generation
                .advance(superblock, self.volume.shared_chunks(), &self.roots)?;
        // Register before the first await that can publish the new generation.
        // Cancellation or a failed mirror write must not lose these pins.
        let mut retired = self.accounting.take_retired();
        for (address, length) in &self.space.take_held() {
            retired.insert_mut(*address, *length);
        }
        retirements.record(&self.generation, retired);
        // Bound the total in-flight I/O by staging one block per concurrent
        // stream item. Volume::stage handles this block's physical copies.
        let mut writes = PendingWrites::new(concurrency);
        for (logical, bytes) in self.trees.blocks() {
            for (index, bytes) in bytes.chunks(READ_ALIGNMENT as usize).enumerate() {
                writes
                    .push(self.volume.stage(
                        logical + index as u64 * READ_ALIGNMENT,
                        bytes,
                        NonZeroUsize::MIN,
                    ))
                    .await?;
            }
        }
        writes.finish().await?;
        let devices = self.volume.shared_devices();
        self.volume.publish(self.image, &dev_items).await?;
        Ok(Committed {
            snapshot,
            devices,
            allocation: Some(allocation),
        })
    }
}
