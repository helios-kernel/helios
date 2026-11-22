//! One owner applies every mutation to a running transaction; readers own
//! independent immutable views of it. No mutex is held across I/O.
//!
//! # Concurrency contract
//!
//! - The [`Writer`] is single-owner. It holds the running transaction, the
//!   last durable generation, the carried allocation state and the reader
//!   pins; every mutation and every commit takes `&mut Writer`, so they are
//!   serialized by ownership, never by a lock.
//! - A mutation applies to the running transaction and is visible the moment
//!   it is accepted: acceptance takes a view of the transaction, which every
//!   later [`Writer::snapshot`] hands out. A view is a handful of persistent
//!   collection roots, so taking one costs reference-count increments, and a
//!   reader holding one reads without the writer and on any processor.
//! - A view keeps what it reaches readable for as long as it lives: the
//!   transaction's private tree blocks are in the view itself, committed
//!   blocks the transaction retires stay pinned through the generation the
//!   transaction started from, and private data the transaction releases is
//!   held from reuse until no live view reaches it.
//! - A write dirties pages of the running transaction and allocates no
//!   extent, as Linux's delayed allocation: it reserves the data space its
//!   pages need when it is accepted, so it is refused, or stored short,
//!   with `ENOSPC` then and never later. [`Writer::writeback`] gives the
//!   dirty data its extents, at Linux's sizes; its caller runs it when the
//!   dirty data reaches its bound, and every commit runs it first.
//! - [`Writer::commit`] makes the running transaction durable as one
//!   generation. Its caller decides when; Linux commits on `sync`, `fsync`
//!   and `fdatasync`, when its `commit=` interval expires, when the dirty
//!   state reaches its bound ([`DEFAULT_DIRTY_METADATA_LIMIT`] unless the
//!   operator chose another), and at unmount. The changes a
//!   commit carries were already visible, so a commit that fails, or whose
//!   future is dropped, cannot withdraw them: the writer is poisoned and the
//!   device keeps the previous complete generation.

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::num::NonZeroUsize;
use core::ops::{Deref, DerefMut};
use helios_hal::fs::RenameMode;
use helios_hal::fs_management::{
    BalanceFilter, BalanceReport, DedupeOutcome, QgroupId, QgroupInfo, QgroupLimit, QuotaStatus,
    ResizeTarget, ScrubReport, SubvolumeInfo, VolumeDeviceInfo,
};

use super::{Filesystem, Snapshot};
use crate::accounting::Allocation;
use crate::compress::policy::Compressor;
use crate::retirement::Retirements;
use crate::roots::Roots;
use crate::source::BlockSink;
use crate::space::{DATA, SpaceError};
use crate::transaction::fallocate::AllocateMode;
use crate::transaction::file::DEFAULT_MAX_INLINE;
use crate::transaction::namespace::{Attributes as RawAttributes, Name as RawName};
use crate::transaction::orphan::{OpenInodes, ReleaseOutcome, committed_orphans};
use crate::transaction::reflink::{CloneRange as RawCloneRange, FileId};
use crate::transaction::replay::PendingLog;
use crate::transaction::reserve::Units;
use crate::transaction::xattr::XattrMode;
use crate::transaction::{Checkpoint, Transaction};
use crate::tree::write::WriteError;
use crate::{DeviceNumber, Error, FileKind, Metadata, Timestamp};

/// The dirty metadata a running transaction holds before it is committed,
/// unless the mount's operator chose another bound: Linux's
/// `BTRFS_DIRTY_METADATA_THRESH`, `SZ_32M` in `fs/btrfs/fs.h`, past which
/// `btrfs_btree_balance_dirty` writes the btree's dirty blocks back. The
/// running transaction keeps its private blocks in memory until commit, so
/// a commit is what writes them back here.
pub const DEFAULT_DIRTY_METADATA_LIMIT: u64 = 32 << 20;

/// The share of memory, in percent, that dirty file data takes before
/// writeback starts: Linux's `dirty_background_ratio`, 10 in
/// `mm/page-writeback.c`, which starts background writeback when the dirty
/// pages reach that share of the memory that can hold them
/// (`global_dirtyable_memory`).
pub const DIRTY_BACKGROUND_RATIO: u64 = 10;

/// The dirty data a mount holds before [`Writer::writeback`], unless its
/// operator chose another bound: [`DIRTY_BACKGROUND_RATIO`] of the
/// `memory_bytes` that can hold it.
pub const fn default_dirty_data_limit(memory_bytes: u64) -> u64 {
    memory_bytes / 100 * DIRTY_BACKGROUND_RATIO
}

/// What the running transaction holds that its commit writes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Dirty {
    /// Bytes of private tree blocks held in memory.
    pub metadata_bytes: u64,
    /// Bytes of file data held in memory without extents, which
    /// [`Writer::writeback`] writes.
    pub data_bytes: u64,
}

impl Dirty {
    /// Nothing waits for a commit.
    pub const fn is_clean(self) -> bool {
        self.metadata_bytes == 0 && self.data_bytes == 0
    }
}

#[derive(Debug)]
struct MountIdentity;

/// A mount-bound inode identity. Its generation detects reuse after deletion.
#[derive(Clone, Debug)]
pub struct InodeHandle {
    mount: Arc<MountIdentity>,
    id: FileId,
    generation: u64,
}

impl InodeHandle {
    pub fn tree(&self) -> u64 {
        self.id.tree
    }
    pub fn number(&self) -> u64 {
        self.id.inode
    }
}

/// Permissions and ownership for a newly created entry. File type is selected
/// by create_file, create_directory, symlink or create_special, never by
/// permission bits. Every bit of `07777` is stored as given, the set-id and
/// sticky bits included, on every kind of inode.
#[derive(Clone, Copy, Debug)]
pub struct Attributes {
    /// The mode bits asked for, before the umask.
    pub permissions: u32,
    pub uid: u32,
    /// The creating process's group; overridden by the parent directory's
    /// when the parent carries `S_ISGID`, as `inode_init_owner` does.
    pub gid: u32,
    /// The creating process's umask. As in Linux's `posix_acl_create`, it
    /// narrows `permissions` only when the parent directory has no default
    /// ACL; a default ACL narrows them instead, and the new inode inherits
    /// it.
    pub umask: u32,
}

impl Attributes {
    fn raw(self, kind: u32) -> Result<RawAttributes, WriteError> {
        self.raw_with_device(kind, 0)
    }

    fn raw_with_device(self, kind: u32, rdev: u64) -> Result<RawAttributes, WriteError> {
        if self.permissions & !0o7777 != 0 {
            return Err(WriteError::InvalidPermissions {
                permissions: self.permissions,
            });
        }
        Ok(RawAttributes {
            mode: kind | self.permissions,
            uid: self.uid,
            gid: self.gid,
            rdev,
            umask: self.umask,
        })
    }
}

/// A node `mknod` makes that holds no data: a device node, a FIFO or a
/// socket, as `btrfs_mknod` in `fs/btrfs/inode.c` creates them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Special {
    CharDevice(DeviceNumber),
    BlockDevice(DeviceNumber),
    Fifo,
    Socket,
}

impl Special {
    /// The file type bits of the mode, and the inode item's `rdev`.
    fn mode_and_rdev(self) -> (u32, u64) {
        match self {
            Self::CharDevice(device) => (0o020_000, device.inode_item()),
            Self::BlockDevice(device) => (0o060_000, device.inode_item()),
            Self::Fifo => (0o010_000, 0),
            Self::Socket => (0o140_000, 0),
        }
    }
}

#[derive(Clone, Copy)]
pub struct Name<'a> {
    pub parent: &'a InodeHandle,
    pub bytes: &'a [u8],
}

#[derive(Clone, Copy)]
pub struct CloneRange<'a> {
    pub source: &'a InodeHandle,
    pub destination: &'a InodeHandle,
    pub source_offset: u64,
    pub destination_offset: u64,
    pub length: u64,
}

pub struct Writer<S, U> {
    /// The last durable generation; `None` once a commit failed or was
    /// dropped, which poisons the writer.
    committed: Option<Filesystem<Arc<S>>>,
    /// Allocation state of `committed`'s generation, loaded and validated
    /// once at mount and replaced only by a commit that published.
    allocation: Allocation,
    retirements: Retirements,
    running: Option<Running<S>>,
    /// Open-handle accounting carried across transactions while `running` is
    /// `None`; mirrored into `running.inner.open` while a transaction runs.
    open: OpenInodes,
    mount: Arc<MountIdentity>,
    /// What every commit needs, the ones a mutation forces included.
    uuids: U,
    /// The mount's compression, which writeback encodes new extents with.
    compressor: Compressor,
    /// Linux's `max_inline` mount option: the most stored bytes an inline
    /// extent holds.
    max_inline: u64,
    concurrency: NonZeroUsize,
}

/// Where a commit gets the UUID of a root record that has none: Linux's
/// `generate_random_uuid`, which a caller with entropy supplies.
pub trait RootUuids: Send {
    fn next_uuid(&mut self) -> [u8; 16];
}

impl<F: FnMut() -> [u8; 16] + Send> RootUuids for F {
    fn next_uuid(&mut self) -> [u8; 16] {
        self()
    }
}

/// The space a mounted filesystem has and uses, as the running transaction
/// leaves it: what `statfs` reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Usage {
    pub total_bytes: u64,
    pub used_bytes: u64,
    /// Bytes available for file data allocation (`f_bavail` in Linux's
    /// `btrfs_statfs`): free space in existing data block groups plus
    /// unallocated device space usable for new data chunks.
    pub available_bytes: u64,
}

/// The transaction every mutation joins until the next commit.
struct Running<S> {
    inner: Transaction<Arc<S>>,
    /// The view as of the last accepted mutation; `None` until one is, when
    /// the committed generation is still what readers see.
    view: Option<Arc<Snapshot>>,
    /// Every view taken of this transaction that a reader may still hold.
    views: Vec<Weak<Snapshot>>,
}

impl<S: BlockSink, U: RootUuids> Writer<S, U> {
    /// Mounts `source` for writing. Every commit takes root UUIDs from
    /// `uuids`, writeback encodes the data of every inode Linux would
    /// compress with `compressor` (the `compress=` mount option), and both
    /// keep at most `concurrency` block writes in flight.
    ///
    /// A log tree a crash left behind an fsync is replayed first, in one
    /// transaction that this call commits before it returns, as Linux's
    /// `btrfs_recover_log_trees` does at mount; `now` is the time that
    /// replay stamps on what its unlinks change. A log that cannot be
    /// replayed refuses the mount, and the device keeps its last committed
    /// generation.
    pub async fn mount(
        source: S,
        uuids: U,
        concurrency: NonZeroUsize,
        compressor: Compressor,
        now: Timestamp,
    ) -> Result<Self, WriteError> {
        let current = Filesystem::mount_committed(Arc::new(source)).await?;
        Self::finish_mount(current, uuids, concurrency, compressor, now).await
    }

    /// Mounts a multi-device btrfs volume for writing.
    pub async fn mount_devices(
        sources: Vec<S>,
        uuids: U,
        concurrency: NonZeroUsize,
        compressor: Compressor,
        now: Timestamp,
    ) -> Result<Self, WriteError> {
        let wrapped: Vec<Arc<S>> = sources.into_iter().map(Arc::new).collect();
        let current = Filesystem::mount_committed_devices(wrapped).await?;
        Self::finish_mount(current, uuids, concurrency, compressor, now).await
    }

    async fn finish_mount(
        current: Filesystem<Arc<S>>,
        uuids: U,
        concurrency: NonZeroUsize,
        compressor: Compressor,
        now: Timestamp,
    ) -> Result<Self, WriteError> {
        current.superblock().check_writable()?;
        let log = current
            .superblock()
            .log_tree()
            .map(|(bytenr, level)| PendingLog { bytenr, level });
        let allocation = Allocation::load(&current.volume, current.snapshot.root_tree).await?;
        let mut writer = Self {
            committed: Some(current),
            allocation,
            retirements: Retirements::default(),
            running: None,
            open: OpenInodes::new(),
            mount: Arc::new(MountIdentity),
            uuids,
            compressor,
            max_inline: DEFAULT_MAX_INLINE,
            concurrency,
        };
        if let Some(log) = log {
            writer.replay(log, now).await?;
        }
        writer.cleanup_orphans().await?;
        Ok(writer)
    }

    /// Replays `log` in a transaction of its own and commits it, which
    /// clears the superblock's log root even when the replay changed
    /// nothing else. Linux reserves nothing up front for it
    /// (`btrfs_start_transaction(tree_root, 0)`), so only the commit's own
    /// hold is checked.
    async fn replay(&mut self, log: PendingLog, now: Timestamp) -> Result<(), WriteError> {
        self.start().await?;
        let running = self
            .running
            .as_mut()
            .expect("a transaction runs once started");
        running.inner.replay_log(log, now).await?;
        running.inner.check_commit_hold(Units::default())?;
        self.commit_running().await
    }

    /// Processes orphan items left behind by a crash across every live
    /// writable subvolume before the writable mount is published, as Linux's
    /// `btrfs_cleanup_fs_roots` and `btrfs_orphan_cleanup`. Does nothing and
    /// writes no generation when no subvolume carries an orphan item.
    async fn cleanup_orphans(&mut self) -> Result<(), WriteError> {
        let pending: Vec<(u64, Vec<u64>)> = {
            let committed = self.committed.as_ref().ok_or(WriteError::WriterPoisoned)?;
            let roots = Roots::load(&committed.volume, committed.snapshot.root_tree).await?;
            let mut pending = Vec::new();
            for tree in roots.writable_subvolumes() {
                let root = roots.get(tree)?;
                let orphans = committed_orphans(&committed.volume, root).await?;
                if !orphans.is_empty() {
                    pending.push((tree, orphans));
                }
            }
            pending
        };
        if pending.is_empty() {
            return Ok(());
        }
        self.start().await?;
        for (tree, orphans) in pending {
            for inode in orphans {
                if self.running.is_none() {
                    self.start().await?;
                }
                let running = self
                    .running
                    .as_mut()
                    .expect("a transaction runs once started");
                running.inner.prepare_mutation().await?;
                running.inner.cleanup_orphan(tree, inode).await?;
                if running.inner.dirty_metadata_bytes() >= DEFAULT_DIRTY_METADATA_LIMIT {
                    running.inner.check_commit_hold(Units::default())?;
                    self.commit_running().await?;
                }
            }
        }
        if let Some(running) = self.running.as_mut() {
            running.inner.check_commit_hold(Units::default())?;
            self.commit_running().await?;
        }
        Ok(())
    }

    /// Whether any open handle currently keeps an unlinked or `O_TMPFILE`
    /// orphan inode alive on this mount.
    pub fn has_open_orphans(&self) -> bool {
        match &self.running {
            Some(running) => running.inner.open.has_orphans(),
            None => self.open.has_orphans(),
        }
    }

    /// The mount's `max_inline` limit, in bytes.
    pub fn max_inline(&self) -> u64 {
        self.max_inline
    }

    /// Changes the mount's `max_inline`, as Linux's
    /// `mount -o remount,max_inline=`: subsequent mutations store inline data
    /// under the new limit, and what is already stored stays as it is.
    pub fn set_max_inline(&mut self, max_inline: u64) {
        self.max_inline = max_inline;
    }

    /// Changes the mount's compression policy, as Linux's
    /// `mount -o remount,compress=`: writes back dirty data queued under the
    /// previous policy first so its reserved extent count stays exact, then
    /// applies `compressor` to subsequent writes.
    pub async fn set_compressor(&mut self, compressor: Compressor) -> Result<(), WriteError> {
        self.writeback().await?;
        let compresses = compressor.algorithm().is_some();
        self.compressor = compressor;
        if let Some(running) = &mut self.running {
            running.inner.delalloc.set_compresses(compresses);
        }
        Ok(())
    }

    /// The space the filesystem has, and what it uses once the running
    /// transaction commits: a write is visible at once, and so is its
    /// space, its dirty data counted at the space it reserved.
    pub fn usage(&self) -> Result<Usage, WriteError> {
        const DUP: u64 = 1 << 5;
        let committed = self.committed.as_ref().ok_or(WriteError::WriterPoisoned)?;
        let superblock = committed.superblock();
        let total_bytes = superblock.total_bytes();
        let (used_bytes, available_bytes) = match &self.running {
            Some(running) => {
                let used = running.inner.bytes_used()? + running.inner.dirty_data_bytes();
                let dup = running
                    .inner
                    .space
                    .latest_flags(DATA)
                    .is_some_and(|flags| flags & DUP != 0);
                let avail = running.inner.data_budget().saturating_add(
                    running
                        .inner
                        .volume
                        .chunks()
                        .unallocated_data_bytes(total_bytes, dup),
                );
                (used, avail.min(total_bytes.saturating_sub(used)))
            }
            None => {
                let used = superblock.bytes_used();
                let chunks = committed.volume.chunks();
                let dup = self
                    .allocation
                    .space
                    .latest_flags(DATA)
                    .is_some_and(|flags| flags & DUP != 0);
                let free_data = self
                    .allocation
                    .space
                    .totals(DATA)
                    .1
                    .saturating_sub(chunks.data_superblock_stripe_bytes());
                let avail =
                    free_data.saturating_add(chunks.unallocated_data_bytes(total_bytes, dup));
                (used, avail.min(total_bytes.saturating_sub(used)))
            }
        };
        Ok(Usage {
            total_bytes,
            used_bytes,
            available_bytes,
        })
    }

    #[cfg(test)]
    pub(crate) fn committed_allocation(&self) -> &Allocation {
        &self.allocation
    }

    /// What a reader sees now: the running transaction as of its last
    /// accepted mutation, or the last durable generation when nothing has
    /// changed since.
    pub fn snapshot(&self) -> Result<Filesystem<Arc<S>>, WriteError> {
        let committed = self.committed.as_ref().ok_or(WriteError::WriterPoisoned)?;
        Ok(
            match self
                .running
                .as_ref()
                .and_then(|running| Some((running, running.view.clone()?)))
            {
                Some((running, snapshot)) => Filesystem {
                    snapshot,
                    volume: running.inner.volume.clone(),
                },
                None => committed.clone(),
            },
        )
    }

    /// What the next commit writes.
    pub fn dirty(&self) -> Dirty {
        self.running
            .as_ref()
            .map_or(Dirty::default(), |running| Dirty {
                metadata_bytes: running.inner.dirty_metadata_bytes(),
                data_bytes: running.inner.dirty_data_bytes(),
            })
    }

    /// Gives the running transaction's dirty data its extents, as Linux's
    /// writeback of an inode's delalloc ranges; the data stays visible as it
    /// was and becomes durable at the next commit. A failure, or dropping the
    /// future, leaves the data dirty and the transaction as it was.
    pub async fn writeback(&mut self) -> Result<(), WriteError> {
        if self.dirty().data_bytes == 0 {
            return Ok(());
        }
        let mut transaction = self.join().await?;
        let mut operation = Mutation::checkpointed(&mut transaction, Units::default());
        operation.inner_mut().prepare_mutation().await?;
        let (inner, compressor, concurrency, _) = operation.split();
        inner.writeback_all(compressor, concurrency).await?;
        // The reservations the data took when it was written pay for this:
        // there is nothing left to refuse it for.
        operation.publish()
    }

    /// Joins the running transaction, starting one from the last durable
    /// generation when none runs, as `btrfs_join_transaction` does. Dropping
    /// the handle leaves every mutation it accepted in the transaction.
    pub async fn join(&mut self) -> Result<WriteTransaction<'_, S, U>, WriteError> {
        self.start().await?;
        Ok(WriteTransaction { writer: self })
    }

    /// Starts a running transaction from the last durable generation unless
    /// one runs.
    async fn start(&mut self) -> Result<(), WriteError> {
        let committed = self.committed.as_ref().ok_or(WriteError::WriterPoisoned)?;
        if self.running.is_none() {
            let (volume, pin) = (committed.volume.clone(), committed.snapshot.clone());
            let mut inner = Transaction::new(
                volume,
                pin,
                &mut self.retirements,
                &self.allocation,
                self.compressor.algorithm().is_some(),
            )
            .await?;
            inner.open = self.open.clone();
            self.running = Some(Running {
                inner,
                view: None,
                views: Vec::new(),
            });
        }
        Ok(())
    }

    /// Makes every mutation the running transaction holds durable as one
    /// generation, which readers then see: its dirty data is written back
    /// first. With nothing running, or nothing changed, nothing is written.
    ///
    /// The changes were visible before this call, so a failure, or dropping
    /// the future before it finishes, poisons the writer instead of
    /// discarding them; the device keeps the previous generation.
    pub async fn commit(&mut self) -> Result<(), WriteError> {
        if self.committed.is_none() {
            return Err(WriteError::WriterPoisoned);
        }
        if self.running.as_ref().is_none_or(|running| {
            !running.inner.force_commit
                && running.inner.dirty_metadata_bytes() == 0
                && running.inner.dirty_data_bytes() == 0
        }) {
            // A clean transaction holds nothing the last commit did not,
            // except any in-memory open-handle accounting updates.
            if let Some(running) = self.running.take() {
                self.open = running.inner.open;
            }
            return Ok(());
        }
        self.commit_running().await
    }

    /// Resolves a normalized relative path inside the running transaction
    /// starting at the default subvolume root.
    async fn resolve_tx_path(&self, path: &str) -> Result<FileId, WriteError> {
        let running = self
            .running
            .as_ref()
            .expect("a transaction runs once started");
        let default = running.inner.base().default_subvolume;
        let mut current = FileId {
            tree: default.root.tree,
            inode: default.root_dirid,
        };
        if !path.is_empty() {
            for seg in path.split('/') {
                current = running
                    .inner
                    .lookup_file(RawName {
                        tree: current.tree,
                        parent: current.inode,
                        bytes: seg.as_bytes(),
                    })
                    .await?
                    .ok_or(WriteError::NoEntry {
                        tree: current.tree,
                        parent: current.inode,
                    })?;
            }
        }
        Ok(current)
    }

    /// Creates a new empty subvolume at `parent_path`/`name` and commits it.
    pub async fn create_subvolume(
        &mut self,
        parent_path: &str,
        name: &[u8],
        attributes: Attributes,
        when: Timestamp,
    ) -> Result<SubvolumeInfo, WriteError> {
        self.start().await?;
        let parent = self.resolve_tx_path(parent_path).await?;
        let raw_attrs = attributes.raw(0o040_000)?;
        let uuid = self.uuids.next_uuid();
        let tree_id = {
            let mut tx = self.join().await?;
            let mut op = Mutation::new(&mut tx, Units::CREATE).await?;
            let id = op
                .inner_mut()
                .create_subvolume(
                    RawName {
                        tree: parent.tree,
                        parent: parent.inode,
                        bytes: name,
                    },
                    raw_attrs,
                    when,
                    uuid,
                )
                .await?;
            op.accept()?;
            id
        };
        self.commit().await?;
        self.subvolume_info(tree_id).await
    }

    /// Creates a snapshot of subvolume `source_tree` at `dest_parent_path`/`name`,
    /// flushing any pending changes and delalloc first, then commits it.
    pub async fn snapshot_subvolume(
        &mut self,
        source_tree: u64,
        dest_parent_path: &str,
        name: &[u8],
        read_only: bool,
        when: Timestamp,
    ) -> Result<SubvolumeInfo, WriteError> {
        // Flush delalloc and commit pending edits so the source root block and
        // its direct children are accounted in `EXTENT_TREE`.
        self.commit().await?;
        self.start().await?;
        let parent = self.resolve_tx_path(dest_parent_path).await?;
        let uuid = self.uuids.next_uuid();
        let snap_tree = {
            let mut tx = self.join().await?;
            let mut op = Mutation::new(&mut tx, Units::CREATE).await?;
            let id = op
                .inner_mut()
                .snapshot_subvolume(
                    source_tree,
                    RawName {
                        tree: parent.tree,
                        parent: parent.inode,
                        bytes: name,
                    },
                    read_only,
                    when,
                    uuid,
                )
                .await?;
            op.accept()?;
            id
        };
        self.commit().await?;
        self.subvolume_info(snap_tree).await
    }

    /// Deletes the subvolume linked at `parent_path`/`name` and commits.
    pub async fn delete_subvolume(
        &mut self,
        parent_path: &str,
        name: &[u8],
        when: Timestamp,
    ) -> Result<(), WriteError> {
        self.commit().await?;
        self.start().await?;
        let parent = self.resolve_tx_path(parent_path).await?;
        {
            let mut tx = self.join().await?;
            let mut op = Mutation::new(&mut tx, Units::UNLINK).await?;
            op.inner_mut()
                .delete_subvolume(
                    RawName {
                        tree: parent.tree,
                        parent: parent.inode,
                        bytes: name,
                    },
                    when,
                )
                .await?;
            op.accept()?;
        }
        self.commit().await
    }

    /// Toggles `BTRFS_ROOT_SUBVOL_RDONLY` on subvolume `tree` and commits.
    pub async fn set_subvolume_read_only(
        &mut self,
        tree: u64,
        read_only: bool,
    ) -> Result<(), WriteError> {
        self.commit().await?;
        self.start().await?;
        {
            let mut tx = self.join().await?;
            let mut op = Mutation::new(&mut tx, Units::INODE_UPDATE).await?;
            op.inner_mut().roots.set_read_only(tree, read_only)?;
            op.inner_mut().force_commit = true;
            op.accept()?;
        }
        self.commit().await
    }

    /// Returns metadata and canonical path for subvolume `tree`.
    pub async fn subvolume_info(&mut self, tree: u64) -> Result<SubvolumeInfo, WriteError> {
        self.start().await?;
        self.running
            .as_ref()
            .expect("transaction started")
            .inner
            .subvolume_info(tree)
            .await
    }

    /// Lists every live subvolume in the filesystem.
    pub async fn list_subvolumes(&mut self) -> Result<Vec<SubvolumeInfo>, WriteError> {
        self.start().await?;
        let inner = &self.running.as_ref().expect("transaction started").inner;
        let trees: Vec<u64> = inner
            .roots
            .live_subvolume_roots()
            .into_iter()
            .map(|(id, _)| id)
            .collect();
        let mut out = Vec::with_capacity(trees.len());
        for tree in trees {
            out.push(inner.subvolume_info(tree).await?);
        }
        Ok(out)
    }

    /// Produces a Linux-compatible btrfs send stream (v1) for read-only
    /// subvolume `tree` (full or incremental against `parent_tree`, with
    /// optional `clone_trees`).
    pub async fn send_subvolume(
        &mut self,
        tree: u64,
        parent_tree: Option<u64>,
        clone_trees: &[u64],
    ) -> Result<Vec<u8>, WriteError> {
        self.commit().await?;
        self.start().await?;
        let view = self.snapshot()?;
        let inner = &self.running.as_ref().expect("transaction started").inner;
        let (_, rel_path) = inner.subvolume_path(tree).await?;
        let basename = rel_path.rsplit('/').next().unwrap_or("subvol");
        crate::send::send_subvolume(
            &view,
            &inner.roots,
            basename.as_bytes(),
            tree,
            parent_tree,
            clone_trees,
        )
        .await
    }

    /// Consumes a Linux-compatible btrfs send stream (v1), creating a new
    /// subvolume (or snapshot for an incremental stream) inside `dest_dir_path`
    /// and committing the result.
    ///
    /// `authorize_source` is called with the canonical mount-relative path of
    /// any existing subvolume referenced by `SNAPSHOT` or `CLONE` before any
    /// data is copied or snapshotted from it.
    pub async fn receive_subvolume<F>(
        &mut self,
        dest_dir_path: &str,
        stream: &[u8],
        when: Timestamp,
        mut authorize_source: F,
    ) -> Result<SubvolumeInfo, WriteError>
    where
        F: FnMut(&str) -> Result<(), WriteError>,
    {
        let commands = crate::receive::parse_stream(stream)?;
        let init = crate::receive::decode_receive_init(&commands)?;

        // Commit any prior pending work so parent snapshot lookup sees committed roots.
        self.commit().await?;
        self.start().await?;
        let dest_parent = self.resolve_tx_path(dest_dir_path).await?;
        let new_uuid = self.uuids.next_uuid();

        let (target_tree, received_uuid, stransid) = match init {
            crate::receive::ReceiveInit::Subvol {
                name,
                uuid,
                ctransid,
            } => {
                let attrs = Attributes {
                    permissions: 0o755,
                    uid: 0,
                    gid: 0,
                    umask: 0,
                }
                .raw(0o040_000)?;
                let mut tx = self.join().await?;
                let mut op = Mutation::new(&mut tx, Units::CREATE).await?;
                let id = op
                    .inner_mut()
                    .create_subvolume(
                        RawName {
                            tree: dest_parent.tree,
                            parent: dest_parent.inode,
                            bytes: name,
                        },
                        attrs,
                        when,
                        new_uuid,
                    )
                    .await?;
                op.accept()?;
                (id, uuid, ctransid)
            }
            crate::receive::ReceiveInit::Snapshot {
                name,
                uuid,
                ctransid,
                clone_uuid,
                clone_ctransid,
            } => {
                let parent_tree = {
                    let inner = &self.running.as_ref().expect("transaction started").inner;
                    let found = inner
                        .roots
                        .find_subvolume_by_uuid(clone_uuid, Some(clone_ctransid))
                        .ok_or_else(|| {
                            WriteError::InvalidStream(alloc::string::String::from(
                                "SNAPSHOT references unknown parent subvolume UUID",
                            ))
                        })?;
                    let (_, parent_root_path) = inner.subvolume_path(found).await?;
                    authorize_source(&parent_root_path)?;
                    found
                };
                let mut tx = self.join().await?;
                let mut op = Mutation::new(&mut tx, Units::CREATE).await?;
                let id = op
                    .inner_mut()
                    .snapshot_subvolume(
                        parent_tree,
                        RawName {
                            tree: dest_parent.tree,
                            parent: dest_parent.inode,
                            bytes: name,
                        },
                        false, // writable while applying stream commands; set RO at END
                        when,
                        new_uuid,
                    )
                    .await?;
                op.accept()?;
                (id, uuid, ctransid)
            }
        };

        // Commit the created subvolume/snapshot first so any in-stream CLONE
        // or rollback operates cleanly, then apply all stream commands in a
        // transaction and commit.
        self.commit().await?;
        self.start().await?;
        {
            let mut tx = self.join().await?;
            let mut op = Mutation::checkpointed(&mut tx, Units::default());
            let (inner, compressor, concurrency, max_inline) = op.split();
            crate::receive::apply_receive_commands(
                inner,
                crate::receive::ReceiveApplyContext {
                    target_tree,
                    received_uuid,
                    stransid,
                    when,
                    compressor,
                    concurrency,
                    max_inline,
                },
                &commands,
                authorize_source,
            )
            .await?;
            op.publish()?;
        }
        self.commit().await?;
        self.subvolume_info(target_tree).await
    }

    /// Lists every backing device currently in the volume.
    pub async fn list_devices(&mut self) -> Result<Vec<VolumeDeviceInfo>, WriteError> {
        self.start().await?;
        self.running
            .as_ref()
            .expect("transaction started")
            .inner
            .list_devices()
            .await
    }

    /// Adds a new backing device `device` to the volume and commits.
    pub async fn add_device(&mut self, device: S) -> Result<VolumeDeviceInfo, WriteError> {
        self.commit().await?;
        self.start().await?;
        let uuid = self.uuids.next_uuid();
        let info = {
            let mut tx = self.join().await?;
            let mut op = Mutation::new(&mut tx, Units::CREATE).await?;
            let info = op
                .inner_mut()
                .add_device(Arc::new(Arc::new(device)), uuid)
                .await?;
            op.publish()?;
            info
        };
        self.commit().await?;
        Ok(info)
    }

    /// Relocates all chunks off `devid`, removes `devid` from the volume,
    /// commits the updated remaining devices, and wipes `devid`'s superblocks.
    pub async fn remove_device(&mut self, devid: u64) -> Result<(), WriteError> {
        self.commit().await?;
        self.start().await?;
        let (to_relocate, dev_count) = {
            let inner = &self.running.as_ref().expect("transaction started").inner;
            let devs = inner.all_dev_items().await?;
            if !devs.iter().any(|(id, _)| *id == devid) {
                return Err(WriteError::DeviceNotFound { devid });
            }
            let chunks: Vec<(u64, u64, u64)> = inner
                .volume
                .chunks()
                .chunks()
                .iter()
                .filter(|c| c.copies().iter().any(|s| s.devid == devid))
                .map(|c| (c.logical(), c.length(), c.flags()))
                .collect();
            (chunks, devs.len())
        };
        if dev_count <= 1 {
            return Err(WriteError::LastDevice);
        }
        for (logical, length, flags) in to_relocate {
            self.relocate_one_chunk(logical, length, flags, Some(devid), None)
                .await?;
        }
        self.commit().await?;
        self.start().await?;
        let detached = {
            let mut tx = self.join().await?;
            let mut op = Mutation::checkpointed(&mut tx, Units::default());
            let dev = op.inner_mut().finish_remove_device(devid).await?;
            op.publish()?;
            dev
        };
        self.commit().await?;
        Transaction::<Arc<S>>::wipe_detached(&detached).await?;
        Ok(())
    }

    /// Replaces `source_devid` in place with `target`, commits, and wipes the
    /// old source device's superblocks.
    pub async fn replace_device(
        &mut self,
        source_devid: u64,
        target: S,
    ) -> Result<VolumeDeviceInfo, WriteError> {
        self.commit().await?;
        self.start().await?;
        let uuid = self.uuids.next_uuid();
        let (info, detached) = {
            let mut tx = self.join().await?;
            let mut op = Mutation::checkpointed(&mut tx, Units::default());
            let res = op
                .inner_mut()
                .replace_device(source_devid, Arc::new(Arc::new(target)), uuid)
                .await?;
            op.publish()?;
            res
        };
        self.commit().await?;
        Transaction::<Arc<S>>::wipe_detached(&detached).await?;
        Ok(info)
    }

    /// Resizes `devid` (or the primary device when `None`) to `target`,
    /// relocating any chunks past the new boundary when shrinking.
    pub async fn resize_device(
        &mut self,
        devid: Option<u64>,
        target: ResizeTarget,
    ) -> Result<VolumeDeviceInfo, WriteError> {
        self.commit().await?;
        self.start().await?;
        let (devid, old_size, new_size) = self
            .running
            .as_ref()
            .expect("transaction started")
            .inner
            .resolve_resize_target(devid, target)
            .await?;

        if new_size < old_size {
            let to_relocate: Vec<(u64, u64, u64)> = self
                .running
                .as_ref()
                .expect("transaction started")
                .inner
                .volume
                .chunks()
                .chunks()
                .iter()
                .filter(|c| {
                    c.copies()
                        .iter()
                        .any(|s| s.devid == devid && s.offset + c.length() > new_size)
                })
                .map(|c| (c.logical(), c.length(), c.flags()))
                .collect();
            for (logical, length, flags) in to_relocate {
                self.relocate_one_chunk(logical, length, flags, None, Some((devid, new_size)))
                    .await?;
            }
        }

        self.commit().await?;
        self.start().await?;
        let info = {
            let mut tx = self.join().await?;
            let mut op = Mutation::checkpointed(&mut tx, Units::default());
            let info = op.inner_mut().finish_resize_device(devid, new_size).await?;
            op.publish()?;
            info
        };
        self.commit().await?;
        Ok(info)
    }

    /// Relocates block groups matching `filter`.
    pub async fn balance(&mut self, filter: BalanceFilter) -> Result<BalanceReport, WriteError> {
        use crate::space::{DATA, METADATA, SYSTEM};
        self.commit().await?;
        self.start().await?;
        let summaries = self
            .running
            .as_ref()
            .expect("transaction started")
            .inner
            .space
            .group_summaries();
        let mut report = BalanceReport::default();
        let mut candidates = Vec::new();
        for (logical, length, flags, used) in summaries {
            let kind_match = (filter.data && flags & DATA != 0)
                || (filter.metadata && flags & METADATA != 0)
                || (filter.system && flags & SYSTEM != 0);
            if !kind_match {
                continue;
            }
            report.considered += 1;
            if let Some(max_pct) = filter.usage_max_percent {
                let pct = if length == 0 {
                    100
                } else {
                    (u128::from(used) * 100 / u128::from(length)) as u64
                };
                if pct > u64::from(max_pct) {
                    continue;
                }
            }
            if let Some(limit) = filter.limit
                && candidates.len() as u64 >= limit
            {
                break;
            }
            candidates.push((logical, length, flags));
        }

        for (logical, length, flags) in candidates {
            self.relocate_one_chunk(logical, length, flags, None, None)
                .await?;
            report.relocated += 1;
        }
        Ok(report)
    }

    /// Relocates a single block group in one commit and deletes the emptied
    /// chunk in the follow-up cleanup commit.
    async fn relocate_one_chunk(
        &mut self,
        logical: u64,
        length: u64,
        flags: u64,
        excluded_device: Option<u64>,
        device_size_limit: Option<(u64, u64)>,
    ) -> Result<(), WriteError> {
        self.commit().await?;
        self.start().await?;
        let concurrency = self.concurrency;
        {
            let mut tx = self.join().await?;
            let mut op = Mutation::checkpointed(&mut tx, Units::default());
            op.inner_mut().excluded_device = excluded_device;
            op.inner_mut().device_size_limit = device_size_limit;
            op.inner_mut()
                .relocate_chunk(logical, length, flags, concurrency)
                .await?;
            op.publish()?;
        }
        self.commit().await?;
        // Second commit allows `remove_unused_groups` to drop the now-empty
        // chunk once no live reader pins the previous generation.
        self.start().await?;
        if let Some(running) = &mut self.running {
            running.inner.excluded_device = excluded_device;
            running.inner.device_size_limit = device_size_limit;
            if !running
                .inner
                .space
                .unused_groups(running.inner.volume.chunks())
                .is_empty()
            {
                running.inner.force_commit = true;
            }
        }
        self.commit().await?;
        Ok(())
    }

    /// Verifies checksums across all allocated metadata blocks, data extents,
    /// and superblocks (optionally restricted to `devid`), repairing corrupt
    /// mirror copies when `!read_only`.
    pub async fn scrub(
        &mut self,
        devid: Option<u64>,
        read_only: bool,
    ) -> Result<ScrubReport, WriteError> {
        self.commit().await?;
        let committed = self.committed.as_ref().ok_or(WriteError::WriterPoisoned)?;
        crate::scrub::scrub_volume(
            &committed.volume,
            committed.snapshot.root_tree,
            devid,
            read_only,
        )
        .await
    }

    /// Enables quota groups and scans existing extents into `QUOTA_TREE`.
    pub async fn quota_enable(&mut self) -> Result<(), WriteError> {
        self.commit().await?;
        self.start().await?;
        {
            let mut tx = self.join().await?;
            let mut op = Mutation::new(&mut tx, Units::CREATE).await?;
            op.inner_mut().quota_enable().await?;
            op.publish()?;
        }
        self.commit().await
    }

    /// Disables quota groups and removes `QUOTA_TREE`.
    pub async fn quota_disable(&mut self) -> Result<(), WriteError> {
        self.commit().await?;
        self.start().await?;
        {
            let mut tx = self.join().await?;
            let mut op = Mutation::checkpointed(&mut tx, Units::default());
            op.inner_mut().quota_disable().await?;
            op.publish()?;
        }
        self.commit().await
    }

    /// Recomputes all quota group counters and commits them.
    pub async fn quota_rescan(&mut self) -> Result<(), WriteError> {
        self.commit().await?;
        self.start().await?;
        {
            let mut tx = self.join().await?;
            let mut op = Mutation::checkpointed(&mut tx, Units::default());
            op.inner_mut().quota_rescan().await?;
            op.publish()?;
        }
        self.commit().await
    }

    pub async fn qgroup_create(&mut self, id: QgroupId) -> Result<(), WriteError> {
        self.start().await?;
        {
            let mut tx = self.join().await?;
            let mut op = Mutation::new(&mut tx, Units::INODE_UPDATE).await?;
            op.inner_mut().qgroup_create(id)?;
            op.publish()?;
        }
        self.commit().await
    }

    pub async fn qgroup_destroy(&mut self, id: QgroupId) -> Result<(), WriteError> {
        self.start().await?;
        {
            let mut tx = self.join().await?;
            let mut op = Mutation::new(&mut tx, Units::INODE_UPDATE).await?;
            op.inner_mut().qgroup_destroy(id)?;
            op.publish()?;
        }
        self.commit().await
    }

    pub async fn qgroup_assign(
        &mut self,
        member: QgroupId,
        parent: QgroupId,
    ) -> Result<(), WriteError> {
        self.start().await?;
        {
            let mut tx = self.join().await?;
            let mut op = Mutation::new(&mut tx, Units::INODE_UPDATE).await?;
            op.inner_mut().qgroup_assign(member, parent)?;
            op.publish()?;
        }
        self.commit().await
    }

    pub async fn qgroup_remove(
        &mut self,
        member: QgroupId,
        parent: QgroupId,
    ) -> Result<(), WriteError> {
        self.start().await?;
        {
            let mut tx = self.join().await?;
            let mut op = Mutation::new(&mut tx, Units::INODE_UPDATE).await?;
            op.inner_mut().qgroup_remove(member, parent)?;
            op.publish()?;
        }
        self.commit().await
    }

    pub async fn qgroup_limit(
        &mut self,
        id: QgroupId,
        limit: QgroupLimit,
    ) -> Result<(), WriteError> {
        self.start().await?;
        {
            let mut tx = self.join().await?;
            let mut op = Mutation::new(&mut tx, Units::INODE_UPDATE).await?;
            op.inner_mut().qgroup_limit(id, limit)?;
            op.publish()?;
        }
        self.commit().await
    }

    pub async fn quota_status(&mut self) -> Result<QuotaStatus, WriteError> {
        self.start().await?;
        Ok(self
            .running
            .as_ref()
            .expect("transaction started")
            .inner
            .quota
            .as_ref()
            .map_or_else(QuotaStatus::default, crate::qgroup::QuotaTree::status))
    }

    pub async fn list_qgroups(&mut self) -> Result<Vec<QgroupInfo>, WriteError> {
        self.start().await?;
        Ok(self
            .running
            .as_ref()
            .expect("transaction started")
            .inner
            .quota
            .as_ref()
            .map_or_else(Vec::new, crate::qgroup::QuotaTree::list))
    }

    /// Commits the running transaction, whatever it holds.
    async fn commit_running(&mut self) -> Result<(), WriteError> {
        let mut current = self.committed.take().ok_or(WriteError::WriterPoisoned)?;
        let running = self
            .running
            .take()
            .expect("the caller commits a running transaction");
        self.open = running.inner.open.clone();
        let uuids = &mut self.uuids;
        let mut committed = running
            .inner
            .commit(
                &mut self.retirements,
                || uuids.next_uuid(),
                &mut self.compressor,
                self.concurrency,
            )
            .await?;
        if let Some(allocation) = committed.allocation.take() {
            self.allocation = allocation;
        }
        current.publish(committed);
        self.committed = Some(current);
        Ok(())
    }
}

/// A handle on the running transaction, as Linux's `btrfs_trans_handle`.
/// Each mutation borrows it exclusively. An error or cancellation restores
/// that operation's checkpoint, preserving earlier accepted mutations.
/// Dropping the handle ends it without a commit; [`Self::commit`] commits.
pub struct WriteTransaction<'a, S, U> {
    writer: &'a mut Writer<S, U>,
}

impl<S: BlockSink, U: RootUuids> WriteTransaction<'_, S, U> {
    fn running(&self) -> &Running<S> {
        self.writer
            .running
            .as_ref()
            .expect("a handle exists only while its transaction runs")
    }

    fn running_mut(&mut self) -> &mut Running<S> {
        self.writer
            .running
            .as_mut()
            .expect("a handle exists only while its transaction runs")
    }

    fn inner(&self) -> &Transaction<Arc<S>> {
        &self.running().inner
    }

    fn inner_mut(&mut self) -> &mut Transaction<Arc<S>> {
        &mut self.running_mut().inner
    }

    /// The running transaction beside the mount's compressor, I/O concurrency
    /// and `max_inline` limit, for the operations that encode or write data.
    pub(crate) fn split(
        &mut self,
    ) -> (&mut Transaction<Arc<S>>, &mut Compressor, NonZeroUsize, u64) {
        let writer = &mut *self.writer;
        let running = writer
            .running
            .as_mut()
            .expect("a handle exists only while its transaction runs");
        (
            &mut running.inner,
            &mut writer.compressor,
            writer.concurrency,
            writer.max_inline,
        )
    }

    /// The mount's `max_inline` limit, in bytes.
    pub fn max_inline(&self) -> u64 {
        self.writer.max_inline()
    }

    /// Changes the mount's `max_inline`, as [`Writer::set_max_inline`].
    pub fn set_max_inline(&mut self, max_inline: u64) {
        self.writer.set_max_inline(max_inline);
    }

    /// Changes the mount's compression policy, as [`Writer::set_compressor`].
    pub async fn set_compressor(&mut self, compressor: Compressor) -> Result<(), WriteError> {
        self.writer.set_compressor(compressor).await
    }

    #[cfg(test)]
    pub(crate) fn edits(&mut self) -> &mut Transaction<Arc<S>> {
        self.inner_mut()
    }

    /// Publishes `view`, taken after an accepted mutation, and returns the
    /// private data released since to the allocator once no live view
    /// reaches it.
    fn install(&mut self, view: Arc<Snapshot>) {
        let running = self.running_mut();
        running.view = Some(view.clone());
        running.views.retain(|view| view.strong_count() != 0);
        let live: Vec<Arc<Snapshot>> = running.views.iter().filter_map(Weak::upgrade).collect();
        running
            .inner
            .space
            .accept_operation(|address| live.iter().any(|view| view.reaches_private_data(address)));
        running.views.push(Arc::downgrade(&view));
    }

    async fn load_handle(&self, id: FileId) -> Result<InodeHandle, WriteError> {
        let (_, metadata) = self.inner().inode_item(id.tree, id.inode).await?;
        Ok(InodeHandle {
            mount: self.writer.mount.clone(),
            id,
            generation: metadata.generation,
        })
    }

    #[cfg(test)]
    pub(crate) async fn fixture_handle(&self, id: FileId) -> Result<InodeHandle, WriteError> {
        self.load_handle(id).await
    }

    async fn checked(&self, handle: &InodeHandle) -> Result<Metadata, WriteError> {
        if !Arc::ptr_eq(&self.writer.mount, &handle.mount) {
            return Err(WriteError::ForeignHandle);
        }
        let stale = || WriteError::StaleHandle {
            tree: handle.id.tree,
            inode: handle.id.inode,
            generation: handle.generation,
        };
        let (_, metadata) = match self
            .inner()
            .inode_item(handle.id.tree, handle.id.inode)
            .await
        {
            Err(WriteError::Read(Error::MissingInode { .. })) => return Err(stale()),
            result => result?,
        };
        if metadata.generation != handle.generation {
            return Err(stale());
        }
        Ok(metadata)
    }

    async fn entry_name<'b>(&self, name: Name<'b>) -> Result<RawName<'b>, WriteError> {
        let metadata = self.checked(name.parent).await?;
        if metadata.kind != FileKind::Directory {
            return Err(Error::WrongKind {
                tree: name.parent.tree(),
                inode: name.parent.number(),
                expected: FileKind::Directory,
                found: metadata.kind,
            }
            .into());
        }
        Ok(RawName {
            tree: name.parent.tree(),
            parent: name.parent.number(),
            bytes: name.bytes,
        })
    }

    pub async fn root(&self) -> Result<InodeHandle, WriteError> {
        let record = self.inner().base().default_subvolume;
        self.load_handle(FileId {
            tree: record.root.tree,
            inode: record.root_dirid,
        })
        .await
    }

    /// A handle on inode `number` of subvolume `tree`, `None` when no such
    /// inode exists in the running transaction. For a caller that resolves a
    /// persisted inode identity without walking from the root, such as a FUSE
    /// or NFS export lookup.
    pub async fn inode(&self, tree: u64, number: u64) -> Result<Option<InodeHandle>, WriteError> {
        if !super::is_subvolume(tree) {
            return Ok(None);
        }
        match self
            .load_handle(FileId {
                tree,
                inode: number,
            })
            .await
        {
            Ok(handle) => Ok(Some(handle)),
            Err(
                WriteError::Read(Error::MissingInode { .. })
                | WriteError::Read(Error::MissingRoot { .. }),
            ) => Ok(None),
            Err(error) => Err(error),
        }
    }

    pub async fn metadata(&self, handle: &InodeHandle) -> Result<Metadata, WriteError> {
        let mut metadata = self.checked(handle).await?;
        metadata.nbytes = metadata
            .nbytes
            .saturating_add(self.inner().unbacked_delalloc_bytes(handle.id));
        Ok(metadata)
    }

    pub async fn lookup(
        &self,
        parent: &InodeHandle,
        bytes: &[u8],
    ) -> Result<Option<InodeHandle>, WriteError> {
        let name = self.entry_name(Name { parent, bytes }).await?;
        match self.inner().lookup_file(name).await? {
            Some(id) => self.load_handle(id).await.map(Some),
            None => Ok(None),
        }
    }

    pub async fn read_file(
        &self,
        file: &InodeHandle,
        offset: u64,
        output: &mut [u8],
    ) -> Result<usize, WriteError> {
        self.checked(file).await?;
        let file = file.id;
        self.inner()
            .read_file(file.tree, file.inode, offset, output)
            .await
    }

    /// Writes `data` at `offset` and returns the bytes stored, as `write(2)`:
    /// fewer than `data.len()` only when the data space ran out partway,
    /// never zero for a nonempty write, which fails instead. The data is
    /// dirty until writeback gives it extents, compressed when the mount
    /// compresses and Linux would compress the inode (no `NODATASUM`,
    /// `NODATACOW` or `NOCOMPRESS`).
    pub async fn write_file(
        &mut self,
        file: &InodeHandle,
        offset: u64,
        data: &[u8],
        when: Timestamp,
    ) -> Result<usize, WriteError> {
        self.checked(file).await?;
        let id = file.id;
        self.inner().roots.check_writable(id.tree)?;
        let sector = u64::from(self.inner().volume.superblock().sectorsize());
        let quota_delta = if data.is_empty() {
            0
        } else {
            (data.len() as u64).next_multiple_of(sector)
        };
        self.inner().check_quota_limit(id.tree, quota_delta)?;
        let max_inline = self.writer.max_inline;
        let units = self
            .reserve_with_data(DataReservation::Write {
                file: id,
                offset,
                length: data.len() as u64,
                max_inline,
            })
            .await?;
        let mut operation = Mutation::new(self, units).await?;
        operation.checked(file).await?;
        let (inner, compressor, _, max_inline) = operation.split();
        let written = inner
            .write_file(id, offset, data, when, compressor, max_inline)
            .await?;
        operation.accept()?;
        Ok(written)
    }

    /// Sets the size of `file`, as `truncate(2)`. A grown or compressed inline
    /// file re-stores its first sector under the mount's policy.
    pub async fn truncate_file(
        &mut self,
        file: &InodeHandle,
        size: u64,
        when: Timestamp,
    ) -> Result<(), WriteError> {
        self.checked(file).await?;
        let max_inline = self.writer.max_inline;
        let units = self
            .reserve_with_data(DataReservation::Truncate {
                file: file.id,
                size,
                max_inline,
            })
            .await?;
        let mut operation = Mutation::new(self, units).await?;
        operation.checked(file).await?;
        let file = file.id;
        operation.inner_mut().roots.check_writable(file.tree)?;
        let (inner, compressor, _, max_inline) = operation.split();
        inner
            .truncate_file(file.tree, file.inode, size, when, compressor, max_inline)
            .await?;
        operation.accept()
    }

    /// Shares `range` of one file's extents into another, as `FICLONERANGE`,
    /// writing back dirty data in the source range first so its extents can be
    /// shared.
    pub async fn clone_range(
        &mut self,
        range: CloneRange<'_>,
        when: Timestamp,
    ) -> Result<(), WriteError> {
        self.checked(range.source).await?;
        self.checked(range.destination).await?;
        let units = self
            .reserve_with_data(DataReservation::Clone {
                source: range.source.id,
                destination: range.destination.id,
                offset: range.destination_offset,
                length: range.length,
            })
            .await?;
        let mut operation = Mutation::new(self, units).await?;
        operation.checked(range.source).await?;
        operation.checked(range.destination).await?;
        let range = RawCloneRange {
            source: range.source.id,
            destination: range.destination.id,
            source_offset: range.source_offset,
            destination_offset: range.destination_offset,
            length: range.length,
        };
        operation
            .inner_mut()
            .roots
            .check_writable(range.destination.tree)?;
        let (inner, compressor, concurrency, max_inline) = operation.split();
        inner
            .clone_range(range, when, compressor, concurrency, max_inline)
            .await?;
        operation.accept()
    }

    /// Deduplicates `range` from source into destination if and only if both
    /// ranges are byte-for-byte identical, as Linux's `FIDEDUPERANGE`.
    pub async fn dedupe_range(
        &mut self,
        range: CloneRange<'_>,
        when: Timestamp,
    ) -> Result<DedupeOutcome, WriteError> {
        self.checked(range.source).await?;
        self.checked(range.destination).await?;
        let units = self
            .reserve_with_data(DataReservation::Clone {
                source: range.source.id,
                destination: range.destination.id,
                offset: range.destination_offset,
                length: range.length,
            })
            .await?;
        let mut operation = Mutation::new(self, units).await?;
        operation.checked(range.source).await?;
        operation.checked(range.destination).await?;
        let range = RawCloneRange {
            source: range.source.id,
            destination: range.destination.id,
            source_offset: range.source_offset,
            destination_offset: range.destination_offset,
            length: range.length,
        };
        operation
            .inner_mut()
            .roots
            .check_writable(range.destination.tree)?;
        let (inner, compressor, concurrency, max_inline) = operation.split();
        let outcome = inner
            .dedupe_range(range, when, compressor, concurrency, max_inline)
            .await?;
        operation.accept()?;
        Ok(outcome)
    }

    /// Preallocates space, punches holes or zeroes a byte range of `file`, as
    /// Linux's `btrfs_fallocate` (`fs/btrfs/file.c`).
    pub async fn fallocate(
        &mut self,
        file: &InodeHandle,
        offset: u64,
        length: u64,
        mode: AllocateMode,
        when: Timestamp,
    ) -> Result<(), WriteError> {
        self.checked(file).await?;
        let id = file.id;
        self.inner().roots.check_writable(id.tree)?;
        let max_inline = self.writer.max_inline;
        let units = self
            .reserve_with_data(DataReservation::Fallocate {
                file: id,
                offset,
                length,
                mode,
                max_inline,
            })
            .await?;
        let mut operation = Mutation::new(self, units).await?;
        operation.checked(file).await?;
        let (inner, compressor, concurrency, max_inline) = operation.split();
        inner
            .fallocate(
                id,
                offset,
                length,
                mode,
                when,
                compressor,
                concurrency,
                max_inline,
            )
            .await?;
        operation.accept()
    }

    pub async fn set_times(
        &mut self,
        file: &InodeHandle,
        access: Option<Timestamp>,
        modified: Option<Timestamp>,
        changed: Timestamp,
    ) -> Result<(), WriteError> {
        let mut operation = Mutation::new(self, Units::INODE_UPDATE).await?;
        operation.checked(file).await?;
        let file = file.id;
        operation.inner_mut().roots.check_writable(file.tree)?;
        operation
            .inner_mut()
            .set_times(file.tree, file.inode, access, modified, changed)
            .await?;
        operation.accept()
    }

    /// Replaces the permission bits (`07777`, the set-id and sticky bits
    /// included on every kind of inode) and stamps `changed`. An access ACL's
    /// base entries follow the new bits.
    pub async fn set_permissions(
        &mut self,
        file: &InodeHandle,
        permissions: u32,
        changed: Timestamp,
    ) -> Result<(), WriteError> {
        let mut operation = Mutation::new(self, Units::MODE).await?;
        operation.checked(file).await?;
        let file = file.id;
        operation.inner_mut().roots.check_writable(file.tree)?;
        operation
            .inner_mut()
            .set_permissions(file.tree, file.inode, permissions, changed)
            .await?;
        operation.accept()
    }

    /// Changes the owner and the group, each left as it is when `None`, and
    /// stamps `changed`. A non-directory loses its set-id bits and its
    /// `security.capability`.
    pub async fn set_owner(
        &mut self,
        file: &InodeHandle,
        uid: Option<u32>,
        gid: Option<u32>,
        changed: Timestamp,
    ) -> Result<(), WriteError> {
        let mut operation = Mutation::new(self, Units::OWNER).await?;
        operation.checked(file).await?;
        let file = file.id;
        operation.inner_mut().roots.check_writable(file.tree)?;
        operation
            .inner_mut()
            .set_owner(file.tree, file.inode, uid, gid, changed)
            .await?;
        operation.accept()
    }

    /// `getxattr(2)`: the length of `name`'s value, which is also copied to
    /// `output` unless `output` is empty (a size query). A nonempty `output`
    /// shorter than the value is [`WriteError::XattrBuffer`] (`ERANGE`), a
    /// bare handler prefix is [`WriteError::XattrName`] (`EINVAL`), an
    /// unhandled namespace is [`WriteError::XattrNamespace`] (`EOPNOTSUPP`),
    /// and an absent attribute is [`WriteError::XattrMissing`] (`ENODATA`).
    pub async fn xattr(
        &self,
        file: &InodeHandle,
        name: &[u8],
        output: &mut [u8],
    ) -> Result<usize, WriteError> {
        self.checked(file).await?;
        self.inner()
            .xattr(file.tree(), file.number(), name, output)
            .await
    }

    /// `listxattr(2)`: every attribute name of `file`, each followed by a NUL,
    /// copied to `output` unless it is empty (a size query). Returns the
    /// bytes the names take.
    pub async fn list_xattrs(
        &self,
        file: &InodeHandle,
        output: &mut [u8],
    ) -> Result<usize, WriteError> {
        self.checked(file).await?;
        self.inner()
            .list_xattrs(file.tree(), file.number(), output)
            .await
    }

    /// `setxattr(2)`. Every namespace Linux's btrfs stores is written:
    /// `user.*` (on regular files, directories and sockets only, else
    /// [`WriteError::XattrNotPermitted`]), `security.*`, `trusted.*` and the
    /// two POSIX ACL names, which are validated, stored in the encoding
    /// `posix_acl_to_xattr` produces and, for the access ACL, set the mode's
    /// permission bits as `btrfs_set_acl` does. Any other namespace is
    /// [`WriteError::XattrNamespace`]. The inode's ctime becomes `changed`.
    /// Whether the caller may write the namespace is not checked here.
    pub async fn set_xattr(
        &mut self,
        file: &InodeHandle,
        name: &[u8],
        value: &[u8],
        mode: XattrMode,
        changed: Timestamp,
    ) -> Result<(), WriteError> {
        let mut operation = Mutation::new(self, Units::XATTR).await?;
        operation.checked(file).await?;
        operation.inner_mut().roots.check_writable(file.tree())?;
        operation
            .inner_mut()
            .set_xattr(file.tree(), file.number(), name, value, mode, changed)
            .await?;
        operation.accept()
    }

    /// `removexattr(2)`, under the rules of [`Self::set_xattr`]; an absent
    /// attribute is [`WriteError::XattrMissing`], except an absent ACL,
    /// whose removal succeeds as `vfs_remove_acl`'s does.
    pub async fn remove_xattr(
        &mut self,
        file: &InodeHandle,
        name: &[u8],
        changed: Timestamp,
    ) -> Result<(), WriteError> {
        let mut operation = Mutation::new(self, Units::XATTR).await?;
        operation.checked(file).await?;
        operation.inner_mut().roots.check_writable(file.tree())?;
        operation
            .inner_mut()
            .remove_xattr(file.tree(), file.number(), name, changed)
            .await?;
        operation.accept()
    }

    pub async fn create_file(
        &mut self,
        name: Name<'_>,
        attributes: Attributes,
        when: Timestamp,
    ) -> Result<InodeHandle, WriteError> {
        self.create(name, attributes.raw(0o100000)?, when).await
    }

    pub async fn create_directory(
        &mut self,
        name: Name<'_>,
        attributes: Attributes,
        when: Timestamp,
    ) -> Result<InodeHandle, WriteError> {
        self.create(name, attributes.raw(0o040000)?, when).await
    }

    /// Creates a device node, a FIFO or a socket, as `mknod`. The node holds
    /// no data; a device node keeps the number it names.
    pub async fn create_special(
        &mut self,
        name: Name<'_>,
        special: Special,
        attributes: Attributes,
        when: Timestamp,
    ) -> Result<InodeHandle, WriteError> {
        let (kind, rdev) = special.mode_and_rdev();
        self.create(name, attributes.raw_with_device(kind, rdev)?, when)
            .await
    }

    async fn create(
        &mut self,
        name: Name<'_>,
        attributes: RawAttributes,
        when: Timestamp,
    ) -> Result<InodeHandle, WriteError> {
        let parent = self.entry_name(name).await?;
        let units = if self
            .inner()
            .has_default_acl(parent.tree, parent.parent)
            .await?
        {
            Units::CREATE_INHERITING_ACLS
        } else {
            Units::CREATE
        };
        let mut operation = Mutation::new(self, units).await?;
        let name = operation.entry_name(name).await?;
        operation.inner_mut().roots.check_writable(name.tree)?;
        let inode = operation
            .inner_mut()
            .create_node(name, attributes, when)
            .await?;
        let handle = operation
            .load_handle(FileId {
                tree: name.tree,
                inode,
            })
            .await?;
        operation.accept()?;
        Ok(handle)
    }

    /// Records one more open handle holding `file` alive across unlinks.
    /// While at least one open handle exists, removing the last link leaves
    /// the inode and an on-disk orphan item in place until the final
    /// [`Self::release_inode`].
    pub async fn open_inode(&mut self, file: &InodeHandle) -> Result<(), WriteError> {
        self.checked(file).await?;
        self.inner_mut().open.retain(file.id, file.generation)
    }

    /// Creates an unnamed regular file inode (`O_TMPFILE`) in `parent`'s
    /// subvolume, inheriting default ACLs and `S_ISGID` group ownership from
    /// `parent` without touching `parent`'s entries or timestamps. Records an
    /// on-disk orphan item and opens one handle on the returned inode; when
    /// `linkable` is true (no `O_EXCL`), [`Self::hard_link`] may later give it
    /// a name and remove its orphan item.
    pub async fn create_tmpfile(
        &mut self,
        parent: &InodeHandle,
        attributes: Attributes,
        linkable: bool,
        when: Timestamp,
    ) -> Result<InodeHandle, WriteError> {
        let parent_meta = self.checked(parent).await?;
        if parent_meta.kind != FileKind::Directory {
            return Err(Error::WrongKind {
                tree: parent.tree(),
                inode: parent.number(),
                expected: FileKind::Directory,
                found: parent_meta.kind,
            }
            .into());
        }
        let raw_attributes = attributes.raw(0o100000)?;
        let units = if self
            .inner()
            .has_default_acl(parent.tree(), parent.number())
            .await?
        {
            Units::TMPFILE_INHERITING_ACLS
        } else {
            Units::TMPFILE
        };
        let mut operation = Mutation::new(self, units).await?;
        operation.checked(parent).await?;
        let (tree, parent_id) = (parent.tree(), parent.number());
        operation.inner_mut().roots.check_writable(tree)?;
        let inode = operation
            .inner_mut()
            .create_tmpfile(tree, parent_id, raw_attributes, linkable, when)
            .await?;
        let handle = operation.load_handle(FileId { tree, inode }).await?;
        operation.accept()?;
        Ok(handle)
    }

    /// Releases one open handle previously acquired with [`Self::open_inode`]
    /// or [`Self::create_tmpfile`]. If this was the final open handle on an
    /// orphaned inode, deletes the inode (its extents, checksums, extended
    /// attributes and delayed-allocation pages) and its orphan item in one
    /// transaction and returns `Ok(true)`; otherwise returns `Ok(false)`.
    pub async fn release_inode(&mut self, file: &InodeHandle) -> Result<bool, WriteError> {
        if !Arc::ptr_eq(&self.writer.mount, &file.mount) {
            return Err(WriteError::ForeignHandle);
        }
        let mut preview = self.inner().open.clone();
        match preview.release(file.id, file.generation)? {
            ReleaseOutcome::StillOpen | ReleaseOutcome::ClosedLinked => {
                self.inner_mut().open = preview;
                Ok(false)
            }
            ReleaseOutcome::DeleteOrphan => {
                let mut operation = Mutation::new(self, Units::UNLINK).await?;
                let outcome = operation
                    .inner_mut()
                    .open
                    .release(file.id, file.generation)?;
                debug_assert_eq!(outcome, ReleaseOutcome::DeleteOrphan);
                operation.inner_mut().roots.check_writable(file.tree())?;
                operation
                    .inner_mut()
                    .delete_orphan_inode(file.tree(), file.number())
                    .await?;
                operation.accept()?;
                Ok(true)
            }
        }
    }

    pub async fn hard_link(
        &mut self,
        name: Name<'_>,
        file: &InodeHandle,
        when: Timestamp,
    ) -> Result<(), WriteError> {
        let metadata = self.checked(file).await?;
        let units = if metadata.nlink == 0 {
            Units::LINK_ORPHAN
        } else {
            Units::LINK
        };
        let mut operation = Mutation::new(self, units).await?;
        operation.checked(file).await?;
        let name = operation.entry_name(name).await?;
        if file.tree() != name.tree {
            return Err(WriteError::CrossSubvolume);
        }
        let inode = file.number();
        operation.inner_mut().roots.check_writable(name.tree)?;
        operation.inner_mut().hard_link(name, inode, when).await?;
        operation.accept()
    }

    pub async fn symlink(
        &mut self,
        name: Name<'_>,
        target: &[u8],
        attributes: Attributes,
        when: Timestamp,
    ) -> Result<InodeHandle, WriteError> {
        let mut operation = Mutation::new(self, Units::SYMLINK).await?;
        let name = operation.entry_name(name).await?;
        operation.inner_mut().roots.check_writable(name.tree)?;
        let inode = operation
            .inner_mut()
            .symlink(name, target, attributes.raw(0o120000)?, when)
            .await?;
        let handle = operation
            .load_handle(FileId {
                tree: name.tree,
                inode,
            })
            .await?;
        operation.accept()?;
        Ok(handle)
    }

    pub async fn rename(
        &mut self,
        source: Name<'_>,
        destination: Name<'_>,
        mode: RenameMode,
        when: Timestamp,
    ) -> Result<(), WriteError> {
        let across = source.parent.id != destination.parent.id;
        let mut operation = Mutation::new(self, Units::rename(across)).await?;
        let source = operation.entry_name(source).await?;
        let destination = operation.entry_name(destination).await?;
        operation.inner_mut().roots.check_writable(source.tree)?;
        operation
            .inner_mut()
            .roots
            .check_writable(destination.tree)?;
        operation
            .inner_mut()
            .rename(source, destination, mode, when)
            .await?;
        operation.accept()
    }

    pub async fn unlink_name(&mut self, name: Name<'_>, when: Timestamp) -> Result<(), WriteError> {
        let mut operation = Mutation::new(self, Units::UNLINK).await?;
        let name = operation.entry_name(name).await?;
        operation.inner_mut().roots.check_writable(name.tree)?;
        operation.inner_mut().unlink_name(name, when).await?;
        operation.accept()
    }

    /// Commits the running transaction, as [`Writer::commit`].
    pub async fn commit(self) -> Result<(), WriteError> {
        self.writer.commit().await
    }

    /// Reserves the metadata a mutation of `units` may need (`reserve`).
    /// What does not fit is given what Linux's metadata flush would free
    /// first: the commit, which runs the work Linux keeps as delayed refs,
    /// then a new chunk. A mutation that still does not fit is refused
    /// before it changes anything.
    async fn reserve(&mut self, units: Units) -> Result<(), WriteError> {
        if self.inner().reserves(units) {
            return Ok(());
        }
        if !self.writer.dirty().is_clean() {
            self.writer.commit().await?;
            self.writer.start().await?;
            if self.inner().reserves(units) {
                return Ok(());
            }
        }
        let mut chunk = Mutation::checkpointed(self, Units::default());
        chunk.inner_mut().force_metadata_chunk().await?;
        chunk.accept()?;
        if self.inner().reserves(units) {
            return Ok(());
        }
        Err(self.inner().exhausted(units))
    }

    /// Reserves both data and metadata space for an operation that may dirty
    /// file pages. A metadata-flush commit can delete an empty data block group
    /// (`remove_unused_groups`), shrinking [`Transaction::data_budget`] below
    /// the data reservation, so data space is re-ensured after that commit.
    async fn reserve_with_data(&mut self, operation: DataReservation) -> Result<Units, WriteError> {
        let mut flushed = false;
        loop {
            let reservation = match operation {
                DataReservation::Write {
                    file,
                    offset,
                    length,
                    max_inline,
                } => {
                    self.inner()
                        .write_reservation(file, offset, length, max_inline)
                        .await?
                }
                DataReservation::Truncate {
                    file,
                    size,
                    max_inline,
                } => {
                    self.inner()
                        .truncate_reservation(file, size, max_inline)
                        .await?
                }
                DataReservation::Clone {
                    source,
                    destination,
                    offset,
                    length,
                } => {
                    self.inner()
                        .clone_reservation(source, destination, offset, length)
                        .await?
                }
                DataReservation::Fallocate {
                    file,
                    offset,
                    length,
                    mode,
                    max_inline,
                } => {
                    let bytes = self
                        .inner()
                        .fallocate_reservation(file, offset, length, mode, max_inline)
                        .await?;
                    if bytes > self.inner().volume.superblock().total_bytes() {
                        return Err(SpaceError::Exhausted { bytes, flags: DATA }.into());
                    }
                    bytes
                }
            };
            self.reserve_data(reservation).await?;
            let units = match operation {
                DataReservation::Write {
                    file,
                    offset,
                    length,
                    max_inline,
                } => {
                    self.inner()
                        .write_units(file, offset, length, max_inline)
                        .await?
                }
                DataReservation::Truncate { .. } => {
                    if reservation == 0 {
                        Units::TRUNCATE
                    } else {
                        Units {
                            insert: 4,
                            update: 1,
                            frees: false,
                        }
                    }
                }
                DataReservation::Clone { .. } => Units::CLONE,
                DataReservation::Fallocate { mode, .. } => {
                    self.inner().fallocate_units(mode, reservation)
                }
            };
            if self.inner().reserves(units) {
                return Ok(units);
            }
            if !flushed && !self.writer.dirty().is_clean() {
                self.writer.commit().await?;
                self.writer.start().await?;
                flushed = true;
                continue;
            }
            let mut chunk = Mutation::checkpointed(self, Units::default());
            chunk.inner_mut().force_metadata_chunk().await?;
            chunk.accept()?;
            if self.inner().reserves(units) {
                return Ok(units);
            }
            return Err(self.inner().exhausted(units));
        }
    }

    /// Makes room for a mutation that may dirty `bytes` of data, in the
    /// order of Linux's data space flush (`priority_reclaim_data_space` and
    /// `data_flush_states` in `fs/btrfs/space-info.c`): data chunks while
    /// the device has room (`ALLOC_CHUNK_FORCE`), then writeback of the
    /// dirty data (`FLUSH_DELALLOC_FULL`), which returns what compression
    /// saves, then a commit (`COMMIT_TRANS`), which returns the extents the
    /// transaction released. What still does not fit makes the write short,
    /// or refuses it when not one sector does.
    async fn reserve_data(&mut self, bytes: u64) -> Result<(), WriteError> {
        self.grow_data_to(bytes).await?;
        if self.inner().data_budget() >= bytes {
            return Ok(());
        }
        if self.writer.dirty().data_bytes != 0 {
            self.writer.writeback().await?;
            if self.inner().data_budget() >= bytes {
                return Ok(());
            }
        }
        if !self.writer.dirty().is_clean() {
            self.writer.commit().await?;
            self.writer.start().await?;
            // A commit can delete unused groups and return device extents.
            self.grow_data_to(bytes).await?;
        }
        Ok(())
    }

    async fn grow_data_to(&mut self, bytes: u64) -> Result<(), WriteError> {
        while self.inner().data_budget() < bytes {
            let mut chunk = Mutation::checkpointed(self, Units::default());
            let grew = chunk.inner_mut().grow_data().await?;
            chunk.accept()?;
            if !grew {
                break;
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum DataReservation {
    Write {
        file: FileId,
        offset: u64,
        length: u64,
        max_inline: u64,
    },
    Truncate {
        file: FileId,
        size: u64,
        max_inline: u64,
    },
    Clone {
        source: FileId,
        destination: FileId,
        offset: u64,
        length: u64,
    },
    Fallocate {
        file: FileId,
        offset: u64,
        length: u64,
        mode: AllocateMode,
        max_inline: u64,
    },
}

/// The mutation future owns this guard. Its drop restores the complete private
/// state after the future's in-flight I/O has been dropped. No reader has seen
/// that state, and committed extents remain pinned throughout rollback.
struct Mutation<'op, 'tx, S: BlockSink, U: RootUuids> {
    transaction: &'op mut WriteTransaction<'tx, S, U>,
    saved: Option<Checkpoint>,
    /// What the mutation reserved: its acceptance checks the commit still
    /// has what it needs.
    units: Units,
}

impl<'op, 'tx, S: BlockSink, U: RootUuids> Mutation<'op, 'tx, S, U> {
    /// Reserves the operation's metadata, checkpoints the transaction, then
    /// makes the chunk room the operation may need: a failure after the
    /// checkpoint restores it like any other.
    async fn new(
        transaction: &'op mut WriteTransaction<'tx, S, U>,
        units: Units,
    ) -> Result<Self, WriteError> {
        transaction.reserve(units).await?;
        let operation = Self::checkpointed(transaction, units);
        operation.transaction.inner_mut().prepare_mutation().await?;
        Ok(operation)
    }

    fn checkpointed(transaction: &'op mut WriteTransaction<'tx, S, U>, units: Units) -> Self {
        let saved = Some(transaction.inner_mut().checkpoint());
        Self {
            transaction,
            saved,
            units,
        }
    }

    /// Accepts the operation and makes it visible to readers. One that left
    /// the commit less than its work needs is refused and rolled back.
    fn accept(self) -> Result<(), WriteError> {
        self.transaction.inner().check_commit_hold(self.units)?;
        self.publish()
    }

    /// Accepts the operation without checking what it left the commit: for
    /// work the transaction already reserved.
    fn publish(mut self) -> Result<(), WriteError> {
        let view = self.transaction.inner().view()?;
        self.saved = None;
        self.transaction.install(view);
        Ok(())
    }
}

impl<'tx, S: BlockSink, U: RootUuids> Deref for Mutation<'_, 'tx, S, U> {
    type Target = WriteTransaction<'tx, S, U>;
    fn deref(&self) -> &Self::Target {
        self.transaction
    }
}

impl<S: BlockSink, U: RootUuids> DerefMut for Mutation<'_, '_, S, U> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.transaction
    }
}

impl<S: BlockSink, U: RootUuids> Drop for Mutation<'_, '_, S, U> {
    fn drop(&mut self) {
        if let Some(saved) = self.saved.take() {
            self.transaction.inner_mut().restore(saved);
        }
    }
}
