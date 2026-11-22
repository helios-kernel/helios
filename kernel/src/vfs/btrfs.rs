//! Btrfs over the block cache.
//!
//! # Concurrency contract
//!
//! - **Snapshot reads (`stat`, `read_at`, `read_dir`, `read_link`)** clone a
//!   published immutable [`Filesystem`] view under a short `spin::Mutex` (held
//!   only for the `Arc` reference-count bump, never across `.await` or I/O)
//!   and execute lock-free on any processor against that view's persistent
//!   tree and dirty-page overlay.
//! - **Mutations and writeback** are owned exclusively by one [`BtrfsService`]
//!   task per writable mount, reached from any processor through a bounded
//!   async channel. Written file data accumulates as dirty pages in the
//!   running transaction until `CommitPolicy::dirty_data_limit` or a commit
//!   writes it back into extents at Linux's sizes (`128 KiB` compressed
//!   windows, up to `128 MiB` uncompressed).
//! - **Prepared writes ([`BtrfsWrite`])** fill each `write_round` buffer
//!   synchronously on the caller and acquire a per-inode async `RawMutex`
//!   across rounds so multi-round and append writes stay contiguous and
//!   preserve their starting offset without blocking unrelated inodes or the
//!   mount service.
//! - **Policy updates ([`LivePolicy`])** store and load `CommitPolicy` knobs
//!   with release/acquire atomics and wake the service through
//!   [`ProgressSignal`] armed before the policy is sampled.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::sync::{Arc as SharedArc, Weak as SharedWeak};
use alloc::vec::Vec;
use core::num::NonZeroUsize;
use core::ops::ControlFlow;
use core::sync::atomic::{AtomicU64, Ordering};
use core::time::Duration;

use bytes::{Bytes, BytesMut};
use helios_btrfs::{
    BlockSink, BlockSource, DirBound, DirPosition, EntryTarget, Error, FileKind, Filesystem, Inode,
    READ_ALIGNMENT, Timestamp,
};
use helios_hal::fs::{
    BlockDevice, BlockSerial, DeviceId, DirCookie, DirEntry, DirStream, FileSystem, FsError,
    FsPath, FsResult, Metadata, NodeId, NodeKind, OpenFlags, RenameMode, WritePosition,
};
use helios_hal::fs_management::{
    BalanceFilter, BalanceReport, DedupeOutcome, QgroupId, QgroupInfo, QgroupLimit, QuotaStatus,
    ResizeTarget, ScrubReport, SubvolumeInfo, VolumeDeviceInfo, VolumeManagement,
    VolumeManagementError, VolumeManagementResult,
};
use helios_hal::io::{IoError, IoResult};
use triomphe::Arc;

use super::DeviceIdAllocator;
use crate::{
    BlockCacheError, BlockPages, CACHE_BLOCK_BYTES, CachedDisk, ProgressSignal, RootEntropyHandle,
};
use helios_btrfs::write::{
    CompressionPolicy, Compressor, DEFAULT_DIRTY_METADATA_LIMIT, DEFAULT_MAX_INLINE, EncodeError,
    WriteError, Writer, default_dirty_data_limit, stream_referenced_sources,
};

mod prepared;
mod writer;
pub use prepared::BtrfsWrite;
pub use writer::BtrfsService;
use writer::{ManageClient, ManageOperation, ManageResponse, Operation, Response};

/// Runtime inputs for writable disk mounts.
#[derive(Clone)]
pub struct BtrfsWriteOptions {
    pub entropy: RootEntropyHandle,
    pub concurrency: NonZeroUsize,
    /// Linux's `compress=<algorithm>[:<level>]` mount option: the algorithm
    /// every compressible inode's new data is written with. `None` writes
    /// every extent uncompressed.
    pub compress: Option<CompressionPolicy>,
    /// When the mount commits, or writes dirty data back, without a sync
    /// asking: Linux's defaults on this machine
    /// ([`CommitPolicy::machine_default`]) when `None`, and a request naming
    /// it for a source other than btrfs is refused. The mount takes it as its
    /// starting value; [`BtrfsFs::set_commit_policy`] changes it later.
    pub commit: Option<CommitPolicy>,
    /// Linux's `max_inline=` mount option, in bytes: the most a file's
    /// stored data may keep inline in its metadata item. `None` takes
    /// Linux's default ([`DEFAULT_MAX_INLINE`]), and a request naming it for
    /// a source other than btrfs is refused. [`BtrfsFs::set_max_inline`]
    /// changes it later.
    pub max_inline: Option<u64>,
    /// Wall-clock nanoseconds since the Unix epoch at the mount request:
    /// what the replay of a log tree a crash left stamps on what it unlinks.
    pub now: u64,
}

/// What the machine keeps of a writable btrfs mount, whatever its device
/// type, so that it can commit every one before it powers off. It holds the
/// mount's queue weakly: an unmounted or dropped mount is not kept alive by
/// it, and its end is still awaited.
#[derive(Clone)]
pub(crate) struct WritableMount {
    writer: SharedWeak<writer::Client>,
    exit: SharedArc<writer::ServiceExit>,
}

impl WritableMount {
    /// Whether the mount's service has ended, so nothing is left to commit.
    pub(crate) fn has_ended(&self) -> bool {
        self.exit.has_ended()
    }

    /// Makes what the mount holds durable: a sync of a live mount, or the
    /// end of one that is going away, whose service commits as it ends.
    pub(crate) async fn settle(&self) {
        match self.writer.upgrade() {
            Some(writer) => {
                if let Err(error) = writer.execute("", 0, Operation::Sync).await {
                    tracing::error!(?error, "btrfs commit before power-off failed");
                }
            }
            None => self.exit.ended().await,
        }
    }
}

/// When a writable mount commits its running transaction, or writes its
/// dirty data back, beyond the syncs that ask for a commit: operator
/// settings, adjustable at runtime.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommitPolicy {
    /// Linux's `commit=` mount option: the longest a change waits after the
    /// running transaction first changed. Zero commits each batch.
    pub interval: Duration,
    /// Dirty metadata the running transaction holds before it commits.
    pub dirty_metadata_limit: u64,
    /// Dirty file data the running transaction holds before the mount
    /// writes it back into extents, as Linux's `vm.dirty_background_bytes`.
    /// Zero writes each batch back.
    pub dirty_data_limit: u64,
}

/// `BTRFS_DEFAULT_COMMIT_INTERVAL`, 30 seconds in `fs/btrfs/fs.h`.
pub const DEFAULT_COMMIT_INTERVAL: Duration = Duration::from_secs(30);

/// `BTRFS_WARNING_COMMIT_INTERVAL`, 300 seconds in `fs/btrfs/fs.h`: a longer
/// `commit=` is taken with a warning.
const WARNING_COMMIT_INTERVAL: u32 = 300;

impl CommitPolicy {
    /// Linux's defaults on a machine of `memory_bytes`, the memory that
    /// holds the dirty data: [`default_dirty_data_limit`] of it.
    pub fn for_machine(memory_bytes: usize) -> Self {
        Self {
            interval: DEFAULT_COMMIT_INTERVAL,
            dirty_metadata_limit: DEFAULT_DIRTY_METADATA_LIMIT,
            dirty_data_limit: default_dirty_data_limit(memory_bytes as u64),
        }
    }

    /// Linux's defaults on this machine.
    pub fn machine_default() -> Self {
        Self::for_machine(crate::machine_memory().usable_bytes)
    }

    /// This policy with the interval Linux's `commit=<seconds>` mount option
    /// gives, as `btrfs_parse_param` reads it: zero is the default interval,
    /// and an interval past [`WARNING_COMMIT_INTERVAL`] is warned about and
    /// kept.
    pub fn with_commit_option(self, seconds: u32) -> Self {
        if seconds > WARNING_COMMIT_INTERVAL {
            tracing::warn!(seconds, "excessive commit interval, use with care");
        }
        Self {
            interval: match seconds {
                0 => DEFAULT_COMMIT_INTERVAL,
                seconds => Duration::from_secs(u64::from(seconds)),
            },
            ..self
        }
    }
}

/// A mount's operator settings as they stand: its [`CommitPolicy`] and its
/// `max_inline`. The operator writes them from any processor. The mount's
/// service re-reads the commit policy on every change, which applies the new
/// values to the running transaction at once, and reads `max_inline` for
/// every batch of mutations.
struct LivePolicy {
    interval_nanos: AtomicU64,
    dirty_metadata_limit: AtomicU64,
    dirty_data_limit: AtomicU64,
    max_inline: AtomicU64,
    /// Raised after every commit policy change, so the service re-arms its
    /// deadline.
    changed: ProgressSignal,
}

impl LivePolicy {
    fn new(policy: CommitPolicy, max_inline: u64) -> Self {
        let live = Self {
            interval_nanos: AtomicU64::new(0),
            dirty_metadata_limit: AtomicU64::new(0),
            dirty_data_limit: AtomicU64::new(0),
            max_inline: AtomicU64::new(max_inline),
            changed: ProgressSignal::new(),
        };
        live.store(policy);
        live
    }

    fn max_inline(&self) -> u64 {
        self.max_inline.load(Ordering::Acquire)
    }

    fn store(&self, policy: CommitPolicy) {
        // An interval past u64 nanoseconds, some 584 years, never expires.
        let nanos = u64::try_from(policy.interval.as_nanos()).unwrap_or(u64::MAX);
        self.interval_nanos.store(nanos, Ordering::Release);
        self.dirty_metadata_limit
            .store(policy.dirty_metadata_limit, Ordering::Release);
        self.dirty_data_limit
            .store(policy.dirty_data_limit, Ordering::Release);
        self.changed.signal();
    }

    fn load(&self) -> CommitPolicy {
        CommitPolicy {
            interval: Duration::from_nanos(self.interval_nanos.load(Ordering::Acquire)),
            dirty_metadata_limit: self.dirty_metadata_limit.load(Ordering::Acquire),
            dirty_data_limit: self.dirty_data_limit.load(Ordering::Acquire),
        }
    }
}
type Snapshot<Device> = Filesystem<SharedArc<Image<Device>>>;

#[derive(Debug, thiserror::Error)]
pub enum BtrfsMountError {
    #[error("disk already has an incompatible mount")]
    Busy,
    #[error(transparent)]
    Read(#[from] Error),
    #[error(transparent)]
    Write(#[from] WriteError),
    #[error("the mount's compression policy cannot be encoded: {0}")]
    Compression(#[from] EncodeError),
}

// A writable mount excludes independent read snapshots: those snapshots have
// no shared retirement accounting with its writer. Clones of this mount share
// both the image lease and the library's generation pins.
enum MountLease {
    Read {
        _lease: crate::OwnedRawRwLockReadLease,
    },
    Write {
        _lease: crate::OwnedRawRwLockWriteLease,
    },
}

struct Image<Device> {
    disk: CachedDisk<Device>,
    _lease: MountLease,
}

impl<Device: BlockDevice<Buffer = BlockPages>> BlockSource for Image<Device> {
    fn size_bytes(&self) -> u64 {
        self.disk.capacity_blocks() * CACHE_BLOCK_BYTES as u64
    }

    async fn read_at(&self, offset: u64, buf: &mut [u8]) -> IoResult<()> {
        self.disk
            .read_at(offset, buf)
            .await
            .map_err(|error| self.io_error(error))
    }
}

impl<Device: BlockDevice<Buffer = BlockPages>> Image<Device> {
    fn io_error(&self, error: BlockCacheError) -> IoError {
        tracing::warn!(%error, serial = ?self.disk.serial(), "btrfs device operation failed");
        match error {
            BlockCacheError::Device(error) => error,
            BlockCacheError::OutOfRange { .. } | BlockCacheError::ByteRangeOutOfRange { .. } => {
                IoError::OutOfBounds
            }
            BlockCacheError::ReadOnly => IoError::ReadOnly,
            BlockCacheError::Aborted => IoError::DeviceFault,
        }
    }
}

impl<Device: BlockDevice<Buffer = BlockPages>> BlockSink for Image<Device> {
    async fn stage(&self, block: u64, bytes: &[u8; READ_ALIGNMENT as usize]) -> IoResult<()> {
        let mut cached = self
            .disk
            .overwrite(block)
            .await
            .map_err(|error| self.io_error(error))?;
        cached.copy_from_slice(bytes);
        Ok(())
    }

    async fn commit(&self, block: u64, bytes: &[u8; READ_ALIGNMENT as usize]) -> IoResult<()> {
        self.disk
            .commit(block, |cached| cached.copy_from_slice(bytes))
            .await
            .map_err(|error| self.io_error(error))
    }
}

// Both transports address complete cache blocks; no partial-block write can
// accidentally make a superblock visible before its transaction is durable.
const _: () = assert!(READ_ALIGNMENT as usize == CACHE_BLOCK_BYTES);

/// A cloneable Btrfs mount with concurrent snapshot reads.
pub struct BtrfsFs<Device: BlockDevice<Buffer = BlockPages>> {
    inner: Arc<Inner<Device>>,
}

struct Inner<Device: BlockDevice<Buffer = BlockPages>> {
    reader: Arc<spin::Mutex<Snapshot<Device>>>,
    /// A writable mount's service queue, shared with the machine's list of
    /// writable mounts (`WritableMount`) by a weak reference.
    writer: Option<SharedArc<writer::Client>>,
    /// Volume management channel owned by the same [`BtrfsService`] task.
    manage: Option<SharedArc<ManageClient<Device>>>,
    /// The commit policy a writable mount's service follows.
    policy: Option<Arc<LivePolicy>>,
    /// Subvolume tree id -> `(DeviceId, root_inode)`, dynamically extended
    /// when subvolumes or snapshots are created at runtime.
    devices: Arc<spin::Mutex<BTreeMap<u64, (DeviceId, u64)>>>,
    /// Volume device id -> backing disk serial, updated on add/remove/replace.
    block_serials: Arc<spin::Mutex<BTreeMap<u64, BlockSerial>>>,
    serial: BlockSerial,
    writes: prepared::Leases,
    write_round: usize,
}

impl<Device: BlockDevice<Buffer = BlockPages>> Clone for BtrfsFs<Device> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<Device: BlockDevice<Buffer = BlockPages>> BtrfsFs<Device> {
    /// Validates the image and assigns each subvolume an identity from
    /// the same allocator as every other mount on this machine.
    pub async fn mount(
        disk: CachedDisk<Device>,
        mut allocate_device: impl FnMut() -> DeviceId + Send,
    ) -> Result<Self, BtrfsMountError> {
        let serial = disk.serial();
        let lease = disk.read_mount().ok_or(BtrfsMountError::Busy)?;
        let reader = Filesystem::mount(SharedArc::new(Image {
            disk,
            _lease: MountLease::Read { _lease: lease },
        }))
        .await?;
        let primary_devid = reader.superblock().devid();
        let mut devices = BTreeMap::new();
        reader
            .subvolumes(|tree, root_inode| {
                devices.insert(tree, (allocate_device(), root_inode));
            })
            .await?;
        let mut block_serials = BTreeMap::new();
        block_serials.insert(primary_devid, serial);
        Ok(Self {
            inner: Arc::new(Inner {
                reader: Arc::new(spin::Mutex::new(reader)),
                writer: None,
                manage: None,
                policy: None,
                devices: Arc::new(spin::Mutex::new(devices)),
                block_serials: Arc::new(spin::Mutex::new(block_serials)),
                serial,
                writes: Arc::new(spin::Mutex::new(BTreeMap::new())),
                write_round: CACHE_BLOCK_BYTES,
            }),
        })
    }

    /// Construct a writable mount and its single-owner service. The caller
    /// runs the service on the kernel executor for the mount's lifetime.
    pub async fn mount_writable(
        disk: CachedDisk<Device>,
        mut allocate_device: impl FnMut() -> DeviceId + Send,
        options: BtrfsWriteOptions,
    ) -> Result<(Self, BtrfsService<Device>), BtrfsMountError> {
        let mut max_id = 0_u64;
        let (fs, service) = Self::mount_writable_inner(
            disk,
            || {
                let id = allocate_device();
                max_id = max_id.max(id.raw());
                id
            },
            None,
            options,
        )
        .await?;
        // Ensure any subvolumes created later in standalone mounts get distinct
        // device ids above those handed out at mount time.
        let _ = max_id;
        Ok((fs, service))
    }

    /// Construct a writable mount using `allocator` for initial and dynamically
    /// created subvolumes.
    pub async fn mount_writable_with_allocator(
        disk: CachedDisk<Device>,
        allocator: DeviceIdAllocator,
        options: BtrfsWriteOptions,
    ) -> Result<(Self, BtrfsService<Device>), BtrfsMountError> {
        let initial = allocator.clone();
        Self::mount_writable_inner(disk, || initial.allocate(), Some(allocator), options).await
    }

    async fn mount_writable_inner(
        disk: CachedDisk<Device>,
        mut allocate_device: impl FnMut() -> DeviceId + Send,
        shared_allocator: Option<DeviceIdAllocator>,
        options: BtrfsWriteOptions,
    ) -> Result<(Self, BtrfsService<Device>), BtrfsMountError> {
        let BtrfsWriteOptions {
            entropy,
            concurrency,
            compress,
            commit,
            max_inline,
            now,
        } = options;
        let compressor = Compressor::new(compress)?;
        let serial = disk.serial();
        let lease = disk.write_mount().ok_or(BtrfsMountError::Busy)?;
        let max_inline = max_inline.unwrap_or(DEFAULT_MAX_INLINE);
        let mut writer = Writer::mount(
            Image {
                disk,
                _lease: MountLease::Write { _lease: lease },
            },
            writer::EntropyUuids(entropy),
            concurrency,
            compressor,
            writer::timestamp(now),
        )
        .await?;
        writer.set_max_inline(max_inline);
        let reader = writer.snapshot()?;
        let primary_devid = reader.superblock().devid();
        let mut devices = BTreeMap::new();
        let mut highest_device = 0_u64;
        reader
            .subvolumes(|tree, root_inode| {
                let id = allocate_device();
                highest_device = highest_device.max(id.raw());
                devices.insert(tree, (id, root_inode));
            })
            .await?;
        let device_ids = shared_allocator
            .unwrap_or_else(|| DeviceIdAllocator::starting_at(highest_device.saturating_add(1)));
        let devices = Arc::new(spin::Mutex::new(devices));
        let mut block_serials = BTreeMap::new();
        block_serials.insert(primary_devid, serial);
        let block_serials = Arc::new(spin::Mutex::new(block_serials));
        let reader = Arc::new(spin::Mutex::new(reader));
        let (client, receiver, exit) = writer::channel(concurrency);
        let (manage_client, manage_receiver) = writer::manage_channel(concurrency);
        let policy = Arc::new(LivePolicy::new(
            commit.unwrap_or_else(CommitPolicy::machine_default),
            max_inline,
        ));
        let service = BtrfsService {
            writer,
            receiver,
            manage_receiver,
            published: reader.clone(),
            devices: devices.clone(),
            block_serials: block_serials.clone(),
            device_ids,
            concurrency,
            policy: policy.clone(),
            _exit: exit,
        };
        Ok((
            Self {
                inner: Arc::new(Inner {
                    reader,
                    writer: Some(SharedArc::new(client)),
                    manage: Some(SharedArc::new(manage_client)),
                    policy: Some(policy),
                    devices,
                    block_serials,
                    serial,
                    writes: Arc::new(spin::Mutex::new(BTreeMap::new())),
                    write_round: CACHE_BLOCK_BYTES.saturating_mul(concurrency.get()),
                }),
            },
            service,
        ))
    }

    /// Returns the registered block device serial for `devid`, if known.
    pub fn device_serial(&self, devid: u64) -> Option<BlockSerial> {
        self.inner.block_serials.lock().get(&devid).copied()
    }

    /// The commit policy of a writable mount; `None` for a read-only one.
    pub fn commit_policy(&self) -> Option<CommitPolicy> {
        self.inner.policy.as_ref().map(|policy| policy.load())
    }

    /// Changes a writable mount's commit policy, as Linux's
    /// `mount -o remount,commit=`: the running transaction is judged by the
    /// new values at once. A read-only mount has none to change.
    pub fn set_commit_policy(&self, policy: CommitPolicy) -> FsResult<()> {
        self.inner
            .policy
            .as_ref()
            .ok_or(FsError::ReadOnly)?
            .store(policy);
        Ok(())
    }

    /// The `max_inline` of a writable mount; `None` for a read-only one.
    pub fn max_inline(&self) -> Option<u64> {
        self.inner.policy.as_ref().map(|policy| policy.max_inline())
    }

    /// Changes a writable mount's `max_inline`, as Linux's
    /// `mount -o remount,max_inline=`: the next mutation stores inline data
    /// under the new limit, and what is already stored stays as it is. A
    /// read-only mount has none to change.
    pub fn set_max_inline(&self, bytes: u64) -> FsResult<()> {
        self.inner
            .policy
            .as_ref()
            .ok_or(FsError::ReadOnly)?
            .max_inline
            .store(bytes, Ordering::Release);
        Ok(())
    }

    /// Ends a writable mount, as Linux's unmount: it resolves once the
    /// mount's service has committed what it held, or failed to, and let the
    /// device go; every request after it fails. A read-only mount has
    /// nothing to end.
    pub async fn unmount(&self) {
        if let Some(manage) = &self.inner.manage {
            manage.close();
        }
        if let Some(writer) = &self.inner.writer {
            writer.unmount().await;
        }
    }

    /// The handle the machine keeps on a writable mount, to commit it
    /// before power-off.
    pub(crate) fn writable(&self) -> Option<WritableMount> {
        self.inner.writer.as_ref().map(|writer| WritableMount {
            writer: SharedArc::downgrade(writer),
            exit: writer.exit().clone(),
        })
    }

    fn snapshot(&self) -> Snapshot<Device> {
        self.inner.reader.lock().clone()
    }

    async fn inode(&self, reader: &Snapshot<Device>, path: FsPath<'_>) -> FsResult<Inode> {
        let mut inode = reader.root().await.map_err(|e| self.fs_error(e))?;
        if !path.is_root() {
            // VFS already normalized the path and owns symlink traversal.
            for name in path.as_str().split('/') {
                inode = reader
                    .lookup(&inode, name.as_bytes())
                    .await
                    .map_err(|e| self.fs_error(e))?
                    .ok_or(FsError::NoEntry)?;
            }
        }
        Ok(inode)
    }

    async fn mutate(&self, path: FsPath<'_>, now: u64, operation: Operation) -> FsResult<()> {
        self.inner
            .writer
            .as_ref()
            .ok_or(FsError::ReadOnly)?
            .execute(path.as_str(), now, operation)
            .await
            .map(drop)
    }

    fn metadata(&self, inode: &Inode) -> FsResult<Metadata> {
        self.inode_metadata(inode.tree(), inode.number(), *inode.metadata())
    }

    fn inode_metadata(
        &self,
        tree: u64,
        number: u64,
        metadata: helios_btrfs::Metadata,
    ) -> FsResult<Metadata> {
        let device = self
            .inner
            .devices
            .lock()
            .get(&tree)
            .copied()
            .ok_or(FsError::Io)?;
        let kind = node_kind(metadata.kind)?;
        Ok(Metadata {
            id: NodeId::new(device.0, number),
            kind,
            link_count: u64::from(metadata.nlink),
            size: if kind == NodeKind::Directory {
                0
            } else {
                metadata.size
            },
            access_nanos: nanos(metadata.atime)?,
            modified_nanos: nanos(metadata.mtime)?,
            status_nanos: nanos(metadata.ctime)?,
        })
    }

    fn fs_error(&self, error: Error) -> FsError {
        match error {
            Error::NotFound { .. } => FsError::NoEntry,
            Error::WrongKind {
                expected: FileKind::Directory,
                ..
            } => FsError::NotDirectory,
            error => {
                tracing::warn!(%error, serial = ?self.inner.serial, "btrfs image is malformed or unreadable");
                FsError::Io
            }
        }
    }
}

fn node_kind(kind: FileKind) -> FsResult<NodeKind> {
    match kind {
        FileKind::Regular => Ok(NodeKind::File),
        FileKind::Directory => Ok(NodeKind::Directory),
        FileKind::Symlink => Ok(NodeKind::Symlink),
        FileKind::CharDevice => Ok(NodeKind::CharacterDevice),
        FileKind::BlockDevice => Ok(NodeKind::BlockDevice),
        FileKind::Fifo => Ok(NodeKind::Fifo),
        FileKind::Socket => Ok(NodeKind::Socket),
    }
}

fn nanos(time: Timestamp) -> FsResult<u64> {
    u64::try_from(time.seconds)
        .ok()
        .and_then(|s| s.checked_mul(1_000_000_000))
        .and_then(|s| s.checked_add(u64::from(time.nanoseconds)))
        .ok_or(FsError::Overflow)
}

impl<Device: BlockDevice<Buffer = BlockPages> + 'static> BtrfsFs<Device> {
    /// The stored Unix ownership and mode bits of the inode at `path`.
    pub async fn unix_attributes(&self, path: FsPath<'_>) -> FsResult<super::UnixAttributes> {
        let inode = self.inode(&self.snapshot(), path).await?;
        let meta = inode.metadata();
        Ok(super::UnixAttributes {
            permissions: meta.permissions & 0o7777,
            uid: meta.uid,
            gid: meta.gid,
        })
    }
}

/// An open btrfs directory stream, bounded at the last `DIR_INDEX` present
/// when it was opened (`btrfs_opendir` and `btrfs_real_readdir` in Linux
/// `fs/btrfs/inode.c`, commit `9b378f6ad48c`, refreshed on `rewind` as commit
/// `fd968e683bd9`).
///
/// Holds only the directory's inode identity and bound, never a `Snapshot`, so
/// keeping a stream open pins no retired CoW blocks.
pub struct BtrfsDir<Device: BlockDevice<Buffer = BlockPages>> {
    fs: BtrfsFs<Device>,
    tree: u64,
    number: u64,
    bound: DirBound,
}

impl<Device: BlockDevice<Buffer = BlockPages> + 'static> DirStream for BtrfsDir<Device> {
    async fn read(&self, cookie: DirCookie, max_entries: usize) -> FsResult<Vec<DirEntry>> {
        let reader = self.fs.snapshot();
        let inode = match reader.inode(self.tree, self.number).await {
            Ok(inode) => inode,
            Err(Error::MissingInode { .. }) => return Ok(Vec::new()),
            Err(error) => return Err(self.fs.fs_error(error)),
        };
        let mut entries = Vec::new();
        let mut failure = None;
        reader
            .read_dir(&inode, DirPosition(cookie.raw()), self.bound, |entry| {
                if entries.len() == max_entries {
                    return ControlFlow::Break(());
                }
                let convert = || -> FsResult<DirEntry> {
                    let number = match entry.target {
                        EntryTarget::Inode(number) => number,
                        EntryTarget::Subvolume(tree) => {
                            self.fs
                                .inner
                                .devices
                                .lock()
                                .get(&tree)
                                .copied()
                                .ok_or(FsError::Io)?
                                .1
                        }
                    };
                    Ok(DirEntry {
                        name: String::from_utf8(entry.name.to_vec())
                            .map_err(|_| FsError::IllegalByteSequence)?,
                        kind: node_kind(entry.kind)?,
                        inode: number,
                        next: DirCookie::new(
                            entry.position.0.checked_add(1).ok_or(FsError::Overflow)?,
                        ),
                    })
                };
                match convert() {
                    Ok(entry) => {
                        entries.push(entry);
                        ControlFlow::Continue(())
                    }
                    Err(error) => {
                        failure = Some(error);
                        ControlFlow::Break(())
                    }
                }
            })
            .await
            .map_err(|e| self.fs.fs_error(e))?;
        match failure {
            Some(error) => Err(error),
            None => Ok(entries),
        }
    }

    async fn rewind(&mut self) -> FsResult<()> {
        let reader = self.fs.snapshot();
        match reader.inode(self.tree, self.number).await {
            Ok(inode) => {
                self.bound = reader
                    .dir_bound(&inode)
                    .await
                    .map_err(|e| self.fs.fs_error(e))?;
                Ok(())
            }
            Err(Error::MissingInode { .. }) => {
                self.bound = DirBound::EMPTY;
                Ok(())
            }
            Err(error) => Err(self.fs.fs_error(error)),
        }
    }
}

impl<Device: BlockDevice<Buffer = BlockPages> + 'static> FileSystem for BtrfsFs<Device> {
    type Write = BtrfsWrite<Device>;
    type Dir = BtrfsDir<Device>;

    async fn stat(&self, path: FsPath<'_>) -> FsResult<Metadata> {
        self.metadata(&self.inode(&self.snapshot(), path).await?)
    }

    async fn open(&self, path: FsPath<'_>, flags: OpenFlags, now: u64) -> FsResult<Metadata> {
        if let Some(writer) = &self.inner.writer {
            return match writer
                .execute(path.as_str(), now, Operation::Open { flags })
                .await?
            {
                Response::Opened { inode, metadata } => {
                    self.inode_metadata(inode.tree(), inode.number(), metadata)
                }
                Response::Done | Response::Written(_) => {
                    unreachable!("open request returns inode metadata")
                }
            };
        }
        let metadata = match self.stat(path).await {
            Ok(metadata) => metadata,
            Err(FsError::NoEntry) if flags.contains(OpenFlags::CREATE) => {
                return Err(FsError::ReadOnly);
            }
            Err(error) => return Err(error),
        };
        if flags.contains(OpenFlags::CREATE | OpenFlags::EXCLUSIVE) {
            return Err(FsError::Exists);
        }
        if let Some(refusal) = metadata.kind.open_refusal() {
            return Err(refusal);
        }
        if flags.contains(OpenFlags::DIRECTORY) && metadata.kind != NodeKind::Directory {
            return Err(FsError::NotDirectory);
        }
        if flags.contains(OpenFlags::TRUNCATE) {
            return Err(FsError::ReadOnly);
        }
        Ok(metadata)
    }

    async fn read_at(&self, path: FsPath<'_>, offset: u64, max_bytes: usize) -> FsResult<Bytes> {
        let reader = self.snapshot();
        let inode = self.inode(&reader, path).await?;
        node_kind(inode.kind())?.require_regular()?;
        let len = inode
            .metadata()
            .size
            .saturating_sub(offset)
            .min(max_bytes as u64) as usize;
        let mut bytes = BytesMut::zeroed(len);
        let count = reader
            .read(&inode, offset, &mut bytes)
            .await
            .map_err(|e| self.fs_error(e))?;
        if count != len {
            return Err(FsError::Io);
        }
        Ok(bytes.freeze())
    }

    async fn open_dir(&self, path: FsPath<'_>) -> FsResult<BtrfsDir<Device>> {
        let reader = self.snapshot();
        let inode = self.inode(&reader, path).await?;
        let bound = reader
            .dir_bound(&inode)
            .await
            .map_err(|e| self.fs_error(e))?;
        Ok(BtrfsDir {
            fs: self.clone(),
            tree: inode.tree(),
            number: inode.number(),
            bound,
        })
    }

    async fn read_link(&self, path: FsPath<'_>) -> FsResult<String> {
        let reader = self.snapshot();
        let inode = self.inode(&reader, path).await?;
        if inode.kind() != FileKind::Symlink {
            return Err(FsError::Invalid);
        }
        // BTRFS_PATH_NAME_MAX bounds a symlink's contents before allocating.
        if inode.metadata().size > 4096 {
            return Err(FsError::Io);
        }
        let mut target = alloc::vec![0; inode.metadata().size as usize];
        let count = reader
            .read_link(&inode, &mut target)
            .await
            .map_err(|e| self.fs_error(e))?;
        target.truncate(count);
        String::from_utf8(target).map_err(|_| FsError::IllegalByteSequence)
    }

    async fn prepare_write(
        &self,
        path: FsPath<'_>,
        position: WritePosition,
        len: usize,
        now: u64,
    ) -> FsResult<Self::Write> {
        prepared::prepare(self, path, position, len, now).await
    }
    async fn set_size(&self, path: FsPath<'_>, size: u64, now: u64) -> FsResult<()> {
        self.mutate(path, now, Operation::Truncate { size }).await
    }
    async fn set_times(
        &self,
        path: FsPath<'_>,
        access: Option<u64>,
        modified: Option<u64>,
        now: u64,
    ) -> FsResult<()> {
        self.mutate(path, now, Operation::Times { access, modified })
            .await
    }
    async fn create_directory(&self, path: FsPath<'_>, now: u64) -> FsResult<()> {
        self.mutate(path, now, Operation::CreateDirectory).await
    }
    async fn remove_directory(&self, path: FsPath<'_>, now: u64) -> FsResult<()> {
        self.mutate(path, now, Operation::Remove { directory: true })
            .await
    }
    async fn unlink(&self, path: FsPath<'_>, now: u64) -> FsResult<()> {
        self.mutate(path, now, Operation::Remove { directory: false })
            .await
    }
    async fn rename(
        &self,
        source: FsPath<'_>,
        destination: FsPath<'_>,
        mode: RenameMode,
        now: u64,
    ) -> FsResult<()> {
        self.mutate(
            source,
            now,
            Operation::Rename {
                destination: String::from(destination.as_str()),
                mode,
            },
        )
        .await
    }
    async fn link(&self, source: FsPath<'_>, destination: FsPath<'_>, now: u64) -> FsResult<()> {
        self.mutate(
            source,
            now,
            Operation::Link {
                destination: String::from(destination.as_str()),
            },
        )
        .await
    }
    async fn symlink(&self, target: &str, path: FsPath<'_>, now: u64) -> FsResult<()> {
        self.mutate(
            path,
            now,
            Operation::Symlink {
                target: String::from(target),
            },
        )
        .await
    }
    async fn sync(&self, path: FsPath<'_>) -> FsResult<()> {
        if self.inner.writer.is_some() {
            self.mutate(path, 0, Operation::Sync).await
        } else {
            self.inode(&self.snapshot(), path).await.map(drop)
        }
    }
    async fn sync_data(&self, path: FsPath<'_>) -> FsResult<()> {
        self.sync(path).await
    }
}

impl<Device: BlockDevice<Buffer = BlockPages> + 'static> BtrfsFs<Device> {
    async fn manage(
        &self,
        operation: ManageOperation<Device>,
    ) -> VolumeManagementResult<ManageResponse> {
        self.inner
            .manage
            .as_ref()
            .ok_or(VolumeManagementError::Fs(FsError::ReadOnly))?
            .execute(operation)
            .await
    }
}

impl<Device: BlockDevice<Buffer = BlockPages> + 'static> VolumeManagement for BtrfsFs<Device> {
    type Device = CachedDisk<Device>;

    async fn create_subvolume(
        &self,
        path: FsPath<'_>,
        now: u64,
    ) -> VolumeManagementResult<SubvolumeInfo> {
        match self
            .manage(ManageOperation::CreateSubvolume {
                path: String::from(path.as_str()),
                now,
            })
            .await?
        {
            ManageResponse::Subvolume(info) => Ok(info),
            _ => unreachable!("create_subvolume returns SubvolumeInfo"),
        }
    }

    async fn delete_subvolume(&self, path: FsPath<'_>, now: u64) -> VolumeManagementResult<()> {
        self.manage(ManageOperation::DeleteSubvolume {
            path: String::from(path.as_str()),
            now,
        })
        .await
        .map(drop)
    }

    async fn snapshot_subvolume(
        &self,
        source: FsPath<'_>,
        destination: FsPath<'_>,
        read_only: bool,
        now: u64,
    ) -> VolumeManagementResult<SubvolumeInfo> {
        match self
            .manage(ManageOperation::SnapshotSubvolume {
                source: String::from(source.as_str()),
                destination: String::from(destination.as_str()),
                read_only,
                now,
            })
            .await?
        {
            ManageResponse::Subvolume(info) => Ok(info),
            _ => unreachable!("snapshot_subvolume returns SubvolumeInfo"),
        }
    }

    async fn set_subvolume_read_only(
        &self,
        path: FsPath<'_>,
        read_only: bool,
        _now: u64,
    ) -> VolumeManagementResult<()> {
        self.manage(ManageOperation::SetSubvolumeReadOnly {
            path: String::from(path.as_str()),
            read_only,
        })
        .await
        .map(drop)
    }

    async fn subvolume_info(&self, path: FsPath<'_>) -> VolumeManagementResult<SubvolumeInfo> {
        match self
            .manage(ManageOperation::SubvolumeInfo {
                path: String::from(path.as_str()),
            })
            .await?
        {
            ManageResponse::Subvolume(info) => Ok(info),
            _ => unreachable!("subvolume_info returns SubvolumeInfo"),
        }
    }

    async fn list_subvolumes(&self) -> VolumeManagementResult<Vec<SubvolumeInfo>> {
        match self.manage(ManageOperation::ListSubvolumes).await? {
            ManageResponse::Subvolumes(list) => Ok(list),
            _ => unreachable!("list_subvolumes returns Vec<SubvolumeInfo>"),
        }
    }

    async fn send_subvolume(
        &self,
        subvolume: FsPath<'_>,
        parent: Option<FsPath<'_>>,
        clone_sources: &[FsPath<'_>],
    ) -> VolumeManagementResult<Vec<u8>> {
        match self
            .manage(ManageOperation::SendSubvolume {
                subvolume: String::from(subvolume.as_str()),
                parent: parent.map(|p| String::from(p.as_str())),
                clone_sources: clone_sources
                    .iter()
                    .map(|p| String::from(p.as_str()))
                    .collect(),
            })
            .await?
        {
            ManageResponse::Stream(bytes) => Ok(bytes),
            _ => unreachable!("send_subvolume returns Vec<u8>"),
        }
    }

    async fn receive_subvolume<'a, F>(
        &'a self,
        destination: FsPath<'a>,
        stream: &'a [u8],
        now: u64,
        mut authorize_source: F,
    ) -> VolumeManagementResult<SubvolumeInfo>
    where
        F: FnMut(FsPath<'_>) -> VolumeManagementResult<()> + Send + 'a,
    {
        // Parse the stream upfront to discover every source subvolume UUID
        // referenced by `SNAPSHOT` or `CLONE`, then authorize each matching
        // subvolume's canonical path via `authorize_source` before sending the
        // receive request to the single-owner service.
        let referenced = stream_referenced_sources(stream).map_err(writer::volume_error)?;
        let mut authorized_sources = BTreeSet::new();
        if !referenced.is_empty() {
            let subvols = self.list_subvolumes().await?;
            for (uuid, ctransid) in referenced {
                if let Some(found) = subvols.iter().find(|sv| {
                    (sv.uuid == uuid && sv.ctransid == ctransid)
                        || (sv.received_uuid == Some(uuid) && sv.stransid == ctransid)
                }) {
                    let rel = FsPath::new(&found.path)
                        .ok_or(VolumeManagementError::Fs(FsError::Invalid))?;
                    authorize_source(rel)?;
                    authorized_sources.insert(found.path.clone());
                }
            }
        }
        match self
            .manage(ManageOperation::ReceiveSubvolume {
                destination: String::from(destination.as_str()),
                stream: stream.to_vec(),
                now,
                authorized_sources,
            })
            .await?
        {
            ManageResponse::Subvolume(info) => Ok(info),
            _ => unreachable!("receive_subvolume returns SubvolumeInfo"),
        }
    }

    async fn reflink(
        &self,
        source: FsPath<'_>,
        source_offset: u64,
        destination: FsPath<'_>,
        destination_offset: u64,
        length: u64,
        now: u64,
    ) -> VolumeManagementResult<()> {
        self.manage(ManageOperation::Reflink {
            source: String::from(source.as_str()),
            source_offset,
            destination: String::from(destination.as_str()),
            destination_offset,
            length,
            now,
        })
        .await
        .map(drop)
    }

    async fn dedupe(
        &self,
        source: FsPath<'_>,
        source_offset: u64,
        destination: FsPath<'_>,
        destination_offset: u64,
        length: u64,
        now: u64,
    ) -> VolumeManagementResult<DedupeOutcome> {
        match self
            .manage(ManageOperation::Dedupe {
                source: String::from(source.as_str()),
                source_offset,
                destination: String::from(destination.as_str()),
                destination_offset,
                length,
                now,
            })
            .await?
        {
            ManageResponse::Dedupe(outcome) => Ok(outcome),
            _ => unreachable!("dedupe returns DedupeOutcome"),
        }
    }

    async fn list_devices(&self) -> VolumeManagementResult<Vec<VolumeDeviceInfo>> {
        if self.inner.manage.is_some() {
            return match self.manage(ManageOperation::ListDevices).await? {
                ManageResponse::Devices(list) => Ok(list),
                _ => unreachable!("list_devices returns Vec<VolumeDeviceInfo>"),
            };
        }
        let reader = self.snapshot();
        let mut list = reader
            .devices()
            .await
            .map_err(|e| VolumeManagementError::Fs(self.fs_error(e)))?;
        let serials = self.inner.block_serials.lock();
        for dev in &mut list {
            dev.serial = serials.get(&dev.devid).copied();
        }
        Ok(list)
    }

    async fn add_device(
        &self,
        device: Self::Device,
        _now: u64,
    ) -> VolumeManagementResult<VolumeDeviceInfo> {
        match self
            .manage(ManageOperation::AddDevice { disk: device })
            .await?
        {
            ManageResponse::Device(info) => Ok(info),
            _ => unreachable!("add_device returns VolumeDeviceInfo"),
        }
    }

    async fn remove_device(&self, devid: u64, _now: u64) -> VolumeManagementResult<()> {
        self.manage(ManageOperation::RemoveDevice { devid })
            .await
            .map(drop)
    }

    async fn replace_device(
        &self,
        source_devid: u64,
        target: Self::Device,
        _now: u64,
    ) -> VolumeManagementResult<VolumeDeviceInfo> {
        match self
            .manage(ManageOperation::ReplaceDevice {
                source_devid,
                target,
            })
            .await?
        {
            ManageResponse::Device(info) => Ok(info),
            _ => unreachable!("replace_device returns VolumeDeviceInfo"),
        }
    }

    async fn resize_device(
        &self,
        devid: Option<u64>,
        target: ResizeTarget,
        _now: u64,
    ) -> VolumeManagementResult<VolumeDeviceInfo> {
        match self
            .manage(ManageOperation::ResizeDevice { devid, target })
            .await?
        {
            ManageResponse::Device(info) => Ok(info),
            _ => unreachable!("resize_device returns VolumeDeviceInfo"),
        }
    }

    async fn balance(
        &self,
        filter: BalanceFilter,
        _now: u64,
    ) -> VolumeManagementResult<BalanceReport> {
        match self.manage(ManageOperation::Balance { filter }).await? {
            ManageResponse::Balance(report) => Ok(report),
            _ => unreachable!("balance returns BalanceReport"),
        }
    }

    async fn scrub(
        &self,
        devid: Option<u64>,
        read_only: bool,
    ) -> VolumeManagementResult<ScrubReport> {
        match self
            .manage(ManageOperation::Scrub { devid, read_only })
            .await?
        {
            ManageResponse::Scrub(report) => Ok(report),
            _ => unreachable!("scrub returns ScrubReport"),
        }
    }

    async fn quota_enable(&self, _now: u64) -> VolumeManagementResult<()> {
        self.manage(ManageOperation::QuotaEnable).await.map(drop)
    }

    async fn quota_disable(&self, _now: u64) -> VolumeManagementResult<()> {
        self.manage(ManageOperation::QuotaDisable).await.map(drop)
    }

    async fn quota_rescan(&self, _now: u64) -> VolumeManagementResult<()> {
        self.manage(ManageOperation::QuotaRescan).await.map(drop)
    }

    async fn qgroup_create(&self, id: QgroupId, _now: u64) -> VolumeManagementResult<()> {
        self.manage(ManageOperation::QgroupCreate { id })
            .await
            .map(drop)
    }

    async fn qgroup_destroy(&self, id: QgroupId, _now: u64) -> VolumeManagementResult<()> {
        self.manage(ManageOperation::QgroupDestroy { id })
            .await
            .map(drop)
    }

    async fn qgroup_assign(
        &self,
        member: QgroupId,
        parent: QgroupId,
        _now: u64,
    ) -> VolumeManagementResult<()> {
        self.manage(ManageOperation::QgroupAssign { member, parent })
            .await
            .map(drop)
    }

    async fn qgroup_remove(
        &self,
        member: QgroupId,
        parent: QgroupId,
        _now: u64,
    ) -> VolumeManagementResult<()> {
        self.manage(ManageOperation::QgroupRemove { member, parent })
            .await
            .map(drop)
    }

    async fn qgroup_limit(
        &self,
        id: QgroupId,
        limit: QgroupLimit,
        _now: u64,
    ) -> VolumeManagementResult<()> {
        self.manage(ManageOperation::QgroupLimit { id, limit })
            .await
            .map(drop)
    }

    async fn quota_status(&self) -> VolumeManagementResult<QuotaStatus> {
        if self.inner.manage.is_some() {
            return match self.manage(ManageOperation::QuotaStatus).await? {
                ManageResponse::QuotaStatus(status) => Ok(status),
                _ => unreachable!("quota_status returns QuotaStatus"),
            };
        }
        let reader = self.snapshot();
        let (status, _) = reader
            .quota_info()
            .await
            .map_err(|e| VolumeManagementError::Fs(self.fs_error(e)))?;
        Ok(status)
    }

    async fn list_qgroups(&self) -> VolumeManagementResult<Vec<QgroupInfo>> {
        if self.inner.manage.is_some() {
            return match self.manage(ManageOperation::ListQgroups).await? {
                ManageResponse::Qgroups(list) => Ok(list),
                _ => unreachable!("list_qgroups returns Vec<QgroupInfo>"),
            };
        }
        let reader = self.snapshot();
        let (_, list) = reader
            .quota_info()
            .await
            .map_err(|e| VolumeManagementError::Fs(self.fs_error(e)))?;
        Ok(list)
    }
}

#[cfg(test)]
mod tests;
