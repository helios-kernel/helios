//! One task owns the mount's writer and its running transaction.
//!
//! # Concurrency contract
//!
//! - **The running transaction has one owner**, the service task. A bounded
//!   queue admits requests from every processor; the task drains a batch of
//!   at most `concurrency` requests and applies them in order, so nothing
//!   else ever touches the transaction and no lock guards it.
//! - **A change is visible once its batch is applied.** After the batch the
//!   task publishes the writer's view of the running transaction under the
//!   short reader lock, then replies. A reader clones that view and reads
//!   without the lock and without the task; the view is persistent, so the
//!   clone is reference-count increments, and it keeps reading what it saw.
//! - **A sync waits for the commit that covers it.** A sync request's reply
//!   is held until a commit that starts after the request was applied has
//!   finished. Every sync drained into one batch shares that batch's one
//!   commit, and syncs that arrive during a commit share the next.
//! - **The task commits on its own** when the commit interval has passed
//!   since the running transaction first changed, when the dirty metadata
//!   reaches the policy's bound, and when the queue closes at unmount. It
//!   writes the dirty data back into extents, without a commit, when that
//!   reaches the policy's data bound. The policy is read afresh on every
//!   change an operator makes.
//! - **A failed commit or writeback ends the service.** Its sync waiters,
//!   and every later request, fail; the device keeps the previous complete
//!   generation. A writeback that failed would fail again in the commit, so
//!   the mount stops taking writes it cannot make durable.

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::sync::Arc as SharedArc;
use alloc::vec::Vec;
use core::future::pending;
use core::num::NonZeroUsize;
use core::pin::pin;
use core::sync::atomic::{AtomicBool, Ordering};

use futures::channel::oneshot;
use futures::future::{Either, select};
use helios_btrfs::write::{
    Attributes, ChunkError, CloneRange, InodeHandle, Name, RootUuids, SpaceError, WriteError,
    WriteTransaction, Writer,
};
use helios_btrfs::{BlockSink, Error, FileKind, Timestamp};
use helios_hal::cpu::{Cpu, Instant};
use helios_hal::fs::{
    BlockDevice, BlockSerial, DeviceId, FsError, FsResult, Landed, NodeKind, OpenFlags, RenameMode,
    WritePosition,
};
use helios_hal::fs_management::{
    BalanceFilter, BalanceReport, DedupeOutcome, QgroupId, QgroupInfo, QgroupLimit, QuotaStatus,
    ResizeTarget, ScrubReport, SubvolumeInfo, VolumeDeviceInfo, VolumeManagementError,
    VolumeManagementResult,
};
use triomphe::Arc;

use super::super::{DeviceIdAllocator, UnixAttributes};
use super::{Image, LivePolicy, MountLease, Snapshot};
use crate::component::{ProviderReceiver, ProviderSender, provider_channel};
use crate::{BlockPages, CachedDisk, ProgressSignal, RootEntropyHandle, Timer};

pub(super) enum Response {
    Done,
    Written(Landed),
    Opened {
        inode: InodeHandle,
        metadata: helios_btrfs::Metadata,
    },
}

pub(super) enum Operation {
    Write {
        inode: InodeHandle,
        position: WritePosition,
        bytes: bytes::Bytes,
    },
    Open {
        flags: OpenFlags,
    },
    CreateDirectory,
    Remove {
        directory: bool,
    },
    Truncate {
        size: u64,
    },
    Times {
        access: Option<u64>,
        modified: Option<u64>,
    },
    Rename {
        destination: String,
        mode: RenameMode,
    },
    Link {
        destination: String,
    },
    Symlink {
        target: String,
    },
    Sync,
}

pub(super) struct Request {
    path: String,
    when: u64,
    operation: Operation,
    reply: oneshot::Sender<FsResult<Response>>,
}

pub(super) enum ManageResponse {
    Done,
    Subvolume(SubvolumeInfo),
    Subvolumes(Vec<SubvolumeInfo>),
    Stream(Vec<u8>),
    Dedupe(DedupeOutcome),
    Device(VolumeDeviceInfo),
    Devices(Vec<VolumeDeviceInfo>),
    Balance(BalanceReport),
    Scrub(ScrubReport),
    QuotaStatus(QuotaStatus),
    Qgroups(Vec<QgroupInfo>),
}

pub(super) enum ManageOperation<Device: BlockDevice<Buffer = BlockPages>> {
    CreateSubvolume {
        path: String,
        now: u64,
    },
    DeleteSubvolume {
        path: String,
        now: u64,
    },
    SnapshotSubvolume {
        source: String,
        destination: String,
        read_only: bool,
        now: u64,
    },
    SetSubvolumeReadOnly {
        path: String,
        read_only: bool,
    },
    SubvolumeInfo {
        path: String,
    },
    ListSubvolumes,
    SendSubvolume {
        subvolume: String,
        parent: Option<String>,
        clone_sources: Vec<String>,
    },
    ReceiveSubvolume {
        destination: String,
        stream: Vec<u8>,
        now: u64,
        authorized_sources: BTreeSet<String>,
    },
    Reflink {
        source: String,
        source_offset: u64,
        destination: String,
        destination_offset: u64,
        length: u64,
        now: u64,
    },
    Dedupe {
        source: String,
        source_offset: u64,
        destination: String,
        destination_offset: u64,
        length: u64,
        now: u64,
    },
    ListDevices,
    AddDevice {
        disk: CachedDisk<Device>,
    },
    RemoveDevice {
        devid: u64,
    },
    ReplaceDevice {
        source_devid: u64,
        target: CachedDisk<Device>,
    },
    ResizeDevice {
        devid: Option<u64>,
        target: ResizeTarget,
    },
    Balance {
        filter: BalanceFilter,
    },
    Scrub {
        devid: Option<u64>,
        read_only: bool,
    },
    QuotaEnable,
    QuotaDisable,
    QuotaRescan,
    QuotaStatus,
    ListQgroups,
    QgroupCreate {
        id: QgroupId,
    },
    QgroupDestroy {
        id: QgroupId,
    },
    QgroupAssign {
        member: QgroupId,
        parent: QgroupId,
    },
    QgroupRemove {
        member: QgroupId,
        parent: QgroupId,
    },
    QgroupLimit {
        id: QgroupId,
        limit: QgroupLimit,
    },
}

pub(super) struct ManageRequest<Device: BlockDevice<Buffer = BlockPages>> {
    operation: ManageOperation<Device>,
    reply: oneshot::Sender<VolumeManagementResult<ManageResponse>>,
}

pub(super) struct ManageClient<Device: BlockDevice<Buffer = BlockPages>> {
    sender: ProviderSender<ManageRequest<Device>>,
}

impl<Device: BlockDevice<Buffer = BlockPages>> Drop for ManageClient<Device> {
    fn drop(&mut self) {
        self.sender.close();
    }
}

impl<Device: BlockDevice<Buffer = BlockPages>> ManageClient<Device> {
    pub(super) fn close(&self) {
        self.sender.close();
    }

    pub(super) async fn execute(
        &self,
        operation: ManageOperation<Device>,
    ) -> VolumeManagementResult<ManageResponse> {
        let (reply, result) = oneshot::channel();
        self.sender
            .send(ManageRequest { operation, reply })
            .await
            .map_err(|_| VolumeManagementError::Fs(FsError::Io))?;
        result
            .await
            .map_err(|_| VolumeManagementError::Fs(FsError::Io))?
    }
}

pub(super) fn manage_channel<Device: BlockDevice<Buffer = BlockPages>>(
    capacity: NonZeroUsize,
) -> (
    ManageClient<Device>,
    ProviderReceiver<ManageRequest<Device>>,
) {
    let (sender, receiver) = provider_channel(capacity.get());
    (ManageClient { sender }, receiver)
}

pub(super) struct Client {
    sender: ProviderSender<Request>,
    exit: SharedArc<ServiceExit>,
}

impl Drop for Client {
    fn drop(&mut self) {
        self.sender.close();
    }
}

/// Whether a writable mount's service has ended: its last commit done or
/// failed, its writer and its hold on the device gone.
pub(crate) struct ServiceExit {
    ended: AtomicBool,
    signal: ProgressSignal,
}

impl ServiceExit {
    fn new() -> Self {
        Self {
            ended: AtomicBool::new(false),
            signal: ProgressSignal::new(),
        }
    }

    pub(crate) fn has_ended(&self) -> bool {
        self.ended.load(Ordering::Acquire)
    }

    /// Resolves once the service has ended.
    pub(crate) async fn ended(&self) {
        loop {
            // Armed before the flag is tested, so an end between the two
            // still wakes this wait.
            let mark = self.signal.mark();
            if self.has_ended() {
                return;
            }
            self.signal.changed(mark).await;
        }
    }
}

/// The service's last field: dropped after its writer and receiver, it
/// reports the end to everyone waiting for it.
pub(super) struct ExitGuard(SharedArc<ServiceExit>);

impl Drop for ExitGuard {
    fn drop(&mut self) {
        self.0.ended.store(true, Ordering::Release);
        self.0.signal.signal();
    }
}

/// Root UUIDs from the kernel's entropy, as RFC 9562 version 4.
pub(super) struct EntropyUuids(pub(super) RootEntropyHandle);

impl RootUuids for EntropyUuids {
    fn next_uuid(&mut self) -> [u8; 16] {
        let mut uuid = [0; 16];
        self.0.fill(&mut uuid);
        // RFC 9562, version 4 and the RFC variant.
        uuid[6] = (uuid[6] & 0x0f) | 0x40;
        uuid[8] = (uuid[8] & 0x3f) | 0x80;
        uuid
    }
}

impl Client {
    /// Ends the mount: no request is taken after this, and it resolves once
    /// the service has committed what it held and let the device go.
    pub(super) async fn unmount(&self) {
        self.sender.close();
        self.exit.ended().await;
    }

    pub(super) fn exit(&self) -> &SharedArc<ServiceExit> {
        &self.exit
    }
    pub(super) async fn execute(
        &self,
        path: &str,
        when: u64,
        operation: Operation,
    ) -> FsResult<Response> {
        let (reply, result) = oneshot::channel();
        self.sender
            .send(Request {
                path: String::from(path),
                when,
                operation,
                reply,
            })
            .await
            .map_err(|_| FsError::Io)?;
        result.await.map_err(|_| FsError::Io)?
    }
}

pub(super) fn channel(capacity: NonZeroUsize) -> (Client, ProviderReceiver<Request>, ExitGuard) {
    let (sender, receiver) = provider_channel(capacity.get());
    let exit = SharedArc::new(ServiceExit::new());
    (
        Client {
            sender,
            exit: exit.clone(),
        },
        receiver,
        ExitGuard(exit),
    )
}

/// The kernel task owning one writable mount. Unmounting, or dropping the
/// mount, closes its queue; the task drains already accepted work, commits
/// it, and then terminates.
pub struct BtrfsService<Device: BlockDevice<Buffer = BlockPages>> {
    pub(super) writer: Writer<Image<Device>, EntropyUuids>,
    pub(super) receiver: ProviderReceiver<Request>,
    pub(super) manage_receiver: ProviderReceiver<ManageRequest<Device>>,
    pub(super) published: Arc<spin::Mutex<Snapshot<Device>>>,
    pub(super) devices: Arc<spin::Mutex<BTreeMap<u64, (DeviceId, u64)>>>,
    pub(super) block_serials: Arc<spin::Mutex<BTreeMap<u64, BlockSerial>>>,
    pub(super) device_ids: DeviceIdAllocator,
    pub(super) concurrency: NonZeroUsize,
    pub(super) policy: Arc<LivePolicy>,
    /// Last, so the end is reported only once everything above has gone.
    pub(super) _exit: ExitGuard,
}

/// A sync request's reply, held until a commit covers it.
type SyncWaiter = oneshot::Sender<FsResult<Response>>;

/// What woke the service.
enum Wake<Device: BlockDevice<Buffer = BlockPages>> {
    Request(Option<Request>),
    Manage(Option<ManageRequest<Device>>),
    /// The commit deadline passed, or the operator changed the policy.
    Policy,
}

impl<Device: BlockDevice<Buffer = BlockPages>> BtrfsService<Device> {
    /// Serves the mount until it is unmounted, timing the commit interval
    /// on `timer`.
    pub async fn run<CpuImpl: Cpu + Clone>(mut self, timer: Timer<CpuImpl>) {
        // When the running transaction first changed: the commit interval
        // runs from here, as Linux's from the transaction's `start_time`.
        let mut dirty_since: Option<Instant> = None;
        let mut manage_open = true;
        loop {
            // Armed before the policy is read, so a change made while the
            // service decides is not missed.
            let mark = self.policy.changed.mark();
            let policy = self.policy.load();
            let dirty = self.writer.dirty();
            if dirty.is_clean() {
                dirty_since = None;
            }
            let deadline = dirty_since.map(|since| {
                since.saturating_add(timer.cpu().timebase().duration_to_ticks(policy.interval))
            });
            if !dirty.is_clean()
                && (dirty.metadata_bytes >= policy.dirty_metadata_limit
                    || deadline.is_some_and(|deadline| deadline <= timer.now()))
            {
                if !self.commit(Vec::new(), &mut dirty_since).await {
                    return;
                }
                continue;
            }
            if dirty.data_bytes != 0 && dirty.data_bytes >= policy.dirty_data_limit {
                if !self.writeback().await {
                    return;
                }
                continue;
            }
            let wake = {
                let request = pin!(self.receiver.recv());
                let manage = pin!(async {
                    if manage_open {
                        self.manage_receiver.recv().await
                    } else {
                        pending().await
                    }
                });
                let due = pin!(async {
                    match deadline {
                        Some(deadline) => timer.sleep_until(deadline).await,
                        None => pending().await,
                    }
                });
                let changed = pin!(self.policy.changed.changed(mark));
                match select(select(request, manage), select(due, changed)).await {
                    Either::Left((Either::Left((request, _)), _)) => Wake::Request(request),
                    Either::Left((Either::Right((manage, _)), _)) => Wake::Manage(manage),
                    Either::Right(_) => Wake::Policy,
                }
            };
            match wake {
                Wake::Policy => {}
                Wake::Manage(None) => {
                    manage_open = false;
                }
                Wake::Manage(Some(req)) => {
                    if !req.reply.is_canceled() {
                        // Box management futures so infrequent volume-admin
                        // state machines do not inflate `BtrfsService::run`'s
                        // stack frame on bare-metal kernel tasks.
                        let res = Box::pin(self.apply_manage(req.operation)).await;
                        if let Ok(snap) = self.writer.snapshot() {
                            Box::pin(self.refresh_subvolume_devices(&snap)).await;
                            *self.published.lock() = snap;
                        }
                        if self.writer.dirty().is_clean() {
                            dirty_since = None;
                        } else if dirty_since.is_none() {
                            dirty_since = Some(timer.now());
                        }
                        let _ = req.reply.send(res);
                    }
                }
                Wake::Request(None) => {
                    // Unmounted: what the running transaction holds becomes
                    // durable before the device is let go.
                    self.commit(Vec::new(), &mut dirty_since).await;
                    return;
                }
                Wake::Request(Some(first)) => {
                    let Some(syncs) = self.apply_batch(first).await else {
                        return;
                    };
                    if self.writer.dirty().is_clean() {
                        dirty_since = None;
                    } else if dirty_since.is_none() {
                        dirty_since = Some(timer.now());
                    }
                    // The dirty data bound is judged at the top of the loop,
                    // once no commit has written the data back here.
                    let dirty = self.writer.dirty();
                    if (!syncs.is_empty()
                        || dirty.metadata_bytes >= self.policy.load().dirty_metadata_limit)
                        && !self.commit(syncs, &mut dirty_since).await
                    {
                        return;
                    }
                }
            }
        }
    }

    async fn refresh_subvolume_devices(&self, snap: &Snapshot<Device>) {
        let mut live = BTreeMap::new();
        if snap
            .subvolumes(|tree, root_inode| {
                live.insert(tree, root_inode);
            })
            .await
            .is_err()
        {
            return;
        }
        let mut devices = self.devices.lock();
        devices.retain(|tree, _| live.contains_key(tree));
        for (tree, root_inode) in live {
            devices
                .entry(tree)
                .or_insert_with(|| (self.device_ids.allocate(), root_inode));
        }
    }

    #[inline(never)]
    async fn resolve_subvolume_tree(&mut self, path: &str) -> VolumeManagementResult<u64> {
        let handle = {
            let tx = self.writer.join().await.map_err(volume_error)?;
            inode(&tx, path).await.map_err(VolumeManagementError::Fs)?
        };
        let info = self
            .writer
            .subvolume_info(handle.tree())
            .await
            .map_err(volume_error)?;
        if info.path != path {
            return Err(VolumeManagementError::NotSubvolume);
        }
        Ok(handle.tree())
    }

    #[inline(never)]
    async fn manage_create_subvolume(
        &mut self,
        path: String,
        now: u64,
    ) -> VolumeManagementResult<ManageResponse> {
        if path.is_empty() {
            return Err(VolumeManagementError::Fs(FsError::Exists));
        }
        let (parent_path, name) = path.rsplit_once('/').unwrap_or(("", path.as_str()));
        let attrs = {
            let tx = self.writer.join().await.map_err(volume_error)?;
            let parent_handle = inode(&tx, parent_path)
                .await
                .map_err(VolumeManagementError::Fs)?;
            inherited(&tx, &parent_handle, NodeKind::Directory)
                .await
                .map_err(VolumeManagementError::Fs)?
        };
        let info = Box::pin(self.writer.create_subvolume(
            parent_path,
            name.as_bytes(),
            attrs,
            timestamp(now),
        ))
        .await
        .map_err(volume_error)?;
        Ok(ManageResponse::Subvolume(info))
    }

    #[inline(never)]
    async fn manage_delete_subvolume(
        &mut self,
        path: String,
        now: u64,
    ) -> VolumeManagementResult<ManageResponse> {
        if path.is_empty() {
            return Err(VolumeManagementError::DefaultSubvolume);
        }
        let _tree = self.resolve_subvolume_tree(&path).await?;
        let (parent_path, name) = path.rsplit_once('/').unwrap_or(("", path.as_str()));
        Box::pin(
            self.writer
                .delete_subvolume(parent_path, name.as_bytes(), timestamp(now)),
        )
        .await
        .map_err(volume_error)?;
        Ok(ManageResponse::Done)
    }

    #[inline(never)]
    async fn manage_snapshot_subvolume(
        &mut self,
        source: String,
        destination: String,
        read_only: bool,
        now: u64,
    ) -> VolumeManagementResult<ManageResponse> {
        if destination.is_empty() {
            return Err(VolumeManagementError::Fs(FsError::Exists));
        }
        let source_tree = self.resolve_subvolume_tree(&source).await?;
        let (parent_path, name) = destination
            .rsplit_once('/')
            .unwrap_or(("", destination.as_str()));
        let info = Box::pin(self.writer.snapshot_subvolume(
            source_tree,
            parent_path,
            name.as_bytes(),
            read_only,
            timestamp(now),
        ))
        .await
        .map_err(volume_error)?;
        Ok(ManageResponse::Subvolume(info))
    }

    #[inline(never)]
    async fn manage_set_subvolume_read_only(
        &mut self,
        path: String,
        read_only: bool,
    ) -> VolumeManagementResult<ManageResponse> {
        let tree = self.resolve_subvolume_tree(&path).await?;
        Box::pin(self.writer.set_subvolume_read_only(tree, read_only))
            .await
            .map_err(volume_error)?;
        Ok(ManageResponse::Done)
    }

    #[inline(never)]
    async fn manage_subvolume_info(
        &mut self,
        path: String,
    ) -> VolumeManagementResult<ManageResponse> {
        let tree = self.resolve_subvolume_tree(&path).await?;
        let info = Box::pin(self.writer.subvolume_info(tree))
            .await
            .map_err(volume_error)?;
        Ok(ManageResponse::Subvolume(info))
    }

    #[inline(never)]
    async fn manage_list_subvolumes(&mut self) -> VolumeManagementResult<ManageResponse> {
        let list = Box::pin(self.writer.list_subvolumes())
            .await
            .map_err(volume_error)?;
        Ok(ManageResponse::Subvolumes(list))
    }

    #[inline(never)]
    async fn manage_send_subvolume(
        &mut self,
        subvolume: String,
        parent: Option<String>,
        clone_sources: Vec<String>,
    ) -> VolumeManagementResult<ManageResponse> {
        let tree = self.resolve_subvolume_tree(&subvolume).await?;
        let parent_tree = match parent {
            Some(ref p) => Some(self.resolve_subvolume_tree(p).await?),
            None => None,
        };
        let mut clone_trees = Vec::with_capacity(clone_sources.len());
        for src in &clone_sources {
            clone_trees.push(self.resolve_subvolume_tree(src).await?);
        }
        let bytes = Box::pin(self.writer.send_subvolume(tree, parent_tree, &clone_trees))
            .await
            .map_err(volume_error)?;
        Ok(ManageResponse::Stream(bytes))
    }

    #[inline(never)]
    async fn manage_receive_subvolume(
        &mut self,
        destination: String,
        stream: Vec<u8>,
        now: u64,
        authorized_sources: BTreeSet<String>,
    ) -> VolumeManagementResult<ManageResponse> {
        let info = Box::pin(self.writer.receive_subvolume(
            &destination,
            &stream,
            timestamp(now),
            |source_path| {
                if authorized_sources.contains(source_path) {
                    Ok(())
                } else {
                    Err(WriteError::PermissionDenied)
                }
            },
        ))
        .await
        .map_err(volume_error)?;
        Ok(ManageResponse::Subvolume(info))
    }

    #[inline(never)]
    async fn manage_reflink(
        &mut self,
        source: String,
        source_offset: u64,
        destination: String,
        destination_offset: u64,
        length: u64,
        now: u64,
    ) -> VolumeManagementResult<ManageResponse> {
        let mut tx = self.writer.join().await.map_err(volume_error)?;
        let src = inode(&tx, &source)
            .await
            .map_err(VolumeManagementError::Fs)?;
        let dst = inode(&tx, &destination)
            .await
            .map_err(VolumeManagementError::Fs)?;
        Box::pin(tx.clone_range(
            CloneRange {
                source: &src,
                destination: &dst,
                source_offset,
                destination_offset,
                length,
            },
            timestamp(now),
        ))
        .await
        .map_err(volume_error)?;
        Ok(ManageResponse::Done)
    }

    #[inline(never)]
    async fn manage_dedupe(
        &mut self,
        source: String,
        source_offset: u64,
        destination: String,
        destination_offset: u64,
        length: u64,
        now: u64,
    ) -> VolumeManagementResult<ManageResponse> {
        let mut tx = self.writer.join().await.map_err(volume_error)?;
        let src = inode(&tx, &source)
            .await
            .map_err(VolumeManagementError::Fs)?;
        let dst = inode(&tx, &destination)
            .await
            .map_err(VolumeManagementError::Fs)?;
        let outcome = Box::pin(tx.dedupe_range(
            CloneRange {
                source: &src,
                destination: &dst,
                source_offset,
                destination_offset,
                length,
            },
            timestamp(now),
        ))
        .await
        .map_err(volume_error)?;
        Ok(ManageResponse::Dedupe(outcome))
    }

    #[inline(never)]
    async fn manage_list_devices(&mut self) -> VolumeManagementResult<ManageResponse> {
        let mut list = Box::pin(self.writer.list_devices())
            .await
            .map_err(volume_error)?;
        let serials = self.block_serials.lock();
        for dev in &mut list {
            dev.serial = serials.get(&dev.devid).copied();
        }
        Ok(ManageResponse::Devices(list))
    }

    #[inline(never)]
    async fn manage_add_device(
        &mut self,
        disk: CachedDisk<Device>,
    ) -> VolumeManagementResult<ManageResponse> {
        let serial = disk.serial();
        let lease = disk
            .write_mount()
            .ok_or(VolumeManagementError::Fs(FsError::Busy))?;
        let image = Image {
            disk,
            _lease: MountLease::Write { _lease: lease },
        };
        let mut info = Box::pin(self.writer.add_device(image))
            .await
            .map_err(volume_error)?;
        self.block_serials.lock().insert(info.devid, serial);
        info.serial = Some(serial);
        Ok(ManageResponse::Device(info))
    }

    #[inline(never)]
    async fn manage_remove_device(&mut self, devid: u64) -> VolumeManagementResult<ManageResponse> {
        Box::pin(self.writer.remove_device(devid))
            .await
            .map_err(volume_error)?;
        self.block_serials.lock().remove(&devid);
        Ok(ManageResponse::Done)
    }

    #[inline(never)]
    async fn manage_replace_device(
        &mut self,
        source_devid: u64,
        target: CachedDisk<Device>,
    ) -> VolumeManagementResult<ManageResponse> {
        let serial = target.serial();
        let lease = target
            .write_mount()
            .ok_or(VolumeManagementError::Fs(FsError::Busy))?;
        let image = Image {
            disk: target,
            _lease: MountLease::Write { _lease: lease },
        };
        let mut info = Box::pin(self.writer.replace_device(source_devid, image))
            .await
            .map_err(volume_error)?;
        self.block_serials.lock().insert(info.devid, serial);
        info.serial = Some(serial);
        Ok(ManageResponse::Device(info))
    }

    #[inline(never)]
    async fn manage_resize_device(
        &mut self,
        devid: Option<u64>,
        target: ResizeTarget,
    ) -> VolumeManagementResult<ManageResponse> {
        let mut info = Box::pin(self.writer.resize_device(devid, target))
            .await
            .map_err(volume_error)?;
        info.serial = self.block_serials.lock().get(&info.devid).copied();
        Ok(ManageResponse::Device(info))
    }

    #[inline(never)]
    async fn manage_balance(
        &mut self,
        filter: BalanceFilter,
    ) -> VolumeManagementResult<ManageResponse> {
        let report = Box::pin(self.writer.balance(filter))
            .await
            .map_err(volume_error)?;
        Ok(ManageResponse::Balance(report))
    }

    #[inline(never)]
    async fn manage_scrub(
        &mut self,
        devid: Option<u64>,
        read_only: bool,
    ) -> VolumeManagementResult<ManageResponse> {
        let report = Box::pin(self.writer.scrub(devid, read_only))
            .await
            .map_err(volume_error)?;
        Ok(ManageResponse::Scrub(report))
    }

    #[inline(never)]
    async fn manage_quota_enable(&mut self) -> VolumeManagementResult<ManageResponse> {
        Box::pin(self.writer.quota_enable())
            .await
            .map_err(volume_error)?;
        Ok(ManageResponse::Done)
    }

    #[inline(never)]
    async fn manage_quota_disable(&mut self) -> VolumeManagementResult<ManageResponse> {
        Box::pin(self.writer.quota_disable())
            .await
            .map_err(volume_error)?;
        Ok(ManageResponse::Done)
    }

    #[inline(never)]
    async fn manage_quota_rescan(&mut self) -> VolumeManagementResult<ManageResponse> {
        Box::pin(self.writer.quota_rescan())
            .await
            .map_err(volume_error)?;
        Ok(ManageResponse::Done)
    }

    #[inline(never)]
    async fn manage_quota_status(&mut self) -> VolumeManagementResult<ManageResponse> {
        let status = Box::pin(self.writer.quota_status())
            .await
            .map_err(volume_error)?;
        Ok(ManageResponse::QuotaStatus(status))
    }

    #[inline(never)]
    async fn manage_list_qgroups(&mut self) -> VolumeManagementResult<ManageResponse> {
        let list = Box::pin(self.writer.list_qgroups())
            .await
            .map_err(volume_error)?;
        Ok(ManageResponse::Qgroups(list))
    }

    #[inline(never)]
    async fn manage_qgroup_create(
        &mut self,
        id: QgroupId,
    ) -> VolumeManagementResult<ManageResponse> {
        Box::pin(self.writer.qgroup_create(id))
            .await
            .map_err(volume_error)?;
        Ok(ManageResponse::Done)
    }

    #[inline(never)]
    async fn manage_qgroup_destroy(
        &mut self,
        id: QgroupId,
    ) -> VolumeManagementResult<ManageResponse> {
        Box::pin(self.writer.qgroup_destroy(id))
            .await
            .map_err(volume_error)?;
        Ok(ManageResponse::Done)
    }

    #[inline(never)]
    async fn manage_qgroup_assign(
        &mut self,
        member: QgroupId,
        parent: QgroupId,
    ) -> VolumeManagementResult<ManageResponse> {
        Box::pin(self.writer.qgroup_assign(member, parent))
            .await
            .map_err(volume_error)?;
        Ok(ManageResponse::Done)
    }

    #[inline(never)]
    async fn manage_qgroup_remove(
        &mut self,
        member: QgroupId,
        parent: QgroupId,
    ) -> VolumeManagementResult<ManageResponse> {
        Box::pin(self.writer.qgroup_remove(member, parent))
            .await
            .map_err(volume_error)?;
        Ok(ManageResponse::Done)
    }

    #[inline(never)]
    async fn manage_qgroup_limit(
        &mut self,
        id: QgroupId,
        limit: QgroupLimit,
    ) -> VolumeManagementResult<ManageResponse> {
        Box::pin(self.writer.qgroup_limit(id, limit))
            .await
            .map_err(volume_error)?;
        Ok(ManageResponse::Done)
    }

    #[inline(never)]
    async fn apply_manage(
        &mut self,
        operation: ManageOperation<Device>,
    ) -> VolumeManagementResult<ManageResponse> {
        match operation {
            ManageOperation::CreateSubvolume { path, now } => {
                self.manage_create_subvolume(path, now).await
            }
            ManageOperation::DeleteSubvolume { path, now } => {
                self.manage_delete_subvolume(path, now).await
            }
            ManageOperation::SnapshotSubvolume {
                source,
                destination,
                read_only,
                now,
            } => {
                self.manage_snapshot_subvolume(source, destination, read_only, now)
                    .await
            }
            ManageOperation::SetSubvolumeReadOnly { path, read_only } => {
                self.manage_set_subvolume_read_only(path, read_only).await
            }
            ManageOperation::SubvolumeInfo { path } => self.manage_subvolume_info(path).await,
            ManageOperation::ListSubvolumes => self.manage_list_subvolumes().await,
            ManageOperation::SendSubvolume {
                subvolume,
                parent,
                clone_sources,
            } => {
                self.manage_send_subvolume(subvolume, parent, clone_sources)
                    .await
            }
            ManageOperation::ReceiveSubvolume {
                destination,
                stream,
                now,
                authorized_sources,
            } => {
                self.manage_receive_subvolume(destination, stream, now, authorized_sources)
                    .await
            }
            ManageOperation::Reflink {
                source,
                source_offset,
                destination,
                destination_offset,
                length,
                now,
            } => {
                self.manage_reflink(
                    source,
                    source_offset,
                    destination,
                    destination_offset,
                    length,
                    now,
                )
                .await
            }
            ManageOperation::Dedupe {
                source,
                source_offset,
                destination,
                destination_offset,
                length,
                now,
            } => {
                self.manage_dedupe(
                    source,
                    source_offset,
                    destination,
                    destination_offset,
                    length,
                    now,
                )
                .await
            }
            ManageOperation::ListDevices => self.manage_list_devices().await,
            ManageOperation::AddDevice { disk } => self.manage_add_device(disk).await,
            ManageOperation::RemoveDevice { devid } => self.manage_remove_device(devid).await,
            ManageOperation::ReplaceDevice {
                source_devid,
                target,
            } => self.manage_replace_device(source_devid, target).await,
            ManageOperation::ResizeDevice { devid, target } => {
                self.manage_resize_device(devid, target).await
            }
            ManageOperation::Balance { filter } => self.manage_balance(filter).await,
            ManageOperation::Scrub { devid, read_only } => {
                self.manage_scrub(devid, read_only).await
            }
            ManageOperation::QuotaEnable => self.manage_quota_enable().await,
            ManageOperation::QuotaDisable => self.manage_quota_disable().await,
            ManageOperation::QuotaRescan => self.manage_quota_rescan().await,
            ManageOperation::QuotaStatus => self.manage_quota_status().await,
            ManageOperation::ListQgroups => self.manage_list_qgroups().await,
            ManageOperation::QgroupCreate { id } => self.manage_qgroup_create(id).await,
            ManageOperation::QgroupDestroy { id } => self.manage_qgroup_destroy(id).await,
            ManageOperation::QgroupAssign { member, parent } => {
                self.manage_qgroup_assign(member, parent).await
            }
            ManageOperation::QgroupRemove { member, parent } => {
                self.manage_qgroup_remove(member, parent).await
            }
            ManageOperation::QgroupLimit { id, limit } => self.manage_qgroup_limit(id, limit).await,
        }
    }

    /// Applies `first` and what else is queued, up to `concurrency`
    /// requests, publishes the result and replies. Returns the syncs left
    /// waiting for a commit, or `None` once the writer is poisoned.
    #[inline(never)]
    async fn apply_batch(&mut self, first: Request) -> Option<Vec<SyncWaiter>> {
        let concurrency = self.concurrency;
        let mut requests = Vec::with_capacity(concurrency.get());
        requests.push(first);
        // A continuous producer cannot postpone the batch's publication.
        while requests.len() < concurrency.get() {
            match self.receiver.try_recv() {
                Ok(request) => requests.push(request),
                Err(_) => break,
            }
        }
        let mut transaction = match self.writer.join().await {
            Ok(transaction) => transaction,
            Err(error) => {
                let error = fs_error(error);
                for request in requests {
                    let _ = request.reply.send(Err(error));
                }
                return None;
            }
        };
        let mut replies = Vec::with_capacity(requests.len());
        let mut syncs = Vec::new();
        // An operator's change applies from the next batch.
        transaction.set_max_inline(self.policy.max_inline());
        for request in requests {
            if request.reply.is_canceled() {
                continue;
            }
            let sync = matches!(request.operation, Operation::Sync);
            let result = apply(
                &mut transaction,
                &request.path,
                request.when,
                request.operation,
            )
            .await;
            match result {
                Ok(_) if sync => syncs.push(request.reply),
                result => replies.push((request.reply, result)),
            }
        }
        *self.published.lock() = self
            .writer
            .snapshot()
            .expect("the writer joined above is not poisoned");
        for (reply, result) in replies {
            let _ = reply.send(result);
        }
        Some(syncs)
    }

    /// Writes the dirty data back into extents and publishes the result,
    /// which releases the pages the previous view held. Returns false once
    /// the writeback failed, which ends the service.
    #[inline(never)]
    async fn writeback(&mut self) -> bool {
        match Box::pin(self.writer.writeback()).await {
            Ok(()) => {
                *self.published.lock() = self
                    .writer
                    .snapshot()
                    .expect("a writer that just wrote back is not poisoned");
                true
            }
            Err(error) => {
                tracing::error!(%error, "btrfs writeback failed; the mount takes no more writes");
                false
            }
        }
    }

    /// Commits the running transaction and answers `syncs`. Returns false
    /// once the commit failed, which poisons the writer and ends the
    /// service.
    #[inline(never)]
    async fn commit(&mut self, syncs: Vec<SyncWaiter>, dirty_since: &mut Option<Instant>) -> bool {
        let committed = Box::pin(self.writer.commit()).await;
        let outcome = match committed {
            Ok(()) => {
                *dirty_since = None;
                *self.published.lock() = self
                    .writer
                    .snapshot()
                    .expect("a writer that just committed is not poisoned");
                Ok(())
            }
            Err(error) => {
                tracing::error!(%error, "btrfs commit failed; the mount takes no more writes");
                Err(fs_error(error))
            }
        };
        for sync in syncs {
            let _ = sync.send(outcome.map(|()| Response::Done));
        }
        outcome.is_ok()
    }
}

async fn inode<S: BlockSink, U: RootUuids>(
    transaction: &WriteTransaction<'_, S, U>,
    path: &str,
) -> FsResult<InodeHandle> {
    let mut inode = transaction.root().await.map_err(fs_error)?;
    if !path.is_empty() {
        for name in path.split('/') {
            inode = transaction
                .lookup(&inode, name.as_bytes())
                .await
                .map_err(fs_error)?
                .ok_or(FsError::NoEntry)?;
        }
    }
    Ok(inode)
}

async fn parent<'a, S: BlockSink, U: RootUuids>(
    transaction: &WriteTransaction<'_, S, U>,
    path: &'a str,
) -> FsResult<(InodeHandle, &'a [u8])> {
    if path.is_empty() {
        return Err(FsError::Busy);
    }
    let (directory, name) = path.rsplit_once('/').unwrap_or(("", path));
    Ok((inode(transaction, directory).await?, name.as_bytes()))
}

/// The attributes a node of `kind` made in `parent` takes. A request
/// reaching the writer carries no creator identity, so the node inherits
/// from its directory ([`UnixAttributes::inherited`]).
async fn inherited<S: BlockSink, U: RootUuids>(
    transaction: &WriteTransaction<'_, S, U>,
    parent: &InodeHandle,
    kind: NodeKind,
) -> FsResult<Attributes> {
    let directory = transaction.metadata(parent).await.map_err(fs_error)?;
    let node = UnixAttributes {
        permissions: directory.permissions,
        uid: directory.uid,
        gid: directory.gid,
    }
    .inherited(kind);
    Ok(Attributes {
        permissions: node.permissions,
        uid: node.uid,
        gid: node.gid,
        umask: 0,
    })
}

pub(super) fn timestamp(nanos: u64) -> Timestamp {
    Timestamp {
        seconds: (nanos / 1_000_000_000) as i64,
        nanoseconds: (nanos % 1_000_000_000) as u32,
    }
}

async fn apply<S: BlockSink, U: RootUuids>(
    transaction: &mut WriteTransaction<'_, S, U>,
    path: &str,
    now: u64,
    operation: Operation,
) -> FsResult<Response> {
    let when = timestamp(now);
    match operation {
        Operation::Write {
            inode,
            position,
            bytes,
        } => {
            let metadata = transaction.metadata(&inode).await.map_err(fs_error)?;
            let offset = match position {
                WritePosition::At(offset) => offset,
                WritePosition::End => metadata.size,
            };
            offset
                .checked_add(bytes.len() as u64)
                .ok_or(FsError::Overflow)?;
            let written = transaction
                .write_file(&inode, offset, &bytes, when)
                .await
                .map_err(fs_error)?;
            // A device with no more free sectors stores a prefix, which the
            // transaction keeps and the caller learns the length of.
            if written != bytes.len() {
                tracing::warn!(
                    written,
                    requested = bytes.len(),
                    "btrfs write ran out of space"
                );
            }
            return Ok(Response::Written(Landed {
                offset,
                len: written,
            }));
        }
        Operation::Open { flags } => {
            let file = match inode(transaction, path).await {
                Ok(file) => {
                    if flags.contains(OpenFlags::CREATE | OpenFlags::EXCLUSIVE) {
                        return Err(FsError::Exists);
                    }
                    file
                }
                Err(FsError::NoEntry) if flags.contains(OpenFlags::CREATE) => {
                    if flags.contains(OpenFlags::DIRECTORY) {
                        return Err(FsError::NotDirectory);
                    }
                    let (parent, bytes) = parent(transaction, path).await?;
                    let attributes = inherited(transaction, &parent, NodeKind::File).await?;
                    transaction
                        .create_file(
                            Name {
                                parent: &parent,
                                bytes,
                            },
                            attributes,
                            when,
                        )
                        .await
                        .map_err(fs_error)?
                }
                Err(error) => return Err(error),
            };
            let metadata = transaction.metadata(&file).await.map_err(fs_error)?;
            if let Some(refusal) = super::node_kind(metadata.kind)?.open_refusal() {
                return Err(refusal);
            }
            if flags.contains(OpenFlags::DIRECTORY) && metadata.kind != FileKind::Directory {
                return Err(FsError::NotDirectory);
            }
            if flags.contains(OpenFlags::TRUNCATE) {
                transaction
                    .truncate_file(&file, 0, when)
                    .await
                    .map_err(fs_error)?;
            }
            let metadata = transaction.metadata(&file).await.map_err(fs_error)?;
            return Ok(Response::Opened {
                inode: file,
                metadata,
            });
        }
        Operation::CreateDirectory | Operation::Symlink { .. } => {
            let (parent, bytes) = parent(transaction, path).await?;
            let name = Name {
                parent: &parent,
                bytes,
            };
            match operation {
                Operation::Symlink { target } => {
                    let attributes = inherited(transaction, &parent, NodeKind::Symlink).await?;
                    transaction
                        .symlink(name, target.as_bytes(), attributes, when)
                        .await
                }
                _ => {
                    let attributes = inherited(transaction, &parent, NodeKind::Directory).await?;
                    transaction.create_directory(name, attributes, when).await
                }
            }
            .map_err(fs_error)?;
        }
        Operation::Rename { destination, mode } => {
            let (source, source_name) = parent(transaction, path).await?;
            let (destination, destination_name) = parent(transaction, &destination).await?;
            transaction
                .rename(
                    Name {
                        parent: &source,
                        bytes: source_name,
                    },
                    Name {
                        parent: &destination,
                        bytes: destination_name,
                    },
                    mode,
                    when,
                )
                .await
                .map_err(fs_error)?;
        }
        Operation::Link { destination } => {
            let file = inode(transaction, path).await?;
            let (parent, bytes) = parent(transaction, &destination).await?;
            transaction
                .hard_link(
                    Name {
                        parent: &parent,
                        bytes,
                    },
                    &file,
                    when,
                )
                .await
                .map_err(fs_error)?;
        }
        Operation::Remove { directory } => {
            let file = inode(transaction, path).await?;
            let kind = transaction.metadata(&file).await.map_err(fs_error)?.kind;
            if directory && kind != FileKind::Directory {
                return Err(FsError::NotDirectory);
            }
            if !directory && kind == FileKind::Directory {
                return Err(FsError::IsDirectory);
            }
            let (parent, bytes) = parent(transaction, path).await?;
            transaction
                .unlink_name(
                    Name {
                        parent: &parent,
                        bytes,
                    },
                    when,
                )
                .await
                .map_err(fs_error)?;
        }
        Operation::Truncate { size } => {
            let file = inode(transaction, path).await?;
            transaction
                .truncate_file(&file, size, when)
                .await
                .map_err(fs_error)?;
        }
        Operation::Times { access, modified } => {
            let file = inode(transaction, path).await?;
            transaction
                .set_times(&file, access.map(timestamp), modified.map(timestamp), when)
                .await
                .map_err(fs_error)?;
        }
        Operation::Sync => {
            inode(transaction, path).await?;
        }
    }
    Ok(Response::Done)
}

pub(super) fn volume_error(error: WriteError) -> VolumeManagementError {
    match error {
        WriteError::NotSubvolume { .. } => VolumeManagementError::NotSubvolume,
        WriteError::ReadOnlySubvolume { .. } => VolumeManagementError::ReadOnlySubvolume,
        WriteError::SubvolumeNotReadOnly { .. } => VolumeManagementError::SubvolumeNotReadOnly,
        WriteError::SubvolumeNotEmpty { .. } => VolumeManagementError::SubvolumeNotEmpty,
        WriteError::DefaultSubvolume { .. } => VolumeManagementError::DefaultSubvolume,
        WriteError::QuotaNotEnabled => VolumeManagementError::QuotaNotEnabled,
        WriteError::QuotaAlreadyEnabled => VolumeManagementError::QuotaAlreadyEnabled,
        WriteError::QuotaExceeded => VolumeManagementError::QuotaExceeded,
        WriteError::QgroupNotFound { id } => VolumeManagementError::QgroupNotFound(id),
        WriteError::QgroupExists { id } => VolumeManagementError::QgroupExists(id),
        WriteError::QgroupInvalidRelation => VolumeManagementError::QgroupInvalidRelation,
        WriteError::DeviceNotFound { devid } => VolumeManagementError::DeviceNotFound(devid),
        WriteError::LastDevice => VolumeManagementError::LastDevice,
        WriteError::DeviceTooSmall { .. } => VolumeManagementError::DeviceTooSmall,
        WriteError::InvalidStream(detail) => VolumeManagementError::InvalidStream(detail),
        WriteError::CloneAlignment => VolumeManagementError::Alignment,
        WriteError::CloneOverlap => VolumeManagementError::Overlap,
        WriteError::CloneChecksumPolicy => VolumeManagementError::ChecksumPolicyMismatch,
        WriteError::CloneSourceRange => VolumeManagementError::CloneSourceOutOfRange,
        WriteError::PermissionDenied => VolumeManagementError::PermissionDenied,
        other => VolumeManagementError::Fs(fs_error(other)),
    }
}

pub(super) fn fs_error(error: WriteError) -> FsError {
    match error {
        WriteError::NoEntry { .. }
        | WriteError::StaleHandle { .. }
        | WriteError::Read(Error::NotFound { .. }) => FsError::NoEntry,
        WriteError::Exists { .. } => FsError::Exists,
        WriteError::NotEmpty { .. } => FsError::NotEmpty,
        WriteError::ReadOnlySubvolume { .. } => FsError::ReadOnly,
        WriteError::InodeFlags { .. } | WriteError::DirectoryLink => FsError::NotPermitted,
        WriteError::CrossSubvolume => FsError::CrossDevice,
        WriteError::InvalidName | WriteError::DirectoryCycle | WriteError::SymlinkTarget { .. } => {
            FsError::Invalid
        }
        WriteError::FileOverflow => FsError::Overflow,
        WriteError::NoSpace { .. }
        | WriteError::IdentifierExhausted { .. }
        | WriteError::Chunk(
            ChunkError::NoDeviceSpace { .. } | ChunkError::SystemArrayFull { .. },
        )
        | WriteError::Space(SpaceError::Exhausted { .. }) => FsError::NoSpace,
        WriteError::Read(Error::WrongKind {
            expected: FileKind::Directory,
            ..
        }) => FsError::NotDirectory,
        WriteError::Read(Error::WrongKind {
            found: FileKind::Directory,
            ..
        }) => FsError::IsDirectory,
        error => {
            tracing::warn!(%error, "btrfs transaction failed");
            FsError::Io
        }
    }
}
