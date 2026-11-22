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
    Attributes, ChunkError, InodeHandle, Name, RootUuids, SpaceError, WriteError, WriteTransaction,
    Writer,
};
use helios_btrfs::{BlockSink, Error, FileKind, Timestamp};
use helios_hal::cpu::{Cpu, Instant};
use helios_hal::fs::{
    BlockDevice, FsError, FsResult, Landed, NodeKind, OpenFlags, RenameMode, WritePosition,
};
use triomphe::Arc;

use super::super::UnixAttributes;
use super::{Image, LivePolicy, Snapshot};
use crate::component::{ProviderReceiver, ProviderSender, provider_channel};
use crate::{BlockPages, ProgressMark, ProgressSignal, RootEntropyHandle, Timer};

/// Pending inode releases enqueued by dropped [`BtrfsOpenHandle`]s.
///
/// # Concurrency contract
///
/// Any processor may push a dropped inode handle under the short `spin::Mutex`
/// (held only for `Vec::push`, never across `.await`) and raise `signal`. Only
/// [`BtrfsService`] drains the queue: on wakeup from `signal`, at the start of
/// each batch before applying new requests, and before the unmount commit.
pub(super) struct PendingReleases {
    inodes: spin::Mutex<Vec<InodeHandle>>,
    signal: ProgressSignal,
}

impl PendingReleases {
    pub(super) fn new() -> Self {
        Self {
            inodes: spin::Mutex::new(Vec::new()),
            signal: ProgressSignal::new(),
        }
    }

    pub(super) fn push(&self, inode: InodeHandle) {
        self.inodes.lock().push(inode);
        self.signal.signal();
    }

    pub(super) fn drain(&self) -> Vec<InodeHandle> {
        core::mem::take(&mut *self.inodes.lock())
    }

    pub(super) fn has_pending(&self) -> bool {
        !self.inodes.lock().is_empty()
    }

    pub(super) fn mark(&self) -> ProgressMark {
        self.signal.mark()
    }

    pub(super) async fn changed(&self, mark: ProgressMark) {
        self.signal.changed(mark).await;
    }
}

struct BtrfsOpenGuard {
    inode: InodeHandle,
    releases: SharedArc<PendingReleases>,
}

impl Drop for BtrfsOpenGuard {
    fn drop(&mut self) {
        self.releases.push(self.inode.clone());
    }
}

#[derive(Clone)]
enum BtrfsOpenInner {
    Writable(SharedArc<BtrfsOpenGuard>),
    ReadOnly { tree: u64, number: u64 },
}

/// An open inode handle on a [`super::BtrfsFs`] mount.
///
/// Clones share one underlying open registration; dropping the final clone
/// schedules an asynchronous inode release on [`BtrfsService`] so an unlinked
/// or `O_TMPFILE` inode is deleted once no handle retains it.
#[derive(Clone)]
pub struct BtrfsOpenHandle {
    inner: BtrfsOpenInner,
}

impl BtrfsOpenHandle {
    pub(super) fn writable(inode: InodeHandle, releases: SharedArc<PendingReleases>) -> Self {
        Self {
            inner: BtrfsOpenInner::Writable(SharedArc::new(BtrfsOpenGuard { inode, releases })),
        }
    }

    pub(super) fn read_only(tree: u64, number: u64) -> Self {
        Self {
            inner: BtrfsOpenInner::ReadOnly { tree, number },
        }
    }

    pub(super) fn tree(&self) -> u64 {
        match &self.inner {
            BtrfsOpenInner::Writable(guard) => guard.inode.tree(),
            BtrfsOpenInner::ReadOnly { tree, .. } => *tree,
        }
    }

    pub(super) fn number(&self) -> u64 {
        match &self.inner {
            BtrfsOpenInner::Writable(guard) => guard.inode.number(),
            BtrfsOpenInner::ReadOnly { number, .. } => *number,
        }
    }

    pub(super) fn inode_handle(&self) -> Option<&InodeHandle> {
        match &self.inner {
            BtrfsOpenInner::Writable(guard) => Some(&guard.inode),
            BtrfsOpenInner::ReadOnly { .. } => None,
        }
    }
}

pub(super) enum Response {
    Done,
    Written(Landed),
    Opened {
        handle: BtrfsOpenHandle,
        metadata: helios_btrfs::Metadata,
    },
}

pub(super) enum Target {
    Path(String),
    Inode(InodeHandle),
}

pub(super) enum Operation {
    Write {
        position: WritePosition,
        bytes: bytes::Bytes,
    },
    Open {
        flags: OpenFlags,
    },
    CreateTmpfile {
        exclusive: bool,
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
    target: Target,
    when: u64,
    operation: Operation,
    reply: oneshot::Sender<FsResult<Response>>,
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
        self.execute_target(Target::Path(String::from(path)), when, operation)
            .await
    }

    pub(super) async fn execute_inode(
        &self,
        inode: InodeHandle,
        when: u64,
        operation: Operation,
    ) -> FsResult<Response> {
        self.execute_target(Target::Inode(inode), when, operation)
            .await
    }

    async fn execute_target(
        &self,
        target: Target,
        when: u64,
        operation: Operation,
    ) -> FsResult<Response> {
        let (reply, result) = oneshot::channel();
        self.sender
            .send(Request {
                target,
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
    pub(super) published: Arc<spin::Mutex<Snapshot<Device>>>,
    pub(super) releases: SharedArc<PendingReleases>,
    pub(super) concurrency: NonZeroUsize,
    pub(super) policy: Arc<LivePolicy>,
    /// Last, so the end is reported only once everything above has gone.
    pub(super) _exit: ExitGuard,
}

/// A sync request's reply, held until a commit covers it.
type SyncWaiter = oneshot::Sender<FsResult<Response>>;

/// What woke the service.
enum Wake {
    Request(Option<Request>),
    /// The commit deadline passed, the operator changed the policy, or an open
    /// handle was dropped.
    Wakeup,
}

impl<Device: BlockDevice<Buffer = BlockPages>> BtrfsService<Device> {
    /// Serves the mount until it is unmounted, timing the commit interval
    /// on `timer`.
    pub async fn run<CpuImpl: Cpu + Clone>(mut self, timer: Timer<CpuImpl>) {
        // When the running transaction first changed: the commit interval
        // runs from here, as Linux's from the transaction's `start_time`.
        let mut dirty_since: Option<Instant> = None;
        loop {
            let release_mark = self.releases.mark();
            if self.releases.has_pending() {
                if !Box::pin(self.drain_releases()).await {
                    return;
                }
                if !self.writer.dirty().is_clean() && dirty_since.is_none() {
                    dirty_since = Some(timer.now());
                }
                continue;
            }
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
                if !Box::pin(self.commit(Vec::new(), &mut dirty_since)).await {
                    return;
                }
                continue;
            }
            if dirty.data_bytes != 0 && dirty.data_bytes >= policy.dirty_data_limit {
                if !Box::pin(self.writeback()).await {
                    return;
                }
                continue;
            }
            let wake = {
                let request = pin!(self.receiver.recv());
                let due = pin!(async {
                    match deadline {
                        Some(deadline) => timer.sleep_until(deadline).await,
                        None => pending().await,
                    }
                });
                let changed = pin!(self.policy.changed.changed(mark));
                let released = pin!(self.releases.changed(release_mark));
                match select(request, select(released, select(due, changed))).await {
                    Either::Left((request, _)) => Wake::Request(request),
                    Either::Right(_) => Wake::Wakeup,
                }
            };
            match wake {
                Wake::Wakeup => {}
                Wake::Request(None) => {
                    // Unmounted: release any dropped handles, then make what
                    // the running transaction holds durable before releasing
                    // the device.
                    if Box::pin(self.drain_releases()).await {
                        Box::pin(self.commit(Vec::new(), &mut dirty_since)).await;
                    }
                    return;
                }
                Wake::Request(Some(first)) => {
                    if !Box::pin(self.drain_releases()).await {
                        return;
                    }
                    let Some(syncs) = Box::pin(self.apply_batch(first)).await else {
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
                        && !Box::pin(self.commit(syncs, &mut dirty_since)).await
                    {
                        return;
                    }
                }
            }
        }
    }

    /// Processes all dropped [`BtrfsOpenHandle`]s queued in [`Self::releases`],
    /// publishing a fresh snapshot if any orphan inode was deleted. Returns
    /// `false` once the writer is poisoned.
    async fn drain_releases(&mut self) -> bool {
        let pending = self.releases.drain();
        if pending.is_empty() {
            return true;
        }
        let mut transaction = match self.writer.join().await {
            Ok(transaction) => transaction,
            Err(error) => {
                tracing::error!(%error, "btrfs join for inode release failed");
                return false;
            }
        };
        let mut deleted_any = false;
        for inode in pending {
            match transaction.release_inode(&inode).await {
                Ok(deleted) => deleted_any |= deleted,
                Err(error) => {
                    tracing::warn!(%error, "releasing open btrfs inode failed");
                }
            }
        }
        if deleted_any {
            *self.published.lock() = self
                .writer
                .snapshot()
                .expect("the writer joined above is not poisoned");
        }
        true
    }

    /// Applies `first` and what else is queued, up to `concurrency`
    /// requests, publishes the result and replies. Returns the syncs left
    /// waiting for a commit, or `None` once the writer is poisoned.
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
                &self.releases,
                request.target,
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
    async fn writeback(&mut self) -> bool {
        match self.writer.writeback().await {
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
    async fn commit(&mut self, syncs: Vec<SyncWaiter>, dirty_since: &mut Option<Instant>) -> bool {
        let committed = self.writer.commit().await;
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

async fn resolve_target<S: BlockSink, U: RootUuids>(
    transaction: &WriteTransaction<'_, S, U>,
    target: &Target,
) -> FsResult<InodeHandle> {
    match target {
        Target::Path(path) => inode(transaction, path).await,
        Target::Inode(handle) => Ok(handle.clone()),
    }
}

fn require_path(target: &Target) -> &str {
    match target {
        Target::Path(path) => path,
        Target::Inode(_) => unreachable!("path operation always carries Target::Path"),
    }
}

async fn apply<S: BlockSink, U: RootUuids>(
    transaction: &mut WriteTransaction<'_, S, U>,
    releases: &SharedArc<PendingReleases>,
    target: Target,
    now: u64,
    operation: Operation,
) -> FsResult<Response> {
    let when = timestamp(now);
    match operation {
        Operation::Write { position, bytes } => {
            let inode = resolve_target(transaction, &target).await?;
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
            let path = require_path(&target);
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
            transaction.open_inode(&file).await.map_err(fs_error)?;
            return Ok(Response::Opened {
                handle: BtrfsOpenHandle::writable(file, releases.clone()),
                metadata,
            });
        }
        Operation::CreateTmpfile { exclusive } => {
            let path = require_path(&target);
            let directory = inode(transaction, path).await?;
            let attributes = inherited(transaction, &directory, NodeKind::File).await?;
            let file = transaction
                .create_tmpfile(&directory, attributes, !exclusive, when)
                .await
                .map_err(fs_error)?;
            let metadata = transaction.metadata(&file).await.map_err(fs_error)?;
            return Ok(Response::Opened {
                handle: BtrfsOpenHandle::writable(file, releases.clone()),
                metadata,
            });
        }
        Operation::CreateDirectory | Operation::Symlink { .. } => {
            let path = require_path(&target);
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
            let path = require_path(&target);
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
            let file = resolve_target(transaction, &target).await?;
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
            let path = require_path(&target);
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
            let file = resolve_target(transaction, &target).await?;
            transaction
                .truncate_file(&file, size, when)
                .await
                .map_err(fs_error)?;
        }
        Operation::Times { access, modified } => {
            let file = resolve_target(transaction, &target).await?;
            transaction
                .set_times(&file, access.map(timestamp), modified.map(timestamp), when)
                .await
                .map_err(fs_error)?;
        }
        Operation::Sync => {
            let file = resolve_target(transaction, &target).await?;
            transaction.metadata(&file).await.map_err(fs_error)?;
        }
    }
    Ok(Response::Done)
}

pub(super) fn fs_error(error: WriteError) -> FsError {
    match error {
        WriteError::NoEntry { .. }
        | WriteError::StaleHandle { .. }
        | WriteError::UnlinkedInode { .. }
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
