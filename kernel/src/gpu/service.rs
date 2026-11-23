//! The typed, async-first public surface of the kernel's GPU subsystem.
//!
//! Both guest ABIs that drive the machine's 3D engine — the
//! `helios:system/gpu` WIT host and the Linux subsystem's `virtio_gpu`
//! DRM render node (#1158) — build on the handles defined here rather
//! than speaking to [`super::owner`] directly:
//!
//! * [`Gpu3dService`] is the machine-wide handle installed at bring-up.
//!   It exposes static [`Gpu3dCapabilities`] (for `VIRTGPU_GETPARAM`)
//!   and opens independent [`GpuSession`]s for authorized callers.
//! * [`GpuSession`] owns one client's renderer session (`helios:system/gpu`'s
//!   instance session or one open `/dev/dri/renderD*` file description).
//!   Dropping it marks the session ended and schedules non-blocking
//!   teardown in drain → blobs → contexts order. [`GpuClient`] is its
//!   cloneable async handle for callers (such as Wasmtime's `Accessor`)
//!   that cannot hold a borrow of their store across `.await`.
//! * [`GpuContext`] is a refcounted handle to one renderer context and
//!   its fence rings. Dropping the last clone schedules `CTX_DESTROY`
//!   once in-flight submissions on that context settle.
//! * [`GpuBlob`] is a refcounted handle to one blob resource (shared
//!   across GEM handles and PRIME `dma-buf` descriptors in Linux DRM, or
//!   held by one WIT `blob` resource). Dropping the last clone schedules
//!   unmap and destruction once any [`GpuImage`] / scanout [`BlobHold`]
//!   has released it. [`BlobMapping`] owns its placement in the
//!   host-visible aperture and unmaps on `unmap().await` or `Drop`.
//!
//! # Concurrency contract
//!
//! Every public type here is `Send + Sync` and free of locks held across
//! `.await`. Control operations (`capsets`, `capset`, `create_context`,
//! `create_blob`, `map`, `unmap`, `attach`, `detach`) travel over the
//! bounded control queue to [`super::owner::serve_control`]. Command
//! submissions admit their ring fence under the ring's async gate in the
//! same non-blocking step that pushes to the bounded submit queue, and
//! release that gate before awaiting queue room or the device's `posted`
//! acknowledgement, so every ring's submissions reach the device in
//! monotone fence order even when multiple threads submit concurrently.
//! Every `Drop` (`GpuSession`, `GpuContext`, `GpuBlob`, `BlobMapping`,
//! `BlobHold`) is O(1) and lock-free: an atomic state transition plus
//! one permit on the control server's `release` [`Notify`].

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::future::poll_fn;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use core::task::{Context, Poll};

use arrayvec::ArrayVec;
use futures::channel::oneshot;
use helios_hal::device::DeviceRegion;
use helios_hal::display::{
    BlobId, BlobMemory, BlobUsage, CapsetId, CapsetList, ContextId, ContextName, DisplayMode,
    FenceId, Gpu3dCapabilities, PixelFormat, RingCount, RingIndex,
};
use helios_hal::iommu::PhysicalRange;
use triomphe::Arc;

use crate::buffer::Buffer;
use crate::component::{ProviderError, ProviderSender};
use crate::exec::{Mutex, Notify, NotifyWaiter, SequenceSignal, SignalTimeline, TimelineSource};
use crate::process::GpuOpenCap;

use super::{Gpu3dServiceError, GpuImage, MAX_EXECUTE_BYTES};

/// Requests the machine's sessions may have waiting on each queue
/// before the next one waits for room.
///
/// The same bound the display path sets, for the same reason: a client
/// that has queued this many submissions is one the renderer has not
/// kept up with, and making it wait is the backpressure a command path
/// needs.
pub const REQUEST_QUEUE_DEPTH: usize = crate::display::REQUEST_QUEUE_DEPTH;

/// Which session a request was made under.
///
/// Counted up from one and never reused, so a handle that outlived its
/// session can never name a later one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionId(u64);

impl SessionId {
    pub const fn raw(self) -> u64 {
        self.0
    }
}

/// What the owner tasks and a session's handles share about one session.
pub(super) struct SessionState {
    pub(super) id: SessionId,
    /// Set once, when [`GpuSession`] is dropped. A request read after it
    /// is set is dropped unanswered.
    pub(super) ended: AtomicBool,
    /// Broadcast to operations waiting on a session that has ended.
    ended_notify: Notify,
    /// Submissions of this session the submit server has popped and the
    /// device has not finished with.
    pub(super) submits_in_flight: AtomicU64,
    /// The control server's wake-up. A drain to zero of an ended
    /// session banks one permit on it, so the pending release resumes.
    pub(super) release: Arc<Notify>,
}

impl SessionState {
    pub(super) fn has_ended(&self) -> bool {
        self.ended.load(Ordering::Acquire)
    }

    /// Whether the device still holds a submission of this session.
    pub(super) fn is_draining(&self) -> bool {
        self.submits_in_flight.load(Ordering::Acquire) != 0
    }
}

/// What the owner task, [`GpuBlob`], [`BlobMapping`] and every scanout
/// share about one blob.
pub(crate) struct BlobShared {
    id: BlobId,
    size: u64,
    memory: BlobMemory,
    usage: BlobUsage,
    /// Image capabilities and scanouts retaining the blob right now.
    holds: AtomicU64,
    /// Set once the last [`GpuBlob`] handle has dropped.
    dropped: AtomicBool,
    /// Set when a [`BlobMapping`] dropped without an awaited `unmap`.
    unmap_pending: AtomicBool,
    /// The control server's wake-up, banked on handle drop, mapping drop
    /// and last scanout release.
    release: Arc<Notify>,
}

impl BlobShared {
    pub(crate) fn new(
        id: BlobId,
        size: u64,
        memory: BlobMemory,
        usage: BlobUsage,
        release: Arc<Notify>,
    ) -> Self {
        Self {
            id,
            size,
            memory,
            usage,
            holds: AtomicU64::new(0),
            dropped: AtomicBool::new(false),
            unmap_pending: AtomicBool::new(false),
            release,
        }
    }

    /// The virtio resource id the device knows the blob by.
    pub(crate) const fn id(&self) -> BlobId {
        self.id
    }

    /// The immutable byte length requested when the blob was created.
    pub(crate) const fn size(&self) -> u64 {
        self.size
    }

    /// Whether an image capability or scanout retains the blob.
    pub(crate) fn is_retained(&self) -> bool {
        self.holds.load(Ordering::Acquire) != 0
    }

    /// Whether every [`GpuBlob`] handle to this resource has dropped.
    pub(super) fn is_dropped(&self) -> bool {
        self.dropped.load(Ordering::Acquire)
    }

    /// Consume a pending asynchronous unmap scheduled by [`BlobMapping::drop`].
    pub(super) fn take_unmap_pending(&self) -> bool {
        self.unmap_pending.swap(false, Ordering::AcqRel)
    }

    #[cfg(test)]
    pub(crate) fn for_test(id: BlobId, size: u64, release: Arc<Notify>) -> Self {
        Self::new(id, size, BlobMemory::Host3d, BlobUsage::SHAREABLE, release)
    }
}

/// Refcounted handle ownership of one blob's lifetime on the device.
struct BlobLease {
    shared: Arc<BlobShared>,
}

impl Drop for BlobLease {
    fn drop(&mut self) {
        self.shared.dropped.store(true, Ordering::Release);
        self.shared.release.notify_one();
    }
}

/// An owned hold on a blob. Device destruction waits for every image
/// capability and scanout to release its hold.
pub struct BlobHold {
    blob: Arc<BlobShared>,
}

impl BlobHold {
    /// Retain the blob for a consumer independently of its creating handle.
    pub(crate) fn new(blob: &Arc<BlobShared>) -> Self {
        blob.holds.fetch_add(1, Ordering::AcqRel);
        Self { blob: blob.clone() }
    }

    /// The blob held.
    pub fn blob(&self) -> BlobId {
        self.blob.id
    }
}

impl Clone for BlobHold {
    fn clone(&self) -> Self {
        Self::new(&self.blob)
    }
}

impl Drop for BlobHold {
    fn drop(&mut self) {
        if self.blob.holds.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.blob.release.notify_one();
        }
    }
}

/// One blob resource on the 3D engine.
///
/// Cloning shares ownership of the underlying device resource (for
/// example across a Linux DRM GEM handle and an exported PRIME `dma-buf`
/// descriptor); dropping the last clone schedules unmap and destruction
/// on the owner task once any [`GpuImage`] or scanout [`BlobHold`] has
/// released it.
#[derive(Clone)]
pub struct GpuBlob {
    service: Arc<Gpu3dShared>,
    session: Arc<SessionState>,
    lease: Arc<BlobLease>,
}

impl GpuBlob {
    pub(super) fn new(
        service: Arc<Gpu3dShared>,
        session: Arc<SessionState>,
        shared: Arc<BlobShared>,
    ) -> Self {
        Self {
            service,
            session,
            lease: Arc::new(BlobLease { shared }),
        }
    }

    /// The virtio resource id (`res_handle` in `virtio_gpu`).
    pub fn id(&self) -> BlobId {
        self.lease.shared.id
    }

    /// The session this blob belongs to.
    pub fn session(&self) -> SessionId {
        self.session.id
    }

    /// Byte length requested at blob creation (`RESOURCE_INFO.size`).
    pub fn size(&self) -> u64 {
        self.lease.shared.size
    }

    /// Backing storage class (`RESOURCE_INFO.blob_mem`).
    pub fn memory(&self) -> BlobMemory {
        self.lease.shared.memory
    }

    /// Usage flags established at creation (`MAPPABLE`, `SHAREABLE`, `CROSS_DEVICE`).
    pub fn usage(&self) -> BlobUsage {
        self.lease.shared.usage
    }

    /// Whether an exported [`GpuImage`] or active scanout currently retains the blob.
    pub fn is_retained(&self) -> bool {
        self.lease.shared.is_retained()
    }

    /// Export an immutable scanout [`GpuImage`] capability over this blob.
    ///
    /// Refused with [`Gpu3dServiceError::SessionEnded`] once the creating
    /// session has ended, and [`Gpu3dServiceError::InvalidBlob`] if the
    /// layout does not fit inside [`Self::size`].
    pub fn image(
        &self,
        mode: DisplayMode,
        format: PixelFormat,
        offset: u32,
        stride: u32,
    ) -> Result<GpuImage, Gpu3dServiceError> {
        if self.session.has_ended() {
            return Err(Gpu3dServiceError::SessionEnded);
        }
        GpuImage::new(&self.lease.shared, mode, format, offset, stride)
    }

    /// Place the blob's host storage in the engine's host-visible aperture.
    ///
    /// Returns a [`BlobMapping`] carrying the [`DeviceRegion`] and its
    /// host-requested caching attributes. Dropping the [`BlobMapping`]
    /// without calling [`BlobMapping::unmap`] schedules an asynchronous
    /// aperture unmap on the owner task.
    pub async fn map(&self) -> Result<BlobMapping, Gpu3dServiceError> {
        if self.session.has_ended() {
            return Err(Gpu3dServiceError::SessionEnded);
        }
        let (reply, answer) = oneshot::channel();
        control_call(
            &self.service,
            &self.session,
            Gpu3dRequest::MapBlob {
                blob: self.id(),
                reply,
            },
            answer,
        )
        .await
    }
}

/// One active placement of a [`GpuBlob`] in the host-visible aperture.
///
/// Callers remove the region from any guest address space before calling
/// [`Self::unmap`] or dropping this guard.
pub struct BlobMapping {
    region: DeviceRegion,
    service: Arc<Gpu3dShared>,
    session: Arc<SessionState>,
    blob: Arc<BlobShared>,
    armed: bool,
}

impl BlobMapping {
    pub(super) fn new(
        region: DeviceRegion,
        service: Arc<Gpu3dShared>,
        session: Arc<SessionState>,
        blob: Arc<BlobShared>,
    ) -> Self {
        Self {
            region,
            service,
            session,
            blob,
            armed: true,
        }
    }

    /// Physical aperture region and caching attributes reported by the device.
    pub const fn region(&self) -> DeviceRegion {
        self.region
    }

    /// Take the blob out of the aperture and await the device's acknowledgement.
    pub async fn unmap(mut self) -> Result<(), Gpu3dServiceError> {
        if self.session.has_ended() {
            self.armed = false;
            return Err(Gpu3dServiceError::SessionEnded);
        }
        let (reply, answer) = oneshot::channel();
        self.service
            .control
            .send(ControlMessage {
                session: self.session.clone(),
                request: Gpu3dRequest::UnmapBlob {
                    blob: self.blob.id,
                    reply,
                },
            })
            .await
            .map_err(closed)?;
        self.armed = false;
        answer.await.unwrap_or(Err(Gpu3dServiceError::SessionEnded))
    }
}

impl Drop for BlobMapping {
    fn drop(&mut self) {
        if self.armed {
            self.blob.unmap_pending.store(true, Ordering::Release);
            self.blob.release.notify_one();
        }
    }
}

/// One ring of one context: the fences admitted onto it, and the fences
/// the device has retired on it.
pub(crate) struct RingTimeline {
    fences: SequenceSignal,
    submitted: AtomicU64,
    /// Serialises fence check + submit-queue push on this ring so concurrent
    /// callers enqueue in strictly monotone fence order; never held across
    /// queue-room or reply waits.
    admit_gate: Mutex<()>,
}

impl RingTimeline {
    fn new() -> Self {
        Self {
            fences: SequenceSignal::new(),
            submitted: AtomicU64::new(0),
            admit_gate: Mutex::new(()),
        }
    }

    /// Every fence retired on this ring, published as its raw value.
    pub(crate) fn signal(&self) -> &SequenceSignal {
        &self.fences
    }

    /// The newest fence admitted onto this ring.
    pub(crate) fn submitted(&self) -> u64 {
        self.submitted.load(Ordering::Acquire)
    }

    /// Whether `fence` comes after every fence already admitted onto the ring.
    pub(crate) fn admits(&self, fence: FenceId) -> bool {
        fence.raw() > self.submitted()
    }

    /// Record that `fence` is on its way to the device.
    pub(crate) fn record_submitted(&self, fence: FenceId) {
        self.submitted.store(fence.raw(), Ordering::Release);
    }

    /// Retire `fence` on this ring, if it comes after what has already
    /// been retired.
    pub(super) fn retire(&self, fence: u64, nanos: u64) {
        if fence > self.fences.sequence() {
            self.fences.publish(fence, nanos);
        }
    }
}

/// Shared state of one renderer context across [`GpuContext`],
/// [`GpuFenceReader`] and the owner tasks.
pub(crate) struct ContextShared {
    id: ContextId,
    capset: CapsetId,
    rings: RingCount,
    timelines: Box<[RingTimeline]>,
    faulted: AtomicBool,
    dropped: AtomicBool,
    pub(super) submits_in_flight: AtomicU64,
    pub(super) release: Arc<Notify>,
}

impl ContextShared {
    pub(super) fn new(
        id: ContextId,
        capset: CapsetId,
        rings: RingCount,
        release: Arc<Notify>,
    ) -> Self {
        Self {
            id,
            capset,
            rings,
            timelines: rings.rings().map(|_| RingTimeline::new()).collect(),
            faulted: AtomicBool::new(false),
            dropped: AtomicBool::new(false),
            submits_in_flight: AtomicU64::new(0),
            release,
        }
    }

    pub(crate) const fn id(&self) -> ContextId {
        self.id
    }

    pub(crate) const fn capset(&self) -> CapsetId {
        self.capset
    }

    pub(crate) const fn rings(&self) -> RingCount {
        self.rings
    }

    pub(crate) fn timeline(&self, ring: RingIndex) -> Option<&RingTimeline> {
        self.timelines.get(ring.index())
    }

    pub(crate) fn is_faulted(&self) -> bool {
        self.faulted.load(Ordering::Acquire)
    }

    pub(super) fn is_dropped(&self) -> bool {
        self.dropped.load(Ordering::Acquire)
    }

    pub(super) fn is_draining(&self) -> bool {
        self.submits_in_flight.load(Ordering::Acquire) != 0
    }

    /// Fault the context and retire every ring up to the newest fence
    /// admitted onto it.
    pub(super) fn fault(&self, nanos: u64) {
        self.faulted.store(true, Ordering::Release);
        for timeline in &*self.timelines {
            timeline.retire(timeline.submitted(), nanos);
        }
    }
}

/// Refcounted handle ownership of one context's lifetime on the device.
struct ContextLease {
    shared: Arc<ContextShared>,
}

impl Drop for ContextLease {
    fn drop(&mut self) {
        self.shared.dropped.store(true, Ordering::Release);
        self.shared.release.notify_one();
    }
}

/// One renderer context and its fence rings.
///
/// Cloning shares ownership of the context; dropping the last clone
/// schedules `CTX_DESTROY` on the owner task once any in-flight
/// submissions on this context have settled.
#[derive(Clone)]
pub struct GpuContext {
    service: Arc<Gpu3dShared>,
    session: Arc<SessionState>,
    lease: Arc<ContextLease>,
}

impl GpuContext {
    pub(super) fn new(
        service: Arc<Gpu3dShared>,
        session: Arc<SessionState>,
        shared: Arc<ContextShared>,
    ) -> Self {
        Self {
            service,
            session,
            lease: Arc::new(ContextLease { shared }),
        }
    }

    /// The device-side context identifier.
    pub fn id(&self) -> ContextId {
        self.lease.shared.id()
    }

    /// The session this context belongs to.
    pub fn session(&self) -> SessionId {
        self.session.id
    }

    /// The capability set this context speaks.
    pub fn capset(&self) -> CapsetId {
        self.lease.shared.capset()
    }

    /// Number of fence rings on this context.
    pub fn rings(&self) -> RingCount {
        self.lease.shared.rings()
    }

    /// Whether the device has faulted this context.
    pub fn is_faulted(&self) -> bool {
        self.lease.shared.is_faulted()
    }

    #[cfg(test)]
    pub(crate) fn shared(&self) -> &Arc<ContextShared> {
        &self.lease.shared
    }

    /// Admit and enqueue a command stream on `ring`, resolving once the
    /// command is on the device's queue.
    ///
    /// Fence admission and channel insertion run together under the
    /// ring's gate and release it before awaiting queue room or the
    /// device's `posted` acknowledgement, so every ring's submissions
    /// enter the bounded submit queue in strictly monotone fence order.
    pub async fn submit(
        &self,
        ring: u8,
        mut commands: SubmitCommands,
        mut completion: Option<SubmitCompletion>,
    ) -> Result<(), Gpu3dServiceError> {
        let shared = &self.lease.shared;
        let Some((ring_index, timeline)) = RingIndex::new(ring)
            .and_then(|index| shared.timeline(index).map(|timeline| (index, timeline)))
        else {
            if shared.is_faulted() {
                return Err(Gpu3dServiceError::DeviceFault);
            }
            if self.session.has_ended() {
                return Err(Gpu3dServiceError::SessionEnded);
            }
            return Err(Gpu3dServiceError::BadRing);
        };

        let answer = loop {
            let gate = timeline.admit_gate.lock().await;
            if self.session.has_ended() {
                return Err(Gpu3dServiceError::SessionEnded);
            }
            if shared.is_faulted() {
                return Err(Gpu3dServiceError::DeviceFault);
            }
            let fence = completion.as_ref().map(|item| item.fence);
            if let Some(fence) = fence
                && !timeline.admits(fence)
            {
                return Err(Gpu3dServiceError::StaleFence);
            }
            let (reply, answer) = oneshot::channel();
            let message = SubmitMessage {
                session: self.session.clone(),
                request: SubmitRequest {
                    context: shared.clone(),
                    commands,
                    ring: ring_index,
                    completion,
                    reply,
                },
            };
            match self.service.submit.try_push(message) {
                Ok(()) => {
                    if let Some(fence) = fence {
                        timeline.record_submitted(fence);
                    }
                    drop(gate);
                    break answer;
                }
                Err((ProviderError::Full, returned)) => {
                    commands = returned.request.commands;
                    completion = returned.request.completion;
                    drop(gate);
                    self.service.submit.room().await;
                }
                Err((error, _)) => return Err(closed(error)),
            }
        };

        answer.await.unwrap_or(Err(Gpu3dServiceError::SessionEnded))
    }

    /// Wait for an admitted `fence` on `ring` to retire, including one
    /// that retired before this call.
    pub async fn wait(&self, ring: u8, fence: u64) -> Result<(), Gpu3dServiceError> {
        let shared = &self.lease.shared;
        if self.session.has_ended() {
            return Err(Gpu3dServiceError::SessionEnded);
        }
        let timeline = RingIndex::new(ring)
            .and_then(|index| shared.timeline(index))
            .ok_or(Gpu3dServiceError::BadRing)?;
        if fence > timeline.submitted() {
            return Err(Gpu3dServiceError::UnsubmittedFence);
        }
        let signal = timeline.signal();
        let mut retired = signal.waiter();
        let mut ended = self.session.ended_notify.waiter();
        let mut last_seen = 0;
        poll_fn(|cx| {
            let _ = self.session.ended_notify.poll_notified(cx, &mut ended);
            loop {
                if self.session.has_ended() {
                    return Poll::Ready(Err(Gpu3dServiceError::SessionEnded));
                }
                // Acquire retirement before checking fault: a failed
                // submission publishes its fault before retiring fences.
                let reached = signal.sequence() >= fence;
                if shared.is_faulted() {
                    return Poll::Ready(Err(Gpu3dServiceError::DeviceFault));
                }
                if reached {
                    return Poll::Ready(Ok(()));
                }
                if signal
                    .poll_next(cx, &mut retired, &mut last_seen)
                    .is_pending()
                {
                    return Poll::Pending;
                }
            }
        })
        .await
    }

    /// Open a monotone stream reader of fences retiring on `ring` after
    /// this moment.
    pub fn fences(&self, ring: u8) -> Result<GpuFenceReader, Gpu3dServiceError> {
        if self.session.has_ended() {
            return Err(Gpu3dServiceError::SessionEnded);
        }
        let shared = &self.lease.shared;
        let Some(ring) = RingIndex::new(ring).filter(|index| shared.rings().contains(*index))
        else {
            return Err(Gpu3dServiceError::BadRing);
        };
        let last_seen = shared
            .timeline(ring)
            .expect("the ring was checked against the context's count")
            .signal()
            .sequence();
        Ok(GpuFenceReader {
            context: shared.clone(),
            ring,
            waiter: None,
            last_seen,
        })
    }

    /// Make `blob` reachable from this context's command stream.
    pub async fn attach(&self, blob: &GpuBlob) -> Result<(), Gpu3dServiceError> {
        self.change_attachment(blob, true).await
    }

    /// Remove `blob` from this context's command stream.
    pub async fn detach(&self, blob: &GpuBlob) -> Result<(), Gpu3dServiceError> {
        self.change_attachment(blob, false).await
    }

    async fn change_attachment(
        &self,
        blob: &GpuBlob,
        attach: bool,
    ) -> Result<(), Gpu3dServiceError> {
        if self.is_faulted() {
            return Err(Gpu3dServiceError::DeviceFault);
        }
        if self.session.has_ended() {
            return Err(Gpu3dServiceError::SessionEnded);
        }
        if blob.session() != self.session() {
            return Err(Gpu3dServiceError::InvalidBlob);
        }
        let (reply, answer) = oneshot::channel();
        let request = if attach {
            Gpu3dRequest::AttachResource {
                context: self.id(),
                blob: blob.id(),
                reply,
            }
        } else {
            Gpu3dRequest::DetachResource {
                context: self.id(),
                blob: blob.id(),
                reply,
            }
        };
        control_call(&self.service, &self.session, request, answer).await
    }
}

/// Monotone reader of fences retiring on one ring of a [`GpuContext`].
pub struct GpuFenceReader {
    context: Arc<ContextShared>,
    ring: RingIndex,
    waiter: Option<NotifyWaiter>,
    last_seen: u64,
}

impl Unpin for GpuFenceReader {}

impl GpuFenceReader {
    /// Poll for the newest fence retired past the last one observed.
    pub fn poll_next(&mut self, cx: &mut Context<'_>) -> Poll<u64> {
        let signal = self
            .context
            .timeline(self.ring)
            .expect("the reader was opened on one of the context's rings")
            .signal();
        let waiter = self.waiter.get_or_insert_with(|| signal.waiter());
        match signal.poll_next(cx, waiter, &mut self.last_seen) {
            Poll::Ready((fence, _nanos)) => Poll::Ready(fence),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Parameters describing a blob resource to create via [`GpuSession::create_blob`]
/// or [`GpuClient::create_blob`].
pub struct BlobCreate {
    /// Where the blob's storage lives.
    pub memory: BlobMemory,
    /// Intended operations (`MAPPABLE`, `SHAREABLE`, `CROSS_DEVICE`).
    pub usage: BlobUsage,
    /// Size in bytes.
    pub size: u64,
    /// Renderer-assigned `blob_id` (`0` for guest blobs and host shmem).
    pub blob_id: u64,
    /// Pinned guest buffer for [`BlobMemory::Guest`] and [`BlobMemory::Host3dGuest`].
    pub backing: Option<Buffer>,
}

/// Work for the task that owns what the renderer holds.
pub(super) enum Gpu3dRequest {
    Capsets {
        reply: oneshot::Sender<Result<CapsetList, Gpu3dServiceError>>,
    },
    Capset {
        id: CapsetId,
        version: u32,
        reply: oneshot::Sender<Result<Vec<u8>, Gpu3dServiceError>>,
    },
    CreateContext {
        capset: CapsetId,
        rings: RingCount,
        name: ContextName,
        reply: oneshot::Sender<Result<GpuContext, Gpu3dServiceError>>,
    },
    CreateBlob {
        context: ContextId,
        params: BlobCreate,
        reply: oneshot::Sender<Result<GpuBlob, Gpu3dServiceError>>,
    },
    MapBlob {
        blob: BlobId,
        reply: oneshot::Sender<Result<BlobMapping, Gpu3dServiceError>>,
    },
    UnmapBlob {
        blob: BlobId,
        reply: oneshot::Sender<Result<(), Gpu3dServiceError>>,
    },
    AttachResource {
        context: ContextId,
        blob: BlobId,
        reply: oneshot::Sender<Result<(), Gpu3dServiceError>>,
    },
    DetachResource {
        context: ContextId,
        blob: BlobId,
        reply: oneshot::Sender<Result<(), Gpu3dServiceError>>,
    },
}

/// An inline command stream, carried in the request itself.
pub type InlineCommands = ArrayVec<u8, MAX_EXECUTE_BYTES>;

/// Where a submission's command stream is.
#[derive(Clone)]
#[expect(
    clippy::large_enum_variant,
    reason = "the inline stream is carried by value so a short execbuffer costs no allocation; \
              the submit queue is bounded, so the size it adds per slot is a fixed cost"
)]
pub enum SubmitCommands {
    /// A run of a command buffer the caller pinned.
    Pages {
        /// Held until the device has answered so its pages cannot return
        /// to the pool while the device may still read them.
        buffer: Buffer,
        /// The physical run inside `buffer` the device reads.
        range: PhysicalRange,
    },
    /// A short stream carried inline by value.
    Inline(InlineCommands),
}

/// A timeline producer signalled when a submitted fence retires.
#[derive(Clone)]
pub struct CompletionSignal {
    pub source: TimelineSource,
    pub value: u64,
}

/// Fence and optional [`TimelineSource`] completions attached to one submission.
#[derive(Clone)]
pub struct SubmitCompletion {
    pub fence: FenceId,
    pub signals: Vec<CompletionSignal>,
}

impl SubmitCompletion {
    pub(super) fn fail(&self) {
        for signal in &self.signals {
            signal.source.fail();
        }
    }

    pub(super) fn signal(&self) {
        for signal in &self.signals {
            // Another producer may already have failed this timeline.
            // Failure remains terminal; completion cannot revive it.
            let _ = signal.source.signal(signal.value);
        }
    }
}

/// Work for the task that posts the command streams.
pub(super) struct SubmitRequest {
    pub(super) context: Arc<ContextShared>,
    pub(super) commands: SubmitCommands,
    pub(super) ring: RingIndex,
    pub(super) completion: Option<SubmitCompletion>,
    pub(super) reply: oneshot::Sender<Result<(), Gpu3dServiceError>>,
}

/// A request on the control queue and the session it was made under.
pub(super) struct ControlMessage {
    pub(super) session: Arc<SessionState>,
    pub(super) request: Gpu3dRequest,
}

/// A request on the submit queue and the session it was made under.
pub(super) struct SubmitMessage {
    pub(super) session: Arc<SessionState>,
    pub(super) request: SubmitRequest,
}

/// What every session shares with the tasks that own the engine.
pub(super) struct Gpu3dShared {
    pub(super) control: ProviderSender<ControlMessage>,
    pub(super) submit: ProviderSender<SubmitMessage>,
    /// The control server's wake-up for pending releases.
    pub(super) release: Arc<Notify>,
    /// The last session id handed out.
    pub(super) sessions: AtomicU64,
    /// Static hardware capabilities read at bring-up.
    pub(super) capabilities: Gpu3dCapabilities,
}

/// One submission the submit server has popped and the device has not
/// finished with.
pub(super) struct InFlightSubmit {
    session: Arc<SessionState>,
    context: Arc<ContextShared>,
}

impl InFlightSubmit {
    pub(super) fn begin(session: Arc<SessionState>, context: Arc<ContextShared>) -> Self {
        session.submits_in_flight.fetch_add(1, Ordering::AcqRel);
        context.submits_in_flight.fetch_add(1, Ordering::AcqRel);
        Self { session, context }
    }
}

impl Drop for InFlightSubmit {
    fn drop(&mut self) {
        let session_drained = self
            .session
            .submits_in_flight
            .fetch_sub(1, Ordering::AcqRel)
            == 1
            && self.session.has_ended();
        let context_drained = self
            .context
            .submits_in_flight
            .fetch_sub(1, Ordering::AcqRel)
            == 1
            && self.context.is_dropped();
        if session_drained || context_drained {
            self.session.release.notify_one();
        }
    }
}

/// The machine's 3D engine, as everything outside the owner tasks sees it.
#[derive(Clone)]
pub struct Gpu3dService {
    shared: Arc<Gpu3dShared>,
}

impl Gpu3dService {
    pub(super) const fn from_shared(shared: Arc<Gpu3dShared>) -> Self {
        Self { shared }
    }

    /// Static hardware capabilities of the machine's 3D engine.
    pub fn capabilities(&self) -> Gpu3dCapabilities {
        self.shared.capabilities
    }

    /// Whether this machine's display engine renders at all.
    pub fn renders(&self) -> bool {
        self.shared.capabilities.renders
    }

    /// Open a session on the machine's 3D engine.
    ///
    /// Refused only when the device renders nothing. `_cap` is the proof
    /// that the caller's authority names the GPU class.
    pub fn open(&self, _cap: GpuOpenCap) -> Result<GpuSession, Gpu3dServiceError> {
        if !self.renders() {
            return Err(Gpu3dServiceError::NoRenderer);
        }
        let id = SessionId(self.shared.sessions.fetch_add(1, Ordering::Relaxed) + 1);
        Ok(GpuSession {
            shared: self.shared.clone(),
            state: Arc::new(SessionState {
                id,
                ended: AtomicBool::new(false),
                ended_notify: Notify::new(),
                submits_in_flight: AtomicU64::new(0),
                release: self.shared.release.clone(),
            }),
        })
    }
}

/// One client's session on the machine's 3D engine.
///
/// Dropping it marks the session ended, wakes every waiter on it, and
/// schedules teardown of every context, blob and aperture placement the
/// session created.
pub struct GpuSession {
    shared: Arc<Gpu3dShared>,
    state: Arc<SessionState>,
}

impl GpuSession {
    pub fn id(&self) -> SessionId {
        self.state.id
    }

    #[cfg(test)]
    pub(super) fn state(&self) -> &Arc<SessionState> {
        &self.state
    }

    /// Static hardware capabilities of the underlying engine.
    pub fn capabilities(&self) -> Gpu3dCapabilities {
        self.shared.capabilities
    }

    /// Cloneable async handle to this session for callers that release
    /// their borrow of `GpuSession` before awaiting.
    pub fn client(&self) -> GpuClient {
        GpuClient {
            shared: self.shared.clone(),
            state: self.state.clone(),
        }
    }

    /// Every capability set the device carries, in its own order.
    pub async fn capsets(&self) -> Result<CapsetList, Gpu3dServiceError> {
        self.client().capsets().await
    }

    /// Read the raw bytes of capability set `id` at `version`.
    pub async fn capset(&self, id: CapsetId, version: u32) -> Result<Vec<u8>, Gpu3dServiceError> {
        self.client().capset(id, version).await
    }

    /// Open a renderer context speaking `capset` with `rings` timelines.
    pub async fn create_context(
        &self,
        capset: CapsetId,
        rings: RingCount,
        name: ContextName,
    ) -> Result<GpuContext, Gpu3dServiceError> {
        self.client().create_context(capset, rings, name).await
    }

    /// Create a blob resource owned by `context` in this session.
    pub async fn create_blob(
        &self,
        context: &GpuContext,
        params: BlobCreate,
    ) -> Result<GpuBlob, Gpu3dServiceError> {
        self.client().create_blob(context, params).await
    }
}

impl Drop for GpuSession {
    fn drop(&mut self) {
        self.state.ended.store(true, Ordering::Release);
        self.state.ended_notify.notify_all();
        self.shared.release.notify_one();
    }
}

/// Cloneable handle to one [`GpuSession`] for async operations.
///
/// Operations on a `GpuClient` whose [`GpuSession`] has been dropped
/// fail with [`Gpu3dServiceError::SessionEnded`].
#[derive(Clone)]
pub struct GpuClient {
    shared: Arc<Gpu3dShared>,
    state: Arc<SessionState>,
}

impl GpuClient {
    pub fn session(&self) -> SessionId {
        self.state.id
    }

    /// Whether the underlying [`GpuSession`] is still open.
    pub fn is_open(&self) -> bool {
        !self.state.has_ended()
    }

    /// Static hardware capabilities of the underlying engine.
    pub fn capabilities(&self) -> Gpu3dCapabilities {
        self.shared.capabilities
    }

    /// Every capability set the device carries, in its own order.
    pub async fn capsets(&self) -> Result<CapsetList, Gpu3dServiceError> {
        if self.state.has_ended() {
            return Err(Gpu3dServiceError::SessionEnded);
        }
        let (reply, answer) = oneshot::channel();
        control_call(
            &self.shared,
            &self.state,
            Gpu3dRequest::Capsets { reply },
            answer,
        )
        .await
    }

    /// Read the raw bytes of capability set `id` at `version`.
    pub async fn capset(&self, id: CapsetId, version: u32) -> Result<Vec<u8>, Gpu3dServiceError> {
        if self.state.has_ended() {
            return Err(Gpu3dServiceError::SessionEnded);
        }
        let (reply, answer) = oneshot::channel();
        control_call(
            &self.shared,
            &self.state,
            Gpu3dRequest::Capset { id, version, reply },
            answer,
        )
        .await
    }

    /// Open a renderer context speaking `capset` with `rings` timelines.
    pub async fn create_context(
        &self,
        capset: CapsetId,
        rings: RingCount,
        name: ContextName,
    ) -> Result<GpuContext, Gpu3dServiceError> {
        if self.state.has_ended() {
            return Err(Gpu3dServiceError::SessionEnded);
        }
        let (reply, answer) = oneshot::channel();
        control_call(
            &self.shared,
            &self.state,
            Gpu3dRequest::CreateContext {
                capset,
                rings,
                name,
                reply,
            },
            answer,
        )
        .await
    }

    /// Create a blob resource owned by `context` in this session.
    pub async fn create_blob(
        &self,
        context: &GpuContext,
        params: BlobCreate,
    ) -> Result<GpuBlob, Gpu3dServiceError> {
        if self.state.has_ended() {
            return Err(Gpu3dServiceError::SessionEnded);
        }
        if context.session() != self.session() {
            return Err(Gpu3dServiceError::InvalidBlob);
        }
        if let Some(alignment) = self.shared.capabilities.blob_alignment
            && !params.size.is_multiple_of(u64::from(alignment.get()))
        {
            return Err(Gpu3dServiceError::InvalidBlob);
        }
        let (reply, answer) = oneshot::channel();
        control_call(
            &self.shared,
            &self.state,
            Gpu3dRequest::CreateBlob {
                context: context.id(),
                params,
                reply,
            },
            answer,
        )
        .await
    }
}

async fn control_call<T>(
    service: &Gpu3dShared,
    session: &Arc<SessionState>,
    request: Gpu3dRequest,
    reply: oneshot::Receiver<Result<T, Gpu3dServiceError>>,
) -> Result<T, Gpu3dServiceError> {
    service
        .control
        .send(ControlMessage {
            session: session.clone(),
            request,
        })
        .await
        .map_err(closed)?;
    reply.await.unwrap_or(Err(Gpu3dServiceError::SessionEnded))
}

const fn closed(error: ProviderError) -> Gpu3dServiceError {
    match error {
        ProviderError::Unavailable | ProviderError::Closed | ProviderError::Full => {
            Gpu3dServiceError::Closed
        }
    }
}
