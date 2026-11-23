//! The kernel's ownership of the display engine's rendering half.
//!
//! The renderer needs no follower task of its own: nothing about it
//! changes without being asked — a monitor announces itself, a fence
//! does not — because a fence is only ever the completion of a command
//! the submit server posted, and that server is already running when it
//! retires. What the engine does need owned is the record of what every
//! session has to give back: the contexts it opened, the blobs it
//! created, and which of those sit in the aperture.
//!
//! # SMP contract
//!
//! Two tasks, both local to the processor that brought the device up,
//! which is the processor the device's interrupt is routed to.
//!
//! * The control server owns everything that changes what the renderer
//!   holds, for every session: capability-set reads, contexts, blobs,
//!   aperture placements and attachments. It serves one request at a
//!   time, so the record of what each session made is never in two
//!   minds about what exists.
//! * The submit server owns the command streams. It is a separate task
//!   for the reason the queues are separate: a submission must not wait
//!   behind a capset read of tens of kilobytes. It posts one command at
//!   a time — the next is popped only once the last is on the device's
//!   ring — so the device sees every ring's commands in the order their
//!   fences were admitted, and drives up to [`SUBMITS_IN_FLIGHT`] of
//!   them through to their answers at once. Every request it pops
//!   counts against its session's and context's in-flight tallies until
//!   the device has answered it, and a release stays pending, without
//!   holding up the control server, until the tally reads zero.
//!
//! Both hold the same device handle. The trait's own contract says every
//! method takes `&self`, may be called from several tasks at once, and
//! that an implementation serialises access to its own rings.

use arrayvec::ArrayVec;
use core::future::Future;
use core::pin::pin;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use core::task::Poll;
use futures::future::{Either, poll_fn, select};
use helios_hal::cpu::Cpu;
use helios_hal::display::{
    BlobId, BlobMemory, BlobRequest, CapsetId, CapsetList, CommandStream, ContextId, ContextName,
    FenceId, Gpu3d, Gpu3dCapabilities, Gpu3dError, RingCount, RingIndex, Submission,
};
use helios_hal::pmm::PhysFrameRange;
use helios_hal::watchdog::Watchdog;
use triomphe::Arc;

use crate::Kernel;
use crate::buffer::Buffer;
use crate::component::{ProviderReceiver, provider_channel};
use crate::exec::{InFlight, Notify, monotonic_nanos};

use super::service::{
    BlobCreate, BlobMapping, BlobShared, ContextShared, ControlMessage, Gpu3dRequest, Gpu3dService,
    Gpu3dShared, GpuBlob, GpuContext, InFlightSubmit, SessionState, SubmitCommands,
    SubmitCompletion, SubmitMessage, SubmitRequest,
};
use super::{
    Gpu3dServiceError, MAX_GPU_BLOBS, MAX_GPU_CONTEXTS, MAX_MACHINE_GPU_BLOBS,
    MAX_MACHINE_GPU_CONTEXTS,
};

/// Bytes of one capability-set read the kernel will carry.
const MAX_CAPSET_BYTES: usize = 1 << 20;

/// Submissions the submit server drives through to their answers at once.
pub(super) const SUBMITS_IN_FLIGHT: usize = 16;

/// Brings the display engine's rendering half under kernel ownership
/// and publishes the GPU subsystem service.
pub fn install_gpu3d_device<CpuImpl, WatchdogImpl, MeasuredBootImpl, Device>(
    kernel: &Kernel<CpuImpl, WatchdogImpl, MeasuredBootImpl>,
    cpu: &CpuImpl,
    device: Device,
) -> Gpu3dService
where
    CpuImpl: Cpu + Clone + Send + Sync + 'static,
    WatchdogImpl: Watchdog + Clone,
    MeasuredBootImpl: helios_hal::measured_boot::MeasuredBoot,
    Device: Gpu3d + Clone,
{
    let capabilities = device.capabilities();
    let (shared, control_rx, submit_rx) = gpu3d_channels(capabilities);

    if capabilities.renders {
        {
            let device = device.clone();
            let shared = shared.clone();
            kernel.spawn_local_detached(async move {
                serve_control(&device, &shared, &control_rx).await;
            });
        }
        {
            let device = device.clone();
            let cpu = cpu.clone();
            kernel.spawn_local_detached(async move {
                serve_submit(&device, &submit_rx, &cpu).await;
            });
        }
    }

    Gpu3dService::from_shared(shared)
}

/// The shared state and the two inboxes one engine's tasks are built around.
pub(super) fn gpu3d_channels(
    capabilities: Gpu3dCapabilities,
) -> (
    Arc<Gpu3dShared>,
    ProviderReceiver<ControlMessage>,
    ProviderReceiver<SubmitMessage>,
) {
    let (control, control_rx) = provider_channel(super::service::REQUEST_QUEUE_DEPTH);
    let (submit, submit_rx) = provider_channel(super::service::REQUEST_QUEUE_DEPTH);
    let shared = Arc::new(Gpu3dShared {
        control,
        submit,
        release: Arc::new(Notify::new()),
        sessions: AtomicU64::new(0),
        capabilities,
    });
    (shared, control_rx, submit_rx)
}

/// One context a session opened.
struct HeldContext {
    session: Arc<SessionState>,
    id: ContextId,
    shared: Arc<ContextShared>,
}

/// One blob a session created, and whether it sits in the aperture.
struct HeldBlob {
    session: Arc<SessionState>,
    id: BlobId,
    shared: Arc<BlobShared>,
    mapped: bool,
    backing: Option<Buffer>,
}

/// Everything every session has the renderer holding.
struct Held {
    contexts: ArrayVec<HeldContext, MAX_MACHINE_GPU_CONTEXTS>,
    blobs: ArrayVec<HeldBlob, MAX_MACHINE_GPU_BLOBS>,
}

impl Held {
    const fn new() -> Self {
        Self {
            contexts: ArrayVec::new_const(),
            blobs: ArrayVec::new_const(),
        }
    }

    fn holds_context(&self, session: &SessionState, context: ContextId) -> bool {
        self.contexts.iter().any(|held| {
            held.session.id == session.id && held.id == context && !held.shared.is_dropped()
        })
    }

    fn blob_index(&self, session: &SessionState, blob: BlobId) -> Option<usize> {
        self.blobs.iter().position(|held| {
            held.session.id == session.id && held.id == blob && !held.shared.is_dropped()
        })
    }

    /// Every session that has ended and still has something here.
    fn ended_sessions(
        &self,
    ) -> ArrayVec<Arc<SessionState>, { MAX_MACHINE_GPU_CONTEXTS + MAX_MACHINE_GPU_BLOBS }> {
        let mut ended = ArrayVec::new();
        for session in self
            .contexts
            .iter()
            .map(|held| &held.session)
            .chain(self.blobs.iter().map(|held| &held.session))
        {
            if session.has_ended()
                && !ended
                    .iter()
                    .any(|seen: &Arc<SessionState>| seen.id == session.id)
            {
                ended.push(session.clone());
            }
        }
        ended
    }

    /// The next blob of `session` nothing holds back any more.
    fn releasable_blob(&self, session: &SessionState) -> Option<usize> {
        self.blobs
            .iter()
            .position(|held| held.session.id == session.id && !held.shared.is_retained())
    }
}

/// Serves everything that changes what the renderer holds.
pub(super) async fn serve_control<Device>(
    device: &Device,
    shared: &Arc<Gpu3dShared>,
    inbox: &ProviderReceiver<ControlMessage>,
) where
    Device: Gpu3d,
{
    let mut held = Held::new();
    let mut capsets: Option<CapsetList> = None;
    loop {
        let released = pin!(shared.release.notified());
        let next = pin!(inbox.recv());
        match select(released, next).await {
            Either::Left(((), _)) => advance_releases(device, &mut held).await,
            Either::Right((Some(message), _)) => {
                if message.session.has_ended() {
                    continue;
                }
                serve_request(device, shared, &mut held, &mut capsets, message).await;
            }
            Either::Right((None, _)) => return,
        }
    }
}

async fn known_capsets<Device: Gpu3d>(
    device: &Device,
    known: &mut Option<CapsetList>,
) -> Result<CapsetList, Gpu3dServiceError> {
    if let Some(capsets) = known {
        return Ok(capsets.clone());
    }
    let capsets = device.capsets().await.map_err(Gpu3dServiceError::from)?;
    *known = Some(capsets.clone());
    Ok(capsets)
}

async fn serve_request<Device>(
    device: &Device,
    service: &Arc<Gpu3dShared>,
    held: &mut Held,
    capsets: &mut Option<CapsetList>,
    message: ControlMessage,
) where
    Device: Gpu3d,
{
    let ControlMessage { session, request } = message;
    match request {
        Gpu3dRequest::Capsets { reply } => {
            let _ = reply.send(known_capsets(device, capsets).await);
        }
        Gpu3dRequest::Capset { id, version, reply } => {
            let _ = reply.send(read_capset(device, capsets, id, version).await);
        }
        Gpu3dRequest::CreateContext {
            capset,
            rings,
            name,
            reply,
        } => {
            if reply.is_canceled() {
                return;
            }
            let created = create_context(
                device, service, held, capsets, &session, capset, rings, name,
            )
            .await;
            let _ = reply.send(created);
        }
        Gpu3dRequest::CreateBlob {
            context,
            params,
            reply,
        } => {
            if reply.is_canceled() {
                return;
            }
            let created = create_blob(device, service, held, &session, context, params).await;
            let _ = reply.send(created);
        }
        Gpu3dRequest::MapBlob { blob, reply } => {
            if reply.is_canceled() {
                return;
            }
            let mapped = map_blob(device, service, held, &session, blob).await;
            let _ = reply.send(mapped);
        }
        Gpu3dRequest::UnmapBlob { blob, reply } => {
            let _ = reply.send(unmap_blob(device, held, &session, blob).await);
        }
        Gpu3dRequest::AttachResource {
            context,
            blob,
            reply,
        } => {
            let _ = reply.send(attach(device, held, &session, context, blob, true).await);
        }
        Gpu3dRequest::DetachResource {
            context,
            blob,
            reply,
        } => {
            let _ = reply.send(attach(device, held, &session, context, blob, false).await);
        }
    }
}

async fn read_capset<Device: Gpu3d>(
    device: &Device,
    known: &mut Option<CapsetList>,
    id: CapsetId,
    version: u32,
) -> Result<alloc::vec::Vec<u8>, Gpu3dServiceError> {
    let capsets = known_capsets(device, known).await?;
    let Some(info) = capsets.iter().find(|info| info.id == id) else {
        return Err(Gpu3dServiceError::NoSuchCapset);
    };
    if version > info.max_version {
        return Err(Gpu3dServiceError::NoSuchCapset);
    }
    let mut bytes = alloc::vec![0_u8; (info.max_size as usize).min(MAX_CAPSET_BYTES)];
    let written = device
        .capset(id, version, &mut bytes)
        .await
        .map_err(Gpu3dServiceError::from)?;
    bytes.truncate(written);
    Ok(bytes)
}

#[expect(
    clippy::too_many_arguments,
    reason = "internal helper taking the server state tables and context parameters explicitly"
)]
async fn create_context<Device: Gpu3d>(
    device: &Device,
    service: &Arc<Gpu3dShared>,
    held: &mut Held,
    known: &mut Option<CapsetList>,
    session: &Arc<SessionState>,
    capset: CapsetId,
    rings: RingCount,
    name: ContextName,
) -> Result<GpuContext, Gpu3dServiceError> {
    let own = held
        .contexts
        .iter()
        .filter(|held| held.session.id == session.id)
        .count();
    if own >= MAX_GPU_CONTEXTS {
        return Err(Gpu3dServiceError::TooManyContexts);
    }
    if held.contexts.is_full() {
        return Err(Gpu3dServiceError::ContextsExhausted);
    }
    if !known_capsets(device, known)
        .await?
        .iter()
        .any(|info| info.id == capset)
    {
        return Err(Gpu3dServiceError::UnsupportedContext);
    }
    let id = device
        .create_context(capset, rings, name)
        .await
        .map_err(Gpu3dServiceError::from)?;
    let shared = Arc::new(ContextShared::new(
        id,
        capset,
        rings,
        service.release.clone(),
    ));
    held.contexts.push(HeldContext {
        session: session.clone(),
        id,
        shared: shared.clone(),
    });
    Ok(GpuContext::new(service.clone(), session.clone(), shared))
}

async fn create_blob<Device: Gpu3d>(
    device: &Device,
    service: &Arc<Gpu3dShared>,
    held: &mut Held,
    session: &Arc<SessionState>,
    context: ContextId,
    params: BlobCreate,
) -> Result<GpuBlob, Gpu3dServiceError> {
    if params.memory == BlobMemory::Guest && params.blob_id != 0 {
        return Err(Gpu3dServiceError::InvalidBlob);
    }
    if !held.holds_context(session, context) {
        return Err(Gpu3dServiceError::InvalidBlob);
    }
    let own = held
        .blobs
        .iter()
        .filter(|held| held.session.id == session.id)
        .count();
    if own >= MAX_GPU_BLOBS {
        return Err(Gpu3dServiceError::TooManyBlobs);
    }
    if held.blobs.is_full() {
        return Err(Gpu3dServiceError::BlobsExhausted);
    }
    let frames = params.backing.as_ref().map(Buffer::frames);
    let pages: &[PhysFrameRange] = match &frames {
        Some(range) => core::slice::from_ref(range),
        None => &[],
    };
    let created = device
        .create_blob(BlobRequest {
            context,
            memory: params.memory,
            usage: params.usage,
            size: params.size,
            blob_id: params.blob_id,
            backing: pages,
        })
        .await;
    let blob = match created {
        Ok(blob) => blob,
        Err(error) => {
            if let (Gpu3dError::Transport(_), Some(backing)) = (&error, params.backing) {
                tracing::error!(
                    %error,
                    bytes = backing.bytes(),
                    "the display engine did not answer a blob create; its backing run is kept \
                     out of the pool for good, because the engine may be reading and writing it"
                );
                backing.leak();
            }
            return Err(Gpu3dServiceError::from(error));
        }
    };
    let shared = Arc::new(BlobShared::new(
        blob,
        params.size,
        params.memory,
        params.usage,
        service.release.clone(),
    ));
    held.blobs.push(HeldBlob {
        session: session.clone(),
        id: blob,
        shared: shared.clone(),
        mapped: false,
        backing: params.backing,
    });
    Ok(GpuBlob::new(service.clone(), session.clone(), shared))
}

async fn release_blob<Device: Gpu3d>(device: &Device, record: HeldBlob) {
    let HeldBlob {
        id,
        mapped,
        backing,
        ..
    } = record;
    if mapped && let Err(error) = device.unmap_blob(id).await {
        keep_backing(
            "would not take a blob out of the aperture",
            &error,
            id,
            backing,
        );
        return;
    }
    if let Err(error) = device.destroy_blob(id).await {
        keep_backing("would not destroy a blob", &error, id, backing);
    }
}

fn keep_backing(refusal: &str, error: &Gpu3dError, blob: BlobId, backing: Option<Buffer>) {
    tracing::error!(
        %error,
        blob = blob.raw(),
        bytes = backing.as_ref().map_or(0, Buffer::bytes),
        "the display engine {refusal}; its backing run is kept out of the pool for good, \
         because the engine may still be reading and writing it"
    );
    if let Some(backing) = backing {
        backing.leak();
    }
}

async fn map_blob<Device: Gpu3d>(
    device: &Device,
    service: &Arc<Gpu3dShared>,
    held: &mut Held,
    session: &Arc<SessionState>,
    blob: BlobId,
) -> Result<BlobMapping, Gpu3dServiceError> {
    let Some(index) = held.blob_index(session, blob) else {
        return Err(Gpu3dServiceError::InvalidBlob);
    };
    if held.blobs[index].mapped {
        if !held.blobs[index].shared.take_unmap_pending() {
            return Err(Gpu3dServiceError::AlreadyMapped);
        }
        device
            .unmap_blob(blob)
            .await
            .map_err(Gpu3dServiceError::from)?;
        held.blobs[index].mapped = false;
    } else {
        let _ = held.blobs[index].shared.take_unmap_pending();
    }
    let region = device
        .map_blob(blob)
        .await
        .map_err(Gpu3dServiceError::from)?;
    held.blobs[index].mapped = true;
    Ok(BlobMapping::new(
        region,
        service.clone(),
        session.clone(),
        held.blobs[index].shared.clone(),
    ))
}

async fn unmap_blob<Device: Gpu3d>(
    device: &Device,
    held: &mut Held,
    session: &SessionState,
    blob: BlobId,
) -> Result<(), Gpu3dServiceError> {
    let Some(index) = held
        .blobs
        .iter()
        .position(|record| record.session.id == session.id && record.id == blob)
    else {
        return Err(Gpu3dServiceError::InvalidBlob);
    };
    let _ = held.blobs[index].shared.take_unmap_pending();
    if !held.blobs[index].mapped {
        return Err(Gpu3dServiceError::NotMapped);
    }
    device
        .unmap_blob(blob)
        .await
        .map_err(Gpu3dServiceError::from)?;
    held.blobs[index].mapped = false;
    Ok(())
}

async fn attach<Device: Gpu3d>(
    device: &Device,
    held: &mut Held,
    session: &SessionState,
    context: ContextId,
    blob: BlobId,
    attach: bool,
) -> Result<(), Gpu3dServiceError> {
    if !held.holds_context(session, context) || held.blob_index(session, blob).is_none() {
        return Err(Gpu3dServiceError::InvalidBlob);
    }
    let outcome = if attach {
        device.attach_resource(context, blob).await
    } else {
        device.detach_resource(context, blob).await
    };
    outcome.map_err(Gpu3dServiceError::from)
}

/// Reclaim dropped mappings, dropped blobs, dropped contexts and ended
/// sessions in safe hardware order without blocking other sessions.
async fn advance_releases<Device: Gpu3d>(device: &Device, held: &mut Held) {
    while let Some(index) = held.blobs.iter().position(|blob| {
        !blob.session.has_ended()
            && !blob.shared.is_dropped()
            && blob.mapped
            && blob.shared.take_unmap_pending()
    }) {
        let id = held.blobs[index].id;
        if let Err(error) = device.unmap_blob(id).await {
            tracing::warn!(
                %error,
                blob = id.raw(),
                "the display engine would not unmap a cancelled aperture placement"
            );
        } else {
            held.blobs[index].mapped = false;
        }
    }

    while let Some(index) = held.blobs.iter().position(|blob| {
        blob.shared.is_dropped() && !blob.session.has_ended() && !blob.shared.is_retained()
    }) {
        release_blob(device, held.blobs.remove(index)).await;
    }

    while let Some(index) = held.contexts.iter().position(|context| {
        context.shared.is_dropped() && !context.session.has_ended() && !context.shared.is_draining()
    }) {
        let context = held.contexts.remove(index);
        if let Err(error) = device.destroy_context(context.id).await {
            tracing::warn!(
                %error,
                "the display engine would not release a context its owner destroyed"
            );
        }
    }

    for session in held.ended_sessions() {
        if session.is_draining() {
            continue;
        }
        while let Some(index) = held.releasable_blob(&session) {
            release_blob(device, held.blobs.remove(index)).await;
        }
        if held.blobs.iter().any(|blob| blob.session.id == session.id) {
            continue;
        }
        let mut contexts = 0_usize;
        while let Some(index) = held
            .contexts
            .iter()
            .position(|held| held.session.id == session.id)
        {
            let context = held.contexts.remove(index);
            if let Err(error) = device.destroy_context(context.id).await {
                tracing::warn!(
                    %error,
                    "the display engine would not release a context of a session that ended"
                );
            }
            contexts += 1;
        }
        tracing::info!(session = session.id.raw(), contexts, "gpu session released");
    }
}

struct PendingCompletion {
    context: ContextId,
    ring: RingIndex,
    completion: SubmitCompletion,
}

type PendingCompletions = ArrayVec<PendingCompletion, SUBMITS_IN_FLIGHT>;

fn fail_completions(pending: &mut PendingCompletions, context: ContextId) {
    pending.retain(|point| {
        if point.context != context {
            return true;
        }
        point.completion.fail();
        false
    });
}

fn signal_completion(
    pending: &mut PendingCompletions,
    context: ContextId,
    ring: RingIndex,
    fence: Option<FenceId>,
) {
    pending.retain(|point| {
        if point.context != context || point.ring != ring || Some(point.completion.fence) != fence {
            return true;
        }
        point.completion.signal();
        false
    });
}

struct Finished {
    context: Arc<ContextShared>,
    commands: SubmitCommands,
    ring: RingIndex,
    fence: Option<FenceId>,
    reply: Option<futures::channel::oneshot::Sender<Result<(), Gpu3dServiceError>>>,
    outcome: Result<(), Gpu3dError>,
}

#[expect(
    clippy::large_enum_variant,
    reason = "the event is a stack temporary the server matches at once; boxing the message \
              would allocate per submission to shrink a value that is never stored"
)]
enum SubmitEvent<Done> {
    Finished(Done),
    Next(SubmitMessage),
    Closed,
}

pub(super) async fn serve_submit<Device, CpuImpl>(
    device: &Device,
    inbox: &ProviderReceiver<SubmitMessage>,
    cpu: &CpuImpl,
) where
    Device: Gpu3d,
    CpuImpl: Cpu,
{
    let unposted = AtomicBool::new(false);
    let mut completions = PendingCompletions::new();
    let mut running = pin!(InFlight::<_, SUBMITS_IN_FLIGHT>::new());
    let mut open = true;
    loop {
        let event = {
            let mut next = pin!(inbox.recv());
            poll_fn(|cx| {
                if let Poll::Ready(Some(done)) = running.as_mut().poll_next(cx) {
                    return Poll::Ready(SubmitEvent::Finished(done));
                }
                if open && !unposted.load(Ordering::Acquire) && running.len() < SUBMITS_IN_FLIGHT {
                    return match next.as_mut().poll(cx) {
                        Poll::Ready(Some(message)) => Poll::Ready(SubmitEvent::Next(message)),
                        Poll::Ready(None) => Poll::Ready(SubmitEvent::Closed),
                        Poll::Pending => Poll::Pending,
                    };
                }
                Poll::Pending
            })
            .await
        };
        match event {
            SubmitEvent::Finished((in_flight, finished)) => {
                settle(finished, cpu, &mut completions);
                drop(in_flight);
            }
            SubmitEvent::Closed => {
                open = false;
                if running.is_empty() {
                    return;
                }
            }
            SubmitEvent::Next(SubmitMessage { session, request }) => {
                let in_flight = InFlightSubmit::begin(session.clone(), request.context.clone());
                if session.has_ended() || request.context.is_dropped() {
                    if let Some(completion) = &request.completion {
                        completion.fail();
                    }
                    continue;
                }
                if request.context.is_faulted() {
                    refuse_faulted(request, cpu);
                    continue;
                }
                let SubmitRequest {
                    context,
                    commands,
                    ring,
                    completion,
                    reply,
                } = request;
                let fence = completion.as_ref().map(|completion| completion.fence);
                if let Some(completion) = completion
                    && !completion.signals.is_empty()
                {
                    completions.push(PendingCompletion {
                        context: context.id(),
                        ring,
                        completion,
                    });
                }
                unposted.store(true, Ordering::Release);
                let unposted = &unposted;
                running.as_mut().push(async move {
                    let mut reply = Some(reply);
                    let stream = match &commands {
                        SubmitCommands::Pages { range, .. } => CommandStream::Pages(*range),
                        SubmitCommands::Inline(bytes) => CommandStream::Inline(bytes),
                    };
                    let mut posted = || {
                        unposted.store(false, Ordering::Release);
                        if let Some(reply) = reply.take() {
                            let _ = reply.send(Ok(()));
                        }
                    };
                    let outcome = device
                        .submit(
                            Submission {
                                context: context.id(),
                                commands: stream,
                                ring,
                                fence,
                            },
                            &mut posted,
                        )
                        .await;
                    unposted.store(false, Ordering::Release);
                    (
                        in_flight,
                        Finished {
                            context,
                            commands,
                            ring,
                            fence,
                            reply,
                            outcome,
                        },
                    )
                });
            }
        }
        if !open && running.is_empty() {
            return;
        }
    }
}

fn refuse_faulted<CpuImpl: Cpu>(request: SubmitRequest, cpu: &CpuImpl) {
    if let Some(completion) = &request.completion {
        completion.fail();
        if let Some(timeline) = request.context.timeline(request.ring) {
            timeline.retire(completion.fence.raw(), monotonic_nanos(cpu));
        }
    }
    let _ = request.reply.send(Err(Gpu3dServiceError::DeviceFault));
}

fn settle<CpuImpl: Cpu>(finished: Finished, cpu: &CpuImpl, completions: &mut PendingCompletions) {
    let Finished {
        context,
        commands,
        ring,
        fence,
        reply,
        outcome,
    } = finished;
    let nanos = monotonic_nanos(cpu);
    let timeline = context
        .timeline(ring)
        .expect("the ring was admitted against one of the context's rings");
    let error = match outcome {
        Ok(()) => {
            if context.is_faulted() {
                fail_completions(completions, context.id());
            } else {
                signal_completion(completions, context.id(), ring, fence);
            }
            if let Some(fence) = fence {
                timeline.retire(fence.raw(), nanos);
            }
            return;
        }
        Err(error) => error,
    };
    if let (Gpu3dError::Transport(_), SubmitCommands::Pages { buffer, .. }) = (&error, commands) {
        tracing::error!(
            %error,
            bytes = buffer.bytes(),
            "the display engine did not answer a command submission; its command buffer is \
             kept out of the pool for good, because the engine may still be reading it"
        );
        buffer.leak();
    }
    tracing::error!(
        context = context.id().raw(),
        ring = ring.raw(),
        code = error.device_code(),
        posted = reply.is_none(),
        %error,
        "the display engine refused a command stream; the context is faulted"
    );
    context.fault(nanos);
    fail_completions(completions, context.id());
    if let Some(reply) = reply {
        let _ = reply.send(Err(Gpu3dServiceError::from(error)));
    }
}
