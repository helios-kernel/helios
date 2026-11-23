//! The 3D subsystem's own tests.
//!
//! The device side is a recording fake: every call the owner tasks make
//! is appended to a log, so a test asserts on the exact sequence the
//! display engine was asked for rather than on what the kernel
//! intended. The address space is the recording surface
//! `device::platform`'s test hooks install, so a test can also see when
//! a buffer's run was taken, shown and given back.

use crate::{SignalTimeline, Timeline, TimelineError, TimelineSource};
use alloc::vec::Vec;
use core::future::Future;
use core::num::NonZeroU32;
use core::pin::pin;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use core::task::{Context as TaskContext, Poll, Waker};
use std::task::Wake;

use futures::channel::oneshot;
use futures_lite::future::{block_on, poll_once};
use helios_hal::device::{DeviceRegion, DeviceRegionAttributes};
use helios_hal::display::{
    BlobId, BlobMemory, BlobRequest, BlobUsage, CapsetId, CapsetInfo, CapsetList, CommandStream,
    ContextId, ContextName, DisplayMode, FenceId, Gpu3d, Gpu3dCapabilities, Gpu3dError,
    Gpu3dResult, PixelFormat, RingCount, RingIndex, Submission,
};
use helios_hal::io::IoError;
use helios_hal::iommu::PhysicalRange;
use helios_hal::vmm::VirtAddr;
use std::sync::{Arc as WakeArc, Mutex};
use triomphe::Arc;

use crate::buffer::{Buffer, GuestMemory, Span, ViewTable, WASM_PAGE_BYTES};
use crate::component::ProviderReceiver;
use crate::device::test_hooks;
use crate::process::test_caps;
use crate::test_support::TestCpu;

use super::owner::{gpu3d_channels, serve_control, serve_submit};
use super::service::{
    BlobCreate, BlobMapping, CompletionSignal, ControlMessage, Gpu3dService, Gpu3dShared, GpuBlob,
    GpuContext, InlineCommands, SubmitCommands, SubmitCompletion, SubmitMessage,
};
#[cfg(feature = "wasmtime-runtime")]
use super::service::{BlobShared, ContextShared};
use super::{
    Gpu3dOwnership, Gpu3dServiceError, MAX_GPU_BLOBS, MAX_GPU_CONTEXTS, MAX_GPU_VIEWS,
    MAX_MACHINE_GPU_BLOBS, MAX_MACHINE_GPU_CONTEXTS,
};

const MEMORY_BASE: usize = 0x1_0000_0000;
const MEMORY_BYTES: u64 = 64 * WASM_PAGE_BYTES;

fn memory() -> GuestMemory {
    GuestMemory::new(VirtAddr::new(MEMORY_BASE), MEMORY_BYTES)
}

const fn pages(first: u64, pages: u64) -> Span {
    Span::new(first * WASM_PAGE_BYTES, pages * WASM_PAGE_BYTES)
}

fn pinned(bytes: u64) -> Buffer {
    Buffer::pinned(bytes).expect("the test pool has room")
}

const CAPSET: CapsetId = CapsetId::VENUS;
const CAPSET_MAX_VERSION: u32 = 1;
const APERTURE: u64 = 0x8_0000_0000;

const fn test_capabilities(renders: bool) -> Gpu3dCapabilities {
    Gpu3dCapabilities {
        renders,
        blobs: renders,
        host_visible: renders,
        context_init: renders,
        cross_device: false,
        blob_alignment: None,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Call {
    Capsets,
    Capset(CapsetId, u32),
    CreateContext(CapsetId, u8),
    DestroyContext(ContextId),
    CreateBlob(ContextId, BlobMemory, u64, u64),
    DestroyBlob(BlobId),
    MapBlob(BlobId),
    UnmapBlob(BlobId),
    Attach(ContextId, BlobId),
    Detach(ContextId, BlobId),
    Submit(ContextId, u8, Option<FenceId>),
}

struct FakeGpu3d {
    calls: Mutex<Vec<Call>>,
    capset_bytes: Vec<u8>,
    refuse_context: Mutex<Option<ContextId>>,
    refuse_before_post: AtomicBool,
    submit_hold: Mutex<Option<oneshot::Receiver<()>>>,
    transport_fault_submits: AtomicBool,
    destroy_hold: Mutex<Option<oneshot::Receiver<()>>>,
    refuse_destroy: AtomicBool,
    refuse_unmap: AtomicBool,
    fail_creates: Mutex<Option<bool>>,
    map_attributes: DeviceRegionAttributes,
    capabilities: Gpu3dCapabilities,
    next_context: Mutex<u32>,
    next_blob: Mutex<u32>,
}

impl FakeGpu3d {
    fn new() -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            capset_bytes: alloc::vec![0xde, 0xad, 0xbe, 0xef],
            refuse_context: Mutex::new(None),
            refuse_before_post: AtomicBool::new(false),
            submit_hold: Mutex::new(None),
            transport_fault_submits: AtomicBool::new(false),
            destroy_hold: Mutex::new(None),
            refuse_destroy: AtomicBool::new(false),
            refuse_unmap: AtomicBool::new(false),
            fail_creates: Mutex::new(None),
            map_attributes: DeviceRegionAttributes::PREFETCHABLE_MEMORY,
            capabilities: test_capabilities(true),
            next_context: Mutex::new(1),
            next_blob: Mutex::new(1),
        }
    }

    fn record(&self, call: Call) {
        self.calls.lock().expect("no test panics here").push(call);
    }

    fn calls(&self) -> Vec<Call> {
        self.calls.lock().expect("no test panics here").clone()
    }

    fn saw(&self, call: &Call) -> bool {
        self.calls().contains(call)
    }
}

impl Gpu3d for FakeGpu3d {
    fn capabilities(&self) -> Gpu3dCapabilities {
        self.capabilities
    }

    async fn capsets(&self) -> Gpu3dResult<CapsetList> {
        self.record(Call::Capsets);
        let mut list = CapsetList::new();
        list.push(CapsetInfo {
            id: CAPSET,
            max_version: CAPSET_MAX_VERSION,
            max_size: 4,
        });
        Ok(list)
    }

    async fn capset(&self, id: CapsetId, version: u32, out: &mut [u8]) -> Gpu3dResult<usize> {
        self.record(Call::Capset(id, version));
        let written = self.capset_bytes.len().min(out.len());
        out[..written].copy_from_slice(&self.capset_bytes[..written]);
        Ok(written)
    }

    async fn create_context(
        &self,
        capset: CapsetId,
        rings: RingCount,
        _name: ContextName,
    ) -> Gpu3dResult<ContextId> {
        let id = {
            let mut next = self.next_context.lock().expect("no test panics here");
            let id = ContextId::new(*next);
            *next += 1;
            id
        };
        self.record(Call::CreateContext(capset, rings.get()));
        Ok(id)
    }

    async fn destroy_context(&self, context: ContextId) -> Gpu3dResult<()> {
        self.record(Call::DestroyContext(context));
        Ok(())
    }

    async fn create_blob(&self, request: BlobRequest<'_>) -> Gpu3dResult<BlobId> {
        let id = {
            let mut next = self.next_blob.lock().expect("no test panics here");
            let id = BlobId::new(*next);
            *next += 1;
            id
        };
        self.record(Call::CreateBlob(
            request.context,
            request.memory,
            request.size,
            request.blob_id,
        ));
        match *self.fail_creates.lock().expect("no test panics here") {
            Some(true) => Err(Gpu3dError::Transport(IoError::DeviceFault)),
            Some(false) => Err(Gpu3dError::Unspecified),
            None => Ok(id),
        }
    }

    async fn destroy_blob(&self, blob: BlobId) -> Gpu3dResult<()> {
        self.record(Call::DestroyBlob(blob));
        let hold = self
            .destroy_hold
            .lock()
            .expect("no test panics here")
            .take();
        if let Some(hold) = hold {
            let _ = hold.await;
        }
        if self.refuse_destroy.load(Ordering::Relaxed) {
            return Err(Gpu3dError::Unspecified);
        }
        Ok(())
    }

    async fn map_blob(&self, blob: BlobId) -> Gpu3dResult<DeviceRegion> {
        self.record(Call::MapBlob(blob));
        Ok(DeviceRegion::new(
            PhysicalRange::new(APERTURE, 0x1000),
            self.map_attributes,
        ))
    }

    async fn unmap_blob(&self, blob: BlobId) -> Gpu3dResult<()> {
        self.record(Call::UnmapBlob(blob));
        if self.refuse_unmap.load(Ordering::Relaxed) {
            return Err(Gpu3dError::Unspecified);
        }
        Ok(())
    }

    async fn attach_resource(&self, context: ContextId, blob: BlobId) -> Gpu3dResult<()> {
        self.record(Call::Attach(context, blob));
        Ok(())
    }

    async fn detach_resource(&self, context: ContextId, blob: BlobId) -> Gpu3dResult<()> {
        self.record(Call::Detach(context, blob));
        Ok(())
    }

    async fn submit<'a, Posted>(
        &'a self,
        submission: Submission<'a>,
        posted: &'a mut Posted,
    ) -> Gpu3dResult<()>
    where
        Posted: FnMut() + Send,
    {
        self.record(Call::Submit(
            submission.context,
            submission.ring.raw(),
            submission.fence,
        ));
        match submission.commands {
            CommandStream::Pages(range) => assert!(range.bytes > 0, "a command run covers bytes"),
            CommandStream::Inline(bytes) => assert!(!bytes.is_empty(), "a stream has bytes"),
        }
        if self.refuse_before_post.load(Ordering::Relaxed) {
            return Err(Gpu3dError::Unspecified);
        }
        posted();
        let hold = self.submit_hold.lock().expect("no test panics here").take();
        if let Some(hold) = hold {
            let _ = hold.await;
        }
        if self.transport_fault_submits.load(Ordering::Relaxed) {
            return Err(Gpu3dError::Transport(IoError::DeviceFault));
        }
        if *self.refuse_context.lock().expect("no test panics here") == Some(submission.context) {
            return Err(Gpu3dError::Unspecified);
        }
        Ok(())
    }

    async fn fences(
        &self,
        _context: ContextId,
        _ring: RingIndex,
        after: FenceId,
    ) -> Gpu3dResult<FenceId> {
        Ok(after)
    }
}

fn channels(
    renders: bool,
) -> (
    Arc<Gpu3dShared>,
    ProviderReceiver<ControlMessage>,
    ProviderReceiver<SubmitMessage>,
) {
    gpu3d_channels(test_capabilities(renders))
}

fn with_servers<T>(
    device: &FakeGpu3d,
    shared: &Arc<Gpu3dShared>,
    control: &ProviderReceiver<ControlMessage>,
    submit: &ProviderReceiver<SubmitMessage>,
    work: impl Future<Output = T>,
) -> T {
    let cpu = TestCpu::without_entropy();
    block_on(async {
        let work = pin!(work);
        let servers = pin!(async {
            futures::future::join(
                serve_control(device, shared, control),
                serve_submit(device, submit, &cpu),
            )
            .await;
        });
        futures_lite::future::or(async { Some(work.await) }, async {
            servers.await;
            None
        })
        .await
        .expect("the 3D servers do not end on their own")
    })
}

fn opened_in(shared: &Arc<Gpu3dShared>, views: &mut ViewTable) -> Gpu3dOwnership {
    let service = Gpu3dService::from_shared(shared.clone());
    let mut ownership = Gpu3dOwnership::new();
    ownership
        .open(&service, || views.group(), test_caps::gpu())
        .expect("the engine renders");
    ownership
}

fn opened(shared: &Arc<Gpu3dShared>) -> Gpu3dOwnership {
    opened_in(shared, &mut ViewTable::new())
}

fn close(ownership: &mut Gpu3dOwnership, views: &mut ViewTable) {
    let id = ownership.session_ref().expect("the session is open").id();
    ownership
        .close(id, views)
        .expect("the test pool refills anything");
}

async fn request_context(
    ownership: &Gpu3dOwnership,
    capset: CapsetId,
    rings: u8,
) -> Result<GpuContext, Gpu3dServiceError> {
    ownership
        .session_ref()?
        .create_context(
            capset,
            RingCount::new(rings).expect("the test names a ring count in range"),
            ContextName::new(),
        )
        .await
}

async fn create_context(ownership: &Gpu3dOwnership) -> GpuContext {
    request_context(ownership, CAPSET, 1)
        .await
        .expect("the fake engine agrees")
}

async fn request_blob(
    ownership: &Gpu3dOwnership,
    context: &GpuContext,
    memory: BlobMemory,
    usage: BlobUsage,
    blob_id: u64,
) -> Result<GpuBlob, Gpu3dServiceError> {
    let backing = match memory {
        BlobMemory::Host3d => None,
        BlobMemory::Guest | BlobMemory::Host3dGuest => Some(pinned(4096)),
    };
    ownership
        .session_ref()?
        .create_blob(
            context,
            BlobCreate {
                memory,
                usage,
                size: 4096,
                blob_id,
                backing,
            },
        )
        .await
}

async fn new_blob(
    ownership: &Gpu3dOwnership,
    context: &GpuContext,
    memory: BlobMemory,
    usage: BlobUsage,
) -> GpuBlob {
    request_blob(ownership, context, memory, usage, 0)
        .await
        .expect("the fake engine agrees")
}

async fn place(blob: &GpuBlob) -> BlobMapping {
    blob.map().await.expect("the fake engine agrees")
}

fn page_commands() -> SubmitCommands {
    let buffer = pinned(4096);
    let range = buffer.physical();
    SubmitCommands::Pages { buffer, range }
}

async fn submit_on(
    context: &GpuContext,
    ring: u8,
    fence: Option<u64>,
) -> Result<(), Gpu3dServiceError> {
    context
        .submit(
            ring,
            page_commands(),
            fence.map(|fence| SubmitCompletion {
                fence: FenceId::new(fence),
                signals: Vec::new(),
            }),
        )
        .await
}

fn retired(context: &GpuContext, ring: u8) -> u64 {
    context
        .shared()
        .timeline(RingIndex::new(ring).expect("the test names a ring in range"))
        .expect("the context has the ring")
        .signal()
        .sequence()
}

async fn settle() {
    for _ in 0..16 {
        crate::yield_now().await;
    }
}

#[test]
fn an_engine_that_renders_nothing_cannot_be_opened() {
    test_hooks::install();
    let (shared, _control, _submit) = channels(false);
    let service = Gpu3dService::from_shared(shared);

    assert!(!service.renders());
    assert_eq!(
        service.open(test_caps::gpu()).err(),
        Some(Gpu3dServiceError::NoRenderer)
    );
}

#[test]
fn capabilities_and_blob_alignment_are_enforced_by_the_subsystem() {
    test_hooks::install();
    let mut caps = test_capabilities(true);
    caps.cross_device = true;
    caps.blob_alignment = NonZeroU32::new(4096);
    let (shared, control, submit) = gpu3d_channels(caps);
    let mut device = FakeGpu3d::new();
    device.capabilities = caps;
    let service = Gpu3dService::from_shared(shared.clone());
    assert_eq!(service.capabilities(), caps);

    let session = service.open(test_caps::gpu()).expect("renders");
    assert_eq!(session.capabilities(), caps);

    with_servers(&device, &shared, &control, &submit, async {
        let context = session
            .create_context(CAPSET, RingCount::ONE, ContextName::new())
            .await
            .expect("context created");
        let unaligned = session
            .create_blob(
                &context,
                BlobCreate {
                    memory: BlobMemory::Host3d,
                    usage: BlobUsage::MAPPABLE,
                    size: 4097,
                    blob_id: 1,
                    backing: None,
                },
            )
            .await;
        assert!(matches!(unaligned, Err(Gpu3dServiceError::InvalidBlob)));
        assert!(
            !device
                .calls()
                .iter()
                .any(|call| matches!(call, Call::CreateBlob(..)))
        );

        let aligned = session
            .create_blob(
                &context,
                BlobCreate {
                    memory: BlobMemory::Host3d,
                    usage: BlobUsage::MAPPABLE | BlobUsage::SHAREABLE,
                    size: 8192,
                    blob_id: 2,
                    backing: None,
                },
            )
            .await
            .expect("aligned blob succeeds");
        assert_eq!(aligned.size(), 8192);
        assert_eq!(aligned.memory(), BlobMemory::Host3d);
        assert_eq!(aligned.usage(), BlobUsage::MAPPABLE | BlobUsage::SHAREABLE);
    });
}

#[test]
fn two_instances_hold_contexts_at_once() {
    test_hooks::install();
    let (shared, control, submit) = channels(true);
    let device = FakeGpu3d::new();
    let first = opened(&shared);
    let second = opened(&shared);
    assert_ne!(
        first.session_ref().unwrap().id(),
        second.session_ref().unwrap().id(),
        "each instance has a session of its own"
    );

    with_servers(&device, &shared, &control, &submit, async {
        let (a, b) = futures::future::join(create_context(&first), create_context(&second)).await;
        assert_ne!(a.id(), b.id());

        assert_eq!(submit_on(&a, 0, Some(1)).await, Ok(()));
        assert_eq!(submit_on(&b, 0, Some(1)).await, Ok(()));
        settle().await;
        assert_eq!(retired(&a, 0), 1);
        assert_eq!(retired(&b, 0), 1);
    });
}

#[test]
fn a_second_open_in_one_instance_shares_its_session() {
    test_hooks::install();
    let (shared, _control, _submit) = channels(true);
    let service = Gpu3dService::from_shared(shared);
    let mut views = ViewTable::new();
    let mut ownership = Gpu3dOwnership::new();

    let first = ownership
        .open(&service, || views.group(), test_caps::gpu())
        .expect("the engine renders");
    let second = ownership
        .open(&service, || views.group(), test_caps::gpu())
        .expect("the engine renders");
    assert_eq!(first, second, "both handles name one session");

    ownership
        .close(first, &mut views)
        .expect("the session showed nothing");
    assert!(ownership.is_open(), "one handle still holds the session");
    ownership
        .close(second, &mut views)
        .expect("the session showed nothing");
    assert!(!ownership.is_open(), "the last handle ends it");
}

#[test]
fn one_instance_s_end_releases_only_its_own_resources() {
    test_hooks::install();
    let (shared, control, submit) = channels(true);
    let device = FakeGpu3d::new();
    let mut views = ViewTable::new();
    let mut dying = opened_in(&shared, &mut views);
    let living = opened(&shared);
    let runs = test_hooks::live_runs();

    with_servers(&device, &shared, &control, &submit, async {
        let dead = create_context(&dying).await;
        let kept = create_context(&living).await;
        let dead_blob = new_blob(&dying, &dead, BlobMemory::Guest, BlobUsage::empty()).await;
        let dead_blob_id = dead_blob.id();
        let kept_blob = new_blob(&living, &kept, BlobMemory::Guest, BlobUsage::empty()).await;
        assert_eq!(test_hooks::live_runs() - runs, 2);

        close(&mut dying, &mut views);
        settle().await;

        assert!(device.saw(&Call::DestroyBlob(dead_blob_id)));
        assert!(device.saw(&Call::DestroyContext(dead.id())));
        assert!(!device.saw(&Call::DestroyBlob(kept_blob.id())));
        assert!(!device.saw(&Call::DestroyContext(kept.id())));
        assert_eq!(
            test_hooks::live_runs() - runs,
            1,
            "only the ended session's backing went back to the pool"
        );

        assert_eq!(submit_on(&kept, 0, Some(1)).await, Ok(()));
        let _extra = new_blob(&living, &kept, BlobMemory::Host3d, BlobUsage::MAPPABLE).await;
    });
}

#[test]
fn an_instance_holds_at_most_its_share_of_contexts_and_blobs() {
    test_hooks::install();
    let (shared, control, submit) = channels(true);
    let device = FakeGpu3d::new();
    let ownership = opened(&shared);

    with_servers(&device, &shared, &control, &submit, async {
        let mut contexts = Vec::new();
        for _ in 0..MAX_GPU_CONTEXTS {
            contexts.push(create_context(&ownership).await);
        }
        assert_eq!(
            request_context(&ownership, CAPSET, 1).await.err(),
            Some(Gpu3dServiceError::TooManyContexts)
        );

        let mut blobs = Vec::new();
        for _ in 0..MAX_GPU_BLOBS {
            blobs.push(
                new_blob(
                    &ownership,
                    &contexts[0],
                    BlobMemory::Host3d,
                    BlobUsage::MAPPABLE,
                )
                .await,
            );
        }
        assert_eq!(
            request_blob(
                &ownership,
                &contexts[0],
                BlobMemory::Host3d,
                BlobUsage::MAPPABLE,
                0
            )
            .await
            .err(),
            Some(Gpu3dServiceError::TooManyBlobs)
        );
    });
}

#[test]
fn the_machine_holds_at_most_its_tables_of_contexts_and_blobs() {
    test_hooks::install();
    let (shared, control, submit) = channels(true);
    let device = FakeGpu3d::new();
    let full_sessions = MAX_MACHINE_GPU_CONTEXTS / MAX_GPU_CONTEXTS;
    let sessions: Vec<_> = (0..full_sessions).map(|_| opened(&shared)).collect();
    let late = opened(&shared);
    assert_eq!(
        MAX_MACHINE_GPU_BLOBS / MAX_GPU_BLOBS,
        full_sessions,
        "the blob table fills at the same session count the context table does"
    );

    with_servers(&device, &shared, &control, &submit, async {
        let mut contexts = Vec::new();
        for session in &sessions {
            let mut own = Vec::new();
            for _ in 0..MAX_GPU_CONTEXTS {
                own.push(create_context(session).await);
            }
            contexts.push(own);
        }
        assert_eq!(
            request_context(&late, CAPSET, 1).await.err(),
            Some(Gpu3dServiceError::ContextsExhausted),
            "a session holding nothing is refused once the machine's table is full"
        );

        let given_back = contexts[0].pop().expect("the session holds contexts");
        drop(given_back);
        let late_context = create_context(&late).await;

        let mut blobs = Vec::new();
        for (session, own) in sessions.iter().zip(&contexts) {
            let context = own.first().expect("the session holds contexts");
            for _ in 0..MAX_GPU_BLOBS {
                blobs.push(
                    new_blob(session, context, BlobMemory::Host3d, BlobUsage::MAPPABLE).await,
                );
            }
        }
        assert_eq!(
            request_blob(
                &late,
                &late_context,
                BlobMemory::Host3d,
                BlobUsage::MAPPABLE,
                0,
            )
            .await
            .err(),
            Some(Gpu3dServiceError::BlobsExhausted),
            "a session holding no blob is refused once the machine's table is full"
        );
    });
}

#[test]
fn a_stale_fence_is_checked_per_ring() {
    test_hooks::install();
    let (shared, control, submit) = channels(true);
    let device = FakeGpu3d::new();
    let ownership = opened(&shared);

    with_servers(&device, &shared, &control, &submit, async {
        let context = request_context(&ownership, CAPSET, 2)
            .await
            .expect("the fake engine agrees");
        assert_eq!(submit_on(&context, 0, Some(5)).await, Ok(()));
        assert_eq!(
            submit_on(&context, 0, Some(5)).await,
            Err(Gpu3dServiceError::StaleFence)
        );
        assert_eq!(
            submit_on(&context, 0, Some(4)).await,
            Err(Gpu3dServiceError::StaleFence)
        );
        assert_eq!(
            submit_on(&context, 1, Some(1)).await,
            Ok(()),
            "ring 1 has admitted nothing yet"
        );
        assert_eq!(
            submit_on(&context, 0, None).await,
            Ok(()),
            "no fence, nothing to be stale"
        );
        assert_eq!(submit_on(&context, 0, Some(6)).await, Ok(()));
    });
}

#[test]
fn a_ring_the_context_was_not_created_with_is_a_bad_ring() {
    test_hooks::install();
    let (shared, control, submit) = channels(true);
    let device = FakeGpu3d::new();
    let ownership = opened(&shared);

    with_servers(&device, &shared, &control, &submit, async {
        let context = request_context(&ownership, CAPSET, 2)
            .await
            .expect("two rings are in range");
        for ring in [2, 63, 64, u8::MAX] {
            assert_eq!(
                submit_on(&context, ring, None).await,
                Err(Gpu3dServiceError::BadRing),
                "ring {ring}"
            );
        }
    });
    assert!(RingCount::new(0).is_none());
    assert!(RingCount::new(65).is_none());
}

#[test]
fn fences_retire_on_the_ring_they_were_submitted_on() {
    test_hooks::install();
    let (shared, control, submit) = channels(true);
    let device = FakeGpu3d::new();
    let ownership = opened(&shared);

    with_servers(&device, &shared, &control, &submit, async {
        let context = request_context(&ownership, CAPSET, 2)
            .await
            .expect("the fake engine agrees");
        assert!(device.saw(&Call::CreateContext(CAPSET, 2)));

        assert_eq!(submit_on(&context, 0, Some(3)).await, Ok(()));
        assert_eq!(submit_on(&context, 1, Some(1)).await, Ok(()));
        assert_eq!(submit_on(&context, 1, None).await, Ok(()));
        settle().await;

        assert_eq!(retired(&context, 0), 3);
        assert_eq!(retired(&context, 1), 1);
        let id = context.id();
        assert!(device.saw(&Call::Submit(id, 0, Some(FenceId::new(3)))));
        assert!(device.saw(&Call::Submit(id, 1, Some(FenceId::new(1)))));
        assert!(device.saw(&Call::Submit(id, 1, None)));
    });
}

#[test]
fn an_inline_stream_reaches_the_device() {
    test_hooks::install();
    let (shared, control, submit) = channels(true);
    let device = FakeGpu3d::new();
    let ownership = opened(&shared);

    with_servers(&device, &shared, &control, &submit, async {
        let context = create_context(&ownership).await;
        let inline = InlineCommands::try_from([1_u8, 2, 3, 4].as_slice()).expect("four bytes fit");
        assert_eq!(
            context
                .submit(
                    0,
                    SubmitCommands::Inline(inline),
                    Some(SubmitCompletion {
                        fence: FenceId::new(2),
                        signals: Vec::new(),
                    }),
                )
                .await,
            Ok(())
        );
        settle().await;
        assert_eq!(retired(&context, 0), 2);
    });
}

#[test]
fn a_refusal_faults_only_its_context_and_retires_every_ring() {
    test_hooks::install();
    let (shared, control, submit) = channels(true);
    let device = FakeGpu3d::new();
    let ownership = opened(&shared);
    let other = opened(&shared);

    with_servers(&device, &shared, &control, &submit, async {
        let faulted = request_context(&ownership, CAPSET, 2)
            .await
            .expect("the fake engine agrees");
        let healthy = create_context(&other).await;

        let (gate, hold) = oneshot::channel();
        *device.submit_hold.lock().expect("no test panics here") = Some(hold);
        assert_eq!(
            submit_on(&faulted, 1, Some(9)).await,
            Ok(()),
            "resolved once it is on the ring"
        );
        *device.refuse_context.lock().expect("no test panics here") = Some(faulted.id());
        assert_eq!(
            submit_on(&faulted, 0, Some(2)).await,
            Ok(()),
            "the refusal comes after the submission resolved"
        );
        settle().await;

        assert!(faulted.is_faulted());
        assert_eq!(retired(&faulted, 0), 2);
        assert_eq!(
            retired(&faulted, 1),
            9,
            "a ring whose chain the device still holds retires too"
        );
        assert_eq!(
            submit_on(&faulted, 0, Some(3)).await,
            Err(Gpu3dServiceError::DeviceFault)
        );

        assert!(!healthy.is_faulted());
        assert_eq!(submit_on(&healthy, 0, Some(1)).await, Ok(()));
        settle().await;
        assert_eq!(retired(&healthy, 0), 1);

        gate.send(()).expect("the device is parked on it");
        settle().await;
    });
}

#[test]
fn a_submission_the_driver_could_not_post_is_answered_with_its_refusal() {
    test_hooks::install();
    let (shared, control, submit) = channels(true);
    let device = FakeGpu3d::new();
    device.refuse_before_post.store(true, Ordering::Relaxed);
    let ownership = opened(&shared);

    with_servers(&device, &shared, &control, &submit, async {
        let context = create_context(&ownership).await;
        assert_eq!(
            submit_on(&context, 0, Some(4)).await,
            Err(Gpu3dServiceError::DeviceFault)
        );
        assert_eq!(retired(&context, 0), 4, "its fence retired anyway");
        assert!(context.is_faulted());
    });
}

#[test]
fn a_guest_blob_naming_a_blob_id_is_refused() {
    test_hooks::install();
    let (shared, control, submit) = channels(true);
    let device = FakeGpu3d::new();
    let ownership = opened(&shared);

    with_servers(&device, &shared, &control, &submit, async {
        let context = create_context(&ownership).await;
        assert_eq!(
            request_blob(
                &ownership,
                &context,
                BlobMemory::Guest,
                BlobUsage::empty(),
                5
            )
            .await
            .err(),
            Some(Gpu3dServiceError::InvalidBlob)
        );
        let _blob = request_blob(
            &ownership,
            &context,
            BlobMemory::Host3d,
            BlobUsage::MAPPABLE,
            5,
        )
        .await
        .expect("a host blob names its allocation");
    });

    let created: Vec<_> = device
        .calls()
        .into_iter()
        .filter(|call| matches!(call, Call::CreateBlob(..)))
        .collect();
    assert_eq!(
        created,
        alloc::vec![Call::CreateBlob(
            ContextId::new(1),
            BlobMemory::Host3d,
            4096,
            5
        )],
        "only the host blob reached the device"
    );
}

#[test]
fn a_write_combining_blob_is_shown_write_combined() {
    test_hooks::install();
    let (shared, control, submit) = channels(true);
    let mut device = FakeGpu3d::new();
    device.map_attributes = DeviceRegionAttributes::WRITE_COMBINING_MEMORY;
    let mut views = ViewTable::new();
    let ownership = opened_in(&shared, &mut views);

    let region = with_servers(&device, &shared, &control, &submit, async {
        let context = create_context(&ownership).await;
        let blob = new_blob(
            &ownership,
            &context,
            BlobMemory::Host3d,
            BlobUsage::MAPPABLE,
        )
        .await;
        place(&blob).await.region()
    });
    assert_eq!(
        region.attributes,
        DeviceRegionAttributes::WRITE_COMBINING_MEMORY
    );

    let before = test_hooks::changes().len();
    views
        .show_device(
            memory(),
            pages(2, 1),
            region,
            Some(ownership.views().expect("an open session has a set")),
        )
        .expect("the span is free");
    assert_eq!(
        &test_hooks::changes()[before..],
        &[test_hooks::MappingChange::SubstituteDevice(
            helios_hal::vmm::VirtRange::new(
                VirtAddr::new(MEMORY_BASE + 2 * WASM_PAGE_BYTES as usize),
                0x1000
            ),
            DeviceRegionAttributes::WRITE_COMBINING_MEMORY,
        )],
        "the aperture is shown under the memory type the device reported"
    );
}

#[test]
fn dropping_a_mapping_without_explicit_unmap_releases_the_aperture_slot() {
    test_hooks::install();
    let (shared, control, submit) = channels(true);
    let device = FakeGpu3d::new();
    let ownership = opened(&shared);

    with_servers(&device, &shared, &control, &submit, async {
        let context = create_context(&ownership).await;
        let blob = new_blob(
            &ownership,
            &context,
            BlobMemory::Host3d,
            BlobUsage::MAPPABLE,
        )
        .await;
        let mapping = place(&blob).await;
        drop(mapping);
        let remapped = place(&blob).await;
        remapped.unmap().await.expect("explicit unmap succeeds");
        assert_eq!(
            device
                .calls()
                .iter()
                .filter(|call| matches!(call, Call::UnmapBlob(id) if *id == blob.id()))
                .count(),
            2
        );
    });
}

#[test]
fn cloned_blob_handles_share_lifetime_until_last_clone_drops() {
    test_hooks::install();
    let (shared, control, submit) = channels(true);
    let device = FakeGpu3d::new();
    let ownership = opened(&shared);

    with_servers(&device, &shared, &control, &submit, async {
        let context = create_context(&ownership).await;
        let blob = new_blob(
            &ownership,
            &context,
            BlobMemory::Host3d,
            BlobUsage::SHAREABLE,
        )
        .await;
        let id = blob.id();
        let exported = blob.clone();
        drop(blob);
        settle().await;
        assert!(!device.saw(&Call::DestroyBlob(id)));
        drop(exported);
        settle().await;
        assert!(device.saw(&Call::DestroyBlob(id)));
    });
}

#[test]
fn ending_the_session_ends_every_view_in_its_set() {
    test_hooks::install();
    let (shared, _control, _submit) = channels(true);
    let mut views = ViewTable::new();
    let mut ownership = opened_in(&shared, &mut views);
    let group = ownership.views().expect("an open session has a set");
    let runs = test_hooks::live_runs();

    let commands = pinned(4096);
    let physical = commands.physical();
    views
        .show_buffer(memory(), pages(0, 1), &commands, Some(group))
        .expect("the span is free");
    drop(commands);
    views
        .show_device(
            memory(),
            pages(1, 1),
            DeviceRegion::new(
                PhysicalRange::new(APERTURE, 0x1000),
                DeviceRegionAttributes::PREFETCHABLE_MEMORY,
            ),
            Some(group),
        )
        .expect("the span is free");
    let before = test_hooks::changes().len();

    close(&mut ownership, &mut views);

    assert!(views.is_empty(), "nothing of the session is shown");
    assert!(!ownership.is_open());
    let changes = &test_hooks::changes()[before..];
    assert_eq!(
        changes
            .iter()
            .filter(|change| matches!(change, test_hooks::MappingChange::Restore(_)))
            .count(),
        2,
        "both spans are the instance's ordinary memory again"
    );
    assert!(changes.contains(&test_hooks::MappingChange::Freed(physical)));
    assert_eq!(test_hooks::live_runs(), runs);
}

#[test]
fn a_session_shows_at_most_its_share_of_views() {
    test_hooks::install();
    let (shared, _control, _submit) = channels(true);
    let mut views = ViewTable::new();
    let ownership = opened_in(&shared, &mut views);
    let region = DeviceRegion::new(
        PhysicalRange::new(APERTURE, 0x1000),
        DeviceRegionAttributes::PREFETCHABLE_MEMORY,
    );
    let mut shown = Vec::new();
    for page in 0..MAX_GPU_VIEWS as u64 {
        let group = ownership
            .room_for_view(&views)
            .expect("the session is under its share");
        shown.push(
            views
                .show_device(memory(), pages(page, 1), region, Some(group))
                .expect("the span is free"),
        );
    }

    assert_eq!(
        ownership.room_for_view(&views).err(),
        Some(Gpu3dServiceError::TooManyViews)
    );
    views
        .end(shown.pop().expect("the session shows something"))
        .expect("the test pool refills anything");
    assert!(ownership.room_for_view(&views).is_ok());
}

#[test]
fn a_context_is_refused_for_a_renderer_the_host_does_not_speak() {
    test_hooks::install();
    let (shared, control, submit) = channels(true);
    let device = FakeGpu3d::new();
    let ownership = opened(&shared);

    with_servers(&device, &shared, &control, &submit, async {
        assert_eq!(
            request_context(&ownership, CapsetId::GFXSTREAM_VULKAN, 1)
                .await
                .err(),
            Some(Gpu3dServiceError::UnsupportedContext)
        );
    });

    assert_eq!(
        device.calls(),
        alloc::vec![Call::Capsets],
        "the context never reached the device"
    );
}

#[test]
fn a_capset_s_bytes_reach_their_reader_undecoded() {
    test_hooks::install();
    let (shared, control, submit) = channels(true);
    let device = FakeGpu3d::new();
    let ownership = opened(&shared);

    with_servers(&device, &shared, &control, &submit, async {
        let session = ownership.session_ref().unwrap();
        assert_eq!(
            session.capset(CAPSET, CAPSET_MAX_VERSION).await,
            Ok(alloc::vec![0xde, 0xad, 0xbe, 0xef])
        );
        assert_eq!(
            session.capset(CAPSET, CAPSET_MAX_VERSION + 1).await.err(),
            Some(Gpu3dServiceError::NoSuchCapset)
        );
        assert_eq!(
            session.capset(CapsetId::VIRGL, 0).await.err(),
            Some(Gpu3dServiceError::NoSuchCapset)
        );
    });

    assert_eq!(
        device
            .calls()
            .into_iter()
            .filter(|call| matches!(call, Call::Capset(..)))
            .collect::<Vec<_>>(),
        alloc::vec![Call::Capset(CAPSET, CAPSET_MAX_VERSION)],
        "only the set the device carries, at a version it publishes, was read"
    );
}

#[test]
fn a_blob_for_a_context_the_session_never_opened_is_refused() {
    test_hooks::install();
    let (shared, control, submit) = channels(true);
    let device = FakeGpu3d::new();
    let ownership = opened(&shared);
    let other = opened(&shared);

    with_servers(&device, &shared, &control, &submit, async {
        let foreign = create_context(&other).await;
        assert_eq!(
            request_blob(
                &ownership,
                &foreign,
                BlobMemory::Guest,
                BlobUsage::empty(),
                0
            )
            .await
            .err(),
            Some(Gpu3dServiceError::InvalidBlob)
        );
    });

    assert!(
        !device
            .calls()
            .iter()
            .any(|call| matches!(call, Call::CreateBlob(..))),
        "the blob never reached the device"
    );
}

#[test]
fn an_ended_session_unmaps_then_destroys_then_frees() {
    test_hooks::install();
    let (shared, control, submit) = channels(true);
    let device = FakeGpu3d::new();
    let mut views = ViewTable::new();
    let mut ownership = opened_in(&shared, &mut views);
    let runs = test_hooks::live_runs();

    with_servers(&device, &shared, &control, &submit, async {
        let context = create_context(&ownership).await;
        let blob = new_blob(
            &ownership,
            &context,
            BlobMemory::Host3dGuest,
            BlobUsage::MAPPABLE,
        )
        .await;
        let _mapping = place(&blob).await;
        assert_eq!(test_hooks::live_runs() - runs, 1);

        close(&mut ownership, &mut views);
        assert_eq!(
            test_hooks::live_runs() - runs,
            1,
            "the blob's buffer is not freed by the end itself"
        );
        settle().await;
    });

    let calls = device.calls();
    let position = |wanted: fn(&Call) -> bool| {
        calls
            .iter()
            .position(wanted)
            .expect("the release made the call")
    };
    let unmap = position(|call| matches!(call, Call::UnmapBlob(_)));
    let destroy_blob = position(|call| matches!(call, Call::DestroyBlob(_)));
    let destroy_context = position(|call| matches!(call, Call::DestroyContext(_)));
    assert!(
        unmap < destroy_blob && destroy_blob < destroy_context,
        "the renderer stops placing the storage before it forgets the resource"
    );
    assert!(
        matches!(
            test_hooks::changes().last(),
            Some(test_hooks::MappingChange::Freed(_))
        ),
        "the blob's buffer goes back once the renderer has let go"
    );
    assert_eq!(test_hooks::live_runs(), runs);
}

#[test]
fn a_request_that_outlived_its_session_is_not_served() {
    test_hooks::install();
    let (shared, control, submit) = channels(true);
    let device = FakeGpu3d::new();
    let mut ownership = opened(&shared);
    let stale = ownership.session_ref().unwrap().client();

    with_servers(&device, &shared, &control, &submit, async {
        let context = create_context(&ownership).await;
        device.calls.lock().unwrap().clear();

        close(&mut ownership, &mut ViewTable::new());
        settle().await;
        device.calls.lock().unwrap().clear();

        let _next = opened(&shared);

        assert_eq!(
            stale.capsets().await.err(),
            Some(Gpu3dServiceError::SessionEnded)
        );
        assert_eq!(
            submit_on(&context, 0, Some(1)).await,
            Err(Gpu3dServiceError::SessionEnded)
        );
    });

    assert!(
        device.calls().is_empty(),
        "nothing reached the device under a session that had ended"
    );
}

#[test]
fn a_request_queued_before_the_end_is_dropped() {
    test_hooks::install();
    let (shared, control, submit) = channels(true);
    let device = FakeGpu3d::new();
    let mut ownership = opened(&shared);
    let client = ownership.session_ref().unwrap().client();

    let mut pending = pin!(client.create_context(CAPSET, RingCount::ONE, ContextName::new()));
    assert!(
        block_on(poll_once(pending.as_mut())).is_none(),
        "the request is queued and unanswered"
    );
    close(&mut ownership, &mut ViewTable::new());

    with_servers(&device, &shared, &control, &submit, async {
        assert_eq!(
            pending.await.err(),
            Some(Gpu3dServiceError::SessionEnded),
            "the ended session's request is dropped, not served"
        );
        settle().await;
    });

    assert!(
        device.calls().is_empty(),
        "no device-side context was created for a session that had ended"
    );
}

#[test]
fn a_submission_in_flight_is_finished_before_the_session_is_released() {
    test_hooks::install();
    let (shared, control, submit) = channels(true);
    let device = FakeGpu3d::new();
    let (gate, hold) = oneshot::channel();
    *device.submit_hold.lock().expect("no test panics here") = Some(hold);
    let mut views = ViewTable::new();
    let mut ownership = opened_in(&shared, &mut views);
    let runs = test_hooks::live_runs();

    with_servers(&device, &shared, &control, &submit, async {
        let context = create_context(&ownership).await;
        let buffer = pinned(4096);
        let range = buffer.physical();
        views
            .show_buffer(
                memory(),
                pages(0, 1),
                &buffer,
                Some(ownership.views().expect("an open session has a set")),
            )
            .expect("the span is free");

        assert_eq!(
            context
                .submit(
                    0,
                    SubmitCommands::Pages { buffer, range },
                    Some(SubmitCompletion {
                        fence: FenceId::new(1),
                        signals: Vec::new(),
                    }),
                )
                .await,
            Ok(()),
            "resolved once it is on the ring"
        );
        let submitted = Call::Submit(context.id(), 0, Some(FenceId::new(1)));
        assert!(device.saw(&submitted), "the device is holding the chain");

        close(&mut ownership, &mut views);
        assert!(views.is_empty(), "the session's views end with it");
        settle().await;
        assert!(
            !device
                .calls()
                .iter()
                .any(|call| matches!(call, Call::DestroyContext(_))),
            "the destroy is not issued while a submission is in flight"
        );
        assert_eq!(
            test_hooks::live_runs() - runs,
            1,
            "the command buffer is not freed while the device holds the chain"
        );

        gate.send(()).expect("the device is parked on it");
        settle().await;
        assert!(device.saw(&Call::DestroyContext(context.id())));
    });

    let calls = device.calls();
    let submitted = calls
        .iter()
        .position(|call| matches!(call, Call::Submit(..)))
        .expect("the device saw the submission");
    let destroyed = calls
        .iter()
        .position(|call| matches!(call, Call::DestroyContext(_)))
        .expect("the context is destroyed once the device is done");
    assert!(submitted < destroyed);
    assert_eq!(test_hooks::live_runs(), runs);
}

#[test]
fn dropping_a_context_waits_for_its_in_flight_submissions() {
    test_hooks::install();
    let (shared, control, submit) = channels(true);
    let device = FakeGpu3d::new();
    let (gate, hold) = oneshot::channel();
    *device.submit_hold.lock().expect("no test panics here") = Some(hold);
    let ownership = opened(&shared);

    with_servers(&device, &shared, &control, &submit, async {
        let context = create_context(&ownership).await;
        let id = context.id();
        assert_eq!(submit_on(&context, 0, Some(1)).await, Ok(()));
        drop(context);
        settle().await;
        assert!(
            !device.saw(&Call::DestroyContext(id)),
            "context destroy waits while the submission is still with the device"
        );

        gate.send(()).expect("the device is parked on it");
        settle().await;
        assert!(device.saw(&Call::DestroyContext(id)));
    });
}

#[test]
fn an_ended_session_s_drain_does_not_stall_other_sessions() {
    test_hooks::install();
    let (shared, control, submit) = channels(true);
    let device = FakeGpu3d::new();
    let (gate, hold) = oneshot::channel();
    *device.submit_hold.lock().expect("no test panics here") = Some(hold);
    let mut views = ViewTable::new();
    let mut ending = opened_in(&shared, &mut views);
    let other = opened(&shared);

    with_servers(&device, &shared, &control, &submit, async {
        let held_back = create_context(&ending).await;
        assert_eq!(submit_on(&held_back, 0, Some(1)).await, Ok(()));
        close(&mut ending, &mut views);
        settle().await;

        let context = create_context(&other).await;
        let _blob = new_blob(&other, &context, BlobMemory::Host3d, BlobUsage::MAPPABLE).await;
        assert!(!device.saw(&Call::DestroyContext(held_back.id())));

        gate.send(()).expect("the device is parked on it");
        settle().await;
        assert!(device.saw(&Call::DestroyContext(held_back.id())));
        assert!(!device.saw(&Call::DestroyContext(context.id())));
    });
}

#[test]
fn an_exported_image_retains_storage_until_its_last_scanout_retires() {
    test_hooks::install();
    let (shared, control, submit) = channels(true);
    let device = FakeGpu3d::new();
    let mut views = ViewTable::new();
    let mut ownership = opened_in(&shared, &mut views);
    let runs = test_hooks::live_runs();

    let blob_id = with_servers(&device, &shared, &control, &submit, async {
        let context = create_context(&ownership).await;
        let blob = new_blob(&ownership, &context, BlobMemory::Guest, BlobUsage::empty()).await;
        let first_id = blob.id();
        let image = blob
            .image(
                DisplayMode {
                    width: 4,
                    height: 4,
                },
                PixelFormat::Rgba8888,
                0,
                16,
            )
            .unwrap();
        let (_, scanout) = image.clone().into_scanout();
        drop(image);

        drop(blob);
        settle().await;
        assert!(
            !device.saw(&Call::DestroyBlob(first_id)),
            "no destroy reaches the device while the scanout shows the blob"
        );
        assert_eq!(test_hooks::live_runs() - runs, 1);

        drop(scanout);
        settle().await;
        assert!(device.saw(&Call::DestroyBlob(first_id)));
        assert_eq!(test_hooks::live_runs(), runs);

        let second = new_blob(&ownership, &context, BlobMemory::Guest, BlobUsage::empty()).await;
        let second_id = second.id();
        let image = second
            .image(
                DisplayMode {
                    width: 4,
                    height: 4,
                },
                PixelFormat::Rgba8888,
                0,
                16,
            )
            .unwrap();
        close(&mut ownership, &mut views);
        settle().await;
        assert!(!device.saw(&Call::DestroyBlob(second_id)));
        assert!(!device.saw(&Call::DestroyContext(context.id())));

        let (layout, scanout) = image.into_scanout();
        assert_eq!(layout.blob, second_id);
        settle().await;
        assert!(!device.saw(&Call::DestroyBlob(second_id)));
        drop(scanout);
        settle().await;
        second_id
    });

    let calls = device.calls();
    let destroyed = calls
        .iter()
        .position(|call| *call == Call::DestroyBlob(blob_id))
        .expect("the blob is destroyed once the scanout let go");
    let context_gone = calls
        .iter()
        .position(|call| matches!(call, Call::DestroyContext(_)))
        .expect("and then its context");
    assert!(destroyed < context_gone);
    assert_eq!(test_hooks::live_runs(), runs);
}

#[test]
fn a_command_buffer_too_long_for_the_wire_is_out_of_bounds() {
    assert_eq!(
        Gpu3dServiceError::from(Gpu3dError::CommandBufferLength { bytes: 8 << 20 }),
        Gpu3dServiceError::OutOfBounds
    );
}

#[test]
fn a_blob_is_freed_only_once_the_device_has_destroyed_it() {
    test_hooks::install();
    let (shared, control, submit) = channels(true);
    let device = FakeGpu3d::new();
    let (gate, hold) = oneshot::channel();
    *device.destroy_hold.lock().expect("no test panics here") = Some(hold);
    let ownership = opened(&shared);
    let runs = test_hooks::live_runs();

    with_servers(&device, &shared, &control, &submit, async {
        let context = create_context(&ownership).await;
        let blob = new_blob(&ownership, &context, BlobMemory::Guest, BlobUsage::empty()).await;
        let id = blob.id();
        assert_eq!(test_hooks::live_runs() - runs, 1);

        drop(blob);
        settle().await;
        assert!(device.saw(&Call::DestroyBlob(id)));
        assert_eq!(test_hooks::live_runs() - runs, 1);

        gate.send(()).expect("the device is parked on it");
        settle().await;
        assert_eq!(test_hooks::live_runs(), runs);
    });
}

#[test]
fn a_blob_the_device_would_not_destroy_stays_pinned() {
    test_hooks::install();
    let (shared, control, submit) = channels(true);
    let device = FakeGpu3d::new();
    device.refuse_destroy.store(true, Ordering::Relaxed);
    let mut views = ViewTable::new();
    let mut ownership = opened_in(&shared, &mut views);
    let runs = test_hooks::live_runs();

    with_servers(&device, &shared, &control, &submit, async {
        let context = create_context(&ownership).await;
        let first = new_blob(&ownership, &context, BlobMemory::Guest, BlobUsage::empty()).await;
        let first_id = first.id();
        let _second = new_blob(&ownership, &context, BlobMemory::Guest, BlobUsage::empty()).await;
        assert_eq!(test_hooks::live_runs() - runs, 2);

        drop(first);
        settle().await;
        assert!(device.saw(&Call::DestroyBlob(first_id)));
        assert_eq!(test_hooks::live_runs() - runs, 2);

        close(&mut ownership, &mut views);
        settle().await;
    });

    let destroyed = device
        .calls()
        .iter()
        .filter(|call| matches!(call, Call::DestroyBlob(_)))
        .count();
    assert_eq!(destroyed, 2);
    assert_eq!(test_hooks::live_runs() - runs, 2);
}

#[test]
fn a_blob_the_device_would_not_unmap_stays_pinned() {
    test_hooks::install();
    let (shared, control, submit) = channels(true);
    let device = FakeGpu3d::new();
    device.refuse_unmap.store(true, Ordering::Relaxed);
    let mut views = ViewTable::new();
    let mut ownership = opened_in(&shared, &mut views);
    let runs = test_hooks::live_runs();

    with_servers(&device, &shared, &control, &submit, async {
        let context = create_context(&ownership).await;
        let first = new_blob(
            &ownership,
            &context,
            BlobMemory::Host3dGuest,
            BlobUsage::MAPPABLE,
        )
        .await;
        let first_id = first.id();
        let second = new_blob(
            &ownership,
            &context,
            BlobMemory::Host3dGuest,
            BlobUsage::MAPPABLE,
        )
        .await;
        let _m1 = place(&first).await;
        let _m2 = place(&second).await;
        assert_eq!(test_hooks::live_runs() - runs, 2);

        drop(first);
        settle().await;
        assert!(device.saw(&Call::UnmapBlob(first_id)));
        assert_eq!(test_hooks::live_runs() - runs, 2);

        close(&mut ownership, &mut views);
        settle().await;
    });

    assert!(
        !device
            .calls()
            .iter()
            .any(|call| matches!(call, Call::DestroyBlob(_)))
    );
    assert_eq!(test_hooks::live_runs() - runs, 2);
}

#[test]
fn a_command_buffer_is_kept_only_when_the_device_never_answered() {
    test_hooks::install();
    let (shared, control, submit) = channels(true);
    let device = FakeGpu3d::new();
    let ownership = opened(&shared);
    let runs = test_hooks::live_runs();

    with_servers(&device, &shared, &control, &submit, async {
        let refused = create_context(&ownership).await;
        let unanswered = create_context(&ownership).await;

        *device.refuse_context.lock().expect("no test panics here") = Some(refused.id());
        assert_eq!(submit_on(&refused, 0, Some(1)).await, Ok(()));
        settle().await;
        assert_eq!(test_hooks::live_runs(), runs);

        device
            .transport_fault_submits
            .store(true, Ordering::Relaxed);
        assert_eq!(submit_on(&unanswered, 0, Some(2)).await, Ok(()));
        settle().await;
        assert_eq!(test_hooks::live_runs() - runs, 1);
        assert_eq!(retired(&unanswered, 0), 2);
    });
}

#[test]
fn a_blobs_backing_is_kept_only_when_the_create_was_never_answered() {
    test_hooks::install();
    let (shared, control, submit) = channels(true);
    let device = FakeGpu3d::new();
    let ownership = opened(&shared);
    let runs = test_hooks::live_runs();

    with_servers(&device, &shared, &control, &submit, async {
        let context = create_context(&ownership).await;

        *device.fail_creates.lock().expect("no test panics here") = Some(false);
        let refused = request_blob(
            &ownership,
            &context,
            BlobMemory::Guest,
            BlobUsage::empty(),
            0,
        )
        .await;
        assert!(refused.is_err());
        settle().await;
        assert_eq!(test_hooks::live_runs(), runs);

        *device.fail_creates.lock().expect("no test panics here") = Some(true);
        let unanswered = request_blob(
            &ownership,
            &context,
            BlobMemory::Guest,
            BlobUsage::empty(),
            0,
        )
        .await;
        assert!(unanswered.is_err());
        settle().await;
        assert_eq!(test_hooks::live_runs() - runs, 1);
    });
}

#[cfg(feature = "wasmtime-runtime")]
mod component_host {
    use wasmtime::component::Resource;

    use super::*;
    use crate::wasmtime_adapter::bindings::gpu::bindings::helios::system::gpu as contract;
    use crate::wasmtime_adapter::component_host::service::test_store;
    use crate::wasmtime_adapter::component_host::service::{BlobHandle, CommandBufferHandle};

    fn synthetic_blob(
        shared_service: &Arc<Gpu3dShared>,
        data: &test_store::TestStoreData,
        id: u32,
        size: u64,
    ) -> GpuBlob {
        let session_state = data.device.gpu().session_ref().unwrap().state().clone();
        let shared = Arc::new(BlobShared::new(
            BlobId::new(id),
            size,
            BlobMemory::Host3d,
            BlobUsage::SHAREABLE,
            shared_service.release.clone(),
        ));
        GpuBlob::new(shared_service.clone(), session_state, shared)
    }

    fn synthetic_context(
        shared_service: &Arc<Gpu3dShared>,
        data: &test_store::TestStoreData,
        id: u32,
        rings: RingCount,
    ) -> GpuContext {
        let session_state = data.device.gpu().session_ref().unwrap().state().clone();
        let shared = Arc::new(ContextShared::new(
            ContextId::new(id),
            CAPSET,
            rings,
            shared_service.release.clone(),
        ));
        GpuContext::new(shared_service.clone(), session_state, shared)
    }

    #[test]
    fn exported_images_survive_their_source_session_but_stale_blobs_cannot_export() {
        test_hooks::install();
        let (shared, _control, _submit) = channels(true);
        let service = Gpu3dService::from_shared(shared.clone());
        let mut data = test_store::store_data(&service);
        let session = data
            .device
            .open_gpu(&service, &mut data.views, test_caps::gpu())
            .expect("the engine renders");
        let gpu_blob = synthetic_blob(&shared, &data, 9, 4096);
        let probe = gpu_blob.clone();
        let blob = data
            .table
            .push(BlobHandle {
                blob: gpu_blob,
                backing: None,
                mapped: None,
            })
            .unwrap();
        let layout = contract::ImageLayout {
            width: 8,
            height: 8,
            format: contract::PixelFormat::Rgba8888,
            offset: 32,
            stride: 64,
        };
        let image = contract::HostBlob::image(&mut data, Resource::new_borrow(blob.rep()), layout)
            .unwrap()
            .unwrap();
        assert!(probe.is_retained());
        reopen(&mut data, &service, session);
        let actual =
            contract::Host::describe_image(&mut data, Resource::new_borrow(image.rep())).unwrap();
        assert_eq!(
            (actual.width, actual.height, actual.offset, actual.stride),
            (8, 8, 32, 64)
        );
        assert!(matches!(
            contract::HostBlob::image(&mut data, Resource::new_borrow(blob.rep()), layout).unwrap(),
            Err(contract::Error::SessionEnded)
        ));
        contract::HostBlob::drop(&mut data, blob).unwrap();
        assert!(probe.is_retained());
        contract::HostImage::drop(&mut data, image).unwrap();
        assert!(!probe.is_retained());
    }

    fn shown(data: &mut test_store::TestStoreData, page: u64) -> (Buffer, crate::ViewId) {
        let group = data.device.gpu().views().expect("the session is open");
        let buffer = pinned(4096);
        let view = data
            .views
            .show_buffer(memory(), pages(page, 1), &buffer, Some(group))
            .expect("the span is free");
        (buffer, view)
    }

    fn reopen(
        data: &mut test_store::TestStoreData,
        service: &Gpu3dService,
        first: super::super::SessionId,
    ) -> super::super::SessionId {
        data.device
            .gpu_mut()
            .close(first, &mut data.views)
            .expect("the test pool refills anything");
        data.device
            .open_gpu(service, &mut data.views, test_caps::gpu())
            .expect("the engine renders")
    }

    #[test]
    fn a_command_buffer_that_outlived_its_session_is_refused() {
        test_hooks::install();
        let (shared, _control, _submit) = channels(true);
        let service = Gpu3dService::from_shared(shared.clone());
        let mut data = test_store::store_data(&service);
        let first = data
            .device
            .open_gpu(&service, &mut data.views, test_caps::gpu())
            .expect("the engine renders");
        let (buffer, view) = shown(&mut data, 0);
        let commands = data
            .table
            .push(CommandBufferHandle {
                session: first,
                buffer,
                view,
            })
            .expect("the table has room");
        let (_storage, backing) = shown(&mut data, 1);
        let gpu_blob = synthetic_blob(&shared, &data, 9, 4096);
        let blob = data
            .table
            .push(BlobHandle {
                blob: gpu_blob,
                backing: Some(backing),
                mapped: None,
            })
            .expect("the table has room");

        let live = reopen(&mut data, &service, first);
        assert!(data.views.is_empty(), "the end ended the session's views");
        assert_ne!(live, first, "a new session is a new identity");

        let refused = data
            .command_range(&commands, 0, 16, live)
            .expect("the handle is still in the table");
        assert!(matches!(refused, Err(contract::Error::SessionEnded)));
        assert!(contract::HostCommandBuffer::drop(&mut data, commands).is_ok());
        assert!(contract::HostBlob::drop(&mut data, blob).is_ok());

        let (buffer, view) = shown(&mut data, 2);
        let commands = data
            .table
            .push(CommandBufferHandle {
                session: live,
                buffer,
                view,
            })
            .expect("the table has room");
        contract::HostCommandBuffer::drop(&mut data, commands)
            .expect("a live session's buffer ends its view");
        assert!(!data.views.is_shown(view));
    }

    #[test]
    fn a_context_opens_fence_streams_only_for_a_live_session_and_its_own_rings() {
        test_hooks::install();
        let (shared, _control, _submit) = channels(true);
        let service = Gpu3dService::from_shared(shared.clone());
        let mut data = test_store::store_data(&service);
        let first = data
            .device
            .open_gpu(&service, &mut data.views, test_caps::gpu())
            .expect("the engine renders");
        let rings = RingCount::new(2).expect("two rings are in range");
        let stale_ctx = synthetic_context(&shared, &data, 4, rings);
        let stale = data
            .table
            .push(test_store::context_handle(stale_ctx))
            .expect("the table has room");

        let _live = reopen(&mut data, &service, first);
        let live_ctx = synthetic_context(&shared, &data, 5, rings);
        let live_context = data
            .table
            .push(test_store::context_handle(live_ctx))
            .expect("the table has room");

        let engine =
            wasmtime::Engine::new(&wasmtime::Config::new()).expect("the host engine builds");
        let mut store = wasmtime::Store::new(&engine, data);
        type GpuAccess<'a> = wasmtime::component::Access<
            'a,
            test_store::TestStoreData,
            wasmtime::component::HasSelf<test_store::TestStoreData>,
        >;
        use wasmtime::AsContextMut;
        let mut fences = |context: &Resource<_>, ring: u8| {
            contract::HostContextWithStore::fences(
                GpuAccess::new(store.as_context_mut(), |data| data),
                Resource::new_borrow(context.rep()),
                ring,
            )
            .expect("an answer, not a trap")
            .map(|_| ())
        };
        assert_eq!(fences(&stale, 0), Err(contract::Error::SessionEnded));
        assert_eq!(fences(&live_context, 2), Err(contract::Error::BadRing));
        assert_eq!(fences(&live_context, 1), Ok(()));
        assert_eq!(fences(&live_context, 0), Ok(()));
    }

    fn authority_with(classes: crate::DeviceClassRights) -> crate::ProcessAuthority {
        let mut authority = crate::ProcessAuthority::empty();
        authority.grant_device_classes(classes);
        authority
    }

    #[test]
    fn ordinary_program_is_refused_the_gpu_as_if_there_were_none() {
        test_hooks::install();
        let (shared, _control, _submit) = channels(true);
        let service = Gpu3dService::from_shared(shared);

        for authority in [
            crate::ProcessAuthority::empty(),
            crate::ProcessAuthority::root(),
            authority_with(crate::DeviceClassRights::all() - crate::DeviceClassRights::GPU),
        ] {
            let mut data = test_store::store_data_authorized(authority, |runtime_state| {
                runtime_state.install_gpu3d_service(service.clone());
            });
            let answer = <test_store::TestStoreData as contract::Host>::open(&mut data)
                .expect("a refusal is an answer, not a trap");
            assert!(matches!(answer, Err(contract::Error::Unavailable)));
            assert!(!data.device.gpu().is_open());
        }

        let mut absent =
            test_store::store_data_authorized(crate::ProcessAuthority::empty(), |_| {});
        let none = <test_store::TestStoreData as contract::Host>::open(&mut absent)
            .expect("a machine with no 3D service answers");
        assert!(matches!(none, Err(contract::Error::Unavailable)));
    }

    #[test]
    fn a_program_holding_the_gpu_class_opens_the_engine() {
        test_hooks::install();
        let (shared, _control, _submit) = channels(true);
        let service = Gpu3dService::from_shared(shared);
        let mut data = test_store::store_data_authorized(
            authority_with(crate::DeviceClassRights::GPU),
            |runtime_state| {
                runtime_state.install_gpu3d_service(service.clone());
            },
        );

        let first = <test_store::TestStoreData as contract::Host>::open(&mut data)
            .expect("the open is answered")
            .expect("the GPU class opens the engine");
        let second = <test_store::TestStoreData as contract::Host>::open(&mut data)
            .expect("the open is answered")
            .expect("a second handle is another hold on the session");
        assert!(data.device.gpu().is_open());

        contract::HostGpu::drop(&mut data, first).expect("the drop is answered");
        assert!(data.device.gpu().is_open());
        contract::HostGpu::drop(&mut data, second).expect("the drop is answered");
        assert!(!data.device.gpu().is_open());
    }
}

#[test]
fn waiting_for_a_retired_fence_does_not_need_a_new_event() {
    test_hooks::install();
    let (shared, control, submit) = channels(true);
    let device = FakeGpu3d::new();
    let ownership = opened(&shared);
    with_servers(&device, &shared, &control, &submit, async {
        let context = request_context(&ownership, CAPSET, 2).await.unwrap();
        context
            .shared()
            .timeline(RingIndex::new(0).unwrap())
            .unwrap()
            .record_submitted(FenceId::new(5));
        context
            .shared()
            .timeline(RingIndex::new(0).unwrap())
            .unwrap()
            .retire(5, 0);
        assert_eq!(context.wait(0, 3).await, Ok(()));
        assert_eq!(context.wait(0, 0).await, Ok(()));
        assert_eq!(
            context.wait(0, 6).await,
            Err(Gpu3dServiceError::UnsubmittedFence)
        );
        assert_eq!(
            context.wait(1, 5).await,
            Err(Gpu3dServiceError::UnsubmittedFence)
        );
        assert_eq!(context.wait(2, 0).await, Err(Gpu3dServiceError::BadRing));
    });
}

struct FenceWake(AtomicUsize);

impl Wake for FenceWake {
    fn wake(self: WakeArc<Self>) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

#[test]
fn a_fence_wait_is_woken_by_retirement_and_not_completed_by_an_earlier_point() {
    test_hooks::install();
    let (shared, control, submit) = channels(true);
    let device = FakeGpu3d::new();
    let ownership = opened(&shared);
    let context = with_servers(&device, &shared, &control, &submit, async {
        create_context(&ownership).await
    });
    let timeline = context
        .shared()
        .timeline(RingIndex::new(0).unwrap())
        .unwrap();
    timeline.record_submitted(FenceId::new(5));
    let wakes = WakeArc::new(FenceWake(AtomicUsize::new(0)));
    let waker = Waker::from(wakes.clone());
    let mut cx = TaskContext::from_waker(&waker);
    let mut wait = pin!(context.wait(0, 5));
    assert!(wait.as_mut().poll(&mut cx).is_pending());
    timeline.retire(3, 0);
    assert!(wakes.0.load(Ordering::Relaxed) > 0);
    assert!(wait.as_mut().poll(&mut cx).is_pending());
    wakes.0.store(0, Ordering::Relaxed);
    timeline.retire(5, 0);
    assert!(wakes.0.load(Ordering::Relaxed) > 0);
    assert_eq!(wait.as_mut().poll(&mut cx), Poll::Ready(Ok(())));
}

#[test]
fn ending_a_session_wakes_a_fence_wait_whose_submission_never_retired() {
    test_hooks::install();
    let (shared, control, submit) = channels(true);
    let device = FakeGpu3d::new();
    let ownership = opened(&shared);
    let context = with_servers(&device, &shared, &control, &submit, async {
        create_context(&ownership).await
    });
    context
        .shared()
        .timeline(RingIndex::new(0).unwrap())
        .unwrap()
        .record_submitted(FenceId::new(1));
    let wakes = WakeArc::new(FenceWake(AtomicUsize::new(0)));
    let waker = Waker::from(wakes.clone());
    let mut cx = TaskContext::from_waker(&waker);
    let mut wait = pin!(context.wait(0, 1));
    assert!(wait.as_mut().poll(&mut cx).is_pending());
    drop(ownership);
    assert!(wakes.0.load(Ordering::Relaxed) > 0);
    assert_eq!(
        wait.as_mut().poll(&mut cx),
        Poll::Ready(Err(Gpu3dServiceError::SessionEnded))
    );
}

#[test]
fn faulting_a_context_does_not_report_its_retired_fences_as_successful() {
    test_hooks::install();
    let (shared, control, submit) = channels(true);
    let device = FakeGpu3d::new();
    let ownership = opened(&shared);
    let context = with_servers(&device, &shared, &control, &submit, async {
        create_context(&ownership).await
    });
    context
        .shared()
        .timeline(RingIndex::new(0).unwrap())
        .unwrap()
        .record_submitted(FenceId::new(1));
    block_on(async {
        let mut wait = pin!(context.wait(0, 1));
        assert!(poll_once(wait.as_mut()).await.is_none());
        context.shared().fault(0);
        assert_eq!(wait.await, Err(Gpu3dServiceError::DeviceFault));
        assert_eq!(
            context.wait(0, 1).await,
            Err(Gpu3dServiceError::DeviceFault)
        );
    });
}

#[test]
fn a_submission_keeps_its_signal_source_alive_until_retirement() {
    test_hooks::install();
    let (shared, control, submit) = channels(true);
    let device = FakeGpu3d::new();
    let ownership = opened(&shared);
    with_servers(&device, &shared, &control, &submit, async {
        let context = create_context(&ownership).await;
        let source = TimelineSource::new(0);
        let reader = source.reader();
        let (release, hold) = oneshot::channel();
        *device.submit_hold.lock().unwrap() = Some(hold);
        assert_eq!(
            context
                .submit(
                    0,
                    page_commands(),
                    Some(SubmitCompletion {
                        fence: FenceId::new(1),
                        signals: alloc::vec![CompletionSignal {
                            source: source.clone(),
                            value: 7,
                        }],
                    }),
                )
                .await,
            Ok(())
        );
        drop(source);
        let mut wait = pin!(reader.wait(7));
        assert!(poll_once(wait.as_mut()).await.is_none());
        assert_eq!(reader.value(), Ok(0));
        release.send(()).unwrap();
        assert_eq!(wait.await, Ok(()));
        assert_eq!(reader.wait(8).await, Err(TimelineError::Closed));
    });
}

#[test]
fn a_context_fault_fails_signals_while_an_earlier_submission_is_still_pending() {
    test_hooks::install();
    let (shared, control, submit) = channels(true);
    let device = FakeGpu3d::new();
    let ownership = opened(&shared);
    with_servers(&device, &shared, &control, &submit, async {
        let context = create_context(&ownership).await;
        let source = TimelineSource::new(0);
        let reader = source.reader();
        let (release, hold) = oneshot::channel();
        *device.submit_hold.lock().unwrap() = Some(hold);
        assert_eq!(
            context
                .submit(
                    0,
                    page_commands(),
                    Some(SubmitCompletion {
                        fence: FenceId::new(1),
                        signals: alloc::vec![CompletionSignal { source, value: 1 }],
                    }),
                )
                .await,
            Ok(())
        );
        *device.refuse_context.lock().unwrap() = Some(context.id());
        assert_eq!(submit_on(&context, 0, Some(2)).await, Ok(()));
        assert_eq!(reader.wait(1).await, Err(TimelineError::Failed));
        release.send(()).unwrap();
        settle().await;
        assert_eq!(reader.value(), Err(TimelineError::Failed));
    });
}
