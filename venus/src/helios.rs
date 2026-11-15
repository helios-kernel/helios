//! Helios transport with canonical stack suspension at Vulkan entry points.

#[cfg(all(target_arch = "wasm32", not(target_feature = "atomics")))]
compile_error!("the Venus shared ring requires -Ctarget-feature=+atomics");

use core::num::NonZeroU64;
use core::ptr::NonNull;
use core::time::Duration;
use std::sync::Arc;

use helios_api::memory::{Block, BlockError};

use crate::capset::{self, Capset, CapsetError};
use crate::transport::{
    Completion, MappedBlob, SignalTimeline, Timeline, TimelinePoint, Transport, TransportFactory,
};

mod bindings {
    wit_bindgen::generate!({
        path: "../wit",
        world: "venus-host",
        generate_all,
        async: false,
    });
}

use bindings::helios::system::{gpu, memory, sync};
use bindings::wasi::clocks::monotonic_clock;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("GPU transport refused: {0}")]
    Gpu(#[from] gpu::Error),
    #[error("completion timeline refused: {0}")]
    Timeline(#[from] sync::Error),
    #[error(transparent)]
    Memory(#[from] BlockError),
    #[error(transparent)]
    Capset(#[from] CapsetError),
}

#[derive(Clone)]
pub struct Signal(Arc<sync::SignalSource>);

#[derive(Clone)]
pub struct Reader(Arc<sync::Timeline>);

impl SignalTimeline for Signal {
    type Error = Error;
    type Timeline = Reader;

    fn new(initial: u64) -> Self {
        Self(Arc::new(sync::SignalSource::new(initial)))
    }
    fn reader(&self) -> Reader {
        Reader(Arc::new(self.0.reader()))
    }
    fn signal(&self, value: u64) -> Result<(), Error> {
        self.0.signal(value).map_err(Error::from)
    }
}

impl Timeline for Reader {
    type Error = Error;

    fn value(&self) -> Result<u64, Error> {
        self.0.value().map_err(Error::from)
    }

    fn wait(
        points: &[TimelinePoint<Self>],
        wait_all: bool,
        timeout: Option<Duration>,
    ) -> Result<bool, Error> {
        let deadline = timeout.map(|duration| {
            monotonic_clock::now()
                .saturating_add(u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX))
        });
        let points: Vec<_> = points
            .iter()
            .map(|point| sync::TimelinePoint {
                timeline: &point.timeline.0,
                value: point.value,
            })
            .collect();
        sync::wait(&points, wait_all, deadline).map_err(Error::from)
    }
}

/// A Venus context. The context resource drops before the GPU session.
pub struct Context {
    context: gpu::Context,
    gpu: gpu::Gpu,
}

impl Context {
    pub fn open(rings: u8, name: &str) -> Result<(Self, Capset), Error> {
        let gpu = gpu::open()?;
        let capset = Capset::decode(&gpu.capset(capset::ID, capset::VERSION)?)?;
        let context = gpu.create_context(capset::ID, rings, name)?;
        Ok((Self { context, gpu }, capset))
    }
}

impl TransportFactory for Context {
    type Transport = Self;

    fn create() -> Result<(Self, Capset), Error> {
        // Linux's VIRTGPU_CONTEXT_PARAM_NUM_RINGS and Mesa's Venus
        // max_timeline_count reserve 64 timelines, including CPU ring 0.
        Self::open(64, "helios-venus")
    }
}

/// The resource drops before the guest pages, restoring their ordinary
/// backing before the allocator can reuse the virtual address range.
pub struct Blob {
    resource: gpu::Blob,
    mapping: Block,
    pointer: NonNull<u8>,
}

// SAFETY: Blob exclusively owns its mapping and resource. Moving it to
// another guest thread transfers that ownership without exposing references.
unsafe impl Send for Blob {}

#[cfg(feature = "driver")]
pub struct SubmissionLock(bindings::helios::system::sync::RawMutex);

// SAFETY: the kernel mutex grants one guard at a time across guest tasks
// and threads. The guard resource releases it on drop; canonical lowering
// suspends the guest stack while acquisition waits in the host executor.
#[cfg(feature = "driver")]
unsafe impl crate::driver::SubmissionLock for SubmissionLock {
    type Guard<'a> = bindings::helios::system::sync::RawMutexGuard;

    fn new() -> Self {
        Self(bindings::helios::system::sync::RawMutex::new())
    }

    fn lock(&self) -> Self::Guard<'_> {
        self.0.lock()
    }
}

#[cfg(feature = "driver")]
impl crate::driver::Factory for Context {
    type Lock = SubmissionLock;
}

// SAFETY: `mapping` owns aligned guest pages. The resource's destruction
// removes every mapping before those pages are freed. `pointer` is obtained
// once, before renderer ownership; no slice is subsequently made here.
unsafe impl MappedBlob for Blob {
    fn resource_id(&self) -> u32 {
        self.resource.resource_id()
    }

    fn pointer(&self) -> NonNull<u8> {
        self.pointer
    }

    fn len(&self) -> usize {
        self.mapping.len()
    }
}

impl Transport for Context {
    type Error = Error;
    type Blob = Blob;
    type Signal = Signal;

    fn create_blob(&mut self, size: NonZeroU64, blob_id: u64) -> Result<Blob, Error> {
        let mut mapping = Block::zeroed(size.get())?;
        // Derive the pointer before device memory replaces these pages.
        let pointer = NonNull::new(mapping.bytes_mut().as_mut_ptr()).expect("Block is nonempty");
        let span = mapping.span();
        let resource = self.gpu.create_blob(
            &self.context,
            gpu::BlobMemory::Host3d,
            gpu::BlobUsage::MAPPABLE,
            size.get(),
            blob_id,
            None,
        )?;
        self.context.attach(&resource)?;
        resource.map_blob(memory::Span {
            offset: span.offset,
            length: span.length,
        })?;
        Ok(Blob {
            resource,
            mapping,
            pointer,
        })
    }

    fn execute(
        &mut self,
        commands: &[u8],
        ring: u8,
        completion: Option<Completion<'_, Signal>>,
    ) -> Result<(), Error> {
        let completion = completion.map(|completion| gpu::Completion {
            fence: completion.fence,
            signals: completion
                .signals
                .iter()
                .map(|point| sync::SignalPoint {
                    source: &point.source.0,
                    value: point.value,
                })
                .collect(),
        });
        self.context
            .execute(commands, ring, completion.as_ref())
            .map_err(Error::from)
    }
}
