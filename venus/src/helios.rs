//! Helios transport with canonical stack suspension at Vulkan entry points.

#[cfg(all(target_arch = "wasm32", not(target_feature = "atomics")))]
compile_error!("the Venus shared ring requires -Ctarget-feature=+atomics");

use core::num::NonZeroU64;
use core::ptr::NonNull;
use core::time::Duration;
use std::sync::Arc;

use helios_api::bindings::helios::system::sync::{
    Error as TimelineError, SignalPoint as RawSignalPoint, SignalSource as RawSignalSource,
    Timeline as RawTimeline, TimelinePoint as RawTimelinePoint,
};
use helios_api::memory::{Block, BlockError};

use crate::capset::{self, Capset, CapsetError};
use crate::transport::{
    Completion, MappedBlob, MemoryResource, SignalTimeline, Timeline, TimelinePoint, Transport,
    TransportFactory,
};

mod bindings {
    wit_bindgen::generate!({
        path: "../wit",
        world: "venus-host",
        generate_all,
        sync: true,
        // Resource methods come from the SDK; only suspension-capable imports
        // need this Vulkan ABI's synchronous lowering.
        skip: [
            "[method]timeline.value",
            "[constructor]signal-source",
            "[method]signal-source.reader",
            "[method]signal-source.signal",
            "[method]signal-source.fail",
        ],
        with: {
            "helios:system/sync@0.1.0/timeline-point": helios_api::bindings::helios::system::sync::TimelinePoint,
            "helios:system/sync@0.1.0/signal-point": helios_api::bindings::helios::system::sync::SignalPoint,
            "helios:system/sync@0.1.0/signal-source": helios_api::bindings::helios::system::sync::SignalSource,
            "helios:system/sync@0.1.0/timeline": helios_api::bindings::helios::system::sync::Timeline,
            "helios:system/sync@0.1.0/error": helios_api::bindings::helios::system::sync::Error,
            "helios:system/gpu@0.1.0/image": helios_api::bindings::helios::system::gpu::Image,
            "helios:system/gpu@0.1.0/image-layout": helios_api::image::ImageLayout,
            "helios:system/gpu@0.1.0/pixel-format": helios_api::image::PixelFormat,
        },
    });
}

use bindings::helios::system::{gpu, memory, sync};
use bindings::wasi::clocks::monotonic_clock;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("GPU transport refused: {0}")]
    Gpu(#[from] gpu::Error),
    #[error("completion timeline refused: {0}")]
    Timeline(#[from] TimelineError),
    #[error(transparent)]
    Memory(#[from] BlockError),
    #[error(transparent)]
    Capset(#[from] CapsetError),
}

#[derive(Clone)]
pub struct Signal(Arc<RawSignalSource>);

#[derive(Clone)]
pub struct Reader(Arc<RawTimeline>);

impl SignalTimeline for Signal {
    type Error = Error;
    type Timeline = Reader;

    fn reader(&self) -> Reader {
        Reader(Arc::new(self.0.reader()))
    }
    fn signal(&self, value: u64) -> Result<(), Error> {
        self.0.signal(value).map_err(Error::from)
    }
    fn fail(&self) {
        self.0.fail();
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
            .map(|point| RawTimelinePoint {
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
    memory: DeviceMemory,
}

/// Renderer storage remains owned even when no CPU address is needed.
pub struct DeviceMemory {
    resource: gpu::Blob,
    size: u64,
    mapping: Option<CpuMapping>,
}

struct CpuMapping {
    block: Block,
    pointer: NonNull<u8>,
}

// SAFETY: ownership transfers the resource and its exclusive mapping together.
unsafe impl Send for DeviceMemory {}

// SAFETY: the resource is destroyed before mapping pages return to the allocator.
// The coherent pointer is derived before device ownership and never reborrowed.
unsafe impl MemoryResource for DeviceMemory {
    type Error = Error;

    fn map(&mut self) -> Result<NonNull<u8>, Error> {
        if let Some(mapping) = &self.mapping {
            return Ok(mapping.pointer);
        }
        let mut block = Block::zeroed(self.size)?;
        let pointer = NonNull::new(block.bytes_mut().as_mut_ptr()).expect("Block is nonempty");
        let span = block.span();
        self.resource.map_blob(memory::Span {
            offset: span.offset,
            length: span.length,
        })?;
        self.mapping = Some(CpuMapping { block, pointer });
        Ok(pointer)
    }
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
        self.memory.resource.resource_id()
    }

    fn pointer(&self) -> NonNull<u8> {
        self.memory.mapping.as_ref().unwrap().pointer
    }

    fn len(&self) -> usize {
        self.memory.mapping.as_ref().unwrap().block.len()
    }
}

impl Transport for Context {
    type Error = Error;
    type Blob = Blob;
    type Memory = DeviceMemory;
    type Signal = Signal;

    fn timeline(&self, initial: u64) -> Signal {
        Signal(Arc::new(RawSignalSource::new(initial)))
    }

    fn create_blob(&mut self, size: NonZeroU64, blob_id: u64) -> Result<Blob, Error> {
        let mut memory = self.export_memory(size, blob_id, true)?;
        memory.map()?;
        Ok(Blob { memory })
    }

    fn export_memory(
        &mut self,
        size: NonZeroU64,
        blob_id: u64,
        host_visible: bool,
    ) -> Result<DeviceMemory, Error> {
        let usage = if host_visible {
            gpu::BlobUsage::MAPPABLE
        } else {
            gpu::BlobUsage::empty()
        };
        let resource = self.gpu.create_blob(
            &self.context,
            gpu::BlobMemory::Host3d,
            usage,
            size.get(),
            blob_id,
            None,
        )?;
        self.context.attach(&resource)?;
        Ok(DeviceMemory {
            resource,
            size: size.get(),
            mapping: None,
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
                .map(|point| RawSignalPoint {
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

/// Export Vulkan memory as an owned image for compositor presentation.
///
/// The exported image retains its storage independently of the allocation and
/// does not change the application's Vulkan map/unmap state.
///
/// # Safety
/// `device` must originate from this module's `Context` factory and `memory`
/// must be a live allocation on it. `layout` must describe a linear image bound
/// to that allocation. The caller synchronizes rendering with presentation.
#[cfg(feature = "driver")]
pub unsafe fn export_image(
    device: ash::vk::Device,
    memory: ash::vk::DeviceMemory,
    layout: helios_api::image::ImageLayout,
) -> Result<helios_api::image::Image, ash::vk::Result> {
    // SAFETY: the caller supplies a live allocation from Context's entry table.
    unsafe {
        crate::driver::with_blob::<Context, _>(device, memory, |blob| {
            blob.resource
                .image(layout)
                .map(Into::into)
                .map_err(Error::from)
        })
    }
}

/// Submit a completion marker for all prior work on a Vulkan queue.
///
/// The returned timeline reaches 1 after rendering completes and can be passed
/// to `ImageSurface::present`. This Vulkan transport operation may suspend the
/// guest stack through canonical lowering; waiting on the result uses the SDK.
///
/// # Safety
/// `queue` must be live and originate from this module's `Context` factory.
#[cfg(feature = "driver")]
pub unsafe fn queue_completion(
    queue: ash::vk::Queue,
) -> Result<helios_api::sync::Timeline, ash::vk::Result> {
    // SAFETY: the caller supplies a live queue from Context's entry table.
    let source = unsafe { crate::driver::completion::<Context>(queue) }?;
    Ok(source.0.reader().into())
}
