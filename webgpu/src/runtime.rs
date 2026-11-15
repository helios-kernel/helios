//! Device ownership and async completion for the WebGPU component.
//!
//! Vulkan serializes submission inside the Venus connection. Host waits use
//! shared timelines and release that submission lock before suspension. Error
//! callbacks send to device-owned channels; they never enter component state.

use core::error::Error as StdError;
use core::ops::Range;
use std::sync::{Arc, OnceLock};

use async_channel::Receiver;
use helios_api::sync::{Timeline, TimelineError, wait_all};
use helios_venus::{driver, helios};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Instance(#[from] wgpu_hal::InstanceError),
    #[error(transparent)]
    Adapter(#[from] wgpu::RequestAdapterError),
    #[error(transparent)]
    Device(#[from] wgpu::RequestDeviceError),
    #[error("Vulkan completion failed: {0}")]
    Vulkan(#[from] ash::vk::Result),
    #[error("GPU completion failed: {0}")]
    Timeline(#[from] TimelineError),
    #[error(transparent)]
    Poll(#[from] wgpu::PollError),
    #[error(transparent)]
    Map(#[from] wgpu::BufferAsyncError),
    #[error("wgpu dropped a mapping callback without a result")]
    MappingCallbackClosed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GpuErrorKind {
    Validation,
    OutOfMemory,
    Internal,
}

/// A component-boundary error preserves WebGPU's kind and diagnostic chain.
#[derive(Clone, Debug, thiserror::Error)]
#[error("{message}")]
pub struct GpuError {
    pub kind: GpuErrorKind,
    pub message: String,
    pub causes: Vec<String>,
}

impl From<wgpu::Error> for GpuError {
    fn from(error: wgpu::Error) -> Self {
        let kind = match &error {
            wgpu::Error::Validation { .. } => GpuErrorKind::Validation,
            wgpu::Error::OutOfMemory { .. } => GpuErrorKind::OutOfMemory,
            wgpu::Error::Internal { .. } => GpuErrorKind::Internal,
        };
        let mut causes = Vec::new();
        let mut source = error.source();
        while let Some(cause) = source {
            causes.push(cause.to_string());
            source = cause.source();
        }
        Self {
            kind,
            message: error.to_string(),
            causes,
        }
    }
}

pub(crate) fn open_instance() -> Result<wgpu_hal::vulkan::Instance, wgpu_hal::InstanceError> {
    let descriptor = wgpu_hal::InstanceDescriptor {
        name: "helios-webgpu",
        flags: wgpu::InstanceFlags::default(),
        memory_budget_thresholds: Default::default(),
        backend_options: Default::default(),
        telemetry: None,
        display: None,
    };
    // SAFETY: the Venus factory gives every instance an independent
    // context. wgpu owns the HAL instance and its complete object tree.
    unsafe {
        wgpu_hal::vulkan::Instance::init_from_entry(driver::entry::<helios::Context>(), &descriptor)
    }
}

pub struct Runtime {
    instance: wgpu::Instance,
}

impl Runtime {
    pub async fn open() -> Result<Self, Error> {
        let hal = open_instance()?;
        let instance = unsafe { wgpu::Instance::from_hal::<wgpu_hal::api::Vulkan>(hal) };
        Ok(Self { instance })
    }

    pub async fn request_adapter(
        &self,
        options: &wgpu::RequestAdapterOptions<'_, '_>,
    ) -> Result<wgpu::Adapter, Error> {
        Ok(self.instance.request_adapter(options).await?)
    }
}

#[derive(Clone, Debug)]
pub struct DeviceLost {
    pub reason: wgpu::DeviceLostReason,
    pub message: String,
}

/// A device and its single WebGPU queue, with component-owned notifications.
pub struct Device {
    raw: wgpu::Device,
    queue: wgpu::Queue,
    errors: Receiver<GpuError>,
    loss: DeviceLoss,
}

impl Device {
    pub async fn request(
        adapter: &wgpu::Adapter,
        descriptor: &wgpu::DeviceDescriptor<'_>,
    ) -> Result<Self, Error> {
        let (raw, queue) = adapter.request_device(descriptor).await?;
        let (error_sender, errors) = async_channel::unbounded();
        raw.on_uncaptured_error(Arc::new(move |error| {
            // Closure means the component no longer observes this device.
            let _ = error_sender.try_send(GpuError::from(error));
        }));
        let (loss, notify) = DeviceLoss::new();
        raw.set_device_lost_callback(notify);
        Ok(Self {
            raw,
            queue,
            errors,
            loss,
        })
    }

    pub fn raw(&self) -> &wgpu::Device {
        &self.raw
    }

    pub fn queue(&self) -> &wgpu::Queue {
        &self.queue
    }

    pub fn errors(&self) -> Receiver<GpuError> {
        self.errors.clone()
    }

    pub async fn lost(&self) -> DeviceLost {
        self.loss.wait().await
    }

    /// Mark prior submissions without waiting or retaining a HAL guard.
    pub fn completion(&self) -> Result<Timeline, Error> {
        // SAFETY: Runtime always creates Venus Vulkan devices. The guard is
        // used only to submit a marker; it is dropped before any async wait.
        let hal = unsafe { self.raw.as_hal::<wgpu_hal::api::Vulkan>() }
            .expect("Helios WebGPU devices use the Vulkan backend");
        Ok(unsafe { helios::queue_completion(hal.raw_queue()) }?)
    }

    pub async fn submitted_work_done(&self) -> Result<(), Error> {
        // wgpu defers queue.write_* staging until a submit. This also makes
        // those writes precede the marker when no command buffer follows them.
        self.queue.submit([]);
        let timeline = self.completion()?;
        wait_all(&[timeline.point(1)], None).await?;
        self.raw.poll(wgpu::PollType::Poll)?;
        Ok(())
    }

    pub async fn map(
        &self,
        buffer: &wgpu::Buffer,
        mode: wgpu::MapMode,
        range: Range<u64>,
    ) -> Result<(), Error> {
        let (sender, answer) = async_channel::bounded(1);
        buffer.slice(range).map_async(mode, move |result| {
            let _ = sender.try_send(result);
        });
        self.submitted_work_done().await?;
        answer
            .recv()
            .await
            .map_err(|_| Error::MappingCallbackClosed)??;
        Ok(())
    }
}

/// Closure of the notification channel broadcasts loss to every waiter.
pub(crate) struct DeviceLoss {
    value: Arc<OnceLock<DeviceLost>>,
    wake: Receiver<()>,
}

impl DeviceLoss {
    pub(crate) fn new() -> (
        Self,
        impl Fn(wgpu::DeviceLostReason, String) + Send + Sync + 'static,
    ) {
        let value = Arc::new(OnceLock::new());
        let (wake, receive) = async_channel::bounded(1);
        let state = value.clone();
        (
            Self {
                value,
                wake: receive,
            },
            move |reason, message| {
                let _ = state.set(DeviceLost { reason, message });
                wake.close();
            },
        )
    }

    pub(crate) async fn wait(&self) -> DeviceLost {
        let _ = self.wake.recv().await;
        self.value
            .get()
            .expect("device loss is published before notification closes")
            .clone()
    }
}
