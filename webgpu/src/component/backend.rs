//! Owned wgpu-core resources match the component's independently owned handles.

use crate::runtime::{DeviceLoss, open_instance};
use helios_api::sync::{Timeline, TimelineError, wait_all};
use helios_venus::helios;
use std::sync::Arc;
use wgpu_core::{device, instance};

pub type Buffer = Arc<wgpu_core::resource::Buffer>;
pub type Texture = Arc<wgpu_core::resource::Texture>;
pub type TextureView = Arc<wgpu_core::resource::TextureView>;
pub type Sampler = Arc<wgpu_core::resource::Sampler>;
pub type QuerySet = Arc<wgpu_core::resource::QuerySet>;
pub type ShaderModule = Arc<wgpu_core::pipeline::ShaderModule>;
pub type ComputePipeline = Arc<wgpu_core::pipeline::ComputePipeline>;
pub type RenderPipeline = Arc<wgpu_core::pipeline::RenderPipeline>;
pub type BindGroup = Arc<wgpu_core::binding_model::BindGroup>;
pub type BindGroupLayout = Arc<wgpu_core::binding_model::BindGroupLayout>;
pub type PipelineLayout = Arc<wgpu_core::binding_model::PipelineLayout>;
pub type RenderBundle = Arc<wgpu_core::command::RenderBundle>;
pub type CommandBuffer = Arc<wgpu_core::command::CommandBuffer>;

pub struct Runtime(pub Arc<instance::Instance>);
impl Runtime {
    pub fn open() -> Result<Self, wgpu_hal::InstanceError> {
        Ok(Self(instance::Instance::from_hal_instance::<
            wgpu_hal::api::Vulkan,
        >("helios-webgpu".into(), open_instance()?)))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CompletionError {
    #[error("Vulkan completion failed: {0}")]
    Vulkan(#[from] ash::vk::Result),
    #[error(transparent)]
    Timeline(#[from] TimelineError),
    #[error(transparent)]
    Poll(#[from] device::WaitIdleError),
    #[error(transparent)]
    Submit(#[from] device::queue::QueueSubmitError),
}

pub struct Device {
    pub raw: Arc<device::Device>,
    pub queue: Arc<device::queue::Queue>,
    loss: DeviceLoss,
}

impl Device {
    pub fn request(
        adapter: &Arc<instance::Adapter>,
        descriptor: &device::DeviceDescriptor<'_>,
    ) -> Result<Self, instance::RequestDeviceError> {
        let (raw, queue) = adapter.request_device(descriptor)?;
        let (loss, notify) = DeviceLoss::new();
        raw.set_device_lost_closure(Box::new(notify));
        Ok(Self { raw, queue, loss })
    }

    pub(crate) fn loss(&self) -> DeviceLoss {
        self.loss.clone()
    }

    pub async fn destroy(&self) -> Result<(), CompletionError> {
        let completion = self.completion();
        self.raw.destroy();
        let completion = async {
            let timeline = completion?;
            wait_all(&[timeline.point(1)], None).await?;
            Ok::<(), CompletionError>(())
        }
        .await;
        // Poll even after a failed wait: native device loss can release its
        // notification and mapping callbacks during maintenance.
        let maintenance = self.raw.poll(wgpu_types::PollType::Poll);
        completion?;
        maintenance?;
        Ok(())
    }

    pub fn completion(&self) -> Result<Timeline, CompletionError> {
        // SAFETY: Runtime creates only Venus Vulkan devices. The guard is
        // dropped before the caller can await the returned timeline.
        let queue = unsafe { self.queue.clone().as_hal::<wgpu_hal::api::Vulkan>() }
            .expect("Helios WebGPU queues use Vulkan");
        Ok(unsafe { helios::queue_completion(queue.as_raw()) }?)
    }

    pub async fn submitted_work_done(&self) -> Result<(), CompletionError> {
        self.queue.submit(&[]).map_err(|(_, error)| error)?;
        let timeline = self.completion()?;
        wait_all(&[timeline.point(1)], None).await?;
        self.raw.poll(wgpu_types::PollType::Poll)?;
        Ok(())
    }
}
