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
        let mut descriptor = descriptor.clone();
        adapter.validate_device_descriptor(&mut descriptor)?;
        // SAFETY: this runtime creates Vulkan adapters exclusively. The HAL
        // handle is retained only during synchronous device initialization.
        let hal = unsafe { adapter.clone().as_hal::<wgpu_hal::api::Vulkan>() }
            .expect("Helios WebGPU adapters use Vulkan");
        let foreign = hal
            .physical_device_capabilities()
            .supports_extension(ash::ext::queue_family_foreign::NAME);
        // SAFETY: core validated the features and limits. The callback only
        // adds an advertised extension and changes no requested feature.
        let opened = unsafe {
            hal.open_with_callback(
                descriptor.required_features,
                &descriptor.required_limits,
                &descriptor.memory_hints,
                Some(Box::new(move |args| {
                    if foreign
                        && !args
                            .extensions
                            .contains(&ash::ext::queue_family_foreign::NAME)
                    {
                        args.extensions.push(ash::ext::queue_family_foreign::NAME);
                    }
                })),
            )
        }
        .map_err(device::DeviceError::from_hal)?;
        // SAFETY: this HAL device was created on this exact adapter with the
        // validated descriptor, and ownership passes to core.
        let (raw, queue) =
            unsafe { adapter.create_device_and_queue_from_hal(opened.into(), &descriptor) }?;
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
