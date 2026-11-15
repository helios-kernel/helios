//! Dedicated linear images exported to the compositor, separate from render targets.

use super::backend;
use ash::{Device as VulkanDevice, vk};
use helios_api::image::{Image, ImageLayout, PixelFormat};
use helios_api::{
    surface::{ImageSurface, PresentedFrame, SurfaceError},
    sync::Timeline,
};
use std::sync::Arc;
use wgpu_core::{command, device};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Device(#[from] device::DeviceError),
    #[error(transparent)]
    View(#[from] wgpu_core::resource::CreateTextureViewError),
    #[error(transparent)]
    EncoderState(#[from] command::EncoderStateError),
    #[error("presentation command encoding failed: {0}")]
    Encoder(command::CommandEncoderError),
    #[error(transparent)]
    Submit(#[from] device::queue::QueueSubmitError),
    #[error(transparent)]
    Completion(#[from] backend::CompletionError),
    #[error("Vulkan presentation failed: {0}")]
    Vulkan(#[from] vk::Result),
    #[error("presentation requires {0}")]
    MissingCapability(&'static str),
    #[error("canvas format {0:?} has no linear compositor representation")]
    Format(wgpu_types::TextureFormat),
    #[error("linear image layout exceeds the compositor's 32-bit address space")]
    Layout,
    #[error("canvas extent {width}x{height} is unsupported for the linear presentation format")]
    Extent { width: u32, height: u32 },
}

/// Owns an image and its dedicated memory. The core device outlives both.
/// Only unsubmitted images may be dropped directly; submitted images must be
/// retained by their frame until GPU completion. The exported SDK image owns
/// the renderer storage independently through scanout retirement.
pub struct LinearImage {
    device: Arc<wgpu_core::device::Device>,
    raw_device: VulkanDevice,
    image: vk::Image,
    memory: vk::DeviceMemory,
    exported: Image,
    extent: vk::Extent3D,
    queue_family: u32,
}

/// An immutable frame ready for compositor handoff. The queue independently
/// retains its allocation until completion, including when this value is dropped.
pub struct Frame {
    image: Arc<LinearImage>,
    ready: Timeline,
}

impl Frame {
    pub async fn present(&self, surface: &ImageSurface) -> Result<PresentedFrame, SurfaceError> {
        surface
            .present(self.image.exported(), self.ready.point(1))
            .await
    }
}

impl LinearImage {
    pub fn allocate(
        device: Arc<wgpu_core::device::Device>,
        width: u32,
        height: u32,
        format: wgpu_types::TextureFormat,
    ) -> Result<Self, Error> {
        let (format, pixel_format) = format_pair(format)?;
        // SAFETY: the component creates only Vulkan devices; the guard remains
        // within this synchronous allocation and is dropped before return.
        let hal = unsafe { device.clone().as_hal::<wgpu_hal::api::Vulkan>() }
            .expect("Helios WebGPU devices use Vulkan");
        for (extension, name) in [
            (
                ash::ext::queue_family_foreign::NAME,
                "VK_EXT_queue_family_foreign",
            ),
            (
                ash::ext::external_memory_dma_buf::NAME,
                "VK_EXT_external_memory_dma_buf",
            ),
        ] {
            if !hal.enabled_device_extensions().contains(&extension) {
                return Err(Error::MissingCapability(name));
            }
        }
        let instance = hal.shared_instance().raw_instance();
        let physical = hal.raw_physical_device();
        let handles = vk::ExternalMemoryHandleTypeFlags::DMA_BUF_EXT;
        let mut external =
            vk::PhysicalDeviceExternalImageFormatInfo::default().handle_type(handles);
        let info = vk::PhysicalDeviceImageFormatInfo2::default()
            .format(format)
            .ty(vk::ImageType::TYPE_2D)
            .tiling(vk::ImageTiling::LINEAR)
            .usage(vk::ImageUsageFlags::TRANSFER_DST)
            .push_next(&mut external);
        let mut external_properties = vk::ExternalImageFormatProperties::default();
        let mut properties =
            vk::ImageFormatProperties2::default().push_next(&mut external_properties);
        // SAFETY: the queried physical device belongs to the retained instance.
        unsafe {
            instance.get_physical_device_image_format_properties2(physical, &info, &mut properties)
        }?;
        let limits = properties.image_format_properties;
        if width == 0
            || height == 0
            || width > limits.max_extent.width
            || height > limits.max_extent.height
            || limits.max_extent.depth == 0
            || limits.max_mip_levels == 0
            || limits.max_array_layers == 0
            || !limits.sample_counts.contains(vk::SampleCountFlags::TYPE_1)
        {
            return Err(Error::Extent { width, height });
        }
        if !external_properties
            .external_memory_properties
            .external_memory_features
            .contains(vk::ExternalMemoryFeatureFlags::EXPORTABLE)
        {
            return Err(Error::MissingCapability("exportable linear DMA-BUF images"));
        }
        let raw_device = hal.raw_device().clone();
        let queue_family = hal.queue_family_index();
        let extent = vk::Extent3D {
            width,
            height,
            depth: 1,
        };
        let mut external_create =
            vk::ExternalMemoryImageCreateInfo::default().handle_types(handles);
        let info = vk::ImageCreateInfo::default()
            .image_type(vk::ImageType::TYPE_2D)
            .format(format)
            .extent(extent)
            .mip_levels(1)
            .array_layers(1)
            .samples(vk::SampleCountFlags::TYPE_1)
            .tiling(vk::ImageTiling::LINEAR)
            .usage(vk::ImageUsageFlags::TRANSFER_DST)
            .sharing_mode(vk::SharingMode::EXCLUSIVE)
            .initial_layout(vk::ImageLayout::UNDEFINED)
            .push_next(&mut external_create);
        // SAFETY: all create-info references live for the call; dimensions and
        // sample count satisfy the queried image-format properties.
        let image = unsafe { raw_device.create_image(&info, None) }?;
        let mut allocation = Allocation {
            raw_device: raw_device.clone(),
            image,
            memory: None,
        };
        let requirements = unsafe { raw_device.get_image_memory_requirements(image) };
        let memory_properties = unsafe { instance.get_physical_device_memory_properties(physical) };
        let memory_type = memory_properties
            .memory_types_as_slice()
            .iter()
            .enumerate()
            .filter(|(index, _)| requirements.memory_type_bits & (1 << index) != 0)
            .max_by_key(|(_, ty)| {
                ty.property_flags
                    .contains(vk::MemoryPropertyFlags::DEVICE_LOCAL)
            })
            .map(|(index, _)| index as u32)
            .ok_or(Error::MissingCapability(
                "a compatible linear-image memory type",
            ))?;
        let mut dedicated = vk::MemoryDedicatedAllocateInfo::default().image(image);
        let mut export = vk::ExportMemoryAllocateInfo::default().handle_types(handles);
        let memory_info = vk::MemoryAllocateInfo::default()
            .allocation_size(requirements.size)
            .memory_type_index(memory_type)
            .push_next(&mut dedicated)
            .push_next(&mut export);
        let memory = unsafe { raw_device.allocate_memory(&memory_info, None) }?;
        allocation.memory = Some(memory);
        unsafe { raw_device.bind_image_memory(image, memory, 0) }?;
        let subresource = vk::ImageSubresource::default().aspect_mask(vk::ImageAspectFlags::COLOR);
        let layout = unsafe { raw_device.get_image_subresource_layout(image, subresource) };
        let layout = image_layout(width, height, pixel_format, layout.offset, layout.row_pitch)?;
        // SAFETY: dedicated memory backs this live linear image at offset zero;
        // the layout comes from Vulkan. Submission and scanout are synchronized
        // by the frame owner before it passes this image to the compositor.
        let exported =
            unsafe { helios_venus::helios::export_image(raw_device.handle(), memory, layout) }?;
        drop(hal);
        // Move ownership out of the rollback guard only after export succeeds.
        allocation.image = vk::Image::null();
        allocation.memory = None;
        Ok(Self {
            device,
            raw_device,
            image,
            memory,
            exported,
            extent,
            queue_family,
        })
    }

    /// Submit a copy from a canvas texture and release it to display.
    ///
    /// # Safety
    /// `source` belongs to `device`, has this image's format and extent, one
    /// mip, layer and sample, and COPY_SRC | RENDER_ATTACHMENT usage.
    /// No other thread may submit or destroy the source during this call.
    /// This image belongs to `device` and has never been submitted.
    pub unsafe fn submit(
        self,
        device: &backend::Device,
        source: backend::Texture,
    ) -> Result<Frame, Error> {
        let (transition, error) = device.raw.create_command_encoder(&Default::default());
        if let Some(error) = error {
            return Err(error.into());
        }
        // A load/store pass preserves rendered contents and lets core initialize
        // untouched canvas storage before native copy commands can expose it.
        let (view, error) = source.create_view(&Default::default());
        if let Some(error) = error {
            return Err(error.into());
        }
        let (mut initialize, error) =
            transition.begin_render_pass(command::ResolvedRenderPassDescriptor {
                label: None,
                color_attachments: vec![Some(command::RenderPassColorAttachment {
                    view,
                    depth_slice: None,
                    resolve_target: None,
                    load_op: wgpu_types::LoadOp::Load,
                    store_op: wgpu_types::StoreOp::Store,
                })]
                .into(),
                depth_stencil_attachment: None,
                timestamp_writes: None,
                occlusion_query_set: None,
                multiview_mask: None,
            });
        if let Some(error) = error {
            return Err(Error::Encoder(error));
        }
        initialize.end()?;
        transition.transition_resources(
            std::iter::empty(),
            std::iter::once(wgpu_types::TextureTransition {
                texture: source.clone(),
                selector: None,
                state: wgpu_types::TextureUses::COPY_SRC,
            }),
        )?;
        let (transition, error) = transition.finish(&Default::default());
        if let Some((_, error)) = error {
            return Err(Error::Encoder(error));
        }
        let (copy, error) = device.raw.create_command_encoder(&Default::default());
        if let Some(error) = error {
            return Err(error.into());
        }
        // SAFETY: the caller guarantees a live Vulkan texture on this device.
        // Hold the snatch guard while recording its native image handle.
        let source_hal =
            unsafe { source.as_hal::<wgpu_hal::api::Vulkan>() }.ok_or(device::DeviceError::Lost)?;
        // SAFETY: the first command buffer establishes COPY_SRC; both buffers
        // execute in one submission. Core tracks the source in that submission,
        // and the completion closure below retains the destination allocation.
        let recorded = unsafe {
            copy.as_hal_mut::<wgpu_hal::api::Vulkan, _, _>(|encoder| {
                let encoder = encoder.ok_or(device::DeviceError::Lost)?;
                self.record_copy_and_release(encoder.raw_handle(), source_hal.raw_handle());
                Ok::<(), device::DeviceError>(())
            })
        };
        drop(source_hal);
        recorded?;
        let (copy, error) = copy.finish(&Default::default());
        if let Some((_, error)) = error {
            return Err(Error::Encoder(error));
        }
        let image = Arc::new(self);
        let result = device.queue.submit(&[transition, copy]);
        // A submit error may be reported by maintenance after native submission.
        // Always transfer a reference to the queue before propagating the result.
        // Device stores a weak queue reference, so this creates no ownership cycle.
        let retained = image.clone();
        device
            .queue
            .on_submitted_work_done(Box::new(move || drop(retained)));
        result.map_err(|(_, error)| error)?;
        let ready = device.completion()?;
        Ok(Frame { image, ready })
    }

    pub fn exported(&self) -> &Image {
        &self.exported
    }
    pub fn raw(&self) -> vk::Image {
        self.image
    }
    pub fn extent(&self) -> vk::Extent3D {
        self.extent
    }
    pub fn queue_family(&self) -> u32 {
        self.queue_family
    }
    pub fn device(&self) -> &Arc<wgpu_core::device::Device> {
        &self.device
    }

    /// Record the first and only write to this presentation image.
    ///
    /// # Safety
    /// `commands` is recording on this device's queue family. `source` is a
    /// live, initialized image on this device with matching format and extent,
    /// one sample, and TRANSFER_SRC usage, in TRANSFER_SRC_OPTIMAL layout.
    /// This image has never been submitted. Both images and their memory must
    /// remain alive until submission completion. Submit the release before
    /// signaling the timeline supplied to the compositor.
    pub unsafe fn record_copy_and_release(&self, commands: vk::CommandBuffer, source: vk::Image) {
        let range = color_range();
        let prepare = vk::ImageMemoryBarrier::default()
            .old_layout(vk::ImageLayout::UNDEFINED)
            .new_layout(vk::ImageLayout::TRANSFER_DST_OPTIMAL)
            .src_queue_family_index(vk::QUEUE_FAMILY_IGNORED)
            .dst_queue_family_index(vk::QUEUE_FAMILY_IGNORED)
            .dst_access_mask(vk::AccessFlags::TRANSFER_WRITE)
            .image(self.image)
            .subresource_range(range);
        let layers = vk::ImageSubresourceLayers::default()
            .aspect_mask(vk::ImageAspectFlags::COLOR)
            .layer_count(1);
        let copy = vk::ImageCopy::default()
            .src_subresource(layers)
            .dst_subresource(layers)
            .extent(self.extent);
        let release = release_barrier(self.image, self.queue_family);
        // SAFETY: forwarded from the recording and resource lifetime contract.
        unsafe {
            self.raw_device.cmd_pipeline_barrier(
                commands,
                vk::PipelineStageFlags::TOP_OF_PIPE,
                vk::PipelineStageFlags::TRANSFER,
                vk::DependencyFlags::empty(),
                &[],
                &[],
                &[prepare],
            );
            self.raw_device.cmd_copy_image(
                commands,
                source,
                vk::ImageLayout::TRANSFER_SRC_OPTIMAL,
                self.image,
                vk::ImageLayout::TRANSFER_DST_OPTIMAL,
                &[copy],
            );
            self.raw_device.cmd_pipeline_barrier(
                commands,
                vk::PipelineStageFlags::TRANSFER,
                vk::PipelineStageFlags::BOTTOM_OF_PIPE,
                vk::DependencyFlags::empty(),
                &[],
                &[],
                &[release],
            );
        }
    }
}

fn color_range() -> vk::ImageSubresourceRange {
    vk::ImageSubresourceRange::default()
        .aspect_mask(vk::ImageAspectFlags::COLOR)
        .level_count(1)
        .layer_count(1)
}

fn release_barrier(image: vk::Image, queue_family: u32) -> vk::ImageMemoryBarrier<'static> {
    // Display scanout is a foreign queue, not a Vulkan queue in this driver.
    // A release makes the copy available externally; the compositor waits for
    // the submission timeline before consuming it. No swapchain is involved.
    vk::ImageMemoryBarrier::default()
        .src_access_mask(vk::AccessFlags::TRANSFER_WRITE)
        .old_layout(vk::ImageLayout::TRANSFER_DST_OPTIMAL)
        .new_layout(vk::ImageLayout::GENERAL)
        .src_queue_family_index(queue_family)
        .dst_queue_family_index(vk::QUEUE_FAMILY_FOREIGN_EXT)
        .image(image)
        .subresource_range(color_range())
}

impl Drop for LinearImage {
    fn drop(&mut self) {
        // SAFETY: the frame owner retains submitted images until GPU completion;
        // the SDK export retains storage for any later compositor access.
        unsafe {
            self.raw_device.destroy_image(self.image, None);
            self.raw_device.free_memory(self.memory, None);
        }
    }
}

struct Allocation {
    raw_device: VulkanDevice,
    image: vk::Image,
    memory: Option<vk::DeviceMemory>,
}
impl Drop for Allocation {
    fn drop(&mut self) {
        // SAFETY: construction has not submitted this image. Destroy its binding
        // before freeing the memory, including every partial-construction path.
        unsafe {
            self.raw_device.destroy_image(self.image, None);
            if let Some(memory) = self.memory {
                self.raw_device.free_memory(memory, None);
            }
        }
    }
}

fn format_pair(format: wgpu_types::TextureFormat) -> Result<(vk::Format, PixelFormat), Error> {
    match format {
        wgpu_types::TextureFormat::Bgra8Unorm => {
            Ok((vk::Format::B8G8R8A8_UNORM, PixelFormat::Bgra8888))
        }
        wgpu_types::TextureFormat::Rgba8Unorm => {
            Ok((vk::Format::R8G8B8A8_UNORM, PixelFormat::Rgba8888))
        }
        _ => Err(Error::Format(format)),
    }
}

fn image_layout(
    width: u32,
    height: u32,
    format: PixelFormat,
    offset: u64,
    stride: u64,
) -> Result<ImageLayout, Error> {
    Ok(ImageLayout {
        width,
        height,
        format,
        offset: offset.try_into().map_err(|_| Error::Layout)?,
        stride: stride.try_into().map_err(|_| Error::Layout)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn scanout_release_publishes_transfer_writes_to_foreign_ownership() {
        let barrier = release_barrier(vk::Image::null(), 3);
        assert_eq!(barrier.src_queue_family_index, 3);
        assert_eq!(barrier.dst_queue_family_index, vk::QUEUE_FAMILY_FOREIGN_EXT);
        assert_eq!(barrier.old_layout, vk::ImageLayout::TRANSFER_DST_OPTIMAL);
        assert_eq!(barrier.new_layout, vk::ImageLayout::GENERAL);
        assert_eq!(barrier.src_access_mask, vk::AccessFlags::TRANSFER_WRITE);
        assert!(barrier.dst_access_mask.is_empty());
        assert_eq!(
            barrier.subresource_range.aspect_mask,
            vk::ImageAspectFlags::COLOR
        );
        assert_eq!(barrier.subresource_range.level_count, 1);
        assert_eq!(barrier.subresource_range.layer_count, 1);
    }
    #[test]
    fn exported_layout_preserves_driver_padding_and_rejects_truncation() {
        let layout = image_layout(17, 3, PixelFormat::Bgra8888, 4096, 256).unwrap();
        assert_eq!(
            (layout.width, layout.height, layout.offset, layout.stride),
            (17, 3, 4096, 256)
        );
        assert!(image_layout(1, 1, PixelFormat::Bgra8888, 1_u64 << 32, 4).is_err());
        assert!(image_layout(1, 1, PixelFormat::Bgra8888, 0, 1_u64 << 32).is_err());
    }
}
