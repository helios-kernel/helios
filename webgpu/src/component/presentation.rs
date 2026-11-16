//! Dedicated linear images exported to the compositor, separate from render targets.
//!
//! Everything here runs on the device timeline: allocating the image,
//! recording the copy and submitting it all reach the host.

use std::borrow::Cow;

use ash::{Device as VulkanDevice, vk};
use helios_api::image::{Image, ImageLayout, PixelFormat};
use wgpu_core::{command, device, global::Global, id};

use super::ids::{IdSpace, Release};

type Vulkan = wgpu_hal::api::Vulkan;

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
    #[error("presentation completion marker failed: {0}")]
    Completion(vk::Result),
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

/// Owns an image and its dedicated memory on the device that allocated it.
/// The device timeline retires a submitted image only after the queue has
/// finished with it, and tears the device down only after every image has
/// retired. The exported SDK image owns the renderer storage independently
/// through scanout retirement.
pub struct LinearImage {
    raw_device: VulkanDevice,
    image: vk::Image,
    memory: vk::DeviceMemory,
    extent: vk::Extent3D,
    queue_family: u32,
}

/// Temporary objects of one submission, released once it has been queued:
/// core keeps what the submission uses alive until the queue finishes.
struct Scratch<'a> {
    global: &'a Global,
    ids: &'a IdSpace,
    releases: Vec<Release>,
}

impl Drop for Scratch<'_> {
    fn drop(&mut self) {
        for release in self.releases.drain(..) {
            release.execute(self.global, self.ids);
        }
    }
}

impl Scratch<'_> {
    fn encoder(&mut self, device: id::DeviceId) -> Result<id::CommandEncoderId, Error> {
        let id = self.ids.command_encoders.allocate();
        let (_, error) =
            self.global
                .device_create_command_encoder(device, &Default::default(), Some(id));
        self.releases.push(Release::CommandEncoder(id));
        error.map_or(Ok(id), |error| Err(error.into()))
    }

    fn finish(&mut self, encoder: id::CommandEncoderId) -> Result<id::CommandBufferId, Error> {
        let id = self.ids.command_buffers.allocate();
        let (_, error) = self
            .global
            .command_encoder_finish(encoder, &Default::default(), Some(id));
        self.releases.push(Release::CommandBuffer(id));
        error.map_or(Ok(id), |(_, error)| Err(Error::Encoder(error)))
    }
}

impl LinearImage {
    /// Allocate an exportable image, and the SDK image the compositor reads.
    pub fn allocate(
        global: &Global,
        device: id::DeviceId,
        width: u32,
        height: u32,
        format: wgpu_types::TextureFormat,
    ) -> Result<(Self, Image), Error> {
        let (format, pixel_format) = format_pair(format)?;
        // SAFETY: the component creates only Vulkan devices; the guard remains
        // within this synchronous allocation and is dropped before return.
        let hal = unsafe { global.device_as_hal::<Vulkan>(device) }
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
        Ok((
            Self {
                raw_device,
                image,
                memory,
                extent,
                queue_family,
            },
            exported,
        ))
    }

    /// Submit a copy from a canvas texture and release it to display.
    ///
    /// # Safety
    /// `source` belongs to `device`, has this image's format and extent, one
    /// mip, layer and sample, and COPY_SRC | RENDER_ATTACHMENT usage.
    /// Nothing else may submit on `queue` or destroy the source during this
    /// call. This image belongs to `device` and has never been submitted.
    pub unsafe fn submit(
        &self,
        global: &Global,
        ids: &IdSpace,
        device: id::DeviceId,
        queue: id::QueueId,
        source: id::TextureId,
    ) -> Result<(), Error> {
        let mut scratch = Scratch {
            global,
            ids,
            releases: Vec::new(),
        };
        let transition = scratch.encoder(device)?;
        // A load/store pass preserves rendered contents and lets core initialize
        // untouched canvas storage before native copy commands can expose it.
        let view = ids.texture_views.allocate();
        let (_, error) = global.texture_create_view(source, &Default::default(), Some(view));
        scratch.releases.push(Release::TextureView(view));
        if let Some(error) = error {
            return Err(error.into());
        }
        let (mut initialize, error) = global.command_encoder_begin_render_pass(
            transition,
            &command::RenderPassDescriptor {
                label: None,
                color_attachments: Cow::Owned(vec![Some(command::RenderPassColorAttachment {
                    view,
                    depth_slice: None,
                    resolve_target: None,
                    load_op: wgpu_types::LoadOp::Load,
                    store_op: wgpu_types::StoreOp::Store,
                })]),
                depth_stencil_attachment: None,
                timestamp_writes: None,
                occlusion_query_set: None,
                multiview_mask: None,
            },
        );
        if let Some(error) = error {
            return Err(Error::Encoder(error));
        }
        global.render_pass_end(&mut initialize)?;
        global.command_encoder_transition_resources(
            transition,
            std::iter::empty(),
            std::iter::once(wgpu_types::TextureTransition {
                texture: source,
                selector: None,
                state: wgpu_types::TextureUses::COPY_SRC,
            }),
        )?;
        let transition = scratch.finish(transition)?;
        let copy = scratch.encoder(device)?;
        // SAFETY: the caller guarantees a live Vulkan texture on this device.
        // Hold the snatch guard while recording its native image handle.
        let source_hal =
            unsafe { global.texture_as_hal::<Vulkan>(source) }.ok_or(device::DeviceError::Lost)?;
        // SAFETY: the first command buffer establishes COPY_SRC; both buffers
        // execute in one submission. Core tracks the source in that submission,
        // and the device timeline retains the destination until it completes.
        let recorded = unsafe {
            global.command_encoder_as_hal_mut::<Vulkan, _, _>(copy, |encoder| {
                let encoder = encoder.ok_or(device::DeviceError::Lost)?;
                self.record_copy_and_release(encoder.raw_handle(), source_hal.raw_handle());
                Ok::<(), device::DeviceError>(())
            })
        };
        drop(source_hal);
        recorded?;
        let copy = scratch.finish(copy)?;
        global
            .queue_submit(queue, &[transition, copy])
            .map_err(|(_, error)| error)?;
        Ok(())
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
        // SAFETY: the device timeline drops an image only once the queue no
        // longer uses it, and before the device; the SDK export retains
        // storage for any later compositor access.
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
