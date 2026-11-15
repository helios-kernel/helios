use super::{
    backend,
    buffer::Buffer,
    convert::Convert,
    queue::CommandBuffer,
    recording::{ComputePass, Recorder},
    render::{RenderPass, RenderRecorder},
    resource::{QuerySet, Texture},
    value::Object,
    wit,
};
use core::cell::{Cell, RefCell};
use std::{borrow::Cow, sync::Arc};
use wgpu_core::command as core_command;

pub struct Encoder(pub Recorder<Arc<core_command::CommandEncoder>>);

fn load<T>(operation: wit::GpuLoadOp, clear: T) -> wgpu::LoadOp<T> {
    match operation {
        wit::GpuLoadOp::Load => wgpu::LoadOp::Load,
        wit::GpuLoadOp::Clear => wgpu::LoadOp::Clear(clear),
    }
}

impl Encoder {
    fn buffer_copy(
        &self,
        info: wit::GpuTexelCopyBufferInfo<'_>,
    ) -> Option<wgpu_types::TexelCopyBufferInfo<backend::Buffer>> {
        Some(wgpu_types::TexelCopyBufferInfo {
            buffer: self
                .0
                .resource(&info.buffer.get::<Buffer>().object)?
                .clone(),
            layout: wgpu::TexelCopyBufferLayout {
                offset: info.offset.unwrap_or(0),
                bytes_per_row: info.bytes_per_row,
                rows_per_image: info.rows_per_image,
            },
        })
    }
    fn texture_copy(
        &self,
        info: wit::GpuTexelCopyTextureInfo<'_>,
    ) -> Option<wgpu_types::TexelCopyTextureInfo<backend::Texture>> {
        Some(wgpu_types::TexelCopyTextureInfo {
            texture: self
                .0
                .resource(&info.texture.get::<Texture>().object)?
                .clone(),
            mip_level: info.mip_level.unwrap_or(0),
            origin: info.origin.map(Convert::convert).unwrap_or_default(),
            aspect: info
                .aspect
                .map(Convert::convert)
                .unwrap_or(wgpu::TextureAspect::All),
        })
    }
    fn timestamp(
        &self,
        query: wit::GpuQuerySetBorrow<'_>,
        begin: Option<u32>,
        end: Option<u32>,
    ) -> Option<core_command::PassTimestampWrites> {
        Some(core_command::PassTimestampWrites {
            query_set: self.0.resource(&query.get::<QuerySet>().object)?.clone(),
            beginning_of_pass_write_index: begin,
            end_of_pass_write_index: end,
        })
    }
    fn render_descriptor(
        &self,
        descriptor: wit::GpuRenderPassDescriptor<'_>,
    ) -> Option<core_command::ResolvedRenderPassDescriptor<'static>> {
        let color_attachments = descriptor
            .color_attachments
            .into_iter()
            .map(|attachment| {
                let Some(attachment) = attachment else {
                    return Some(None);
                };
                let resolve_target = match attachment.resolve_target {
                    Some(view) => Some(
                        self.0
                            .resource(view.get::<Object<backend::TextureView>>())?
                            .clone(),
                    ),
                    None => None,
                };
                Some(Some(core_command::RenderPassColorAttachment {
                    view: self
                        .0
                        .resource(attachment.view.get::<Object<backend::TextureView>>())?
                        .clone(),
                    depth_slice: attachment.depth_slice,
                    resolve_target,
                    load_op: load(
                        attachment.load_op,
                        attachment
                            .clear_value
                            .map(Convert::convert)
                            .unwrap_or_default(),
                    ),
                    store_op: attachment.store_op.convert(),
                }))
            })
            .collect::<Option<Vec<_>>>()?;
        let depth_stencil_attachment = match descriptor.depth_stencil_attachment {
            Some(attachment) => Some(core_command::RenderPassDepthStencilAttachment {
                view: self
                    .0
                    .resource(attachment.view.get::<Object<backend::TextureView>>())?
                    .clone(),
                depth: core_command::PassChannel {
                    load_op: attachment
                        .depth_load_op
                        .map(|op| load(op, attachment.depth_clear_value)),
                    store_op: attachment.depth_store_op.map(Convert::convert),
                    read_only: attachment.depth_read_only.unwrap_or(false),
                },
                stencil: core_command::PassChannel {
                    load_op: attachment
                        .stencil_load_op
                        .map(|op| load(op, Some(attachment.stencil_clear_value.unwrap_or(0)))),
                    store_op: attachment.stencil_store_op.map(Convert::convert),
                    read_only: attachment.stencil_read_only.unwrap_or(false),
                },
            }),
            None => None,
        };
        let timestamp_writes = match descriptor.timestamp_writes {
            Some(writes) => Some(self.timestamp(
                writes.query_set,
                writes.beginning_of_pass_write_index,
                writes.end_of_pass_write_index,
            )?),
            None => None,
        };
        let occlusion_query_set = match descriptor.occlusion_query_set {
            Some(query) => Some(self.0.resource(&query.get::<QuerySet>().object)?.clone()),
            None => None,
        };
        Some(core_command::ResolvedRenderPassDescriptor {
            label: descriptor.label.map(Cow::Owned),
            color_attachments: Cow::Owned(color_attachments),
            depth_stencil_attachment,
            timestamp_writes,
            occlusion_query_set,
            multiview_mask: None,
        })
    }
}

impl wit::GuestGpuCommandEncoder for Encoder {
    fn label(&self) -> String {
        self.0.object.label()
    }
    fn set_label(&self, label: String) {
        self.0.object.set_label(label);
    }
    fn push_debug_group(&self, label: String) {
        self.0.with(|raw| raw.push_debug_group(&label));
    }
    fn pop_debug_group(&self) {
        self.0.with(|raw| raw.pop_debug_group());
    }
    fn insert_debug_marker(&self, label: String) {
        self.0.with(|raw| raw.insert_debug_marker(&label));
    }
    fn begin_compute_pass(
        &self,
        descriptor: Option<wit::GpuComputePassDescriptor<'_>>,
    ) -> wit::GpuComputePassEncoder {
        let label = descriptor.as_ref().and_then(|d| d.label.clone());
        let raw = (|| {
            let timestamp_writes = match descriptor.and_then(|d| d.timestamp_writes) {
                Some(writes) => Some(self.timestamp(
                    writes.query_set,
                    writes.beginning_of_pass_write_index,
                    writes.end_of_pass_write_index,
                )?),
                None => None,
            };
            self.0.created(|raw| {
                raw.begin_compute_pass(&core_command::ComputePassDescriptor {
                    label: label.as_deref().map(Cow::Borrowed),
                    timestamp_writes,
                })
            })
        })();
        wit::GpuComputePassEncoder::new(ComputePass(Recorder::new(
            self.0.object.owner.clone(),
            raw,
            label,
            self.0.invalid.clone(),
        )))
    }
    fn begin_render_pass(
        &self,
        descriptor: wit::GpuRenderPassDescriptor<'_>,
    ) -> wit::GpuRenderPassEncoder {
        let label = descriptor.label.clone();
        // GPURenderPassDescriptor.maxDrawCount defaults to 50,000,000 in WebGPU.
        let limit = descriptor.max_draw_count.unwrap_or(50_000_000);
        let raw = self
            .render_descriptor(descriptor)
            .and_then(|descriptor| self.0.created(|raw| raw.begin_render_pass(descriptor)));
        wit::GpuRenderPassEncoder::new(RenderPass(RenderRecorder {
            recorder: Recorder::new(
                self.0.object.owner.clone(),
                raw,
                label,
                self.0.invalid.clone(),
            ),
            draws: Cell::new(0),
            limit,
        }))
    }
    fn copy_buffer_to_buffer(
        &self,
        source: wit::GpuBufferBorrow<'_>,
        source_offset: Option<u64>,
        destination: wit::GpuBufferBorrow<'_>,
        destination_offset: Option<u64>,
        size: Option<u64>,
    ) {
        if let (Some(source), Some(destination)) = (
            self.0.resource(&source.get::<Buffer>().object),
            self.0.resource(&destination.get::<Buffer>().object),
        ) {
            self.0.with(|raw| {
                raw.copy_buffer_to_buffer(
                    source.clone(),
                    source_offset.unwrap_or(0),
                    destination.clone(),
                    destination_offset.unwrap_or(0),
                    size,
                )
            });
        }
    }
    fn copy_buffer_to_texture(
        &self,
        source: wit::GpuTexelCopyBufferInfo<'_>,
        destination: wit::GpuTexelCopyTextureInfo<'_>,
        size: wit::GpuExtent3D,
    ) {
        if let (Some(source), Some(destination)) =
            (self.buffer_copy(source), self.texture_copy(destination))
        {
            self.0
                .with(|raw| raw.copy_buffer_to_texture(&source, &destination, &size.convert()));
        }
    }
    fn copy_texture_to_buffer(
        &self,
        source: wit::GpuTexelCopyTextureInfo<'_>,
        destination: wit::GpuTexelCopyBufferInfo<'_>,
        size: wit::GpuExtent3D,
    ) {
        if let (Some(source), Some(destination)) =
            (self.texture_copy(source), self.buffer_copy(destination))
        {
            self.0
                .with(|raw| raw.copy_texture_to_buffer(&source, &destination, &size.convert()));
        }
    }
    fn copy_texture_to_texture(
        &self,
        source: wit::GpuTexelCopyTextureInfo<'_>,
        destination: wit::GpuTexelCopyTextureInfo<'_>,
        size: wit::GpuExtent3D,
    ) {
        if let (Some(source), Some(destination)) =
            (self.texture_copy(source), self.texture_copy(destination))
        {
            self.0
                .with(|raw| raw.copy_texture_to_texture(&source, &destination, &size.convert()));
        }
    }
    fn clear_buffer(
        &self,
        buffer: wit::GpuBufferBorrow<'_>,
        offset: Option<u64>,
        size: Option<u64>,
    ) {
        if let Some(buffer) = self.0.resource(&buffer.get::<Buffer>().object) {
            self.0
                .with(|raw| raw.clear_buffer(buffer.clone(), offset.unwrap_or(0), size));
        }
    }
    fn resolve_query_set(
        &self,
        query: wit::GpuQuerySetBorrow<'_>,
        first: u32,
        count: u32,
        destination: wit::GpuBufferBorrow<'_>,
        offset: u64,
    ) {
        if let (Some(query), Some(destination)) = (
            self.0.resource(&query.get::<QuerySet>().object),
            self.0.resource(&destination.get::<Buffer>().object),
        ) {
            self.0.with(|raw| {
                raw.resolve_query_set(query.clone(), first, count, destination.clone(), offset)
            });
        }
    }
    fn finish(&self, descriptor: Option<wit::GpuCommandBufferDescriptor>) -> wit::GpuCommandBuffer {
        let label = descriptor.and_then(|d| d.label);
        let native = self.0.take().map(|raw| {
            let (buffer, error) = raw.finish(&wgpu_types::CommandBufferDescriptor {
                label: label.as_deref().map(Cow::Borrowed),
            });
            if let Some((_, error)) = error {
                self.0.object.owner.report(&error);
            }
            buffer
        });
        let owner = self.0.object.owner.clone();
        let object = match native.filter(|_| !self.0.invalid.get()) {
            Some(raw) => Object::new(owner, RefCell::new(Some(raw)), label),
            None => Object::invalid(owner, label),
        };
        wit::GpuCommandBuffer::new(CommandBuffer(object))
    }
}
