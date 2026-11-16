use core::cell::Cell;
use std::borrow::Cow;

use wgpu_core::{
    command::{
        PassChannel, PassTimestampWrites, RenderPassColorAttachment,
        RenderPassDepthStencilAttachment, RenderPassDescriptor, TexelCopyBufferInfo,
        TexelCopyTextureInfo,
    },
    id::{self, markers},
};

use super::{
    buffer::Buffer,
    command::{Command, EncoderCommand},
    content::Handle,
    convert::Convert,
    queue::CommandBuffer,
    recording::{ComputePass, Recorder},
    render::{RenderPass, RenderRecorder},
    resource::{QuerySet, Texture},
    wit,
};

pub struct Encoder(pub Recorder<markers::CommandEncoder>);

fn load<T>(operation: wit::GpuLoadOp, clear: T) -> wgpu_types::LoadOp<T> {
    match operation {
        wit::GpuLoadOp::Load => wgpu_types::LoadOp::Load,
        wit::GpuLoadOp::Clear => wgpu_types::LoadOp::Clear(clear),
    }
}

impl Encoder {
    fn record(&self, command: EncoderCommand) {
        self.0
            .device()
            .enqueue(Command::Encoder(self.0.handle.id, command));
    }
    fn view(&self, view: wit::GpuTextureViewBorrow<'_>) -> id::TextureViewId {
        self.0.resolve(view.get::<Handle<markers::TextureView>>())
    }
    fn buffer_copy(&self, info: wit::GpuTexelCopyBufferInfo<'_>) -> TexelCopyBufferInfo {
        wgpu_types::TexelCopyBufferInfo {
            buffer: self.0.resolve(&info.buffer.get::<Buffer>().handle),
            layout: wgpu_types::TexelCopyBufferLayout {
                offset: info.offset.unwrap_or(0),
                bytes_per_row: info.bytes_per_row,
                rows_per_image: info.rows_per_image,
            },
        }
    }
    fn texture_copy(&self, info: wit::GpuTexelCopyTextureInfo<'_>) -> TexelCopyTextureInfo {
        wgpu_types::TexelCopyTextureInfo {
            texture: self.0.resolve(&info.texture.get::<Texture>().handle),
            mip_level: info.mip_level.unwrap_or(0),
            origin: info.origin.map(Convert::convert).unwrap_or_default(),
            aspect: info
                .aspect
                .map(Convert::convert)
                .unwrap_or(wgpu_types::TextureAspect::All),
        }
    }
    fn timestamp(
        &self,
        query: wit::GpuQuerySetBorrow<'_>,
        begin: Option<u32>,
        end: Option<u32>,
    ) -> PassTimestampWrites<id::QuerySetId> {
        PassTimestampWrites {
            query_set: self.0.resolve(&query.get::<QuerySet>().handle),
            beginning_of_pass_write_index: begin,
            end_of_pass_write_index: end,
        }
    }
    fn render_descriptor(
        &self,
        descriptor: wit::GpuRenderPassDescriptor<'_>,
    ) -> RenderPassDescriptor<'static> {
        let color_attachments = descriptor
            .color_attachments
            .into_iter()
            .map(|attachment| {
                attachment.map(|attachment| RenderPassColorAttachment {
                    view: self.view(attachment.view),
                    depth_slice: attachment.depth_slice,
                    resolve_target: attachment.resolve_target.map(|view| self.view(view)),
                    load_op: load(
                        attachment.load_op,
                        attachment
                            .clear_value
                            .map(Convert::convert)
                            .unwrap_or_default(),
                    ),
                    store_op: attachment.store_op.convert(),
                })
            })
            .collect::<Vec<_>>();
        let depth_stencil_attachment = descriptor.depth_stencil_attachment.map(|attachment| {
            RenderPassDepthStencilAttachment {
                view: self.view(attachment.view),
                depth: PassChannel {
                    load_op: attachment
                        .depth_load_op
                        .map(|op| load(op, attachment.depth_clear_value)),
                    store_op: attachment.depth_store_op.map(Convert::convert),
                    read_only: attachment.depth_read_only.unwrap_or(false),
                },
                stencil: PassChannel {
                    load_op: attachment
                        .stencil_load_op
                        .map(|op| load(op, Some(attachment.stencil_clear_value.unwrap_or(0)))),
                    store_op: attachment.stencil_store_op.map(Convert::convert),
                    read_only: attachment.stencil_read_only.unwrap_or(false),
                },
            }
        });
        RenderPassDescriptor {
            label: descriptor.label.map(Cow::Owned),
            color_attachments: Cow::Owned(color_attachments),
            depth_stencil_attachment,
            timestamp_writes: descriptor.timestamp_writes.map(|writes| {
                self.timestamp(
                    writes.query_set,
                    writes.beginning_of_pass_write_index,
                    writes.end_of_pass_write_index,
                )
            }),
            occlusion_query_set: descriptor
                .occlusion_query_set
                .map(|query| self.0.resolve(&query.get::<QuerySet>().handle)),
            multiview_mask: None,
        }
    }
}

impl wit::GuestGpuCommandEncoder for Encoder {
    fn label(&self) -> String {
        self.0.handle.label()
    }
    fn set_label(&self, label: String) {
        self.0.handle.set_label(label);
    }
    fn push_debug_group(&self, label: String) {
        self.record(EncoderCommand::PushDebugGroup(label));
    }
    fn pop_debug_group(&self) {
        self.record(EncoderCommand::PopDebugGroup);
    }
    fn insert_debug_marker(&self, label: String) {
        self.record(EncoderCommand::InsertDebugMarker(label));
    }
    fn begin_compute_pass(
        &self,
        descriptor: Option<wit::GpuComputePassDescriptor<'_>>,
    ) -> wit::GpuComputePassEncoder {
        let label = descriptor.as_ref().and_then(|d| d.label.clone());
        let pass = Handle::new(self.0.device(), label.clone());
        let timestamp_writes = descriptor.and_then(|d| d.timestamp_writes).map(|writes| {
            self.timestamp(
                writes.query_set,
                writes.beginning_of_pass_write_index,
                writes.end_of_pass_write_index,
            )
        });
        self.record(EncoderCommand::BeginComputePass {
            id: pass.id,
            descriptor: wgpu_core::command::ComputePassDescriptor {
                label: label.map(Cow::Owned),
                timestamp_writes,
            },
        });
        wit::GpuComputePassEncoder::new(ComputePass(Recorder::new(pass, self.0.invalid.clone())))
    }
    fn begin_render_pass(
        &self,
        descriptor: wit::GpuRenderPassDescriptor<'_>,
    ) -> wit::GpuRenderPassEncoder {
        let pass = Handle::new(self.0.device(), descriptor.label.clone());
        // GPURenderPassDescriptor.maxDrawCount defaults to 50,000,000 in WebGPU.
        let limit = descriptor.max_draw_count.unwrap_or(50_000_000);
        self.record(EncoderCommand::BeginRenderPass {
            id: pass.id,
            descriptor: self.render_descriptor(descriptor),
        });
        wit::GpuRenderPassEncoder::new(RenderPass(RenderRecorder {
            recorder: Recorder::new(pass, self.0.invalid.clone()),
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
        self.record(EncoderCommand::CopyBufferToBuffer {
            source: self.0.resolve(&source.get::<Buffer>().handle),
            source_offset: source_offset.unwrap_or(0),
            destination: self.0.resolve(&destination.get::<Buffer>().handle),
            destination_offset: destination_offset.unwrap_or(0),
            size,
        });
    }
    fn copy_buffer_to_texture(
        &self,
        source: wit::GpuTexelCopyBufferInfo<'_>,
        destination: wit::GpuTexelCopyTextureInfo<'_>,
        size: wit::GpuExtent3D,
    ) {
        self.record(EncoderCommand::CopyBufferToTexture {
            source: self.buffer_copy(source),
            destination: self.texture_copy(destination),
            size: size.convert(),
        });
    }
    fn copy_texture_to_buffer(
        &self,
        source: wit::GpuTexelCopyTextureInfo<'_>,
        destination: wit::GpuTexelCopyBufferInfo<'_>,
        size: wit::GpuExtent3D,
    ) {
        self.record(EncoderCommand::CopyTextureToBuffer {
            source: self.texture_copy(source),
            destination: self.buffer_copy(destination),
            size: size.convert(),
        });
    }
    fn copy_texture_to_texture(
        &self,
        source: wit::GpuTexelCopyTextureInfo<'_>,
        destination: wit::GpuTexelCopyTextureInfo<'_>,
        size: wit::GpuExtent3D,
    ) {
        self.record(EncoderCommand::CopyTextureToTexture {
            source: self.texture_copy(source),
            destination: self.texture_copy(destination),
            size: size.convert(),
        });
    }
    fn clear_buffer(
        &self,
        buffer: wit::GpuBufferBorrow<'_>,
        offset: Option<u64>,
        size: Option<u64>,
    ) {
        self.record(EncoderCommand::ClearBuffer {
            buffer: self.0.resolve(&buffer.get::<Buffer>().handle),
            offset: offset.unwrap_or(0),
            size,
        });
    }
    fn resolve_query_set(
        &self,
        query: wit::GpuQuerySetBorrow<'_>,
        first: u32,
        count: u32,
        destination: wit::GpuBufferBorrow<'_>,
        offset: u64,
    ) {
        self.record(EncoderCommand::ResolveQuerySet {
            query_set: self.0.resolve(&query.get::<QuerySet>().handle),
            first,
            count,
            destination: self.0.resolve(&destination.get::<Buffer>().handle),
            offset,
        });
    }
    fn finish(&self, descriptor: Option<wit::GpuCommandBufferDescriptor>) -> wit::GpuCommandBuffer {
        let label = descriptor.and_then(|d| d.label);
        let handle = Handle::new(self.0.device(), label.clone());
        self.record(EncoderCommand::Finish {
            id: handle.id,
            label,
        });
        wit::GpuCommandBuffer::new(CommandBuffer {
            handle,
            valid: !self.0.invalid.get(),
            consumed: Cell::new(false),
        })
    }
}
