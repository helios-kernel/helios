use core::cell::Cell;

use wgpu_core::id::markers;

use super::{
    buffer::Buffer,
    command::{BundleCommand, Command, DrawCommand, RenderCommand},
    content::Handle,
    convert::Convert,
    ids::Kind,
    recording::Recorder,
    wit,
};

pub struct RenderBundle {
    pub handle: Handle<markers::RenderBundle>,
    pub draws: u64,
}
impl wit::GuestGpuRenderBundle for RenderBundle {
    fn label(&self) -> String {
        self.handle.label()
    }
    fn set_label(&self, label: String) {
        self.handle.set_label(label);
    }
}

pub struct RenderRecorder<K: Kind> {
    pub recorder: Recorder<K>,
    pub draws: Cell<u64>,
    pub limit: u64,
}

impl<K: Kind> RenderRecorder<K> {
    fn count(&self, count: u64) -> bool {
        match self.draws.get().checked_add(count) {
            Some(total) if total <= self.limit => {
                self.draws.set(total);
                true
            }
            _ => {
                self.recorder.reject("render pass exceeds max-draw-count");
                false
            }
        }
    }
}

pub struct RenderPass(pub RenderRecorder<markers::RenderPassEncoder>);
pub struct BundleEncoder(pub RenderRecorder<markers::RenderBundleEncoder>);

impl RenderPass {
    fn record(&self, command: RenderCommand) {
        let recorder = &self.0.recorder;
        recorder
            .device()
            .enqueue(Command::RenderPass(recorder.handle.id, command));
    }
    fn record_draw(&self, command: DrawCommand) {
        self.record(RenderCommand::Draw(command));
    }
}

impl BundleEncoder {
    fn record(&self, command: BundleCommand) {
        let recorder = &self.0.recorder;
        recorder
            .device()
            .enqueue(Command::Bundle(recorder.handle.id, command));
    }
    fn record_draw(&self, command: DrawCommand) {
        self.record(BundleCommand::Draw(command));
    }
}

macro_rules! render_commands {
    () => {
        fn label(&self) -> String {
            self.0.recorder.handle.label()
        }
        fn set_label(&self, label: String) {
            self.0.recorder.handle.set_label(label);
        }
        fn push_debug_group(&self, label: String) {
            self.record_draw(DrawCommand::PushDebugGroup(label));
        }
        fn pop_debug_group(&self) {
            self.record_draw(DrawCommand::PopDebugGroup);
        }
        fn insert_debug_marker(&self, label: String) {
            self.record_draw(DrawCommand::InsertDebugMarker(label));
        }
        fn set_pipeline(&self, pipeline: wit::GpuRenderPipelineBorrow<'_>) {
            self.record_draw(DrawCommand::SetPipeline(
                self.0
                    .recorder
                    .resolve(pipeline.get::<Handle<markers::RenderPipeline>>()),
            ));
        }
        fn set_bind_group(
            &self,
            index: u32,
            group: Option<wit::GpuBindGroupBorrow<'_>>,
            offsets: Option<Vec<u32>>,
            start: Option<u64>,
            count: Option<u32>,
        ) -> Result<(), wit::SetBindGroupError> {
            let offsets = self.0.recorder.offsets(offsets, start, count)?;
            self.record_draw(DrawCommand::SetBindGroup {
                index,
                group: self.0.recorder.group(group),
                offsets,
            });
            Ok(())
        }
        fn set_immediates(
            &self,
            offset: u32,
            data: Vec<u8>,
            data_offset: Option<u64>,
            data_size: Option<u64>,
        ) {
            if let Some(data) = self.0.recorder.data(data, data_offset, data_size) {
                self.record_draw(DrawCommand::SetImmediates { offset, data });
            }
        }
        fn set_index_buffer(
            &self,
            buffer: wit::GpuBufferBorrow<'_>,
            format: wit::GpuIndexFormat,
            offset: Option<u64>,
            size: Option<u64>,
        ) {
            self.record_draw(DrawCommand::SetIndexBuffer {
                buffer: self.0.recorder.resolve(&buffer.get::<Buffer>().handle),
                format: format.convert(),
                offset: offset.unwrap_or(0),
                size,
            });
        }
        fn set_vertex_buffer(
            &self,
            slot: u32,
            buffer: Option<wit::GpuBufferBorrow<'_>>,
            offset: Option<u64>,
            size: Option<u64>,
        ) {
            self.record_draw(DrawCommand::SetVertexBuffer {
                slot,
                buffer: buffer
                    .map(|buffer| self.0.recorder.resolve(&buffer.get::<Buffer>().handle)),
                offset: offset.unwrap_or(0),
                size,
            });
        }
        fn draw(
            &self,
            vertices: u32,
            instances: Option<u32>,
            first_vertex: Option<u32>,
            first_instance: Option<u32>,
        ) {
            if self.0.count(1) {
                self.record_draw(DrawCommand::Draw {
                    vertices,
                    instances: instances.unwrap_or(1),
                    first_vertex: first_vertex.unwrap_or(0),
                    first_instance: first_instance.unwrap_or(0),
                });
            }
        }
        fn draw_indexed(
            &self,
            indices: u32,
            instances: Option<u32>,
            first_index: Option<u32>,
            base_vertex: Option<i32>,
            first_instance: Option<u32>,
        ) {
            if self.0.count(1) {
                self.record_draw(DrawCommand::DrawIndexed {
                    indices,
                    instances: instances.unwrap_or(1),
                    first_index: first_index.unwrap_or(0),
                    base_vertex: base_vertex.unwrap_or(0),
                    first_instance: first_instance.unwrap_or(0),
                });
            }
        }
        fn draw_indirect(&self, buffer: wit::GpuBufferBorrow<'_>, offset: u64) {
            if self.0.count(1) {
                self.record_draw(DrawCommand::DrawIndirect {
                    buffer: self.0.recorder.resolve(&buffer.get::<Buffer>().handle),
                    offset,
                });
            }
        }
        fn draw_indexed_indirect(&self, buffer: wit::GpuBufferBorrow<'_>, offset: u64) {
            if self.0.count(1) {
                self.record_draw(DrawCommand::DrawIndexedIndirect {
                    buffer: self.0.recorder.resolve(&buffer.get::<Buffer>().handle),
                    offset,
                });
            }
        }
    };
}

impl wit::GuestGpuRenderPassEncoder for RenderPass {
    render_commands!();
    fn end(&self) {
        self.record(RenderCommand::End);
    }
    fn set_viewport(
        &self,
        x: f32,
        y: f32,
        width: f32,
        height: f32,
        min_depth: f32,
        max_depth: f32,
    ) {
        self.record(RenderCommand::SetViewport {
            x,
            y,
            width,
            height,
            min_depth,
            max_depth,
        });
    }
    fn set_scissor_rect(&self, x: u32, y: u32, width: u32, height: u32) {
        self.record(RenderCommand::SetScissorRect {
            x,
            y,
            width,
            height,
        });
    }
    fn set_blend_constant(&self, color: wit::GpuColor) {
        self.record(RenderCommand::SetBlendConstant(color.convert()));
    }
    fn set_stencil_reference(&self, reference: u32) {
        self.record(RenderCommand::SetStencilReference(reference));
    }
    fn begin_occlusion_query(&self, index: u32) {
        self.record(RenderCommand::BeginOcclusionQuery(index));
    }
    fn end_occlusion_query(&self) {
        self.record(RenderCommand::EndOcclusionQuery);
    }
    fn execute_bundles(&self, bundles: Vec<wit::GpuRenderBundleBorrow<'_>>) {
        let mut ids = Vec::with_capacity(bundles.len());
        for bundle in &bundles {
            let bundle = bundle.get::<RenderBundle>();
            if !self.0.count(bundle.draws) {
                return;
            }
            ids.push(self.0.recorder.resolve(&bundle.handle));
        }
        self.record(RenderCommand::ExecuteBundles(ids));
    }
}

impl wit::GuestGpuRenderBundleEncoder for BundleEncoder {
    render_commands!();
    fn finish(&self, descriptor: Option<wit::GpuRenderBundleDescriptor>) -> wit::GpuRenderBundle {
        let label = descriptor.and_then(|d| d.label);
        let recorder = &self.0.recorder;
        let handle = Handle::new(recorder.device(), label.clone());
        self.record(BundleCommand::Finish {
            id: handle.id,
            label,
            invalid: recorder.invalid.get(),
        });
        wit::GpuRenderBundle::new(RenderBundle {
            handle,
            draws: self.0.draws.get(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::component::content::tests::new_device;
    use std::rc::Rc;
    use wit::GuestGpuRenderPassEncoder;

    #[test]
    fn exceeding_max_draw_count_rejects_the_encoder_and_records_nothing() {
        let (device, commands) = new_device();
        let invalid = Rc::new(Cell::new(false));
        let pass = RenderPass(RenderRecorder {
            recorder: Recorder::new(Handle::new(&device, None), invalid.clone()),
            draws: Cell::new(0),
            limit: 1,
        });
        pass.draw(3, None, None, None);
        assert!(!invalid.get());
        pass.draw(3, None, None, None);
        assert!(invalid.get());
        let recorded: Vec<_> = core::iter::from_fn(|| commands.try_recv().ok())
            .map(|queued| queued.command)
            .collect();
        assert!(matches!(
            &recorded[..],
            [
                Command::RenderPass(_, RenderCommand::Draw(DrawCommand::Draw { vertices: 3, .. })),
                Command::Error(error),
            ] if error.message == "render pass exceeds max-draw-count"
        ));
    }
}
