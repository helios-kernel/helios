use super::{backend, buffer::Buffer, convert::Convert, recording::Recorder, value::Object, wit};
use core::cell::Cell;

pub struct RenderBundle {
    pub object: Object<backend::RenderBundle>,
    pub draws: u64,
}
impl wit::GuestGpuRenderBundle for RenderBundle {
    fn label(&self) -> String {
        self.object.label()
    }
    fn set_label(&self, label: String) {
        self.object.set_label(label);
    }
}

pub struct RenderRecorder<T> {
    pub recorder: Recorder<T>,
    pub draws: Cell<u64>,
    pub limit: u64,
}

impl<T> RenderRecorder<T> {
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

pub struct RenderPass(pub RenderRecorder<wgpu_core::command::RenderPass>);
pub struct BundleEncoder(pub RenderRecorder<wgpu_core::command::RenderBundleEncoder>);

macro_rules! render_commands {
    ($($color:expr)?) => {
        fn label(&self) -> String {
            self.0.recorder.object.label()
        }
        fn set_label(&self, label: String) {
            self.0.recorder.object.set_label(label);
        }
        fn push_debug_group(&self, label: String) {
            self.0.recorder.with(|raw| raw.push_debug_group(&label $(, $color)?));
        }
        fn pop_debug_group(&self) {
            self.0.recorder.with(|raw| raw.pop_debug_group());
        }
        fn insert_debug_marker(&self, label: String) {
            self.0
                .recorder
                .with(|raw| raw.insert_debug_marker(&label $(, $color)?));
        }
        fn set_pipeline(&self, pipeline: wit::GpuRenderPipelineBorrow<'_>) {
            if let Some(pipeline) = self
                .0
                .recorder
                .resource(pipeline.get::<Object<backend::RenderPipeline>>())
            {
                self.0
                    .recorder
                    .with(|raw| raw.set_pipeline(pipeline.clone()));
            }
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
            let group = match group.as_ref() {
                Some(group) => match self
                    .0
                    .recorder
                    .resource(group.get::<Object<backend::BindGroup>>())
                {
                    Some(group) => Some(group.clone()),
                    None => return Ok(()),
                },
                None => None,
            };
            self.0
                .recorder
                .with(|raw| raw.set_bind_group(index, group, &offsets));
            Ok(())
        }
        fn set_immediates(
            &self,
            offset: u32,
            data: Vec<u8>,
            data_offset: Option<u64>,
            data_size: Option<u64>,
        ) {
            if let Some(data) = self.0.recorder.data(&data, data_offset, data_size) {
                self.0.recorder.with(|raw| raw.set_immediates(offset, data));
            }
        }
        fn set_index_buffer(
            &self,
            buffer: wit::GpuBufferBorrow<'_>,
            format: wit::GpuIndexFormat,
            offset: Option<u64>,
            size: Option<u64>,
        ) {
            if let Some(buffer) = self.0.recorder.resource(&buffer.get::<Buffer>().object) {
                self.0.recorder.with(|raw| {
                    raw.set_index_buffer(
                        buffer.clone(),
                        format.convert(),
                        offset.unwrap_or(0),
                        size,
                    )
                });
            }
        }
        fn set_vertex_buffer(
            &self,
            slot: u32,
            buffer: Option<wit::GpuBufferBorrow<'_>>,
            offset: Option<u64>,
            size: Option<u64>,
        ) {
            let buffer = match buffer.as_ref() {
                Some(buffer) => match self.0.recorder.resource(&buffer.get::<Buffer>().object) {
                    Some(buffer) => Some(buffer.clone()),
                    None => return,
                },
                None => None,
            };
            self.0
                .recorder
                .with(|raw| raw.set_vertex_buffer(slot, buffer, offset.unwrap_or(0), size));
        }
        fn draw(
            &self,
            vertices: u32,
            instances: Option<u32>,
            first_vertex: Option<u32>,
            first_instance: Option<u32>,
        ) {
            if self.0.count(1) {
                self.0.recorder.with(|raw| {
                    raw.draw(
                        vertices,
                        instances.unwrap_or(1),
                        first_vertex.unwrap_or(0),
                        first_instance.unwrap_or(0),
                    )
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
                self.0.recorder.with(|raw| {
                    raw.draw_indexed(
                        indices,
                        instances.unwrap_or(1),
                        first_index.unwrap_or(0),
                        base_vertex.unwrap_or(0),
                        first_instance.unwrap_or(0),
                    )
                });
            }
        }
        fn draw_indirect(&self, buffer: wit::GpuBufferBorrow<'_>, offset: u64) {
            if self.0.count(1) {
                if let Some(buffer) = self.0.recorder.resource(&buffer.get::<Buffer>().object) {
                    self.0
                        .recorder
                        .with(|raw| raw.draw_indirect(buffer.clone(), offset));
                }
            }
        }
        fn draw_indexed_indirect(&self, buffer: wit::GpuBufferBorrow<'_>, offset: u64) {
            if self.0.count(1) {
                if let Some(buffer) = self.0.recorder.resource(&buffer.get::<Buffer>().object) {
                    self.0
                        .recorder
                        .with(|raw| raw.draw_indexed_indirect(buffer.clone(), offset));
                }
            }
        }
    };
}

impl wit::GuestGpuRenderPassEncoder for RenderPass {
    render_commands!(0);
    fn end(&self) {
        self.0.recorder.with(|raw| raw.end());
        self.0.recorder.take();
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
        self.0
            .recorder
            .with(|raw| raw.set_viewport(x, y, width, height, min_depth, max_depth));
    }
    fn set_scissor_rect(&self, x: u32, y: u32, width: u32, height: u32) {
        self.0
            .recorder
            .with(|raw| raw.set_scissor_rect(x, y, width, height));
    }
    fn set_blend_constant(&self, color: wit::GpuColor) {
        self.0
            .recorder
            .with(|raw| raw.set_blend_constant(color.convert()));
    }
    fn set_stencil_reference(&self, reference: u32) {
        self.0
            .recorder
            .with(|raw| raw.set_stencil_reference(reference));
    }
    fn begin_occlusion_query(&self, index: u32) {
        self.0.recorder.with(|raw| raw.begin_occlusion_query(index));
    }
    fn end_occlusion_query(&self) {
        self.0.recorder.with(|raw| raw.end_occlusion_query());
    }
    fn execute_bundles(&self, bundles: Vec<wit::GpuRenderBundleBorrow<'_>>) {
        let mut native = Vec::with_capacity(bundles.len());
        for bundle in &bundles {
            let bundle = bundle.get::<RenderBundle>();
            let Some(raw) = self.0.recorder.resource(&bundle.object) else {
                return;
            };
            if !self.0.count(bundle.draws) {
                return;
            }
            native.push(raw.clone());
        }
        self.0.recorder.with(|raw| raw.execute_bundles(&native));
    }
}

impl wit::GuestGpuRenderBundleEncoder for BundleEncoder {
    render_commands!();
    fn finish(&self, descriptor: Option<wit::GpuRenderBundleDescriptor>) -> wit::GpuRenderBundle {
        let label = descriptor.and_then(|d| d.label);
        let raw = self.0.recorder.take().and_then(|mut raw| {
            if self.0.recorder.invalid.get() {
                return None;
            }
            Some(self.0.recorder.object.owner.created(raw.finish(
                &wgpu_types::RenderBundleDescriptor {
                    label: label.as_deref().map(Into::into),
                },
            )))
        });
        let owner = self.0.recorder.object.owner.clone();
        let object = match raw {
            Some(raw) => Object::new(owner, raw, label),
            None => Object::invalid(owner, label),
        };
        wit::GpuRenderBundle::new(RenderBundle {
            object,
            draws: self.0.draws.get(),
        })
    }
}
