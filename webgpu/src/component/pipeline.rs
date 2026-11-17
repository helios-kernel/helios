//! Owned descriptors keep synchronous and asynchronous pipeline validation equal.

use std::borrow::Cow;

use wgpu_core::{
    device::global::{ComputePipelineDescriptor, RenderPipelineDescriptor},
    id::{self, markers},
    pipeline,
};
use wgpu_types::error::{ErrorType, WebGpuError};

use super::{
    command::Create,
    content::{DeviceShared, Handle},
    convert::Convert,
    device::Device,
    value::{Dictionary, Shader},
    wit,
};

fn layout(device: &DeviceShared, mode: wit::GpuLayoutMode<'_>) -> Option<id::PipelineLayoutId> {
    match mode {
        wit::GpuLayoutMode::Auto => None,
        wit::GpuLayoutMode::Specific(layout) => {
            Some(device.resolve(layout.get::<Handle<markers::PipelineLayout>>()))
        }
    }
}

fn stage(
    device: &DeviceShared,
    module: wit::GpuShaderModuleBorrow<'_>,
    entry_point: Option<String>,
    constants: Option<wit::RecordGpuPipelineConstantValue>,
) -> pipeline::ProgrammableStageDescriptor<'static, id::ShaderModuleId> {
    pipeline::ProgrammableStageDescriptor {
        module: device.resolve(&module.get::<Shader>().handle),
        entry_point: entry_point.map(Cow::Owned),
        constants: constants
            .map(|c| c.get::<Dictionary<f64>>().entries().into_iter().collect())
            .unwrap_or_default(),
        zero_initialize_workgroup_memory: true,
    }
}

fn compute(
    device: &DeviceShared,
    descriptor: wit::GpuComputePipelineDescriptor<'_>,
) -> ComputePipelineDescriptor<'static> {
    pipeline::ComputePipelineDescriptor {
        label: descriptor.label.map(Cow::Owned),
        layout: layout(device, descriptor.layout),
        stage: stage(
            device,
            descriptor.compute.module,
            descriptor.compute.entry_point,
            descriptor.compute.constants,
        ),
        cache: None,
    }
}

fn render(
    device: &DeviceShared,
    descriptor: wit::GpuRenderPipelineDescriptor<'_>,
) -> Box<RenderPipelineDescriptor<'static>> {
    let vertex = descriptor.vertex;
    let fragment = descriptor.fragment.map(|fragment| pipeline::FragmentState {
        stage: stage(
            device,
            fragment.module,
            fragment.entry_point,
            fragment.constants,
        ),
        targets: fragment
            .targets
            .into_iter()
            .map(|t| t.map(Convert::convert))
            .collect(),
    });
    Box::new(pipeline::RenderPipelineDescriptor {
        label: descriptor.label.map(Cow::Owned),
        layout: layout(device, descriptor.layout),
        vertex: pipeline::VertexState {
            stage: stage(device, vertex.module, vertex.entry_point, vertex.constants),
            buffers: vertex
                .buffers
                .unwrap_or_default()
                .into_iter()
                .map(|buffer| {
                    buffer.map(|buffer| pipeline::VertexBufferLayout {
                        array_stride: buffer.array_stride,
                        step_mode: buffer
                            .step_mode
                            .unwrap_or(wit::GpuVertexStepMode::Vertex)
                            .convert(),
                        attributes: buffer
                            .attributes
                            .into_iter()
                            .map(Convert::convert)
                            .collect(),
                    })
                })
                .collect(),
        },
        primitive: descriptor
            .primitive
            .map(Convert::convert)
            .unwrap_or_default(),
        depth_stencil: descriptor.depth_stencil.map(Convert::convert),
        multisample: descriptor
            .multisample
            .map(Convert::convert)
            .unwrap_or_default(),
        fragment,
        multiview_mask: None,
        cache: None,
    })
}

/// The rejection an async pipeline creation answers with.
pub fn pipeline_error(error: impl WebGpuError) -> wit::CreatePipelineError {
    let reason = match error.webgpu_error_type() {
        ErrorType::Validation => wit::GpuPipelineErrorReason::Validation,
        ErrorType::Internal | ErrorType::OutOfMemory | ErrorType::DeviceLost => {
            wit::GpuPipelineErrorReason::Internal
        }
    };
    let mut messages = vec![error.to_string()];
    let mut source = error.source();
    while let Some(cause) = source {
        messages.push(cause.to_string());
        source = cause.source();
    }
    wit::CreatePipelineError {
        kind: wit::CreatePipelineErrorKind::GpuPipelineError(reason),
        message: messages.join(": "),
    }
}

/// Await the device timeline's verdict. The caller holds the device, so its
/// task is alive and answers every creation.
async fn verdict(
    answer: async_channel::Receiver<Result<(), wit::CreatePipelineError>>,
) -> Result<(), wit::CreatePipelineError> {
    answer
        .recv()
        .await
        .unwrap_or_else(|_| unreachable!("the device task answers every pipeline creation"))
}

impl Device {
    pub fn create_compute_pipeline(
        &self,
        descriptor: wit::GpuComputePipelineDescriptor<'_>,
    ) -> wit::GpuComputePipeline {
        let handle = Handle::new(&self.shared, descriptor.label.clone());
        self.create(Create::ComputePipeline {
            id: handle.id,
            descriptor: compute(&self.shared, descriptor),
            reply: None,
        });
        wit::GpuComputePipeline::new(handle)
    }

    pub async fn create_compute_pipeline_async(
        &self,
        descriptor: wit::GpuComputePipelineDescriptor<'_>,
    ) -> Result<wit::GpuComputePipeline, wit::CreatePipelineError> {
        // A rejected pipeline's handle drops here, releasing its invalid object.
        let handle = Handle::new(&self.shared, descriptor.label.clone());
        let (reply, answer) = async_channel::bounded(1);
        self.create(Create::ComputePipeline {
            id: handle.id,
            descriptor: compute(&self.shared, descriptor),
            reply: Some(reply),
        });
        verdict(answer).await?;
        Ok(wit::GpuComputePipeline::new(handle))
    }

    pub fn create_render_pipeline(
        &self,
        descriptor: wit::GpuRenderPipelineDescriptor<'_>,
    ) -> wit::GpuRenderPipeline {
        let handle = Handle::new(&self.shared, descriptor.label.clone());
        self.create(Create::RenderPipeline {
            id: handle.id,
            descriptor: render(&self.shared, descriptor),
            reply: None,
        });
        wit::GpuRenderPipeline::new(handle)
    }

    pub async fn create_render_pipeline_async(
        &self,
        descriptor: wit::GpuRenderPipelineDescriptor<'_>,
    ) -> Result<wit::GpuRenderPipeline, wit::CreatePipelineError> {
        let handle = Handle::new(&self.shared, descriptor.label.clone());
        let (reply, answer) = async_channel::bounded(1);
        self.create(Create::RenderPipeline {
            id: handle.id,
            descriptor: render(&self.shared, descriptor),
            reply: Some(reply),
        });
        verdict(answer).await?;
        Ok(wit::GpuRenderPipeline::new(handle))
    }
}
