//! Owned descriptors keep synchronous and asynchronous pipeline validation equal.

use wgpu_core::pipeline;
use wgpu_types::error::{ErrorType, WebGpuError};

use super::{
    backend,
    convert::Convert,
    device::Device,
    value::{Dictionary, Object, Shader},
    wit,
};

#[derive(Debug, thiserror::Error)]
#[error("pipeline uses an invalid {0}")]
struct InvalidResource(&'static str);

impl WebGpuError for InvalidResource {
    fn webgpu_error_type(&self) -> ErrorType {
        ErrorType::Validation
    }
}

fn layout(
    mode: wit::GpuLayoutMode<'_>,
) -> Result<Option<backend::PipelineLayout>, InvalidResource> {
    match mode {
        wit::GpuLayoutMode::Auto => Ok(None),
        wit::GpuLayoutMode::Specific(layout) => layout
            .get::<Object<backend::PipelineLayout>>()
            .raw
            .clone()
            .map(Some)
            .ok_or(InvalidResource("pipeline layout")),
    }
}

fn stage(
    module: wit::GpuShaderModuleBorrow<'_>,
    entry_point: Option<String>,
    constants: Option<wit::RecordGpuPipelineConstantValue>,
) -> Result<pipeline::ProgrammableStageDescriptor<'static>, InvalidResource> {
    Ok(pipeline::ProgrammableStageDescriptor {
        module: module
            .get::<Shader>()
            .object
            .raw
            .clone()
            .ok_or(InvalidResource("shader module"))?,
        entry_point: entry_point.map(Into::into),
        constants: constants
            .map(|c| c.get::<Dictionary<f64>>().entries().into_iter().collect())
            .unwrap_or_default(),
        zero_initialize_workgroup_memory: true,
    })
}

fn compute(
    descriptor: wit::GpuComputePipelineDescriptor<'_>,
) -> Result<pipeline::ComputePipelineDescriptor<'static>, InvalidResource> {
    Ok(pipeline::ComputePipelineDescriptor {
        label: descriptor.label.map(Into::into),
        layout: layout(descriptor.layout)?,
        stage: stage(
            descriptor.compute.module,
            descriptor.compute.entry_point,
            descriptor.compute.constants,
        )?,
        cache: None,
    })
}

fn render(
    descriptor: wit::GpuRenderPipelineDescriptor<'_>,
) -> Result<pipeline::ResolvedGeneralRenderPipelineDescriptor<'static>, InvalidResource> {
    let vertex = descriptor.vertex;
    let fragment = descriptor
        .fragment
        .map(|fragment| {
            Ok(pipeline::FragmentState {
                stage: stage(fragment.module, fragment.entry_point, fragment.constants)?,
                targets: fragment
                    .targets
                    .into_iter()
                    .map(|t| t.map(Convert::convert))
                    .collect(),
            })
        })
        .transpose()?;
    Ok(pipeline::RenderPipelineDescriptor {
        label: descriptor.label.map(Into::into),
        layout: layout(descriptor.layout)?,
        vertex: pipeline::VertexState {
            stage: stage(vertex.module, vertex.entry_point, vertex.constants)?,
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
    }
    .into())
}

fn pipeline_error(error: impl WebGpuError) -> wit::CreatePipelineError {
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

impl Device {
    pub fn create_compute_pipeline(
        &self,
        descriptor: wit::GpuComputePipelineDescriptor<'_>,
    ) -> wit::GpuComputePipeline {
        let label = descriptor.label.clone();
        let owner = &self.object.owner;
        let object = match compute(descriptor) {
            Ok(descriptor) => Object::new(
                owner.clone(),
                owner.created(owner.device.raw.create_compute_pipeline(descriptor)),
                label,
            ),
            Err(error) => {
                owner.report(&error);
                Object::invalid(owner.clone(), label)
            }
        };
        wit::GpuComputePipeline::new(object)
    }

    pub async fn create_compute_pipeline_async(
        &self,
        descriptor: wit::GpuComputePipelineDescriptor<'_>,
    ) -> Result<wit::GpuComputePipeline, wit::CreatePipelineError> {
        let label = descriptor.label.clone();
        let descriptor = compute(descriptor).map_err(pipeline_error)?;
        let owner = &self.object.owner;
        let raw = owner
            .device
            .raw
            .create_compute_pipeline_inner(descriptor)
            .map_err(pipeline_error)?;
        Ok(wit::GpuComputePipeline::new(Object::new(
            owner.clone(),
            raw,
            label,
        )))
    }

    pub fn create_render_pipeline(
        &self,
        descriptor: wit::GpuRenderPipelineDescriptor<'_>,
    ) -> wit::GpuRenderPipeline {
        let label = descriptor.label.clone();
        let owner = &self.object.owner;
        let object = match render(descriptor) {
            Ok(descriptor) => Object::new(
                owner.clone(),
                owner.created(owner.device.raw.create_render_pipeline(descriptor)),
                label,
            ),
            Err(error) => {
                owner.report(&error);
                Object::invalid(owner.clone(), label)
            }
        };
        wit::GpuRenderPipeline::new(object)
    }

    pub async fn create_render_pipeline_async(
        &self,
        descriptor: wit::GpuRenderPipelineDescriptor<'_>,
    ) -> Result<wit::GpuRenderPipeline, wit::CreatePipelineError> {
        let label = descriptor.label.clone();
        let descriptor = render(descriptor).map_err(pipeline_error)?;
        let owner = &self.object.owner;
        let raw = owner
            .device
            .raw
            .create_render_pipeline_inner(descriptor)
            .map_err(pipeline_error)?;
        Ok(wit::GpuRenderPipeline::new(Object::new(
            owner.clone(),
            raw,
            label,
        )))
    }
}
