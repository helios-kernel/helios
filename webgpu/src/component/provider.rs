//! The component the world exports: every resource type of `wasi:webgpu`
//! and the platform canvas, bound to their implementations.

use helios_api::bindings::exports::helios::webgpu::canvas as platform;

use super::{
    adapter::Adapter,
    backend,
    buffer::Buffer,
    canvas::{Canvas, CanvasContext},
    device::Device,
    encoder::Encoder,
    gpu::Gpu,
    queue::{CommandBuffer, Queue},
    recording::ComputePass,
    render::{BundleEncoder, RenderBundle, RenderPass},
    resource::{AdapterInfo, QuerySet, Texture},
    value::{
        CompilationInfo, CompilationMessage, Dictionary, Features, LanguageFeatures, Limits,
        Object, Shader, UncapturedError,
    },
    wit,
};
use crate::runtime::{DeviceLost, GpuError};

/// Marker for the exported implementation.
pub struct Provider;

impl wit::Guest for Provider {
    type Gpu = Gpu;
    type GpuAdapter = Adapter;
    type GpuAdapterInfo = AdapterInfo;
    type GpuBindGroup = Object<backend::BindGroup>;
    type GpuBindGroupLayout = Object<backend::BindGroupLayout>;
    type GpuBuffer = Buffer;
    type GpuCanvasContext = CanvasContext;
    type GpuCommandBuffer = CommandBuffer;
    type GpuCommandEncoder = Encoder;
    type GpuCompilationInfo = CompilationInfo;
    type GpuCompilationMessage = CompilationMessage;
    type GpuComputePassEncoder = ComputePass;
    type GpuComputePipeline = Object<backend::ComputePipeline>;
    type GpuDevice = Device;
    type GpuDeviceLostInfo = DeviceLost;
    type GpuError = GpuError;
    type GpuPipelineLayout = Object<backend::PipelineLayout>;
    type GpuQuerySet = QuerySet;
    type GpuQueue = Queue;
    type GpuRenderBundle = RenderBundle;
    type GpuRenderBundleEncoder = BundleEncoder;
    type GpuRenderPassEncoder = RenderPass;
    type GpuRenderPipeline = Object<backend::RenderPipeline>;
    type GpuSampler = Object<backend::Sampler>;
    type GpuShaderModule = Shader;
    type GpuSupportedFeatures = Features;
    type GpuSupportedLimits = Limits;
    type GpuTexture = Texture;
    type GpuTextureView = Object<backend::TextureView>;
    type GpuUncapturedErrorEvent = UncapturedError;
    type RecordGpuPipelineConstantValue = Dictionary<f64>;
    type RecordOptionGpuSize64 = Dictionary<Option<u64>>;
    type WgslLanguageFeatures = LanguageFeatures;

    fn get_gpu() -> wit::Gpu {
        wit::Gpu::new(Gpu::default())
    }
}

impl platform::Guest for Provider {
    type Canvas = Canvas;
}
