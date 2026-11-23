//! What the content timeline asks of a device timeline.
//!
//! Every value here is owned and names objects only by the ids the content
//! timeline allocated, so a synchronous export builds a command, queues it
//! and returns; the device task executes the queue in order. Answers travel
//! back on one-shot channels that only async exports await.

use core::{cell::OnceCell, ops::Range};
use std::rc::Rc;

use async_channel::Sender;
use helios_api::{image::Image, sync::Timeline, sync::TimelineError};
use wgpu_core::{
    binding_model,
    command::{
        ComputePassDescriptor, PassTimestampWrites, RenderBundleEncoderDescriptor,
        RenderPassDescriptor, TexelCopyBufferInfo, TexelCopyTextureInfo,
    },
    device::{
        HostMap,
        global::{BindingResource, ComputePipelineDescriptor, RenderPipelineDescriptor},
    },
    id, resource,
};

use super::{
    ids::Release, presentation, presentation::LinearImage, scope::ErrorTarget,
    value::CompilationMessage, wit,
};
use crate::runtime::{DeviceLoss, GpuError};

/// One-shot answer to the content timeline.
pub type Reply<T> = Sender<T>;

/// A command and the error scopes it reports to.
pub struct Queued {
    pub target: ErrorTarget,
    pub command: Command,
}

/// Owned bytes with the range a command reads from them, so selecting a
/// sub-range on the content timeline copies nothing.
pub struct Bytes {
    pub data: Vec<u8>,
    pub range: Range<usize>,
}

impl Bytes {
    pub fn all(data: Vec<u8>) -> Self {
        let range = 0..data.len();
        Self { data, range }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data[self.range.clone()]
    }
}

pub enum Command {
    /// An error the content timeline found, reported in queue order.
    Error(GpuError),
    /// Answered once every earlier command has executed.
    Fence(Reply<()>),
    /// Answered with the device's loss notification.
    Lost(Reply<DeviceLoss>),
    /// Route uncaptured errors of later commands to `events`.
    Subscribe {
        events: Sender<GpuError>,
        done: Reply<()>,
    },
    Release(Release),
    StandIn(StandIn),
    Create(Create),
    DestroyBuffer(id::BufferId),
    DestroyTexture(id::TextureId),
    DestroyQuerySet(id::QuerySetId),
    /// Map `range`, then answer with a copy of its contents.
    Map {
        buffer: id::BufferId,
        host: HostMap,
        range: Range<u64>,
        reply: Reply<Result<Vec<u8>, wit::MapAsyncError>>,
    },
    /// Write the content timeline's copy of a writable mapping back at its
    /// offset, then unmap.
    Unmap {
        buffer: id::BufferId,
        write_back: Option<(u64, Vec<u8>)>,
    },
    Submit(Vec<id::CommandBufferId>),
    WriteBuffer {
        buffer: id::BufferId,
        offset: u64,
        data: Bytes,
    },
    WriteTexture {
        destination: TexelCopyTextureInfo,
        data: Vec<u8>,
        layout: wgpu_types::TexelCopyBufferLayout,
        size: wgpu_types::Extent3d,
    },
    /// Answered when the queue has completed all work submitted before it.
    WorkDone(Reply<()>),
    Encoder(id::CommandEncoderId, EncoderCommand),
    ComputePass(id::ComputePassEncoderId, ComputeCommand),
    RenderPass(id::RenderPassEncoderId, RenderCommand),
    Bundle(id::RenderBundleEncoderId, BundleCommand),
    Present(Present),
    /// Destroy the device, answered after its last submission completes.
    Destroy(Reply<()>),
    /// A completion watcher saw the queue reach a marker.
    Completed(Completion),
}

pub enum Create {
    Buffer {
        id: id::BufferId,
        descriptor: resource::BufferDescriptor<'static>,
    },
    Texture {
        id: id::TextureId,
        descriptor: resource::TextureDescriptor<'static>,
    },
    ChildTexture {
        parent: id::TextureId,
        id: id::TextureId,
        descriptor: resource::TextureDescriptor<'static>,
    },
    TextureView {
        texture: id::TextureId,
        id: id::TextureViewId,
        descriptor: resource::TextureViewDescriptor<'static>,
    },
    Sampler {
        id: id::SamplerId,
        descriptor: resource::SamplerDescriptor<'static>,
    },
    BindGroupLayout {
        id: id::BindGroupLayoutId,
        descriptor: binding_model::BindGroupLayoutDescriptor<'static>,
    },
    /// A layout the content timeline already rejected.
    InvalidBindGroupLayout {
        id: id::BindGroupLayoutId,
        label: Option<String>,
    },
    PipelineLayout {
        id: id::PipelineLayoutId,
        descriptor: binding_model::PipelineLayoutDescriptor<'static, id::BindGroupLayoutId>,
    },
    BindGroup {
        id: id::BindGroupId,
        label: Option<String>,
        layout: id::BindGroupLayoutId,
        entries: Vec<(u32, Binding)>,
    },
    ShaderModule {
        id: id::ShaderModuleId,
        label: Option<String>,
        code: String,
        diagnostics: Rc<OnceCell<Vec<CompilationMessage>>>,
    },
    /// With a reply, the pipeline is created for an async export: its error
    /// rejects the call instead of reaching an error scope.
    ComputePipeline {
        id: id::ComputePipelineId,
        descriptor: ComputePipelineDescriptor<'static>,
        reply: Option<Reply<Result<(), wit::CreatePipelineError>>>,
    },
    /// Boxed: the descriptor is several times the size of any other.
    RenderPipeline {
        id: id::RenderPipelineId,
        descriptor: Box<RenderPipelineDescriptor<'static>>,
        reply: Option<Reply<Result<(), wit::CreatePipelineError>>>,
    },
    PipelineBindGroupLayout {
        pipeline: Pipeline,
        index: u32,
        id: id::BindGroupLayoutId,
    },
    CommandEncoder {
        id: id::CommandEncoderId,
        label: Option<String>,
    },
    RenderBundleEncoder {
        id: id::RenderBundleEncoderId,
        descriptor: RenderBundleEncoderDescriptor<'static>,
    },
    QuerySet {
        id: id::QuerySetId,
        descriptor: wgpu_types::QuerySetDescriptor<wgpu_core::Label<'static>>,
    },
}

pub enum Binding {
    Resource(BindingResource<'static>),
    /// A whole texture: the device timeline creates its default view.
    DefaultView(id::TextureId),
}

pub enum Pipeline {
    Compute(id::ComputePipelineId),
    Render(id::RenderPipelineId),
}

/// The invalid object a foreign reference is replaced by.
///
/// A command never names an object of another device: that device's
/// timeline may not have created it yet, or may already have dropped it.
/// The content timeline substitutes this device's stand-in of the same
/// kind, so core reports the reference as an invalid object and invalidates
/// whatever depends on it, as WebGPU requires for a foreign object.
pub enum StandIn {
    Buffer(id::BufferId),
    Texture(id::TextureId),
    TextureView(id::TextureViewId),
    Sampler(id::SamplerId),
    BindGroupLayout(id::BindGroupLayoutId),
    PipelineLayout(id::PipelineLayoutId),
    BindGroup(id::BindGroupId),
    ShaderModule(id::ShaderModuleId),
    ComputePipeline(id::ComputePipelineId),
    RenderPipeline(id::RenderPipelineId),
    QuerySet(id::QuerySetId),
    RenderBundle(id::RenderBundleId),
}

pub enum EncoderCommand {
    PushDebugGroup(String),
    PopDebugGroup,
    InsertDebugMarker(String),
    BeginComputePass {
        id: id::ComputePassEncoderId,
        descriptor: ComputePassDescriptor<'static, PassTimestampWrites<id::QuerySetId>>,
    },
    BeginRenderPass {
        id: id::RenderPassEncoderId,
        descriptor: RenderPassDescriptor<'static>,
    },
    CopyBufferToBuffer {
        source: id::BufferId,
        source_offset: u64,
        destination: id::BufferId,
        destination_offset: u64,
        size: Option<u64>,
    },
    CopyBufferToTexture {
        source: TexelCopyBufferInfo,
        destination: TexelCopyTextureInfo,
        size: wgpu_types::Extent3d,
    },
    CopyTextureToBuffer {
        source: TexelCopyTextureInfo,
        destination: TexelCopyBufferInfo,
        size: wgpu_types::Extent3d,
    },
    CopyTextureToTexture {
        source: TexelCopyTextureInfo,
        destination: TexelCopyTextureInfo,
        size: wgpu_types::Extent3d,
    },
    ClearBuffer {
        buffer: id::BufferId,
        offset: u64,
        size: Option<u64>,
    },
    ResolveQuerySet {
        query_set: id::QuerySetId,
        first: u32,
        count: u32,
        destination: id::BufferId,
        offset: u64,
    },
    Finish {
        id: id::CommandBufferId,
        label: Option<String>,
    },
}

pub enum ComputeCommand {
    End,
    PushDebugGroup(String),
    PopDebugGroup,
    InsertDebugMarker(String),
    SetPipeline(id::ComputePipelineId),
    Dispatch([u32; 3]),
    DispatchIndirect {
        buffer: id::BufferId,
        offset: u64,
    },
    SetBindGroup {
        index: u32,
        group: Option<id::BindGroupId>,
        offsets: Vec<u32>,
    },
    SetImmediates {
        offset: u32,
        data: Bytes,
    },
}

/// Commands a render pass and a render bundle encoder record alike.
pub enum DrawCommand {
    PushDebugGroup(String),
    PopDebugGroup,
    InsertDebugMarker(String),
    SetPipeline(id::RenderPipelineId),
    SetBindGroup {
        index: u32,
        group: Option<id::BindGroupId>,
        offsets: Vec<u32>,
    },
    SetImmediates {
        offset: u32,
        data: Bytes,
    },
    SetIndexBuffer {
        buffer: id::BufferId,
        format: wgpu_types::IndexFormat,
        offset: u64,
        size: Option<u64>,
    },
    SetVertexBuffer {
        slot: u32,
        buffer: Option<id::BufferId>,
        offset: u64,
        size: Option<u64>,
    },
    Draw {
        vertices: u32,
        instances: u32,
        first_vertex: u32,
        first_instance: u32,
    },
    DrawIndexed {
        indices: u32,
        instances: u32,
        first_index: u32,
        base_vertex: i32,
        first_instance: u32,
    },
    DrawIndirect {
        buffer: id::BufferId,
        offset: u64,
    },
    DrawIndexedIndirect {
        buffer: id::BufferId,
        offset: u64,
    },
}

pub enum RenderCommand {
    Draw(DrawCommand),
    SetViewport {
        x: f32,
        y: f32,
        width: f32,
        height: f32,
        min_depth: f32,
        max_depth: f32,
    },
    SetScissorRect {
        x: u32,
        y: u32,
        width: u32,
        height: u32,
    },
    SetBlendConstant(wgpu_types::Color),
    SetStencilReference(u32),
    BeginOcclusionQuery(u32),
    EndOcclusionQuery,
    ExecuteBundles(Vec<id::RenderBundleId>),
    End,
}

pub enum BundleCommand {
    Draw(DrawCommand),
    /// `invalid` marks an encoder the content timeline already rejected:
    /// the bundle is registered invalid.
    Finish {
        id: id::RenderBundleId,
        label: Option<String>,
        invalid: bool,
    },
}

/// Copy the canvas drawing buffer into a fresh exported image and submit.
pub struct Present {
    pub parent: id::TextureId,
    pub width: u32,
    pub height: u32,
    pub format: wgpu_types::TextureFormat,
    pub reply: Reply<Result<Frame, presentation::Error>>,
}

/// An exported image and the marker its copy signals.
pub struct Frame {
    pub image: Image,
    pub ready: Timeline,
}

pub struct Completion {
    pub waited: Result<bool, TimelineError>,
    pub then: AfterCompletion,
}

/// What the device timeline does once the queue reaches a marker, after
/// polling the device.
pub enum AfterCompletion {
    Poll,
    Destroyed(Reply<()>),
    /// The GPU no longer reads the image: release it. Boxed: the image
    /// carries its device's whole Vulkan dispatch table.
    Retire(Box<LinearImage>),
}
