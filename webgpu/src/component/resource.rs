use std::{borrow::Cow, rc::Rc};

use wgpu_core::id::markers;

use super::command::{Command, Create, Pipeline};
use super::content::Handle;
use super::convert::Convert;
use super::wit;

pub struct AdapterInfo(pub wgpu_types::AdapterInfo);
impl wit::GuestGpuAdapterInfo for AdapterInfo {
    fn vendor(&self) -> String {
        format!("{:x}", self.0.vendor)
    }
    // wgpu exposes no architecture identifier. WebGPU permits empty identifying strings.
    fn architecture(&self) -> String {
        String::new()
    }
    fn device(&self) -> String {
        format!("{:x}", self.0.device)
    }
    fn description(&self) -> String {
        self.0.name.clone()
    }
    fn subgroup_min_size(&self) -> u32 {
        self.0.subgroup_min_size
    }
    fn subgroup_max_size(&self) -> u32 {
        self.0.subgroup_max_size
    }
    fn is_fallback_adapter(&self) -> bool {
        self.0.device_type == wgpu_types::DeviceType::Cpu
    }
}

macro_rules! labeled {
    ($($guest:ident => $marker:ident),* $(,)?) => {$ (
        impl wit::$guest for Handle<markers::$marker> {
            fn label(&self) -> String { Handle::label(self) }
            fn set_label(&self, label: String) { Handle::set_label(self, label); }
        }
    )*};
}

labeled! {
    GuestGpuBindGroup => BindGroup,
    GuestGpuBindGroupLayout => BindGroupLayout,
    GuestGpuPipelineLayout => PipelineLayout,
    GuestGpuSampler => Sampler,
    GuestGpuTextureView => TextureView,
}

macro_rules! pipeline {
    ($guest:ident, $marker:ident, $kind:ident) => {
        impl wit::$guest for Handle<markers::$marker> {
            fn label(&self) -> String {
                Handle::label(self)
            }
            fn set_label(&self, label: String) {
                Handle::set_label(self, label);
            }
            fn get_bind_group_layout(&self, index: u32) -> wit::GpuBindGroupLayout {
                let layout = Handle::<markers::BindGroupLayout>::new(&self.device, None);
                self.device
                    .enqueue(Command::Create(Create::PipelineBindGroupLayout {
                        pipeline: Pipeline::$kind(self.id),
                        index,
                        id: layout.id,
                    }));
                wit::GpuBindGroupLayout::new(layout)
            }
        }
    };
}
pipeline!(GuestGpuComputePipeline, ComputePipeline, Compute);
pipeline!(GuestGpuRenderPipeline, RenderPipeline, Render);

pub struct QuerySet {
    pub handle: Handle<markers::QuerySet>,
    pub kind: wit::GpuQueryType,
    pub count: u32,
}
impl wit::GuestGpuQuerySet for QuerySet {
    fn destroy(&self) {
        self.handle
            .device
            .enqueue(Command::DestroyQuerySet(self.handle.id));
    }
    fn type_(&self) -> wit::GpuQueryType {
        self.kind
    }
    fn count(&self) -> u32 {
        self.count
    }
    fn label(&self) -> String {
        self.handle.label()
    }
    fn set_label(&self, label: String) {
        self.handle.set_label(label);
    }
}

/// A texture handle and the descriptor its getters answer from. Clones
/// share one handle: the canvas hands out its current texture repeatedly.
#[derive(Clone)]
pub struct Texture {
    pub handle: Rc<Handle<markers::Texture>>,
    pub descriptor: Rc<wit::GpuTextureDescriptor>,
}

impl Texture {
    pub fn new(handle: Handle<markers::Texture>, descriptor: wit::GpuTextureDescriptor) -> Self {
        Self {
            handle: Rc::new(handle),
            descriptor: Rc::new(descriptor),
        }
    }

    /// The descriptor core creates the texture from.
    pub fn native(
        descriptor: &wit::GpuTextureDescriptor,
    ) -> wgpu_core::resource::TextureDescriptor<'static> {
        wgpu_core::resource::TextureDescriptor {
            label: descriptor.label.clone().map(Cow::Owned),
            size: descriptor.size.convert(),
            mip_level_count: descriptor.mip_level_count.unwrap_or(1),
            sample_count: descriptor.sample_count.unwrap_or(1),
            dimension: descriptor
                .dimension
                .unwrap_or(wit::GpuTextureDimension::D2)
                .convert(),
            format: descriptor.format.convert(),
            usage: descriptor.usage.convert(),
            view_formats: descriptor
                .view_formats
                .as_deref()
                .unwrap_or_default()
                .iter()
                .copied()
                .map(Convert::convert)
                .collect(),
        }
    }
}

impl wit::GuestGpuTexture for Texture {
    fn create_view(
        &self,
        descriptor: Option<wit::GpuTextureViewDescriptor>,
    ) -> wit::GpuTextureView {
        let device = &self.handle.device;
        let label = descriptor.as_ref().and_then(|d| d.label.clone());
        let view = Handle::<markers::TextureView>::new(device, label);
        let mut native = wgpu_core::resource::TextureViewDescriptor::default();
        let mut rejected = false;
        if let Some(descriptor) = &descriptor {
            native.label = descriptor.label.clone().map(Cow::Owned);
            native.format = descriptor.format.map(Convert::convert);
            native.dimension = descriptor.dimension.map(Convert::convert);
            native.usage = descriptor.usage.map(Convert::convert);
            native.range.aspect = descriptor
                .aspect
                .map(Convert::convert)
                .unwrap_or(wgpu_types::TextureAspect::All);
            native.range.base_mip_level = descriptor.base_mip_level.unwrap_or(0);
            native.range.mip_level_count = descriptor.mip_level_count;
            native.range.base_array_layer = descriptor.base_array_layer.unwrap_or(0);
            native.range.array_layer_count = descriptor.array_layer_count;
            if descriptor
                .swizzle
                .as_deref()
                .is_some_and(|swizzle| swizzle != "rgba")
            {
                device.invalid("texture-component-swizzle was not enabled on this device");
                rejected = true;
            }
        }
        if rejected {
            // Core has no swizzle: a view of the device's invalid texture
            // registers the invalid view, and core's own report of it is
            // dropped after the one above.
            device.enqueue_discarding(Command::Create(Create::TextureView {
                texture: device.stand_in::<markers::Texture>(),
                id: view.id,
                descriptor: native,
            }));
        } else {
            device.enqueue(Command::Create(Create::TextureView {
                texture: self.handle.id,
                id: view.id,
                descriptor: native,
            }));
        }
        wit::GpuTextureView::new(view)
    }
    fn destroy(&self) {
        self.handle
            .device
            .enqueue(Command::DestroyTexture(self.handle.id));
    }
    fn width(&self) -> u32 {
        self.descriptor.size.width
    }
    fn height(&self) -> u32 {
        self.descriptor.size.height.unwrap_or(1)
    }
    fn depth_or_array_layers(&self) -> u32 {
        self.descriptor.size.depth_or_array_layers.unwrap_or(1)
    }
    fn mip_level_count(&self) -> u32 {
        self.descriptor.mip_level_count.unwrap_or(1)
    }
    fn sample_count(&self) -> u32 {
        self.descriptor.sample_count.unwrap_or(1)
    }
    fn dimension(&self) -> wit::GpuTextureDimension {
        self.descriptor
            .dimension
            .unwrap_or(wit::GpuTextureDimension::D2)
    }
    fn format(&self) -> wit::GpuTextureFormat {
        self.descriptor.format
    }
    fn usage(&self) -> wit::GpuTextureUsage {
        self.descriptor.usage
    }
    fn texture_binding_view_dimension(&self) -> Option<wit::GpuTextureViewDimension> {
        self.descriptor.texture_binding_view_dimension
    }
    fn label(&self) -> String {
        self.handle.label()
    }
    fn set_label(&self, label: String) {
        self.handle.set_label(label);
    }
}
