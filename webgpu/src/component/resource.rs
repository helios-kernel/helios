use super::backend;
use super::convert::Convert;
use super::value::Object;
use super::wit;

pub struct AdapterInfo(pub wgpu::AdapterInfo);
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
        self.0.device_type == wgpu::DeviceType::Cpu
    }
}

macro_rules! pipeline {
    ($guest:ident, $raw:ty) => {
        impl wit::$guest for Object<$raw> {
            fn label(&self) -> String {
                self.label()
            }
            fn set_label(&self, label: String) {
                self.set_label(label);
            }
            fn get_bind_group_layout(&self, index: u32) -> wit::GpuBindGroupLayout {
                let layout = match self.get() {
                    Some(raw) => Object::new(
                        self.owner.clone(),
                        self.owner.created(raw.get_bind_group_layout(index)),
                        None,
                    ),
                    None => Object::invalid(self.owner.clone(), None),
                };
                wit::GpuBindGroupLayout::new(layout)
            }
        }
    };
}
pipeline!(GuestGpuComputePipeline, backend::ComputePipeline);
pipeline!(GuestGpuRenderPipeline, backend::RenderPipeline);

pub struct QuerySet {
    pub object: Object<backend::QuerySet>,
    pub kind: wit::GpuQueryType,
    pub count: u32,
}
impl wit::GuestGpuQuerySet for QuerySet {
    fn destroy(&self) {
        if let Some(raw) = &self.object.raw {
            raw.destroy();
        }
    }
    fn type_(&self) -> wit::GpuQueryType {
        self.kind
    }
    fn count(&self) -> u32 {
        self.count
    }
    fn label(&self) -> String {
        self.object.label()
    }
    fn set_label(&self, label: String) {
        self.object.set_label(label);
    }
}

pub struct Texture {
    pub object: Object<backend::Texture>,
    pub descriptor: wit::GpuTextureDescriptor,
}

impl wit::GuestGpuTexture for Texture {
    fn create_view(
        &self,
        descriptor: Option<wit::GpuTextureViewDescriptor>,
    ) -> wit::GpuTextureView {
        let label = descriptor.as_ref().and_then(|d| d.label.clone());
        let invalid = || {
            wit::GpuTextureView::new(Object::<backend::TextureView>::invalid(
                self.object.owner.clone(),
                label.clone(),
            ))
        };
        let Some(raw) = self.object.get() else {
            return invalid();
        };
        let mut view = wgpu_core::resource::TextureViewDescriptor::default();
        if let Some(descriptor) = &descriptor {
            if descriptor
                .swizzle
                .as_deref()
                .is_some_and(|swizzle| swizzle != "rgba")
            {
                self.object
                    .owner
                    .invalid("texture-component-swizzle was not enabled on this device");
                return invalid();
            }
            view.label = descriptor.label.as_deref().map(Into::into);
            view.format = descriptor.format.map(Convert::convert);
            view.dimension = descriptor.dimension.map(Convert::convert);
            view.usage = descriptor.usage.map(Convert::convert);
            view.range.aspect = descriptor
                .aspect
                .map(Convert::convert)
                .unwrap_or(wgpu::TextureAspect::All);
            view.range.base_mip_level = descriptor.base_mip_level.unwrap_or(0);
            view.range.mip_level_count = descriptor.mip_level_count;
            view.range.base_array_layer = descriptor.base_array_layer.unwrap_or(0);
            view.range.array_layer_count = descriptor.array_layer_count;
        }
        let raw = self.object.owner.created(raw.create_view(&view));
        wit::GpuTextureView::new(Object::new(self.object.owner.clone(), raw, label))
    }
    fn destroy(&self) {
        if let Some(raw) = &self.object.raw {
            raw.destroy();
        }
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
        self.object.label()
    }
    fn set_label(&self, label: String) {
        self.object.set_label(label);
    }
}
