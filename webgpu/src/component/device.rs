//! Device-owned creation preserves core validation and invalid resource objects.

use core::cell::Cell;
use std::rc::Rc;
use wgpu_core::{binding_model, command, pipeline, resource};

use super::{
    backend,
    buffer::Buffer,
    convert::Convert,
    encoder::Encoder,
    queue::Queue,
    recording::Recorder,
    render::{BundleEncoder, RenderRecorder},
    resource::{QuerySet, Texture},
    state::DeviceState,
    value::{CompilationMessage, Object, Shader},
    wit,
};

pub struct Device {
    pub object: Object<()>,
    pub queue: Queue,
    pub info: wgpu_types::AdapterInfo,
}

impl Device {
    pub fn create_texture(&self, mut descriptor: wit::GpuTextureDescriptor) -> wit::GpuTexture {
        let owner = &self.object.owner;
        let native = resource::TextureDescriptor {
            label: descriptor.label.as_deref().map(Into::into),
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
        };
        let raw = owner.created(owner.device.raw.create_texture(&native));
        // Core devices leave this compatibility-only texture property undefined.
        descriptor.texture_binding_view_dimension = None;
        wit::GpuTexture::new(Texture {
            object: Object::new(owner.clone(), raw, descriptor.label.clone()),
            descriptor,
        })
    }
    pub fn create_bind_group_layout(
        &self,
        descriptor: wit::GpuBindGroupLayoutDescriptor,
    ) -> wit::GpuBindGroupLayout {
        let owner = &self.object.owner;
        let entries = descriptor
            .entries
            .into_iter()
            .map(binding_layout)
            .collect::<Result<Vec<_>, _>>();
        let object = match entries {
            Ok(entries) => {
                let raw = owner.created(owner.device.raw.create_bind_group_layout(
                    &binding_model::BindGroupLayoutDescriptor {
                        label: descriptor.label.as_deref().map(Into::into),
                        entries: entries.into(),
                    },
                ));
                Object::new(owner.clone(), raw, descriptor.label)
            }
            Err(error) => {
                owner.invalid(error.to_string());
                Object::invalid(owner.clone(), descriptor.label)
            }
        };
        wit::GpuBindGroupLayout::new(object)
    }

    pub fn create_pipeline_layout(
        &self,
        descriptor: wit::GpuPipelineLayoutDescriptor<'_>,
    ) -> wit::GpuPipelineLayout {
        let owner = &self.object.owner;
        let layouts = descriptor
            .bind_group_layouts
            .iter()
            .map(|layout| match layout {
                Some(layout) => layout
                    .get::<Object<backend::BindGroupLayout>>()
                    .get()
                    .map(|raw| Some(raw.clone())),
                None => Some(None),
            })
            .collect::<Option<Vec<_>>>();
        let object = match layouts {
            Some(layouts) => {
                let raw = owner.created(owner.device.raw.create_pipeline_layout(
                    &binding_model::PipelineLayoutDescriptor {
                        label: descriptor.label.as_deref().map(Into::into),
                        bind_group_layouts: layouts.into(),
                        immediate_size: descriptor.immediate_size.unwrap_or(0),
                    },
                ));
                Object::new(owner.clone(), raw, descriptor.label)
            }
            None => {
                owner.invalid("pipeline layout uses an invalid bind group layout");
                Object::invalid(owner.clone(), descriptor.label)
            }
        };
        wit::GpuPipelineLayout::new(object)
    }

    fn binding(
        &self,
        binding: &wit::GpuBindingResource<'_>,
    ) -> Option<binding_model::BindingResource<'static>> {
        use binding_model::{BindingResource as B, BufferBinding};
        use wit::GpuBindingResource as W;
        Some(match binding {
            W::GpuBuffer(buffer) => B::Buffer(BufferBinding {
                buffer: buffer.get::<Buffer>().object.get()?.clone(),
                offset: 0,
                size: None,
            }),
            W::GpuBufferBinding(binding) => B::Buffer(BufferBinding {
                buffer: binding.buffer.get::<Buffer>().object.get()?.clone(),
                offset: binding.offset.unwrap_or(0),
                size: binding.size,
            }),
            W::GpuSampler(sampler) => {
                B::Sampler(sampler.get::<Object<backend::Sampler>>().get()?.clone())
            }
            W::GpuTextureView(view) => {
                B::TextureView(view.get::<Object<backend::TextureView>>().get()?.clone())
            }
            W::GpuTexture(texture) => {
                let texture = texture.get::<Texture>().object.get()?;
                B::TextureView(
                    self.object
                        .owner
                        .created(texture.create_view(&resource::TextureViewDescriptor::default())),
                )
            }
        })
    }

    pub fn create_bind_group(
        &self,
        descriptor: wit::GpuBindGroupDescriptor<'_>,
    ) -> wit::GpuBindGroup {
        let owner = &self.object.owner;
        let layout = descriptor
            .layout
            .get::<Object<backend::BindGroupLayout>>()
            .get();
        let entries = descriptor
            .entries
            .iter()
            .map(|entry| {
                Some(binding_model::BindGroupEntry {
                    binding: entry.binding,
                    resource: self.binding(&entry.resource)?,
                })
            })
            .collect::<Option<Vec<_>>>();
        let object = match (layout, entries) {
            (Some(layout), Some(entries)) => {
                let raw = owner.created(owner.device.raw.create_bind_group(
                    &binding_model::BindGroupDescriptor {
                        label: descriptor.label.as_deref().map(Into::into),
                        layout: layout.clone(),
                        entries: entries.into(),
                    },
                ));
                Object::new(owner.clone(), raw, descriptor.label)
            }
            _ => {
                owner.invalid("bind group uses an invalid resource");
                Object::invalid(owner.clone(), descriptor.label)
            }
        };
        wit::GpuBindGroup::new(object)
    }
    pub fn new(
        device: backend::Device,
        info: wgpu_types::AdapterInfo,
        label: Option<String>,
        queue_label: Option<String>,
    ) -> Self {
        let owner = Rc::new(DeviceState::new(device));
        Self {
            object: Object::new(owner.clone(), (), label),
            queue: Queue::new(owner, queue_label),
            info,
        }
    }

    pub fn create_buffer(&self, descriptor: wit::GpuBufferDescriptor) -> wit::GpuBuffer {
        let owner = &self.object.owner;
        let (raw, error) = owner
            .device
            .raw
            .create_buffer(&wgpu_types::BufferDescriptor {
                label: descriptor.label.as_deref().map(Into::into),
                size: descriptor.size,
                usage: descriptor.usage.convert(),
                mapped_at_creation: descriptor.mapped_at_creation.unwrap_or(false),
            });
        let object = match error {
            Some(error) => {
                owner.report(&error);
                Object::invalid(owner.clone(), descriptor.label.clone())
            }
            None => Object::new(owner.clone(), raw, descriptor.label.clone()),
        };
        wit::GpuBuffer::new(Buffer::new(object, &descriptor))
    }

    pub fn create_sampler(&self, descriptor: Option<wit::GpuSamplerDescriptor>) -> wit::GpuSampler {
        let label = descriptor.as_ref().and_then(|d| d.label.clone());
        let defaults = wgpu_types::SamplerDescriptor::<Option<&str>>::default();
        let mut native = resource::SamplerDescriptor {
            label: label.as_deref().map(Into::into),
            address_modes: [
                defaults.address_mode_u,
                defaults.address_mode_v,
                defaults.address_mode_w,
            ],
            mag_filter: defaults.mag_filter,
            min_filter: defaults.min_filter,
            mipmap_filter: defaults.mipmap_filter,
            lod_min_clamp: defaults.lod_min_clamp,
            lod_max_clamp: defaults.lod_max_clamp,
            compare: defaults.compare,
            anisotropy_clamp: defaults.anisotropy_clamp,
            border_color: None,
        };
        if let Some(d) = descriptor {
            for (target, source) in native.address_modes.iter_mut().zip([
                d.address_mode_u,
                d.address_mode_v,
                d.address_mode_w,
            ]) {
                if let Some(source) = source {
                    *target = source.convert();
                }
            }
            native.mag_filter = d
                .mag_filter
                .map(Convert::convert)
                .unwrap_or(native.mag_filter);
            native.min_filter = d
                .min_filter
                .map(Convert::convert)
                .unwrap_or(native.min_filter);
            native.mipmap_filter = d
                .mipmap_filter
                .map(Convert::convert)
                .unwrap_or(native.mipmap_filter);
            native.lod_min_clamp = d.lod_min_clamp.unwrap_or(native.lod_min_clamp);
            native.lod_max_clamp = d.lod_max_clamp.unwrap_or(native.lod_max_clamp);
            native.compare = d.compare.map(Convert::convert);
            native.anisotropy_clamp = d.max_anisotropy.unwrap_or(native.anisotropy_clamp);
        }
        let owner = &self.object.owner;
        let raw = owner.created(owner.device.raw.create_sampler(&native));
        wit::GpuSampler::new(Object::new(owner.clone(), raw, label))
    }

    pub fn create_shader_module(
        &self,
        descriptor: wit::GpuShaderModuleDescriptor<'_>,
    ) -> wit::GpuShaderModule {
        let owner = &self.object.owner;
        // Compilation hints are optional optimization hints in WebGPU. Core
        // compiles each entry point when its pipeline is created.
        let (raw, error) = owner.device.raw.create_shader_module(
            &pipeline::ShaderModuleDescriptor {
                label: descriptor.label.as_deref().map(Into::into),
                runtime_checks: wgpu_types::ShaderRuntimeChecks::default(),
            },
            pipeline::ShaderModuleSource::Wgsl(descriptor.code.as_str().into()),
        );
        let diagnostics = match error {
            Some(error) => {
                owner.report(&error);
                wgpu::CompilationInfo::from(error)
                    .messages
                    .into_iter()
                    .map(|message| CompilationMessage::from_wgpu(message, &descriptor.code))
                    .collect()
            }
            None => Vec::new(),
        };
        wit::GpuShaderModule::new(Shader {
            object: Object::new(owner.clone(), raw, descriptor.label),
            diagnostics,
        })
    }

    pub fn create_command_encoder(
        &self,
        descriptor: Option<wit::GpuCommandEncoderDescriptor>,
    ) -> wit::GpuCommandEncoder {
        let label = descriptor.and_then(|d| d.label);
        let owner = &self.object.owner;
        let raw = owner.created(owner.device.raw.create_command_encoder(
            &wgpu_types::CommandEncoderDescriptor {
                label: label.as_deref().map(Into::into),
            },
        ));
        wit::GpuCommandEncoder::new(Encoder(Recorder::new(
            owner.clone(),
            Some(raw),
            label,
            Rc::new(Cell::new(false)),
        )))
    }

    pub fn create_render_bundle_encoder(
        &self,
        descriptor: wit::GpuRenderBundleEncoderDescriptor,
    ) -> wit::GpuRenderBundleEncoder {
        let native = command::RenderBundleEncoderDescriptor {
            label: descriptor.label.as_deref().map(Into::into),
            color_formats: descriptor
                .color_formats
                .into_iter()
                .map(|f| f.map(Convert::convert))
                .collect(),
            depth_stencil: descriptor.depth_stencil_format.map(|format| {
                wgpu_types::RenderBundleDepthStencil {
                    format: format.convert(),
                    depth_read_only: descriptor.depth_read_only.unwrap_or(false),
                    stencil_read_only: descriptor.stencil_read_only.unwrap_or(false),
                }
            }),
            sample_count: descriptor.sample_count.unwrap_or(1),
            multiview: None,
        };
        let owner = &self.object.owner;
        let (raw, error) = owner.device.raw.create_render_bundle_encoder(&native);
        let invalid = error.is_some();
        if let Some(error) = error {
            owner.report(&error);
        }
        wit::GpuRenderBundleEncoder::new(BundleEncoder(RenderRecorder {
            recorder: Recorder::new(
                owner.clone(),
                Some(*raw),
                descriptor.label,
                Rc::new(Cell::new(invalid)),
            ),
            draws: Cell::new(0),
            // The enclosing render pass enforces its maxDrawCount, including
            // every execution of this bundle.
            limit: u64::MAX,
        }))
    }

    pub fn create_query_set(
        &self,
        descriptor: wit::GpuQuerySetDescriptor,
    ) -> Result<wit::GpuQuerySet, wit::CreateQuerySetError> {
        let owner = &self.object.owner;
        // WebGPU createQuerySet throws TypeError before device validation when
        // timestamp-query was not enabled.
        if matches!(descriptor.type_, wit::GpuQueryType::Timestamp)
            && !owner
                .device
                .raw
                .features()
                .contains(wgpu_types::Features::TIMESTAMP_QUERY)
        {
            return Err(wit::CreateQuerySetError {
                kind: wit::CreateQuerySetErrorKind::TypeError,
                message: "timestamp-query was not enabled on this device".into(),
            });
        }
        let raw = owner.created(owner.device.raw.create_query_set(
            &wgpu_types::QuerySetDescriptor {
                label: descriptor.label.as_deref().map(Into::into),
                ty: descriptor.type_.convert(),
                count: descriptor.count,
            },
        ));
        Ok(wit::GpuQuerySet::new(QuerySet {
            object: Object::new(owner.clone(), raw, descriptor.label),
            kind: descriptor.type_,
            count: descriptor.count,
        }))
    }
}

#[derive(Debug, thiserror::Error)]
#[error("bind group layout entry {0} must specify exactly one binding kind")]
struct BindingKindCount(u32);

fn binding_layout(
    entry: wit::GpuBindGroupLayoutEntry,
) -> Result<wgpu_types::BindGroupLayoutEntry, BindingKindCount> {
    use wgpu_types::{BindingType as B, BufferBindingType, TextureSampleType};
    let ty = match (
        entry.buffer,
        entry.sampler,
        entry.texture,
        entry.storage_texture,
    ) {
        (Some(buffer), None, None, None) => B::Buffer {
            ty: match buffer.type_.unwrap_or(wit::GpuBufferBindingType::Uniform) {
                wit::GpuBufferBindingType::Uniform => BufferBindingType::Uniform,
                wit::GpuBufferBindingType::Storage => {
                    BufferBindingType::Storage { read_only: false }
                }
                wit::GpuBufferBindingType::ReadOnlyStorage => {
                    BufferBindingType::Storage { read_only: true }
                }
            },
            has_dynamic_offset: buffer.has_dynamic_offset.unwrap_or(false),
            min_binding_size: buffer
                .min_binding_size
                .and_then(wgpu_types::BufferSize::new),
        },
        (None, Some(sampler), None, None) => B::Sampler(
            sampler
                .type_
                .unwrap_or(wit::GpuSamplerBindingType::Filtering)
                .convert(),
        ),
        (None, None, Some(texture), None) => B::Texture {
            sample_type: match texture
                .sample_type
                .unwrap_or(wit::GpuTextureSampleType::Float)
            {
                wit::GpuTextureSampleType::Float => TextureSampleType::Float { filterable: true },
                wit::GpuTextureSampleType::UnfilterableFloat => {
                    TextureSampleType::Float { filterable: false }
                }
                wit::GpuTextureSampleType::Depth => TextureSampleType::Depth,
                wit::GpuTextureSampleType::Sint => TextureSampleType::Sint,
                wit::GpuTextureSampleType::Uint => TextureSampleType::Uint,
            },
            view_dimension: texture
                .view_dimension
                .unwrap_or(wit::GpuTextureViewDimension::D2)
                .convert(),
            multisampled: texture.multisampled.unwrap_or(false),
        },
        (None, None, None, Some(texture)) => B::StorageTexture {
            access: texture
                .access
                .unwrap_or(wit::GpuStorageTextureAccess::WriteOnly)
                .convert(),
            format: texture.format.convert(),
            view_dimension: texture
                .view_dimension
                .unwrap_or(wit::GpuTextureViewDimension::D2)
                .convert(),
        },
        _ => return Err(BindingKindCount(entry.binding)),
    };
    Ok(wgpu_types::BindGroupLayoutEntry {
        binding: entry.binding,
        visibility: entry.visibility.convert(),
        ty,
        count: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry() -> wit::GpuBindGroupLayoutEntry {
        wit::GpuBindGroupLayoutEntry {
            binding: 3,
            visibility: wit::GpuShaderStage::COMPUTE,
            buffer: None,
            sampler: None,
            texture: None,
            storage_texture: None,
        }
    }

    #[test]
    fn binding_layout_rejects_missing_and_ambiguous_kinds() {
        assert!(binding_layout(entry()).is_err());
        let mut descriptor = entry();
        descriptor.buffer = Some(wit::GpuBufferBindingLayout {
            type_: None,
            has_dynamic_offset: None,
            min_binding_size: None,
        });
        descriptor.sampler = Some(wit::GpuSamplerBindingLayout { type_: None });
        assert!(binding_layout(descriptor).is_err());
    }

    #[test]
    fn zero_minimum_binding_size_defers_size_validation_to_pipeline_use() {
        let mut descriptor = entry();
        descriptor.buffer = Some(wit::GpuBufferBindingLayout {
            type_: Some(wit::GpuBufferBindingType::ReadOnlyStorage),
            has_dynamic_offset: Some(true),
            min_binding_size: Some(0),
        });
        let layout = binding_layout(descriptor).unwrap();
        assert_eq!(layout.binding, 3);
        assert_eq!(layout.visibility, wgpu_types::ShaderStages::COMPUTE);
        assert_eq!(
            layout.ty,
            wgpu_types::BindingType::Buffer {
                ty: wgpu_types::BufferBindingType::Storage { read_only: true },
                has_dynamic_offset: true,
                min_binding_size: None,
            }
        );
    }
}
