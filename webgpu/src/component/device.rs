//! The device on the content timeline: every creation allocates an id,
//! queues the creation and returns. Core validates on the device timeline
//! and registers an invalid object under the id when validation fails.

use core::cell::{Cell, OnceCell, RefCell};
use std::{borrow::Cow, rc::Rc};

use wgpu_core::{
    binding_model, command as core_command, device::global::BindingResource, id::markers, resource,
};

use super::{
    buffer::Buffer,
    command::{Binding, Command, Create},
    content::{DeviceShared, Handle},
    convert::Convert,
    encoder::Encoder,
    queue::Queue,
    recording::Recorder,
    render::{BundleEncoder, RenderRecorder},
    resource::{AdapterInfo, QuerySet, Texture},
    value::{Features, Limits, Shader},
    wit,
};
use crate::runtime::{DeviceLost, GpuErrorKind};

#[derive(Clone)]
pub struct Device {
    pub shared: Rc<DeviceShared>,
    label: Rc<RefCell<String>>,
    pub queue: Queue,
}

impl Device {
    pub fn new(
        shared: Rc<DeviceShared>,
        label: Option<String>,
        queue_label: Option<String>,
    ) -> Self {
        Self {
            queue: Queue::new(shared.clone(), queue_label),
            shared,
            label: Rc::new(RefCell::new(label.unwrap_or_default())),
        }
    }

    pub fn create(&self, create: Create) {
        self.shared.enqueue(Command::Create(create));
    }

    pub fn create_texture(&self, mut descriptor: wit::GpuTextureDescriptor) -> wit::GpuTexture {
        let handle = Handle::new(&self.shared, descriptor.label.clone());
        self.create(Create::Texture {
            id: handle.id,
            descriptor: Texture::native(&descriptor),
        });
        // Core devices leave this compatibility-only texture property undefined.
        descriptor.texture_binding_view_dimension = None;
        wit::GpuTexture::new(Texture::new(handle, descriptor))
    }

    pub fn create_bind_group_layout(
        &self,
        descriptor: wit::GpuBindGroupLayoutDescriptor,
    ) -> wit::GpuBindGroupLayout {
        let handle =
            Handle::<markers::BindGroupLayout>::new(&self.shared, descriptor.label.clone());
        let entries = descriptor
            .entries
            .into_iter()
            .map(binding_layout)
            .collect::<Result<Vec<_>, _>>();
        match entries {
            Ok(entries) => self.create(Create::BindGroupLayout {
                id: handle.id,
                descriptor: binding_model::BindGroupLayoutDescriptor {
                    label: descriptor.label.map(Cow::Owned),
                    entries: Cow::Owned(entries),
                },
            }),
            Err(error) => {
                self.shared.invalid(error.to_string());
                self.create(Create::InvalidBindGroupLayout {
                    id: handle.id,
                    label: descriptor.label,
                });
            }
        }
        wit::GpuBindGroupLayout::new(handle)
    }

    pub fn create_pipeline_layout(
        &self,
        descriptor: wit::GpuPipelineLayoutDescriptor<'_>,
    ) -> wit::GpuPipelineLayout {
        let handle = Handle::<markers::PipelineLayout>::new(&self.shared, descriptor.label.clone());
        let bind_group_layouts = descriptor
            .bind_group_layouts
            .iter()
            .map(|layout| {
                layout.as_ref().map(|layout| {
                    self.shared
                        .resolve(layout.get::<Handle<markers::BindGroupLayout>>())
                })
            })
            .collect();
        self.create(Create::PipelineLayout {
            id: handle.id,
            descriptor: binding_model::PipelineLayoutDescriptor {
                label: descriptor.label.map(Cow::Owned),
                bind_group_layouts: Cow::Owned(bind_group_layouts),
                immediate_size: descriptor.immediate_size.unwrap_or(0),
            },
        });
        wit::GpuPipelineLayout::new(handle)
    }

    fn binding(&self, binding: &wit::GpuBindingResource<'_>) -> Binding {
        use binding_model::BufferBinding;
        use wit::GpuBindingResource as W;
        let resource = match binding {
            W::GpuBuffer(buffer) => BindingResource::Buffer(BufferBinding {
                buffer: self.shared.resolve(&buffer.get::<Buffer>().handle),
                offset: 0,
                size: None,
            }),
            W::GpuBufferBinding(binding) => BindingResource::Buffer(BufferBinding {
                buffer: self.shared.resolve(&binding.buffer.get::<Buffer>().handle),
                offset: binding.offset.unwrap_or(0),
                size: binding.size,
            }),
            W::GpuSampler(sampler) => BindingResource::Sampler(
                self.shared
                    .resolve(sampler.get::<Handle<markers::Sampler>>()),
            ),
            W::GpuTextureView(view) => BindingResource::TextureView(
                self.shared
                    .resolve(view.get::<Handle<markers::TextureView>>()),
            ),
            W::GpuTexture(texture) => {
                return Binding::DefaultView(self.shared.resolve(&texture.get::<Texture>().handle));
            }
        };
        Binding::Resource(resource)
    }

    pub fn create_bind_group(
        &self,
        descriptor: wit::GpuBindGroupDescriptor<'_>,
    ) -> wit::GpuBindGroup {
        let handle = Handle::<markers::BindGroup>::new(&self.shared, descriptor.label.clone());
        let entries = descriptor
            .entries
            .iter()
            .map(|entry| (entry.binding, self.binding(&entry.resource)))
            .collect();
        self.create(Create::BindGroup {
            id: handle.id,
            label: descriptor.label,
            layout: self
                .shared
                .resolve(descriptor.layout.get::<Handle<markers::BindGroupLayout>>()),
            entries,
        });
        wit::GpuBindGroup::new(handle)
    }

    pub fn create_buffer(&self, descriptor: wit::GpuBufferDescriptor) -> wit::GpuBuffer {
        let handle = Handle::new(&self.shared, descriptor.label.clone());
        self.create(Create::Buffer {
            id: handle.id,
            descriptor: wgpu_types::BufferDescriptor {
                label: descriptor.label.clone().map(Cow::Owned),
                size: descriptor.size,
                usage: descriptor.usage.convert(),
                mapped_at_creation: descriptor.mapped_at_creation.unwrap_or(false),
            },
        });
        wit::GpuBuffer::new(Buffer::new(handle, &descriptor))
    }

    pub fn create_sampler(&self, descriptor: Option<wit::GpuSamplerDescriptor>) -> wit::GpuSampler {
        let label = descriptor.as_ref().and_then(|d| d.label.clone());
        let defaults = wgpu_types::SamplerDescriptor::<Option<&str>>::default();
        let mut native = resource::SamplerDescriptor {
            label: label.clone().map(Cow::Owned),
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
        let handle = Handle::<markers::Sampler>::new(&self.shared, label);
        self.create(Create::Sampler {
            id: handle.id,
            descriptor: native,
        });
        wit::GpuSampler::new(handle)
    }

    pub fn create_shader_module(
        &self,
        descriptor: wit::GpuShaderModuleDescriptor<'_>,
    ) -> wit::GpuShaderModule {
        // Compilation hints are optional optimization hints in WebGPU. Core
        // compiles each entry point when its pipeline is created.
        let handle = Handle::new(&self.shared, descriptor.label.clone());
        let diagnostics = Rc::new(OnceCell::new());
        self.create(Create::ShaderModule {
            id: handle.id,
            label: descriptor.label,
            code: descriptor.code,
            diagnostics: diagnostics.clone(),
        });
        wit::GpuShaderModule::new(Shader {
            handle,
            diagnostics,
        })
    }

    pub fn create_command_encoder(
        &self,
        descriptor: Option<wit::GpuCommandEncoderDescriptor>,
    ) -> wit::GpuCommandEncoder {
        let label = descriptor.and_then(|d| d.label);
        let handle = Handle::new(&self.shared, label.clone());
        self.create(Create::CommandEncoder {
            id: handle.id,
            label,
        });
        wit::GpuCommandEncoder::new(Encoder(Recorder::new(handle, Rc::new(Cell::new(false)))))
    }

    pub fn create_render_bundle_encoder(
        &self,
        descriptor: wit::GpuRenderBundleEncoderDescriptor,
    ) -> wit::GpuRenderBundleEncoder {
        let handle = Handle::new(&self.shared, descriptor.label.clone());
        self.create(Create::RenderBundleEncoder {
            id: handle.id,
            descriptor: core_command::RenderBundleEncoderDescriptor {
                label: descriptor.label.map(Cow::Owned),
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
            },
        });
        wit::GpuRenderBundleEncoder::new(BundleEncoder(RenderRecorder {
            recorder: Recorder::new(handle, Rc::new(Cell::new(false))),
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
        // WebGPU createQuerySet throws TypeError before device validation when
        // timestamp-query was not enabled.
        if matches!(descriptor.type_, wit::GpuQueryType::Timestamp)
            && !self
                .shared
                .capabilities
                .features
                .contains(wgpu_types::Features::TIMESTAMP_QUERY)
        {
            return Err(wit::CreateQuerySetError {
                kind: wit::CreateQuerySetErrorKind::TypeError,
                message: "timestamp-query was not enabled on this device".into(),
            });
        }
        let handle = Handle::new(&self.shared, descriptor.label.clone());
        self.create(Create::QuerySet {
            id: handle.id,
            descriptor: wgpu_types::QuerySetDescriptor {
                label: descriptor.label.map(Cow::Owned),
                ty: descriptor.type_.convert(),
                count: descriptor.count,
            },
        });
        Ok(wit::GpuQuerySet::new(QuerySet {
            handle,
            kind: descriptor.type_,
            count: descriptor.count,
        }))
    }
}

macro_rules! create_resource {
    ($name:ident, $descriptor:ty, $result:ty) => {
        fn $name(&self, descriptor: $descriptor) -> $result {
            Device::$name(self, descriptor)
        }
    };
}

impl wit::GuestGpuDevice for Device {
    fn label(&self) -> String {
        self.label.borrow().clone()
    }
    fn set_label(&self, label: String) {
        *self.label.borrow_mut() = label;
    }
    fn features(&self) -> wit::GpuSupportedFeatures {
        wit::GpuSupportedFeatures::new(Features {
            raw: self.shared.capabilities.features,
            core: true,
        })
    }
    fn limits(&self) -> wit::GpuSupportedLimits {
        let capabilities = &self.shared.capabilities;
        wit::GpuSupportedLimits::new(Limits {
            raw: capabilities.limits.clone(),
            stages: capabilities.downlevel.flags,
        })
    }
    fn adapter_info(&self) -> wit::GpuAdapterInfo {
        wit::GpuAdapterInfo::new(AdapterInfo(self.shared.capabilities.info.clone()))
    }
    fn queue(&self) -> wit::GpuQueue {
        wit::GpuQueue::new(self.queue.clone())
    }

    async fn destroy(&self) {
        let (reply, answer) = async_channel::bounded(1);
        self.shared.enqueue(Command::Destroy(reply));
        // A closed reply means the device timeline answered nothing because
        // the device was already gone; destruction holds either way.
        let _ = answer.recv().await;
    }

    create_resource!(create_buffer, wit::GpuBufferDescriptor, wit::GpuBuffer);
    create_resource!(create_texture, wit::GpuTextureDescriptor, wit::GpuTexture);
    create_resource!(
        create_sampler,
        Option<wit::GpuSamplerDescriptor>,
        wit::GpuSampler
    );
    create_resource!(
        create_bind_group_layout,
        wit::GpuBindGroupLayoutDescriptor,
        wit::GpuBindGroupLayout
    );
    create_resource!(
        create_pipeline_layout,
        wit::GpuPipelineLayoutDescriptor<'_>,
        wit::GpuPipelineLayout
    );
    create_resource!(
        create_bind_group,
        wit::GpuBindGroupDescriptor<'_>,
        wit::GpuBindGroup
    );
    create_resource!(
        create_shader_module,
        wit::GpuShaderModuleDescriptor<'_>,
        wit::GpuShaderModule
    );
    create_resource!(
        create_compute_pipeline,
        wit::GpuComputePipelineDescriptor<'_>,
        wit::GpuComputePipeline
    );
    create_resource!(
        create_render_pipeline,
        wit::GpuRenderPipelineDescriptor<'_>,
        wit::GpuRenderPipeline
    );
    create_resource!(
        create_command_encoder,
        Option<wit::GpuCommandEncoderDescriptor>,
        wit::GpuCommandEncoder
    );
    create_resource!(
        create_render_bundle_encoder,
        wit::GpuRenderBundleEncoderDescriptor,
        wit::GpuRenderBundleEncoder
    );
    create_resource!(create_query_set, wit::GpuQuerySetDescriptor, Result<wit::GpuQuerySet, wit::CreateQuerySetError>);

    async fn create_compute_pipeline_async(
        &self,
        descriptor: wit::GpuComputePipelineDescriptor<'_>,
    ) -> Result<wit::GpuComputePipeline, wit::CreatePipelineError> {
        Device::create_compute_pipeline_async(self, descriptor).await
    }
    async fn create_render_pipeline_async(
        &self,
        descriptor: wit::GpuRenderPipelineDescriptor<'_>,
    ) -> Result<wit::GpuRenderPipeline, wit::CreatePipelineError> {
        Device::create_render_pipeline_async(self, descriptor).await
    }

    fn push_error_scope(&self, filter: wit::GpuErrorFilter) {
        self.shared.scopes.push(match filter {
            wit::GpuErrorFilter::Validation => GpuErrorKind::Validation,
            wit::GpuErrorFilter::OutOfMemory => GpuErrorKind::OutOfMemory,
            wit::GpuErrorFilter::Internal => GpuErrorKind::Internal,
        });
    }

    async fn pop_error_scope(&self) -> Result<Option<wit::GpuError>, wit::PopErrorScopeError> {
        let scope = self
            .shared
            .scopes
            .pop()
            .map_err(|error| wit::PopErrorScopeError {
                kind: wit::PopErrorScopeErrorKind::OperationError,
                message: error.to_string(),
            })?;
        // Commands queued while the scope was open report into it; once the
        // device timeline has passed them all, its first error is final.
        let (reply, answer) = async_channel::bounded(1);
        self.shared.enqueue(Command::Fence(reply));
        let _ = answer.recv().await;
        Ok(scope.take().map(wit::GpuError::new))
    }

    async fn lost(&self) -> helios_api::wit_bindgen::FutureReader<wit::GpuDeviceLostInfo> {
        // A cancelled producer must complete its canonical future. Cancellation
        // ends this observer, so it reports an unknown reason rather than
        // fabricating a successful device-destruction notification.
        let (writer, reader) = helios_api::bindings::wit_future::new(|| {
            wit::GpuDeviceLostInfo::new(DeviceLost {
                reason: wgpu_types::DeviceLostReason::Unknown,
                message: "device loss observation was cancelled".into(),
            })
        });
        // wgpu-core runs the loss callback on the device timeline, which
        // answers with the notification it fills. The observer holds that
        // notification and no part of the device.
        let (reply, answer) = async_channel::bounded(1);
        self.shared.enqueue(Command::Lost(reply));
        let loss = answer
            .recv()
            .await
            .unwrap_or_else(|_| unreachable!("the device task answers while a handle lives"));
        helios_api::task::spawn(async move {
            // Closure without a notification means the device timeline has
            // released the native device.
            let lost = loss.wait().await.unwrap_or_else(|error| DeviceLost {
                reason: wgpu_types::DeviceLostReason::Destroyed,
                message: error.to_string(),
            });
            let _ = writer.write(wit::GpuDeviceLostInfo::new(lost)).await;
        });
        reader
    }

    async fn on_uncaptured_error(&self) -> helios_api::wit_bindgen::StreamReader<wit::GpuError> {
        let (subscriber, events) = async_channel::unbounded();
        let (done, subscribed) = async_channel::bounded(1);
        self.shared.enqueue(Command::Subscribe {
            events: subscriber,
            done,
        });
        let _ = subscribed.recv().await;
        let (mut writer, reader) = helios_api::bindings::wit_stream::new();
        helios_api::task::spawn(async move {
            while let Ok(error) = events.recv().await {
                if writer.write_one(wit::GpuError::new(error)).await.is_some() {
                    break;
                }
            }
        });
        reader
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
