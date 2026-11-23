//! WebGPU names and limit negotiation at the component boundary.

use super::wit;

#[derive(Debug, thiserror::Error)]
#[error("required feature is not supported: {0}")]
pub struct UnsupportedFeature(pub &'static str);

pub fn required_features(
    requested: impl IntoIterator<Item = wit::GpuFeatureName>,
    available: wgpu_types::Features,
    core: bool,
) -> Result<wgpu_types::Features, UnsupportedFeature> {
    let mut features = wgpu_types::Features::empty();
    for requested in requested {
        let mut next = Some(requested);
        while let Some(feature) = next.take() {
            let name = feature_name(feature);
            if matches!(feature, wit::GpuFeatureName::CoreFeaturesAndLimits) {
                if !core {
                    return Err(UnsupportedFeature(name));
                }
                continue;
            }
            let native = name
                .parse::<wgpu_types::Features>()
                .map_err(|_| UnsupportedFeature(name))?;
            if !available.contains(native) {
                return Err(UnsupportedFeature(name));
            }
            features |= native;
            next = match feature {
                wit::GpuFeatureName::TextureCompressionBcSliced3d => {
                    Some(wit::GpuFeatureName::TextureCompressionBc)
                }
                wit::GpuFeatureName::TextureCompressionAstcSliced3d => {
                    Some(wit::GpuFeatureName::TextureCompressionAstc)
                }
                wit::GpuFeatureName::TextureFormatsTier2 => {
                    Some(wit::GpuFeatureName::TextureFormatsTier1)
                }
                wit::GpuFeatureName::TextureFormatsTier1 => {
                    Some(wit::GpuFeatureName::Rg11b10ufloatRenderable)
                }
                _ => None,
            };
        }
    }
    Ok(features)
}

pub fn feature_name(feature: wit::GpuFeatureName) -> &'static str {
    use wit::GpuFeatureName as F;
    match feature {
        F::CoreFeaturesAndLimits => "core-features-and-limits",
        F::DepthClipControl => "depth-clip-control",
        F::Depth32floatStencil8 => "depth32float-stencil8",
        F::TextureCompressionBc => "texture-compression-bc",
        F::TextureCompressionBcSliced3d => "texture-compression-bc-sliced-3d",
        F::TextureCompressionEtc2 => "texture-compression-etc2",
        F::TextureCompressionAstc => "texture-compression-astc",
        F::TextureCompressionAstcSliced3d => "texture-compression-astc-sliced-3d",
        F::TimestampQuery => "timestamp-query",
        F::IndirectFirstInstance => "indirect-first-instance",
        F::ShaderF16 => "shader-f16",
        F::Rg11b10ufloatRenderable => "rg11b10ufloat-renderable",
        F::Bgra8unormStorage => "bgra8unorm-storage",
        F::Float32Filterable => "float32-filterable",
        F::Float32Blendable => "float32-blendable",
        F::ClipDistances => "clip-distances",
        F::DualSourceBlending => "dual-source-blending",
        F::Subgroups => "subgroups",
        F::TextureFormatsTier1 => "texture-formats-tier1",
        F::TextureFormatsTier2 => "texture-formats-tier2",
        F::PrimitiveIndex => "primitive-index",
        F::TextureComponentSwizzle => "texture-component-swizzle",
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LimitError {
    #[error("unknown required limit: {0}")]
    Unknown(String),
    #[error("required limit {name} cannot represent {value}")]
    Overflow { name: String, value: u64 },
    #[error("required alignment {name} must be a power of two below 2^32, got {value}")]
    Alignment { name: String, value: u64 },
}

/// Values below WebGPU's default maxima (or above its default alignments)
/// cannot reduce the baseline capabilities of a device.
pub fn required_limits(
    values: impl IntoIterator<Item = (String, Option<u64>)>,
) -> Result<wgpu_types::Limits, LimitError> {
    let mut limits = wgpu_types::Limits::default();
    for (name, value) in values {
        let Some(value) = value else { continue };
        if matches!(
            name.as_str(),
            "minUniformBufferOffsetAlignment" | "minStorageBufferOffsetAlignment"
        ) && (!value.is_power_of_two() || value > u64::from(u32::MAX))
        {
            return Err(LimitError::Alignment { name, value });
        }
        macro_rules! maxima {
            ($($name:literal => $field:ident),* $(,)?) => {
                match name.as_str() {
                    $($name => {
                        limits.$field = limits.$field.max(value.try_into().map_err(|_| LimitError::Overflow { name: name.clone(), value })?);
                    },)*
                    "minUniformBufferOffsetAlignment" => {
                        limits.min_uniform_buffer_offset_alignment = limits.min_uniform_buffer_offset_alignment.min(value.try_into().map_err(|_| LimitError::Overflow { name: name.clone(), value })?);
                    }
                    "minStorageBufferOffsetAlignment" => {
                        limits.min_storage_buffer_offset_alignment = limits.min_storage_buffer_offset_alignment.min(value.try_into().map_err(|_| LimitError::Overflow { name: name.clone(), value })?);
                    }
                    _ => return Err(LimitError::Unknown(name)),
                }
            };
        }
        maxima! {
            "maxTextureDimension1D" => max_texture_dimension_1d,
            "maxTextureDimension2D" => max_texture_dimension_2d,
            "maxTextureDimension3D" => max_texture_dimension_3d,
            "maxTextureArrayLayers" => max_texture_array_layers,
            "maxBindGroups" => max_bind_groups,
            "maxBindGroupsPlusVertexBuffers" => max_bind_groups_plus_vertex_buffers,
            "maxImmediateSize" => max_immediate_size,
            "maxBindingsPerBindGroup" => max_bindings_per_bind_group,
            "maxDynamicUniformBuffersPerPipelineLayout" => max_dynamic_uniform_buffers_per_pipeline_layout,
            "maxDynamicStorageBuffersPerPipelineLayout" => max_dynamic_storage_buffers_per_pipeline_layout,
            "maxSampledTexturesPerShaderStage" => max_sampled_textures_per_shader_stage,
            "maxSamplersPerShaderStage" => max_samplers_per_shader_stage,
            "maxStorageBuffersPerShaderStage" => max_storage_buffers_per_shader_stage,
            "maxStorageBuffersInVertexStage" => max_storage_buffers_per_shader_stage,
            "maxStorageBuffersInFragmentStage" => max_storage_buffers_per_shader_stage,
            "maxStorageTexturesPerShaderStage" => max_storage_textures_per_shader_stage,
            "maxStorageTexturesInVertexStage" => max_storage_textures_per_shader_stage,
            "maxStorageTexturesInFragmentStage" => max_storage_textures_per_shader_stage,
            "maxUniformBuffersPerShaderStage" => max_uniform_buffers_per_shader_stage,
            "maxUniformBufferBindingSize" => max_uniform_buffer_binding_size,
            "maxStorageBufferBindingSize" => max_storage_buffer_binding_size,
            "maxVertexBuffers" => max_vertex_buffers,
            "maxBufferSize" => max_buffer_size,
            "maxVertexAttributes" => max_vertex_attributes,
            "maxVertexBufferArrayStride" => max_vertex_buffer_array_stride,
            "maxInterStageShaderVariables" => max_inter_stage_shader_variables,
            "maxColorAttachments" => max_color_attachments,
            "maxColorAttachmentBytesPerSample" => max_color_attachment_bytes_per_sample,
            "maxComputeWorkgroupStorageSize" => max_compute_workgroup_storage_size,
            "maxComputeInvocationsPerWorkgroup" => max_compute_invocations_per_workgroup,
            "maxComputeWorkgroupSizeX" => max_compute_workgroup_size_x,
            "maxComputeWorkgroupSizeY" => max_compute_workgroup_size_y,
            "maxComputeWorkgroupSizeZ" => max_compute_workgroup_size_z,
            "maxComputeWorkgroupsPerDimension" => max_compute_workgroups_per_dimension,
        }
    }
    Ok(limits)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alignment_requests_are_validated_before_default_clamping() {
        for value in [0, 3, 257, 1_u64 << 32] {
            assert!(matches!(
                required_limits([("minUniformBufferOffsetAlignment".into(), Some(value))]),
                Err(LimitError::Alignment { .. })
            ));
        }
        assert!(required_limits([("minStorageBufferOffsetAlignment".into(), Some(512))]).is_ok());
    }

    #[test]
    fn sliced_compression_enables_its_base_feature() {
        let available = wgpu_types::Features::TEXTURE_COMPRESSION_BC
            | wgpu_types::Features::TEXTURE_COMPRESSION_BC_SLICED_3D;
        assert_eq!(
            required_features(
                [wit::GpuFeatureName::TextureCompressionBcSliced3d],
                available,
                true
            )
            .unwrap(),
            available
        );
    }

    #[test]
    fn required_features_reject_unavailable_capabilities_and_deduplicate() {
        use wit::GpuFeatureName as F;
        let available = wgpu_types::Features::TIMESTAMP_QUERY;
        assert_eq!(
            required_features(
                [
                    F::TimestampQuery,
                    F::TimestampQuery,
                    F::CoreFeaturesAndLimits
                ],
                available,
                true
            )
            .unwrap(),
            available
        );
        assert!(required_features([F::ShaderF16], available, true).is_err());
        assert!(required_features([F::CoreFeaturesAndLimits], available, false).is_err());
        assert!(
            required_features(
                [F::TextureComponentSwizzle],
                wgpu_types::Features::all(),
                true
            )
            .is_err()
        );
    }

    #[test]
    fn absent_values_are_ignored_but_unknown_defined_limits_are_errors() {
        assert!(required_limits([("futureLimit".into(), None)]).is_ok());
        assert!(matches!(
            required_limits([("futureLimit".into(), Some(1))]),
            Err(LimitError::Unknown(_))
        ));
    }

    #[test]
    fn limits_keep_baselines_and_combine_stage_requests_without_truncation() {
        let limits = required_limits([
            ("maxTextureDimension2D".into(), Some(1)),
            ("maxStorageBuffersInVertexStage".into(), Some(32)),
            ("maxStorageBuffersInFragmentStage".into(), Some(64)),
            ("minUniformBufferOffsetAlignment".into(), Some(16)),
        ])
        .unwrap();
        assert_eq!(
            limits.max_texture_dimension_2d,
            wgpu_types::Limits::default().max_texture_dimension_2d
        );
        assert_eq!(limits.max_storage_buffers_per_shader_stage, 64);
        assert_eq!(limits.min_uniform_buffer_offset_alignment, 16);
        assert!(matches!(
            required_limits([("maxVertexBuffers".into(), Some(u64::MAX))]),
            Err(LimitError::Overflow { .. })
        ));
    }
}
