use core::cell::{OnceCell, RefCell};
use indexmap::IndexMap;
use std::rc::Rc;
use wgpu_core::id::markers;

use super::{command::Command, content::Handle, wit};
use crate::runtime::{DeviceLost, GpuError, GpuErrorKind};

pub struct Dictionary<T>(RefCell<IndexMap<String, T>>);

impl<T: Copy> Dictionary<T> {
    pub fn entries(&self) -> Vec<(String, T)> {
        self.0
            .borrow()
            .iter()
            .map(|(key, value)| (key.clone(), *value))
            .collect()
    }
}

macro_rules! dictionary {
    ($guest:ident, $value:ty) => {
        impl wit::$guest for Dictionary<$value> {
            fn new() -> Self {
                Self(RefCell::new(IndexMap::new()))
            }
            fn add(&self, key: String, value: $value) {
                self.0.borrow_mut().insert(key, value);
            }
            fn get(&self, key: String) -> Option<$value> {
                self.0.borrow().get(&key).copied()
            }
            fn has(&self, key: String) -> bool {
                self.0.borrow().contains_key(&key)
            }
            fn remove(&self, key: String) {
                self.0.borrow_mut().shift_remove(&key);
            }
            fn keys(&self) -> Vec<String> {
                self.0.borrow().keys().cloned().collect()
            }
            fn values(&self) -> Vec<$value> {
                self.0.borrow().values().copied().collect()
            }
            fn entries(&self) -> Vec<(String, $value)> {
                self.entries()
            }
        }
    };
}

dictionary!(GuestRecordGpuPipelineConstantValue, f64);
dictionary!(GuestRecordOptionGpuSize64, Option<u64>);

impl wit::GuestGpuError for GpuError {
    fn message(&self) -> String {
        core::iter::once(self.message.as_str())
            .chain(self.causes.iter().map(String::as_str))
            .collect::<Vec<_>>()
            .join(": ")
    }
    fn kind(&self) -> wit::GpuErrorKind {
        match self.kind {
            GpuErrorKind::Validation => wit::GpuErrorKind::ValidationError,
            GpuErrorKind::OutOfMemory => wit::GpuErrorKind::OutOfMemoryError,
            GpuErrorKind::Internal => wit::GpuErrorKind::InternalError,
        }
    }
}

pub struct UncapturedError(pub GpuError);
impl wit::GuestGpuUncapturedErrorEvent for UncapturedError {
    fn error(&self) -> wit::GpuError {
        wit::GpuError::new(self.0.clone())
    }
}

impl wit::GuestGpuDeviceLostInfo for DeviceLost {
    fn reason(&self) -> wit::GpuDeviceLostReason {
        match self.reason {
            wgpu::DeviceLostReason::Destroyed => wit::GpuDeviceLostReason::Destroyed,
            wgpu::DeviceLostReason::Unknown => wit::GpuDeviceLostReason::Unknown,
        }
    }
    fn message(&self) -> String {
        self.message.clone()
    }
}

pub struct Features {
    pub raw: wgpu::Features,
    pub core: bool,
}
impl wit::GuestGpuSupportedFeatures for Features {
    fn has(&self, value: String) -> bool {
        if value == "core-features-and-limits" {
            return self.core;
        }
        let Ok(feature) = value.parse::<wgpu::Features>() else {
            return false;
        };
        // Exclude wgpu extensions and alternate spellings accepted by its parser.
        feature.as_str() == Some(value.as_str())
            && !value.starts_with("wgpu-")
            && self.raw.contains(feature)
    }
}

pub struct LanguageFeatures;
impl wit::GuestWgslLanguageFeatures for LanguageFeatures {
    fn has(&self, value: String) -> bool {
        wgpu_core::naga::front::wgsl::ImplementedLanguageExtension::all()
            .iter()
            .any(|extension| extension.to_ident() == value)
    }
}

pub struct Limits {
    pub raw: wgpu::Limits,
    pub stages: wgpu::DownlevelFlags,
}

macro_rules! limit_getters {
    ($($name:ident : $ty:ty => $field:ident),* $(,)?) => {$ (
        fn $name(&self) -> $ty { self.raw.$field }
    )*};
}

impl wit::GuestGpuSupportedLimits for Limits {
    limit_getters! {
        max_texture_dimension1_d: u32 => max_texture_dimension_1d,
        max_texture_dimension2_d: u32 => max_texture_dimension_2d,
        max_texture_dimension3_d: u32 => max_texture_dimension_3d,
        max_texture_array_layers: u32 => max_texture_array_layers,
        max_bind_groups: u32 => max_bind_groups,
        max_bind_groups_plus_vertex_buffers: u32 => max_bind_groups_plus_vertex_buffers,
        max_immediate_size: u32 => max_immediate_size,
        max_bindings_per_bind_group: u32 => max_bindings_per_bind_group,
        max_dynamic_uniform_buffers_per_pipeline_layout: u32 => max_dynamic_uniform_buffers_per_pipeline_layout,
        max_dynamic_storage_buffers_per_pipeline_layout: u32 => max_dynamic_storage_buffers_per_pipeline_layout,
        max_sampled_textures_per_shader_stage: u32 => max_sampled_textures_per_shader_stage,
        max_samplers_per_shader_stage: u32 => max_samplers_per_shader_stage,
        max_storage_buffers_per_shader_stage: u32 => max_storage_buffers_per_shader_stage,
        max_storage_textures_per_shader_stage: u32 => max_storage_textures_per_shader_stage,
        max_uniform_buffers_per_shader_stage: u32 => max_uniform_buffers_per_shader_stage,
        max_uniform_buffer_binding_size: u64 => max_uniform_buffer_binding_size,
        max_storage_buffer_binding_size: u64 => max_storage_buffer_binding_size,
        min_uniform_buffer_offset_alignment: u32 => min_uniform_buffer_offset_alignment,
        min_storage_buffer_offset_alignment: u32 => min_storage_buffer_offset_alignment,
        max_vertex_buffers: u32 => max_vertex_buffers,
        max_buffer_size: u64 => max_buffer_size,
        max_vertex_attributes: u32 => max_vertex_attributes,
        max_vertex_buffer_array_stride: u32 => max_vertex_buffer_array_stride,
        max_inter_stage_shader_variables: u32 => max_inter_stage_shader_variables,
        max_color_attachments: u32 => max_color_attachments,
        max_color_attachment_bytes_per_sample: u32 => max_color_attachment_bytes_per_sample,
        max_compute_workgroup_storage_size: u32 => max_compute_workgroup_storage_size,
        max_compute_invocations_per_workgroup: u32 => max_compute_invocations_per_workgroup,
        max_compute_workgroup_size_x: u32 => max_compute_workgroup_size_x,
        max_compute_workgroup_size_y: u32 => max_compute_workgroup_size_y,
        max_compute_workgroup_size_z: u32 => max_compute_workgroup_size_z,
        max_compute_workgroups_per_dimension: u32 => max_compute_workgroups_per_dimension,
    }
    fn max_storage_buffers_in_vertex_stage(&self) -> u32 {
        if self.stages.contains(wgpu::DownlevelFlags::VERTEX_STORAGE) {
            self.raw.max_storage_buffers_per_shader_stage
        } else {
            0
        }
    }
    fn max_storage_buffers_in_fragment_stage(&self) -> u32 {
        if self.stages.contains(wgpu::DownlevelFlags::FRAGMENT_STORAGE) {
            self.raw.max_storage_buffers_per_shader_stage
        } else {
            0
        }
    }
    fn max_storage_textures_in_vertex_stage(&self) -> u32 {
        self.raw.max_storage_textures_per_shader_stage
    }
    fn max_storage_textures_in_fragment_stage(&self) -> u32 {
        self.raw.max_storage_textures_per_shader_stage
    }
}

/// A shader module. The device timeline fills its diagnostics when it
/// compiles the module.
pub struct Shader {
    pub handle: Handle<markers::ShaderModule>,
    pub diagnostics: Rc<OnceCell<Vec<CompilationMessage>>>,
}

pub struct CompilationInfo(pub Vec<CompilationMessage>);
#[derive(Clone)]
pub struct CompilationMessage {
    message: String,
    kind: wit::GpuCompilationMessageType,
    line: u64,
    column: u64,
    offset: u64,
    length: u64,
}

impl CompilationMessage {
    pub fn from_wgpu(message: wgpu::CompilationMessage, source: &str) -> Self {
        let kind = match message.message_type {
            wgpu::CompilationMessageType::Error => wit::GpuCompilationMessageType::Error,
            wgpu::CompilationMessageType::Warning => wit::GpuCompilationMessageType::Warning,
            wgpu::CompilationMessageType::Info => wit::GpuCompilationMessageType::Info,
        };
        let (line, column, offset, length) = match message.location {
            Some(location) => {
                let start = location.offset as usize;
                let end = start + location.length as usize;
                let line_start = start + 1 - location.line_position as usize;
                (
                    u64::from(location.line_number),
                    source[line_start..start].encode_utf16().count() as u64 + 1,
                    source[..start].encode_utf16().count() as u64,
                    source[start..end].encode_utf16().count() as u64,
                )
            }
            // WebGPU uses zero when a diagnostic has no source location.
            None => (0, 0, 0, 0),
        };
        Self {
            message: message.message,
            kind,
            line,
            column,
            offset,
            length,
        }
    }
}

impl wit::GuestGpuShaderModule for Shader {
    async fn get_compilation_info(&self) -> wit::GpuCompilationInfo {
        // The module's creation precedes this fence on its device timeline.
        let (reply, answer) = async_channel::bounded(1);
        self.handle.device.enqueue(Command::Fence(reply));
        let _ = answer.recv().await;
        let messages = self
            .diagnostics
            .get()
            .unwrap_or_else(|| unreachable!("the device timeline compiled the module"));
        wit::GpuCompilationInfo::new(CompilationInfo(messages.clone()))
    }

    fn label(&self) -> String {
        self.handle.label()
    }
    fn set_label(&self, label: String) {
        self.handle.set_label(label);
    }
}
impl wit::GuestGpuCompilationInfo for CompilationInfo {
    fn messages(&self) -> Vec<wit::GpuCompilationMessage> {
        self.0
            .iter()
            .cloned()
            .map(wit::GpuCompilationMessage::new)
            .collect()
    }
}
impl wit::GuestGpuCompilationMessage for CompilationMessage {
    fn message(&self) -> String {
        self.message.clone()
    }
    fn type_(&self) -> wit::GpuCompilationMessageType {
        self.kind
    }
    fn line_num(&self) -> u64 {
        self.line
    }
    fn line_pos(&self) -> u64 {
        self.column
    }
    fn offset(&self) -> u64 {
        self.offset
    }
    fn length(&self) -> u64 {
        self.length
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wit::{GuestGpuCompilationMessage, GuestRecordOptionGpuSize64};

    #[test]
    fn optional_dictionary_values_distinguish_absence_and_preserve_order() {
        let values = Dictionary::<Option<u64>>::new();
        values.add("maxBufferSize".into(), Some(4096));
        values.add("maxTextureDimension2D".into(), None);
        assert_eq!(values.get("missing".into()), None);
        assert_eq!(values.get("maxTextureDimension2D".into()), Some(None));
        values.add("maxBufferSize".into(), Some(8192));
        assert_eq!(values.keys(), ["maxBufferSize", "maxTextureDimension2D"]);
        values.remove("maxBufferSize".into());
        values.add("maxBufferSize".into(), Some(16384));
        assert_eq!(values.keys(), ["maxTextureDimension2D", "maxBufferSize"]);
    }

    #[test]
    fn shader_locations_count_utf16_across_cjk_and_supplementary_characters() {
        let source = "// 中文 日本語 한국어 🏳️‍🌈\nlet 文 = 🦀;";
        let offset = source.find('🦀').unwrap();
        let line_start = source.rfind('\n').unwrap() + 1;
        let diagnostic = CompilationMessage::from_wgpu(
            wgpu::CompilationMessage {
                message: "unexpected token".into(),
                message_type: wgpu::CompilationMessageType::Error,
                location: Some(wgpu::SourceLocation {
                    line_number: 2,
                    line_position: (offset - line_start + 1) as u32,
                    offset: offset as u32,
                    length: '🦀'.len_utf8() as u32,
                }),
            },
            source,
        );
        assert_eq!(diagnostic.line_num(), 2);
        assert_eq!(diagnostic.line_pos(), 9);
        assert_eq!(diagnostic.length(), 2);
        assert_eq!(
            diagnostic.offset(),
            source[..offset].encode_utf16().count() as u64
        );
    }
}
