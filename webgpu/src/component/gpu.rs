use super::{adapter::Adapter, backend::Runtime, convert::Convert, value::LanguageFeatures, wit};

pub struct Gpu {
    pub runtime: Result<Runtime, wgpu_hal::InstanceError>,
}

impl Default for Gpu {
    fn default() -> Self {
        Self {
            runtime: Runtime::open(),
        }
    }
}

impl wit::GuestGpu for Gpu {
    async fn request_adapter(
        &self,
        options: Option<wit::GpuRequestAdapterOptions>,
    ) -> Option<wit::GpuAdapter> {
        let runtime = self.runtime.as_ref().ok()?;
        let mut native = wgpu_types::RequestAdapterOptions::default();
        if let Some(options) = options {
            // WebGPU permits core-defaulting adapters for compatibility requests
            // when the implementation does not enforce compatibility validation.
            if options
                .feature_level
                .as_deref()
                .is_some_and(|level| !matches!(level, "core" | "compatibility"))
            {
                return None;
            }
            native.power_preference = options
                .power_preference
                .map(Convert::convert)
                .unwrap_or_default();
            native.force_fallback_adapter = options.force_fallback_adapter.unwrap_or(false);
            // No WebXR session is exposed by this platform; xr-compatible is a
            // hint that WebGPU permits such implementations to ignore.
        }
        let raw = runtime
            .0
            .request_adapter(&native, wgpu_types::Backends::VULKAN)
            .ok()?;
        Adapter::core(raw).map(wit::GpuAdapter::new)
    }
    fn get_preferred_canvas_format(&self) -> wit::GpuTextureFormat {
        wit::GpuTextureFormat::Bgra8unorm
    }
    fn wgsl_language_features(&self) -> wit::WgslLanguageFeatures {
        wit::WgslLanguageFeatures::new(LanguageFeatures)
    }
}
