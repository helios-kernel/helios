use core::cell::OnceCell;

use super::{adapter::Adapter, convert::Convert, instance::Instance, value::LanguageFeatures, wit};

/// The `gpu` entry point.
///
/// `get-gpu` is a synchronous export and opening the Vulkan instance waits
/// on the host, so the instance opens on the first `request-adapter`, an
/// async export, which also enumerates the adapters.
#[derive(Default)]
pub struct Gpu {
    instance: OnceCell<Option<Instance>>,
}

impl wit::GuestGpu for Gpu {
    async fn request_adapter(
        &self,
        options: Option<wit::GpuRequestAdapterOptions>,
    ) -> Option<wit::GpuAdapter> {
        let instance = self
            .instance
            .get_or_init(|| {
                Instance::open()
                    .inspect_err(|error| {
                        tracing::error!(%error, "the Vulkan instance did not open");
                    })
                    .ok()
            })
            .as_ref()?;
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
        Adapter::request(instance, &native).map(wit::GpuAdapter::new)
    }
    fn get_preferred_canvas_format(&self) -> wit::GpuTextureFormat {
        wit::GpuTextureFormat::Bgra8unorm
    }
    fn wgsl_language_features(&self) -> wit::WgslLanguageFeatures {
        wit::WgslLanguageFeatures::new(LanguageFeatures)
    }
}
