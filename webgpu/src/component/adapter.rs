//! Adapter requests negotiate capabilities before consuming the adapter.

use core::cell::Cell;
use std::sync::Arc;
use wgpu_core::instance;

use super::{
    backend, capability,
    device::Device,
    resource::AdapterInfo,
    value::{Dictionary, Features, Limits},
    wit,
};

pub struct Adapter {
    raw: Arc<instance::Adapter>,
    consumed: Cell<bool>,
}

impl Adapter {
    /// Core WebGPU requires the default limits and every core downlevel flag.
    pub fn core(raw: Arc<instance::Adapter>) -> Option<Self> {
        if !raw.downlevel_capabilities().is_webgpu_compliant()
            || !wgpu_types::Limits::default().check_limits(&raw.limits())
        {
            return None;
        }
        Some(Self {
            raw,
            consumed: Cell::new(false),
        })
    }

    pub fn features(&self) -> wit::GpuSupportedFeatures {
        wit::GpuSupportedFeatures::new(Features {
            raw: self.raw.features(),
            core: true,
        })
    }

    pub fn limits(&self) -> wit::GpuSupportedLimits {
        wit::GpuSupportedLimits::new(Limits {
            raw: self.raw.limits(),
            stages: self.raw.downlevel_capabilities().flags,
        })
    }

    pub fn info(&self) -> wit::GpuAdapterInfo {
        wit::GpuAdapterInfo::new(AdapterInfo(self.raw.get_info()))
    }

    pub async fn request_device(
        &self,
        descriptor: Option<wit::GpuDeviceDescriptor>,
    ) -> Result<Device, wit::RequestDeviceError> {
        let (features, limits, label, queue_label) = match descriptor {
            Some(descriptor) => (
                descriptor.required_features.unwrap_or_default(),
                descriptor
                    .required_limits
                    .map(|limits| limits.get::<Dictionary<Option<u64>>>().entries())
                    .unwrap_or_default(),
                descriptor.label,
                descriptor.default_queue.and_then(|queue| queue.label),
            ),
            None => (Vec::new(), Vec::new(), None, None),
        };
        let features = capability::required_features(features, self.raw.features(), true).map_err(
            |error| wit::RequestDeviceError {
                kind: wit::RequestDeviceErrorKind::TypeError,
                message: error.to_string(),
            },
        )?;
        let operation = |message| wit::RequestDeviceError {
            kind: wit::RequestDeviceErrorKind::OperationError,
            message,
        };
        if self.consumed.get() {
            return Err(operation("adapter has already provided a device".into()));
        }
        let limits =
            capability::required_limits(limits).map_err(|error| operation(error.to_string()))?;
        let descriptor = wgpu_types::DeviceDescriptor {
            label: label.as_deref().map(Into::into),
            required_features: features,
            required_limits: limits,
            ..Default::default()
        };
        let device = backend::Device::request(&self.raw, &descriptor)
            .map_err(|error| operation(error.to_string()))?;
        self.consumed.set(true);
        Ok(Device::new(device, self.raw.get_info(), label, queue_label))
    }
}
