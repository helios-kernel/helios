//! Adapter requests negotiate capabilities before consuming the adapter.

use core::cell::Cell;
use std::rc::Rc;

use wgpu_core::{device::DeviceError, id, instance::RequestAdapterOptions};

use super::{
    capability,
    content::{Capabilities, DeviceShared},
    device::Device,
    instance::Instance,
    resource::AdapterInfo,
    timeline::Timeline,
    value::{Dictionary, Features, Limits},
    wit,
};

type Vulkan = wgpu_hal::api::Vulkan;

pub struct Adapter {
    instance: Instance,
    id: id::AdapterId,
    features: wgpu_types::Features,
    limits: wgpu_types::Limits,
    downlevel: wgpu_types::DownlevelCapabilities,
    info: wgpu_types::AdapterInfo,
    consumed: Cell<bool>,
}

impl Drop for Adapter {
    fn drop(&mut self) {
        self.instance.drop_adapter(self.id);
    }
}

impl wit::GuestGpuAdapter for Adapter {
    fn features(&self) -> wit::GpuSupportedFeatures {
        wit::GpuSupportedFeatures::new(Features {
            raw: self.features,
            core: true,
        })
    }
    fn limits(&self) -> wit::GpuSupportedLimits {
        wit::GpuSupportedLimits::new(Limits {
            raw: self.limits.clone(),
            stages: self.downlevel.flags,
        })
    }
    fn info(&self) -> wit::GpuAdapterInfo {
        wit::GpuAdapterInfo::new(AdapterInfo(self.info.clone()))
    }
    async fn request_device(
        &self,
        descriptor: Option<wit::GpuDeviceDescriptor>,
    ) -> Result<wit::GpuDevice, wit::RequestDeviceError> {
        Adapter::request_device(self, descriptor)
            .await
            .map(wit::GpuDevice::new)
    }
}

impl Adapter {
    /// Select an adapter on behalf of the async `request-adapter` export.
    /// Core WebGPU requires the default limits and every core downlevel flag.
    pub fn request(instance: &Instance, options: &RequestAdapterOptions) -> Option<Self> {
        let global = instance.global();
        let id = instance.ids.adapters.allocate();
        if global
            .request_adapter(options, wgpu_types::Backends::VULKAN, Some(id))
            .is_err()
        {
            instance.ids.adapters.release(id);
            return None;
        }
        let adapter = Self {
            instance: instance.clone(),
            id,
            features: global.adapter_features(id),
            limits: global.adapter_limits(id),
            downlevel: global.adapter_downlevel_capabilities(id),
            info: global.adapter_get_info(id),
            consumed: Cell::new(false),
        };
        // A rejected adapter drops through its handle like any other.
        (adapter.downlevel.is_webgpu_compliant()
            && wgpu_types::Limits::default().check_limits(&adapter.limits))
        .then_some(adapter)
    }

    /// Open the device and start its timeline. This runs in the async
    /// `request-device` export, whose component-model task then keeps
    /// running the device task after the export has returned.
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
        let features =
            capability::required_features(features, self.features, true).map_err(|error| {
                wit::RequestDeviceError {
                    kind: wit::RequestDeviceErrorKind::TypeError,
                    message: error.to_string(),
                }
            })?;
        let operation = |message| wit::RequestDeviceError {
            kind: wit::RequestDeviceErrorKind::OperationError,
            message,
        };
        if self.consumed.get() {
            return Err(operation("adapter has already provided a device".into()));
        }
        let limits =
            capability::required_limits(limits).map_err(|error| operation(error.to_string()))?;
        let mut descriptor = wgpu_types::DeviceDescriptor {
            label: label.as_deref().map(Into::into),
            required_features: features,
            required_limits: limits,
            ..Default::default()
        };
        let global = self.instance.global();
        global
            .adapter_validate_device_descriptor(self.id, &mut descriptor)
            .map_err(|error| operation(error.to_string()))?;
        // SAFETY: this instance creates Vulkan adapters exclusively. The HAL
        // handle is retained only during synchronous device initialization.
        let hal = unsafe { global.adapter_as_hal::<Vulkan>(self.id) }
            .expect("Helios WebGPU adapters use Vulkan");
        let foreign = hal
            .physical_device_capabilities()
            .supports_extension(ash::ext::queue_family_foreign::NAME);
        // SAFETY: core validated the features and limits. The callback only
        // adds an advertised extension and changes no requested feature.
        let opened = unsafe {
            hal.open_with_callback(
                descriptor.required_features,
                &descriptor.required_limits,
                &descriptor.memory_hints,
                Some(Box::new(move |args| {
                    if foreign
                        && !args
                            .extensions
                            .contains(&ash::ext::queue_family_foreign::NAME)
                    {
                        args.extensions.push(ash::ext::queue_family_foreign::NAME);
                    }
                })),
            )
        }
        .map_err(|error| operation(DeviceError::from_hal(error).to_string()))?;
        drop(hal);
        let ids = self.instance.ids.clone();
        let device = ids.devices.allocate();
        let queue = ids.queues.allocate();
        // SAFETY: this HAL device was opened on this exact adapter with the
        // validated descriptor, and ownership passes to core.
        if let Err(error) = unsafe {
            global.create_device_from_hal(
                self.id,
                opened.into(),
                &descriptor,
                Some(device),
                Some(queue),
            )
        } {
            ids.devices.release(device);
            ids.queues.release(queue);
            return Err(operation(error.to_string()));
        }
        self.consumed.set(true);
        let capabilities = Capabilities {
            features: global.device_features(device),
            limits: global.device_limits(device),
            downlevel: global.device_downlevel_properties(device),
            info: self.info.clone(),
        };
        let (commands, queued) = async_channel::unbounded();
        let timeline = Timeline::new(global, ids.clone(), device, queue, commands.downgrade());
        helios_api::task::spawn(timeline.run(queued));
        let shared = Rc::new(DeviceShared::new(commands, ids, capabilities));
        Ok(Device::new(shared, label, queue_label))
    }
}
