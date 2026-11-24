//! Vulkan bring-up through the ash driver and canonical import boundary.

use ash::vk;
use helios_venus::driver::entry;
use helios_venus::helios::Context;

mod compute;
mod webgpu;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Vulkan returned {0}")]
    Vulkan(#[from] vk::Result),
    #[error("queue completion failed: {0}")]
    Timeline(#[from] helios_api::sync::TimelineError),
    #[error(transparent)]
    WebGpu(#[from] helios_webgpu::runtime::Error),
    #[error(transparent)]
    WebGpuReported(helios_webgpu::runtime::GpuError),
    #[error(transparent)]
    WebGpuMap(#[from] helios_webgpu::wgpu::MapRangeError),
    #[error("the Venus instance has no physical devices")]
    NoPhysicalDevices,
    #[error("the Venus physical device has no compute queue")]
    NoComputeQueue,
    #[error("the Venus physical device has no host-visible coherent memory type")]
    NoHostMemory,
    #[error("the Venus physical device does not support timeline semaphores")]
    NoTimelineSemaphores,
    #[error("Vulkan synchronization check failed: {0}")]
    Synchronization(&'static str),
    #[error("Vulkan memory read back {found:#04x} at byte {offset}, expected {expected:#04x}")]
    MemoryReadback {
        offset: usize,
        expected: u8,
        found: u8,
    },
    #[error("compute output {index} was {found}, expected {expected}")]
    ComputeReadback {
        index: u32,
        expected: u32,
        found: u32,
    },
}

pub async fn run() -> Result<(), Error> {
    // Exercise atomic std TLS before GPU consumers use randomized maps.
    std::hint::black_box(std::hash::RandomState::new());
    let entry = entry::<Context>();
    // SAFETY: `entry` owns the loaded Vulkan dispatch table.
    let version = unsafe { entry.try_enumerate_instance_version() }?.unwrap_or(vk::API_VERSION_1_0);
    let application = vk::ApplicationInfo::default()
        .application_name(c"helios-gpu-test")
        .api_version(version);
    let extensions = [ash::khr::get_physical_device_properties2::NAME.as_ptr()];
    let create_info = vk::InstanceCreateInfo::default()
        .application_info(&application)
        .enabled_extension_names(&extensions);
    // SAFETY: `create_info` and its referenced `application` and `extensions`
    // strings remain valid for the duration of `create_instance`.
    let instance = unsafe { entry.create_instance(&create_info, None) }?;
    let result = async {
        // SAFETY: `instance` is a live Vulkan instance created above.
        let physical_devices = unsafe { instance.enumerate_physical_devices() }?;
        let physical = *physical_devices.first().ok_or(Error::NoPhysicalDevices)?;
        // SAFETY: `physical` was returned by `instance` above.
        let families = unsafe { instance.get_physical_device_queue_family_properties(physical) };
        let family = families
            .iter()
            .position(|family| {
                family.queue_count != 0 && family.queue_flags.contains(vk::QueueFlags::COMPUTE)
            })
            .ok_or(Error::NoComputeQueue)? as u32;
        let priorities = [1.0];
        let queues = [vk::DeviceQueueCreateInfo::default()
            .queue_family_index(family)
            .queue_priorities(&priorities)];
        let mut timeline = vk::PhysicalDeviceTimelineSemaphoreFeatures::default();
        let mut features = vk::PhysicalDeviceFeatures2::default().push_next(&mut timeline);
        let properties2 =
            ash::khr::get_physical_device_properties2::Instance::new(&entry, &instance);
        // SAFETY: `physical` belongs to `instance`, and `features` and its
        // chained `timeline` struct are valid writable memory for this call.
        unsafe { properties2.get_physical_device_features2(physical, &mut features) };
        if timeline.timeline_semaphore == vk::FALSE {
            return Err(Error::NoTimelineSemaphores);
        }
        let device_info = vk::DeviceCreateInfo::default()
            .queue_create_infos(&queues)
            .push_next(&mut timeline);
        // SAFETY: `physical` belongs to `instance`, and `device_info` along
        // with `queues` and `timeline` remain live for `create_device`.
        let device = unsafe { instance.create_device(physical, &device_info, None) }?;
        // SAFETY: `device` is live and `family` has at least one queue (`queue_count != 0`).
        let queue = unsafe { device.get_device_queue(family, 0) };
        let result = async {
            memory(&instance, physical, &device)?;
            compute::run(&instance, physical, &device, queue, family).await
        }
        .await;
        // SAFETY: `memory` and `compute::run` have retired all device work and
        // destroyed all child handles before destroying `device`.
        unsafe { device.destroy_device(None) };
        result?;
        println!(
            "gpu-test:venus device-queue ok devices={} family={family}",
            physical_devices.len()
        );
        println!("gpu-test:venus ring-reply ok api={version:#x}");
        Ok(())
    }
    .await;
    // SAFETY: the device and all child Vulkan objects created from `instance`
    // were destroyed before destroying `instance`.
    unsafe { instance.destroy_instance(None) };
    result?;
    webgpu::run().await
}

fn memory(
    instance: &ash::Instance,
    physical: vk::PhysicalDevice,
    device: &ash::Device,
) -> Result<(), Error> {
    // SAFETY: `physical` belongs to the live `instance`.
    let properties = unsafe { instance.get_physical_device_memory_properties(physical) };
    let memory_type = host_memory_type(&properties, u32::MAX)?;
    let bytes = super::PAGE_BYTES;
    let alloc_info = vk::MemoryAllocateInfo::default()
        .allocation_size(bytes)
        .memory_type_index(memory_type);
    // SAFETY: `device` is live and `alloc_info` names a valid host-coherent
    // memory type from `physical`.
    let allocation = unsafe { device.allocate_memory(&alloc_info, None) }?;
    let result = (|| {
        // SAFETY: `allocation` is live, host-visible, `bytes` bytes long, and
        // not currently mapped.
        let pointer =
            unsafe { device.map_memory(allocation, 0, bytes, vk::MemoryMapFlags::empty()) }?
                .cast::<u8>();
        let result = (|| {
            for offset in 0..bytes as usize {
                // SAFETY: `offset < bytes` and `pointer` points to a mapped
                // allocation of `bytes` bytes.
                let slot = unsafe { pointer.add(offset) };
                // SAFETY: `slot` points to a valid mapped byte inside `allocation`.
                unsafe { slot.write_volatile((offset as u8).wrapping_mul(17)) };
            }
            for offset in 0..bytes as usize {
                let expected = (offset as u8).wrapping_mul(17);
                // SAFETY: `offset < bytes` and `pointer` points to a mapped
                // allocation of `bytes` bytes.
                let slot = unsafe { pointer.add(offset) };
                // SAFETY: `slot` points to a valid mapped byte written above.
                let found = unsafe { slot.read_volatile() };
                if found != expected {
                    return Err(Error::MemoryReadback {
                        offset,
                        expected,
                        found,
                    });
                }
            }
            Ok(())
        })();
        // SAFETY: `allocation` is currently mapped and no pointers into the
        // mapping are used after unmapping.
        unsafe { device.unmap_memory(allocation) };
        result
    })();
    // SAFETY: `allocation` was unmapped above and is owned by this function.
    unsafe { device.free_memory(allocation, None) };
    result?;
    println!("gpu-test:venus memory-map ok bytes={bytes}");
    Ok(())
}

fn host_memory_type(
    properties: &vk::PhysicalDeviceMemoryProperties,
    bits: u32,
) -> Result<u32, Error> {
    let required = vk::MemoryPropertyFlags::HOST_VISIBLE | vk::MemoryPropertyFlags::HOST_COHERENT;
    properties.memory_types[..properties.memory_type_count as usize]
        .iter()
        .enumerate()
        .find(|(index, memory)| {
            bits & (1 << index) != 0 && memory.property_flags.contains(required)
        })
        .map(|(index, _)| index as u32)
        .ok_or(Error::NoHostMemory)
}
