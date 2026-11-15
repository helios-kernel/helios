//! Vulkan bring-up through the ash driver and canonical import boundary.

use ash::vk;
use helios_venus::driver::entry;
use helios_venus::helios::Context;

mod compute;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Vulkan returned {0}")]
    Vulkan(#[from] vk::Result),
    #[error("the Venus instance has no physical devices")]
    NoPhysicalDevices,
    #[error("the Venus physical device has no compute queue")]
    NoComputeQueue,
    #[error("the Venus physical device has no host-visible coherent memory type")]
    NoHostMemory,
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

pub fn run() -> Result<(), Error> {
    // Exercise atomic std TLS before GPU consumers use randomized maps.
    std::hint::black_box(std::hash::RandomState::new());
    let entry = entry::<Context>();
    // SAFETY: all objects are used within their Vulkan lifetimes; the driver
    // owns dispatch storage and serializes requests through its context.
    unsafe {
        let version = entry
            .try_enumerate_instance_version()?
            .unwrap_or(vk::API_VERSION_1_0);
        let application = vk::ApplicationInfo::default()
            .application_name(c"helios-gpu-test")
            .api_version(version);
        let instance = entry.create_instance(
            &vk::InstanceCreateInfo::default().application_info(&application),
            None,
        )?;
        let result = (|| {
            let physical_devices = instance.enumerate_physical_devices()?;
            let physical = *physical_devices.first().ok_or(Error::NoPhysicalDevices)?;
            let families = instance.get_physical_device_queue_family_properties(physical);
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
            let device = instance.create_device(
                physical,
                &vk::DeviceCreateInfo::default().queue_create_infos(&queues),
                None,
            )?;
            let queue = device.get_device_queue(family, 0);
            let result = memory(&instance, physical, &device)
                .and_then(|()| compute::run(&instance, physical, &device, queue, family));
            device.destroy_device(None);
            result?;
            println!(
                "gpu-test:venus device-queue ok devices={} family={family}",
                physical_devices.len()
            );
            println!("gpu-test:venus ring-reply ok api={version:#x}");
            Ok(())
        })();
        instance.destroy_instance(None);
        result
    }
}

fn memory(
    instance: &ash::Instance,
    physical: vk::PhysicalDevice,
    device: &ash::Device,
) -> Result<(), Error> {
    // SAFETY: physical and device belong to this live instance.
    unsafe {
        let properties = instance.get_physical_device_memory_properties(physical);
        let memory_type = host_memory_type(&properties, u32::MAX)?;
        let bytes = super::PAGE_BYTES;
        let allocation = device.allocate_memory(
            &vk::MemoryAllocateInfo::default()
                .allocation_size(bytes)
                .memory_type_index(memory_type),
            None,
        )?;
        let result = (|| {
            let pointer = device
                .map_memory(allocation, 0, bytes, vk::MemoryMapFlags::empty())?
                .cast::<u8>();
            let result = (|| {
                for offset in 0..bytes as usize {
                    pointer
                        .add(offset)
                        .write_volatile((offset as u8).wrapping_mul(17));
                }
                for offset in 0..bytes as usize {
                    let expected = (offset as u8).wrapping_mul(17);
                    let found = pointer.add(offset).read_volatile();
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
            device.unmap_memory(allocation);
            result
        })();
        device.free_memory(allocation, None);
        result?;
        println!("gpu-test:venus memory-map ok bytes={bytes}");
        Ok(())
    }
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
