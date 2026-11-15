//! Vulkan bring-up through the synchronous canonical import boundary.

use std::num::{NonZeroU32, NonZeroUsize};
use std::ptr::{null, null_mut};
use std::time::Duration;

use helios_venus::ObjectBase;
use helios_venus::connection::Connection;
use helios_venus::helios::Context;
use helios_venus::protocol as vk;
use helios_venus::ring::Layout;
use helios_venus::transport::{MappedBlob, TransportFactory};

mod compute;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Transport(#[from] helios_venus::helios::Error),
    #[error(transparent)]
    Connection(#[from] helios_venus::connection::Error<helios_venus::helios::Error>),
    #[error(transparent)]
    Ring(#[from] helios_venus::ring::RingError),
    #[error("{command} returned Vulkan result {result}")]
    Vulkan { command: &'static str, result: i32 },
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

fn success(command: &'static str, result: vk::VkResult) -> Result<(), Error> {
    if result == vk::VK_SUCCESS {
        Ok(())
    } else {
        Err(Error::Vulkan {
            command,
            result: result.0,
        })
    }
}

pub fn run() -> Result<(), Error> {
    // Atomics change wasm TLS relocations. Exercise std's thread-local
    // hash seed so a build mixing atomics with the prebuilt non-atomic
    // standard library traps before a later GPU consumer uses it.
    std::hint::black_box(std::hash::RandomState::new());
    // Ring zero tracks CPU command consumption; ring one tracks the
    // compute queue bound below with VkDeviceQueueTimelineInfoMESA.
    let (transport, capset) = Context::create()?;
    // One wasm page of command bytes; the test keeps the renderer's
    // idle period short enough to exercise notification as well.
    let layout = Layout::new(NonZeroU32::new(65536).unwrap())?;
    let mut connection = Connection::new(transport, capset, layout, Duration::from_millis(1))?;
    let mut version = 0;
    // SAFETY: the output lives until the reply has been decoded.
    success("vkEnumerateInstanceVersion", unsafe {
        vk::vn_call_vkEnumerateInstanceVersion(&mut connection, &mut version)?
    })?;

    let application = vk::VkApplicationInfo {
        sType: vk::VK_STRUCTURE_TYPE_APPLICATION_INFO,
        pNext: null(),
        pApplicationName: c"helios-gpu-test".as_ptr(),
        applicationVersion: 0,
        pEngineName: null(),
        engineVersion: 0,
        apiVersion: version,
    };
    let instance_info = vk::VkInstanceCreateInfo {
        sType: vk::VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO,
        pNext: null(),
        flags: 0,
        pApplicationInfo: &application,
        enabledLayerCount: 0,
        ppEnabledLayerNames: null(),
        enabledExtensionCount: 0,
        ppEnabledExtensionNames: null(),
    };
    let mut instance_storage = Box::new(ObjectBase {
        id: connection.object_id()?,
    });
    let mut instance = vk::VkInstance(&mut *instance_storage);
    // SAFETY: every create-info pointer is live; the output handle points
    // at stable storage with a connection-local renderer identifier.
    success("vkCreateInstance", unsafe {
        vk::vn_call_vkCreateInstance(&mut connection, &instance_info, null(), &mut instance)?
    })?;

    let mut count = 0;
    // SAFETY: this is the count-only form of physical-device enumeration.
    success("vkEnumeratePhysicalDevices(count)", unsafe {
        vk::vn_call_vkEnumeratePhysicalDevices(&mut connection, instance, &mut count, null_mut())?
    })?;
    let mut physical_storage = (0..count)
        .map(|_| connection.object_id().map(|id| ObjectBase { id }))
        .collect::<Result<Vec<_>, _>>()?;
    let mut physical_devices: Vec<_> = physical_storage
        .iter_mut()
        .map(|storage| vk::VkPhysicalDevice(storage))
        .collect();
    if physical_devices.is_empty() {
        return Err(Error::NoPhysicalDevices);
    }
    // SAFETY: the array has `count` live handles, each backed by stable
    // object storage that remains alive until the instance is destroyed.
    success("vkEnumeratePhysicalDevices", unsafe {
        vk::vn_call_vkEnumeratePhysicalDevices(
            &mut connection,
            instance,
            &mut count,
            physical_devices.as_mut_ptr(),
        )?
    })?;
    physical_devices.truncate(count as usize);
    let physical = *physical_devices.first().ok_or(Error::NoPhysicalDevices)?;
    let mut family_count = 0;
    // SAFETY: count-only query for the selected live physical device.
    unsafe {
        vk::vn_call_vkGetPhysicalDeviceQueueFamilyProperties(
            &mut connection,
            physical,
            &mut family_count,
            null_mut(),
        )?;
    }
    // SAFETY: queue-family properties contain only integer fields and
    // integer aggregates. Zero initializes the output capacity for sizing.
    let mut families =
        vec![unsafe { core::mem::zeroed::<vk::VkQueueFamilyProperties>() }; family_count as usize];
    // SAFETY: the output array has `family_count` initialized entries.
    unsafe {
        vk::vn_call_vkGetPhysicalDeviceQueueFamilyProperties(
            &mut connection,
            physical,
            &mut family_count,
            families.as_mut_ptr(),
        )?;
    }
    families.truncate(family_count as usize);
    let family = families
        .iter()
        .position(|family| {
            family.queueCount != 0 && family.queueFlags & vk::VK_QUEUE_COMPUTE_BIT.0 as u32 != 0
        })
        .ok_or(Error::NoComputeQueue)? as u32;
    let priority = 1.0;
    let queue_info = vk::VkDeviceQueueCreateInfo {
        sType: vk::VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO,
        pNext: null(),
        flags: 0,
        queueFamilyIndex: family,
        queueCount: 1,
        pQueuePriorities: &priority,
    };
    let device_info = vk::VkDeviceCreateInfo {
        sType: vk::VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO,
        pNext: null(),
        flags: 0,
        queueCreateInfoCount: 1,
        pQueueCreateInfos: &queue_info,
        enabledLayerCount: 0,
        ppEnabledLayerNames: null(),
        enabledExtensionCount: 0,
        ppEnabledExtensionNames: null(),
        pEnabledFeatures: null(),
    };
    let mut device_storage = Box::new(ObjectBase {
        id: connection.object_id()?,
    });
    let mut device = vk::VkDevice(&mut *device_storage);
    // SAFETY: the physical device, create-info chain, and preallocated
    // output handle all remain live throughout request and reply processing.
    success("vkCreateDevice", unsafe {
        vk::vn_call_vkCreateDevice(&mut connection, physical, &device_info, null(), &mut device)?
    })?;

    let timeline = vk::VkDeviceQueueTimelineInfoMESA {
        sType: vk::VK_STRUCTURE_TYPE_DEVICE_QUEUE_TIMELINE_INFO_MESA,
        pNext: null(),
        ringIdx: 1,
    };
    let get_queue = vk::VkDeviceQueueInfo2 {
        sType: vk::VK_STRUCTURE_TYPE_DEVICE_QUEUE_INFO_2,
        pNext: (&raw const timeline).cast(),
        flags: 0,
        queueFamilyIndex: family,
        queueIndex: 0,
    };
    let mut queue_storage = Box::new(ObjectBase {
        id: connection.object_id()?,
    });
    let mut queue = vk::VkQueue(&mut *queue_storage);
    // SAFETY: the device has this queue, and the pNext chain binds it to
    // an available context timeline. Queue storage stays live until teardown.
    unsafe {
        vk::vn_call_vkGetDeviceQueue2(&mut connection, device, &get_queue, &mut queue)?;
    }
    memory(&mut connection, physical, device)?;
    compute::run(&mut connection, physical, device, queue, family)?;
    connection.wait_queue(1)?;
    // SAFETY: no device work or child allocations remain. The final close
    // waits for both destruction commands before any handle storage is freed.
    unsafe {
        vk::vn_call_vkDestroyDevice(&mut connection, device, null())?;
        vk::vn_call_vkDestroyInstance(&mut connection, instance, null())?;
    }
    connection.close()?;
    println!("gpu-test:venus device-queue ok devices={count} family={family}");
    println!("gpu-test:venus ring-reply ok api={version:#x}");
    Ok(())
}

fn memory(
    connection: &mut Connection<Context>,
    physical: vk::VkPhysicalDevice,
    device: vk::VkDevice,
) -> Result<(), Error> {
    // SAFETY: this output structure contains only integer fields, flags
    // and fixed arrays of them; zero is a valid initialized representation.
    let mut properties = unsafe { core::mem::zeroed::<vk::VkPhysicalDeviceMemoryProperties>() };
    // SAFETY: the physical device is live and properties is writable.
    unsafe {
        vk::vn_call_vkGetPhysicalDeviceMemoryProperties(connection, physical, &mut properties)?;
    }
    let required = (vk::VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT.0
        | vk::VK_MEMORY_PROPERTY_HOST_COHERENT_BIT.0) as u32;
    let memory_type = properties
        .memoryTypes
        .iter()
        .take(properties.memoryTypeCount as usize)
        .position(|memory| memory.propertyFlags & required == required)
        .ok_or(Error::NoHostMemory)? as u32;
    let allocate = vk::VkMemoryAllocateInfo {
        sType: vk::VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO,
        pNext: null(),
        allocationSize: super::PAGE_BYTES,
        memoryTypeIndex: memory_type,
    };
    let mut memory = vk::VkDeviceMemory(connection.object_id()?);
    // SAFETY: allocation metadata and the output object identifier are
    // live, and the memory type came from this device's reported properties.
    success("vkAllocateMemory", unsafe {
        vk::vn_call_vkAllocateMemory(connection, device, &allocate, null(), &mut memory)?
    })?;
    let size = NonZeroUsize::new(super::PAGE_BYTES as usize).unwrap();
    let blob = connection.memory_blob(memory, size)?;
    let pointer = blob.pointer().as_ptr();
    // A position-dependent test pattern exposes addressing mistakes.
    let pattern = |offset: usize| (offset as u8).wrapping_mul(17);
    for offset in 0..size.get() {
        let expected = pattern(offset);
        // SAFETY: this is newly allocated coherent host-visible memory;
        // no GPU command uses it. Volatile accesses exercise the mapping.
        unsafe { pointer.add(offset).write_volatile(expected) };
    }
    for offset in 0..size.get() {
        let expected = pattern(offset);
        // SAFETY: the same live mapping and bounds as the writes above.
        let found = unsafe { pointer.add(offset).read_volatile() };
        if found != expected {
            return Err(Error::MemoryReadback {
                offset,
                expected,
                found,
            });
        }
    }
    // Revoke the guest mapping and release the blob reference before
    // enqueueing destruction of the renderer's Vulkan memory object.
    drop(blob);
    // SAFETY: no buffer, image or submitted work references this allocation.
    unsafe { vk::vn_call_vkFreeMemory(connection, device, memory, null())? };
    println!("gpu-test:venus memory-map ok bytes={}", size.get());
    Ok(())
}
