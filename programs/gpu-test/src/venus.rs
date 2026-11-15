//! Vulkan bring-up through the synchronous canonical import boundary.

use std::num::NonZeroU32;
use std::ptr::{null, null_mut};
use std::time::Duration;

use helios_venus::ObjectBase;
use helios_venus::connection::Connection;
use helios_venus::helios::Context;
use helios_venus::protocol as vk;
use helios_venus::ring::Layout;

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
    let (transport, capset) = Context::open(2, "venus-test")?;
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
