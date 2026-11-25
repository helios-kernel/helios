use core::ffi::{CStr, c_char};
use core::ptr::null;
use std::collections::BTreeMap;
use std::sync::Arc;

use ash::vk::{self, Handle};

use super::Factory;
use super::allocator::HostAllocator;
use super::external::{ExternalMemory, enables_external_memory, renderer_device_extensions};
use super::instance::{
    Dispatch, State, TransportError, invoke_void, object, shared, wait_for_points,
};
use crate::connection::Error;
use crate::protocol as wire;
#[cfg(feature = "helios")]
use crate::transport::{SignalPoint, Transport};

#[repr(C)]
pub(super) struct Device<F: Factory> {
    dispatch: Dispatch<F>,
    pub(super) allocator: HostAllocator,
    pub(super) memory_properties: vk::PhysicalDeviceMemoryProperties,
    /// Immutable after creation, so entry points read it without the lock.
    pub(super) external: ExternalMemory,
    queues: Vec<Box<Queue<F>, HostAllocator>>,
    pub(super) memories: BTreeMap<u64, Box<super::memory::Memory<F::Transport>, HostAllocator>>,
    pub(super) fences: BTreeMap<u64, Box<super::sync::Fence<F::Transport>, HostAllocator>>,
    pub(super) semaphores: BTreeMap<u64, Box<super::sync::Semaphore<F::Transport>, HostAllocator>>,
    pub(super) pools: BTreeMap<u64, Box<super::command::Pool<F>, HostAllocator>>,
}

#[repr(C)]
pub(super) struct Queue<F: Factory> {
    dispatch: Dispatch<F>,
    family: u32,
    index: u32,
    flags: vk::DeviceQueueCreateFlags,
    pub(super) ring: u8,
    pub(super) device: u64,
}

/// Mark all prior work on a live Vulkan queue with a fresh completion source.
///
/// # Safety
/// The queue belongs to F and remains live throughout the call.
#[cfg(feature = "helios")]
pub(crate) unsafe fn completion<F: Factory>(
    queue: vk::Queue,
) -> Result<<F::Transport as Transport>::Signal, vk::Result> {
    // SAFETY: the caller supplies a live queue from this factory.
    let owner = unsafe { shared::<F>(object(queue)) };
    // SAFETY: `Queue::ring` is immutable after device creation.
    let ring = unsafe { (*object(queue).cast::<Queue<F>>()).ring };
    let mut state = owner.lock();
    if state.fault.is_some() {
        return Err(vk::Result::ERROR_DEVICE_LOST);
    }
    let source = state.connection.timeline(0);
    state
        .connection
        .signal_queue(
            ring,
            &[SignalPoint {
                source: &source,
                value: 1,
            }],
        )
        .map_err(|error| state.fail(error))?;
    Ok(source)
}

/// Create a logical Vulkan device and its requested queues.
///
/// # Safety
/// `physical`, `info`, `allocator`, and `output` must satisfy Vulkan's
/// `vkCreateDevice` contract for a physical device owned by `F`.
pub(super) unsafe extern "system" fn create_device<F: Factory>(
    physical: vk::PhysicalDevice,
    info: *const vk::DeviceCreateInfo<'_>,
    allocator: *const vk::AllocationCallbacks<'_>,
    output: *mut vk::Device,
) -> vk::Result {
    // SAFETY: Vulkan supplies a writable output pointer.
    unsafe { *output = vk::Device::null() };
    // SAFETY: Vulkan supplies a live physical device belonging to this factory.
    let owner = unsafe { shared::<F>(object(physical)) };
    let mut state = owner.lock();
    if state.fault.is_some() {
        return vk::Result::ERROR_DEVICE_LOST;
    }
    // SAFETY: Vulkan supplies valid allocation callbacks or null for default allocation.
    let allocator = unsafe { HostAllocator::new(allocator, vk::SystemAllocationScope::DEVICE) };
    let result = (|| -> Result<vk::Result, Error<TransportError<F>>> {
        let mut memory_properties = vk::PhysicalDeviceMemoryProperties::default();
        // SAFETY: the physical device is live and output has the Vulkan ABI layout.
        unsafe {
            wire::vn_call_vkGetPhysicalDeviceMemoryProperties(
                &mut state.connection,
                wire::VkPhysicalDevice(object(physical)),
                (&raw mut memory_properties).cast(),
            )
        }?;
        // The guest implements the external memory extensions; the renderer
        // enables the ones its own handle type needs.
        // SAFETY: Vulkan supplies a live `DeviceCreateInfo` for this call.
        let create_info = unsafe { &*info };
        let extension_names = if create_info.enabled_extension_count == 0 {
            &[]
        } else {
            // SAFETY: `pp_enabled_extension_names` has `enabled_extension_count` entries.
            unsafe {
                core::slice::from_raw_parts(
                    create_info.pp_enabled_extension_names,
                    create_info.enabled_extension_count as usize,
                )
            }
        };
        let application: Vec<&CStr> = extension_names
            .iter()
            .map(|&name| {
                // SAFETY: each entry in `pp_enabled_extension_names` is a live NUL-terminated C string.
                unsafe { CStr::from_ptr(name) }
            })
            .collect();
        let external = if enables_external_memory(&application) {
            // SAFETY: `physical` is a live physical device belonging to this instance.
            match unsafe { state.physical_external(physical) }? {
                Ok(physical) => physical.memory,
                Err(result) => return Ok(result),
            }
        } else {
            ExternalMemory::NONE
        };
        let renderer_extensions = match renderer_device_extensions(&application, external) {
            Ok(extensions) => extensions,
            Err(result) => return Ok(result),
        };
        let renderer_names: Option<Vec<*const c_char>> = renderer_extensions
            .map(|extensions| extensions.iter().map(|name| name.as_ptr()).collect());
        let mut renderer_info = *create_info;
        if let Some(names) = &renderer_names {
            renderer_info.enabled_extension_count = names.len() as u32;
            renderer_info.pp_enabled_extension_names = names.as_ptr();
        }
        let id = state.connection.object_id()?;
        let mut device = match Box::try_new_in(
            Device::<F> {
                dispatch: Dispatch {
                    base: crate::ObjectBase { id },
                    shared: Arc::downgrade(&owner),
                },
                allocator,
                memory_properties,
                external,
                queues: Vec::new(),
                memories: BTreeMap::new(),
                pools: BTreeMap::new(),
                fences: BTreeMap::new(),
                semaphores: BTreeMap::new(),
            },
            allocator,
        ) {
            Ok(device) => device,
            Err(_) => return Ok(vk::Result::ERROR_OUT_OF_HOST_MEMORY),
        };
        let mut timelines = state.timelines;
        let infos = if create_info.queue_create_info_count == 0 {
            &[]
        } else {
            // SAFETY: Vulkan's device create-info specifies a live queue create-info array.
            unsafe {
                core::slice::from_raw_parts(
                    create_info.p_queue_create_infos,
                    create_info.queue_create_info_count as usize,
                )
            }
        };
        for queue_info in infos {
            for index in 0..queue_info.queue_count {
                let ring = (!timelines).trailing_zeros();
                // The fixed virtio GPU fencing space has 64 timeline bits.
                // Like Mesa, creation fails when it cannot bind a queue.
                if ring == u64::BITS {
                    return Ok(vk::Result::ERROR_INITIALIZATION_FAILED);
                }
                timelines |= 1u64 << ring;
                let queue = Queue {
                    dispatch: Dispatch {
                        base: crate::ObjectBase {
                            id: state.connection.object_id()?,
                        },
                        shared: Arc::downgrade(&owner),
                    },
                    family: queue_info.queue_family_index,
                    index,
                    flags: queue_info.flags,
                    ring: ring as u8,
                    device: id,
                };
                match Box::try_new_in(
                    queue,
                    device
                        .allocator
                        .with_scope(vk::SystemAllocationScope::OBJECT),
                ) {
                    Ok(queue) => device.queues.push(queue),
                    Err(_) => return Ok(vk::Result::ERROR_OUT_OF_HOST_MEMORY),
                }
            }
        }
        let mut handle = wire::VkDevice(&mut device.dispatch.base);
        // SAFETY: all guest object storage and create-info pointers are live.
        let result = unsafe {
            wire::vn_call_vkCreateDevice(
                &mut state.connection,
                wire::VkPhysicalDevice(object(physical)),
                (&raw const renderer_info).cast(),
                null(),
                &mut handle,
            )
        }?;
        if result != wire::VK_SUCCESS {
            return Ok(vk::Result::from_raw(result.0));
        }
        for queue in &mut device.queues {
            let timeline = wire::VkDeviceQueueTimelineInfoMESA {
                sType: wire::VK_STRUCTURE_TYPE_DEVICE_QUEUE_TIMELINE_INFO_MESA,
                pNext: null(),
                ringIdx: u32::from(queue.ring),
            };
            let queue_info = wire::VkDeviceQueueInfo2 {
                sType: wire::VK_STRUCTURE_TYPE_DEVICE_QUEUE_INFO_2,
                pNext: (&raw const timeline).cast(),
                flags: queue.flags.as_raw(),
                queueFamilyIndex: queue.family,
                queueIndex: queue.index,
            };
            let mut queue_handle = wire::VkQueue(&mut queue.dispatch.base);
            // SAFETY: the queue was requested by this device's create-info;
            // its stable storage and timeline remain owned by that device.
            unsafe {
                wire::vn_call_vkGetDeviceQueue2(
                    &mut state.connection,
                    handle,
                    &queue_info,
                    &mut queue_handle,
                )
            }?;
        }
        let pointer = (&raw mut *device) as usize as u64;
        state.devices.insert(id, device);
        state.timelines = timelines;
        // SAFETY: ownership remains in the instance registry until destruction.
        unsafe { *output = vk::Device::from_raw(pointer) };
        Ok(vk::Result::SUCCESS)
    })();
    state.finish(result)
}

unsafe extern "system" fn destroy_device<F: Factory>(
    device: vk::Device,
    _allocator: *const vk::AllocationCallbacks<'_>,
) {
    if device == vk::Device::null() {
        return;
    }
    let pointer = object(device);
    // SAFETY: Vulkan supplies a live device handle belonging to this factory.
    let owner = unsafe { shared::<F>(pointer) };
    // SAFETY: the live device's dispatch header is immutable after creation.
    let id = unsafe { (*pointer).id };
    let mut state = owner.lock();
    // SAFETY: Vulkan requires no pending work and no live device children.
    let result = unsafe {
        wire::vn_call_vkDestroyDevice(&mut state.connection, wire::VkDevice(pointer), null())
    }
    .and_then(|()| state.connection.flush());
    if let Err(error) = result {
        let _ = state.fail(error);
    }
    let device = state
        .devices
        .remove(&id)
        .expect("live Vulkan device is registered");
    for queue in &device.queues {
        state.timelines &= !(1u64 << queue.ring);
    }
}

/// Look up a queue created on `device` by family, index, and creation flags.
///
/// # Safety
/// `device` must be a live device handle of `F` and `output` must be valid for writes.
unsafe fn queue<F: Factory>(
    device: vk::Device,
    family: u32,
    index: u32,
    flags: vk::DeviceQueueCreateFlags,
    output: *mut vk::Queue,
) {
    // SAFETY: Vulkan supplies a writable output pointer.
    unsafe { *output = vk::Queue::null() };
    // SAFETY: the live device's dispatch header is immutable after creation.
    let id = unsafe { (*object(device)).id };
    let call = |state: &mut State<F>| {
        let device = &state.devices[&id];
        let queue = device
            .queues
            .iter()
            .find(|queue| queue.family == family && queue.index == index && queue.flags == flags)
            .expect("Vulkan queue lookup names a queue requested at device creation");
        let handle = vk::Queue::from_raw((&raw const **queue) as usize as u64);
        // SAFETY: `output` is writable and unaliased for this call.
        unsafe { *output = handle };
        Ok(())
    };
    // SAFETY: `device` is a live dispatchable object of this factory.
    unsafe { invoke_void::<F>(object(device), call) };
}

unsafe extern "system" fn get_device_queue<F: Factory>(
    device: vk::Device,
    family: u32,
    index: u32,
    output: *mut vk::Queue,
) {
    // SAFETY: forwarded unchanged from Vulkan; this entry queries flags zero.
    unsafe {
        queue::<F>(
            device,
            family,
            index,
            vk::DeviceQueueCreateFlags::empty(),
            output,
        )
    };
}

unsafe extern "system" fn get_device_queue2<F: Factory>(
    device: vk::Device,
    info: *const vk::DeviceQueueInfo2<'_>,
    output: *mut vk::Queue,
) {
    // SAFETY: Vulkan supplies a live `DeviceQueueInfo2` for this call.
    let queue_info = unsafe { &*info };
    // SAFETY: Vulkan requires a valid device and writable queue output.
    unsafe {
        queue::<F>(
            device,
            queue_info.queue_family_index,
            queue_info.queue_index,
            queue_info.flags,
            output,
        )
    };
}

unsafe extern "system" fn queue_wait_idle<F: Factory>(queue: vk::Queue) -> vk::Result {
    let pointer = object(queue);
    // SAFETY: queue owns this immutable timeline assignment until destruction.
    let ring = unsafe { (*pointer.cast::<Queue<F>>()).ring };
    // SAFETY: `pointer` is a live queue handle of this factory.
    unsafe {
        wait_for_points::<F>(pointer, true, u64::MAX, |state| {
            state.connection.completion_points(1u64 << ring)
        })
    }
}

unsafe extern "system" fn device_wait_idle<F: Factory>(device: vk::Device) -> vk::Result {
    // SAFETY: device is live and its dispatch header is immutable.
    let id = unsafe { (*object(device)).id };
    // SAFETY: `device` is a live device handle of this factory.
    unsafe {
        wait_for_points::<F>(object(device), true, u64::MAX, |state| {
            let timelines = state.devices[&id]
                .queues
                .iter()
                .fold(0, |mask, queue| mask | (1u64 << queue.ring));
            state.connection.completion_points(timelines)
        })
    }
}

unsafe extern "system" fn get_device_proc_addr<F: Factory>(
    device: vk::Device,
    name: *const c_char,
) -> vk::PFN_vkVoidFunction {
    if device == vk::Device::null() {
        return None;
    }
    // SAFETY: Vulkan supplies a NUL-terminated command name.
    let name = unsafe { CStr::from_ptr(name) }.to_bytes();
    lookup::<F>(name).or_else(|| super::generated::lookup::<F>(name, true))
}

pub(super) fn lookup<F: Factory>(name: &[u8]) -> vk::PFN_vkVoidFunction {
    let pointer = match name {
        b"vkGetDeviceProcAddr" => get_device_proc_addr::<F> as *const (),
        b"vkDestroyDevice" => destroy_device::<F> as *const (),
        b"vkGetDeviceQueue" => get_device_queue::<F> as *const (),
        b"vkGetDeviceQueue2" => get_device_queue2::<F> as *const (),
        b"vkQueueWaitIdle" => queue_wait_idle::<F> as *const (),
        b"vkDeviceWaitIdle" => device_wait_idle::<F> as *const (),
        _ => {
            return super::sync::lookup::<F>(name)
                .or_else(|| super::memory::lookup::<F>(name))
                .or_else(|| super::external::lookup::<F>(name))
                .or_else(|| super::command::lookup::<F>(name));
        }
    };
    // SAFETY: Vulkan resolves the erased pointer to the command's signature.
    Some(unsafe { core::mem::transmute::<*const (), unsafe extern "system" fn()>(pointer) })
}
