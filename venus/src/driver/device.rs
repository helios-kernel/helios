use core::ffi::{CStr, c_char};
use core::ptr::null;
use std::collections::BTreeMap;
use std::sync::Arc;

use ash::vk::{self, Handle};

use super::Factory;
use super::allocator::HostAllocator;
use super::instance::{Dispatch, TransportError, invoke_result, invoke_void, object, shared};
use crate::connection::Error;
use crate::protocol as wire;

#[repr(C)]
pub(super) struct Device<F: Factory> {
    dispatch: Dispatch<F>,
    pub(super) allocator: HostAllocator,
    queues: Vec<Box<Queue<F>, HostAllocator>>,
    pub(super) memories: BTreeMap<u64, Box<super::memory::Memory<F::Transport>, HostAllocator>>,
    pub(super) pools: BTreeMap<u64, Box<super::command::Pool<F>, HostAllocator>>,
}

#[repr(C)]
struct Queue<F: Factory> {
    dispatch: Dispatch<F>,
    family: u32,
    index: u32,
    flags: vk::DeviceQueueCreateFlags,
    ring: u8,
}

pub(super) unsafe extern "system" fn create_device<F: Factory>(
    physical: vk::PhysicalDevice,
    info: *const vk::DeviceCreateInfo<'_>,
    allocator: *const vk::AllocationCallbacks<'_>,
    output: *mut vk::Device,
) -> vk::Result {
    // SAFETY: Vulkan supplies live input structures and writable output.
    unsafe { *output = vk::Device::null() };
    let owner = unsafe { shared::<F>(object(physical)) };
    let mut state = owner.lock();
    if state.fault.is_some() {
        return vk::Result::ERROR_DEVICE_LOST;
    }
    let allocator = unsafe { HostAllocator::new(allocator, vk::SystemAllocationScope::DEVICE) };
    let result = (|| -> Result<vk::Result, Error<TransportError<F>>> {
        let id = state.connection.object_id()?;
        let mut device = match Box::try_new_in(
            Device::<F> {
                dispatch: Dispatch {
                    base: crate::ObjectBase { id },
                    shared: Arc::downgrade(&owner),
                },
                allocator,
                queues: Vec::new(),
                memories: BTreeMap::new(),
                pools: BTreeMap::new(),
            },
            allocator,
        ) {
            Ok(device) => device,
            Err(_) => return Ok(vk::Result::ERROR_OUT_OF_HOST_MEMORY),
        };
        let mut timelines = state.timelines;
        // SAFETY: Vulkan's device create-info specifies a live array.
        let infos = unsafe {
            core::slice::from_raw_parts(
                (*info).p_queue_create_infos,
                (*info).queue_create_info_count as usize,
            )
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
                info.cast(),
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
    result.unwrap_or_else(|error| state.fail(error))
}

unsafe extern "system" fn destroy_device<F: Factory>(
    device: vk::Device,
    _allocator: *const vk::AllocationCallbacks<'_>,
) {
    if device == vk::Device::null() {
        return;
    }
    let pointer = object(device);
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

unsafe fn queue<F: Factory>(
    device: vk::Device,
    family: u32,
    index: u32,
    flags: vk::DeviceQueueCreateFlags,
    output: *mut vk::Queue,
) {
    // SAFETY: Vulkan supplies a writable output and a live device.
    unsafe {
        *output = vk::Queue::null();
        let id = (*object(device)).id;
        invoke_void::<F>(object(device), |state| {
            let device = &state.devices[&id];
            let queue = device
                .queues
                .iter()
                .find(|queue| {
                    queue.family == family && queue.index == index && queue.flags == flags
                })
                .expect("Vulkan queue lookup names a queue requested at device creation");
            *output = vk::Queue::from_raw((&raw const **queue) as usize as u64);
            Ok(())
        });
    }
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
    // SAFETY: Vulkan requires a valid queue-info structure and output.
    unsafe {
        queue::<F>(
            device,
            (*info).queue_family_index,
            (*info).queue_index,
            (*info).flags,
            output,
        )
    };
}

unsafe extern "system" fn queue_wait_idle<F: Factory>(queue: vk::Queue) -> vk::Result {
    let pointer = object(queue);
    // SAFETY: queue owns this immutable timeline assignment until destruction.
    let ring = unsafe { (*pointer.cast::<Queue<F>>()).ring };
    let result = unsafe {
        invoke_result::<F>(pointer, |state| {
            state.connection.wait_queue(ring)?;
            Ok(wire::VK_SUCCESS)
        })
    };
    vk::Result::from_raw(result.0)
}

unsafe extern "system" fn device_wait_idle<F: Factory>(device: vk::Device) -> vk::Result {
    // SAFETY: device is live and its dispatch header is immutable.
    let id = unsafe { (*object(device)).id };
    let result = unsafe {
        invoke_result::<F>(object(device), |state| {
            let timelines = state.devices[&id]
                .queues
                .iter()
                .fold(0, |mask, queue| mask | (1u64 << queue.ring));
            state.connection.wait_queues(timelines)?;
            Ok(wire::VK_SUCCESS)
        })
    };
    vk::Result::from_raw(result.0)
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
        _ => return super::memory::lookup::<F>(name).or_else(|| super::command::lookup::<F>(name)),
    };
    // SAFETY: Vulkan resolves the erased pointer to the command's signature.
    Some(unsafe { core::mem::transmute::<*const (), unsafe extern "system" fn()>(pointer) })
}
