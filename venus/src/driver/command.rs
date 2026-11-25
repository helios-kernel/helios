use core::ptr::null;
use std::collections::BTreeMap;
use std::sync::Arc;

use ash::vk::{self, Handle};

use super::Factory;
use super::allocator::HostAllocator;
use super::instance::{Dispatch, TransportError, object, shared};
use crate::ObjectBase;
use crate::connection::Error;
use crate::protocol as wire;

pub(super) struct Pool<F: Factory> {
    allocator: HostAllocator,
    buffers: BTreeMap<u64, Box<Dispatch<F>, HostAllocator>>,
}

unsafe extern "system" fn create_pool<F: Factory>(
    device: vk::Device,
    info: *const vk::CommandPoolCreateInfo<'_>,
    allocator: *const vk::AllocationCallbacks<'_>,
    output: *mut vk::CommandPool,
) -> vk::Result {
    // SAFETY: Vulkan supplies a writable output slot.
    unsafe { *output = vk::CommandPool::null() };
    // SAFETY: Vulkan supplies a live device handle of this factory.
    let owner = unsafe { shared::<F>(object(device)) };
    // SAFETY: the live device's dispatch header is immutable after creation.
    let device_id = unsafe { (*object(device)).id };
    let mut state = owner.lock();
    if state.fault.is_some() {
        return vk::Result::ERROR_DEVICE_LOST;
    }
    // SAFETY: Vulkan supplies valid allocation callbacks or null for default allocation.
    let allocator = unsafe { HostAllocator::new(allocator, vk::SystemAllocationScope::OBJECT) };
    let result = (|| -> Result<vk::Result, Error<TransportError<F>>> {
        let pool = match Box::try_new_in(
            Pool {
                allocator,
                buffers: BTreeMap::new(),
            },
            allocator,
        ) {
            Ok(pool) => pool,
            Err(_) => return Ok(vk::Result::ERROR_OUT_OF_HOST_MEMORY),
        };
        let mut handle = wire::VkCommandPool(state.connection.object_id()?);
        // SAFETY: the renderer consumes only serialized values and its own
        // allocator; guest callbacks belong to the pool and its buffers.
        let result = unsafe {
            wire::vn_call_vkCreateCommandPool(
                &mut state.connection,
                wire::VkDevice(object(device)),
                info.cast(),
                null(),
                &mut handle,
            )
        }?;
        if result != wire::VK_SUCCESS {
            return Ok(vk::Result::from_raw(result.0));
        }
        state
            .devices
            .get_mut(&device_id)
            .unwrap()
            .pools
            .insert(handle.0, pool);
        // SAFETY: `output` is writable and transfers the registered pool handle.
        unsafe { *output = vk::CommandPool::from_raw(handle.0) };
        Ok(vk::Result::SUCCESS)
    })();
    state.finish(result)
}

unsafe extern "system" fn destroy_pool<F: Factory>(
    device: vk::Device,
    pool: vk::CommandPool,
    _allocator: *const vk::AllocationCallbacks<'_>,
) {
    if pool == vk::CommandPool::null() {
        return;
    }
    // SAFETY: Vulkan requires a live device and no pending use of this pool or its buffers.
    let owner = unsafe { shared::<F>(object(device)) };
    // SAFETY: the live device's dispatch header is immutable after creation.
    let device_id = unsafe { (*object(device)).id };
    let mut state = owner.lock();
    if state.fault.is_none() {
        // SAFETY: the device and pool are live and no command buffers from this pool are pending.
        let result = unsafe {
            wire::vn_call_vkDestroyCommandPool(
                &mut state.connection,
                wire::VkDevice(object(device)),
                wire::VkCommandPool(pool.as_raw()),
                null(),
            )
        };
        if let Err(error) = result {
            let _ = state.fail(error);
        }
    }
    // The wire command already owns all identifiers. No renderer accesses
    // these guest pointers, so no CPU fence is needed to release them.
    state
        .devices
        .get_mut(&device_id)
        .unwrap()
        .pools
        .remove(&pool.as_raw())
        .expect("destroyed command pool belongs to this device");
}

unsafe extern "system" fn allocate_buffers<F: Factory>(
    device: vk::Device,
    info: *const vk::CommandBufferAllocateInfo<'_>,
    output: *mut vk::CommandBuffer,
) -> vk::Result {
    // SAFETY: Vulkan supplies a live device handle of this factory.
    let owner = unsafe { shared::<F>(object(device)) };
    // SAFETY: the live device's dispatch header is immutable after creation.
    let device_id = unsafe { (*object(device)).id };
    // SAFETY: Vulkan provides a live `CommandBufferAllocateInfo` for this call.
    let allocate_info = unsafe { &*info };
    let count = allocate_info.command_buffer_count as usize;
    let pool_id = allocate_info.command_pool.as_raw();
    for index in 0..count {
        // SAFETY: Vulkan guarantees `output` has capacity for `count` handles.
        let slot = unsafe { output.add(index) };
        // SAFETY: `slot` is aligned and writable.
        unsafe { slot.write(vk::CommandBuffer::null()) };
    }
    let mut state = owner.lock();
    if state.fault.is_some() {
        return vk::Result::ERROR_DEVICE_LOST;
    }
    let allocator = state.devices[&device_id].pools[&pool_id].allocator;
    let result = (|| -> Result<vk::Result, Error<TransportError<F>>> {
        let mut buffers = Vec::with_capacity(count);
        for _ in 0..count {
            let dispatch = Dispatch {
                base: ObjectBase {
                    id: state.connection.object_id()?,
                },
                shared: Arc::downgrade(&owner),
            };
            match Box::try_new_in(dispatch, allocator) {
                Ok(buffer) => buffers.push(buffer),
                Err(_) => return Ok(vk::Result::ERROR_OUT_OF_HOST_MEMORY),
            }
        }
        let mut handles: Vec<_> = buffers
            .iter_mut()
            .map(|buffer| wire::VkCommandBuffer(&mut buffer.base))
            .collect();
        // SAFETY: every output has a stable allocation and renderer ID.
        let result = unsafe {
            wire::vn_call_vkAllocateCommandBuffers(
                &mut state.connection,
                wire::VkDevice(object(device)),
                info.cast(),
                handles.as_mut_ptr(),
            )
        }?;
        if result != wire::VK_SUCCESS {
            return Ok(vk::Result::from_raw(result.0));
        }
        let pool = state
            .devices
            .get_mut(&device_id)
            .unwrap()
            .pools
            .get_mut(&pool_id)
            .unwrap();
        for (index, buffer) in buffers.into_iter().enumerate() {
            let handle = vk::CommandBuffer::from_raw((&raw const *buffer) as usize as u64);
            pool.buffers.insert(buffer.base.id, buffer);
            // SAFETY: ownership transfers through the pool; `output` has `count` slots.
            let slot = unsafe { output.add(index) };
            // SAFETY: `slot` is aligned and writable.
            unsafe { slot.write(handle) };
        }
        Ok(vk::Result::SUCCESS)
    })();
    state.finish(result)
}

unsafe extern "system" fn free_buffers<F: Factory>(
    device: vk::Device,
    pool: vk::CommandPool,
    count: u32,
    buffers: *const vk::CommandBuffer,
) {
    // SAFETY: Vulkan supplies a live device handle of this factory.
    let owner = unsafe { shared::<F>(object(device)) };
    // SAFETY: the live device's dispatch header is immutable after creation.
    let device_id = unsafe { (*object(device)).id };
    let mut state = owner.lock();
    if state.fault.is_none() {
        // SAFETY: Vulkan supplies `count` non-pending handles owned by `pool`.
        let result = unsafe {
            wire::vn_call_vkFreeCommandBuffers(
                &mut state.connection,
                wire::VkDevice(object(device)),
                wire::VkCommandPool(pool.as_raw()),
                count,
                buffers.cast(),
            )
        };
        if let Err(error) = result {
            let _ = state.fail(error);
        }
    }
    let pool = state
        .devices
        .get_mut(&device_id)
        .unwrap()
        .pools
        .get_mut(&pool.as_raw())
        .unwrap();
    for index in 0..count as usize {
        // SAFETY: `buffers` has `count` valid entries for this call.
        let slot = unsafe { buffers.add(index) };
        // SAFETY: `slot` is aligned and readable.
        let handle = unsafe { *slot };
        // Vulkan permits null entries in vkFreeCommandBuffers.
        if handle != vk::CommandBuffer::null() {
            // SAFETY: non-null command buffer handles point to a live `Dispatch` header.
            let id = unsafe { (*object(handle)).id };
            pool.buffers
                .remove(&id)
                .expect("freed command buffer belongs to this pool");
        }
    }
}

pub(super) fn lookup<F: Factory>(name: &[u8]) -> vk::PFN_vkVoidFunction {
    let pointer = match name {
        b"vkCreateCommandPool" => create_pool::<F> as *const (),
        b"vkDestroyCommandPool" => destroy_pool::<F> as *const (),
        b"vkAllocateCommandBuffers" => allocate_buffers::<F> as *const (),
        b"vkFreeCommandBuffers" => free_buffers::<F> as *const (),
        _ => return None,
    };
    // SAFETY: Vulkan restores the named function's signature.
    Some(unsafe { core::mem::transmute::<*const (), unsafe extern "system" fn()>(pointer) })
}
