use core::ffi::c_void;
use core::num::NonZeroU64;
use core::ops::Range;
use core::ptr::{null, null_mut};
use core::sync::atomic::{Ordering, fence};

use ash::vk::{self, Handle};

use super::Factory;
use super::allocator::HostAllocator;
use super::instance::{TransportError, invoke_result, invoke_void, object, shared};
use crate::connection::Error;
use crate::protocol as wire;
use crate::transport::{MemoryResource, Transport};

pub(super) struct Memory<T: Transport> {
    size: u64,
    host_visible: bool,
    resource: Option<T::Memory>,
    active: Option<Range<u64>>,
}

unsafe extern "system" fn allocate<F: Factory>(
    device: vk::Device,
    info: *const vk::MemoryAllocateInfo<'_>,
    allocator: *const vk::AllocationCallbacks<'_>,
    output: *mut vk::DeviceMemory,
) -> vk::Result {
    // SAFETY: Vulkan requires writable output and a live device.
    unsafe { *output = vk::DeviceMemory::null() };
    let owner = unsafe { shared::<F>(object(device)) };
    let device_id = unsafe { (*object(device)).id };
    let mut state = owner.lock();
    if state.fault.is_some() {
        return vk::Result::ERROR_DEVICE_LOST;
    }
    let allocator = unsafe { HostAllocator::new(allocator, vk::SystemAllocationScope::OBJECT) };
    let result = (|| -> Result<vk::Result, Error<TransportError<F>>> {
        // SAFETY: the create-info remains live throughout this Vulkan call.
        let allocation = Memory {
            size: unsafe { (*info).allocation_size },
            host_visible: state
                .devices
                .get(&device_id)
                .unwrap()
                .memory_properties
                .memory_types[unsafe { (*info).memory_type_index } as usize]
                .property_flags
                .contains(vk::MemoryPropertyFlags::HOST_VISIBLE),
            resource: None,
            active: None,
        };
        let allocation = match Box::try_new_in(allocation, allocator) {
            Ok(allocation) => allocation,
            Err(_) => return Ok(vk::Result::ERROR_OUT_OF_HOST_MEMORY),
        };
        let mut handle = wire::VkDeviceMemory(state.connection.object_id()?);
        // SAFETY: callback pointers are guest-only; the renderer allocates
        // using its own allocator and the already assigned memory ID.
        let result = unsafe {
            wire::vn_call_vkAllocateMemory(
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
            .memories
            .insert(handle.0, allocation);
        // SAFETY: this transfers the registered Vulkan handle to the caller.
        unsafe { *output = vk::DeviceMemory::from_raw(handle.0) };
        Ok(vk::Result::SUCCESS)
    })();
    state.finish(result)
}

unsafe extern "system" fn free<F: Factory>(
    device: vk::Device,
    memory: vk::DeviceMemory,
    _allocator: *const vk::AllocationCallbacks<'_>,
) {
    if memory == vk::DeviceMemory::null() {
        return;
    }
    // SAFETY: Vulkan requires a live allocation owned by device, without
    // pending GPU accesses or resources still bound to it.
    let owner = unsafe { shared::<F>(object(device)) };
    let device_id = unsafe { (*object(device)).id };
    let mut state = owner.lock();
    let allocation = state
        .devices
        .get_mut(&device_id)
        .unwrap()
        .memories
        .remove(&memory.as_raw())
        .expect("freed Vulkan memory is owned by this device");
    // Revoke guest mappings even after device loss, before renderer release.
    drop(allocation);
    if state.fault.is_none() {
        let result = unsafe {
            wire::vn_call_vkFreeMemory(
                &mut state.connection,
                wire::VkDevice(object(device)),
                wire::VkDeviceMemory(memory.as_raw()),
                null(),
            )
        };
        if let Err(error) = result {
            let _ = state.fail(error);
        }
    }
}

unsafe extern "system" fn map<F: Factory>(
    device: vk::Device,
    memory: vk::DeviceMemory,
    offset: u64,
    size: u64,
    _flags: vk::MemoryMapFlags,
    output: *mut *mut c_void,
) -> vk::Result {
    // SAFETY: Vulkan supplies a writable output pointer and valid range.
    unsafe { *output = null_mut() };
    // SAFETY: the Vulkan caller owns this device and allocation.
    let result = unsafe {
        with_memory::<F, _>(device, memory, |allocation| {
            let pointer = allocation.resource.as_mut().unwrap().map()?;
            let allocation_size = allocation.size;
            let end = if size == vk::WHOLE_SIZE {
                allocation_size
            } else {
                offset + size
            };
            allocation.active = Some(offset..end);
            // SAFETY: Vulkan validates the range against the allocation.
            *output = pointer.as_ptr().add(offset as usize).cast();
            Ok(())
        })
    };
    result.map_or_else(|error| error, |()| vk::Result::SUCCESS)
}

/// Visit an allocation's retained blob without changing its Vulkan mapping.
///
/// # Safety
/// The device belongs to F and memory is a live allocation on that device.
#[cfg(feature = "helios")]
pub(crate) unsafe fn with_blob<F: Factory, R>(
    device: vk::Device,
    memory: vk::DeviceMemory,
    visit: impl FnOnce(&<F::Transport as Transport>::Memory) -> Result<R, TransportError<F>>,
) -> Result<R, vk::Result> {
    // SAFETY: forwarded from the caller's device and allocation contract.
    unsafe {
        with_memory::<F, _>(device, memory, |allocation| {
            visit(allocation.resource.as_ref().unwrap())
        })
    }
}

unsafe fn with_memory<F: Factory, R>(
    device: vk::Device,
    memory: vk::DeviceMemory,
    visit: impl FnOnce(&mut Memory<F::Transport>) -> Result<R, TransportError<F>>,
) -> Result<R, vk::Result> {
    // SAFETY: the caller supplies a live device of this factory.
    let owner = unsafe { shared::<F>(object(device)) };
    let device_id = unsafe { (*object(device)).id };
    let mut state = owner.lock();
    if state.fault.is_some() {
        return Err(vk::Result::ERROR_DEVICE_LOST);
    }
    let memory_id = memory.as_raw();
    let allocation = state
        .devices
        .get(&device_id)
        .unwrap()
        .memories
        .get(&memory_id)
        .expect("Vulkan memory is owned by this device");
    if allocation.resource.is_none() {
        let length = NonZeroU64::new(allocation.size).expect("Vulkan allocations are nonempty");
        let host_visible = allocation.host_visible;
        let resource = state
            .connection
            .memory_resource(wire::VkDeviceMemory(memory_id), length, host_visible)
            .map_err(|error| state.fail(error))?;
        state
            .devices
            .get_mut(&device_id)
            .unwrap()
            .memories
            .get_mut(&memory_id)
            .unwrap()
            .resource = Some(resource);
    }
    let allocation = state
        .devices
        .get_mut(&device_id)
        .unwrap()
        .memories
        .get_mut(&memory_id)
        .unwrap();
    let result = visit(allocation);
    result.map_err(|error| state.fail(Error::Transport(error)))
}

unsafe extern "system" fn unmap<F: Factory>(device: vk::Device, memory: vk::DeviceMemory) {
    // SAFETY: Vulkan requires a live, currently mapped allocation.
    unsafe {
        let device_id = (*object(device)).id;
        invoke_void::<F>(object(device), |state| {
            let memory = state
                .devices
                .get_mut(&device_id)
                .unwrap()
                .memories
                .get_mut(&memory.as_raw())
                .unwrap();
            memory.active = None;
            // As in Mesa's virtgpu backend, retain the coherent blob for
            // remapping; only the application's mapping lifetime ends here.
            Ok(())
        });
    }
}

unsafe extern "system" fn flush<F: Factory>(
    device: vk::Device,
    _count: u32,
    _ranges: *const vk::MappedMemoryRange<'_>,
) -> vk::Result {
    // SAFETY: Vulkan supplies valid mapped ranges. MappedBlob guarantees
    // coherence, so no device cache operation is needed; publish host writes.
    let result = unsafe {
        invoke_result::<F>(object(device), |_| {
            fence(Ordering::Release);
            Ok(wire::VK_SUCCESS)
        })
    };
    vk::Result::from_raw(result.0)
}

unsafe extern "system" fn invalidate<F: Factory>(
    device: vk::Device,
    _count: u32,
    _ranges: *const vk::MappedMemoryRange<'_>,
) -> vk::Result {
    // SAFETY: the caller has synchronized device writes. Coherent mappings
    // need an acquire ordering point, not a renderer-side remapping request.
    let result = unsafe {
        invoke_result::<F>(object(device), |_| {
            fence(Ordering::Acquire);
            Ok(wire::VK_SUCCESS)
        })
    };
    vk::Result::from_raw(result.0)
}

pub(super) fn lookup<F: Factory>(name: &[u8]) -> vk::PFN_vkVoidFunction {
    let pointer = match name {
        b"vkAllocateMemory" => allocate::<F> as *const (),
        b"vkFreeMemory" => free::<F> as *const (),
        b"vkMapMemory" => map::<F> as *const (),
        b"vkUnmapMemory" => unmap::<F> as *const (),
        b"vkFlushMappedMemoryRanges" => flush::<F> as *const (),
        b"vkInvalidateMappedMemoryRanges" => invalidate::<F> as *const (),
        _ => return None,
    };
    // SAFETY: Vulkan restores the function signature named by the lookup.
    Some(unsafe { core::mem::transmute::<*const (), unsafe extern "system" fn()>(pointer) })
}
