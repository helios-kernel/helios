use core::ffi::{CStr, c_char};
use core::ptr::{null, null_mut};
use std::collections::BTreeMap;
use std::sync::{Arc, Weak};

use ash::vk::{self, Handle};

use super::allocator::HostAllocator;
use super::exclusive::Exclusive;
use super::{Configuration, Factory};
use crate::ObjectBase;
use crate::connection::{Connection, Error};
use crate::protocol as wire;
use crate::transport::{SignalTimeline, Timeline, Transport, WaitPoint};

pub(super) type TransportError<F> =
    <<F as crate::transport::TransportFactory>::Transport as Transport>::Error;
pub(super) type Shared<F> = Exclusive<State<F>, <F as Factory>::Lock>;
type OwnedDispatch<F> = Box<Dispatch<F>, HostAllocator>;

#[repr(C)]
pub(super) struct Dispatch<F: Factory> {
    pub(super) base: ObjectBase,
    pub(super) shared: Weak<Shared<F>>,
}

#[repr(C)]
struct Instance<F: Factory> {
    dispatch: Dispatch<F>,
    owner: Arc<Shared<F>>,
    allocator: HostAllocator,
}

pub(super) struct State<F: Factory> {
    pub(super) connection: Connection<F::Transport>,
    physical: Option<Vec<OwnedDispatch<F>>>,
    allocator: HostAllocator,
    pub(super) fault: Option<Error<TransportError<F>>>,
    pub(super) devices: BTreeMap<u64, Box<super::device::Device<F>, HostAllocator>>,
    pub(super) timelines: u64,
    /// Each physical device's external memory, by object ID, from first use.
    pub(super) external: BTreeMap<u64, super::external::PhysicalExternal>,
}

pub(super) fn object<H: Handle>(handle: H) -> *mut ObjectBase {
    handle.as_raw() as usize as *mut ObjectBase
}

pub(super) unsafe fn shared<F: Factory>(object: *mut ObjectBase) -> Arc<Shared<F>> {
    // SAFETY: the caller supplies a live dispatchable handle of this factory.
    unsafe { &*object.cast::<Dispatch<F>>() }
        .shared
        .upgrade()
        .expect("Vulkan object outlives its instance")
}

impl<F: Factory> State<F> {
    pub(super) fn finish(
        &mut self,
        result: Result<vk::Result, Error<TransportError<F>>>,
    ) -> vk::Result {
        match result {
            Ok(vk::Result::ERROR_DEVICE_LOST) => self.fail(Error::DeviceLost),
            Ok(result) => result,
            Err(error) => self.fail(error),
        }
    }

    pub(super) fn fail(&mut self, error: Error<TransportError<F>>) -> vk::Result {
        tracing::error!(error = %error, "Venus connection failed");
        self.connection.fail_timelines();
        for device in self.devices.values() {
            for fence in device.fences.values() {
                fence.fail();
            }
            for semaphore in device.semaphores.values() {
                semaphore.fail();
            }
        }
        self.fault = Some(error);
        vk::Result::ERROR_DEVICE_LOST
    }
}

pub(super) unsafe fn invoke<F: Factory, R>(
    object: *mut ObjectBase,
    call: impl FnOnce(&mut State<F>) -> Result<R, Error<TransportError<F>>>,
) -> Result<R, vk::Result> {
    // SAFETY: the Vulkan caller supplies a live object from this entry table.
    let shared = unsafe { shared::<F>(object) };
    let mut state = shared.lock();
    if state.fault.is_some() {
        return Err(vk::Result::ERROR_DEVICE_LOST);
    }
    call(&mut state).map_err(|error| state.fail(error))
}

pub(super) unsafe fn invoke_result<F: Factory>(
    object: *mut ObjectBase,
    call: impl FnOnce(&mut State<F>) -> Result<wire::VkResult, Error<TransportError<F>>>,
) -> wire::VkResult {
    // SAFETY: forwarded unchanged from the Vulkan entry point.
    match unsafe {
        invoke::<F, _>(object, |state| {
            let result = call(state).map(|result| vk::Result::from_raw(result.0));
            Ok(wire::VkResult(state.finish(result).as_raw()))
        })
    } {
        Ok(result) => result,
        Err(result) => wire::VkResult(result.as_raw()),
    }
}

/// Captures completion points while serializing submission, then suspends
/// without the lock so other threads can submit future signals.
pub(super) unsafe fn wait_for_points<F: Factory>(
    object: *mut ObjectBase,
    wait_all: bool,
    timeout: u64,
    capture: impl FnOnce(
        &mut State<F>,
    ) -> Result<Vec<WaitPoint<F::Transport>>, Error<TransportError<F>>>,
) -> vk::Result {
    // SAFETY: the caller holds a live dispatchable object of this factory.
    let owner = unsafe { shared::<F>(object) };
    let points = {
        let mut state = owner.lock();
        if state.fault.is_some() {
            return vk::Result::ERROR_DEVICE_LOST;
        }
        match capture(&mut state) {
            Ok(points) => points,
            Err(error) => return state.fail(error),
        }
    };
    let result = <<F::Transport as Transport>::Signal as SignalTimeline>::Timeline::wait(
        &points,
        wait_all,
        (timeout != u64::MAX).then(|| core::time::Duration::from_nanos(timeout)),
    );
    let mut state = owner.lock();
    if state.fault.is_some() {
        return vk::Result::ERROR_DEVICE_LOST;
    }
    match result {
        Ok(true) => vk::Result::SUCCESS,
        Ok(false) => vk::Result::TIMEOUT,
        Err(error) => state.fail(Error::Transport(error)),
    }
}

pub(super) unsafe fn invoke_void<F: Factory>(
    object: *mut ObjectBase,
    call: impl FnOnce(&mut State<F>) -> Result<(), Error<TransportError<F>>>,
) {
    // SAFETY: forwarded unchanged from the Vulkan entry point. A failed
    // void command records device loss, observable by subsequent result calls.
    let _ = unsafe { invoke::<F, _>(object, call) };
}

fn open<F: Factory>() -> Result<Connection<F::Transport>, Error<TransportError<F>>> {
    let (transport, capset) = F::create().map_err(Error::Transport)?;
    let Configuration {
        layout,
        idle_timeout,
    } = F::configuration();
    Connection::new(transport, capset, layout, idle_timeout)
}

fn global<F: Factory>(
    call: impl FnOnce(&mut Connection<F::Transport>) -> Result<wire::VkResult, Error<TransportError<F>>>,
) -> vk::Result {
    let result = (|| {
        let mut connection = open::<F>()?;
        let result = call(&mut connection)?;
        connection.close()?;
        Ok::<_, Error<TransportError<F>>>(result)
    })();
    match result {
        Ok(result) => vk::Result::from_raw(result.0),
        Err(error) => {
            tracing::error!(error = %error, "Venus global query failed");
            vk::Result::ERROR_INITIALIZATION_FAILED
        }
    }
}

unsafe extern "system" fn enumerate_version<F: Factory>(version: *mut u32) -> vk::Result {
    global::<F>(|connection| {
        // SAFETY: Vulkan's caller supplies a writable version word.
        unsafe { wire::vn_call_vkEnumerateInstanceVersion(connection, version) }
    })
}

fn supported_extensions() -> [(&'static CStr, u32); 1] {
    [(
        ash::khr::get_physical_device_properties2::NAME,
        ash::khr::get_physical_device_properties2::SPEC_VERSION,
    )]
}

unsafe extern "system" fn enumerate_extensions(
    layer: *const c_char,
    count: *mut u32,
    properties: *mut vk::ExtensionProperties,
) -> vk::Result {
    // An ICD implements no instance layers; a loader handles layer queries.
    if !layer.is_null() {
        return vk::Result::ERROR_LAYER_NOT_PRESENT;
    }
    // The renderer enumerates private wire extensions, not guest Vulkan
    // extensions. These queries are core in the renderer's required Vulkan 1.1.
    let extensions = supported_extensions().map(|(name, version)| {
        vk::ExtensionProperties::default()
            .extension_name(name)
            .expect("extension names fit VK_MAX_EXTENSION_NAME_SIZE")
            .spec_version(version)
    });
    // SAFETY: Vulkan supplies a writable count and the declared output capacity.
    unsafe { write_properties(count, properties, &extensions) }
}

/// Answer a Vulkan enumeration of `items`: the count alone when `output` is
/// null, else as many as `count` holds, INCOMPLETE when that is not all.
///
/// # Safety
/// `count` is writable and, unless `output` is null, `output` has room for
/// the `count` it points to.
pub(super) unsafe fn write_properties<T: Copy>(
    count: *mut u32,
    output: *mut T,
    items: &[T],
) -> vk::Result {
    // SAFETY: forwarded from the caller.
    let written = unsafe {
        if output.is_null() {
            *count = items.len() as u32;
            return vk::Result::SUCCESS;
        }
        let written = (*count as usize).min(items.len());
        core::ptr::copy_nonoverlapping(items.as_ptr(), output, written);
        *count = written as u32;
        written
    };
    if written < items.len() {
        vk::Result::INCOMPLETE
    } else {
        vk::Result::SUCCESS
    }
}

unsafe extern "system" fn enumerate_layers(
    count: *mut u32,
    _properties: *mut vk::LayerProperties,
) -> vk::Result {
    // SAFETY: a driver does not provide loader layers; count is writable.
    unsafe { *count = 0 };
    vk::Result::SUCCESS
}

unsafe extern "system" fn create_instance<F: Factory>(
    info: *const vk::InstanceCreateInfo<'_>,
    allocator: *const vk::AllocationCallbacks<'_>,
    output: *mut vk::Instance,
) -> vk::Result {
    // SAFETY: Vulkan requires writable output storage and valid callbacks.
    unsafe { *output = vk::Instance::null() };
    let connection = match open::<F>() {
        Ok(connection) => connection,
        Err(error) => {
            tracing::error!(error = %error, "Venus instance connection failed");
            return vk::Result::ERROR_INITIALIZATION_FAILED;
        }
    };
    // SAFETY: forwarded unchanged from the Vulkan entry point.
    unsafe { create_on_connection::<F>(connection, info, allocator, output) }
}

pub(super) unsafe fn create_on_connection<F: Factory>(
    connection: Connection<F::Transport>,
    info: *const vk::InstanceCreateInfo<'_>,
    allocator: *const vk::AllocationCallbacks<'_>,
    output: *mut vk::Instance,
) -> vk::Result {
    // SAFETY: both callers supply writable output and Vulkan-valid inputs.
    unsafe { *output = vk::Instance::null() };
    // Instance extensions are implemented in the guest. virglrenderer requires
    // an empty extension list and enables its own host-side extensions.
    let mut renderer_info = unsafe { *info };
    if renderer_info.enabled_layer_count != 0 {
        return vk::Result::ERROR_LAYER_NOT_PRESENT;
    }
    for index in 0..renderer_info.enabled_extension_count as usize {
        // SAFETY: Vulkan requires enabled_extension_count live C-string pointers.
        let name = unsafe { CStr::from_ptr(*renderer_info.pp_enabled_extension_names.add(index)) };
        if !supported_extensions()
            .iter()
            .any(|(supported, _)| *supported == name)
        {
            return vk::Result::ERROR_EXTENSION_NOT_PRESENT;
        }
    }
    renderer_info.enabled_extension_count = 0;
    renderer_info.pp_enabled_extension_names = null();
    let allocator = unsafe { HostAllocator::new(allocator, vk::SystemAllocationScope::INSTANCE) };
    let owner = Arc::new(Exclusive::new(State::<F> {
        connection,
        physical: None,
        allocator,
        fault: None,
        devices: BTreeMap::new(),
        // Virtio's CPU timeline occupies ring zero.
        timelines: 1,
        external: BTreeMap::new(),
    }));
    let mut state = owner.lock();
    let id = match state.connection.object_id() {
        Ok(id) => id,
        Err(error) => return state.fail(error),
    };
    let mut instance = match Box::try_new_in(
        Instance::<F> {
            dispatch: Dispatch {
                base: ObjectBase { id },
                shared: Arc::downgrade(&owner),
            },
            owner: owner.clone(),
            allocator,
        },
        allocator,
    ) {
        Ok(instance) => instance,
        Err(_) => return vk::Result::ERROR_OUT_OF_HOST_MEMORY,
    };
    let mut handle = wire::VkInstance(&mut instance.dispatch.base);
    // SAFETY: create-info and output satisfy Vulkan's contract; allocator
    // callbacks stay in the guest, while the renderer uses its own allocator.
    let result = unsafe {
        wire::vn_call_vkCreateInstance(
            &mut state.connection,
            (&raw const renderer_info).cast(),
            null(),
            &mut handle,
        )
    };
    match result {
        Ok(result) if result == wire::VK_SUCCESS => {
            let (pointer, _) = Box::into_raw_with_allocator(instance);
            // SAFETY: ownership transfers to vkDestroyInstance; repr(C)
            // puts the dispatch header at the instance allocation's address.
            unsafe { *output = vk::Instance::from_raw(pointer as usize as u64) };
            vk::Result::SUCCESS
        }
        Ok(result) => state.finish(Ok(vk::Result::from_raw(result.0))),
        Err(error) => state.fail(error),
    }
}

unsafe extern "system" fn destroy_instance<F: Factory>(
    instance: vk::Instance,
    _allocator: *const vk::AllocationCallbacks<'_>,
) {
    if instance == vk::Instance::null() {
        return;
    }
    let pointer = instance.as_raw() as usize as *mut Instance<F>;
    // SAFETY: the instance was allocated by create_instance and Vulkan
    // requires every device and concurrent instance call to have finished.
    let instance = unsafe { Box::from_raw_in(pointer, (*pointer).allocator) };
    let mut state = instance.owner.lock();
    let handle = wire::VkInstance((&raw const instance.dispatch.base).cast_mut());
    // SAFETY: the remote instance is live and all device children are gone.
    let result = unsafe { wire::vn_call_vkDestroyInstance(&mut state.connection, handle, null()) }
        .and_then(|()| state.connection.flush());
    if let Err(error) = result {
        let _ = state.fail(error);
    }
    // Dropping the owner ends its context and mappings after the dispatch
    // guard is released. Physical devices are owned by the state itself.
}

unsafe extern "system" fn enumerate_physical_devices<F: Factory>(
    instance: vk::Instance,
    count: *mut u32,
    output: *mut vk::PhysicalDevice,
) -> vk::Result {
    // SAFETY: Vulkan requires a live instance of this entry table.
    let instance = unsafe { &*(instance.as_raw() as usize as *const Instance<F>) };
    let mut state = instance.owner.lock();
    if state.fault.is_some() {
        return vk::Result::ERROR_DEVICE_LOST;
    }
    if state.physical.is_none() {
        let mut total = 0;
        let handle = wire::VkInstance((&raw const instance.dispatch.base).cast_mut());
        // SAFETY: this is the count-only query on a live instance.
        let result = unsafe {
            wire::vn_call_vkEnumeratePhysicalDevices(
                &mut state.connection,
                handle,
                &mut total,
                null_mut(),
            )
        };
        match result {
            Ok(result) if result == wire::VK_SUCCESS => {}
            Ok(result) => return state.finish(Ok(vk::Result::from_raw(result.0))),
            Err(error) => return state.fail(error),
        }
        let mut objects = Vec::with_capacity(total as usize);
        for _ in 0..total {
            let id = match state.connection.object_id() {
                Ok(id) => id,
                Err(error) => return state.fail(error),
            };
            let object = Dispatch {
                base: ObjectBase { id },
                shared: Arc::downgrade(&instance.owner),
            };
            match Box::try_new_in(object, state.allocator) {
                Ok(object) => objects.push(object),
                Err(_) => return vk::Result::ERROR_OUT_OF_HOST_MEMORY,
            }
        }
        let mut handles: Vec<_> = objects
            .iter_mut()
            .map(|object| wire::VkPhysicalDevice(&mut object.base))
            .collect();
        if total != 0 {
            // SAFETY: all output handles have stable preallocated storage.
            let result = unsafe {
                wire::vn_call_vkEnumeratePhysicalDevices(
                    &mut state.connection,
                    handle,
                    &mut total,
                    handles.as_mut_ptr(),
                )
            };
            match result {
                Ok(result) if result == wire::VK_SUCCESS => {}
                Ok(result) => return state.finish(Ok(vk::Result::from_raw(result.0))),
                Err(error) => return state.fail(error),
            }
        }
        objects.truncate(total as usize);
        state.physical = Some(objects);
    }
    let objects = state.physical.as_ref().unwrap();
    if output.is_null() {
        // SAFETY: count-only enumeration supplies a writable count.
        unsafe { *count = objects.len() as u32 };
        return vk::Result::SUCCESS;
    }
    // SAFETY: count specifies writable output capacity.
    let written = unsafe { (*count as usize).min(objects.len()) };
    for (index, object) in objects.iter().take(written).enumerate() {
        let handle = vk::PhysicalDevice::from_raw((&raw const **object) as usize as u64);
        // SAFETY: index is below the caller's output capacity.
        unsafe { output.add(index).write(handle) };
    }
    unsafe { *count = written as u32 };
    if written < objects.len() {
        vk::Result::INCOMPLETE
    } else {
        vk::Result::SUCCESS
    }
}

pub(super) unsafe extern "system" fn get_instance_proc_addr<F: Factory>(
    instance: vk::Instance,
    name: *const c_char,
) -> vk::PFN_vkVoidFunction {
    // SAFETY: Vulkan requires a NUL-terminated function name. Erasing the
    // pointer is prescribed by Vulkan; ash restores the named signature.
    let name = unsafe { CStr::from_ptr(name) }.to_bytes();
    let pointer = match name {
        b"vkGetInstanceProcAddr" => get_instance_proc_addr::<F> as *const (),
        b"vkCreateInstance" => create_instance::<F> as *const (),
        b"vkEnumerateInstanceVersion" => enumerate_version::<F> as *const (),
        b"vkEnumerateInstanceExtensionProperties" => enumerate_extensions as *const (),
        b"vkEnumerateInstanceLayerProperties" => enumerate_layers as *const (),
        _ if instance == vk::Instance::null() => return None,
        b"vkDestroyInstance" => destroy_instance::<F> as *const (),
        b"vkEnumeratePhysicalDevices" => enumerate_physical_devices::<F> as *const (),
        b"vkCreateDevice" => super::device::create_device::<F> as *const (),
        _ => {
            return super::external::instance_lookup::<F>(name)
                .or_else(|| super::device::lookup::<F>(name))
                .or_else(|| super::generated::lookup::<F>(name, false));
        }
    };
    Some(unsafe { core::mem::transmute::<*const (), unsafe extern "system" fn()>(pointer) })
}
