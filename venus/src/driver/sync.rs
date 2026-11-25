use core::ptr::null;
use std::collections::BTreeMap;

use ash::vk::{self, Handle};

use super::Factory;
use super::allocator::HostAllocator;
use super::chain::next;
use super::device::Queue;
use super::instance::{State, invoke_result, object, shared, wait_for_points};
use crate::connection::{Connection, Error};
use crate::protocol as wire;
use crate::transport::{SignalPoint, SignalTimeline, Timeline, TimelinePoint, Transport};

struct SignalState<S: SignalTimeline> {
    source: S,
    reader: S::Timeline,
}

impl<S: SignalTimeline> SignalState<S> {
    fn new(source: S) -> Self {
        let reader = source.reader();
        Self { source, reader }
    }

    fn point(&self, value: u64) -> TimelinePoint<S::Timeline> {
        TimelinePoint {
            timeline: self.reader.clone(),
            value,
        }
    }
}

pub(super) struct Fence<T: Transport> {
    signal: SignalState<T::Signal>,
    generation: u64,
}

impl<T: Transport> Fence<T> {
    pub(super) fn fail(&self) {
        self.signal.source.fail();
    }
}

pub(super) struct Semaphore<T: Transport> {
    // Binary semaphores are renderer-owned and have no host wait capability.
    signal: Option<SignalState<T::Signal>>,
}

impl<T: Transport> Semaphore<T> {
    pub(super) fn fail(&self) {
        if let Some(signal) = &self.signal {
            signal.source.fail();
        }
    }

    /// Return the timeline signal state for a timeline semaphore.
    ///
    /// # Safety
    /// `self` must be a timeline semaphore (`self.signal.is_some()`).
    unsafe fn timeline(&self) -> &SignalState<T::Signal> {
        // SAFETY: Vulkan permits host semaphore operations only on timeline semaphores.
        unsafe { self.signal.as_ref().unwrap_unchecked() }
    }
}

/// View `count` Vulkan array elements from `pointer` as a shared slice.
///
/// # Safety
/// If `count > 0`, `pointer` must be valid, aligned, and point to `count`
/// live, initialized elements of `T` for `'a`.
unsafe fn slice<'a, T>(pointer: *const T, count: u32) -> &'a [T] {
    if count == 0 {
        &[]
    } else {
        // SAFETY: Vulkan supplies count live elements; zero counts may use null.
        unsafe { core::slice::from_raw_parts(pointer, count as usize) }
    }
}

unsafe extern "system" fn create_fence<F: Factory>(
    device: vk::Device,
    info: *const vk::FenceCreateInfo<'_>,
    allocator: *const vk::AllocationCallbacks<'_>,
    output: *mut vk::Fence,
) -> vk::Result {
    // SAFETY: Vulkan supplies a writable output slot.
    unsafe { *output = vk::Fence::null() };
    // SAFETY: the live device's dispatch header is immutable after creation.
    let device_id = unsafe { (*object(device)).id };
    // SAFETY: Vulkan supplies valid allocation callbacks or null for default allocation.
    let allocator = unsafe { HostAllocator::new(allocator, vk::SystemAllocationScope::OBJECT) };
    // SAFETY: Vulkan supplies a live `FenceCreateInfo` for this call.
    let create_info = unsafe { &*info };
    let initial = u64::from(create_info.flags.contains(vk::FenceCreateFlags::SIGNALED));
    let call = |state: &mut State<F>| {
        let fence = Fence::<F::Transport> {
            signal: SignalState::new(state.connection.timeline(initial)),
            generation: 1,
        };
        let Ok(fence) = Box::try_new_in(fence, allocator) else {
            return Ok(wire::VK_ERROR_OUT_OF_HOST_MEMORY);
        };
        let mut handle = wire::VkFence(state.connection.object_id()?);
        // SAFETY: `device`, `info`, and `handle` satisfy Vulkan's fence create contract.
        let result = unsafe {
            wire::vn_call_vkCreateFence(
                &mut state.connection,
                wire::VkDevice(object(device)),
                info.cast(),
                null(),
                &mut handle,
            )
        }?;
        if result == wire::VK_SUCCESS {
            state
                .devices
                .get_mut(&device_id)
                .unwrap()
                .fences
                .insert(handle.0, fence);
            // SAFETY: `output` is writable and transfers the registered fence handle.
            unsafe { *output = vk::Fence::from_raw(handle.0) };
        }
        Ok(result)
    };
    // SAFETY: `device` is a live device handle of `F`.
    let result = unsafe { invoke_result::<F>(object(device), call) };
    vk::Result::from_raw(result.0)
}

unsafe extern "system" fn destroy_fence<F: Factory>(
    device: vk::Device,
    fence: vk::Fence,
    _allocator: *const vk::AllocationCallbacks<'_>,
) {
    if fence == vk::Fence::null() {
        return;
    }
    // SAFETY: Vulkan supplies a live device handle of `F`.
    let owner = unsafe { shared::<F>(object(device)) };
    let mut state = owner.lock();
    // SAFETY: the live device's dispatch header is immutable after creation.
    let device_id = unsafe { (*object(device)).id };
    state
        .devices
        .get_mut(&device_id)
        .unwrap()
        .fences
        .remove(&fence.as_raw())
        .expect("fence belongs to this device");
    if state.fault.is_none() {
        // SAFETY: the caller owns this fence and no operation still uses it.
        let result = unsafe {
            wire::vn_call_vkDestroyFence(
                &mut state.connection,
                wire::VkDevice(object(device)),
                wire::VkFence(fence.as_raw()),
                null(),
            )
        };
        if let Err(error) = result {
            let _ = state.fail(error);
        }
    }
}

unsafe extern "system" fn reset_fences<F: Factory>(
    device: vk::Device,
    count: u32,
    fences: *const vk::Fence,
) -> vk::Result {
    // SAFETY: the live device's dispatch header is immutable after creation.
    let device_id = unsafe { (*object(device)).id };
    let call = |state: &mut State<F>| {
        // SAFETY: `fences` holds `count` live fence handles belonging to `device`.
        let result = unsafe {
            wire::vn_call_vkResetFences(
                &mut state.connection,
                wire::VkDevice(object(device)),
                count,
                fences.cast(),
            )
        }?;
        if result == wire::VK_SUCCESS {
            // SAFETY: `fences` holds `count` live fence handles for this call.
            let handles = unsafe { slice(fences, count) };
            for handle in handles {
                let fence = state
                    .devices
                    .get_mut(&device_id)
                    .unwrap()
                    .fences
                    .get_mut(&handle.as_raw())
                    .unwrap();
                fence.generation = fence
                    .generation
                    .checked_add(1)
                    .ok_or(Error::FenceGenerations)?;
            }
        }
        Ok(result)
    };
    // SAFETY: Vulkan supplies a live device and externally synchronized fences.
    let result = unsafe { invoke_result::<F>(object(device), call) };
    vk::Result::from_raw(result.0)
}

unsafe extern "system" fn fence_status<F: Factory>(
    device: vk::Device,
    fence: vk::Fence,
) -> vk::Result {
    // SAFETY: the live device's dispatch header is immutable after creation.
    let device_id = unsafe { (*object(device)).id };
    // SAFETY: `device` is a live device handle of `F` and `fence` is live on `device`.
    let result = unsafe {
        invoke_result::<F>(object(device), |state| {
            let fence = &state.devices[&device_id].fences[&fence.as_raw()];
            let value = fence.signal.reader.value().map_err(Error::Transport)?;
            Ok(if value >= fence.generation {
                wire::VK_SUCCESS
            } else {
                wire::VK_NOT_READY
            })
        })
    };
    vk::Result::from_raw(result.0)
}

unsafe extern "system" fn wait_fences<F: Factory>(
    device: vk::Device,
    count: u32,
    fences: *const vk::Fence,
    wait_all: vk::Bool32,
    timeout: u64,
) -> vk::Result {
    // SAFETY: the live device's dispatch header is immutable after creation.
    let device_id = unsafe { (*object(device)).id };
    let call = |state: &mut State<F>| {
        // SAFETY: `fences` holds `count` live fence handles for this call.
        let handles = unsafe { slice(fences, count) };
        Ok(handles
            .iter()
            .map(|handle| {
                let fence = &state.devices[&device_id].fences[&handle.as_raw()];
                fence.signal.point(fence.generation)
            })
            .collect())
    };
    // SAFETY: `device` is a live device handle of `F` and all fences remain live.
    unsafe { wait_for_points::<F>(object(device), wait_all != 0, timeout, call) }
}

unsafe extern "system" fn create_semaphore<F: Factory>(
    device: vk::Device,
    info: *const vk::SemaphoreCreateInfo<'_>,
    allocator: *const vk::AllocationCallbacks<'_>,
    output: *mut vk::Semaphore,
) -> vk::Result {
    // SAFETY: Vulkan supplies a writable output slot.
    unsafe { *output = vk::Semaphore::null() };
    // SAFETY: the live device's dispatch header is immutable after creation.
    let device_id = unsafe { (*object(device)).id };
    // SAFETY: Vulkan supplies valid allocation callbacks or null for default allocation.
    let allocator = unsafe { HostAllocator::new(allocator, vk::SystemAllocationScope::OBJECT) };
    // SAFETY: Vulkan supplies a live `SemaphoreCreateInfo` for this call.
    let create_info = unsafe { &*info };
    // SAFETY: `create_info.p_next` is null or a live `pNext` chain for this call.
    let timeline_initial = unsafe { next::<vk::SemaphoreTypeCreateInfo<'_>>(create_info.p_next) }
        .filter(|info| info.semaphore_type == vk::SemaphoreType::TIMELINE)
        .map(|info| info.initial_value);
    let call = |state: &mut State<F>| {
        let signal =
            timeline_initial.map(|initial| SignalState::new(state.connection.timeline(initial)));
        let Ok(semaphore) = Box::try_new_in(Semaphore::<F::Transport> { signal }, allocator) else {
            return Ok(wire::VK_ERROR_OUT_OF_HOST_MEMORY);
        };
        let mut handle = wire::VkSemaphore(state.connection.object_id()?);
        // SAFETY: `device`, `info`, and `handle` satisfy Vulkan's semaphore create contract.
        let result = unsafe {
            wire::vn_call_vkCreateSemaphore(
                &mut state.connection,
                wire::VkDevice(object(device)),
                info.cast(),
                null(),
                &mut handle,
            )
        }?;
        if result == wire::VK_SUCCESS {
            state
                .devices
                .get_mut(&device_id)
                .unwrap()
                .semaphores
                .insert(handle.0, semaphore);
            // SAFETY: `output` is writable and transfers the registered semaphore handle.
            unsafe { *output = vk::Semaphore::from_raw(handle.0) };
        }
        Ok(result)
    };
    // SAFETY: `device` is a live device handle of `F`.
    let result = unsafe { invoke_result::<F>(object(device), call) };
    vk::Result::from_raw(result.0)
}

unsafe extern "system" fn destroy_semaphore<F: Factory>(
    device: vk::Device,
    semaphore: vk::Semaphore,
    _allocator: *const vk::AllocationCallbacks<'_>,
) {
    if semaphore == vk::Semaphore::null() {
        return;
    }
    // SAFETY: Vulkan supplies a live device handle of `F`.
    let owner = unsafe { shared::<F>(object(device)) };
    let mut state = owner.lock();
    // SAFETY: the live device's dispatch header is immutable after creation.
    let device_id = unsafe { (*object(device)).id };
    state
        .devices
        .get_mut(&device_id)
        .unwrap()
        .semaphores
        .remove(&semaphore.as_raw())
        .expect("semaphore belongs to this device");
    if state.fault.is_none() {
        // SAFETY: the caller owns this semaphore and no operation still uses it.
        let result = unsafe {
            wire::vn_call_vkDestroySemaphore(
                &mut state.connection,
                wire::VkDevice(object(device)),
                wire::VkSemaphore(semaphore.as_raw()),
                null(),
            )
        };
        if let Err(error) = result {
            let _ = state.fail(error);
        }
    }
}

unsafe extern "system" fn counter<F: Factory>(
    device: vk::Device,
    semaphore: vk::Semaphore,
    output: *mut u64,
) -> vk::Result {
    // SAFETY: the live device's dispatch header is immutable after creation.
    let device_id = unsafe { (*object(device)).id };
    let call = |state: &mut State<F>| {
        // SAFETY: Vulkan requires `semaphore` to be a timeline semaphore.
        let timeline =
            unsafe { state.devices[&device_id].semaphores[&semaphore.as_raw()].timeline() };
        let value = timeline.reader.value().map_err(Error::Transport)?;
        // SAFETY: Vulkan supplies a writable `u64` output pointer.
        unsafe { *output = value };
        Ok(wire::VK_SUCCESS)
    };
    // SAFETY: `device` is a live device handle of `F`.
    let result = unsafe { invoke_result::<F>(object(device), call) };
    vk::Result::from_raw(result.0)
}

unsafe extern "system" fn signal_semaphore<F: Factory>(
    device: vk::Device,
    info: *const vk::SemaphoreSignalInfo<'_>,
) -> vk::Result {
    // SAFETY: the live device's dispatch header is immutable after creation.
    let device_id = unsafe { (*object(device)).id };
    // SAFETY: Vulkan supplies a live `SemaphoreSignalInfo` for this call.
    let signal_info = unsafe { &*info };
    let call = |state: &mut State<F>| {
        // SAFETY: `device` and `info` satisfy Vulkan's `vkSignalSemaphore` contract.
        let result = unsafe {
            wire::vn_call_vkSignalSemaphore(
                &mut state.connection,
                wire::VkDevice(object(device)),
                info.cast(),
            )
        }?;
        if result == wire::VK_SUCCESS {
            // SAFETY: Vulkan requires `signal_info.semaphore` to be a timeline semaphore.
            let timeline = unsafe {
                state.devices[&device_id].semaphores[&signal_info.semaphore.as_raw()].timeline()
            };
            timeline
                .source
                .signal(signal_info.value)
                .map_err(Error::Transport)?;
        }
        Ok(result)
    };
    // SAFETY: `device` is a live device handle of `F`.
    let result = unsafe { invoke_result::<F>(object(device), call) };
    vk::Result::from_raw(result.0)
}

unsafe extern "system" fn wait_semaphores<F: Factory>(
    device: vk::Device,
    info: *const vk::SemaphoreWaitInfo<'_>,
    timeout: u64,
) -> vk::Result {
    // SAFETY: the live device's dispatch header is immutable after creation.
    let device_id = unsafe { (*object(device)).id };
    // SAFETY: Vulkan supplies a live `SemaphoreWaitInfo` for this call.
    let wait_info = unsafe { &*info };
    let call = |state: &mut State<F>| {
        // SAFETY: `p_semaphores` holds `semaphore_count` live semaphore handles.
        let handles = unsafe { slice(wait_info.p_semaphores, wait_info.semaphore_count) };
        // SAFETY: `p_values` holds `semaphore_count` live wait values.
        let values = unsafe { slice(wait_info.p_values, wait_info.semaphore_count) };
        Ok(handles
            .iter()
            .zip(values)
            .map(|(handle, value)| {
                // SAFETY: Vulkan requires every waited handle to be a timeline semaphore.
                let timeline =
                    unsafe { state.devices[&device_id].semaphores[&handle.as_raw()].timeline() };
                timeline.point(*value)
            })
            .collect())
    };
    // SAFETY: `device` is a live device handle of `F` and semaphores remain live.
    unsafe {
        wait_for_points::<F>(
            object(device),
            !wait_info.flags.contains(vk::SemaphoreWaitFlags::ANY),
            timeout,
            call,
        )
    }
}

fn fence_signal<T: Transport>(
    fences: &BTreeMap<u64, Box<Fence<T>, HostAllocator>>,
    fence: vk::Fence,
    signals: &mut Vec<(T::Signal, u64)>,
) {
    if fence != vk::Fence::null() {
        let fence = &fences[&fence.as_raw()];
        signals.push((fence.signal.source.clone(), fence.generation));
    }
}

type SemaphoreMap<T> = BTreeMap<u64, Box<Semaphore<T>, HostAllocator>>;
type Signals<T> = Vec<(<T as Transport>::Signal, u64)>;

trait SubmitBatch: Sized {
    /// Collect all timeline semaphore signal points produced by this batch.
    ///
    /// # Safety
    /// All semaphore pointers, counts, and chained timeline value structures in
    /// `self` must satisfy Vulkan's submission contract, and every referenced
    /// semaphore must be present in `semaphores`.
    unsafe fn signals<T: Transport>(&self, semaphores: &SemaphoreMap<T>, signals: &mut Signals<T>);

    /// Encode and submit this batch (or an empty fence-only batch) over `connection`.
    ///
    /// # Safety
    /// `queue`, `submit`, and `fence` must be valid Vulkan objects and live
    /// submission structures for the duration of the wire call.
    unsafe fn call<T: Transport>(
        connection: &mut Connection<T>,
        queue: wire::VkQueue,
        submit: Option<&Self>,
        fence: wire::VkFence,
    ) -> Result<wire::VkResult, Error<T::Error>>;
}

impl SubmitBatch for vk::SubmitInfo<'_> {
    unsafe fn signals<T: Transport>(&self, semaphores: &SemaphoreMap<T>, signals: &mut Signals<T>) {
        // SAFETY: `self.p_next` is null or a live `pNext` chain for this submission.
        let values = unsafe { next::<vk::TimelineSemaphoreSubmitInfo<'_>>(self.p_next) };
        // SAFETY: `p_signal_semaphores` holds `signal_semaphore_count` live handles.
        let handles = unsafe { slice(self.p_signal_semaphores, self.signal_semaphore_count) };
        for (index, handle) in handles.iter().enumerate() {
            if let Some(signal) = &semaphores[&handle.as_raw()].signal {
                // SAFETY: Vulkan requires `VkTimelineSemaphoreSubmitInfo` when signaling
                // a timeline semaphore in `VkSubmitInfo`.
                let timeline_info = unsafe { values.unwrap_unchecked() };
                // SAFETY: Vulkan requires `signal_semaphore_value_count >= signal_semaphore_count`.
                let value_ptr = unsafe { timeline_info.p_signal_semaphore_values.add(index) };
                // SAFETY: `value_ptr` points to an initialized `u64` value for this semaphore.
                let value = unsafe { *value_ptr };
                signals.push((signal.source.clone(), value));
            }
        }
    }

    unsafe fn call<T: Transport>(
        connection: &mut Connection<T>,
        queue: wire::VkQueue,
        submit: Option<&Self>,
        fence: wire::VkFence,
    ) -> Result<wire::VkResult, Error<T::Error>> {
        // SAFETY: structures have the generated protocol's C layout and remain live for the call.
        unsafe {
            wire::vn_call_vkQueueSubmit(
                connection,
                queue,
                u32::from(submit.is_some()),
                submit.map_or(null(), |submit| core::ptr::from_ref(submit).cast()),
                fence,
            )
        }
    }
}

impl SubmitBatch for vk::SubmitInfo2<'_> {
    unsafe fn signals<T: Transport>(&self, semaphores: &SemaphoreMap<T>, signals: &mut Signals<T>) {
        // SAFETY: Vulkan supplies signal_semaphore_info_count live records.
        let infos = unsafe {
            slice(
                self.p_signal_semaphore_infos,
                self.signal_semaphore_info_count,
            )
        };
        for info in infos {
            if let Some(signal) = &semaphores[&info.semaphore.as_raw()].signal {
                signals.push((signal.source.clone(), info.value));
            }
        }
    }

    unsafe fn call<T: Transport>(
        connection: &mut Connection<T>,
        queue: wire::VkQueue,
        submit: Option<&Self>,
        fence: wire::VkFence,
    ) -> Result<wire::VkResult, Error<T::Error>> {
        // SAFETY: structures have the generated protocol's C layout and remain live for the call.
        unsafe {
            wire::vn_call_vkQueueSubmit2(
                connection,
                queue,
                u32::from(submit.is_some()),
                submit.map_or(null(), |submit| core::ptr::from_ref(submit).cast()),
                fence,
            )
        }
    }
}

/// Submit `count` batches on `queue` and attach transport timeline signals.
///
/// # Safety
/// `queue` must be a live queue belonging to `F`, `submits` must point to
/// `count` valid submission structures (unless `count == 0`), and `fence` must
/// be null or a live unsignaled fence on the same device.
unsafe fn submit_batches<F: Factory, S: SubmitBatch>(
    queue: vk::Queue,
    count: u32,
    submits: *const S,
    fence: vk::Fence,
) -> vk::Result {
    let (device_id, ring) = {
        // SAFETY: `queue` points to a live `Queue<F>` whose `device` and `ring` are immutable.
        let queue_state = unsafe { &*object(queue).cast::<Queue<F>>() };
        (queue_state.device, queue_state.ring)
    };
    let call = |state: &mut State<F>| {
        // SAFETY: Vulkan supplies `count` live submission structures.
        let submits = unsafe { slice(submits, count) };
        // Each batch gets a marker before the next is published: a later
        // batch may wait for future work which depends on this batch's signal.
        // A zero-count submission still signals its fence after prior queue work.
        for index in 0..submits.len().max(1) {
            let submit = submits.get(index);
            let last_fence = if index + 1 == submits.len().max(1) {
                fence
            } else {
                vk::Fence::null()
            };
            let device = &state.devices[&device_id];
            let mut signals = Vec::new();
            if let Some(submit) = submit {
                // SAFETY: `submit` and `device.semaphores` satisfy `SubmitBatch::signals`.
                unsafe { submit.signals(&device.semaphores, &mut signals) };
            }
            fence_signal(&device.fences, last_fence, &mut signals);
            // SAFETY: `queue`, `submit`, and `last_fence` are live for this wire call.
            let result = unsafe {
                S::call(
                    &mut state.connection,
                    wire::VkQueue(object(queue)),
                    submit,
                    wire::VkFence(last_fence.as_raw()),
                )
            }?;
            if result != wire::VK_SUCCESS {
                return Ok(result);
            }
            if !signals.is_empty() {
                let points: Vec<_> = signals
                    .iter()
                    .map(|(source, value)| SignalPoint {
                        source,
                        value: *value,
                    })
                    .collect();
                state.connection.signal_queue(ring, &points)?;
            }
        }
        Ok(wire::VK_SUCCESS)
    };
    // SAFETY: `queue` is a live queue handle of `F`.
    let result = unsafe { invoke_result::<F>(object(queue), call) };
    vk::Result::from_raw(result.0)
}

unsafe extern "system" fn queue_submit<F: Factory>(
    queue: vk::Queue,
    count: u32,
    submits: *const vk::SubmitInfo<'_>,
    fence: vk::Fence,
) -> vk::Result {
    // SAFETY: forwarded unchanged from Vulkan's entry point.
    unsafe { submit_batches::<F, _>(queue, count, submits, fence) }
}

unsafe extern "system" fn queue_submit2<F: Factory>(
    queue: vk::Queue,
    count: u32,
    submits: *const vk::SubmitInfo2<'_>,
    fence: vk::Fence,
) -> vk::Result {
    // SAFETY: forwarded unchanged from Vulkan's entry point.
    unsafe { submit_batches::<F, _>(queue, count, submits, fence) }
}

pub(super) fn lookup<F: Factory>(name: &[u8]) -> vk::PFN_vkVoidFunction {
    let pointer = match name {
        b"vkCreateFence" => create_fence::<F> as *const (),
        b"vkDestroyFence" => destroy_fence::<F> as *const (),
        b"vkResetFences" => reset_fences::<F> as *const (),
        b"vkGetFenceStatus" => fence_status::<F> as *const (),
        b"vkWaitForFences" => wait_fences::<F> as *const (),
        b"vkCreateSemaphore" => create_semaphore::<F> as *const (),
        b"vkDestroySemaphore" => destroy_semaphore::<F> as *const (),
        b"vkGetSemaphoreCounterValue" | b"vkGetSemaphoreCounterValueKHR" => {
            counter::<F> as *const ()
        }
        b"vkSignalSemaphore" | b"vkSignalSemaphoreKHR" => signal_semaphore::<F> as *const (),
        b"vkWaitSemaphores" | b"vkWaitSemaphoresKHR" => wait_semaphores::<F> as *const (),
        b"vkQueueSubmit" => queue_submit::<F> as *const (),
        b"vkQueueSubmit2" | b"vkQueueSubmit2KHR" => queue_submit2::<F> as *const (),
        _ => return None,
    };
    // SAFETY: Vulkan's caller resolves this pointer using the named command's signature.
    Some(unsafe { core::mem::transmute::<*const (), unsafe extern "system" fn()>(pointer) })
}
