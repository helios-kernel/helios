use core::ptr::null;
use std::collections::BTreeMap;

use ash::vk::{self, Handle};

use super::Factory;
use super::allocator::HostAllocator;
use super::chain::next;
use super::device::Queue;
use super::instance::{invoke_result, object, shared, wait_for_points};
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

    unsafe fn timeline(&self) -> &SignalState<T::Signal> {
        // SAFETY: Vulkan permits host semaphore operations only on timeline semaphores.
        unsafe { self.signal.as_ref().unwrap_unchecked() }
    }
}

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
    // SAFETY: all input pointers and the output slot follow Vulkan's create contract.
    unsafe {
        *output = vk::Fence::null();
        let device_id = (*object(device)).id;
        let allocator = HostAllocator::new(allocator, vk::SystemAllocationScope::OBJECT);
        let result = invoke_result::<F>(object(device), |state| {
            let initial = u64::from((*info).flags.contains(vk::FenceCreateFlags::SIGNALED));
            let fence = Fence::<F::Transport> {
                signal: SignalState::new(state.connection.timeline(initial)),
                generation: 1,
            };
            let Ok(fence) = Box::try_new_in(fence, allocator) else {
                return Ok(wire::VK_ERROR_OUT_OF_HOST_MEMORY);
            };
            let mut handle = wire::VkFence(state.connection.object_id()?);
            let result = wire::vn_call_vkCreateFence(
                &mut state.connection,
                wire::VkDevice(object(device)),
                info.cast(),
                null(),
                &mut handle,
            )?;
            if result == wire::VK_SUCCESS {
                state
                    .devices
                    .get_mut(&device_id)
                    .unwrap()
                    .fences
                    .insert(handle.0, fence);
                *output = vk::Fence::from_raw(handle.0);
            }
            Ok(result)
        });
        vk::Result::from_raw(result.0)
    }
}

unsafe extern "system" fn destroy_fence<F: Factory>(
    device: vk::Device,
    fence: vk::Fence,
    _allocator: *const vk::AllocationCallbacks<'_>,
) {
    if fence == vk::Fence::null() {
        return;
    }
    // SAFETY: the caller owns this fence and no operation still uses it.
    unsafe {
        let owner = shared::<F>(object(device));
        let mut state = owner.lock();
        let device_id = (*object(device)).id;
        state
            .devices
            .get_mut(&device_id)
            .unwrap()
            .fences
            .remove(&fence.as_raw())
            .expect("fence belongs to this device");
        if state.fault.is_none()
            && let Err(error) = wire::vn_call_vkDestroyFence(
                &mut state.connection,
                wire::VkDevice(object(device)),
                wire::VkFence(fence.as_raw()),
                null(),
            )
        {
            let _ = state.fail(error);
        }
    }
}

unsafe extern "system" fn reset_fences<F: Factory>(
    device: vk::Device,
    count: u32,
    fences: *const vk::Fence,
) -> vk::Result {
    // SAFETY: Vulkan supplies live, externally synchronized fences belonging to device.
    unsafe {
        let device_id = (*object(device)).id;
        let result = invoke_result::<F>(object(device), |state| {
            let result = wire::vn_call_vkResetFences(
                &mut state.connection,
                wire::VkDevice(object(device)),
                count,
                fences.cast(),
            )?;
            if result == wire::VK_SUCCESS {
                for handle in slice(fences, count) {
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
        });
        vk::Result::from_raw(result.0)
    }
}

unsafe extern "system" fn fence_status<F: Factory>(
    device: vk::Device,
    fence: vk::Fence,
) -> vk::Result {
    // SAFETY: fence is a live object of device.
    unsafe {
        let device_id = (*object(device)).id;
        let result = invoke_result::<F>(object(device), |state| {
            let fence = &state.devices[&device_id].fences[&fence.as_raw()];
            let value = fence.signal.reader.value().map_err(Error::Transport)?;
            Ok(if value >= fence.generation {
                wire::VK_SUCCESS
            } else {
                wire::VK_NOT_READY
            })
        });
        vk::Result::from_raw(result.0)
    }
}

unsafe extern "system" fn wait_fences<F: Factory>(
    device: vk::Device,
    count: u32,
    fences: *const vk::Fence,
    wait_all: vk::Bool32,
    timeout: u64,
) -> vk::Result {
    // SAFETY: all fences remain live throughout this wait.
    unsafe {
        let device_id = (*object(device)).id;
        wait_for_points::<F>(object(device), wait_all != 0, timeout, |state| {
            Ok(slice(fences, count)
                .iter()
                .map(|handle| {
                    let fence = &state.devices[&device_id].fences[&handle.as_raw()];
                    fence.signal.point(fence.generation)
                })
                .collect())
        })
    }
}

unsafe extern "system" fn create_semaphore<F: Factory>(
    device: vk::Device,
    info: *const vk::SemaphoreCreateInfo<'_>,
    allocator: *const vk::AllocationCallbacks<'_>,
    output: *mut vk::Semaphore,
) -> vk::Result {
    // SAFETY: all input pointers and the output slot follow Vulkan's create contract.
    unsafe {
        *output = vk::Semaphore::null();
        let device_id = (*object(device)).id;
        let allocator = HostAllocator::new(allocator, vk::SystemAllocationScope::OBJECT);
        let result = invoke_result::<F>(object(device), |state| {
            let signal = next::<vk::SemaphoreTypeCreateInfo<'_>>((*info).p_next)
                .filter(|info| info.semaphore_type == vk::SemaphoreType::TIMELINE)
                .map(|info| SignalState::new(state.connection.timeline(info.initial_value)));
            let Ok(semaphore) = Box::try_new_in(Semaphore::<F::Transport> { signal }, allocator)
            else {
                return Ok(wire::VK_ERROR_OUT_OF_HOST_MEMORY);
            };
            let mut handle = wire::VkSemaphore(state.connection.object_id()?);
            let result = wire::vn_call_vkCreateSemaphore(
                &mut state.connection,
                wire::VkDevice(object(device)),
                info.cast(),
                null(),
                &mut handle,
            )?;
            if result == wire::VK_SUCCESS {
                state
                    .devices
                    .get_mut(&device_id)
                    .unwrap()
                    .semaphores
                    .insert(handle.0, semaphore);
                *output = vk::Semaphore::from_raw(handle.0);
            }
            Ok(result)
        });
        vk::Result::from_raw(result.0)
    }
}

unsafe extern "system" fn destroy_semaphore<F: Factory>(
    device: vk::Device,
    semaphore: vk::Semaphore,
    _allocator: *const vk::AllocationCallbacks<'_>,
) {
    if semaphore == vk::Semaphore::null() {
        return;
    }
    // SAFETY: the caller owns this semaphore and no operation still uses it.
    unsafe {
        let owner = shared::<F>(object(device));
        let mut state = owner.lock();
        let device_id = (*object(device)).id;
        state
            .devices
            .get_mut(&device_id)
            .unwrap()
            .semaphores
            .remove(&semaphore.as_raw())
            .expect("semaphore belongs to this device");
        if state.fault.is_none()
            && let Err(error) = wire::vn_call_vkDestroySemaphore(
                &mut state.connection,
                wire::VkDevice(object(device)),
                wire::VkSemaphore(semaphore.as_raw()),
                null(),
            )
        {
            let _ = state.fail(error);
        }
    }
}

unsafe extern "system" fn counter<F: Factory>(
    device: vk::Device,
    semaphore: vk::Semaphore,
    output: *mut u64,
) -> vk::Result {
    // SAFETY: Vulkan requires a timeline semaphore and a writable output value.
    unsafe {
        let device_id = (*object(device)).id;
        let result = invoke_result::<F>(object(device), |state| {
            *output = state.devices[&device_id].semaphores[&semaphore.as_raw()]
                .timeline()
                .reader
                .value()
                .map_err(Error::Transport)?;
            Ok(wire::VK_SUCCESS)
        });
        vk::Result::from_raw(result.0)
    }
}

unsafe extern "system" fn signal_semaphore<F: Factory>(
    device: vk::Device,
    info: *const vk::SemaphoreSignalInfo<'_>,
) -> vk::Result {
    // SAFETY: the caller supplies a timeline semaphore and a valid advancing value.
    unsafe {
        let device_id = (*object(device)).id;
        let result = invoke_result::<F>(object(device), |state| {
            let result = wire::vn_call_vkSignalSemaphore(
                &mut state.connection,
                wire::VkDevice(object(device)),
                info.cast(),
            )?;
            if result == wire::VK_SUCCESS {
                state.devices[&device_id].semaphores[&(*info).semaphore.as_raw()]
                    .timeline()
                    .source
                    .signal((*info).value)
                    .map_err(Error::Transport)?;
            }
            Ok(result)
        });
        vk::Result::from_raw(result.0)
    }
}

unsafe extern "system" fn wait_semaphores<F: Factory>(
    device: vk::Device,
    info: *const vk::SemaphoreWaitInfo<'_>,
    timeout: u64,
) -> vk::Result {
    // SAFETY: semaphore and value arrays are live, equally sized, and contain timeline semaphores.
    unsafe {
        let device_id = (*object(device)).id;
        let info = &*info;
        wait_for_points::<F>(
            object(device),
            !info.flags.contains(vk::SemaphoreWaitFlags::ANY),
            timeout,
            |state| {
                Ok(slice(info.p_semaphores, info.semaphore_count)
                    .iter()
                    .zip(slice(info.p_values, info.semaphore_count))
                    .map(|(handle, value)| {
                        state.devices[&device_id].semaphores[&handle.as_raw()]
                            .timeline()
                            .point(*value)
                    })
                    .collect())
            },
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
    unsafe fn signals<T: Transport>(&self, semaphores: &SemaphoreMap<T>, signals: &mut Signals<T>);
    unsafe fn call<T: Transport>(
        connection: &mut Connection<T>,
        queue: wire::VkQueue,
        submit: Option<&Self>,
        fence: wire::VkFence,
    ) -> Result<wire::VkResult, Error<T::Error>>;
}

impl SubmitBatch for vk::SubmitInfo<'_> {
    unsafe fn signals<T: Transport>(&self, semaphores: &SemaphoreMap<T>, signals: &mut Signals<T>) {
        // SAFETY: Vulkan validates the arrays and timeline-value chain together.
        unsafe {
            let values = next::<vk::TimelineSemaphoreSubmitInfo<'_>>(self.p_next);
            for (index, handle) in slice(self.p_signal_semaphores, self.signal_semaphore_count)
                .iter()
                .enumerate()
            {
                if let Some(signal) = &semaphores[&handle.as_raw()].signal {
                    signals.push((
                        signal.source.clone(),
                        *values
                            .unwrap_unchecked()
                            .p_signal_semaphore_values
                            .add(index),
                    ));
                }
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
        for info in unsafe {
            slice(
                self.p_signal_semaphore_infos,
                self.signal_semaphore_info_count,
            )
        } {
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

unsafe fn submit_batches<F: Factory, S: SubmitBatch>(
    queue: vk::Queue,
    count: u32,
    submits: *const S,
    fence: vk::Fence,
) -> vk::Result {
    // SAFETY: the queue is externally synchronized and submission structures satisfy Vulkan.
    unsafe {
        let queue_state = &*object(queue).cast::<Queue<F>>();
        let result = invoke_result::<F>(object(queue), |state| {
            let submits = slice(submits, count);
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
                let device = &state.devices[&queue_state.device];
                let mut signals = Vec::new();
                if let Some(submit) = submit {
                    submit.signals(&device.semaphores, &mut signals);
                }
                fence_signal(&device.fences, last_fence, &mut signals);
                let result = S::call(
                    &mut state.connection,
                    wire::VkQueue(object(queue)),
                    submit,
                    wire::VkFence(last_fence.as_raw()),
                )?;
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
                    state.connection.signal_queue(queue_state.ring, &points)?;
                }
            }
            Ok(wire::VK_SUCCESS)
        });
        vk::Result::from_raw(result.0)
    }
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
