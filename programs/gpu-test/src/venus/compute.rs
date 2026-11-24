use super::{Error, host_memory_type, vk};

struct Resources<'a> {
    device: &'a ash::Device,
    buffer: vk::Buffer,
    memory: vk::DeviceMemory,
    mapped: bool,
    set_layout: vk::DescriptorSetLayout,
    layout: vk::PipelineLayout,
    shader: vk::ShaderModule,
    pipeline: vk::Pipeline,
    pool: vk::DescriptorPool,
    commands: vk::CommandPool,
    fence: vk::Fence,
    semaphore: vk::Semaphore,
    queue: vk::Queue,
    pending: bool,
}

impl Drop for Resources<'_> {
    fn drop(&mut self) {
        if self.pending {
            // An expired smoke-test deadline does not cancel GPU work.
            // SAFETY: `self.device` and `self.queue` are live, and waiting on
            // `self.queue` retires all pending submissions before teardown.
            let _ = unsafe { self.device.queue_wait_idle(self.queue) };
        }
        // SAFETY: `self.fence` is null or owned by `self` and idle after `queue_wait_idle`.
        unsafe { self.device.destroy_fence(self.fence, None) };
        // SAFETY: `self.semaphore` is null or owned by `self` and idle after `queue_wait_idle`.
        unsafe { self.device.destroy_semaphore(self.semaphore, None) };
        // SAFETY: `self.commands` is null or owned by `self` and idle after `queue_wait_idle`.
        unsafe { self.device.destroy_command_pool(self.commands, None) };
        // SAFETY: `self.pool` is null or owned by `self` and idle after `queue_wait_idle`.
        unsafe { self.device.destroy_descriptor_pool(self.pool, None) };
        // SAFETY: `self.pipeline` is null or owned by `self` and idle after `queue_wait_idle`.
        unsafe { self.device.destroy_pipeline(self.pipeline, None) };
        // SAFETY: `self.shader` is null or owned by `self` and no longer referenced.
        unsafe { self.device.destroy_shader_module(self.shader, None) };
        // SAFETY: `self.layout` is null or owned by `self` and no longer referenced.
        unsafe { self.device.destroy_pipeline_layout(self.layout, None) };
        // SAFETY: `self.set_layout` is null or owned by `self` and no longer referenced.
        unsafe {
            self.device
                .destroy_descriptor_set_layout(self.set_layout, None);
        }
        if self.mapped {
            // SAFETY: `self.memory` is currently mapped and no mapped pointers are used after this.
            unsafe { self.device.unmap_memory(self.memory) };
        }
        // SAFETY: `self.buffer` is null or owned by `self` and idle after `queue_wait_idle`.
        unsafe { self.device.destroy_buffer(self.buffer, None) };
        // SAFETY: `self.memory` is null or owned by `self` and unmapped above.
        unsafe { self.device.free_memory(self.memory, None) };
    }
}

pub(super) async fn run(
    instance: &ash::Instance,
    physical: vk::PhysicalDevice,
    device: &ash::Device,
    queue: vk::Queue,
    family: u32,
) -> Result<(), Error> {
    let mut resources = Resources {
        device,
        buffer: vk::Buffer::null(),
        memory: vk::DeviceMemory::null(),
        mapped: false,
        set_layout: vk::DescriptorSetLayout::null(),
        layout: vk::PipelineLayout::null(),
        shader: vk::ShaderModule::null(),
        pipeline: vk::Pipeline::null(),
        pool: vk::DescriptorPool::null(),
        commands: vk::CommandPool::null(),
        fence: vk::Fence::null(),
        semaphore: vk::Semaphore::null(),
        queue,
        pending: false,
    };
    // One page exercises multiple shader invocations and mapped cache lines.
    let bytes = super::super::PAGE_BYTES;
    let count = (bytes / size_of::<u32>() as u64) as u32;
    let buffer_info = vk::BufferCreateInfo::default()
        .size(bytes)
        .usage(vk::BufferUsageFlags::STORAGE_BUFFER)
        .sharing_mode(vk::SharingMode::EXCLUSIVE);
    // SAFETY: `device` is live and `buffer_info` is a valid create-info struct.
    resources.buffer = unsafe { device.create_buffer(&buffer_info, None) }?;
    // SAFETY: `resources.buffer` is a live buffer created on `device`.
    let requirements = unsafe { device.get_buffer_memory_requirements(resources.buffer) };
    // SAFETY: `physical` belongs to the live `instance`.
    let properties = unsafe { instance.get_physical_device_memory_properties(physical) };
    let memory_type = host_memory_type(&properties, requirements.memory_type_bits)?;
    let alloc_info = vk::MemoryAllocateInfo::default()
        .allocation_size(requirements.size)
        .memory_type_index(memory_type);
    // SAFETY: `device` is live and `alloc_info` uses a valid size and memory type.
    resources.memory = unsafe { device.allocate_memory(&alloc_info, None) }?;
    // SAFETY: `resources.buffer` and `resources.memory` are live, compatible, and unbound.
    unsafe { device.bind_buffer_memory(resources.buffer, resources.memory, 0) }?;
    // SAFETY: `resources.memory` is live, host-visible, `requirements.size` bytes
    // long, and not currently mapped.
    let pointer = unsafe {
        device.map_memory(
            resources.memory,
            0,
            requirements.size,
            vk::MemoryMapFlags::empty(),
        )
    }?
    .cast::<u32>();
    resources.mapped = true;
    for index in 0..count {
        // SAFETY: `requirements.size >= bytes = count * 4`, so `index < count`
        // stays within the mapped `u32` range of `resources.memory`.
        let slot = unsafe { pointer.add(index as usize) };
        // SAFETY: `slot` points to an aligned, mapped `u32` inside `resources.memory`.
        unsafe { slot.write_volatile(index) };
    }

    let bindings = [vk::DescriptorSetLayoutBinding::default()
        .binding(0)
        .descriptor_type(vk::DescriptorType::STORAGE_BUFFER)
        .descriptor_count(1)
        .stage_flags(vk::ShaderStageFlags::COMPUTE)];
    let set_layout_info = vk::DescriptorSetLayoutCreateInfo::default().bindings(&bindings);
    // SAFETY: `device` is live and `set_layout_info` borrows valid `bindings`.
    resources.set_layout = unsafe { device.create_descriptor_set_layout(&set_layout_info, None) }?;
    let layouts = [resources.set_layout];
    let pipeline_layout_info = vk::PipelineLayoutCreateInfo::default().set_layouts(&layouts);
    // SAFETY: `device` is live and `layouts` holds the live `set_layout`.
    resources.layout = unsafe { device.create_pipeline_layout(&pipeline_layout_info, None) }?;
    let code: Vec<u32> = include_bytes!(concat!(env!("OUT_DIR"), "/compute.spv"))
        .chunks_exact(size_of::<u32>())
        .map(|word| u32::from_le_bytes(word.try_into().unwrap()))
        .collect();
    let shader_info = vk::ShaderModuleCreateInfo::default().code(&code);
    // SAFETY: `device` is live and `code` holds valid aligned SPIR-V words.
    resources.shader = unsafe { device.create_shader_module(&shader_info, None) }?;
    let stage = vk::PipelineShaderStageCreateInfo::default()
        .stage(vk::ShaderStageFlags::COMPUTE)
        .module(resources.shader)
        .name(c"main");
    let pipeline_info = [vk::ComputePipelineCreateInfo::default()
        .stage(stage)
        .layout(resources.layout)];
    // SAFETY: `device` is live and `pipeline_info` references live shader and layout handles.
    let pipeline_result =
        unsafe { device.create_compute_pipelines(vk::PipelineCache::null(), &pipeline_info, None) };
    match pipeline_result {
        Ok(pipelines) => resources.pipeline = pipelines[0],
        Err((pipelines, error)) => {
            resources.pipeline = pipelines[0];
            return Err(error.into());
        }
    }
    let sizes = [vk::DescriptorPoolSize::default()
        .ty(vk::DescriptorType::STORAGE_BUFFER)
        .descriptor_count(1)];
    let pool_info = vk::DescriptorPoolCreateInfo::default()
        .max_sets(1)
        .pool_sizes(&sizes);
    // SAFETY: `device` is live and `pool_info` borrows valid `sizes`.
    resources.pool = unsafe { device.create_descriptor_pool(&pool_info, None) }?;
    let allocate_sets_info = vk::DescriptorSetAllocateInfo::default()
        .descriptor_pool(resources.pool)
        .set_layouts(&layouts);
    // SAFETY: `device`, `resources.pool`, and `layouts` are live.
    let sets = unsafe { device.allocate_descriptor_sets(&allocate_sets_info) }?;
    let descriptors = [vk::DescriptorBufferInfo::default()
        .buffer(resources.buffer)
        .range(bytes)];
    let writes = [vk::WriteDescriptorSet::default()
        .dst_set(sets[0])
        .dst_binding(0)
        .descriptor_type(vk::DescriptorType::STORAGE_BUFFER)
        .buffer_info(&descriptors)];
    // SAFETY: `sets[0]` and `resources.buffer` are live and unsubmitted.
    unsafe { device.update_descriptor_sets(&writes, &[]) };
    let cmd_pool_info = vk::CommandPoolCreateInfo::default().queue_family_index(family);
    // SAFETY: `device` is live and `family` is a valid queue family index on it.
    resources.commands = unsafe { device.create_command_pool(&cmd_pool_info, None) }?;
    let cmd_alloc_info = vk::CommandBufferAllocateInfo::default()
        .command_pool(resources.commands)
        .level(vk::CommandBufferLevel::PRIMARY)
        .command_buffer_count(1);
    // SAFETY: `device` and `resources.commands` are live.
    let commands = unsafe { device.allocate_command_buffers(&cmd_alloc_info) }?;
    let command = commands[0];
    let begin_info =
        vk::CommandBufferBeginInfo::default().flags(vk::CommandBufferUsageFlags::ONE_TIME_SUBMIT);
    // SAFETY: `command` is freshly allocated and in the initial state.
    unsafe { device.begin_command_buffer(command, &begin_info) }?;
    // SAFETY: `command` is recording and `resources.pipeline` is a live compute pipeline.
    unsafe {
        device.cmd_bind_pipeline(command, vk::PipelineBindPoint::COMPUTE, resources.pipeline)
    };
    // SAFETY: `command`, `resources.layout`, and `sets` are live.
    unsafe {
        device.cmd_bind_descriptor_sets(
            command,
            vk::PipelineBindPoint::COMPUTE,
            resources.layout,
            0,
            &sets,
            &[],
        );
    }
    // SAFETY: `command` is recording with a bound compute pipeline and descriptor set.
    unsafe { device.cmd_dispatch(command, count, 1, 1) };
    let barriers = [vk::MemoryBarrier::default()
        .src_access_mask(vk::AccessFlags::SHADER_WRITE)
        .dst_access_mask(vk::AccessFlags::HOST_READ)];
    // SAFETY: `command` is recording and `barriers` is valid for this call.
    unsafe {
        device.cmd_pipeline_barrier(
            command,
            vk::PipelineStageFlags::COMPUTE_SHADER,
            vk::PipelineStageFlags::HOST,
            vk::DependencyFlags::empty(),
            &barriers,
            &[],
            &[],
        );
    }
    // SAFETY: `command` is recording and all recorded commands are complete.
    unsafe { device.end_command_buffer(command) }?;
    // SAFETY: `device` is live.
    resources.fence = unsafe { device.create_fence(&vk::FenceCreateInfo::default(), None) }?;
    let mut kind =
        vk::SemaphoreTypeCreateInfo::default().semaphore_type(vk::SemaphoreType::TIMELINE);
    let semaphore_info = vk::SemaphoreCreateInfo::default().push_next(&mut kind);
    // SAFETY: `device` is live and `semaphore_info` borrows `kind` for this call.
    resources.semaphore = unsafe { device.create_semaphore(&semaphore_info, None) }?;
    let fences = [resources.fence];
    // SAFETY: `device` and `resources.fence` are live.
    if unsafe { device.wait_for_fences(&fences, true, 0) } != Err(vk::Result::TIMEOUT) {
        return Err(Error::Synchronization("new fence did not time out"));
    }
    let signal_info = vk::SemaphoreSignalInfo::default()
        .semaphore(resources.semaphore)
        .value(1);
    // SAFETY: `device` and `resources.semaphore` are live timeline objects.
    unsafe { device.signal_semaphore(&signal_info) }?;
    let semaphores = [resources.semaphore];
    let waits = [1];
    let signals = [2];
    let stages = [vk::PipelineStageFlags::COMPUTE_SHADER];
    let mut values = vk::TimelineSemaphoreSubmitInfo::default()
        .wait_semaphore_values(&waits)
        .signal_semaphore_values(&signals);
    let submits = [vk::SubmitInfo::default()
        .command_buffers(&commands)
        .wait_semaphores(&semaphores)
        .wait_dst_stage_mask(&stages)
        .signal_semaphores(&semaphores)
        .push_next(&mut values)];
    // SAFETY: `queue`, `submits`, `resources.fence`, and all referenced command,
    // descriptor, buffer, pipeline, and semaphore objects remain live until retired.
    unsafe { device.queue_submit(queue, &submits, resources.fence) }?;
    resources.pending = true;
    // Ten seconds bounds this one-page functional smoke, including CI scheduling.
    let timeout = std::time::Duration::from_secs(10).as_nanos() as u64;
    let completion = helios_venus::helios::queue_completion(queue)?;
    let deadline = helios_api::bindings::wasi::clocks::monotonic_clock::now() + timeout;
    if !helios_api::sync::wait_all(&[completion.point(1)], Some(deadline)).await? {
        return Err(Error::Synchronization(
            "queue completion timeline timed out",
        ));
    }
    let wait_info = vk::SemaphoreWaitInfo::default()
        .semaphores(&semaphores)
        .values(&signals);
    // SAFETY: `device` and `resources.semaphore` are live and `wait_info` borrows valid slices.
    unsafe { device.wait_semaphores(&wait_info, timeout) }?;
    // SAFETY: `device` and `resources.fence` are live.
    unsafe { device.wait_for_fences(&fences, true, timeout) }?;
    resources.pending = false;
    // SAFETY: `device` and `resources.fence` are live.
    let fence_signaled = unsafe { device.get_fence_status(resources.fence) }?;
    // SAFETY: `device` and `resources.semaphore` are live.
    let semaphore_value = unsafe { device.get_semaphore_counter_value(resources.semaphore) }?;
    if !fence_signaled || semaphore_value != 2 {
        return Err(Error::Synchronization(
            "completed submission has unsignaled objects",
        ));
    }
    for index in 0..count {
        // SAFETY: `requirements.size >= bytes = count * 4`, so `index < count`
        // stays within the mapped `u32` range of `resources.memory`.
        let slot = unsafe { pointer.add(index as usize) };
        // SAFETY: `slot` points to an aligned, mapped `u32` inside `resources.memory`,
        // and the GPU submission retired with a SHADER_WRITE->HOST_READ barrier above.
        let found = unsafe { slot.read_volatile() };
        // This mirrors compute.wgsl's arithmetic, not its GPU execution.
        let expected = index * 3 + 7;
        if found != expected {
            return Err(Error::ComputeReadback {
                index,
                expected,
                found,
            });
        }
    }
    // SAFETY: `device` and `resources.fence` are live and not in use by any submission.
    unsafe { device.reset_fences(&fences) }?;
    // SAFETY: `device` and `resources.fence` are live.
    if unsafe { device.get_fence_status(resources.fence) }? {
        return Err(Error::Synchronization("reset fence remains signaled"));
    }
    // SAFETY: `queue` and `resources.fence` are live and idle.
    unsafe { device.queue_submit(queue, &[], resources.fence) }?;
    resources.pending = true;
    // SAFETY: `device` and `resources.fence` are live.
    unsafe { device.wait_for_fences(&fences, true, timeout) }?;
    resources.pending = false;
    println!("gpu-test:venus sdk-queue-completion ok");
    println!("gpu-test:venus synchronization ok cpu-signal=1 gpu-signal=2 fence-reset=1");
    println!("gpu-test:venus compute-readback ok words={count}");
    Ok(())
}
