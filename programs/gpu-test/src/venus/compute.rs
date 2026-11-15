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
        // SAFETY: every field is either null or owned here. No submitted work
        // remains when this owner drops: run waits for the queue after submit.
        unsafe {
            if self.pending {
                // An expired smoke-test deadline does not cancel GPU work.
                let _ = self.device.queue_wait_idle(self.queue);
            }
            self.device.destroy_fence(self.fence, None);
            self.device.destroy_semaphore(self.semaphore, None);
            self.device.destroy_command_pool(self.commands, None);
            self.device.destroy_descriptor_pool(self.pool, None);
            self.device.destroy_pipeline(self.pipeline, None);
            self.device.destroy_shader_module(self.shader, None);
            self.device.destroy_pipeline_layout(self.layout, None);
            self.device
                .destroy_descriptor_set_layout(self.set_layout, None);
            if self.mapped {
                self.device.unmap_memory(self.memory);
            }
            self.device.destroy_buffer(self.buffer, None);
            self.device.free_memory(self.memory, None);
        }
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
    // SAFETY: inputs remain live for each call; resources owns every created
    // handle, and queue retirement precedes mapped reads and destruction.
    unsafe {
        resources.buffer = device.create_buffer(
            &vk::BufferCreateInfo::default()
                .size(bytes)
                .usage(vk::BufferUsageFlags::STORAGE_BUFFER)
                .sharing_mode(vk::SharingMode::EXCLUSIVE),
            None,
        )?;
        let requirements = device.get_buffer_memory_requirements(resources.buffer);
        let properties = instance.get_physical_device_memory_properties(physical);
        let memory_type = host_memory_type(&properties, requirements.memory_type_bits)?;
        resources.memory = device.allocate_memory(
            &vk::MemoryAllocateInfo::default()
                .allocation_size(requirements.size)
                .memory_type_index(memory_type),
            None,
        )?;
        device.bind_buffer_memory(resources.buffer, resources.memory, 0)?;
        let pointer = device
            .map_memory(
                resources.memory,
                0,
                requirements.size,
                vk::MemoryMapFlags::empty(),
            )?
            .cast::<u32>();
        resources.mapped = true;
        for index in 0..count {
            pointer.add(index as usize).write_volatile(index);
        }

        let bindings = [vk::DescriptorSetLayoutBinding::default()
            .binding(0)
            .descriptor_type(vk::DescriptorType::STORAGE_BUFFER)
            .descriptor_count(1)
            .stage_flags(vk::ShaderStageFlags::COMPUTE)];
        resources.set_layout = device.create_descriptor_set_layout(
            &vk::DescriptorSetLayoutCreateInfo::default().bindings(&bindings),
            None,
        )?;
        let layouts = [resources.set_layout];
        resources.layout = device.create_pipeline_layout(
            &vk::PipelineLayoutCreateInfo::default().set_layouts(&layouts),
            None,
        )?;
        let code: Vec<u32> = include_bytes!(concat!(env!("OUT_DIR"), "/compute.spv"))
            .chunks_exact(size_of::<u32>())
            .map(|word| u32::from_le_bytes(word.try_into().unwrap()))
            .collect();
        resources.shader = device
            .create_shader_module(&vk::ShaderModuleCreateInfo::default().code(&code), None)?;
        let stage = vk::PipelineShaderStageCreateInfo::default()
            .stage(vk::ShaderStageFlags::COMPUTE)
            .module(resources.shader)
            .name(c"main");
        let pipeline_info = [vk::ComputePipelineCreateInfo::default()
            .stage(stage)
            .layout(resources.layout)];
        match device.create_compute_pipelines(vk::PipelineCache::null(), &pipeline_info, None) {
            Ok(pipelines) => resources.pipeline = pipelines[0],
            Err((pipelines, error)) => {
                resources.pipeline = pipelines[0];
                return Err(error.into());
            }
        }
        let sizes = [vk::DescriptorPoolSize::default()
            .ty(vk::DescriptorType::STORAGE_BUFFER)
            .descriptor_count(1)];
        resources.pool = device.create_descriptor_pool(
            &vk::DescriptorPoolCreateInfo::default()
                .max_sets(1)
                .pool_sizes(&sizes),
            None,
        )?;
        let sets = device.allocate_descriptor_sets(
            &vk::DescriptorSetAllocateInfo::default()
                .descriptor_pool(resources.pool)
                .set_layouts(&layouts),
        )?;
        let descriptors = [vk::DescriptorBufferInfo::default()
            .buffer(resources.buffer)
            .range(bytes)];
        let writes = [vk::WriteDescriptorSet::default()
            .dst_set(sets[0])
            .dst_binding(0)
            .descriptor_type(vk::DescriptorType::STORAGE_BUFFER)
            .buffer_info(&descriptors)];
        device.update_descriptor_sets(&writes, &[]);
        resources.commands = device.create_command_pool(
            &vk::CommandPoolCreateInfo::default().queue_family_index(family),
            None,
        )?;
        let commands = device.allocate_command_buffers(
            &vk::CommandBufferAllocateInfo::default()
                .command_pool(resources.commands)
                .level(vk::CommandBufferLevel::PRIMARY)
                .command_buffer_count(1),
        )?;
        let command = commands[0];
        device.begin_command_buffer(
            command,
            &vk::CommandBufferBeginInfo::default()
                .flags(vk::CommandBufferUsageFlags::ONE_TIME_SUBMIT),
        )?;
        device.cmd_bind_pipeline(command, vk::PipelineBindPoint::COMPUTE, resources.pipeline);
        device.cmd_bind_descriptor_sets(
            command,
            vk::PipelineBindPoint::COMPUTE,
            resources.layout,
            0,
            &sets,
            &[],
        );
        device.cmd_dispatch(command, count, 1, 1);
        let barriers = [vk::MemoryBarrier::default()
            .src_access_mask(vk::AccessFlags::SHADER_WRITE)
            .dst_access_mask(vk::AccessFlags::HOST_READ)];
        device.cmd_pipeline_barrier(
            command,
            vk::PipelineStageFlags::COMPUTE_SHADER,
            vk::PipelineStageFlags::HOST,
            vk::DependencyFlags::empty(),
            &barriers,
            &[],
            &[],
        );
        device.end_command_buffer(command)?;
        resources.fence = device.create_fence(&vk::FenceCreateInfo::default(), None)?;
        let mut kind =
            vk::SemaphoreTypeCreateInfo::default().semaphore_type(vk::SemaphoreType::TIMELINE);
        resources.semaphore = device.create_semaphore(
            &vk::SemaphoreCreateInfo::default().push_next(&mut kind),
            None,
        )?;
        let fences = [resources.fence];
        if device.wait_for_fences(&fences, true, 0) != Err(vk::Result::TIMEOUT) {
            return Err(Error::Synchronization("new fence did not time out"));
        }
        device.signal_semaphore(
            &vk::SemaphoreSignalInfo::default()
                .semaphore(resources.semaphore)
                .value(1),
        )?;
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
        device.queue_submit(queue, &submits, resources.fence)?;
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
        device.wait_semaphores(
            &vk::SemaphoreWaitInfo::default()
                .semaphores(&semaphores)
                .values(&signals),
            timeout,
        )?;
        device.wait_for_fences(&fences, true, timeout)?;
        resources.pending = false;
        if !device.get_fence_status(resources.fence)?
            || device.get_semaphore_counter_value(resources.semaphore)? != 2
        {
            return Err(Error::Synchronization(
                "completed submission has unsignaled objects",
            ));
        }
        for index in 0..count {
            let found = pointer.add(index as usize).read_volatile();
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
        device.reset_fences(&fences)?;
        if device.get_fence_status(resources.fence)? {
            return Err(Error::Synchronization("reset fence remains signaled"));
        }
        device.queue_submit(queue, &[], resources.fence)?;
        resources.pending = true;
        device.wait_for_fences(&fences, true, timeout)?;
        resources.pending = false;
    }
    println!("gpu-test:venus sdk-queue-completion ok");
    println!("gpu-test:venus synchronization ok cpu-signal=1 gpu-signal=2 fence-reset=1");
    println!("gpu-test:venus compute-readback ok words={count}");
    Ok(())
}
