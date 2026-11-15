use super::{Connection, Context, Error, MappedBlob, NonZeroUsize, ObjectBase, null, success, vk};

pub(super) fn run(
    connection: &mut Connection<Context>,
    physical: vk::VkPhysicalDevice,
    device: vk::VkDevice,
    queue: vk::VkQueue,
    family: u32,
) -> Result<(), Error> {
    // One page exercises multiple shader invocations and mapped cache lines.
    let bytes = super::super::PAGE_BYTES;
    let count = (bytes / size_of::<u32>() as u64) as u32;
    let buffer_info = vk::VkBufferCreateInfo {
        sType: vk::VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO,
        pNext: null(),
        flags: 0,
        size: bytes,
        usage: vk::VK_BUFFER_USAGE_STORAGE_BUFFER_BIT.0 as u32,
        sharingMode: vk::VK_SHARING_MODE_EXCLUSIVE,
        queueFamilyIndexCount: 0,
        pQueueFamilyIndices: null(),
    };
    let mut buffer = vk::VkBuffer(connection.object_id()?);
    // SAFETY: all inputs and preallocated output identifiers remain live
    // through the synchronous request/reply calls below. Child resources
    // are destroyed after queue retirement and before their parents.
    unsafe {
        success(
            "vkCreateBuffer",
            vk::vn_call_vkCreateBuffer(connection, device, &buffer_info, null(), &mut buffer)?,
        )?;
    }
    // SAFETY: these output structures consist entirely of integer fields.
    let mut requirements: vk::VkMemoryRequirements = unsafe { core::mem::zeroed() };
    // SAFETY: integer fields and fixed arrays have valid zero values.
    let mut properties: vk::VkPhysicalDeviceMemoryProperties = unsafe { core::mem::zeroed() };
    // SAFETY: the device owns buffer; both outputs are writable.
    unsafe {
        vk::vn_call_vkGetBufferMemoryRequirements(connection, device, buffer, &mut requirements)?;
        vk::vn_call_vkGetPhysicalDeviceMemoryProperties(connection, physical, &mut properties)?;
    }
    let required = (vk::VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT.0
        | vk::VK_MEMORY_PROPERTY_HOST_COHERENT_BIT.0) as u32;
    let memory_type = properties
        .memoryTypes
        .iter()
        .take(properties.memoryTypeCount as usize)
        .enumerate()
        .find(|(index, memory)| {
            requirements.memoryTypeBits & (1 << index) != 0
                && memory.propertyFlags & required == required
        })
        .ok_or(Error::NoHostMemory)?
        .0 as u32;
    let allocation = vk::VkMemoryAllocateInfo {
        sType: vk::VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO,
        pNext: null(),
        allocationSize: requirements.size,
        memoryTypeIndex: memory_type,
    };
    let mut memory = vk::VkDeviceMemory(connection.object_id()?);
    // SAFETY: the memory type and size satisfy this buffer's requirements;
    // offset zero satisfies its alignment.
    unsafe {
        success(
            "vkAllocateMemory(compute)",
            vk::vn_call_vkAllocateMemory(connection, device, &allocation, null(), &mut memory)?,
        )?;
        success(
            "vkBindBufferMemory",
            vk::vn_call_vkBindBufferMemory(connection, device, buffer, memory, 0)?,
        )?;
    }
    let size = NonZeroUsize::new(
        usize::try_from(requirements.size).expect("test allocation fits the address space"),
    )
    .expect("nonempty buffer requires memory");
    let blob = connection.memory_blob(memory, size)?;
    let pointer = blob.pointer().as_ptr().cast::<u32>();
    for index in 0..count {
        // SAFETY: the mapping is aligned, covers the buffer, and no GPU
        // work has been submitted. Volatile writes exercise mapped memory.
        unsafe { pointer.add(index as usize).write_volatile(index) };
    }

    let binding = vk::VkDescriptorSetLayoutBinding {
        binding: 0,
        descriptorType: vk::VK_DESCRIPTOR_TYPE_STORAGE_BUFFER,
        descriptorCount: 1,
        stageFlags: vk::VK_SHADER_STAGE_COMPUTE_BIT.0 as u32,
        pImmutableSamplers: null(),
    };
    let set_info = vk::VkDescriptorSetLayoutCreateInfo {
        sType: vk::VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO,
        pNext: null(),
        flags: 0,
        bindingCount: 1,
        pBindings: &binding,
    };
    let mut set_layout = vk::VkDescriptorSetLayout(connection.object_id()?);
    // SAFETY: binding and output storage outlive this call.
    unsafe {
        success(
            "vkCreateDescriptorSetLayout",
            vk::vn_call_vkCreateDescriptorSetLayout(
                connection,
                device,
                &set_info,
                null(),
                &mut set_layout,
            )?,
        )?;
    }
    let layout_info = vk::VkPipelineLayoutCreateInfo {
        sType: vk::VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO,
        pNext: null(),
        flags: 0,
        setLayoutCount: 1,
        pSetLayouts: &set_layout,
        pushConstantRangeCount: 0,
        pPushConstantRanges: null(),
    };
    let mut layout = vk::VkPipelineLayout(connection.object_id()?);
    // SAFETY: set_layout belongs to device and stays live.
    unsafe {
        success(
            "vkCreatePipelineLayout",
            vk::vn_call_vkCreatePipelineLayout(
                connection,
                device,
                &layout_info,
                null(),
                &mut layout,
            )?,
        )?;
    }
    let code: Vec<u32> = include_bytes!(concat!(env!("OUT_DIR"), "/compute.spv"))
        .chunks_exact(size_of::<u32>())
        .map(|word| u32::from_le_bytes(word.try_into().unwrap()))
        .collect();
    let shader_info = vk::VkShaderModuleCreateInfo {
        sType: vk::VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO,
        pNext: null(),
        flags: 0,
        codeSize: code.len() * size_of::<u32>(),
        pCode: code.as_ptr(),
    };
    let mut shader = vk::VkShaderModule(connection.object_id()?);
    // SAFETY: code owns aligned SPIR-V validated during the build.
    unsafe {
        success(
            "vkCreateShaderModule",
            vk::vn_call_vkCreateShaderModule(
                connection,
                device,
                &shader_info,
                null(),
                &mut shader,
            )?,
        )?;
    }
    let pipeline_info = vk::VkComputePipelineCreateInfo {
        sType: vk::VK_STRUCTURE_TYPE_COMPUTE_PIPELINE_CREATE_INFO,
        pNext: null(),
        flags: 0,
        stage: vk::VkPipelineShaderStageCreateInfo {
            sType: vk::VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO,
            pNext: null(),
            flags: 0,
            stage: vk::VK_SHADER_STAGE_COMPUTE_BIT,
            module: shader,
            pName: c"main".as_ptr(),
            pSpecializationInfo: null(),
        },
        layout,
        basePipelineHandle: vk::VkPipeline(0),
        basePipelineIndex: -1,
    };
    let mut pipeline = vk::VkPipeline(connection.object_id()?);
    // SAFETY: shader and layout are live; one input and one output exist.
    unsafe {
        success(
            "vkCreateComputePipelines",
            vk::vn_call_vkCreateComputePipelines(
                connection,
                device,
                vk::VkPipelineCache(0),
                1,
                &pipeline_info,
                null(),
                &mut pipeline,
            )?,
        )?;
    }
    let pool_size = vk::VkDescriptorPoolSize {
        r#type: vk::VK_DESCRIPTOR_TYPE_STORAGE_BUFFER,
        descriptorCount: 1,
    };
    let pool_info = vk::VkDescriptorPoolCreateInfo {
        sType: vk::VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO,
        pNext: null(),
        flags: 0,
        maxSets: 1,
        poolSizeCount: 1,
        pPoolSizes: &pool_size,
    };
    let mut pool = vk::VkDescriptorPool(connection.object_id()?);
    // SAFETY: this pool has capacity for the one descriptor set below.
    unsafe {
        success(
            "vkCreateDescriptorPool",
            vk::vn_call_vkCreateDescriptorPool(connection, device, &pool_info, null(), &mut pool)?,
        )?;
    }
    let set_allocate = vk::VkDescriptorSetAllocateInfo {
        sType: vk::VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO,
        pNext: null(),
        descriptorPool: pool,
        descriptorSetCount: 1,
        pSetLayouts: &set_layout,
    };
    let mut set = vk::VkDescriptorSet(connection.object_id()?);
    // SAFETY: the pool and layout are live; one output slot exists.
    unsafe {
        success(
            "vkAllocateDescriptorSets",
            vk::vn_call_vkAllocateDescriptorSets(connection, device, &set_allocate, &mut set)?,
        )?;
    }
    let buffer_descriptor = vk::VkDescriptorBufferInfo {
        buffer,
        offset: 0,
        range: bytes,
    };
    let write = vk::VkWriteDescriptorSet {
        sType: vk::VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET,
        pNext: null(),
        dstSet: set,
        dstBinding: 0,
        dstArrayElement: 0,
        descriptorCount: 1,
        descriptorType: vk::VK_DESCRIPTOR_TYPE_STORAGE_BUFFER,
        pImageInfo: null(),
        pBufferInfo: &buffer_descriptor,
        pTexelBufferView: null(),
    };
    let command_pool_info = vk::VkCommandPoolCreateInfo {
        sType: vk::VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO,
        pNext: null(),
        flags: 0,
        queueFamilyIndex: family,
    };
    let mut command_pool = vk::VkCommandPool(connection.object_id()?);
    // SAFETY: the descriptor matches the layout; family owns the queue.
    unsafe {
        vk::vn_call_vkUpdateDescriptorSets(connection, device, 1, &write, 0, null())?;
        success(
            "vkCreateCommandPool",
            vk::vn_call_vkCreateCommandPool(
                connection,
                device,
                &command_pool_info,
                null(),
                &mut command_pool,
            )?,
        )?;
    }
    let command_allocate = vk::VkCommandBufferAllocateInfo {
        sType: vk::VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO,
        pNext: null(),
        commandPool: command_pool,
        level: vk::VK_COMMAND_BUFFER_LEVEL_PRIMARY,
        commandBufferCount: 1,
    };
    let mut command_storage = Box::new(ObjectBase {
        id: connection.object_id()?,
    });
    let mut command = vk::VkCommandBuffer(&mut *command_storage);
    let begin = vk::VkCommandBufferBeginInfo {
        sType: vk::VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO,
        pNext: null(),
        flags: vk::VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT.0 as u32,
        pInheritanceInfo: null(),
    };
    let barrier = vk::VkMemoryBarrier {
        sType: vk::VK_STRUCTURE_TYPE_MEMORY_BARRIER,
        pNext: null(),
        srcAccessMask: vk::VK_ACCESS_SHADER_WRITE_BIT.0 as u32,
        dstAccessMask: vk::VK_ACCESS_HOST_READ_BIT.0 as u32,
    };
    // SAFETY: recording is single-owner; every bound resource remains live
    // until retirement. The barrier publishes shader writes to host reads.
    unsafe {
        success(
            "vkAllocateCommandBuffers",
            vk::vn_call_vkAllocateCommandBuffers(
                connection,
                device,
                &command_allocate,
                &mut command,
            )?,
        )?;
        success(
            "vkBeginCommandBuffer",
            vk::vn_call_vkBeginCommandBuffer(connection, command, &begin)?,
        )?;
        vk::vn_call_vkCmdBindPipeline(
            connection,
            command,
            vk::VK_PIPELINE_BIND_POINT_COMPUTE,
            pipeline,
        )?;
        vk::vn_call_vkCmdBindDescriptorSets(
            connection,
            command,
            vk::VK_PIPELINE_BIND_POINT_COMPUTE,
            layout,
            0,
            1,
            &set,
            0,
            null(),
        )?;
        vk::vn_call_vkCmdDispatch(connection, command, count, 1, 1)?;
        vk::vn_call_vkCmdPipelineBarrier(
            connection,
            command,
            vk::VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT.0 as u32,
            vk::VK_PIPELINE_STAGE_HOST_BIT.0 as u32,
            0,
            1,
            &barrier,
            0,
            null(),
            0,
            null(),
        )?;
        success(
            "vkEndCommandBuffer",
            vk::vn_call_vkEndCommandBuffer(connection, command)?,
        )?;
    }
    let submit = vk::VkSubmitInfo {
        sType: vk::VK_STRUCTURE_TYPE_SUBMIT_INFO,
        pNext: null(),
        waitSemaphoreCount: 0,
        pWaitSemaphores: null(),
        pWaitDstStageMask: null(),
        commandBufferCount: 1,
        pCommandBuffers: &command,
        signalSemaphoreCount: 0,
        pSignalSemaphores: null(),
    };
    // SAFETY: the executable command buffer belongs to this queue family;
    // coherent host writes become available through queue submission.
    unsafe {
        success(
            "vkQueueSubmit",
            vk::vn_call_vkQueueSubmit(connection, queue, 1, &submit, vk::VkFence(0))?,
        )?;
    }
    connection.wait_queue(1)?;
    for index in 0..count {
        // SAFETY: the queue has retired, the mapping is coherent and the
        // command's memory barrier made every shader write host-visible.
        let found = unsafe { pointer.add(index as usize).read_volatile() };
        // This mirrors the arithmetic in compute.wgsl, not its GPU execution.
        let expected = index * 3 + 7;
        if found != expected {
            return Err(Error::ComputeReadback {
                index,
                expected,
                found,
            });
        }
    }
    drop(blob);
    // SAFETY: all GPU work has completed; child resources are destroyed
    // before their storage and parents. Destroying pools releases children.
    unsafe {
        vk::vn_call_vkDestroyCommandPool(connection, device, command_pool, null())?;
        vk::vn_call_vkDestroyDescriptorPool(connection, device, pool, null())?;
        vk::vn_call_vkDestroyPipeline(connection, device, pipeline, null())?;
        vk::vn_call_vkDestroyShaderModule(connection, device, shader, null())?;
        vk::vn_call_vkDestroyPipelineLayout(connection, device, layout, null())?;
        vk::vn_call_vkDestroyDescriptorSetLayout(connection, device, set_layout, null())?;
        vk::vn_call_vkDestroyBuffer(connection, device, buffer, null())?;
        vk::vn_call_vkFreeMemory(connection, device, memory, null())?;
    }
    connection.flush()?;
    println!("gpu-test:venus compute-readback ok words={count}");
    Ok(())
}
