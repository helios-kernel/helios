use helios_webgpu::runtime::{Device, Runtime};
use helios_webgpu::wgpu;

use super::Error;

pub(super) async fn run() -> Result<(), Error> {
    let runtime = Runtime::open().await?;
    let adapter = runtime.request_adapter(&Default::default()).await?;
    let info = adapter.get_info();
    let device = Device::request(&adapter, &Default::default()).await?;
    println!(
        "gpu-test:wgpu adapter ok name={} backend={:?}",
        info.name, info.backend
    );
    println!("gpu-test:wgpu device ok");

    // The Vulkan smoke's page-sized arithmetic workload also exercises
    // wgpu-core validation, WGSL compilation, and asynchronous buffer mapping.
    let bytes = super::super::PAGE_BYTES;
    let count = (bytes / size_of::<u32>() as u64) as u32;
    let raw = device.raw();
    let errors = raw.push_error_scope(wgpu::ErrorFilter::Validation);
    let storage = raw.create_buffer(&wgpu::BufferDescriptor {
        label: Some("webgpu compute storage"),
        size: bytes,
        usage: wgpu::BufferUsages::STORAGE
            | wgpu::BufferUsages::COPY_SRC
            | wgpu::BufferUsages::COPY_DST,
        mapped_at_creation: false,
    });
    let readback = raw.create_buffer(&wgpu::BufferDescriptor {
        label: Some("webgpu compute readback"),
        size: bytes,
        usage: wgpu::BufferUsages::COPY_DST | wgpu::BufferUsages::MAP_READ,
        mapped_at_creation: false,
    });
    let input: Vec<_> = (0..count).flat_map(u32::to_le_bytes).collect();
    device.queue().write_buffer(&storage, 0, &input);
    let shader = raw.create_shader_module(wgpu::ShaderModuleDescriptor {
        label: Some("webgpu compute"),
        source: wgpu::ShaderSource::Wgsl(include_str!("../compute.wgsl").into()),
    });
    let pipeline = raw.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
        label: Some("webgpu compute"),
        layout: None,
        module: &shader,
        entry_point: Some("main"),
        compilation_options: Default::default(),
        cache: None,
    });
    let bindings = raw.create_bind_group(&wgpu::BindGroupDescriptor {
        label: Some("webgpu compute data"),
        layout: &pipeline.get_bind_group_layout(0),
        entries: &[wgpu::BindGroupEntry {
            binding: 0,
            resource: storage.as_entire_binding(),
        }],
    });
    let mut encoder = raw.create_command_encoder(&Default::default());
    {
        let mut pass = encoder.begin_compute_pass(&Default::default());
        pass.set_pipeline(&pipeline);
        pass.set_bind_group(0, &bindings, &[]);
        pass.dispatch_workgroups(count, 1, 1);
    }
    encoder.copy_buffer_to_buffer(&storage, 0, &readback, 0, bytes);
    device.queue().submit([encoder.finish()]);
    device.map(&readback, wgpu::MapMode::Read, 0..bytes).await?;
    let mapped = readback.get_mapped_range(..)?;
    for (index, bytes) in mapped
        .as_chunks::<{ size_of::<u32>() }>()
        .0
        .iter()
        .enumerate()
    {
        let found = u32::from_le_bytes(*bytes);
        let expected = index as u32 * 3 + 7;
        if found != expected {
            return Err(Error::ComputeReadback {
                index: index as u32,
                expected,
                found,
            });
        }
    }
    drop(mapped);
    readback.unmap();
    if let Some(error) = errors.pop().await {
        return Err(Error::WebGpuReported(error.into()));
    }
    if let Ok(error) = device.errors().try_recv() {
        return Err(Error::WebGpuReported(error));
    }
    println!("gpu-test:wgpu compute-readback ok words={count}");
    Ok(())
}
