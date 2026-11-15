use wgpu_hal::{Adapter, Instance};

use super::{Context, Error, entry};

pub(super) fn run() -> Result<(), Error> {
    let descriptor = wgpu_hal::InstanceDescriptor {
        name: "helios-webgpu-smoke",
        flags: Default::default(),
        memory_budget_thresholds: Default::default(),
        backend_options: Default::default(),
        telemetry: None,
        display: None,
    };
    // SAFETY: the Venus entry owns independent connections for each instance;
    // adapters drop before the instance, and this smoke creates no surfaces.
    let instance =
        unsafe { wgpu_hal::vulkan::Instance::init_from_entry(entry::<Context>(), &descriptor)? };
    let adapters = unsafe { instance.enumerate_adapters(None) };
    let adapter = adapters.first().ok_or(Error::NoWebGpuAdapter)?;
    // SAFETY: limits come from this adapter, no optional features are requested,
    // and the device and queue are dropped before their adapter and instance.
    let opened = unsafe {
        adapter.adapter.open(
            Default::default(),
            &adapter.capabilities.limits,
            &Default::default(),
        )?
    };
    println!(
        "gpu-test:wgpu adapter ok count={} name={} backend={:?}",
        adapters.len(),
        adapter.info.name,
        adapter.info.backend,
    );
    drop(opened);
    println!("gpu-test:wgpu device ok");
    Ok(())
}
