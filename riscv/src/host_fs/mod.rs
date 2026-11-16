//! virtio-9p host share over MMIO for the riscv backend.
//!
//! Concurrency contract: the device is constructed on the bootstrap
//! hart before interrupts are enabled. Afterwards every caller submits
//! straight to the device, which pipelines requests and routes each
//! completion back to the task that submitted it; completions arrive on
//! the PLIC line the device tree names, so callers await a notification
//! instead of polling the used ring.

use fdt::Fdt;
use helios_kernel::Virtio9pTransport;

use crate::net::PlicInterrupt;

pub(crate) const HOST_MOUNT_TAG: &str = helios_kernel::HOST_SHARE_MOUNT_TAG;

pub(crate) type HostFsTransportService =
    Virtio9pTransport<helios_virtio::VirtioMmioTransport<helios_virtio::MmioBus>>;

pub(crate) type HostFileSystemService =
    helios_kernel::HostFsClient<HostFsTransportService, crate::RiscvCpu>;

pub(crate) struct HostFsInterrupt {
    pub(crate) line: PlicInterrupt,
    pub(crate) transport: HostFsTransportService,
}

pub(crate) fn install(
    cpu: &crate::RiscvCpu,
    fdt: &Fdt<'_>,
    debug_state: &crate::debug_state::RuntimeState,
) -> Option<HostFsInterrupt> {
    let Some((transport, line)) = discover_9p_device(fdt) else {
        tracing::warn!("virtio 9p device was not discovered on the platform bus");
        return None;
    };

    debug_state.install_host_fs_service(HostFileSystemService::new(
        transport.clone(),
        cpu.clone(),
        debug_state.profiles(),
    ));
    tracing::info!(
        "virtio 9p online mount_tag={HOST_MOUNT_TAG} irq={}",
        line.number()
    );

    Some(HostFsInterrupt { line, transport })
}

fn discover_9p_device(fdt: &Fdt<'_>) -> Option<(HostFsTransportService, PlicInterrupt)> {
    let candidate = helios_virtio::mmio_candidates(fdt).find(|candidate| {
        crate::matches_virtio_mmio_device(candidate.base, helios_virtio::DeviceType::_9P)
    })?;
    let base = candidate.base;
    let header = core::ptr::NonNull::new(base as *mut u8)
        .unwrap_or_else(|| panic!("virtio MMIO base {base:#x} was unexpectedly null"));
    let line = candidate
        .interrupt
        .and_then(PlicInterrupt::from_specifier)
        .unwrap_or_else(|| panic!("virtio-9p node at {base:#x} has no valid interrupt source"));
    let device =
        unsafe { helios_virtio::p9_from_mmio(header, candidate.size) }.unwrap_or_else(|error| {
            panic!("failed to initialize virtio-9p device at {base:#x}: {error}")
        });
    Some((Virtio9pTransport::new(device), line))
}

pub(crate) fn has_9p_device(fdt: &Fdt<'_>) -> bool {
    crate::count_virtio_mmio_devices(fdt, helios_virtio::DeviceType::_9P) != 0
}
