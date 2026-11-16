//! virtio-9p host share over PCI for the x86 backend.
//!
//! Concurrency contract: the device is constructed on the bootstrap
//! processor before interrupts are unmasked. Afterwards every caller
//! submits straight to the device, which pipelines requests and routes
//! each completion back to the task that submitted it; completions
//! arrive on the device's MSI-X vector, so callers await a notification
//! instead of polling the used ring.

use helios_kernel::{HostFsTransport, Virtio9pTransport};
use helios_virtio::{DeviceType, VirtioPciTransport};
use pci_types::PciAddress;

use crate::debug_state::RuntimeState;
use crate::iommu::X86DmaPool;
use crate::pci::{PciRoot, VirtioFunctions};

pub(crate) type HostFsTransportService = Virtio9pTransport<VirtioPciTransport<X86DmaPool>>;

pub(crate) type HostFileSystemService =
    helios_kernel::HostFsClient<HostFsTransportService, crate::X86Cpu>;

/// The PCI function that carries the platform's virtio-9p host share.
pub(crate) fn discover(virtio: &VirtioFunctions) -> Option<PciAddress> {
    virtio.find_virtio_function(DeviceType::_9P)
}

/// Brings up the virtio-9p function at `address` and installs the host
/// file system service on top of it.
pub(crate) fn install(
    cpu: &crate::X86Cpu,
    pci: &PciRoot,
    address: PciAddress,
    dma: X86DmaPool,
    vector: u8,
    destination_apic_id: u32,
    debug_state: &RuntimeState,
) -> HostFsTransportService {
    let msix_vector = pci.bind_msix_vector(address, vector, destination_apic_id);
    let device = helios_virtio::p9_from_pci(&pci.access(), address, pci, dma, Some(msix_vector))
        .unwrap_or_else(|error| {
            panic!("failed to initialize the virtio-9p function at {address}: {error}")
        });
    let transport = Virtio9pTransport::new(device);
    debug_state.install_host_fs_service(HostFileSystemService::new(
        transport.clone(),
        cpu.clone(),
        debug_state.profiles(),
    ));
    tracing::info!(
        "virtio 9p online transport=pci function={address} msix_vector={vector:#x} mount_tag={}",
        transport.mount_tag()
    );
    transport
}
