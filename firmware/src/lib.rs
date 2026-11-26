//! Firmware tables turned into `hal` values.
//!
//! Concurrency contract: every reader here is an immutable view over a
//! firmware table the backend opened on the bootstrap processor. Nothing
//! is allocated, so a reader runs before the heap exists, and nothing is
//! shared mutably, so no operation needs a lock or an atomic.

#![no_std]

#[cfg(feature = "acpi")]
mod acpi;
#[cfg(feature = "devicetree")]
mod devicetree;
mod error;
mod iommu;

#[cfg(feature = "acpi")]
pub use self::acpi::{
    AcpiMemory, AcpiNuma, GiccUidKey, LocalApicKey, MPIDR_AFFINITY_MASK, SratProcessor,
    SratProcessorKey,
};
#[cfg(feature = "devicetree")]
pub use devicetree::{DeviceTreeMemory, DeviceTreeNuma};
pub use error::{FirmwareNumaError, NodeName};
#[cfg(feature = "devicetree")]
pub use iommu::parse_devicetree_pci_iommu;
pub use iommu::{FirmwareIommuError, MAX_PCI_IOMMU_RANGES, PciIommuRange, VirtioIommuTopology};
#[cfg(feature = "acpi")]
pub use iommu::{VIOT_SIGNATURE, parse_viot};

use helios_hal::cpu::ProcessorId;

/// Backend-supplied mapping from the kernel's dense processor index to the
/// identity the firmware keys affinity by (APIC/x2APIC id, MPIDR, hart id).
pub trait ProcessorIdentities {
    fn processor_count(&self) -> usize;
    fn hardware_id(&self, processor: ProcessorId) -> u64;
}
