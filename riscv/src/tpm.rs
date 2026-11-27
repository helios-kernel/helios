//! The machine's TPM 2.0, as the device tree names it, handed to the kernel as
//! its measured-boot device.
//!
//! Adapter code only: this module locates a `tcg,tpm-tis-mmio` node in the
//! flattened device tree (directly under `/` or one bus below with `ranges`
//! translation), maps its locality-0 MMIO window in the higher-half direct
//! map, and calls `helios_tpm::discover` with Limine's TPM event log to run
//! the measured-boot qualification checks.
//!
//! Concurrency contract: discovery runs once, on the bootstrap hart, before the
//! kernel is initialised and before any secondary hart starts.

use core::ptr::NonNull;

use fdt::Fdt;
use fdt::node::FdtNode;
use helios_hal::boot::MeasurementLog;
use helios_tpm::{
    Discovered, Discovery, InterfaceDescription, LOCALITY_BYTES, LoaderLog, MmioWindow,
};

use crate::{LimineBootHandoff, RiscvCpu};

/// `compatible` string of a TPM's FIFO interface over MMIO (QEMU
/// `tpm-tis-device`, `hw/core/sysbus-fdt.c`).
const TPM_TIS_MMIO: &str = "tcg,tpm-tis-mmio";

/// Opens the TPM the device tree describes and runs the measured-boot checks
/// against it.
///
/// A TPM that fails a check is reported and not handed over; one that fails
/// while it is checked stops the boot.
pub(crate) fn discover(
    fdt: &Fdt<'_>,
    handoff: &LimineBootHandoff,
    cpu: RiscvCpu,
) -> Discovered<MmioWindow, RiscvCpu> {
    let Some(base) = find_tpm_base(fdt) else {
        return (None, Discovery::NotDescribed);
    };
    let physical_base = usize::try_from(base)
        .unwrap_or_else(|_| panic!("the TPM at {base:#x} is outside the physical address space"));
    let virtual_base = crate::vmm::map_mmio_range(physical_base, LOCALITY_BYTES);
    // SAFETY: `map_mmio_range` mapped locality 0's register window in the
    // higher-half direct map and never unmaps it, `base` came from the device
    // tree's `tcg,tpm-tis-mmio` node, and nothing else in this kernel touches
    // the TPM's registers.
    let window = unsafe {
        MmioWindow::new(
            NonNull::new(virtual_base as *mut u8)
                .unwrap_or_else(|| panic!("the TPM's register page mapped to a null address")),
            LOCALITY_BYTES,
        )
    };
    let log = handoff
        .tables
        .measurement_log
        .as_ref()
        .map(|log: &MeasurementLog| {
            // SAFETY: Limine's event log lives in bootloader-reclaimable
            // memory, which this backend never hands to the allocator, in the
            // direct map the response points into.
            unsafe { LoaderLog::mapped(log) }
        });
    helios_kernel::complete_device_future_at_bring_up(helios_tpm::discover(
        InterfaceDescription::DeviceTreeFifo,
        window,
        base,
        cpu,
        log,
    ))
    .unwrap_or_else(|error| {
        panic!("the TPM 2.0 at {base:#x} failed while measured boot was checked: {error}")
    })
}

fn find_tpm_base(fdt: &Fdt<'_>) -> Option<u64> {
    let is_tpm = |node: &FdtNode<'_, '_>| {
        node.compatible()
            .is_some_and(|entries| entries.all().any(|entry| entry == TPM_TIS_MMIO))
    };
    let root_cells = fdt.root().cell_sizes();
    for node in fdt
        .find_node("/")
        .into_iter()
        .flat_map(|root| root.children())
    {
        if is_tpm(&node) {
            return Some(first_region_base(&node) as u64);
        }
        for child in node.children() {
            if is_tpm(&child) {
                let raw_base = first_region_base(&child);
                let translated = translate(&node, root_cells.address_cells, raw_base);
                return Some(translated as u64);
            }
        }
    }
    if fdt.find_compatible(&[TPM_TIS_MMIO]).is_some() {
        panic!(
            "the tcg,tpm-tis-mmio node sits deeper than one bus below the root, whose address \
             translation this backend does not follow"
        );
    }
    None
}

fn first_region_base(node: &FdtNode<'_, '_>) -> usize {
    let region = node
        .reg()
        .and_then(|mut regions| regions.next())
        .unwrap_or_else(|| panic!("RISC-V {TPM_TIS_MMIO} node has no usable reg property"));
    assert!(
        region.size.is_some_and(|size| size >= LOCALITY_BYTES),
        "RISC-V {TPM_TIS_MMIO} reg window is smaller than locality 0 ({LOCALITY_BYTES} bytes)"
    );
    region.starting_address as usize
}

fn translate(bus: &FdtNode<'_, '_>, parent_address_cells: usize, address: usize) -> usize {
    let ranges = bus.property("ranges").unwrap_or_else(|| {
        panic!(
            "the bus above the {TPM_TIS_MMIO} node has no ranges property, so its addresses do \
             not reach the processor"
        )
    });
    if ranges.value.is_empty() {
        return address;
    }
    let cells = bus.cell_sizes();
    let child_bytes = cells.address_cells * 4;
    let parent_bytes = parent_address_cells * 4;
    let size_bytes = cells.size_cells * 4;
    let entry_bytes = child_bytes + parent_bytes + size_bytes;
    assert!(
        entry_bytes != 0 && ranges.value.len().is_multiple_of(entry_bytes),
        "the bus above the {TPM_TIS_MMIO} node has a ranges property of the wrong size"
    );
    for entry in ranges.value.chunks_exact(entry_bytes) {
        let (child, rest) = entry.split_at(child_bytes);
        let (parent, size) = rest.split_at(parent_bytes);
        let (Some(child), Some(parent), Some(size)) =
            (fdt_cells(child), fdt_cells(parent), fdt_cells(size))
        else {
            panic!(
                "a ranges entry above the {TPM_TIS_MMIO} node is not one or two cells per field"
            );
        };
        if let Some(offset) = address.checked_sub(child).filter(|offset| *offset < size) {
            return parent.checked_add(offset).unwrap_or_else(|| {
                panic!("the {TPM_TIS_MMIO} node translates past the end of the address space")
            });
        }
    }
    panic!("no ranges entry of its bus covers the {TPM_TIS_MMIO} node's registers")
}

fn fdt_cells(bytes: &[u8]) -> Option<usize> {
    if bytes.len() != 4 && bytes.len() != 8 {
        return None;
    }
    let mut value = 0_usize;
    for &cell in bytes.as_chunks::<4>().0 {
        let cell = u32::from_be_bytes(cell) as usize;
        value = value.checked_shl(32)? | cell;
    }
    Some(value)
}
