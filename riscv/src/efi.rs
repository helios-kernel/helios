//! The firmware's own device tree, found through the UEFI configuration
//! table.
//!
//! The tree Limine hands over via `DtbRequest` is a copy of the firmware's
//! with every `/memory` node deleted, because the executable is meant to take
//! its memory extents from the memory map (`common/protos/limine.c`). That
//! copy cannot describe locality: memory nodes are what `numa-node-id`
//! places memory with. The firmware's original stays where the firmware put
//! it, and the configuration table's `EFI_DTB_TABLE_GUID` entry names its
//! physical address.
//!
//! Every step is read through Limine's direct map, at base revision 6:
//! - the system table: Limine returns its direct-map address from base
//!   revision 5 on;
//! - the configuration table array: from base revision 5 on, Limine
//!   guarantees it lies in a `RESERVED_MAPPED` entry, a type the direct
//!   map covers from base revision 4 on;
//! - the tree: its memory-map entry is checked before a byte is read.
//!
//! Concurrency contract: read on the bootstrap hart before any secondary
//! starts, and never written; nothing here takes a lock.

use core::ops::Range;
use core::ptr::NonNull;

use fdt::{Fdt, FdtError};
use limine::memmap::{
    Entry, MEMMAP_ACPI_NVS, MEMMAP_ACPI_RECLAIMABLE, MEMMAP_BOOTLOADER_RECLAIMABLE,
    MEMMAP_MAPPED_RESERVED, MEMMAP_USABLE,
};
use r_efi::efi::{ConfigurationTable, DTB_TABLE_GUID, SYSTEM_TABLE_SIGNATURE, SystemTable};
use thiserror::Error;

/// The memory-map types the firmware's tree may lie in: every memory type the
/// direct map covers at base revision 4 and later. RISC-V EDK2 (`RiscVVirt`)
/// may leave QEMU's device tree in `EfiConventionalMemory` (`MEMMAP_USABLE`);
/// the caller reserves its physical range out of the bootstrap allocator
/// before priming it.
const FIRMWARE_TREE_MEMORY_TYPES: [u64; 5] = [
    MEMMAP_USABLE,
    MEMMAP_BOOTLOADER_RECLAIMABLE,
    MEMMAP_MAPPED_RESERVED,
    MEMMAP_ACPI_RECLAIMABLE,
    MEMMAP_ACPI_NVS,
];

pub(crate) struct FirmwareTree {
    pub(crate) fdt: Fdt<'static>,
    pub(crate) physical_range: Range<usize>,
}

/// Why the firmware's own device tree could not be read.
#[derive(Debug, Error)]
pub(crate) enum FirmwareTreeError {
    #[error(
        "Limine gave no EFI system table on a UEFI boot, so the firmware's own device tree \
         cannot be found"
    )]
    NoSystemTable,
    #[error("the EFI system table's signature is {found:#018x}, not `IBI SYST`")]
    SystemTableSignature { found: u64 },
    #[error("the firmware's device tree at {physical:#x} lies in no memory-map entry")]
    OutsideMemoryMap { physical: usize },
    #[error(
        "the firmware's device tree at {physical:#x} lies in Limine memory-map type \
         {memory_type}, which is not firmware memory the direct map covers"
    )]
    MemoryType { physical: usize, memory_type: u64 },
    #[error(
        "the firmware's device tree at {physical:#x} is not a valid blob within its memory-map \
         entry: {reason}"
    )]
    Malformed { physical: usize, reason: FdtError },
}

/// Where the firmware's own device tree is looked up.
pub(crate) struct FirmwareTreeLocator {
    system_table: Option<NonNull<SystemTable>>,
    memory_map: &'static [&'static Entry],
    physical_memory_offset: usize,
}

impl FirmwareTreeLocator {
    pub(crate) fn new(
        system_table: Option<NonNull<SystemTable>>,
        memory_map: &'static [&'static Entry],
        physical_memory_offset: usize,
    ) -> Self {
        Self {
            system_table,
            memory_map,
            physical_memory_offset,
        }
    }

    /// The firmware's own tree and its physical byte range, or `None` when the
    /// configuration table holds no device tree.
    pub(crate) fn open(&self) -> Result<Option<FirmwareTree>, FirmwareTreeError> {
        let system_table = self.system_table.ok_or(FirmwareTreeError::NoSystemTable)?;
        // SAFETY: Limine's response is the direct-map address of the
        // firmware's system table, which base revision 5 and later keep
        // mapped as `RESERVED_MAPPED` for the life of the kernel, and
        // nothing writes it.
        let system_table = unsafe { system_table.as_ref() };
        if system_table.hdr.signature != SYSTEM_TABLE_SIGNATURE {
            return Err(FirmwareTreeError::SystemTableSignature {
                found: system_table.hdr.signature,
            });
        }
        let Some(entry) = self
            .configuration_table(system_table)
            .iter()
            .find(|entry| entry.vendor_guid == DTB_TABLE_GUID)
        else {
            return Ok(None);
        };
        self.tree_at(entry.vendor_table as usize).map(Some)
    }

    fn configuration_table(&self, system_table: &SystemTable) -> &'static [ConfigurationTable] {
        let count = system_table.number_of_table_entries;
        if count == 0 {
            return &[];
        }
        let physical = system_table.configuration_table as usize;
        assert!(
            physical != 0,
            "EFI system table reports {count} configuration entries at a null address"
        );
        let array = physical
            .checked_add(self.physical_memory_offset)
            .expect("EFI configuration table virtual address overflow");
        let array_ptr = array as *const ConfigurationTable;
        assert!(
            array_ptr.is_aligned(),
            "EFI configuration table pointer {array:#x} is misaligned"
        );
        assert!(
            count
                .checked_mul(core::mem::size_of::<ConfigurationTable>())
                .is_some_and(|bytes| bytes <= isize::MAX as usize),
            "EFI configuration table byte length exceeds isize::MAX"
        );
        // SAFETY: base revision 5 and later map the configuration table
        // array as `RESERVED_MAPPED`, and the system table counts its
        // entries (UEFI 2.10, section 4.3); pointer validity, alignment,
        // and byte length were checked above, and nothing writes it.
        unsafe { core::slice::from_raw_parts(array_ptr, count) }
    }

    fn tree_at(&self, physical: usize) -> Result<FirmwareTree, FirmwareTreeError> {
        let address = physical as u64;
        let entry = self
            .memory_map
            .iter()
            .find(|entry| (entry.base..entry.base.saturating_add(entry.length)).contains(&address))
            .ok_or(FirmwareTreeError::OutsideMemoryMap { physical })?;
        if !FIRMWARE_TREE_MEMORY_TYPES.contains(&entry.type_) {
            return Err(FirmwareTreeError::MemoryType {
                physical,
                memory_type: entry.type_,
            });
        }
        let available = usize::try_from(entry.base.saturating_add(entry.length) - address)
            .ok()
            .filter(|&len| len <= isize::MAX as usize)
            .expect("EFI firmware tree memory-map slice length exceeds isize::MAX");
        let ptr = physical
            .checked_add(self.physical_memory_offset)
            .expect("EFI firmware tree virtual address overflow") as *const u8;
        // SAFETY: the bytes from `physical` to the end of its memory-map
        // entry are covered by the direct map, and the caller reserves the
        // returned physical range out of the bootstrap allocator before any
        // allocation runs.
        let bytes = unsafe { core::slice::from_raw_parts(ptr, available) };
        let malformed = |reason: FdtError| FirmwareTreeError::Malformed { physical, reason };
        let size = Fdt::new(bytes).map_err(malformed)?.total_size();
        let fdt = Fdt::new(&bytes[..size]).map_err(malformed)?;
        let end = physical
            .checked_add(size)
            .expect("EFI firmware tree physical range overflow");
        Ok(FirmwareTree {
            fdt,
            physical_range: physical..end,
        })
    }
}
