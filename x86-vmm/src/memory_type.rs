//! The memory types a user mapping of a device region takes.
//!
//! A 4 KiB leaf entry selects one of eight `IA32_PAT` entries with
//! `index = PAT << 2 | PCD << 1 | PWT` (Intel SDM Vol. 3A, Table 13-11
//! "Selection of PAT Entries with PAT, PCD, and PWT Flags"). The table
//! is the power-up value of SDM Vol. 3A Table 13-12 "Memory Type Setting
//! of PAT Entries Following a Power-up or Reset" with one change: entry
//! [`WRITE_COMBINING_ENTRY`] (`PAT` alone), which power-up makes a second
//! write-back entry, is programmed to write-combining on every processor
//! at bring-up by the backend. Every other entry keeps its power-up type
//! — entry 0 is write-back, and entry 3 (`PWT | PCD`) is uncacheable, the
//! encoding the kernel's own register-file mappings rely on — so nothing
//! that was mapped before the write changes type under it.

use helios_hal::device::{DeviceRegionAttributes, MemoryKind};
use x86_64::structures::paging::PageTableFlags;

/// The `PAT` bit of a 4 KiB leaf entry: bit 7, the position a
/// higher-level entry uses for its page-size flag (SDM Vol. 3A, Table
/// 4-20 "Format of a Page-Table Entry that Maps a 4-KByte Page"). The
/// `x86_64` crate names the position only by its page-size meaning.
const PAT_BIT: PageTableFlags = PageTableFlags::HUGE_PAGE;

/// The bits of a 4 KiB leaf entry that select the memory type: `PWT`,
/// `PCD` and `PAT`.
pub const MEMORY_TYPE_BITS: PageTableFlags = PageTableFlags::WRITE_THROUGH
    .union(PageTableFlags::NO_CACHE)
    .union(PAT_BIT);

/// The `IA32_PAT` entry write-combining is programmed into, and the
/// index a leaf selects it with: `PAT` set, `PCD` and `PWT` clear.
pub const WRITE_COMBINING_ENTRY: u32 = 4;

/// The `PWT`/`PCD`/`PAT` bits a region's kind calls for: none
/// (write-back) for memory the processor may treat as RAM, `PWT | PCD`
/// (uncacheable) for a register file, and `PAT` alone
/// (write-combining) for memory whose stores may merge.
const fn memory_type_flags(kind: MemoryKind) -> PageTableFlags {
    match kind {
        MemoryKind::Normal => PageTableFlags::empty(),
        MemoryKind::Device => PageTableFlags::WRITE_THROUGH.union(PageTableFlags::NO_CACHE),
        MemoryKind::WriteCombining => PAT_BIT,
    }
}

/// The leaf flags that show a device region: present, never executable,
/// writable only when the region is, and the region's memory type.
pub fn device_leaf_flags(attributes: DeviceRegionAttributes) -> PageTableFlags {
    let mut flags =
        PageTableFlags::PRESENT | PageTableFlags::NO_EXECUTE | memory_type_flags(attributes.kind);
    if attributes.writable {
        flags |= PageTableFlags::WRITABLE;
    }
    flags
}

#[cfg(test)]
mod tests {
    use super::*;

    const UNCACHEABLE: PageTableFlags =
        PageTableFlags::WRITE_THROUGH.union(PageTableFlags::NO_CACHE);

    #[test]
    fn read_only_register_file_is_uncacheable_and_not_writable() {
        assert_eq!(
            device_leaf_flags(DeviceRegionAttributes::READ_ONLY_REGISTERS),
            PageTableFlags::PRESENT | PageTableFlags::NO_EXECUTE | UNCACHEABLE
        );
    }

    #[test]
    fn writable_register_file_is_uncacheable_and_writable() {
        assert_eq!(
            device_leaf_flags(DeviceRegionAttributes::REGISTERS),
            PageTableFlags::PRESENT
                | PageTableFlags::NO_EXECUTE
                | PageTableFlags::WRITABLE
                | UNCACHEABLE
        );
    }

    #[test]
    fn prefetchable_memory_is_write_back() {
        assert_eq!(
            device_leaf_flags(DeviceRegionAttributes::PREFETCHABLE_MEMORY),
            PageTableFlags::PRESENT | PageTableFlags::NO_EXECUTE | PageTableFlags::WRITABLE
        );
    }

    /// Write-combining selects entry 4, the one bring-up programs: the
    /// `PAT` bit with `PCD` and `PWT` clear.
    #[test]
    fn write_combining_memory_selects_the_programmed_entry() {
        let flags = device_leaf_flags(DeviceRegionAttributes::WRITE_COMBINING_MEMORY);
        assert_eq!(
            flags,
            PageTableFlags::PRESENT
                | PageTableFlags::NO_EXECUTE
                | PageTableFlags::WRITABLE
                | PAT_BIT
        );
        let index = u32::from(flags.contains(PAT_BIT)) << 2
            | u32::from(flags.contains(PageTableFlags::NO_CACHE)) << 1
            | u32::from(flags.contains(PageTableFlags::WRITE_THROUGH));
        assert_eq!(index, WRITE_COMBINING_ENTRY);
    }

    /// Memory every access must reach uncached is mapped the way a
    /// register file is.
    #[test]
    fn uncached_memory_is_uncacheable() {
        assert_eq!(
            device_leaf_flags(DeviceRegionAttributes::UNCACHED_MEMORY),
            PageTableFlags::PRESENT
                | PageTableFlags::NO_EXECUTE
                | PageTableFlags::WRITABLE
                | UNCACHEABLE
        );
    }
}
