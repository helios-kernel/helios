//! Bring-up of the `IA32_PAT` table the user mappings' memory types
//! select from.
//!
//! The leaf encoding of each memory type is
//! [`helios_x86_vmm::memory_type`]'s; this module programs the one
//! entry that encoding needs changed from its power-up value (SDM Vol.
//! 3A Table 13-12 "Memory Type Setting of PAT Entries Following a
//! Power-up or Reset"), which a leaf selects with `PAT` alone.

use helios_x86_vmm::memory_type::WRITE_COMBINING_ENTRY;
use x86::msr::{IA32_PAT, rdmsr, wrmsr};

/// The memory-type encoding of write-combining in an `IA32_PAT` entry
/// (SDM Vol. 3A, Table 13-10 "Memory Types That Can Be Encoded With
/// PAT").
const PAT_TYPE_WRITE_COMBINING: u64 = 0x01;

/// Programs `IA32_PAT` entry [`WRITE_COMBINING_ENTRY`] to
/// write-combining on the calling processor, keeping every other entry
/// as it is.
///
/// Called once on every processor during its bring-up, before it can
/// run anything that maps device memory: the SDM requires every
/// processor to hold the same table (Vol. 3A §13.12.4 "Programming the
/// PAT"). No mapping selects entry 4 before this runs — nothing in this
/// backend sets the `PAT` bit before it — so no translation the
/// processor already caches changes memory type, which is what lets the
/// write skip the cache-disable procedure §13.11.8 prescribes for
/// changing a type that is in use.
pub(crate) fn program_page_attribute_table() {
    let shift = WRITE_COMBINING_ENTRY * 8;
    // SAFETY: `IA32_PAT` exists on every processor this backend boots
    // (PAT support is architectural on x86-64), and the only entry the
    // write changes is one no mapping selects yet.
    unsafe {
        let table = rdmsr(IA32_PAT);
        let table = (table & !(0xff << shift)) | (PAT_TYPE_WRITE_COMBINING << shift);
        wrmsr(IA32_PAT, table);
    }
}
