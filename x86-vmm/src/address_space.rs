//! x86_64 user virtual address space over a [`Machine`]'s page tables.
//!
//! The kernel's page tables map physical memory and the kernel image in
//! the higher half. The lower 128 TiB of the canonical address space is
//! otherwise unused, and a [`USER_VA_BASE`]..[`USER_VA_END`] window of it
//! is carved out for dynamic user mappings.
//!
//! Reservations are tracked in software in a [`ReservationTracker`];
//! commit / decommit / protect / release / swap walk the machine's root
//! table and mutate leaf entries through [`Machine::frame_pointer`].
//! Every translation change is invalidated on the executing processor
//! through [`Machine::invalidate_local`], and one that removes or narrows
//! a translation or clears accessed flags is broadcast to every other
//! processor through [`Machine::shootdown`] before an old frame goes back
//! to its pool.

use alloc::vec::Vec;
use core::alloc::Layout;
use core::mem::{align_of, size_of};
use core::ptr::{self, NonNull};
use core::sync::atomic::{AtomicU64, Ordering};

use helios_hal::device::{DeviceRegion, DmaPlacement};
use helios_hal::iommu::PhysicalRange;
use helios_hal::pmm::PhysFrame;
use helios_hal::vmm::{
    AddressSpace, AddressSpaceError, PageAge, PageFlags, SwapToken, Translation, VirtAddr,
    VirtRange,
};
use helios_kernel::{
    InstalledAddressSpace, MemoryOwner, ReservationLookup, ReservationTracker, SwapLeafFormat,
    SwapSpace, VaCursor, validate_range,
};
use spin::Mutex;
use x86_64::VirtAddr as X86VirtAddr;
use x86_64::structures::paging::page_table::PageTableIndex;
use x86_64::structures::paging::{Page, PageTable, PageTableFlags, Size4KiB};

use crate::memory_type;
use crate::{InstalledMachine, Machine};

/// Start of the user-VA window. `0x0000_2000_0000_0000` keeps the
/// canonical-address constraint satisfied (bits 47..63 must all be
/// zero or all one for x86-64 four-level paging) and stays well clear
/// of the user 0..2 TiB region typical userland tools assume.
pub const USER_VA_BASE: usize = 0x0000_2000_0000_0000;
/// 32 TiB user window — enough for ~6500 4 GiB+guard wasm linear
/// memories, far beyond what realistic kernel-plugin loads will hold
/// concurrently.
pub const USER_VA_END: usize = 0x0000_4000_0000_0000;
const PAGE: usize = PhysFrame::SIZE;
/// Bytes one level-1 table maps: 512 four-kilobyte pages.
const LEAF_TABLE_SPAN: usize = PAGE * 512;
/// Physical-address field of a 4-level x86-64 page-table entry (bits 12..52;
/// Intel SDM Vol. 3A, Tables 4-15, 4-17, and 4-18).
const ENTRY_ADDR_MASK: u64 = 0x000f_ffff_ffff_f000;

/// A leaf an unmap has retired but whose frame is not yet free.
///
/// The first pass of [`X86UserAddressSpace::unmap_range`] clears
/// `PRESENT` and sets this bit, keeping the frame address in the leaf;
/// the shootdown goes out once for the whole range; the second pass
/// reads the frame back out of every leaf so marked and frees it. The
/// bit is one of the three the architecture leaves to software.
const RETIRED: PageTableFlags = PageTableFlags::BIT_9;

/// Software marker identifying a not-present leaf that carries a swap token.
///
/// Disjoint from `PRESENT` (bit 0), hardware `ACCESSED` / `DIRTY` (bits 5/6),
/// and [`RETIRED`] (bit 9). The 32-bit [`SwapToken`] is stored bitwise
/// inverted in the PFN field (bits 12..52) so its upper PFN bits are all ones
/// and a not-present swap entry never names frame 0 or low physical RAM
/// (L1TF mitigation).
const SWAP_MARKER: u64 = PageTableFlags::BIT_10.bits();
const SWAP_TOKEN_SHIFT: u32 = 12;

/// Bits of a present leaf preserved across a permission-only `protect`:
/// physical address, PAT/PCD/PWT memory type, and hardware accessed/dirty bits.
const PROTECT_PRESERVED_MASK: u64 = ENTRY_ADDR_MASK
    | memory_type::MEMORY_TYPE_BITS.bits()
    | PageTableFlags::ACCESSED.bits()
    | PageTableFlags::DIRTY.bits();

const _: () = {
    assert!(size_of::<PageTable>() == 512 * size_of::<u64>());
    assert!(align_of::<PageTable>() >= align_of::<AtomicU64>());
    assert!(SWAP_MARKER & PageTableFlags::PRESENT.bits() == 0);
    assert!(SWAP_MARKER & PageTableFlags::ACCESSED.bits() == 0);
    assert!(SWAP_MARKER & PageTableFlags::DIRTY.bits() == 0);
    assert!(SWAP_MARKER & RETIRED.bits() == 0);
    assert!(SWAP_MARKER & ENTRY_ADDR_MASK == 0);
};

const fn swap_leaf_entry(token: SwapToken) -> u64 {
    let inverted = (!(token.raw() as u64) << SWAP_TOKEN_SHIFT) & ENTRY_ADDR_MASK;
    SWAP_MARKER | inverted
}

fn swap_entry_token(entry: u64) -> Option<SwapToken> {
    if entry & PageTableFlags::PRESENT.bits() != 0 || entry & SWAP_MARKER == 0 {
        return None;
    }
    let inverted = (entry & ENTRY_ADDR_MASK) >> SWAP_TOKEN_SHIFT;
    SwapToken::new((!inverted) as u32)
}

/// Owned x86 user address space over the page tables of machine `M`.
///
/// # Concurrency contract
///
/// `state` is the one lock that serialises every mutation of this
/// address space's page-table structure, and the reservation records it
/// guards. A path that can build an intermediate table (`commit`,
/// `prepare_demand_commit`, `ensure_accessible_subranges`), rewrite a
/// leaf of a committed range (`protect`, `relocate`, `substitute_memory`,
/// `substitute_device`, `restore`, `withdraw`, `swap_out_page`,
/// `swap_in_page`, `scan_committed_pages`), or clear the leaves of a
/// range it takes out of the tracker (`decommit`, `release`,
/// `end_demand_commit`, `decommit_committed_subranges`), takes `state`
/// before its first check and holds it through its last table access and
/// the matching tracker record; for the clearing paths that is from the
/// tracker update through the last leaf cleared, the shootdown and the
/// frames freed behind it (and, for `release`, the return of the range to
/// the free list). No helper it calls takes `state` again.
///
/// `state` is a plain spin lock taken from task context with interrupts
/// enabled and never from an interrupt or trap handler, so a processor
/// spinning on it still acknowledges TLB shootdowns. Holding it across
/// a shootdown is the existing order (`state` then the broadcast lock).
/// Lock order against [`SwapSpace`] is `state` then `swap`'s orphan list;
/// `drain_orphaned_swap_tokens` takes only the orphan list. Nothing
/// awaits or blocks while holding `state`: the frame and table
/// allocations under it take the machine's pools, whose interrupt-masking
/// locks nothing holds across `state`.
///
/// Not under `state`: `swapped_token`, `commit_demand_page`, and
/// `leaf_entry` walk tables lock-free via atomic entry loads and raw
/// `*mut AtomicU64` pointers (no `&mut PageTable` is ever formed), which
/// is sound because no intermediate table is freed while the address
/// space lives, intermediate entries are published with `Release` stores,
/// and `commit_demand_page` writes only a leaf in a prepared
/// demand-commit region that only its fiber faults on; and `allocate_run`
/// and `free_run`, which change no translation. `translate` holds `state`
/// across both its tracker lookup and its table walk.
pub struct X86UserAddressSpace<M> {
    machine: M,
    processor_count: usize,
    /// Bump pointer for fresh reservations within the user-VA window.
    /// Reservations released via `release` are returned to a free
    /// list rather than to the bump pointer; the simple bump path
    /// covers the steady-state allocate-and-release-much-later
    /// pattern that the runtime drives, while the free list catches
    /// tight reservation churn.
    va_cursor: VaCursor,
    state: Mutex<ReservationTracker>,
    /// Shared swap bookkeeping: swap-out ordering, frame lifecycle,
    /// rollback, orphan queue, and ageing walk. This backend supplies the
    /// x86-64 leaf encoding and TLB invalidation via [`SwapLeafFormat`].
    swap: SwapSpace,
}

#[derive(Clone, Copy)]
struct RelocationPage {
    leaf: *mut AtomicU64,
    virt: usize,
    old_phys: usize,
    old_flags: u64,
    new_phys: usize,
}

impl<M: Machine> X86UserAddressSpace<M> {
    pub fn new(machine: M, processor_count: usize) -> Self {
        Self {
            machine,
            processor_count,
            va_cursor: VaCursor::new(USER_VA_BASE, USER_VA_END),
            state: Mutex::new(ReservationTracker::new()),
            swap: SwapSpace::new(),
        }
    }

    /// Where `frame` appears in the kernel's own map.
    ///
    /// The pinned runs `allocate_run` hands out are reached through the
    /// machine's physical-memory window, so the alias is that window's
    /// pointer for the frame.
    pub fn kernel_alias(&self, frame: PhysFrame) -> VirtAddr {
        VirtAddr::new(self.machine.frame_pointer(frame.phys_addr()) as usize)
    }

    fn assert_smp_safe(&self) {
        assert!(
            self.processor_count <= usize::BITS as usize,
            "X86UserAddressSpace supports at most {} processors in its TLB shootdown ack mask; got {}",
            usize::BITS,
            self.processor_count
        );
    }

    /// Invalidates `virt` on this processor and then on every other one.
    fn invalidate_everywhere(&self, virt: VirtRange) {
        self.machine.invalidate_local(virt);
        self.machine.shootdown(virt);
    }

    /// Give one pinned run back to the user pool with the layout it was
    /// allocated with: a contiguous run is one allocation, not a pile of
    /// frames, and the allocator is owed the size and alignment it
    /// produced.
    fn free_pinned_run(&self, phys: usize, bytes: usize, align: usize) {
        let layout = Layout::from_size_align(bytes, align)
            .unwrap_or_else(|_| panic!("x86 pinned run has an invalid layout"));
        self.machine.free_run(phys, layout);
    }

    fn carve_reservation(&self, byte_len: usize) -> Option<VirtRange> {
        self.state
            .lock()
            .reuse_free_range(byte_len)
            .or_else(|| self.va_cursor.carve(byte_len))
    }

    /// The level-4 table of the address space this processor is running
    /// in, as a raw pointer through the machine's window.
    fn level_4_table(&self) -> *mut PageTable {
        self.table_at(self.machine.root_table().start_address().as_u64() as usize)
    }

    /// The table at physical address `phys`, through the machine's
    /// window.
    fn table_at(&self, phys: usize) -> *mut PageTable {
        self.machine.frame_pointer(phys).cast()
    }

    /// The table `table[index]` points at, building it when the entry
    /// is unused.
    ///
    /// The caller holds `state` (see the type's concurrency contract),
    /// so no other processor is editing this walk. Intermediate entries
    /// are present and writable and never carry `NO_EXECUTE`: the
    /// permission that matters is the leaf's, and clearing execute on a
    /// parent would take it away from every mapping below it, compiled
    /// code included.
    fn ensure_table(
        &self,
        table: *mut PageTable,
        index: PageTableIndex,
    ) -> Result<*mut PageTable, AddressSpaceError> {
        let slot = usize::from(index);
        // SAFETY: `table` is a live 4 KiB-aligned page table of 512 8-byte
        // entries reached through the machine's window, and `PageTableIndex`
        // is guaranteed `< 512`.
        let entry_ptr = unsafe { table.cast::<AtomicU64>().add(slot) };
        // SAFETY: `entry_ptr` points to a live, 8-byte-aligned page-table
        // entry that is never freed while the address space lives.
        let entry = unsafe { &*entry_ptr };
        let mut raw = entry.load(Ordering::Acquire);
        if raw == 0 {
            let frame = self
                .machine
                .allocate_table()
                .ok_or(AddressSpaceError::PageTableExhausted)?;
            raw = frame.start_address().as_u64()
                | (PageTableFlags::PRESENT | PageTableFlags::WRITABLE).bits();
            // Publish the freshly zeroed child table before any lock-free
            // `leaf_entry` walk can follow this entry.
            entry.store(raw, Ordering::Release);
        }
        assert!(
            !PageTableFlags::from_bits_truncate(raw).contains(PageTableFlags::HUGE_PAGE),
            "x86 user-VA walk hit a huge page where a table was expected"
        );
        Ok(self.table_at((raw & ENTRY_ADDR_MASK) as usize))
    }

    /// Builds any missing intermediate tables for `virt` and returns the
    /// leaf slot pointer. Caller holds `state`.
    fn ensure_leaf_entry(&self, virt: usize) -> Result<*mut AtomicU64, AddressSpaceError> {
        let page = Page::<Size4KiB>::containing_address(X86VirtAddr::new(virt as u64));
        let p4 = self.level_4_table();
        let p3 = self.ensure_table(p4, page.p4_index())?;
        let p2 = self.ensure_table(p3, page.p3_index())?;
        let p1 = self.ensure_table(p2, page.p2_index())?;
        let leaf_slot = usize::from(page.p1_index());
        // SAFETY: `p1` is a live 4 KiB-aligned level-1 page table of 512
        // 8-byte entries and `leaf_slot < 512`.
        let leaf = unsafe { p1.cast::<AtomicU64>().add(leaf_slot) };
        Ok(leaf)
    }

    /// The leaf entry for `virt`, or `None` when the walk runs into a
    /// level that was never built.
    ///
    /// Lock-free by construction: no table below the user window is ever
    /// freed while the address space lives, intermediate entries are
    /// published with `Release` stores, and raw `*mut AtomicU64` pointers
    /// avoid forming `&mut PageTable` over sibling slots.
    fn leaf_entry(&self, virt: usize) -> Option<*mut AtomicU64> {
        let page = Page::<Size4KiB>::containing_address(X86VirtAddr::new(virt as u64));
        let mut table = self.level_4_table();
        for index in [page.p4_index(), page.p3_index(), page.p2_index()] {
            let slot = usize::from(index);
            // SAFETY: `table` is a live 4 KiB-aligned page table of 512 8-byte
            // entries in the machine's window, and `slot < 512`.
            let entry_ptr = unsafe { table.cast::<AtomicU64>().add(slot) };
            // SAFETY: `entry_ptr` points to a live, 8-byte-aligned entry that
            // is never freed while the address space lives; `Acquire` pairs
            // with `ensure_table`'s `Release` store.
            let raw = unsafe { &*entry_ptr }.load(Ordering::Acquire);
            if raw == 0 {
                return None;
            }
            assert!(
                !PageTableFlags::from_bits_truncate(raw).contains(PageTableFlags::HUGE_PAGE),
                "x86 user VA {virt:#x} resolves through a huge page"
            );
            table = self.table_at((raw & ENTRY_ADDR_MASK) as usize);
        }
        let leaf_slot = usize::from(page.p1_index());
        // SAFETY: `table` is the live level-1 page table of 512 entries for
        // this address and `leaf_slot < 512`; computing the element pointer
        // directly avoids forming `&mut PageTable` over sibling slots.
        let leaf = unsafe { table.cast::<AtomicU64>().add(leaf_slot) };
        Some(leaf)
    }

    fn map_pages(&self, virt: VirtRange, flags: PageTableFlags) -> Result<(), AddressSpaceError> {
        let flag_bits = flags.bits();
        for offset in (0..virt.byte_len).step_by(PAGE) {
            let virt_addr = virt.start.raw() + offset;
            let mapped_pages = offset / PAGE;
            let phys = match self.machine.allocate_frame() {
                Ok(phys) => phys,
                Err(error) => {
                    self.rollback_partial_commit(virt.start.raw(), mapped_pages);
                    return Err(error);
                }
            };
            let phys_u64 = phys as u64;
            if !phys.is_multiple_of(PAGE) || phys_u64 & !ENTRY_ADDR_MASK != 0 {
                self.machine.free_frame(phys);
                self.rollback_partial_commit(virt.start.raw(), mapped_pages);
                return Err(AddressSpaceError::Misaligned);
            }
            let leaf_ptr = match self.ensure_leaf_entry(virt_addr) {
                Ok(leaf) => leaf,
                Err(error) => {
                    self.machine.free_frame(phys);
                    self.rollback_partial_commit(virt.start.raw(), mapped_pages);
                    return Err(error);
                }
            };
            // SAFETY: `leaf_ptr` points to a live aligned leaf slot in a
            // reserved, uncommitted range owned under `state`.
            let leaf = unsafe { &*leaf_ptr };
            if leaf.load(Ordering::Acquire) != 0 {
                self.machine.free_frame(phys);
                self.rollback_partial_commit(virt.start.raw(), mapped_pages);
                return Err(AddressSpaceError::Overlap);
            }
            leaf.store(phys_u64 | flag_bits, Ordering::Release);
            self.machine
                .invalidate_local(VirtRange::new(VirtAddr::new(virt_addr), PAGE));
        }
        Ok(())
    }

    /// Unmaps every mapped page of `virt`, one shootdown for the whole
    /// range, and frees the frames on the far side of it.
    ///
    /// A frame must not be reusable while another processor can still
    /// translate to it, and a leaf's local invalidation reaches the
    /// calling processor only, so the frames wait for the acknowledgement
    /// of the broadcast. Rather than holding them in a batch and
    /// broadcasting once per batch — one IPI round per 128 pages, so a
    /// linear memory's teardown was hundreds of rounds — the leaves
    /// themselves hold them: the first pass retires each leaf (`PRESENT`
    /// off, [`RETIRED`] on, frame kept), one broadcast covers the range,
    /// and the second pass frees what the retired leaves name. Pages that
    /// were never mapped (or whose swap leaves were already cleared) are
    /// left alone, which is what the runtime's imprecise decommit of a
    /// pooled slot and a demand-commit region nothing faulted on both
    /// need.
    fn unmap_range(&self, virt: VirtRange) {
        let mut retired = 0;
        for offset in (0..virt.byte_len).step_by(PAGE) {
            let virt_addr = virt.start.raw() + offset;
            let Some(entry_ptr) = self.leaf_entry(virt_addr) else {
                continue;
            };
            // SAFETY: the pointer came from a completed walk of live
            // tables, and the caller owns the range under `state`.
            let entry = unsafe { &*entry_ptr };
            let raw = entry.load(Ordering::Acquire);
            if raw == 0 {
                continue;
            }
            assert!(
                raw & PageTableFlags::PRESENT.bits() != 0,
                "x86 user page {virt_addr:#x} was not present during unmap (raw={raw:#x})"
            );
            let retired_raw = (raw & !PageTableFlags::PRESENT.bits()) | RETIRED.bits();
            entry.store(retired_raw, Ordering::Release);
            retired += 1;
        }
        if retired == 0 {
            return;
        }
        self.invalidate_everywhere(virt);
        for offset in (0..virt.byte_len).step_by(PAGE) {
            let virt_addr = virt.start.raw() + offset;
            let Some(entry_ptr) = self.leaf_entry(virt_addr) else {
                continue;
            };
            // SAFETY: as above.
            let entry = unsafe { &*entry_ptr };
            let raw = entry.load(Ordering::Acquire);
            if raw & RETIRED.bits() == 0 {
                continue;
            }
            let phys = (raw & ENTRY_ADDR_MASK) as usize;
            entry.store(0, Ordering::Release);
            self.machine.free_frame(phys);
        }
    }

    fn protect_pages(
        &self,
        virt: VirtRange,
        flags: PageTableFlags,
    ) -> Result<(), AddressSpaceError> {
        let new_perms = flags.bits();
        let mut old_perms = Vec::new();
        for offset in (0..virt.byte_len).step_by(PAGE) {
            let virt_addr = virt.start.raw() + offset;
            let Some(leaf_ptr) = self.leaf_entry(virt_addr) else {
                self.rollback_partial_protect(&old_perms);
                return Err(AddressSpaceError::NotCommitted);
            };
            // SAFETY: the pointer came from a completed walk of live tables,
            // and the caller holds `state`.
            let leaf = unsafe { &*leaf_ptr };
            let mut raw = leaf.load(Ordering::Acquire);
            let previous_perms = loop {
                if raw & PageTableFlags::PRESENT.bits() == 0 {
                    self.rollback_partial_protect(&old_perms);
                    return Err(AddressSpaceError::NotCommitted);
                }
                // Preserve physical address, PAT/PCD/PWT memory type (for
                // substituted device regions), and concurrent hardware A/D
                // updates via compare-exchange.
                let updated = (raw & PROTECT_PRESERVED_MASK) | new_perms;
                match leaf.compare_exchange_weak(raw, updated, Ordering::AcqRel, Ordering::Acquire)
                {
                    Ok(_) => break raw & !PROTECT_PRESERVED_MASK,
                    Err(observed) => raw = observed,
                }
            };
            self.machine
                .invalidate_local(VirtRange::new(VirtAddr::new(virt_addr), PAGE));
            old_perms.push((virt_addr, leaf_ptr, previous_perms));
        }
        Ok(())
    }

    /// Restores the permission bits a failed `protect_pages` had already
    /// changed.
    ///
    /// The pages briefly carried the new flags, and another processor may
    /// have translated one in that window, so the restored range is shot
    /// down the way the success path is: a stale narrower translation is
    /// a spurious fault on a page the tracker says is committed, and a
    /// stale wider one is a permission the caller withdrew.
    fn rollback_partial_protect(&self, old_perms: &[(usize, *mut AtomicU64, u64)]) {
        for &(virt_addr, leaf_ptr, previous_perms) in old_perms.iter().rev() {
            // SAFETY: `protect_pages` updated this mapped leaf a moment ago
            // under the same `state`.
            let leaf = unsafe { &*leaf_ptr };
            let mut raw = leaf.load(Ordering::Acquire);
            loop {
                assert!(
                    raw & PageTableFlags::PRESENT.bits() != 0,
                    "x86 AddressSpace::protect rollback lost present bit at {virt_addr:#x}"
                );
                let restored = (raw & PROTECT_PRESERVED_MASK) | previous_perms;
                match leaf.compare_exchange_weak(raw, restored, Ordering::AcqRel, Ordering::Acquire)
                {
                    Ok(_) => break,
                    Err(observed) => raw = observed,
                }
            }
            self.machine
                .invalidate_local(VirtRange::new(VirtAddr::new(virt_addr), PAGE));
        }
        if let (Some(&(first, _, _)), Some(&(last, _, _))) = (old_perms.first(), old_perms.last()) {
            self.machine
                .shootdown(VirtRange::new(VirtAddr::new(first), last - first + PAGE));
        }
    }

    /// Walks every page of `virt`, unmapping the ones a demand commit
    /// mapped and leaving the ones nothing faulted on alone.
    fn unmap_demand_pages(&self, virt: VirtRange) {
        self.unmap_range(virt);
    }

    fn build_relocation_plan(
        &self,
        virt: VirtRange,
    ) -> Result<Vec<RelocationPage>, AddressSpaceError> {
        let mut pages: Vec<RelocationPage> = Vec::new();
        for offset in (0..virt.byte_len).step_by(PAGE) {
            let virt_addr = virt.start.raw() + offset;
            let Some(leaf_ptr) = self.leaf_entry(virt_addr) else {
                for page in pages {
                    self.machine.free_frame(page.new_phys);
                }
                return Err(AddressSpaceError::NotCommitted);
            };
            // SAFETY: `leaf_entry` walked live tables and `state` is held.
            let raw = unsafe { &*leaf_ptr }.load(Ordering::Acquire);
            if raw & PageTableFlags::PRESENT.bits() == 0 {
                for page in pages {
                    self.machine.free_frame(page.new_phys);
                }
                return Err(AddressSpaceError::NotCommitted);
            }
            let old_phys = (raw & ENTRY_ADDR_MASK) as usize;
            let old_flags = raw & !ENTRY_ADDR_MASK;
            // A replacement from the node the old frame is on: a
            // relocation that moved the page to another node would undo
            // its placement.
            let new_phys = match self.machine.allocate_frame_beside(old_phys) {
                Ok(phys) => phys,
                Err(error) => {
                    for page in pages {
                        self.machine.free_frame(page.new_phys);
                    }
                    return Err(error);
                }
            };
            if !new_phys.is_multiple_of(PAGE) || (new_phys as u64) & !ENTRY_ADDR_MASK != 0 {
                self.machine.free_frame(new_phys);
                for page in pages {
                    self.machine.free_frame(page.new_phys);
                }
                return Err(AddressSpaceError::Misaligned);
            }
            // SAFETY: both frames are reached through the machine's
            // window, the old one is mapped in a range the caller holds
            // `state` over and the new one is fresh.
            unsafe {
                ptr::copy_nonoverlapping(
                    self.machine.frame_pointer(old_phys) as *const u8,
                    self.machine.frame_pointer(new_phys),
                    PAGE,
                );
            }
            pages.push(RelocationPage {
                leaf: leaf_ptr,
                virt: virt_addr,
                old_phys,
                old_flags,
                new_phys,
            });
        }
        Ok(pages)
    }

    fn rollback_partial_commit(&self, start: usize, mapped_pages: usize) {
        if mapped_pages == 0 {
            return;
        }
        self.unmap_range(VirtRange::new(VirtAddr::new(start), mapped_pages * PAGE));
    }

    /// The leaf entry of every page of `virt`, when every one of them is
    /// present. Nothing is changed.
    fn present_leaves(&self, virt: VirtRange) -> Result<Vec<*mut AtomicU64>, AddressSpaceError> {
        let mut leaves = Vec::with_capacity(virt.byte_len / PAGE);
        for offset in (0..virt.byte_len).step_by(PAGE) {
            let leaf = self
                .leaf_entry(virt.start.raw() + offset)
                .ok_or(AddressSpaceError::NotCommitted)?;
            // SAFETY: the pointer came from a completed walk of live
            // tables, and the caller holds `state`.
            let raw = unsafe { &*leaf }.load(Ordering::Acquire);
            if raw & PageTableFlags::PRESENT.bits() == 0 {
                return Err(AddressSpaceError::NotCommitted);
            }
            leaves.push(leaf);
        }
        Ok(leaves)
    }

    /// The leaf entry of every page of `virt`, when every one of them is
    /// present or holds a swap entry: a page the swap policy evicted has
    /// no frame, and substitution takes it like a resident one. Nothing is
    /// changed.
    fn substitutable_leaves(
        &self,
        virt: VirtRange,
    ) -> Result<Vec<*mut AtomicU64>, AddressSpaceError> {
        let mut leaves = Vec::with_capacity(virt.byte_len / PAGE);
        for offset in (0..virt.byte_len).step_by(PAGE) {
            let leaf = self
                .leaf_entry(virt.start.raw() + offset)
                .ok_or(AddressSpaceError::NotCommitted)?;
            // SAFETY: the pointer came from a completed walk of live
            // tables, and the caller holds `state`.
            let raw = unsafe { &*leaf }.load(Ordering::Acquire);
            if raw & PageTableFlags::PRESENT.bits() == 0 && swap_entry_token(raw).is_none() {
                return Err(AddressSpaceError::NotCommitted);
            }
            leaves.push(leaf);
        }
        Ok(leaves)
    }

    /// Show the physical bytes from `phys` at `virt` with `pt_flags`, in
    /// place of the pool frames or swap entries that are there.
    ///
    /// The reservation lock is held from the check that `virt` is
    /// committed or swapped out and unsubstituted, across every leaf
    /// rewrite and the shootdown, to the bookkeeping that marks it. Each
    /// leaf goes from its old entry to the new present entry in a single
    /// store, old pool frames are freed only after the shootdown has been
    /// acknowledged, and any replaced swap entries have their tokens
    /// queued for release.
    fn substitute_leaves(
        &self,
        virt: VirtRange,
        phys: usize,
        pt_flags: PageTableFlags,
    ) -> Result<(), AddressSpaceError> {
        let mut state = self.state.lock();
        state.check_substitutable(virt)?;
        let leaves = self.substitutable_leaves(virt)?;
        let mut replaced = Vec::with_capacity(leaves.len());
        let flag_bits = (pt_flags | PageTableFlags::ACCESSED).bits();
        for (index, leaf) in leaves.into_iter().enumerate() {
            // SAFETY: `substitutable_leaves` walked live tables for this
            // range, and `state` is held.
            let entry = unsafe { &*leaf };
            let old = entry.load(Ordering::Acquire);
            if old & PageTableFlags::PRESENT.bits() != 0 {
                replaced.push((old & ENTRY_ADDR_MASK) as usize);
            }
            let new_phys = (phys + index * PAGE) as u64;
            entry.store((new_phys & ENTRY_ADDR_MASK) | flag_bits, Ordering::Release);
        }
        if replaced.is_empty() {
            self.machine.invalidate_local(virt);
        } else {
            self.invalidate_everywhere(virt);
            for old in replaced {
                self.machine.free_frame(old);
            }
        }
        // Swapped-out leaves now carry the substitution's present entries,
        // which `discard` leaves alone; it only queues their tokens.
        self.swap.discard(self, state.record_substitute(virt)?);
        Ok(())
    }

    /// Drop the leaves of a substituted range, freeing no frame, and
    /// shoot the range down on every processor before returning.
    ///
    /// The frames behind a substitution belong to the run's owner, so
    /// this is the unmap [`Self::unmap_range`] must never be allowed to
    /// do to them. Pages with no leaf are left alone.
    fn drop_substituted_leaves(&self, virt: VirtRange) {
        let mut dropped = false;
        for offset in (0..virt.byte_len).step_by(PAGE) {
            let Some(leaf) = self.leaf_entry(virt.start.raw() + offset) else {
                continue;
            };
            // SAFETY: as in `unmap_range`: the caller owns the range
            // under `state`.
            let entry = unsafe { &*leaf };
            if entry.load(Ordering::Acquire) != 0 {
                entry.store(0, Ordering::Release);
                dropped = true;
            }
        }
        if dropped {
            self.invalidate_everywhere(virt);
        }
    }

    /// [`Self::drop_substituted_leaves`] for each part a tracker
    /// reported, to run before the rest of the range is unmapped.
    fn drop_substituted_parts(&self, parts: &[VirtRange]) {
        for part in parts {
            self.drop_substituted_leaves(*part);
        }
    }

    /// Maps fresh frames under `virt` while holding `state`.
    ///
    /// No shootdown goes out: every page here was not present a moment
    /// ago, x86-64 caches no not-present translation, and every path
    /// that unmaps or detaches a page broadcasts before its frame is
    /// freed.
    fn commit_locked(
        &self,
        state: &mut ReservationTracker,
        virt: VirtRange,
        flags: PageFlags,
    ) -> Result<(), AddressSpaceError> {
        let pt_flags = page_flags_to_pt(flags)? | PageTableFlags::ACCESSED;
        state.precheck_commit(virt)?;
        // Committing over a swapped-out page throws its contents away:
        // clearing the swap leaf is what `map_pages` expects, and the
        // backing extent still has to be given back.
        self.swap.discard(self, state.take_swap_entries_in(virt));
        self.map_pages(virt, pt_flags)?;
        let owner = self.machine.current_owner();
        self.swap
            .discard(self, state.record_commit(virt, flags, owner)?);
        Ok(())
    }

    fn protect_locked(
        &self,
        state: &mut ReservationTracker,
        virt: VirtRange,
        flags: PageFlags,
    ) -> Result<(), AddressSpaceError> {
        let pt_flags = page_flags_to_pt(flags)?;
        state.ensure_committed(virt)?;
        self.protect_pages(virt, pt_flags)?;
        self.machine.shootdown(virt);
        state.record_protect(virt, flags)?;
        Ok(())
    }

    /// Decommit only the parts of `range` that are actually committed or
    /// swapped out.
    ///
    /// The runtime resets a pooled slot by asking for a range whose committed
    /// extent it does not track precisely, so a whole-range decommit would
    /// fail on the first uncommitted page. A substitution inside the range
    /// is dropped without freeing the run's frames, as a withdraw would.
    pub fn decommit_committed_subranges(&self, range: VirtRange) -> Result<(), AddressSpaceError> {
        self.assert_smp_safe();
        validate_range(range)?;
        let mut state = self.state.lock();
        self.swap.discard(self, state.take_swap_entries_in(range));
        let removal = state.take_committed_intersections(range)?;
        self.drop_substituted_parts(&removal.substituted);
        for subrange in removal.ranges {
            self.unmap_range(subrange);
        }
        Ok(())
    }

    /// Give `range` `flags`, committing the parts of it that are not
    /// committed yet and re-protecting the parts that are.
    pub fn ensure_accessible_subranges(
        &self,
        range: VirtRange,
        flags: PageFlags,
    ) -> Result<(), AddressSpaceError> {
        self.assert_smp_safe();
        validate_range(range)?;
        let mut state = self.state.lock();
        let plan = state.accessibility_plan(range)?;
        for subrange in plan.protect {
            self.protect_locked(&mut state, subrange, flags)?;
        }
        for subrange in plan.commit {
            self.commit_locked(&mut state, subrange, flags)?;
        }
        Ok(())
    }
}

/// The four-level x86-64 leaf encoding swap works through.
///
/// A swap entry has `PRESENT` clear, [`SWAP_MARKER`] (`BIT_10`, disjoint
/// from [`RETIRED`] and from A/D) set, and the 32-bit [`SwapToken`] stored
/// bitwise inverted in the PFN field (bits 12..52) so its upper address
/// bits stay all ones and a speculative L1TF walk never addresses frame 0
/// or low physical memory.
impl<M: Machine> SwapLeafFormat for X86UserAddressSpace<M> {
    fn swapped_token(&self, addr: VirtAddr) -> Option<SwapToken> {
        let virt = addr.page_floor().raw();
        if !(USER_VA_BASE..USER_VA_END).contains(&virt) {
            return None;
        }
        let entry_ptr = self.leaf_entry(virt)?;
        // SAFETY: `leaf_entry` walked live tables that are never freed
        // while the address space lives to an aligned 8-byte leaf slot.
        let raw = unsafe { &*entry_ptr }.load(Ordering::Acquire);
        swap_entry_token(raw)
    }

    fn detach(
        &self,
        _tracker: &ReservationTracker,
        addr: VirtAddr,
        token: SwapToken,
    ) -> Result<NonNull<u8>, AddressSpaceError> {
        let virt = addr.raw();
        let entry_ptr = self
            .leaf_entry(virt)
            .ok_or(AddressSpaceError::NotCommitted)?;
        // SAFETY: `leaf_entry` walked live tables and the caller holds `state`.
        let entry = unsafe { &*entry_ptr };
        let raw = entry.load(Ordering::Acquire);
        if raw & PageTableFlags::PRESENT.bits() == 0 {
            return Err(AddressSpaceError::NotCommitted);
        }
        let phys = (raw & ENTRY_ADDR_MASK) as usize;
        entry.store(swap_leaf_entry(token), Ordering::Release);
        self.invalidate_everywhere(VirtRange::new(addr, PAGE));
        Ok(
            NonNull::new(self.machine.frame_pointer(phys)).unwrap_or_else(|| {
                panic!("x86 swap-out found a null kernel pointer for physical frame {phys:#x}")
            }),
        )
    }

    fn attach(
        &self,
        _tracker: &ReservationTracker,
        addr: VirtAddr,
        expected: SwapToken,
        frame: NonNull<u8>,
        flags: PageFlags,
    ) -> Result<(), AddressSpaceError> {
        let pt_flags = page_flags_to_pt(flags)? | PageTableFlags::ACCESSED;
        let entry_ptr = self
            .leaf_entry(addr.raw())
            .ok_or(AddressSpaceError::NotSwapped)?;
        // SAFETY: `leaf_entry` walked live tables and the caller holds `state`.
        let entry = unsafe { &*entry_ptr };
        if swap_entry_token(entry.load(Ordering::Acquire)) != Some(expected) {
            return Err(AddressSpaceError::NotSwapped);
        }
        let phys = self
            .machine
            .physical_address(frame)
            .ok_or(AddressSpaceError::Misaligned)?;
        let phys_u64 = phys as u64;
        if !phys.is_multiple_of(PAGE) || phys_u64 & !ENTRY_ADDR_MASK != 0 {
            return Err(AddressSpaceError::Misaligned);
        }
        entry.store(phys_u64 | pt_flags.bits(), Ordering::Release);
        // Not-present to present needs no remote shootdown; invalidate
        // locally in case this processor speculatively cached the entry.
        self.machine.invalidate_local(VirtRange::new(addr, PAGE));
        Ok(())
    }

    fn clear_swapped(&self, addr: VirtAddr) {
        let Some(entry_ptr) = self.leaf_entry(addr.raw()) else {
            return;
        };
        // SAFETY: `leaf_entry` walked live tables and the caller holds `state`.
        let entry = unsafe { &*entry_ptr };
        if swap_entry_token(entry.load(Ordering::Acquire)).is_some() {
            entry.store(0, Ordering::Release);
        }
    }

    fn test_and_clear_accessed(&self, addr: VirtAddr) -> Option<PageAge> {
        let entry_ptr = self.leaf_entry(addr.raw())?;
        // SAFETY: `leaf_entry` walked live tables and the caller holds `state`.
        let entry = unsafe { &*entry_ptr };
        let current = entry.load(Ordering::Acquire);
        if current & PageTableFlags::PRESENT.bits() == 0 {
            return None;
        }
        // The caller holds `state`, so no other software writer can replace
        // or unmap this leaf. Hardware may concurrently set `ACCESSED` or
        // `DIRTY`; an atomic AND clears only `ACCESSED` without losing
        // `DIRTY`.
        let previous = entry.fetch_and(!PageTableFlags::ACCESSED.bits(), Ordering::AcqRel);
        Some(if previous & PageTableFlags::ACCESSED.bits() != 0 {
            PageAge::Hot
        } else {
            PageAge::Cold
        })
    }

    fn accessed_cleared(&self, start: VirtAddr, pages: usize) {
        if pages == 0 {
            return;
        }
        self.invalidate_everywhere(VirtRange::new(start, pages * PAGE));
    }
}

impl<M: Machine> AddressSpace for X86UserAddressSpace<M> {
    fn reserve(&self, byte_len: usize) -> Result<VirtRange, AddressSpaceError> {
        if byte_len == 0 {
            return Err(AddressSpaceError::EmptyRange);
        }
        if !byte_len.is_multiple_of(PAGE) {
            return Err(AddressSpaceError::Misaligned);
        }
        let range = self
            .carve_reservation(byte_len)
            .ok_or(AddressSpaceError::OutOfFrames)?;
        self.state.lock().reserve(range);
        Ok(range)
    }

    fn release(&self, virt: VirtRange) -> Result<(), AddressSpaceError> {
        self.assert_smp_safe();
        // One critical section from the tracker update through the last
        // leaf cleared to the return of the range to the free list: a
        // `commit` of the range cannot map it between the record and the
        // unmap, and `reserve` cannot reuse it before its leaves are gone.
        let mut state = self.state.lock();
        let released = state.release(virt)?;
        self.swap.discard(self, released.swapped);
        for region in &released.committed {
            if region.substituted {
                self.drop_substituted_leaves(region.range);
            } else {
                self.unmap_range(region.range);
            }
        }
        state.push_free_range(virt);
        Ok(())
    }

    fn commit(&self, virt: VirtRange, flags: PageFlags) -> Result<(), AddressSpaceError> {
        self.assert_smp_safe();
        validate_range(virt)?;
        let mut state = self.state.lock();
        self.commit_locked(&mut state, virt, flags)
    }

    /// One allocation out of the user pool, taken on the executing
    /// processor: what a device is told is where the run sits in
    /// physical memory. No translation changes, so no lock and no
    /// shootdown.
    fn allocate_run(
        &self,
        bytes: usize,
        placement: DmaPlacement,
    ) -> Result<PhysicalRange, AddressSpaceError> {
        if bytes == 0 {
            return Err(AddressSpaceError::EmptyRange);
        }
        if !bytes.is_multiple_of(PAGE) {
            return Err(AddressSpaceError::Misaligned);
        }
        let align = usize::try_from(placement.align)
            .ok()
            .filter(|align| align.is_power_of_two() && *align >= PAGE)
            .ok_or(AddressSpaceError::Misaligned)?;
        let layout =
            Layout::from_size_align(bytes, align).map_err(|_| AddressSpaceError::Misaligned)?;
        let phys = self.machine.allocate_run(layout)?;
        if !placement.accepts(phys as u64, bytes as u64) {
            self.free_pinned_run(phys, bytes, align);
            return Err(AddressSpaceError::OutOfFrames);
        }
        Ok(PhysicalRange::new(phys as u64, bytes as u64))
    }

    fn free_run(&self, run: PhysicalRange, align: u64) -> Result<(), AddressSpaceError> {
        let align = usize::try_from(align)
            .ok()
            .filter(|align| align.is_power_of_two() && *align >= PAGE)
            .ok_or(AddressSpaceError::Misaligned)?;
        let bytes = usize::try_from(run.bytes).map_err(|_| AddressSpaceError::Misaligned)?;
        let start = usize::try_from(run.start).map_err(|_| AddressSpaceError::Misaligned)?;
        if bytes == 0 || !bytes.is_multiple_of(PAGE) || !start.is_multiple_of(align) {
            return Err(AddressSpaceError::Misaligned);
        }
        self.free_pinned_run(start, bytes, align);
        Ok(())
    }

    /// The leaves carry ordinary write-back attributes. The reservation
    /// lock is held across the rewrite: see [`Self::substitute_leaves`].
    fn substitute_memory(
        &self,
        virt: VirtRange,
        physical: PhysicalRange,
        flags: PageFlags,
    ) -> Result<(), AddressSpaceError> {
        self.assert_smp_safe();
        validate_range(virt)?;
        if physical.bytes as usize != virt.byte_len
            || !(physical.start as usize).is_multiple_of(PAGE)
        {
            return Err(AddressSpaceError::Misaligned);
        }
        // Ordinary memory attributes: these bytes are somebody's
        // buffer, and a second holder that reached them uncached would
        // see a picture the first holder's stores had not reached yet.
        let pt_flags = page_flags_to_pt(flags)?;
        self.substitute_leaves(virt, physical.start as usize, pt_flags)
    }

    /// The region's own attributes, from
    /// [`memory_type::device_leaf_flags`]: uncacheable for a register
    /// file, write-back for memory, read-only when the region is not
    /// writable, never executable. The
    /// reservation lock is held across the rewrite: see
    /// [`Self::substitute_leaves`].
    fn substitute_device(
        &self,
        virt: VirtRange,
        region: DeviceRegion,
    ) -> Result<(), AddressSpaceError> {
        self.assert_smp_safe();
        validate_range(virt)?;
        if !region.is_frame_aligned() || region.physical.bytes as usize != virt.byte_len {
            return Err(AddressSpaceError::Misaligned);
        }
        self.substitute_leaves(
            virt,
            region.physical.start as usize,
            memory_type::device_leaf_flags(region.attributes),
        )
    }

    /// The reservation lock is held from the check that `virt` is
    /// substituted, across the allocation of every fresh frame and every
    /// leaf rewrite, to the bookkeeping. Frames are all allocated
    /// before the first leaf changes, so running out leaves the
    /// substitution in place.
    fn restore(&self, virt: VirtRange) -> Result<(), AddressSpaceError> {
        self.assert_smp_safe();
        validate_range(virt)?;
        let mut state = self.state.lock();
        let regions = state.substituted_regions(virt)?;
        let mut page_flags = Vec::with_capacity(virt.byte_len / PAGE);
        for region in &regions {
            let pt_flags = (page_flags_to_pt(region.flags)? | PageTableFlags::ACCESSED).bits();
            page_flags.extend(core::iter::repeat_n(pt_flags, region.range.byte_len / PAGE));
        }
        let leaves = self.present_leaves(virt)?;
        let mut fresh = Vec::with_capacity(leaves.len());
        for _ in &leaves {
            match self.machine.allocate_frame() {
                Ok(phys) => fresh.push(phys),
                Err(error) => {
                    for phys in fresh {
                        self.machine.free_frame(phys);
                    }
                    return Err(error);
                }
            }
        }
        for ((leaf, phys), flag_bits) in leaves.into_iter().zip(fresh).zip(page_flags) {
            // SAFETY: as in `substitute_leaves`.
            let entry = unsafe { &*leaf };
            entry.store(
                ((phys as u64) & ENTRY_ADDR_MASK) | flag_bits,
                Ordering::Release,
            );
        }
        // What was shown here is not ours to free; the shootdown is so
        // that no processor keeps reading it through the old leaf.
        self.invalidate_everywhere(virt);
        state.record_restore(virt)
    }

    /// The reservation lock is held across the leaf removal, the
    /// shootdown and the bookkeeping. Nothing is allocated.
    fn withdraw(&self, virt: VirtRange) -> Result<(), AddressSpaceError> {
        self.assert_smp_safe();
        validate_range(virt)?;
        let mut state = self.state.lock();
        state.substituted_regions(virt)?;
        self.drop_substituted_leaves(virt);
        state.record_withdraw(virt)
    }

    fn decommit(&self, virt: VirtRange) -> Result<(), AddressSpaceError> {
        self.assert_smp_safe();
        validate_range(virt)?;
        // Held from the tracker update through the last leaf cleared, as
        // in `release`: a concurrent `commit` of `virt` waits for the
        // unmap instead of interleaving with it.
        let mut state = self.state.lock();
        let removed = state.record_decommit(virt)?;
        self.swap.discard(self, removed.swapped);
        self.drop_substituted_parts(&removed.substituted);
        self.unmap_range(virt);
        Ok(())
    }

    fn protect(&self, virt: VirtRange, flags: PageFlags) -> Result<(), AddressSpaceError> {
        self.assert_smp_safe();
        validate_range(virt)?;
        let mut state = self.state.lock();
        self.protect_locked(&mut state, virt, flags)
    }

    fn prepare_demand_commit(
        &self,
        virt: VirtRange,
        flags: PageFlags,
    ) -> Result<(), AddressSpaceError> {
        self.assert_smp_safe();
        validate_range(virt)?;
        // The flags are validated here rather than at the first fault:
        // a fault-time commit has no way to report a bad combination.
        let _ = page_flags_to_pt(flags)?;
        let mut state = self.state.lock();
        state.precheck_commit(virt)?;
        self.swap.discard(self, state.take_swap_entries_in(virt));
        // One walk per level-1 table, not per page: every page of a
        // block shares the table the walk builds, and this runs under
        // the reservation lock on every store creation.
        for block in virt.block_starts(LEAF_TABLE_SPAN) {
            let page = Page::<Size4KiB>::containing_address(X86VirtAddr::new(block.raw() as u64));
            let p4 = self.level_4_table();
            let p3 = self.ensure_table(p4, page.p4_index())?;
            let p2 = self.ensure_table(p3, page.p3_index())?;
            self.ensure_table(p2, page.p2_index())?;
        }
        // `MemoryOwner::NONE` on purpose. The residency accounting and
        // the swap aging pass both key on a real owner, and neither may
        // see this region: its pages are not resident until something
        // faults on them, and ageing one would offer the swap policy the
        // stack its own fault handler is standing on.
        self.swap
            .discard(self, state.record_commit(virt, flags, MemoryOwner::NONE)?);
        Ok(())
    }

    fn commit_demand_page(
        &self,
        addr: VirtAddr,
        frame: NonNull<u8>,
        flags: PageFlags,
    ) -> Result<(), AddressSpaceError> {
        let virt = addr.raw();
        if !addr.is_page_aligned() {
            return Err(AddressSpaceError::Misaligned);
        }
        let pt_flags = page_flags_to_pt(flags)? | PageTableFlags::ACCESSED;
        let entry_ptr = self
            .leaf_entry(virt)
            .ok_or(AddressSpaceError::NotDemandCommit)?;
        let phys = self
            .machine
            .physical_address(frame)
            .ok_or(AddressSpaceError::Misaligned)?;
        let phys_u64 = phys as u64;
        if !phys.is_multiple_of(PAGE) || phys_u64 & !ENTRY_ADDR_MASK != 0 {
            return Err(AddressSpaceError::Misaligned);
        }
        // SAFETY: the walk above completed through live tables, and the
        // page it names is inside a prepared demand-commit region, which
        // only the fiber running on it ever faults on.
        let entry = unsafe { &*entry_ptr };
        if entry.load(Ordering::Acquire) != 0 {
            return Err(AddressSpaceError::Overlap);
        }
        entry.store(phys_u64 | pt_flags.bits(), Ordering::Release);
        // The page went from unmapped to mapped, so no processor can
        // hold a translation for it and the local invalidate is the
        // whole of the TLB work. A negative entry is not cached on any
        // x86-64 implementation that matters, and the architecture
        // requires this invalidate for the ones that speculate.
        self.machine.invalidate_local(VirtRange::new(addr, PAGE));
        Ok(())
    }

    fn end_demand_commit(
        &self,
        virt: VirtRange,
        mapped: VirtRange,
    ) -> Result<(), AddressSpaceError> {
        self.assert_smp_safe();
        validate_range(virt)?;
        if !virt.encloses(mapped) {
            return Err(AddressSpaceError::NotDemandCommit);
        }
        // Held through the unmap, as in `decommit`.
        let mut state = self.state.lock();
        let removed = state.record_decommit(virt)?;
        debug_assert!(
            removed.swapped.is_empty() && removed.substituted.is_empty(),
            "a demand-commit region is never offered to the swap policy or substituted"
        );
        self.swap.discard(self, removed.swapped);
        self.unmap_demand_pages(mapped);
        Ok(())
    }

    fn translate(&self, addr: VirtAddr) -> Translation {
        if addr.raw() < USER_VA_BASE || addr.raw() >= USER_VA_END {
            return Translation::Unmapped;
        }
        // Hold `state` across both the tracker lookup and the leaf read so
        // the answer is consistent with concurrent mutations.
        let state = self.state.lock();
        let committed = match state.lookup(addr) {
            ReservationLookup::Unreserved => return Translation::Unmapped,
            ReservationLookup::Reserved => return Translation::Reserved,
            ReservationLookup::Committed(region) => region,
        };
        let Some(entry_ptr) = self.leaf_entry(addr.raw()) else {
            return Translation::Reserved;
        };
        // SAFETY: `leaf_entry` walked live tables and `state` is held.
        let raw = unsafe { &*entry_ptr }.load(Ordering::Acquire);
        if raw & PageTableFlags::PRESENT.bits() == 0 {
            return Translation::Reserved;
        }
        let phys = (raw & ENTRY_ADDR_MASK) as usize;
        Translation::Committed {
            frame: PhysFrame::from_phys_addr(phys),
            flags: committed.flags,
        }
    }

    fn relocate(&self, virt: VirtRange) -> Result<(), AddressSpaceError> {
        self.assert_smp_safe();
        validate_range(virt)?;
        let state = self.state.lock();
        state.ensure_committed(virt)?;
        // A substitution has no pool frames to copy and free.
        state.ensure_unsubstituted(virt)?;

        let pages = self.build_relocation_plan(virt)?;
        for page in &pages {
            // SAFETY: `build_relocation_plan` walked live tables for this
            // range and `state` is held across the replacement.
            let entry = unsafe { &*page.leaf };
            entry.store(
                ((page.new_phys as u64) & ENTRY_ADDR_MASK) | page.old_flags,
                Ordering::Release,
            );
            self.machine
                .invalidate_local(VirtRange::new(VirtAddr::new(page.virt), PAGE));
        }
        self.machine.shootdown(virt);
        for page in &pages {
            self.machine.free_frame(page.old_phys);
        }
        Ok(())
    }

    fn swap_out_page(
        &self,
        addr: VirtAddr,
        token: SwapToken,
        out: &mut [u8],
    ) -> Result<PageFlags, AddressSpaceError> {
        self.assert_smp_safe();
        self.swap
            .swap_out_page(&mut self.state.lock(), self, addr, token, out)
    }

    fn swap_in_page(&self, addr: VirtAddr, bytes: &[u8]) -> Result<SwapToken, AddressSpaceError> {
        self.swap
            .swap_in_page(&mut self.state.lock(), self, addr, bytes)
    }

    fn swapped_token(&self, addr: VirtAddr) -> Option<SwapToken> {
        SwapLeafFormat::swapped_token(self, addr)
    }

    fn scan_committed_pages<Visit>(&self, owner: u64, visit: Visit) -> usize
    where
        Visit: FnMut(VirtAddr, PageFlags, PageAge) -> bool,
    {
        self.assert_smp_safe();
        self.swap
            .scan_committed_pages(&self.state.lock(), self, owner, visit)
    }

    fn owned_resident_bytes(&self, owner: u64) -> u64 {
        self.state
            .lock()
            .owned_resident_bytes(MemoryOwner::new(owner))
    }

    fn visit_owned_resident_bytes<Visit>(&self, mut visit: Visit)
    where
        Visit: FnMut(u64, u64),
    {
        self.state
            .lock()
            .visit_owned_resident_bytes(|owner, bytes| visit(owner.raw(), bytes));
    }

    fn drain_orphaned_swap_tokens<Visit>(&self, visit: Visit) -> usize
    where
        Visit: FnMut(SwapToken),
    {
        self.swap.drain_orphaned_swap_tokens(visit)
    }
}

impl<M: InstalledMachine> InstalledAddressSpace for X86UserAddressSpace<M> {
    fn installed() -> &'static Self {
        M::installed()
    }
}

fn page_flags_to_pt(flags: PageFlags) -> Result<PageTableFlags, AddressSpaceError> {
    // x86 has no allocation-tag storage to map.
    if flags.is_empty() || flags.contains(PageFlags::TAGGED) {
        return Err(AddressSpaceError::InvalidFlags);
    }
    // No `USER_ACCESSIBLE`: every helios thread runs in ring 0, guest wasm
    // included, so the "user" window is a range the kernel owns on a guest's
    // behalf rather than a privilege boundary. Marking it user-accessible
    // would buy nothing and would make the mappings unusable the moment SMAP
    // or SMEP is enabled — including for the runtime's compiled code, which
    // is mapped in this window and fetched in ring 0. This matches the
    // aarch64 backend's `AP_KERNEL_RW`.
    let mut pt = PageTableFlags::PRESENT;
    if flags.contains(PageFlags::WRITE) {
        pt |= PageTableFlags::WRITABLE;
    }
    if !flags.contains(PageFlags::EXECUTE) {
        pt |= PageTableFlags::NO_EXECUTE;
    }
    Ok(pt)
}
