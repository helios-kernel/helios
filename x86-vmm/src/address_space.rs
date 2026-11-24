//! x86_64 user virtual address space over a [`Machine`]'s page tables.
//!
//! The kernel's page tables map physical memory and the kernel image in
//! the higher half. The lower 128 TiB of the canonical address space is
//! otherwise unused, and a [`USER_VA_BASE`]..[`USER_VA_END`] window of it
//! is carved out for dynamic user mappings.
//!
//! Reservations are tracked in software in a [`ReservationTracker`];
//! commit / decommit / protect / release walk the machine's root table
//! and mutate leaf entries through a `MappedPageTable` that reaches each
//! table through [`Machine::frame_pointer`]. Every translation change is
//! invalidated on the executing processor through
//! [`Machine::invalidate_local`], and one that removes or narrows a
//! translation on every other processor through [`Machine::shootdown`]
//! before an old frame goes back to its pool.

use alloc::vec::Vec;
use core::alloc::Layout;
use core::mem::{align_of, size_of};
use core::ptr;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU64, Ordering};

use helios_hal::device::{DeviceRegion, DmaPlacement};
use helios_hal::iommu::PhysicalRange;
use helios_hal::pmm::PhysFrame;
use helios_hal::vmm::{
    AddressSpace, AddressSpaceError, PageFlags, Translation, VirtAddr, VirtRange,
};
use helios_kernel::{
    InstalledAddressSpace, MemoryOwner, ReservationLookup, ReservationTracker, VaCursor,
    validate_range,
};
use spin::Mutex;
use x86_64::PhysAddr;
use x86_64::VirtAddr as X86VirtAddr;
use x86_64::structures::paging::mapper::{
    MappedPageTable, MapperFlush, PageTableFrameMapping, TranslateResult,
};
use x86_64::structures::paging::page_table::{PageTableEntry, PageTableIndex};
use x86_64::structures::paging::{
    FrameAllocator, Mapper, Page, PageTable, PageTableFlags, PhysFrame as X86PhysFrame, Size4KiB,
    Translate,
};

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

const _: () = {
    assert!(size_of::<PageTable>() == 512 * size_of::<u64>());
    assert!(align_of::<PageTable>() >= align_of::<AtomicU64>());
    assert!(size_of::<PageTableEntry>() == size_of::<u64>());
    assert!(align_of::<PageTableEntry>() == align_of::<AtomicU64>());
};

/// A leaf an unmap has retired but whose frame is not yet free.
///
/// The first pass of [`X86UserAddressSpace::unmap_range`] clears
/// `PRESENT` and sets this bit, keeping the frame address in the leaf;
/// the shootdown goes out once for the whole range; the second pass
/// reads the frame back out of every leaf so marked and frees it. The
/// bit is one of the three the architecture leaves to software.
const RETIRED: PageTableFlags = PageTableFlags::BIT_9;

/// Owned x86 user address space over the page tables of machine `M`.
///
/// # Concurrency contract
///
/// `state` is the one lock that serialises every mutation of this
/// address space's page-table structure, and the reservation records it
/// guards. A path that can build an intermediate table (`commit`,
/// `relocate`, `prepare_demand_commit` and `ensure_accessible_subranges`,
/// through `MappedPageTable::map_to` or `ensure_table`), or rewrite a
/// leaf of a committed range (`protect`, `relocate`,
/// `substitute_memory`, `restore`, `withdraw`,
/// `ensure_accessible_subranges`, `decommit_committed_subranges`), or
/// that clears the leaves of a range it takes out of the tracker
/// (`decommit`, `release`, `end_demand_commit`,
/// `decommit_committed_subranges`), takes `state` before its first
/// check and holds it through its last table access and the matching
/// tracker record; for the clearing paths that is from the tracker
/// update through the last leaf cleared, the shootdown and the frames
/// freed behind it (and, for `release`, the return of the range to the
/// free list). No helper it calls takes `state` again. The shape is "build under the lock", not
/// "publish by compare-exchange": the lock already orders the tracker
/// against the tables, so the check, the walk and the record are one
/// critical section and there is no loser table to free, and the next
/// holder of `state` sees tables and tracker agree.
///
/// `state` is a plain spin lock taken from task context with interrupts
/// enabled and never from an interrupt or trap handler, so a processor
/// spinning on it still acknowledges TLB shootdowns. Holding it across
/// a shootdown is the existing order (`state` then the broadcast lock).
/// Nothing awaits or blocks while holding it: the frame and table
/// allocations under it take the machine's pools, whose interrupt-masking
/// locks nothing holds across `state`.
///
/// Not under `state`: `commit_demand_page` and `leaf_entry` walk tables
/// lock-free via atomic entry loads and raw leaf-entry pointers (without
/// forming `&PageTable` or `&mut PageTable`), which is sound because no
/// intermediate table is freed while the address space lives, intermediate
/// entries are published with `Release` stores, and the one leaf
/// `commit_demand_page` writes belongs to a prepared demand-commit region
/// only its fiber faults on; and `allocate_run` and `free_run`, which
/// change no translation. `translate` holds `state` across both its tracker
/// lookup and its table walk.
/// `unmap_range`, `unmap_demand_pages`, `drop_substituted_leaves` and
/// `drop_substituted_parts` take no lock themselves and are only called
/// with `state` held.
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
}

#[derive(Clone, Copy)]
struct RelocationPage {
    page: Page<Size4KiB>,
    virt: usize,
    old_phys: usize,
    old_flags: PageTableFlags,
    new_phys: usize,
}

/// How a `MappedPageTable` reaches a table: through the machine's
/// physical-memory window.
struct TableWindow<'a, M>(&'a M);

// SAFETY: `Machine`'s contract makes every table frame the address space
// walks readable and writable through `frame_pointer`, and table frames
// are 4 KiB aligned, so the pointer is a valid `PageTable`.
unsafe impl<M: Machine> PageTableFrameMapping for TableWindow<'_, M> {
    fn frame_to_pointer(&self, frame: X86PhysFrame) -> *mut PageTable {
        self.0
            .frame_pointer(frame.start_address().as_u64() as usize)
            .cast()
    }
}

/// Where a `MappedPageTable` takes a table it has to build.
struct TableFrames<'a, M>(&'a M);

// SAFETY: `Machine::allocate_table` returns zeroed frames nothing else
// uses.
unsafe impl<M: Machine> FrameAllocator<Size4KiB> for TableFrames<'_, M> {
    fn allocate_frame(&mut self) -> Option<X86PhysFrame> {
        self.0.allocate_table()
    }
}

type Tables<'a, M> = MappedPageTable<'a, TableWindow<'a, M>>;

impl<M: Machine> X86UserAddressSpace<M> {
    pub fn new(machine: M, processor_count: usize) -> Self {
        Self {
            machine,
            processor_count,
            va_cursor: VaCursor::new(USER_VA_BASE, USER_VA_END),
            state: Mutex::new(ReservationTracker::new()),
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

    /// The page tables of the address space this processor is running
    /// in.
    fn tables(&self) -> Tables<'_, M> {
        // SAFETY: the root frame is a live page table reached through the
        // machine's window (`Machine`'s contract). Concurrent mutation of
        // the tables is ordered by `state`, as the type's concurrency
        // contract says.
        let root = unsafe { &mut *self.level_4_table() };
        // SAFETY: `TableWindow` reaches every table below the root.
        unsafe { MappedPageTable::new(root, TableWindow(&self.machine)) }
    }

    fn table_frames(&self) -> TableFrames<'_, M> {
        TableFrames(&self.machine)
    }

    /// Invalidates the executing processor's translation of `page`, the
    /// one change a `MapperFlush` stands for.
    fn invalidate_page(&self, flush: MapperFlush<Size4KiB>, page: Page<Size4KiB>) {
        flush.ignore();
        self.machine.invalidate_local(VirtRange::new(
            VirtAddr::new(page.start_address().as_u64() as usize),
            PAGE,
        ));
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

    fn map_pages(
        &self,
        tables: &mut Tables<'_, M>,
        virt: VirtRange,
        flags: PageTableFlags,
    ) -> Result<(), AddressSpaceError> {
        let mut frame_allocator = self.table_frames();
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
            let frame =
                X86PhysFrame::from_start_address(PhysAddr::new(phys as u64)).map_err(|_| {
                    self.machine.free_frame(phys);
                    self.rollback_partial_commit(virt.start.raw(), mapped_pages);
                    AddressSpaceError::Misaligned
                })?;
            let page = Page::<Size4KiB>::from_start_address(X86VirtAddr::new(virt_addr as u64))
                .map_err(|_| {
                    self.machine.free_frame(phys);
                    self.rollback_partial_commit(virt.start.raw(), mapped_pages);
                    AddressSpaceError::Misaligned
                })?;
            // SAFETY: `frame` is a fresh user frame nothing else maps,
            // and `page` lies in a reserved, uncommitted range this
            // caller owns under `state`.
            match unsafe { tables.map_to(page, frame, flags, &mut frame_allocator) } {
                Ok(flush) => self.invalidate_page(flush, page),
                Err(_) => {
                    self.machine.free_frame(phys);
                    self.rollback_partial_commit(virt.start.raw(), mapped_pages);
                    return Err(AddressSpaceError::PageTableExhausted);
                }
            }
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
    /// were never mapped are left alone, which is what the runtime's
    /// imprecise decommit of a pooled slot and a demand-commit region
    /// nothing faulted on both need.
    fn unmap_range(&self, virt: VirtRange) {
        let mut retired = 0;
        for offset in (0..virt.byte_len).step_by(PAGE) {
            let virt_addr = virt.start.raw() + offset;
            let Some(entry_ptr) = self.leaf_entry(virt_addr) else {
                continue;
            };
            // SAFETY: the pointer came from a completed walk of live
            // tables, and the caller owns the range: it holds `state`
            // from the tracker update that took the range out.
            let entry = unsafe { &mut *entry_ptr };
            if entry.is_unused() {
                continue;
            }
            assert!(
                entry.flags().contains(PageTableFlags::PRESENT),
                "x86 user page {virt_addr:#x} was already retired"
            );
            let flags = (entry.flags() - PageTableFlags::PRESENT) | RETIRED;
            entry.set_flags(flags);
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
            let entry = unsafe { &mut *entry_ptr };
            if !entry.flags().contains(RETIRED) {
                continue;
            }
            let phys = entry.addr().as_u64() as usize;
            entry.set_unused();
            self.machine.free_frame(phys);
        }
    }

    fn protect_pages(
        &self,
        tables: &mut Tables<'_, M>,
        virt: VirtRange,
        flags: PageTableFlags,
    ) -> Result<(), AddressSpaceError> {
        let mut old_flags = Vec::new();
        for offset in (0..virt.byte_len).step_by(PAGE) {
            let virt_addr = virt.start.raw() + offset;
            let page = Page::<Size4KiB>::from_start_address(X86VirtAddr::new(virt_addr as u64))
                .map_err(|_| AddressSpaceError::Misaligned)?;
            let previous = match tables.translate(X86VirtAddr::new(virt_addr as u64)) {
                TranslateResult::Mapped { flags, .. } => flags,
                _ => {
                    self.rollback_partial_protect(tables, &old_flags);
                    return Err(AddressSpaceError::NotCommitted);
                }
            };
            // A substituted device region keeps its memory type through
            // a protection change: `flags` says what the owner may do,
            // never how the hardware is reached.
            let flags = flags | (previous & memory_type::MEMORY_TYPE_BITS);
            // SAFETY: the page is mapped in a committed range the caller
            // holds `state` over.
            match unsafe { tables.update_flags(page, flags) } {
                Ok(flush) => {
                    self.invalidate_page(flush, page);
                    old_flags.push((page, previous));
                }
                Err(_) => {
                    self.rollback_partial_protect(tables, &old_flags);
                    return Err(AddressSpaceError::NotCommitted);
                }
            }
        }
        Ok(())
    }

    /// Restores the flags a failed `protect_pages` had already changed.
    ///
    /// The pages briefly carried the new flags, and another processor may
    /// have translated one in that window, so the restored range is shot
    /// down the way the success path is: a stale narrower translation is
    /// a spurious fault on a page the tracker says is committed, and a
    /// stale wider one is a permission the caller withdrew.
    fn rollback_partial_protect(
        &self,
        tables: &mut Tables<'_, M>,
        old_flags: &[(Page<Size4KiB>, PageTableFlags)],
    ) {
        for (page, flags) in old_flags.iter().rev().copied() {
            // SAFETY: `protect_pages` changed this mapped page's flags a
            // moment ago under the same `state`.
            let flush = unsafe { tables.update_flags(page, flags) }.unwrap_or_else(|error| {
                panic!("x86 AddressSpace::protect rollback failed: {error:?}")
            });
            self.invalidate_page(flush, page);
        }
        if let (Some((first, _)), Some((last, _))) = (old_flags.first(), old_flags.last()) {
            let start = first.start_address().as_u64() as usize;
            let end = last.start_address().as_u64() as usize + PAGE;
            self.machine
                .shootdown(VirtRange::new(VirtAddr::new(start), end - start));
        }
    }

    /// The level-4 table of the address space this processor is running
    /// in, as a raw pointer through the machine's window.
    fn level_4_table(&self) -> *mut PageTable {
        self.table_at(self.machine.root_table().start_address())
    }

    /// The table at physical address `phys`, through the machine's
    /// window.
    fn table_at(&self, phys: PhysAddr) -> *mut PageTable {
        self.machine.frame_pointer(phys.as_u64() as usize).cast()
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
        Ok(self.table_at(PhysAddr::new(raw & ENTRY_ADDR_MASK)))
    }

    /// The leaf entry for `virt`, or `None` when the walk runs into a
    /// level that was never built.
    ///
    /// Lock-free by construction: no table below a prepared
    /// demand-commit region is ever freed while the address space
    /// lives, so a walk that finds one can keep going. Uses raw pointers
    /// and atomic loads so concurrent walks or demand faults in the same
    /// table never alias `&mut PageTable`.
    fn leaf_entry(&self, virt: usize) -> Option<*mut PageTableEntry> {
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
            table = self.table_at(PhysAddr::new(raw & ENTRY_ADDR_MASK));
        }
        let leaf_slot = usize::from(page.p1_index());
        // SAFETY: `table` is the live level-1 page table of 512 entries for
        // this address and `leaf_slot < 512`; computing the element pointer
        // directly avoids forming `&mut PageTable` over sibling slots.
        let leaf = unsafe { table.cast::<PageTableEntry>().add(leaf_slot) };
        Some(leaf)
    }

    /// Walks every page of `virt`, unmapping the ones a demand commit
    /// mapped and leaving the ones nothing faulted on alone.
    fn unmap_demand_pages(&self, virt: VirtRange) {
        self.unmap_range(virt);
    }

    fn build_relocation_plan(
        &self,
        tables: &Tables<'_, M>,
        virt: VirtRange,
    ) -> Result<Vec<RelocationPage>, AddressSpaceError> {
        let mut pages: Vec<RelocationPage> = Vec::new();
        for offset in (0..virt.byte_len).step_by(PAGE) {
            let virt_addr = virt.start.raw() + offset;
            let page = Page::<Size4KiB>::from_start_address(X86VirtAddr::new(virt_addr as u64))
                .map_err(|_| AddressSpaceError::Misaligned)?;
            let (old_phys, old_flags) = match tables.translate(X86VirtAddr::new(virt_addr as u64)) {
                TranslateResult::Mapped { frame, flags, .. } => {
                    (frame.start_address().as_u64() as usize, flags)
                }
                _ => {
                    for page in pages {
                        self.machine.free_frame(page.new_phys);
                    }
                    return Err(AddressSpaceError::NotCommitted);
                }
            };
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
                page,
                virt: virt_addr,
                old_phys,
                old_flags,
                new_phys,
            });
        }
        Ok(pages)
    }

    fn remap_page(
        &self,
        tables: &mut Tables<'_, M>,
        page: RelocationPage,
        phys: usize,
        flags: PageTableFlags,
    ) -> Result<(), AddressSpaceError> {
        let mut frame_allocator = self.table_frames();
        let (old_frame, flush) = tables
            .unmap(page.page)
            .map_err(|_| AddressSpaceError::NotCommitted)?;
        self.invalidate_page(flush, page.page);
        let new_frame = X86PhysFrame::from_start_address(PhysAddr::new(phys as u64))
            .map_err(|_| AddressSpaceError::Misaligned)?;
        // SAFETY: the page was just unmapped under `state`, and
        // `new_frame` is the frame the relocation owns for it.
        match unsafe { tables.map_to(page.page, new_frame, flags, &mut frame_allocator) } {
            Ok(flush) => {
                self.invalidate_page(flush, page.page);
                Ok(())
            }
            Err(_) => {
                // SAFETY: as above, putting back the frame that was there.
                let flush = unsafe {
                    tables.map_to(page.page, old_frame, page.old_flags, &mut frame_allocator)
                }
                .unwrap_or_else(|error| {
                    panic!(
                        "x86 AddressSpace::relocate failed to restore page {:#x}: {error:?}",
                        page.virt
                    )
                });
                self.invalidate_page(flush, page.page);
                Err(AddressSpaceError::PageTableExhausted)
            }
        }
    }

    fn rollback_relocation(
        &self,
        tables: &mut Tables<'_, M>,
        pages: &[RelocationPage],
        installed: usize,
    ) {
        for page in pages[..installed].iter().rev().copied() {
            self.remap_page(tables, page, page.old_phys, page.old_flags)
                .unwrap_or_else(|error| {
                    panic!(
                        "x86 AddressSpace::relocate rollback failed at {:#x}: {error}",
                        page.virt
                    )
                });
        }
        // The pages this restored were briefly mapped to the replacement
        // frames, and `remap_page` only invalidates the local processor, so
        // the replacements are not free to reuse until every processor has
        // dropped those translations (AGENTS §3.4).
        if let Some(first) = pages.first() {
            self.machine.shootdown(VirtRange::new(
                VirtAddr::new(first.virt),
                pages.len() * PAGE,
            ));
        }
        for page in pages {
            self.machine.free_frame(page.new_phys);
        }
    }

    fn rollback_partial_commit(&self, start: usize, mapped_pages: usize) {
        if mapped_pages == 0 {
            return;
        }
        self.unmap_range(VirtRange::new(VirtAddr::new(start), mapped_pages * PAGE));
    }

    /// The leaf entry of every page of `virt`, when every one of them is
    /// present. Nothing is changed.
    fn present_leaves(
        &self,
        virt: VirtRange,
    ) -> Result<Vec<*mut PageTableEntry>, AddressSpaceError> {
        let mut leaves = Vec::with_capacity(virt.byte_len / PAGE);
        for offset in (0..virt.byte_len).step_by(PAGE) {
            let leaf = self
                .leaf_entry(virt.start.raw() + offset)
                .ok_or(AddressSpaceError::NotCommitted)?;
            // SAFETY: the pointer came from a completed walk of live
            // tables, and the caller holds the reservation lock.
            if !unsafe { &*leaf }.flags().contains(PageTableFlags::PRESENT) {
                return Err(AddressSpaceError::NotCommitted);
            }
            leaves.push(leaf);
        }
        Ok(leaves)
    }

    /// Show the physical bytes from `phys` at `virt` with `pt_flags`, in
    /// place of the pool frames that are there.
    ///
    /// The reservation lock is held from the check that `virt` is
    /// committed (this backend never swaps) and unsubstituted, across
    /// every leaf rewrite and the shootdown, to the bookkeeping that
    /// marks it. Each leaf goes from one present entry to another in a
    /// single store, so a processor racing the call reads the old page or
    /// the new one, and the old frames are freed only after the shootdown
    /// has been acknowledged. The old and new leaves name different
    /// physical frames, so no frame is ever mapped with two memory types
    /// at once.
    fn substitute_leaves(
        &self,
        virt: VirtRange,
        phys: usize,
        pt_flags: PageTableFlags,
    ) -> Result<(), AddressSpaceError> {
        let mut state = self.state.lock();
        state.check_substitutable(virt)?;
        let leaves = self.present_leaves(virt)?;
        let mut replaced = Vec::with_capacity(leaves.len());
        for (index, leaf) in leaves.into_iter().enumerate() {
            // SAFETY: `present_leaves` walked live tables for this
            // range, and the reservation lock is held.
            let entry = unsafe { &mut *leaf };
            replaced.push(entry.addr().as_u64() as usize);
            entry.set_addr(PhysAddr::new((phys + index * PAGE) as u64), pt_flags);
        }
        self.invalidate_everywhere(virt);
        for old in replaced {
            self.machine.free_frame(old);
        }
        // This backend never swaps, so every page was committed and no
        // swap extent is orphaned.
        let orphaned = state.record_substitute(virt)?;
        debug_assert!(orphaned.is_empty());
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
            let entry = unsafe { &mut *leaf };
            if !entry.is_unused() {
                entry.set_unused();
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

    /// Decommit only the parts of `range` that are actually committed.
    ///
    /// The runtime resets a pooled slot by asking for a range whose committed
    /// extent it does not track precisely, so a whole-range decommit would
    /// fail on the first uncommitted page. A substitution inside the range
    /// is dropped without freeing the run's frames, as a withdraw would.
    pub fn decommit_committed_subranges(&self, range: VirtRange) -> Result<(), AddressSpaceError> {
        self.assert_smp_safe();
        validate_range(range)?;
        let mut state = self.state.lock();
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
        let pt_flags = page_flags_to_pt(flags)?;
        let mut state = self.state.lock();
        let plan = state.accessibility_plan(range)?;
        let mut tables = self.tables();
        for subrange in plan.protect {
            state.ensure_committed(subrange)?;
            self.protect_pages(&mut tables, subrange, pt_flags)?;
            self.machine.shootdown(subrange);
            state.record_protect(subrange, flags)?;
        }
        for subrange in plan.commit {
            state.precheck_commit(subrange)?;
            // No shootdown: see `commit`.
            self.map_pages(&mut tables, subrange, pt_flags)?;
            // This backend has no swap, so committing over the range can
            // never orphan a swap extent; the assertion keeps that true if
            // swap reaches this architecture (#25). The region is the
            // instance's whose turn this processor is in: the OOM killer
            // ranks an instance by what it holds of the pool.
            let owner = self.machine.current_owner();
            let orphaned = state.record_commit(subrange, flags, owner)?;
            debug_assert!(orphaned.is_empty());
        }
        Ok(())
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
        // This backend has no swap, so a released reservation never holds a
        // swap token; the assertion keeps that true if swap ever reaches
        // this architecture (#25).
        debug_assert!(released.swapped.is_empty());
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

    /// Maps fresh frames under `virt`.
    ///
    /// No shootdown goes out: every page here was not present a moment
    /// ago, x86-64 caches no not-present translation, and every path
    /// that unmaps a page broadcasts before its frame is freed, so no
    /// processor can hold a translation for any of these pages. The
    /// local invalidation `map_pages` issues is the whole of the TLB
    /// work, the same as `commit_demand_page` and the aarch64 and riscv
    /// backends. A broadcast here was one IPI round per `memory.grow`,
    /// and the compute rows that grow paid it on every step (#419).
    fn commit(&self, virt: VirtRange, flags: PageFlags) -> Result<(), AddressSpaceError> {
        self.assert_smp_safe();
        validate_range(virt)?;
        let pt_flags = page_flags_to_pt(flags)?;

        // One critical section from precheck to record: two commits
        // that share a missing intermediate table cannot both build it.
        let mut state = self.state.lock();
        state.precheck_commit(virt)?;

        let mut tables = self.tables();
        self.map_pages(&mut tables, virt, pt_flags)?;

        // Owned and unswapped, see `ensure_accessible_subranges`.
        let owner = self.machine.current_owner();
        let orphaned = state.record_commit(virt, flags, owner)?;
        debug_assert!(orphaned.is_empty());
        Ok(())
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
            let pt_flags = page_flags_to_pt(region.flags)?;
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
        for ((leaf, phys), pt_flags) in leaves.into_iter().zip(fresh).zip(page_flags) {
            // SAFETY: as in `substitute_memory`.
            let entry = unsafe { &mut *leaf };
            entry.set_addr(PhysAddr::new(phys as u64), pt_flags);
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
        self.drop_substituted_parts(&removed.substituted);
        self.unmap_range(virt);
        Ok(())
    }

    fn protect(&self, virt: VirtRange, flags: PageFlags) -> Result<(), AddressSpaceError> {
        self.assert_smp_safe();
        validate_range(virt)?;
        let pt_flags = page_flags_to_pt(flags)?;
        // The check, the leaf rewrite and the record are one critical
        // section, as in `ensure_accessible_subranges`: a concurrent
        // decommit or commit of the range cannot slip between them.
        let mut state = self.state.lock();
        state.ensure_committed(virt)?;
        let mut tables = self.tables();
        self.protect_pages(&mut tables, virt, pt_flags)?;
        self.machine.shootdown(virt);
        state.record_protect(virt, flags)?;
        Ok(())
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
        let orphaned = state.record_commit(virt, flags, MemoryOwner::NONE)?;
        debug_assert!(orphaned.is_empty());
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
        let pt_flags = page_flags_to_pt(flags)?;
        let entry_ptr = self
            .leaf_entry(virt)
            .ok_or(AddressSpaceError::NotDemandCommit)?;
        let phys = self
            .machine
            .physical_address(frame)
            .ok_or(AddressSpaceError::Misaligned)?;
        let frame = X86PhysFrame::<Size4KiB>::from_start_address(PhysAddr::new(phys as u64))
            .map_err(|_| AddressSpaceError::Misaligned)?;
        // SAFETY: the walk above completed through live tables, and the
        // page it names is inside a prepared demand-commit region, which
        // only the fiber running on it ever faults on.
        let entry = unsafe { &mut *entry_ptr };
        if !entry.is_unused() {
            return Err(AddressSpaceError::Overlap);
        }
        entry.set_frame(frame, pt_flags);
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
        let _ = state.record_decommit(virt)?;
        self.unmap_demand_pages(mapped);
        Ok(())
    }

    fn translate(&self, addr: VirtAddr) -> Translation {
        if addr.raw() < USER_VA_BASE || addr.raw() >= USER_VA_END {
            return Translation::Unmapped;
        }
        // Hold `state` across the table walk so `tables()` has exclusive
        // access to the root table and cannot race a concurrent mutation.
        let state = self.state.lock();
        let committed = match state.lookup(addr) {
            ReservationLookup::Unreserved => return Translation::Unmapped,
            ReservationLookup::Reserved => return Translation::Reserved,
            ReservationLookup::Committed(region) => region,
        };
        match self.tables().translate(X86VirtAddr::new(addr.raw() as u64)) {
            TranslateResult::Mapped { frame, .. } => {
                let phys = frame.start_address().as_u64() as usize;
                Translation::Committed {
                    frame: PhysFrame::from_phys_addr(phys & !(PAGE - 1)),
                    flags: committed.flags,
                }
            }
            _ => Translation::Reserved,
        }
    }

    fn relocate(&self, virt: VirtRange) -> Result<(), AddressSpaceError> {
        self.assert_smp_safe();
        validate_range(virt)?;
        // Held through the remap: `remap_page` unmaps and re-maps leaves
        // of a committed range and `map_to` may build a table.
        let state = self.state.lock();
        state.ensure_committed(virt)?;
        // A substitution has no pool frames to copy and free.
        state.ensure_unsubstituted(virt)?;

        let mut tables = self.tables();
        let pages = self.build_relocation_plan(&tables, virt)?;
        for (index, page) in pages.iter().copied().enumerate() {
            if let Err(error) = self.remap_page(&mut tables, page, page.new_phys, page.old_flags) {
                self.rollback_relocation(&mut tables, &pages, index);
                return Err(error);
            }
        }
        self.machine.shootdown(virt);
        for page in &pages {
            self.machine.free_frame(page.old_phys);
        }
        Ok(())
    }

    /// Every committed page is resident: this backend has no swap.
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
