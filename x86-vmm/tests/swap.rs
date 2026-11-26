//! Swap leaf encoding, aging, shootdowns, and lifecycle tests for
//! [`X86UserAddressSpace`].
//!
//! Uses a host [`Machine`] backed by `helios_kernel`'s `UserMemoryPool` so
//! `SwapSpace`'s frame allocation/deallocation and the address space's own
//! commit/decommit paths share one pool and accounting can be checked
//! byte-for-byte.

use std::alloc::{Layout, alloc_zeroed, dealloc};
use std::ptr::NonNull;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Once};

use helios_hal::cpu::ProcessorId;
use helios_hal::device::DmaPlacement;
use helios_hal::numa::{NodeId, SingleNode};
use helios_hal::vmm::{
    AddressSpace, AddressSpaceError, PageAge, PageFlags, SwapToken, Translation, VirtAddr,
    VirtRange,
};
use helios_kernel::{
    AGE_BATCH_PAGES, MemoryOwner, NodeRun, UserMemoryPool, allocate_user_frame_zeroed_on,
    allocate_user_run_zeroed_on, deallocate_user_frame_on, deallocate_user_run_on,
    install_user_memory_pool, user_heap_stats,
};
use helios_x86_vmm::{Machine, USER_VA_BASE, USER_VA_END, X86UserAddressSpace};
use x86_64::structures::paging::{Page, PageTable, PageTableFlags, PhysFrame, Size4KiB};
use x86_64::{PhysAddr, VirtAddr as X86VirtAddr};

struct TestInterruptMask;

impl helios_hal::critical_section::LocalInterruptMask for TestInterruptMask {
    fn mask() -> bool {
        false
    }

    unsafe fn restore(was_enabled: bool) {
        debug_assert!(
            !was_enabled,
            "the host test mask never reports interrupts as enabled"
        );
    }
}

helios_hal::critical_section::set_local_interrupt_mask_impl!(TestInterruptMask);

#[unsafe(no_mangle)]
extern "Rust" fn helios_current_processor() -> ProcessorId {
    ProcessorId::new(0)
}

const PAGE: usize = 4096;
const POOL_BYTES: usize = 8 * 1024 * 1024;
const ENTRY_ADDR_MASK: u64 = 0x000f_ffff_ffff_f000;
const RETIRED_BIT: u64 = PageTableFlags::BIT_9.bits();
const SWAP_MARKER_BIT: u64 = PageTableFlags::BIT_10.bits();
const RW: PageFlags = PageFlags::READ.union(PageFlags::WRITE);
const RX: PageFlags = PageFlags::READ.union(PageFlags::EXECUTE);

fn token(raw: u32) -> SwapToken {
    SwapToken::new(raw).expect("non-zero token")
}

/// Serialises tests that share the process-global `UserMemoryPool` and
/// inspect `user_heap_stats()`.
fn serialise() -> MutexGuard<'static, ()> {
    static TURN: Mutex<()> = Mutex::new(());
    static POOL: Once = Once::new();
    let guard = TURN.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    POOL.call_once(|| {
        let layout = Layout::from_size_align(POOL_BYTES, PAGE).expect("pool layout");
        // Leaked on purpose: the pool is `&'static` for the test process.
        // SAFETY: `layout` has non-zero size and page alignment.
        let base = unsafe { alloc_zeroed(layout) } as usize;
        assert!(base != 0, "user pool allocation failed");
        install_user_memory_pool(UserMemoryPool::new(
            &SingleNode::new(1),
            ProcessorId::new(0),
            &[NodeRun {
                start: base,
                end: base + POOL_BYTES,
                node: NodeId::FIRST,
            }],
        ));
    });
    guard
}

fn pool_allocated_bytes() -> usize {
    user_heap_stats().allocated_bytes
}

struct SwapHostMemory {
    root: PhysFrame,
    tables: Mutex<Vec<usize>>,
    owner: AtomicU64,
    shootdowns: Mutex<Vec<(usize, usize)>>,
}

impl SwapHostMemory {
    fn new(owner: u64) -> Self {
        let tables = Mutex::new(Vec::new());
        let root = alloc_table_frame(&tables);
        Self {
            root,
            tables,
            owner: AtomicU64::new(owner),
            shootdowns: Mutex::new(Vec::new()),
        }
    }

    fn set_owner(&self, owner: u64) {
        self.owner.store(owner, Ordering::Release);
    }

    fn take_shootdowns(&self) -> Vec<(usize, usize)> {
        core::mem::take(&mut *self.shootdowns.lock().expect("shootdowns lock"))
    }

    /// Reads the raw 64-bit level-1 PTE for `virt`, if its leaf table exists.
    fn raw_leaf(&self, virt: usize) -> Option<u64> {
        let leaf = self.leaf_atomic(virt)?;
        Some(leaf.load(Ordering::Acquire))
    }

    /// Mutates the raw 64-bit level-1 PTE for `virt` (simulating hardware
    /// A/D updates).
    fn or_leaf_bits(&self, virt: usize, bits: u64) {
        let leaf = self.leaf_atomic(virt).expect("leaf table exists");
        leaf.fetch_or(bits, Ordering::AcqRel);
    }

    fn leaf_atomic(&self, virt: usize) -> Option<&AtomicU64> {
        let page = Page::<Size4KiB>::containing_address(X86VirtAddr::new(virt as u64));
        let mut table = self.root.start_address().as_u64() as *const PageTable;
        for index in [page.p4_index(), page.p3_index(), page.p2_index()] {
            let slot = usize::from(index);
            // SAFETY: `table` is a live 512-entry page table allocated by this
            // fixture and `slot < 512`.
            let entry_ptr = unsafe { table.cast::<AtomicU64>().add(slot) };
            // SAFETY: `entry_ptr` points to an aligned live entry.
            let raw = unsafe { &*entry_ptr }.load(Ordering::Acquire);
            if raw == 0 {
                return None;
            }
            table = (raw & ENTRY_ADDR_MASK) as *const PageTable;
        }
        let leaf_slot = usize::from(page.p1_index());
        // SAFETY: `table` is a live 512-entry L1 table and `leaf_slot < 512`.
        let leaf_ptr = unsafe { table.cast::<AtomicU64>().add(leaf_slot) };
        // SAFETY: `leaf_ptr` points to an aligned entry owned by `self` for
        // the lifetime of `&self`.
        Some(unsafe { &*leaf_ptr })
    }
}

impl Drop for SwapHostMemory {
    fn drop(&mut self) {
        let layout = Layout::from_size_align(PAGE, PAGE).expect("table layout");
        for start in self.tables.get_mut().expect("tables lock").drain(..) {
            // SAFETY: every table address came from `alloc_zeroed(layout)`.
            unsafe { dealloc(start as *mut u8, layout) };
        }
    }
}

fn alloc_table_frame(tables: &Mutex<Vec<usize>>) -> PhysFrame {
    let layout = Layout::from_size_align(PAGE, PAGE).expect("table layout");
    // SAFETY: `layout` has non-zero size and page alignment.
    let ptr = unsafe { alloc_zeroed(layout) } as usize;
    assert!(ptr != 0, "table frame allocation failed");
    tables.lock().expect("tables lock").push(ptr);
    PhysFrame::from_start_address(PhysAddr::new(ptr as u64)).expect("4 KiB aligned table")
}

struct SwapHost(Arc<SwapHostMemory>);

// SAFETY: table frames are live host allocations kept until `SwapHostMemory`
// drops; user frames and runs come from `UserMemoryPool` and their physical
// address equals their host pointer.
unsafe impl Machine for SwapHost {
    fn root_table(&self) -> PhysFrame {
        self.0.root
    }

    fn allocate_table(&self) -> Option<PhysFrame> {
        Some(alloc_table_frame(&self.0.tables))
    }

    fn frame_pointer(&self, phys: usize) -> *mut u8 {
        phys as *mut u8
    }

    fn physical_address(&self, pointer: NonNull<u8>) -> Option<usize> {
        Some(pointer.as_ptr() as usize)
    }

    fn allocate_frame(&self) -> Result<usize, AddressSpaceError> {
        let frame = allocate_user_frame_zeroed_on(ProcessorId::new(0))
            .map_err(|_| AddressSpaceError::OutOfFrames)?;
        Ok(frame.as_ptr() as usize)
    }

    fn allocate_frame_beside(&self, _phys: usize) -> Result<usize, AddressSpaceError> {
        self.allocate_frame()
    }

    fn free_frame(&self, phys: usize) {
        let ptr = NonNull::new(phys as *mut u8).expect("non-null user frame");
        deallocate_user_frame_on(ProcessorId::new(0), ptr);
    }

    fn allocate_run(&self, layout: Layout) -> Result<usize, AddressSpaceError> {
        let run = allocate_user_run_zeroed_on(ProcessorId::new(0), layout)
            .map_err(|_| AddressSpaceError::OutOfFrames)?;
        Ok(run.as_ptr() as usize)
    }

    fn free_run(&self, phys: usize, layout: Layout) {
        let ptr = NonNull::new(phys as *mut u8).expect("non-null user run");
        deallocate_user_run_on(ProcessorId::new(0), ptr, layout);
    }

    fn current_owner(&self) -> MemoryOwner {
        MemoryOwner::new(self.0.owner.load(Ordering::Acquire))
    }

    fn invalidate_local(&self, _range: VirtRange) {}

    fn shootdown(&self, range: VirtRange) {
        self.0
            .shootdowns
            .lock()
            .expect("shootdowns lock")
            .push((range.start.raw(), range.byte_len));
    }
}

fn fresh(owner: u64) -> (Arc<SwapHostMemory>, X86UserAddressSpace<SwapHost>) {
    let memory = Arc::new(SwapHostMemory::new(owner));
    let space = X86UserAddressSpace::new(SwapHost(Arc::clone(&memory)), 4);
    (memory, space)
}

fn write_committed_page(space: &X86UserAddressSpace<SwapHost>, addr: VirtAddr, fill: u8) {
    let frame = match space.translate(addr) {
        Translation::Committed { frame, .. } => frame.phys_addr(),
        other => panic!(
            "expected committed page at {:#x}, got {other:?}",
            addr.raw()
        ),
    };
    // SAFETY: `frame` is a live user-pool frame mapped at `addr`.
    unsafe { core::ptr::write_bytes(frame as *mut u8, fill, PAGE) };
}

fn read_committed_page(space: &X86UserAddressSpace<SwapHost>, addr: VirtAddr) -> Vec<u8> {
    let frame = match space.translate(addr) {
        Translation::Committed { frame, .. } => frame.phys_addr(),
        other => panic!(
            "expected committed page at {:#x}, got {other:?}",
            addr.raw()
        ),
    };
    // SAFETY: `frame` is a live user-pool frame mapped at `addr`.
    unsafe { core::slice::from_raw_parts(frame as *const u8, PAGE) }.to_vec()
}

fn drain_sorted(space: &X86UserAddressSpace<SwapHost>) -> Vec<SwapToken> {
    let mut out = Vec::new();
    let count = space.drain_orphaned_swap_tokens(|tok| out.push(tok));
    assert_eq!(count, out.len());
    out.sort();
    out
}

#[test]
fn l1tf_safe_swap_leaf_encoding_and_round_trip() {
    let _turn = serialise();
    let before = pool_allocated_bytes();
    let (memory, space) = fresh(1);
    let tokens = [token(1), token(42), token(0x1234_5678), token(u32::MAX)];
    let range = space.reserve(tokens.len() * PAGE).expect("reserve");
    space.commit(range, RW).expect("commit");
    assert_eq!(space.owned_resident_bytes(1), (tokens.len() * PAGE) as u64);
    assert_eq!(pool_allocated_bytes(), before + tokens.len() * PAGE);

    let mut saved = Vec::new();
    for (idx, tok) in tokens.iter().copied().enumerate() {
        let addr = VirtAddr::new(range.start.raw() + idx * PAGE);
        let fill = (idx as u8).wrapping_mul(0x37).wrapping_add(0x11);
        write_committed_page(&space, addr, fill);

        memory.take_shootdowns();
        let mut buf = vec![0_u8; PAGE];
        let flags = space.swap_out_page(addr, tok, &mut buf).expect("swap out");
        assert_eq!(flags, RW);
        assert!(buf.iter().all(|&b| b == fill));
        assert_eq!(memory.take_shootdowns(), [(addr.raw(), PAGE)]);

        let raw = memory.raw_leaf(addr.raw()).expect("leaf exists");
        assert_eq!(raw & PageTableFlags::PRESENT.bits(), 0, "PRESENT must be 0");
        assert_eq!(raw & RETIRED_BIT, 0, "RETIRED must be 0");
        assert_eq!(
            raw & PageTableFlags::ACCESSED.bits(),
            0,
            "ACCESSED must be 0"
        );
        assert_eq!(raw & PageTableFlags::DIRTY.bits(), 0, "DIRTY must be 0");
        assert_ne!(raw & SWAP_MARKER_BIT, 0, "SWAP_MARKER must be set");

        let encoded_pfn_field = raw & ENTRY_ADDR_MASK;
        let expected_pfn_field = (!u64::from(tok.raw()) << 12) & ENTRY_ADDR_MASK;
        assert_eq!(encoded_pfn_field, expected_pfn_field);
        // Upper 8 bits of the 40-bit PFN field (bits 44..52) are always 0xff,
        // so even `u32::MAX` never encodes frame 0 or low RAM (L1TF).
        assert_eq!(
            encoded_pfn_field & 0x000f_f000_0000_0000,
            0x000f_f000_0000_0000
        );

        assert_eq!(space.swapped_token(addr), Some(tok));
        assert_eq!(
            space.swapped_token(VirtAddr::new(addr.raw() + 123)),
            Some(tok),
            "interior page offset resolves to the same swap token"
        );
        assert_eq!(space.translate(addr), Translation::Reserved);
        saved.push((addr, tok, buf));
    }

    assert_eq!(space.owned_resident_bytes(1), 0);
    assert_eq!(pool_allocated_bytes(), before);
    assert_eq!(
        space.swapped_token(VirtAddr::new(USER_VA_BASE - PAGE)),
        None
    );
    assert_eq!(space.swapped_token(VirtAddr::new(USER_VA_END)), None);

    for (addr, tok, buf) in saved {
        memory.take_shootdowns();
        let restored = space.swap_in_page(addr, &buf).expect("swap in");
        assert_eq!(restored, tok);
        assert!(
            memory.take_shootdowns().is_empty(),
            "not-present to present needs no remote shootdown"
        );
        assert_eq!(space.swapped_token(addr), None);
        assert_eq!(read_committed_page(&space, addr), buf);
        let raw = memory.raw_leaf(addr.raw()).expect("leaf exists");
        assert_ne!(raw & PageTableFlags::PRESENT.bits(), 0);
        assert_ne!(
            raw & PageTableFlags::ACCESSED.bits(),
            0,
            "reinstated page starts hot with ACCESSED set"
        );
        assert_ne!(raw & PageTableFlags::WRITABLE.bits(), 0);
        assert_ne!(raw & PageTableFlags::NO_EXECUTE.bits(), 0);
    }
    assert_eq!(space.owned_resident_bytes(1), (tokens.len() * PAGE) as u64);

    space.release(range).expect("release");
    assert_eq!(pool_allocated_bytes(), before);
}

#[test]
fn aging_scan_uses_hardware_accessed_bit_and_batches_shootdowns() {
    let _turn = serialise();
    let before = pool_allocated_bytes();
    let (memory, space) = fresh(1);
    let pages = 2 * AGE_BATCH_PAGES + 19;
    let range = space.reserve((pages + 1) * PAGE).expect("reserve");
    let owner1_range = VirtRange::new(range.start, pages * PAGE);
    let owner2_range = VirtRange::new(VirtAddr::new(range.start.raw() + pages * PAGE), PAGE);
    space.commit(owner1_range, RW).expect("commit owner 1");
    memory.set_owner(2);
    space.commit(owner2_range, RX).expect("commit owner 2");

    // Simulate hardware setting DIRTY on page 0 so we verify clearing ACCESSED
    // preserves DIRTY.
    memory.or_leaf_bits(range.start.raw(), PageTableFlags::DIRTY.bits());
    memory.take_shootdowns();

    let mut ages = Vec::new();
    let visited = space.scan_committed_pages(1, |_, flags, age| {
        assert_eq!(flags, RW);
        ages.push(age);
        true
    });
    assert_eq!(visited, pages);
    assert!(ages.iter().all(|&age| age == PageAge::Hot));
    assert_eq!(
        memory.take_shootdowns(),
        [
            (range.start.raw(), AGE_BATCH_PAGES * PAGE),
            (
                range.start.raw() + AGE_BATCH_PAGES * PAGE,
                AGE_BATCH_PAGES * PAGE
            ),
            (range.start.raw() + 2 * AGE_BATCH_PAGES * PAGE, 19 * PAGE),
        ],
        "shootdowns are batched at AGE_BATCH_PAGES plus the tail"
    );
    let page0_raw = memory.raw_leaf(range.start.raw()).expect("page 0");
    assert_eq!(page0_raw & PageTableFlags::ACCESSED.bits(), 0);
    assert_ne!(
        page0_raw & PageTableFlags::DIRTY.bits(),
        0,
        "clearing ACCESSED preserves DIRTY"
    );
    // Owner 2's page must remain untouched.
    let owner2_raw = memory.raw_leaf(owner2_range.start.raw()).expect("owner 2");
    assert_ne!(owner2_raw & PageTableFlags::ACCESSED.bits(), 0);

    // Hardware touches page 5 between scans.
    let hot_page = range.start.raw() + 5 * PAGE;
    memory.or_leaf_bits(hot_page, PageTableFlags::ACCESSED.bits());
    memory.take_shootdowns();

    ages.clear();
    space.scan_committed_pages(1, |_, _, age| {
        ages.push(age);
        true
    });
    assert_eq!(ages[5], PageAge::Hot);
    assert!(
        ages.iter()
            .enumerate()
            .all(|(i, &age)| (i == 5) == (age == PageAge::Hot))
    );
    assert_eq!(memory.take_shootdowns(), [(hot_page, PAGE)]);

    space.release(range).expect("release");
    assert_eq!(pool_allocated_bytes(), before);
}

#[test]
fn commit_decommit_release_substitute_and_protect_handle_swapped_pages() {
    let _turn = serialise();
    let before = pool_allocated_bytes();
    let (memory, space) = fresh(7);
    let range = space.reserve(6 * PAGE).expect("reserve");
    space.commit(range, RW).expect("commit");

    let mut scratch = vec![0_u8; PAGE];
    for i in 0..6 {
        let addr = VirtAddr::new(range.start.raw() + i * PAGE);
        space
            .swap_out_page(addr, token(i as u32 + 1), &mut scratch)
            .expect("swap out");
    }

    // 1. Commit over page 0 discards token 1 and maps a fresh frame.
    let page0 = VirtRange::new(range.start, PAGE);
    space.commit(page0, RX).expect("commit over swapped page");
    assert_eq!(space.swapped_token(page0.start), None);
    assert_eq!(drain_sorted(&space), [token(1)]);
    assert!(drain_sorted(&space).is_empty());

    // Verify `protect` preserves A/D bits on page 0.
    memory.or_leaf_bits(page0.start.raw(), PageTableFlags::DIRTY.bits());
    space.protect(page0, RW).expect("protect");
    let raw0 = memory.raw_leaf(page0.start.raw()).expect("page 0");
    assert_ne!(raw0 & PageTableFlags::WRITABLE.bits(), 0);
    assert_ne!(raw0 & PageTableFlags::NO_EXECUTE.bits(), 0);
    assert_ne!(raw0 & PageTableFlags::ACCESSED.bits(), 0);
    assert_ne!(raw0 & PageTableFlags::DIRTY.bits(), 0);

    // 2. `decommit_committed_subranges` over page 0 (present) + page 1 (swapped).
    let span01 = VirtRange::new(range.start, 2 * PAGE);
    space
        .decommit_committed_subranges(span01)
        .expect("decommit subranges");
    assert_eq!(memory.raw_leaf(range.start.raw()), Some(0));
    assert_eq!(memory.raw_leaf(range.start.raw() + PAGE), Some(0));
    assert_eq!(drain_sorted(&space), [token(2)]);

    // 3. `ensure_accessible_subranges` over page 2 (swapped) commits fresh and orphans token 3.
    let page2 = VirtRange::new(VirtAddr::new(range.start.raw() + 2 * PAGE), PAGE);
    space
        .ensure_accessible_subranges(page2, RW)
        .expect("ensure accessible over swapped");
    assert_eq!(space.swapped_token(page2.start), None);
    assert_eq!(drain_sorted(&space), [token(3)]);

    // 4. `substitute_memory` over page 2 (present) + page 3 (swapped).
    let run = space
        .allocate_run(
            2 * PAGE,
            DmaPlacement {
                align: PAGE as u64,
                limit: u64::MAX,
            },
        )
        .expect("allocate run");
    let span23 = VirtRange::new(VirtAddr::new(range.start.raw() + 2 * PAGE), 2 * PAGE);
    space
        .substitute_memory(span23, run, RW)
        .expect("substitute mixed present+swapped");
    assert_eq!(drain_sorted(&space), [token(4)]);
    assert_eq!(
        space.swap_in_page(VirtAddr::new(range.start.raw() + 3 * PAGE), &scratch),
        Err(AddressSpaceError::NotSwapped)
    );

    // 5. `release` drops remaining swapped pages 4 and 5 and substituted pages 2 and 3.
    space.release(range).expect("release");
    assert_eq!(drain_sorted(&space), [token(5), token(6)]);
    space.free_run(run, PAGE as u64).expect("free run");
    assert_eq!(pool_allocated_bytes(), before);
}
