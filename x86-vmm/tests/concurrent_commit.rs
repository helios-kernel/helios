//! The x86 user address space driven by real threads over host memory.
//!
//! [`Host`] is a [`Machine`] whose physical memory is the host's: a
//! frame's physical address is the address of a 4 KiB-aligned host
//! allocation, so the page tables the address space builds are ordinary
//! memory the test can walk. There is no TLB to invalidate. Everything
//! above the machine — the reservation lock, the tracker and the table
//! walk — is the code the kernel runs.

use std::alloc::{Layout, alloc_zeroed, dealloc};
use std::hint::spin_loop;
use std::ptr::NonNull;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use helios_hal::vmm::{
    AddressSpace, AddressSpaceError, PageFlags, Translation, VirtAddr, VirtRange,
};
use helios_hal::vmm_test_harness::{
    AddressSpaceFixture, Concurrently, run_concurrent_conformance, run_conformance,
};
use helios_kernel::MemoryOwner;
use helios_x86_vmm::{Machine, USER_VA_BASE, X86UserAddressSpace};
use x86_64::structures::paging::{Page, PageTable, PhysFrame, Size4KiB};
use x86_64::{PhysAddr, VirtAddr as X86VirtAddr};

const PAGE: usize = 4096;

/// Host memory standing in for a machine's physical memory.
///
/// Every frame is a zeroed host allocation whose address is its physical
/// address, kept until the memory drops, so a frame the address space
/// loses track of (a table a race overwrote) is still reclaimed.
struct HostMemory {
    root: PhysFrame,
    allocations: Mutex<Vec<(usize, Layout)>>,
}

impl HostMemory {
    fn new() -> Self {
        let allocations = Mutex::new(Vec::new());
        let root = allocate(&allocations, frame_layout());
        Self {
            root: host_frame(root),
            allocations,
        }
    }

    fn give_back(&self, phys: usize) {
        let mut allocations = self.allocations.lock().expect("host memory lock");
        let index = allocations
            .iter()
            .position(|(start, _)| *start == phys)
            .unwrap_or_else(|| panic!("{phys:#x} was never handed out"));
        let (start, layout) = allocations.swap_remove(index);
        // SAFETY: `start` came from `alloc_zeroed` with `layout`, and the
        // record is gone, so it is freed once.
        unsafe { dealloc(start as *mut u8, layout) };
    }

    /// Whether the root table's entry above `virt` is still empty, which
    /// is to say whether a commit there has a level-3 table to build.
    fn root_entry_is_unused(&self, virt: usize) -> bool {
        let page = Page::<Size4KiB>::containing_address(X86VirtAddr::new(virt as u64));
        let root = self.root.start_address().as_u64() as *const PageTable;
        // SAFETY: the root is a live host allocation, and nothing writes
        // it while the test looks.
        let root = unsafe { &*root };
        root[page.p4_index()].is_unused()
    }
}

impl Drop for HostMemory {
    fn drop(&mut self) {
        let allocations = self.allocations.get_mut().expect("host memory lock");
        for (start, layout) in allocations.drain(..) {
            // SAFETY: as in `give_back`.
            unsafe { dealloc(start as *mut u8, layout) };
        }
    }
}

fn frame_layout() -> Layout {
    Layout::from_size_align(PAGE, PAGE).expect("a frame layout")
}

fn host_frame(start: usize) -> PhysFrame {
    PhysFrame::from_start_address(PhysAddr::new(start as u64))
        .expect("a host frame is 4 KiB aligned")
}

fn allocate(allocations: &Mutex<Vec<(usize, Layout)>>, layout: Layout) -> usize {
    // SAFETY: `layout` has a non-zero size.
    let start = unsafe { alloc_zeroed(layout) } as usize;
    assert!(
        start != 0,
        "the host would not lend {} bytes",
        layout.size()
    );
    allocations
        .lock()
        .expect("host memory lock")
        .push((start, layout));
    start
}

/// The machine over one [`HostMemory`], which the test keeps a handle to
/// so it can look at the tables.
struct Host(Arc<HostMemory>);

// SAFETY: every frame and run is a live host allocation until it is given
// back or the memory drops, and a physical address is the allocation's
// host address, so `frame_pointer` reaches it and `physical_address`
// inverts it. Table frames are zeroed and only given back on drop.
unsafe impl Machine for Host {
    fn root_table(&self) -> PhysFrame {
        self.0.root
    }

    fn allocate_table(&self) -> Option<PhysFrame> {
        Some(host_frame(allocate(&self.0.allocations, frame_layout())))
    }

    fn frame_pointer(&self, phys: usize) -> *mut u8 {
        phys as *mut u8
    }

    fn physical_address(&self, pointer: NonNull<u8>) -> Option<usize> {
        Some(pointer.as_ptr() as usize)
    }

    fn allocate_frame(&self) -> Result<usize, AddressSpaceError> {
        Ok(allocate(&self.0.allocations, frame_layout()))
    }

    fn allocate_frame_beside(&self, _phys: usize) -> Result<usize, AddressSpaceError> {
        // The host is one memory node.
        Ok(allocate(&self.0.allocations, frame_layout()))
    }

    fn free_frame(&self, phys: usize) {
        self.0.give_back(phys);
    }

    fn allocate_run(&self, layout: Layout) -> Result<usize, AddressSpaceError> {
        Ok(allocate(&self.0.allocations, layout))
    }

    fn free_run(&self, phys: usize, _layout: Layout) {
        self.0.give_back(phys);
    }

    fn current_owner(&self) -> MemoryOwner {
        MemoryOwner::NONE
    }

    // The host walks the tables in memory: there is no TLB to drop.
    fn invalidate_local(&self, _range: VirtRange) {}

    fn shootdown(&self, _range: VirtRange) {}
}

/// Two processors, as far as the shootdown mask is concerned.
const PROCESSORS: usize = 2;

fn fresh_address_space() -> X86UserAddressSpace<Host> {
    X86UserAddressSpace::new(Host(Arc::new(HostMemory::new())), PROCESSORS)
}

/// How many fresh address spaces the two threads race through, in
/// batches of [`BATCH`] alive at once. With the reservation lock taken
/// out of `commit`, the two walks only have to meet inside one table's
/// check-then-store window once for the test to fail; this many rounds
/// gives a multi-core host thousands of chances.
const ROUNDS: usize = 4000;
const BATCH: usize = 500;

/// Two threads commit the two adjacent pages of one reservation, each its
/// own, at the same moment, in an address space with no table above
/// them: both walks need the same level-3, level-2 and level-1 tables,
/// and none exists yet. Afterwards every page must translate to a frame
/// of its own that holds what its committer wrote there.
#[test]
fn adjacent_commits_under_one_missing_table_keep_every_page() {
    for batch in 0..ROUNDS / BATCH {
        let rounds: Vec<_> = (0..BATCH)
            .map(|_| {
                let memory = Arc::new(HostMemory::new());
                let address_space = X86UserAddressSpace::new(Host(Arc::clone(&memory)), PROCESSORS);
                let range = address_space
                    .reserve(2 * PAGE)
                    .expect("reserve two pages in a fresh address space");
                assert_eq!(
                    range.start.raw(),
                    USER_VA_BASE,
                    "a fresh address space reserves from the bottom of its window"
                );
                assert!(
                    memory.root_entry_is_unused(range.start.raw()),
                    "the two pages must start with no table above them"
                );
                (address_space, range)
            })
            .collect();
        race_commits(&rounds, batch);
        for (index, (address_space, range)) in rounds.iter().enumerate() {
            let round = batch * BATCH + index;
            let mut frames = [0; 2];
            for (page, frame) in frames.iter_mut().enumerate() {
                let addr = VirtAddr::new(range.start.raw() + page * PAGE);
                *frame = committed_frame(address_space, addr, round, page);
                // SAFETY: a live host frame the page's commit took; both
                // threads have finished.
                let read = unsafe { (*frame as *const u64).read() };
                assert_eq!(
                    read,
                    marker(round, page),
                    "round {round}: page {page} reads back another page's bytes"
                );
            }
            assert_ne!(
                frames[0], frames[1],
                "round {round}: the two pages share a frame"
            );
        }
    }
}

/// Thread `page` commits page `page` of every round's reservation and
/// writes its marker through the frame it translates to.
///
/// The threads meet at a rendezvous before each round, spun rather than
/// parked so that both leave it within a few cycles of each other and
/// their walks overlap. Neither panics while the other may be waiting
/// for it there: what goes wrong is collected and reported once both
/// have finished.
fn race_commits(rounds: &[(X86UserAddressSpace<Host>, VirtRange)], batch: usize) {
    let flags = PageFlags::READ | PageFlags::WRITE;
    let arrived = AtomicUsize::new(0);
    let failures = Mutex::new(Vec::new());
    thread::scope(|scope| {
        for page in 0..2 {
            let arrived = &arrived;
            let failures = &failures;
            scope.spawn(move || {
                for (index, (address_space, range)) in rounds.iter().enumerate() {
                    let round = batch * BATCH + index;
                    arrived.fetch_add(1, Ordering::AcqRel);
                    while arrived.load(Ordering::Acquire) < 2 * (index + 1) {
                        spin_loop();
                    }
                    let mine = VirtRange::new(VirtAddr::new(range.start.raw() + page * PAGE), PAGE);
                    if let Err(error) = address_space.commit(mine, flags) {
                        let failure = format!("round {round}: page {page} commit failed: {error}");
                        failures.lock().expect("failure list").push(failure);
                        continue;
                    }
                    match address_space.translate(mine.start) {
                        Translation::Committed { frame, .. } => {
                            // SAFETY: the frame is a live host allocation
                            // this page's commit just took, and only this
                            // thread touches it.
                            unsafe { (frame.phys_addr() as *mut u64).write(marker(round, page)) };
                        }
                        other => {
                            let failure = format!(
                                "round {round}: page {page} translates as {other:?} right after \
                                 its commit"
                            );
                            failures.lock().expect("failure list").push(failure);
                        }
                    }
                }
            });
        }
    });
    let failures = failures.into_inner().expect("failure list");
    assert!(
        failures.is_empty(),
        "{} of {} commits went wrong; the first: {}",
        failures.len(),
        2 * rounds.len(),
        failures[0]
    );
}

/// The frame `addr` translates to, which a commit of it must have left.
fn committed_frame(
    address_space: &X86UserAddressSpace<Host>,
    addr: VirtAddr,
    round: usize,
    page: usize,
) -> usize {
    match address_space.translate(addr) {
        Translation::Committed { frame, .. } => frame.phys_addr(),
        other => panic!(
            "round {round}: page {page} at {:#x} was committed but translates as {other:?}",
            addr.raw()
        ),
    }
}

fn marker(round: usize, page: usize) -> u64 {
    ((round as u64) << 1) | page as u64
}

/// Runs both closures on threads of their own.
struct Threads;

impl Concurrently for Threads {
    fn join<A, B>(&self, first: A, second: B)
    where
        A: FnOnce() + Send,
        B: FnOnce() + Send,
    {
        thread::scope(|scope| {
            scope.spawn(first);
            scope.spawn(second);
        });
    }
}

/// The conformance suite every address space passes. Committed pages are
/// not mapped on the host, so the harness does not write through them.
#[test]
fn address_space_conformance() {
    run_conformance(AddressSpaceFixture {
        fresh: fresh_address_space,
        verify_writes: false,
    });
}

#[test]
fn address_space_concurrent_conformance() {
    run_concurrent_conformance(fresh_address_space, &Threads);
}
