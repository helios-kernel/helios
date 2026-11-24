//! The fiber-stack arena under real threads standing in for processors.
//!
//! A reserve commit is served from the user pool, which another processor
//! may be inside of, and a cold claim draws on the same pool while it may
//! be empty. The arena's own bookkeeping is covered by the kernel's unit
//! tests against a fake address space; what only a hosted machine adds is
//! more than one thread to take the pool's locks, so these tests are about
//! what happens when the pool is contended or empty: the commit waits and
//! is served, the claim and reserve commit answer with typed errors, and
//! nothing panics.

#![cfg(test)]

use std::alloc::Layout;
use std::collections::BTreeMap;
use std::ptr::NonNull;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use helios_hal::cpu::ProcessorId;
use helios_hal::pmm::PhysFrame;
use helios_hal::vmm::{AddressSpaceError, VirtAddr, VirtRange};
use helios_kernel::{
    AllocationTagHooks, FIBER_STACK_COMMIT_STEP, FIBER_STACK_ENTRY_RESERVE,
    FIBER_STACK_HOST_RESERVE, FiberStack, FiberStackError, FiberStackVmHooks, StackFault,
    StackReserveError, allocate_user_frame_zeroed, allocate_user_run_zeroed_on, claim_fiber_stack,
    classify_stack_fault, commit_fiber_stack_reserve, deallocate_user_frame,
    deallocate_user_run_on, install_fiber_stack_arena, install_fiber_stack_hooks,
    install_user_memory_pool,
};

use crate::cpu::set_current_processor;

/// Ninety-six pages deep: a fault at the bottom has most of them to commit.
const STACK_BYTES: usize = 96 * PhysFrame::SIZE;
const SLOTS: usize = 2;
/// Two processors that run fibers and a third that contends for the pool.
const PROCESSORS: usize = 3;
/// The processor that holds the pool's lock in the contended tests.
const CONTENDING_PROCESSOR: u16 = 2;
/// A cold claim's entry window, in pages.
const ENTRY_WINDOW_PAGES: usize = FIBER_STACK_ENTRY_RESERVE / PhysFrame::SIZE;
const ARENA_BASE: usize = 0x0000_4000_0000_0000;

/// The fake page table: every mapped page and the frame behind it. A real
/// address space owns the frames it maps and gives them back with the
/// range that held them, and so does this.
static MAPPED: Mutex<BTreeMap<usize, usize>> = Mutex::new(BTreeMap::new());
static PREPARED: AtomicUsize = AtomicUsize::new(0);

static HOOKS: FiberStackVmHooks = FiberStackVmHooks {
    reserve: |bytes| Ok(VirtRange::new(VirtAddr::new(ARENA_BASE), bytes)),
    prepare_demand_commit: |_, _| {
        PREPARED.fetch_add(1, Ordering::Relaxed);
        Ok(())
    },
    commit_demand_page: |addr, frame, _| {
        let mut mapped = MAPPED.lock().expect("fake page table");
        if mapped.insert(addr.raw(), frame.as_ptr() as usize).is_some() {
            return Err(AddressSpaceError::Overlap);
        }
        Ok(())
    },
    end_demand_commit: |virt, _| {
        let mut mapped = MAPPED.lock().expect("fake page table");
        let pages: Vec<usize> = mapped
            .range(virt.start.raw()..virt.end().raw())
            .map(|(page, _)| *page)
            .collect();
        for page in pages {
            let frame = mapped.remove(&page).expect("a page just listed");
            deallocate_user_frame(NonNull::new(frame as *mut u8).expect("a mapped frame"));
        }
        Ok(())
    },
    tags: AllocationTagHooks::NONE,
};

/// Builds the user pool and the arena on top of it, with the calling
/// thread as processor 0. Each test runs in its own process, so the
/// install-once statics are fresh.
fn arena() {
    set_current_processor(ProcessorId::new(0));
    install_user_memory_pool(crate::test_pool::single_node_machine(PROCESSORS));
    install_fiber_stack_hooks(&HOOKS);
    install_fiber_stack_arena(SLOTS, STACK_BYTES, 0);
}

/// The contending processor's side of a contended pool: every pass takes
/// and gives back a run of two frames, which the pool serves from its
/// buddy heap under the buddy lock and never from a frame cache.
fn hammer_the_buddy_lock(stop: &AtomicBool) -> usize {
    let processor = ProcessorId::new(CONTENDING_PROCESSOR);
    set_current_processor(processor);
    let layout = Layout::from_size_align(2 * PhysFrame::SIZE, PhysFrame::SIZE).expect("run layout");
    let mut passes = 0;
    while !stop.load(Ordering::Acquire) {
        let run = allocate_user_run_zeroed_on(processor, layout)
            .expect("the pool has room for a two-frame run");
        deallocate_user_run_on(processor, run, layout);
        passes += 1;
    }
    passes
}

#[test]
fn a_cold_claim_and_a_reserve_commit_with_the_pool_exhausted_answer_without_panicking() {
    arena();
    // Everything the pool has.
    let mut held = Vec::new();
    while let Ok(frame) = allocate_user_frame_zeroed() {
        held.push(frame);
    }

    let refusal = claim_fiber_stack(STACK_BYTES).err();
    assert!(
        matches!(refusal, Some(FiberStackError::OutOfMemory(_))),
        "a cold claim with the pool exhausted is a typed out-of-memory error: {refusal:?}"
    );
    assert_eq!(PREPARED.load(Ordering::Relaxed), 0);

    // With the window's frames back the claim succeeds; then the pool
    // runs dry again and a reserve commit needing more than is left is
    // refused with a typed error, not fatal, while a guard hit stays a
    // guard classification.
    for _ in 0..ENTRY_WINDOW_PAGES {
        deallocate_user_frame(held.pop().expect("a frame to give back"));
    }
    let stack = claim_fiber_stack(STACK_BYTES).expect("the entry window's frames are back");
    let guard = classify_stack_fault(VirtAddr::new(stack.range().start - PhysFrame::SIZE));
    assert!(
        matches!(guard, StackFault::Guard { .. }),
        "a guard hit classifies as a guard overflow: {guard:?}"
    );
    let refusal = commit_fiber_stack_reserve(entry_sp(&stack));
    assert!(
        matches!(refusal, Err(StackReserveError::OutOfMemory(_))),
        "a reserve commit the pool cannot back is a typed out-of-memory error: {refusal:?}"
    );
    assert_eq!(
        MAPPED.lock().expect("fake page table").len(),
        ENTRY_WINDOW_PAGES,
        "the refused commit mapped nothing beyond the entry window"
    );
}

/// A stack pointer two pages and a little below the top of `stack`, where
/// host code with the entry window under it has run.
fn entry_sp(stack: &FiberStack) -> usize {
    stack.range().end - 2 * PhysFrame::SIZE - 100
}

/// The run a commit at [`entry_sp`] leaves committed, in pages: the two
/// pages above the stack pointer, the reserve and the step below it, and the
/// page the stack pointer's own offset rounds down into.
const ENTRY_COMMIT_PAGES: usize =
    2 + (FIBER_STACK_HOST_RESERVE + FIBER_STACK_COMMIT_STEP) / PhysFrame::SIZE + 1;

#[test]
fn two_processors_commit_their_reserves_while_a_third_holds_the_pool() {
    arena();
    let stop = AtomicBool::new(false);

    std::thread::scope(|scope| {
        let hammer = scope.spawn(|| hammer_the_buddy_lock(&stop));
        for _ in 0..200 {
            // Two stacks, each committed by its own processor at the same
            // time, against the third processor's use of the pool. No
            // reserve exists here: every frame comes through the pool, and
            // a commit that gave up on a lock another processor holds would
            // fail this.
            let first = claim_fiber_stack(STACK_BYTES).expect("a free slot");
            let second = claim_fiber_stack(STACK_BYTES).expect("a second free slot");
            let committed = std::thread::scope(|commits| {
                [(0, &first), (1, &second)]
                    .map(|(processor, stack)| {
                        commits.spawn(move || {
                            set_current_processor(ProcessorId::new(processor));
                            commit_fiber_stack_reserve(entry_sp(stack))
                        })
                    })
                    .map(|commit| commit.join().expect("the committing processor"))
            });
            for (stack, limit) in [&first, &second].into_iter().zip(committed) {
                let top = stack.range().end;
                let need = top - ENTRY_COMMIT_PAGES * PhysFrame::SIZE;
                assert_eq!(
                    limit.expect("a commit that waits for the pool is served"),
                    need + FIBER_STACK_HOST_RESERVE,
                    "each stack's commit answers its own floor plus the reserve"
                );
                assert_eq!(
                    MAPPED
                        .lock()
                        .expect("fake page table")
                        .range(need..top)
                        .count(),
                    ENTRY_COMMIT_PAGES,
                    "the whole run below the stack pointer is mapped"
                );
            }
            drop((first, second));
        }
        stop.store(true, Ordering::Release);
        let passes = hammer.join().expect("the contending processor");
        assert!(passes > 0, "the third processor used the pool meanwhile");
    });
    assert!(
        MAPPED.lock().expect("fake page table").is_empty(),
        "every stack gave its frames back"
    );
}
