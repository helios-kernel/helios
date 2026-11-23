//! Lazily committed fiber stacks.
//!
//! Every store the component host runs owns one async fiber stack, and
//! the stack is sized for the deepest thing that runs on it — CPython's
//! class construction — rather than for what an average program touches.
//! Committing that span up front is what made a live instance cost
//! megabytes of user memory it never read.
//!
//! So the kernel reserves one *arena* of user address space at engine
//! construction, `slots × (guard + stack)`, and hands the runtime stacks
//! out of it. A slot is `[guard][stack]` with the guard at the bottom,
//! the direction a stack grows. Only the top page of a fresh stack is
//! committed, through the user pool's fallible path; every page below it
//! arrives when something faults on it, and when the stack is dropped the
//! slot keeps those pages for the next stack while a machine-wide budget
//! has room for them, or gives them back when it does not.
//!
//! # Retained slots
//!
//! Giving a slot's pages back is the expensive half of a stack's life:
//! every page unmapped is a TLB shootdown to every other processor, and
//! under a hypervisor an interrupt to an idle processor is a wake-up
//! measured in hundreds of microseconds. A store is torn down on the
//! spawn path, so that cost lands on every process start. A released
//! slot therefore stays *warm* — its committed pages kept, its region
//! still recorded — and the next stack claims a warm slot before a cold
//! one: no page-table work, no fault for the pages the last stack
//! touched, and no shootdown when it goes. The pages a warm slot holds
//! count against `retain_budget`; a release that would exceed it gives
//! its pages back instead. A warm slot carries what its last stack
//! wrote, which is the runtime's own contract for a reused stack
//! (`async_stack_zeroing(false)`).
//!
//! # Why the arena exists at all
//!
//! A fault-time commit runs on the faulting stack's own processor,
//! inside whatever the interrupted code was doing, and the arena's shape
//! is what lets it be short:
//!
//! - Classifying an address is arithmetic. Subtract the base, divide by
//!   the slot stride, compare against the guard length, read one atomic
//!   flag. No lookup, no tracker, no list.
//! - The page tables above the leaf already exist, because
//!   [`hal::vmm::AddressSpace::prepare_demand_commit`](helios_hal::vmm::AddressSpace::prepare_demand_commit)
//!   built them on the ordinary locked path when the stack was created.
//!   The fault writes leaf entries into tables nothing is editing.
//! - The frames come from one of two places, chosen by what the fault
//!   interrupted. Every lock on the user pool's path is an
//!   [`IrqSafeMutex`](super::irq_safe), which masks the holder's
//!   interrupts while it is held, so a context that was interrupted with
//!   interrupts enabled holds none of them, and the fault takes its
//!   frames through the pool's ordinary blocking path: it only ever waits
//!   for another processor's critical section, which waits for nothing.
//!   A context interrupted with interrupts masked may hold one, so the
//!   fault cannot wait: it takes its frames from the per-processor
//!   [`super::frame_reserve`], which no lock guards.
//!
//! # Concurrency contract
//!
//! The arena is machine-wide and every one of its operations may arrive
//! from any processor:
//!
//! - `claim` and the release in [`FiberStack`]'s `Drop` run on the
//!   ordinary path with no fault outstanding. They may wait on the pool's
//!   locks and take the address space's own lock through the hooks.
//!   Slot state moves by compare-and-swap.
//! - [`resolve_stack_fault`] runs in fault context on the processor that
//!   faulted. Classification is lock-free. Frames are taken through the
//!   pool's blocking path, which takes only `IrqSafeMutex` locks, when the
//!   interrupted context says it was running with interrupts enabled
//!   ([`InterruptedContext`]), and from the processor's own lock-free
//!   reserve when it says they were masked; the first form waits on
//!   another processor's pool critical section if it meets one, the
//!   second never waits. The leaf writes that map the frames take no lock
//!   and need no shootdown: a not-present page becoming present is one no
//!   processor caches. Nothing fans out to another processor.
//!
//! One fiber runs on one processor at a time, so the pages of a given
//! slot are only ever faulted in by one processor at a time; the atomics
//! below are what keep that true against a fiber that migrates between
//! polls, and what keep a claim on one processor from racing a release
//! on another. Per-processor counters are a [`PerProcessor`] table: each
//! processor's on a cache line of its own, in its own node's memory.
//!
//! A slot's `node` is written by the claiming processor (any processor)
//! on a cold claim and read by every claim's scan for a warm slot; it
//! sits in the slot's padded block, which claim and release already
//! write.
//!
//! A slot's guard page is never mapped. Guest code that overflows its
//! stack hits it and the runtime turns the fault into a wasm trap;
//! kernel code that overflows one hits the same page with nothing to
//! unwind, and [`StackFault`] is what names the slot in the fatal
//! report.

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt;
use core::ops::Range;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering};

use crossbeam_utils::CachePadded;
use helios_hal::cpu::{ProcessorId, current_processor};
use helios_hal::numa::NodeId;
use helios_hal::pmm::PhysFrame;
use helios_hal::tagging::{AllocationTags, NoAllocationTags, Tag, TagSet};
use helios_hal::vmm::{AddressSpaceError, PageFlags, VirtAddr, VirtRange};
use spin::Once;
use thiserror::Error;

use super::locality::Locality;
use super::per_processor::PerProcessor;
use super::{allocate_user_frame_zeroed_on, deallocate_user_frame_on, frame_reserve};
use crate::ProgramOutOfMemory;
#[cfg(all(target_os = "none", feature = "wasmtime-bare-metal"))]
use crate::wasmtime_adapter::parking::ParkedFibers;

/// Bytes of unmapped address space below every fiber stack.
///
/// One page would catch a walk off the bottom of the stack, and nothing
/// else. A frame larger than the guard could step over it and land in
/// the slot below, where the fault would look like an ordinary demand
/// commit and the overflow would go unnoticed; 64 KiB is larger than any
/// frame either Cranelift or the kernel's own Rust code builds, so an
/// overflow always lands inside it.
pub const FIBER_STACK_GUARD_BYTES: usize = 64 * 1024;

/// Allocation-tag operations the arena needs, as plain function pointers.
///
/// Mirrors [`AllocationTags`] without `dyn`: a backend fills this with
/// [`AllocationTagHooks::of`] when it tags fiber stacks, or uses
/// [`AllocationTagHooks::NONE`] when it does not.
#[derive(Clone, Copy)]
pub struct AllocationTagHooks {
    /// Bytes one allocation tag covers.
    pub granule_bytes: usize,
    /// Whether the executing processor checks tags.
    pub checking: fn() -> bool,
    /// Chooses a tag outside `Tag::UNCHECKED`, `Tag::FREE` and `avoid` and
    /// stores it across `range`.
    pub assign: unsafe fn(NonNull<[u8]>, TagSet) -> Tag,
    /// Stores `tag` across `range`.
    pub store: unsafe fn(NonNull<[u8]>, Tag),
    /// Returns `addr` carrying `tag`.
    pub apply: fn(usize, Tag) -> usize,
    /// Returns `addr` with any logical tag removed.
    pub strip: fn(usize) -> usize,
}

impl AllocationTagHooks {
    /// Hook table for a concrete [`AllocationTags`] implementation.
    pub const fn of<A: AllocationTags>() -> Self {
        Self {
            granule_bytes: A::GRANULE_BYTES,
            checking: A::checking,
            assign: A::assign,
            store: A::store,
            apply: A::apply,
            strip: A::strip,
        }
    }

    /// Identity hooks for hardware that stores no allocation tags.
    pub const NONE: Self = Self::of::<NoAllocationTags>();
}

/// The address-space operations the arena needs, as plain function
/// pointers.
///
/// Same shape and reason as [`super::SwapVmHooks`]: the kernel is not
/// generic over the address space — there is exactly one per machine,
/// chosen at link time — and a `dyn AddressSpace` would put a vtable on
/// the page-fault path. The backend that owns the address space builds
/// one `&'static` table and installs it at boot.
pub struct FiberStackVmHooks {
    /// Carve the arena's virtual range. Called once.
    pub reserve: fn(usize) -> Result<VirtRange, AddressSpaceError>,
    /// Record one slot's body as a demand-commit region and build every
    /// page-table level above its leaves.
    pub prepare_demand_commit: fn(VirtRange, PageFlags) -> Result<(), AddressSpaceError>,
    /// Map one page of a prepared region from fault context.
    pub commit_demand_page: fn(VirtAddr, NonNull<u8>, PageFlags) -> Result<(), AddressSpaceError>,
    /// Give one slot's body back, frames and record together. The
    /// second range is the part of the body a commit may have mapped:
    /// from the slot's watermark to its top.
    pub end_demand_commit: fn(VirtRange, VirtRange) -> Result<(), AddressSpaceError>,
    /// Allocation-tag operations for stack bodies.
    pub tags: AllocationTagHooks,
}

/// What a fault entry knows about the context it interrupted.
///
/// The fault may wait for the user pool's locks only when the interrupted
/// context holds none of them. Every one of those locks masks its
/// holder's interrupts, so the interrupted context's own interrupt-enable
/// bit, as the exception saved it, is the whole answer: enabled, the
/// fault takes its frames through the pool; masked, it takes them from
/// the per-processor reserve. The backend reads the bit from the frame it
/// saved: `RFLAGS.IF` on x86, `SPSR_EL1.I` (inverted) on aarch64,
/// `sstatus.SPIE` on riscv.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InterruptedContext {
    /// Whether the context the fault interrupted was running with
    /// interrupts enabled.
    pub interrupts_enabled: bool,
}

/// What a backend's fault entry does with a faulting address.
///
/// The three fault entries all read the same way: ask, return when the
/// answer is [`StackFault::Committed`], and carry the value into the
/// fatal report otherwise. [`StackFault`]'s `Display` is written to be
/// appended to that report — it says nothing at all for an address the
/// arena does not own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StackFault {
    /// The arena does not own this address; the fault belongs to
    /// whatever the entry would have done with it anyway.
    Elsewhere,
    /// A reserved page inside a live stack, committed in place together
    /// with any gap between it and the committed range. The faulting
    /// instruction runs again.
    Committed,
    /// The user pool could not back the faulting page and the gap above
    /// it. Nothing was committed: the stack is as the fault found it.
    Starved {
        slot: usize,
        addr: usize,
        shortfall: ProgramOutOfMemory,
    },
    /// The guard page below a live fiber stack: a stack overflow.
    ///
    /// Guest code overflowing its stack is the runtime's to trap, so the
    /// entry hands the fault on as it always did. Kernel code that
    /// overflows a fiber stack has nothing to unwind, so the runtime
    /// declines it and the entry's fatal path reports this.
    Guard { slot: usize, addr: usize },
}

impl fmt::Display for StackFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Elsewhere | Self::Committed => Ok(()),
            Self::Starved {
                slot,
                addr,
                shortfall,
            } => write!(
                f,
                "; {addr:#x} in fiber stack slot {slot} needed a page and the user pool is \
                 exhausted: {shortfall}"
            ),
            Self::Guard { slot, addr } => write!(
                f,
                "; {addr:#x} is the guard page below fiber stack slot {slot}, so a kernel path \
                 overflowed a fiber stack"
            ),
        }
    }
}

/// Why a stack could not be handed out.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum FiberStackError {
    #[error("the fiber stack arena was not built before a stack was asked for")]
    NoArena,
    #[error(
        "the runtime asked for a {requested}-byte fiber stack and the arena's slots are \
         {slot} bytes"
    )]
    WrongSize { requested: usize, slot: usize },
    #[error("every one of the arena's {slots} fiber stack slots is live")]
    Exhausted { slots: usize },
    #[error("the address space refused to prepare a fiber stack slot: {0}")]
    Prepare(#[source] AddressSpaceError),
    /// The user pool could not back the stack's top page. The runtime
    /// wraps this in its own error, so the failed instantiation or call
    /// is classified as running out of memory like any refused grow.
    #[error("the user pool could not back a fiber stack's top page: {0}")]
    OutOfMemory(#[source] ProgramOutOfMemory),
}

/// One slot's mutable state.
///
/// `live` is written by the claim that takes the slot and by the release
/// that gives it back, from any processor. `watermark` is written by the
/// fault path on whichever processor is running the fiber, and read by
/// the release; it is the lowest address in this slot anything has ever
/// faulted on, and `body_top` when nothing has.
/// A slot with nothing mapped and no region recorded.
const SLOT_COLD: u8 = 0;
/// A released slot whose pages are still committed, counted against the
/// arena's retain budget, waiting for the next claim.
const SLOT_WARM: u8 = 1;
/// A slot a running stack owns.
const SLOT_LIVE: u8 = 2;

/// Every move between the three states is one compare-and-swap on
/// `state`, which is what lets a claim on one processor race a release
/// on another without a lock.
struct FiberStackSlot {
    state: AtomicU8,
    /// The node whose memory the slot's pages were last committed from:
    /// written with the claimant's node by a cold claim, which commits
    /// the top page and takes most of the rest by fault on the
    /// claimant's processor, and read by every claim's scan for a warm
    /// slot. A warm slot outlives the processor that faulted it, so this
    /// is what lets the next claimant prefer pages on its own node.
    /// Meaningless while the slot is cold.
    node: AtomicU8,
    /// The logical tag of the live stack owning this slot, or the tag its
    /// previous owner held while the slot is warm or cold so the next claim
    /// avoids repeating it. Stored as [`Tag::raw`].
    tag: AtomicU8,
    watermark: AtomicUsize,
    /// One bit per page in the slot's body, set when that page is mapped.
    /// A large stack frame can skip a page and leave a hole between
    /// `watermark` and `body_top`; tagging loops walk only the set bits so
    /// they never issue a tag store against an unmapped hole.
    committed_pages: Box<[AtomicU64]>,
    /// The Wasmtime unpark generation the fiber on this stack last
    /// returned from a parking wait at; see
    /// `wasmtime_adapter::parking`. A value left by an earlier fiber is
    /// one the generation has already reached, so it can only make the
    /// next fiber's first wait return early, never miss an unpark.
    #[cfg(all(target_os = "none", feature = "wasmtime-bare-metal"))]
    parked_generation: AtomicU64,
}

impl FiberStackSlot {
    fn mark_page_committed(&self, page_index: usize) {
        let word = page_index / 64;
        let bit = page_index % 64;
        self.committed_pages[word].fetch_or(1u64 << bit, Ordering::Release);
    }

    fn clear_committed_pages(&self) {
        for word in &self.committed_pages {
            word.store(0, Ordering::Release);
        }
    }

    fn for_each_committed_page(&self, body_start: usize, mut visit: impl FnMut(usize)) {
        for (word_index, word) in self.committed_pages.iter().enumerate() {
            let mut bits = word.load(Ordering::Acquire);
            while bits != 0 {
                let bit = bits.trailing_zeros() as usize;
                let page_index = word_index * 64 + bit;
                visit(body_start + page_index * PhysFrame::SIZE);
                bits &= bits - 1;
            }
        }
    }
}

/// The machine's fiber stacks.
pub struct FiberStackArena {
    hooks: &'static FiberStackVmHooks,
    checking: bool,
    base: usize,
    slot_bytes: usize,
    stack_bytes: usize,
    slots: Box<[CachePadded<FiberStackSlot>]>,
    /// The most bytes warm slots may hold between them.
    retain_budget: usize,
    /// Bytes warm slots hold now. Written on every claim and release from
    /// whichever processor runs them, so it sits on its own line.
    retained_bytes: CachePadded<AtomicUsize>,
    /// One block per processor, on its own line and in its own node's
    /// memory, because `demand_commits` is written from fault context on
    /// its own processor.
    processors: PerProcessor<ProcessorCommits>,
    /// Where each processor sits, for the warm-slot node preference.
    locality: &'static Locality,
    /// What every released stack cost, summed. Written on the release
    /// path from whichever processor tears the store down, which is why
    /// the pair sits on its own line rather than beside a per-processor
    /// counter.
    released: CachePadded<ReleasedTotals>,
    /// The Wasmtime parking registry of the fibers these stacks run.
    /// Written by every unpark, from whichever processor runs the
    /// notifying wasm thread, so it sits on its own line.
    #[cfg(all(target_os = "none", feature = "wasmtime-bare-metal"))]
    parked: CachePadded<ParkedFibers>,
}

/// What one processor has done for the arena.
struct ProcessorCommits {
    /// Demand commits this processor has resolved. Written by this
    /// processor alone, from fault context.
    demand_commits: AtomicU64,
    /// Pages those faults mapped, the faulting page and any gap above it
    /// together. Written like `demand_commits`, by the owning processor
    /// alone.
    committed_pages: AtomicU64,
    /// Whether the console has already been told this processor is
    /// resolving commits. Swapped once, from the release path, which is a
    /// place a `tracing` call is allowed; see
    /// [`FiberStackArena::announce_processors`].
    announced: AtomicBool,
}

struct ReleasedTotals {
    stacks: AtomicU64,
    committed_bytes: AtomicU64,
}

/// What the arena is holding, for the boot log and the stats panel.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FiberStackArenaStats {
    /// Slots the arena has in total.
    pub slots: usize,
    /// Slots a live stack is using right now.
    pub live_slots: usize,
    /// Released slots still holding their pages for the next stack.
    pub warm_slots: usize,
    /// Bytes those warm slots hold, against the retain budget.
    pub retained_bytes: usize,
    /// Bytes of user memory the live stacks have actually faulted in.
    pub committed_bytes: usize,
    /// Bytes of user memory the same stacks would have cost committed
    /// up front.
    pub eager_bytes: usize,
    /// Demand commits resolved since boot, across every processor.
    pub demand_commits: u64,
    /// Pages those demand commits mapped, skipped gaps included.
    pub demand_committed_pages: u64,
    /// Stacks given back over the life of the arena.
    pub released_stacks: u64,
    /// Bytes those stacks had committed when they were given back.
    pub released_committed_bytes: u64,
    /// What the same stacks would have cost committed up front.
    pub released_eager_bytes: u64,
}

static HOOKS: Once<&'static FiberStackVmHooks> = Once::new();
static ARENA: Once<FiberStackArena> = Once::new();

/// Publishes the address space's demand-commit surface. Called once by
/// the backend that owns the address space, before any engine is built.
pub fn install_fiber_stack_hooks(hooks: &'static FiberStackVmHooks) {
    let mut installed = false;
    HOOKS.call_once(|| {
        installed = true;
        hooks
    });
    assert!(installed, "fiber-stack address-space hooks installed twice");
}

/// Builds the arena, once, for `slots` stacks of `stack_bytes` each.
///
/// Called at engine construction. The kernel builds more than one engine
/// and they share this arena: the number that bounds live stacks is the
/// kernel's instance budget, which is machine-wide, and each engine's
/// own stack pool carries the same number.
///
/// # Panics
///
/// When the backend installed no hooks, or when the address space
/// refuses the reservation. Both are boot-time configuration failures on
/// a target that has no second way to place a fiber stack, so they are
/// reported here rather than answered with a smaller stack or an eagerly
/// committed one.
pub fn install_fiber_stack_arena(slots: usize, stack_bytes: usize, retain_bytes: usize) {
    ARENA.call_once(|| {
        let hooks = *HOOKS.get().unwrap_or_else(|| {
            panic!(
                "this backend installed no fiber-stack address-space hooks, so it cannot host \
                 the lazily committed fiber stacks the component engine needs"
            )
        });
        assert!(slots != 0, "the fiber stack arena needs at least one slot");
        assert!(
            stack_bytes != 0 && stack_bytes.is_multiple_of(PhysFrame::SIZE),
            "a fiber stack of {stack_bytes} bytes is not a whole number of pages"
        );
        let checking = (hooks.tags.checking)();
        if checking {
            assert!(
                hooks.tags.granule_bytes.is_power_of_two()
                    && PhysFrame::SIZE.is_multiple_of(hooks.tags.granule_bytes),
                "allocation tag granule {} must be a power of two dividing a page",
                hooks.tags.granule_bytes,
            );
        }
        let pool = super::user_memory_pool();
        let slot_bytes = FIBER_STACK_GUARD_BYTES
            .checked_add(stack_bytes)
            .unwrap_or_else(|| panic!("fiber stack slot size overflows"));
        let bytes = slot_bytes
            .checked_mul(slots)
            .unwrap_or_else(|| panic!("fiber stack arena size overflows"));
        let range = (hooks.reserve)(bytes).unwrap_or_else(|error| {
            panic!("the address space refused the {bytes}-byte fiber stack arena: {error}")
        });
        let bitmap_words = (stack_bytes / PhysFrame::SIZE).div_ceil(64);
        let mut slot_states = Vec::with_capacity(slots);
        slot_states.resize_with(slots, || {
            let mut committed_pages = Vec::with_capacity(bitmap_words);
            committed_pages.resize_with(bitmap_words, || AtomicU64::new(0));
            CachePadded::new(FiberStackSlot {
                state: AtomicU8::new(SLOT_COLD),
                node: AtomicU8::new(0),
                tag: AtomicU8::new(Tag::FREE.raw()),
                watermark: AtomicUsize::new(0),
                committed_pages: committed_pages.into_boxed_slice(),
                #[cfg(all(target_os = "none", feature = "wasmtime-bare-metal"))]
                parked_generation: AtomicU64::new(0),
            })
        });
        tracing::info!(
            target: "helios_kernel::fiber_stack",
            base = range.start.raw(),
            slots,
            stack_bytes,
            guard_bytes = FIBER_STACK_GUARD_BYTES,
            reserved_bytes = bytes,
            retain_bytes,
            tagged = checking,
            "fiber stack arena reserved; stacks commit on demand"
        );
        FiberStackArena {
            hooks,
            checking,
            base: range.start.raw(),
            slot_bytes,
            stack_bytes,
            slots: slot_states.into_boxed_slice(),
            retain_budget: retain_bytes,
            retained_bytes: CachePadded::new(AtomicUsize::new(0)),
            processors: PerProcessor::new(pool, |_, _| ProcessorCommits {
                demand_commits: AtomicU64::new(0),
                committed_pages: AtomicU64::new(0),
                announced: AtomicBool::new(false),
            }),
            locality: pool.locality(),
            released: CachePadded::new(ReleasedTotals {
                stacks: AtomicU64::new(0),
                committed_bytes: AtomicU64::new(0),
            }),
            #[cfg(all(target_os = "none", feature = "wasmtime-bare-metal"))]
            parked: CachePadded::new(ParkedFibers::new()),
        }
    });
}

/// Whether this machine has an arena, and so anything that draws on the
/// page-fault frame reserve.
pub(super) fn arena_installed() -> bool {
    ARENA.get().is_some()
}

/// What the arena is holding right now, or nothing when this machine
/// has none.
pub fn fiber_stack_arena_stats() -> Option<FiberStackArenaStats> {
    ARENA.get().map(FiberStackArena::stats)
}

/// Demand commits processor `processor` has resolved since boot.
pub fn fiber_stack_demand_commits_on(processor: ProcessorId) -> u64 {
    ARENA
        .get()
        .and_then(|arena| arena.processors.try_get(processor))
        .map_or(0, |commits| commits.demand_commits.load(Ordering::Relaxed))
}

/// Classifies `addr` and, when it is a demand-commit page, resolves it.
///
/// This is what a backend's fault entry calls, with what it knows of the
/// context the fault interrupted. Classification takes no lock and walks
/// no list. Resolving takes the frames through the user pool's blocking
/// path when `interrupted` says interrupts were enabled, which the module
/// docs show is safe, and from the processor's reserve when it says they
/// were masked.
///
/// # Panics
///
/// When `interrupted` says interrupts were masked and the processor's
/// reserve cannot supply the frames the fault needs: a path holding an
/// interrupt-masking lock grew its stack further than the reserve covers
/// between two refills, or the pool is exhausted.
pub fn resolve_stack_fault(addr: VirtAddr, interrupted: InterruptedContext) -> StackFault {
    let Some(arena) = ARENA.get() else {
        return StackFault::Elsewhere;
    };
    arena.resolve(addr, interrupted)
}

impl FiberStackArena {
    fn reserved_bytes(&self) -> usize {
        self.slot_bytes * self.slots.len()
    }

    /// The body of slot `index`: the stack itself, above its guard.
    fn body(&self, index: usize) -> VirtRange {
        let start = self.base + index * self.slot_bytes + FIBER_STACK_GUARD_BYTES;
        VirtRange::new(VirtAddr::new(start), self.stack_bytes)
    }

    fn guard(&self, index: usize) -> Range<*mut u8> {
        let start = self.base + index * self.slot_bytes;
        (start as *mut u8)..((start + FIBER_STACK_GUARD_BYTES) as *mut u8)
    }

    fn page_flags(&self) -> PageFlags {
        let mut flags = PageFlags::READ | PageFlags::WRITE;
        if self.checking {
            flags |= PageFlags::TAGGED;
        }
        flags
    }

    fn page_range(page: usize) -> NonNull<[u8]> {
        let ptr = NonNull::new(page as *mut u8).expect("a mapped fiber-stack page is not null");
        NonNull::slice_from_raw_parts(ptr, PhysFrame::SIZE)
    }

    /// Assigns one fresh tag avoiding `slot`'s previous tag across every
    /// committed page of `index`, and publishes that tag on `slot`.
    fn tag_committed_pages(&self, index: usize) -> Tag {
        if !self.checking {
            return Tag::UNCHECKED;
        }
        let slot = &self.slots[index];
        let body = self.body(index);
        let previous = Tag::new(slot.tag.load(Ordering::Relaxed));
        let avoid = TagSet::EMPTY.with(previous);
        let mut assigned: Option<Tag> = None;
        slot.for_each_committed_page(body.start.raw(), |page| {
            let range = Self::page_range(page);
            match assigned {
                None => {
                    // SAFETY: `page` is a committed `PageFlags::TAGGED` page
                    // of a slot exclusively owned by this live claim, and
                    // `PhysFrame::SIZE` is a multiple of the tag granule.
                    let tag = unsafe { (self.hooks.tags.assign)(range, avoid) };
                    assigned = Some(tag);
                }
                Some(tag) => {
                    // SAFETY: as above.
                    unsafe { (self.hooks.tags.store)(range, tag) };
                }
            }
        });
        let tag = assigned.expect("a claimed fiber stack has at least its top page committed");
        slot.tag.store(tag.raw(), Ordering::Release);
        tag
    }

    /// Returns every committed page of slot `index` to [`Tag::FREE`] so any
    /// stale pointer left behind by the released stack faults on access.
    fn clear_slot_tags(&self, index: usize) {
        if !self.checking {
            return;
        }
        let slot = &self.slots[index];
        let body = self.body(index);
        slot.for_each_committed_page(body.start.raw(), |page| {
            // SAFETY: `page` is still mapped `PageFlags::TAGGED` in this slot,
            // which is being released exclusively by its owner.
            unsafe { (self.hooks.tags.store)(Self::page_range(page), Tag::FREE) };
        });
    }

    #[cfg(all(target_os = "none", feature = "wasmtime-bare-metal"))]
    fn parked_generation(&self, addr: usize) -> &AtomicU64 {
        let addr = (self.hooks.tags.strip)(addr);
        let index = addr
            .checked_sub(self.base)
            .filter(|offset| *offset < self.reserved_bytes())
            .map(|offset| offset / self.slot_bytes)
            .unwrap_or_else(|| {
                panic!(
                    "Wasmtime parking wait at stack address {addr:#x}, outside the fiber-stack \
                     arena: only a fiber can give its processor back while it waits"
                )
            });
        let slot = &self.slots[index];
        assert_eq!(
            slot.state.load(Ordering::Acquire),
            SLOT_LIVE,
            "Wasmtime parking wait on fiber stack slot {index}, which no live stack owns"
        );
        &slot.parked_generation
    }

    /// Resolves a fault at `addr`, or classifies it.
    ///
    /// A fault on a page of a live stack's body maps `[page, watermark)`:
    /// the faulting page and any gap a large frame skipped above it, so
    /// the committed range stays one run `[watermark, top)`, every page
    /// charged to the pool as user memory. The frames are all taken before
    /// any is mapped. A fault that interrupted a context with interrupts
    /// enabled takes them through the pool and answers
    /// [`StackFault::Starved`] with nothing mapped when the pool cannot
    /// back them all; one that interrupted a masked context takes them
    /// from the processor's reserve without touching the pool.
    ///
    /// Concurrency: fault context on the faulting processor, see the
    /// module docs. The slot's watermark has one writer, the processor
    /// running its fiber.
    ///
    /// # Panics
    ///
    /// - The slot is not live: the runtime is running on a stack it gave
    ///   back.
    /// - The page is already inside the committed range: the stack's
    ///   bookkeeping and its page tables disagree.
    /// - The faulting context had interrupts masked and the processor's
    ///   reserve cannot supply the frames.
    fn resolve(&self, addr: VirtAddr, interrupted: InterruptedContext) -> StackFault {
        let raw = (self.hooks.tags.strip)(addr.raw());
        let Some(offset) = raw.checked_sub(self.base) else {
            return StackFault::Elsewhere;
        };
        if offset >= self.reserved_bytes() {
            return StackFault::Elsewhere;
        }
        let index = offset / self.slot_bytes;
        let within = offset - index * self.slot_bytes;
        let slot = &self.slots[index];
        if slot.state.load(Ordering::Acquire) != SLOT_LIVE {
            panic!(
                "page fault at {raw:#x} inside fiber stack slot {index}, which no live stack \
                 owns: the runtime is running on a stack it gave back"
            );
        }
        if within < FIBER_STACK_GUARD_BYTES {
            return StackFault::Guard {
                slot: index,
                addr: raw,
            };
        }
        let page = raw & !(PhysFrame::SIZE - 1);
        let committed_from = slot.watermark.load(Ordering::Acquire);
        if page >= committed_from {
            panic!(
                "page fault at {raw:#x} in fiber stack slot {index}, on a page its committed range \
                 from {committed_from:#x} already maps: the stack's bookkeeping and its page tables \
                 disagree"
            );
        }
        let pages = (committed_from - page) / PhysFrame::SIZE;
        let processor = current_processor();
        let mut frames = if interrupted.interrupts_enabled {
            match FrameChain::take(processor, pages) {
                Ok(frames) => frames,
                Err(shortfall) => {
                    return StackFault::Starved {
                        slot: index,
                        addr: raw,
                        shortfall,
                    };
                }
            }
        } else {
            FrameChain::take_from_reserve(processor, pages).unwrap_or_else(|held| {
                panic!(
                    "a fault at {raw:#x} in fiber stack slot {index}, from a context running with \
                     interrupts masked, needed {pages} frames and processor {} reserved {held} of \
                     its {}: a path holding an interrupt-masking lock grew its stack further than \
                     the reserve covers between two refills, or the user pool is exhausted",
                    processor.id(),
                    frame_reserve::RESERVE_CAPACITY,
                )
            })
        };
        let live_tag = self
            .checking
            .then(|| Tag::new(slot.tag.load(Ordering::Acquire)));
        if let Err(error) = self.map_frames(index, &mut frames, live_tag) {
            panic!(
                "page fault at {raw:#x} in fiber stack slot {index} could not be committed in \
                 place: {error}"
            );
        }
        let commits = self.processors.get(processor);
        commits.demand_commits.fetch_add(1, Ordering::Relaxed);
        commits
            .committed_pages
            .fetch_add(pages as u64, Ordering::Relaxed);
        if interrupted.interrupts_enabled {
            // The interrupted context held no pool lock, so the refill
            // may wait on the pool like the fault just did. It is one
            // atomic load when the reserve is full.
            frame_reserve::top_up(processor);
        }
        // Nothing is logged from here. `tracing` reaches the debug
        // console, which is a lock the interrupted code may be holding
        // on this very processor; the counters above are what the
        // release path reports instead.
        StackFault::Committed
    }

    /// Maps `frames`, one page each, immediately below slot `index`'s
    /// committed range, from the page next to it downwards.
    ///
    /// The watermark follows every page, so the committed range is one
    /// run at each step and the release walk stays exact however far a
    /// refused page got. The refused page's frame goes back on the chain:
    /// a fault that interrupted a masked context may not hand it to the
    /// pool, so what becomes of the chain is the caller's to decide.
    fn map_frames(
        &self,
        index: usize,
        frames: &mut FrameChain,
        tag_new_pages: Option<Tag>,
    ) -> Result<(), AddressSpaceError> {
        let slot = &self.slots[index];
        let body_start = self.body(index).start.raw();
        let flags = self.page_flags();
        while let Some(frame) = frames.pop() {
            let page = VirtAddr::new(slot.watermark.load(Ordering::Acquire) - PhysFrame::SIZE);
            if let Err(error) = (self.hooks.commit_demand_page)(page, frame, flags) {
                frames.push(frame);
                return Err(error);
            }
            if let Some(tag) = tag_new_pages {
                // SAFETY: `page` was just committed with `PageFlags::TAGGED`
                // in this live slot, and `PhysFrame::SIZE` is a multiple of
                // the granule.
                unsafe { (self.hooks.tags.store)(Self::page_range(page.raw()), tag) };
            }
            slot.mark_page_committed((page.raw() - body_start) / PhysFrame::SIZE);
            slot.watermark.fetch_min(page.raw(), Ordering::AcqRel);
        }
        Ok(())
    }

    /// Takes a slot: a warm one as it stands, or a cold one prepared
    /// with its top page committed, the one the runtime writes the fiber's
    /// initial frame to.
    ///
    /// The top page's frame comes from the pool's blocking fallible path
    /// and is taken before anything of the slot is touched, so a pool
    /// that cannot back it answers [`FiberStackError::OutOfMemory`] with
    /// the slot as it was found. A claim never draws on the page-fault
    /// reserve.
    ///
    /// Concurrency: ordinary context on any processor. It waits on the
    /// pool's locks, so no pool lock may be held by the caller.
    fn claim(&'static self, stack_bytes: usize) -> Result<FiberStack, FiberStackError> {
        if stack_bytes != self.stack_bytes {
            return Err(FiberStackError::WrongSize {
                requested: stack_bytes,
                slot: self.stack_bytes,
            });
        }
        let processor = current_processor();
        let node = self.locality.node_of(processor);
        if let Some(index) = self.take_warm_slot(node) {
            // The pages its last stack touched are still mapped, so the
            // runtime's first frame lands on a committed page and nothing
            // here touches the address space. Retagging gives the reused
            // pages a fresh tag distinct from the previous stack's.
            self.retained_bytes
                .fetch_sub(self.committed_bytes(index), Ordering::AcqRel);
            let tag = self.tag_committed_pages(index);
            return Ok(FiberStack {
                arena: self,
                index,
                tag,
            });
        }
        let index = self
            .take_slot(SLOT_COLD, None)
            .ok_or(FiberStackError::Exhausted {
                slots: self.slots.len(),
            })?;
        let body = self.body(index);
        // The runtime writes the fiber's initial frame at the top of the
        // stack, so that page is committed here rather than left to a
        // fault. Its frame is taken before anything of the slot is
        // touched, so a pool that cannot back it leaves the slot exactly
        // as it was found.
        let mut frames = match FrameChain::take(processor, 1) {
            Ok(frames) => frames,
            Err(shortfall) => {
                self.slots[index].state.store(SLOT_COLD, Ordering::Release);
                return Err(FiberStackError::OutOfMemory(shortfall));
            }
        };
        if let Err(error) = (self.hooks.prepare_demand_commit)(body, self.page_flags()) {
            frames.give_back(processor);
            self.slots[index].state.store(SLOT_COLD, Ordering::Release);
            return Err(FiberStackError::Prepare(error));
        }
        let body_top = body.end().raw();
        // Every page this claim commits, the top one below and the rest
        // by fault, comes from the claimant's processor, so that is the
        // node the slot's pages are on until it goes cold again.
        self.slots[index]
            .node
            .store(node.index() as u8, Ordering::Relaxed);
        self.slots[index].clear_committed_pages();
        self.slots[index]
            .watermark
            .store(body_top, Ordering::Release);
        if let Err(error) = self.map_frames(index, &mut frames, None) {
            frames.give_back(processor);
            (self.hooks.end_demand_commit)(body, body).unwrap_or_else(|cleanup| {
                panic!(
                    "fiber stack slot {index} could not be given back after its top page was \
                     refused ({error}): {cleanup}"
                )
            });
            self.slots[index]
                .watermark
                .store(body_top, Ordering::Release);
            self.slots[index].state.store(SLOT_COLD, Ordering::Release);
            return Err(FiberStackError::Prepare(error));
        }
        let tag = self.tag_committed_pages(index);
        Ok(FiberStack {
            arena: self,
            index,
            tag,
        })
    }

    /// Moves the lowest slot in state `from` to live and returns it.
    ///
    /// Lowest first, on purpose: a cold claim then lands on a slot whose
    /// leaf tables an earlier claim already built, and the warm slots
    /// stay packed at the bottom of the arena. The load before the
    /// exchange keeps a scan over hundreds of live slots to plain reads.
    ///
    /// With `on_node`, only a slot whose pages sit on that node.
    fn take_slot(&self, from: u8, on_node: Option<NodeId>) -> Option<usize> {
        self.slots.iter().position(|slot| {
            slot.state.load(Ordering::Acquire) == from
                && on_node.is_none_or(|node| {
                    usize::from(slot.node.load(Ordering::Relaxed)) == node.index()
                })
                && slot
                    .state
                    .compare_exchange(from, SLOT_LIVE, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
        })
    }

    /// A warm slot for a claimant on `node`: one whose pages are on that
    /// node if there is one, any warm slot otherwise, lowest first within
    /// each. A machine with one node has no node to prefer, so it scans
    /// once.
    fn take_warm_slot(&self, node: NodeId) -> Option<usize> {
        if self.locality.node_count() > 1
            && let Some(index) = self.take_slot(SLOT_WARM, Some(node))
        {
            return Some(index);
        }
        self.take_slot(SLOT_WARM, None)
    }

    /// Bytes slot `index` has committed: from its watermark to its top.
    fn committed_bytes(&self, index: usize) -> usize {
        self.body(index)
            .end()
            .raw()
            .saturating_sub(self.slots[index].watermark.load(Ordering::Acquire))
    }

    /// Gives slot `index` back: warm, keeping its pages for the next
    /// stack, while the retain budget has room for them; otherwise cold,
    /// with every page a fault ever mapped returned to the user pool on
    /// the ordinary locked path with the shootdown that path already
    /// does.
    fn release(&self, index: usize) {
        let committed_bytes = self.committed_bytes(index);
        // Return every committed granule to `Tag::FREE` before the slot is
        // parked warm or unmapped, so stale pointers to this stack fault and
        // recycled frames never carry a live tag.
        self.clear_slot_tags(index);
        // What this stack actually cost, against what it would have cost
        // committed up front, summed for the boot-end report. Nothing is
        // logged per release: a store teardown is on the spawn path, and
        // a console line there is a serial write per instance.
        self.released.stacks.fetch_add(1, Ordering::Relaxed);
        self.released
            .committed_bytes
            .fetch_add(committed_bytes as u64, Ordering::Relaxed);
        let retained = self
            .retained_bytes
            .fetch_add(committed_bytes, Ordering::AcqRel);
        if retained + committed_bytes <= self.retain_budget {
            self.slots[index].state.store(SLOT_WARM, Ordering::Release);
            self.announce_processors();
            return;
        }
        self.retained_bytes
            .fetch_sub(committed_bytes, Ordering::AcqRel);
        let body = self.body(index);
        let watermark = self.slots[index].watermark.load(Ordering::Acquire);
        // Only the pages between the watermark and the top can be
        // mapped, so that is all the address space walks.
        let mapped = VirtRange::new(VirtAddr::new(watermark), committed_bytes);
        (self.hooks.end_demand_commit)(body, mapped).unwrap_or_else(|error| {
            panic!(
                "fiber stack slot {index} at {:#x} could not be given back: {error}",
                body.start.raw()
            )
        });
        self.slots[index].clear_committed_pages();
        self.slots[index]
            .watermark
            .store(body.end().raw(), Ordering::Release);
        self.slots[index].state.store(SLOT_COLD, Ordering::Release);
        self.announce_processors();
    }

    /// Names each processor that has resolved a demand commit, once.
    ///
    /// The fault path may not log, so this is where the per-processor
    /// counters reach the console: on the release path, at most once per
    /// processor for the whole boot. Whether the fault path works on a
    /// processor is not something to infer from a stack that did not
    /// crash, and a machine where only the bootstrap processor ever
    /// resolved one is a machine where the others were never asked.
    fn announce_processors(&self) {
        for (processor, counters) in self.processors.iter() {
            let commits = counters.demand_commits.load(Ordering::Relaxed);
            // The flag shares its processor's line with the counter the
            // fault path writes, so it is read first and written once:
            // a swap is a write even when it changes nothing.
            if commits == 0
                || counters.announced.load(Ordering::Acquire)
                || counters.announced.swap(true, Ordering::AcqRel)
            {
                continue;
            }
            tracing::info!(
                target: "helios_kernel::fiber_stack",
                processor = processor.id(),
                demand_commits = commits,
                "processor is resolving fiber stack demand commits"
            );
        }
    }

    fn stats(&self) -> FiberStackArenaStats {
        let mut live_slots = 0;
        let mut warm_slots = 0;
        let mut committed_bytes = 0;
        for (index, slot) in self.slots.iter().enumerate() {
            match slot.state.load(Ordering::Acquire) {
                SLOT_LIVE => {
                    live_slots += 1;
                    committed_bytes += self.committed_bytes(index);
                }
                SLOT_WARM => warm_slots += 1,
                _ => {}
            }
        }
        let released_stacks = self.released.stacks.load(Ordering::Relaxed);
        FiberStackArenaStats {
            slots: self.slots.len(),
            live_slots,
            warm_slots,
            retained_bytes: self.retained_bytes.load(Ordering::Acquire),
            committed_bytes,
            eager_bytes: live_slots * self.stack_bytes,
            demand_commits: self
                .processors
                .iter()
                .map(|(_, counters)| counters.demand_commits.load(Ordering::Relaxed))
                .sum(),
            demand_committed_pages: self
                .processors
                .iter()
                .map(|(_, counters)| counters.committed_pages.load(Ordering::Relaxed))
                .sum(),
            released_stacks,
            released_committed_bytes: self.released.committed_bytes.load(Ordering::Relaxed),
            released_eager_bytes: released_stacks * self.stack_bytes as u64,
        }
    }
}

/// The frames one commit needs, taken from the user pool (or, for a
/// masked fault, the processor's reserve) before any of them is mapped.
///
/// Mapping is not undone from fault context (taking a translation away
/// needs a shootdown, and frees nothing until every processor has
/// acknowledged it), so a commit that could run out of frames halfway
/// must not have mapped any. Taking all of them first makes a refusal
/// cost nothing: the chain gives its frames back to the pool and the
/// stack is as it was.
///
/// The list is threaded through the frames' own first word, as
/// [`super::frame_slab`] does, so it allocates nothing. Every frame is
/// zeroed by the pool and the link is cleared on the way out, so a frame
/// leaves the chain exactly as the pool handed it over.
///
/// Concurrency: a local value of the one context that built it.
struct FrameChain {
    head: Option<NonNull<u8>>,
}

impl FrameChain {
    /// `count` zeroed frames from the user pool, through its blocking
    /// path, or the refusal that stopped it, with what was taken given
    /// back.
    fn take(processor: ProcessorId, count: usize) -> Result<Self, ProgramOutOfMemory> {
        let mut chain = Self { head: None };
        for _ in 0..count {
            match allocate_user_frame_zeroed_on(processor) {
                Ok(frame) => chain.push(frame),
                Err(shortfall) => {
                    chain.give_back(processor);
                    return Err(shortfall);
                }
            }
        }
        Ok(chain)
    }

    /// `count` zeroed frames from `processor`'s reserve, without touching
    /// the pool, or how many the reserve held when it ran dry. The frames
    /// taken before it ran dry are not returned: the caller panics.
    fn take_from_reserve(processor: ProcessorId, count: usize) -> Result<Self, usize> {
        let mut chain = Self { head: None };
        for held in 0..count {
            match frame_reserve::take_frame(processor) {
                Some(frame) => chain.push(frame),
                None => return Err(held),
            }
        }
        Ok(chain)
    }

    fn push(&mut self, frame: NonNull<u8>) {
        // SAFETY: the pool handed this page over whole and nothing else
        // holds it, and a page has room for a pointer-sized link at its
        // start.
        unsafe { frame.cast::<Option<NonNull<u8>>>().write(self.head) };
        self.head = Some(frame);
    }

    /// The most recently taken frame, zeroed again.
    fn pop(&mut self) -> Option<NonNull<u8>> {
        let frame = self.head?;
        // SAFETY: `push` wrote the link of every frame on the chain, and
        // this one is leaving it, so nothing reads the link again.
        unsafe {
            let link = frame.cast::<Option<NonNull<u8>>>();
            self.head = link.read();
            link.write(None);
        }
        Some(frame)
    }

    fn give_back(&mut self, processor: ProcessorId) {
        while let Some(frame) = self.pop() {
            deallocate_user_frame_on(processor, frame);
        }
    }
}

/// One fiber stack, owned by the runtime for as long as its store lives.
///
/// Dropping it gives the slot back. The runtime's stack pool drops the
/// stack when the store that ran on it is torn down, and the generic
/// pool keeps nothing warm, so this is the whole lifecycle.
pub struct FiberStack {
    arena: &'static FiberStackArena,
    index: usize,
    tag: Tag,
}

impl FiberStack {
    /// The stack's usable range, guard excluded, carrying the slot's
    /// logical tag so stack-limit comparisons against `SP` share its top byte.
    pub fn range(&self) -> Range<usize> {
        let body = self.arena.body(self.index);
        let apply = self.arena.hooks.tags.apply;
        apply(body.start.raw(), self.tag)..apply(body.end().raw(), self.tag)
    }

    /// The highest address of the stack; the fiber's initial stack
    /// pointer, carrying the slot's logical tag.
    pub fn top(&self) -> *mut u8 {
        let end = self.arena.body(self.index).end().raw();
        (self.arena.hooks.tags.apply)(end, self.tag) as *mut u8
    }

    /// The unmapped range below the stack.
    pub fn guard_range(&self) -> Range<*mut u8> {
        let guard = self.arena.guard(self.index);
        let apply = self.arena.hooks.tags.apply;
        (apply(guard.start as usize, self.tag) as *mut u8)
            ..(apply(guard.end as usize, self.tag) as *mut u8)
    }
}

impl Drop for FiberStack {
    fn drop(&mut self) {
        self.arena.release(self.index);
    }
}

/// The arena's Wasmtime parking registry, and the unpark generation the
/// fiber running on the stack that holds `addr` last returned from a
/// parking wait at. Panics when `addr` is not inside a live fiber stack.
#[cfg(all(target_os = "none", feature = "wasmtime-bare-metal"))]
pub(crate) fn fiber_parking(addr: usize) -> (&'static ParkedFibers, &'static AtomicU64) {
    let arena = installed_arena();
    (&arena.parked, arena.parked_generation(addr))
}

/// The arena's Wasmtime parking registry.
#[cfg(all(target_os = "none", feature = "wasmtime-bare-metal"))]
pub(crate) fn parked_fibers() -> &'static ParkedFibers {
    &installed_arena().parked
}

#[cfg(all(target_os = "none", feature = "wasmtime-bare-metal"))]
fn installed_arena() -> &'static FiberStackArena {
    ARENA
        .get()
        .expect("Wasmtime parking hook before the fiber-stack arena was installed")
}

/// Takes one stack out of the arena.
pub fn claim_fiber_stack(stack_bytes: usize) -> Result<FiberStack, FiberStackError> {
    ARENA
        .get()
        .ok_or(FiberStackError::NoArena)?
        .claim(stack_bytes)
}

#[cfg(test)]
mod tests {
    use core::alloc::Layout;
    use core::sync::atomic::AtomicUsize;
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    use helios_hal::cpu::ProcessorId;

    use super::*;
    use crate::test_processor_identity;

    /// Bytes of pretend user memory the pool is built over. It has to
    /// cover the reserve and every page the tests commit.
    const POOL_BYTES: usize = 4 * 1024 * 1024;
    /// Deep enough for a fault dozens of pages below the top.
    const TEST_STACK_BYTES: usize = 96 * PhysFrame::SIZE;
    const TEST_SLOTS: usize = 3;
    /// Two, so that a commit resolved on the test's processor can be
    /// shown to land on that processor's counter and no other.
    const TEST_PROCESSORS: usize = 2;
    /// Two pages of warm slots: enough to keep two untouched stacks and
    /// too little for one that grew.
    const TEST_RETAIN_BYTES: usize = 2 * PhysFrame::SIZE;
    /// Where the fake address space puts the arena. Any page-aligned
    /// value works; nothing dereferences it.
    const TEST_ARENA_BASE: usize = 0x0000_4000_0000_0000;
    const TEST_SLOT_BYTES: usize = FIBER_STACK_GUARD_BYTES + TEST_STACK_BYTES;

    static PREPARED: AtomicUsize = AtomicUsize::new(0);
    static COMMITTED: AtomicUsize = AtomicUsize::new(0);
    static ENDED: AtomicUsize = AtomicUsize::new(0);
    /// The `mapped` range of the most recent `end_demand_commit`, as
    /// `(start, byte_len)`.
    static LAST_MAPPED: (AtomicUsize, AtomicUsize) = (AtomicUsize::new(0), AtomicUsize::new(0));
    /// The fake page table: every mapped page and the frame behind it.
    static MAPPED: Mutex<BTreeMap<usize, usize>> = Mutex::new(BTreeMap::new());

    /// An address space that records what the arena asked of it.
    ///
    /// The arena's own logic is the geometry, the slot bookkeeping and
    /// the fault classification; what the page tables do with the
    /// result is each backend's, and is covered by booting them. The
    /// fake does keep what a real one owes the pool: a page mapped twice
    /// is refused, a page in a guard is refused, a frame handed to it is
    /// a whole zeroed page, and ending a commit gives its frames back.
    static TEST_HOOKS: FiberStackVmHooks = FiberStackVmHooks {
        reserve: |bytes| {
            assert_eq!(bytes, TEST_SLOTS * TEST_SLOT_BYTES);
            Ok(VirtRange::new(VirtAddr::new(TEST_ARENA_BASE), bytes))
        },
        prepare_demand_commit: |virt, flags| {
            assert_eq!(virt.byte_len, TEST_STACK_BYTES);
            assert_eq!(flags, PageFlags::READ | PageFlags::WRITE);
            PREPARED.fetch_add(1, Ordering::Relaxed);
            Ok(())
        },
        commit_demand_page: |addr, frame, flags| {
            assert!(addr.is_page_aligned());
            assert_eq!(flags, PageFlags::READ | PageFlags::WRITE);
            assert!(
                (addr.raw() - TEST_ARENA_BASE) % TEST_SLOT_BYTES >= FIBER_STACK_GUARD_BYTES,
                "{addr:?} is in a guard, which is never mapped"
            );
            // SAFETY: the frame is one whole page the pool handed over.
            let page = unsafe { core::slice::from_raw_parts(frame.as_ptr(), PhysFrame::SIZE) };
            assert!(
                page.iter().all(|byte| *byte == 0),
                "a frame arrives zeroed, its chain link included"
            );
            let mut mapped = MAPPED.lock().expect("fake page table");
            if mapped.insert(addr.raw(), frame.as_ptr() as usize).is_some() {
                return Err(AddressSpaceError::Overlap);
            }
            COMMITTED.fetch_add(1, Ordering::Relaxed);
            Ok(())
        },
        end_demand_commit: |virt, mapped| {
            assert_eq!(virt.byte_len, TEST_STACK_BYTES);
            assert!(
                virt.encloses(mapped),
                "the mapped range {mapped:?} lies inside the body {virt:?}"
            );
            LAST_MAPPED.0.store(mapped.start.raw(), Ordering::Relaxed);
            LAST_MAPPED.1.store(mapped.byte_len, Ordering::Relaxed);
            ENDED.fetch_add(1, Ordering::Relaxed);
            let mut table = MAPPED.lock().expect("fake page table");
            let pages: alloc::vec::Vec<usize> = table
                .range(virt.start.raw()..virt.end().raw())
                .map(|(page, _)| *page)
                .collect();
            for page in pages {
                let frame = table.remove(&page).expect("a page just listed");
                assert!(
                    mapped.start.raw() <= page && page < mapped.end().raw(),
                    "page {page:#x} is mapped outside the range the arena named"
                );
                super::super::deallocate_user_frame(
                    NonNull::new(frame as *mut u8).expect("a mapped frame"),
                );
            }
            Ok(())
        },
        tags: AllocationTagHooks::NONE,
    };

    fn enabled() -> InterruptedContext {
        InterruptedContext {
            interrupts_enabled: true,
        }
    }

    fn masked() -> InterruptedContext {
        InterruptedContext {
            interrupts_enabled: false,
        }
    }

    /// The fake page table's mapped pages, lowest first.
    fn mapped_pages() -> alloc::vec::Vec<usize> {
        MAPPED
            .lock()
            .expect("fake page table")
            .keys()
            .copied()
            .collect()
    }

    /// The pages of `[low, high)`.
    fn pages_between(low: usize, high: usize) -> alloc::vec::Vec<usize> {
        (low..high).step_by(PhysFrame::SIZE).collect()
    }

    /// Frames taken out of the pool, so a test can give some back.
    struct Hoard(alloc::vec::Vec<NonNull<u8>>);

    impl Hoard {
        /// Takes every frame the pool has, then gives `left` of them
        /// back.
        fn exhaust_pool_leaving(left: usize) -> Self {
            let mut hoard = Self(alloc::vec::Vec::new());
            while let Ok(frame) = super::super::allocate_user_frame_zeroed() {
                hoard.0.push(frame);
            }
            hoard.give_back(left);
            hoard
        }

        fn give_back(&mut self, count: usize) {
            for _ in 0..count {
                super::super::deallocate_user_frame(self.0.pop().expect("a frame to give back"));
            }
        }
    }

    /// How many frames the pool can hand out right now; it takes them
    /// all and gives them back.
    fn frames_in_pool() -> usize {
        let mut held = alloc::vec::Vec::new();
        while let Ok(frame) = super::super::allocate_user_frame_zeroed() {
            held.push(frame);
        }
        let count = held.len();
        for frame in held {
            super::super::deallocate_user_frame(frame);
        }
        count
    }

    /// Brings up the user pool the arena draws on and the arena on top
    /// of it. Each test runs in its own process, so the install-once
    /// statics are fresh every time.
    fn arena_retaining(retain_bytes: usize) {
        let layout = Layout::from_size_align(POOL_BYTES, PhysFrame::SIZE).expect("pool layout");
        // Leaked on purpose: the pool is a `&'static` for the life of
        // the machine, and a test process is that life.
        // SAFETY: the layout has a non-zero size.
        let base = unsafe { alloc::alloc::alloc_zeroed(layout) } as usize;
        assert!(base != 0, "pool backing");
        let pool =
            super::super::install_user_memory_pool(super::super::UserMemoryPool::single_node(
                TEST_PROCESSORS,
                &[(base, base + POOL_BYTES)],
            ));
        frame_reserve::configure(pool);
        install_fiber_stack_hooks(&TEST_HOOKS);
        install_fiber_stack_arena(TEST_SLOTS, TEST_STACK_BYTES, retain_bytes);
    }

    fn arena() {
        arena_retaining(TEST_RETAIN_BYTES);
    }

    #[test]
    fn a_fresh_stack_commits_only_its_top_page_and_reports_its_guard() {
        arena();
        let stack = claim_fiber_stack(TEST_STACK_BYTES).expect("a free slot");

        assert_eq!(PREPARED.load(Ordering::Relaxed), 1);
        assert_eq!(
            COMMITTED.load(Ordering::Relaxed),
            1,
            "a fresh stack pays for its top page, not for the span it may grow into"
        );
        let top = stack.range().end;
        assert_eq!(mapped_pages(), pages_between(top - PhysFrame::SIZE, top));
        assert_eq!(
            reserved_bytes(),
            0,
            "a claim draws on the page-fault reserve never and fills it never"
        );
        let range = stack.range();
        assert_eq!(range.end - range.start, TEST_STACK_BYTES);
        assert_eq!(stack.top() as usize, range.end);
        let guard = stack.guard_range();
        assert_eq!(guard.end as usize, range.start);
        assert_eq!(
            guard.end as usize - guard.start as usize,
            FIBER_STACK_GUARD_BYTES
        );
    }

    #[test]
    fn an_enabled_fault_commits_exactly_the_page_and_the_gap_above_it_as_one_run() {
        arena();
        let stack = claim_fiber_stack(TEST_STACK_BYTES).expect("a free slot");
        let range = stack.range();
        let committed_before = COMMITTED.load(Ordering::Relaxed);

        // Thirty pages below the top: with a gap between the committed
        // top page and the faulting page that a large frame skipped.
        let page = range.end - 30 * PhysFrame::SIZE;
        assert_eq!(
            resolve_stack_fault(VirtAddr::new(page + 8), enabled()),
            StackFault::Committed
        );

        assert_eq!(
            mapped_pages(),
            pages_between(page, range.end),
            "the committed range is one run from the faulting page to the top, the skipped gap \
             included, and nothing below the faulting page"
        );
        let faulted_pages = 29;
        assert_eq!(
            COMMITTED.load(Ordering::Relaxed),
            committed_before + faulted_pages
        );
        let stats = fiber_stack_arena_stats().expect("arena stats");
        assert_eq!(stats.live_slots, 1);
        assert_eq!(stats.committed_bytes, range.end - page);
        assert_eq!(stats.eager_bytes, TEST_STACK_BYTES);
        assert_eq!(stats.demand_commits, 1, "one fault is one demand commit");
        assert_eq!(stats.demand_committed_pages, faulted_pages as u64);
    }

    #[test]
    fn a_served_enabled_fault_tops_the_reserve_up_through_the_pool() {
        arena();
        let stack = claim_fiber_stack(TEST_STACK_BYTES).expect("a free slot");
        assert_eq!(reserved_bytes(), 0);

        assert_eq!(
            resolve_stack_fault(thirty_page_fault(&stack), enabled()),
            StackFault::Committed
        );
        assert_eq!(
            reserved_bytes(),
            frame_reserve::RESERVE_CAPACITY * PhysFrame::SIZE,
            "the fault's frames came from the pool and the reserve was refilled behind it"
        );
    }

    #[test]
    fn a_guard_hit_is_an_overflow_for_any_interrupted_context() {
        arena();
        let stack = claim_fiber_stack(TEST_STACK_BYTES).expect("a free slot");
        let range = stack.range();
        let mapped_before = mapped_pages();

        for interrupted in [enabled(), masked()] {
            let guard = VirtAddr::new(range.start - PhysFrame::SIZE);
            let outcome = resolve_stack_fault(guard, interrupted);
            assert!(
                matches!(outcome, StackFault::Guard { .. }),
                "a guard hit is a stack overflow, never a commit and never the masked-fault \
                 panic: {outcome:?}"
            );
            assert!(
                alloc::format!("{outcome}").contains("guard page"),
                "the fatal report has to name it"
            );
        }
        assert_eq!(mapped_pages(), mapped_before);
    }

    #[test]
    fn a_fault_on_the_lowest_page_of_the_body_commits_the_whole_body_and_never_the_guard() {
        arena();
        let stack = claim_fiber_stack(TEST_STACK_BYTES).expect("a free slot");
        let range = stack.range();

        assert_eq!(
            resolve_stack_fault(VirtAddr::new(range.start), enabled()),
            StackFault::Committed
        );
        assert_eq!(mapped_pages(), pages_between(range.start, range.end));
        assert_eq!(
            fiber_stack_arena_stats().expect("stats").committed_bytes,
            TEST_STACK_BYTES
        );
    }

    #[test]
    fn an_address_outside_the_arena_is_nobody_else_business() {
        arena();
        assert_eq!(
            resolve_stack_fault(VirtAddr::new(TEST_ARENA_BASE - PhysFrame::SIZE), enabled()),
            StackFault::Elsewhere
        );
        let past = TEST_ARENA_BASE + TEST_SLOTS * TEST_SLOT_BYTES;
        assert_eq!(
            resolve_stack_fault(VirtAddr::new(past), enabled()),
            StackFault::Elsewhere
        );
    }

    /// A processor's reserve, filled the way the executor loop fills it,
    /// with the calling thread as processor 0.
    fn full_reserve() {
        frame_reserve::top_up(current_processor());
        assert_eq!(
            reserved_bytes(),
            frame_reserve::RESERVE_CAPACITY * PhysFrame::SIZE
        );
    }

    fn reserved_bytes() -> usize {
        frame_reserve::reserved_bytes()
    }

    #[test]
    #[should_panic(expected = "needed 29 frames and processor 0 reserved 0 of its 64")]
    fn a_masked_fault_with_the_reserve_empty_is_the_named_panic() {
        arena();
        let stack = claim_fiber_stack(TEST_STACK_BYTES).expect("a free slot");
        assert_eq!(reserved_bytes(), 0);

        let _ = resolve_stack_fault(thirty_page_fault(&stack), masked());
    }

    #[test]
    fn a_masked_fault_is_served_from_the_reserve_while_another_processor_holds_the_pool_lock() {
        arena();
        let stack = claim_fiber_stack(TEST_STACK_BYTES).expect("a free slot");
        let fault = thirty_page_fault(&stack);
        full_reserve();
        let served = core::sync::atomic::AtomicBool::new(false);

        std::thread::scope(|scope| {
            test_processor_identity::set(ProcessorId::new(1));
            let pool = super::super::user::installed_user_memory_pool().expect("pool");
            pool.hold_buddy_lock_while(|| {
                scope.spawn(|| {
                    test_processor_identity::set(ProcessorId::new(0));
                    assert_eq!(resolve_stack_fault(fault, masked()), StackFault::Committed);
                    served.store(true, Ordering::Release);
                });
                // The fault has no pool lock to wait for; give it ample
                // time to finish while this thread still holds the lock.
                for _ in 0..200 {
                    if served.load(Ordering::Acquire) {
                        break;
                    }
                    std::thread::sleep(core::time::Duration::from_millis(10));
                }
                assert!(
                    served.load(Ordering::Acquire),
                    "the masked fault was not served while the pool lock was held: it touched \
                     the pool"
                );
            });
        });
        assert_eq!(
            reserved_bytes(),
            (frame_reserve::RESERVE_CAPACITY - 29) * PhysFrame::SIZE,
            "the fault's twenty-nine frames came out of the reserve, and the reserve is not \
             refilled from fault context"
        );
        assert_eq!(
            mapped_pages(),
            pages_between(stack.range().end - 30 * PhysFrame::SIZE, stack.range().end)
        );
    }

    #[test]
    #[should_panic(expected = "already maps")]
    fn a_fault_on_a_page_the_stack_already_maps_is_a_bookkeeping_defect() {
        arena();
        let stack = claim_fiber_stack(TEST_STACK_BYTES).expect("a free slot");
        let range = stack.range();

        let _ = resolve_stack_fault(VirtAddr::new(range.end - PhysFrame::SIZE), enabled());
    }

    #[test]
    fn a_dropped_stack_gives_its_slot_back_and_the_arena_refuses_more_than_it_has() {
        arena();
        let held: alloc::vec::Vec<FiberStack> = (0..TEST_SLOTS)
            .map(|_| claim_fiber_stack(TEST_STACK_BYTES).expect("a free slot"))
            .collect();
        assert_eq!(
            claim_fiber_stack(TEST_STACK_BYTES).err(),
            Some(FiberStackError::Exhausted { slots: TEST_SLOTS })
        );

        drop(held);
        // Two untouched stacks fit the retain budget and stay warm; the
        // third does not and is given back.
        assert_eq!(ENDED.load(Ordering::Relaxed), 1);
        let stats = fiber_stack_arena_stats().expect("stats");
        assert_eq!(stats.live_slots, 0);
        assert_eq!(stats.warm_slots, 2);
        assert_eq!(stats.retained_bytes, 2 * PhysFrame::SIZE);
        assert_eq!(stats.released_stacks, TEST_SLOTS as u64);
        assert_eq!(
            stats.released_committed_bytes,
            (TEST_SLOTS * PhysFrame::SIZE) as u64,
            "an untouched stack cost its top page and nothing more"
        );
        // And the slots are usable again: a warm one first, as it stands.
        let prepared = PREPARED.load(Ordering::Relaxed);
        let committed = COMMITTED.load(Ordering::Relaxed);
        let reused = claim_fiber_stack(TEST_STACK_BYTES).expect("a slot came back");
        let stats = fiber_stack_arena_stats().expect("stats");
        assert_eq!(stats.live_slots, 1);
        assert_eq!(stats.warm_slots, 1);
        assert_eq!(stats.retained_bytes, PhysFrame::SIZE);
        assert_eq!(PREPARED.load(Ordering::Relaxed), prepared);
        assert_eq!(COMMITTED.load(Ordering::Relaxed), committed);
        assert_eq!(reused.range().end - reused.range().start, TEST_STACK_BYTES);
    }

    #[test]
    fn a_warm_slot_serves_the_next_stack_without_touching_the_address_space_or_the_pool() {
        // Room for a stack that grew, so it is kept rather than given back.
        arena_retaining(TEST_STACK_BYTES);
        let first = claim_fiber_stack(TEST_STACK_BYTES).expect("a free slot");
        let range = first.range();
        assert_eq!(
            resolve_stack_fault(VirtAddr::new(range.end - 20 * PhysFrame::SIZE), enabled()),
            StackFault::Committed
        );
        // The top page, the skipped gap and the faulting page.
        let held = 20 * PhysFrame::SIZE;
        drop(first);
        let stats = fiber_stack_arena_stats().expect("stats");
        assert_eq!(stats.warm_slots, 1);
        assert_eq!(stats.retained_bytes, held);
        assert_eq!(ENDED.load(Ordering::Relaxed), 0);

        // Nothing is left in the pool: a warm claim has to need none.
        let _hoard = Hoard::exhaust_pool_leaving(0);
        let prepared = PREPARED.load(Ordering::Relaxed);
        let committed = COMMITTED.load(Ordering::Relaxed);
        let second = claim_fiber_stack(TEST_STACK_BYTES).expect("the warm slot");
        assert_eq!(second.range(), range, "the warm slot is the one handed out");
        assert_eq!(PREPARED.load(Ordering::Relaxed), prepared);
        assert_eq!(COMMITTED.load(Ordering::Relaxed), committed);
        let stats = fiber_stack_arena_stats().expect("stats");
        assert_eq!(stats.warm_slots, 0);
        assert_eq!(stats.retained_bytes, 0);
        assert_eq!(
            stats.committed_bytes, held,
            "the pages the first stack touched are still the second's"
        );
    }

    #[test]
    fn a_released_stack_hands_back_only_the_span_it_touched() {
        arena();
        let stack = claim_fiber_stack(TEST_STACK_BYTES).expect("a free slot");
        let range = stack.range();
        let page = range.end - 30 * PhysFrame::SIZE;
        assert_eq!(
            resolve_stack_fault(VirtAddr::new(page + 8), enabled()),
            StackFault::Committed
        );

        drop(stack);
        let lowest = page;
        assert_eq!(LAST_MAPPED.0.load(Ordering::Relaxed), lowest);
        assert_eq!(
            LAST_MAPPED.1.load(Ordering::Relaxed),
            range.end - lowest,
            "the address space walks from the watermark to the top and nothing below"
        );
        assert!(
            mapped_pages().is_empty(),
            "every frame the stack held went back to the address space's owner"
        );
        let stats = fiber_stack_arena_stats().expect("stats");
        assert_eq!(stats.released_stacks, 1);
        assert_eq!(stats.released_committed_bytes, (range.end - lowest) as u64);
    }

    #[test]
    fn a_stack_of_the_wrong_size_is_refused_rather_than_trimmed() {
        arena();
        assert_eq!(
            claim_fiber_stack(TEST_STACK_BYTES * 2).err(),
            Some(FiberStackError::WrongSize {
                requested: TEST_STACK_BYTES * 2,
                slot: TEST_STACK_BYTES,
            })
        );
    }

    #[test]
    fn every_processor_counts_its_own_demand_commits() {
        arena();
        let stack = claim_fiber_stack(TEST_STACK_BYTES).expect("a free slot");
        let range = stack.range();
        assert_eq!(
            resolve_stack_fault(VirtAddr::new(range.end - 20 * PhysFrame::SIZE), enabled()),
            StackFault::Committed
        );

        // A test runs on one processor; the other's counter has to stay
        // where it was, or the counters are not per processor.
        let here = current_processor();
        let other = ProcessorId::new(u16::from(here.id() == 0));
        assert_eq!(fiber_stack_demand_commits_on(here), 1);
        assert_eq!(fiber_stack_demand_commits_on(other), 0);
        assert_eq!(fiber_stack_arena_stats().expect("stats").demand_commits, 1);
    }

    /// The fault that needs 30 pages, and the page it faults on.
    fn thirty_page_fault(stack: &FiberStack) -> VirtAddr {
        VirtAddr::new(stack.range().end - 30 * PhysFrame::SIZE + 8)
    }

    #[test]
    fn an_enabled_fault_with_the_pool_exhausted_is_starved_and_changes_nothing() {
        arena();
        let stack = claim_fiber_stack(TEST_STACK_BYTES).expect("a free slot");
        let fault = thirty_page_fault(&stack);
        let mapped_before = mapped_pages();
        let stats_before = fiber_stack_arena_stats().expect("stats");

        // One frame short of the twenty-nine the fault needs.
        let mut hoard = Hoard::exhaust_pool_leaving(28);
        let outcome = resolve_stack_fault(fault, enabled());
        let StackFault::Starved {
            slot,
            addr,
            shortfall,
        } = outcome
        else {
            panic!("a pool one frame short must starve the fault: {outcome:?}");
        };
        assert_eq!(slot, 0);
        assert_eq!(addr, fault.raw());
        assert_eq!(shortfall.requested_bytes, PhysFrame::SIZE);
        assert!(
            alloc::format!("{outcome}").contains("user pool is exhausted"),
            "the fatal report has to name it"
        );

        assert_eq!(mapped_pages(), mapped_before, "nothing was mapped");
        let stats = fiber_stack_arena_stats().expect("stats");
        assert_eq!(stats.committed_bytes, stats_before.committed_bytes);
        assert_eq!(stats.demand_commits, stats_before.demand_commits);
        assert_eq!(stats.demand_committed_pages, 0);
        assert_eq!(
            frames_in_pool(),
            28,
            "the frames the fault had taken went back to the pool"
        );

        // And it is recoverable: with the twenty-ninth frame back the same
        // fault is served.
        hoard.give_back(1);
        assert_eq!(resolve_stack_fault(fault, enabled()), StackFault::Committed);
        assert_eq!(
            mapped_pages().len(),
            mapped_before.len() + 29,
            "the whole run arrives together"
        );
    }

    #[test]
    fn a_cold_claim_with_the_pool_exhausted_is_a_typed_error_and_leaves_the_reserve_alone() {
        arena();
        full_reserve();
        let mut hoard = Hoard::exhaust_pool_leaving(0);

        let refusal = claim_fiber_stack(TEST_STACK_BYTES).err();
        let Some(FiberStackError::OutOfMemory(shortfall)) = refusal else {
            panic!("a pool with no frame must refuse the claim: {refusal:?}");
        };
        assert_eq!(shortfall.requested_bytes, PhysFrame::SIZE);
        assert_eq!(
            PREPARED.load(Ordering::Relaxed),
            0,
            "nothing of the slot is touched before its top page is in hand"
        );
        assert!(mapped_pages().is_empty());
        let stats = fiber_stack_arena_stats().expect("stats");
        assert_eq!((stats.live_slots, stats.warm_slots), (0, 0));
        assert_eq!(
            reserved_bytes(),
            frame_reserve::RESERVE_CAPACITY * PhysFrame::SIZE,
            "a claim does not draw on the page-fault reserve"
        );

        // The slot is as found: with a frame back the same claim takes it.
        hoard.give_back(1);
        let stack = claim_fiber_stack(TEST_STACK_BYTES).expect("the slot is still cold");
        assert_eq!(
            stack.range().start,
            TEST_ARENA_BASE + FIBER_STACK_GUARD_BYTES,
            "the refused claim left the lowest slot free"
        );
        assert_eq!(mapped_pages().len(), 1);
    }

    #[test]
    fn an_enabled_fault_waits_for_a_pool_lock_another_processor_holds_and_is_served_with_the_reserve_empty()
     {
        arena();
        let stack = claim_fiber_stack(TEST_STACK_BYTES).expect("a free slot");
        let fault = thirty_page_fault(&stack);
        assert_eq!(reserved_bytes(), 0, "this processor's reserve is empty");
        // Frames the pool holds in its fallback shard, so the faulting
        // processor's own shard is empty and the allocation has to take
        // the buddy lock.
        let mut hoard = Hoard::exhaust_pool_leaving(0);
        hoard.give_back(64);
        let served = core::sync::atomic::AtomicBool::new(false);

        std::thread::scope(|scope| {
            test_processor_identity::set(ProcessorId::new(1));
            let pool = super::super::user::installed_user_memory_pool().expect("pool");
            pool.hold_buddy_lock_while(|| {
                scope.spawn(|| {
                    // Processor 0 faults while processor 1 is inside the
                    // pool's critical section.
                    test_processor_identity::set(ProcessorId::new(0));
                    assert_eq!(resolve_stack_fault(fault, enabled()), StackFault::Committed);
                    served.store(true, Ordering::Release);
                });
                std::thread::sleep(core::time::Duration::from_millis(200));
                assert!(
                    !served.load(Ordering::Acquire),
                    "the fault was served, or refused, while the pool lock was held: it did not \
                     wait for it"
                );
            });
        });
        assert!(served.load(Ordering::Acquire));
        assert_eq!(mapped_pages().len(), 1 + 29);
    }

    #[test]
    fn the_refill_waits_out_a_pool_lock_another_processor_holds_and_fills_the_reserve() {
        arena();
        let processor = ProcessorId::new(0);
        assert_eq!(reserved_bytes(), 0, "the reserve starts empty");
        let filled = core::sync::atomic::AtomicBool::new(false);

        std::thread::scope(|scope| {
            test_processor_identity::set(ProcessorId::new(1));
            let pool = super::super::user::installed_user_memory_pool().expect("pool");
            pool.hold_buddy_lock_while(|| {
                scope.spawn(|| {
                    test_processor_identity::set(processor);
                    frame_reserve::top_up(processor);
                    filled.store(true, Ordering::Release);
                });
                std::thread::sleep(core::time::Duration::from_millis(200));
                assert!(
                    !filled.load(Ordering::Acquire),
                    "the refill returned while the pool's lock was held: it gave up instead of \
                     waiting"
                );
            });
        });
        assert_eq!(
            reserved_bytes(),
            frame_reserve::RESERVE_CAPACITY * PhysFrame::SIZE,
            "the refill filled the reserve once the lock came free"
        );
    }

    /// The failed instantiation or call has to classify as out of memory:
    /// the runtime wraps the creator's error in its own, and the
    /// classifier walks the chain for the pool's refusal.
    #[cfg(feature = "wasmtime-runtime")]
    #[test]
    fn the_runtimes_error_chain_reaches_the_pools_refusal() {
        let refusal = ProgramOutOfMemory {
            requested_bytes: PhysFrame::SIZE,
            available_bytes: 0,
            pool_bytes: POOL_BYTES,
            reserved_bytes: 0,
        };
        let error = wasmtime::Error::new(FiberStackError::OutOfMemory(refusal));
        assert!(
            error.chain().any(|cause| cause.is::<ProgramOutOfMemory>()),
            "the creator's error reaches the runtime with the refusal in its chain"
        );
    }

    mod tagged {
        use super::*;
        use alloc::vec::Vec;
        use spin::Mutex;

        const TAG_SHIFT: usize = 56;
        const TAG_MASK: usize = 0xf;
        const TEST_TAGGED_BASE: usize = 0xffff_c000_0000_0000;

        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        enum TagOp {
            Assign { start: usize, len: usize, tag: Tag },
            Store { start: usize, len: usize, tag: Tag },
        }

        static NEXT_TAG: AtomicU8 = AtomicU8::new(1);
        static OPS: Mutex<Vec<TagOp>> = Mutex::new(Vec::new());

        struct RecordingTags;

        impl AllocationTags for RecordingTags {
            const GRANULE_BYTES: usize = 16;

            fn checking() -> bool {
                true
            }

            unsafe fn assign(range: NonNull<[u8]>, avoid: TagSet) -> Tag {
                let mut candidate = NEXT_TAG.fetch_add(1, Ordering::Relaxed);
                let tag = loop {
                    let raw = candidate & 0xf;
                    candidate = candidate.wrapping_add(1);
                    let tag = Tag::new(raw);
                    if tag != Tag::FREE && tag != Tag::UNCHECKED && !avoid.contains(tag) {
                        break tag;
                    }
                };
                NEXT_TAG.store(candidate, Ordering::Relaxed);
                OPS.lock().push(TagOp::Assign {
                    start: range.as_ptr() as *mut u8 as usize,
                    len: range.len(),
                    tag,
                });
                tag
            }

            unsafe fn store(range: NonNull<[u8]>, tag: Tag) {
                OPS.lock().push(TagOp::Store {
                    start: range.as_ptr() as *mut u8 as usize,
                    len: range.len(),
                    tag,
                });
            }

            fn apply(addr: usize, tag: Tag) -> usize {
                (addr & !(TAG_MASK << TAG_SHIFT)) | (usize::from(tag.raw()) << TAG_SHIFT)
            }

            fn strip(addr: usize) -> usize {
                (((addr << 8) as isize) >> 8) as usize
            }
        }

        static TAGGED_HOOKS: FiberStackVmHooks = FiberStackVmHooks {
            reserve: |bytes| Ok(VirtRange::new(VirtAddr::new(TEST_TAGGED_BASE), bytes)),
            prepare_demand_commit: |_virt, flags| {
                assert_eq!(
                    flags,
                    PageFlags::READ | PageFlags::WRITE | PageFlags::TAGGED
                );
                Ok(())
            },
            commit_demand_page: |addr, _frame, flags| {
                assert!(addr.is_page_aligned());
                assert_eq!(
                    flags,
                    PageFlags::READ | PageFlags::WRITE | PageFlags::TAGGED
                );
                Ok(())
            },
            end_demand_commit: |_virt, _mapped| Ok(()),
            tags: AllocationTagHooks::of::<RecordingTags>(),
        };

        fn tagged_arena() {
            let layout = Layout::from_size_align(POOL_BYTES, PhysFrame::SIZE).expect("pool layout");
            // SAFETY: non-zero size, intentionally leaked for the test process.
            let base = unsafe { alloc::alloc::alloc_zeroed(layout) } as usize;
            let pool = super::super::super::install_user_memory_pool(
                super::super::super::UserMemoryPool::single_node(
                    TEST_PROCESSORS,
                    &[(base, base + POOL_BYTES)],
                ),
            );
            frame_reserve::configure(pool);
            install_fiber_stack_hooks(&TAGGED_HOOKS);
            install_fiber_stack_arena(TEST_SLOTS, TEST_STACK_BYTES, TEST_RETAIN_BYTES);
        }

        fn tag_of(addr: usize) -> Tag {
            Tag::new(((addr >> TAG_SHIFT) & TAG_MASK) as u8)
        }

        #[test]
        fn tagged_stacks_tag_committed_pages_and_rotate_across_warm_reuse() {
            tagged_arena();
            let first = claim_fiber_stack(TEST_STACK_BYTES).expect("first stack");
            let first_range = first.range();
            let first_tag = tag_of(first_range.start);
            assert_ne!(first_tag, Tag::FREE);
            assert_ne!(first_tag, Tag::UNCHECKED);
            assert_eq!(tag_of(first_range.end), first_tag);
            assert_eq!(first_range.end - first_range.start, TEST_STACK_BYTES);
            assert_eq!(first.top() as usize, first_range.end);
            assert_eq!(first.guard_range().end as usize, first_range.start);

            let top_page = RecordingTags::strip(first_range.end) - PhysFrame::SIZE;
            let mid_page = RecordingTags::strip(first_range.end) - 2 * PhysFrame::SIZE;
            let deep_page = RecordingTags::strip(first_range.end) - 3 * PhysFrame::SIZE;
            {
                let ops = OPS.lock();
                assert_eq!(
                    ops.as_slice(),
                    &[TagOp::Assign {
                        start: top_page,
                        len: PhysFrame::SIZE,
                        tag: first_tag,
                    }]
                );
            }
            OPS.lock().clear();

            // Fault three pages below the top; resolving commits both pages
            // below watermark and tags each with the live slot's tag, and
            // accepts a tagged faulting address.
            let deep_tagged = first_range.end - 3 * PhysFrame::SIZE + 16;
            assert_eq!(
                resolve_stack_fault(VirtAddr::new(deep_tagged), enabled()),
                StackFault::Committed
            );
            {
                let ops = OPS.lock();
                assert_eq!(
                    ops.as_slice(),
                    &[
                        TagOp::Store {
                            start: mid_page,
                            len: PhysFrame::SIZE,
                            tag: first_tag,
                        },
                        TagOp::Store {
                            start: deep_page,
                            len: PhysFrame::SIZE,
                            tag: first_tag,
                        },
                    ]
                );
            }
            OPS.lock().clear();

            // Releasing returns every committed page to Tag::FREE.
            drop(first);
            {
                let ops = OPS.lock();
                assert_eq!(
                    ops.as_slice(),
                    &[
                        TagOp::Store {
                            start: deep_page,
                            len: PhysFrame::SIZE,
                            tag: Tag::FREE,
                        },
                        TagOp::Store {
                            start: mid_page,
                            len: PhysFrame::SIZE,
                            tag: Tag::FREE,
                        },
                        TagOp::Store {
                            start: top_page,
                            len: PhysFrame::SIZE,
                            tag: Tag::FREE,
                        },
                    ]
                );
            }
            OPS.lock().clear();

            // The slot exceeded the two-page retain budget (3 committed pages),
            // so it went cold; claim again and confirm a fresh stack avoids
            // the slot's previous tag.
            let second = claim_fiber_stack(TEST_STACK_BYTES).expect("second stack");
            let second_tag = tag_of(second.range().start);
            assert_ne!(second_tag, first_tag);
            assert_ne!(second_tag, Tag::FREE);
            assert_ne!(second_tag, Tag::UNCHECKED);
            OPS.lock().clear();

            // Drop untouched (1 page <= retain budget) so it stays warm, then
            // re-claim warm and verify it rotates to a third distinct tag.
            drop(second);
            assert_eq!(
                OPS.lock().as_slice(),
                &[TagOp::Store {
                    start: top_page,
                    len: PhysFrame::SIZE,
                    tag: Tag::FREE,
                }]
            );
            OPS.lock().clear();

            let third = claim_fiber_stack(TEST_STACK_BYTES).expect("warm stack");
            let third_tag = tag_of(third.range().start);
            assert_ne!(third_tag, second_tag);
            assert_eq!(
                RecordingTags::strip(third.range().start),
                RecordingTags::strip(first_range.start)
            );
            assert_eq!(
                OPS.lock().as_slice(),
                &[TagOp::Assign {
                    start: top_page,
                    len: PhysFrame::SIZE,
                    tag: third_tag,
                }]
            );
        }
    }
}
