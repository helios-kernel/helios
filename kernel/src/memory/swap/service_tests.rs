//! The swap service's failure paths, driven against a backend that fails
//! on demand and an address space that models what the real ones do to a
//! page-table entry.
//!
//! The service is private to the kernel and needs no executor to be
//! driven: a fault is issued by polling `fault_in` once (which queues the
//! request and parks), the service is run by hand, and the fault is
//! polled again for its result. Tests that need two requests in the queue
//! at once issue both before running the service.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::cell::{Cell, RefCell};
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, Waker};
use std::sync::Mutex;

use helios_hal::dma::{BufError, BufResult};
use helios_hal::vmm::{AddressSpaceError, PageFlags};

use super::*;
use crate::test_support::TestCpu;
use crate::{InstanceActivity, ProcessorTurn, RegisteredInstance, StoreTurns};

const PAGE: usize = PhysFrame::SIZE;

/// What the fake address space holds for one page.
enum FakePage {
    Present(Vec<u8>),
    Swapped(SwapToken),
}

#[derive(Default)]
struct FakeSpace {
    pages: BTreeMap<usize, FakePage>,
    /// How many of the next `swap_in_page` calls refuse, leaving the entry
    /// as it was, the way the real address spaces do.
    reinstatements_to_refuse: u32,
    orphans: Vec<SwapToken>,
    /// The instance every page belongs to, and the registry that knows
    /// whether it is on a processor: a detach checks it at the moment it
    /// happens.
    owner: Option<(InstanceRegistry, InstanceId)>,
}

std::thread_local! {
    static SPACE: RefCell<FakeSpace> = RefCell::new(FakeSpace::default());
    static CLOCK_NANOS: Cell<u64> = const { Cell::new(0) };
}

fn with_space<R>(f: impl FnOnce(&mut FakeSpace) -> R) -> R {
    SPACE.with(|space| f(&mut space.borrow_mut()))
}

fn set_clock(nanos: u64) {
    CLOCK_NANOS.with(|clock| clock.set(nanos));
}

static TEST_HOOKS: SwapVmHooks = SwapVmHooks {
    swap_out_page: |addr, token, out| {
        with_space(|space| {
            if let Some((registry, id)) = &space.owner {
                assert!(
                    registry.idle_instances(u64::MAX, 0).contains(id),
                    "page {:#x} detached while its instance is on a processor",
                    addr.raw()
                );
            }
            let page = space
                .pages
                .get_mut(&addr.raw())
                .ok_or(AddressSpaceError::NotCommitted)?;
            let FakePage::Present(bytes) = page else {
                return Err(AddressSpaceError::NotCommitted);
            };
            out.copy_from_slice(bytes);
            *page = FakePage::Swapped(token);
            Ok(PageFlags::READ | PageFlags::WRITE)
        })
    },
    swap_in_page: |addr, bytes| {
        with_space(|space| {
            if space.reinstatements_to_refuse > 0 {
                space.reinstatements_to_refuse -= 1;
                return Err(AddressSpaceError::OutOfFrames);
            }
            let page = space
                .pages
                .get_mut(&addr.raw())
                .ok_or(AddressSpaceError::NotSwapped)?;
            let FakePage::Swapped(token) = *page else {
                return Err(AddressSpaceError::NotSwapped);
            };
            *page = FakePage::Present(bytes.to_vec());
            Ok(token)
        })
    },
    swapped_token: |addr| {
        with_space(|space| match space.pages.get(&addr.page_floor().raw()) {
            Some(FakePage::Swapped(token)) => Some(*token),
            _ => None,
        })
    },
    // Every resident page belongs to the one instance, and every one is
    // cold: the pass takes whatever its plan has room for.
    scan_committed_pages: |_, context, visit| {
        let resident: Vec<VirtAddr> = with_space(|space| {
            space
                .pages
                .iter()
                .filter(|(_, page)| matches!(page, FakePage::Present(_)))
                .map(|(addr, _)| VirtAddr::new(*addr))
                .collect()
        });
        let mut visited = 0;
        for addr in resident {
            visited += 1;
            if !visit(
                context,
                addr,
                PageFlags::READ | PageFlags::WRITE,
                PageAge::Cold,
            ) {
                break;
            }
        }
        visited
    },
    owned_resident_bytes: |_| 0,
    drain_orphaned_swap_tokens: |context, visit| {
        let orphans = with_space(|space| core::mem::take(&mut space.orphans));
        let count = orphans.len();
        for token in orphans {
            visit(context, token);
        }
        count
    },
    now_ticks: || CLOCK_NANOS.with(Cell::get),
};

#[derive(Debug, Error)]
#[error("injected swap backend failure")]
struct Injected;

#[derive(Default)]
struct FlakyState {
    next_token: u64,
    extents: BTreeMap<u64, Vec<u8>>,
    reads_to_fail: u32,
    writes_to_refuse: u32,
    /// Every token passed to `release`, in call order.
    released: Vec<u64>,
    /// A store whose turn begins once this many more writes have landed:
    /// another processor putting the instance on while the pass awaits
    /// the device.
    turn_after_writes: Option<(u32, &'static StoreTurns)>,
    /// The turn that began, until the test ends it.
    open_turn: Option<ProcessorTurn<'static>>,
}

/// A backend whose reads and writes fail on demand. A failed read leaves
/// the extent in place and a successful one consumes it, the contract the
/// virtio backend keeps.
#[derive(Clone, Default)]
struct FlakyBackend {
    state: Arc<Mutex<FlakyState>>,
}

impl FlakyBackend {
    fn fail_reads(&self, count: u32) {
        self.state.lock().unwrap().reads_to_fail = count;
    }

    fn refuse_writes(&self, count: u32) {
        self.state.lock().unwrap().writes_to_refuse = count;
    }

    fn begin_turn_after_writes(&self, writes: u32, turns: &'static StoreTurns) {
        self.state.lock().unwrap().turn_after_writes = Some((writes, turns));
    }

    fn end_turn(&self, now_nanos: u64) {
        let turn = self
            .state
            .lock()
            .unwrap()
            .open_turn
            .take()
            .expect("a turn began during the pass");
        let _ = turn.end(now_nanos);
    }

    fn released(&self) -> Vec<u64> {
        self.state.lock().unwrap().released.clone()
    }

    fn extents(&self) -> Vec<Vec<u8>> {
        self.state
            .lock()
            .unwrap()
            .extents
            .values()
            .cloned()
            .collect()
    }
}

impl SwapBackend for FlakyBackend {
    type Token = u64;
    type Error = Injected;
    type Buffer = Box<[u8]>;

    fn buffer(&self, bytes: usize) -> Result<Self::Buffer, Self::Error> {
        Ok(vec![0_u8; bytes].into_boxed_slice())
    }

    async fn swap_out(
        &self,
        page: Self::Buffer,
    ) -> BufResult<Self::Token, Self::Buffer, Self::Error> {
        let mut state = self.state.lock().unwrap();
        if state.writes_to_refuse > 0 {
            state.writes_to_refuse -= 1;
            return Err(BufError::returned(Injected, page));
        }
        state.next_token += 1;
        let token = state.next_token;
        state.extents.insert(token, page.to_vec());
        if let Some((writes, turns)) = state.turn_after_writes.as_mut() {
            *writes -= 1;
            if *writes == 0 {
                let turns = *turns;
                state.turn_after_writes = None;
                state.open_turn = Some(turns.begin(1));
            }
        }
        Ok((token, page))
    }

    async fn swap_in(
        &self,
        token: Self::Token,
        mut page: Self::Buffer,
    ) -> BufResult<(), Self::Buffer, Self::Error> {
        let mut state = self.state.lock().unwrap();
        if state.reads_to_fail > 0 {
            state.reads_to_fail -= 1;
            return Err(BufError::returned(Injected, page));
        }
        let bytes = state.extents.remove(&token).expect("a live token");
        page.copy_from_slice(&bytes);
        Ok(((), page))
    }

    async fn release(&self, token: Self::Token) {
        let mut state = self.state.lock().unwrap();
        state.released.push(token);
        state
            .extents
            .remove(&token)
            .expect("a release only ever names a token that swap_in has not consumed");
    }
}

struct Harness {
    service: SwapService<FlakyBackend, TestCpu>,
    handle: SwapHandle,
    backend: FlakyBackend,
    /// The instance every resident page belongs to. It has no store, so
    /// it is off every processor until a test gives it one.
    instance: RegisteredInstance,
}

fn block_on<F: Future>(future: F) -> F::Output {
    futures_lite::future::block_on(future)
}

impl Harness {
    fn new() -> Self {
        with_space(|space| *space = FakeSpace::default());
        set_clock(0);
        let backend = FlakyBackend::default();
        let handle = SwapHandle::new(
            "test",
            0,
            SwapClock {
                timebase: Timebase::new(1_000_000_000),
                now_ticks: TEST_HOOKS.now_ticks,
            },
        );
        let registry = InstanceRegistry::new();
        let instance = registry.register("evicted", 0);
        with_space(|space| space.owner = Some((registry.clone(), instance.id())));
        let service = SwapService {
            backend: backend.clone(),
            handle: handle.clone(),
            hooks: &TEST_HOOKS,
            registry,
            native_spaces: NativeSpaceRegistry::new(),
            cpu: TestCpu::with_entropy(0),
            map: SwapMap::new(),
            page: Some(vec![0_u8; PAGE].into_boxed_slice()),
            report: SwapReport::default(),
        };
        Self {
            service,
            handle,
            backend,
            instance,
        }
    }

    fn evict_instance(&mut self, budget: usize) -> usize {
        let id = self.instance.id();
        block_on(self.service.evict_owner(id, budget, EvictionAge::Any))
    }

    fn is_resident(&self, addr: VirtAddr) -> bool {
        with_space(|space| matches!(space.pages[&addr.raw()], FakePage::Present(_)))
    }

    /// A resident page at page number `number`, filled with a pattern
    /// that differs per page and per byte.
    fn resident(&self, number: usize, seed: u8) -> VirtAddr {
        let addr = VirtAddr::new(number * PAGE);
        with_space(|space| {
            space
                .pages
                .insert(addr.raw(), FakePage::Present(pattern(seed)));
        });
        addr
    }

    fn evict(&mut self, addr: VirtAddr) -> Result<(), ()> {
        let id = self.instance.id();
        block_on(self.service.swap_out(id, addr))
    }

    /// The index the page-table entry carries, if the page is swapped.
    fn index_of(&self, addr: VirtAddr) -> Option<SwapToken> {
        (TEST_HOOKS.swapped_token)(addr)
    }

    fn contents(&self, addr: VirtAddr) -> Vec<u8> {
        with_space(|space| match &space.pages[&addr.raw()] {
            FakePage::Present(bytes) => bytes.clone(),
            FakePage::Swapped(_) => panic!("page {:#x} is not resident", addr.raw()),
        })
    }

    fn serve(&mut self) {
        block_on(self.service.serve_faults());
    }

    fn fault(&mut self, addr: VirtAddr) -> Result<(), SwapFaultError> {
        let handle = self.handle.clone();
        let mut fault = issue(&handle, addr);
        self.serve();
        poll(&mut fault).expect("the service settled the fault")
    }

    fn teardown(&mut self, index: SwapToken) {
        with_space(|space| space.orphans.push(index));
        block_on(self.service.release_orphaned_tokens());
    }
}

fn pattern(seed: u8) -> Vec<u8> {
    (0..PAGE)
        .map(|index| seed.wrapping_add((index % 251) as u8))
        .collect()
}

/// Queues a fault the way the trampoline does, without running the
/// service.
fn issue(
    handle: &SwapHandle,
    addr: VirtAddr,
) -> Pin<Box<impl Future<Output = Result<(), SwapFaultError>>>> {
    let mut fault = Box::pin(handle.fault_in(addr));
    assert!(
        poll(&mut fault).is_none(),
        "a fault parks until the service has run"
    );
    fault
}

fn poll<T>(future: &mut Pin<Box<impl Future<Output = T>>>) -> Option<T> {
    let mut context = Context::from_waker(Waker::noop());
    match future.as_mut().poll(&mut context) {
        Poll::Ready(value) => Some(value),
        Poll::Pending => None,
    }
}

#[test]
fn a_failed_read_leaves_the_entry_and_the_extent_as_they_were() {
    let mut harness = Harness::new();
    let first = harness.resident(1, 0x10);
    let second = harness.resident(2, 0x20);
    harness.evict(first).expect("evict first");
    let index = harness.index_of(first).expect("first is swapped");

    harness.backend.fail_reads(1);
    assert_eq!(harness.fault(first), Err(SwapFaultError::Backend));
    assert_eq!(
        harness.index_of(first),
        Some(index),
        "the page-table entry still names the index"
    );
    assert_eq!(harness.backend.extents(), [pattern(0x10)]);

    // Another page going out in between must not be handed the index the
    // first page's entry still carries.
    harness.evict(second).expect("evict second");
    assert_ne!(
        harness.index_of(second),
        Some(index),
        "an index a page-table entry still names is not free"
    );

    harness.fault(first).expect("the retry succeeds");
    assert_eq!(harness.contents(first), pattern(0x10));
    harness.fault(second).expect("the second page is unharmed");
    assert_eq!(harness.contents(second), pattern(0x20));
}

#[test]
fn a_failed_reinstatement_sends_the_page_back_under_the_same_index() {
    let mut harness = Harness::new();
    let addr = harness.resident(1, 0x30);
    harness.evict(addr).expect("evict");
    let index = harness.index_of(addr).expect("swapped");

    with_space(|space| space.reinstatements_to_refuse = 1);
    assert_eq!(harness.fault(addr), Err(SwapFaultError::AddressSpace));
    assert_eq!(
        harness.index_of(addr),
        Some(index),
        "the entry still names the index"
    );
    assert_eq!(
        harness.backend.extents(),
        [pattern(0x30)],
        "the backend holds the page again, because the staging buffer held its only copy"
    );

    harness.fault(addr).expect("the next fault succeeds");
    assert_eq!(harness.contents(addr), pattern(0x30));
}

#[test]
fn a_page_that_cannot_go_back_to_the_backend_is_lost_and_its_index_stays_reserved() {
    let mut harness = Harness::new();
    let lost = harness.resident(1, 0x40);
    let other = harness.resident(2, 0x50);
    harness.evict(lost).expect("evict");
    let index = harness.index_of(lost).expect("swapped");

    with_space(|space| space.reinstatements_to_refuse = 1);
    harness.backend.refuse_writes(1);
    assert_eq!(harness.fault(lost), Err(SwapFaultError::AddressSpace));
    assert_eq!(harness.index_of(lost), Some(index));
    assert_eq!(harness.backend.extents(), Vec::<Vec<u8>>::new());

    assert_eq!(
        harness.fault(lost),
        Err(SwapFaultError::PageLost),
        "a fault on a lost page reports it, so the owning instance traps"
    );

    harness.evict(other).expect("evict other");
    assert_ne!(
        harness.index_of(other),
        Some(index),
        "a lost page's index stays reserved"
    );

    // Tearing the address space down releases the reservation.
    harness.teardown(index);
    let third = harness.resident(3, 0x60);
    harness.evict(third).expect("evict third");
    assert_eq!(harness.index_of(third), Some(index));
}

#[test]
fn a_refused_write_puts_the_page_back() {
    let mut harness = Harness::new();
    let addr = harness.resident(1, 0x70);
    harness.backend.refuse_writes(1);
    assert_eq!(harness.evict(addr), Err(()));
    assert_eq!(harness.contents(addr), pattern(0x70));
    assert_eq!(harness.index_of(addr), None);

    harness.evict(addr).expect("the next eviction succeeds");
    harness.fault(addr).expect("fault");
    assert_eq!(harness.contents(addr), pattern(0x70));
}

#[test]
fn a_refused_write_with_a_failed_put_back_loses_the_page_loudly() {
    let mut harness = Harness::new();
    let addr = harness.resident(1, 0x80);
    // The backend refuses the write and the retry of it, and the address
    // space refuses the put-back.
    harness.backend.refuse_writes(2);
    with_space(|space| space.reinstatements_to_refuse = 1);
    assert_eq!(harness.evict(addr), Err(()));
    let index = harness
        .index_of(addr)
        .expect("the entry still names an index");

    assert_eq!(harness.fault(addr), Err(SwapFaultError::PageLost));
    let other = harness.resident(2, 0x90);
    harness.evict(other).expect("evict other");
    assert_ne!(harness.index_of(other), Some(index));
    harness.teardown(index);
}

#[test]
fn a_failed_put_back_that_the_backend_then_accepts_leaves_the_page_swapped_out() {
    let mut harness = Harness::new();
    let addr = harness.resident(1, 0xa0);
    harness.backend.refuse_writes(1);
    with_space(|space| space.reinstatements_to_refuse = 1);
    harness
        .evict(addr)
        .expect("the retry of the write lands, so the page is out");
    assert!(harness.index_of(addr).is_some());
    harness.fault(addr).expect("fault");
    assert_eq!(harness.contents(addr), pattern(0xa0));
}

#[test]
fn teardown_releases_a_swapped_out_page_once_and_never_a_swapped_in_one() {
    let mut harness = Harness::new();
    let back = harness.resident(1, 0xc0);
    let out = harness.resident(2, 0xc1);
    harness.evict(back).expect("evict the page that returns");
    harness.evict(out).expect("evict the page that stays out");
    let back_index = harness.index_of(back).expect("swapped out");
    let out_index = harness.index_of(out).expect("swapped out");
    harness.fault(back).expect("swap the first page back in");
    assert_eq!(harness.backend.released(), Vec::<u64>::new());

    // The address space's teardown hands over the index of every page it
    // ever swapped out, the swapped-in one included.
    harness.teardown(back_index);
    assert_eq!(
        harness.backend.released(),
        Vec::<u64>::new(),
        "a token swap_in consumed is never released"
    );
    harness.teardown(out_index);
    harness.teardown(out_index);
    assert_eq!(
        harness.backend.released(),
        vec![2],
        "the page still out is released once, under its own token"
    );
}

#[test]
fn two_faults_on_one_page_both_succeed() {
    let mut harness = Harness::new();
    let addr = harness.resident(1, 0xb0);
    harness.evict(addr).expect("evict");

    let handle = harness.handle.clone();
    let mut first = issue(&handle, addr);
    let mut second = issue(&handle, VirtAddr::new(addr.raw() + 17));
    harness.serve();
    assert_eq!(poll(&mut first), Some(Ok(())));
    assert_eq!(
        poll(&mut second),
        Some(Ok(())),
        "the page is present, so the instruction retries"
    );
    assert_eq!(harness.contents(addr), pattern(0xb0));
    assert_eq!(harness.handle.stats().pages_in, 1);
}

/// An instance that begins a turn while the pass is waiting on the
/// device keeps every page the pass had planned to take: nothing leaves
/// memory while it runs, and the pass takes the rest once it is off
/// again.
#[test]
fn an_instance_that_starts_running_mid_pass_keeps_its_pages() {
    let mut harness = Harness::new();
    let pages: Vec<VirtAddr> = (1..=4)
        .map(|number| harness.resident(number, number as u8))
        .collect();
    let activity = InstanceActivity::new(harness.instance.clone(), 0);
    let turns: &'static StoreTurns = Box::leak(Box::new(activity.turns()));
    harness.backend.begin_turn_after_writes(1, turns);

    assert_eq!(
        harness.evict_instance(pages.len() * PAGE),
        PAGE,
        "the page whose write was in flight is out, and nothing after it"
    );
    assert!(!harness.is_resident(pages[0]));
    for &addr in &pages[1..] {
        assert!(
            harness.is_resident(addr),
            "page {:#x} left memory while its instance ran",
            addr.raw()
        );
    }

    harness.backend.end_turn(2);
    assert_eq!(harness.evict_instance(pages.len() * PAGE), 3 * PAGE);
    for (number, &addr) in pages.iter().enumerate() {
        harness.fault(addr).expect("fault the page back");
        assert_eq!(harness.contents(addr), pattern(number as u8 + 1));
    }
    drop(activity);
}

#[test]
fn fault_latency_counts_the_time_a_request_spent_queued() {
    let mut harness = Harness::new();
    let addr = harness.resident(1, 0xc0);
    harness.evict(addr).expect("evict");

    set_clock(1_000);
    let handle = harness.handle.clone();
    let mut fault = issue(&handle, addr);
    // The service is busy elsewhere for fifty microseconds before it gets
    // to the request; the read itself takes no time on the test clock.
    set_clock(51_000);
    harness.serve();
    assert_eq!(poll(&mut fault), Some(Ok(())));

    let stats = harness.handle.stats();
    assert_eq!(stats.faults_served, 1);
    assert_eq!(
        stats.mean_fault_latency_nanos, 50_000,
        "latency runs from the request to its completion, queue included"
    );
}

/// The checks a host call or a runtime copy makes, over the fake address
/// space and the harness's swap service.
fn residency(handle: &SwapHandle) -> GuestResidency {
    GuestResidency {
        hooks: &TEST_HOOKS,
        // Leaked: a residency names its handle `'static`, as the machine's
        // one swap handle is.
        handle: Box::leak(Box::new(Once::initialized(handle.clone()))),
    }
}

/// Stands in for a host call's copy: writes `byte` at the start of each
/// page, and refuses to run while any of them is out.
fn copy_into(pages: &[VirtAddr], byte: u8) {
    with_space(|space| {
        for page in pages {
            match space.pages.get_mut(&page.raw()) {
                Some(FakePage::Present(bytes)) => bytes[0] = byte,
                _ => panic!("the copy ran while page {:#x} was out", page.raw()),
            }
        }
    });
}

/// The issue's done-when case: a page a host call is about to write was
/// evicted while its instance was idle. The call waits for the page
/// rather than faulting outside a fiber, and completes, its write
/// landing, once the page is back.
#[test]
fn a_host_call_writing_into_an_evicted_page_completes_once_it_is_back() {
    let mut harness = Harness::new();
    let head = harness.resident(1, 0x10);
    let tail = harness.resident(2, 0x20);
    harness.evict(tail).expect("evict the page the call writes");
    let residency = residency(&harness.handle);

    // Eight bytes either side of the page boundary.
    let range = VirtRange::new(VirtAddr::new(tail.raw() - 8), 16);
    let mut call = Box::pin(residency.with_present(range, || {
        copy_into(&[head, tail], 0xee);
        "written"
    }));
    assert!(
        poll(&mut call).is_none(),
        "the call waits for the page instead of touching it"
    );
    assert!(
        harness.index_of(tail).is_some(),
        "nothing has read the page back yet"
    );

    harness.serve();
    assert_eq!(poll(&mut call), Some(Ok("written")));
    let mut expected = pattern(0x20);
    expected[0] = 0xee;
    assert_eq!(
        harness.contents(tail),
        expected,
        "the page came back with its bytes, and the call's write landed on it"
    );
}

/// A page brought back for one check may be taken again before the
/// waiter is next polled; the access runs only after a check that finds
/// every page present, in its own poll.
#[test]
fn a_page_taken_again_before_the_access_runs_is_brought_back_again() {
    let mut harness = Harness::new();
    let page = harness.resident(1, 0x30);
    harness.evict(page).expect("evict");
    let residency = residency(&harness.handle);

    let mut call = Box::pin(residency.with_present(VirtRange::new(page, PAGE), || {
        copy_into(&[page], 0x31);
    }));
    assert!(poll(&mut call).is_none());
    harness.serve();
    // Back in, and out again before the waiter runs.
    harness.evict(page).expect("evict again");
    assert!(
        poll(&mut call).is_none(),
        "the re-check finds the page out and waits again"
    );
    harness.serve();
    assert_eq!(poll(&mut call), Some(Ok(())));
    assert_eq!(harness.contents(page)[0], 0x31);
    assert_eq!(harness.handle.stats().pages_in, 2);
}

/// A page that cannot be read back fails the access, which never runs:
/// the caller traps its guest rather than copying memory that is gone.
#[test]
fn a_page_that_cannot_come_back_fails_the_access_without_running_it() {
    let mut harness = Harness::new();
    let page = harness.resident(1, 0x40);
    harness.evict(page).expect("evict");
    harness.backend.fail_reads(1);
    let residency = residency(&harness.handle);

    let mut call = Box::pin(residency.with_present(VirtRange::new(page, PAGE), || {
        panic!("the access ran over a page that never came back")
    }));
    assert!(poll(&mut call).is_none());
    harness.serve();
    assert_eq!(poll(&mut call), Some(Err(SwapFaultError::Backend)));
}

/// Before the swap device comes up nothing can have been swapped out, so
/// an access runs at once without asking the address space anything.
#[test]
fn an_access_before_swap_comes_up_runs_at_once() {
    let residency = GuestResidency {
        hooks: &TEST_HOOKS,
        handle: Box::leak(Box::new(Once::new())),
    };
    let mut call =
        Box::pin(residency.with_present(VirtRange::new(VirtAddr::new(PAGE), PAGE), || "ran"));
    assert_eq!(poll(&mut call), Some(Ok("ran")));
}

/// The stream path: a page of a guest's read buffer is swapped out when
/// a host producer is about to deliver into it. The runtime asks the
/// residency hook in the poll that would make the copy; the hook hands
/// back the fault-in instead of letting the copy through, and once that
/// has resolved the same check lets the delivery go ahead.
#[cfg(feature = "wasmtime-runtime")]
#[test]
fn a_stream_delivery_into_an_evicted_read_buffer_waits_for_the_fault_in() {
    use core::ptr::NonNull;

    use wasmtime::component::GuestMemoryResidency;

    use crate::wasmtime_adapter::residency::SwapResidencyHook;

    let mut harness = Harness::new();
    let buffer = harness.resident(3, 0x50);
    let tail = harness.resident(4, 0x60);
    harness
        .evict(tail)
        .expect("evict the second page of the read buffer");
    let mut hook = SwapResidencyHook::new(residency(&harness.handle));

    // The guest's read buffer as the runtime names it: host addresses,
    // two pages long. The fake address space is never dereferenced.
    let read_buffer = NonNull::slice_from_raw_parts(
        NonNull::new(buffer.raw() as *mut u8).expect("a page is never at address zero"),
        2 * PAGE,
    );
    let mut wait = Box::pin(
        hook.wait_until_resident(read_buffer)
            .expect("a page of the read buffer is out, so the delivery must wait"),
    );
    assert!(
        poll(&mut wait).is_none(),
        "the fault-in waits for the device"
    );
    harness.serve();
    assert_eq!(poll(&mut wait), Some(Ok(())));
    assert!(
        hook.wait_until_resident(read_buffer).is_none(),
        "every page of the buffer is back, so the delivery goes ahead in this poll"
    );
    assert_eq!(harness.contents(tail), pattern(0x60));
}

/// A guest's linear memory whose pages swap through the fake address
/// space and the harness's swap service, for tests outside this module
/// that run a host call's guest-memory step against an evicted page.
///
/// The memory is real and page-aligned, so the code under test reads and
/// writes it as it would a guest's. Evicting a page hands its bytes to the
/// swap backend and fills the page with [`Self::POISON`], as a frame that
/// went back to the pool holds whatever its next owner wrote; reading the
/// page back restores its bytes. A copy that ran while its page was out
/// therefore reads the poison, or loses what it wrote when the page comes
/// back, and the test sees either.
pub(crate) struct GuestSwap {
    harness: Harness,
    base: core::ptr::NonNull<u8>,
    /// Which pages are out, their real bytes poisoned.
    out: Vec<bool>,
}

impl GuestSwap {
    /// What an evicted page holds until it comes back.
    pub(crate) const POISON: u8 = 0xa5;

    /// A zeroed memory of `pages` pages, every one of them present.
    pub(crate) fn new(pages: usize) -> Self {
        let harness = Harness::new();
        // SAFETY: the layout is non-empty: every test memory has a page.
        let base =
            core::ptr::NonNull::new(unsafe { alloc::alloc::alloc_zeroed(Self::layout(pages)) })
                .expect("the test memory allocates");
        let memory = Self {
            harness,
            base,
            out: vec![false; pages],
        };
        for page in 0..pages {
            let addr = memory.page_addr(page);
            with_space(|space| {
                space
                    .pages
                    .insert(addr.raw(), FakePage::Present(vec![0; PAGE]));
            });
        }
        memory
    }

    fn layout(pages: usize) -> alloc::alloc::Layout {
        assert!(pages > 0, "a test memory has at least one page");
        alloc::alloc::Layout::from_size_align(pages * PAGE, PAGE)
            .expect("a test memory is a whole number of pages")
    }

    /// The host address the memory starts at.
    pub(crate) fn base(&self) -> usize {
        self.base.as_ptr() as usize
    }

    /// The memory's length in bytes.
    pub(crate) fn len(&self) -> usize {
        self.out.len() * PAGE
    }

    /// The memory as the guest would see it now: an evicted page reads
    /// as poison.
    pub(crate) fn bytes(&self) -> &[u8] {
        // SAFETY: the allocation is `len` bytes and lives as long as `self`.
        unsafe { core::slice::from_raw_parts(self.base.as_ptr(), self.len()) }
    }

    /// The memory, for a test to lay out what the guest passes in.
    pub(crate) fn bytes_mut(&mut self) -> &mut [u8] {
        // SAFETY: as in `bytes`, borrowed mutably through `self`.
        unsafe { core::slice::from_raw_parts_mut(self.base.as_ptr(), self.len()) }
    }

    /// The checks a host call makes over this memory.
    pub(crate) fn residency(&self) -> GuestResidency {
        residency(&self.harness.handle)
    }

    fn page_addr(&self, page: usize) -> VirtAddr {
        assert!(
            page < self.out.len(),
            "page {page} is outside the test memory"
        );
        VirtAddr::new(self.base() + page * PAGE)
    }

    /// Takes page `page` out, the way a pass over an idle instance would.
    pub(crate) fn evict(&mut self, page: usize) {
        let addr = self.page_addr(page);
        let range = page * PAGE..(page + 1) * PAGE;
        let bytes = self.bytes()[range.clone()].to_vec();
        with_space(|space| {
            space.pages.insert(addr.raw(), FakePage::Present(bytes));
        });
        self.harness.evict(addr).expect("the page goes out");
        self.bytes_mut()[range].fill(Self::POISON);
        self.out[page] = true;
    }

    /// Whether page `page` is out.
    pub(crate) fn is_out(&self, page: usize) -> bool {
        self.harness.index_of(self.page_addr(page)).is_some()
    }

    /// How many fault-ins wait for the swap service.
    pub(crate) fn queued_faults(&self) -> usize {
        self.harness.handle.shared.faults.len()
    }

    /// Makes the next `count` reads from the swap device fail, so a page
    /// faulted in meanwhile cannot come back.
    pub(crate) fn fail_reads(&self, count: u32) {
        self.harness.backend.fail_reads(count);
    }

    /// Runs the swap service over every queued fault-in, and puts each
    /// page that came back where the code under test reads it.
    pub(crate) fn serve(&mut self) {
        self.harness.serve();
        for page in 0..self.out.len() {
            if !self.out[page] || self.is_out(page) {
                continue;
            }
            let addr = self.page_addr(page);
            let bytes = with_space(|space| match &space.pages[&addr.raw()] {
                FakePage::Present(bytes) => bytes.clone(),
                FakePage::Swapped(_) => unreachable!("a page with no swap token is present"),
            });
            self.bytes_mut()[page * PAGE..(page + 1) * PAGE].copy_from_slice(&bytes);
            self.out[page] = false;
        }
    }
}

impl Drop for GuestSwap {
    fn drop(&mut self) {
        // SAFETY: allocated in `new` with this layout and freed only here.
        unsafe { alloc::alloc::dealloc(self.base.as_ptr(), Self::layout(self.out.len())) };
    }
}

/// The page size [`GuestSwap`] works in.
pub(crate) const GUEST_SWAP_PAGE: usize = PAGE;

mod native_swap_tests {
    use core::ptr::NonNull;

    use helios_hal::cpu::{Cpu, Instant, ProcessorId, Timebase, TimerInterrupt};
    use helios_hal::hv::RegisterId;
    use helios_hal::native::{
        ExtendedState, InstructionSet, NativeError, NativeExecution, NativeUnavailable, Stop,
        UserContext, UserSpace,
    };

    use super::*;
    use crate::memory::{NativeSpace, UserTranslation};

    #[derive(Clone, Copy)]
    struct ModelPte {
        _physical: u64,
        flags: PageFlags,
        accessed: bool,
    }

    #[derive(Clone)]
    struct ModelTables {
        ptes: Arc<spin::Mutex<BTreeMap<u64, ModelPte>>>,
        fail_next_install: Arc<core::sync::atomic::AtomicU32>,
    }

    impl ModelTables {
        fn new() -> Self {
            Self {
                ptes: Arc::new(spin::Mutex::new(BTreeMap::new())),
                fail_next_install: Arc::new(core::sync::atomic::AtomicU32::new(0)),
            }
        }
    }

    // SAFETY: host-only model tables for unit-testing `SwapService` with `NativeSpace`.
    unsafe impl UserTranslation for ModelTables {
        fn install(
            &mut self,
            base: u64,
            physical: u64,
            flags: PageFlags,
        ) -> Result<(), NativeError> {
            let remaining = self.fail_next_install.load(Ordering::Acquire);
            if remaining > 0 {
                self.fail_next_install
                    .store(remaining - 1, Ordering::Release);
                return Err(NativeError::OutOfMemory);
            }
            let prev = self.ptes.lock().insert(
                base,
                ModelPte {
                    _physical: physical,
                    flags,
                    accessed: true,
                },
            );
            assert!(prev.is_none(), "double install at {base:#x}");
            Ok(())
        }

        fn uninstall(&mut self, base: u64) {
            let prev = self.ptes.lock().remove(&base);
            assert!(prev.is_some(), "uninstall missing page {base:#x}");
        }

        fn protect(&mut self, base: u64, flags: PageFlags) {
            let mut ptes = self.ptes.lock();
            let entry = ptes.get_mut(&base).expect("protect on mapped page");
            entry.flags = flags;
            entry.accessed = true;
        }

        fn invalidate(&self, _first: u64, _last: u64) {}

        fn physical(&self, frame: NonNull<u8>) -> u64 {
            frame.as_ptr() as u64
        }

        fn new_empty(&self) -> Result<Self, NativeError> {
            Ok(Self::new())
        }

        fn test_and_clear_accessed(&mut self, base: u64) -> bool {
            let mut ptes = self.ptes.lock();
            let Some(entry) = ptes.get_mut(&base) else {
                return false;
            };
            let hot = entry.accessed;
            entry.accessed = false;
            hot
        }
    }

    struct DummyContext;

    // SAFETY: never enters hardware user mode; only satisfies `NativeExecution::Context`.
    unsafe impl UserContext for DummyContext {
        type Space = NativeSpace<ModelTables>;

        fn register(&self, _: RegisterId) -> Result<u64, NativeError> {
            Err(NativeError::Register)
        }
        fn set_register(&mut self, _: RegisterId, _: u64) -> Result<(), NativeError> {
            Err(NativeError::Register)
        }
        fn thread_pointer(&self) -> VirtAddr {
            VirtAddr::new(0)
        }
        fn set_thread_pointer(&mut self, _: VirtAddr) -> Result<(), NativeError> {
            Ok(())
        }
        fn extended_state(&self) -> ExtendedState {
            ExtendedState::X86Xsave(Vec::new())
        }
        fn set_extended_state(&mut self, _: &ExtendedState) -> Result<(), NativeError> {
            Ok(())
        }
        fn try_clone(&self) -> Result<Self, NativeError> {
            Ok(Self)
        }
        fn resume(&mut self, _: &Self::Space) -> Stop {
            Stop::Preempted
        }
    }

    #[derive(Clone, Copy)]
    struct NativeTestCpu;

    impl NativeExecution for NativeTestCpu {
        type Space = NativeSpace<ModelTables>;
        type Context = DummyContext;

        fn instruction_set(&self) -> InstructionSet {
            InstructionSet::X86_64
        }

        fn user_range(&self) -> VirtRange {
            VirtRange::new(VirtAddr::new(PAGE), 0x1_0000_0000)
        }

        fn create_space(&self) -> Result<Self::Space, NativeError> {
            Ok(NativeSpace::new(
                ModelTables::new(),
                PAGE as u64,
                0x1_0000_0000,
            ))
        }

        fn create_context(&self, _: VirtAddr, _: VirtAddr) -> Result<Self::Context, NativeError> {
            Ok(DummyContext)
        }
    }

    impl Cpu for NativeTestCpu {
        type Hypervisor = core::convert::Infallible;
        type Native = Self;
        const TIMER_INTERRUPT: TimerInterrupt = TimerInterrupt::Deadline;

        fn has_lazy_commit_virtual_memory(&self) -> bool {
            true
        }

        fn processor_count(&self) -> usize {
            1
        }

        fn bootstrap_processor(&self) -> ProcessorId {
            ProcessorId::new(0)
        }

        fn park_current(&self) {}

        type WakeOnlyMask = ();

        fn mask_to_wake_only(&self) {
            panic!("test CPU never freezes")
        }

        fn park_wake_only(&self, _: &core::sync::atomic::AtomicU8, _: u8) {
            panic!("test CPU never freezes")
        }

        fn start_processor(&self, _: ProcessorId) {}

        fn wake_processor(&self, _: ProcessorId) {}

        fn stop_current(&self) {
            panic!("test CPU never stops a processor")
        }

        fn restart_processor(&self, _: ProcessorId) {
            panic!("test CPU never restarts a processor")
        }

        fn now(&self) -> Instant {
            Instant::new(CLOCK_NANOS.with(Cell::get))
        }

        fn timebase(&self) -> Timebase {
            Timebase::new(1_000_000_000)
        }

        fn set_deadline(&self, _: Instant) {}

        fn publish_executable(&self, _: *const u8, _: usize) {}

        fn unpublish_executable(&self, _: *const u8, _: usize) {}

        fn native_feature_probe(&self) -> Option<fn(&str) -> Option<bool>> {
            None
        }

        fn shutdown(&self) -> ! {
            panic!("test CPU should not shut down")
        }

        fn reboot(&self) -> ! {
            panic!("test CPU should not reboot")
        }

        fn native(&self) -> Result<&Self::Native, NativeUnavailable> {
            Ok(self)
        }
    }

    fn ensure_pool() {
        const POOL_BYTES: usize = 4 * 1024 * 1024;
        if crate::memory::installed_user_memory_pool().is_some() {
            return;
        }
        let layout = alloc::alloc::Layout::from_size_align(POOL_BYTES, PAGE).expect("pool layout");
        // SAFETY: nonzero size, leaked for the lifetime of the test process pool.
        let base = unsafe { alloc::alloc::alloc_zeroed(layout) } as usize;
        assert!(base != 0);
        crate::memory::install_user_memory_pool(crate::memory::UserMemoryPool::single_node(
            1,
            &[(base, base + POOL_BYTES)],
        ));
    }

    struct NativeHarness {
        service: SwapService<FlakyBackend, NativeTestCpu>,
        handle: SwapHandle,
        backend: FlakyBackend,
        native_spaces: NativeSpaceRegistry<NativeSpace<ModelTables>>,
    }

    impl NativeHarness {
        fn new() -> Self {
            ensure_pool();
            with_space(|space| *space = FakeSpace::default());
            set_clock(0);
            let backend = FlakyBackend::default();
            let handle = SwapHandle::new(
                "native-test",
                64 * PAGE as u64,
                SwapClock {
                    timebase: Timebase::new(1_000_000_000),
                    now_ticks: TEST_HOOKS.now_ticks,
                },
            );
            let native_spaces = NativeSpaceRegistry::new();
            native_spaces.attach_swap_handle(handle.clone());
            let service = SwapService {
                backend: backend.clone(),
                handle: handle.clone(),
                hooks: &TEST_HOOKS,
                registry: InstanceRegistry::new(),
                native_spaces: native_spaces.clone(),
                cpu: NativeTestCpu,
                map: SwapMap::new(),
                page: Some(vec![0_u8; PAGE].into_boxed_slice()),
                report: SwapReport::default(),
            };
            Self {
                service,
                handle,
                backend,
                native_spaces,
            }
        }

        fn fault_native(&mut self, space_id: u64, base: VirtAddr) -> Result<(), SwapFaultError> {
            let mut fault = Box::pin(self.handle.fault_in_native(space_id, base));
            assert!(
                poll(&mut fault).is_none(),
                "native fault-in parks until service runs"
            );
            block_on(self.service.serve_faults());
            poll(&mut fault).expect("service settled native fault")
        }
    }

    #[test]
    fn native_yellow_idle_and_red_aging_eviction_fault_in_and_zero_leaks() {
        let mut harness = NativeHarness::new();
        let rw = PageFlags::READ | PageFlags::WRITE;
        let tables_idle = ModelTables::new();
        let space_idle = Arc::new(NativeSpace::new(
            tables_idle.clone(),
            PAGE as u64,
            0x1_0000_0000,
        ));
        let tables_active = ModelTables::new();
        let space_active = Arc::new(NativeSpace::new(
            tables_active.clone(),
            PAGE as u64,
            0x1_0000_0000,
        ));

        let payload_a = "中文 日本語 한국어 page-a".as_bytes();
        let payload_b = "中文 日本語 한국어 page-b".as_bytes();
        space_idle
            .map(VirtRange::new(VirtAddr::new(0x10_000), 2 * PAGE), &[], rw)
            .unwrap();
        space_idle
            .write(VirtAddr::new(0x10_000), payload_a)
            .unwrap();
        space_idle
            .write(VirtAddr::new(0x11_000), payload_b)
            .unwrap();

        space_active
            .map(VirtRange::new(VirtAddr::new(0x20_000), 2 * PAGE), &[], rw)
            .unwrap();
        space_active
            .write(VirtAddr::new(0x20_000), b"hot-page")
            .unwrap();
        space_active
            .write(VirtAddr::new(0x21_000), b"cold-page")
            .unwrap();

        let reg_idle =
            harness
                .native_spaces
                .register(Arc::clone(&space_idle), MemoryOwner::new(101), 0);
        let reg_active =
            harness
                .native_spaces
                .register(Arc::clone(&space_active), MemoryOwner::new(102), 0);

        // Advance clock past IDLE_SWAP_AFTER; touch `reg_active` so only `reg_idle` is idle.
        let now = IDLE_SWAP_AFTER.as_nanos() as u64 + 1_000_000;
        set_clock(now);
        reg_active.record_activity(now);

        // Yellow pass evicts `reg_idle`'s 2 pages and leaves `reg_active` untouched.
        let moved = block_on(harness.service.evict_idle_pass(
            now,
            IDLE_SWAP_AFTER.as_nanos() as u64,
            SWAP_BATCH_BYTES,
        ));
        assert_eq!(moved, 2 * PAGE);
        assert_eq!(space_idle.swapped_bytes(), 2 * PAGE as u64);
        assert_eq!(space_active.swapped_bytes(), 0);
        let stats = harness.handle.stats();
        assert_eq!(stats.pages_out, 2);
        assert_eq!(stats.used_bytes, 2 * PAGE as u64);

        // Async fault-in restores page 0x10_000 byte-exact.
        harness
            .fault_native(reg_idle.space_id(), VirtAddr::new(0x10_000))
            .unwrap();
        let mut readback = vec![0u8; payload_a.len()];
        space_idle
            .read(VirtAddr::new(0x10_000), &mut readback)
            .unwrap();
        assert_eq!(readback, payload_a);
        assert_eq!(space_idle.swapped_bytes(), PAGE as u64);
        assert_eq!(harness.handle.stats().pages_in, 1);
        assert_eq!(harness.handle.stats().used_bytes, PAGE as u64);

        // Red pass 1 on `reg_active`: both pages start Hot -> clears ACCESSED, evicts 0.
        let red1 = block_on(harness.service.evict_cold_pass(now, SWAP_BATCH_BYTES));
        assert_eq!(red1, 0);
        assert_eq!(space_active.swapped_bytes(), 0);

        // Touch 0x20_000 (AF fault restores ACCESSED), leave 0x21_000 untouched.
        space_active
            .resolve_fault(VirtAddr::new(0x20_000), PageFlags::READ)
            .unwrap();

        // Red pass 2: evicts ONLY cold 0x21_000 (and 0x10_000 which was cleared in red1).
        let red2 = block_on(harness.service.evict_cold_pass(now, SWAP_BATCH_BYTES));
        assert!(red2 >= PAGE);
        assert_eq!(space_active.swapped_token(VirtAddr::new(0x20_000)), None);
        assert!(
            space_active
                .swapped_token(VirtAddr::new(0x21_000))
                .is_some()
        );

        // Fault back in 0x21_000 and verify byte-exact content.
        harness
            .fault_native(reg_active.space_id(), VirtAddr::new(0x21_000))
            .unwrap();
        let mut cold_back = [0u8; 9];
        space_active
            .read(VirtAddr::new(0x21_000), &mut cold_back)
            .unwrap();
        assert_eq!(&cold_back, b"cold-page");

        // Unmap one swapped page, then drop both registrations (exit/execve):
        // release_orphaned_tokens must free 100% of backend extents (zero leaks!).
        space_idle
            .unmap(VirtRange::new(VirtAddr::new(0x11_000), PAGE))
            .unwrap();
        drop(reg_idle);
        drop(reg_active);
        block_on(harness.service.release_orphaned_tokens());
        assert!(
            harness.backend.extents().is_empty(),
            "all swap extents must be released on unmap and space teardown"
        );
        assert_eq!(harness.handle.stats().used_bytes, 0);
    }

    #[test]
    fn native_swap_handles_backend_refusal_and_concurrent_unmap_during_fault_in() {
        let mut harness = NativeHarness::new();
        let rw = PageFlags::READ | PageFlags::WRITE;
        let tables = ModelTables::new();
        let space = Arc::new(NativeSpace::new(tables.clone(), PAGE as u64, 0x1_0000_0000));
        space
            .map(VirtRange::new(VirtAddr::new(0x10_000), 2 * PAGE), &[], rw)
            .unwrap();
        space
            .write(VirtAddr::new(0x10_000), b"rollback-ok")
            .unwrap();
        space
            .write(VirtAddr::new(0x11_000), b"unmap-race!")
            .unwrap();
        let reg = harness
            .native_spaces
            .register(Arc::clone(&space), MemoryOwner::new(201), 0);

        // Backend refuses write -> SwapService puts the page back into NativeSpace cleanly.
        harness.backend.refuse_writes(1);
        let moved = block_on(harness.service.evict_native_space(
            reg.space_id(),
            PAGE,
            EvictionAge::Any,
        ));
        assert_eq!(moved, 0);
        assert_eq!(space.swapped_bytes(), 0);
        let mut check = [0u8; 11];
        space.read(VirtAddr::new(0x10_000), &mut check).unwrap();
        assert_eq!(&check, b"rollback-ok");

        // Evict both pages successfully, then simulate reinstatement OOM failure ->
        // rehomes back to backend and later succeeds.
        let moved = block_on(harness.service.evict_native_space(
            reg.space_id(),
            2 * PAGE,
            EvictionAge::Any,
        ));
        assert_eq!(moved, 2 * PAGE);
        tables.fail_next_install.store(1, Ordering::Release);
        assert_eq!(
            harness.fault_native(reg.space_id(), VirtAddr::new(0x10_000)),
            Err(SwapFaultError::AddressSpace)
        );
        assert!(space.swapped_token(VirtAddr::new(0x10_000)).is_some());
        harness
            .fault_native(reg.space_id(), VirtAddr::new(0x10_000))
            .unwrap();
        space.read(VirtAddr::new(0x10_000), &mut check).unwrap();
        assert_eq!(&check, b"rollback-ok");

        // Teardown releases remaining swapped page 0x11_000 cleanly.
        drop(reg);
        block_on(harness.service.release_orphaned_tokens());
        assert!(harness.backend.extents().is_empty());
        assert_eq!(harness.handle.stats().used_bytes, 0);
    }
}
