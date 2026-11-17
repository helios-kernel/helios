extern crate alloc;

use alloc::collections::VecDeque;
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::{Context, Poll};

use hashbrown::HashMap;
use hashbrown::hash_map::Entry;
use spin::Mutex;
use triomphe::Arc;

use helios_sync::{Notify, NotifyWaiter};

const FUTEX_TABLE_INITIAL_CAPACITY: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ProcessMemoryIdentity(u64);

impl ProcessMemoryIdentity {
    pub const fn new(raw: u64) -> Self {
        assert!(raw != 0, "process memory identity zero is reserved");
        Self(raw)
    }

    pub const fn raw(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct GuestAddress(u64);

impl GuestAddress {
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    /// The address a wasm32 guest passed as a pointer.
    pub const fn wasm32(raw: u32) -> Self {
        Self(raw as u64)
    }

    /// The address `bytes` past this one, for a field of a guest structure or
    /// an element of a guest array.
    ///
    /// The sum is computed in 64 bits and saturates, so it never wraps back
    /// into low guest memory. An address beyond the 32-bit guest space is
    /// representable and lies outside every guest memory, so the access that
    /// uses it fails with `EFAULT` at the host-call memory helpers.
    #[must_use]
    pub const fn offset(self, bytes: u64) -> Self {
        Self(self.0.saturating_add(bytes))
    }

    pub const fn raw(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FutexKey {
    memory: ProcessMemoryIdentity,
    address: GuestAddress,
}

impl FutexKey {
    pub const fn new(memory: ProcessMemoryIdentity, address: GuestAddress) -> Self {
        Self { memory, address }
    }

    pub const fn memory(self) -> ProcessMemoryIdentity {
        self.memory
    }

    pub const fn address(self) -> GuestAddress {
        self.address
    }
}

/// One queued wait, shared by its registration and its key's queue.
///
/// A wake releases a specific waiter: it takes the waiter off its key's
/// queue, sets `released`, and broadcasts on the waiter's own signal. The
/// signal belongs to this one wait and is only ever broadcast, once, so
/// it carries no permit for anyone else to claim.
struct FutexWaiter {
    /// Written once, by the wake that dequeues the waiter, under the
    /// table lock and before the broadcast.
    released: AtomicBool,
    signal: Notify,
}

impl FutexWaiter {
    fn new() -> Self {
        Self {
            released: AtomicBool::new(false),
            signal: Notify::new(),
        }
    }

    fn release(&self) {
        self.released.store(true, Ordering::Release);
        self.signal.notify_all();
    }
}

/// One live futex wait, queued on its key until a wake releases it or
/// this value is dropped.
///
/// The wait is queued, and its release armed, when it is created, so a
/// caller registers before it compares the guest word and a wake that
/// lands between the comparison and the park still releases it.
///
/// Dropping an unreleased registration takes it off its key's queue and
/// removes the key once its queue is empty, so a wait whose future is
/// cancelled while parked (a signal ending the thread, a kill, the store's
/// teardown) leaves nothing behind. A released registration is already
/// off the queue. It owns a handle to the table it is queued in; the drop
/// takes the table's lock, which is never held across an `.await`
/// anywhere.
pub struct FutexWaitRegistration {
    table: FutexTable,
    key: FutexKey,
    waiter: Arc<FutexWaiter>,
    wait: NotifyWaiter,
}

impl FutexWaitRegistration {
    pub fn key(&self) -> FutexKey {
        self.key
    }

    /// Whether a wake has released this wait.
    ///
    /// A wait that ends another way (a timeout, a word that no longer
    /// matches) reads this to learn whether a wake counted it anyway.
    pub fn is_released(&self) -> bool {
        self.waiter.released.load(Ordering::Acquire)
    }

    /// Polls until a wake releases this wait.
    pub fn poll_released(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        loop {
            if self.is_released() {
                return Poll::Ready(());
            }
            match self.waiter.signal.poll_notified(cx, &mut self.wait) {
                Poll::Ready(()) => continue,
                Poll::Pending => return Poll::Pending,
            }
        }
    }

    /// Resolves once a wake releases this wait.
    pub async fn released(&mut self) {
        core::future::poll_fn(|cx| self.poll_released(cx)).await;
    }
}

impl Drop for FutexWaitRegistration {
    fn drop(&mut self) {
        let mut entries = self.table.entries.lock();
        // Read under the lock a wake releases under: a waiter either is
        // still queued here or was dequeued by the wake that released it.
        if self.waiter.released.load(Ordering::Relaxed) {
            return;
        }
        match entries.entry(self.key) {
            Entry::Occupied(mut entry) => {
                let queue = entry.get_mut();
                let index = queue
                    .iter()
                    .position(|queued| Arc::ptr_eq(queued, &self.waiter))
                    .expect("an unreleased futex wait is queued on its key");
                queue.remove(index);
                if queue.is_empty() {
                    entry.remove();
                }
            }
            Entry::Vacant(_) => panic!("an unreleased futex wait referenced an unknown key"),
        }
    }
}

/// The machine's futex waits, shared by every wait that is queued in it.
///
/// Each key holds its unreleased waiters in arrival order. Cloning yields
/// another handle to the same table. Concurrency contract: every operation
/// takes the table's spin lock for a bounded, non-awaiting critical
/// section; a wake broadcasts to the waiters it releases inside it, which
/// is lock-free and never blocks.
pub struct FutexTable {
    entries: Arc<Mutex<HashMap<FutexKey, VecDeque<Arc<FutexWaiter>>>>>,
}

impl Default for FutexTable {
    fn default() -> Self {
        Self::new()
    }
}

impl FutexTable {
    pub fn new() -> Self {
        Self {
            entries: Arc::new(Mutex::new(HashMap::with_capacity(
                FUTEX_TABLE_INITIAL_CAPACITY,
            ))),
        }
    }

    /// Queues a wait on `key` until a wake releases it or the returned
    /// registration is dropped.
    pub fn prepare_wait(&self, key: FutexKey) -> FutexWaitRegistration {
        let waiter = Arc::new(FutexWaiter::new());
        // Armed before the waiter is queued, so no wake can precede it.
        let wait = waiter.signal.waiter();
        self.entries
            .lock()
            .entry(key)
            .or_default()
            .push_back(waiter.clone());
        FutexWaitRegistration {
            table: self.clone(),
            key,
            waiter,
            wait,
        }
    }

    /// Releases up to `count` of the key's waiters, oldest first, and
    /// returns how many it released.
    ///
    /// A released waiter leaves the queue at once, so a later wake on
    /// the key, made before the released waiters have run, never counts
    /// them again, and a wait queued after it is not released by it.
    pub fn wake(&self, key: FutexKey, count: usize) -> usize {
        let mut entries = self.entries.lock();
        let Entry::Occupied(mut entry) = entries.entry(key) else {
            return 0;
        };
        let queue = entry.get_mut();
        let released = count.min(queue.len());
        for waiter in queue.drain(..released) {
            waiter.release();
        }
        if queue.is_empty() {
            entry.remove();
        }
        released
    }

    /// Releases every waiter queued on the key and returns how many it
    /// released. A wait queued after it parks, exactly as a futex
    /// requires.
    pub fn wake_all(&self, key: FutexKey) -> usize {
        // Released under the lock, which is what a registration's drop
        // relies on to find an unreleased waiter still queued.
        let mut entries = self.entries.lock();
        let Some(queue) = entries.remove(&key) else {
            return 0;
        };
        for waiter in &queue {
            waiter.release();
        }
        queue.len()
    }

    /// The number of keys with at least one queued wait.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub fn capacity(&self) -> usize {
        self.entries.lock().capacity()
    }
    pub fn len(&self) -> usize {
        self.entries.lock().len()
    }
}

impl Clone for FutexTable {
    fn clone(&self) -> Self {
        Self {
            entries: self.entries.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use core::task::{Context, Waker};

    use futures_lite::future::{block_on, poll_once};

    use super::*;

    fn key(memory: u64, address: u64) -> FutexKey {
        FutexKey::new(
            ProcessMemoryIdentity::new(memory),
            GuestAddress::new(address),
        )
    }

    #[test]
    fn guest_address_offset_does_not_wrap_the_32_bit_guest_space() {
        let top = GuestAddress::wasm32(u32::MAX - 2);

        assert_eq!(top.offset(4).raw(), u64::from(u32::MAX) + 2);
        assert_eq!(GuestAddress::new(u64::MAX).offset(1).raw(), u64::MAX);
    }

    #[test]
    fn futex_table_preallocates_expected_wait_keys() {
        let table = FutexTable::new();

        assert!(table.capacity() >= 64);
    }

    #[test]
    fn wake_one_targets_matching_key() {
        let table = FutexTable::new();
        let registration = table.prepare_wait(key(1, 0x1000));

        assert_eq!(table.wake(key(1, 0x2000), 1), 0);
        assert_eq!(table.wake(key(1, 0x1000), 1), 1);

        assert!(registration.is_released());
    }

    #[test]
    fn process_memory_identity_partitions_same_guest_address() {
        let table = FutexTable::new();
        let mut left = table.prepare_wait(key(1, 0x1000));
        let mut right = table.prepare_wait(key(2, 0x1000));

        assert_eq!(table.wake(key(1, 0x1000), 1), 1);
        assert!(
            !right.is_released(),
            "a wake on one memory leaves the other"
        );
        assert_eq!(table.wake(key(2, 0x1000), 1), 1);

        block_on(left.released());
        block_on(right.released());
    }

    /// A wake releases the waiters that queued first, and only as many
    /// as it was asked for.
    #[test]
    fn wake_releases_the_oldest_waiters_it_was_asked_for() {
        let table = FutexTable::new();
        let first = table.prepare_wait(key(1, 0x1000));
        let second = table.prepare_wait(key(1, 0x1000));
        let third = table.prepare_wait(key(1, 0x1000));

        assert_eq!(table.wake(key(1, 0x1000), 2), 2);

        assert!(first.is_released());
        assert!(second.is_released());
        assert!(!third.is_released());
        assert_eq!(table.wake(key(1, 0x1000), 5), 1, "only the third is left");
        assert!(third.is_released());
    }

    #[test]
    fn wake_all_reports_all_waiters_for_key() {
        let table = FutexTable::new();
        // Both waits are queued before the wake, as the guest-facing wait
        // path queues before it compares the futex word.
        let mut first = table.prepare_wait(key(1, 0x1000));
        let mut second = table.prepare_wait(key(1, 0x1000));

        assert_eq!(table.wake_all(key(1, 0x1000)), 2);

        block_on(first.released());
        block_on(second.released());
    }

    /// A parked wait is woken by the wake that releases it, not only
    /// found released the next time it is polled.
    #[test]
    fn a_parked_wait_is_woken_by_its_release() {
        let table = FutexTable::new();
        let parked = table.prepare_wait(key(1, 0x1000));
        let mut parked = core::pin::pin!(async move {
            let mut parked = parked;
            parked.released().await;
        });

        assert!(
            block_on(poll_once(parked.as_mut())).is_none(),
            "the wait parks"
        );
        assert_eq!(table.wake(key(1, 0x1000), 1), 1);
        assert!(
            block_on(poll_once(parked.as_mut())).is_some(),
            "the release completes the parked wait"
        );
    }

    /// A wake-all releases the waits that exist: a wait queued after it
    /// parks, or every futex wait that follows a wake on the same key
    /// returns without ever blocking.
    #[test]
    fn a_wait_that_follows_wake_all_still_parks() {
        let table = FutexTable::new();
        let mut earlier = table.prepare_wait(key(1, 0x1000));

        assert_eq!(table.wake_all(key(1, 0x1000)), 1);

        let mut later = table.prepare_wait(key(1, 0x1000));
        block_on(earlier.released());
        assert!(
            block_on(poll_once(later.released())).is_none(),
            "a futex wait queued after the wake has nothing to complete it"
        );
    }

    /// A wake that follows a wake-all before the released waiters have
    /// run finds nobody left to release: it reports no wake, and a later
    /// wait on the key, made while the released waiters still hold their
    /// registrations, parks.
    #[test]
    fn a_wake_after_wake_all_releases_nobody_and_a_later_wait_parks() {
        let table = FutexTable::new();
        let mut first = table.prepare_wait(key(1, 0x1000));
        let mut second = table.prepare_wait(key(1, 0x1000));

        assert_eq!(table.wake_all(key(1, 0x1000)), 2);
        assert_eq!(
            table.wake(key(1, 0x1000), 1),
            0,
            "both waiters were already released"
        );

        let mut later = table.prepare_wait(key(1, 0x1000));
        assert!(
            block_on(poll_once(later.released())).is_none(),
            "a wait made after the wakes parks"
        );

        block_on(first.released());
        block_on(second.released());
    }

    /// A wait whose future is dropped while parked leaves nothing behind:
    /// a wake finds nobody, and the table is empty once no wait is
    /// queued.
    #[test]
    fn a_wait_dropped_while_parked_dequeues_itself() {
        let table = FutexTable::new();
        let mut registration = table.prepare_wait(key(1, 0x1000));
        let mut cx = Context::from_waker(Waker::noop());
        assert!(
            registration.poll_released(&mut cx).is_pending(),
            "the wait parks"
        );
        assert_eq!(table.len(), 1);

        drop(registration);

        assert_eq!(table.len(), 0, "the entry leaves with its last wait");
        assert_eq!(table.wake(key(1, 0x1000), 1), 0, "nobody is parked");
        assert_eq!(table.wake_all(key(1, 0x1000)), 0, "nobody is parked");

        let mut next = table.prepare_wait(key(1, 0x1000));
        assert!(
            block_on(poll_once(next.released())).is_none(),
            "a new wait parks"
        );
        drop(next);
        assert_eq!(table.len(), 0);
    }

    /// A released wait is off its key's queue already, so dropping it
    /// touches nothing, while a wait still queued on the key stays.
    #[test]
    fn a_released_wait_drops_without_touching_its_key() {
        let table = FutexTable::new();
        let released = table.prepare_wait(key(1, 0x1000));
        assert_eq!(table.wake(key(1, 0x1000), 1), 1);
        let queued = table.prepare_wait(key(1, 0x1000));

        drop(released);

        assert_eq!(table.len(), 1);
        assert_eq!(table.wake(key(1, 0x1000), 2), 1);
        assert!(queued.is_released());
        drop(queued);
        assert_eq!(table.len(), 0);
    }

    /// Only the dropped wait is dequeued: the entry stays while another
    /// wait on the key is queued.
    #[test]
    fn a_dropped_wait_leaves_the_other_waits_on_its_key_queued() {
        let table = FutexTable::new();
        let kept = table.prepare_wait(key(1, 0x1000));
        let dropped = table.prepare_wait(key(1, 0x1000));

        drop(dropped);

        assert_eq!(table.len(), 1);
        assert_eq!(table.wake(key(1, 0x1000), 2), 1);
        drop(kept);
        assert_eq!(table.len(), 0);
    }
}
