//! Typed hand-off slot for an interface the kernel forwards to a plugin.
//!
//! Some capabilities the kernel exposes to guests are not implemented by the
//! kernel at all: it validates the request, turns it into a transport-neutral
//! message, and hands it to a user-mode component that owns the protocol. The
//! HTTP client is the first such capability; a key-value store, a
//! configuration source, and TLS termination all fit the same shape.
//!
//! A [`ProviderSlot`] is the meeting point. The supervisor that owns the
//! plugin installs the sending half of a bounded queue exactly once during
//! startup; every host call afterwards sends a message through it and awaits
//! the reply on a channel the message itself carried along. Because the slot
//! is written once and read many times, a send costs one atomic load rather
//! than a lock, and a missing provider is a typed error rather than a panic —
//! a kernel image built without the plugin must still answer the WIT call.
//!
//! # Concurrency contract
//!
//! [`ProviderSlot::install`] is racy-safe single-writer: the first caller wins
//! and every later caller gets [`ProviderAlreadyInstalled`]. Installing twice
//! is a wiring bug, so callers treat that error as fatal.
//! [`ProviderSlot::send`] is lock-free apart from the queue's own
//! backpressure and may be called concurrently from any processor; producers
//! park on a [`Notify`] rather than spinning, and the single consumer parks the
//! same way when the queue is empty. Both notifications are broadcasts that
//! store nothing, and every waiter arms its wait before it tests the queue:
//! the queue is the state, a wake only says it may have moved, so no wake
//! outlives the queue state it was raised for.
//!
//! `futures::channel::mpsc` is deliberately not used here: it lives behind
//! `futures-channel`'s `std` feature, which a `#![no_std]` kernel cannot
//! enable. The queue below is the same `concurrent-queue` + `Notify` pairing
//! the kernel's byte channels already use, made generic over the message
//! type.

extern crate alloc;

use core::future::Future;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};

use concurrent_queue::{ConcurrentQueue, PopError, PushError};
use crossbeam_utils::CachePadded;
use helios_hal::cpu::{ProcessorId, current_processor};
use spin::Once;
use thiserror::Error;
use triomphe::Arc;

use crate::Notify;
use crate::memory::{PerProcessor, UserMemoryPool};

/// A provider was installed into a slot that already had one.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[error("a provider is already installed in this slot")]
pub struct ProviderAlreadyInstalled;

/// Why a message could not be handed to the provider.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum ProviderError {
    /// No provider was ever installed — the plugin is not provisioned in this
    /// kernel image.
    #[error("no provider installed")]
    Unavailable,
    /// The provider was installed but has since stopped receiving.
    #[error("provider stopped")]
    Closed,
    /// The provider's queue is full and the caller could not wait.
    #[error("provider queue is full")]
    Full,
}

/// Shared state of one provider queue.
struct ProviderChannel<M> {
    queue: ConcurrentQueue<M>,
    /// Broadcast after every push and on close, for the single consumer,
    /// which arms before it pops.
    ready: Notify,
    /// Broadcast after every pop and on close, for however many producers
    /// are parked; each arms before it pushes or tests for room.
    room: Notify,
}

/// Sending half of a provider queue. Cloneable and callable from any
/// processor.
pub struct ProviderSender<M> {
    channel: Arc<ProviderChannel<M>>,
}

impl<M> Clone for ProviderSender<M> {
    fn clone(&self) -> Self {
        Self {
            channel: self.channel.clone(),
        }
    }
}

/// Receiving half of a provider queue, owned by the plugin supervisor.
///
/// Dropping it closes the queue so every parked and future producer observes
/// [`ProviderError::Closed`] instead of waiting for a consumer that is gone.
pub struct ProviderReceiver<M> {
    channel: Arc<ProviderChannel<M>>,
}

/// Create a bounded provider queue holding at most `capacity` messages.
///
/// # Panics
///
/// Panics when `capacity` is zero: a queue that can never hold a message would
/// deadlock every producer.
pub fn provider_channel<M>(capacity: usize) -> (ProviderSender<M>, ProviderReceiver<M>) {
    assert!(capacity > 0, "provider queue capacity must be non-zero");
    let channel = Arc::new(ProviderChannel {
        queue: ConcurrentQueue::bounded(capacity),
        ready: Notify::new(),
        room: Notify::new(),
    });
    (
        ProviderSender {
            channel: channel.clone(),
        },
        ProviderReceiver { channel },
    )
}

impl<M> ProviderSender<M> {
    /// Queue `message`, parking while the queue is full.
    pub async fn send(&self, message: M) -> Result<(), ProviderError> {
        let mut message = message;
        loop {
            // Armed before the push: `room` is a broadcast and banks
            // nothing, so a pop or a close between a full push and the
            // park would otherwise leave this sender asleep beside a free
            // slot or a closed queue.
            let room = self.channel.room.notified();
            match self.channel.queue.push(message) {
                Ok(()) => {
                    self.channel.ready.notify_all();
                    return Ok(());
                }
                Err(PushError::Full(returned)) => {
                    message = returned;
                    room.await;
                }
                Err(PushError::Closed(_)) => return Err(ProviderError::Closed),
            }
        }
    }
}

impl<M> ProviderSender<M> {
    /// Queue `message` if there is room, and report rather than park
    /// when there is not.
    ///
    /// For the callers that cannot await: a `Drop` telling a plugin that
    /// something it was serving is gone. A message that does not fit is
    /// a plugin that is already behind, and the caller says what losing
    /// it costs at its own call site.
    pub fn try_send(&self, message: M) -> Result<(), ProviderError> {
        match self.channel.queue.push(message) {
            Ok(()) => {
                self.channel.ready.notify_all();
                Ok(())
            }
            Err(PushError::Full(_)) => Err(ProviderError::Full),
            Err(PushError::Closed(_)) => Err(ProviderError::Closed),
        }
    }
}

impl<M> ProviderSender<M> {
    /// Wait until the queue has room for one message, or has closed.
    ///
    /// For a producer that has to decide what it sends in the same step
    /// that sends it — a check against state the send itself changes —
    /// and so sends with [`Self::try_send`] and parks here on
    /// [`ProviderError::Full`] rather than parking inside a send with
    /// the decision already made. Every pop releases every producer
    /// parked here to test the queue again, so a producer woken here
    /// that then sends nothing leaves no other producer asleep.
    pub async fn room(&self) {
        loop {
            // Armed before the queue is tested, for the reason `send`
            // arms before its push.
            let room = self.channel.room.notified();
            if !self.channel.queue.is_full() || self.channel.queue.is_closed() {
                return;
            }
            room.await;
        }
    }
}

impl<M> ProviderSender<M> {
    /// Close the queue after its owner's last client goes away. Queued work
    /// remains available to the receiver; blocked producers observe closure.
    pub fn close(&self) {
        self.channel.queue.close();
        self.channel.ready.notify_all();
        self.channel.room.notify_all();
    }
}

impl<M> ProviderReceiver<M> {
    /// Take queued work without parking, for a service's bounded batch.
    pub fn try_recv(&self) -> Result<M, ProviderError> {
        match self.channel.queue.pop() {
            Ok(message) => {
                self.channel.room.notify_all();
                Ok(message)
            }
            Err(PopError::Empty) => Err(ProviderError::Unavailable),
            Err(PopError::Closed) => Err(ProviderError::Closed),
        }
    }
    /// Await the next message, or `None` once the queue is closed and drained.
    pub async fn recv(&self) -> Option<M> {
        loop {
            // Armed before the pop: `ready` is a broadcast and banks
            // nothing, so a push between an empty pop and the park is
            // only observed by a wait that already exists.
            let ready = self.channel.ready.notified();
            match self.channel.queue.pop() {
                Ok(message) => {
                    self.channel.room.notify_all();
                    return Some(message);
                }
                Err(PopError::Empty) => ready.await,
                Err(PopError::Closed) => return None,
            }
        }
    }
}

impl<M> Drop for ProviderReceiver<M> {
    fn drop(&mut self) {
        self.channel.queue.close();
        self.channel.room.notify_all();
    }
}

/// Write-once slot holding the sending half of a provider's work queue.
pub struct ProviderSlot<M> {
    installed: AtomicBool,
    sender: Once<ProviderSender<M>>,
}

impl<M> ProviderSlot<M> {
    /// An empty slot. Every `send` reports [`ProviderError::Unavailable`]
    /// until a provider is installed.
    pub const fn new() -> Self {
        Self {
            installed: AtomicBool::new(false),
            sender: Once::new(),
        }
    }

    /// Whether a provider has been installed.
    pub fn is_installed(&self) -> bool {
        self.sender.get().is_some()
    }

    /// Claim the slot for `sender`.
    ///
    /// Returns [`ProviderAlreadyInstalled`] when the slot is already taken;
    /// two supervisors for one interface is a wiring bug the caller should
    /// treat as fatal.
    pub fn install(&self, sender: ProviderSender<M>) -> Result<(), ProviderAlreadyInstalled> {
        if self.installed.swap(true, Ordering::AcqRel) {
            return Err(ProviderAlreadyInstalled);
        }
        self.sender.call_once(|| sender);
        Ok(())
    }

    /// Hand `message` to the provider, waiting for room in its queue.
    ///
    /// Resolves as soon as the message is queued; the reply travels on
    /// whatever channel the message itself carries. An uninstalled slot fails
    /// immediately rather than parking forever.
    pub fn send(&self, message: M) -> impl Future<Output = Result<(), ProviderError>> + Send + '_
    where
        M: Send,
    {
        let sender = self.sender.get();
        async move {
            let sender = sender.ok_or(ProviderError::Unavailable)?;
            sender.send(message).await
        }
    }

    /// Hand `message` to the provider without waiting for room.
    ///
    /// For the callers that cannot await, which is every `Drop`.
    pub fn try_send(&self, message: M) -> Result<(), ProviderError> {
        self.sender
            .get()
            .ok_or(ProviderError::Unavailable)?
            .try_send(message)
    }
}

impl<M> Default for ProviderSlot<M> {
    fn default() -> Self {
        Self::new()
    }
}

/// Shard state marker indicating the processor serves its own queue directly.
const SHARD_ACTIVE: u32 = u32::MAX;

/// Encodes a redirected target [`ProcessorId`] in a shard's atomic `state`.
fn shard_redirected(target: ProcessorId) -> u32 {
    u32::from(target.id())
}

/// Decodes a shard's atomic `state`, returning `Some(target)` when redirected.
fn decode_redirect(state: u32) -> Option<ProcessorId> {
    if state == SHARD_ACTIVE {
        None
    } else {
        Some(ProcessorId::new(u16::try_from(state).unwrap_or_else(
            |_| panic!("invalid shard redirect state {state}"),
        )))
    }
}

/// Per-processor bounded shard owned on one core's cache line and NUMA node.
///
/// # Concurrency contract
///
/// - `queue`, `ready`, and `room` are lock-free MPSC/MPMC structures matching
///   [`ProviderChannel`]. On the common path a caller pushes onto
///   `shards.get(current_processor())` and the shard's own supervisor pops
///   from the same processor, keeping queue/state writes on the local core's
///   cache line.
/// - `state` (`SHARD_ACTIVE` or redirected successor id) is updated with
///   `SeqCst` during processor online/offline transitions and paired in a
///   Dekker handshake with `pushers`: a producer increments `pushers`
///   (`SeqCst`) before inspecting `state` and keeps it elevated only across
///   the non-blocking `ConcurrentQueue::push`, never across `.await`. After
///   storing a redirect (`SeqCst`), [`PerProcessorProvider::redirect_shard`]
///   spins only for those active non-blocking pushes to finish (`pushers == 0`)
///   and then drains all remaining messages into an active successor shard.
struct ProviderShard<M> {
    queue: ConcurrentQueue<M>,
    ready: Notify,
    room: Notify,
    state: AtomicU32,
    pushers: AtomicUsize,
}

impl<M> ProviderShard<M> {
    fn new(capacity: usize) -> Self {
        Self {
            queue: ConcurrentQueue::bounded(capacity),
            ready: Notify::new(),
            room: Notify::new(),
            state: AtomicU32::new(SHARD_ACTIVE),
            pushers: AtomicUsize::new(0),
        }
    }

    fn redirect_target(&self, ordering: Ordering) -> Option<ProcessorId> {
        decode_redirect(self.state.load(ordering))
    }
}

/// Drops `pushers` automatically once the non-blocking push attempt ends.
struct PusherGuard<'a, M> {
    shard: &'a ProviderShard<M>,
}

impl<M> Drop for PusherGuard<'_, M> {
    fn drop(&mut self) {
        self.shard.pushers.fetch_sub(1, Ordering::Release);
    }
}

/// Write-once container of NUMA-local, cache-line-padded provider shards, one
/// per possible processor.
///
/// Used by sharded kernel plugins whose instances run per-processor alongside
/// each processor's network pump so callers submit work without cross-core
/// queue traffic, while processor hot-unplug atomically redirects and drains
/// work to a live successor core.
pub struct PerProcessorProvider<M> {
    installed: AtomicBool,
    shards: Once<PerProcessor<CachePadded<ProviderShard<M>>>>,
}

impl<M> PerProcessorProvider<M> {
    /// An empty sharded provider. Every `send` reports
    /// [`ProviderError::Unavailable`] until [`Self::install`] claims it.
    pub const fn new() -> Self {
        Self {
            installed: AtomicBool::new(false),
            shards: Once::new(),
        }
    }

    /// Whether shards have been provisioned.
    pub fn is_installed(&self) -> bool {
        self.shards.get().is_some()
    }

    /// Allocate one cache-padded shard per processor on `pool`'s NUMA nodes.
    ///
    /// Returns [`ProviderAlreadyInstalled`] if called more than once.
    ///
    /// # Panics
    ///
    /// Panics when `capacity` is zero.
    pub fn install(
        &self,
        pool: &UserMemoryPool,
        capacity: usize,
    ) -> Result<(), ProviderAlreadyInstalled> {
        assert!(capacity > 0, "provider queue capacity must be non-zero");
        if self.installed.swap(true, Ordering::AcqRel) {
            return Err(ProviderAlreadyInstalled);
        }
        self.shards.call_once(|| {
            PerProcessor::new(pool, |_, _| CachePadded::new(ProviderShard::new(capacity)))
        });
        Ok(())
    }

    /// Walks redirect links from `start` up to `shards.len()` hops to find an
    /// active destination shard.
    fn resolve_target(
        shards: &PerProcessor<CachePadded<ProviderShard<M>>>,
        start: ProcessorId,
    ) -> ProcessorId {
        let mut current = start;
        for _ in 0..shards.len() {
            match shards.get(current).redirect_target(Ordering::Acquire) {
                Some(next) => current = next,
                None => return current,
            }
        }
        current
    }

    /// Hand `message` to the active shard serving `current_processor()`,
    /// waiting for queue room if full.
    pub fn send(&self, message: M) -> impl Future<Output = Result<(), ProviderError>> + Send + '_
    where
        M: Send,
    {
        let mut message = message;
        let shards = self.shards.get();
        async move {
            let shards = shards.ok_or(ProviderError::Unavailable)?;
            loop {
                let target = Self::resolve_target(shards, current_processor());
                let shard = &**shards.get(target);
                let room = shard.room.notified();
                shard.pushers.fetch_add(1, Ordering::SeqCst);
                let guard = PusherGuard { shard };
                if shard.redirect_target(Ordering::SeqCst).is_some() {
                    drop(guard);
                    continue;
                }
                let pushed = shard.queue.push(message);
                drop(guard);
                match pushed {
                    Ok(()) => {
                        shard.ready.notify_all();
                        return Ok(());
                    }
                    Err(PushError::Full(returned)) => {
                        message = returned;
                        room.await;
                    }
                    Err(PushError::Closed(_)) => return Err(ProviderError::Closed),
                }
            }
        }
    }

    /// Queue `message` on the active shard serving `current_processor()`
    /// without waiting for room.
    pub fn try_send(&self, message: M) -> Result<(), ProviderError> {
        let shards = self.shards.get().ok_or(ProviderError::Unavailable)?;
        let mut message = message;
        for _ in 0..=shards.len() {
            let target = Self::resolve_target(shards, current_processor());
            let shard = &**shards.get(target);
            shard.pushers.fetch_add(1, Ordering::SeqCst);
            let guard = PusherGuard { shard };
            if shard.redirect_target(Ordering::SeqCst).is_some() {
                drop(guard);
                continue;
            }
            let pushed = shard.queue.push(message);
            drop(guard);
            return match pushed {
                Ok(()) => {
                    shard.ready.notify_all();
                    Ok(())
                }
                Err(PushError::Full(returned)) => {
                    message = returned;
                    let _ = message;
                    Err(ProviderError::Full)
                }
                Err(PushError::Closed(_)) => Err(ProviderError::Closed),
            };
        }
        Err(ProviderError::Unavailable)
    }

    /// Await the next queued message on `processor`'s shard.
    pub async fn recv_on(&self, processor: ProcessorId) -> Option<M> {
        let shards = self.shards.get()?;
        let shard = &**shards.get(processor);
        loop {
            let ready = shard.ready.notified();
            match shard.queue.pop() {
                Ok(message) => {
                    shard.room.notify_all();
                    return Some(message);
                }
                Err(PopError::Empty) => ready.await,
                Err(PopError::Closed) => return None,
            }
        }
    }

    /// Take the next queued message on `processor`'s shard without waiting.
    pub fn try_recv_on(&self, processor: ProcessorId) -> Result<M, ProviderError> {
        let shards = self.shards.get().ok_or(ProviderError::Unavailable)?;
        let shard = &**shards.get(processor);
        match shard.queue.pop() {
            Ok(message) => {
                shard.room.notify_all();
                Ok(message)
            }
            Err(PopError::Empty) => Err(ProviderError::Unavailable),
            Err(PopError::Closed) => Err(ProviderError::Closed),
        }
    }

    /// Mark `processor`'s shard active again when that processor comes online.
    pub fn activate_shard(&self, processor: ProcessorId) {
        let Some(shards) = self.shards.get() else {
            return;
        };
        let shard = &**shards.get(processor);
        shard.state.store(SHARD_ACTIVE, Ordering::SeqCst);
    }

    /// Atomically mark `processor`'s shard redirected to `successor`, drain all
    /// already-queued items into the active successor shard (dropping any item
    /// if the destination is full), and wake any parked producers.
    ///
    /// Returns the number of queued messages forwarded.
    pub fn redirect_shard(&self, processor: ProcessorId, successor: ProcessorId) -> usize {
        let Some(shards) = self.shards.get() else {
            return 0;
        };
        let departing = &**shards.get(processor);
        departing
            .state
            .store(shard_redirected(successor), Ordering::SeqCst);
        while departing.pushers.load(Ordering::SeqCst) != 0 {
            core::hint::spin_loop();
        }
        let mut forwarded = 0;
        while let Ok(message) = departing.queue.pop() {
            for _ in 0..=shards.len() {
                let target = Self::resolve_target(shards, successor);
                if target == processor {
                    break;
                }
                let dest = &**shards.get(target);
                dest.pushers.fetch_add(1, Ordering::SeqCst);
                let guard = PusherGuard { shard: dest };
                if dest.redirect_target(Ordering::SeqCst).is_some() {
                    drop(guard);
                    continue;
                }
                let pushed = dest.queue.push(message);
                drop(guard);
                match pushed {
                    Ok(()) => {
                        dest.ready.notify_all();
                        forwarded += 1;
                    }
                    Err(PushError::Full(returned)) | Err(PushError::Closed(returned)) => {
                        drop(returned);
                    }
                }
                break;
            }
        }
        departing.room.notify_all();
        forwarded
    }

    /// How many processor shards exist once installed.
    pub fn shard_count(&self) -> Option<usize> {
        self.shards.get().map(PerProcessor::len)
    }
}

impl<M> Default for PerProcessorProvider<M> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_lite::future::block_on;

    #[test]
    fn an_empty_slot_reports_unavailable_without_parking() {
        let slot = ProviderSlot::<u32>::new();
        assert!(!slot.is_installed());
        assert_eq!(block_on(slot.send(7)), Err(ProviderError::Unavailable));
    }

    #[test]
    fn an_installed_slot_delivers_messages_in_order() {
        let slot = ProviderSlot::<u32>::new();
        let (sender, receiver) = provider_channel(4);
        slot.install(sender).expect("first install must win");
        assert!(slot.is_installed());

        block_on(async {
            slot.send(1).await.expect("send must reach the provider");
            slot.send(2).await.expect("send must reach the provider");
            assert_eq!(receiver.recv().await, Some(1));
            assert_eq!(receiver.recv().await, Some(2));
        });
    }

    #[test]
    fn installing_twice_is_reported_as_a_wiring_bug() {
        let slot = ProviderSlot::<u32>::new();
        let (first, _first_rx) = provider_channel(1);
        let (second, _second_rx) = provider_channel(1);
        assert_eq!(slot.install(first), Ok(()));
        assert_eq!(slot.install(second), Err(ProviderAlreadyInstalled));
    }

    #[test]
    fn a_dropped_receiver_reports_the_provider_as_closed() {
        let slot = ProviderSlot::<u32>::new();
        let (sender, receiver) = provider_channel(1);
        slot.install(sender).expect("first install must win");
        drop(receiver);
        assert_eq!(block_on(slot.send(1)), Err(ProviderError::Closed));
    }

    #[test]
    fn a_full_queue_parks_the_producer_until_the_consumer_drains_it() {
        let (sender, receiver) = provider_channel::<u32>(1);
        block_on(async {
            sender.send(1).await.expect("first message fits");
            // The queue is full now: this send only completes because the
            // consumer, driven by the same single-threaded executor, frees a
            // slot and broadcasts `room` to the armed producer.
            let produce = async {
                sender.send(2).await.expect("second message must fit later");
                sender.send(3).await.expect("third message must fit later");
            };
            let consume = async {
                assert_eq!(receiver.recv().await, Some(1));
                assert_eq!(receiver.recv().await, Some(2));
                assert_eq!(receiver.recv().await, Some(3));
            };
            futures::future::join(produce, consume).await;
        });
    }

    /// Polls a fresh wait on `notify` once, reporting whether it completed.
    fn completes_at_once(notify: &Notify) -> bool {
        let mut context = core::task::Context::from_waker(core::task::Waker::noop());
        core::pin::pin!(notify.notified())
            .as_mut()
            .poll(&mut context)
            .is_ready()
    }

    /// A burst the consumer takes without ever parking leaves no wake
    /// behind on either signal: a wait made once the queue is empty, or
    /// once it is full again, parks instead of completing on a wake that
    /// described a queue state long gone.
    #[test]
    fn a_burst_taken_without_parking_leaves_no_wake_behind() {
        let (sender, receiver) = provider_channel::<u32>(2);
        for message in 0..2 {
            sender.try_send(message).expect("the burst fits");
        }
        assert_eq!(receiver.try_recv(), Ok(0));
        assert_eq!(block_on(receiver.recv()), Some(1));

        assert!(
            !completes_at_once(&receiver.channel.ready),
            "an empty queue has nothing for the consumer"
        );

        for message in 2..4 {
            sender.try_send(message).expect("the queue has room again");
        }
        assert!(
            !completes_at_once(&sender.channel.room),
            "a full queue has no room for a producer"
        );
    }

    #[test]
    fn queued_messages_survive_the_last_sender() {
        let (sender, receiver) = provider_channel::<u32>(2);
        block_on(async {
            sender.send(1).await.expect("message fits");
            drop(sender);
            // Only the receiver closes the queue: a slot keeps its sender for
            // the kernel's lifetime, so the supervisor parks on an idle queue
            // rather than treating "no senders" as shutdown.
            assert_eq!(receiver.recv().await, Some(1));
        });
    }

    fn test_three_core_pool() -> &'static UserMemoryPool {
        crate::test_support::TestMachine {
            processor_nodes: alloc::vec![0, 0, 0],
            distances: alloc::vec![10],
        }
        .pool(crate::test_support::TEST_POOL_NODE_BYTES)
    }

    #[test]
    fn per_processor_provider_routes_locally_without_cross_core_traffic() {
        let provider = PerProcessorProvider::<u32>::new();
        assert!(!provider.is_installed());
        assert_eq!(block_on(provider.send(1)), Err(ProviderError::Unavailable));

        let pool = test_three_core_pool();
        provider.install(pool, 4).expect("first install succeeds");
        assert_eq!(
            provider.install(pool, 4),
            Err(ProviderAlreadyInstalled),
            "installing twice must be caught"
        );
        assert_eq!(provider.shard_count(), Some(3));

        crate::test_processor_identity::set(ProcessorId::new(1));
        block_on(provider.send(101)).expect("core 1 send succeeds");
        crate::test_processor_identity::set(ProcessorId::new(2));
        block_on(provider.send(202)).expect("core 2 send succeeds");
        crate::test_processor_identity::set(ProcessorId::new(0));
        block_on(provider.send(100)).expect("core 0 send succeeds");

        assert_eq!(provider.try_recv_on(ProcessorId::new(0)), Ok(100));
        assert_eq!(provider.try_recv_on(ProcessorId::new(1)), Ok(101));
        assert_eq!(provider.try_recv_on(ProcessorId::new(2)), Ok(202));
        assert_eq!(
            provider.try_recv_on(ProcessorId::new(1)),
            Err(ProviderError::Unavailable)
        );
    }

    #[test]
    fn per_processor_provider_redirects_queued_work_and_reactivates_on_online() {
        let provider = PerProcessorProvider::<u32>::new();
        provider
            .install(test_three_core_pool(), 4)
            .expect("install succeeds");

        // Enqueue onto cores 1 and 2 before core 2 goes offline to 1 and then
        // core 1 goes offline to 0 (chained redirect).
        crate::test_processor_identity::set(ProcessorId::new(2));
        block_on(provider.send(21)).expect("core 2 enqueue");
        block_on(provider.send(22)).expect("core 2 second enqueue");

        assert_eq!(
            provider.redirect_shard(ProcessorId::new(2), ProcessorId::new(1)),
            2
        );
        assert_eq!(
            provider.try_recv_on(ProcessorId::new(2)),
            Err(ProviderError::Unavailable)
        );
        // Any subsequent call still observing core 2 lands on core 1.
        block_on(provider.send(23)).expect("redirected to core 1");

        // Core 1 now goes offline to core 0; all 3 items arrive on core 0.
        assert_eq!(
            provider.redirect_shard(ProcessorId::new(1), ProcessorId::new(0)),
            3
        );
        crate::test_processor_identity::set(ProcessorId::new(2));
        block_on(provider.send(24)).expect("chained redirect hits core 0");

        assert_eq!(provider.try_recv_on(ProcessorId::new(0)), Ok(21));
        assert_eq!(provider.try_recv_on(ProcessorId::new(0)), Ok(22));
        assert_eq!(provider.try_recv_on(ProcessorId::new(0)), Ok(23));
        assert_eq!(provider.try_recv_on(ProcessorId::new(0)), Ok(24));

        // Bringing core 2 back online restores local shard delivery.
        provider.activate_shard(ProcessorId::new(2));
        crate::test_processor_identity::set(ProcessorId::new(2));
        block_on(provider.send(25)).expect("reactivated shard 2 takes work again");
        assert_eq!(provider.try_recv_on(ProcessorId::new(2)), Ok(25));
    }
}
