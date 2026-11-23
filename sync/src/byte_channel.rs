//! Async byte-stream channels used to connect a spawned child component's
//! stdio streams to the parent that spawned it.
//!
//! Writers can be cloned freely, and EOF is delivered once *every* writer
//! has been dropped. Readers can be cloned too — a guest's threads share a
//! pipe's descriptor, and epoll waits on it beside them — and the reader
//! side closes once every reader has been dropped. Data and EOF wake every
//! parked reader, and room or a closed reader wakes every parked writer.
//!
//! Every operation is async — nothing here ever spins or blocks the
//! cooperative executor.
//!
//! # Flow control
//!
//! The queue holds at most [`BYTE_CHANNEL_CHUNK_CAPACITY`] chunks. That
//! bound is *flow control*, not an assertion: a guest that prints faster
//! than its reader drains must be made to wait, never to kill the kernel.
//! [`ByteWriter::try_write`] reports [`TryWrite::Full`] and hands the
//! chunk back to the caller; [`ByteWriter::write`] parks the calling task
//! on the `writable` signal until room appears. No byte is ever dropped
//! on a full channel and a transiently full channel is never reported as
//! an error.
//!
//! A parked writer is resumed as soon as a pop frees a slot — the resume
//! threshold is "the queue is no longer full", identical to the predicate
//! the writer parked on. A lower watermark (say, half capacity) would
//! batch wakeups better, but it deadlocks peers that alternate: a reader
//! that consumes part of a burst and then waits for the writer's next
//! chunk would never let the writer past a half-full queue. POSIX pipes
//! wake writers on any read progress for the same reason, and wakeups are
//! already coalesced here — a broadcast drains the waker set, and a pop
//! only signals when the queue was full, so one park costs exactly one
//! wakeup.
//!
//! # Concurrency contract (SMP)
//!
//! - `ByteChunks` is the only mutable queue state and lives behind a
//!   `spin::Mutex`. It is held for the duration of a push/pop/clear and
//!   never across a wake or an `.await`.
//! - The close flags (`reader_closed`, `writer_closed`) and the handle
//!   counters are plain atomics. Close is published with `Release` and
//!   observed with `Acquire`, so a writer that sees "open" and then
//!   pushes under the queue lock cannot race a `close_reader` that
//!   already drained the queue: `close_reader` sets the flag *while
//!   holding* the queue lock.
//! - Each direction has its own [`ByteSignal`]. A signal is a broadcast:
//!   a generation counter plus a waker set guarded by its own
//!   `spin::Mutex`. It stores no permit, so no wake outlives the queue
//!   state it was raised for and no waiter can take a wake another
//!   waiter needed. The two signals are independent, so a drain on one
//!   CPU and a write on another never contend on the same lock.
//! - A waiter arms before it tests: its [`SignalWait`] samples the
//!   generation when it is created and again each time it completes, and
//!   only then is the queue or a close flag read. A broadcast raised
//!   after that sample completes the wait, whenever the waiter parks.
//! - Wakeup safety (no lost wakeups) rests on a Dekker-style handshake
//!   between [`ByteSignal::poll_notified`] and the notifiers. A waiter
//!   compares the generation with its sample, registers its waker, then
//!   compares *again* before reporting `Pending`. A notifier advances the
//!   generation first and only then looks at the waiter count. Both the
//!   generation and the waiter count are stored and loaded `SeqCst` so
//!   that the store-then-load pairs on the two sides cannot be
//!   reordered: if the notifier's count load misses a registration, its
//!   generation store is ordered before the waiter's second load, and
//!   the waiter returns `Ready` instead of parking.

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use core::task::{Context, Poll, Waker};

use bytes::Bytes;
use heapless::{Deque, Vec as HeapVec};
use spin::Mutex;
use triomphe::Arc;

const BYTE_CHANNEL_CHUNK_CAPACITY: usize = 256;
// Keep process/stdio/socketpair setup cheap while preserving the common
// 64-chunk burst shape: 16 chunks stay in the channel allocation and the first
// overflow reserve covers the remaining 48 chunks. Local divan keeps the
// 64-chunk case at 2.304 KiB while create/drop and 16-chunk transfers move to
// a 768 B channel allocation instead of the old inline-64 2.304 KiB slab.
const BYTE_CHANNEL_INLINE_CHUNKS: usize = 16;
const BYTE_CHANNEL_OVERFLOW_INITIAL_CHUNKS: usize = 48;
/// Waiters parked without touching the allocator. One reader and one
/// writer task per channel is the norm; guest threads sharing a pipe can
/// exceed it, and those spill into [`WakerSet::overflow`] rather than
/// panicking a kernel that a guest can drive.
const BYTE_CHANNEL_WAKER_CAPACITY: usize = 8;

/// A single byte-stream channel, closable from both ends. Producers push
/// reference-counted byte chunks; consumers await and receive the same chunks
/// back without forcing an extra copy at adapter boundaries.
struct ByteChannel {
    queue: ByteQueue,
    /// Wakes every parked consumer when new bytes or a close event are
    /// available.
    readable: ByteSignal,
    /// Notifies producers parked on a full queue that a slot was freed or
    /// that the channel closed under them.
    writable: ByteSignal,
    /// Set to `true` once every `ByteWriter` cloneable handle has been
    /// dropped, signalling EOF to the reader.
    writer_closed: AtomicBool,
    /// Set to `true` when the reader has gone away, so writers can stop
    /// producing bytes.
    reader_closed: AtomicBool,
    writer_handles: AtomicUsize,
    reader_handles: AtomicUsize,
}

impl ByteChannel {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            queue: ByteQueue::new(),
            readable: ByteSignal::new(),
            writable: ByteSignal::new(),
            writer_closed: AtomicBool::new(false),
            reader_closed: AtomicBool::new(false),
            writer_handles: AtomicUsize::new(1),
            reader_handles: AtomicUsize::new(1),
        })
    }

    fn push(&self, bytes: Bytes) -> Result<QueuePush, ClosedPeer> {
        self.queue
            .push_if_open(bytes, &self.reader_closed, &self.writer_closed)
    }

    /// Pop one chunk and release a writer parked on a full queue.
    ///
    /// The wakeup is only issued when the queue *was* full, which is the
    /// only state a writer can park in, so a steady drain of a channel
    /// nobody is blocked on costs one comparison.
    fn pop(&self) -> Option<Bytes> {
        let (bytes, was_full) = self.queue.pop();
        if was_full && bytes.is_some() {
            self.writable.notify_all();
        }
        bytes
    }

    fn close_reader(&self) {
        self.queue.close_reader(&self.reader_closed);
        self.readable.notify_all();
        self.writable.notify_all();
    }

    /// Publish that every writer is gone: EOF for every reader.
    fn close_writer(&self) {
        self.writer_closed.store(true, Ordering::Release);
        self.readable.notify_all();
        self.writable.notify_all();
    }

    fn is_closed(&self) -> bool {
        self.reader_closed.load(Ordering::Acquire) || self.writer_closed.load(Ordering::Acquire)
    }
}

struct ByteQueue {
    chunks: Mutex<ByteChunks>,
}

struct ByteChunks {
    inline: Deque<Bytes, BYTE_CHANNEL_INLINE_CHUNKS>,
    overflow: Option<VecDeque<Bytes>>,
    len: usize,
}

/// Outcome of a push against the bounded queue.
enum QueuePush {
    Pushed,
    /// The queue is at capacity; the chunk is handed back untouched.
    Full(Bytes),
}

impl ByteQueue {
    const fn new() -> Self {
        Self {
            chunks: Mutex::new(ByteChunks::new()),
        }
    }

    fn push_if_open(
        &self,
        bytes: Bytes,
        reader_closed: &AtomicBool,
        writer_closed: &AtomicBool,
    ) -> Result<QueuePush, ClosedPeer> {
        let mut chunks = self.chunks.lock();
        if reader_closed.load(Ordering::Acquire) || writer_closed.load(Ordering::Acquire) {
            return Err(ClosedPeer);
        }
        Ok(chunks.push(bytes))
    }

    /// Pops one chunk, reporting whether the queue was full beforehand.
    fn pop(&self) -> (Option<Bytes>, bool) {
        let mut chunks = self.chunks.lock();
        let was_full = chunks.is_full();
        (chunks.pop(), was_full)
    }

    fn pop_limit(&self, limit: usize) -> (Option<Bytes>, bool) {
        let mut chunks = self.chunks.lock();
        let was_full = chunks.is_full();
        let front = if !chunks.inline.is_empty() {
            chunks.inline.front_mut()
        } else {
            chunks.overflow.as_mut().and_then(VecDeque::front_mut)
        };
        if let Some(front) = front
            && front.len() > limit
        {
            return (Some(front.split_to(limit)), false);
        }
        (chunks.pop(), was_full)
    }

    fn is_empty(&self) -> bool {
        self.chunks.lock().is_empty()
    }

    fn is_full(&self) -> bool {
        self.chunks.lock().is_full()
    }

    fn close_reader(&self, reader_closed: &AtomicBool) {
        let mut chunks = self.chunks.lock();
        reader_closed.store(true, Ordering::Release);
        chunks.clear();
    }

    #[cfg(test)]
    const fn capacity(&self) -> usize {
        BYTE_CHANNEL_CHUNK_CAPACITY
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.chunks.lock().len
    }
}

impl ByteChunks {
    const fn new() -> Self {
        Self {
            inline: Deque::new(),
            overflow: None,
            len: 0,
        }
    }

    fn push(&mut self, bytes: Bytes) -> QueuePush {
        if self.is_full() {
            return QueuePush::Full(bytes);
        }
        if let Some(overflow) = self.overflow.as_mut() {
            overflow.push_back(bytes);
            self.len += 1;
            debug_assert!(self.len <= BYTE_CHANNEL_CHUNK_CAPACITY);
            return QueuePush::Pushed;
        }

        match self.inline.push_back(bytes) {
            Ok(()) => {
                self.len += 1;
            }
            Err(bytes) => {
                let mut overflow = VecDeque::with_capacity(BYTE_CHANNEL_OVERFLOW_INITIAL_CHUNKS);
                overflow.push_back(bytes);
                self.overflow = Some(overflow);
                self.len += 1;
            }
        }
        debug_assert!(self.len <= BYTE_CHANNEL_CHUNK_CAPACITY);
        QueuePush::Pushed
    }

    fn pop(&mut self) -> Option<Bytes> {
        if let Some(bytes) = self.inline.pop_front() {
            self.len -= 1;
            return Some(bytes);
        }
        let overflow = self.overflow.as_mut()?;
        let bytes = overflow.pop_front();
        if bytes.is_some() {
            self.len -= 1;
        }
        if overflow.is_empty() {
            self.overflow = None;
        }
        bytes
    }

    fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn is_full(&self) -> bool {
        self.len >= BYTE_CHANNEL_CHUNK_CAPACITY
    }

    fn clear(&mut self) {
        self.inline.clear();
        self.overflow = None;
        self.len = 0;
    }
}

/// Parked wakers for one direction of one channel.
///
/// The inline capacity covers the ordinary one-task-per-direction case
/// without allocating. It spills instead of panicking because the number
/// of parked tasks is guest-driven: a guest's threads can all block writing
/// to the same pipe.
struct WakerSet {
    inline: HeapVec<Waker, BYTE_CHANNEL_WAKER_CAPACITY>,
    overflow: Option<Vec<Waker>>,
    len: usize,
}

impl WakerSet {
    const fn new() -> Self {
        Self {
            inline: HeapVec::new(),
            overflow: None,
            len: 0,
        }
    }

    fn push(&mut self, waker: Waker) {
        if let Some(overflow) = self.overflow.as_mut() {
            overflow.push(waker);
            self.len += 1;
            return;
        }
        match self.inline.push(waker) {
            Ok(()) => self.len += 1,
            Err(waker) => {
                self.overflow = Some(alloc::vec![waker]);
                self.len += 1;
            }
        }
    }

    fn pop(&mut self) -> Option<Waker> {
        if let Some(overflow) = self.overflow.as_mut() {
            let waker = overflow.pop();
            let drained = overflow.is_empty();
            if drained {
                self.overflow = None;
            }
            if waker.is_some() {
                self.len -= 1;
                return waker;
            }
        }
        let waker = self.inline.pop();
        if waker.is_some() {
            self.len -= 1;
        }
        waker
    }

    /// Replace a previously registered waker in place, keeping the set
    /// free of duplicates for a repeatedly polled future.
    fn replace(&mut self, registered: &Waker, waker: Waker) -> bool {
        if let Some(overflow) = self.overflow.as_mut()
            && let Some(stored) = overflow
                .iter_mut()
                .find(|stored| stored.will_wake(registered))
        {
            *stored = waker;
            return true;
        }
        if let Some(stored) = self
            .inline
            .iter_mut()
            .find(|stored| stored.will_wake(registered))
        {
            *stored = waker;
            return true;
        }
        false
    }

    fn remove(&mut self, waker: &Waker) {
        if let Some(overflow) = self.overflow.as_mut()
            && let Some(index) = overflow.iter().position(|stored| stored.will_wake(waker))
        {
            overflow.swap_remove(index);
            let drained = overflow.is_empty();
            if drained {
                self.overflow = None;
            }
            self.len -= 1;
            return;
        }
        if let Some(index) = self
            .inline
            .iter()
            .position(|stored| stored.will_wake(waker))
        {
            self.inline.swap_remove(index);
            self.len -= 1;
        }
    }
}

/// Broadcast wake-up for one direction of one channel.
///
/// Every waiter re-reads the queue and the close flags for itself, so a
/// signal only says "the state may have moved": it releases every wait
/// armed before it and stores nothing for a wait armed after it.
struct ByteSignal {
    /// Advanced once per [`Self::notify_all`]. A wait completes when the
    /// generation moves past the value it was armed at.
    generation: AtomicU64,
    /// Number of wakers currently parked in `wakers`. Mutated only under
    /// the `wakers` lock, read without it on the notify fast path.
    waiters: AtomicUsize,
    wakers: Mutex<WakerSet>,
}

impl ByteSignal {
    const fn new() -> Self {
        Self {
            generation: AtomicU64::new(0),
            waiters: AtomicUsize::new(0),
            wakers: Mutex::new(WakerSet::new()),
        }
    }

    /// Samples the generation a new wait is armed at.
    fn arm(&self) -> u64 {
        self.generation.load(Ordering::SeqCst)
    }

    /// Release every wait armed before this call and wake every parked
    /// waiter, each of which re-evaluates the channel for itself.
    fn notify_all(&self) {
        if !self.advance() {
            return;
        }
        while let Some(waker) = self.take_waker() {
            waker.wake();
        }
    }

    /// Advance the generation and report whether anyone is parked.
    ///
    /// The `SeqCst` pair is load-bearing: see the module's wakeup-safety
    /// note. A `Release` store followed by an `Acquire` load may be
    /// reordered, and that reordering is exactly a lost wakeup.
    fn advance(&self) -> bool {
        self.generation.fetch_add(1, Ordering::SeqCst);
        self.waiters.load(Ordering::SeqCst) != 0
    }

    fn take_waker(&self) -> Option<Waker> {
        let mut wakers = self.wakers.lock();
        let waker = wakers.pop();
        self.waiters.store(wakers.len, Ordering::SeqCst);
        waker
    }

    fn poll_notified(&self, cx: &mut Context<'_>, wait: &mut SignalWait) -> Poll<()> {
        if self.complete_if_advanced(wait) {
            return Poll::Ready(());
        }
        self.register_waker(wait, cx.waker());
        if self.complete_if_advanced(wait) {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }

    /// Completes `wait` when a broadcast has landed since it was armed,
    /// re-arming it at the current generation so the caller's next test
    /// of the channel is covered by the next broadcast.
    fn complete_if_advanced(&self, wait: &mut SignalWait) -> bool {
        let generation = self.generation.load(Ordering::SeqCst);
        if generation == wait.observed {
            return false;
        }
        wait.observed = generation;
        self.remove_registered_waker(wait);
        true
    }

    fn register_waker(&self, wait: &mut SignalWait, waker: &Waker) {
        let new_waker = waker.clone();
        let mut wakers = self.wakers.lock();
        if let Some(registered) = wait.registered.as_ref()
            && wakers.replace(registered, new_waker.clone())
        {
            wait.registered = Some(new_waker);
            return;
        }
        wait.registered = None;
        wakers.push(new_waker.clone());
        self.waiters.store(wakers.len, Ordering::SeqCst);
        wait.registered = Some(new_waker);
    }

    fn remove_registered_waker(&self, wait: &mut SignalWait) {
        if let Some(waker) = wait.registered.take() {
            self.remove_waker(&waker);
        }
    }

    fn remove_waker(&self, waker: &Waker) {
        let mut wakers = self.wakers.lock();
        wakers.remove(waker);
        self.waiters.store(wakers.len, Ordering::SeqCst);
    }
}

/// Reusable wait on one signal: the generation it is armed at and the
/// waker it has registered.
struct SignalWait {
    observed: u64,
    registered: Option<Waker>,
}

impl SignalWait {
    /// A wait armed on `signal` now, before the caller tests the channel.
    fn armed(signal: &ByteSignal) -> Self {
        Self::armed_at(signal.arm())
    }

    /// A wait armed at a generation the caller sampled before it tested
    /// the channel.
    const fn armed_at(observed: u64) -> Self {
        Self {
            observed,
            registered: None,
        }
    }
}

/// Producer half of a byte stream. Writers can be cloned — the channel
/// stays open as long as any cloned writer is alive; it closes once they
/// are all dropped.
pub struct ByteWriter {
    channel: Arc<ByteChannel>,
}

/// Consumer half of a byte stream. Clonable so multiple async tasks can
/// share the same byte feed — the underlying queue is already
/// MPMC-safe. Dropping the last clone closes the reader side.
pub struct ByteReader {
    channel: Arc<ByteChannel>,
}

pub struct ByteReadWait {
    channel: Arc<ByteChannel>,
    wait: SignalWait,
}

impl Drop for ByteReadWait {
    fn drop(&mut self) {
        if let Some(waker) = self.wait.registered.take() {
            self.channel.readable.remove_waker(&waker);
        }
    }
}

/// Reusable parking state for [`ByteWriter::poll_writable`] and
/// [`ByteWriter::poll_write`], mirroring [`ByteReadWait`].
pub struct ByteWriteWait {
    channel: Arc<ByteChannel>,
    wait: SignalWait,
}

impl Drop for ByteWriteWait {
    fn drop(&mut self) {
        if let Some(waker) = self.wait.registered.take() {
            self.channel.writable.remove_waker(&waker);
        }
    }
}

pub fn byte_channel() -> (ByteWriter, ByteReader) {
    let channel = ByteChannel::new();
    (
        ByteWriter {
            channel: channel.clone(),
        },
        ByteReader { channel },
    )
}

/// Indicates that the peer has gone away. Writers see this when the reader
/// was dropped; readers see EOF as `Option::None` instead.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClosedPeer;

/// Outcome of a non-blocking [`ByteWriter::try_write`].
#[derive(Debug, PartialEq, Eq)]
pub enum TryWrite {
    /// The chunk was queued.
    Written,
    /// The queue is at capacity. The chunk is returned untouched so the
    /// caller can park on writability and retry with the same bytes —
    /// nothing is dropped and nothing is reported as an error.
    Full(Bytes),
    /// The peer has gone away; the chunk will never be delivered.
    Closed,
}

impl Clone for ByteWriter {
    fn clone(&self) -> Self {
        // The separate closed flags publish EOF/peer-close visibility; these
        // counters only elect the last handle.
        let previous = self.channel.writer_handles.fetch_add(1, Ordering::Relaxed);
        assert!(
            previous != 0,
            "byte writer cloned after liveness reached zero"
        );
        Self {
            channel: self.channel.clone(),
        }
    }
}

impl Drop for ByteWriter {
    fn drop(&mut self) {
        let previous = self.channel.writer_handles.fetch_sub(1, Ordering::Relaxed);
        assert!(previous != 0, "byte writer handle count underflowed");
        if previous == 1 {
            self.channel.close_writer();
        }
    }
}

impl Clone for ByteReader {
    fn clone(&self) -> Self {
        // The separate closed flags publish EOF/peer-close visibility; these
        // counters only elect the last handle.
        let previous = self.channel.reader_handles.fetch_add(1, Ordering::Relaxed);
        assert!(
            previous != 0,
            "byte reader cloned after liveness reached zero"
        );
        Self {
            channel: self.channel.clone(),
        }
    }
}

impl Drop for ByteReader {
    fn drop(&mut self) {
        let previous = self.channel.reader_handles.fetch_sub(1, Ordering::Relaxed);
        assert!(previous != 0, "byte reader handle count underflowed");
        if previous == 1 {
            self.channel.close_reader();
        }
    }
}

impl ByteWriter {
    /// Reusable parking state for the poll-based write paths, armed now:
    /// create it before testing whether the channel can take a write.
    pub fn wait_state(&self) -> ByteWriteWait {
        ByteWriteWait {
            channel: self.channel.clone(),
            wait: SignalWait::armed(&self.channel.writable),
        }
    }

    /// Push a chunk of bytes to the consumer, parking the calling task
    /// while the queue is at capacity. Resolves once the chunk is queued
    /// or the peer is gone.
    pub async fn write(&self, bytes: impl Into<Bytes>) -> Result<(), ClosedPeer> {
        let mut pending = match self.try_write(bytes) {
            TryWrite::Written => return Ok(()),
            TryWrite::Closed => return Err(ClosedPeer),
            TryWrite::Full(bytes) => Some(bytes),
        };
        let mut wait = self.wait_state();
        core::future::poll_fn(|cx| self.poll_write(cx, &mut wait, &mut pending)).await
    }

    /// Non-blocking push. Reports [`TryWrite::Full`] with the chunk
    /// handed back when the queue is at capacity.
    pub fn try_write(&self, bytes: impl Into<Bytes>) -> TryWrite {
        if self.channel.is_closed() {
            return TryWrite::Closed;
        }
        let bytes = bytes.into();
        if bytes.is_empty() {
            return TryWrite::Written;
        }
        match self.channel.push(bytes) {
            Ok(QueuePush::Pushed) => {
                self.channel.readable.notify_all();
                TryWrite::Written
            }
            Ok(QueuePush::Full(bytes)) => TryWrite::Full(bytes),
            Err(ClosedPeer) => TryWrite::Closed,
        }
    }

    /// Poll-driven push for synchronous poll contexts (a component's
    /// stream consumers). On `Poll::Pending` the chunk stays in `pending` and the
    /// task is registered for the next writability wakeup.
    pub fn poll_write(
        &self,
        cx: &mut Context<'_>,
        wait: &mut ByteWriteWait,
        pending: &mut Option<Bytes>,
    ) -> Poll<Result<(), ClosedPeer>> {
        loop {
            let Some(bytes) = pending.take() else {
                return Poll::Ready(Ok(()));
            };
            match self.try_write(bytes) {
                TryWrite::Written => return Poll::Ready(Ok(())),
                TryWrite::Closed => return Poll::Ready(Err(ClosedPeer)),
                TryWrite::Full(bytes) => {
                    *pending = Some(bytes);
                    match self.channel.writable.poll_notified(cx, &mut wait.wait) {
                        Poll::Ready(()) => continue,
                        Poll::Pending => return Poll::Pending,
                    }
                }
            }
        }
    }

    /// True when a `try_write` would not report [`TryWrite::Full`]: the
    /// queue has room, or the channel is closed and the write would fail
    /// outright rather than block.
    pub fn is_writable(&self) -> bool {
        self.channel.is_closed() || !self.channel.queue.is_full()
    }

    pub fn poll_writable(&self, cx: &mut Context<'_>, wait: &mut ByteWriteWait) -> Poll<()> {
        loop {
            if self.is_writable() {
                return Poll::Ready(());
            }
            match self.channel.writable.poll_notified(cx, &mut wait.wait) {
                Poll::Ready(()) => continue,
                Poll::Pending => return Poll::Pending,
            }
        }
    }

    /// Await room in the queue without pushing anything, for adapters
    /// whose readiness pollable is separate from the write itself.
    pub async fn writable(&self) {
        if self.is_writable() {
            return;
        }
        let mut wait = self.wait_state();
        core::future::poll_fn(|cx| self.poll_writable(cx, &mut wait)).await;
    }

    /// Returns true once the reader has been dropped.
    pub fn is_reader_closed(&self) -> bool {
        self.channel.reader_closed.load(Ordering::Acquire)
    }

    /// Resolves once the reader half is gone.
    ///
    /// A producer that parks on something other than this channel has
    /// no other way to learn that the consumer went away: it is not
    /// waiting on the queue, so the close that wakes writability wakes
    /// nothing it holds. A TCP bridge is one — it parks on a
    /// socket read with no deadline — and a bridge that never learns
    /// its channel is gone never ends, keeping the socket it reads from
    /// alive for the rest of the boot (#184).
    ///
    /// The wait is armed before the flag is tested, so a close between
    /// the two resolves it rather than being slept through.
    pub async fn reader_closed(&self) {
        let mut wait = self.wait_state();
        core::future::poll_fn(|cx| {
            loop {
                if self.is_reader_closed() {
                    return Poll::Ready(());
                }
                match self.channel.writable.poll_notified(cx, &mut wait.wait) {
                    Poll::Ready(()) => continue,
                    Poll::Pending => return Poll::Pending,
                }
            }
        })
        .await;
    }

    pub fn close(&self) {
        self.channel.close_writer();
    }
}

impl ByteReader {
    /// Reusable parking state for the poll-based read paths, armed now:
    /// create it before testing whether the channel is readable.
    pub fn wait_state(&self) -> ByteReadWait {
        self.wait_state_armed_at(self.channel.readable.arm())
    }

    fn wait_state_armed_at(&self, generation: u64) -> ByteReadWait {
        ByteReadWait {
            channel: self.channel.clone(),
            wait: SignalWait::armed_at(generation),
        }
    }

    /// True while the shared stream still contains unread bytes.
    pub fn has_buffered_data(&self) -> bool {
        !self.channel.queue.is_empty()
    }

    /// True after the final writer closes, including while buffered data remains.
    pub fn is_writer_closed(&self) -> bool {
        self.channel.writer_closed.load(Ordering::Acquire)
    }

    pub fn is_readable(&self) -> bool {
        !self.channel.queue.is_empty()
            || self.channel.writer_closed.load(Ordering::Acquire)
            || self.channel.reader_closed.load(Ordering::Acquire)
    }

    pub fn poll_readable(
        &self,
        cx: &mut core::task::Context<'_>,
        wait: &mut ByteReadWait,
    ) -> core::task::Poll<()> {
        loop {
            if self.is_readable() {
                return core::task::Poll::Ready(());
            }
            match self.channel.readable.poll_notified(cx, &mut wait.wait) {
                core::task::Poll::Ready(()) => continue,
                core::task::Poll::Pending => return core::task::Poll::Pending,
            }
        }
    }

    /// Await the next chunk. Returns `None` when every writer has been
    /// dropped and the queue is drained (EOF).
    pub async fn read(&self) -> Option<Bytes> {
        // Armed before the first pop; the parking state that carries the
        // wait is only built if that pop comes back empty, and re-arms
        // itself each time it completes, before the next pop.
        let armed = self.channel.readable.arm();
        let mut wait = None;
        loop {
            match self.channel.pop() {
                Some(bytes) => return Some(bytes),
                None => {
                    if self.channel.writer_closed.load(Ordering::Acquire)
                        || self.channel.reader_closed.load(Ordering::Acquire)
                    {
                        // Drain races: a writer might have enqueued right
                        // before the last liveness guard dropped.
                        return self.channel.pop();
                    }
                    let wait = wait.get_or_insert_with(|| self.wait_state_armed_at(armed));
                    core::future::poll_fn(|cx| {
                        self.channel.readable.poll_notified(cx, &mut wait.wait)
                    })
                    .await;
                }
            }
        }
    }

    /// Reads at most `limit` bytes while keeping the unconsumed tail in the
    /// shared queue. Duplicated read handles observe one byte stream.
    pub fn try_read_limit(&self, limit: usize) -> TryRead {
        if limit == 0 {
            return TryRead::Ready(Bytes::new());
        }
        // Observe closure before taking the queue lock: a final write that
        // precedes closure must be visible to this pop before it can report EOF.
        let closed = self.channel.is_closed();
        let (bytes, freed_full_slot) = self.channel.queue.pop_limit(limit);
        if freed_full_slot && bytes.is_some() {
            self.channel.writable.notify_all();
        }
        match bytes {
            Some(bytes) => TryRead::Ready(bytes),
            None if closed => TryRead::Eof,
            None => TryRead::Pending,
        }
    }
    pub async fn read_limit(&self, limit: usize) -> Option<Bytes> {
        let mut wait = self.wait_state();
        core::future::poll_fn(|cx| {
            loop {
                match self.try_read_limit(limit) {
                    TryRead::Ready(bytes) => return Poll::Ready(Some(bytes)),
                    TryRead::Eof => return Poll::Ready(None),
                    TryRead::Pending => {
                        match self.channel.readable.poll_notified(cx, &mut wait.wait) {
                            Poll::Ready(()) => continue,
                            Poll::Pending => return Poll::Pending,
                        }
                    }
                }
            }
        })
        .await
    }

    /// Non-blocking peek: returns an immediately available chunk or
    /// signals EOF / not-ready.
    pub fn try_read(&self) -> TryRead {
        match self.channel.pop() {
            Some(bytes) => TryRead::Ready(bytes),
            None => {
                if self.channel.writer_closed.load(Ordering::Acquire)
                    || self.channel.reader_closed.load(Ordering::Acquire)
                {
                    TryRead::Eof
                } else {
                    TryRead::Pending
                }
            }
        }
    }

    pub fn poll_read(
        &self,
        cx: &mut core::task::Context<'_>,
        wait: &mut ByteReadWait,
    ) -> core::task::Poll<Option<Bytes>> {
        loop {
            match self.channel.pop() {
                Some(bytes) => return core::task::Poll::Ready(Some(bytes)),
                None => {
                    if self.channel.writer_closed.load(Ordering::Acquire)
                        || self.channel.reader_closed.load(Ordering::Acquire)
                    {
                        return core::task::Poll::Ready(self.channel.pop());
                    }
                    match self.channel.readable.poll_notified(cx, &mut wait.wait) {
                        core::task::Poll::Ready(()) => continue,
                        core::task::Poll::Pending => return core::task::Poll::Pending,
                    }
                }
            }
        }
    }

    pub fn close(&self) {
        self.channel.close_reader();
    }
}

pub enum TryRead {
    Ready(Bytes),
    Pending,
    Eof,
}

#[cfg(test)]
mod tests {
    use alloc::sync::Arc as StdArc;
    use alloc::vec::Vec;
    use core::future::Future;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use core::task::{Context, Poll};

    use bytes::Bytes;
    use futures::task::{ArcWake, waker};

    use super::{BYTE_CHANNEL_CHUNK_CAPACITY, TryWrite, byte_channel};

    struct CountingWaker {
        wakes: AtomicUsize,
    }

    impl CountingWaker {
        fn new() -> StdArc<Self> {
            StdArc::new(Self {
                wakes: AtomicUsize::new(0),
            })
        }

        fn count(&self) -> usize {
            self.wakes.load(Ordering::SeqCst)
        }
    }

    impl ArcWake for CountingWaker {
        fn wake_by_ref(arc_self: &StdArc<Self>) {
            arc_self.wakes.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn fill_to_capacity(writer: &super::ByteWriter) {
        for index in 0..BYTE_CHANNEL_CHUNK_CAPACITY {
            assert_eq!(
                writer.try_write(Bytes::copy_from_slice(&(index as u16).to_le_bytes())),
                TryWrite::Written,
                "chunk {index} should fit below capacity"
            );
        }
    }

    #[test]
    fn a_partial_reader_drains_a_concurrent_final_write_before_eof() {
        for _ in 0..100 {
            let (writer, reader) = byte_channel();
            std::thread::scope(|scope| {
                scope.spawn(move || {
                    assert_eq!(
                        writer.try_write(Bytes::from_static(b"tail")),
                        TryWrite::Written
                    );
                });
                let first = futures_lite::future::block_on(reader.read_limit(2));
                let second = futures_lite::future::block_on(reader.read_limit(2));
                assert_eq!(first.as_deref(), Some(&b"ta"[..]));
                assert_eq!(second.as_deref(), Some(&b"il"[..]));
                assert!(futures_lite::future::block_on(reader.read_limit(2)).is_none());
            });
        }
    }

    #[test]
    fn partial_reads_leave_one_tail_for_all_read_handles() {
        let (writer, reader) = byte_channel();
        let duplicate = reader.clone();
        assert_eq!(
            writer.try_write(Bytes::from_static(b"abcdef")),
            TryWrite::Written
        );
        assert!(
            matches!(reader.try_read_limit(2), super::TryRead::Ready(bytes) if bytes == b"ab"[..])
        );
        drop(writer);
        assert!(duplicate.is_writer_closed());
        assert!(duplicate.has_buffered_data());
        assert!(
            matches!(duplicate.try_read_limit(8), super::TryRead::Ready(bytes) if bytes == b"cdef"[..])
        );
        assert!(matches!(reader.try_read_limit(1), super::TryRead::Eof));
    }

    #[test]
    fn byte_channel_preserves_bytes_chunks_without_copying() {
        let (writer, reader) = byte_channel();
        let bytes = Bytes::from_static(b"helios");
        let ptr = bytes.as_ptr();

        futures_lite::future::block_on(writer.write(bytes)).expect("reader is still open");
        drop(writer);

        let received = futures_lite::future::block_on(reader.read())
            .expect("queued bytes should be delivered before EOF");
        assert_eq!(received.as_ref(), b"helios");
        assert_eq!(received.as_ptr(), ptr);
    }

    #[test]
    fn byte_channel_queue_is_bounded_to_kernel_capacity() {
        let (writer, _) = byte_channel();

        assert_eq!(writer.channel.queue.capacity(), BYTE_CHANNEL_CHUNK_CAPACITY);
    }

    #[test]
    fn byte_channel_poll_read_uses_reusable_wait_state() {
        let (writer, reader) = byte_channel();
        let mut wait = reader.wait_state();

        futures_lite::future::block_on(writer.write(Bytes::from_static(b"poll")))
            .expect("reader is still open");
        drop(writer);

        let received = futures_lite::future::block_on(futures_lite::future::poll_fn(|cx| {
            reader.poll_read(cx, &mut wait)
        }))
        .expect("queued bytes should be delivered before EOF");

        assert_eq!(received.as_ref(), b"poll");
    }

    #[test]
    fn byte_channel_spills_after_inline_chunks_without_reordering() {
        let (writer, reader) = byte_channel();
        for value in 0..80u8 {
            futures_lite::future::block_on(writer.write(Bytes::copy_from_slice(&[value])))
                .expect("reader is still open");
        }
        drop(writer);

        for value in 0..80u8 {
            let received = futures_lite::future::block_on(reader.read())
                .expect("queued byte should be delivered before EOF");
            assert_eq!(received.as_ref(), &[value]);
        }
        assert!(futures_lite::future::block_on(reader.read()).is_none());
    }

    #[test]
    fn byte_channel_preserves_capacity_after_inline_segment_drains() {
        let (writer, reader) = byte_channel();
        for value in 0..80u16 {
            futures_lite::future::block_on(
                writer.write(Bytes::copy_from_slice(&value.to_le_bytes())),
            )
            .expect("reader is still open");
        }

        for value in 0..64u16 {
            let received = futures_lite::future::block_on(reader.read())
                .expect("queued byte should be delivered before EOF");
            assert_eq!(received.as_ref(), &value.to_le_bytes());
        }

        for value in 80..320u16 {
            futures_lite::future::block_on(
                writer.write(Bytes::copy_from_slice(&value.to_le_bytes())),
            )
            .expect("reader is still open");
        }
        drop(writer);

        for value in 64..320u16 {
            let received = futures_lite::future::block_on(reader.read())
                .expect("queued byte should be delivered before EOF");
            assert_eq!(received.as_ref(), &value.to_le_bytes());
        }
        assert!(futures_lite::future::block_on(reader.read()).is_none());
    }

    #[test]
    fn byte_channel_reports_readability_for_data_and_eof() {
        let (writer, reader) = byte_channel();

        assert!(!reader.is_readable());
        futures_lite::future::block_on(writer.write(Bytes::from_static(b"ready")))
            .expect("reader is still open");
        assert!(reader.is_readable());

        let received = futures_lite::future::block_on(reader.read())
            .expect("queued bytes should be delivered before EOF");
        assert_eq!(received.as_ref(), b"ready");
        assert!(!reader.is_readable());

        drop(writer);
        assert!(reader.is_readable());
        assert!(futures_lite::future::block_on(reader.read()).is_none());
    }

    #[test]
    fn byte_writer_close_reports_eof_after_queued_bytes() {
        let (writer, reader) = byte_channel();

        futures_lite::future::block_on(writer.write(Bytes::from_static(b"before-close")))
            .expect("reader is still open");
        writer.close();
        assert_eq!(
            futures_lite::future::block_on(writer.write(Bytes::from_static(b"after-close"))),
            Err(super::ClosedPeer)
        );

        let received = futures_lite::future::block_on(reader.read())
            .expect("queued bytes should be delivered before EOF");
        assert_eq!(received.as_ref(), b"before-close");
        assert!(futures_lite::future::block_on(reader.read()).is_none());
    }

    /// Polls `future` once with a no-op waker, reporting whether it
    /// finished.
    fn poll_pinned(future: core::pin::Pin<&mut impl core::future::Future<Output = ()>>) -> bool {
        let waker = core::task::Waker::noop();
        let mut context = core::task::Context::from_waker(waker);
        core::future::Future::poll(future, &mut context).is_ready()
    }

    /// A producer parked on something other than the queue still has
    /// to learn that the consumer went away. Without this a TCP
    /// bridge, which parks on a deadline-free socket read, outlived
    /// the instance whose channel it was feeding and kept that
    /// instance's connection open for the rest of the boot (#184).
    #[test]
    fn a_writer_learns_that_its_reader_is_gone_while_parked_elsewhere() {
        let (writer, reader) = byte_channel();

        let mut closed = core::pin::pin!(writer.reader_closed());
        assert!(
            !poll_pinned(closed.as_mut()),
            "a live reader leaves the wait parked"
        );

        drop(reader);

        assert!(
            poll_pinned(closed.as_mut()),
            "dropping the reader must release a producer parked on the close"
        );
    }

    /// The same, for a close that lands before the wait is built: the
    /// flag is the state, the signal is only the wake-up.
    #[test]
    fn a_writer_that_asks_after_its_reader_is_gone_does_not_park() {
        let (writer, reader) = byte_channel();
        drop(reader);

        futures_lite::future::block_on(writer.reader_closed());
    }

    #[test]
    fn byte_reader_close_rejects_future_writes() {
        let (writer, reader) = byte_channel();

        reader.close();

        assert!(writer.is_reader_closed());
        assert_eq!(
            futures_lite::future::block_on(writer.write(Bytes::from_static(b"closed"))),
            Err(super::ClosedPeer)
        );
        assert!(reader.is_readable());
        assert!(futures_lite::future::block_on(reader.read()).is_none());
    }

    #[test]
    fn byte_channel_try_write_reports_full_at_capacity_without_losing_bytes() {
        let (writer, reader) = byte_channel();
        fill_to_capacity(&writer);

        assert!(!writer.is_writable());
        let rejected = match writer.try_write(Bytes::from_static(b"overflow")) {
            TryWrite::Full(bytes) => bytes,
            TryWrite::Written => panic!("a full channel must not accept another chunk"),
            TryWrite::Closed => panic!("the reader is still open"),
        };
        assert_eq!(rejected.as_ref(), b"overflow");
        assert_eq!(writer.channel.queue.len(), BYTE_CHANNEL_CHUNK_CAPACITY);

        // One pop makes room, and the same bytes go in untouched.
        futures_lite::future::block_on(reader.read()).expect("queued bytes are available");
        assert!(writer.is_writable());
        assert_eq!(writer.try_write(rejected), TryWrite::Written);
    }

    #[test]
    fn byte_channel_writer_pends_at_capacity_and_resumes_after_a_drain() {
        let (writer, reader) = byte_channel();
        fill_to_capacity(&writer);

        let counter = CountingWaker::new();
        let waker = waker(counter.clone());
        let mut cx = Context::from_waker(&waker);
        let mut wait = writer.wait_state();
        let mut pending = Some(Bytes::from_static(b"parked"));

        assert!(
            writer
                .poll_write(&mut cx, &mut wait, &mut pending)
                .is_pending(),
            "a full channel must park the writer instead of panicking"
        );
        assert_eq!(counter.count(), 0);
        assert!(pending.is_some(), "the parked chunk must not be dropped");

        futures_lite::future::block_on(reader.read()).expect("queued bytes are available");
        assert_eq!(counter.count(), 1, "the drain must wake the parked writer");

        assert_eq!(
            writer.poll_write(&mut cx, &mut wait, &mut pending),
            Poll::Ready(Ok(()))
        );
        assert!(pending.is_none());

        // The parked chunk is delivered in order, after everything queued
        // before it.
        let mut received = Vec::new();
        drop(writer);
        while let Some(bytes) = futures_lite::future::block_on(reader.read()) {
            received.push(bytes);
        }
        assert_eq!(received.len(), BYTE_CHANNEL_CHUNK_CAPACITY);
        assert_eq!(
            received
                .last()
                .expect("the parked chunk is the final delivery")
                .as_ref(),
            b"parked"
        );
    }

    #[test]
    fn byte_channel_write_future_completes_after_the_reader_drains() {
        let (writer, reader) = byte_channel();
        fill_to_capacity(&writer);

        let counter = CountingWaker::new();
        let waker = waker(counter.clone());
        let mut cx = Context::from_waker(&waker);
        let mut write = core::pin::pin!(writer.write(Bytes::from_static(b"awaited")));

        assert!(write.as_mut().poll(&mut cx).is_pending());
        futures_lite::future::block_on(reader.read()).expect("queued bytes are available");
        assert!(counter.count() >= 1);
        assert_eq!(write.as_mut().poll(&mut cx), Poll::Ready(Ok(())));
    }

    #[test]
    fn byte_channel_does_not_lose_a_wakeup_when_a_drain_races_registration() {
        let (writer, reader) = byte_channel();
        fill_to_capacity(&writer);
        let signal = &writer.channel.writable;

        let counter = CountingWaker::new();
        let waker = waker(counter.clone());
        let mut cx = Context::from_waker(&waker);

        // Interleaving A: the drain broadcasts after the writer armed and
        // decided the queue was full but before the waker is registered.
        // Nobody is parked, so no wake is sent — the generation the wait
        // was armed at alone has to carry the writer through, or it parks
        // forever.
        let mut wait = super::SignalWait::armed(signal);
        signal.notify_all();
        assert_eq!(
            counter.count(),
            0,
            "no waker is registered yet, so nothing can be woken"
        );
        assert_eq!(signal.poll_notified(&mut cx, &mut wait), Poll::Ready(()));

        // Interleaving B: the writer registers first, so the drain reaches
        // its waker and the following poll observes the new generation.
        assert!(signal.poll_notified(&mut cx, &mut wait).is_pending());
        signal.notify_all();
        assert_eq!(counter.count(), 1);
        assert_eq!(signal.poll_notified(&mut cx, &mut wait), Poll::Ready(()));

        // The same handshake end to end, driven by a real drain.
        let mut wait = writer.wait_state();
        let mut pending = Some(Bytes::from_static(b"raced"));
        assert!(
            writer
                .poll_write(&mut cx, &mut wait, &mut pending)
                .is_pending()
        );
        futures_lite::future::block_on(reader.read()).expect("queued bytes are available");
        assert_eq!(counter.count(), 2);
        assert_eq!(
            writer.poll_write(&mut cx, &mut wait, &mut pending),
            Poll::Ready(Ok(())),
            "the broadcast raised by the drain must be observed"
        );
        assert!(pending.is_none());
    }

    #[test]
    fn byte_channel_wakes_every_parked_writer() {
        let (writer, reader) = byte_channel();
        let second = writer.clone();
        fill_to_capacity(&writer);

        let first_counter = CountingWaker::new();
        let first_waker = waker(first_counter.clone());
        let mut first_cx = Context::from_waker(&first_waker);
        let mut first_wait = writer.wait_state();
        let mut first_pending = Some(Bytes::from_static(b"first"));

        let second_counter = CountingWaker::new();
        let second_waker = waker(second_counter.clone());
        let mut second_cx = Context::from_waker(&second_waker);
        let mut second_wait = second.wait_state();
        let mut second_pending = Some(Bytes::from_static(b"second"));

        assert!(
            writer
                .poll_write(&mut first_cx, &mut first_wait, &mut first_pending)
                .is_pending()
        );
        assert!(
            second
                .poll_write(&mut second_cx, &mut second_wait, &mut second_pending)
                .is_pending()
        );

        futures_lite::future::block_on(reader.read()).expect("queued bytes are available");

        assert_eq!(first_counter.count(), 1);
        assert_eq!(second_counter.count(), 1);
    }

    /// A pipe a guest's threads share can have several readers parked on
    /// it at once. EOF is a state every one of them has to observe: a
    /// close that reached only one would leave the others asleep on a
    /// channel that can never produce another byte.
    #[test]
    fn a_closing_writer_completes_every_parked_reader() {
        let (writer, reader) = byte_channel();
        let second = reader.clone();

        let first_counter = CountingWaker::new();
        let first_waker = waker(first_counter.clone());
        let mut first_cx = Context::from_waker(&first_waker);
        let mut first_wait = reader.wait_state();

        let second_counter = CountingWaker::new();
        let second_waker = waker(second_counter.clone());
        let mut second_cx = Context::from_waker(&second_waker);
        let mut second_wait = second.wait_state();

        assert!(
            reader
                .poll_read(&mut first_cx, &mut first_wait)
                .is_pending()
        );
        assert!(
            second
                .poll_read(&mut second_cx, &mut second_wait)
                .is_pending()
        );

        drop(writer);

        assert_eq!(first_counter.count(), 1, "the close wakes the first reader");
        assert_eq!(
            second_counter.count(),
            1,
            "the close wakes the second reader"
        );
        assert_eq!(
            reader.poll_read(&mut first_cx, &mut first_wait),
            Poll::Ready(None)
        );
        assert_eq!(
            second.poll_read(&mut second_cx, &mut second_wait),
            Poll::Ready(None)
        );
    }

    /// Data is the same: every parked reader re-reads the queue, one of
    /// them takes the chunk, and the rest park again.
    #[test]
    fn a_write_wakes_every_parked_reader() {
        let (writer, reader) = byte_channel();
        let second = reader.clone();

        let first_counter = CountingWaker::new();
        let first_waker = waker(first_counter.clone());
        let mut first_cx = Context::from_waker(&first_waker);
        let mut first_wait = reader.wait_state();

        let second_counter = CountingWaker::new();
        let second_waker = waker(second_counter.clone());
        let mut second_cx = Context::from_waker(&second_waker);
        let mut second_wait = second.wait_state();

        assert!(
            reader
                .poll_readable(&mut first_cx, &mut first_wait)
                .is_pending()
        );
        assert!(
            second
                .poll_readable(&mut second_cx, &mut second_wait)
                .is_pending()
        );

        assert_eq!(
            writer.try_write(Bytes::from_static(b"one")),
            TryWrite::Written
        );

        assert_eq!(first_counter.count(), 1, "the write wakes the first reader");
        assert_eq!(
            second_counter.count(),
            1,
            "the write wakes the second reader"
        );
        assert_eq!(
            reader.poll_read(&mut first_cx, &mut first_wait),
            Poll::Ready(Some(Bytes::from_static(b"one")))
        );
        assert!(
            second
                .poll_read(&mut second_cx, &mut second_wait)
                .is_pending(),
            "the chunk is gone, so the second reader parks again"
        );
    }

    #[test]
    fn byte_channel_parked_writer_observes_a_closing_reader() {
        let (writer, reader) = byte_channel();
        fill_to_capacity(&writer);

        let counter = CountingWaker::new();
        let waker = waker(counter.clone());
        let mut cx = Context::from_waker(&waker);
        let mut wait = writer.wait_state();
        let mut pending = Some(Bytes::from_static(b"orphaned"));

        assert!(
            writer
                .poll_write(&mut cx, &mut wait, &mut pending)
                .is_pending()
        );

        reader.close();

        assert_eq!(counter.count(), 1, "closing must wake parked writers");
        assert_eq!(
            writer.poll_write(&mut cx, &mut wait, &mut pending),
            Poll::Ready(Err(super::ClosedPeer))
        );
    }

    #[test]
    fn byte_channel_parked_writer_observes_a_dropped_reader() {
        let (writer, reader) = byte_channel();
        fill_to_capacity(&writer);

        let counter = CountingWaker::new();
        let waker = waker(counter.clone());
        let mut cx = Context::from_waker(&waker);
        let mut wait = writer.wait_state();
        let mut pending = Some(Bytes::from_static(b"orphaned"));

        assert!(
            writer
                .poll_write(&mut cx, &mut wait, &mut pending)
                .is_pending()
        );

        drop(reader);

        assert_eq!(counter.count(), 1);
        assert_eq!(
            writer.poll_write(&mut cx, &mut wait, &mut pending),
            Poll::Ready(Err(super::ClosedPeer))
        );
        assert!(
            writer.is_writable(),
            "a closed channel never parks a writer"
        );
    }

    #[test]
    fn byte_channel_poll_writable_tracks_queue_occupancy() {
        let (writer, reader) = byte_channel();
        let mut wait = writer.wait_state();
        let counter = CountingWaker::new();
        let waker = waker(counter.clone());
        let mut cx = Context::from_waker(&waker);

        assert_eq!(writer.poll_writable(&mut cx, &mut wait), Poll::Ready(()));
        fill_to_capacity(&writer);
        assert!(writer.poll_writable(&mut cx, &mut wait).is_pending());

        futures_lite::future::block_on(reader.read()).expect("queued bytes are available");
        assert_eq!(writer.poll_writable(&mut cx, &mut wait), Poll::Ready(()));
    }

    #[test]
    fn byte_channel_write_survives_more_parked_waiters_than_inline_capacity() {
        let (writer, reader) = byte_channel();
        fill_to_capacity(&writer);

        let waiters = super::BYTE_CHANNEL_WAKER_CAPACITY + 4;
        let mut counters = Vec::new();
        let mut wakers = Vec::new();
        let mut waits = Vec::new();
        let mut pendings = Vec::new();
        for _ in 0..waiters {
            let counter = CountingWaker::new();
            wakers.push(waker(counter.clone()));
            counters.push(counter);
            waits.push(writer.wait_state());
            pendings.push(Some(Bytes::from_static(b"crowd")));
        }

        for index in 0..waiters {
            let mut cx = Context::from_waker(&wakers[index]);
            assert!(
                writer
                    .poll_write(&mut cx, &mut waits[index], &mut pendings[index])
                    .is_pending(),
                "waiter {index} should park on the full channel"
            );
        }

        futures_lite::future::block_on(reader.read()).expect("queued bytes are available");

        for (index, counter) in counters.iter().enumerate() {
            assert_eq!(counter.count(), 1, "waiter {index} should have been woken");
        }
    }
}
