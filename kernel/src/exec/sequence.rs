use core::sync::atomic::{AtomicU64, Ordering};
use core::task::{Context, Poll};

use super::{Notify, NotifyWaiter};

/// A counted event a stream in some instance's store is driven by.
///
/// Display completion, output changes and GPU ring retirement publish
/// their progress through this primitive.
///
/// # Concurrency contract
///
/// Written by the owner tasks and read from whichever processor runs the
/// reading store. A reader arms the notification inside
/// [`Self::poll_next`] before it re-reads the count, so an event
/// published between the read and the park wakes it; the notification is
/// a broadcast, because every reader of one signal is owed the same
/// event.
#[derive(Default)]
pub struct SequenceSignal {
    sequence: AtomicU64,
    nanos: AtomicU64,
    published: Notify,
}

impl SequenceSignal {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record event number `sequence`, taken at `nanos` on the kernel's
    /// monotonic clock, and wake every reader waiting for one.
    pub fn publish(&self, sequence: u64, nanos: u64) {
        self.nanos.store(nanos, Ordering::Release);
        self.sequence.store(sequence, Ordering::Release);
        self.published.notify_all();
    }

    /// Advance an untimestamped timeline from any processor.
    pub(super) fn advance(&self, sequence: u64) {
        if self.sequence.fetch_max(sequence, Ordering::AcqRel) < sequence {
            self.wake();
        }
    }

    pub(super) fn wake(&self) {
        self.published.notify_all();
    }

    pub(super) fn poll_wake(&self, cx: &mut Context<'_>, waiter: &mut NotifyWaiter) -> Poll<()> {
        self.published.poll_notified(cx, waiter)
    }

    /// Bump the count by one, taking the time from `nanos`.
    pub fn bump(&self, nanos: u64) -> u64 {
        let next = self.sequence.load(Ordering::Acquire) + 1;
        self.publish(next, nanos);
        next
    }

    /// How many events this signal has published.
    pub fn sequence(&self) -> u64 {
        self.sequence.load(Ordering::Acquire)
    }

    /// A fresh wait on this signal.
    pub fn waiter(&self) -> NotifyWaiter {
        self.published.waiter()
    }

    /// The next event published after `last_seen`, as its count and the
    /// clock reading it was taken at.
    pub fn poll_next(
        &self,
        cx: &mut Context<'_>,
        waiter: &mut NotifyWaiter,
        last_seen: &mut u64,
    ) -> Poll<(u64, u64)> {
        loop {
            let sequence = self.sequence.load(Ordering::Acquire);
            if sequence != *last_seen {
                *last_seen = sequence;
                return Poll::Ready((sequence, self.nanos.load(Ordering::Acquire)));
            }
            match self.published.poll_notified(cx, waiter) {
                Poll::Ready(()) => continue,
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}
