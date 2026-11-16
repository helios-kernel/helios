use crate::InterruptTarget;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use core::task::{Context, Poll};
use helios_sync::Notify;
use spin::Mutex;
const NO_PENDING_SIGNAL: u32 = u32::MAX;
/// One signal mailbox: a process's, shared by every store of the
/// process (its threads' included), or one thread's, read only by that
/// thread's store. It holds the one pending delivery, the interval
/// timer's generation, the broadcast a raise sends to the turns driving
/// the stores that read it, and the instance a raise interrupts. A
/// thread's mailbox also carries the end of its process
/// ([`Self::end_thread`]), which reaches the thread the way a signal
/// does and is never taken.
///
/// # Concurrency
///
/// Any processor may raise (a parent's `proc_raise`, a sibling's
/// `thread_signal`, the interval timer task) or end the thread (the
/// process's last turn); one turn at a time takes. The pending signal,
/// the end and the generation are single atomics and the broadcast is
/// lock-free; only naming and reaching the interrupt target takes a
/// spin lock, see [`Signals::target`].
pub struct SignalState<T: InterruptTarget> {
    shared: Arc<Signals<T>>,
}

struct Signals<T: InterruptTarget> {
    pending: AtomicU32,
    /// Set once, when the process this thread belongs to has ended. It
    /// is a stop the thread's store owes its guest at every turn from
    /// then on, so it is read and never taken.
    thread_ended: AtomicBool,
    interval_generation: AtomicU64,
    /// Broadcast by every raise and by the thread's end, after either is
    /// stored, so a turn whose guest is suspended in a host call ends the
    /// call instead of waiting for the host call to resolve.
    raised: Notify,
    /// The process a raise interrupts, once a store of it exists.
    ///
    /// Raises come from host calls and timer tasks, never from an
    /// interrupt handler, so a spin lock is enough; it is also what orders
    /// a raise against [`SignalState::attach`], which see the comment
    /// there.
    target: Mutex<Option<T>>,
}

impl<T: InterruptTarget> SignalState<T> {
    pub fn new() -> Self {
        Self {
            shared: Arc::new(Signals {
                pending: AtomicU32::new(NO_PENDING_SIGNAL),
                thread_ended: AtomicBool::new(false),
                interval_generation: AtomicU64::new(0),
                raised: Notify::new(),
                target: Mutex::new(None),
            }),
        }
    }

    /// Marks `signal` pending and brings it to the guest: a running
    /// guest takes it at its next interrupt check, which interrupting
    /// every store of the process makes immediate, and a suspended one
    /// through the turn that waits on `raised`.
    pub fn raise(&self, signal: u32) {
        self.shared.pending.store(signal, Ordering::Release);
        self.deliver();
    }

    /// Ends the thread whose mailbox this is, because its process ended:
    /// a running thread meets the end at its next interrupt check, which
    /// interrupting the process's stores makes immediate, and a suspended
    /// one through the turn that waits on `raised`, which drops the call
    /// it is suspended in (a parked `memory.atomic.wait` included).
    pub fn end_thread(&self) {
        self.shared.thread_ended.store(true, Ordering::Release);
        self.deliver();
    }

    /// Whether [`Self::end_thread`] has ended the thread.
    pub fn thread_ended(&self) -> bool {
        self.shared.thread_ended.load(Ordering::Acquire)
    }

    /// Brings what was just stored to the stores that read this mailbox:
    /// wakes the turns whose guests are suspended and interrupts the
    /// running ones.
    fn deliver(&self) {
        self.shared.raised.notify_all();
        if let Some(target) = &*self.shared.target.lock() {
            target.interrupt();
        }
    }

    /// Names `instance`, whose stores `interrupts` reaches, as the process
    /// a raise interrupts. Every store of the process attaches when it is
    /// created; a replacement image attaches its own instance.
    ///
    /// A raise or an end that came before the target was named left its
    /// mark and interrupted nothing, so this interrupts on its behalf.
    /// The lock orders the two: one that takes it after this released it
    /// finds the target, and one that took it before had already stored
    /// its mark, which the loads below then see.
    pub fn attach(&self, target: T) {
        *self.shared.target.lock() = Some(target.clone());
        if self.shared.pending.load(Ordering::Acquire) != NO_PENDING_SIGNAL || self.thread_ended() {
            target.interrupt();
        }
    }
    pub fn wait_state(&self) -> helios_sync::NotifyWaiter {
        self.shared.raised.waiter()
    }
    pub fn poll_changed(
        &self,
        cx: &mut Context<'_>,
        wait: &mut helios_sync::NotifyWaiter,
    ) -> Poll<()> {
        self.shared.raised.poll_notified(cx, wait)
    }

    pub fn take_pending(&self) -> Option<u32> {
        match self
            .shared
            .pending
            .swap(NO_PENDING_SIGNAL, Ordering::AcqRel)
        {
            NO_PENDING_SIGNAL => None,
            signal => Some(signal),
        }
    }

    pub fn next_interval_generation(&self) -> u64 {
        self.shared
            .interval_generation
            .fetch_add(1, Ordering::AcqRel)
            .saturating_add(1)
    }

    pub fn cancel_interval(&self) {
        let _ = self.next_interval_generation();
    }

    pub fn interval_generation_is_current(&self, generation: u64) -> bool {
        self.shared.interval_generation.load(Ordering::Acquire) == generation
    }
}

impl<T: InterruptTarget> Clone for SignalState<T> {
    fn clone(&self) -> Self {
        Self {
            shared: self.shared.clone(),
        }
    }
}
impl<T: InterruptTarget> Default for SignalState<T> {
    fn default() -> Self {
        Self::new()
    }
}
