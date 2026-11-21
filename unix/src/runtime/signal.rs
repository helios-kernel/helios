use alloc::sync::Arc;
use core::num::NonZeroU8;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use core::task::{Context, Poll};

use helios_sync::Notify;
use spin::Mutex;
use thiserror::Error;

use crate::InterruptTarget;

/// A valid UNIX signal number in `1..=64` (`_NSIG`).
///
/// Signal `0` is the null existence-and-authority probe of `kill(pid, 0)` and
/// `pthread_kill(tid, 0)`, never a deliverable signal, so the type excludes it
/// by construction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Signal(NonZeroU8);

impl Signal {
    /// Highest valid real-time signal number (`SIGRTMAX`).
    pub const MAX: u8 = 64;
    /// Highest standard non-real-time signal number (`1..=31`).
    pub const STANDARD_MAX: u8 = 31;

    pub const SIGHUP: Self = Self::constant(1);
    pub const SIGINT: Self = Self::constant(2);
    pub const SIGQUIT: Self = Self::constant(3);
    pub const SIGILL: Self = Self::constant(4);
    pub const SIGTRAP: Self = Self::constant(5);
    pub const SIGABRT: Self = Self::constant(6);
    pub const SIGBUS: Self = Self::constant(7);
    pub const SIGFPE: Self = Self::constant(8);
    pub const SIGKILL: Self = Self::constant(9);
    pub const SIGUSR1: Self = Self::constant(10);
    pub const SIGSEGV: Self = Self::constant(11);
    pub const SIGUSR2: Self = Self::constant(12);
    pub const SIGPIPE: Self = Self::constant(13);
    pub const SIGALRM: Self = Self::constant(14);
    pub const SIGTERM: Self = Self::constant(15);
    pub const SIGSTKFLT: Self = Self::constant(16);
    pub const SIGCHLD: Self = Self::constant(17);
    pub const SIGCONT: Self = Self::constant(18);
    pub const SIGSTOP: Self = Self::constant(19);
    pub const SIGTSTP: Self = Self::constant(20);
    pub const SIGTTIN: Self = Self::constant(21);
    pub const SIGTTOU: Self = Self::constant(22);
    pub const SIGURG: Self = Self::constant(23);
    pub const SIGXCPU: Self = Self::constant(24);
    pub const SIGXFSZ: Self = Self::constant(25);
    pub const SIGVTALRM: Self = Self::constant(26);
    pub const SIGPROF: Self = Self::constant(27);
    pub const SIGWINCH: Self = Self::constant(28);
    pub const SIGIO: Self = Self::constant(29);
    pub const SIGPWR: Self = Self::constant(30);
    pub const SIGSYS: Self = Self::constant(31);

    const fn constant(raw: u8) -> Self {
        assert!(raw >= 1 && raw <= Self::MAX);
        match NonZeroU8::new(raw) {
            Some(value) => Self(value),
            None => unreachable!(),
        }
    }

    /// Constructs a signal in `1..=64`, returning `None` for `0` or `> 64`.
    pub const fn new(raw: u8) -> Option<Self> {
        if raw >= 1 && raw <= Self::MAX {
            match NonZeroU8::new(raw) {
                Some(value) => Some(Self(value)),
                None => None,
            }
        } else {
            None
        }
    }

    /// Constructs a standard signal in `1..=31`, returning `None` for `0` or
    /// `> 31`.
    pub const fn from_standard(raw: u8) -> Option<Self> {
        if raw >= 1 && raw <= Self::STANDARD_MAX {
            match NonZeroU8::new(raw) {
                Some(value) => Some(Self(value)),
                None => None,
            }
        } else {
            None
        }
    }

    pub const fn raw(self) -> u8 {
        self.0.get()
    }

    /// Single-bit mask `(1 << (signal - 1))` inside a 64-signal [`SignalSet`].
    pub const fn bit(self) -> u64 {
        1_u64 << (self.0.get() - 1)
    }

    /// Whether POSIX and Linux forbid catching, blocking, or ignoring this
    /// signal (`SIGKILL` and `SIGSTOP`, Linux `sig_kernel_only`).
    pub const fn is_uncatchable(self) -> bool {
        matches!(self.0.get(), 9 | 19)
    }

    /// Kernel default action when the signal's disposition is `SIG_DFL`
    /// (`signal(7)`).
    pub const fn default_action(self) -> DefaultSignalAction {
        match self.0.get() {
            17 | 23 | 28 => DefaultSignalAction::Ignore,
            18 => DefaultSignalAction::Continue,
            19..=22 => DefaultSignalAction::Stop,
            3..=8 | 11 | 24 | 25 | 31 => DefaultSignalAction::CoreDump,
            _ => DefaultSignalAction::Terminate,
        }
    }

    /// Resolves this signal against `disposition`, enforcing that
    /// [`Self::SIGKILL`] and [`Self::SIGSTOP`] always take their default
    /// action and folding default-ignored signals into
    /// [`ResolvedSignal::Ignore`].
    pub fn resolve<H>(self, disposition: SignalDisposition<H>) -> ResolvedSignal<H> {
        if self.is_uncatchable() {
            return ResolvedSignal::Default(self.default_action());
        }
        match disposition {
            SignalDisposition::Ignore => ResolvedSignal::Ignore,
            SignalDisposition::Catch(handler) => ResolvedSignal::Catch(handler),
            SignalDisposition::Default => match self.default_action() {
                DefaultSignalAction::Ignore => ResolvedSignal::Ignore,
                action => ResolvedSignal::Default(action),
            },
        }
    }
}

/// Default kernel action for a signal at `SIG_DFL` (`signal(7)`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DefaultSignalAction {
    /// Terminate the process.
    Terminate,
    /// Terminate the process and dump core when core limits permit.
    CoreDump,
    /// Discard the signal.
    Ignore,
    /// Continue the process if stopped, otherwise discard the signal.
    Continue,
    /// Stop the process.
    Stop,
}

/// Configured disposition of one signal, parameterized over the ABI's handler
/// representation `H`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SignalDisposition<H> {
    #[default]
    Default,
    Ignore,
    Catch(H),
}

/// Effective action produced by [`Signal::resolve`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResolvedSignal<H> {
    Ignore,
    Catch(H),
    Default(DefaultSignalAction),
}

/// Attempted to ignore or catch [`Signal::SIGKILL`] or [`Signal::SIGSTOP`].
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[error("signal {0} cannot be caught or ignored")]
pub struct UncatchableSignal(pub u8);

/// Per-signal disposition table covering signals `1..=64`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignalActions<H> {
    entries: [SignalDisposition<H>; Signal::MAX as usize],
}

impl<H> Default for SignalActions<H> {
    fn default() -> Self {
        Self::new()
    }
}

impl<H> SignalActions<H> {
    pub fn new() -> Self {
        Self {
            entries: core::array::from_fn(|_| SignalDisposition::Default),
        }
    }

    pub const fn get(&self, signal: Signal) -> &SignalDisposition<H> {
        &self.entries[(signal.raw() - 1) as usize]
    }

    /// Updates `signal`'s disposition and returns its previous one, refusing
    /// non-default dispositions on [`Signal::SIGKILL`] and [`Signal::SIGSTOP`].
    pub fn set(
        &mut self,
        signal: Signal,
        disposition: SignalDisposition<H>,
    ) -> Result<SignalDisposition<H>, UncatchableSignal> {
        if signal.is_uncatchable() && !matches!(disposition, SignalDisposition::Default) {
            return Err(UncatchableSignal(signal.raw()));
        }
        Ok(core::mem::replace(
            &mut self.entries[(signal.raw() - 1) as usize],
            disposition,
        ))
    }

    /// Resets caught handlers to [`SignalDisposition::Default`] while keeping
    /// [`SignalDisposition::Ignore`] intact, as POSIX `execve(2)` specifies.
    pub fn reset_caught_for_exec(&mut self) {
        for entry in &mut self.entries {
            if matches!(entry, SignalDisposition::Catch(_)) {
                *entry = SignalDisposition::Default;
            }
        }
    }
}

/// Bitmask of signals `1..=64`, where bit `s - 1` represents signal `s`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SignalSet(u64);

impl SignalSet {
    pub const EMPTY: Self = Self(0);
    pub const UNCATCHABLE: Self = Self(Signal::SIGKILL.bit() | Signal::SIGSTOP.bit());

    pub const fn from_bits(bits: u64) -> Self {
        Self(bits)
    }

    pub const fn bits(self) -> u64 {
        self.0
    }

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    pub const fn contains(self, signal: Signal) -> bool {
        (self.0 & signal.bit()) != 0
    }

    pub const fn with(self, signal: Signal) -> Self {
        Self(self.0 | signal.bit())
    }

    pub const fn without(self, signal: Signal) -> Self {
        Self(self.0 & !signal.bit())
    }

    pub fn insert(&mut self, signal: Signal) {
        self.0 |= signal.bit();
    }

    pub fn remove(&mut self, signal: Signal) -> bool {
        let present = self.contains(signal);
        self.0 &= !signal.bit();
        present
    }

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub const fn difference(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }

    /// Lowest-numbered signal present in the set, matching Linux `next_signal`
    /// delivery order.
    pub const fn first(self) -> Option<Signal> {
        if self.0 == 0 {
            None
        } else {
            Signal::new(self.0.trailing_zeros() as u8 + 1)
        }
    }

    /// Removes and returns the lowest-numbered signal present in the set.
    pub fn take_first(&mut self) -> Option<Signal> {
        let signal = self.first()?;
        self.remove(signal);
        Some(signal)
    }
}

/// Decision for one pending signal during [`SignalState::sweep_pending`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignalSweep {
    /// Clear the signal bit without returning it (an ignored signal).
    Drop,
    /// Keep the signal bit set in the mailbox (a blocked or deferred-handler
    /// signal).
    Retain,
    /// Clear and return this signal (the lowest-numbered `Take` wins).
    Take,
}

/// One signal mailbox: a process's, shared by every store of the process (its
/// threads' included), or one thread's, read only by that thread's store.
///
/// Pending signals are held as an atomic 64-bit [`SignalSet`] bitmask rather
/// than a single slot, so raising a second signal before a turn inspects the
/// mailbox retains both and delivers them in signal-number order. A thread's
/// mailbox also carries the end of its process ([`Self::end_thread`]), which
/// reaches the thread the way a signal does and stays owed from then on.
///
/// # Concurrency
///
/// - **Lock-free paths:** [`Self::raise`], [`Self::pending_set`],
///   [`Self::sweep_pending`], [`Self::take_pending`],
///   [`Self::take_pending_unmasked`], [`Self::end_thread`],
///   [`Self::thread_ended`], and the interval generation operations all act on
///   single atomics (`pending`, `thread_ended`, `interval_generation`), and
///   wakeup notifications go through the lock-free [`Notify::notify_all`]
///   broadcast. Any processor may raise concurrently; multiple turns sharing a
///   process mailbox claim pending bits via a compare-exchange loop, so no two
///   processors ever deliver the same raise twice and a concurrent `fetch_or`
///   raise of another signal is never lost.
/// - **Spin-locked path:** Naming or interrupting the execution target takes
///   [`Signals::target`]'s `spin::Mutex` briefly in task context to order
///   [`Self::attach`] against [`Self::deliver`], and never holds the guard
///   across `.await` or from an interrupt handler.
pub struct SignalState<T: InterruptTarget> {
    shared: Arc<Signals<T>>,
}

struct Signals<T: InterruptTarget> {
    pending: AtomicU64,
    /// Set once, when the process this thread belongs to has ended. It is a
    /// stop the thread's store owes its guest at every turn from then on, so
    /// it is read and never taken.
    thread_ended: AtomicBool,
    interval_generation: AtomicU64,
    /// Broadcast by every raise and by the thread's end, after either is
    /// stored, so a turn whose guest is suspended in a host call wakes
    /// immediately instead of waiting for the host call to resolve.
    raised: Notify,
    /// The execution target a raise interrupts, once a store of it exists.
    ///
    /// Raises come from host calls and timer tasks, never from an interrupt
    /// handler, so a spin lock is enough; it orders a raise against
    /// [`SignalState::attach`].
    target: Mutex<Option<T>>,
}

impl<T: InterruptTarget> SignalState<T> {
    pub fn new() -> Self {
        Self {
            shared: Arc::new(Signals {
                pending: AtomicU64::new(0),
                thread_ended: AtomicBool::new(false),
                interval_generation: AtomicU64::new(0),
                raised: Notify::new(),
                target: Mutex::new(None),
            }),
        }
    }

    /// Marks `signal` pending in the bitmask without overwriting any other
    /// pending signal, wakes suspended turns, and interrupts running stores.
    pub fn raise(&self, signal: Signal) {
        self.shared.pending.fetch_or(signal.bit(), Ordering::AcqRel);
        self.deliver();
    }

    /// Ends the thread whose mailbox this is, because its process ended: a
    /// running thread meets the end at its next interrupt check, which
    /// interrupting the process's stores makes immediate, and a suspended one
    /// through the turn that waits on `raised`, which drops the call it is
    /// suspended in (a parked `memory.atomic.wait` included).
    pub fn end_thread(&self) {
        self.shared.thread_ended.store(true, Ordering::Release);
        self.deliver();
    }

    /// Whether [`Self::end_thread`] has ended the thread.
    pub fn thread_ended(&self) -> bool {
        self.shared.thread_ended.load(Ordering::Acquire)
    }

    /// Snapshot of currently pending signals on this mailbox.
    pub fn pending_set(&self) -> SignalSet {
        SignalSet::from_bits(self.shared.pending.load(Ordering::Acquire))
    }

    /// Brings what was just stored to the stores that read this mailbox: wakes
    /// the turns whose guests are suspended and interrupts the running ones.
    fn deliver(&self) {
        self.shared.raised.notify_all();
        if let Some(target) = &*self.shared.target.lock() {
            target.interrupt();
        }
    }

    /// Names `target` as the execution target a raise interrupts. Every store
    /// of the process attaches when it is created; a replacement image
    /// attaches its own instance.
    ///
    /// A raise or an end that came before the target was named left its mark
    /// and interrupted nothing, so this interrupts on its behalf. The lock
    /// orders the two: one that takes it after this released it finds the
    /// target, and one that took it before had already stored its mark, which
    /// the loads below then see.
    pub fn attach(&self, target: T) {
        *self.shared.target.lock() = Some(target.clone());
        if !self.pending_set().is_empty() || self.thread_ended() {
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

    /// Atomically sweeps pending signals in ascending signal-number order:
    /// clears every signal `classify` marks [`SignalSweep::Drop`], leaves
    /// [`SignalSweep::Retain`] bits set, and clears and returns the first
    /// signal marked [`SignalSweep::Take`], if any.
    pub fn sweep_pending(&self, mut classify: impl FnMut(Signal) -> SignalSweep) -> Option<Signal> {
        let mut current = self.shared.pending.load(Ordering::Acquire);
        loop {
            if current == 0 {
                return None;
            }
            let mut remaining = SignalSet::from_bits(current);
            let mut clear = 0_u64;
            let mut chosen = None;
            while let Some(signal) = remaining.take_first() {
                match classify(signal) {
                    SignalSweep::Drop => clear |= signal.bit(),
                    SignalSweep::Retain => {}
                    SignalSweep::Take => {
                        clear |= signal.bit();
                        chosen = Some(signal);
                        break;
                    }
                }
            }
            if clear == 0 {
                return None;
            }
            match self.shared.pending.compare_exchange_weak(
                current,
                current & !clear,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return chosen,
                Err(actual) => current = actual,
            }
        }
    }

    /// Claims and returns the lowest-numbered pending signal, if any.
    pub fn take_pending(&self) -> Option<Signal> {
        self.sweep_pending(|_| SignalSweep::Take)
    }

    /// Claims and returns the lowest-numbered pending signal not in `blocked`,
    /// keeping blocked signals pending.
    pub fn take_pending_unmasked(&self, blocked: SignalSet) -> Option<Signal> {
        self.sweep_pending(|signal| {
            if blocked.contains(signal) {
                SignalSweep::Retain
            } else {
                SignalSweep::Take
            }
        })
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

#[cfg(test)]
mod tests {
    extern crate std;

    use core::sync::atomic::AtomicUsize;

    use super::*;

    #[derive(Clone, Default)]
    struct CountingInterruptTarget(Arc<AtomicUsize>);

    impl InterruptTarget for CountingInterruptTarget {
        fn interrupt(&self) {
            self.0.fetch_add(1, Ordering::AcqRel);
        }
    }

    #[test]
    fn signal_rejects_zero_and_out_of_range_numbers() {
        assert_eq!(Signal::new(0), None);
        assert_eq!(Signal::from_standard(0), None);
        assert_eq!(Signal::new(1), Some(Signal::SIGHUP));
        assert_eq!(Signal::from_standard(31), Some(Signal::SIGSYS));
        assert_eq!(Signal::from_standard(32), None);
        assert!(Signal::new(32).is_some());
        assert!(Signal::new(64).is_some());
        assert_eq!(Signal::new(65), None);
    }

    #[test]
    fn bitmask_retains_multiple_pending_signals_in_ascending_order() {
        let state = SignalState::<CountingInterruptTarget>::new();
        let target = CountingInterruptTarget::default();
        state.attach(target.clone());

        state.raise(Signal::SIGTERM);
        state.raise(Signal::SIGINT);
        state.raise(Signal::SIGUSR1);
        state.raise(Signal::SIGINT);
        assert_eq!(target.0.load(Ordering::Acquire), 4);
        assert!(state.pending_set().contains(Signal::SIGINT));
        assert!(state.pending_set().contains(Signal::SIGUSR1));
        assert!(state.pending_set().contains(Signal::SIGTERM));

        assert_eq!(state.take_pending(), Some(Signal::SIGINT));
        assert_eq!(state.take_pending(), Some(Signal::SIGUSR1));
        assert_eq!(state.take_pending(), Some(Signal::SIGTERM));
        assert_eq!(state.take_pending(), None);
    }

    #[test]
    fn sweep_pending_drops_ignored_retains_deferred_and_takes_fatal_past_retained() {
        let state = SignalState::<CountingInterruptTarget>::new();
        state.raise(Signal::SIGUSR1);
        state.raise(Signal::SIGCHLD);
        state.raise(Signal::SIGSTOP);

        let fatal = state.sweep_pending(|signal| match signal {
            Signal::SIGCHLD => SignalSweep::Drop,
            Signal::SIGUSR1 => SignalSweep::Retain,
            _ => SignalSweep::Take,
        });
        assert_eq!(fatal, Some(Signal::SIGSTOP));
        assert!(!state.pending_set().contains(Signal::SIGCHLD));
        assert!(
            state.pending_set().contains(Signal::SIGUSR1),
            "retained handler signal stays pending for a safe point"
        );
        assert_eq!(
            state.take_pending_unmasked(SignalSet::EMPTY.with(Signal::SIGUSR1)),
            None
        );
        assert_eq!(
            state.take_pending_unmasked(SignalSet::EMPTY),
            Some(Signal::SIGUSR1)
        );
    }

    #[test]
    fn dispositions_enforce_uncatchable_signals_default_actions_and_exec_reset() {
        let mut actions = SignalActions::<&'static str>::new();
        assert_eq!(
            actions.set(Signal::SIGKILL, SignalDisposition::Ignore),
            Err(UncatchableSignal(9))
        );
        assert_eq!(
            actions.set(Signal::SIGSTOP, SignalDisposition::Catch("handler")),
            Err(UncatchableSignal(19))
        );
        assert_eq!(
            Signal::SIGKILL.resolve::<()>(SignalDisposition::Ignore),
            ResolvedSignal::Default(DefaultSignalAction::Terminate)
        );
        assert_eq!(
            Signal::SIGSTOP.resolve(SignalDisposition::Catch("handler")),
            ResolvedSignal::Default(DefaultSignalAction::Stop)
        );
        assert_eq!(
            Signal::SIGCHLD.resolve::<()>(SignalDisposition::Default),
            ResolvedSignal::Ignore
        );
        assert_eq!(
            Signal::SIGURG.resolve::<()>(SignalDisposition::Default),
            ResolvedSignal::Ignore
        );
        assert_eq!(
            Signal::SIGWINCH.resolve::<()>(SignalDisposition::Default),
            ResolvedSignal::Ignore
        );
        assert_eq!(
            Signal::SIGCONT.resolve::<()>(SignalDisposition::Default),
            ResolvedSignal::Default(DefaultSignalAction::Continue)
        );

        actions
            .set(Signal::SIGINT, SignalDisposition::Ignore)
            .expect("SIGINT can be ignored");
        actions
            .set(Signal::SIGUSR1, SignalDisposition::Catch("on_usr1"))
            .expect("SIGUSR1 can be caught");
        assert_eq!(
            Signal::SIGINT.resolve(*actions.get(Signal::SIGINT)),
            ResolvedSignal::Ignore
        );
        assert_eq!(
            Signal::SIGUSR1.resolve(*actions.get(Signal::SIGUSR1)),
            ResolvedSignal::Catch("on_usr1")
        );

        actions.reset_caught_for_exec();
        assert_eq!(*actions.get(Signal::SIGINT), SignalDisposition::Ignore);
        assert_eq!(*actions.get(Signal::SIGUSR1), SignalDisposition::Default);
    }

    #[test]
    fn concurrent_raises_and_takers_deliver_each_distinct_signal_exactly_once() {
        let state = SignalState::<CountingInterruptTarget>::new();
        let delivered = AtomicU64::new(0);
        let duplicates = AtomicUsize::new(0);

        std::thread::scope(|scope| {
            for sig in 1_u8..=64 {
                let sender = state.clone();
                scope.spawn(move || {
                    sender.raise(Signal::new(sig).unwrap());
                });
            }
            for _ in 0..4 {
                let receiver = state.clone();
                let delivered = &delivered;
                let duplicates = &duplicates;
                scope.spawn(move || {
                    while delivered.load(Ordering::Acquire) != u64::MAX {
                        if let Some(sig) = receiver.take_pending() {
                            let prev = delivered.fetch_or(sig.bit(), Ordering::AcqRel);
                            if (prev & sig.bit()) != 0 {
                                duplicates.fetch_add(1, Ordering::AcqRel);
                            }
                        } else {
                            std::thread::yield_now();
                        }
                    }
                });
            }
        });

        assert_eq!(delivered.load(Ordering::Acquire), u64::MAX);
        assert_eq!(duplicates.load(Ordering::Acquire), 0);
        assert!(state.pending_set().is_empty());
    }
}
