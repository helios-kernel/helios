//! Linux signals, signal delivery, alternate stacks, and interval timers
//! (`rt_sigaction`, `rt_sigprocmask`, `rt_sigpending`, `rt_sigsuspend`,
//! `rt_sigtimedwait`, `rt_sigreturn`, `sigaltstack`, `kill`, `tkill`,
//! `tgkill`, `pause`, `alarm`, `getitimer`, `setitimer`).
//!
//! Semantics follow Linux v6.12 (`kernel/signal.c`, `kernel/time/itimer.c`,
//! `signal(7)`), built over `helios_unix`'s shared [`Signal`], [`SignalSet`],
//! [`SignalDisposition`], and [`SignalActions`].
//!
//! # Concurrency contract
//!
//! - [`ProcessSignals`] is shared across every thread of one process and
//!   referenced by its container's [`PidNamespace`] for container-local
//!   `kill`/`tkill`/`tgkill`.
//! - Hot-path queries (`has_deliverable_signal`, `current_mask`, `is_stopped`)
//!   use single atomic loads without taking any lock.
//! - Internal spin locks (`actions`, `shared_pending`, `threads`,
//!   `ThreadSignalSlot::private_pending`, `timers`) are strictly short
//!   synchronous critical sections never held across an `.await`. When more
//!   than one lock is acquired, the order is always `actions` ->
//!   `shared_pending` -> `threads` -> `private_pending`; `timers` is a leaf
//!   lock.
//! - Wakeups go through lock-free [`Notify::notify_all`] after every spin lock
//!   is dropped.

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::future::{Future, poll_fn};
use core::num::NonZeroU32;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use core::task::{Context, Poll};

use helios_hal::native::{UserContext, UserFault};
use helios_sync::{Notify, NotifyWaiter};
use helios_unix::{
    DefaultSignalAction, ResolvedSignal, Signal, SignalActions, SignalDisposition, SignalSet,
};
use spin::Mutex;

use super::io::Clock;
use super::system::{CAP_KILL, Credentials};
use super::{
    EAGAIN, EFAULT, EINTR, EINVAL, ENOMEM, EPERM, ESRCH, PidNamespace, SyscallOutcome, UserMemory,
    errno,
};
use crate::abi::Abi;
use crate::signal_frame::{
    self, BUS_ADRERR, FrameDeliveryInput, SA_NOCLDSTOP, SA_NOCLDWAIT, SA_NODEFER, SA_RESETHAND,
    SA_RESTART, SIGINFO_SIZE, SS_AUTODISARM, SS_DISABLE, SS_ONSTACK, STACK_T_SIZE, SigAltStack,
    SigInfo, SigInfoPayload, SignalFrameError,
};

// Linux UAPI constants (`include/uapi/asm-generic/signal-defs.h`,
// `include/uapi/linux/time.h`).
const SIG_DFL: u64 = 0;
const SIG_IGN: u64 = 1;
const SIG_BLOCK: u32 = 0;
const SIG_UNBLOCK: u32 = 1;
const SIG_SETMASK: u32 = 2;
const SIGSET_BYTES: u64 = 8;
const KERNEL_SIGACTION_BYTES: usize = 32;
const ITIMERVAL_BYTES: usize = 32;
const TIMESPEC_BYTES: usize = 16;
const NANOS_PER_SEC: u64 = 1_000_000_000;
const NANOS_PER_USEC: u64 = 1_000;
const USECS_PER_SEC: i64 = 1_000_000;
const ITIMER_REAL: i32 = 0;
const ITIMER_VIRTUAL: i32 = 1;
const ITIMER_PROF: i32 = 2;
/// Cap on queued real-time signals per queue (standard Linux default RLIMIT_SIGPENDING bound).
const MAX_RT_QUEUED: usize = 1024;

/// Caught handler configuration stored in `SignalActions<LinuxHandler>`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LinuxHandler {
    pub handler: u64,
    pub flags: u64,
    pub restorer: u64,
    pub mask: SignalSet,
}

/// Extra `sigaction` fields preserved for `SIG_DFL` / `SIG_IGN` entries so
/// `rt_sigaction(sig, NULL, &oldact)` round-trips `sa_flags`, `sa_restorer`,
/// and `sa_mask` identically to Linux `struct k_sigaction`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct ActionMeta {
    flags: u64,
    restorer: u64,
    mask: SignalSet,
}

struct ActionsState {
    dispositions: SignalActions<LinuxHandler>,
    meta: [ActionMeta; Signal::MAX as usize],
}

impl ActionsState {
    fn new() -> Self {
        Self {
            dispositions: SignalActions::new(),
            meta: [ActionMeta::default(); Signal::MAX as usize],
        }
    }

    fn read_raw(&self, signal: Signal) -> [u8; KERNEL_SIGACTION_BYTES] {
        let index = (signal.raw() - 1) as usize;
        let (handler, flags, restorer, mask) = match self.dispositions.get(signal) {
            SignalDisposition::Default => {
                let m = self.meta[index];
                (SIG_DFL, m.flags, m.restorer, m.mask)
            }
            SignalDisposition::Ignore => {
                let m = self.meta[index];
                (SIG_IGN, m.flags, m.restorer, m.mask)
            }
            SignalDisposition::Catch(action) => {
                (action.handler, action.flags, action.restorer, action.mask)
            }
        };
        let mut bytes = [0u8; KERNEL_SIGACTION_BYTES];
        bytes[0..8].copy_from_slice(&handler.to_le_bytes());
        bytes[8..16].copy_from_slice(&flags.to_le_bytes());
        bytes[16..24].copy_from_slice(&restorer.to_le_bytes());
        bytes[24..32].copy_from_slice(&mask.bits().to_le_bytes());
        bytes
    }

    fn resolved(&self, signal: Signal) -> ResolvedSignal<LinuxHandler> {
        signal.resolve(*self.dispositions.get(signal))
    }

    fn is_ignored(&self, signal: Signal) -> bool {
        matches!(self.resolved(signal), ResolvedSignal::Ignore)
    }

    fn set_raw(&mut self, signal: Signal, bytes: &[u8; KERNEL_SIGACTION_BYTES]) -> bool {
        let handler = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        let flags = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
        let restorer = u64::from_le_bytes(bytes[16..24].try_into().unwrap());
        let mask = SignalSet::from_bits(u64::from_le_bytes(bytes[24..32].try_into().unwrap()))
            .without_uncatchable();
        let disposition = match handler {
            SIG_DFL => SignalDisposition::Default,
            SIG_IGN => SignalDisposition::Ignore,
            _ => SignalDisposition::Catch(LinuxHandler {
                handler,
                flags,
                restorer,
                mask,
            }),
        };
        let index = (signal.raw() - 1) as usize;
        self.meta[index] = ActionMeta {
            flags,
            restorer,
            mask,
        };
        self.dispositions
            .set(signal, disposition)
            .expect("uncatchable signals rejected before ActionsState::set_raw");
        self.is_ignored(signal)
    }

    fn reset_to_default(&mut self, signal: Signal) {
        let index = (signal.raw() - 1) as usize;
        self.meta[index] = ActionMeta::default();
        let _ = self.dispositions.set(signal, SignalDisposition::Default);
    }

    fn clone_state(&self) -> Self {
        Self {
            dispositions: self.dispositions.clone(),
            meta: self.meta,
        }
    }

    fn reset_for_exec(&mut self) {
        for raw in 1..=Signal::MAX {
            let sig = Signal::new(raw).expect("1..=64 is valid");
            if matches!(self.dispositions.get(sig), SignalDisposition::Catch(_)) {
                self.reset_to_default(sig);
            }
        }
    }

    fn ignored_signals(&self) -> Vec<Signal> {
        let mut out = Vec::new();
        for raw in 1..=Signal::MAX {
            let sig = Signal::new(raw).expect("1..=64 is valid");
            if matches!(self.dispositions.get(sig), SignalDisposition::Ignore) {
                out.push(sig);
            }
        }
        out
    }

    fn sigchld_auto_reap(&self) -> bool {
        let index = (Signal::SIGCHLD.raw() - 1) as usize;
        matches!(
            self.dispositions.get(Signal::SIGCHLD),
            SignalDisposition::Ignore
        ) || (self.meta[index].flags & SA_NOCLDWAIT != 0)
    }

    fn sigchld_nocldstop(&self) -> bool {
        let index = (Signal::SIGCHLD.raw() - 1) as usize;
        self.meta[index].flags & SA_NOCLDSTOP != 0
    }
}

/// Standard coalesced signals (`1..=31`) plus queued FIFO real-time signals
/// (`32..=64`), matching Linux `struct sigpending`.
struct PendingQueue {
    standard_bits: SignalSet,
    standard_info: [Option<SigInfo>; Signal::STANDARD_MAX as usize],
    rt_queue: VecDeque<SigInfo>,
}

impl PendingQueue {
    const fn new() -> Self {
        Self {
            standard_bits: SignalSet::EMPTY,
            standard_info: [None; Signal::STANDARD_MAX as usize],
            rt_queue: VecDeque::new(),
        }
    }

    fn bits(&self) -> SignalSet {
        let mut bits = self.standard_bits;
        for info in &self.rt_queue {
            bits.insert(info.signo);
        }
        bits
    }

    fn push(&mut self, info: SigInfo) -> bool {
        if info.signo.is_realtime() {
            if self.rt_queue.len() >= MAX_RT_QUEUED {
                return false;
            }
            self.rt_queue.push_back(info);
            true
        } else {
            let index = (info.signo.raw() - 1) as usize;
            if self.standard_bits.contains(info.signo) {
                return false;
            }
            self.standard_bits.insert(info.signo);
            self.standard_info[index] = Some(info);
            true
        }
    }

    /// Removes and returns the lowest-numbered pending signal present in
    /// `wanted` (`kernel/signal.c` `next_signal`).
    fn take_matching(&mut self, wanted: SignalSet) -> Option<SigInfo> {
        let std_ready = self.standard_bits.intersection(wanted);
        if let Some(sig) = std_ready.first() {
            self.standard_bits.remove(sig);
            let index = (sig.raw() - 1) as usize;
            return self.standard_info[index].take();
        }
        let mut best: Option<(usize, u8)> = None;
        for (idx, info) in self.rt_queue.iter().enumerate() {
            if wanted.contains(info.signo) {
                let raw = info.signo.raw();
                if best.is_none_or(|(_, best_raw)| raw < best_raw) {
                    best = Some((idx, raw));
                }
            }
        }
        best.and_then(|(idx, _)| self.rt_queue.remove(idx))
    }

    fn discard(&mut self, signal: Signal) {
        if signal.is_realtime() {
            self.rt_queue.retain(|info| info.signo != signal);
        } else {
            self.standard_bits.remove(signal);
            self.standard_info[(signal.raw() - 1) as usize] = None;
        }
    }
}

#[derive(Default)]
struct IntervalTimers {
    /// `ITIMER_REAL`: monotonic deadline in nanoseconds when armed.
    real_deadline_ns: Option<u64>,
    real_interval_ns: u64,
    real_generation: u64,
    /// `ITIMER_VIRTUAL`: remaining user CPU time in nanoseconds.
    virtual_remaining_ns: u64,
    virtual_interval_ns: u64,
    /// `ITIMER_PROF`: remaining total (user + kernel) CPU time in nanoseconds.
    prof_remaining_ns: u64,
    prof_interval_ns: u64,
}

/// Process-wide signal state shared by all threads in a Linux thread group.
///
/// The disposition table (`actions`) is separately reference-counted so
/// `clone(CLONE_SIGHAND)` without `CLONE_THREAD` shares only dispositions
/// while keeping distinct `tgid`, pending mailboxes, stop state, and timers,
/// and unshares the table on `execve` (`fs/exec.c` `unshare_sighand`).
pub struct ProcessSignals {
    tgid: NonZeroU32,
    pgid: AtomicU32,
    actions: Mutex<Arc<Mutex<ActionsState>>>,
    shared_pending: Mutex<PendingQueue>,
    shared_bits: AtomicU64,
    threads: Mutex<Vec<Arc<ThreadSignalSlot>>>,
    stopped: AtomicBool,
    stop_notify: Notify,
    timers: Mutex<IntervalTimers>,
    real_timer_notify: Notify,
}

impl ProcessSignals {
    pub fn new(tgid: NonZeroU32) -> Arc<Self> {
        Arc::new(Self {
            tgid,
            pgid: AtomicU32::new(tgid.get()),
            actions: Mutex::new(Arc::new(Mutex::new(ActionsState::new()))),
            shared_pending: Mutex::new(PendingQueue::new()),
            shared_bits: AtomicU64::new(0),
            threads: Mutex::new(Vec::new()),
            stopped: AtomicBool::new(false),
            stop_notify: Notify::new(),
            timers: Mutex::new(IntervalTimers::default()),
            real_timer_notify: Notify::new(),
        })
    }

    fn actions_handle(&self) -> Arc<Mutex<ActionsState>> {
        self.actions.lock().clone()
    }

    pub const fn tgid(&self) -> NonZeroU32 {
        self.tgid
    }

    pub fn pgid(&self) -> u32 {
        self.pgid.load(Ordering::Acquire)
    }

    pub fn set_pgid(&self, pgid: u32) {
        self.pgid.store(pgid, Ordering::Release);
    }

    /// Creates a child process's signal state for `fork`/`clone`: inherits
    /// `pgid` and signal dispositions (sharing the table when `share_sighand`
    /// is set, or resetting to defaults when `clear_sighand` is set), while
    /// always giving the child its own `tgid`, empty pending queues, stop
    /// state, and disarmed interval timers (`kernel/fork.c`).
    pub(super) fn clone_for_fork(
        &self,
        child_tgid: NonZeroU32,
        share_sighand: bool,
        clear_sighand: bool,
    ) -> Arc<Self> {
        let actions = if share_sighand {
            self.actions_handle()
        } else if clear_sighand {
            Arc::new(Mutex::new(ActionsState::new()))
        } else {
            let snapshot = self.actions_handle().lock().clone_state();
            Arc::new(Mutex::new(snapshot))
        };
        Arc::new(Self {
            tgid: child_tgid,
            pgid: AtomicU32::new(self.pgid()),
            actions: Mutex::new(actions),
            shared_pending: Mutex::new(PendingQueue::new()),
            shared_bits: AtomicU64::new(0),
            threads: Mutex::new(Vec::new()),
            stopped: AtomicBool::new(false),
            stop_notify: Notify::new(),
            timers: Mutex::new(IntervalTimers::default()),
            real_timer_notify: Notify::new(),
        })
    }

    /// Applies POSIX `execve` signal-disposition reset: unshares the
    /// disposition table if shared via `CLONE_SIGHAND` (`fs/exec.c`
    /// `unshare_sighand`), resets caught handlers to `SIG_DFL` while keeping
    /// `SIG_IGN` dispositions ignored (`kernel/signal.c`
    /// `flush_signal_handlers`), and disarms CPU interval timers.
    pub fn reset_for_exec(&self) {
        {
            let mut slot = self.actions.lock();
            if Arc::strong_count(&slot) > 1 {
                let mut unshared = slot.lock().clone_state();
                unshared.reset_for_exec();
                *slot = Arc::new(Mutex::new(unshared));
            } else {
                slot.lock().reset_for_exec();
            }
        }
        self.stopped.store(false, Ordering::Release);
        {
            let mut timers = self.timers.lock();
            timers.virtual_remaining_ns = 0;
            timers.virtual_interval_ns = 0;
            timers.prof_remaining_ns = 0;
            timers.prof_interval_ns = 0;
        }
    }

    /// Signals currently set to `SIG_IGN` (carried across `execve` into a
    /// WASIX/Wasm replacement image).
    pub fn ignored_signals(&self) -> Vec<Signal> {
        self.actions_handle().lock().ignored_signals()
    }

    /// Whether exiting children should be auto-reaped without becoming zombies
    /// (`SIGCHLD` ignored or `SA_NOCLDWAIT`).
    pub(super) fn sigchld_auto_reap(&self) -> bool {
        self.actions_handle().lock().sigchld_auto_reap()
    }

    /// Whether child stop/continue notifications are suppressed (`SA_NOCLDSTOP`).
    pub(super) fn sigchld_nocldstop(&self) -> bool {
        self.actions_handle().lock().sigchld_nocldstop()
    }

    pub fn is_stopped(&self) -> bool {
        self.stopped.load(Ordering::Acquire)
    }

    pub fn stop_waiter(&self) -> NotifyWaiter {
        self.stop_notify.waiter()
    }

    pub fn poll_stop_changed(&self, cx: &mut Context<'_>, wait: &mut NotifyWaiter) -> Poll<()> {
        self.stop_notify.poll_notified(cx, wait)
    }

    pub fn real_timer_waiter(&self) -> NotifyWaiter {
        self.real_timer_notify.waiter()
    }

    pub fn poll_real_timer_changed(
        &self,
        cx: &mut Context<'_>,
        wait: &mut NotifyWaiter,
    ) -> Poll<()> {
        self.real_timer_notify.poll_notified(cx, wait)
    }

    /// Returns `(deadline_ns, generation)` of the active `ITIMER_REAL` timer,
    /// if armed.
    pub fn next_real_timer_deadline(&self) -> Option<(u64, u64)> {
        let timers = self.timers.lock();
        timers
            .real_deadline_ns
            .map(|deadline| (deadline, timers.real_generation))
    }

    /// Fires `ITIMER_REAL` if its deadline has passed at `now_ns`, reloading
    /// `it_interval` when non-zero and raising `SIGALRM`.
    pub fn fire_real_timer_if_due(&self, now_ns: u64) -> bool {
        let fired = {
            let mut timers = self.timers.lock();
            if let Some(deadline) = timers.real_deadline_ns
                && now_ns >= deadline
            {
                let elapsed = now_ns - deadline;
                if let Some(periods) = elapsed.checked_div(timers.real_interval_ns).map(|q| q + 1) {
                    // Advance past any missed intervals so periodic timers
                    // stay phase-aligned without spinning on catch-up.
                    timers.real_deadline_ns = Some(
                        deadline.saturating_add(periods.saturating_mul(timers.real_interval_ns)),
                    );
                } else {
                    timers.real_deadline_ns = None;
                }
                true
            } else {
                false
            }
        };
        if fired {
            self.raise_process(SigInfo::from_timer(Signal::SIGALRM));
        }
        fired
    }

    /// Advances `ITIMER_VIRTUAL` by `user_ns` and `ITIMER_PROF` by `total_ns`,
    /// raising `SIGVTALRM` and `SIGPROF` on expiry (`kernel/time/itimer.c`).
    pub fn account_cpu_timers(&self, user_ns: u64, total_ns: u64) {
        if user_ns == 0 && total_ns == 0 {
            return;
        }
        let (fire_virtual, fire_prof) = {
            let mut timers = self.timers.lock();
            let mut v_fired = false;
            if timers.virtual_remaining_ns > 0 && user_ns > 0 {
                if user_ns >= timers.virtual_remaining_ns {
                    v_fired = true;
                    timers.virtual_remaining_ns = timers.virtual_interval_ns;
                } else {
                    timers.virtual_remaining_ns -= user_ns;
                }
            }
            let mut p_fired = false;
            if timers.prof_remaining_ns > 0 && total_ns > 0 {
                if total_ns >= timers.prof_remaining_ns {
                    p_fired = true;
                    timers.prof_remaining_ns = timers.prof_interval_ns;
                } else {
                    timers.prof_remaining_ns -= total_ns;
                }
            }
            (v_fired, p_fired)
        };
        if fire_virtual {
            self.raise_process(SigInfo::from_timer(Signal::SIGVTALRM));
        }
        if fire_prof {
            self.raise_process(SigInfo::from_timer(Signal::SIGPROF));
        }
    }

    /// Registers a new thread's signal slot with this process.
    pub fn register_thread(
        self: &Arc<Self>,
        tid: NonZeroU32,
        inherited_mask: SignalSet,
    ) -> Arc<ThreadSignalSlot> {
        let slot = Arc::new(ThreadSignalSlot {
            tid,
            process: self.clone(),
            private_pending: Mutex::new(PendingQueue::new()),
            private_bits: AtomicU64::new(0),
            mask: AtomicU64::new(inherited_mask.without_uncatchable().bits()),
            saved_mask: Mutex::new(None),
            altstack: Mutex::new(SigAltStack::disabled()),
            sigtimedwait_set: AtomicU64::new(0),
            wake_notify: Notify::new(),
        });
        self.threads.lock().push(slot.clone());
        slot
    }

    /// Removes an exiting thread's slot from the process thread list.
    pub fn unregister_thread(&self, tid: NonZeroU32) {
        self.threads.lock().retain(|slot| slot.tid != tid);
    }

    /// Enqueues an externally raised signal (for example from a parent WASIX
    /// process or owner kill) into this process's shared signal mailbox.
    pub fn raise_external(&self, signal: Signal) {
        let _ = self.raise_process(SigInfo::from_kill(signal, 0, 0));
    }

    /// Enqueues a process-directed signal (`kill`, interval timers, external
    /// signals) and wakes an eligible thread (`kernel/signal.c`
    /// `__send_signal_locked` / `complete_signal`). Returns `true` when
    /// `SIGCONT` resumed a stopped process.
    pub fn raise_process(&self, info: SigInfo) -> bool {
        let signal = info.signo;
        let resumed = self.apply_stop_continue_side_effects(signal);

        let is_ignored = self.actions_handle().lock().is_ignored(signal);
        let to_wake = {
            let mut pending = self.shared_pending.lock();
            let threads = self.threads.lock();
            if is_ignored && !signal.is_uncatchable() {
                // Linux `sig_ignored`: discard unblocked ignored signals unless
                // some thread has it masked or is waiting for it in sigtimedwait.
                let any_blocked_or_waiting = threads.iter().any(|slot| {
                    slot.current_mask().contains(signal)
                        || SignalSet::from_bits(slot.sigtimedwait_set.load(Ordering::Acquire))
                            .contains(signal)
                });
                if !any_blocked_or_waiting {
                    return resumed;
                }
            }
            pending.push(info);
            self.shared_bits
                .store(pending.bits().bits(), Ordering::Release);

            let mut wake_list: Vec<Arc<ThreadSignalSlot>> = Vec::new();
            if signal == Signal::SIGKILL {
                wake_list.extend(threads.iter().cloned());
            } else {
                // First prefer a thread actively waiting for this signal in
                // `rt_sigtimedwait`, then any thread that does not block it.
                if let Some(waiter) = threads.iter().find(|slot| {
                    SignalSet::from_bits(slot.sigtimedwait_set.load(Ordering::Acquire))
                        .contains(signal)
                }) {
                    wake_list.push(waiter.clone());
                } else if !is_ignored
                    && let Some(target) = threads
                        .iter()
                        .find(|slot| !slot.current_mask().contains(signal))
                {
                    wake_list.push(target.clone());
                }
            }
            wake_list
        };

        if signal == Signal::SIGKILL {
            self.stopped.store(false, Ordering::Release);
            self.stop_notify.notify_all();
        }
        for slot in to_wake {
            slot.wake_notify.notify_all();
        }
        resumed
    }

    /// Enqueues a thread-directed signal (`tkill`, `tgkill`, `SIGPIPE`).
    /// Returns `true` when `SIGCONT` resumed a stopped process.
    pub fn raise_thread(&self, target: &ThreadSignalSlot, info: SigInfo) -> bool {
        let signal = info.signo;
        let resumed = self.apply_stop_continue_side_effects(signal);

        let is_ignored = self.actions_handle().lock().is_ignored(signal);
        let waiting_for =
            SignalSet::from_bits(target.sigtimedwait_set.load(Ordering::Acquire)).contains(signal);
        let masked = target.current_mask().contains(signal);
        if is_ignored && !signal.is_uncatchable() && !masked && !waiting_for {
            return resumed;
        }
        {
            let mut pending = target.private_pending.lock();
            pending.push(info);
            target
                .private_bits
                .store(pending.bits().bits(), Ordering::Release);
        }
        if signal == Signal::SIGKILL {
            self.stopped.store(false, Ordering::Release);
            self.stop_notify.notify_all();
            let threads = self.threads.lock().clone();
            for slot in threads {
                slot.wake_notify.notify_all();
            }
        } else if waiting_for || (!masked && !is_ignored) {
            target.wake_notify.notify_all();
        }
        resumed
    }

    fn apply_stop_continue_side_effects(&self, signal: Signal) -> bool {
        if signal == Signal::SIGCONT {
            let was_stopped = self.stopped.swap(false, Ordering::AcqRel);
            self.discard_pending_everywhere(Signal::SIGSTOP);
            self.discard_pending_everywhere(Signal::SIGTSTP);
            self.discard_pending_everywhere(Signal::SIGTTIN);
            self.discard_pending_everywhere(Signal::SIGTTOU);
            self.stop_notify.notify_all();
            was_stopped
        } else if matches!(
            signal,
            Signal::SIGSTOP | Signal::SIGTSTP | Signal::SIGTTIN | Signal::SIGTTOU
        ) {
            self.discard_pending_everywhere(Signal::SIGCONT);
            false
        } else {
            false
        }
    }

    fn discard_pending_everywhere(&self, signal: Signal) {
        let mut shared = self.shared_pending.lock();
        shared.discard(signal);
        self.shared_bits
            .store(shared.bits().bits(), Ordering::Release);
        let threads = self.threads.lock();
        for slot in threads.iter() {
            let mut private = slot.private_pending.lock();
            private.discard(signal);
            slot.private_bits
                .store(private.bits().bits(), Ordering::Release);
        }
    }

    fn shared_pending_bits(&self) -> SignalSet {
        SignalSet::from_bits(self.shared_bits.load(Ordering::Acquire))
    }

    fn take_shared_matching(&self, wanted: SignalSet) -> Option<SigInfo> {
        let mut pending = self.shared_pending.lock();
        let taken = pending.take_matching(wanted);
        if taken.is_some() {
            self.shared_bits
                .store(pending.bits().bits(), Ordering::Release);
        }
        taken
    }
}

/// Per-thread signal mask, private pending queue, alternate stack, and wait
/// state (`kernel/signal.c`).
pub struct ThreadSignalSlot {
    tid: NonZeroU32,
    process: Arc<ProcessSignals>,
    private_pending: Mutex<PendingQueue>,
    private_bits: AtomicU64,
    mask: AtomicU64,
    /// Original mask saved by `rt_sigsuspend`, `epoll_pwait`, or `ppoll`
    /// (`TIF_RESTORE_SIGMASK`).
    saved_mask: Mutex<Option<SignalSet>>,
    altstack: Mutex<SigAltStack>,
    /// Signals this thread is actively awaiting in `rt_sigtimedwait`.
    sigtimedwait_set: AtomicU64,
    wake_notify: Notify,
}

impl ThreadSignalSlot {
    pub const fn tid(&self) -> NonZeroU32 {
        self.tid
    }

    pub fn process(&self) -> &Arc<ProcessSignals> {
        &self.process
    }

    pub fn current_mask(&self) -> SignalSet {
        SignalSet::from_bits(self.mask.load(Ordering::Acquire))
    }

    pub fn set_mask(&self, mask: SignalSet) {
        self.mask
            .store(mask.without_uncatchable().bits(), Ordering::Release);
    }

    pub fn pending_set(&self) -> SignalSet {
        let private = SignalSet::from_bits(self.private_bits.load(Ordering::Acquire));
        private.union(self.process.shared_pending_bits())
    }

    /// Installs a temporary signal mask while preserving the caller's original
    /// mask (`TIF_RESTORE_SIGMASK`) for `rt_sigsuspend`, `epoll_pwait`, and
    /// `ppoll`.
    pub fn push_temp_mask(&self, temp_mask: SignalSet) {
        let original = self.current_mask();
        *self.saved_mask.lock() = Some(original);
        self.set_mask(temp_mask);
    }

    /// Restores the saved signal mask if `push_temp_mask` was active and the
    /// syscall completed without handing off to signal delivery.
    pub fn restore_temp_mask(&self) {
        if let Some(original) = self.saved_mask.lock().take() {
            self.set_mask(original);
        }
    }

    /// Fast lock-free check for whether any unmasked, non-ignored signal is
    /// currently pending for this thread. Drops unmasked ignored signals that
    /// were queued while blocked.
    pub fn has_deliverable_signal(&self) -> bool {
        let unmasked = self.pending_set().difference(self.current_mask());
        if unmasked.is_empty() {
            return false;
        }
        // Fast path found at least one unmasked pending bit; check dispositions
        // so an ignored signal that was queued while blocked does not falsely
        // interrupt a blocking syscall.
        let mut remaining = unmasked;
        while let Some(signal) = remaining.take_first() {
            let ignored = self.process.actions_handle().lock().is_ignored(signal);
            if ignored && !signal.is_uncatchable() {
                let single = SignalSet::EMPTY.with(signal);
                let _ = self.take_private_matching(single);
                let _ = self.process.take_shared_matching(single);
                continue;
            }
            return true;
        }
        false
    }

    /// Asynchronously waits until this thread has a deliverable unmasked signal.
    pub async fn wait_deliverable(&self) {
        loop {
            let mut wait = self.wake_notify.waiter();
            if self.has_deliverable_signal() {
                return;
            }
            poll_fn(|cx| self.wake_notify.poll_notified(cx, &mut wait)).await;
        }
    }

    /// Races `future` against arrival of a deliverable signal for this thread.
    /// Ready I/O / timer completion wins over a concurrent signal.
    pub(super) async fn interruptible<F: Future>(&self, future: F) -> WaitOutcome<F::Output> {
        let mut future = core::pin::pin!(future);
        let mut signal_wait = core::pin::pin!(self.wait_deliverable());
        poll_fn(|cx| {
            if let Poll::Ready(output) = future.as_mut().poll(cx) {
                return Poll::Ready(WaitOutcome::Ready(output));
            }
            if signal_wait.as_mut().poll(cx).is_ready() {
                return Poll::Ready(WaitOutcome::Interrupted);
            }
            Poll::Pending
        })
        .await
    }

    fn take_private_matching(&self, wanted: SignalSet) -> Option<SigInfo> {
        let mut pending = self.private_pending.lock();
        let taken = pending.take_matching(wanted);
        if taken.is_some() {
            self.private_bits
                .store(pending.bits().bits(), Ordering::Release);
        }
        taken
    }

    pub(super) fn clone_altstack(&self) -> SigAltStack {
        *self.altstack.lock()
    }

    pub(super) fn set_altstack(&self, alt: SigAltStack) {
        *self.altstack.lock() = alt;
    }

    pub(super) fn reset_for_exec(&self) {
        *self.altstack.lock() = SigAltStack::disabled();
        *self.saved_mask.lock() = None;
    }

    /// Takes the next pending signal matching `wanted` (used by the kernel to
    /// forward container signals into a Wasm/WASIX replacement image).
    pub fn take_pending_signal(&self) -> Option<Signal> {
        self.take_any_matching(SignalSet::EMPTY.complement())
            .map(|info| info.signo)
    }

    /// Arms a wakeup waiter on this thread's signal mailbox.
    pub fn signal_waiter(&self) -> NotifyWaiter {
        self.wake_notify.waiter()
    }

    /// Polls this thread's signal wakeup waiter.
    pub fn poll_signal_waiter(&self, cx: &mut Context<'_>, waiter: &mut NotifyWaiter) -> Poll<()> {
        self.wake_notify.poll_notified(cx, waiter)
    }

    fn take_any_matching(&self, wanted: SignalSet) -> Option<SigInfo> {
        // Thread-private signals take precedence over process-shared signals
        // (`kernel/signal.c` `dequeue_signal`).
        self.take_private_matching(wanted)
            .or_else(|| self.process.take_shared_matching(wanted))
    }
}

/// Result of [`ThreadSignalSlot::interruptible`].
pub(super) enum WaitOutcome<T> {
    Ready(T),
    Interrupted,
}

/// Context saved when a blocking syscall was interrupted by a signal, telling
/// [`deliver_pending_signals`] whether `SA_RESTART` may restart it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyscallRestart {
    /// Linux `-ERESTARTSYS`: restart if the handler has `SA_RESTART` or if no
    /// handler runs; otherwise return `-EINTR`.
    RestartSys { orig_reg: u64 },
    /// Linux `-ERESTARTNOHAND`: return `-EINTR` if any handler runs; restart
    /// only if no handler runs (e.g. ignored or stopped-and-continued).
    RestartNoHand { orig_reg: u64 },
}

/// Outcome of checking and delivering pending signals before returning to user
/// mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignalDelivery {
    /// No deliverable signal remained; user execution resumes normally.
    None,
    /// A signal handler frame was constructed on the user stack and `context`
    /// now points at the handler.
    Delivered,
    /// A default stop signal (`SIGSTOP`/`SIGTSTP`/`SIGTTIN`/`SIGTTOU`) stopped
    /// the process; the thread should park until `SIGCONT` or `SIGKILL`.
    Stopped(Signal),
    /// A fatal signal ended the thread group.
    Terminated { signal: Signal, core_dumped: bool },
}

fn rollback_syscall<C: UserContext>(abi: Abi, context: &mut C, orig_reg: u64) {
    let pc_reg = abi.program_counter_register();
    let result_reg = abi.system_call_registers().result;
    let pc = context
        .register(pc_reg)
        .expect("ABI program counter register exists");
    context
        .set_register(pc_reg, pc.wrapping_sub(abi.syscall_instruction_bytes()))
        .expect("ABI program counter register is writable");
    context
        .set_register(result_reg, orig_reg)
        .expect("ABI result register is writable");
}

fn set_eintr<C: UserContext>(abi: Abi, context: &mut C) {
    let result_reg = abi.system_call_registers().result;
    context
        .set_register(result_reg, errno(EINTR))
        .expect("ABI result register is writable");
}

/// Delivers at most one pending unmasked signal to `context` on return to user
/// mode, handling `SA_RESTART`, `SA_RESETHAND`, `SA_NODEFER`, `SA_ONSTACK`,
/// `SS_AUTODISARM`, `TIF_RESTORE_SIGMASK`, stop/continue, and default fatal
/// actions (`kernel/signal.c` `get_signal` + arch `do_signal`).
pub fn deliver_pending_signals<C: UserContext, M: UserMemory>(
    abi: Abi,
    thread: &ThreadSignalSlot,
    context: &mut C,
    memory: &mut M,
    restart: Option<SyscallRestart>,
    sigreturn_trampoline: u64,
) -> SignalDelivery {
    loop {
        let active_mask = thread.current_mask();
        let wanted = active_mask.complement();
        let Some(info) = thread.take_any_matching(wanted) else {
            // No deliverable signal left: restore any saved temporary mask and
            // restart an interrupted syscall if one was pending.
            thread.restore_temp_mask();
            if let Some(
                SyscallRestart::RestartSys { orig_reg }
                | SyscallRestart::RestartNoHand { orig_reg },
            ) = restart
            {
                rollback_syscall(abi, context, orig_reg);
            }
            return SignalDelivery::None;
        };

        let resolved = {
            let actions_arc = thread.process.actions_handle();
            let mut actions = actions_arc.lock();
            let resolved = actions.resolved(info.signo);
            if let ResolvedSignal::Catch(handler) = resolved
                && handler.flags & SA_RESETHAND != 0
            {
                actions.reset_to_default(info.signo);
            }
            resolved
        };

        match resolved {
            ResolvedSignal::Ignore => continue,
            ResolvedSignal::Default(
                DefaultSignalAction::Ignore | DefaultSignalAction::Continue,
            ) => {
                continue;
            }
            ResolvedSignal::Default(DefaultSignalAction::Terminate) => {
                return SignalDelivery::Terminated {
                    signal: info.signo,
                    core_dumped: false,
                };
            }
            ResolvedSignal::Default(DefaultSignalAction::CoreDump) => {
                return SignalDelivery::Terminated {
                    signal: info.signo,
                    core_dumped: true,
                };
            }
            ResolvedSignal::Default(DefaultSignalAction::Stop) => {
                thread.process.stopped.store(true, Ordering::Release);
                thread.restore_temp_mask();
                if let Some(
                    SyscallRestart::RestartSys { orig_reg }
                    | SyscallRestart::RestartNoHand { orig_reg },
                ) = restart
                {
                    rollback_syscall(abi, context, orig_reg);
                }
                return SignalDelivery::Stopped(info.signo);
            }
            ResolvedSignal::Catch(action) => {
                match restart {
                    Some(SyscallRestart::RestartSys { orig_reg })
                        if action.flags & SA_RESTART != 0 =>
                    {
                        rollback_syscall(abi, context, orig_reg);
                    }
                    Some(
                        SyscallRestart::RestartSys { .. } | SyscallRestart::RestartNoHand { .. },
                    ) => {
                        set_eintr(abi, context);
                    }
                    None => {}
                }

                // `TIF_RESTORE_SIGMASK`: `uc_sigmask` receives the pre-suspend
                // saved mask, while the handler executes under the active mask
                // union `sa_mask` (plus `signo` unless `SA_NODEFER`).
                let saved_mask = thread.saved_mask.lock().take().unwrap_or(active_mask);
                let mut handler_mask = active_mask.union(action.mask);
                if action.flags & SA_NODEFER == 0 {
                    handler_mask.insert(info.signo);
                }
                handler_mask = handler_mask.without_uncatchable();

                let altstack = *thread.altstack.lock();
                match signal_frame::setup_signal_frame(
                    context,
                    memory,
                    FrameDeliveryInput {
                        abi,
                        info,
                        handler: action.handler,
                        restorer: action.restorer,
                        flags: action.flags,
                        saved_mask,
                        altstack,
                        sigreturn_trampoline,
                        fault_address: 0,
                    },
                ) {
                    Ok(used_altstack) => {
                        if used_altstack && (altstack.flags & SS_AUTODISARM != 0) {
                            *thread.altstack.lock() = SigAltStack::disabled();
                        }
                        thread.set_mask(handler_mask);
                        return SignalDelivery::Delivered;
                    }
                    Err(_) => {
                        return SignalDelivery::Terminated {
                            signal: Signal::SIGSEGV,
                            core_dumped: true,
                        };
                    }
                }
            }
        }
    }
}

/// Delivers a synchronous hardware fault (`SIGSEGV`, `SIGBUS`, `SIGFPE`,
/// `SIGILL`, `SIGTRAP`) with Linux `force_sig_fault` semantics: if the signal
/// is masked, ignored, or set to `SIG_DFL` (or writing the signal frame
/// faults), the process is forcefully terminated (`kernel/signal.c`
/// `force_sig_info_to_task`).
pub fn deliver_fault_signal<C: UserContext, M: UserMemory>(
    abi: Abi,
    thread: &ThreadSignalSlot,
    fault: UserFault,
    context: &mut C,
    memory: &mut M,
    sigreturn_trampoline: u64,
) -> SignalDelivery {
    let (info, fault_address) = SigInfo::from_fault(fault);
    deliver_forced_siginfo(
        abi,
        thread,
        info,
        fault_address,
        context,
        memory,
        sigreturn_trampoline,
    )
}

/// Delivers a synchronous `SIGBUS` (`BUS_ADRERR`) fault with `si_addr =
/// fault_address` (such as accessing a whole page beyond a mapped file's end)
/// using Linux `force_sig_fault` semantics.
pub fn deliver_bus_fault_signal<C: UserContext, M: UserMemory>(
    abi: Abi,
    thread: &ThreadSignalSlot,
    fault_address: u64,
    context: &mut C,
    memory: &mut M,
    sigreturn_trampoline: u64,
) -> SignalDelivery {
    let info = SigInfo {
        signo: Signal::SIGBUS,
        errno: 0,
        code: BUS_ADRERR,
        payload: SigInfoPayload::Fault {
            addr: fault_address,
        },
    };
    deliver_forced_siginfo(
        abi,
        thread,
        info,
        fault_address,
        context,
        memory,
        sigreturn_trampoline,
    )
}

fn deliver_forced_siginfo<C: UserContext, M: UserMemory>(
    abi: Abi,
    thread: &ThreadSignalSlot,
    info: SigInfo,
    fault_address: u64,
    context: &mut C,
    memory: &mut M,
    sigreturn_trampoline: u64,
) -> SignalDelivery {
    let signal = info.signo;
    let active_mask = thread.current_mask();

    let action = {
        let actions_arc = thread.process.actions_handle();
        let mut actions = actions_arc.lock();
        if active_mask.contains(signal) {
            actions.reset_to_default(signal);
            None
        } else {
            match actions.resolved(signal) {
                ResolvedSignal::Catch(handler) => {
                    if handler.flags & SA_RESETHAND != 0 {
                        actions.reset_to_default(signal);
                    }
                    Some(handler)
                }
                _ => None,
            }
        }
    };

    let Some(action) = action else {
        return SignalDelivery::Terminated {
            signal,
            core_dumped: matches!(signal.default_action(), DefaultSignalAction::CoreDump),
        };
    };

    let mut handler_mask = active_mask.union(action.mask);
    if action.flags & SA_NODEFER == 0 {
        handler_mask.insert(signal);
    }
    handler_mask = handler_mask.without_uncatchable();

    let altstack = *thread.altstack.lock();
    match signal_frame::setup_signal_frame(
        context,
        memory,
        FrameDeliveryInput {
            abi,
            info,
            handler: action.handler,
            restorer: action.restorer,
            flags: action.flags,
            saved_mask: active_mask,
            altstack,
            sigreturn_trampoline,
            fault_address,
        },
    ) {
        Ok(used_altstack) => {
            if used_altstack && (altstack.flags & SS_AUTODISARM != 0) {
                *thread.altstack.lock() = SigAltStack::disabled();
            }
            thread.set_mask(handler_mask);
            SignalDelivery::Delivered
        }
        Err(_) => SignalDelivery::Terminated {
            signal: Signal::SIGSEGV,
            core_dumped: true,
        },
    }
}

/// Restores register context, extended state, signal mask, and alternate stack
/// from the user signal frame on `rt_sigreturn`.
pub fn restore_from_sigreturn<C: UserContext, M: UserMemory>(
    abi: Abi,
    thread: &ThreadSignalSlot,
    context: &mut C,
    memory: &M,
) -> Result<(), SignalFrameError> {
    let restored = signal_frame::restore_signal_frame(abi, context, memory)?;
    *thread.saved_mask.lock() = None;
    thread.set_mask(restored.sigmask);

    // `kernel/signal.c` `restore_altstack`: reinstall `uc_stack` when valid
    // and not currently executing on the alternate stack (re-arms
    // `SS_AUTODISARM`).
    let restored_sp = context
        .register(abi.stack_pointer_register())
        .map_err(|_| SignalFrameError::InvalidContext)?;
    let mut altstack = thread.altstack.lock();
    if !altstack.on_stack(restored_sp) {
        let mode = restored.uc_stack_flags & !SS_AUTODISARM;
        if mode == SS_DISABLE {
            *altstack = SigAltStack::disabled();
        } else if (mode == 0 || mode == SS_ONSTACK) && restored.uc_stack_size >= abi.min_sigstksz()
        {
            *altstack = SigAltStack {
                sp: restored.uc_stack_sp,
                size: restored.uc_stack_size,
                flags: restored.uc_stack_flags & SS_AUTODISARM,
            };
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Syscall implementations
// ---------------------------------------------------------------------------

/// `rt_sigaction(signum, act, oldact, sigsetsize)` (`kernel/signal.c`
/// `do_sigaction`).
pub(super) fn rt_sigaction<M: UserMemory>(
    signals: &ProcessSignals,
    args: [u64; 6],
    memory: &mut M,
) -> u64 {
    let signum = args[0] as i32;
    let act_ptr = args[1];
    let oldact_ptr = args[2];
    let sigsetsize = args[3];
    if sigsetsize != SIGSET_BYTES {
        return errno(EINVAL);
    }
    let Some(signal) = u8::try_from(signum).ok().and_then(Signal::new) else {
        return errno(EINVAL);
    };
    if act_ptr != 0 && signal.is_uncatchable() {
        return errno(EINVAL);
    }

    let new_bytes = if act_ptr != 0 {
        let mut buf = [0u8; KERNEL_SIGACTION_BYTES];
        if memory.read(act_ptr, &mut buf).is_err() {
            return errno(EFAULT);
        }
        Some(buf)
    } else {
        None
    };

    let actions_arc = signals.actions_handle();
    let (old_bytes, became_ignored) = {
        let mut actions = actions_arc.lock();
        let old = actions.read_raw(signal);
        let ignored = new_bytes.is_some_and(|buf| actions.set_raw(signal, &buf));
        (old, ignored)
    };

    if oldact_ptr != 0 && memory.write(oldact_ptr, &old_bytes).is_err() {
        // Writing oldact failed; on Linux the read/write order checks oldact
        // before mutating, so restore if we changed it.
        if new_bytes.is_some() {
            actions_arc.lock().set_raw(signal, &old_bytes);
        }
        return errno(EFAULT);
    }

    // `kernel/signal.c` `do_sigaction`: setting a signal to ignored discards
    // all pending instances of that signal across the process.
    if became_ignored {
        signals.discard_pending_everywhere(signal);
    }
    0
}

/// `rt_sigprocmask(how, set, oldset, sigsetsize)` (`kernel/signal.c`
/// `SYSCALL_DEFINE4(rt_sigprocmask)`).
pub(super) fn rt_sigprocmask<M: UserMemory>(
    thread: &ThreadSignalSlot,
    args: [u64; 6],
    memory: &mut M,
) -> u64 {
    let how = args[0] as u32;
    let set_ptr = args[1];
    let oldset_ptr = args[2];
    let sigsetsize = args[3];
    if sigsetsize != SIGSET_BYTES {
        return errno(EINVAL);
    }

    let old_mask = thread.current_mask();
    let new_mask = if set_ptr != 0 {
        let mut buf = [0u8; 8];
        if memory.read(set_ptr, &mut buf).is_err() {
            return errno(EFAULT);
        }
        let requested = SignalSet::from_bits(u64::from_le_bytes(buf));
        match how {
            SIG_BLOCK => Some(old_mask.union(requested).without_uncatchable()),
            SIG_UNBLOCK => Some(old_mask.difference(requested).without_uncatchable()),
            SIG_SETMASK => Some(requested.without_uncatchable()),
            _ => return errno(EINVAL),
        }
    } else {
        None
    };

    if oldset_ptr != 0
        && memory
            .write(oldset_ptr, &old_mask.bits().to_le_bytes())
            .is_err()
    {
        return errno(EFAULT);
    }

    if let Some(updated) = new_mask {
        thread.set_mask(updated);
    }
    0
}

/// `rt_sigpending(set, sigsetsize)` (`kernel/signal.c` `do_sigpending`).
pub(super) fn rt_sigpending<M: UserMemory>(
    thread: &ThreadSignalSlot,
    args: [u64; 6],
    memory: &mut M,
) -> u64 {
    let set_ptr = args[0];
    let sigsetsize = args[1];
    if sigsetsize != SIGSET_BYTES {
        return errno(EINVAL);
    }
    let pending = thread.pending_set().bits().to_le_bytes();
    if memory.write(set_ptr, &pending).is_err() {
        return errno(EFAULT);
    }
    0
}

/// `rt_sigsuspend(unewset, sigsetsize)` (`kernel/signal.c`
/// `SYSCALL_DEFINE2(rt_sigsuspend)`).
pub(super) async fn rt_sigsuspend<M: UserMemory>(
    thread: &ThreadSignalSlot,
    args: [u64; 6],
    memory: &M,
) -> SyscallOutcome {
    let set_ptr = args[0];
    let sigsetsize = args[1];
    if sigsetsize != SIGSET_BYTES {
        return SyscallOutcome::Return(errno(EINVAL));
    }
    let mut buf = [0u8; 8];
    if memory.read(set_ptr, &mut buf).is_err() {
        return SyscallOutcome::Return(errno(EFAULT));
    }
    let temp_mask = SignalSet::from_bits(u64::from_le_bytes(buf)).without_uncatchable();
    thread.push_temp_mask(temp_mask);
    thread.wait_deliverable().await;
    SyscallOutcome::RestartNoHand
}

/// `pause()` (`kernel/signal.c` `SYSCALL_DEFINE0(pause)`).
pub(super) async fn pause(thread: &ThreadSignalSlot) -> SyscallOutcome {
    thread.wait_deliverable().await;
    SyscallOutcome::RestartNoHand
}

/// RAII guard that clears `ThreadSignalSlot::sigtimedwait_set` on drop.
struct SigtimedwaitGuard<'a> {
    thread: &'a ThreadSignalSlot,
}

impl Drop for SigtimedwaitGuard<'_> {
    fn drop(&mut self) {
        self.thread.sigtimedwait_set.store(0, Ordering::Release);
    }
}

/// `rt_sigtimedwait(uthese, uinfo, uts, sigsetsize)` (`kernel/signal.c`
/// `do_sigtimedwait`).
pub(super) async fn rt_sigtimedwait<M: UserMemory, C: Clock>(
    thread: &ThreadSignalSlot,
    args: [u64; 6],
    memory: &mut M,
    clock: &C,
) -> SyscallOutcome {
    let uthese = args[0];
    let uinfo = args[1];
    let uts = args[2];
    let sigsetsize = args[3];
    if sigsetsize != SIGSET_BYTES {
        return SyscallOutcome::Return(errno(EINVAL));
    }
    let mut mask_buf = [0u8; 8];
    if memory.read(uthese, &mut mask_buf).is_err() {
        return SyscallOutcome::Return(errno(EFAULT));
    }
    let wanted = SignalSet::from_bits(u64::from_le_bytes(mask_buf)).without_uncatchable();

    let timeout_ns = if uts != 0 {
        let mut ts = [0u8; TIMESPEC_BYTES];
        if memory.read(uts, &mut ts).is_err() {
            return SyscallOutcome::Return(errno(EFAULT));
        }
        let sec = i64::from_le_bytes(ts[0..8].try_into().unwrap());
        let nsec = i64::from_le_bytes(ts[8..16].try_into().unwrap());
        if sec < 0 || !(0..NANOS_PER_SEC as i64).contains(&nsec) {
            return SyscallOutcome::Return(errno(EINVAL));
        }
        Some(
            (sec as u64)
                .saturating_mul(NANOS_PER_SEC)
                .saturating_add(nsec as u64),
        )
    } else {
        None
    };

    if let Some(info) = thread.take_any_matching(wanted) {
        return SyscallOutcome::Return(write_sigtimedwait_info(memory, uinfo, info));
    }
    if timeout_ns == Some(0) {
        return SyscallOutcome::Return(errno(EAGAIN));
    }

    let deadline = timeout_ns.map(|delta| clock.now_nanos().saturating_add(delta));
    thread
        .sigtimedwait_set
        .store(wanted.bits(), Ordering::Release);
    let _guard = SigtimedwaitGuard { thread };

    loop {
        let mut wake = thread.wake_notify.waiter();
        if let Some(info) = thread.take_any_matching(wanted) {
            return SyscallOutcome::Return(write_sigtimedwait_info(memory, uinfo, info));
        }
        // An unmasked deliverable signal NOT in `wanted` interrupts
        // `rt_sigtimedwait` with `-EINTR` (`sigtimedwait(2)`).
        let unmasked_other = thread
            .pending_set()
            .difference(thread.current_mask())
            .difference(wanted);
        if !unmasked_other.is_empty() && has_non_ignored_signal(&thread.process, unmasked_other) {
            return SyscallOutcome::Return(errno(EINTR));
        }
        if deadline.is_some_and(|end| clock.now_nanos() >= end) {
            return SyscallOutcome::Return(errno(EAGAIN));
        }
        let sleep = async {
            match deadline {
                Some(end) => clock.sleep_until(end).await,
                None => core::future::pending().await,
            }
        };
        let mut sleep = core::pin::pin!(sleep);
        poll_fn(|cx| {
            if thread.wake_notify.poll_notified(cx, &mut wake).is_ready() {
                return Poll::Ready(());
            }
            if sleep.as_mut().poll(cx).is_ready() {
                return Poll::Ready(());
            }
            Poll::Pending
        })
        .await;
    }
}

fn has_non_ignored_signal(process: &ProcessSignals, mut set: SignalSet) -> bool {
    let actions_arc = process.actions_handle();
    let actions = actions_arc.lock();
    while let Some(signal) = set.take_first() {
        if signal.is_uncatchable() || !actions.is_ignored(signal) {
            return true;
        }
    }
    false
}

fn write_sigtimedwait_info<M: UserMemory>(memory: &mut M, uinfo: u64, info: SigInfo) -> u64 {
    if uinfo != 0 {
        let encoded: [u8; SIGINFO_SIZE] = info.encode();
        if memory.write(uinfo, &encoded).is_err() {
            return errno(EFAULT);
        }
    }
    u64::from(info.signo.raw())
}

/// `sigaltstack(uss, oss)` (`kernel/signal.c` `do_sigaltstack`).
pub(super) fn sigaltstack<M: UserMemory>(
    abi: Abi,
    thread: &ThreadSignalSlot,
    current_sp: u64,
    args: [u64; 6],
    memory: &mut M,
) -> u64 {
    let uss_ptr = args[0];
    let oss_ptr = args[1];

    let old_encoded = thread.altstack.lock().encode_stack_t(current_sp);

    let parsed_new = if uss_ptr != 0 {
        let mut buf = [0u8; STACK_T_SIZE];
        if memory.read(uss_ptr, &mut buf).is_err() {
            return errno(EFAULT);
        }
        let (ss_sp, ss_flags, ss_size) = SigAltStack::decode_stack_t(&buf);
        let alt = *thread.altstack.lock();
        if alt.on_stack(current_sp) {
            return errno(EPERM);
        }
        let mode = ss_flags & !SS_AUTODISARM;
        match mode {
            SS_DISABLE => Some(SigAltStack::disabled()),
            0 | SS_ONSTACK => {
                if ss_size < abi.min_sigstksz() {
                    return errno(ENOMEM);
                }
                Some(SigAltStack {
                    sp: ss_sp,
                    size: ss_size,
                    flags: ss_flags & SS_AUTODISARM,
                })
            }
            _ => return errno(EINVAL),
        }
    } else {
        None
    };

    if oss_ptr != 0 && memory.write(oss_ptr, &old_encoded).is_err() {
        return errno(EFAULT);
    }
    if let Some(updated) = parsed_new {
        *thread.altstack.lock() = updated;
    }
    0
}

/// Checks whether `sender` may signal `target` inside the container
/// (`kernel/signal.c` `check_kill_permission`).
fn can_signal(
    pids: &PidNamespace,
    sender_tgid: NonZeroU32,
    sender: &Credentials,
    target_tgid: NonZeroU32,
    target: &Credentials,
    signal: Option<Signal>,
) -> bool {
    if sender_tgid == target_tgid {
        return true;
    }
    if sender.capabilities.has_effective(CAP_KILL) {
        return true;
    }
    let su = sender.user;
    let tu = target.user;
    if su.effective == tu.saved
        || su.effective == tu.real
        || su.real == tu.saved
        || su.real == tu.real
    {
        return true;
    }
    signal == Some(Signal::SIGCONT)
        && pids.sid(sender_tgid.get()).is_some()
        && pids.sid(sender_tgid.get()) == pids.sid(target_tgid.get())
}

fn decode_optional_signal(raw: i32) -> Result<Option<Signal>, u64> {
    if raw == 0 {
        Ok(None)
    } else {
        u8::try_from(raw)
            .ok()
            .and_then(Signal::new)
            .map(Some)
            .ok_or_else(|| errno(EINVAL))
    }
}

/// `kill(pid, sig)` (`kernel/signal.c` `kill_something_info`), scoped strictly
/// to the calling process's container [`PidNamespace`].
pub(super) fn kill(
    pids: &PidNamespace,
    caller_tgid: NonZeroU32,
    caller_pgid: u32,
    caller_creds: &Credentials,
    args: [u64; 6],
) -> u64 {
    let pid = args[0] as i32;
    let signal = match decode_optional_signal(args[1] as i32) {
        Ok(sig) => sig,
        Err(err) => return err,
    };

    if pid > 0 {
        let Some((target_signals, target_creds)) = pids.lookup_process(pid as u32) else {
            return errno(ESRCH);
        };
        let target_creds = target_creds.lock().clone();
        if !can_signal(
            pids,
            caller_tgid,
            caller_creds,
            target_signals.tgid(),
            &target_creds,
            signal,
        ) {
            return errno(EPERM);
        }
        if let Some(sig) = signal
            && target_signals.raise_process(SigInfo::from_kill(
                sig,
                caller_tgid.get(),
                caller_creds.user.real,
            ))
        {
            pids.mark_continued(target_signals.tgid());
        }
        return 0;
    }

    let targets = if pid == 0 {
        pids.processes_in_group(caller_pgid)
    } else if pid == -1 {
        // Linux `kill(-1, sig)`: all processes in the PID namespace except
        // init (PID 1) and the caller.
        pids.all_processes_except(caller_tgid.get())
    } else if pid == i32::MIN {
        return errno(ESRCH);
    } else {
        pids.processes_in_group((-pid) as u32)
    };

    if targets.is_empty() {
        return errno(ESRCH);
    }
    let mut delivered_any = false;
    for (target_signals, target_creds) in targets {
        let creds = target_creds.lock().clone();
        if !can_signal(
            pids,
            caller_tgid,
            caller_creds,
            target_signals.tgid(),
            &creds,
            signal,
        ) {
            continue;
        }
        delivered_any = true;
        if let Some(sig) = signal
            && target_signals.raise_process(SigInfo::from_kill(
                sig,
                caller_tgid.get(),
                caller_creds.user.real,
            ))
        {
            pids.mark_continued(target_signals.tgid());
        }
    }
    if delivered_any { 0 } else { errno(EPERM) }
}

/// `tkill(tid, sig)` (`kernel/signal.c` `SYSCALL_DEFINE2(tkill)`).
pub(super) fn tkill(
    pids: &PidNamespace,
    caller_tgid: NonZeroU32,
    caller_creds: &Credentials,
    args: [u64; 6],
) -> u64 {
    let tid = args[0] as i32;
    if tid <= 0 {
        return errno(EINVAL);
    }
    let signal = match decode_optional_signal(args[1] as i32) {
        Ok(sig) => sig,
        Err(err) => return err,
    };
    let Some((target_tgid, target_slot, target_creds)) = pids.lookup_thread(tid as u32) else {
        return errno(ESRCH);
    };
    let creds = target_creds.lock().clone();
    if !can_signal(pids, caller_tgid, caller_creds, target_tgid, &creds, signal) {
        return errno(EPERM);
    }
    if let Some(sig) = signal
        && target_slot.process.raise_thread(
            &target_slot,
            SigInfo::from_tkill(sig, caller_tgid.get(), caller_creds.user.real),
        )
    {
        pids.mark_continued(target_tgid);
    }
    0
}

/// `tgkill(tgid, tid, sig)` (`kernel/signal.c` `SYSCALL_DEFINE3(tgkill)`).
pub(super) fn tgkill(
    pids: &PidNamespace,
    caller_tgid: NonZeroU32,
    caller_creds: &Credentials,
    args: [u64; 6],
) -> u64 {
    let tgid = args[0] as i32;
    let tid = args[1] as i32;
    if tgid <= 0 || tid <= 0 {
        return errno(EINVAL);
    }
    let signal = match decode_optional_signal(args[2] as i32) {
        Ok(sig) => sig,
        Err(err) => return err,
    };
    let Some((target_tgid, target_slot, target_creds)) = pids.lookup_thread(tid as u32) else {
        return errno(ESRCH);
    };
    if target_tgid.get() != tgid as u32 {
        return errno(ESRCH);
    }
    let creds = target_creds.lock().clone();
    if !can_signal(pids, caller_tgid, caller_creds, target_tgid, &creds, signal) {
        return errno(EPERM);
    }
    if let Some(sig) = signal
        && target_slot.process.raise_thread(
            &target_slot,
            SigInfo::from_tkill(sig, caller_tgid.get(), caller_creds.user.real),
        )
    {
        pids.mark_continued(target_tgid);
    }
    0
}

/// `alarm(seconds)` (`kernel/time/itimer.c` `alarm_setitimer`).
pub(super) fn alarm<C: Clock>(signals: &ProcessSignals, args: [u64; 6], clock: &C) -> u64 {
    let seconds = u64::from(args[0] as u32);
    let now = clock.now_nanos();
    let old_rem_ns = {
        let mut timers = signals.timers.lock();
        let rem = timers
            .real_deadline_ns
            .map_or(0, |deadline| deadline.saturating_sub(now));
        timers.real_interval_ns = 0;
        timers.real_deadline_ns = if seconds == 0 {
            None
        } else {
            Some(now.saturating_add(seconds.saturating_mul(NANOS_PER_SEC)))
        };
        timers.real_generation = timers.real_generation.wrapping_add(1);
        rem
    };
    signals.real_timer_notify.notify_all();
    // `kernel/time/itimer.c` `alarm_setitimer`: round to nearest second, and
    // return at least 1 whenever a non-zero alarm was pending.
    if old_rem_ns == 0 {
        0
    } else {
        let mut secs = old_rem_ns / NANOS_PER_SEC;
        let rem_ns = old_rem_ns % NANOS_PER_SEC;
        if secs == 0 || rem_ns >= NANOS_PER_SEC / 2 {
            secs += 1;
        }
        secs
    }
}

/// `getitimer(which, curr_value)` (`kernel/time/itimer.c` `do_getitimer`).
pub(super) fn getitimer<M: UserMemory, C: Clock>(
    signals: &ProcessSignals,
    args: [u64; 6],
    memory: &mut M,
    clock: &C,
) -> u64 {
    let which = args[0] as i32;
    let curr_ptr = args[1];
    let now = clock.now_nanos();
    let (interval_ns, value_ns) = {
        let timers = signals.timers.lock();
        match which {
            ITIMER_REAL => (
                timers.real_interval_ns,
                timers
                    .real_deadline_ns
                    .map_or(0, |deadline| deadline.saturating_sub(now)),
            ),
            ITIMER_VIRTUAL => (timers.virtual_interval_ns, timers.virtual_remaining_ns),
            ITIMER_PROF => (timers.prof_interval_ns, timers.prof_remaining_ns),
            _ => return errno(EINVAL),
        }
    };
    let encoded = encode_itimerval(interval_ns, value_ns);
    if memory.write(curr_ptr, &encoded).is_err() {
        return errno(EFAULT);
    }
    0
}

/// `setitimer(which, new_value, old_value)` (`kernel/time/itimer.c`
/// `do_setitimer`).
pub(super) fn setitimer<M: UserMemory, C: Clock>(
    signals: &ProcessSignals,
    args: [u64; 6],
    memory: &mut M,
    clock: &C,
) -> u64 {
    let which = args[0] as i32;
    let new_ptr = args[1];
    let old_ptr = args[2];
    if !matches!(which, ITIMER_REAL | ITIMER_VIRTUAL | ITIMER_PROF) {
        return errno(EINVAL);
    }
    let mut raw = [0u8; ITIMERVAL_BYTES];
    if memory.read(new_ptr, &mut raw).is_err() {
        return errno(EFAULT);
    }
    let Some((new_interval_ns, new_value_ns)) = decode_itimerval(&raw) else {
        return errno(EINVAL);
    };
    if old_ptr != 0 && memory.check_writable(old_ptr, ITIMERVAL_BYTES).is_err() {
        return errno(EFAULT);
    }

    let now = clock.now_nanos();
    let old = {
        let mut timers = signals.timers.lock();
        match which {
            ITIMER_REAL => {
                let prev = (
                    timers.real_interval_ns,
                    timers
                        .real_deadline_ns
                        .map_or(0, |deadline| deadline.saturating_sub(now)),
                );
                if new_value_ns == 0 {
                    timers.real_deadline_ns = None;
                    timers.real_interval_ns = 0;
                } else {
                    timers.real_deadline_ns = Some(now.saturating_add(new_value_ns));
                    timers.real_interval_ns = new_interval_ns;
                }
                timers.real_generation = timers.real_generation.wrapping_add(1);
                prev
            }
            ITIMER_VIRTUAL => {
                let prev = (timers.virtual_interval_ns, timers.virtual_remaining_ns);
                if new_value_ns == 0 {
                    timers.virtual_remaining_ns = 0;
                    timers.virtual_interval_ns = 0;
                } else {
                    timers.virtual_remaining_ns = new_value_ns;
                    timers.virtual_interval_ns = new_interval_ns;
                }
                prev
            }
            ITIMER_PROF => {
                let prev = (timers.prof_interval_ns, timers.prof_remaining_ns);
                if new_value_ns == 0 {
                    timers.prof_remaining_ns = 0;
                    timers.prof_interval_ns = 0;
                } else {
                    timers.prof_remaining_ns = new_value_ns;
                    timers.prof_interval_ns = new_interval_ns;
                }
                prev
            }
            _ => unreachable!(),
        }
    };
    if which == ITIMER_REAL {
        signals.real_timer_notify.notify_all();
    }
    if old_ptr != 0 {
        let encoded = encode_itimerval(old.0, old.1);
        if memory.write(old_ptr, &encoded).is_err() {
            return errno(EFAULT);
        }
    }
    0
}

fn decode_itimerval(bytes: &[u8; ITIMERVAL_BYTES]) -> Option<(u64, u64)> {
    let parse_tv = |offset: usize| -> Option<u64> {
        let sec = i64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
        let usec = i64::from_le_bytes(bytes[offset + 8..offset + 16].try_into().unwrap());
        if sec < 0 || !(0..USECS_PER_SEC).contains(&usec) {
            return None;
        }
        Some(
            (sec as u64)
                .saturating_mul(NANOS_PER_SEC)
                .saturating_add((usec as u64).saturating_mul(NANOS_PER_USEC)),
        )
    };
    Some((parse_tv(0)?, parse_tv(16)?))
}

fn encode_itimerval(interval_ns: u64, value_ns: u64) -> [u8; ITIMERVAL_BYTES] {
    let mut bytes = [0u8; ITIMERVAL_BYTES];
    let write_tv = |dst: &mut [u8], offset: usize, ns: u64| {
        let sec = ns / NANOS_PER_SEC;
        let usec = (ns % NANOS_PER_SEC).div_ceil(NANOS_PER_USEC);
        let (sec, usec) = if usec >= USECS_PER_SEC as u64 {
            (sec + 1, 0)
        } else {
            (sec, usec)
        };
        dst[offset..offset + 8].copy_from_slice(&sec.to_le_bytes());
        dst[offset + 8..offset + 16].copy_from_slice(&usec.to_le_bytes());
    };
    write_tv(&mut bytes, 0, interval_ns);
    write_tv(&mut bytes, 16, value_ns);
    bytes
}
