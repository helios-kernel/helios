//! Thread creation (`clone`, `clone3`), thread-group exit tracking,
//! `sched_yield`, `sched_getaffinity`, `nanosleep` and `clock_nanosleep`.
//!
//! Flag rules and argument layouts follow Linux v6.12 (`kernel/fork.c`,
//! `kernel/sched/syscalls.c` and `kernel/time/posix-timers.c`).

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::num::NonZeroU32;
use core::sync::atomic::{AtomicU64, Ordering};

use super::futex::FUTEX_TID_MASK;
use super::process::{
    ChildWaitState, ProcessTreeRecord, TryWaitResult, WaitCloneFilter, WaitEvent, WaitEventKind,
    WaitTarget,
};
use super::signal::{ProcessSignals, ThreadSignalSlot, WaitOutcome};
use super::system::Credentials;
use super::*;

// include/uapi/linux/sched.h.
pub(super) const CSIGNAL: u64 = 0x0000_00ff;
const CLONE_NEWTIME: u64 = 0x0000_0080;
pub(super) const CLONE_VM: u64 = 0x0000_0100;
pub(super) const CLONE_FS: u64 = 0x0000_0200;
pub(super) const CLONE_FILES: u64 = 0x0000_0400;
pub(super) const CLONE_SIGHAND: u64 = 0x0000_0800;
const CLONE_PIDFD: u64 = 0x0000_1000;
const CLONE_PTRACE: u64 = 0x0000_2000;
pub(super) const CLONE_VFORK: u64 = 0x0000_4000;
pub(super) const CLONE_PARENT: u64 = 0x0000_8000;
const CLONE_THREAD: u64 = 0x0001_0000;
const CLONE_NEWNS: u64 = 0x0002_0000;
pub(super) const CLONE_SYSVSEM: u64 = 0x0004_0000;
pub(super) const CLONE_SETTLS: u64 = 0x0008_0000;
pub(super) const CLONE_PARENT_SETTID: u64 = 0x0010_0000;
pub(super) const CLONE_CHILD_CLEARTID: u64 = 0x0020_0000;
pub(super) const CLONE_DETACHED: u64 = 0x0040_0000;
pub(super) const CLONE_UNTRACED: u64 = 0x0080_0000;
pub(super) const CLONE_CHILD_SETTID: u64 = 0x0100_0000;
const CLONE_NEWCGROUP: u64 = 0x0200_0000;
const CLONE_NEWUTS: u64 = 0x0400_0000;
const CLONE_NEWIPC: u64 = 0x0800_0000;
const CLONE_NEWUSER: u64 = 0x1000_0000;
const CLONE_NEWPID: u64 = 0x2000_0000;
const CLONE_NEWNET: u64 = 0x4000_0000;
pub(super) const CLONE_IO: u64 = 0x8000_0000;
pub(super) const CLONE_CLEAR_SIGHAND: u64 = 1 << 32;
const CLONE_INTO_CGROUP: u64 = 1 << 33;

const KNOWN_CLONE3_FLAGS: u64 = CLONE_NEWTIME
    | CLONE_VM
    | CLONE_FS
    | CLONE_FILES
    | CLONE_SIGHAND
    | CLONE_PIDFD
    | CLONE_PTRACE
    | CLONE_VFORK
    | CLONE_PARENT
    | CLONE_THREAD
    | CLONE_NEWNS
    | CLONE_SYSVSEM
    | CLONE_SETTLS
    | CLONE_PARENT_SETTID
    | CLONE_CHILD_CLEARTID
    | CLONE_UNTRACED
    | CLONE_CHILD_SETTID
    | CLONE_NEWCGROUP
    | CLONE_NEWUTS
    | CLONE_NEWIPC
    | CLONE_NEWUSER
    | CLONE_NEWPID
    | CLONE_NEWNET
    | CLONE_IO
    | CLONE_CLEAR_SIGHAND
    | CLONE_INTO_CGROUP;

const REQUIRED_THREAD_FLAGS: u64 = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD;
const OPTIONAL_THREAD_FLAGS: u64 = CLONE_SYSVSEM
    | CLONE_SETTLS
    | CLONE_PARENT_SETTID
    | CLONE_CHILD_CLEARTID
    | CLONE_CHILD_SETTID
    | CLONE_DETACHED
    | CLONE_UNTRACED
    | CLONE_IO;

const CLONE_ARGS_SIZE_VER0: u64 = 64;
const CLONE_ARGS_SIZE_VER2: usize = 88;
const PAGE_BYTES: u64 = 4096;

// include/uapi/linux/time.h.
const TIMER_ABSTIME: u32 = 1;
const NANOS_PER_SECOND: u64 = 1_000_000_000;

const ESRCH: u64 = 3;
const E2BIG: u64 = 7;
const EAGAIN: u64 = 11;

struct RegisteredThread {
    tgid: NonZeroU32,
    slot: Arc<ThreadSignalSlot>,
    credentials: Arc<spin::Mutex<Credentials>>,
}

struct PidNamespaceState {
    next_pid: u32,
    allocated: BTreeSet<u32>,
    live_processes: u32,
    processes: BTreeMap<u32, ProcessTreeRecord>,
    threads: BTreeMap<u32, RegisteredThread>,
}

struct PidNamespaceInner {
    state: spin::Mutex<PidNamespaceState>,
    wait_changed: Notify,
}

impl PidNamespaceState {
    fn allocate_raw(&mut self) -> Result<NonZeroU32, u64> {
        let mut scanned = 0u32;
        while scanned < FUTEX_TID_MASK {
            let candidate = self.next_pid;
            self.next_pid = if candidate >= FUTEX_TID_MASK {
                1
            } else {
                candidate + 1
            };
            scanned += 1;
            if self.allocated.insert(candidate) {
                return Ok(NonZeroU32::new(candidate).expect("candidate is in 1..=FUTEX_TID_MASK"));
            }
        }
        Err(EAGAIN)
    }
}

/// Container-local PID and TID allocator and process tree (`kernel/pid.c`,
/// `kernel/exit.c`).
///
/// Process and thread IDs start at 1 within each container, never collide
/// across processes or threads inside the container, and are never visible
/// from another container.
///
/// # Concurrency contract
///
/// Synchronized by a short synchronous `spin::Mutex`, never held across an
/// `.await`; child wait state transitions broadcast on lock-free `wait_changed`
/// after releasing the mutex.
#[derive(Clone)]
pub struct PidNamespace {
    inner: Arc<PidNamespaceInner>,
}

impl core::fmt::Debug for PidNamespace {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let state = self.inner.state.lock();
        formatter
            .debug_struct("PidNamespace")
            .field("live_processes", &state.live_processes)
            .field("allocated", &state.allocated.len())
            .finish()
    }
}

impl Default for PidNamespace {
    fn default() -> Self {
        Self::new()
    }
}

impl PidNamespace {
    /// A fresh PID namespace whose first process receives PID 1.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(PidNamespaceInner {
                state: spin::Mutex::new(PidNamespaceState {
                    next_pid: 1,
                    allocated: BTreeSet::new(),
                    live_processes: 0,
                    processes: BTreeMap::new(),
                    threads: BTreeMap::new(),
                }),
                wait_changed: Notify::new(),
            }),
        }
    }

    /// A private namespace seeded with one process `leader`, for standalone
    /// tests that construct [`Process`] without a container.
    pub(super) fn standalone(leader: NonZeroU32) -> Self {
        let next_pid = leader
            .get()
            .checked_add(1)
            .filter(|&id| id <= FUTEX_TID_MASK)
            .unwrap_or(1);
        let mut allocated = BTreeSet::new();
        allocated.insert(leader.get());
        Self {
            inner: Arc::new(PidNamespaceInner {
                state: spin::Mutex::new(PidNamespaceState {
                    next_pid,
                    allocated,
                    live_processes: 1,
                    processes: BTreeMap::new(),
                    threads: BTreeMap::new(),
                }),
                wait_changed: Notify::new(),
            }),
        }
    }

    /// Allocates a new process (thread-group leader) ID starting at 1 and
    /// increments the container's live process count.
    pub fn allocate_process(&self) -> Result<NonZeroU32, u64> {
        let mut state = self.inner.state.lock();
        let pid = state.allocate_raw()?;
        state.live_processes = state.live_processes.saturating_add(1);
        Ok(pid)
    }

    /// Unconditionally releases a process ID (used for root/ephemeral
    /// processes with no container parent and for rollback on failed spawn).
    pub fn release_process(&self, pid: NonZeroU32) {
        let mut state = self.inner.state.lock();
        let was_live = state
            .processes
            .remove(&pid.get())
            .is_none_or(|record| record.is_live());
        state.threads.remove(&pid.get());
        if state.allocated.remove(&pid.get()) && was_live {
            state.live_processes = state.live_processes.saturating_sub(1);
        }
        // If container PID 1 exits, clean up any orphaned zombies.
        if pid.get() == 1 {
            let orphaned: Vec<u32> = state
                .processes
                .iter()
                .filter(|(_, record)| !record.is_live() && record.ppid == 1)
                .map(|(&child_pid, _)| child_pid)
                .collect();
            for child_pid in orphaned {
                state.processes.remove(&child_pid);
                state.allocated.remove(&child_pid);
            }
        }
        drop(state);
        self.inner.wait_changed.notify_all();
    }

    /// Allocates a thread ID inside this namespace for a cloned thread.
    pub fn allocate_tid(&self) -> Result<NonZeroU32, u64> {
        self.inner.state.lock().allocate_raw()
    }

    /// Releases a non-leader thread ID when the thread exits.
    pub fn release_tid(&self, tid: NonZeroU32) {
        let mut state = self.inner.state.lock();
        state.threads.remove(&tid.get());
        state.allocated.remove(&tid.get());
    }

    pub(super) fn register_process(
        &self,
        tgid: NonZeroU32,
        signals: Arc<ProcessSignals>,
        credentials: Arc<spin::Mutex<Credentials>>,
    ) {
        let mut state = self.inner.state.lock();
        state.allocated.insert(tgid.get());
        state.processes.insert(
            tgid.get(),
            ProcessTreeRecord::new_root(tgid, signals, credentials),
        );
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn register_child_process(
        &self,
        pid: NonZeroU32,
        ppid: u32,
        pgid: NonZeroU32,
        sid: NonZeroU32,
        exit_signal: Option<Signal>,
        signals: Arc<ProcessSignals>,
        credentials: Arc<spin::Mutex<Credentials>>,
    ) {
        let mut state = self.inner.state.lock();
        state.allocated.insert(pid.get());
        state.processes.insert(
            pid.get(),
            ProcessTreeRecord {
                ppid,
                pgid,
                sid,
                exit_signal,
                has_execed: false,
                state: ChildWaitState::Running,
                signals,
                credentials,
            },
        );
    }

    /// Marks `pid` as having completed `execve` (so its parent may no longer
    /// change its process group with `setpgid`).
    pub fn mark_execed(&self, pid: NonZeroU32) {
        if let Some(record) = self.inner.state.lock().processes.get_mut(&pid.get()) {
            record.has_execed = true;
        }
    }

    /// Records that `pid` stopped on `signal`, notifying its parent's `wait4` /
    /// `waitid` (`WUNTRACED`/`WSTOPPED`) and raising `SIGCHLD` unless the
    /// parent has `SA_NOCLDSTOP`.
    pub fn mark_stopped(&self, pid: NonZeroU32, signal: Signal) {
        let parent_notify = {
            let mut state = self.inner.state.lock();
            let (ppid, child_uid) = match state.processes.get_mut(&pid.get()) {
                Some(record) if record.is_live() => {
                    record.state = ChildWaitState::Stopped {
                        signal,
                        reported: false,
                    };
                    (record.ppid, record.real_uid())
                }
                _ => return,
            };
            if ppid != 0 {
                state
                    .processes
                    .get(&ppid)
                    .filter(|parent| parent.is_live())
                    .map(|parent| (parent.signals.clone(), child_uid))
            } else {
                None
            }
        };
        if let Some((parent_signals, uid)) = parent_notify
            && !parent_signals.sigchld_nocldstop()
        {
            parent_signals.raise_process(crate::signal_frame::SigInfo {
                signo: Signal::SIGCHLD,
                errno: 0,
                code: crate::signal_frame::CLD_STOPPED,
                payload: crate::signal_frame::SigInfoPayload::Child {
                    pid: pid.get(),
                    uid,
                    status: i32::from(signal.raw()),
                },
            });
        }
        self.inner.wait_changed.notify_all();
    }

    /// Records that stopped process `pid` resumed on `SIGCONT`, waking any
    /// parent waiting with `WCONTINUED`.
    pub fn mark_continued(&self, pid: NonZeroU32) {
        let parent_notify = {
            let mut state = self.inner.state.lock();
            let (ppid, child_uid) = match state.processes.get_mut(&pid.get()) {
                Some(record) if record.is_live() => {
                    record.state = ChildWaitState::Continued { reported: false };
                    (record.ppid, record.real_uid())
                }
                _ => return,
            };
            if ppid != 0 {
                state
                    .processes
                    .get(&ppid)
                    .filter(|parent| parent.is_live())
                    .map(|parent| (parent.signals.clone(), child_uid))
            } else {
                None
            }
        };
        if let Some((parent_signals, uid)) = parent_notify
            && !parent_signals.sigchld_nocldstop()
        {
            parent_signals.raise_process(crate::signal_frame::SigInfo {
                signo: Signal::SIGCHLD,
                errno: 0,
                code: crate::signal_frame::CLD_CONTINUED,
                payload: crate::signal_frame::SigInfoPayload::Child {
                    pid: pid.get(),
                    uid,
                    status: i32::from(Signal::SIGCONT.raw()),
                },
            });
        }
        self.inner.wait_changed.notify_all();
    }

    /// Transitions `pid` to exited/zombie state, reparents any children of
    /// `pid` to PID 1, auto-reaps if the parent is gone or ignores `SIGCHLD` /
    /// sets `SA_NOCLDWAIT`, and notifies parent (`SIGCHLD` + `wait_changed`).
    pub fn mark_exited(&self, pid: NonZeroU32, termination: ChildTermination) {
        let mut signals_to_send: Vec<(Arc<ProcessSignals>, crate::signal_frame::SigInfo)> =
            Vec::new();
        {
            let mut state = self.inner.state.lock();
            let Some(record) = state.processes.get(&pid.get()) else {
                return;
            };
            if !record.is_live() {
                return;
            }
            let ppid = record.ppid;
            let exit_signal = record.exit_signal;
            let child_uid = record.real_uid();

            state.threads.remove(&pid.get());
            state.live_processes = state.live_processes.saturating_sub(1);

            // Reparent surviving children of `pid` to container init (PID 1),
            // or auto-reap their zombies if PID 1 is absent or is `pid` itself.
            let init_alive = pid.get() != 1
                && state
                    .processes
                    .get(&1)
                    .is_some_and(ProcessTreeRecord::is_live);
            let init_auto_reap = init_alive
                && state
                    .processes
                    .get(&1)
                    .is_some_and(|init| init.signals.sigchld_auto_reap());
            let mut reparented_zombies = Vec::new();
            let mut auto_reap_children = Vec::new();
            for (&child_pid, child) in state.processes.iter_mut() {
                if child.ppid == pid.get() {
                    if init_alive {
                        child.ppid = 1;
                        if let ChildWaitState::Exited(term) = child.state {
                            if init_auto_reap {
                                auto_reap_children.push(child_pid);
                            } else {
                                reparented_zombies.push((child_pid, child.real_uid(), term));
                            }
                        }
                    } else {
                        child.ppid = 0;
                        if !child.is_live() {
                            auto_reap_children.push(child_pid);
                        }
                    }
                }
            }
            for child_pid in auto_reap_children {
                state.processes.remove(&child_pid);
                state.allocated.remove(&child_pid);
            }
            if !reparented_zombies.is_empty()
                && let Some(init) = state.processes.get(&1)
            {
                for (zpid, zuid, term) in reparented_zombies {
                    let event = WaitEvent {
                        pid: zpid,
                        uid: zuid,
                        kind: WaitEventKind::Exited(term),
                    };
                    signals_to_send.push((init.signals.clone(), event.encode_siginfo()));
                }
            }

            // Decide whether `pid` stays as a zombie for `ppid` or auto-reaps.
            let parent_info = if ppid != 0 {
                state
                    .processes
                    .get(&ppid)
                    .filter(|parent| parent.is_live())
                    .map(|parent| (parent.signals.clone(), parent.signals.sigchld_auto_reap()))
            } else {
                None
            };

            match parent_info {
                Some((parent_signals, auto_reap)) => {
                    if exit_signal == Some(Signal::SIGCHLD) && auto_reap {
                        state.processes.remove(&pid.get());
                        state.allocated.remove(&pid.get());
                    } else {
                        if let Some(entry) = state.processes.get_mut(&pid.get()) {
                            entry.state = ChildWaitState::Exited(termination);
                        }
                        if let Some(sig) = exit_signal {
                            let info = if sig == Signal::SIGCHLD {
                                WaitEvent {
                                    pid: pid.get(),
                                    uid: child_uid,
                                    kind: WaitEventKind::Exited(termination),
                                }
                                .encode_siginfo()
                            } else {
                                crate::signal_frame::SigInfo::from_kill(sig, pid.get(), child_uid)
                            };
                            signals_to_send.push((parent_signals, info));
                        }
                    }
                }
                None => {
                    // No live parent inside this container: release PID immediately.
                    state.processes.remove(&pid.get());
                    state.allocated.remove(&pid.get());
                }
            }
        }
        for (target_signals, info) in signals_to_send {
            let _ = target_signals.raise_process(info);
        }
        self.inner.wait_changed.notify_all();
    }

    pub(super) fn wait_waiter(&self) -> NotifyWaiter {
        self.inner.wait_changed.waiter()
    }

    pub(super) fn poll_wait_changed(
        &self,
        cx: &mut Context<'_>,
        waiter: &mut NotifyWaiter,
    ) -> Poll<()> {
        self.inner.wait_changed.poll_notified(cx, waiter)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn try_wait(
        &self,
        parent: NonZeroU32,
        target: WaitTarget,
        clone_filter: WaitCloneFilter,
        want_exited: bool,
        want_stopped: bool,
        want_continued: bool,
        nowait: bool,
    ) -> TryWaitResult {
        let mut state = self.inner.state.lock();
        let mut matched_any_child = false;
        let mut ready_pid: Option<(u32, WaitEvent)> = None;

        for (&pid, record) in state.processes.iter() {
            if record.ppid != parent.get() || !clone_filter.matches(record.exit_signal) {
                continue;
            }
            let matches = match target {
                WaitTarget::Any => true,
                WaitTarget::Pid(want) => pid == want,
                WaitTarget::Pgid(want) => record.pgid.get() == want,
            };
            if !matches {
                continue;
            }
            matched_any_child = true;
            let event_kind = match record.state {
                ChildWaitState::Exited(term) if want_exited => Some(WaitEventKind::Exited(term)),
                ChildWaitState::Stopped {
                    signal,
                    reported: false,
                } if want_stopped => Some(WaitEventKind::Stopped(signal)),
                ChildWaitState::Continued { reported: false } if want_continued => {
                    Some(WaitEventKind::Continued)
                }
                _ => None,
            };
            if let Some(kind) = event_kind {
                ready_pid = Some((
                    pid,
                    WaitEvent {
                        pid,
                        uid: record.real_uid(),
                        kind,
                    },
                ));
                break;
            }
        }

        if let Some((pid, event)) = ready_pid {
            if !nowait {
                match event.kind {
                    WaitEventKind::Exited(_) => {
                        state.processes.remove(&pid);
                        state.allocated.remove(&pid);
                    }
                    WaitEventKind::Stopped(_) => {
                        if let Some(record) = state.processes.get_mut(&pid)
                            && let ChildWaitState::Stopped { reported, .. } = &mut record.state
                        {
                            *reported = true;
                        }
                    }
                    WaitEventKind::Continued => {
                        if let Some(record) = state.processes.get_mut(&pid)
                            && let ChildWaitState::Continued { reported } = &mut record.state
                        {
                            *reported = true;
                        }
                    }
                }
            }
            return TryWaitResult::Event(event);
        }

        if matched_any_child {
            TryWaitResult::Pending
        } else {
            TryWaitResult::NoChildren
        }
    }

    pub(super) fn ppid(&self, pid: u32) -> u32 {
        self.inner
            .state
            .lock()
            .processes
            .get(&pid)
            .map_or(0, |record| record.ppid)
    }

    pub(super) fn pgid(&self, pid: u32) -> Option<NonZeroU32> {
        self.inner
            .state
            .lock()
            .processes
            .get(&pid)
            .filter(|record| record.is_live())
            .map(|record| record.pgid)
    }

    pub(super) fn sid(&self, pid: u32) -> Option<NonZeroU32> {
        self.inner
            .state
            .lock()
            .processes
            .get(&pid)
            .filter(|record| record.is_live())
            .map(|record| record.sid)
    }

    pub(super) fn setpgid(
        &self,
        caller: NonZeroU32,
        raw_pid: u32,
        raw_pgid: u32,
    ) -> Result<(), u64> {
        const EACCES: u64 = 13;
        let target_pid = if raw_pid == 0 { caller.get() } else { raw_pid };
        let new_pgid =
            NonZeroU32::new(if raw_pgid == 0 { target_pid } else { raw_pgid }).ok_or(EINVAL)?;

        let mut state = self.inner.state.lock();
        let caller_sid = state
            .processes
            .get(&caller.get())
            .map(|record| record.sid)
            .unwrap_or(caller);

        let (target_ppid, target_sid, target_has_execed) = {
            let Some(target) = state
                .processes
                .get(&target_pid)
                .filter(|record| record.is_live())
            else {
                return Err(ESRCH);
            };
            (target.ppid, target.sid, target.has_execed)
        };

        let is_self = target_pid == caller.get();
        let is_child = target_ppid == caller.get();
        if !is_self && !is_child {
            return Err(ESRCH);
        }
        if is_child && target_has_execed {
            return Err(EACCES);
        }
        if target_pid == target_sid.get() || target_sid != caller_sid {
            return Err(EPERM);
        }
        if new_pgid.get() != target_pid {
            let group_exists_in_session = state.processes.values().any(|record| {
                record.is_live() && record.sid == caller_sid && record.pgid == new_pgid
            });
            if !group_exists_in_session {
                return Err(EPERM);
            }
        }
        if let Some(target) = state.processes.get_mut(&target_pid) {
            target.pgid = new_pgid;
            target.signals.set_pgid(new_pgid.get());
        }
        Ok(())
    }

    pub(super) fn setsid(&self, caller: NonZeroU32) -> Result<NonZeroU32, u64> {
        let mut state = self.inner.state.lock();
        let conflict = state
            .processes
            .values()
            .any(|record| record.is_live() && record.pgid == caller);
        if conflict {
            return Err(EPERM);
        }
        let target = state
            .processes
            .get_mut(&caller.get())
            .filter(|record| record.is_live())
            .ok_or(EPERM)?;
        target.sid = caller;
        target.pgid = caller;
        target.signals.set_pgid(caller.get());
        Ok(caller)
    }

    pub(super) fn register_thread(
        &self,
        tgid: NonZeroU32,
        slot: Arc<ThreadSignalSlot>,
        credentials: Arc<spin::Mutex<Credentials>>,
    ) {
        self.inner.state.lock().threads.insert(
            slot.tid().get(),
            RegisteredThread {
                tgid,
                slot,
                credentials,
            },
        );
    }

    pub(super) fn unregister_thread(&self, tid: NonZeroU32) {
        self.inner.state.lock().threads.remove(&tid.get());
    }

    pub(super) fn lookup_process(
        &self,
        pid: u32,
    ) -> Option<(Arc<ProcessSignals>, Arc<spin::Mutex<Credentials>>)> {
        let state = self.inner.state.lock();
        state
            .processes
            .get(&pid)
            .filter(|entry| entry.is_live())
            .map(|entry| (entry.signals.clone(), entry.credentials.clone()))
    }

    pub(super) fn processes_in_group(
        &self,
        pgid: u32,
    ) -> alloc::vec::Vec<(Arc<ProcessSignals>, Arc<spin::Mutex<Credentials>>)> {
        let state = self.inner.state.lock();
        state
            .processes
            .values()
            .filter(|entry| entry.is_live() && entry.pgid.get() == pgid)
            .map(|entry| (entry.signals.clone(), entry.credentials.clone()))
            .collect()
    }

    pub(super) fn all_processes_except(
        &self,
        caller_pid: u32,
    ) -> alloc::vec::Vec<(Arc<ProcessSignals>, Arc<spin::Mutex<Credentials>>)> {
        let state = self.inner.state.lock();
        state
            .processes
            .iter()
            .filter(|&(&pid, entry)| entry.is_live() && pid != 1 && pid != caller_pid)
            .map(|(_, entry)| (entry.signals.clone(), entry.credentials.clone()))
            .collect()
    }

    pub(super) fn lookup_thread(
        &self,
        tid: u32,
    ) -> Option<(
        NonZeroU32,
        Arc<ThreadSignalSlot>,
        Arc<spin::Mutex<Credentials>>,
    )> {
        let state = self.inner.state.lock();
        state
            .threads
            .get(&tid)
            .map(|entry| (entry.tgid, entry.slot.clone(), entry.credentials.clone()))
    }

    /// Whether `pid` is currently allocated (live or unreaped zombie) in this namespace.
    pub fn contains(&self, pid: u32) -> bool {
        self.inner.state.lock().allocated.contains(&pid)
    }

    /// Number of live processes (thread groups) in this namespace, as
    /// `sysinfo().procs` reports.
    pub fn process_count(&self) -> u32 {
        self.inner.state.lock().live_processes
    }
}

struct LiveThread {
    tid: NonZeroU32,
    robust_list: Arc<AtomicU64>,
}

/// Shared membership and termination state of one Linux thread group.
pub(super) struct ThreadGroup {
    leader: NonZeroU32,
    pids: PidNamespace,
    live: Vec<LiveThread>,
    /// Closed once `exit_group`, a fatal signal, a fault or an owner kill
    /// condemns the thread group; no further threads are admitted.
    closed: bool,
    /// First group-wide termination (`exit_group`, fatal signal, fault or
    /// owner kill).
    group_termination: Option<ChildTermination>,
    /// Status passed to the most recent single-thread `exit(2)`, reported
    /// when the last thread exits without `exit_group`.
    last_thread_exit: u32,
}

impl ThreadGroup {
    pub(super) fn new(leader: NonZeroU32, pids: PidNamespace, robust_list: Arc<AtomicU64>) -> Self {
        Self {
            leader,
            pids,
            live: vec![LiveThread {
                tid: leader,
                robust_list,
            }],
            closed: false,
            group_termination: None,
            last_thread_exit: 0,
        }
    }

    pub(super) fn contains(&self, tid: u32) -> bool {
        self.live.iter().any(|thread| thread.tid.get() == tid)
    }

    pub(super) fn robust_list_of(&self, tid: u32) -> Option<u64> {
        self.live
            .iter()
            .find(|thread| thread.tid.get() == tid)
            .map(|thread| thread.robust_list.load(Ordering::Acquire))
    }

    pub(super) fn group_ended(&self) -> bool {
        self.closed
    }

    pub(super) fn all_exited(&self) -> bool {
        self.live.is_empty()
    }

    pub(super) fn termination(&self) -> ChildTermination {
        self.group_termination
            .unwrap_or(ChildTermination::Exited(self.last_thread_exit))
    }

    /// Admits a new thread into the group, enforcing `max_threads`
    /// (`RLIMIT_NPROC`) and allocating a unique nonzero TID within
    /// `FUTEX_TID_MASK` from the container's PID namespace.
    pub(super) fn admit(
        &mut self,
        _tgid: NonZeroU32,
        max_threads: u64,
        robust_list: Arc<AtomicU64>,
    ) -> Result<NonZeroU32, u64> {
        if self.closed || self.live.len() as u64 >= max_threads {
            return Err(EAGAIN);
        }
        let tid = self.pids.allocate_tid()?;
        self.live.push(LiveThread { tid, robust_list });
        Ok(tid)
    }

    pub(super) fn withdraw(&mut self, tid: NonZeroU32) -> bool {
        if let Some(pos) = self.live.iter().position(|thread| thread.tid == tid) {
            self.live.swap_remove(pos);
            self.pids.unregister_thread(tid);
            if tid != self.leader {
                self.pids.release_tid(tid);
            }
        }
        self.live.is_empty()
    }

    /// Records a thread's exit and returns `(broadcast_group_stop, all_exited)`.
    pub(super) fn finish(&mut self, tid: NonZeroU32, exit: Exit) -> (bool, bool) {
        let broadcast = match exit {
            Exit::Thread(code) => {
                self.last_thread_exit = u32::from(code);
                false
            }
            Exit::Group(code) => {
                let first = !self.closed;
                self.closed = true;
                if self.group_termination.is_none() {
                    self.group_termination = Some(ChildTermination::Exited(u32::from(code)));
                }
                first
            }
        };
        let all_exited = self.withdraw(tid);
        (broadcast, all_exited)
    }

    /// Condemns the thread group with `termination` (first group termination
    /// wins) and withdraws `tid` if still present.
    pub(super) fn terminate_group(
        &mut self,
        tid: Option<NonZeroU32>,
        termination: ChildTermination,
    ) -> bool {
        let first = !self.closed;
        self.closed = true;
        if self.group_termination.is_none() {
            self.group_termination = Some(termination);
        }
        if let Some(tid) = tid {
            self.withdraw(tid);
        }
        first || self.live.is_empty()
    }
}

pub(super) struct ParsedClone {
    pub(super) flags: u64,
    pub(super) stack: Option<u64>,
    pub(super) parent_tid: u64,
    pub(super) child_tid: u64,
    pub(super) tls: u64,
}

fn validate_thread_flag_combinations(flags: u64) -> Result<(), u64> {
    // kernel/fork.c `copy_process`.
    if flags & CLONE_THREAD != 0 && flags & CLONE_SIGHAND == 0 {
        return Err(EINVAL);
    }
    if flags & CLONE_SIGHAND != 0 && flags & CLONE_VM == 0 {
        return Err(EINVAL);
    }
    if flags & CLONE_SIGHAND != 0 && flags & CLONE_CLEAR_SIGHAND != 0 {
        return Err(EINVAL);
    }
    if flags & CLONE_THREAD != 0 && flags & (CLONE_NEWUSER | CLONE_NEWPID | CLONE_PIDFD) != 0 {
        return Err(EINVAL);
    }
    if flags & (CLONE_NEWNS | CLONE_FS) == (CLONE_NEWNS | CLONE_FS) {
        return Err(EINVAL);
    }
    if flags & REQUIRED_THREAD_FLAGS != REQUIRED_THREAD_FLAGS {
        return Err(ENOSYS);
    }
    if flags & !(REQUIRED_THREAD_FLAGS | OPTIONAL_THREAD_FLAGS) != 0 {
        return Err(ENOSYS);
    }
    Ok(())
}

/// `clone` (`kernel/fork.c` `SYSCALL_DEFINE5(clone)`).
pub(super) async fn clone<
    R: Resources,
    M: UserMemory,
    T: Thread<R>,
    F: super::fs::Filesystem<R>,
>(
    process: &Process<R>,
    args: [u64; 6],
    memory: &mut M,
    thread: &mut T,
    fs: &mut F,
) -> u64 {
    let decoded = process.shared.abi.clone_registers(args);
    let raw_flags = u64::from(decoded.flags as u32);
    let exit_signal_raw = raw_flags & CSIGNAL;
    let flags = raw_flags & !CSIGNAL;
    let parsed = ParsedClone {
        flags,
        stack: (decoded.stack != 0).then_some(decoded.stack),
        parent_tid: decoded.parent_tid,
        child_tid: decoded.child_tid,
        tls: decoded.tls,
    };
    if flags & CLONE_THREAD != 0 {
        if let Err(err) = validate_thread_flag_combinations(flags) {
            return errno(err);
        }
        spawn_parsed_clone(process, parsed, memory, thread)
    } else {
        let exit_signal = match super::process::validate_process_clone_flags(flags, exit_signal_raw)
        {
            Ok(sig) => sig,
            Err(err) => return errno(err),
        };
        super::process::clone_process(process, parsed, exit_signal, memory, thread, fs).await
    }
}

/// `clone3(uargs, size)` (`kernel/fork.c` `SYSCALL_DEFINE2(clone3)` and
/// `copy_clone_args_from_user`).
pub(super) async fn clone3<
    R: Resources,
    M: UserMemory,
    T: Thread<R>,
    F: super::fs::Filesystem<R>,
>(
    process: &Process<R>,
    args: [u64; 6],
    memory: &mut M,
    thread: &mut T,
    fs: &mut F,
) -> u64 {
    let [uargs, size, ..] = args;
    if size > PAGE_BYTES {
        return errno(E2BIG);
    }
    if size < CLONE_ARGS_SIZE_VER0 {
        return errno(EINVAL);
    }
    if uargs > process.shared.abi.task_size().saturating_sub(size) {
        return errno(EFAULT);
    }
    let known = (size as usize).min(CLONE_ARGS_SIZE_VER2);
    let mut raw = [0u8; CLONE_ARGS_SIZE_VER2];
    if memory.read(uargs, &mut raw[..known]).is_err() {
        return errno(EFAULT);
    }
    if size as usize > CLONE_ARGS_SIZE_VER2 {
        let extra = size as usize - CLONE_ARGS_SIZE_VER2;
        let mut tail = vec![0u8; extra];
        if memory
            .read(uargs + CLONE_ARGS_SIZE_VER2 as u64, &mut tail)
            .is_err()
        {
            return errno(EFAULT);
        }
        if tail.iter().any(|&byte| byte != 0) {
            return errno(E2BIG);
        }
    }
    let word =
        |index: usize| u64::from_le_bytes(raw[index * 8..(index + 1) * 8].try_into().unwrap());
    let flags = word(0);
    let child_tid = word(2);
    let parent_tid = word(3);
    let exit_signal = word(4);
    let stack_base = word(5);
    let stack_size = word(6);
    let tls = word(7);
    let set_tid = word(8);
    let set_tid_size = word(9);

    if flags & (CSIGNAL | CLONE_DETACHED) != 0
        || flags & !KNOWN_CLONE3_FLAGS != 0
        || exit_signal & !CSIGNAL != 0
        || (flags & (CLONE_THREAD | CLONE_PARENT) != 0 && exit_signal != 0)
        || (stack_base == 0) != (stack_size == 0)
        || (set_tid == 0) != (set_tid_size == 0)
    {
        return errno(EINVAL);
    }
    if set_tid_size != 0 {
        return errno(EPERM);
    }
    let stack = match stack_base {
        0 => None,
        base => match base.checked_add(stack_size) {
            Some(top) if top <= process.shared.abi.task_size() => Some(top),
            _ => return errno(EINVAL),
        },
    };
    let parsed = ParsedClone {
        flags,
        stack,
        parent_tid,
        child_tid,
        tls,
    };
    if flags & CLONE_THREAD != 0 {
        if let Err(err) = validate_thread_flag_combinations(flags) {
            return errno(err);
        }
        spawn_parsed_clone(process, parsed, memory, thread)
    } else {
        let exit_sig = match super::process::validate_process_clone_flags(flags, exit_signal) {
            Ok(sig) => sig,
            Err(err) => return errno(err),
        };
        super::process::clone_process(process, parsed, exit_sig, memory, thread, fs).await
    }
}

pub(super) fn write_tid<M: UserMemory>(
    address: u64,
    tid: u32,
    memory: &mut M,
) -> Result<(), MemoryFault> {
    if address & 3 == 0 {
        memory.atomic_store_u32(address, tid)
    } else {
        memory.write(address, &tid.to_le_bytes())
    }
}

fn spawn_parsed_clone<R: Resources, M: UserMemory, T: Thread<R>>(
    process: &Process<R>,
    parsed: ParsedClone,
    memory: &mut M,
    thread: &mut T,
) -> u64 {
    let tls = if parsed.flags & CLONE_SETTLS != 0 {
        if parsed.tls >= process.shared.abi.task_size() {
            return errno(EPERM);
        }
        Some(parsed.tls)
    } else {
        None
    };
    let max_threads = process.limit(Resource::Nproc).current;
    let robust_list = Arc::new(AtomicU64::new(0));
    let tid =
        match process
            .shared
            .threads
            .lock()
            .admit(process.pid(), max_threads, robust_list.clone())
        {
            Ok(tid) => tid,
            Err(err) => return errno(err),
        };
    if parsed.flags & CLONE_PARENT_SETTID != 0
        && write_tid(parsed.parent_tid, tid.get(), memory).is_err()
    {
        process.shared.threads.lock().withdraw(tid);
        return errno(EFAULT);
    }
    if parsed.flags & CLONE_CHILD_SETTID != 0 {
        let _ = write_tid(parsed.child_tid, tid.get(), memory);
    }
    // Child thread inherits the caller's signal mask and starts with an empty
    // private pending set and disabled alternate stack (`kernel/fork.c`).
    let thread_signals = process
        .shared
        .signals
        .register_thread(tid, process.signals.current_mask());
    process.shared.pids.register_thread(
        process.pid(),
        thread_signals.clone(),
        process.shared.credentials.clone(),
    );
    let child = Process {
        shared: process.shared.clone(),
        tid,
        signals: thread_signals,
        clear_child_tid: if parsed.flags & CLONE_CHILD_CLEARTID != 0 {
            parsed.child_tid
        } else {
            0
        },
        robust_list,
        exited: false,
    };
    match thread.spawn_thread(
        child,
        SpawnedThread {
            stack: parsed.stack,
            tls,
        },
    ) {
        Ok(()) => u64::from(tid.get()),
        Err(error) => {
            // `child` dropped inside `spawn_thread`, which already withdrew
            // `tid`; withdraw again idempotently in case a custom host dropped
            // after `exited` or before.
            process.shared.signals.unregister_thread(tid);
            process.shared.threads.lock().withdraw(tid);
            errno(match error {
                SpawnError::OutOfMemory => ENOMEM,
                SpawnError::Busy => EAGAIN,
                SpawnError::InvalidTls => EPERM,
            })
        }
    }
}

/// `sched_yield()` (`kernel/sched/syscalls.c`).
pub(super) async fn sched_yield() -> u64 {
    system::yield_now().await;
    0
}

/// `sched_getaffinity(pid, cpusetsize, mask)` (`kernel/sched/syscalls.c`).
///
/// Raw kernel syscall returns the byte length written to `mask` (a multiple
/// of `sizeof(unsigned long)`), which libc uses to zero any trailing bytes.
pub(super) fn sched_getaffinity<R: Resources, M: UserMemory, O: System>(
    process: &Process<R>,
    args: [u64; 6],
    memory: &mut M,
    output: &O,
) -> u64 {
    let pid = args[0] as u32 as i32;
    let len = args[1] as u32 as usize;
    let cpus = output.processor_count().max(1) as usize;
    let required = cpus.div_ceil(64) * 8;
    if !len.is_multiple_of(8) || len < required {
        return errno(EINVAL);
    }
    if pid < 0 || (pid != 0 && !process.shared.threads.lock().contains(pid as u32)) {
        return errno(ESRCH);
    }
    let mut mask = vec![0u8; required];
    for cpu in 0..cpus {
        mask[cpu / 8] |= 1 << (cpu % 8);
    }
    if memory.write(args[2], &mask).is_err() {
        return errno(EFAULT);
    }
    required as u64
}

/// `nanosleep(req, rem)` (`kernel/time/hrtimer.c`).
pub(super) async fn nanosleep<M: UserMemory, O: Clock + System>(
    signals: &ThreadSignalSlot,
    args: [u64; 6],
    memory: &mut M,
    output: &O,
) -> u64 {
    clock_nanosleep(signals, [0, 0, args[0], args[1], 0, 0], memory, output).await
}

/// `clock_nanosleep(clockid, flags, req, rem)` (`kernel/time/posix-timers.c`).
///
/// Interrupted relative sleeps write the remaining time to `rem` (if non-null)
/// and return `-EINTR`; neither `nanosleep` nor `clock_nanosleep` is restarted
/// by `SA_RESTART` (`signal(7)`).
pub(super) async fn clock_nanosleep<M: UserMemory, O: Clock + System>(
    signals: &ThreadSignalSlot,
    args: [u64; 6],
    memory: &mut M,
    output: &O,
) -> u64 {
    enum SleepClock {
        Realtime,
        Monotonic,
    }
    let clock = match args[0] as u32 as i32 {
        0 | 11 => SleepClock::Realtime,
        1 | 2 | 7 => SleepClock::Monotonic,
        // `clock_thread`, `clock_monotonic_raw`, `clock_realtime_coarse`, and
        // `clock_monotonic_coarse` have `.nsleep = NULL` in Linux v6.12
        // (`kernel/time/posix-timers.c`, `kernel/time/posix-cpu-timers.c`), so
        // `clock_nanosleep` answers `EOPNOTSUPP`.
        3..=6 => return errno(EOPNOTSUPP),
        _ => return errno(EINVAL),
    };
    let mut bytes = [0u8; 16];
    if memory.read(args[2], &mut bytes).is_err() {
        return errno(EFAULT);
    }
    let sec = i64::from_le_bytes(bytes[..8].try_into().unwrap());
    let nsec = i64::from_le_bytes(bytes[8..].try_into().unwrap());
    if sec < 0 || !(0..NANOS_PER_SECOND as i64).contains(&nsec) {
        return errno(EINVAL);
    }
    let flags = args[1] as u32;
    if flags & !TIMER_ABSTIME != 0 {
        return errno(EINVAL);
    }
    let requested = (sec as u64)
        .saturating_mul(NANOS_PER_SECOND)
        .saturating_add(nsec as u64);
    let rem_ptr = args[3];
    if flags & TIMER_ABSTIME != 0 {
        let now = match clock {
            SleepClock::Realtime => output.realtime_nanos(),
            SleepClock::Monotonic => output.now_nanos(),
        };
        if requested > now {
            let deadline = output.now_nanos().saturating_add(requested - now);
            if matches!(
                signals.interruptible(output.sleep_until(deadline)).await,
                WaitOutcome::Interrupted
            ) {
                return errno(EINTR);
            }
        }
    } else if requested != 0 {
        let deadline = output.now_nanos().saturating_add(requested);
        if matches!(
            signals.interruptible(output.sleep_until(deadline)).await,
            WaitOutcome::Interrupted
        ) {
            if rem_ptr != 0 {
                let remaining = deadline.saturating_sub(output.now_nanos());
                let mut out = [0u8; 16];
                out[..8].copy_from_slice(&(remaining / NANOS_PER_SECOND).to_le_bytes());
                out[8..].copy_from_slice(&(remaining % NANOS_PER_SECOND).to_le_bytes());
                if memory.write(rem_ptr, &out).is_err() {
                    return errno(EFAULT);
                }
            }
            return errno(EINTR);
        }
    }
    0
}
