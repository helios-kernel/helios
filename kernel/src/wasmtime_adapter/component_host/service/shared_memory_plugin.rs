//! Core-pinned multi-core execution for shared-memory WASI Preview 1 + `wasi-threads`
//! kernel plugins (`compiler`, and future shared-memory core modules).
//!
//! # Concurrency contract
//!
//! - [`SharedMemorySessionSlot`] serialises sessions that share one plugin linear
//!   memory through [`crate::RawMutex`]. Only one session touches the shared
//!   memory at a time; waiting callers park cleanly without spinning.
//! - [`run_shared_memory_session`] binds the session's lifetime to its body,
//!   never to its requester: if a requester drops its reply channel before the
//!   slot is free, the session exits without instantiating anything; if a
//!   requester leaves mid-session, `condemn` fires at most once and the session
//!   still joins every core-pinned worker before releasing the slot.
//! - [`CoreAffinityPlan`] snapshots live online `Kernel`-role processors when a
//!   session starts (`OnlineSet` + `component_host_processor_role`) and pins
//!   main and spawned worker threads 1:1 onto distinct `ProcessorId`s via
//!   [`crate::Spawner::try_spawn_on`]. If a target core went offline in the
//!   window between snapshot and spawn, `spawn_pinned` falls back in ring order
//!   across remaining online cores in the plan (and finally `bootstrap`, which
//!   stays online for the life of the machine).

use core::future::{Future, poll_fn};
use core::pin::pin;
use core::sync::atomic::{AtomicI32, AtomicU32, AtomicUsize, Ordering};
use core::task::Poll;

use alloc::sync::Arc;
use alloc::vec::Vec;
use futures::channel::oneshot::Sender;
use helios_hal::cpu::{Cpu, ProcessorId};
use smallvec::SmallVec;
use spin::Mutex;
use wasmtime::{InstancePre, SharedMemory};

use super::{ComponentHostProcessorRole, component_host_processor_role};
use crate::wasmtime_adapter::preemption::GuestInterrupts;
use crate::wasmtime_adapter::store::user_residency;
use crate::{
    InstanceId, InstanceRegistry, KillOutcome, KillReason, OnlineSet, ProgramExecError, RawMutex,
    RawMutexLease, Spawner,
};

/// Exclusive lease gate over a shared-memory kernel plugin's linear memory.
pub(super) struct SharedMemorySessionSlot {
    lock: RawMutex,
}

/// Ownership of a shared-memory plugin session; dropping it wakes one queued session.
pub(super) struct SharedMemorySessionLease<'a> {
    _lease: RawMutexLease<'a>,
}

impl SharedMemorySessionSlot {
    pub(super) fn new() -> Self {
        Self {
            lock: RawMutex::new(),
        }
    }

    /// Parks until the slot is free, then acquires it.
    pub(super) async fn acquire(&self) -> SharedMemorySessionLease<'_> {
        SharedMemorySessionLease {
            _lease: self.lock.lock().await,
        }
    }
}

/// Snapshot of live online `Kernel`-role processors at the start of a
/// shared-memory multi-core plugin session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct CoreAffinityPlan {
    targets: SmallVec<[ProcessorId; 16]>,
    bootstrap: ProcessorId,
}

impl CoreAffinityPlan {
    /// Captures all currently online `Kernel`-role processors for this session,
    /// placing `caller` at index `0` when eligible so the main store starts on
    /// the initiating core. Falls back to `[bootstrap]` when single-core or when
    /// no secondary `Kernel` processor is online.
    pub(super) fn capture<CpuImpl: Cpu>(
        cpu: &CpuImpl,
        online: &OnlineSet,
        caller: ProcessorId,
    ) -> Self {
        let processor_count = cpu.processor_count();
        let bootstrap = cpu.bootstrap_processor();
        let mut targets = SmallVec::new();
        for index in 0..processor_count {
            let id =
                ProcessorId::new(u16::try_from(index).unwrap_or_else(|_| {
                    panic!("processor index {index} exceeds ProcessorId range")
                }));
            if online.contains(id)
                && component_host_processor_role(id, processor_count, bootstrap)
                    == ComponentHostProcessorRole::Kernel
            {
                targets.push(id);
            }
        }
        if targets.is_empty() {
            targets.push(bootstrap);
        } else if let Some(pos) = targets.iter().position(|&id| id == caller) {
            targets.swap(0, pos);
        }
        Self { targets, bootstrap }
    }

    /// Creates a single-processor plan for scratch initialization and isolated unit tests.
    pub(super) fn single(processor: ProcessorId) -> Self {
        let mut targets = SmallVec::new();
        targets.push(processor);
        Self {
            targets,
            bootstrap: processor,
        }
    }

    /// Number of parallel threads advertised to the plugin for this session.
    pub(super) fn worker_count(&self) -> u32 {
        u32::try_from(self.targets.len())
            .unwrap_or_else(|_| panic!("shared-memory plugin processor count exceeds u32"))
    }

    /// Processor assigned to the session's main store.
    pub(super) fn main(&self) -> ProcessorId {
        self.targets[0]
    }

    /// Processor assigned to spawned worker `worker_slot` (`1:1` across `targets`).
    pub(super) fn worker(&self, worker_slot: usize) -> ProcessorId {
        self.targets[worker_slot % self.targets.len()]
    }

    /// Pins `future` onto `preferred`, falling back in ring order across remaining
    /// online processors in the plan (and finally `bootstrap`) if `preferred`
    /// went offline between snapshot and spawn.
    pub(super) fn spawn_pinned<CpuImpl, Fut>(
        &self,
        spawner: &Spawner<CpuImpl>,
        preferred: ProcessorId,
        future: Fut,
    ) -> crate::JoinHandle<Fut::Output>
    where
        CpuImpl: Cpu + Clone,
        Fut: Future + Send + 'static,
        Fut::Output: Send + 'static,
    {
        let mut pending = match spawner.try_spawn_on(preferred, future) {
            Ok(handle) => return handle,
            Err(error) => error.future,
        };
        let start = self
            .targets
            .iter()
            .position(|&id| id == preferred)
            .map_or(0, |index| index + 1);
        for offset in 0..self.targets.len() {
            let candidate = self.targets[(start + offset) % self.targets.len()];
            if candidate == preferred {
                continue;
            }
            match spawner.try_spawn_on(candidate, pending) {
                Ok(handle) => return handle,
                Err(error) => pending = error.future,
            }
        }
        if preferred != self.bootstrap && !self.targets.contains(&self.bootstrap) {
            match spawner.try_spawn_on(self.bootstrap, pending) {
                Ok(handle) => return handle,
                Err(error) => pending = error.future,
            }
        }
        drop(pending);
        panic!(
            "shared-memory plugin session could not place task on preferred core {} or bootstrap core {}",
            preferred.id(),
            self.bootstrap.id()
        );
    }
}

/// Telemetry and trap status reported when one shared-memory worker store exits.
pub(super) struct SharedMemoryThreadReport {
    /// Trap error that condemned the session, when this worker was first to trap.
    pub(super) trap: Option<ProgramExecError>,
    pub(super) thread_id: i32,
    pub(super) processor: u16,
    pub(super) spawned_ns: u64,
    pub(super) started_ns: u64,
    pub(super) instantiated_ns: u64,
    pub(super) finished_ns: u64,
}

/// Shared runtime state held across sessions of one cached core-module plugin.
pub(super) struct SharedMemoryCoreShared<T> {
    pub(super) memory: SharedMemory,
    pub(super) entropy: Mutex<crate::EntropyPool>,
    pub(super) instance_pre: spin::Once<Arc<InstancePre<T>>>,
    pub(super) next_thread_id: AtomicI32,
    /// Per-session worker spawn index so each session distributes threads 1:1
    /// starting at `targets[0]`.
    pub(super) session_worker_cursor: AtomicUsize,
    /// Live worker count (`RAYON_NUM_THREADS`) for the active session.
    pub(super) active_worker_threads: AtomicU32,
    pub(super) thread_tasks: Mutex<Vec<crate::JoinHandle<SharedMemoryThreadReport>>>,
    /// Interrupt routes of the engine every plugin store runs on.
    pub(super) interrupts: Arc<GuestInterrupts>,
}

impl<T> SharedMemoryCoreShared<T> {
    pub(super) fn new(
        memory: SharedMemory,
        entropy: crate::EntropyPool,
        interrupts: Arc<GuestInterrupts>,
        initial_worker_threads: u32,
    ) -> Self {
        Self {
            memory,
            entropy: Mutex::new(entropy),
            instance_pre: spin::Once::new(),
            next_thread_id: AtomicI32::new(0),
            session_worker_cursor: AtomicUsize::new(0),
            active_worker_threads: AtomicU32::new(initial_worker_threads.max(1)),
            thread_tasks: Mutex::new(Vec::new()),
            interrupts,
        }
    }

    /// Resets per-session worker assignment state under the held session slot.
    pub(super) fn begin_session(&self, plan: &CoreAffinityPlan) {
        self.session_worker_cursor.store(0, Ordering::Relaxed);
        self.active_worker_threads
            .store(plan.worker_count(), Ordering::Relaxed);
    }

    pub(super) fn worker_threads(&self) -> u32 {
        self.active_worker_threads.load(Ordering::Relaxed).max(1)
    }
}

/// Runs one shared-memory plugin session for the requester on `reply`.
///
/// Acquires `slot` unless the requester drops `reply` first, drives `body` to
/// completion so every core-pinned worker is joined before releasing `lease`,
/// and condemns the instance at most once if the requester goes away mid-run.
pub(super) async fn run_shared_memory_session<Reply, Output, Condemn, Body>(
    slot: &SharedMemorySessionSlot,
    mut reply: Sender<Reply>,
    start: impl FnOnce() -> (Condemn, Body),
    finish: impl FnOnce(Output) -> Reply,
) where
    Condemn: FnOnce(),
    Body: Future<Output = Output>,
{
    let Some(lease) = acquire_unless_abandoned(slot, &mut reply).await else {
        return;
    };
    let (condemn, body) = start();
    let output = watch_requester(&mut reply, condemn, body).await;
    // All workers are joined by `body`, so nothing touches shared memory now.
    drop(lease);
    if reply.is_canceled() {
        return;
    }
    let _ = reply.send(finish(output));
}

async fn acquire_unless_abandoned<'slot, Reply>(
    slot: &'slot SharedMemorySessionSlot,
    reply: &mut Sender<Reply>,
) -> Option<SharedMemorySessionLease<'slot>> {
    let mut acquire = pin!(slot.acquire());
    poll_fn(|cx| {
        if reply.poll_canceled(cx).is_ready() {
            return Poll::Ready(None);
        }
        acquire.as_mut().poll(cx).map(Some)
    })
    .await
}

async fn watch_requester<Reply, Output>(
    reply: &mut Sender<Reply>,
    condemn: impl FnOnce(),
    body: impl Future<Output = Output>,
) -> Output {
    let mut condemn = Some(condemn);
    let mut body = pin!(body);
    poll_fn(|cx| {
        if condemn.is_some()
            && reply.poll_canceled(cx).is_ready()
            && let Some(condemn) = condemn.take()
        {
            condemn();
        }
        body.as_mut().poll(cx)
    })
    .await
}

/// Condemns `instance` for `reason` and interrupts every store of it (main and
/// workers alike) so parked or running stores unwind promptly.
pub(super) fn condemn_session(
    registry: &InstanceRegistry,
    interrupts: &GuestInterrupts,
    instance: InstanceId,
    reason: KillReason,
    now_nanos: u64,
) -> KillOutcome {
    let residency = user_residency();
    let outcome = registry.request_kill(instance, reason, now_nanos, &residency);
    interrupts.interrupt_instance(instance);
    outcome
}

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;
    use alloc::task::Wake;
    use core::future::Future;
    use core::pin::{Pin, pin};
    use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use core::task::{Context, Waker};

    use futures::channel::oneshot;
    use helios_hal::cpu::Timebase;
    use helios_hal::watchdog::ProgressCounter;

    use super::*;
    use crate::memory::UserMemoryPool;
    use crate::test_support::{RecordingSmpCpu, TEST_POOL_NODE_BYTES, TestMachine};
    use crate::{Executor, test_processor_identity};

    #[derive(Default)]
    struct WakeCount(AtomicUsize);

    impl WakeCount {
        fn count(&self) -> usize {
            self.0.load(Ordering::SeqCst)
        }
    }

    impl Wake for WakeCount {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct Task {
        wakes: Arc<WakeCount>,
        waker: Waker,
    }

    impl Task {
        fn new() -> Self {
            let wakes = Arc::new(WakeCount::default());
            Self {
                waker: Waker::from(wakes.clone()),
                wakes,
            }
        }

        fn context(&self) -> Context<'_> {
            Context::from_waker(&self.waker)
        }
    }

    struct Platform {
        registry: InstanceRegistry,
        interrupts: GuestInterrupts,
    }

    impl Platform {
        fn new() -> Self {
            Self {
                registry: InstanceRegistry::new(),
                interrupts: GuestInterrupts::new(1, Timebase::new(1_000_000_000)),
            }
        }
    }

    struct Compile {
        compiled: oneshot::Receiver<()>,
        workers: [oneshot::Receiver<()>; 2],
        body_polls: Arc<AtomicUsize>,
    }

    struct Gates {
        compiled: oneshot::Sender<()>,
        workers: [oneshot::Sender<()>; 2],
    }

    fn compile() -> (Compile, Gates, Arc<AtomicUsize>) {
        let (compiled_tx, compiled) = oneshot::channel();
        let (first_tx, first) = oneshot::channel();
        let (second_tx, second) = oneshot::channel();
        let body_polls = Arc::new(AtomicUsize::new(0));
        (
            Compile {
                compiled,
                workers: [first, second],
                body_polls: body_polls.clone(),
            },
            Gates {
                compiled: compiled_tx,
                workers: [first_tx, second_tx],
            },
            body_polls,
        )
    }

    impl Compile {
        async fn run(self) -> &'static str {
            let Self {
                compiled,
                workers: [first, second],
                body_polls,
            } = self;
            let _ = counted(&body_polls, compiled).await;
            let _ = counted(&body_polls, first).await;
            let _ = counted(&body_polls, second).await;
            "compiled"
        }
    }

    async fn counted(polls: &AtomicUsize, mut gate: oneshot::Receiver<()>) {
        let _ = poll_fn(|cx| {
            polls.fetch_add(1, Ordering::SeqCst);
            Pin::new(&mut gate).poll(cx)
        })
        .await;
    }

    #[test]
    fn a_dropped_reply_condemns_its_session() {
        let platform = Platform::new();
        let slot = SharedMemorySessionSlot::new();
        let (reply, requester) = oneshot::channel::<&'static str>();
        let instance = platform.registry.register("compiler-plugin", 0);
        let condemnations = Arc::new(AtomicUsize::new(0));
        let (body, gates, body_polls) = compile();
        let session = run_shared_memory_session(
            &slot,
            reply,
            {
                let condemnations = condemnations.clone();
                let registry = platform.registry.clone();
                let interrupts = &platform.interrupts;
                let id = instance.id();
                move || {
                    (
                        move || {
                            condemnations.fetch_add(1, Ordering::SeqCst);
                            condemn_session(
                                &registry,
                                interrupts,
                                id,
                                KillReason::RequesterGone,
                                0,
                            );
                        },
                        body.run(),
                    )
                }
            },
            |output| output,
        );
        let mut session = pin!(session);
        let task = Task::new();

        assert!(session.as_mut().poll(&mut task.context()).is_pending());
        assert_eq!(condemnations.load(Ordering::SeqCst), 0);
        assert_eq!(instance.pending_kill(), None);

        drop(requester);
        assert_eq!(task.wakes.count(), 1);
        let polls_before = body_polls.load(Ordering::SeqCst);
        assert!(session.as_mut().poll(&mut task.context()).is_pending());
        assert_eq!(instance.pending_kill(), Some(KillReason::RequesterGone));
        assert_eq!(condemnations.load(Ordering::SeqCst), 1);
        assert!(body_polls.load(Ordering::SeqCst) > polls_before);

        assert!(session.as_mut().poll(&mut task.context()).is_pending());
        assert_eq!(condemnations.load(Ordering::SeqCst), 1);
        let Gates { compiled, workers } = gates;
        compiled.send(()).unwrap();
        for worker in workers {
            worker.send(()).unwrap();
        }
        assert!(session.as_mut().poll(&mut task.context()).is_ready());
    }

    #[test]
    fn the_session_slot_outlives_every_worker() {
        let platform = Platform::new();
        let slot = SharedMemorySessionSlot::new();
        let (reply, requester) = oneshot::channel::<&'static str>();
        let instance = platform.registry.register("compiler-plugin", 0);
        let (body, gates, _) = compile();
        let session = run_shared_memory_session(
            &slot,
            reply,
            {
                let registry = platform.registry.clone();
                let interrupts = &platform.interrupts;
                let id = instance.id();
                move || {
                    (
                        move || {
                            condemn_session(
                                &registry,
                                interrupts,
                                id,
                                KillReason::RequesterGone,
                                0,
                            );
                        },
                        body.run(),
                    )
                }
            },
            |output| output,
        );
        let mut session = pin!(session);
        let task = Task::new();
        let next_task = Task::new();

        assert!(session.as_mut().poll(&mut task.context()).is_pending());
        drop(requester);
        let Gates { compiled, workers } = gates;
        let [first, second] = workers;

        compiled.send(()).unwrap();
        assert!(session.as_mut().poll(&mut session_cx(&task)).is_pending());
        let mut next = pin!(slot.acquire());
        assert!(next.as_mut().poll(&mut next_task.context()).is_pending());

        first.send(()).unwrap();
        assert!(session.as_mut().poll(&mut task.context()).is_pending());
        assert!(next.as_mut().poll(&mut next_task.context()).is_pending());

        second.send(()).unwrap();
        assert!(session.as_mut().poll(&mut task.context()).is_ready());
        assert_eq!(next_task.wakes.count(), 1);
        assert!(next.as_mut().poll(&mut next_task.context()).is_ready());
    }

    fn session_cx(task: &Task) -> Context<'_> {
        task.context()
    }

    #[test]
    fn a_queued_session_whose_requester_left_never_starts() {
        let slot = SharedMemorySessionSlot::new();
        let holder = futures_lite::future::block_on(slot.acquire());
        let (reply, requester) = oneshot::channel::<&'static str>();
        let started = Arc::new(AtomicBool::new(false));
        let session = run_shared_memory_session(
            &slot,
            reply,
            {
                let started = started.clone();
                move || {
                    started.store(true, Ordering::SeqCst);
                    (|| {}, core::future::ready("compiled"))
                }
            },
            |output| output,
        );
        let mut session = pin!(session);
        let task = Task::new();

        assert!(session.as_mut().poll(&mut task.context()).is_pending());
        drop(requester);
        assert_eq!(task.wakes.count(), 1);
        assert!(session.as_mut().poll(&mut task.context()).is_ready());
        drop(holder);
        assert!(!started.load(Ordering::SeqCst));
        let mut again = pin!(slot.acquire());
        assert!(again.as_mut().poll(&mut task.context()).is_ready());
    }

    fn four_core_pool() -> &'static UserMemoryPool {
        TestMachine {
            processor_nodes: alloc::vec![0, 0, 0, 0],
            distances: alloc::vec![10],
        }
        .pool(TEST_POOL_NODE_BYTES)
    }

    #[test]
    fn affinity_plan_filters_offline_and_system_cores_and_falls_back_cleanly() {
        test_processor_identity::set(ProcessorId::new(0));
        let executor0 = Executor::isolated(
            ProgressCounter::new(),
            four_core_pool(),
            ProcessorId::new(0),
        );
        let control = executor0
            .spawner(RecordingSmpCpu::new(0, 4))
            .processor_control();
        let online = control.online_set();
        for id in 0..4u16 {
            let processor = ProcessorId::new(id);
            executor0.group().bring_processor_online(processor);
        }
        // Take core 2 offline: only online Kernel-role cores remain.
        let executor2 = executor0.sibling(ProgressCounter::new(), ProcessorId::new(2));
        let cpu2 = RecordingSmpCpu::new(2, 4);
        assert_eq!(executor2.take_offline(&cpu2, ProcessorId::new(0)), Ok(()));

        let cpu = RecordingSmpCpu::new(0, 4);
        let plan = CoreAffinityPlan::capture(&cpu, online, ProcessorId::new(3));
        assert_eq!(plan.main(), ProcessorId::new(3));
        assert!(!plan.targets.contains(&ProcessorId::new(2)));
        if cfg!(feature = "embedded-debugger") {
            assert!(!plan.targets.contains(&ProcessorId::new(1)));
            assert_eq!(
                plan.targets.as_slice(),
                &[ProcessorId::new(3), ProcessorId::new(0)]
            );
        } else {
            assert_eq!(
                plan.targets.as_slice(),
                &[
                    ProcessorId::new(3),
                    ProcessorId::new(0),
                    ProcessorId::new(1)
                ]
            );
        }

        // Simulate core 3 going offline between capture and thread spawn:
        // spawning for core 3 falls back to the next online core in the plan (0).
        let executor3 = executor0.sibling(ProgressCounter::new(), ProcessorId::new(3));
        let cpu3 = RecordingSmpCpu::new(3, 4);
        assert_eq!(executor3.take_offline(&cpu3, ProcessorId::new(0)), Ok(()));
        test_processor_identity::set(ProcessorId::new(0));

        let observed = Arc::new(AtomicUsize::new(usize::MAX));
        let spawner = executor0.spawner(cpu.clone());
        let handle = plan.spawn_pinned(&spawner, ProcessorId::new(3), {
            let observed = observed.clone();
            async move {
                observed.store(
                    usize::from(helios_hal::cpu::current_processor().id()),
                    Ordering::SeqCst,
                );
            }
        });
        let timer0 = executor0.timer(cpu.clone());
        executor0.run_until_stalled_with_stats(&timer0);
        drop(handle);
        assert_eq!(observed.load(Ordering::SeqCst), 0);
    }
}
