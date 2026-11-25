use alloc::sync::Arc;
use alloc::vec::Vec;
use core::pin::pin;
use core::sync::atomic::{AtomicUsize, Ordering};
use core::task::{Context, Poll, Waker};

use futures_lite::future::block_on;
use helios_hal::cpu::{Cpu, ProcessorId};
use helios_hal::watchdog::ProgressCounter;
use helios_unix::{ChildTermination, Signal, SignalTermination};
use spin::Mutex;
use wasmtime::{
    Caller, Extern, Func, Global, GlobalType, MemoryType, Mutability, SharedMemory, Val, ValType,
};

use super::*;
use crate::test_support::{TestCpu, TestNetworkService, UnsupportedStorage};
use crate::wasmtime_adapter::engine::build_component_engine_for_platform;
use crate::{Executor, InstanceRegistry, KillReason, ProcessAuthority, TaskFunding};

fn read_nothing(_: &mut Vec<u8>, _: u32) {}

type TestProgramStore = Preview1ProgramStore<TestCpu, TestNetworkService, UnsupportedStorage>;
type TestStore = wasmtime::Store<TestProgramStore>;

struct SignalHarness {
    engine: wasmtime::Engine,
    cpu: TestCpu,
    executor: Executor,
    timer: crate::Timer<TestCpu>,
    spawner: crate::InstanceSpawner<TestCpu>,
    runtime_state: HostRuntimeState<TestCpu, TestNetworkService, UnsupportedStorage>,
    interrupts: Arc<GuestInterrupts>,
    registry: InstanceRegistry,
}

impl SignalHarness {
    fn new() -> Self {
        let cpu = TestCpu::with_entropy(0x43);
        let engine = build_component_engine_for_platform(&cpu)
            .expect("component engine builds on test platform");
        let interrupts = Arc::new(GuestInterrupts::new(1, cpu.timebase()));
        let runtime_state: HostRuntimeState<TestCpu, TestNetworkService, UnsupportedStorage> =
            crate::RuntimeState::new(
                cpu.timebase(),
                1,
                0,
                crate::BootPayload::for_tests(),
                GuestIsa::for_build_target(cpu.native_feature_probe()),
            );
        runtime_state.install_root_entropy(triomphe::Arc::new(
            crate::RootEntropy::from_platform(
                &cpu,
                None,
                None,
                crate::MachineGeneration::new(None),
            )
            .expect("test CPU has entropy"),
        ));
        let executor = Executor::isolated(
            ProgressCounter::new(),
            crate::test_support::single_node_pool(1),
            ProcessorId::new(0),
        );
        let registry = InstanceRegistry::new();
        let host_instance = registry.register("wasix-signal-harness", 0);
        let spawner = executor
            .spawner(cpu)
            .instance_spawner(TaskFunding::Instance, &host_instance);
        let timer = executor.timer(cpu);

        Self {
            engine,
            cpu,
            executor,
            timer,
            spawner,
            runtime_state,
            interrupts,
            registry,
        }
    }

    fn open_process_store(
        &self,
        authority: ProcessAuthority,
        dispositions: Vec<WasixSignalDisposition>,
    ) -> (
        TestStore,
        StoreInterrupts<TestCpu>,
        SharedMemory,
        crate::RegisteredInstance,
    ) {
        let instance = self.registry.register("wasix-signal-proc", 0);
        let memory = SharedMemory::new(
            &self.engine,
            MemoryType::shared(2, 4).expect("2..=4 is a valid shared memory type"),
        )
        .expect("shared memory allocates");
        let threads = WasixImageThreads::new();
        let signal_state = WasixSignalState::new();
        let store_data = Preview1ProgramStore::new(
            self.cpu,
            self.timer.clone(),
            self.spawner.clone(),
            self.runtime_state.clone(),
            self.interrupts.clone(),
            instance.clone(),
            None,
            alloc::vec![String::from("signal-test")],
            Vec::new(),
            authority,
            OutputMode::Serial,
            read_nothing,
            crate::DebugSerialWriter::of::<test_store::DiscardPort>(),
            Some(memory.clone()),
            None,
            DescriptorOrigin::Fresh,
            signal_state,
            threads.main_mailbox(),
            dispositions,
            None,
            true,
            threads,
        );
        let mut store = wasmtime::Store::new(&self.engine, store_data);
        let registration = configure_preview1_program_store(&mut store);
        (store, registration, memory, instance)
    }

    fn open_worker_store(
        &self,
        parent: &TestProgramStore,
        instance: crate::RegisteredInstance,
        memory: SharedMemory,
    ) -> (
        u32,
        WasixSignalState,
        Arc<WasixThreadExit>,
        TestStore,
        StoreInterrupts<TestCpu>,
    ) {
        let worker_mailbox = WasixSignalState::new();
        let worker_exit = Arc::new(WasixThreadExit::new());
        let tid = parent
            .threads
            .admit(worker_mailbox.clone(), worker_exit.clone())
            .expect("live process admits worker thread");
        let mut store_data = parent.spawn_thread_store(worker_mailbox.clone());
        let _ = (instance, memory);
        store_data.thread_id = tid;
        let mut store = wasmtime::Store::new(&self.engine, store_data);
        let registration = configure_preview1_program_store(&mut store);
        (tid, worker_mailbox, worker_exit, store, registration)
    }
}

fn write_guest_bytes(memory: &SharedMemory, offset: usize, bytes: &[u8]) {
    for (idx, &byte) in bytes.iter().enumerate() {
        // SAFETY: test harness writes to disjoint scratch offsets within the 2-page SharedMemory.
        unsafe {
            memory.data()[offset + idx].get().write(byte);
        }
    }
}

fn read_guest_bytes(memory: &SharedMemory, offset: usize, len: usize) -> Vec<u8> {
    (0..len)
        .map(|idx| {
            // SAFETY: test harness reads initialized scratch offsets within the 2-page SharedMemory.
            unsafe { memory.data()[offset + idx].get().read() }
        })
        .collect()
}

fn install_asyncify_exports(
    store: &mut wasmtime::Store<
        Preview1ProgramStore<TestCpu, TestNetworkService, UnsupportedStorage>,
    >,
    memory: SharedMemory,
    stack_lower: u32,
    stack_pointer: u32,
    stack_upper: u32,
    on_hook: impl Fn(
        &str,
        &mut Caller<'_, Preview1ProgramStore<TestCpu, TestNetworkService, UnsupportedStorage>>,
    ) -> wasmtime::Result<()>
    + Send
    + Sync
    + 'static,
) {
    let hook = Arc::new(on_hook);
    let data_end = Global::new(
        &mut *store,
        GlobalType::new(ValType::I32, Mutability::Const),
        Val::I32(stack_lower as i32),
    )
    .expect("data_end global");
    let heap_base = Global::new(
        &mut *store,
        GlobalType::new(ValType::I32, Mutability::Const),
        Val::I32(stack_upper as i32),
    )
    .expect("heap_base global");
    let sp = Global::new(
        &mut *store,
        GlobalType::new(ValType::I32, Mutability::Var),
        Val::I32(stack_pointer as i32),
    )
    .expect("stack_pointer global");

    let hook_start_unwind = hook.clone();
    let mem_start_unwind = memory.clone();
    let start_unwind = Func::wrap_async(
        &mut *store,
        move |mut caller: Caller<
            '_,
            Preview1ProgramStore<TestCpu, TestNetworkService, UnsupportedStorage>,
        >,
              (data_ptr,): (i32,)| {
            let hook = hook_start_unwind.clone();
            let mem = mem_start_unwind.clone();
            Box::new(async move {
                // Record a simulated 8-byte unwind frame past `data_ptr + 8`.
                let begin = (data_ptr as u32) + WASIX_ASYNCIFY_DATA_SIZE;
                let finish = begin + 8;
                write_guest_bytes(&mem, data_ptr as usize, &finish.to_le_bytes());
                write_guest_bytes(&mem, begin as usize, &[0xA5; 8]);
                hook("asyncify_start_unwind", &mut caller)?;
                if let Some(stop) = caller.data_mut().on_interrupt().err() {
                    return Err(stop);
                }
                Ok(())
            })
        },
    );

    let hook_stop_unwind = hook.clone();
    let stop_unwind = Func::wrap_async(
        &mut *store,
        move |mut caller: Caller<
            '_,
            Preview1ProgramStore<TestCpu, TestNetworkService, UnsupportedStorage>,
        >,
              (): ()| {
            let hook = hook_stop_unwind.clone();
            Box::new(async move {
                hook("asyncify_stop_unwind", &mut caller)?;
                if let Some(stop) = caller.data_mut().on_interrupt().err() {
                    return Err(stop);
                }
                Ok(())
            })
        },
    );

    let hook_start_rewind = hook.clone();
    let start_rewind = Func::wrap_async(
        &mut *store,
        move |mut caller: Caller<
            '_,
            Preview1ProgramStore<TestCpu, TestNetworkService, UnsupportedStorage>,
        >,
              (_data_ptr,): (i32,)| {
            let hook = hook_start_rewind.clone();
            Box::new(async move {
                hook("asyncify_start_rewind", &mut caller)?;
                if let Some(stop) = caller.data_mut().on_interrupt().err() {
                    return Err(stop);
                }
                Ok(())
            })
        },
    );

    let hook_stop_rewind = hook;
    let stop_rewind = Func::wrap_async(
        &mut *store,
        move |mut caller: Caller<
            '_,
            Preview1ProgramStore<TestCpu, TestNetworkService, UnsupportedStorage>,
        >,
              (): ()| {
            let hook = hook_stop_rewind.clone();
            Box::new(async move {
                hook("asyncify_stop_rewind", &mut caller)?;
                if let Some(stop) = caller.data_mut().on_interrupt().err() {
                    return Err(stop);
                }
                Ok(())
            })
        },
    );

    let data = store.data_mut();
    data.define_test_export("__data_end", Extern::Global(data_end));
    data.define_test_export("__heap_base", Extern::Global(heap_base));
    data.define_test_export("__stack_pointer", Extern::Global(sp));
    data.define_test_export("asyncify_start_unwind", Extern::Func(start_unwind));
    data.define_test_export("asyncify_stop_unwind", Extern::Func(stop_unwind));
    data.define_test_export("asyncify_start_rewind", Extern::Func(start_rewind));
    data.define_test_export("asyncify_stop_rewind", Extern::Func(stop_rewind));
}

#[test]
fn signal_zero_probes_validate_authority_and_targets_without_raising() {
    let harness = SignalHarness::new();

    // Without SignalAuthority, proc_signal(pid, 0) refuses with NOTCAPABLE.
    let (mut unpriv_store, unpriv_interrupts, _, unpriv_instance) =
        harness.open_process_store(ProcessAuthority::empty(), Vec::new());
    let self_unpriv_pid = u32::try_from(unpriv_instance.id().raw()).expect("pid fits u32");
    let unpriv_probe = Func::wrap_async(&mut unpriv_store, move |mut caller, (): ()| {
        Box::new(async move { wasix_proc_signal(&mut caller, self_unpriv_pid, 0).await })
    })
    .typed::<(), i32>(&unpriv_store)
    .expect("typed probe");
    let turns = unpriv_store.data().guest_turns();
    let errno = block_on(
        unpriv_interrupts.drive(turns.drive(unpriv_probe.call_async(&mut unpriv_store, ()))),
    )
    .expect("probe completes");
    assert_eq!(errno, p1::errno::NOTCAPABLE);

    // With root authority, test self, live child, completed child, missing child,
    // main tid 0, live worker tid, exited worker tid, proc_raise(0), and proc_raise_interval(0).
    let (mut store, interrupts, memory, instance) =
        harness.open_process_store(ProcessAuthority::root(), Vec::new());
    let self_pid = u32::try_from(instance.id().raw()).expect("pid fits u32");

    let live_child_signals = WasixSignalState::new();
    let (_live_tx, live_rx) = futures::channel::oneshot::channel();
    store
        .data_mut()
        .insert_child(501, live_child_signals.clone(), live_rx);

    let done_child_signals = WasixSignalState::new();
    let (done_tx, done_rx) = futures::channel::oneshot::channel();
    let _ = done_tx.send(Ok(ChildExit {
        instance_id: crate::InstanceId::from_raw(502),
        termination: ChildTermination::Exited(7),
        filesystem: None,
    }));
    store
        .data_mut()
        .insert_child(502, done_child_signals.clone(), done_rx);

    let (live_tid, live_worker_mailbox, _live_worker_exit, _worker_store, _worker_int) =
        harness.open_worker_store(store.data(), instance.clone(), memory.clone());
    let (done_tid, done_worker_mailbox, done_worker_exit, mut worker_probe_store, worker_probe_int) =
        harness.open_worker_store(store.data(), instance.clone(), memory.clone());

    // From a spawned worker thread, thread_signal(0, 0) and thread_signal(self_tid, 0) both
    // succeed without raising on main or the worker.
    let worker_probe = Func::wrap_async(&mut worker_probe_store, move |mut caller, (): ()| {
        Box::new(async move {
            assert_eq!(
                wasix_thread_signal(&mut caller, 0, 0).await?,
                p1::errno::SUCCESS
            );
            assert_eq!(
                wasix_thread_signal(&mut caller, done_tid as i32, 0).await?,
                p1::errno::SUCCESS
            );
            Ok(())
        })
    })
    .typed::<(), ()>(&worker_probe_store)
    .expect("worker probe");
    let worker_turns = worker_probe_store.data().guest_turns();
    block_on(
        worker_probe_int
            .drive(worker_turns.drive(worker_probe.call_async(&mut worker_probe_store, ()))),
    )
    .expect("worker signal 0 probes succeed");
    assert!(store.data().thread_signals.pending_set().is_empty());
    assert!(done_worker_mailbox.pending_set().is_empty());

    // Mark the second worker exited; thread_signal(done_tid, 0) must now report SRCH.
    done_worker_exit.publish(0);

    let mem_for_join = memory.clone();
    let main_probe = Func::wrap_async(&mut store, move |mut caller, (): ()| {
        let mem = mem_for_join.clone();
        Box::new(async move {
            assert_eq!(
                wasix_proc_signal(&mut caller, self_pid, 0).await?,
                p1::errno::SUCCESS
            );
            assert_eq!(
                wasix_proc_signal(&mut caller, 501, 0).await?,
                p1::errno::SUCCESS
            );
            assert_eq!(
                wasix_proc_signal(&mut caller, 502, 0).await?,
                p1::errno::SRCH
            );
            assert_eq!(
                wasix_proc_signal(&mut caller, 9999, 0).await?,
                p1::errno::SRCH
            );
            assert_eq!(
                wasix_proc_signal(&mut caller, self_pid, -1).await?,
                p1::errno::INVAL
            );

            // Completed child 502 must still be joinable with its real Exited(7) status.
            let pid_ptr = 64_u32;
            let status_ptr = 96_u32;
            write_guest_bytes(&mem, pid_ptr as usize, &[WASIX_OPTION_SOME, 0, 0, 0]);
            write_guest_bytes(&mem, (pid_ptr + 4) as usize, &502_u32.to_le_bytes());
            assert_eq!(
                p1_reply(
                    wasix_proc_join(
                        &mut caller,
                        pid_ptr,
                        WASIX_JOIN_FLAG_NON_BLOCKING,
                        status_ptr
                    )
                    .await
                )?,
                p1::errno::SUCCESS
            );
            let status = read_guest_bytes(&mem, status_ptr as usize, 6);
            assert_eq!(status[0], WASIX_JOIN_STATUS_EXIT_NORMAL);
            assert_eq!(u16::from_le_bytes([status[2], status[3]]), 7);

            // Thread signal 0 probes.
            assert_eq!(
                wasix_thread_signal(&mut caller, 0, 0).await?,
                p1::errno::SUCCESS
            );
            assert_eq!(
                wasix_thread_signal(&mut caller, live_tid as i32, 0).await?,
                p1::errno::SUCCESS
            );
            assert_eq!(
                wasix_thread_signal(&mut caller, done_tid as i32, 0).await?,
                p1::errno::SRCH
            );
            assert_eq!(
                wasix_thread_signal(&mut caller, 7777, 0).await?,
                p1::errno::SRCH
            );
            assert_eq!(
                wasix_thread_signal(&mut caller, -1, 0).await?,
                p1::errno::INVAL
            );

            // proc_raise(0) and proc_raise_interval(0, ...) validate without raising.
            assert_eq!(p1_proc_raise(&mut caller, 0).await?, p1::errno::SUCCESS);
            assert_eq!(p1_proc_raise(&mut caller, -1).await?, p1::errno::INVAL);
            assert_eq!(p1_proc_raise(&mut caller, 32).await?, p1::errno::INVAL);
            assert_eq!(
                wasix_proc_raise_interval(&mut caller, 0, 1_000_000, 1),
                p1::errno::SUCCESS
            );
            assert!(caller.data().signal_interval.is_none());
            Ok(())
        })
    })
    .typed::<(), ()>(&store)
    .expect("main probe");

    let turns = store.data().guest_turns();
    block_on(interrupts.drive(turns.drive(main_probe.call_async(&mut store, ()))))
        .expect("all signal 0 probes complete without terminating the store");

    assert!(live_child_signals.pending_set().is_empty());
    assert!(done_child_signals.pending_set().is_empty());
    assert!(live_worker_mailbox.pending_set().is_empty());
    assert!(store.data().signal_state.pending_set().is_empty());
    assert!(store.data().thread_signals.pending_set().is_empty());
}

#[test]
fn ignored_and_default_ignored_signals_are_dropped_while_uncatchable_signals_terminate() {
    let harness = SignalHarness::new();
    let dispositions = alloc::vec![
        WasixSignalDisposition {
            signal: Signal::SIGTERM.raw(),
            action: WasixSignalDispositionAction::Ignore,
        },
        // Attempt to ignore SIGKILL and SIGSTOP; must be ignored by the kernel.
        WasixSignalDisposition {
            signal: Signal::SIGKILL.raw(),
            action: WasixSignalDispositionAction::Ignore,
        },
        WasixSignalDisposition {
            signal: Signal::SIGSTOP.raw(),
            action: WasixSignalDispositionAction::Ignore,
        },
    ];
    let (mut store, interrupts, memory, instance) =
        harness.open_process_store(ProcessAuthority::root(), dispositions);
    let self_pid = u32::try_from(instance.id().raw()).expect("pid fits u32");

    // External raises of explicitly-ignored SIGTERM and default-ignored SIGCHLD,
    // SIGCONT, SIGURG, SIGWINCH must all be dropped without stopping the guest.
    for ignored in [
        Signal::SIGTERM,
        Signal::SIGCHLD,
        Signal::SIGCONT,
        Signal::SIGURG,
        Signal::SIGWINCH,
    ] {
        store.data().signal_state.raise(ignored);
        store.data().thread_signals.raise(ignored);
    }
    assert!(store.data().signals().owed_stop().is_none());
    assert!(store.data().signal_state.pending_set().is_empty());
    assert!(store.data().thread_signals.pending_set().is_empty());

    // Component signal sweeps also drop default-ignored signals while taking fatal ones.
    let comp_signals = WasixSignalState::new();
    comp_signals.raise(Signal::SIGCHLD);
    comp_signals.raise(Signal::SIGWINCH);
    assert!(super::super::take_component_signal_stop(&comp_signals).is_none());
    comp_signals.raise(Signal::SIGCHLD);
    comp_signals.raise(Signal::SIGTERM);
    let comp_stop = super::super::take_component_signal_stop(&comp_signals)
        .expect("SIGTERM past SIGCHLD stops component");
    assert_eq!(
        preview1_process_end(comp_stop, None),
        Ok(ChildTermination::Signaled(SignalTermination {
            signal: Signal::SIGTERM.raw(),
            core_dumped: false,
        }))
    );

    // Self-directed proc_signal / thread_signal / proc_raise of ignored signals return SUCCESS.
    let self_ignored = Func::wrap_async(&mut store, move |mut caller, (): ()| {
        Box::new(async move {
            assert_eq!(
                wasix_proc_signal(&mut caller, self_pid, i32::from(Signal::SIGTERM.raw())).await?,
                p1::errno::SUCCESS
            );
            assert_eq!(
                wasix_thread_signal(&mut caller, 0, i32::from(Signal::SIGCHLD.raw())).await?,
                p1::errno::SUCCESS
            );
            assert_eq!(
                p1_proc_raise(&mut caller, i32::from(Signal::SIGTERM.raw())).await?,
                p1::errno::SUCCESS
            );
            assert_eq!(
                p1_proc_raise(&mut caller, i32::from(Signal::SIGWINCH.raw())).await?,
                p1::errno::SUCCESS
            );
            Ok(())
        })
    })
    .typed::<(), ()>(&store)
    .expect("self_ignored");
    let turns = store.data().guest_turns();
    block_on(interrupts.drive(turns.drive(self_ignored.call_async(&mut store, ()))))
        .expect("ignored signals do not end the caller");

    // An ignored signal raised while a store is parked in thread_sleep must NOT wake it with EINTR.
    let sleep_call = Func::wrap_async(&mut store, |mut caller, (): ()| {
        Box::new(async move {
            let errno = wasix_thread_sleep(&mut caller, 60_000_000_000).await;
            p1_finish_errno_call(&mut caller, errno).await
        })
    })
    .typed::<(), i32>(&store)
    .expect("sleep_call");
    let sleep_signals = store.data().signal_state.clone();
    {
        let turns = store.data().guest_turns();
        let mut fut = pin!(interrupts.drive(turns.drive(sleep_call.call_async(&mut store, ()))));
        let mut cx = Context::from_waker(Waker::noop());
        assert!(fut.as_mut().poll(&mut cx).is_pending());
        sleep_signals.raise(Signal::SIGTERM);
        sleep_signals.raise(Signal::SIGCHLD);
        assert!(
            fut.as_mut().poll(&mut cx).is_pending(),
            "ignored signals must neither stop nor EINTR-wake thread_sleep"
        );
    }

    // Even when callback_signal is ALSO registered, SIGKILL (9) and SIGSTOP (19) cannot be caught.
    let handler_calls = Arc::new(AtomicUsize::new(0));
    let calls_ref = handler_calls.clone();
    let on_signal = Func::wrap(&mut store, move |_sig: i32| {
        calls_ref.fetch_add(1, Ordering::SeqCst);
    });
    store
        .data_mut()
        .define_test_export("on_signal", Extern::Func(on_signal));
    write_guest_bytes(&memory, 128, b"on_signal");
    let register = Func::wrap_async(&mut store, |mut caller, (): ()| {
        Box::new(async move { wasix_callback_signal(&mut caller, 128, 9) })
    })
    .typed::<(), ()>(&store)
    .expect("register");
    let turns = store.data().guest_turns();
    block_on(interrupts.drive(turns.drive(register.call_async(&mut store, ()))))
        .expect("registers callback_signal");
    assert_eq!(
        store.data().process_signals.callback().as_deref(),
        Some("on_signal")
    );

    // Worker thread targeted with SIGSTOP ends with 128 + 19 and never invokes on_signal.
    let (_tid, worker_mailbox, _worker_exit, mut worker_store, worker_int) =
        harness.open_worker_store(store.data(), instance.clone(), memory.clone());
    worker_mailbox.raise(Signal::SIGSTOP);
    let worker_noop = Func::wrap_async(&mut worker_store, |mut caller, (): ()| {
        Box::new(async move { p1_finish_errno_call(&mut caller, p1::errno::SUCCESS).await })
    })
    .typed::<(), i32>(&worker_store)
    .expect("worker_noop");
    let worker_turns = worker_store.data().guest_turns();
    let worker_res = block_on(
        worker_int.drive(worker_turns.drive(worker_noop.call_async(&mut worker_store, ()))),
    )
    .map(drop);
    assert_eq!(
        wasix_thread_call_end::<()>(worker_res, None, None),
        WasixThreadCallEnd::Thread(128 + u32::from(Signal::SIGSTOP.raw()))
    );
    assert_eq!(handler_calls.load(Ordering::SeqCst), 0);

    // Process targeted with SIGKILL ends with Signaled(9) and never invokes on_signal.
    let raise_kill = Func::wrap_async(&mut store, |mut caller, (): ()| {
        Box::new(async move { p1_proc_raise(&mut caller, i32::from(Signal::SIGKILL.raw())).await })
    })
    .typed::<(), i32>(&store)
    .expect("raise_kill");
    let turns = store.data().guest_turns();
    let err = block_on(interrupts.drive(turns.drive(raise_kill.call_async(&mut store, ()))))
        .expect_err("SIGKILL terminates the process");
    assert_eq!(handler_calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        store.data_mut().take_process_end(err),
        Ok(ChildTermination::Signaled(SignalTermination {
            signal: Signal::SIGKILL.raw(),
            core_dumped: false,
        }))
    );
}

#[test]
fn callback_signal_delivers_multiple_retained_signals_masks_reentrancy_and_clears_on_sentinel() {
    let harness = SignalHarness::new();
    let dispositions = alloc::vec![WasixSignalDisposition {
        signal: Signal::SIGUSR2.raw(),
        action: WasixSignalDispositionAction::Ignore,
    }];
    let (mut store, interrupts, memory, _instance) =
        harness.open_process_store(ProcessAuthority::root(), dispositions);

    let delivered = Arc::new(Mutex::new(Vec::<i32>::new()));
    let usr1_depth = Arc::new(AtomicUsize::new(0));
    let max_usr1_depth = Arc::new(AtomicUsize::new(0));
    let reentered_once = Arc::new(AtomicUsize::new(0));

    let delivered_ref = delivered.clone();
    let depth_ref = usr1_depth.clone();
    let max_ref = max_usr1_depth.clone();
    let reenter_ref = reentered_once.clone();
    let on_signal = Func::wrap_async(
        &mut store,
        move |mut caller: Caller<
            '_,
            Preview1ProgramStore<TestCpu, TestNetworkService, UnsupportedStorage>,
        >,
              (signo,): (i32,)| {
            let delivered = delivered_ref.clone();
            let depth = depth_ref.clone();
            let max_seen = max_ref.clone();
            let reenter = reenter_ref.clone();
            Box::new(async move {
                let is_usr1 = signo == i32::from(Signal::SIGUSR1.raw());
                if is_usr1 {
                    let now = depth.fetch_add(1, Ordering::SeqCst) + 1;
                    max_seen.fetch_max(now, Ordering::SeqCst);
                }
                delivered.lock().push(signo);
                if is_usr1 && reenter.fetch_add(1, Ordering::SeqCst) == 0 {
                    // Re-raise SIGUSR1 from inside its own handler and hit a host safe point:
                    // `active_signal_handlers` must keep SIGUSR1 masked until this handler frame
                    // returns rather than recursing, while other unmasked signals may deliver.
                    caller.data().signal_state.raise(Signal::SIGUSR1);
                    let _ = p1_finish_errno_call(&mut caller, p1::errno::SUCCESS).await?;
                }
                if is_usr1 {
                    depth.fetch_sub(1, Ordering::SeqCst);
                }
                Ok(())
            })
        },
    );
    let wrong_sig = Func::wrap(&mut store, || {});
    store
        .data_mut()
        .define_test_export("on_signal", Extern::Func(on_signal));
    store
        .data_mut()
        .define_test_export("wrong_sig", Extern::Func(wrong_sig));

    write_guest_bytes(&memory, 32, b"on_signal");
    write_guest_bytes(&memory, 64, b"__wasm_signal_blocked");
    write_guest_bytes(&memory, 128, b"wrong_sig");

    let run = Func::wrap_async(&mut store, |mut caller, (): ()| {
        Box::new(async move {
            wasix_callback_signal(&mut caller, 32, 9)?;

            // Raise multiple distinct signals before a safe point: multi-signal bitmask retains
            // all catchable ones (`SIGINT`, `SIGUSR1`, `SIGALRM`, and `SIGCHLD` for guests that
            // catch child/window events via `callback_signal`) while dropping explicitly-ignored
            // `SIGUSR2`.
            caller.data().thread_signals.raise(Signal::SIGINT);
            caller.data().signal_state.raise(Signal::SIGUSR1);
            caller.data().signal_state.raise(Signal::SIGUSR2);
            caller.data().signal_state.raise(Signal::SIGALRM);
            caller.data().signal_state.raise(Signal::SIGCHLD);

            // Safe point delivers thread-directed SIGINT first, then process-directed SIGUSR1
            // (which re-raises SIGUSR1 once while masked), drops ignored SIGUSR2, delivers
            // SIGALRM and SIGCHLD, and finally delivers the unmasked second SIGUSR1.
            assert_eq!(
                p1_finish_errno_call(&mut caller, p1::errno::SUCCESS).await?,
                p1::errno::SUCCESS
            );
            Ok(())
        })
    })
    .typed::<(), ()>(&store)
    .expect("run");

    let turns = store.data().guest_turns();
    block_on(interrupts.drive(turns.drive(run.call_async(&mut store, ()))))
        .expect("all caught signals deliver cleanly");

    assert_eq!(
        *delivered.lock(),
        alloc::vec![
            i32::from(Signal::SIGINT.raw()),
            i32::from(Signal::SIGUSR1.raw()),
            i32::from(Signal::SIGALRM.raw()),
            i32::from(Signal::SIGCHLD.raw()),
            i32::from(Signal::SIGUSR1.raw()),
        ]
    );
    assert_eq!(
        max_usr1_depth.load(Ordering::SeqCst),
        1,
        "a handler must not re-enter itself for the same masked signal"
    );

    // Wrong signature or unexported sentinel (`__wasm_signal_blocked`, as `wasix-libc` passes
    // before re-raising SIGABRT/SIG_DFL) clears the callback and restores default termination.
    let clear_and_raise = Func::wrap_async(&mut store, |mut caller, (): ()| {
        Box::new(async move {
            wasix_callback_signal(&mut caller, 128, 9)?;
            assert!(caller.data().process_signals.callback().is_none());
            wasix_callback_signal(&mut caller, 32, 9)?;
            assert_eq!(
                caller.data().process_signals.callback().as_deref(),
                Some("on_signal")
            );
            wasix_callback_signal(&mut caller, 64, 21)?;
            assert!(caller.data().process_signals.callback().is_none());
            p1_proc_raise(&mut caller, i32::from(Signal::SIGTERM.raw())).await
        })
    })
    .typed::<(), i32>(&store)
    .expect("clear_and_raise");

    let count_before = delivered.lock().len();
    let turns = store.data().guest_turns();
    let err = block_on(interrupts.drive(turns.drive(clear_and_raise.call_async(&mut store, ()))))
        .expect_err("after clearing callback_signal, SIGTERM terminates");
    assert_eq!(delivered.lock().len(), count_before);
    assert_eq!(
        store.data_mut().take_process_end(err),
        Ok(ChildTermination::Signaled(SignalTermination {
            signal: Signal::SIGTERM.raw(),
            core_dumped: false,
        }))
    );
}

#[test]
fn shared_process_signals_wake_parked_worker_with_eintr_and_run_handler() {
    let harness = SignalHarness::new();
    let (mut main_store, main_interrupts, memory, instance) =
        harness.open_process_store(ProcessAuthority::root(), Vec::new());

    // Register `on_signal` on main BEFORE spawning the worker, matching `wasix-libc`'s
    // once-per-process `callback_signal("__wasm_signal")` registration.
    let main_on_signal = Func::wrap(&mut main_store, |_sig: i32| {});
    main_store
        .data_mut()
        .define_test_export("on_signal", Extern::Func(main_on_signal));
    write_guest_bytes(&memory, 16, b"on_signal");
    let reg = Func::wrap_async(&mut main_store, |mut caller, (): ()| {
        Box::new(async move { wasix_callback_signal(&mut caller, 16, 9) })
    })
    .typed::<(), ()>(&main_store)
    .expect("reg");
    let main_turns = main_store.data().guest_turns();
    block_on(main_interrupts.drive(main_turns.drive(reg.call_async(&mut main_store, ()))))
        .expect("main registers callback");

    let (worker_tid, _worker_mailbox, _worker_exit, mut worker_store, worker_interrupts) =
        harness.open_worker_store(main_store.data(), instance, memory.clone());

    let worker_delivered = Arc::new(Mutex::new(Vec::<i32>::new()));
    let worker_log = worker_delivered.clone();
    let worker_on_signal = Func::wrap(&mut worker_store, move |sig: i32| {
        worker_log.lock().push(sig);
    });
    worker_store
        .data_mut()
        .define_test_export("on_signal", Extern::Func(worker_on_signal));

    // Park worker in `futex_wait` on address 256 expecting value 0x11223344 with no timeout.
    write_guest_bytes(&memory, 256, &0x1122_3344_u32.to_le_bytes());
    write_guest_bytes(&memory, 264, &[WASIX_OPTION_NONE]);
    let worker_futex = Func::wrap_async(&mut worker_store, |mut caller, (): ()| {
        Box::new(async move {
            let answer = wasix_futex_wait(&mut caller, 256, 0x1122_3344, 264, 280).await;
            p1_finish_async_call(&mut caller, answer).await
        })
    })
    .typed::<(), i32>(&worker_store)
    .expect("worker_futex");

    let worker_turns = worker_store.data().guest_turns();
    let mut parked_worker = pin!(
        worker_interrupts.drive(worker_turns.drive(worker_futex.call_async(&mut worker_store, ())))
    );
    let mut cx = Context::from_waker(Waker::noop());
    assert!(parked_worker.as_mut().poll(&mut cx).is_pending());

    // Main sends SIGUSR1 to worker via `wasix_thread_signal`.
    let send_to_worker = Func::wrap_async(&mut main_store, move |mut caller, (): ()| {
        Box::new(async move {
            wasix_thread_signal(
                &mut caller,
                worker_tid as i32,
                i32::from(Signal::SIGUSR1.raw()),
            )
            .await
        })
    })
    .typed::<(), i32>(&main_store)
    .expect("send_to_worker");
    let main_turns = main_store.data().guest_turns();
    assert_eq!(
        block_on(
            main_interrupts.drive(main_turns.drive(send_to_worker.call_async(&mut main_store, ())))
        )
        .expect("thread_signal completes"),
        p1::errno::SUCCESS
    );

    // Worker wakes from futex_wait with EINTR after invoking its `on_signal(10)` export.
    match parked_worker.as_mut().poll(&mut cx) {
        Poll::Ready(Ok(errno)) => assert_eq!(errno, p1::errno::INTR),
        other => panic!("expected futex_wait to complete with EINTR, got {other:?}"),
    }
    assert_eq!(
        *worker_delivered.lock(),
        alloc::vec![i32::from(Signal::SIGUSR1.raw())]
    );
}

#[test]
fn asyncify_unwind_and_rewind_preserve_thread_and_process_stops_and_defer_caught_handlers() {
    let harness = SignalHarness::new();

    // 1. Thread-directed fatal signal mid-asyncify unwind on a spawned worker ends ONLY that
    //    worker thread with status 128 + SIGTERM (143), never failing the process as Internal.
    {
        let (main_store, _main_int, memory, instance) =
            harness.open_process_store(ProcessAuthority::root(), Vec::new());
        let (worker_tid, worker_mailbox, worker_exit, mut worker_store, worker_int) =
            harness.open_worker_store(main_store.data(), instance, memory.clone());

        let mailbox_in_unwind = worker_mailbox.clone();
        install_asyncify_exports(
            &mut worker_store,
            memory.clone(),
            512,
            1024,
            1536,
            move |hook_name, _caller| {
                if hook_name == "asyncify_stop_unwind" {
                    mailbox_in_unwind.raise(Signal::SIGTERM);
                }
                Ok(())
            },
        );

        let checkpoint = Func::wrap_async(&mut worker_store, |mut caller, (): ()| {
            Box::new(async move { wasix_stack_checkpoint(&mut caller, 64, 96).await })
        })
        .typed::<(), i32>(&worker_store)
        .expect("checkpoint");

        let turns = worker_store.data().guest_turns();
        assert_eq!(
            block_on(worker_int.drive(turns.drive(checkpoint.call_async(&mut worker_store, ()))))
                .expect("initial stack_checkpoint unwind call succeeds"),
            p1::errno::SUCCESS
        );
        assert!(!worker_store.data().asyncify.is_idle());

        let stop = match block_on(handle_wasix_asyncify_completion(
            &mut worker_store,
            &worker_int,
        )) {
            Err(AsyncifyError::GuestStop(stop)) => stop,
            other => panic!("expected GuestStop from mid-unwind thread signal, got {other:?}"),
        };
        let call_end = wasix_thread_call_end::<()>(Err(stop), None, None);
        assert_eq!(
            call_end,
            WasixThreadCallEnd::Thread(128 + u32::from(Signal::SIGTERM.raw()))
        );
        assert!(
            main_store.data().threads.take_process_end().is_none(),
            "a thread-directed signal mid-unwind must not terminate or fail the process"
        );
        if let WasixThreadCallEnd::Thread(code) = call_end {
            worker_exit.publish(code);
        }
        let joined = main_store
            .data()
            .threads
            .exit_of(worker_tid)
            .expect("worker exit slot exists");
        assert_eq!(block_on(joined.wait()), 143);
    }

    // 2. Process-directed fatal signal during `asyncify_start_unwind` and Operator kill during
    //    `asyncify_start_rewind` map to Signaled(15) and Killed, never Internal.
    {
        let (mut store, interrupts, memory, _instance) =
            harness.open_process_store(ProcessAuthority::root(), Vec::new());
        let proc_signals = store.data().signal_state.clone();
        install_asyncify_exports(
            &mut store,
            memory,
            512,
            1024,
            1536,
            move |hook_name, _caller| {
                if hook_name == "asyncify_start_unwind" {
                    proc_signals.raise(Signal::SIGTERM);
                }
                Ok(())
            },
        );
        let checkpoint = Func::wrap_async(&mut store, |mut caller, (): ()| {
            Box::new(async move { wasix_stack_checkpoint(&mut caller, 64, 96).await })
        })
        .typed::<(), i32>(&store)
        .expect("checkpoint");
        let turns = store.data().guest_turns();
        let err = block_on(interrupts.drive(turns.drive(checkpoint.call_async(&mut store, ()))))
            .expect_err("SIGTERM during asyncify_start_unwind stops immediately");
        assert_eq!(
            store.data_mut().take_process_end(err),
            Ok(ChildTermination::Signaled(SignalTermination {
                signal: Signal::SIGTERM.raw(),
                core_dumped: false,
            }))
        );
    }
    {
        let (mut store, interrupts, memory, instance) =
            harness.open_process_store(ProcessAuthority::root(), Vec::new());
        let registry = &harness.registry;
        let instance_id = instance.id();
        install_asyncify_exports(&mut store, memory, 512, 1024, 1536, |_, _| Ok(()));
        let checkpoint = Func::wrap_async(&mut store, |mut caller, (): ()| {
            Box::new(async move { wasix_stack_checkpoint(&mut caller, 64, 96).await })
        })
        .typed::<(), i32>(&store)
        .expect("checkpoint");
        let turns = store.data().guest_turns();
        assert_eq!(
            block_on(interrupts.drive(turns.drive(checkpoint.call_async(&mut store, ()))))
                .expect("unwind begins"),
            p1::errno::SUCCESS
        );
        // Condemn the instance with an Operator kill while asyncify is about to complete unwind.
        registry.request_kill(
            instance_id,
            KillReason::Operator,
            0,
            &crate::UserResidency::default(),
        );
        let stop = match block_on(handle_wasix_asyncify_completion(&mut store, &interrupts)) {
            Err(AsyncifyError::GuestStop(stop)) => stop,
            other => panic!("expected GuestStop on operator kill mid-asyncify, got {other:?}"),
        };
        assert_eq!(
            store.data_mut().take_process_end(stop),
            Ok(ChildTermination::Killed)
        );
    }

    // 3. A caught signal (`SIGUSR1`) arriving mid-unwind/mid-rewind does NOT execute its handler
    //    while asyncify state is active; it stays retained and runs once `asyncify_stop_rewind`
    //    finishes.
    {
        let (mut store, interrupts, memory, _instance) =
            harness.open_process_store(ProcessAuthority::root(), Vec::new());
        let events = Arc::new(Mutex::new(Vec::<&'static str>::new()));
        let events_for_hooks = events.clone();
        let proc_signals = store.data().signal_state.clone();
        install_asyncify_exports(
            &mut store,
            memory.clone(),
            512,
            1024,
            1536,
            move |hook_name, caller| {
                let label = match hook_name {
                    "asyncify_start_unwind" => {
                        // Raise caught SIGUSR1 as unwind starts; it must wait until stop_rewind!
                        proc_signals.raise(Signal::SIGUSR1);
                        "start_unwind"
                    }
                    "asyncify_stop_unwind" => "stop_unwind",
                    "asyncify_start_rewind" => "start_rewind",
                    "asyncify_stop_rewind" => {
                        assert!(
                            !caller.data().asyncify.is_idle(),
                            "asyncify must remain non-idle until stop_rewind completes"
                        );
                        "stop_rewind"
                    }
                    _ => "other",
                };
                events_for_hooks.lock().push(label);
                Ok(())
            },
        );

        let events_for_sig = events.clone();
        let on_signal = Func::wrap(&mut store, move |sig: i32| {
            assert_eq!(sig, i32::from(Signal::SIGUSR1.raw()));
            events_for_sig.lock().push("on_signal");
        });
        store
            .data_mut()
            .define_test_export("on_signal", Extern::Func(on_signal));
        write_guest_bytes(&memory, 16, b"on_signal");
        let reg = Func::wrap_async(&mut store, |mut caller, (): ()| {
            Box::new(async move { wasix_callback_signal(&mut caller, 16, 9) })
        })
        .typed::<(), ()>(&store)
        .expect("reg");
        let turns = store.data().guest_turns();
        block_on(interrupts.drive(turns.drive(reg.call_async(&mut store, ()))))
            .expect("registers callback_signal");

        let checkpoint = Func::wrap_async(&mut store, |mut caller, (): ()| {
            Box::new(async move { wasix_stack_checkpoint(&mut caller, 64, 96).await })
        })
        .typed::<(), i32>(&store)
        .expect("checkpoint");

        // Unwind pass:
        let turns = store.data().guest_turns();
        assert_eq!(
            block_on(interrupts.drive(turns.drive(checkpoint.call_async(&mut store, ()))))
                .expect("unwind pass succeeds"),
            p1::errno::SUCCESS
        );
        assert_eq!(*events.lock(), alloc::vec!["start_unwind"]);

        // Asyncify completion transitions to Rewinding without running `on_signal`:
        assert!(matches!(
            block_on(handle_wasix_asyncify_completion(&mut store, &interrupts)),
            Ok(AsyncifyOutcome::Rewinding)
        ));
        assert_eq!(
            *events.lock(),
            alloc::vec!["start_unwind", "stop_unwind", "start_rewind"],
            "caught signal must not execute during unwind or rewind setup"
        );
        assert!(
            store
                .data()
                .signal_state
                .pending_set()
                .contains(Signal::SIGUSR1),
            "caught signal remains retained across asyncify unwind/rewind"
        );

        // Rewind pass re-enters `wasix_stack_checkpoint`, finishes `stop_rewind`, writes
        // `ret_value = 0`, and THEN delivers `on_signal(SIGUSR1)` at the safe point!
        let turns = store.data().guest_turns();
        assert_eq!(
            block_on(interrupts.drive(turns.drive(checkpoint.call_async(&mut store, ()))))
                .expect("rewind pass succeeds and delivers deferred signal"),
            p1::errno::SUCCESS
        );
        assert_eq!(
            *events.lock(),
            alloc::vec![
                "start_unwind",
                "stop_unwind",
                "start_rewind",
                "stop_rewind",
                "on_signal",
            ]
        );
        assert!(store.data().signal_state.pending_set().is_empty());
        let _ = &harness.executor;
    }
}

#[test]
fn fatal_signal_preempts_lower_numbered_caught_signal() {
    let harness = SignalHarness::new();
    let (mut store, interrupts, memory, _instance) =
        harness.open_process_store(ProcessAuthority::root(), Vec::new());

    let handler_calls = Arc::new(AtomicUsize::new(0));
    let calls_ref = handler_calls.clone();
    let on_signal = Func::wrap(
        &mut store,
        move |mut caller: Caller<'_, TestProgramStore>, _sig: i32| -> wasmtime::Result<()> {
            calls_ref.fetch_add(1, Ordering::SeqCst);
            // Attempt to mask SIGKILL with proc_exit(0) if handler ever ran.
            caller.data_mut().request_exit(0);
            Err(wasmtime::Error::new(Preview1Exit))
        },
    );
    store
        .data_mut()
        .define_test_export("on_signal", Extern::Func(on_signal));
    write_guest_bytes(&memory, 16, b"on_signal");
    let reg = Func::wrap_async(&mut store, |mut caller, (): ()| {
        Box::new(async move { wasix_callback_signal(&mut caller, 16, 9) })
    })
    .typed::<(), ()>(&store)
    .expect("reg");
    let turns = store.data().guest_turns();
    block_on(interrupts.drive(turns.drive(reg.call_async(&mut store, ()))))
        .expect("registers callback_signal");

    // Raise lower-numbered caught SIGINT (2) on thread mailbox AND uncatchable SIGKILL (9)
    // on process mailbox before hitting a safe point: SIGKILL must preempt SIGINT without
    // ever invoking `on_signal`.
    let call = Func::wrap_async(&mut store, |mut caller, (): ()| {
        Box::new(async move {
            caller.data().thread_signals.raise(Signal::SIGINT);
            caller.data().signal_state.raise(Signal::SIGKILL);
            p1_finish_errno_call(&mut caller, p1::errno::SUCCESS).await
        })
    })
    .typed::<(), i32>(&store)
    .expect("call");

    let turns = store.data().guest_turns();
    let err = block_on(interrupts.drive(turns.drive(call.call_async(&mut store, ()))))
        .expect_err("SIGKILL preempts lower-numbered caught SIGINT");
    assert_eq!(handler_calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        store.data_mut().take_process_end(err),
        Ok(ChildTermination::Signaled(SignalTermination {
            signal: Signal::SIGKILL.raw(),
            core_dumped: false,
        }))
    );
}

#[test]
fn blocking_proc_join_wakes_on_caught_signal_and_runs_handler() {
    let harness = SignalHarness::new();
    let (mut store, interrupts, memory, _instance) =
        harness.open_process_store(ProcessAuthority::root(), Vec::new());

    let delivered = Arc::new(Mutex::new(Vec::<i32>::new()));
    let delivered_ref = delivered.clone();
    let on_signal = Func::wrap(&mut store, move |sig: i32| {
        delivered_ref.lock().push(sig);
    });
    store
        .data_mut()
        .define_test_export("on_signal", Extern::Func(on_signal));
    write_guest_bytes(&memory, 16, b"on_signal");
    let reg = Func::wrap_async(&mut store, |mut caller, (): ()| {
        Box::new(async move { wasix_callback_signal(&mut caller, 16, 9) })
    })
    .typed::<(), ()>(&store)
    .expect("reg");
    let turns = store.data().guest_turns();
    block_on(interrupts.drive(turns.drive(reg.call_async(&mut store, ()))))
        .expect("registers callback_signal");

    let (child_tx, child_rx) = futures::channel::oneshot::channel();
    store
        .data_mut()
        .insert_child(601, WasixSignalState::new(), child_rx);

    let pid_ptr = 64_u32;
    let status_ptr = 96_u32;
    write_guest_bytes(&memory, pid_ptr as usize, &[WASIX_OPTION_SOME, 0, 0, 0]);
    write_guest_bytes(&memory, (pid_ptr + 4) as usize, &601_u32.to_le_bytes());

    let join_fn = Func::wrap_async(&mut store, move |mut caller, (): ()| {
        Box::new(async move {
            let answer = wasix_proc_join(&mut caller, pid_ptr, 0, status_ptr).await;
            p1_finish_async_call(&mut caller, answer).await
        })
    })
    .typed::<(), i32>(&store)
    .expect("join_fn");

    let proc_signals = store.data().signal_state.clone();
    {
        let turns = store.data().guest_turns();
        let mut join_fut = pin!(interrupts.drive(turns.drive(join_fn.call_async(&mut store, ()))));
        let mut cx = Context::from_waker(Waker::noop());
        assert!(join_fut.as_mut().poll(&mut cx).is_pending());

        proc_signals.raise(Signal::SIGUSR1);
        match join_fut.as_mut().poll(&mut cx) {
            Poll::Ready(Ok(errno)) => assert_eq!(errno, p1::errno::INTR),
            other => panic!("expected blocking proc_join to wake with EINTR, got {other:?}"),
        }
    }
    assert_eq!(
        *delivered.lock(),
        alloc::vec![i32::from(Signal::SIGUSR1.raw())]
    );

    // Child 601 is still tracked and joins cleanly once it exits.
    let _ = child_tx.send(Ok(ChildExit {
        instance_id: crate::InstanceId::from_raw(601),
        termination: ChildTermination::Exited(11),
        filesystem: None,
    }));
    let turns = store.data().guest_turns();
    assert_eq!(
        block_on(interrupts.drive(turns.drive(join_fn.call_async(&mut store, ()))))
            .expect("second join succeeds"),
        p1::errno::SUCCESS
    );
    let status = read_guest_bytes(&memory, status_ptr as usize, 6);
    assert_eq!(status[0], WASIX_JOIN_STATUS_EXIT_NORMAL);
    assert_eq!(u16::from_le_bytes([status[2], status[3]]), 11);
}

#[test]
fn post_return_signal_handler_unwind_runs_asyncify_completion_before_rewind() {
    let harness = SignalHarness::new();
    let (mut store, interrupts, memory, _instance) =
        harness.open_process_store(ProcessAuthority::root(), Vec::new());

    let events = Arc::new(Mutex::new(Vec::<&'static str>::new()));
    let hook_events = events.clone();
    install_asyncify_exports(
        &mut store,
        memory.clone(),
        512,
        1024,
        1536,
        move |hook_name, _caller| {
            let label = match hook_name {
                "asyncify_start_unwind" => "start_unwind",
                "asyncify_stop_unwind" => "stop_unwind",
                "asyncify_start_rewind" => "start_rewind",
                "asyncify_stop_rewind" => "stop_rewind",
                _ => "other",
            };
            hook_events.lock().push(label);
            Ok(())
        },
    );

    // Capture a valid snapshot first at guest address 64 (24-byte `stack_snapshot`).
    let checkpoint = Func::wrap_async(&mut store, |mut caller, (): ()| {
        Box::new(async move { wasix_stack_checkpoint(&mut caller, 64, 96).await })
    })
    .typed::<(), i32>(&store)
    .expect("checkpoint");
    let turns = store.data().guest_turns();
    assert_eq!(
        block_on(interrupts.drive(turns.drive(checkpoint.call_async(&mut store, ()))))
            .expect("capture unwind"),
        p1::errno::SUCCESS
    );
    assert_eq!(
        block_on(finish_wasix_guest_call(&mut store, &interrupts)).expect("capture completes"),
        AsyncifyOutcome::Rewinding
    );
    let turns = store.data().guest_turns();
    assert_eq!(
        block_on(interrupts.drive(turns.drive(checkpoint.call_async(&mut store, ()))))
            .expect("capture rewind"),
        p1::errno::SUCCESS
    );
    events.lock().clear();

    // Register a signal handler that calls `wasix_stack_restore(64, 42)` after `_start` returns.
    let handler_events = events.clone();
    let on_signal = Func::wrap_async(&mut store, move |mut caller, (signo,): (i32,)| {
        let handler_events = handler_events.clone();
        Box::new(async move {
            assert_eq!(signo, i32::from(Signal::SIGUSR1.raw()));
            handler_events.lock().push("on_signal");
            wasix_stack_restore(&mut caller, 64, 42).await
        })
    });
    store
        .data_mut()
        .define_test_export("on_signal", Extern::Func(on_signal));
    write_guest_bytes(&memory, 16, b"on_signal");
    let reg = Func::wrap_async(&mut store, |mut caller, (): ()| {
        Box::new(async move { wasix_callback_signal(&mut caller, 16, 9) })
    })
    .typed::<(), ()>(&store)
    .expect("reg");
    let turns = store.data().guest_turns();
    block_on(interrupts.drive(turns.drive(reg.call_async(&mut store, ()))))
        .expect("registers callback_signal");

    // Raise SIGUSR1 and run `finish_wasix_guest_call` as `run_core_module_image` and
    // `call_wasix_thread` do after `_start` returns cleanly: it must process the handler's
    // `Restoring` unwind through `handle_wasix_asyncify_completion` before returning `Rewinding`.
    store.data().signal_state.raise(Signal::SIGUSR1);
    let outcome = block_on(finish_wasix_guest_call(&mut store, &interrupts))
        .expect("post-return handler unwind transitions cleanly to Rewinding");
    assert_eq!(outcome, AsyncifyOutcome::Rewinding);
    assert_eq!(store.data().asyncify.rewind_value, Some(42));
    assert!(matches!(
        store.data().asyncify.phase,
        WasixAsyncifyPhase::Idle
    ));
    assert_eq!(
        *events.lock(),
        alloc::vec!["on_signal", "start_unwind", "stop_unwind", "start_rewind"]
    );
}
