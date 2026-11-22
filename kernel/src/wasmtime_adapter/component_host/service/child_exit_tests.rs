use super::*;
use crate::test_support::{TestCpu, TestNetworkService, UnsupportedStorage};
use futures_lite::future::block_on;
use helios_hal::cpu::ProcessorId;
use helios_hal::watchdog::ProgressCounter;
use helios_unix::{ChildTermination, SignalTermination};
use wasmtime::component::HasSelf;

fn child_handle_with_result(
    instance_id: crate::InstanceId,
    result: Result<ChildTermination, ProgramExecError>,
) -> ChildHandle {
    let (tx, rx) = futures::channel::oneshot::channel();
    let _ = tx.send(result.map(|termination| ChildExit {
        instance_id,
        termination,
        filesystem: None,
    }));
    let (stdin_tx, _stdin_rx) = crate::byte_channel();
    let (_stdout_tx, stdout_rx) = crate::byte_channel();
    let (_stderr_tx, stderr_rx) = crate::byte_channel();
    ChildHandle {
        instance_id,
        signal_state: WasixSignalState::new(),
        stdin: Some(stdin_tx),
        stdout: Some(stdout_rx),
        stderr: Some(stderr_rx),
        exit: Some(rx),
    }
}

fn component_test_engine() -> wasmtime::Engine {
    let mut config = wasmtime::Config::new();
    config.wasm_component_model(true);
    config.wasm_component_model_async(true);
    config.concurrency_support(true);
    wasmtime::Engine::new(&config).expect("component test engine initializes")
}

fn await_program_wit_wait(
    handle: ChildHandle,
) -> Result<
    super::super::program_bindings::helios::system::programs::ExitStatus,
    super::super::program_bindings::helios::system::programs::SpawnError,
> {
    use super::super::program_bindings::helios::system::programs::HostChildWithStore;

    let engine = component_test_engine();
    let mut store = wasmtime::Store::new(
        &engine,
        test_store::store_data_authorized(ProcessAuthority::root(), |_| {}),
    );
    let resource = store
        .data_mut()
        .table
        .push(handle)
        .expect("resource table admits child handle");
    block_on(store.run_concurrent(async move |accessor| {
        <HasSelf<test_store::TestStoreData> as HostChildWithStore<_>>::wait(accessor, resource)
            .await
    }))
    .expect("concurrent run succeeds")
    .expect("wait host call succeeds")
}

fn await_debugger_wit_wait(
    handle: ChildHandle,
) -> Result<
    super::super::debugger_bindings::helios::system::programs::ExitStatus,
    super::super::debugger_bindings::helios::system::programs::SpawnError,
> {
    use super::super::debugger_bindings::helios::system::programs::HostChildWithStore;

    let engine = component_test_engine();
    let mut store = wasmtime::Store::new(
        &engine,
        test_store::store_data_authorized(ProcessAuthority::root(), |_| {}),
    );
    let resource = store
        .data_mut()
        .table
        .push(handle)
        .expect("resource table admits child handle");
    block_on(store.run_concurrent(async move |accessor| {
        <HasSelf<test_store::TestStoreData> as HostChildWithStore<_>>::wait(accessor, resource)
            .await
    }))
    .expect("concurrent run succeeds")
    .expect("wait host call succeeds")
}

#[test]
fn child_wait_reports_each_of_the_four_endings_distinctly() {
    use super::super::debugger_bindings::helios::system::programs as dbg_wit;
    use super::super::program_bindings::helios::system::programs as prog_wit;

    let cases = [
        (41_u64, ChildTermination::Exited(0)),
        (42_u64, ChildTermination::Exited(137)),
        (
            43_u64,
            ChildTermination::Signaled(SignalTermination {
                signal: 15,
                core_dumped: false,
            }),
        ),
        (
            44_u64,
            ChildTermination::Signaled(SignalTermination {
                signal: 11,
                core_dumped: true,
            }),
        ),
        (45_u64, ChildTermination::Trapped),
        (46_u64, ChildTermination::Killed),
    ];

    for (raw_id, expected) in cases {
        let id = crate::InstanceId::from_raw(raw_id);
        let direct = block_on(child_handle_with_result(id, Ok(expected)).wait())
            .expect("child handle wait succeeds");
        assert_eq!(direct.instance_id, id);
        assert_eq!(direct.termination, expected);

        let prog_status = await_program_wit_wait(child_handle_with_result(id, Ok(expected)))
            .expect("program WIT child.wait reports termination");
        assert_eq!(prog_status.instance_id, raw_id);
        match (expected, prog_status.termination) {
            (ChildTermination::Exited(a), prog_wit::ChildTermination::Exited(b)) => {
                assert_eq!(a, b);
            }
            (
                ChildTermination::Signaled(SignalTermination {
                    signal: a_sig,
                    core_dumped: a_core,
                }),
                prog_wit::ChildTermination::Signaled(prog_wit::SignalTermination {
                    signal: b_sig,
                    core_dumped: b_core,
                }),
            ) => {
                assert_eq!((a_sig, a_core), (b_sig, b_core));
            }
            (ChildTermination::Trapped, prog_wit::ChildTermination::Trapped)
            | (ChildTermination::Killed, prog_wit::ChildTermination::Killed) => {}
            other => panic!("mismatched program WIT termination: {other:?}"),
        }

        let dbg_status = await_debugger_wit_wait(child_handle_with_result(id, Ok(expected)))
            .expect("debugger WIT child.wait reports termination");
        assert_eq!(dbg_status.instance_id, raw_id);
        match (expected, dbg_status.termination) {
            (ChildTermination::Exited(a), dbg_wit::ChildTermination::Exited(b)) => {
                assert_eq!(a, b);
            }
            (
                ChildTermination::Signaled(SignalTermination {
                    signal: a_sig,
                    core_dumped: a_core,
                }),
                dbg_wit::ChildTermination::Signaled(dbg_wit::SignalTermination {
                    signal: b_sig,
                    core_dumped: b_core,
                }),
            ) => {
                assert_eq!((a_sig, a_core), (b_sig, b_core));
            }
            (ChildTermination::Trapped, dbg_wit::ChildTermination::Trapped)
            | (ChildTermination::Killed, dbg_wit::ChildTermination::Killed) => {}
            other => panic!("mismatched debugger WIT termination: {other:?}"),
        }
    }

    let failed = await_program_wit_wait(child_handle_with_result(
        crate::InstanceId::from_raw(99),
        Err(ProgramExecError {
            kind: ProgramExecErrorKind::OutOfMemory,
            detail: ProgramExecErrorDetail::ExecutorTaskCapacityExhausted,
        }),
    ))
    .expect_err("a launch or OOM failure stays a SpawnError");
    assert_eq!(failed.kind, prog_wit::SpawnErrorKind::OutOfMemory);
}

struct CountingJoinWaker(core::sync::atomic::AtomicUsize);

impl std::task::Wake for CountingJoinWaker {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, AtomicOrdering::SeqCst);
    }
}

type ChildExitSender = futures::channel::oneshot::Sender<Result<ChildExit, ProgramExecError>>;
type Exec3Args = (u32, u32, u32, u32, u32, u32, i32, u32, u32);
type Exec2Args = (u32, u32, u32, u32, u32, u32);

struct WasixJoinHarness {
    store: wasmtime::Store<Preview1ProgramStore<TestCpu, TestNetworkService, UnsupportedStorage>>,
    memory: SharedMemory,
    join: wasmtime::TypedFunc<(u32, u32, u32), i32>,
    exec3: wasmtime::TypedFunc<Exec3Args, i32>,
    exec2: wasmtime::TypedFunc<Exec2Args, ()>,
    caller_probe: wasmtime::TypedFunc<u32, u32>,
}

impl WasixJoinHarness {
    fn new() -> Self {
        let mut config = wasmtime::Config::new();
        config.wasm_threads(true);
        config.shared_memory(true);
        let engine = wasmtime::Engine::new(&config).expect("shared-memory engine initializes");
        let memory = SharedMemory::new(
            &engine,
            wasmtime::MemoryType::shared(1, 1).expect("1..=1 is a valid shared memory type"),
        )
        .expect("shared memory allocates");

        let cpu = TestCpu::with_entropy(0x5a);
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
        let executor = crate::Executor::isolated(
            ProgressCounter::new(),
            crate::test_support::single_node_pool(1),
            ProcessorId::new(0),
        );
        let registry = crate::InstanceRegistry::new();
        let instance = registry.register("wasix-parent", 0);
        let interrupts = Arc::new(GuestInterrupts::new(1, cpu.timebase()));
        let threads = WasixProcessThreads::new();
        let store_data = Preview1ProgramStore::new(
            cpu,
            executor.timer(cpu),
            executor
                .spawner(cpu)
                .instance_spawner(crate::TaskFunding::Instance, &instance),
            runtime_state,
            interrupts,
            instance,
            None,
            alloc::vec!["/bin/parent".to_owned()],
            alloc::vec![("INHERITED".to_owned(), "keep".to_owned())],
            ProcessAuthority::root(),
            OutputMode::Serial,
            |_, _| {},
            crate::DebugSerialWriter::of::<test_store::DiscardPort>(),
            Some(memory.clone()),
            None,
            None,
            WasixSignalState::new(),
            threads.main_mailbox(),
            Vec::new(),
            None,
            true,
            threads,
        );
        let mut store = wasmtime::Store::new(&engine, store_data);
        let join = wasmtime::Func::wrap_async(
            &mut store,
            |mut caller: Caller<
                '_,
                Preview1ProgramStore<TestCpu, TestNetworkService, UnsupportedStorage>,
            >,
             (pid_ptr, flags, ret_status): (u32, u32, u32)| {
                Box::new(async move {
                    p1_reply(wasix_proc_join(&mut caller, pid_ptr, flags, ret_status).await)
                })
            },
        )
        .typed::<(u32, u32, u32), i32>(&store)
        .expect("proc_join signature matches");

        // Simulates a WASIX guest frame calling `proc_exec3` and then
        // continuing in the caller when `proc_exec3` returns an errno
        // instead of unwinding into a replacement image.
        let exec3 = wasmtime::Func::wrap_async(
            &mut store,
            |mut caller: Caller<
                '_,
                Preview1ProgramStore<TestCpu, TestNetworkService, UnsupportedStorage>,
            >,
             (name, name_len, args, args_len, env, env_len, search_path, path, path_len): Exec3Args| {
                Box::new(async move {
                    let errno = wasix_proc_exec3(
                        &mut caller,
                        name,
                        name_len,
                        args,
                        args_len,
                        env,
                        env_len,
                        search_path,
                        path,
                        path_len,
                    )
                    .await?;
                    if let Some(mem) = p1_async_memory(&mut caller) {
                        let _ = mem.write_u32(GuestAddress::wasm32(256), 0xcafe_babe).await;
                    }
                    Ok(errno)
                })
            },
        )
        .typed::<Exec3Args, i32>(&store)
        .expect("proc_exec3 signature matches");

        let exec2 = wasmtime::Func::wrap_async(
            &mut store,
            |mut caller: Caller<
                '_,
                Preview1ProgramStore<TestCpu, TestNetworkService, UnsupportedStorage>,
            >,
             (name, name_len, args, args_len, env, env_len): Exec2Args| {
                Box::new(async move {
                    wasix_proc_exec(
                        &mut caller,
                        name,
                        name_len,
                        args,
                        args_len,
                        Some((env, env_len)),
                    )
                    .await
                })
            },
        )
        .typed::<Exec2Args, ()>(&store)
        .expect("proc_exec2 signature matches");

        let caller_probe = wasmtime::Func::wrap(
            &mut store,
            |caller: Caller<
                '_,
                Preview1ProgramStore<TestCpu, TestNetworkService, UnsupportedStorage>,
            >,
             step: u32|
             -> u32 {
                assert_eq!(caller.data().arguments, ["/bin/parent"]);
                assert_eq!(
                    caller.data().environment,
                    [("INHERITED".to_owned(), "keep".to_owned())]
                );
                step + 1
            },
        )
        .typed::<u32, u32>(&store)
        .expect("caller_probe signature matches");

        Self {
            store,
            memory,
            join,
            exec3,
            exec2,
            caller_probe,
        }
    }

    fn spawn_child(&mut self, pid: u32) -> ChildExitSender {
        let (tx, rx) = futures::channel::oneshot::channel();
        self.store
            .data_mut()
            .insert_child(pid, WasixSignalState::new(), rx);
        tx
    }

    fn finish_child(tx: ChildExitSender, pid: u32, termination: ChildTermination) {
        tx.send(Ok(ChildExit {
            instance_id: crate::InstanceId::from_raw(u64::from(pid)),
            termination,
            filesystem: None,
        }))
        .unwrap_or_else(|_| panic!("child {pid}'s exit receiver was dropped"));
    }

    fn write_guest(&self, offset: usize, bytes: &[u8]) {
        for (i, &b) in bytes.iter().enumerate() {
            unsafe {
                self.memory.data()[offset + i].get().write(b);
            }
        }
    }

    fn read_guest(&self, offset: usize, len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| unsafe { self.memory.data()[offset + i].get().read() })
            .collect()
    }

    fn prepare_join_buffers(&self, requested_pid: Option<u32>) -> (u32, u32) {
        let pid_ptr = 16_u32;
        let status_ptr = 32_u32;
        self.write_guest(pid_ptr as usize, &[0_u8; 8]);
        self.write_guest(status_ptr as usize, &[0xff_u8; 6]);
        match requested_pid {
            Some(pid) => {
                self.write_guest(pid_ptr as usize, &[WASIX_OPTION_SOME]);
                self.write_guest(
                    (pid_ptr + WASIX_OPTION_UNION_U32_OFFSET) as usize,
                    &pid.to_le_bytes(),
                );
            }
            None => {
                self.write_guest(pid_ptr as usize, &[WASIX_OPTION_NONE]);
            }
        }
        (pid_ptr, status_ptr)
    }

    fn decode_join_buffers(&self, pid_ptr: u32, status_ptr: u32) -> (Option<u32>, [u8; 6]) {
        let pid_bytes = self.read_guest(pid_ptr as usize, 8);
        let joined_pid = (pid_bytes[0] == WASIX_OPTION_SOME)
            .then(|| u32::from_le_bytes(pid_bytes[4..8].try_into().expect("four pid bytes")));
        let status: [u8; 6] = self
            .read_guest(status_ptr as usize, 6)
            .try_into()
            .expect("six status bytes");
        (joined_pid, status)
    }

    fn call_join(&mut self, requested_pid: Option<u32>, flags: u32) -> (i32, Option<u32>, [u8; 6]) {
        let (pid_ptr, status_ptr) = self.prepare_join_buffers(requested_pid);
        let errno = block_on(
            self.join
                .call_async(&mut self.store, (pid_ptr, flags, status_ptr)),
        )
        .expect("host proc_join call completes");
        let (joined_pid, status) = self.decode_join_buffers(pid_ptr, status_ptr);
        (errno, joined_pid, status)
    }
}

#[test]
fn wasix_proc_join_produces_each_of_the_four_endings_from_the_shared_record() {
    let mut harness = WasixJoinHarness::new();

    for flags in [0_u32, WASIX_JOIN_FLAG_NON_BLOCKING] {
        let cases = [
            (101_u32, ChildTermination::Exited(42)),
            (
                102_u32,
                ChildTermination::Signaled(SignalTermination {
                    signal: 15,
                    core_dumped: false,
                }),
            ),
            (
                103_u32,
                ChildTermination::Signaled(SignalTermination {
                    signal: 11,
                    core_dumped: true,
                }),
            ),
            (104_u32, ChildTermination::Trapped),
            (105_u32, ChildTermination::Killed),
        ];

        for (pid, termination) in cases {
            let (tx, rx) = futures::channel::oneshot::channel();
            let _ = tx.send(Ok(ChildExit {
                instance_id: crate::InstanceId::from_raw(u64::from(pid)),
                termination,
                filesystem: None,
            }));
            harness
                .store
                .data_mut()
                .insert_child(pid, WasixSignalState::new(), rx);

            let (errno, joined_pid, status) = harness.call_join(Some(pid), flags);
            assert_eq!(errno, p1::errno::SUCCESS);
            assert_eq!(joined_pid, Some(pid));

            match termination {
                ChildTermination::Exited(code) => {
                    assert_eq!(status[0], WASIX_JOIN_STATUS_EXIT_NORMAL);
                    assert_eq!(u16::from_le_bytes([status[2], status[3]]), code as u16,);
                }
                ChildTermination::Signaled(SignalTermination {
                    signal,
                    core_dumped,
                }) => {
                    assert_eq!(status[0], WASIX_JOIN_STATUS_EXIT_SIGNAL);
                    assert_eq!(u16::from_le_bytes([status[2], status[3]]), 0);
                    assert_eq!(status[4], (signal & 0x7f) | (u8::from(core_dumped) << 7));
                }
                ChildTermination::Trapped => {
                    assert_eq!(status[0], WASIX_JOIN_STATUS_EXIT_SIGNAL);
                    assert_eq!(u16::from_le_bytes([status[2], status[3]]), 0);
                    assert_eq!(status[4], WASIX_SIGABRT);
                }
                ChildTermination::Killed => {
                    assert_eq!(status[0], WASIX_JOIN_STATUS_EXIT_SIGNAL);
                    assert_eq!(u16::from_le_bytes([status[2], status[3]]), 0);
                    assert_eq!(status[4], WASIX_SIGKILL);
                }
            }
        }

        // A failed launch or OOM returns its errno and reaps the slot
        // instead of fabricating an EXIT_NORMAL status.
        let (tx, rx) = futures::channel::oneshot::channel();
        let _ = tx.send(Err(ProgramExecError {
            kind: ProgramExecErrorKind::OutOfMemory,
            detail: ProgramExecErrorDetail::ExecutorTaskCapacityExhausted,
        }));
        harness
            .store
            .data_mut()
            .insert_child(199, WasixSignalState::new(), rx);
        let (errno, _pid, _status) = harness.call_join(Some(199), flags);
        assert_eq!(errno, p1::errno::NOMEM);
        assert!(harness.store.data().children.is_empty());
    }
}

/// `proc_join` with no pid under `WNOHANG` checks every child: when two
/// children exist and the second exits first while the first stays running,
/// `WNOHANG` reaps the second child immediately, reports `NOTHING` while
/// only the running first child remains, and reaps the first once it exits.
#[test]
fn wnohang_any_child_join_reaps_second_child_while_first_stays_running() {
    let mut harness = WasixJoinHarness::new();
    let first = harness.spawn_child(10);
    let second = harness.spawn_child(11);
    WasixJoinHarness::finish_child(second, 11, ChildTermination::Exited(7));

    let (errno, joined_pid, status) = harness.call_join(None, WASIX_JOIN_FLAG_NON_BLOCKING);
    assert_eq!(errno, p1::errno::SUCCESS);
    assert_eq!(joined_pid, Some(11));
    assert_eq!(status[0], WASIX_JOIN_STATUS_EXIT_NORMAL);
    assert_eq!(u16::from_le_bytes([status[2], status[3]]), 7);

    let (errno, joined_pid, status) = harness.call_join(None, WASIX_JOIN_FLAG_NON_BLOCKING);
    assert_eq!(errno, p1::errno::SUCCESS);
    assert_eq!(joined_pid, None);
    assert_eq!(status[0], WASIX_JOIN_STATUS_NOTHING);

    WasixJoinHarness::finish_child(first, 10, ChildTermination::Exited(3));
    let (errno, joined_pid, status) = harness.call_join(None, WASIX_JOIN_FLAG_NON_BLOCKING);
    assert_eq!(errno, p1::errno::SUCCESS);
    assert_eq!(joined_pid, Some(10));
    assert_eq!(status[0], WASIX_JOIN_STATUS_EXIT_NORMAL);
    assert_eq!(u16::from_le_bytes([status[2], status[3]]), 3);

    let (errno, joined_pid, status) = harness.call_join(None, WASIX_JOIN_FLAG_NON_BLOCKING);
    assert_eq!(errno, p1::errno::SUCCESS);
    assert_eq!(joined_pid, None);
    assert_eq!(status[0], WASIX_JOIN_STATUS_NOTHING);
}

/// A blocking `proc_join` with no pid registers its waker on every running
/// child: when the second child exits while the first stays running, the
/// parked join wakes immediately and reaps the second child without waiting
/// on the first.
#[test]
fn blocking_any_child_join_waits_on_all_children_and_wakes_when_second_exits_first() {
    let mut harness = WasixJoinHarness::new();
    let first = harness.spawn_child(20);
    let second = harness.spawn_child(21);

    let (pid_ptr, status_ptr) = harness.prepare_join_buffers(None);
    let wakes = Arc::new(CountingJoinWaker(core::sync::atomic::AtomicUsize::new(0)));
    let waker = core::task::Waker::from(wakes.clone());
    let mut cx = Context::from_waker(&waker);

    {
        let mut join_fut = core::pin::pin!(
            harness
                .join
                .call_async(&mut harness.store, (pid_ptr, 0, status_ptr))
        );
        assert!(
            join_fut.as_mut().poll(&mut cx).is_pending(),
            "both children are still running"
        );
        assert_eq!(wakes.0.load(AtomicOrdering::SeqCst), 0);

        WasixJoinHarness::finish_child(second, 21, ChildTermination::Exited(9));
        assert_eq!(
            wakes.0.load(AtomicOrdering::SeqCst),
            1,
            "the second child's exit wakes the parked any-child join"
        );

        let Poll::Ready(Ok(errno)) = join_fut.as_mut().poll(&mut cx) else {
            panic!("woken any-child join completes on next poll");
        };
        assert_eq!(errno, p1::errno::SUCCESS);
    }

    let (joined_pid, status) = harness.decode_join_buffers(pid_ptr, status_ptr);
    assert_eq!(joined_pid, Some(21));
    assert_eq!(status[0], WASIX_JOIN_STATUS_EXIT_NORMAL);
    assert_eq!(u16::from_le_bytes([status[2], status[3]]), 9);
    assert!(
        harness
            .store
            .data_mut()
            .live_child_signal_target(20)
            .is_some(),
        "the first child remains running in the table"
    );
    assert!(
        harness
            .store
            .data_mut()
            .live_child_signal_target(21)
            .is_none()
    );

    WasixJoinHarness::finish_child(first, 20, ChildTermination::Exited(4));
    let (errno, joined_pid, status) = harness.call_join(None, 0);
    assert_eq!(errno, p1::errno::SUCCESS);
    assert_eq!(joined_pid, Some(20));
    assert_eq!(status[0], WASIX_JOIN_STATUS_EXIT_NORMAL);
    assert_eq!(u16::from_le_bytes([status[2], status[3]]), 4);
}

/// An any-child `proc_join` reports signaled and trapped children with
/// `EXIT_SIGNAL` and failed launches or dropped channels as errnos; only a
/// child's own exit yields `EXIT_NORMAL`.
#[test]
fn any_child_proc_join_reports_trapped_signaled_and_failed_launch_distinctly() {
    let mut harness = WasixJoinHarness::new();

    for flags in [0_u32, WASIX_JOIN_FLAG_NON_BLOCKING] {
        let running = harness.spawn_child(30);
        let signaled = harness.spawn_child(31);
        WasixJoinHarness::finish_child(
            signaled,
            31,
            ChildTermination::Signaled(SignalTermination {
                signal: 15,
                core_dumped: false,
            }),
        );
        let (errno, joined_pid, status) = harness.call_join(None, flags);
        assert_eq!(errno, p1::errno::SUCCESS);
        assert_eq!(joined_pid, Some(31));
        assert_eq!(status[0], WASIX_JOIN_STATUS_EXIT_SIGNAL);
        assert_eq!(u16::from_le_bytes([status[2], status[3]]), 0);
        assert_eq!(status[4], 15);

        let trapped = harness.spawn_child(32);
        WasixJoinHarness::finish_child(trapped, 32, ChildTermination::Trapped);
        let (errno, joined_pid, status) = harness.call_join(None, flags);
        assert_eq!(errno, p1::errno::SUCCESS);
        assert_eq!(joined_pid, Some(32));
        assert_eq!(status[0], WASIX_JOIN_STATUS_EXIT_SIGNAL);
        assert_eq!(u16::from_le_bytes([status[2], status[3]]), 0);
        assert_eq!(status[4], WASIX_SIGABRT);

        let failed_launch = harness.spawn_child(33);
        failed_launch
            .send(Err(ProgramExecError {
                kind: ProgramExecErrorKind::NotFound,
                detail: ProgramExecErrorDetail::MissingArtifactPayload,
            }))
            .expect("receiver is alive");
        let (errno, _joined_pid, status) = harness.call_join(None, flags);
        assert_eq!(errno, p1::errno::NOENT);
        assert_ne!(
            status[0], WASIX_JOIN_STATUS_EXIT_NORMAL,
            "a failed launch never writes EXIT_NORMAL"
        );

        let dropped = harness.spawn_child(34);
        drop(dropped);
        let (errno, _joined_pid, status) = harness.call_join(None, flags);
        assert_eq!(errno, p1::errno::IO);
        assert_ne!(status[0], WASIX_JOIN_STATUS_EXIT_NORMAL);

        WasixJoinHarness::finish_child(running, 30, ChildTermination::Exited(0));
        let (errno, joined_pid, status) = harness.call_join(None, flags);
        assert_eq!(errno, p1::errno::SUCCESS);
        assert_eq!(joined_pid, Some(30));
        assert_eq!(status[0], WASIX_JOIN_STATUS_EXIT_NORMAL);
        assert_eq!(u16::from_le_bytes([status[2], status[3]]), 0);
        assert!(harness.store.data().children.is_empty());
    }
}

/// `proc_exec3` with an out-of-bounds or non-UTF-8 environment fails with
/// `EFAULT`, leaves no pending `WasixExecReplacement`, and returns to the
/// caller so the caller keeps running; legacy `_Noreturn` `proc_exec2`
/// likewise refuses the unreadable environment with `EFAULT` instead of
/// proceeding with an empty environment.
#[test]
fn proc_exec_with_unreadable_environment_fails_with_efault_and_caller_keeps_running() {
    let mut harness = WasixJoinHarness::new();

    // Seed an executable file at `/prog.wasm` in the store's filesystem so
    // path lookup and source read succeed whenever `proc_exec*` reaches them.
    let ns = harness.store.data().filesystem.clone();
    block_on(async {
        let root_dir = FsDescriptor {
            path: String::from("/"),
            kind: FsNodeKind::Directory,
            flags: FsDescriptorFlags::READ
                | FsDescriptorFlags::WRITE
                | FsDescriptorFlags::MUTATE_DIRECTORY,
            identity: None,
            mount: None,
            open: None,
        };
        let created = wasi_fs::open_at(
            &ns,
            root_dir.grant().expect("root directory grant"),
            fs_types::PathFlags::empty(),
            "prog.wasm",
            fs_types::OpenFlags::CREATE,
            FsDescriptorFlags::READ | FsDescriptorFlags::WRITE,
            1,
        )
        .await
        .expect("creates /prog.wasm");
        wasi_fs::write(
            &ns,
            created.grant().expect("file write grant"),
            helios_hal::fs::WritePosition::At(0),
            b"\0asm\x01\0\0\0",
            1,
        )
        .await
        .expect("writes /prog.wasm");
        read_program_source_from(&ns, &harness.store.data().authority, "/prog.wasm")
            .await
            .expect("/prog.wasm is readable as a program source");
    });

    let name = b"/prog.wasm";
    let args = b"prog\n";
    harness.write_guest(64, name);
    harness.write_guest(96, args);
    harness.write_guest(128, &[0xff, 0xfe, 0xff, 0xfe]);

    let bad_envs: &[(u32, u32)] = &[
        (65_530, 16),  // straddles the end of the 64 KiB linear memory
        (65_536, 1),   // starts one byte past linear memory
        (u32::MAX, 4), // u32 address wraparound
        (128, 4),      // in-bounds invalid UTF-8
    ];

    for (step, &(env_ptr, env_len)) in bad_envs.iter().enumerate() {
        harness.write_guest(256, &[0_u8; 4]);
        let errno = block_on(harness.exec3.call_async(
            &mut harness.store,
            (
                64,
                name.len() as u32,
                96,
                args.len() as u32,
                env_ptr,
                env_len,
                0,
                0,
                0,
            ),
        ))
        .expect("proc_exec3 returns errno instead of trapping the caller");

        assert_eq!(
            errno,
            p1::errno::FAULT,
            "env=({env_ptr:#x}, {env_len}) must fail with EFAULT"
        );
        let witness = u32::from_le_bytes(
            harness
                .read_guest(256, 4)
                .try_into()
                .expect("four witness bytes"),
        );
        assert_eq!(
            witness, 0xcafe_babe,
            "caller frame must keep running after proc_exec3 returns EFAULT"
        );
        assert!(
            harness.store.data_mut().take_exec_replacement().is_none(),
            "failed proc_exec3 must never queue an exec replacement"
        );
        // Subsequent calls on the same store continue executing normally with
        // the caller's original arguments and environment intact.
        let next_step = block_on(
            harness
                .caller_probe
                .call_async(&mut harness.store, step as u32),
        )
        .expect("caller store keeps running subsequent calls");
        assert_eq!(next_step, step as u32 + 1);
    }

    // Legacy `_Noreturn` `proc_exec2` has no errno return slot in its wasm
    // signature, so it unwinds with a `ProgramExecError` whose errno is
    // `EFAULT` and queues no replacement.
    let error = block_on(harness.exec2.call_async(
        &mut harness.store,
        (64, name.len() as u32, 96, args.len() as u32, 65_530, 16),
    ))
    .expect_err("proc_exec2 unwinds on out-of-bounds environment");
    assert_eq!(p1_errno_from_wasmtime_error(&error), p1::errno::FAULT);
    assert!(harness.store.data_mut().take_exec_replacement().is_none());
}

#[test]
fn runtime_end_classification_distinguishes_exits_signals_traps_owner_kills_and_oom() {
    assert_eq!(
        preview1_process_end(wasmtime::Error::new(Preview1Exit), Some(19)),
        Ok(ChildTermination::Exited(19))
    );
    assert_eq!(
        preview1_process_end(
            wasmtime::Error::new(Preview1SignalExit { signal: 15 }),
            Some(0)
        ),
        Ok(ChildTermination::Signaled(SignalTermination {
            signal: 15,
            core_dumped: false,
        }))
    );
    assert_eq!(
        preview1_process_end(
            wasmtime::Error::new(wasmtime::Trap::UnreachableCodeReached),
            None,
        ),
        Ok(ChildTermination::Trapped)
    );
    assert_eq!(
        preview1_process_end(
            wasmtime::Error::new(crate::memory::SwapFaultError::Backend),
            None,
        ),
        Ok(ChildTermination::Trapped)
    );
    for reason in [
        crate::KillReason::Operator,
        crate::KillReason::RequesterGone,
    ] {
        assert_eq!(
            preview1_process_end(
                wasmtime::Error::from(crate::InstanceKilled { reason }),
                Some(0),
            ),
            Ok(ChildTermination::Killed)
        );
    }
    let oom = preview1_process_end(
        wasmtime::Error::from(crate::InstanceKilled {
            reason: crate::KillReason::OutOfMemory,
        }),
        Some(0),
    )
    .expect_err("OOM kill stays a runtime error");
    assert_eq!(oom.kind, ProgramExecErrorKind::OutOfMemory);

    // A component child suspended in a host future wakes and ends as
    // Signaled when its parent raises on its signal_state.
    let data = test_store::store_data_authorized(ProcessAuthority::root(), |_| {});
    let signals = WasixSignalState::new();
    let turns = data.guest_turns_with_epilogue(super::super::ComponentStoreEpilogue::new(
        data.retirement.turn_queue(),
        Some(signals.clone()),
    ));
    let mut driven = core::pin::pin!(turns.drive(core::future::pending::<wasmtime::Result<()>>()));
    let waker = futures::task::noop_waker_ref();
    let mut cx = Context::from_waker(waker);
    assert!(driven.as_mut().poll(&mut cx).is_pending());
    signals.raise(helios_unix::Signal::SIGTERM);
    let Poll::Ready(Err(stop)) = driven.as_mut().poll(&mut cx) else {
        panic!("signal stops the suspended component turn");
    };
    assert_eq!(
        preview1_process_end(stop, None),
        Ok(ChildTermination::Signaled(SignalTermination {
            signal: 15,
            core_dumped: false,
        }))
    );
}

#[cfg(feature = "linux")]
mod linux_tests {
    use super::*;
    use core::sync::atomic::AtomicUsize;
    use helios_hal::cpu::{Cpu, Instant, Timebase, TimerInterrupt};
    use helios_hal::entropy::{EntropyQuality, EntropyUnavailable};
    use helios_hal::hv::RegisterId;
    use helios_hal::native::{
        FaultKind, InstructionSet, Mapping, NativeError, NativeExecution, NativeUnavailable, Stop,
        UserContext, UserFault, UserSpace,
    };
    use helios_hal::pmm::PhysFrame;
    use helios_hal::vmm::{PageFlags, VirtAddr, VirtRange};

    #[derive(Clone, Copy, Debug)]
    enum LinuxBehavior {
        ExitGroup(u8),
        SuspendInRead,
        PageFault,
    }

    #[derive(Clone)]
    struct MockLinuxCpu {
        base: TestCpu,
        behavior: LinuxBehavior,
    }

    struct MockSpace;

    // SAFETY: MockSpace maps no hardware page tables and never enters user mode.
    unsafe impl UserSpace for MockSpace {
        fn map(&self, _: VirtRange, _: &[u8], _: PageFlags) -> Result<(), NativeError> {
            Ok(())
        }
        fn map_anywhere(
            &self,
            hint: VirtAddr,
            byte_len: usize,
            _: PageFlags,
        ) -> Result<VirtRange, NativeError> {
            Ok(VirtRange::new(hint, byte_len))
        }
        fn read(&self, _: VirtAddr, output: &mut [u8]) -> Result<(), NativeError> {
            output.fill(0);
            Ok(())
        }
        fn check_writable(&self, _: VirtAddr, _: usize) -> Result<(), NativeError> {
            Ok(())
        }
        fn write(&self, _: VirtAddr, _: &[u8]) -> Result<(), NativeError> {
            Ok(())
        }
        fn atomic_load_u32(&self, _: VirtAddr) -> Result<u32, NativeError> {
            Ok(0)
        }
        fn atomic_store_u32(&self, _: VirtAddr, _: u32) -> Result<(), NativeError> {
            Ok(())
        }
        fn atomic_compare_exchange_u32(
            &self,
            _: VirtAddr,
            expected: u32,
            _: u32,
        ) -> Result<Result<u32, u32>, NativeError> {
            Ok(Ok(expected))
        }
        fn unmap(&self, _: VirtRange) -> Result<(), NativeError> {
            Ok(())
        }
        fn protect(&self, _: VirtRange, _: PageFlags) -> Result<(), NativeError> {
            Ok(())
        }
        fn discard(&self, _: VirtRange) -> Result<(), NativeError> {
            Ok(())
        }
        fn remap(&self, _: VirtRange, _: VirtRange) -> Result<(), NativeError> {
            Ok(())
        }
        fn resolve_fault(&self, _: VirtAddr, _: PageFlags) -> Result<(), NativeError> {
            Err(NativeError::NotMapped)
        }
        fn mapping(&self, _: VirtRange) -> Option<Mapping> {
            None
        }
        fn free_range(&self, hint: VirtAddr, _: usize) -> Option<VirtAddr> {
            Some(hint)
        }
    }

    struct MockContext {
        behavior: LinuxBehavior,
        step: AtomicUsize,
        result: u64,
        tp: VirtAddr,
    }

    // SAFETY: MockContext never enters hardware user mode.
    unsafe impl UserContext for MockContext {
        type Space = MockSpace;

        fn register(&self, register: RegisterId) -> Result<u64, NativeError> {
            match (self.behavior, register) {
                (LinuxBehavior::ExitGroup(_), RegisterId::X86Gpr(0)) => Ok(231),
                (LinuxBehavior::ExitGroup(code), RegisterId::X86Gpr(7)) => Ok(u64::from(code)),
                // read(fd = 0, buf = 0x40_1000, count = 1) blocks on empty child stdin.
                (LinuxBehavior::SuspendInRead, RegisterId::X86Gpr(0)) => Ok(0),
                (LinuxBehavior::SuspendInRead, RegisterId::X86Gpr(7)) => Ok(0),
                (LinuxBehavior::SuspendInRead, RegisterId::X86Gpr(6)) => Ok(0x40_1000),
                (LinuxBehavior::SuspendInRead, RegisterId::X86Gpr(2)) => Ok(1),
                (_, RegisterId::X86Gpr(_)) => Ok(0),
                _ => Err(NativeError::Register),
            }
        }

        fn set_register(&mut self, register: RegisterId, value: u64) -> Result<(), NativeError> {
            if matches!(register, RegisterId::X86Gpr(0)) {
                self.result = value;
                Ok(())
            } else {
                Err(NativeError::Register)
            }
        }

        fn thread_pointer(&self) -> VirtAddr {
            self.tp
        }

        fn set_thread_pointer(&mut self, address: VirtAddr) -> Result<(), NativeError> {
            self.tp = address;
            Ok(())
        }

        fn try_clone(&self) -> Result<Self, NativeError> {
            Ok(Self {
                behavior: self.behavior,
                step: AtomicUsize::new(self.step.load(AtomicOrdering::Relaxed)),
                result: self.result,
                tp: self.tp,
            })
        }

        fn resume(&mut self, _: &MockSpace) -> Stop {
            let _ = self.step.fetch_add(1, AtomicOrdering::Relaxed);
            match self.behavior {
                LinuxBehavior::ExitGroup(_) | LinuxBehavior::SuspendInRead => Stop::SystemCall,
                LinuxBehavior::PageFault => Stop::Fault(UserFault {
                    kind: FaultKind::Page {
                        address: VirtAddr::new(0x1000),
                        access: PageFlags::READ,
                        present: false,
                    },
                    instruction: VirtAddr::new(0x40_0000),
                }),
            }
        }
    }

    impl NativeExecution for MockLinuxCpu {
        type Space = MockSpace;
        type Context = MockContext;

        fn instruction_set(&self) -> InstructionSet {
            InstructionSet::X86_64
        }

        fn user_range(&self) -> VirtRange {
            VirtRange::new(
                VirtAddr::new(PhysFrame::SIZE),
                (1usize << 47) - 2 * PhysFrame::SIZE,
            )
        }

        fn create_space(&self) -> Result<Self::Space, NativeError> {
            Ok(MockSpace)
        }

        fn create_context(&self, _: VirtAddr, _: VirtAddr) -> Result<Self::Context, NativeError> {
            Ok(MockContext {
                behavior: self.behavior,
                step: AtomicUsize::new(0),
                result: 0,
                tp: VirtAddr::new(PhysFrame::SIZE),
            })
        }
    }

    impl Cpu for MockLinuxCpu {
        type Hypervisor = core::convert::Infallible;
        type Native = Self;
        const TIMER_INTERRUPT: TimerInterrupt = TimerInterrupt::Deadline;

        fn native(&self) -> Result<&Self::Native, NativeUnavailable> {
            Ok(self)
        }
        fn has_lazy_commit_virtual_memory(&self) -> bool {
            true
        }
        fn processor_count(&self) -> usize {
            1
        }
        fn bootstrap_processor(&self) -> ProcessorId {
            ProcessorId::new(0)
        }
        fn park_current(&self) {}
        type WakeOnlyMask = ();
        fn mask_to_wake_only(&self) {
            unreachable!()
        }
        fn park_wake_only(&self, _: &core::sync::atomic::AtomicU8, _: u8) {
            unreachable!()
        }
        fn start_processor(&self, _: ProcessorId) {}
        fn wake_processor(&self, _: ProcessorId) {}
        fn stop_current(&self) {
            unreachable!()
        }
        fn restart_processor(&self, _: ProcessorId) {
            unreachable!()
        }
        fn now(&self) -> Instant {
            self.base.now()
        }
        fn timebase(&self) -> Timebase {
            self.base.timebase()
        }
        fn set_deadline(&self, _: Instant) {}
        fn publish_executable(&self, _: *const u8, _: usize) {}
        fn unpublish_executable(&self, _: *const u8, _: usize) {}
        fn native_feature_probe(&self) -> Option<fn(&str) -> Option<bool>> {
            self.base.native_feature_probe()
        }
        fn fill_entropy(&self, buffer: &mut [u8]) -> Result<EntropyQuality, EntropyUnavailable> {
            self.base.fill_entropy(buffer)
        }
        fn shutdown(&self) -> ! {
            unreachable!()
        }
        fn reboot(&self) -> ! {
            unreachable!()
        }
    }

    /// Minimal valid static little-endian x86-64 `ET_EXEC` ELF with one RX
    /// `PT_LOAD` segment at `0x400000`.
    fn minimal_x86_64_elf() -> Bytes {
        let mut elf = vec![0_u8; 4096];
        elf[0..4].copy_from_slice(b"\x7fELF");
        elf[4] = 2; // ELFCLASS64
        elf[5] = 1; // ELFDATA2LSB
        elf[6] = 1; // EV_CURRENT
        elf[16..18].copy_from_slice(&2_u16.to_le_bytes()); // ET_EXEC
        elf[18..20].copy_from_slice(&62_u16.to_le_bytes()); // EM_X86_64
        elf[20..24].copy_from_slice(&1_u32.to_le_bytes()); // EV_CURRENT
        let entry = 0x40_0080_u64;
        elf[24..32].copy_from_slice(&entry.to_le_bytes()); // e_entry
        elf[32..40].copy_from_slice(&64_u64.to_le_bytes()); // e_phoff
        elf[52..54].copy_from_slice(&64_u16.to_le_bytes()); // e_ehsize
        elf[54..56].copy_from_slice(&56_u16.to_le_bytes()); // e_phentsize
        elf[56..58].copy_from_slice(&1_u16.to_le_bytes()); // e_phnum

        // Program header 0: PT_LOAD, PF_R | PF_X, vaddr 0x400000, filesz/memsz 4096.
        let ph = &mut elf[64..120];
        ph[0..4].copy_from_slice(&1_u32.to_le_bytes()); // PT_LOAD
        ph[4..8].copy_from_slice(&5_u32.to_le_bytes()); // PF_R | PF_X
        ph[8..16].copy_from_slice(&0_u64.to_le_bytes()); // p_offset
        ph[16..24].copy_from_slice(&0x40_0000_u64.to_le_bytes()); // p_vaddr
        ph[24..32].copy_from_slice(&0x40_0000_u64.to_le_bytes()); // p_paddr
        ph[32..40].copy_from_slice(&4096_u64.to_le_bytes()); // p_filesz
        ph[40..48].copy_from_slice(&4096_u64.to_le_bytes()); // p_memsz
        ph[48..56].copy_from_slice(&4096_u64.to_le_bytes()); // p_align

        Bytes::from(elf)
    }

    fn run_mock_linux(
        behavior: LinuxBehavior,
        before_poll: impl FnOnce(&crate::InstanceRegistry, crate::InstanceId, &WasixSignalState),
    ) -> ChildExit {
        let cpu = MockLinuxCpu {
            base: TestCpu::with_entropy(0x5a),
            behavior,
        };
        let runtime_state: HostRuntimeState<MockLinuxCpu, TestNetworkService, UnsupportedStorage> =
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
            .expect("entropy"),
        ));
        let executor = crate::Executor::isolated(
            ProgressCounter::new(),
            crate::test_support::single_node_pool(1),
            ProcessorId::new(0),
        );
        let registry = crate::InstanceRegistry::new();
        let instance = registry.register("linux-child", 0);
        let id = instance.id();
        let exec_context = ProgramExecContext {
            cpu: cpu.clone(),
            timer: executor.timer(cpu.clone()),
            spawner: executor.spawner(cpu.clone()),
            runtime_state,
            instance_registry: registry.clone(),
            parent_instance_id: None,
            read_serial: |_, _| {},
            write_serial: crate::DebugSerialWriter::of::<test_store::DiscardPort>(),
        };
        let executable =
            LinuxExecutable::load(&cpu, minimal_x86_64_elf()).expect("minimal x86-64 ELF loads");
        let signal_state = WasixSignalState::new();
        let (_stdin_tx_hold, stdin_rx) = crate::byte_channel();
        let (stdout_tx, _stdout_rx) = crate::byte_channel();
        let (stderr_tx, _stderr_rx) = crate::byte_channel();
        let output_mode = OutputMode::Child {
            stdin_rx,
            stdout_tx,
            stderr_tx,
        };
        let timeline = phases::Timeline::begin(&cpu, "spawn", "/linux/mock");
        let argv = ProgramArgv::launched("mock", Vec::new());

        let instance_spawner = executor
            .spawner(cpu.clone())
            .instance_spawner(crate::TaskFunding::Instance, &instance);
        let container = Arc::new(crate::LinuxContainer::ephemeral(
            crate::ContainerId::new(core::num::NonZeroU64::new(1).unwrap()),
            ProcessAuthority::root(),
            exec_context.runtime_state.root_namespace(),
        ));
        let mut fut = core::pin::pin!(run_linux_process(
            exec_context,
            argv,
            Vec::new(),
            container,
            None,
            None,
            signal_state.clone(),
            instance_spawner,
            instance,
            output_mode,
            executable,
            &timeline,
        ));
        let waker = futures::task::noop_waker_ref();
        let mut cx = Context::from_waker(waker);
        if let Poll::Ready(res) = fut.as_mut().poll(&mut cx) {
            return res.expect("Linux process completed");
        }
        before_poll(&registry, id, &signal_state);
        match fut.as_mut().poll(&mut cx) {
            Poll::Ready(res) => res.expect("Linux process completed after event"),
            Poll::Pending => panic!("Linux process remained pending after wake event"),
        }
    }

    #[test]
    fn linux_process_host_reports_exits_signals_faults_and_owner_kills_in_shared_record() {
        let exited = run_mock_linux(LinuxBehavior::ExitGroup(7), |_, _, _| {});
        assert_eq!(exited.termination, ChildTermination::Exited(7));

        let faulted = run_mock_linux(LinuxBehavior::PageFault, |_, _, _| {});
        assert_eq!(
            faulted.termination,
            ChildTermination::Signaled(SignalTermination {
                signal: helios_linux::abi::SIGSEGV,
                core_dumped: false,
            })
        );

        let signaled = run_mock_linux(LinuxBehavior::SuspendInRead, |_, _, signals| {
            signals.raise(helios_unix::Signal::SIGTERM);
        });
        assert_eq!(
            signaled.termination,
            ChildTermination::Signaled(SignalTermination {
                signal: 15,
                core_dumped: false,
            })
        );

        let killed = run_mock_linux(LinuxBehavior::SuspendInRead, |registry, id, _| {
            assert_eq!(
                registry.request_kill(
                    id,
                    crate::KillReason::Operator,
                    0,
                    &crate::UserResidency::default()
                ),
                crate::KillOutcome::Requested
            );
        });
        assert_eq!(killed.termination, ChildTermination::Killed);
    }

    const SCRATCH_BASE: usize = 0x50_0000;
    const SCRATCH_LEN: usize = 8192;

    #[derive(Clone, Copy)]
    enum ScriptStep {
        Syscall { num: u64, args: [u64; 6] },
        Preempt,
    }

    struct ScriptState {
        steps: Vec<ScriptStep>,
        cursor: AtomicUsize,
        results: spin::Mutex<Vec<i64>>,
        memory: spin::Mutex<Vec<u8>>,
    }

    impl ScriptState {
        fn new(steps: Vec<ScriptStep>, seed: impl FnOnce(&mut [u8])) -> Arc<Self> {
            let mut memory = vec![0_u8; SCRATCH_LEN];
            seed(&mut memory);
            Arc::new(Self {
                steps,
                cursor: AtomicUsize::new(0),
                results: spin::Mutex::new(Vec::new()),
                memory: spin::Mutex::new(memory),
            })
        }

        fn read_cstr(&self, offset: usize, max_len: usize) -> String {
            let mem = self.memory.lock();
            let slice = &mem[offset..offset + max_len];
            let end = slice.iter().position(|&b| b == 0).unwrap_or(max_len);
            String::from_utf8(slice[..end].to_vec()).expect("valid utf8")
        }

        fn read_u16_le(&self, offset: usize) -> u16 {
            let mem = self.memory.lock();
            u16::from_le_bytes([mem[offset], mem[offset + 1]])
        }
    }

    #[derive(Clone)]
    struct ScriptedLinuxCpu {
        base: TestCpu,
        script: Arc<ScriptState>,
    }

    struct ScriptedSpace {
        memory: Arc<ScriptState>,
    }

    // SAFETY: ScriptedSpace maps no hardware page tables and never enters user mode.
    unsafe impl UserSpace for ScriptedSpace {
        fn map(&self, _: VirtRange, _: &[u8], _: PageFlags) -> Result<(), NativeError> {
            Ok(())
        }
        fn map_anywhere(
            &self,
            hint: VirtAddr,
            byte_len: usize,
            _: PageFlags,
        ) -> Result<VirtRange, NativeError> {
            Ok(VirtRange::new(hint, byte_len))
        }
        fn read(&self, addr: VirtAddr, output: &mut [u8]) -> Result<(), NativeError> {
            let raw = addr.raw();
            if raw >= SCRATCH_BASE && raw + output.len() <= SCRATCH_BASE + SCRATCH_LEN {
                let start = raw - SCRATCH_BASE;
                let mem = self.memory.memory.lock();
                output.copy_from_slice(&mem[start..start + output.len()]);
                Ok(())
            } else {
                Err(NativeError::NotMapped)
            }
        }
        fn check_writable(&self, addr: VirtAddr, len: usize) -> Result<(), NativeError> {
            let raw = addr.raw();
            if raw >= SCRATCH_BASE && raw + len <= SCRATCH_BASE + SCRATCH_LEN {
                Ok(())
            } else {
                Err(NativeError::NotMapped)
            }
        }
        fn write(&self, addr: VirtAddr, input: &[u8]) -> Result<(), NativeError> {
            let raw = addr.raw();
            if raw >= SCRATCH_BASE && raw + input.len() <= SCRATCH_BASE + SCRATCH_LEN {
                let start = raw - SCRATCH_BASE;
                let mut mem = self.memory.memory.lock();
                mem[start..start + input.len()].copy_from_slice(input);
                Ok(())
            } else {
                Err(NativeError::NotMapped)
            }
        }
        fn atomic_load_u32(&self, _: VirtAddr) -> Result<u32, NativeError> {
            Ok(0)
        }
        fn atomic_store_u32(&self, _: VirtAddr, _: u32) -> Result<(), NativeError> {
            Ok(())
        }
        fn atomic_compare_exchange_u32(
            &self,
            _: VirtAddr,
            expected: u32,
            _: u32,
        ) -> Result<Result<u32, u32>, NativeError> {
            Ok(Ok(expected))
        }
        fn unmap(&self, _: VirtRange) -> Result<(), NativeError> {
            Ok(())
        }
        fn protect(&self, _: VirtRange, _: PageFlags) -> Result<(), NativeError> {
            Ok(())
        }
        fn discard(&self, _: VirtRange) -> Result<(), NativeError> {
            Ok(())
        }
        fn remap(&self, _: VirtRange, _: VirtRange) -> Result<(), NativeError> {
            Ok(())
        }
        fn resolve_fault(&self, _: VirtAddr, _: PageFlags) -> Result<(), NativeError> {
            Err(NativeError::NotMapped)
        }
        fn mapping(&self, _: VirtRange) -> Option<Mapping> {
            None
        }
        fn free_range(&self, hint: VirtAddr, _: usize) -> Option<VirtAddr> {
            Some(hint)
        }
    }

    struct ScriptedContext {
        script: Arc<ScriptState>,
        current: Option<(u64, [u64; 6])>,
        tp: VirtAddr,
    }

    // SAFETY: ScriptedContext never enters hardware user mode.
    unsafe impl UserContext for ScriptedContext {
        type Space = ScriptedSpace;

        fn register(&self, register: RegisterId) -> Result<u64, NativeError> {
            let (num, args) = self.current.unwrap_or((231, [0; 6]));
            match register {
                RegisterId::X86Gpr(0) => Ok(num),
                RegisterId::X86Gpr(7) => Ok(args[0]),
                RegisterId::X86Gpr(6) => Ok(args[1]),
                RegisterId::X86Gpr(2) => Ok(args[2]),
                RegisterId::X86Gpr(10) => Ok(args[3]),
                RegisterId::X86Gpr(8) => Ok(args[4]),
                RegisterId::X86Gpr(9) => Ok(args[5]),
                RegisterId::X86Gpr(_) => Ok(0),
                _ => Err(NativeError::Register),
            }
        }

        fn set_register(&mut self, register: RegisterId, value: u64) -> Result<(), NativeError> {
            if matches!(register, RegisterId::X86Gpr(0)) {
                self.script.results.lock().push(value as i64);
                Ok(())
            } else {
                Err(NativeError::Register)
            }
        }

        fn thread_pointer(&self) -> VirtAddr {
            self.tp
        }

        fn set_thread_pointer(&mut self, address: VirtAddr) -> Result<(), NativeError> {
            self.tp = address;
            Ok(())
        }

        fn try_clone(&self) -> Result<Self, NativeError> {
            Ok(Self {
                script: self.script.clone(),
                current: self.current,
                tp: self.tp,
            })
        }

        fn resume(&mut self, _: &ScriptedSpace) -> Stop {
            let index = self.script.cursor.fetch_add(1, AtomicOrdering::Relaxed);
            match self.script.steps.get(index).copied() {
                Some(ScriptStep::Syscall { num, args }) => {
                    self.current = Some((num, args));
                    Stop::SystemCall
                }
                Some(ScriptStep::Preempt) => Stop::Preempted,
                None => {
                    self.current = Some((231, [0; 6]));
                    Stop::SystemCall
                }
            }
        }
    }

    impl NativeExecution for ScriptedLinuxCpu {
        type Space = ScriptedSpace;
        type Context = ScriptedContext;

        fn instruction_set(&self) -> InstructionSet {
            InstructionSet::X86_64
        }
        fn user_range(&self) -> VirtRange {
            VirtRange::new(
                VirtAddr::new(PhysFrame::SIZE),
                (1usize << 47) - 2 * PhysFrame::SIZE,
            )
        }
        fn create_space(&self) -> Result<Self::Space, NativeError> {
            Ok(ScriptedSpace {
                memory: self.script.clone(),
            })
        }
        fn create_context(&self, _: VirtAddr, _: VirtAddr) -> Result<Self::Context, NativeError> {
            Ok(ScriptedContext {
                script: self.script.clone(),
                current: None,
                tp: VirtAddr::new(PhysFrame::SIZE),
            })
        }
    }

    impl Cpu for ScriptedLinuxCpu {
        type Hypervisor = core::convert::Infallible;
        type Native = Self;
        const TIMER_INTERRUPT: TimerInterrupt = TimerInterrupt::Deadline;

        fn native(&self) -> Result<&Self::Native, NativeUnavailable> {
            Ok(self)
        }
        fn has_lazy_commit_virtual_memory(&self) -> bool {
            true
        }
        fn processor_count(&self) -> usize {
            1
        }
        fn bootstrap_processor(&self) -> ProcessorId {
            ProcessorId::new(0)
        }
        fn park_current(&self) {}
        type WakeOnlyMask = ();
        fn mask_to_wake_only(&self) {
            unreachable!()
        }
        fn park_wake_only(&self, _: &core::sync::atomic::AtomicU8, _: u8) {
            unreachable!()
        }
        fn start_processor(&self, _: ProcessorId) {}
        fn wake_processor(&self, _: ProcessorId) {}
        fn stop_current(&self) {
            unreachable!()
        }
        fn restart_processor(&self, _: ProcessorId) {
            unreachable!()
        }
        fn now(&self) -> Instant {
            self.base.now()
        }
        fn timebase(&self) -> Timebase {
            self.base.timebase()
        }
        fn set_deadline(&self, _: Instant) {}
        fn publish_executable(&self, _: *const u8, _: usize) {}
        fn unpublish_executable(&self, _: *const u8, _: usize) {}
        fn native_feature_probe(&self) -> Option<fn(&str) -> Option<bool>> {
            self.base.native_feature_probe()
        }
        fn fill_entropy(&self, buffer: &mut [u8]) -> Result<EntropyQuality, EntropyUnavailable> {
            self.base.fill_entropy(buffer)
        }
        fn shutdown(&self) -> ! {
            unreachable!()
        }
        fn reboot(&self) -> ! {
            unreachable!()
        }
    }

    fn mount_container_memory(
        ns: &crate::Namespace<UnsupportedStorage>,
        point: &str,
        rights: helios_hal::fs::FileSystemRights,
        sharing: crate::MountSharing,
    ) -> crate::vfs::MemoryFs {
        let fs = crate::vfs::MemoryFs::new(ns.table().allocate_device());
        let cap = ProcessAuthority::root().derive_mount_cap(point).unwrap();
        block_on(ns.mount(
            &cap,
            crate::MountedFs::Memory(fs.clone()),
            crate::MountGrant { rights, sharing },
        ))
        .expect("mount test memory fs");
        fs
    }

    async fn create_container_file(fs: &crate::vfs::MemoryFs, path: &str, data: &[u8]) {
        use helios_hal::fs::{FileSystem, FsPath, OpenFlags, WritePosition};
        let path = FsPath::new(path).unwrap();
        let _ = fs.open(path, OpenFlags::CREATE, 0).await.unwrap();
        crate::vfs::write_bytes(fs, path, WritePosition::At(0), data, 0)
            .await
            .unwrap();
    }

    fn build_scripted_linux_future(
        script: Arc<ScriptState>,
        container: Arc<crate::LinuxContainer<UnsupportedStorage>>,
    ) -> core::pin::Pin<Box<dyn core::future::Future<Output = Result<ChildExit, ProgramExecError>>>>
    {
        let cpu = ScriptedLinuxCpu {
            base: TestCpu::with_entropy(0x5a),
            script,
        };
        let runtime_state: HostRuntimeState<
            ScriptedLinuxCpu,
            TestNetworkService,
            UnsupportedStorage,
        > = crate::RuntimeState::new(
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
            .expect("entropy"),
        ));
        let executor = crate::Executor::isolated(
            ProgressCounter::new(),
            crate::test_support::single_node_pool(1),
            ProcessorId::new(0),
        );
        let registry = crate::InstanceRegistry::new();
        let instance = registry.register("container-linux", 0);
        let exec_context = ProgramExecContext {
            cpu: cpu.clone(),
            timer: executor.timer(cpu.clone()),
            spawner: executor.spawner(cpu.clone()),
            runtime_state,
            instance_registry: registry,
            parent_instance_id: None,
            read_serial: |_, _| {},
            write_serial: crate::DebugSerialWriter::of::<test_store::DiscardPort>(),
        };
        let executable =
            LinuxExecutable::load(&cpu, minimal_x86_64_elf()).expect("minimal x86-64 ELF loads");
        let signal_state = WasixSignalState::new();
        let (_stdin_tx_hold, stdin_rx) = crate::byte_channel();
        let (stdout_tx, _stdout_rx) = crate::byte_channel();
        let (stderr_tx, _stderr_rx) = crate::byte_channel();
        let output_mode = OutputMode::Child {
            stdin_rx,
            stdout_tx,
            stderr_tx,
        };
        let timeline = phases::Timeline::begin(&cpu, "container-spawn", "/bin/app");
        let argv = ProgramArgv::launched("app", Vec::new());
        let instance_spawner = executor
            .spawner(cpu.clone())
            .instance_spawner(crate::TaskFunding::Instance, &instance);
        Box::pin(async move {
            let _executor = executor;
            run_linux_process(
                exec_context,
                argv,
                Vec::new(),
                container,
                None,
                None,
                signal_state,
                instance_spawner,
                instance,
                output_mode,
                executable,
                &timeline,
            )
            .await
        })
    }

    #[test]
    fn side_by_side_linux_containers_isolate_pids_uts_mounts_and_authority() {
        use crate::vfs::BOOT_DEVICE;
        use crate::{
            BootFs, ClockAuthorityRights, ContainerConfig, ContainerId, ContainerMountSpec,
            DirectoryAuthorityRights, EmbeddedBootDirectory, EmbeddedBootFs, LinuxContainer,
            MountSharing, SharedOwner,
        };
        use helios_hal::fs::{FileSystemRights, FsError};
        use helios_linux::syscall::{Credentials, UtsField};

        const BOOT_IMAGE: EmbeddedBootFs = EmbeddedBootFs::new(
            &[
                EmbeddedBootDirectory::new("root-a", 0),
                EmbeddedBootDirectory::new("root-b", 0),
                EmbeddedBootDirectory::new("shared", 0),
                EmbeddedBootDirectory::new("host-secret", 0),
            ],
            &[],
        );
        let host_ns = crate::Namespace::<UnsupportedStorage>::new(crate::MountTable::new(
            BootFs::new(BOOT_IMAGE, BOOT_DEVICE),
            4,
        ));
        let rw = FileSystemRights::READ | FileSystemRights::WRITE;
        let rwx = DirectoryAuthorityRights::READ
            | DirectoryAuthorityRights::WRITE
            | DirectoryAuthorityRights::MUTATE_DIRECTORY
            | DirectoryAuthorityRights::EXECUTE;
        let rx = DirectoryAuthorityRights::READ | DirectoryAuthorityRights::EXECUTE;

        let root_a = mount_container_memory(&host_ns, "/root-a", rw, MountSharing::Private);
        let root_b = mount_container_memory(&host_ns, "/root-b", rw, MountSharing::Private);
        let shared = mount_container_memory(&host_ns, "/shared", rw, MountSharing::Shared);
        let host_only = mount_container_memory(&host_ns, "/host-secret", rw, MountSharing::Shared);
        block_on(async {
            create_container_file(&root_a, "only-a", b"\x7fELF-a").await;
            create_container_file(&root_b, "only-b", b"\x7fELF-b").await;
            create_container_file(&shared, "common", b"shared").await;
            create_container_file(&host_only, "secret", b"secret").await;
        });

        // Container A: uid 0 with narrow authority (no SET_WALL_CLOCK).
        let container_a = Arc::new(
            block_on(LinuxContainer::create(
                ContainerId::new(core::num::NonZeroU64::new(1).unwrap()),
                &ProcessAuthority::root(),
                &host_ns,
                ProcessAuthority::empty(),
                ContainerConfig {
                    root: ContainerMountSpec {
                        source_path: String::from("/root-a"),
                        target_path: String::from("/"),
                        rights: rwx,
                        sharing: MountSharing::Private,
                    },
                    mounts: vec![ContainerMountSpec {
                        source_path: String::from("/shared"),
                        target_path: String::from("/shared"),
                        rights: rx,
                        sharing: MountSharing::Shared,
                    }],
                    shared_owner: SharedOwner {
                        uid: 1000,
                        gid: 1000,
                    },
                    credentials: Credentials::root(),
                    hostname: UtsField::from_configured("alpha").unwrap(),
                    domainname: UtsField::from_configured("a.local").unwrap(),
                },
            ))
            .expect("container A creates"),
        );

        // Container B: uid 1000 inside a container that DOES grant SET_WALL_CLOCK.
        let mut clock_authority = ProcessAuthority::empty();
        clock_authority.grant_clock_rights(ClockAuthorityRights::SET_WALL_CLOCK);
        let container_b = Arc::new(
            block_on(LinuxContainer::create(
                ContainerId::new(core::num::NonZeroU64::new(2).unwrap()),
                &ProcessAuthority::root(),
                &host_ns,
                clock_authority,
                ContainerConfig {
                    root: ContainerMountSpec {
                        source_path: String::from("/root-b"),
                        target_path: String::from("/"),
                        rights: rwx,
                        sharing: MountSharing::Private,
                    },
                    mounts: vec![ContainerMountSpec {
                        source_path: String::from("/shared"),
                        target_path: String::from("/shared"),
                        rights: rx,
                        sharing: MountSharing::Shared,
                    }],
                    shared_owner: SharedOwner {
                        uid: 2000,
                        gid: 2000,
                    },
                    credentials: Credentials::for_ids(1000, 1000, Vec::new()),
                    hostname: UtsField::from_configured("beta").unwrap(),
                    domainname: UtsField::from_configured("b.local").unwrap(),
                },
            ))
            .expect("container B creates"),
        );

        // Offsets inside the 8 KiB scratch buffer at SCRATCH_BASE:
        // 0x000: struct new_utsname before rename (390 bytes)
        // 0x200: struct sysinfo (112 bytes; `procs` is u16 at offset 80)
        // 0x300: new hostname bytes
        // 0x400: struct new_utsname after rename (390 bytes)
        // 0x600: struct timespec (16 bytes)
        const UTS_BEFORE: u64 = SCRATCH_BASE as u64;
        const SYSINFO_BUF: u64 = (SCRATCH_BASE + 0x200) as u64;
        const NEW_HOST: u64 = (SCRATCH_BASE + 0x300) as u64;
        const UTS_AFTER: u64 = (SCRATCH_BASE + 0x400) as u64;
        const TS_BUF: u64 = (SCRATCH_BASE + 0x600) as u64;

        // x86-64 Linux syscall numbers:
        // 39 = getpid, 63 = uname, 99 = sysinfo, 170 = sethostname,
        // 227 = clock_settime, 228 = clock_gettime, 231 = exit_group.
        let script_a = ScriptState::new(
            vec![
                ScriptStep::Syscall {
                    num: 39,
                    args: [0; 6],
                },
                // Pause while container B starts its PID 1 too so both live side by side.
                ScriptStep::Preempt,
                ScriptStep::Syscall {
                    num: 99,
                    args: [SYSINFO_BUF, 0, 0, 0, 0, 0],
                },
                ScriptStep::Syscall {
                    num: 63,
                    args: [UTS_BEFORE, 0, 0, 0, 0, 0],
                },
                ScriptStep::Syscall {
                    num: 170,
                    args: [NEW_HOST, 9, 0, 0, 0, 0],
                },
                ScriptStep::Syscall {
                    num: 63,
                    args: [UTS_AFTER, 0, 0, 0, 0, 0],
                },
                ScriptStep::Syscall {
                    num: 228,
                    args: [0, TS_BUF, 0, 0, 0, 0],
                },
                ScriptStep::Syscall {
                    num: 227,
                    args: [0, TS_BUF, 0, 0, 0, 0],
                },
                ScriptStep::Preempt,
                ScriptStep::Syscall {
                    num: 231,
                    args: [0, 0, 0, 0, 0, 0],
                },
            ],
            |mem| mem[0x300..0x309].copy_from_slice(b"alpha-box"),
        );

        let script_b = ScriptState::new(
            vec![
                ScriptStep::Syscall {
                    num: 39,
                    args: [0; 6],
                },
                ScriptStep::Preempt,
                ScriptStep::Syscall {
                    num: 99,
                    args: [SYSINFO_BUF, 0, 0, 0, 0, 0],
                },
                ScriptStep::Syscall {
                    num: 63,
                    args: [UTS_BEFORE, 0, 0, 0, 0, 0],
                },
                ScriptStep::Syscall {
                    num: 170,
                    args: [NEW_HOST, 8, 0, 0, 0, 0],
                },
                ScriptStep::Syscall {
                    num: 63,
                    args: [UTS_AFTER, 0, 0, 0, 0, 0],
                },
                ScriptStep::Syscall {
                    num: 228,
                    args: [0, TS_BUF, 0, 0, 0, 0],
                },
                ScriptStep::Syscall {
                    num: 227,
                    args: [0, TS_BUF, 0, 0, 0, 0],
                },
                ScriptStep::Syscall {
                    num: 231,
                    args: [0, 0, 0, 0, 0, 0],
                },
            ],
            |mem| mem[0x300..0x308].copy_from_slice(b"beta-box"),
        );

        let mut fut_a = build_scripted_linux_future(script_a.clone(), container_a.clone());
        let mut fut_b = build_scripted_linux_future(script_b.clone(), container_b.clone());
        let waker = futures::task::noop_waker_ref();
        let mut cx = Context::from_waker(waker);

        // Poll both once so both containers hold a live PID 1 simultaneously.
        assert!(matches!(fut_a.as_mut().poll(&mut cx), Poll::Pending));
        assert!(matches!(fut_b.as_mut().poll(&mut cx), Poll::Pending));
        assert_eq!(container_a.process_count(), 1);
        assert_eq!(container_b.process_count(), 1);

        // Poll A through sethostname + clock_settime while B is still alive, then finish B and A.
        assert!(matches!(fut_a.as_mut().poll(&mut cx), Poll::Pending));
        let exit_b = match fut_b.as_mut().poll(&mut cx) {
            Poll::Ready(res) => res.expect("container B process exited"),
            Poll::Pending => panic!("container B remained pending"),
        };
        let exit_a = match fut_a.as_mut().poll(&mut cx) {
            Poll::Ready(res) => res.expect("container A process exited"),
            Poll::Pending => panic!("container A remained pending"),
        };
        assert_eq!(exit_a.termination, ChildTermination::Exited(0));
        assert_eq!(exit_b.termination, ChildTermination::Exited(0));
        assert_eq!(container_a.process_count(), 0);
        assert_eq!(container_b.process_count(), 0);

        // Process A (uid 0, narrow authority): PID 1, procs == 1, renamed own UTS,
        // clock_settime refused with -EPERM (-1) despite uid 0.
        assert_eq!(
            *script_a.results.lock(),
            vec![1, 0, 0, 0, 0, 0, -1],
            "container A syscall results"
        );
        assert_eq!(script_a.read_u16_le(0x200 + 80), 1);
        assert_eq!(script_a.read_cstr(65, 65), "alpha");
        assert_eq!(script_a.read_cstr(5 * 65, 65), "a.local");
        assert_eq!(script_a.read_cstr(0x400 + 65, 65), "alpha-box");

        // Process B (uid 1000, SET_WALL_CLOCK container): PID 1, procs == 1,
        // UTS untouched by A's sethostname, sethostname & clock_settime both -EPERM (-1).
        assert_eq!(
            *script_b.results.lock(),
            vec![1, 0, 0, -1, 0, 0, -1],
            "container B syscall results"
        );
        assert_eq!(script_b.read_u16_le(0x200 + 80), 1);
        assert_eq!(script_b.read_cstr(65, 65), "beta");
        assert_eq!(script_b.read_cstr(5 * 65, 65), "b.local");
        assert_eq!(script_b.read_cstr(0x400 + 65, 65), "beta");

        // Cross-container and host-secret isolation on executables & mounts.
        assert!(block_on(container_a.filesystem().read_executable("/only-a")).is_ok());
        assert!(matches!(
            block_on(container_a.filesystem().read_executable("/only-b")),
            Err(FsError::NoEntry)
        ));
        assert!(matches!(
            block_on(
                container_a
                    .filesystem()
                    .read_executable("/host-secret/secret")
            ),
            Err(FsError::NoEntry)
        ));
        assert!(block_on(container_b.filesystem().read_executable("/only-b")).is_ok());
        assert!(matches!(
            block_on(container_b.filesystem().read_executable("/only-a")),
            Err(FsError::NoEntry)
        ));
    }

    #[test]
    fn linux_uid_zero_and_setuid_narrow_container_clock_authority() {
        use crate::vfs::BOOT_DEVICE;
        use crate::{
            BootFs, ClockAuthorityRights, ContainerConfig, ContainerId, ContainerMountSpec,
            DirectoryAuthorityRights, EmbeddedBootDirectory, EmbeddedBootFs, LinuxContainer,
            MountSharing, SharedOwner,
        };
        use helios_hal::fs::FileSystemRights;
        use helios_linux::syscall::{Credentials, UtsField};

        const BOOT_IMAGE: EmbeddedBootFs =
            EmbeddedBootFs::new(&[EmbeddedBootDirectory::new("root", 0)], &[]);
        let host_ns = crate::Namespace::<UnsupportedStorage>::new(crate::MountTable::new(
            BootFs::new(BOOT_IMAGE, BOOT_DEVICE),
            2,
        ));
        let _root = mount_container_memory(
            &host_ns,
            "/root",
            FileSystemRights::READ | FileSystemRights::WRITE,
            MountSharing::Private,
        );
        let mut authority = ProcessAuthority::empty();
        authority.grant_clock_rights(ClockAuthorityRights::SET_WALL_CLOCK);
        let container = Arc::new(
            block_on(LinuxContainer::create(
                ContainerId::new(core::num::NonZeroU64::new(10).unwrap()),
                &ProcessAuthority::root(),
                &host_ns,
                authority,
                ContainerConfig {
                    root: ContainerMountSpec {
                        source_path: String::from("/root"),
                        target_path: String::from("/"),
                        rights: DirectoryAuthorityRights::READ | DirectoryAuthorityRights::EXECUTE,
                        sharing: MountSharing::Private,
                    },
                    mounts: Vec::new(),
                    shared_owner: SharedOwner { uid: 0, gid: 0 },
                    credentials: Credentials::root(),
                    hostname: UtsField::from_configured("clock-box").unwrap(),
                    domainname: UtsField::UNSET,
                },
            ))
            .expect("container creates"),
        );

        const TS_BUF: u64 = (SCRATCH_BASE + 0x100) as u64;
        // 228 = clock_gettime, 227 = clock_settime, 105 = setuid, 102 = getuid, 231 = exit_group.
        let script = ScriptState::new(
            vec![
                ScriptStep::Syscall {
                    num: 228,
                    args: [0, TS_BUF, 0, 0, 0, 0],
                },
                ScriptStep::Syscall {
                    num: 227,
                    args: [0, TS_BUF, 0, 0, 0, 0],
                },
                ScriptStep::Syscall {
                    num: 105,
                    args: [1000, 0, 0, 0, 0, 0],
                },
                ScriptStep::Syscall {
                    num: 102,
                    args: [0; 6],
                },
                ScriptStep::Syscall {
                    num: 227,
                    args: [0, TS_BUF, 0, 0, 0, 0],
                },
                ScriptStep::Syscall {
                    num: 105,
                    args: [0, 0, 0, 0, 0, 0],
                },
                ScriptStep::Syscall {
                    num: 231,
                    args: [0, 0, 0, 0, 0, 0],
                },
            ],
            |_| {},
        );

        let exit = block_on(build_scripted_linux_future(script.clone(), container))
            .expect("process exited");
        assert_eq!(exit.termination, ChildTermination::Exited(0));
        assert_eq!(
            *script.results.lock(),
            vec![0, 0, 0, 1000, -1, -1],
            "uid 0 succeeds within container clock authority, setuid(1000) narrows it to -EPERM"
        );
    }

    fn test_program_service<CpuImpl: Cpu + Clone>(
        cpu: &CpuImpl,
    ) -> UserProgramService<CpuImpl, TestNetworkService, UnsupportedStorage> {
        let runtime = crate::wasmtime_adapter::WasmtimeComponentRuntime::new(cpu.clone());
        let engine = <crate::wasmtime_adapter::WasmtimeComponentRuntime<CpuImpl> as crate::ComponentRuntimeFactory<
            CpuImpl,
            HostRuntimeState<CpuImpl, TestNetworkService, UnsupportedStorage>,
            UnsupportedStorage,
        >>::create_engine(&runtime)
        .expect("create engine");
        let preview1_core_linker =
            preview1_program_linker(engine.raw()).expect("create preview1 linker");
        UserProgramService {
            inner: Arc::new(UserProgramServiceInner {
                runtime,
                engine,
                preview1_core_linker,
                shared_memory_pool: Arc::new(Mutex::new(SharedMemoryPool::new(1 << 20))),
                component_cache: Mutex::new(ComponentCache::new(1 << 20)),
                component_instance_pre_cache: Mutex::new(ComponentCache::new(1 << 20)),
                core_module_cache: Mutex::new(ComponentCache::new(1 << 20)),
                core_module_instance_pre_cache: Arc::new(Mutex::new(ComponentCache::new(1 << 20))),
                compiler_artifact: None,
                cwasm_signing_key: crate::signing_key::CwasmSigningKey::from_seed(
                    &helios_hal::measured_boot::SealedSecret::new(
                        [0x42; helios_hal::measured_boot::SealedSecret::LEN],
                    ),
                ),
                guest_isa: GuestIsa::for_build_target(cpu.native_feature_probe()),
                compiler_plugin: Mutex::new(None),
                compile_slot: SharedMemorySessionSlot::new(),
                code_map: CodeMap::new(),
                clock_cpu: cpu.clone(),
                http_client_pre: spin::Once::new(),
                plugin_read_serial: |_, _| {},
                plugin_write_serial: crate::DebugSerialWriter::of::<test_store::DiscardPort>(),
                next_container_id: core::sync::atomic::AtomicU64::new(1),
                containers: Mutex::new(alloc::collections::BTreeMap::new()),
                retired_containers: Arc::new(Mutex::new(Vec::new())),
                _marker: core::marker::PhantomData,
            }),
        }
    }

    #[test]
    fn program_service_container_lifecycle_exec_spawn_and_retired_private_claim_release() {
        use crate::vfs::BOOT_DEVICE;
        use crate::{
            BootFs, ContainerConfig, ContainerMountSpec, DirectoryAuthorityRights,
            EmbeddedBootDirectory, EmbeddedBootFs, MountSharing, SharedOwner,
        };
        use helios_hal::fs::FileSystemRights;
        use helios_linux::syscall::{Credentials, UtsField};

        const BOOT_IMAGE: EmbeddedBootFs = EmbeddedBootFs::new(
            &[
                EmbeddedBootDirectory::new("box-a", 0),
                EmbeddedBootDirectory::new("box-b", 0),
            ],
            &[],
        );
        let host_ns = crate::Namespace::<UnsupportedStorage>::new(crate::MountTable::new(
            BootFs::new(BOOT_IMAGE, BOOT_DEVICE),
            4,
        ));
        let rw = FileSystemRights::READ | FileSystemRights::WRITE;
        let rwx = DirectoryAuthorityRights::READ
            | DirectoryAuthorityRights::WRITE
            | DirectoryAuthorityRights::MUTATE_DIRECTORY
            | DirectoryAuthorityRights::EXECUTE;
        let box_a = mount_container_memory(&host_ns, "/box-a", rw, MountSharing::Private);
        let box_b = mount_container_memory(&host_ns, "/box-b", rw, MountSharing::Private);
        block_on(async {
            create_container_file(&box_a, "app", &minimal_x86_64_elf()).await;
            create_container_file(&box_b, "other", &minimal_x86_64_elf()).await;
        });

        let script = ScriptState::new(
            vec![
                ScriptStep::Syscall {
                    num: 39,
                    args: [0; 6],
                },
                ScriptStep::Syscall {
                    num: 231,
                    args: [9, 0, 0, 0, 0, 0],
                },
            ],
            |_| {},
        );
        let cpu = ScriptedLinuxCpu {
            base: TestCpu::with_entropy(0x5a),
            script: script.clone(),
        };
        let service = test_program_service(&cpu);

        let config_a = || ContainerConfig {
            root: ContainerMountSpec {
                source_path: String::from("/box-a"),
                target_path: String::from("/"),
                rights: rwx,
                sharing: MountSharing::Private,
            },
            mounts: Vec::new(),
            shared_owner: SharedOwner { uid: 0, gid: 0 },
            credentials: Credentials::root(),
            hostname: UtsField::from_configured("svc-a").unwrap(),
            domainname: UtsField::UNSET,
        };

        let mut handle_a = block_on(service.create_container(
            &ProcessAuthority::root(),
            &host_ns,
            ProcessAuthority::empty(),
            config_a(),
        ))
        .expect("create container A");
        let container_a = service
            .get_container(&handle_a)
            .expect("container A resolves while active");

        // Second container cannot claim the same Private mount while handle_a lives.
        let busy = block_on(service.create_container(
            &ProcessAuthority::root(),
            &host_ns,
            ProcessAuthority::empty(),
            config_a(),
        ));
        assert!(matches!(
            busy,
            Err(ProgramExecError {
                kind: ProgramExecErrorKind::PermissionDenied,
                ..
            })
        ));

        // Build an executor + exec_context to run `spawn_in_container` and `exec_in_container`.
        let runtime_state: HostRuntimeState<
            ScriptedLinuxCpu,
            TestNetworkService,
            UnsupportedStorage,
        > = crate::RuntimeState::new(
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
            .expect("entropy"),
        ));
        let executor = crate::Executor::isolated(
            ProgressCounter::new(),
            crate::test_support::single_node_pool(1),
            ProcessorId::new(0),
        );
        let registry = crate::InstanceRegistry::new();
        let make_context = || ProgramExecContext {
            cpu: cpu.clone(),
            timer: executor.timer(cpu.clone()),
            spawner: executor.spawner(cpu.clone()),
            runtime_state: runtime_state.clone(),
            instance_registry: registry.clone(),
            parent_instance_id: None,
            read_serial: |_, _| {},
            write_serial: crate::DebugSerialWriter::of::<test_store::DiscardPort>(),
        };

        // Attempting to exec a path from `/box-b` inside container A fails with NotFound.
        let missing = block_on(service.exec_in_container(
            make_context(),
            "/other",
            Vec::new(),
            ProgramLaunch::in_container(
                ProgramArgv::launched("other", Vec::new()),
                Vec::new(),
                container_a.clone(),
                None,
            ),
        ));
        assert!(matches!(
            missing,
            Err(ProgramExecError {
                kind: ProgramExecErrorKind::NotFound,
                ..
            })
        ));

        let timer = executor.timer(cpu.clone());
        // `spawn_in_container` loads `/app` strictly from container A's root and runs it as PID 1.
        let spawned = block_on(service.spawn_in_container(
            make_context(),
            "/app",
            ProgramLaunch::in_container(
                ProgramArgv::launched("app", Vec::new()),
                Vec::new(),
                container_a.clone(),
                None,
            ),
        ))
        .expect("spawn_in_container succeeds");
        executor.run_until_stalled_with_stats(&timer);
        let exit = block_on(spawned.wait()).expect("spawned child exits");
        assert_eq!(exit.termination, ChildTermination::Exited(9));
        assert_eq!(*script.results.lock(), vec![1]);

        // Reset script for `exec_in_container` too.
        script.cursor.store(0, AtomicOrdering::Relaxed);
        script.results.lock().clear();
        let exec_fut = core::pin::pin!(service.exec_in_container(
            make_context(),
            "/app",
            Vec::new(),
            ProgramLaunch::in_container(
                ProgramArgv::launched("app", Vec::new()),
                Vec::new(),
                container_a.clone(),
                None,
            ),
        ));
        drop(container_a);
        // Drive executor alongside `exec_in_container` until it resolves.
        let mut exec_fut = exec_fut;
        let waker = futures::task::noop_waker_ref();
        let mut cx = Context::from_waker(waker);
        let exec_result = loop {
            if let Poll::Ready(res) = exec_fut.as_mut().poll(&mut cx) {
                break res.expect("exec_in_container succeeds");
            }
            let stats = executor.run_until_stalled_with_stats(&timer);
            assert!(
                stats.runnable_count() > 0,
                "executor must make progress for exec_in_container"
            );
        };
        assert_eq!(exec_result.exit_code, 9);
        // Second process launched inside the same container gets PID 2.
        assert_eq!(*script.results.lock(), vec![2]);

        // Explicit `remove_container` removes container A and releases its private claim.
        service.remove_container(&mut handle_a);
        assert!(service.get_container(&handle_a).is_err());

        // Create a second handle and drop it WITHOUT `remove_container` (simulating store
        // teardown) — `retired_containers` draining on the next `create_container` must
        // release the private mount claim so a third container can claim `/box-a`.
        let handle_dropped = block_on(service.create_container(
            &ProcessAuthority::root(),
            &host_ns,
            ProcessAuthority::empty(),
            config_a(),
        ))
        .expect("reclaim container A after remove_container");
        drop(handle_dropped);

        let mut handle_reclaimed = block_on(service.create_container(
            &ProcessAuthority::root(),
            &host_ns,
            ProcessAuthority::empty(),
            config_a(),
        ))
        .expect("reclaim container A after implicit ContainerHandle drop drains retired queue");
        service.remove_container(&mut handle_reclaimed);
    }

    #[test]
    fn wit_program_container_bindings_validate_config_credentials_and_authority() {
        use super::super::program_bindings::helios::system::programs as wit;
        use super::super::program_bindings::helios::system::programs::{
            HostContainerWithStore, HostWithStore,
        };
        use helios_hal::fs::FileSystemRights;
        use helios_linux::syscall::NGROUPS_MAX;

        let engine = component_test_engine();
        let cpu = TestCpu::with_entropy(0x5a);
        let service = test_program_service(&cpu);

        let make_root_mount = || wit::ContainerMount {
            source_path: String::from("/"),
            target_path: String::from("/"),
            rights: vec![wit::FilesystemRight::Read, wit::FilesystemRight::Execute],
            sharing: wit::ContainerMountSharing::Shared,
        };
        let make_valid_config = || wit::ContainerConfig {
            root: make_root_mount(),
            mounts: Vec::new(),
            shared_owner: wit::ContainerIdentity { uid: 0, gid: 0 },
            credentials: wit::ContainerCredentials {
                uid: 0,
                gid: 0,
                supplementary_groups: Vec::new(),
            },
            hostname: String::from("wit-box"),
            domainname: String::from("local"),
            capability_grants: Vec::new(),
        };

        // 1. Caller without SPAWN or EXEC authority is refused with PermissionDenied.
        let mut store = wasmtime::Store::new(
            &engine,
            test_store::store_data_authorized(ProcessAuthority::empty(), |_| {}),
        );
        store
            .data()
            .runtime_state
            .install_program_service(service.clone());
        let no_auth = block_on(store.run_concurrent(async |accessor| {
            <HasSelf<test_store::TestStoreData> as HostWithStore<_>>::create_container(
                accessor,
                make_valid_config(),
            )
            .await
        }))
        .expect("concurrent")
        .expect("host call");
        assert!(matches!(
            no_auth,
            Err(wit::SpawnError {
                kind: wit::SpawnErrorKind::PermissionDenied,
                ..
            })
        ));

        // 2. Authorized caller with a Private mount in its namespace.
        let mut store = wasmtime::Store::new(
            &engine,
            test_store::store_data_authorized(ProcessAuthority::root(), |_| {}),
        );
        store
            .data()
            .runtime_state
            .install_program_service(service.clone());
        {
            use helios_hal::fs::{FileSystem, FsPath};
            let ns = store.data().filesystem().clone();
            let root = ns.resolve("/").expect("root resolves");
            block_on(
                root.fs()
                    .create_directory(FsPath::new("priv-root").unwrap(), 0),
            )
            .expect("mkdir /priv-root");
            let priv_fs = crate::vfs::MemoryFs::new(ns.table().allocate_device());
            let cap = ProcessAuthority::root()
                .derive_mount_cap("/priv-root")
                .unwrap();
            block_on(ns.mount(
                &cap,
                crate::MountedFs::Memory(priv_fs),
                crate::MountGrant {
                    rights: FileSystemRights::READ | FileSystemRights::WRITE,
                    sharing: crate::MountSharing::Private,
                },
            ))
            .expect("mount /priv-root");
        }

        // 2a. CapabilityGrant::Directory in container-config.capability-grants is refused.
        let mut with_dir_grant = make_valid_config();
        with_dir_grant
            .capability_grants
            .push(wit::CapabilityGrant::Directory(wit::DirectoryGrant {
                source_path: String::from("/"),
                guest_name: String::from("/"),
                rights: vec![wit::FilesystemRight::Read],
            }));
        let dir_refused = block_on(store.run_concurrent(async |accessor| {
            <HasSelf<test_store::TestStoreData> as HostWithStore<_>>::create_container(
                accessor,
                with_dir_grant,
            )
            .await
        }))
        .expect("concurrent")
        .expect("host call");
        assert!(matches!(
            dir_refused,
            Err(wit::SpawnError {
                kind: wit::SpawnErrorKind::PermissionDenied,
                ..
            })
        ));

        // 2b. Invalid credentials (u32::MAX uid/gid/group and > NGROUPS_MAX groups) are refused.
        for bad_creds in [
            wit::ContainerCredentials {
                uid: u32::MAX,
                gid: 0,
                supplementary_groups: Vec::new(),
            },
            wit::ContainerCredentials {
                uid: 0,
                gid: u32::MAX,
                supplementary_groups: Vec::new(),
            },
            wit::ContainerCredentials {
                uid: 1000,
                gid: 1000,
                supplementary_groups: vec![u32::MAX],
            },
            wit::ContainerCredentials {
                uid: 1000,
                gid: 1000,
                supplementary_groups: vec![1; NGROUPS_MAX + 1],
            },
        ] {
            let mut bad_cfg = make_valid_config();
            bad_cfg.credentials = bad_creds;
            let refused = block_on(store.run_concurrent(async |accessor| {
                <HasSelf<test_store::TestStoreData> as HostWithStore<_>>::create_container(
                    accessor, bad_cfg,
                )
                .await
            }))
            .expect("concurrent")
            .expect("host call");
            assert!(matches!(
                refused,
                Err(wit::SpawnError {
                    kind: wit::SpawnErrorKind::InvalidPath,
                    ..
                })
            ));
        }

        // 2c. Invalid UTS hostname (> 64 bytes) is refused.
        let mut bad_uts = make_valid_config();
        bad_uts.hostname = "a".repeat(65);
        let uts_refused = block_on(store.run_concurrent(async |accessor| {
            <HasSelf<test_store::TestStoreData> as HostWithStore<_>>::create_container(
                accessor, bad_uts,
            )
            .await
        }))
        .expect("concurrent")
        .expect("host call");
        assert!(matches!(
            uts_refused,
            Err(wit::SpawnError {
                kind: wit::SpawnErrorKind::InvalidPath,
                ..
            })
        ));

        // 2d. Valid private container creates; invalid per-launch credentials in spawn/exec
        // are refused; private mount contention is enforced and released on `HostContainerWithStore::drop`.
        let make_priv_config = || wit::ContainerConfig {
            root: wit::ContainerMount {
                source_path: String::from("/priv-root"),
                target_path: String::from("/"),
                rights: vec![wit::FilesystemRight::Read, wit::FilesystemRight::Execute],
                sharing: wit::ContainerMountSharing::Private,
            },
            ..make_valid_config()
        };
        let container_res = block_on(store.run_concurrent(async |accessor| {
            <HasSelf<test_store::TestStoreData> as HostWithStore<_>>::create_container(
                accessor,
                make_priv_config(),
            )
            .await
        }))
        .expect("concurrent")
        .expect("host call")
        .expect("private container creates");

        let rep = container_res.rep();
        let bad_spawn = block_on(store.run_concurrent(async |accessor| {
            <HasSelf<test_store::TestStoreData> as HostContainerWithStore<_>>::spawn(
                accessor,
                wasmtime::component::Resource::new_borrow(rep),
                wit::ContainerSpawnRequest {
                    name: String::from("app"),
                    args: Vec::new(),
                    env: Vec::new(),
                    path: String::from("/app"),
                    credentials: Some(wit::ContainerCredentials {
                        uid: u32::MAX,
                        gid: 0,
                        supplementary_groups: Vec::new(),
                    }),
                },
            )
            .await
        }))
        .expect("concurrent")
        .expect("host call");
        assert!(matches!(
            bad_spawn,
            Err(wit::SpawnError {
                kind: wit::SpawnErrorKind::InvalidPath,
                ..
            })
        ));

        let bad_exec = block_on(store.run_concurrent(async |accessor| {
            <HasSelf<test_store::TestStoreData> as HostContainerWithStore<_>>::exec(
                accessor,
                wasmtime::component::Resource::new_borrow(rep),
                wit::ContainerExecRequest {
                    name: String::from("app"),
                    args: Vec::new(),
                    env: Vec::new(),
                    path: String::from("/app"),
                    stdin: Vec::new(),
                    credentials: Some(wit::ContainerCredentials {
                        uid: 0,
                        gid: u32::MAX,
                        supplementary_groups: Vec::new(),
                    }),
                },
            )
            .await
        }))
        .expect("concurrent")
        .expect("host call");
        assert!(matches!(
            bad_exec,
            Err(wit::ExecError {
                kind: wit::ExecErrorKind::InvalidPath,
                ..
            })
        ));

        let second_busy = block_on(store.run_concurrent(async |accessor| {
            <HasSelf<test_store::TestStoreData> as HostWithStore<_>>::create_container(
                accessor,
                make_priv_config(),
            )
            .await
        }))
        .expect("concurrent")
        .expect("host call");
        assert!(matches!(
            second_busy,
            Err(wit::SpawnError {
                kind: wit::SpawnErrorKind::PermissionDenied,
                ..
            })
        ));

        // Dropping the WIT container resource releases the private mount claim at once.
        block_on(store.run_concurrent(async |accessor| {
            accessor.with(|access| {
                <HasSelf<test_store::TestStoreData> as HostContainerWithStore<_>>::drop(
                    access,
                    container_res,
                )
            })
        }))
        .expect("concurrent")
        .expect("drop succeeds");

        let reclaimed = block_on(store.run_concurrent(async |accessor| {
            <HasSelf<test_store::TestStoreData> as HostWithStore<_>>::create_container(
                accessor,
                make_priv_config(),
            )
            .await
        }))
        .expect("concurrent")
        .expect("host call");
        assert!(reclaimed.is_ok());
    }
}
