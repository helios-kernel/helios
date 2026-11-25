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

#[test]
fn buffered_exec_kills_an_endless_writer_at_the_configured_output_limit() {
    let data = test_store::store_data_authorized(ProcessAuthority::empty(), |_| {});
    let child_instance = data.instance_registry.register("endless-writer", 1);
    let child_id = child_instance.id();

    let (stdin_tx, _stdin_rx) = crate::byte_channel();
    let (stdout_tx, stdout_rx) = crate::byte_channel();
    let (stderr_tx, stderr_rx) = crate::byte_channel();
    let (exit_tx, exit_rx) = futures::channel::oneshot::channel();
    let child = ChildHandle {
        instance_id: child_id,
        signal_state: WasixSignalState::new(),
        stdin: Some(stdin_tx),
        stdout: Some(stdout_rx),
        stderr: Some(stderr_rx),
        exit: Some(exit_rx),
    };

    let limit = 4096_usize;
    let outcome = block_on(async {
        let producer = async {
            let chunk = alloc::vec![b'x'; 1024];
            let mut sent = 0usize;
            // Write endlessly until the kernel closes stdout or condemns the child.
            while child_instance.pending_kill().is_none()
                && stdout_tx.write(chunk.clone()).await.is_ok()
            {
                sent += chunk.len();
                crate::yield_now().await;
            }
            drop(stdout_tx);
            drop(stderr_tx);
            let _ = exit_tx.send(Ok(ChildExit {
                instance_id: child_id,
                termination: ChildTermination::Killed,
                filesystem: None,
            }));
            sent
        };
        let drain = drain_child_output_bounded(
            child,
            limit,
            &data.runtime_state,
            &data.instance_registry,
            &data.cpu,
        );
        futures::future::join(producer, drain).await
    });

    assert_eq!(
        outcome.1.err(),
        Some(ProgramExecError {
            kind: ProgramExecErrorKind::OutOfMemory,
            detail: ProgramExecErrorDetail::OutputLimitExceeded,
        })
    );
    assert_eq!(
        child_instance.pending_kill(),
        Some(crate::KillReason::OutOfMemory),
        "the endless writer is condemned when buffered output exceeds the limit"
    );
    assert!(
        outcome.0 <= limit + 2 * 1024,
        "output stopped promptly at the configured bound, sent={}",
        outcome.0
    );
}

#[test]
fn child_wait_reports_each_of_the_four_endings_distinctly() {
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
            DescriptorOrigin::Fresh,
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
            // SAFETY: `self.memory.data()[offset + i]` is bounds-checked and owned exclusively by
            // the test harness between calls with no concurrent guest access.
            unsafe {
                self.memory.data()[offset + i].get().write(b);
            }
        }
    }

    fn read_guest(&self, offset: usize, len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| {
                // SAFETY: `self.memory.data()[offset + i]` is bounds-checked and owned exclusively
                // by the test harness between calls with no concurrent guest access.
                unsafe { self.memory.data()[offset + i].get().read() }
            })
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
        let payer = crate::StoragePayer::for_test();
        let created = wasi_fs::open_at(
            &ns,
            root_dir.grant().expect("root directory grant"),
            fs_types::PathFlags::empty(),
            "prog.wasm",
            fs_types::OpenFlags::CREATE,
            FsDescriptorFlags::READ | FsDescriptorFlags::WRITE,
            1,
            &payer,
        )
        .await
        .expect("creates /prog.wasm");
        wasi_fs::write(
            &ns,
            created.grant().expect("file write grant"),
            helios_hal::fs::WritePosition::At(0),
            b"\0asm\x01\0\0\0",
            1,
            &payer,
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
        ExtendedState, FaultKind, InstructionSet, Mapping, NativeError, NativeExecution,
        NativeUnavailable, Stop, UserContext, UserFault, UserSpace,
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
        fn populate(&self, _: VirtAddr, _: &[u8]) -> Result<(), NativeError> {
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
        fn clone_cow(&self) -> Result<Self, NativeError> {
            Ok(MockSpace)
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

        fn extended_state(&self) -> ExtendedState {
            ExtendedState::X86Xsave(alloc::vec![0; 576])
        }

        fn set_extended_state(&mut self, state: &ExtendedState) -> Result<(), NativeError> {
            match state {
                ExtendedState::X86Xsave(_) => Ok(()),
                _ => Err(NativeError::Register),
            }
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
            LinuxExecRuntime {
                exec_context,
                wasm: None,
            },
            argv,
            Vec::new(),
            container,
            None,
            None,
            crate::InheritedSockets::new(),
            DescriptorOrigin::Fresh,
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
        fn populate(&self, addr: VirtAddr, input: &[u8]) -> Result<(), NativeError> {
            self.write(addr, input)
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
        fn clone_cow(&self) -> Result<Self, NativeError> {
            Ok(ScriptedSpace {
                memory: self.memory.clone(),
            })
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

        fn extended_state(&self) -> ExtendedState {
            ExtendedState::X86Xsave(alloc::vec![0; 576])
        }

        fn set_extended_state(&mut self, state: &ExtendedState) -> Result<(), NativeError> {
            match state {
                ExtendedState::X86Xsave(_) => Ok(()),
                _ => Err(NativeError::Register),
            }
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
        let payer = crate::StoragePayer::for_test();
        let _ = fs.open(path, OpenFlags::CREATE, 0, &payer).await.unwrap();
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
                LinuxExecRuntime {
                    exec_context,
                    wasm: None,
                },
                argv,
                Vec::new(),
                container,
                None,
                None,
                crate::InheritedSockets::new(),
                DescriptorOrigin::Fresh,
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
                        sharing: crate::ContainerMountSharing::Private,
                    },
                    mounts: vec![ContainerMountSpec {
                        source_path: String::from("/shared"),
                        target_path: String::from("/shared"),
                        rights: rx,
                        sharing: crate::ContainerMountSharing::Shared,
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
                        sharing: crate::ContainerMountSharing::Private,
                    },
                    mounts: vec![ContainerMountSpec {
                        source_path: String::from("/shared"),
                        target_path: String::from("/shared"),
                        rights: rx,
                        sharing: crate::ContainerMountSharing::Shared,
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
                        sharing: crate::ContainerMountSharing::Private,
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
                next_provider_generation: core::sync::atomic::AtomicU64::new(1),
                surface_provider: Mutex::new(None),
                http_provider: Mutex::new(None),
                compiler_registration: Mutex::new(None),
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
                sharing: crate::ContainerMountSharing::Private,
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
            let payer = crate::StoragePayer::for_test();
            block_on(
                root.fs()
                    .create_directory(FsPath::new("priv-root").unwrap(), 0, &payer),
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
                    cwd: None,
                    sockets: Vec::new(),
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
                    cwd: None,
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

    #[test]
    fn execve_on_private_btrfs_enforces_may_exec_setid_file_caps_nosuid_nnp_and_authority_ceiling()
    {
        use alloc::collections::{BTreeMap, VecDeque};
        use core::sync::atomic::AtomicUsize;
        use ferrosys::btrfs::{FormatOptions, format_to};
        use ferrosys::{Metadata as BtrfsMeta, Timestamp as BtrfsTimestamp, TreeBuilder};
        use helios_btrfs::write::Attributes as BtrfsAttributes;
        use helios_hal::fs::{
            DeviceId, FileSystemRights, FsPath, OpenFlags, WritePosition, write_with,
        };
        use helios_linux::syscall::{
            CAP_NET_ADMIN, CAP_NET_BIND_SERVICE, CAP_NET_RAW, CAP_SYS_TIME, Credentials, UtsField,
        };
        use std::io::{Read, Seek, SeekFrom};

        use crate::io::{MemoryDisk, cache_over};
        use crate::test_support::{UnsupportedHostFileSystem, test_timer};
        use crate::vfs::{
            BOOT_DEVICE, BtrfsFs, BtrfsWriteOptions, CommitPolicy, MemoryFs, MountGrant,
            MountSharing, MountTable, MountedFs, Namespace, SharedOwner, Storage, XattrSetMode,
        };
        use crate::{
            BootFs, ContainerConfig, ContainerId, ContainerMountSpec, DirectoryAuthorityRights,
            EmbeddedBootDirectory, EmbeddedBootFs, LinuxContainer, NetworkAuthorityRights,
            ProcessAuthority,
        };

        const FORMATTED_BYTES: usize = 128 << 20;
        const BTRFS_EXEC_BOOT: EmbeddedBootFs = EmbeddedBootFs::new(
            &[
                EmbeddedBootDirectory::new("priv", 0),
                EmbeddedBootDirectory::new("shared", 0),
            ],
            &[],
        );
        const RWX: DirectoryAuthorityRights = DirectoryAuthorityRights::READ
            .union(DirectoryAuthorityRights::WRITE)
            .union(DirectoryAuthorityRights::MUTATE_DIRECTORY)
            .union(DirectoryAuthorityRights::EXECUTE);

        #[derive(Clone, Copy)]
        struct BtrfsExecStorage;
        impl Storage for BtrfsExecStorage {
            type HostShare = UnsupportedHostFileSystem;
            type Disk = MemoryDisk;
        }

        // Real mapped-byte user address space for scripted `run_linux_process` execution.
        #[derive(Default)]
        struct MapSpace {
            bytes: spin::Mutex<BTreeMap<usize, u8>>,
        }

        impl MapSpace {
            fn write_bytes(&self, addr: usize, data: &[u8]) {
                let mut map = self.bytes.lock();
                for (i, &b) in data.iter().enumerate() {
                    map.insert(addr + i, b);
                }
            }
            fn read_u64(&self, addr: usize) -> u64 {
                let map = self.bytes.lock();
                let mut buf = [0u8; 8];
                for (i, slot) in buf.iter_mut().enumerate() {
                    *slot = map.get(&(addr + i)).copied().unwrap_or(0);
                }
                u64::from_le_bytes(buf)
            }
            fn read_u32(&self, addr: usize) -> u32 {
                let map = self.bytes.lock();
                let mut buf = [0u8; 4];
                for (i, slot) in buf.iter_mut().enumerate() {
                    *slot = map.get(&(addr + i)).copied().unwrap_or(0);
                }
                u32::from_le_bytes(buf)
            }
        }

        // SAFETY: MapSpace is an in-memory test double that never maps hardware page tables.
        unsafe impl UserSpace for MapSpace {
            fn map(
                &self,
                range: VirtRange,
                initial: &[u8],
                _: PageFlags,
            ) -> Result<(), NativeError> {
                let start = range.start.raw();
                let mut map = self.bytes.lock();
                for i in 0..range.byte_len {
                    map.insert(start + i, initial.get(i).copied().unwrap_or(0));
                }
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
            fn check_writable(&self, _: VirtAddr, _: usize) -> Result<(), NativeError> {
                Ok(())
            }
            fn remap(&self, _: VirtRange, _: VirtRange) -> Result<(), NativeError> {
                Ok(())
            }
            fn unmap(&self, _: VirtRange) -> Result<(), NativeError> {
                Ok(())
            }
            fn protect(&self, _: VirtRange, _: PageFlags) -> Result<(), NativeError> {
                Ok(())
            }
            fn read(&self, address: VirtAddr, out: &mut [u8]) -> Result<(), NativeError> {
                let map = self.bytes.lock();
                let base = address.raw();
                for (i, slot) in out.iter_mut().enumerate() {
                    *slot = map.get(&(base + i)).copied().unwrap_or(0);
                }
                Ok(())
            }
            fn write(&self, address: VirtAddr, bytes: &[u8]) -> Result<(), NativeError> {
                self.write_bytes(address.raw(), bytes);
                Ok(())
            }
            fn populate(&self, address: VirtAddr, bytes: &[u8]) -> Result<(), NativeError> {
                self.write_bytes(address.raw(), bytes);
                Ok(())
            }
            fn resolve_fault(&self, _: VirtAddr, _: PageFlags) -> Result<(), NativeError> {
                Ok(())
            }
            fn discard(&self, _: VirtRange) -> Result<(), NativeError> {
                Ok(())
            }
            fn atomic_load_u32(&self, address: VirtAddr) -> Result<u32, NativeError> {
                Ok(self.read_u32(address.raw()))
            }
            fn atomic_store_u32(&self, address: VirtAddr, value: u32) -> Result<(), NativeError> {
                self.write_bytes(address.raw(), &value.to_le_bytes());
                Ok(())
            }
            fn atomic_compare_exchange_u32(
                &self,
                address: VirtAddr,
                expected: u32,
                new: u32,
            ) -> Result<Result<u32, u32>, NativeError> {
                let cur = self.read_u32(address.raw());
                if cur == expected {
                    self.write_bytes(address.raw(), &new.to_le_bytes());
                    Ok(Ok(cur))
                } else {
                    Ok(Err(cur))
                }
            }
            fn mapping(&self, _: VirtRange) -> Option<Mapping> {
                None
            }
            fn free_range(&self, hint: VirtAddr, _: usize) -> Option<VirtAddr> {
                Some(hint)
            }
            fn clone_cow(&self) -> Result<Self, NativeError> {
                Ok(Self {
                    bytes: spin::Mutex::new(self.bytes.lock().clone()),
                })
            }
        }

        struct ScriptStep {
            writes: Vec<(usize, Vec<u8>)>,
            regs: [u64; 7], // [rax, rdi, rsi, rdx, r10, r8, r9]
            capture_cap_buf: Option<usize>,
        }

        #[derive(Default)]
        struct ScriptState {
            steps: VecDeque<ScriptStep>,
            results: Vec<u64>,
            captured_caps: Vec<(u64, u64)>, // (effective, permitted)
            auxv: Vec<BTreeMap<u64, u64>>,
            pending_cap_buf: Option<usize>,
        }

        #[derive(Clone)]
        struct ScriptCpu {
            base: TestCpu,
            state: Arc<spin::Mutex<ScriptState>>,
        }

        struct ScriptContext {
            state: Arc<spin::Mutex<ScriptState>>,
            regs: [u64; 7],
            sp: u64,
            tp: VirtAddr,
            started: AtomicUsize,
        }

        // SAFETY: ScriptContext never enters hardware user mode.
        unsafe impl UserContext for ScriptContext {
            type Space = MapSpace;

            fn register(&self, register: RegisterId) -> Result<u64, NativeError> {
                match register {
                    RegisterId::X86Gpr(0) => Ok(self.regs[0]),
                    RegisterId::X86Gpr(7) => Ok(self.regs[1]),
                    RegisterId::X86Gpr(6) => Ok(self.regs[2]),
                    RegisterId::X86Gpr(2) => Ok(self.regs[3]),
                    RegisterId::X86Gpr(10) => Ok(self.regs[4]),
                    RegisterId::X86Gpr(8) => Ok(self.regs[5]),
                    RegisterId::X86Gpr(9) => Ok(self.regs[6]),
                    RegisterId::X86Gpr(4) => Ok(self.sp),
                    RegisterId::X86Gpr(_) => Ok(0),
                    _ => Err(NativeError::Register),
                }
            }
            fn set_register(
                &mut self,
                register: RegisterId,
                value: u64,
            ) -> Result<(), NativeError> {
                if matches!(register, RegisterId::X86Gpr(0)) {
                    self.regs[0] = value;
                    self.state.lock().results.push(value);
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
            fn extended_state(&self) -> ExtendedState {
                ExtendedState::X86Xsave(alloc::vec![0; 576])
            }
            fn set_extended_state(&mut self, _: &ExtendedState) -> Result<(), NativeError> {
                Ok(())
            }
            fn try_clone(&self) -> Result<Self, NativeError> {
                Ok(Self {
                    state: self.state.clone(),
                    regs: self.regs,
                    sp: self.sp,
                    tp: self.tp,
                    started: AtomicUsize::new(0),
                })
            }
            fn resume(&mut self, space: &MapSpace) -> Stop {
                let pending_cap_buf = self.state.lock().pending_cap_buf.take();
                if let Some(addr) = pending_cap_buf {
                    let eff_lo = space.read_u32(addr) as u64;
                    let perm_lo = space.read_u32(addr + 4) as u64;
                    let eff_hi = space.read_u32(addr + 12) as u64;
                    let perm_hi = space.read_u32(addr + 16) as u64;
                    self.state
                        .lock()
                        .captured_caps
                        .push((eff_lo | (eff_hi << 32), perm_lo | (perm_hi << 32)));
                }
                if self.started.fetch_add(1, AtomicOrdering::Relaxed) == 0 {
                    // Parse the initial ELF stack's auxiliary vector on entry.
                    let mut cursor = self.sp as usize;
                    let argc = space.read_u64(cursor) as usize;
                    cursor += 8 + (argc + 1) * 8;
                    while space.read_u64(cursor) != 0 {
                        cursor += 8;
                    }
                    cursor += 8; // skip NULL after envp
                    let mut auxv = BTreeMap::new();
                    loop {
                        let tag = space.read_u64(cursor);
                        let val = space.read_u64(cursor + 8);
                        cursor += 16;
                        if tag == 0 {
                            break;
                        }
                        auxv.insert(tag, val);
                    }
                    self.state.lock().auxv.push(auxv);
                }
                let next = self.state.lock().steps.pop_front();
                match next {
                    Some(step) => {
                        for (addr, data) in &step.writes {
                            space.write_bytes(*addr, data);
                        }
                        self.state.lock().pending_cap_buf = step.capture_cap_buf;
                        self.regs = step.regs;
                        Stop::SystemCall
                    }
                    None => {
                        self.regs = [231, 0, 0, 0, 0, 0, 0]; // exit_group(0)
                        Stop::SystemCall
                    }
                }
            }
        }

        impl NativeExecution for ScriptCpu {
            type Space = MapSpace;
            type Context = ScriptContext;
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
                Ok(MapSpace::default())
            }
            fn create_context(
                &self,
                _: VirtAddr,
                sp: VirtAddr,
            ) -> Result<Self::Context, NativeError> {
                Ok(ScriptContext {
                    state: self.state.clone(),
                    regs: [0; 7],
                    sp: sp.raw() as u64,
                    tp: VirtAddr::new(PhysFrame::SIZE),
                    started: AtomicUsize::new(0),
                })
            }
        }

        impl Cpu for ScriptCpu {
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
            fn fill_entropy(
                &self,
                buffer: &mut [u8],
            ) -> Result<EntropyQuality, EntropyUnavailable> {
                self.base.fill_entropy(buffer)
            }
            fn shutdown(&self) -> ! {
                unreachable!()
            }
            fn reboot(&self) -> ! {
                unreachable!()
            }
        }

        // Format a real writable Btrfs disk image.
        let time = BtrfsTimestamp::from_secs(1_700_000_000);
        let tree = TreeBuilder::new().root(BtrfsMeta::new(0o755, time));
        let mut img = tempfile::tempfile().expect("temp btrfs image");
        img.set_len(FORMATTED_BYTES as u64).expect("set_len");
        format_to(
            &mut img,
            tree,
            FORMATTED_BYTES as u64,
            FormatOptions::new([0x77; 16], time),
        )
        .expect("format btrfs");
        img.seek(SeekFrom::Start(0)).expect("rewind");
        let mut raw_img = Vec::new();
        img.read_to_end(&mut raw_img).expect("read btrfs image");
        let disk = MemoryDisk::holding_writable("btrfs-exec-rw", &raw_img);
        let cache = cache_over(&disk, 256, 1);

        let elf_bytes = minimal_x86_64_elf();
        let now = 1_700_000_000_000_000_000_u64;

        let make_cap_v2 = |effective: bool, permitted: u64| -> Vec<u8> {
            let mut out = vec![0u8; 20];
            let magic = 0x0200_0000_u32 | if effective { 1 } else { 0 };
            out[0..4].copy_from_slice(&magic.to_le_bytes());
            out[4..8].copy_from_slice(&(permitted as u32).to_le_bytes());
            out[12..16].copy_from_slice(&((permitted >> 32) as u32).to_le_bytes());
            out
        };

        let cstr = |s: &str| -> Vec<u8> {
            let mut b = s.as_bytes().to_vec();
            b.push(0);
            b
        };

        // Helper builders for scripted x86-64 syscalls.
        const SYS_EXECVE: u64 = 59;
        const SYS_GETUID: u64 = 102;
        const SYS_GETGID: u64 = 104;
        const SYS_GETEUID: u64 = 107;
        const SYS_GETEGID: u64 = 108;
        const SYS_CAPGET: u64 = 125;
        const SYS_PRCTL: u64 = 157;
        const SYS_EXIT_GROUP: u64 = 231;
        const EACCES_NEG: u64 = 13u64.wrapping_neg();

        let step_execve = |path: &str| -> ScriptStep {
            let path_addr = 0x20_0000_usize;
            let argv_addr = 0x20_0100_usize;
            let envp_addr = 0x20_0200_usize;
            let mut argv_bytes = Vec::with_capacity(16);
            argv_bytes.extend_from_slice(&(path_addr as u64).to_le_bytes());
            argv_bytes.extend_from_slice(&0u64.to_le_bytes());
            ScriptStep {
                writes: vec![
                    (path_addr, cstr(path)),
                    (argv_addr, argv_bytes),
                    (envp_addr, 0u64.to_le_bytes().to_vec()),
                ],
                regs: [
                    SYS_EXECVE,
                    path_addr as u64,
                    argv_addr as u64,
                    envp_addr as u64,
                    0,
                    0,
                    0,
                ],
                capture_cap_buf: None,
            }
        };
        let step_simple = |nr: u64, a0: u64, a1: u64| -> ScriptStep {
            ScriptStep {
                writes: Vec::new(),
                regs: [nr, a0, a1, 0, 0, 0, 0],
                capture_cap_buf: None,
            }
        };
        let step_capget = || -> ScriptStep {
            let hdr_addr = 0x20_0300_usize;
            let data_addr = 0x20_0320_usize;
            let mut hdr = [0u8; 8];
            hdr[0..4].copy_from_slice(&0x2008_0522_u32.to_le_bytes()); // _LINUX_CAPABILITY_VERSION_3
            ScriptStep {
                writes: vec![(hdr_addr, hdr.to_vec()), (data_addr, vec![0u8; 24])],
                regs: [SYS_CAPGET, hdr_addr as u64, data_addr as u64, 0, 0, 0, 0],
                capture_cap_buf: Some(data_addr),
            }
        };

        let timer = test_timer(TestCpu::without_entropy());
        block_on(async {
            let entropy = triomphe::Arc::new(
                crate::RootEntropy::from_platform(
                    &TestCpu::with_entropy(0x42),
                    None,
                    None,
                    crate::MachineGeneration::new(None),
                )
                .expect("entropy"),
            );
            let (btrfs, btrfs_service) = BtrfsFs::mount_writable(
                cache.disk(0),
                || DeviceId::new(220),
                BtrfsWriteOptions {
                    entropy: entropy.clone(),
                    concurrency: core::num::NonZeroUsize::new(2).unwrap(),
                    compress: None,
                    commit: Some(CommitPolicy::for_machine(1 << 30)),
                    max_inline: None,
                    now,
                },
            )
            .await
            .expect("mount writable btrfs");

            let client = async {
                // Populate real binaries & scripts on the private Btrfs mount.
                let write_btrfs_file = |p: &str, mode: u32, uid: u32, gid: u32, data: &[u8]| {
                    let btrfs = &btrfs;
                    let p = String::from(p);
                    let data = data.to_vec();
                    async move {
                        let attrs = BtrfsAttributes {
                            permissions: mode,
                            uid,
                            gid,
                            umask: 0,
                        };
                        let payer = crate::StoragePayer::for_test();
                        btrfs
                            .open_unix(
                                FsPath::new(&p).unwrap(),
                                OpenFlags::CREATE | OpenFlags::EXCLUSIVE,
                                attrs,
                                now,
                            )
                            .await
                            .expect("create btrfs file");
                        write_with(
                            btrfs,
                            FsPath::new(&p).unwrap(),
                            WritePosition::At(0),
                            data.len(),
                            now,
                            &payer,
                            |offset, dst| dst.copy_from_slice(&data[offset..offset + dst.len()]),
                        )
                        .await
                        .expect("write btrfs file");
                    }
                };

                write_btrfs_file("noexec_bin", 0o644, 0, 0, &elf_bytes).await;
                write_btrfs_file("plain_bin", 0o755, 0, 0, &elf_bytes).await;
                write_btrfs_file("suid_bin", 0o4755, 0, 0, &elf_bytes).await;
                write_btrfs_file("exec_only_suid", 0o4111, 0, 0, &elf_bytes).await;
                write_btrfs_file("sgid_bin", 0o2755, 1000, 500, &elf_bytes).await;
                write_btrfs_file("fcap_bin", 0o755, 0, 0, &elf_bytes).await;
                let raw_cap = make_cap_v2(
                    true,
                    (1u64 << CAP_NET_BIND_SERVICE)
                        | (1u64 << CAP_SYS_TIME)
                        | (1u64 << CAP_NET_ADMIN),
                );
                btrfs
                    .set_xattr(
                        FsPath::new("fcap_bin").unwrap(),
                        "security.capability",
                        Bytes::from(raw_cap),
                        XattrSetMode::Any,
                        now,
                    )
                    .await
                    .expect("set security.capability");
                write_btrfs_file("suid_script", 0o4755, 0, 0, b"#!/plain_bin\n").await;
                btrfs
                    .create_directory_unix(
                        FsPath::new("dir_noexec").unwrap(),
                        BtrfsAttributes {
                            permissions: 0o700,
                            uid: 0,
                            gid: 0,
                            umask: 0,
                        },
                        now,
                    )
                    .await
                    .expect("mkdir dir_noexec");
                write_btrfs_file("dir_noexec/hidden_bin", 0o755, 0, 0, &elf_bytes).await;

                // Populate a setuid binary on a shared (NO_SUID) MemoryFs mount.
                let shared_mem = MemoryFs::new(DeviceId::new(221));
                let payer = crate::StoragePayer::for_test();
                shared_mem
                    .open_unix(
                        FsPath::new("suid_bin").unwrap(),
                        OpenFlags::CREATE | OpenFlags::EXCLUSIVE,
                        BtrfsAttributes {
                            permissions: 0o4755,
                            uid: 0,
                            gid: 0,
                            umask: 0,
                        },
                        now,
                        &payer,
                    )
                    .expect("create shared suid_bin");
                write_with(
                    &shared_mem,
                    FsPath::new("suid_bin").unwrap(),
                    WritePosition::At(0),
                    elf_bytes.len(),
                    now,
                    &payer,
                    |offset, dst| dst.copy_from_slice(&elf_bytes[offset..offset + dst.len()]),
                )
                .await
                .expect("write shared suid_bin");

                let host_ns = Namespace::<BtrfsExecStorage>::new(MountTable::new(
                    BootFs::new(BTRFS_EXEC_BOOT, BOOT_DEVICE),
                    8,
                ));
                let root_auth = ProcessAuthority::root();
                let rw = FileSystemRights::READ | FileSystemRights::WRITE;
                host_ns
                    .mount(
                        &root_auth.derive_mount_cap("/priv").unwrap(),
                        MountedFs::Btrfs(btrfs),
                        MountGrant {
                            rights: rw,
                            sharing: MountSharing::Private,
                        },
                    )
                    .await
                    .expect("mount /priv");
                host_ns
                    .mount(
                        &root_auth.derive_mount_cap("/shared").unwrap(),
                        MountedFs::Memory(shared_mem),
                        MountGrant {
                            rights: rw,
                            sharing: MountSharing::Shared,
                        },
                    )
                    .await
                    .expect("mount /shared");

                // Container authority grants PRIVILEGED_BIND (CAP_NET_BIND_SERVICE) and
                // omits SET_WALL_CLOCK (CAP_SYS_TIME) & ADMIN (CAP_NET_ADMIN / CAP_NET_RAW).
                let mut container_auth = ProcessAuthority::empty();
                container_auth.grant_network_rights(NetworkAuthorityRights::PRIVILEGED_BIND);
                let container = Arc::new(
                    LinuxContainer::create(
                        ContainerId::new(NonZeroU64::new(84).unwrap()),
                        &root_auth,
                        &host_ns,
                        container_auth,
                        ContainerConfig {
                            root: ContainerMountSpec {
                                source_path: String::from("/priv"),
                                target_path: String::from("/"),
                                rights: RWX,
                                sharing: crate::ContainerMountSharing::Private,
                            },
                            mounts: vec![ContainerMountSpec {
                                source_path: String::from("/shared"),
                                target_path: String::from("/shared"),
                                rights: RWX,
                                sharing: crate::ContainerMountSharing::Shared,
                            }],
                            shared_owner: SharedOwner { uid: 0, gid: 0 },
                            credentials: Credentials::root(),
                            hostname: UtsField::UNSET,
                            domainname: UtsField::UNSET,
                        },
                    )
                    .await
                    .expect("create container"),
                );

                let run_scenario = |initial_creds: Credentials, steps: Vec<ScriptStep>| {
                    let container = container.clone();
                    let elf_bytes = elf_bytes.clone();
                    let entropy = entropy.clone();
                    Box::pin(async move {
                        let state = Arc::new(spin::Mutex::new(ScriptState {
                            steps: VecDeque::from(steps),
                            ..ScriptState::default()
                        }));
                        let cpu = ScriptCpu {
                            base: TestCpu::with_entropy(0x55),
                            state: state.clone(),
                        };
                        let runtime_state: HostRuntimeState<
                            ScriptCpu,
                            TestNetworkService,
                            BtrfsExecStorage,
                        > = crate::RuntimeState::new(
                            cpu.timebase(),
                            1,
                            0,
                            crate::BootPayload::for_tests(),
                            GuestIsa::for_build_target(cpu.native_feature_probe()),
                        );
                        runtime_state.install_root_entropy(entropy);
                        let executor = crate::Executor::isolated(
                            ProgressCounter::new(),
                            crate::test_support::single_node_pool(1),
                            ProcessorId::new(0),
                        );
                        let registry = crate::InstanceRegistry::new();
                        let instance = registry.register("linux-exec-btrfs", 0);
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
                            LinuxExecutable::load(&cpu, elf_bytes).expect("load minimal ELF");
                        let (_stdin_tx, stdin_rx) = crate::byte_channel();
                        let (stdout_tx, _stdout_rx) = crate::byte_channel();
                        let (stderr_tx, _stderr_rx) = crate::byte_channel();
                        let instance_spawner = executor
                            .spawner(cpu.clone())
                            .instance_spawner(crate::TaskFunding::Instance, &instance);
                        let timeline = phases::Timeline::begin(&cpu, "spawn", "/linux/exec-test");
                        let exit = Box::pin(run_linux_process(
                            LinuxExecRuntime {
                                exec_context,
                                wasm: None,
                            },
                            ProgramArgv::launched("exec-test", Vec::new()),
                            Vec::new(),
                            container,
                            Some(initial_creds),
                            None,
                            crate::InheritedSockets::new(),
                            DescriptorOrigin::Fresh,
                            WasixSignalState::new(),
                            instance_spawner,
                            instance,
                            OutputMode::Child {
                                stdin_rx,
                                stdout_tx,
                                stderr_tx,
                            },
                            executable,
                            &timeline,
                        ))
                        .await
                        .expect("run_linux_process");
                        assert_eq!(exit.termination, ChildTermination::Exited(0));
                        let st = state.lock();
                        (
                            st.results.clone(),
                            st.captured_caps.clone(),
                            st.auxv.clone(),
                        )
                    })
                };

                // 1. Missing MAY_EXEC (0o644) -> EACCES for both u1000 and uid 0 (CAP_DAC_OVERRIDE),
                //    and missing dir search MAY_EXEC (/dir_noexec/hidden_bin) -> EACCES for u1000.
                let (res_noexec_user, _, _) = run_scenario(
                    Credentials::for_ids(1000, 100, vec![]),
                    vec![
                        step_execve("/noexec_bin"),
                        step_execve("/dir_noexec/hidden_bin"),
                        step_simple(SYS_EXIT_GROUP, 0, 0),
                    ],
                )
                .await;
                assert_eq!(res_noexec_user, vec![EACCES_NEG, EACCES_NEG]);

                let (res_noexec_root, _, _) = run_scenario(
                    Credentials::root(),
                    vec![
                        step_execve("/noexec_bin"),
                        step_simple(SYS_EXIT_GROUP, 0, 0),
                    ],
                )
                .await;
                assert_eq!(res_noexec_root, vec![EACCES_NEG]);

                // 2. S_ISUID root (0o4755) on private Btrfs: u1000 -> euid 0, ruid 1000,
                //    AT_SECURE = 1, and live capget() clamped to container ProcessAuthority
                //    (CAP_NET_BIND_SERVICE allowed, CAP_SYS_TIME / CAP_NET_ADMIN / CAP_NET_RAW absent).
                let (res_suid, caps_suid, auxv_suid) = run_scenario(
                    Credentials::for_ids(1000, 100, vec![]),
                    vec![
                        step_execve("/suid_bin"),
                        step_simple(SYS_GETUID, 0, 0),
                        step_simple(SYS_GETEUID, 0, 0),
                        step_simple(SYS_GETGID, 0, 0),
                        step_simple(SYS_GETEGID, 0, 0),
                        step_capget(),
                        step_simple(SYS_EXIT_GROUP, 0, 0),
                    ],
                )
                .await;
                assert_eq!(res_suid, vec![1000, 0, 100, 100, 0]);
                assert_eq!(caps_suid.len(), 1);
                let (suid_eff, suid_perm) = caps_suid[0];
                assert_ne!(suid_eff & (1u64 << CAP_NET_BIND_SERVICE), 0);
                assert_eq!(suid_eff & (1u64 << CAP_SYS_TIME), 0);
                assert_eq!(suid_eff & (1u64 << CAP_NET_ADMIN), 0);
                assert_eq!(suid_eff & (1u64 << CAP_NET_RAW), 0);
                assert_eq!(suid_eff, suid_perm);
                assert_eq!(auxv_suid.len(), 2);
                assert_eq!(auxv_suid[0].get(&23), Some(&0)); // initial AT_SECURE = 0
                assert_eq!(auxv_suid[1].get(&11), Some(&1000)); // AT_UID
                assert_eq!(auxv_suid[1].get(&12), Some(&0)); // AT_EUID
                assert_eq!(auxv_suid[1].get(&13), Some(&100)); // AT_GID
                assert_eq!(auxv_suid[1].get(&14), Some(&100)); // AT_EGID
                assert_eq!(auxv_suid[1].get(&23), Some(&1)); // AT_SECURE = 1

                // 3. Execute-only S_ISUID (0o4111): u1000 can execve even without MAY_READ.
                let (res_exec_only, _, auxv_exec_only) = run_scenario(
                    Credentials::for_ids(1000, 100, vec![]),
                    vec![
                        step_execve("/exec_only_suid"),
                        step_simple(SYS_GETEUID, 0, 0),
                        step_simple(SYS_EXIT_GROUP, 0, 0),
                    ],
                )
                .await;
                assert_eq!(res_exec_only, vec![0]);
                assert_eq!(auxv_exec_only[1].get(&12), Some(&0));
                assert_eq!(auxv_exec_only[1].get(&23), Some(&1));

                // 4. S_ISGID (0o2755, gid 500) on private Btrfs: u1000 -> egid 500, AT_SECURE = 1.
                let (res_sgid, _, auxv_sgid) = run_scenario(
                    Credentials::for_ids(1000, 100, vec![]),
                    vec![
                        step_execve("/sgid_bin"),
                        step_simple(SYS_GETGID, 0, 0),
                        step_simple(SYS_GETEGID, 0, 0),
                        step_simple(SYS_EXIT_GROUP, 0, 0),
                    ],
                )
                .await;
                assert_eq!(res_sgid, vec![100, 500]);
                assert_eq!(auxv_sgid[1].get(&14), Some(&500));
                assert_eq!(auxv_sgid[1].get(&23), Some(&1));

                // 5. File capabilities (`security.capability`) on private Btrfs:
                //    u1000 keeps euid 1000, gets AT_SECURE = 1, and live capget() reports
                //    only CAP_NET_BIND_SERVICE (CAP_SYS_TIME / CAP_NET_ADMIN clamped out).
                let (res_fcap, caps_fcap, auxv_fcap) = run_scenario(
                    Credentials::for_ids(1000, 100, vec![]),
                    vec![
                        step_execve("/fcap_bin"),
                        step_simple(SYS_GETEUID, 0, 0),
                        step_capget(),
                        step_simple(SYS_EXIT_GROUP, 0, 0),
                    ],
                )
                .await;
                assert_eq!(res_fcap, vec![1000, 0]);
                assert_eq!(
                    caps_fcap,
                    vec![(1u64 << CAP_NET_BIND_SERVICE, 1u64 << CAP_NET_BIND_SERVICE)]
                );
                assert_eq!(auxv_fcap[1].get(&12), Some(&1000));
                assert_eq!(auxv_fcap[1].get(&23), Some(&1)); // AT_SECURE = 1 from file caps

                // 6. Setuid `#!` script (/suid_script 0o4755 -> /plain_bin 0o755):
                //    ignores script S_ISUID (fs/binfmt_script.c).
                let (res_script, caps_script, auxv_script) = run_scenario(
                    Credentials::for_ids(1000, 100, vec![]),
                    vec![
                        step_execve("/suid_script"),
                        step_simple(SYS_GETEUID, 0, 0),
                        step_capget(),
                        step_simple(SYS_EXIT_GROUP, 0, 0),
                    ],
                )
                .await;
                assert_eq!(res_script, vec![1000, 0]);
                assert_eq!(caps_script, vec![(0, 0)]);
                assert_eq!(auxv_script[1].get(&12), Some(&1000));
                assert_eq!(auxv_script[1].get(&23), Some(&0));

                // 7. Shared mount (`NO_SUID`) blocks S_ISUID on /shared/suid_bin.
                let (res_nosuid, caps_nosuid, auxv_nosuid) = run_scenario(
                    Credentials::for_ids(1000, 100, vec![]),
                    vec![
                        step_execve("/shared/suid_bin"),
                        step_simple(SYS_GETEUID, 0, 0),
                        step_capget(),
                        step_simple(SYS_EXIT_GROUP, 0, 0),
                    ],
                )
                .await;
                assert_eq!(res_nosuid, vec![1000, 0]);
                assert_eq!(caps_nosuid, vec![(0, 0)]);
                assert_eq!(auxv_nosuid[1].get(&12), Some(&1000));
                assert_eq!(auxv_nosuid[1].get(&23), Some(&0));

                // 8. PR_SET_NO_NEW_PRIVS suppresses both S_ISUID and file capabilities,
                //    and persists across execve (`PR_GET_NO_NEW_PRIVS == 1`).
                let (res_nnp, caps_nnp, auxv_nnp) = run_scenario(
                    Credentials::for_ids(1000, 100, vec![]),
                    vec![
                        step_simple(SYS_PRCTL, 38, 1), // PR_SET_NO_NEW_PRIVS
                        step_execve("/suid_bin"),
                        step_simple(SYS_GETEUID, 0, 0),
                        step_capget(),
                        step_simple(SYS_PRCTL, 39, 0), // PR_GET_NO_NEW_PRIVS
                        step_execve("/fcap_bin"),
                        step_simple(SYS_GETEUID, 0, 0),
                        step_capget(),
                        step_simple(SYS_PRCTL, 39, 0),
                        step_simple(SYS_EXIT_GROUP, 0, 0),
                    ],
                )
                .await;
                assert_eq!(res_nnp, vec![0, 1000, 0, 1, 1000, 0, 1]);
                assert_eq!(caps_nnp, vec![(0, 0), (0, 0)]);
                assert_eq!(auxv_nnp[1].get(&12), Some(&1000));
                assert_eq!(auxv_nnp[1].get(&23), Some(&0));
                assert_eq!(auxv_nnp[2].get(&12), Some(&1000));
                assert_eq!(auxv_nnp[2].get(&23), Some(&0));

                // Verify the exact capability bitmasks computed for /suid_bin and /fcap_bin
                // against the container's ProcessAuthority ceiling (CAP_NET_BIND_SERVICE
                // granted; CAP_SYS_TIME / CAP_NET_ADMIN / CAP_NET_RAW clamped out).
                let suid_creds = container
                    .filesystem()
                    .exec_credentials_at(
                        "/",
                        "/suid_bin",
                        &Credentials::for_ids(1000, 100, vec![]),
                        container.authority_cap_ceiling(),
                    )
                    .await
                    .expect("exec_credentials_at /suid_bin");
                assert!(suid_creds.capabilities.has_effective(CAP_NET_BIND_SERVICE));
                assert!(!suid_creds.capabilities.has_effective(CAP_SYS_TIME));
                assert!(!suid_creds.capabilities.has_effective(CAP_NET_ADMIN));
                assert!(!suid_creds.capabilities.has_effective(CAP_NET_RAW));

                let fcap_creds = container
                    .filesystem()
                    .exec_credentials_at(
                        "/",
                        "/fcap_bin",
                        &Credentials::for_ids(1000, 100, vec![]),
                        container.authority_cap_ceiling(),
                    )
                    .await
                    .expect("exec_credentials_at /fcap_bin");
                assert_eq!(
                    fcap_creds.capabilities.effective,
                    1u64 << CAP_NET_BIND_SERVICE
                );
                assert_eq!(
                    fcap_creds.capabilities.permitted,
                    1u64 << CAP_NET_BIND_SERVICE
                );

                drop(container);
                host_ns
                    .unmount(&root_auth.derive_unmount_cap("/priv").unwrap())
                    .await
                    .expect("unmount /priv");
                host_ns
                    .unmount(&root_auth.derive_unmount_cap("/shared").unwrap())
                    .await
                    .expect("unmount /shared");
            };

            futures::future::join(Box::pin(client), Box::pin(btrfs_service.run(timer))).await;
        });
    }

    #[test]
    fn default_linux_image_set_get_permissions_and_per_instance_isolation() {
        use super::super::program_bindings::helios::system::programs::{
            self as wit, HostWithStore,
        };
        use crate::DirectoryAuthorityRights;
        use helios_hal::fs::{FileSystem, FileSystemRights, FsPath, OpenFlags};

        let engine = component_test_engine();
        let rx = DirectoryAuthorityRights::READ | DirectoryAuthorityRights::EXECUTE;

        let make_store = |auth: ProcessAuthority| {
            wasmtime::Store::new(&engine, test_store::store_data_authorized(auth, |_| {}))
        };

        // Build a read-only image directory `/alpine` and a regular file `/not-a-dir`.
        let mut store_a = make_store({
            let mut auth = ProcessAuthority::empty();
            auth.insert_directory_preopen(
                crate::DirectoryPreopen::new("/alpine", "/alpine", rx).unwrap(),
            );
            auth.insert_directory_preopen(
                crate::DirectoryPreopen::new("/not-a-dir", "/not-a-dir", rx).unwrap(),
            );
            auth
        });
        {
            let ns = store_a.data().filesystem().clone();
            let root = ns.resolve("/").unwrap();
            let payer = crate::StoragePayer::for_test();
            block_on(
                root.fs()
                    .create_directory(FsPath::new("alpine").unwrap(), 0, &payer),
            )
            .expect("mkdir /alpine");
            let img_fs = crate::vfs::MemoryFs::new(ns.table().allocate_device());
            block_on(
                ns.mount(
                    &ProcessAuthority::root()
                        .derive_mount_cap("/alpine")
                        .unwrap(),
                    crate::MountedFs::Memory(img_fs),
                    crate::MountGrant {
                        rights: FileSystemRights::READ,
                        sharing: crate::MountSharing::Shared,
                    },
                ),
            )
            .expect("mount RO /alpine");
            block_on(root.fs().open(
                FsPath::new("not-a-dir").unwrap(),
                OpenFlags::CREATE,
                1,
                &payer,
            ))
            .expect("create /not-a-dir");
        }

        // Sibling store B starts with None.
        let mut store_b = make_store(ProcessAuthority::root());

        // 1. Caller with ONLY READ|EXECUTE (no WRITE) succeeds on `/alpine`.
        let img = wit::DefaultLinuxImage {
            root_path: String::from("/alpine"),
            env: vec![
                (String::from("PATH"), String::from("/usr/bin:/bin")),
                (String::from("LANG"), String::from("C.UTF-8")),
            ],
            credentials: Some(wit::ContainerCredentials {
                uid: 1000,
                gid: 1000,
                supplementary_groups: vec![10],
            }),
        };
        let res = block_on(store_a.run_concurrent(async |accessor| {
            <HasSelf<test_store::TestStoreData> as HostWithStore<_>>::set_default_image(
                accessor,
                Some(img.clone()),
            )
            .await
        }))
        .expect("concurrent")
        .expect("host call");
        assert!(res.is_ok(), "READ|EXECUTE authority suffices: {res:?}");

        // 2. get_default_image returns the configured image on store A, while
        //    store B still sees None (zero machine-wide global state).
        let got_a = block_on(store_a.run_concurrent(async |accessor| {
            accessor
                .with(<HasSelf<test_store::TestStoreData> as HostWithStore<_>>::get_default_image)
        }))
        .expect("concurrent")
        .expect("host call")
        .expect("store A has default image");
        assert_eq!(got_a.root_path, "/alpine");
        assert_eq!(got_a.env, img.env);
        assert_eq!(got_a.credentials.as_ref().unwrap().uid, 1000);

        let got_b = block_on(store_b.run_concurrent(async |accessor| {
            accessor
                .with(<HasSelf<test_store::TestStoreData> as HostWithStore<_>>::get_default_image)
        }))
        .expect("concurrent")
        .expect("host call");
        assert!(got_b.is_none(), "sibling store must remain isolated");

        // 3. Regular file is rejected with InvalidPath.
        let non_dir = block_on(store_a.run_concurrent(async |accessor| {
            <HasSelf<test_store::TestStoreData> as HostWithStore<_>>::set_default_image(
                accessor,
                Some(wit::DefaultLinuxImage {
                    root_path: String::from("/not-a-dir"),
                    env: Vec::new(),
                    credentials: None,
                }),
            )
            .await
        }))
        .expect("concurrent")
        .expect("host call");
        assert!(matches!(
            non_dir,
            Err(wit::SpawnError {
                kind: wit::SpawnErrorKind::InvalidPath,
                ..
            })
        ));

        // 4. Caller missing EXECUTE (READ-only) is rejected with PermissionDenied.
        let mut store_ro = make_store({
            let mut auth = ProcessAuthority::empty();
            auth.insert_directory_preopen(
                crate::DirectoryPreopen::new("/alpine", "/alpine", DirectoryAuthorityRights::READ)
                    .unwrap(),
            );
            auth
        });
        let denied = block_on(store_ro.run_concurrent(async |accessor| {
            <HasSelf<test_store::TestStoreData> as HostWithStore<_>>::set_default_image(
                accessor,
                Some(img),
            )
            .await
        }))
        .expect("concurrent")
        .expect("host call");
        assert!(matches!(
            denied,
            Err(wit::SpawnError {
                kind: wit::SpawnErrorKind::PermissionDenied,
                ..
            })
        ));

        // 5. Clearing with None resets get_default_image to None.
        let cleared = block_on(store_a.run_concurrent(async |accessor| {
            <HasSelf<test_store::TestStoreData> as HostWithStore<_>>::set_default_image(
                accessor, None,
            )
            .await
        }))
        .expect("concurrent")
        .expect("host call");
        assert!(cleared.is_ok());
        let after_clear = block_on(store_a.run_concurrent(async |accessor| {
            accessor
                .with(<HasSelf<test_store::TestStoreData> as HostWithStore<_>>::get_default_image)
        }))
        .expect("concurrent")
        .expect("host call");
        assert!(after_clear.is_none());
    }

    #[test]
    fn default_linux_image_ephemeral_overlay_shebang_env_merge_and_cwd() {
        use crate::vfs::{BOOT_DEVICE, MemoryFs};
        use crate::{
            BootFs, DefaultLinuxCredentials, DefaultLinuxImage, DirectoryAuthorityRights,
            DirectoryPreopen, EmbeddedBootDirectory, EmbeddedBootFs, MountGrant, MountSharing,
            MountedFs, Namespace,
        };
        use helios_hal::fs::{FileSystem, FileSystemRights, FsPath};

        // 1. Unit-test parse_shebang, rewrite_shebang, and merge_default_image_env.
        assert_eq!(
            parse_shebang(b"#!/bin/sh -e\necho hi\n"),
            Some((String::from("/bin/sh"), Some(String::from("-e"))))
        );
        assert_eq!(
            parse_shebang(b"#!  /usr/bin/env   python3  \r\n"),
            Some((String::from("/usr/bin/env"), Some(String::from("python3"))))
        );
        assert_eq!(parse_shebang(b"\x7fELF"), None);

        let mut argv = ProgramArgv::launched("myscript", vec![String::from("arg1")]);
        argv.rewrite_shebang(
            String::from("/bin/sh"),
            Some(String::from("-e")),
            String::from("/bin/myscript"),
        );
        assert_eq!(
            argv.into_vec(),
            vec!["/bin/sh", "-e", "/bin/myscript", "arg1"]
        );

        let merged = merge_default_image_env(
            &[
                (String::from("PATH"), String::from("/usr/bin:/bin")),
                (String::from("FOO"), String::from("from-image")),
            ],
            vec![
                (String::from("FOO"), String::from("from-request")),
                (String::from("EXTRA"), String::from("1")),
            ],
        );
        assert_eq!(
            merged,
            vec![
                (String::from("PATH"), String::from("/usr/bin:/bin")),
                (String::from("FOO"), String::from("from-request")),
                (String::from("EXTRA"), String::from("1")),
            ]
        );

        // 2. Build a read-only image with `/bin/interp` (minimal ELF), `/bin/run.sh`
        //    (`#!/bin/interp -x`), `/bin/loop.sh` (`#!/bin/loop.sh`), and `/work` subdir,
        //    plus a writable host share `/host-dir`.
        const BOOT_IMAGE: EmbeddedBootFs = EmbeddedBootFs::new(
            &[
                EmbeddedBootDirectory::new("img", 0),
                EmbeddedBootDirectory::new("host-dir", 0),
            ],
            &[],
        );
        let ns = Namespace::<UnsupportedStorage>::new(crate::MountTable::new(
            BootFs::new(BOOT_IMAGE, BOOT_DEVICE),
            4,
        ));
        let root_auth = ProcessAuthority::root();
        let payer = crate::StoragePayer::for_test();
        let img_fs = MemoryFs::new(ns.table().allocate_device());
        let host_fs = MemoryFs::new(ns.table().allocate_device());
        block_on(async {
            img_fs
                .create_directory(FsPath::new("bin").unwrap(), 1, &payer)
                .await
                .unwrap();
            img_fs
                .create_directory(FsPath::new("app").unwrap(), 1, &payer)
                .await
                .unwrap();
            create_container_file(&img_fs, "bin/interp", &minimal_x86_64_elf()).await;
            create_container_file(&img_fs, "bin/run.sh", b"#!/bin/interp -x\necho ok\n").await;
            create_container_file(&img_fs, "bin/loop.sh", b"#!/bin/loop.sh\n").await;
            create_container_file(&host_fs, "data.txt", b"host-visible").await;
            ns.mount(
                &root_auth.derive_mount_cap("/img").unwrap(),
                MountedFs::Memory(img_fs),
                MountGrant {
                    rights: FileSystemRights::READ,
                    sharing: MountSharing::Shared,
                },
            )
            .await
            .unwrap();
            ns.mount(
                &root_auth.derive_mount_cap("/host-dir").unwrap(),
                MountedFs::Memory(host_fs),
                MountGrant {
                    rights: FileSystemRights::READ | FileSystemRights::WRITE,
                    sharing: MountSharing::Shared,
                },
            )
            .await
            .unwrap();
        });

        let held_lower = ns.resolve("/img").unwrap().held();
        let default_image = DefaultLinuxImage {
            root_path: String::from("/img"),
            lower: held_lower,
            env: vec![(String::from("IMG_ENV"), String::from("yes"))],
            credentials: Some(DefaultLinuxCredentials {
                uid: 1000,
                gid: 1000,
                supplementary_groups: Vec::new(),
            }),
        };

        let mut child_auth = ProcessAuthority::empty();
        child_auth.insert_directory_preopen(
            DirectoryPreopen::new(
                "/host-dir",
                "/mnt/host",
                DirectoryAuthorityRights::READ | DirectoryAuthorityRights::WRITE,
            )
            .unwrap(),
        );

        let cpu = ScriptedLinuxCpu {
            base: TestCpu::with_entropy(0x11),
            script: ScriptState::new(Vec::new(), |_| {}),
        };
        let service = test_program_service(&cpu);
        let container = service
            .create_ephemeral_overlay_container(child_auth, &ns, &default_image)
            .expect("create ephemeral overlay container");

        // Verify host bind mount `/mnt/host` is overlaid on top of the ephemeral root
        // and default credentials took effect.
        assert_eq!(container.default_credentials().user.effective, 1000);
        assert!(block_on(container.filesystem().stat("/mnt/host/data.txt")).is_ok());

        // Verify `validate_container_cwd` accepts `/app` and rejects `/bin/interp`.
        assert_eq!(
            block_on(validate_container_cwd(&container, Some("/app"))).unwrap(),
            Some(String::from("/app"))
        );
        assert!(matches!(
            block_on(validate_container_cwd(&container, Some("/bin/interp"))),
            Err(ProgramExecError {
                kind: ProgramExecErrorKind::InvalidPath,
                ..
            })
        ));

        // Verify `#!` script resolution rewrites argv and loads `/bin/interp`,
        // and a recursive `#!` loop fails fast after MAX_SHEBANG_DEPTH.
        let timeline = phases::Timeline::disabled();
        let root_creds = helios_linux::syscall::Credentials::root();
        let mut script_argv = ProgramArgv::launched("run.sh", vec![String::from("hello")]);
        block_on(load_container_executable(
            &cpu,
            &container,
            "/bin/run.sh",
            &mut script_argv,
            &root_creds,
            &timeline,
        ))
        .expect("shebang script resolves to ELF interpreter");
        assert_eq!(
            script_argv.into_vec(),
            vec!["/bin/interp", "-x", "/bin/run.sh", "hello"]
        );

        let mut loop_argv = ProgramArgv::launched("loop.sh", Vec::new());
        let loop_err = block_on(load_container_executable(
            &cpu,
            &container,
            "/bin/loop.sh",
            &mut loop_argv,
            &root_creds,
            &timeline,
        ));
        assert!(matches!(
            loop_err,
            Err(ProgramExecError {
                kind: ProgramExecErrorKind::InvalidPath,
                ..
            })
        ));

        // Verify `getcwd` observes an explicit `cwd` override inside a Linux process.
        const CWD_BUF: u64 = (SCRATCH_BASE + 0x200) as u64;
        // 79 = getcwd, 231 = exit_group.
        let cwd_script = ScriptState::new(
            vec![
                ScriptStep::Syscall {
                    num: 79,
                    args: [CWD_BUF, 64, 0, 0, 0, 0],
                },
                ScriptStep::Syscall {
                    num: 231,
                    args: [0, 0, 0, 0, 0, 0],
                },
            ],
            |_| {},
        );
        let cwd_cpu = ScriptedLinuxCpu {
            base: TestCpu::with_entropy(0x22),
            script: cwd_script.clone(),
        };
        let cwd_exec = LinuxExecutable::load(&cwd_cpu, minimal_x86_64_elf()).unwrap();
        let runtime_state = HostRuntimeState::<_, TestNetworkService, UnsupportedStorage>::new(
            cwd_cpu.timebase(),
            1,
            0,
            crate::BootPayload::for_tests(),
            GuestIsa::for_build_target(cwd_cpu.native_feature_probe()),
        );
        runtime_state.install_root_entropy(triomphe::Arc::new(
            crate::RootEntropy::from_platform(
                &cwd_cpu,
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
        let instance = registry.register("cwd-child", 0);
        let exec_context = ProgramExecContext {
            cpu: cwd_cpu.clone(),
            timer: executor.timer(cwd_cpu.clone()),
            spawner: executor.spawner(cwd_cpu.clone()),
            runtime_state,
            instance_registry: registry,
            parent_instance_id: None,
            read_serial: |_, _| {},
            write_serial: crate::DebugSerialWriter::of::<test_store::DiscardPort>(),
        };
        let (_stx, srx) = crate::byte_channel();
        let (otx, _orx) = crate::byte_channel();
        let (etx, _erx) = crate::byte_channel();
        let spawner = executor
            .spawner(cwd_cpu.clone())
            .instance_spawner(crate::TaskFunding::Instance, &instance);
        let exit = block_on(run_linux_process(
            LinuxExecRuntime {
                exec_context,
                wasm: None,
            },
            ProgramArgv::launched("interp", Vec::new()),
            Vec::new(),
            container.clone(),
            None,
            Some(String::from("/app")),
            crate::InheritedSockets::new(),
            DescriptorOrigin::Fresh,
            WasixSignalState::new(),
            spawner,
            instance,
            OutputMode::Child {
                stdin_rx: srx,
                stdout_tx: otx,
                stderr_tx: etx,
            },
            cwd_exec,
            &timeline,
        ))
        .expect("cwd process completes");
        assert_eq!(exit.termination, ChildTermination::Exited(0));
        let cwd_len = cwd_script.results.lock()[0] as usize;
        assert_eq!(cwd_len, b"/app\0".len());
        let got_cwd = &cwd_script.memory.lock()[0x200..0x200 + cwd_len];
        assert_eq!(got_cwd, b"/app\0");
    }

    #[test]
    fn child_signal_enforces_authority_range_and_delivers_signal() {
        use super::super::program_bindings::helios::system::programs::{
            self as wit, HostChildWithStore,
        };

        let engine = component_test_engine();
        let signal_state = WasixSignalState::new();
        let make_handle = |state: WasixSignalState| {
            let (_tx, rx) = futures::channel::oneshot::channel();
            ChildHandle {
                instance_id: crate::InstanceId::from_raw(77),
                signal_state: state,
                stdin: None,
                stdout: None,
                stderr: None,
                exit: Some(rx),
            }
        };

        // 1. Missing ProcessRight::Signal -> PermissionDenied.
        let mut no_sig_store = wasmtime::Store::new(
            &engine,
            test_store::store_data_authorized(ProcessAuthority::empty(), |_| {}),
        );
        let h1 = no_sig_store
            .data_mut()
            .table
            .push(make_handle(signal_state.clone()))
            .unwrap();
        let denied = block_on(no_sig_store.run_concurrent(async |accessor| {
            accessor.with(|access| {
                <HasSelf<test_store::TestStoreData> as HostChildWithStore<_>>::signal(
                    access, h1, 15,
                )
            })
        }))
        .expect("concurrent")
        .expect("host call");
        assert!(matches!(
            denied,
            Err(wit::SpawnError {
                kind: wit::SpawnErrorKind::PermissionDenied,
                ..
            })
        ));

        // 2. Authorized caller: invalid signal 0 and 65 rejected; signal 15 delivered.
        let mut ok_store = wasmtime::Store::new(
            &engine,
            test_store::store_data_authorized(ProcessAuthority::root(), |_| {}),
        );
        let h2_rep = ok_store
            .data_mut()
            .table
            .push(make_handle(signal_state.clone()))
            .unwrap()
            .rep();
        let bad0 = block_on(ok_store.run_concurrent(async |accessor| {
            accessor.with(|access| {
                <HasSelf<test_store::TestStoreData> as HostChildWithStore<_>>::signal(
                    access,
                    wasmtime::component::Resource::new_borrow(h2_rep),
                    0,
                )
            })
        }))
        .expect("concurrent")
        .expect("host call");
        assert!(matches!(
            bad0,
            Err(wit::SpawnError {
                kind: wit::SpawnErrorKind::InvalidHint,
                ..
            })
        ));

        let delivered = block_on(ok_store.run_concurrent(async |accessor| {
            accessor.with(|access| {
                <HasSelf<test_store::TestStoreData> as HostChildWithStore<_>>::signal(
                    access,
                    wasmtime::component::Resource::new_borrow(h2_rep),
                    15,
                )
            })
        }))
        .expect("concurrent")
        .expect("host call");
        assert!(delivered.is_ok());
        assert_eq!(
            signal_state.take_pending(),
            Some(helios_unix::Signal::SIGTERM)
        );
    }

    #[test]
    fn inherited_tcp_and_vsock_listeners_handoff_to_wit_preview1_and_linux_fd3() {
        use super::super::program_bindings::helios::system::programs::{
            self as wit, HostWithStore,
        };
        use crate::vsock::{ComponentHostVsockService, VsockService};
        use helios_hal::vsock::{
            VsockAddress, VsockDelivery, VsockDevice, VsockOp, VsockPacketHeader, VsockReceived,
        };

        /// In-memory mock vsock transport that delivers queued packets from a
        /// channel and records outbound packets.
        struct MockVsockDevice {
            cid: u64,
            rx: Mutex<alloc::collections::VecDeque<(VsockPacketHeader, Vec<u8>)>>,
            tx: Mutex<Vec<(VsockPacketHeader, Vec<u8>)>>,
        }

        impl MockVsockDevice {
            fn new(cid: u64) -> Self {
                Self {
                    cid,
                    rx: Mutex::new(alloc::collections::VecDeque::new()),
                    tx: Mutex::new(Vec::new()),
                }
            }

            fn enqueue(&self, header: VsockPacketHeader, payload: Vec<u8>) {
                self.rx.lock().push_back((header, payload));
            }
        }

        impl VsockDevice for MockVsockDevice {
            fn guest_cid(&self) -> u64 {
                self.cid
            }

            fn max_payload_bytes(&self) -> usize {
                4096
            }

            async fn send(
                &self,
                header: VsockPacketHeader,
                payload: &[u8],
            ) -> helios_hal::io::IoResult<()> {
                self.tx.lock().push((header, payload.to_vec()));
                Ok(())
            }

            async fn receive_into(
                &self,
                payload: &mut [u8],
            ) -> helios_hal::io::IoResult<VsockDelivery> {
                loop {
                    if let Some((hdr, data)) = self.rx.lock().pop_front() {
                        payload[..data.len()].copy_from_slice(&data);
                        return Ok(VsockDelivery::Packet(VsockReceived {
                            header: hdr,
                            payload_len: data.len(),
                        }));
                    }
                    futures_lite::future::yield_now().await;
                }
            }
        }

        let cpu = TestCpu::with_entropy(0x33);
        let vsock_executor = crate::Executor::isolated(
            ProgressCounter::new(),
            crate::test_support::single_node_pool(1),
            ProcessorId::new(0),
        );
        let timer = vsock_executor.timer(cpu);
        let dev = Arc::new(MockVsockDevice::new(7));
        struct ArcVsockDevice(Arc<MockVsockDevice>);
        impl VsockDevice for ArcVsockDevice {
            fn guest_cid(&self) -> u64 {
                self.0.guest_cid()
            }
            fn max_payload_bytes(&self) -> usize {
                self.0.max_payload_bytes()
            }
            async fn send(
                &self,
                header: VsockPacketHeader,
                payload: &[u8],
            ) -> helios_hal::io::IoResult<()> {
                self.0.send(header, payload).await
            }
            async fn receive_into(
                &self,
                payload: &mut [u8],
            ) -> helios_hal::io::IoResult<VsockDelivery> {
                self.0.receive_into(payload).await
            }
        }

        let raw_vsock = VsockService::new(cpu, timer, ArcVsockDevice(dev.clone()));
        let vsock_svc = ComponentHostVsockService::from_service(raw_vsock.clone());

        // 1. Bind a vsock listener on port 9000; inject an incoming peer connect
        //    packet + data payload BEFORE hand-off and pump one receive step.
        let listener_id = vsock_svc.listen(9000, 4).expect("vsock listen");
        assert!(!vsock_svc.listener_readable(listener_id).unwrap());

        let vsock_hdr =
            |src_port: u32, dst_port: u32, op: VsockOp, payload_len: u32| VsockPacketHeader {
                source: VsockAddress::host(src_port),
                destination: VsockAddress {
                    cid: 7,
                    port: dst_port,
                },
                op,
                flags: 0,
                payload_len,
                buf_alloc: 65536,
                fwd_cnt: 0,
            };
        dev.enqueue(vsock_hdr(50000, 9000, VsockOp::Request, 0), Vec::new());
        dev.enqueue(vsock_hdr(50000, 9000, VsockOp::Data, 5), b"hello".to_vec());
        // Drive the vsock pump just enough to ingest both queued packets.
        block_on(async {
            let mut pump = core::pin::pin!(raw_vsock.clone().run_forever());
            let waker = futures::task::noop_waker_ref();
            let mut cx = Context::from_waker(waker);
            let _ = pump.as_mut().poll(&mut cx);
            let _ = pump.as_mut().poll(&mut cx);
        });
        // Supervisor `wait_readable` observes readiness WITHOUT consuming the connection!
        assert!(block_on(vsock_svc.wait_readable(listener_id, 1_000_000)).unwrap());
        assert!(vsock_svc.listener_readable(listener_id).unwrap());

        // 2. Wasm component hand-off: `take_inherited_sockets` returns `[Tcp, Vsock]`
        //    once and `[]` on a second call.
        let engine = component_test_engine();
        let store_data = test_store::store_data_authorized(ProcessAuthority::root(), |_| {});
        let net_svc = TestNetworkService::new();
        store_data
            .runtime_state
            .install_network_service(net_svc.clone());
        let retire = store_data.retirement.sender();
        let tcp_raw =
            crate::InheritedSocket::from_tcp_listener(&mut crate::ComponentTcpListener::new(
                42,
                crate::NetworkIpAddress::Ipv4(crate::Ipv4Address::new([127, 0, 0, 1])),
                8080,
                64,
                retire,
            ))
            .unwrap();
        let vsock_inherited =
            crate::InheritedSocket::from_vsock_listener(vsock_svc.clone(), listener_id);
        let mut child_store = wasmtime::Store::new(
            &engine,
            store_data.with_inherited_sockets(crate::InheritedSockets::from_vec(vec![
                tcp_raw,
                vsock_inherited,
            ])),
        );
        let taken = block_on(child_store.run_concurrent(async |accessor| {
            accessor.with(
                <HasSelf<test_store::TestStoreData> as HostWithStore<_>>::take_inherited_sockets,
            )
        }))
        .expect("concurrent")
        .expect("host call");
        assert_eq!(taken.len(), 2);
        assert!(matches!(taken[0], wit::InheritedSocket::Tcp(_)));
        assert!(matches!(taken[1], wit::InheritedSocket::Vsock(_)));
        let taken_again = block_on(child_store.run_concurrent(async |accessor| {
            accessor.with(
                <HasSelf<test_store::TestStoreData> as HostWithStore<_>>::take_inherited_sockets,
            )
        }))
        .expect("concurrent")
        .expect("host call");
        assert!(taken_again.is_empty());

        // Move the vsock listener back out of the component table for Linux fd=3 hand-off!
        let wit::InheritedSocket::Vsock(vsock_res) = &taken[1] else {
            unreachable!();
        };
        let mut comp_vsock: super::super::ComponentVsockListener = child_store
            .data_mut()
            .table
            .delete(wasmtime::component::Resource::new_own(vsock_res.rep()))
            .unwrap();
        let (reclaimed_svc, reclaimed_id) = comp_vsock.take().unwrap();

        // 3. Preview1 / WASIX hand-off: inherited sockets occupy fd = 3+,
        //    shifting preopened directories right behind them.
        let mut wasix_auth = ProcessAuthority::empty();
        wasix_auth.insert_directory_preopen(
            crate::DirectoryPreopen::new("/", "/", crate::DirectoryAuthorityRights::READ).unwrap(),
        );
        let p1_sock = UnixSocket::<TestNetworkService>::from_vsock(VsockSocket::Listening {
            listener: OwnedVsockListener::new(
                crate::UnixNetwork::with_vsock(None, Some(reclaimed_svc.clone())),
                reclaimed_id.as_u64(),
            ),
            local_cid: 7,
            local_port: 9000,
            options: unix_socket_options::<TestNetworkService>(),
        });
        let p1_table = Preview1DescriptorTable::from_authority_with_sockets(
            &wasix_auth,
            crate::DescriptorLimit::DEFAULT,
            vec![p1_sock],
        );
        assert!(matches!(
            p1_table.get(3),
            Some(Preview1Descriptor::Socket(_))
        ));
        assert!(matches!(
            p1_table.get(4),
            Some(Preview1Descriptor::Preopen { .. })
        ));
        drop(p1_table);

        // 4. Linux process hand-off: pre-bound vsock listener with queued connection
        //    + payload arrives at fd = 3; Linux getsockname, getsockopt(SO_DOMAIN /
        //    SO_ACCEPTCONN), accept4, and read receive the queued bytes with zero loss!
        let linux_listener = vsock_svc.listen(9001, 4).expect("vsock listen 9001");
        dev.enqueue(vsock_hdr(50001, 9001, VsockOp::Request, 0), Vec::new());
        dev.enqueue(vsock_hdr(50001, 9001, VsockOp::Data, 5), b"hello".to_vec());
        block_on(async {
            let mut pump = core::pin::pin!(raw_vsock.clone().run_forever());
            let waker = futures::task::noop_waker_ref();
            let mut cx = Context::from_waker(waker);
            let _ = pump.as_mut().poll(&mut cx);
            let _ = pump.as_mut().poll(&mut cx);
        });
        assert!(block_on(vsock_svc.wait_readable(linux_listener, 1_000_000)).unwrap());

        const ADDR_BUF: u64 = (SCRATCH_BASE + 0x300) as u64;
        const ADDR_LEN: u64 = (SCRATCH_BASE + 0x320) as u64;
        const OPT_VAL: u64 = (SCRATCH_BASE + 0x330) as u64;
        const OPT_LEN: u64 = (SCRATCH_BASE + 0x340) as u64;
        const READ_BUF: u64 = (SCRATCH_BASE + 0x360) as u64;
        // 51 = getsockname, 55 = getsockopt, 288 = accept4, 0 = read, 231 = exit_group.
        // SOL_SOCKET = 1, SO_ACCEPTCONN = 30, SO_DOMAIN = 39.
        let sock_script = ScriptState::new(
            vec![
                ScriptStep::Syscall {
                    num: 51,
                    args: [3, ADDR_BUF, ADDR_LEN, 0, 0, 0],
                },
                ScriptStep::Syscall {
                    num: 55,
                    args: [3, 1, 39, OPT_VAL, OPT_LEN, 0],
                },
                ScriptStep::Syscall {
                    num: 55,
                    args: [3, 1, 30, OPT_VAL + 4, OPT_LEN, 0],
                },
                ScriptStep::Syscall {
                    num: 288,
                    args: [3, 0, 0, 0, 0, 0],
                },
                ScriptStep::Syscall {
                    num: 0,
                    args: [4, READ_BUF, 16, 0, 0, 0],
                },
                ScriptStep::Syscall {
                    num: 231,
                    args: [0, 0, 0, 0, 0, 0],
                },
            ],
            |scratch| {
                scratch[0x320..0x324].copy_from_slice(&16_u32.to_le_bytes());
                scratch[0x340..0x344].copy_from_slice(&4_u32.to_le_bytes());
            },
        );
        let linux_cpu = ScriptedLinuxCpu {
            base: TestCpu::with_entropy(0x44),
            script: sock_script.clone(),
        };
        let linux_exec = LinuxExecutable::load(&linux_cpu, minimal_x86_64_elf()).unwrap();
        let ns = crate::Namespace::<UnsupportedStorage>::new(crate::MountTable::new(
            crate::BootFs::new(
                crate::EmbeddedBootFs::new(&[], &[]),
                crate::vfs::BOOT_DEVICE,
            ),
            4,
        ));
        let runtime_state = HostRuntimeState::<_, TestNetworkService, UnsupportedStorage>::new(
            linux_cpu.timebase(),
            1,
            0,
            crate::BootPayload::for_tests(),
            GuestIsa::for_build_target(linux_cpu.native_feature_probe()),
        );
        runtime_state.install_vsock_service(vsock_svc.clone());
        runtime_state.install_root_entropy(triomphe::Arc::new(
            crate::RootEntropy::from_platform(
                &linux_cpu,
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
        let instance = registry.register("vsock-child", 0);
        let exec_context = ProgramExecContext {
            cpu: linux_cpu.clone(),
            timer: executor.timer(linux_cpu.clone()),
            spawner: executor.spawner(linux_cpu.clone()),
            runtime_state,
            instance_registry: registry,
            parent_instance_id: None,
            read_serial: |_, _| {},
            write_serial: crate::DebugSerialWriter::of::<test_store::DiscardPort>(),
        };
        let container = Arc::new(crate::LinuxContainer::ephemeral(
            crate::ContainerId::new(core::num::NonZeroU64::new(90).unwrap()),
            ProcessAuthority::root(),
            &ns,
        ));
        let (_stx, srx) = crate::byte_channel();
        let (otx, _orx) = crate::byte_channel();
        let (etx, _erx) = crate::byte_channel();
        let spawner = executor
            .spawner(linux_cpu.clone())
            .instance_spawner(crate::TaskFunding::Instance, &instance);
        let timeline = phases::Timeline::disabled();
        let exit = block_on(run_linux_process(
            LinuxExecRuntime {
                exec_context,
                wasm: None,
            },
            ProgramArgv::launched("vsock-srv", Vec::new()),
            Vec::new(),
            container,
            None,
            None,
            crate::InheritedSockets::from_vec(vec![crate::InheritedSocket::from_vsock_listener(
                vsock_svc.clone(),
                linux_listener,
            )]),
            DescriptorOrigin::Fresh,
            WasixSignalState::new(),
            spawner,
            instance,
            OutputMode::Child {
                stdin_rx: srx,
                stdout_tx: otx,
                stderr_tx: etx,
            },
            linux_exec,
            &timeline,
        ))
        .expect("vsock server completes");
        assert_eq!(exit.termination, ChildTermination::Exited(0));
        let results = sock_script.results.lock().clone();
        assert_eq!(results, vec![0, 0, 0, 4, 5]);
        let scratch = sock_script.memory.lock();
        // getsockname: AF_VSOCK (40), port 9001, cid 7.
        assert_eq!(u16::from_le_bytes([scratch[0x300], scratch[0x301]]), 40);
        assert_eq!(
            u32::from_le_bytes(scratch[0x304..0x308].try_into().unwrap()),
            9001
        );
        assert_eq!(
            u32::from_le_bytes(scratch[0x308..0x30c].try_into().unwrap()),
            7
        );
        // getsockopt SO_DOMAIN = 40 (AF_VSOCK), SO_ACCEPTCONN = 1.
        assert_eq!(
            u32::from_le_bytes(scratch[0x330..0x334].try_into().unwrap()),
            40
        );
        assert_eq!(
            u32::from_le_bytes(scratch[0x334..0x338].try_into().unwrap()),
            1
        );
        // read(4) received the pre-queued "hello" bytes with zero loss!
        assert_eq!(&scratch[0x360..0x365], b"hello");
    }

    #[test]
    fn execve_loads_dynamic_pie_with_pt_interp_and_enforces_interpreter_authority() {
        use crate::test_support::UnsupportedStorage;
        use crate::vfs::BOOT_DEVICE;
        use crate::{
            BootFs, ContainerConfig, ContainerId, ContainerMountSharing, ContainerMountSpec,
            DirectoryAuthorityRights, EmbeddedBootDirectory, EmbeddedBootFile, EmbeddedBootFs,
            LinuxContainer, ProcessAuthority, SharedOwner,
        };
        use alloc::collections::{BTreeMap, VecDeque};
        use core::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
        use helios_hal::cpu::{Instant, Timebase, TimerInterrupt};
        use helios_hal::entropy::{EntropyQuality, EntropyUnavailable};
        use helios_hal::hv::RegisterId;
        use helios_hal::native::{
            ExtendedState, InstructionSet, Mapping, NativeError, NativeExecution,
            NativeUnavailable, Stop, UserContext, UserSpace,
        };
        use helios_hal::pmm::PhysFrame;
        use helios_hal::vmm::{PageFlags, VirtAddr, VirtRange};
        use helios_linux::syscall::{Credentials, UtsField};

        fn build_x86_elf(e_type: u16, base: u64, interp: Option<&[u8]>) -> Vec<u8> {
            let mut bytes = alloc::vec![0u8; 2 * PhysFrame::SIZE];
            let mut phdrs: Vec<[u8; 56]> = Vec::new();
            let push = |phdrs: &mut Vec<[u8; 56]>,
                        p_type: u32,
                        p_flags: u32,
                        p_offset: u64,
                        p_vaddr: u64,
                        p_filesz: u64,
                        p_memsz: u64,
                        p_align: u64| {
                let mut h = [0u8; 56];
                h[0..4].copy_from_slice(&p_type.to_le_bytes());
                h[4..8].copy_from_slice(&p_flags.to_le_bytes());
                h[8..16].copy_from_slice(&p_offset.to_le_bytes());
                h[16..24].copy_from_slice(&p_vaddr.to_le_bytes());
                h[24..32].copy_from_slice(&p_vaddr.to_le_bytes());
                h[32..40].copy_from_slice(&p_filesz.to_le_bytes());
                h[40..48].copy_from_slice(&p_memsz.to_le_bytes());
                h[48..56].copy_from_slice(&p_align.to_le_bytes());
                phdrs.push(h);
            };
            if let Some(path) = interp {
                let off = 0x300u64;
                bytes[off as usize..off as usize + path.len()].copy_from_slice(path);
                push(
                    &mut phdrs,
                    3,
                    4,
                    off,
                    base + off,
                    path.len() as u64,
                    path.len() as u64,
                    1,
                );
            }
            push(&mut phdrs, 1, 4, 0, base, 0x500, 0x500, 4096);
            push(&mut phdrs, 1, 5, 0x1000, base + 0x1000, 0x200, 0x200, 4096);
            push(&mut phdrs, 2, 4, 0x400, base + 0x400, 0x40, 0x40, 8);
            bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
            bytes[16..18].copy_from_slice(&e_type.to_le_bytes());
            bytes[18..20].copy_from_slice(&62u16.to_le_bytes());
            bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
            bytes[24..32].copy_from_slice(&(base + 0x1000).to_le_bytes());
            bytes[32..40].copy_from_slice(&64u64.to_le_bytes());
            bytes[52..54].copy_from_slice(&64u16.to_le_bytes());
            bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
            bytes[56..58].copy_from_slice(&(phdrs.len() as u16).to_le_bytes());
            for (i, h) in phdrs.iter().enumerate() {
                bytes[64 + i * 56..64 + (i + 1) * 56].copy_from_slice(h);
            }
            bytes
        }

        #[derive(Default)]
        struct DynMapSpace {
            bytes: spin::Mutex<BTreeMap<usize, u8>>,
        }
        impl DynMapSpace {
            fn write_bytes(&self, addr: usize, data: &[u8]) {
                let mut map = self.bytes.lock();
                for (i, &b) in data.iter().enumerate() {
                    map.insert(addr + i, b);
                }
            }
            fn read_u64(&self, addr: usize) -> u64 {
                let map = self.bytes.lock();
                let mut buf = [0u8; 8];
                for (i, slot) in buf.iter_mut().enumerate() {
                    *slot = map.get(&(addr + i)).copied().unwrap_or(0);
                }
                u64::from_le_bytes(buf)
            }
            fn read_cstr(&self, addr: usize) -> String {
                let map = self.bytes.lock();
                let mut out = Vec::new();
                let mut cur = addr;
                while let Some(&b) = map.get(&cur) {
                    if b == 0 {
                        break;
                    }
                    out.push(b);
                    cur += 1;
                }
                String::from_utf8(out).unwrap()
            }
        }
        // SAFETY: host test double, never enters hardware user mode.
        unsafe impl UserSpace for DynMapSpace {
            fn map(
                &self,
                range: VirtRange,
                initial: &[u8],
                _: PageFlags,
            ) -> Result<(), NativeError> {
                let start = range.start.raw();
                let mut map = self.bytes.lock();
                for i in 0..range.byte_len {
                    map.insert(start + i, initial.get(i).copied().unwrap_or(0));
                }
                Ok(())
            }
            fn map_anywhere(
                &self,
                hint: VirtAddr,
                len: usize,
                _: PageFlags,
            ) -> Result<VirtRange, NativeError> {
                Ok(VirtRange::new(hint, len))
            }
            fn read(&self, addr: VirtAddr, out: &mut [u8]) -> Result<(), NativeError> {
                let map = self.bytes.lock();
                for (i, slot) in out.iter_mut().enumerate() {
                    *slot = map.get(&(addr.raw() + i)).copied().unwrap_or(0);
                }
                Ok(())
            }
            fn check_writable(&self, _: VirtAddr, _: usize) -> Result<(), NativeError> {
                Ok(())
            }
            fn write(&self, addr: VirtAddr, data: &[u8]) -> Result<(), NativeError> {
                self.write_bytes(addr.raw(), data);
                Ok(())
            }
            fn populate(&self, addr: VirtAddr, data: &[u8]) -> Result<(), NativeError> {
                self.write_bytes(addr.raw(), data);
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
                Ok(())
            }
            fn mapping(&self, _: VirtRange) -> Option<Mapping> {
                None
            }
            fn free_range(&self, hint: VirtAddr, _: usize) -> Option<VirtAddr> {
                Some(hint)
            }
            fn clone_cow(&self) -> Result<Self, NativeError> {
                Ok(Self {
                    bytes: spin::Mutex::new(self.bytes.lock().clone()),
                })
            }
        }

        struct DynStep {
            writes: Vec<(usize, Vec<u8>)>,
            regs: [u64; 7],
        }
        #[derive(Default)]
        struct DynState {
            steps: VecDeque<DynStep>,
            results: Vec<u64>,
            entries: Vec<u64>,
            auxvs: Vec<BTreeMap<u64, u64>>,
            execfns: Vec<String>,
        }
        #[derive(Clone)]
        struct DynCpu {
            base: TestCpu,
            state: Arc<spin::Mutex<DynState>>,
        }
        struct DynCtx {
            state: Arc<spin::Mutex<DynState>>,
            regs: [u64; 7],
            entry: u64,
            sp: u64,
            tp: VirtAddr,
            started: AtomicUsize,
        }
        // SAFETY: host test double, never enters hardware user mode.
        unsafe impl UserContext for DynCtx {
            type Space = DynMapSpace;
            fn register(&self, reg: RegisterId) -> Result<u64, NativeError> {
                match reg {
                    RegisterId::X86Gpr(0) => Ok(self.regs[0]),
                    RegisterId::X86Gpr(7) => Ok(self.regs[1]),
                    RegisterId::X86Gpr(6) => Ok(self.regs[2]),
                    RegisterId::X86Gpr(2) => Ok(self.regs[3]),
                    RegisterId::X86Gpr(10) => Ok(self.regs[4]),
                    RegisterId::X86Gpr(8) => Ok(self.regs[5]),
                    RegisterId::X86Gpr(9) => Ok(self.regs[6]),
                    RegisterId::X86Gpr(4) => Ok(self.sp),
                    RegisterId::X86Gpr(_) => Ok(0),
                    _ => Err(NativeError::Register),
                }
            }
            fn set_register(&mut self, reg: RegisterId, val: u64) -> Result<(), NativeError> {
                if matches!(reg, RegisterId::X86Gpr(0)) {
                    self.regs[0] = val;
                    self.state.lock().results.push(val);
                    Ok(())
                } else {
                    Err(NativeError::Register)
                }
            }
            fn thread_pointer(&self) -> VirtAddr {
                self.tp
            }
            fn set_thread_pointer(&mut self, addr: VirtAddr) -> Result<(), NativeError> {
                self.tp = addr;
                Ok(())
            }
            fn extended_state(&self) -> ExtendedState {
                ExtendedState::X86Xsave(alloc::vec![0; 576])
            }
            fn set_extended_state(&mut self, _: &ExtendedState) -> Result<(), NativeError> {
                Ok(())
            }
            fn try_clone(&self) -> Result<Self, NativeError> {
                Ok(Self {
                    state: self.state.clone(),
                    regs: self.regs,
                    entry: self.entry,
                    sp: self.sp,
                    tp: self.tp,
                    started: AtomicUsize::new(0),
                })
            }
            fn resume(&mut self, space: &DynMapSpace) -> Stop {
                if self.started.fetch_add(1, AtomicOrdering::Relaxed) == 0 {
                    let mut cursor = self.sp as usize;
                    let argc = space.read_u64(cursor) as usize;
                    cursor += 8 + (argc + 1) * 8;
                    while space.read_u64(cursor) != 0 {
                        cursor += 8;
                    }
                    cursor += 8;
                    let mut auxv = BTreeMap::new();
                    loop {
                        let tag = space.read_u64(cursor);
                        let val = space.read_u64(cursor + 8);
                        cursor += 16;
                        if tag == 0 {
                            break;
                        }
                        auxv.insert(tag, val);
                    }
                    let execfn = auxv
                        .get(&31)
                        .map(|&p| space.read_cstr(p as usize))
                        .unwrap_or_default();
                    let mut st = self.state.lock();
                    st.entries.push(self.entry);
                    st.auxvs.push(auxv);
                    st.execfns.push(execfn);
                }
                match self.state.lock().steps.pop_front() {
                    Some(step) => {
                        for (addr, data) in &step.writes {
                            space.write_bytes(*addr, data);
                        }
                        self.regs = step.regs;
                        Stop::SystemCall
                    }
                    None => {
                        self.regs = [231, 0, 0, 0, 0, 0, 0];
                        Stop::SystemCall
                    }
                }
            }
        }
        impl NativeExecution for DynCpu {
            type Space = DynMapSpace;
            type Context = DynCtx;
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
                Ok(DynMapSpace::default())
            }
            fn create_context(
                &self,
                entry: VirtAddr,
                sp: VirtAddr,
            ) -> Result<Self::Context, NativeError> {
                Ok(DynCtx {
                    state: self.state.clone(),
                    regs: [0; 7],
                    entry: entry.raw() as u64,
                    sp: sp.raw() as u64,
                    tp: VirtAddr::new(PhysFrame::SIZE),
                    started: AtomicUsize::new(0),
                })
            }
        }
        impl Cpu for DynCpu {
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
            fn mask_to_wake_only(&self) {}
            fn park_wake_only(&self, _: &core::sync::atomic::AtomicU8, _: u8) {}
            fn start_processor(&self, _: ProcessorId) {}
            fn wake_processor(&self, _: ProcessorId) {}
            fn stop_current(&self) {}
            fn restart_processor(&self, _: ProcessorId) {}
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
            fn fill_entropy(
                &self,
                buffer: &mut [u8],
            ) -> Result<EntropyQuality, EntropyUnavailable> {
                self.base.fill_entropy(buffer)
            }
            fn shutdown(&self) -> ! {
                unreachable!()
            }
            fn reboot(&self) -> ! {
                unreachable!()
            }
        }

        const SYS_EXECVE: u64 = 59;
        const SYS_EXIT_GROUP: u64 = 231;
        const ENOENT_NEG: u64 = 2u64.wrapping_neg();
        const ENOEXEC_NEG: u64 = 8u64.wrapping_neg();
        const EACCES_NEG: u64 = 13u64.wrapping_neg();

        let step_execve = |path: &str| -> DynStep {
            let mut path_bytes = path.as_bytes().to_vec();
            path_bytes.push(0);
            let mut argv_bytes = Vec::new();
            argv_bytes.extend_from_slice(&0x10_0000u64.to_le_bytes());
            argv_bytes.extend_from_slice(&0u64.to_le_bytes());
            let envp_bytes = 0u64.to_le_bytes().to_vec();
            DynStep {
                writes: alloc::vec![
                    (0x10_0000, path_bytes),
                    (0x10_0200, argv_bytes),
                    (0x10_0300, envp_bytes),
                ],
                regs: [SYS_EXECVE, 0x10_0000, 0x10_0200, 0x10_0300, 0, 0, 0],
            }
        };

        let interp_elf: &'static [u8] = Box::leak(build_x86_elf(3, 0, None).into_boxed_slice());
        let bad_recursive: &'static [u8] =
            Box::leak(build_x86_elf(3, 0, Some(b"/lib/ld.so\0")).into_boxed_slice());
        let dyn_pie: &'static [u8] =
            Box::leak(build_x86_elf(3, 0, Some(b"/lib/ld.so\0")).into_boxed_slice());
        let dyn_missing: &'static [u8] =
            Box::leak(build_x86_elf(3, 0, Some(b"/lib/missing.so\0")).into_boxed_slice());
        let dyn_noexec: &'static [u8] =
            Box::leak(build_x86_elf(3, 0, Some(b"/noexec/ld.so\0")).into_boxed_slice());
        let dyn_recursive: &'static [u8] =
            Box::leak(build_x86_elf(3, 0, Some(b"/lib/bad_interp.so\0")).into_boxed_slice());

        let dirs: &'static [EmbeddedBootDirectory] = Box::leak(
            alloc::vec![
                EmbeddedBootDirectory::new("root", 0),
                EmbeddedBootDirectory::new("root/bin", 0),
                EmbeddedBootDirectory::new("root/lib", 0),
                EmbeddedBootDirectory::new("root/noexec", 0),
                EmbeddedBootDirectory::new("noexec_src", 0),
            ]
            .into_boxed_slice(),
        );
        let entries: &'static [EmbeddedBootFile] = Box::leak(
            alloc::vec![
                EmbeddedBootFile::new("root/lib/ld.so", interp_elf, 0),
                EmbeddedBootFile::new("root/lib/bad_interp.so", bad_recursive, 0),
                EmbeddedBootFile::new("root/bin/dyn_pie", dyn_pie, 0),
                EmbeddedBootFile::new("root/bin/dyn_missing", dyn_missing, 0),
                EmbeddedBootFile::new("root/bin/dyn_noexec", dyn_noexec, 0),
                EmbeddedBootFile::new("root/bin/dyn_recursive", dyn_recursive, 0),
                EmbeddedBootFile::new("noexec_src/ld.so", interp_elf, 0),
            ]
            .into_boxed_slice(),
        );
        let boot_fs = BootFs::new(EmbeddedBootFs::new(dirs, entries), BOOT_DEVICE);
        let host_ns =
            crate::Namespace::<UnsupportedStorage>::new(crate::MountTable::new(boot_fs, 8));
        let root_auth = ProcessAuthority::root();

        block_on(async {
            let entropy = triomphe::Arc::new(
                crate::RootEntropy::from_platform(
                    &TestCpu::with_entropy(0x33),
                    None,
                    None,
                    crate::MachineGeneration::new(None),
                )
                .expect("entropy"),
            );
            let container = Arc::new(
                LinuxContainer::create(
                    ContainerId::new(core::num::NonZeroU64::new(1).unwrap()),
                    &root_auth,
                    &host_ns,
                    ProcessAuthority::root(),
                    ContainerConfig {
                        root: ContainerMountSpec {
                            source_path: String::from("/root"),
                            target_path: String::from("/"),
                            rights: DirectoryAuthorityRights::READ
                                | DirectoryAuthorityRights::EXECUTE,
                            sharing: ContainerMountSharing::Shared,
                        },
                        mounts: alloc::vec![ContainerMountSpec {
                            source_path: String::from("/noexec_src"),
                            target_path: String::from("/noexec"),
                            rights: DirectoryAuthorityRights::READ,
                            sharing: ContainerMountSharing::Shared,
                        }],
                        shared_owner: SharedOwner { uid: 0, gid: 0 },
                        credentials: Credentials::root(),
                        hostname: UtsField::from_bytes(b"helios-dyn").unwrap(),
                        domainname: UtsField::from_bytes(b"").unwrap(),
                    },
                )
                .await
                .expect("create container"),
            );

            let state = Arc::new(spin::Mutex::new(DynState {
                steps: VecDeque::from(alloc::vec![
                    step_execve("/bin/dyn_missing"),
                    step_execve("/bin/dyn_noexec"),
                    step_execve("/bin/dyn_recursive"),
                    step_execve("/bin/dyn_pie"),
                    DynStep {
                        writes: Vec::new(),
                        regs: [SYS_EXIT_GROUP, 0, 0, 0, 0, 0, 0],
                    },
                ]),
                ..DynState::default()
            }));
            let cpu = DynCpu {
                base: TestCpu::with_entropy(0x33),
                state: state.clone(),
            };
            let runtime_state: HostRuntimeState<DynCpu, TestNetworkService, UnsupportedStorage> =
                crate::RuntimeState::new(
                    cpu.timebase(),
                    1,
                    0,
                    crate::BootPayload::for_tests(),
                    GuestIsa::for_build_target(cpu.native_feature_probe()),
                );
            runtime_state.install_root_entropy(entropy);
            let executor = crate::Executor::isolated(
                ProgressCounter::new(),
                crate::test_support::single_node_pool(1),
                ProcessorId::new(0),
            );
            let registry = crate::InstanceRegistry::new();
            let instance = registry.register("linux-dyn-execve", 0);
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
            let initial_exe =
                LinuxExecutable::load(&cpu, minimal_x86_64_elf()).expect("load initial static ELF");
            let (_stdin_tx, stdin_rx) = crate::byte_channel();
            let (stdout_tx, _stdout_rx) = crate::byte_channel();
            let (stderr_tx, _stderr_rx) = crate::byte_channel();
            let instance_spawner = executor
                .spawner(cpu.clone())
                .instance_spawner(crate::TaskFunding::Instance, &instance);
            let timeline = phases::Timeline::begin(&cpu, "spawn", "/linux/dyn-execve");
            let exit = Box::pin(run_linux_process(
                LinuxExecRuntime {
                    exec_context,
                    wasm: None,
                },
                ProgramArgv::launched("initial-static", Vec::new()),
                Vec::new(),
                container,
                Some(Credentials::root()),
                None,
                crate::InheritedSockets::new(),
                DescriptorOrigin::Fresh,
                WasixSignalState::new(),
                instance_spawner,
                instance,
                OutputMode::Child {
                    stdin_rx,
                    stdout_tx,
                    stderr_tx,
                },
                initial_exe,
                &timeline,
            ))
            .await
            .expect("run_linux_process");
            assert_eq!(exit.termination, ChildTermination::Exited(0));

            let st = state.lock();
            // Three failed execve attempts return exact Linux errnos without killing caller;
            // fourth execve succeeds into /bin/dyn_pie + /lib/ld.so!
            assert_eq!(st.results, alloc::vec![ENOENT_NEG, EACCES_NEG, ENOEXEC_NEG]);
            assert_eq!(st.auxvs.len(), 2);
            // Initial static image had AT_BASE == 0.
            assert_eq!(st.auxvs[0].get(&7), Some(&0));
            assert_eq!(st.auxvs[0].get(&8), Some(&0));
            // Post-execve dynamic PIE has AT_BASE != 0, AT_FLAGS == 0, AT_PHENT == 56,
            // AT_PHNUM == 4, AT_ENTRY != initial_pc (initial_pc == interpreter entry),
            // and AT_EXECFN == "/bin/dyn_pie".
            let dyn_auxv = &st.auxvs[1];
            let at_base = *dyn_auxv.get(&7).expect("AT_BASE");
            let at_entry = *dyn_auxv.get(&9).expect("AT_ENTRY");
            assert_ne!(at_base, 0);
            assert_eq!(dyn_auxv.get(&4), Some(&56));
            assert_eq!(dyn_auxv.get(&5), Some(&4));
            assert_eq!(dyn_auxv.get(&8), Some(&0));
            assert_ne!(at_entry, st.entries[1]);
            assert_eq!(st.entries[1], at_base + 0x1000);
            assert_eq!(st.execfns[1], "/bin/dyn_pie");
        });
    }
}
