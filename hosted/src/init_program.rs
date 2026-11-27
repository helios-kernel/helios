#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::io;
    use std::path::PathBuf;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll, Waker};
    use std::time::Duration;

    use futures_io::{AsyncRead, AsyncWrite};
    use helios_hal::cpu::{Cpu, ProcessorId};
    use helios_hal::numa::SingleNode;
    use helios_hal::serial::ByteSerial;
    use helios_hal::{
        DeviceInventory, DmaModel, Platform, ProcessorStartupPolicy, ProcessorTopology,
    };
    use helios_inspector_protocol::auth::{
        AuthError, AuthPolicy, AuthProof, AuthPublicKey, CONSOLE_AUTH_REPLY_PATH, ClientIdentity,
        ConsoleLoginAuthReply, ConsoleLoginProof, DirectoryRightsMask, DirectoryRule,
        INSPECTOR_POLICY_PATH, ScopeRule, SessionGrants, TransportKind, client_handshake,
    };
    use helios_wit_rpc::Endpoint;
    use helios_wit_rpc::inspector::helios::system::{
        inspect as rpc_inspect,
        mounts::{self as rpc_mounts, MountErrorKind, MountRequest, MountSharing, MountSource},
        programs::{self as rpc_programs, ExecErrorKind, ExecRequest},
    };
    use helios_wit_rpc::inspector::wasi::filesystem::types::ErrorCode as RpcFsErrorCode;
    use helios_wit_rpc::inspector_fs::{self, FsRpcError};
    use helios_workspace_root::root_key::INSPECTOR_CLIENT_SECRET_FILE;

    use crate::config::DEFAULT_HEAP_BYTES;
    use crate::console::HostedConsole;
    use crate::cpu::{HostedCpu, detect_host_native_feature};
    use crate::net::HostedNetworkDevice;
    use crate::rtc::HostRtc;
    use crate::runtime::{HostedMachine, HostedStorage};

    type TestNetworkService = helios_kernel::NetworkService<HostedCpu, HostedNetworkDevice>;
    type TestRuntimeState =
        helios_kernel::HostRuntimeState<HostedCpu, TestNetworkService, HostedStorage>;

    static CAPTURED_SERIAL_OUT: Mutex<Vec<u8>> = Mutex::new(Vec::new());
    static CAPTURED_SERIAL_OUT_WAKER: Mutex<Option<Waker>> = Mutex::new(None);
    static CAPTURED_SERIAL_IN: Mutex<VecDeque<u8>> = Mutex::new(VecDeque::new());
    static TEST_DEBUG_CONSOLE: helios_kernel::DebugConsole = helios_kernel::DebugConsole::new();

    struct CapturedDebugPort;

    impl ByteSerial for CapturedDebugPort {
        fn try_read_byte(&self) -> Option<u8> {
            CAPTURED_SERIAL_IN.lock().unwrap().pop_front()
        }

        fn write_bytes(&self, bytes: &[u8]) {
            CAPTURED_SERIAL_OUT.lock().unwrap().extend_from_slice(bytes);
            if let Some(waker) = CAPTURED_SERIAL_OUT_WAKER.lock().unwrap().take() {
                waker.wake();
            }
        }

        fn enable_receive_interrupt(&self) {}

        fn disable_receive_interrupt(&self) {}
    }

    impl helios_kernel::DebugSerialAccess for CapturedDebugPort {
        type Port = Self;

        fn port() -> Self {
            Self
        }

        fn console() -> &'static helios_kernel::DebugConsole {
            &TEST_DEBUG_CONSOLE
        }
    }

    const CAPTURED_SERIAL_WRITER: helios_kernel::DebugSerialWriter =
        helios_kernel::DebugSerialWriter::of::<CapturedDebugPort>();

    fn read_captured_serial(buffer: &mut Vec<u8>, max_bytes: u32) {
        helios_kernel::read_debug_serial::<CapturedDebugPort>(buffer, max_bytes);
    }

    /// Async host-side reader draining guest output from `CAPTURED_SERIAL_OUT`
    /// starting at `cursor`.
    struct CapturedSerialReader {
        cursor: usize,
        closed: Arc<AtomicBool>,
    }

    impl AsyncRead for CapturedSerialReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            let out = CAPTURED_SERIAL_OUT.lock().unwrap();
            if self.cursor < out.len() {
                let avail = &out[self.cursor..];
                let count = avail.len().min(buf.len());
                buf[..count].copy_from_slice(&avail[..count]);
                drop(out);
                self.cursor += count;
                return Poll::Ready(Ok(count));
            }
            drop(out);
            if self.closed.load(Ordering::Acquire) {
                return Poll::Ready(Ok(0));
            }
            *CAPTURED_SERIAL_OUT_WAKER.lock().unwrap() = Some(cx.waker().clone());
            // Re-check after registering the waker to avoid lost wakeups.
            let out = CAPTURED_SERIAL_OUT.lock().unwrap();
            if self.cursor < out.len() {
                let avail = &out[self.cursor..];
                let count = avail.len().min(buf.len());
                buf[..count].copy_from_slice(&avail[..count]);
                drop(out);
                self.cursor += count;
                return Poll::Ready(Ok(count));
            }
            Poll::Pending
        }
    }

    /// Async host-side writer pushing bytes into `CAPTURED_SERIAL_IN` and
    /// waking the guest debug serial receiver immediately.
    struct CapturedSerialWriter;

    impl AsyncWrite for CapturedSerialWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            CAPTURED_SERIAL_IN
                .lock()
                .unwrap()
                .extend(buf.iter().copied());
            TEST_DEBUG_CONSOLE.receive_signal().notify_all();
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            TEST_DEBUG_CONSOLE.receive_signal().notify_all();
            Poll::Ready(Ok(()))
        }

        fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            TEST_DEBUG_CONSOLE.receive_signal().notify_all();
            Poll::Ready(Ok(()))
        }
    }

    fn test_bootfs_path() -> PathBuf {
        PathBuf::from(
            std::env::var_os("HELIOS_BOOTFS")
                .expect("HELIOS_BOOTFS must name the kernel-prebuild payload"),
        )
    }

    /// The payload `kernel-prebuild` wrote for this host, named in the
    /// `HELIOS_BOOTFS` path the Justfile exports for the test.
    fn test_payload() -> helios_kernel::BootPayload {
        let bootfs = test_bootfs_path();
        let bytes = std::fs::read(&bootfs)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", bootfs.display()));
        helios_kernel::BootPayload::parse(Box::leak(bytes.into_boxed_slice()))
            .unwrap_or_else(|error| panic!("{} is not a valid payload: {error}", bootfs.display()))
    }

    #[test]
    fn embedded_debugger_is_provisioned() {
        let payload = test_payload();
        let files = payload.bootfs().files();

        assert!(
            files.iter().all(|file| file.path() != "bin/debugger"),
            "legacy /bin/debugger must not be provisioned in bootfs"
        );

        for required in [
            "bin/inspector-host",
            "bin/inspector-tls",
            "bin/inspector-worker",
        ] {
            let entry = files
                .iter()
                .find(|file| file.path() == required)
                .unwrap_or_else(|| panic!("kernel prebuild bootfs must carry /{required}"));
            assert!(
                !entry.contents().is_empty(),
                "/{required} payload must not be empty"
            );
        }

        let policy_rel = INSPECTOR_POLICY_PATH.trim_start_matches('/');
        let policy_file = files
            .iter()
            .find(|file| file.path() == policy_rel)
            .unwrap_or_else(|| panic!("kernel prebuild bootfs must carry {INSPECTOR_POLICY_PATH}"));
        let policy = AuthPolicy::decode_postcard(policy_file.contents())
            .expect("staged inspector auth policy must decode cleanly");
        assert!(
            !policy.static_keys.is_empty() || !policy.trusted_cas.is_empty(),
            "staged inspector auth policy must authorize at least one credential"
        );

        let init = payload.embedded_init();
        assert_eq!(init.argv0(), "/init.wasm");
        assert!(
            !init.component().bytes().is_empty(),
            "embedded init component payload must not be empty"
        );
    }

    #[test]
    fn embedded_debugger_boots_alongside_payload_init() {
        CAPTURED_SERIAL_OUT.lock().unwrap().clear();
        *CAPTURED_SERIAL_OUT_WAKER.lock().unwrap() = None;
        CAPTURED_SERIAL_IN.lock().unwrap().clear();

        let bootfs_path = test_bootfs_path();
        let client_key_path = bootfs_path
            .parent()
            .expect("bootfs path has parent directory")
            .join(INSPECTOR_CLIENT_SECRET_FILE);
        let client_identity =
            ClientIdentity::from_seed_file(&client_key_path).unwrap_or_else(|e| {
                panic!(
                    "failed to load development inspector client key {}: {e}",
                    client_key_path.display()
                )
            });

        let bootstrap = ProcessorId::new(0);
        let machine = HostedMachine::new(1, bootstrap, DEFAULT_HEAP_BYTES);
        machine.register_thread(bootstrap, std::thread::current());
        let cpu = HostedCpu::new(bootstrap, machine.clone());

        helios_kernel::prime_bootstrap_allocator(
            machine.bootstrap_memory_regions(),
            &SingleNode::new(1),
            bootstrap,
        );
        let platform = Platform::new(HostedConsole::new(), cpu.clone())
            .with_topology(
                ProcessorTopology::start_all_secondaries(bootstrap, 1)
                    .with_startup_policy(ProcessorStartupPolicy::BootstrapOnly),
            )
            .with_dma_model(DmaModel::Translated)
            .with_devices(DeviceInventory::new().with_debug_serial());
        let kernel = helios_kernel::init(platform);
        cpu.install_timer(kernel.timer());

        let payload = test_payload();
        let debug_state: TestRuntimeState = helios_kernel::RuntimeState::new(
            machine.timebase(),
            1,
            machine.now().ticks(),
            payload,
            helios_kernel::GuestIsa::for_build_target(Some(detect_host_native_feature)),
        );
        let generation = helios_kernel::MachineGeneration::new(None);
        debug_state.install_machine_generation(generation.clone());
        debug_state.install_root_entropy(helios_kernel::seed_root_entropy(
            &cpu,
            None,
            None::<&helios_kernel::NoEntropyDevice>,
            generation,
        ));
        debug_state.seed_wall_clock(cpu.now().ticks(), &HostRtc);

        let service = helios_kernel::install_component_host_program_service(
            &kernel,
            &cpu,
            &debug_state,
            read_captured_serial,
            CAPTURED_SERIAL_WRITER,
        )
        .expect("bootstrap processor installs program service");

        let root_init = debug_state.embedded_init();
        let root_name = root_init.component().name().to_owned();
        let observed_inspector = Arc::new(AtomicBool::new(false));
        let observed_root = Arc::new(AtomicBool::new(false));
        let observed_components_inspect = Arc::new(AtomicBool::new(false));
        let observed_auth_rejected = Arc::new(AtomicBool::new(false));
        let observed_attenuated_rpc = Arc::new(AtomicBool::new(false));
        let observed_atomic_reply_roundtrip = Arc::new(AtomicBool::new(false));
        let observed_boot_preamble = Arc::new(Mutex::new(String::new()));

        let stop_timer = kernel.timer();
        let stop_state = debug_state.clone();
        let stop_cpu = cpu.clone();
        let stop_service = service.clone();
        let stop_observed_inspector = observed_inspector.clone();
        let stop_observed_root = observed_root.clone();
        let stop_observed_components_inspect = observed_components_inspect.clone();
        let stop_observed_auth_rejected = observed_auth_rejected.clone();
        let stop_observed_attenuated_rpc = observed_attenuated_rpc.clone();
        let stop_observed_atomic_reply_roundtrip = observed_atomic_reply_roundtrip.clone();
        let stop_observed_boot_preamble = observed_boot_preamble.clone();

        // Once the root supervisor completes init, spawns `/bin/inspector-host`,
        // and invokes `signal-ready` (emitting `[KDBG run:begin]`), verify:
        // 1. Live `/inspector` supervisor state and `/components/inspector/*` inspect entries;
        // 2. Unauthorized Ed25519 client is rejected over `TransportKind::Serial`;
        // 3. Authorized Ed25519 client requesting attenuated read-only grants succeeds,
        //    spawns `/bin/inspector-worker`, executes allowed WIT-RPC (`inspect` + WASI
        //    `read_file`), and is denied by kernel `ProcessAuthority` on disallowed
        //    operations (`write_file`, `mounts.mount`, `programs.exec`).
        kernel.spawn_local_detached(async move {
            let deadline = Duration::from_secs(30);
            let mut waited = Duration::ZERO;
            let ready_end_cursor = loop {
                assert!(
                    waited < deadline,
                    "timed out waiting for root supervisor readiness and inspector-host launch"
                );
                let marker_end = {
                    let bytes = CAPTURED_SERIAL_OUT.lock().unwrap();
                    let text = String::from_utf8_lossy(&bytes);
                    text.find("[KDBG run:begin]").map(|pos| {
                        let rest = &bytes[pos..];
                        let nl = rest.iter().position(|b| *b == b'\n').map_or(rest.len(), |i| i + 1);
                        (pos + nl, text[..pos + nl].to_owned())
                    })
                };
                if let Some((cursor, preamble)) = marker_end {
                    let now = stop_state.uptime_nanos(stop_cpu.now().ticks());
                    let instances = stop_state.instance_registry().snapshot(now);
                    if instances.iter().any(|inst| inst.name == root_name) {
                        stop_observed_root.store(true, Ordering::Release);
                    }
                    assert!(
                        instances.iter().all(|inst| inst.name != "debugger"),
                        "legacy `debugger` instance must never be spawned"
                    );
                    if let Some(host_inst) =
                        instances.iter().find(|inst| inst.name == "inspector-host")
                    {
                        stop_observed_inspector.store(true, Ordering::Release);
                        *stop_observed_boot_preamble.lock().unwrap() = preamble;

                        let prefixes = helios_kernel::PrefixSet::from_prefixes(["/components/"])
                            .expect("valid /components/ inspect prefix");
                        let inspect_snap = stop_state.inspect_registry().snapshot(
                            now,
                            host_inst.id,
                            Some(helios_kernel::AuthorityScope::Machine),
                            &stop_state.instance_registry(),
                            None,
                            None,
                            &prefixes,
                            0,
                        );
                        let has_inspector_running = inspect_snap.entries.iter().any(|entry| {
                            entry.path == "/components/inspector/state"
                                && matches!(
                                    &entry.value,
                                    helios_kernel::InspectValue::Text(s) if s == "running"
                                )
                        });
                        let has_inspector_id = inspect_snap.entries.iter().any(|entry| {
                            entry.path == "/components/inspector/instance_id"
                                && matches!(
                                    entry.value,
                                    helios_kernel::InspectValue::Unsigned64(id)
                                        if id == host_inst.id.raw()
                                )
                        });
                        let has_tls_unstarted = inspect_snap.entries.iter().any(|entry| {
                            entry.path == "/components/inspector/tls/state"
                                && matches!(
                                    &entry.value,
                                    helios_kernel::InspectValue::Text(s) if s == "unstarted"
                                )
                        });
                        let has_worker_unstarted = inspect_snap.entries.iter().any(|entry| {
                            entry.path == "/components/inspector/worker/state"
                                && matches!(
                                    &entry.value,
                                    helios_kernel::InspectValue::Text(s) if s == "unstarted"
                                )
                        });
                        let has_compiler_unstarted = inspect_snap.entries.iter().any(|entry| {
                            entry.path == "/components/plugins/compiler/state"
                                && matches!(
                                    &entry.value,
                                    helios_kernel::InspectValue::Text(s) if s == "unstarted"
                                )
                        });
                        if has_inspector_running
                            && has_inspector_id
                            && has_tls_unstarted
                            && has_worker_unstarted
                            && has_compiler_unstarted
                        {
                            stop_observed_components_inspect.store(true, Ordering::Release);
                        }
                        break (cursor, host_inst.id);
                    }
                }
                stop_timer.sleep_for(Duration::from_millis(5)).await;
                waited += Duration::from_millis(5);
            };

            let (cursor, host_inst_id) = ready_end_cursor;
            let closed = Arc::new(AtomicBool::new(false));
            let mut serial_read = CapturedSerialReader {
                cursor,
                closed: Arc::clone(&closed),
            };
            let mut serial_write = CapturedSerialWriter;

            // Step 1: Forged / unauthorized Ed25519 key MUST be rejected by `inspector-host`.
            let bogus_identity = ClientIdentity::from_static_seed([0xee; 32]);
            let rejected = client_handshake(
                &mut serial_read,
                &mut serial_write,
                TransportKind::Serial,
                &bogus_identity,
                None,
                None,
                None,
            )
            .await;
            assert!(
                matches!(rejected, Err(AuthError::Rejected { .. })),
                "unauthorized client key must be rejected, got: {rejected:?}"
            );
            stop_observed_auth_rejected.store(true, Ordering::Release);

            // Step 2: Authorized Ed25519 key requesting strictly attenuated read-only grants
            // (`inspect_read: Machine` + `/` read-only; NO write, NO mount, NO process exec).
            let mut narrow_grants = SessionGrants::empty();
            narrow_grants.inspect_read = Some(ScopeRule::Machine);
            narrow_grants.directories.push(DirectoryRule {
                source_path: "/".to_owned(),
                guest_name: "/".to_owned(),
                rights: DirectoryRightsMask::READ,
            });
            let attenuated_identity = client_identity
                .with_attenuated_grants(narrow_grants, None, None, None)
                .expect("attenuating client identity succeeds");
            let (_hello, granted, _session_id) = client_handshake(
                &mut serial_read,
                &mut serial_write,
                TransportKind::Serial,
                &attenuated_identity,
                None,
                None,
                None,
            )
            .await
            .expect("authorized attenuated client handshake must succeed");
            assert_eq!(granted.inspect_read, Some(ScopeRule::Machine));
            assert!(granted.mount.is_empty());
            assert!(granted.process.is_empty());

            // Step 3: Drive live `helios-wit-rpc` straight to the spawned `inspector-worker`.
            let endpoint = Endpoint::new(serial_read, serial_write, ());
            let peer = endpoint.handle();
            let rpc_checks = async {
                // 3a. Allowed: `helios:system/inspect.snapshot`
                let snap = rpc_inspect::RpcClient::new(peer.clone())
                    .snapshot(
                        rpc_inspect::Query {
                            prefixes: vec!["/kernel/clock".to_owned(), "/components/".to_owned()],
                        },
                        64,
                    )
                    .await
                    .expect("inspect RPC succeeds")
                    .expect("inspect query accepted");
                assert!(
                    snap.entries
                        .iter()
                        .any(|e| e.path == "/components/inspector/state"),
                    "live inspect snapshot must expose /components/inspector/state"
                );

                // 3b. Allowed: WASI Preview 3 read-only file access via `inspector_fs::read_file`
                let init_txt = inspector_fs::read_file(&peer, "/init.txt")
                    .await
                    .expect("read-only WASI preopen must read /init.txt");
                assert!(
                    String::from_utf8_lossy(&init_txt).contains("Helios init loaded from bootfs."),
                    "unexpected /init.txt contents"
                );

                // 3c. Denied by kernel `ProcessAuthority`: WASI file write on read-only preopen
                let write_err = inspector_fs::write_file(&peer, "/denied.txt", b"nope", false)
                    .await
                    .expect_err("write on read-only worker authority must be denied by kernel");
                assert!(
                    matches!(write_err, FsRpcError::Fs { .. }),
                    "expected kernel WASI filesystem permission error, got: {write_err:?}"
                );

                // 3d. Denied by kernel `ProcessAuthority`: `helios:system/mounts.mount`
                let mount_res = rpc_mounts::RpcClient::new(peer.clone())
                    .mount(MountRequest {
                        source: MountSource::Memory,
                        path: "/tmp".to_owned(),
                        read_only: false,
                        sharing: MountSharing::Private,
                        compress: None,
                        commit: None,
                        max_inline: None,
                    })
                    .await
                    .expect("mounts.mount RPC wire call completes");
                assert!(
                    matches!(mount_res, Err(ref err) if err.kind == MountErrorKind::PermissionDenied),
                    "worker without mount grant must receive PermissionDenied from kernel, got: {mount_res:?}"
                );

                // 3e. Denied by kernel `ProcessAuthority`: `helios:system/programs.exec`
                let exec_res = rpc_programs::RpcClient::new(peer.clone())
                    .exec(ExecRequest {
                        name: "denied".to_owned(),
                        args: Vec::new(),
                        env: Vec::new(),
                        path: "/bin/inspector-worker".to_owned(),
                        cwd: None,
                        stdin: Vec::new(),
                        hint: None,
                        capability_grants: Vec::new(),
                    })
                    .await
                    .expect("programs.exec RPC wire call completes");
                assert!(
                    matches!(exec_res, Err(ref err) if err.kind == ExecErrorKind::PermissionDenied),
                    "worker without process grant must receive PermissionDenied from kernel, got: {exec_res:?}"
                );
            };
            let drive_fut = async {
                let res = endpoint.drive().await;
                panic!("RPC endpoint terminated before checks finished: {res:?}");
            };
            futures_lite::future::or(rpc_checks, drive_fut).await;

            stop_observed_attenuated_rpc.store(true, Ordering::Release);

            // End the read-only worker so `inspector-host::run_serial_loop`
            // accepts a second full-authority session over the same debug port.
            drop(peer);
            let residency = helios_kernel::UserResidency::default();
            {
                let now = stop_state.uptime_nanos(stop_cpu.now().ticks());
                for inst in stop_state.instance_registry().snapshot(now) {
                    if inst.name.starts_with("inspector-worker-") {
                        let _ = stop_state.instance_registry().request_kill(
                            inst.id,
                            helios_kernel::KillReason::Operator,
                            now,
                            &residency,
                        );
                        stop_service.interrupt_instance(inst.id);
                    }
                }
            }
            CAPTURED_SERIAL_IN.lock().unwrap().push_back(0);
            TEST_DEBUG_CONSOLE.receive_signal().notify_all();
            for _ in 0..400 {
                let now = stop_state.uptime_nanos(stop_cpu.now().ticks());
                let still_running = stop_state
                    .instance_registry()
                    .snapshot(now)
                    .iter()
                    .any(|inst| inst.name.starts_with("inspector-worker-"));
                if !still_running {
                    break;
                }
                stop_timer.sleep_for(Duration::from_millis(5)).await;
            }
            CAPTURED_SERIAL_IN.lock().unwrap().clear();

            // Step 4: Full-authority session verifying live `inspector_fs`
            // atomic stage-and-rename delivery of `ConsoleLoginAuthReply` on
            // `/run` tmpfs through real `inspector-worker` + `helios-kernel`.
            let full_cursor = CAPTURED_SERIAL_OUT.lock().unwrap().len();
            let mut full_serial_read = CapturedSerialReader {
                cursor: full_cursor,
                closed: Arc::clone(&closed),
            };
            let mut full_serial_write = CapturedSerialWriter;
            let (_full_hello, _full_granted, _full_session_id) = client_handshake(
                &mut full_serial_read,
                &mut full_serial_write,
                TransportKind::Serial,
                &client_identity,
                None,
                None,
                None,
            )
            .await
            .expect("full-authority serial handshake must succeed");

            let full_endpoint = Endpoint::new(full_serial_read, full_serial_write, ());
            let full_peer = full_endpoint.handle();
            let reply_roundtrip = async {
                let expected_reply = ConsoleLoginAuthReply::Approved(ConsoleLoginProof {
                    request_id: 1,
                    username: "lexo".to_owned(),
                    public_key: AuthPublicKey::Ed25519([0x21; 32]),
                    proof: AuthProof::Ed25519([0x42; 64]),
                });
                let encoded = expected_reply
                    .encode_postcard()
                    .expect("encode ConsoleLoginAuthReply");
                let staging_path = "/run/console-auth/.reply-1.tmp";

                inspector_fs::mkdir(&full_peer, "/run/console-auth")
                    .await
                    .expect("mkdir /run/console-auth on /run tmpfs");
                inspector_fs::write_file(&full_peer, staging_path, &encoded, false)
                    .await
                    .expect("stage ConsoleLoginAuthReply bytes via write_via_stream");

                // Final reply path must not exist while only the staging file was written.
                let pre_rename = inspector_fs::stat(&full_peer, CONSOLE_AUTH_REPLY_PATH).await;
                assert!(
                    matches!(
                        pre_rename,
                        Err(FsRpcError::Fs {
                            code: RpcFsErrorCode::NoEntry,
                            ..
                        })
                    ),
                    "final reply path must not exist before atomic rename, got: {pre_rename:?}"
                );

                inspector_fs::rename(&full_peer, staging_path, CONSOLE_AUTH_REPLY_PATH)
                    .await
                    .expect("atomic rename of staged reply into reply.postcard");

                let read_back = inspector_fs::read_file(&full_peer, CONSOLE_AUTH_REPLY_PATH)
                    .await
                    .expect("read published reply.postcard");
                assert_eq!(
                    read_back, encoded,
                    "write_via_stream + rename must preserve every byte without truncation"
                );
                let decoded = ConsoleLoginAuthReply::decode_postcard(&read_back)
                    .expect("published reply.postcard must decode cleanly");
                assert_eq!(decoded, expected_reply);

                let post_rename_stage = inspector_fs::stat(&full_peer, staging_path).await;
                assert!(
                    matches!(
                        post_rename_stage,
                        Err(FsRpcError::Fs {
                            code: RpcFsErrorCode::NoEntry,
                            ..
                        })
                    ),
                    "staging file must be gone after rename, got: {post_rename_stage:?}"
                );
            };
            let full_drive_fut = async {
                let res = full_endpoint.drive().await;
                panic!("full-authority RPC endpoint terminated before checks finished: {res:?}");
            };
            futures_lite::future::or(reply_roundtrip, full_drive_fut).await;

            stop_observed_atomic_reply_roundtrip.store(true, Ordering::Release);

            // Cleanly tear down worker + inspector-host so `run_root_component_once` exits.
            closed.store(true, Ordering::Release);
            if let Some(waker) = CAPTURED_SERIAL_OUT_WAKER.lock().unwrap().take() {
                waker.wake();
            }
            drop(full_peer);
            let now = stop_state.uptime_nanos(stop_cpu.now().ticks());
            for inst in stop_state.instance_registry().snapshot(now) {
                if inst.id == host_inst_id || inst.name.starts_with("inspector-worker-") {
                    let _ = stop_state.instance_registry().request_kill(
                        inst.id,
                        helios_kernel::KillReason::Operator,
                        now,
                        &residency,
                    );
                    stop_service.interrupt_instance(inst.id);
                }
            }
            CAPTURED_SERIAL_IN.lock().unwrap().push_back(0);
            TEST_DEBUG_CONSOLE.receive_signal().notify_all();
        });

        helios_kernel::run_root_component_once(
            root_init,
            cpu,
            &kernel,
            debug_state,
            read_captured_serial,
            CAPTURED_SERIAL_WRITER,
        )
        .expect("root supervisor component must boot and exit cleanly");

        assert!(
            observed_root.load(Ordering::Acquire),
            "root supervisor component instance must be live at readiness"
        );
        assert!(
            observed_inspector.load(Ordering::Acquire),
            "root supervisor must spawn /bin/inspector-host before signaling ready"
        );
        assert!(
            observed_components_inspect.load(Ordering::Acquire),
            "root component-manager must publish live /components/inspector/* state via helios:system/inspect"
        );
        assert!(
            observed_auth_rejected.load(Ordering::Acquire),
            "inspector-host must reject unauthorized Ed25519 credentials over serial"
        );
        assert!(
            observed_attenuated_rpc.load(Ordering::Acquire),
            "attenuated inspector-worker session must enforce kernel ProcessAuthority end to end"
        );
        assert!(
            observed_atomic_reply_roundtrip.load(Ordering::Acquire),
            "full-authority inspector-worker session must write and atomically rename ConsoleLoginAuthReply on /run tmpfs"
        );

        let output = observed_boot_preamble.lock().unwrap().clone();
        assert!(
            output
                .lines()
                .any(|line| line == "helios init: online root=/"),
            "root supervisor must emit its online banner, got:\n{output}"
        );
        assert!(
            output.lines().any(|line| line == "file init.txt"),
            "root supervisor must list root bootfs entries, got:\n{output}"
        );
        let init_txt_pos = output
            .find("Helios init loaded from bootfs.")
            .unwrap_or_else(|| panic!("root supervisor must print /init.txt, got:\n{output}"));
        let ready_pos = output.find("[KDBG run:begin]").unwrap_or_else(|| {
            panic!("root supervisor must emit [KDBG run:begin], got:\n{output}")
        });
        assert!(
            init_txt_pos < ready_pos,
            "boot-readiness marker must follow init banner output, got:\n{output}"
        );
    }
}
