//! End-to-end integration tests for `helios-inspector-shell`:
//! - Live `<Tab>` completion via `helios_nu::complete_async` + `AsyncReedlineCompleter`
//!   (commands, flags, downstream pipeline table columns, `/kernel/*` inspect paths,
//!   live instances/monikers, diagnostic targets, VFS paths)
//! - 150ms remote latency ceiling against a stalled guest
//! - 1.5s TTL completion cache deduplicating repeated `<Tab>` presses
//! - `helios nu -c '<pipeline>'`, `--local` host file I/O, `bundle`, and `fleet` commands.

use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use async_io::Async;
use helios_inspector_protocol::debugger::filesystem::{DirectoryEntry, EntryKind};
use helios_inspector_protocol::debugger::methods as dbg_methods;
use helios_inspector_protocol::system::{
    inspect::{
        ComponentPublication, Entry as InspectEntry, PublicationStatus, SnapshotResult,
        Value as InspectValue,
    },
    instances::Instance,
    methods as sys_methods,
    tracing::{Event as TraceEvent, Field as TraceField, Level as TraceLevel, Value as TraceValue},
};
use helios_inspector_protocol::wire::{Frame, read_frame, write_frame};
use helios_inspector_shell::completer::CompletionSnapshot;
use helios_inspector_shell::{
    AsyncReedlineCompleter, COMPLETION_CACHE_TTL, COMPLETION_REMOTE_TIMEOUT, HostEnv, OutputFormat,
    RemoteCompletionCache, eval_command, spawn_completion_worker,
};
use helios_nu::{CompletionKind, ShellSession};
use helios_ops::{Fleet, RpcConnection, Session, SessionOptions, Target};
use reedline::{Completer as _, CompletionResult, CompletionStatus};
use tempfile::TempDir;
use tokio::sync::RwLock;

struct MockGuestCounters {
    inspect_calls: AtomicUsize,
    instances_calls: AtomicUsize,
    list_calls: AtomicUsize,
}

impl Default for MockGuestCounters {
    fn default() -> Self {
        Self {
            inspect_calls: AtomicUsize::new(0),
            instances_calls: AtomicUsize::new(0),
            list_calls: AtomicUsize::new(0),
        }
    }
}

/// Spawn an in-process mock guest speaking the real `helios-inspector-protocol` wire framing.
fn spawn_mock_guest(
    delay: Duration,
) -> (Session, Arc<MockGuestCounters>, tokio::task::JoinHandle<()>) {
    let (host, guest) = UnixStream::pair().expect("create unix stream pair");
    host.set_nonblocking(true).expect("host nonblocking");
    guest.set_nonblocking(true).expect("guest nonblocking");

    let host_read = host.try_clone().expect("clone host read");
    let conn = RpcConnection::from_split(
        Box::new(Async::new(host_read).expect("register host read")),
        Box::new(Async::new(host).expect("register host write")),
    );
    let target = Target::new("test-vm", "serial:///tmp/test-vm.sock").expect("target");
    let session = Session::from_connection(target, conn, SessionOptions::default());

    let guest_read = guest.try_clone().expect("clone guest read");
    let mut reader = Async::new(guest_read).expect("register guest read");
    let mut writer = Async::new(guest).expect("register guest write");

    let counters = Arc::new(MockGuestCounters::default());
    let counters_clone = Arc::clone(&counters);

    let handle = tokio::spawn(async move {
        let mut active: std::collections::HashMap<u32, (String, String, Vec<u8>)> =
            std::collections::HashMap::new();
        while let Ok(Some(frame)) = read_frame(&mut reader).await {
            match frame {
                Frame::Open {
                    invocation,
                    instance,
                    func,
                } => {
                    active.insert(invocation, (instance, func, Vec::new()));
                    if write_frame(&mut writer, &Frame::Accept { invocation })
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Frame::Data {
                    invocation,
                    payload,
                    ..
                } => {
                    if let Some((_, _, buf)) = active.get_mut(&invocation) {
                        buf.extend_from_slice(&payload);
                    }
                }
                Frame::Close { invocation, path } if path.is_empty() => {
                    let Some((instance, func, payload)) = active.remove(&invocation) else {
                        continue;
                    };
                    if !delay.is_zero() {
                        tokio::time::sleep(delay).await;
                    }
                    let reply = dispatch_mock(&counters_clone, &instance, &func, &payload);
                    let _ = write_frame(
                        &mut writer,
                        &Frame::Data {
                            invocation,
                            path: Vec::new(),
                            payload: reply,
                        },
                    )
                    .await;
                    let _ = write_frame(
                        &mut writer,
                        &Frame::Close {
                            invocation,
                            path: Vec::new(),
                        },
                    )
                    .await;
                }
                _ => {}
            }
        }
    });

    (session, counters, handle)
}

fn dispatch_mock(
    counters: &MockGuestCounters,
    instance: &str,
    func: &str,
    payload: &[u8],
) -> Vec<u8> {
    match (instance, func) {
        (sys_methods::INSPECT_INSTANCE, sys_methods::INSPECT_SNAPSHOT) => {
            counters.inspect_calls.fetch_add(1, Ordering::SeqCst);
            let result: Result<
                SnapshotResult,
                helios_inspector_protocol::system::inspect::FilterError,
            > = Ok(SnapshotResult {
                timestamp: 123_456_789,
                truncated: false,
                publications: vec![ComponentPublication {
                    instance_id: 7,
                    instance_name: "http-client".to_owned(),
                    name: "state".to_owned(),
                    generation: 1,
                    status: PublicationStatus::Ok,
                }],
                entries: vec![
                    InspectEntry {
                        path: "/kernel/memory/total-bytes".to_owned(),
                        value: InspectValue::Unsigned64(2 * 1024 * 1024 * 1024),
                    },
                    InspectEntry {
                        path: "/kernel/memory/available-bytes".to_owned(),
                        value: InspectValue::Unsigned64(1024 * 1024 * 1024),
                    },
                    InspectEntry {
                        path: "/kernel/processors/online".to_owned(),
                        value: InspectValue::Unsigned64(4),
                    },
                    InspectEntry {
                        path: "/core/http-client/requests-total".to_owned(),
                        value: InspectValue::Unsigned64(42),
                    },
                ],
            });
            postcard::to_allocvec(&result).expect("encode inspect")
        }
        (sys_methods::INSTANCES_INSTANCE, sys_methods::INSTANCES_SNAPSHOT) => {
            counters.instances_calls.fetch_add(1, Ordering::SeqCst);
            let list = vec![
                Instance {
                    id: 1,
                    name: "init".to_owned(),
                    started_at: 100,
                    uptime: 5_000_000_000,
                    memory_bytes: 4 * 1024 * 1024,
                    cpu_busy: 12,
                },
                Instance {
                    id: 7,
                    name: "http-client".to_owned(),
                    started_at: 200,
                    uptime: 3_000_000_000,
                    memory_bytes: 8 * 1024 * 1024,
                    cpu_busy: 45,
                },
            ];
            postcard::to_allocvec(&list).expect("encode instances")
        }
        (sys_methods::TRACING_INSTANCE, sys_methods::TRACING_RECENT) => {
            let events: Result<
                Vec<TraceEvent>,
                helios_inspector_protocol::system::tracing::FilterError,
            > = Ok(vec![TraceEvent {
                timestamp: 1000,
                level: TraceLevel::Info,
                target: "helios_kernel::net::tcp".to_owned(),
                fields: vec![TraceField {
                    key: "message".to_owned(),
                    value: TraceValue::Text("link up".to_owned()),
                }],
            }]);
            postcard::to_allocvec(&events).expect("encode tracing")
        }
        (dbg_methods::FILESYSTEM_INSTANCE, "list") => {
            counters.list_calls.fetch_add(1, Ordering::SeqCst);
            #[derive(serde::Deserialize)]
            struct PathReq {
                path: String,
            }
            let req: PathReq = postcard::from_bytes(payload).expect("decode path");
            let entries = match req.path.as_str() {
                "/" => vec![
                    DirectoryEntry {
                        name: "bin".to_owned(),
                        kind: EntryKind::Directory,
                    },
                    DirectoryEntry {
                        name: "etc".to_owned(),
                        kind: EntryKind::Directory,
                    },
                ],
                "/bin" => vec![
                    DirectoryEntry {
                        name: "nu".to_owned(),
                        kind: EntryKind::File,
                    },
                    DirectoryEntry {
                        name: "ping".to_owned(),
                        kind: EntryKind::File,
                    },
                ],
                "/etc" => vec![DirectoryEntry {
                    name: "rc.nu".to_owned(),
                    kind: EntryKind::File,
                }],
                _ => Vec::new(),
            };
            postcard::to_allocvec(&entries).expect("encode list")
        }
        (dbg_methods::FILESYSTEM_INSTANCE, "read") => {
            let bytes = b"echo hello from guest\n".to_vec();
            postcard::to_allocvec(&bytes).expect("encode read")
        }
        (sys_methods::PROFILING_INSTANCE, sys_methods::PROFILING_METRICS) => {
            let res: Result<
                Vec<helios_inspector_protocol::system::profiling::MetricSample>,
                helios_inspector_protocol::system::profiling::FilterError,
            > = Ok(Vec::new());
            postcard::to_allocvec(&res).expect("encode metrics")
        }
        (sys_methods::PROFILING_INSTANCE, sys_methods::PROFILING_FOLDED) => {
            let res: Result<
                Vec<helios_inspector_protocol::system::profiling::FoldedSample>,
                helios_inspector_protocol::system::profiling::FilterError,
            > = Ok(Vec::new());
            postcard::to_allocvec(&res).expect("encode folded")
        }
        _ => postcard::to_allocvec(&()).expect("encode unit"),
    }
}

#[tokio::test]
async fn live_tab_completion_covers_commands_flags_columns_inspect_instances_vfs_and_cache() {
    let (session, counters, server_task) = spawn_mock_guest(Duration::ZERO);
    let cache = RemoteCompletionCache::new(COMPLETION_CACHE_TTL, COMPLETION_REMOTE_TIMEOUT);
    let env = HostEnv::with_cache(session, None, cache);
    let completion_env = env.for_completion();
    let nu_session = ShellSession::new(completion_env).await;

    // 1. Command names (Nushell builtins + host `fleet` / `bundle`)
    let cmds = nu_session.complete("fl", 2).await;
    assert!(
        cmds.iter()
            .any(|c| c.value == "fleet" && c.kind == CompletionKind::Command),
        "expected `fleet` command completion, got {cmds:?}"
    );
    let bundle_cmds = nu_session.complete("bun", 3).await;
    assert!(
        bundle_cmds.iter().any(|c| c.value == "bundle"),
        "expected `bundle` command completion, got {bundle_cmds:?}"
    );

    // 2. Flags (including host `--local` on `open`)
    let flags = nu_session.complete("open --", 7).await;
    assert!(
        flags
            .iter()
            .any(|f| f.value == "--local" && f.kind == CompletionKind::Flag),
        "expected `--local` flag completion on `open`, got {flags:?}"
    );

    // 3. Downstream pipeline Type::Table column names
    let ps_cols = nu_session.complete("ps | where ", 11).await;
    assert!(
        ps_cols
            .iter()
            .any(|c| c.value == "moniker" && c.kind == CompletionKind::Column),
        "expected `moniker` column after `ps | where `, got {ps_cols:?}"
    );
    let inspect_cols = nu_session.complete("inspect | select ", 17).await;
    assert!(
        inspect_cols
            .iter()
            .any(|c| c.value == "path" && c.kind == CompletionKind::Column),
        "expected `path` column after `inspect | select `, got {inspect_cols:?}"
    );

    // 4. Live `/kernel/*` & component inspect keys
    let started = Instant::now();
    let inspect_keys = nu_session.complete("inspect /kernel/m", 17).await;
    assert!(started.elapsed() < Duration::from_millis(150));
    assert!(
        inspect_keys.iter().any(
            |k| k.value == "/kernel/memory/total-bytes" && k.kind == CompletionKind::InspectKey
        ),
        "expected `/kernel/memory/total-bytes`, got {inspect_keys:?}"
    );
    // Repeat within 1.5s TTL must hit cache without a second RPC!
    let before_cached = counters.inspect_calls.load(Ordering::SeqCst);
    let inspect_keys_cached = nu_session.complete("inspect /kernel/p", 17).await;
    assert!(
        inspect_keys_cached
            .iter()
            .any(|k| k.value == "/kernel/processors/online")
    );
    assert_eq!(
        counters.inspect_calls.load(Ordering::SeqCst),
        before_cached,
        "1.5s TTL cache should satisfy repeat inspect completions without another RPC"
    );

    // 5. Live component monikers / instances
    let monikers = nu_session.complete("with-scope /h", 13).await;
    assert!(
        monikers
            .iter()
            .any(|m| m.value == "/http-client" && m.kind == CompletionKind::Moniker),
        "expected `/http-client` moniker completion, got {monikers:?}"
    );

    // 6. Live diagnostic targets (built-in + observed tracing targets)
    let diag_targets = nu_session
        .complete("with-instruction-profile --target helios_kernel::", 49)
        .await;
    assert!(
        diag_targets
            .iter()
            .any(|t| t.value == "helios_kernel::net::tcp"
                && t.kind == CompletionKind::DiagnosticTarget),
        "expected live tracing target completion, got {diag_targets:?}"
    );

    // 7. Live remote VFS paths
    let vfs_paths = nu_session.complete("ls /etc/", 8).await;
    assert!(
        vfs_paths
            .iter()
            .any(|p| p.value == "/etc/rc.nu" && p.kind == CompletionKind::Path),
        "expected `/etc/rc.nu` VFS path completion, got {vfs_paths:?}"
    );

    server_task.abort();
}

#[tokio::test]
async fn remote_completion_respects_150ms_bound_when_guest_stalls() {
    // Guest deliberately sleeps 2 seconds (> 150ms bound).
    let (session, _counters, server_task) = spawn_mock_guest(Duration::from_secs(2));
    let env = HostEnv::new(session, None).for_completion();
    let nu_session = ShellSession::new(env).await;

    let started = Instant::now();
    let items = nu_session.complete("inspect /kernel/", 16).await;
    let elapsed = started.elapsed();

    assert!(
        elapsed < Duration::from_millis(350),
        "remote completion exceeded 150ms bound (elapsed {elapsed:?})"
    );
    assert!(
        items.is_empty(),
        "stalled remote should return empty on cold miss"
    );

    server_task.abort();
}

#[tokio::test]
async fn async_reedline_completer_resolves_without_block_on() {
    let (session, _counters, server_task) = spawn_mock_guest(Duration::ZERO);
    let env = HostEnv::new(session, None).for_completion();
    let nu_session = ShellSession::new(env.clone()).await;

    let snapshot = Arc::new(RwLock::new(CompletionSnapshot {
        engine_state: nu_session.engine_state().clone(),
        stack: nu_session.stack().clone(),
    }));
    let (mut completer, req_rx, resp_tx) = AsyncReedlineCompleter::channel_pair();
    let worker = spawn_completion_worker(env, snapshot, req_rx, resp_tx, None);

    // First call returns Pending without blocking.
    let first = completer.complete("inspect /kernel/", 16);
    assert!(matches!(first, CompletionResult::Pending));

    // Poll until worker completes (no block_on anywhere).
    let deadline = Instant::now() + Duration::from_millis(500);
    while completer.poll_completion() != CompletionStatus::Ready {
        assert!(Instant::now() < deadline, "completion worker timed out");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    let fresh = completer.complete("inspect /kernel/", 16);
    match fresh {
        CompletionResult::Fresh { suggestions, .. } => {
            assert!(
                suggestions
                    .iter()
                    .any(|s| s.value == "/kernel/memory/total-bytes"),
                "expected fresh reedline suggestion for /kernel/memory/total-bytes, got {suggestions:?}"
            );
        }
        other => panic!("expected Fresh completion result, got {other:?}"),
    }

    worker.abort();
    server_task.abort();
}

#[tokio::test]
async fn eval_command_supports_pipelines_local_io_bundle_and_fleet() {
    let (session, _counters, server_task) = spawn_mock_guest(Duration::ZERO);
    let fleet = Fleet::from_sessions(vec![session.clone()], 2);
    let env = HostEnv::new(session, Some(fleet));

    // 1. Inline pipeline `-c` over live inspect + Nushell `where` + JSON output
    let json_out = eval_command(
        env.clone(),
        "inspect /kernel/ | where path == '/kernel/processors/online' | get value | first",
        OutputFormat::Json,
    )
    .await
    .expect("eval inspect pipeline");
    assert_eq!(json_out.trim(), "4");

    // 2. Host `--local` save & open round-trip
    let tmp = TempDir::new().expect("tempdir");
    let local_json = tmp.path().join("procs.json");
    let save_cmd = format!("ps | save --local --force '{}'", local_json.display());
    eval_command(env.clone(), &save_cmd, OutputFormat::Table)
        .await
        .expect("local save");
    let open_cmd = format!("open --local '{}' | length", local_json.display());
    let count = eval_command(env.clone(), &open_cmd, OutputFormat::Json)
        .await
        .expect("local open");
    assert_eq!(count.trim(), "2");

    // 3. Host `bundle` command writing `.tar.zst`
    let bundle_path = tmp.path().join("node.tar.zst");
    let bundle_cmd = format!("bundle '{}'", bundle_path.display());
    let bundle_out = eval_command(env.clone(), &bundle_cmd, OutputFormat::Json)
        .await
        .expect("bundle command");
    assert!(bundle_out.contains("test-vm"));
    assert!(bundle_path.exists());

    // 4. Host `fleet ps` command
    let fleet_out = eval_command(
        env,
        "fleet ps | where name == 'http-client' | get target | first",
        OutputFormat::Json,
    )
    .await
    .expect("fleet ps");
    assert_eq!(fleet_out.trim(), "\"test-vm\"");

    server_task.abort();
}

#[tokio::test]
async fn with_scope_enforces_monotonic_attenuation_and_blocks_escapes() {
    let (session, _counters, server_task) = spawn_mock_guest(Duration::ZERO);
    let env = HostEnv::new(session, None);

    let scoped_ok = eval_command(
        env.clone(),
        "with-scope /core/http-client { inspect /core/http-client | length }",
        OutputFormat::Json,
    )
    .await
    .expect("in-scope inspect succeeds");
    assert_eq!(scoped_ok.trim(), "1");

    let kernel_escape = eval_command(
        env.clone(),
        "with-scope /core/http-client { inspect /kernel/ }",
        OutputFormat::Json,
    )
    .await;
    assert!(
        kernel_escape.is_err(),
        "with-scope /core/http-client must deny `/kernel/` inspect, got {kernel_escape:?}"
    );

    let sibling_escape = eval_command(
        env.clone(),
        "with-scope /core/http-client { inspect /core/http-client-admin }",
        OutputFormat::Json,
    )
    .await;
    assert!(
        sibling_escape.is_err(),
        "with-scope must enforce path-segment boundaries, got {sibling_escape:?}"
    );

    let widen_escape = eval_command(
        env,
        "with-scope /core/http-client { with-scope / { inspect } }",
        OutputFormat::Json,
    )
    .await;
    assert!(
        widen_escape.is_err(),
        "nested with-scope must not widen back to `/`, got {widen_escape:?}"
    );

    server_task.abort();
}
