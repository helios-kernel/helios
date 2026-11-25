//! End-to-end integration tests for `helios-inspector-shell` over `helios-wit-rpc`
//! (zero `helios:debugger/*`):
//! - Live `<Tab>` completion via `helios_nu::complete_async` + `AsyncReedlineCompleter`
//!   (commands, flags, downstream pipeline table columns, `/kernel/*` inspect paths,
//!   live instances/monikers, diagnostic targets, VFS paths over `wasi:filesystem`)
//! - 150ms remote latency ceiling against a stalled guest
//! - 1.5s TTL completion cache deduplicating repeated `<Tab>` presses
//! - `helios nu -c '<pipeline>'`, `--local` host file I/O, `bundle`, and `fleet` commands.

use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use async_io::Async;
use helios_inspector_shell::completer::CompletionSnapshot;
use helios_inspector_shell::{
    AsyncReedlineCompleter, COMPLETION_CACHE_TTL, COMPLETION_REMOTE_TIMEOUT, HostEnv, OutputFormat,
    RemoteCompletionCache, eval_command, spawn_completion_worker,
};
use helios_nu::{CompletionKind, ShellSession};
use helios_ops::{Fleet, RpcConnection, Session, SessionOptions, Target};
use helios_wit_rpc::inspector::helios::system::{
    filters::FilterError,
    inspect::{
        self as rpc_inspect, ComponentPublication, Entry as InspectEntry, PublicationStatus, Query,
        SnapshotResult, Value as InspectValue,
    },
    instances::{self as rpc_instances, Instance},
    profiling::{
        self as rpc_profiling, Filter as ProfileFilter, FoldedSample, MetricFilter, MetricSample,
    },
    tracing::{
        self as rpc_tracing, Event as TraceEvent, Field as TraceField, Level as TraceLevel,
        Value as TraceValue,
    },
};
use helios_wit_rpc::inspector::wasi::filesystem::{
    preopens as rpc_preopens,
    types::{
        self as rpc_fs, Advice, DescriptorFlags, DescriptorStat, DescriptorType, DirectoryEntry,
        ErrorCode, Filesize, MetadataHashValue, NewTimestamp, OpenFlags, PathFlags,
    },
};
use helios_wit_rpc::{
    Dispatcher, Endpoint, FutureReader, ResourceEntry, ResourceSlotAccess, ServerInvocation,
    StreamReader, WireError, future as rpc_future, stream as rpc_stream,
};
use reedline::{Completer as _, CompletionResult, CompletionStatus};
use tempfile::TempDir;
use tokio::sync::RwLock;

#[derive(Default)]
struct MockGuestCounters {
    inspect_calls: AtomicUsize,
    instances_calls: AtomicUsize,
    list_calls: AtomicUsize,
}

#[derive(Clone)]
struct MockDirHandle {
    path: String,
}

enum MockResource {
    Dir(Arc<MockDirHandle>),
    Pub(Arc<()>),
    Sampling(Arc<()>),
}

impl ResourceEntry for MockResource {
    fn kind_name(&self) -> &'static str {
        match self {
            Self::Dir(_) => "descriptor",
            Self::Pub(_) => "publication",
            Self::Sampling(_) => "sampling-session",
        }
    }
}

impl ResourceSlotAccess<rpc_fs::Descriptor, MockDirHandle> for MockResource {
    fn into_entry(arc: Arc<MockDirHandle>) -> Self {
        Self::Dir(arc)
    }
    fn borrow_entry(&self) -> Option<&Arc<MockDirHandle>> {
        match self {
            Self::Dir(d) => Some(d),
            _ => None,
        }
    }
    fn take_entry(self) -> Result<Arc<MockDirHandle>, Self> {
        match self {
            Self::Dir(d) => Ok(d),
            other => Err(other),
        }
    }
}

impl ResourceSlotAccess<rpc_inspect::Publication, ()> for MockResource {
    fn into_entry(arc: Arc<()>) -> Self {
        Self::Pub(arc)
    }
    fn borrow_entry(&self) -> Option<&Arc<()>> {
        match self {
            Self::Pub(p) => Some(p),
            _ => None,
        }
    }
    fn take_entry(self) -> Result<Arc<()>, Self> {
        match self {
            Self::Pub(p) => Ok(p),
            other => Err(other),
        }
    }
}

impl ResourceSlotAccess<rpc_profiling::SamplingSession, ()> for MockResource {
    fn into_entry(arc: Arc<()>) -> Self {
        Self::Sampling(arc)
    }
    fn borrow_entry(&self) -> Option<&Arc<()>> {
        match self {
            Self::Sampling(s) => Some(s),
            _ => None,
        }
    }
    fn take_entry(self) -> Result<Arc<()>, Self> {
        match self {
            Self::Sampling(s) => Ok(s),
            other => Err(other),
        }
    }
}

struct MockInspect {
    counters: Arc<MockGuestCounters>,
    delay: Duration,
}

impl rpc_inspect::RpcHandler for MockInspect {
    type Publication = ();

    async fn publish(
        &self,
        _name: String,
        _span: helios_wit_rpc::inspector::helios::system::memory::Span,
    ) -> Result<Self::Publication, rpc_inspect::PublishError> {
        Ok(())
    }

    async fn snapshot(&self, _query: Query, _limit: u32) -> Result<SnapshotResult, FilterError> {
        if !self.delay.is_zero() {
            tokio::time::sleep(self.delay).await;
        }
        self.counters.inspect_calls.fetch_add(1, Ordering::SeqCst);
        Ok(SnapshotResult {
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
        })
    }
}

struct MockInstances {
    counters: Arc<MockGuestCounters>,
    delay: Duration,
}

impl rpc_instances::RpcHandler for MockInstances {
    async fn snapshot(&self) -> Vec<Instance> {
        if !self.delay.is_zero() {
            tokio::time::sleep(self.delay).await;
        }
        self.counters.instances_calls.fetch_add(1, Ordering::SeqCst);
        vec![
            Instance {
                id: 1,
                name: "init".to_owned(),
                started_at: 100,
                uptime: 5_000_000_000,
                memory_bytes: 4 * 1024 * 1024,
                storage_bytes: 0,
                cpu_busy: 12,
            },
            Instance {
                id: 7,
                name: "http-client".to_owned(),
                started_at: 200,
                uptime: 3_000_000_000,
                memory_bytes: 8 * 1024 * 1024,
                storage_bytes: 0,
                cpu_busy: 45,
            },
        ]
    }

    async fn kill(&self, _id: u64) -> Result<(), rpc_instances::KillError> {
        Ok(())
    }
}

struct MockTracing;

impl rpc_tracing::RpcHandler for MockTracing {
    async fn recent(
        &self,
        _filter: rpc_tracing::Filter,
        _limit: u32,
    ) -> Result<Vec<TraceEvent>, FilterError> {
        Ok(vec![TraceEvent {
            timestamp: 1000,
            level: TraceLevel::Info,
            target: "helios_kernel::net::tcp".to_owned(),
            fields: vec![TraceField {
                key: "message".to_owned(),
                value: TraceValue::Text("link up".to_owned()),
            }],
        }])
    }

    async fn subscribe(
        &self,
        _filter: rpc_tracing::Filter,
    ) -> Result<StreamReader<TraceEvent>, FilterError> {
        let (_tx, rx) = rpc_stream();
        Ok(rx)
    }

    async fn set_target_enabled(
        &self,
        _target: String,
        _enabled: bool,
    ) -> Result<(), rpc_tracing::TargetError> {
        Ok(())
    }
}

struct MockProfiling;

impl rpc_profiling::RpcHandler for MockProfiling {
    type SamplingSession = ();

    async fn set_enabled(&self, _enabled: bool) -> Result<(), rpc_profiling::ControlError> {
        Ok(())
    }

    async fn clear(&self) -> Result<(), rpc_profiling::ControlError> {
        Ok(())
    }

    async fn folded(
        &self,
        _filter: ProfileFilter,
        _limit: u32,
    ) -> Result<Vec<FoldedSample>, FilterError> {
        Ok(Vec::new())
    }

    async fn metrics(
        &self,
        _filter: MetricFilter,
        _limit: u32,
    ) -> Result<Vec<MetricSample>, FilterError> {
        Ok(Vec::new())
    }

    async fn start_instruction_sampling(
        &self,
    ) -> Result<Self::SamplingSession, rpc_profiling::InstructionProfileError> {
        Ok(())
    }

    async fn instruction_samples(
        &self,
    ) -> Result<rpc_profiling::InstructionProfile, rpc_profiling::InstructionProfileError> {
        Ok(rpc_profiling::InstructionProfile {
            period_nanos: 1_000,
            kernel_image_base: 0,
            samples: Vec::new(),
            dropped: 0,
        })
    }

    async fn raw_profile_size(&self) -> Result<u64, rpc_profiling::RawProfileError> {
        Ok(0)
    }

    async fn raw_profile_read(
        &self,
        _offset: u64,
        _len: u32,
    ) -> Result<Vec<u8>, rpc_profiling::RawProfileError> {
        Ok(Vec::new())
    }
}

struct MockPreopens;

impl rpc_preopens::RpcHandler for MockPreopens {
    type Descriptor = MockDirHandle;

    async fn get_directories(&self) -> Vec<(Self::Descriptor, String)> {
        vec![(
            MockDirHandle {
                path: "/".to_owned(),
            },
            "/".to_owned(),
        )]
    }
}

struct MockFs {
    counters: Arc<MockGuestCounters>,
}

fn join_mock_path(base: &str, rel: &str) -> String {
    let rel = rel.trim_matches('/');
    if rel.is_empty() {
        base.to_owned()
    } else if base == "/" {
        format!("/{rel}")
    } else {
        format!("{base}/{rel}")
    }
}

fn mock_stat(ty: DescriptorType, size: u64) -> DescriptorStat {
    DescriptorStat {
        r#type: ty,
        link_count: 1,
        size,
        data_access_timestamp: None,
        data_modification_timestamp: None,
        status_change_timestamp: None,
    }
}

impl rpc_fs::RpcHandler for MockFs {
    type Descriptor = MockDirHandle;

    async fn descriptor_read_via_stream(
        &self,
        _self_: &Self::Descriptor,
        _offset: Filesize,
    ) -> (StreamReader<u8>, FutureReader<Result<(), ErrorCode>>) {
        let (mut tx, rx) = rpc_stream::<u8>();
        let (ftx, frx) = rpc_future::<Result<(), ErrorCode>>();
        tokio::spawn(async move {
            let _ = tx.send_batch(b"echo hello from guest\n".to_vec()).await;
            let _ = tx.close().await;
            let _ = ftx.resolve(Ok(())).await;
        });
        (rx, frx)
    }

    async fn descriptor_write_via_stream(
        &self,
        _self_: &Self::Descriptor,
        mut data: StreamReader<u8>,
        _offset: Filesize,
    ) -> FutureReader<Result<(), ErrorCode>> {
        let (ftx, frx) = rpc_future::<Result<(), ErrorCode>>();
        tokio::spawn(async move {
            while let Ok(Some(_)) = data.next_batch().await {}
            let _ = ftx.resolve(Ok(())).await;
        });
        frx
    }

    async fn descriptor_append_via_stream(
        &self,
        _self_: &Self::Descriptor,
        mut data: StreamReader<u8>,
    ) -> FutureReader<Result<(), ErrorCode>> {
        let (ftx, frx) = rpc_future::<Result<(), ErrorCode>>();
        tokio::spawn(async move {
            while let Ok(Some(_)) = data.next_batch().await {}
            let _ = ftx.resolve(Ok(())).await;
        });
        frx
    }

    async fn descriptor_advise(
        &self,
        _self_: &Self::Descriptor,
        _offset: Filesize,
        _length: Filesize,
        _advice: Advice,
    ) -> Result<(), ErrorCode> {
        Ok(())
    }

    async fn descriptor_sync_data(&self, _self_: &Self::Descriptor) -> Result<(), ErrorCode> {
        Ok(())
    }

    async fn descriptor_get_flags(
        &self,
        _self_: &Self::Descriptor,
    ) -> Result<DescriptorFlags, ErrorCode> {
        Ok(DescriptorFlags::READ)
    }

    async fn descriptor_get_type(
        &self,
        _self_: &Self::Descriptor,
    ) -> Result<DescriptorType, ErrorCode> {
        Ok(DescriptorType::Directory)
    }

    async fn descriptor_set_size(
        &self,
        _self_: &Self::Descriptor,
        _size: Filesize,
    ) -> Result<(), ErrorCode> {
        Ok(())
    }

    async fn descriptor_set_times(
        &self,
        _self_: &Self::Descriptor,
        _data_access_timestamp: NewTimestamp,
        _data_modification_timestamp: NewTimestamp,
    ) -> Result<(), ErrorCode> {
        Ok(())
    }

    async fn descriptor_read_directory(
        &self,
        self_: &Self::Descriptor,
    ) -> (
        StreamReader<DirectoryEntry>,
        FutureReader<Result<(), ErrorCode>>,
    ) {
        self.counters.list_calls.fetch_add(1, Ordering::SeqCst);
        let entries = match self_.path.as_str() {
            "/" => vec![
                DirectoryEntry {
                    r#type: DescriptorType::Directory,
                    name: "bin".to_owned(),
                },
                DirectoryEntry {
                    r#type: DescriptorType::Directory,
                    name: "etc".to_owned(),
                },
            ],
            "/bin" => vec![
                DirectoryEntry {
                    r#type: DescriptorType::RegularFile,
                    name: "nu".to_owned(),
                },
                DirectoryEntry {
                    r#type: DescriptorType::RegularFile,
                    name: "ping".to_owned(),
                },
            ],
            "/etc" => vec![DirectoryEntry {
                r#type: DescriptorType::RegularFile,
                name: "rc.nu".to_owned(),
            }],
            _ => Vec::new(),
        };
        let (mut tx, rx) = rpc_stream::<DirectoryEntry>();
        let (ftx, frx) = rpc_future::<Result<(), ErrorCode>>();
        tokio::spawn(async move {
            if !entries.is_empty() {
                let _ = tx.send_batch(entries).await;
            }
            let _ = tx.close().await;
            let _ = ftx.resolve(Ok(())).await;
        });
        (rx, frx)
    }

    async fn descriptor_sync(&self, _self_: &Self::Descriptor) -> Result<(), ErrorCode> {
        Ok(())
    }

    async fn descriptor_create_directory_at(
        &self,
        _self_: &Self::Descriptor,
        _path: String,
    ) -> Result<(), ErrorCode> {
        Ok(())
    }

    async fn descriptor_stat(
        &self,
        _self_: &Self::Descriptor,
    ) -> Result<DescriptorStat, ErrorCode> {
        Ok(mock_stat(DescriptorType::Directory, 0))
    }

    async fn descriptor_stat_at(
        &self,
        self_: &Self::Descriptor,
        _path_flags: PathFlags,
        path: String,
    ) -> Result<DescriptorStat, ErrorCode> {
        let full = join_mock_path(&self_.path, &path);
        match full.as_str() {
            "/" | "/bin" | "/etc" => Ok(mock_stat(DescriptorType::Directory, 0)),
            "/bin/nu" | "/bin/ping" | "/etc/rc.nu" => {
                Ok(mock_stat(DescriptorType::RegularFile, 22))
            }
            _ => Err(ErrorCode::NoEntry),
        }
    }

    async fn descriptor_set_times_at(
        &self,
        _self_: &Self::Descriptor,
        _path_flags: PathFlags,
        _path: String,
        _data_access_timestamp: NewTimestamp,
        _data_modification_timestamp: NewTimestamp,
    ) -> Result<(), ErrorCode> {
        Ok(())
    }

    async fn descriptor_link_at(
        &self,
        _self_: &Self::Descriptor,
        _old_path_flags: PathFlags,
        _old_path: String,
        _new_descriptor: &Self::Descriptor,
        _new_path: String,
    ) -> Result<(), ErrorCode> {
        Ok(())
    }

    async fn descriptor_open_at(
        &self,
        self_: &Self::Descriptor,
        _path_flags: PathFlags,
        path: String,
        _open_flags: OpenFlags,
        _flags: DescriptorFlags,
    ) -> Result<Self::Descriptor, ErrorCode> {
        Ok(MockDirHandle {
            path: join_mock_path(&self_.path, &path),
        })
    }

    async fn descriptor_readlink_at(
        &self,
        _self_: &Self::Descriptor,
        _path: String,
    ) -> Result<String, ErrorCode> {
        Err(ErrorCode::Invalid)
    }

    async fn descriptor_remove_directory_at(
        &self,
        _self_: &Self::Descriptor,
        _path: String,
    ) -> Result<(), ErrorCode> {
        Ok(())
    }

    async fn descriptor_rename_at(
        &self,
        _self_: &Self::Descriptor,
        _old_path: String,
        _new_descriptor: &Self::Descriptor,
        _new_path: String,
    ) -> Result<(), ErrorCode> {
        Ok(())
    }

    async fn descriptor_symlink_at(
        &self,
        _self_: &Self::Descriptor,
        _old_path: String,
        _new_path: String,
    ) -> Result<(), ErrorCode> {
        Ok(())
    }

    async fn descriptor_unlink_file_at(
        &self,
        _self_: &Self::Descriptor,
        _path: String,
    ) -> Result<(), ErrorCode> {
        Ok(())
    }

    async fn descriptor_is_same_object(
        &self,
        self_: &Self::Descriptor,
        other: &Self::Descriptor,
    ) -> bool {
        self_.path == other.path
    }

    async fn descriptor_metadata_hash(
        &self,
        _self_: &Self::Descriptor,
    ) -> Result<MetadataHashValue, ErrorCode> {
        Ok(MetadataHashValue { lower: 0, upper: 0 })
    }

    async fn descriptor_metadata_hash_at(
        &self,
        _self_: &Self::Descriptor,
        _path_flags: PathFlags,
        _path: String,
    ) -> Result<MetadataHashValue, ErrorCode> {
        Ok(MetadataHashValue { lower: 0, upper: 0 })
    }
}

struct MockGuestDispatcher {
    inspect: rpc_inspect::RpcServer<MockInspect>,
    instances: rpc_instances::RpcServer<MockInstances>,
    tracing: rpc_tracing::RpcServer<MockTracing>,
    profiling: rpc_profiling::RpcServer<MockProfiling>,
    preopens: rpc_preopens::RpcServer<MockPreopens>,
    fs: rpc_fs::RpcServer<MockFs>,
}

impl Dispatcher for MockGuestDispatcher {
    type Resource = MockResource;

    fn supports(&self, instance: &str, func: &str) -> bool {
        self.inspect.supports_call(instance, func)
            || self.instances.supports_call(instance, func)
            || self.tracing.supports_call(instance, func)
            || self.profiling.supports_call(instance, func)
            || self.preopens.supports_call(instance, func)
            || self.fs.supports_call(instance, func)
    }

    async fn dispatch<'a>(
        &'a self,
        ctx: ServerInvocation<'a, Self::Resource>,
        instance: &'a str,
        func: &'a str,
    ) -> Result<(), WireError> {
        if self.inspect.supports_call(instance, func) {
            self.inspect.dispatch_with(ctx, instance, func).await
        } else if self.instances.supports_call(instance, func) {
            self.instances.dispatch_with(ctx, instance, func).await
        } else if self.tracing.supports_call(instance, func) {
            self.tracing.dispatch_with(ctx, instance, func).await
        } else if self.profiling.supports_call(instance, func) {
            self.profiling.dispatch_with(ctx, instance, func).await
        } else if self.preopens.supports_call(instance, func) {
            self.preopens.dispatch_with(ctx, instance, func).await
        } else if self.fs.supports_call(instance, func) {
            self.fs.dispatch_with(ctx, instance, func).await
        } else {
            Err(WireError::MalformedPayload {
                context: "MockGuestDispatcher".to_owned(),
                detail: format!("unsupported {instance}.{func}"),
            })
        }
    }
}

/// Spawn an in-process mock guest speaking the real `helios-wit-rpc` wire protocol.
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
    let reader = Async::new(guest_read).expect("register guest read");
    let writer = Async::new(guest).expect("register guest write");

    let counters = Arc::new(MockGuestCounters::default());
    let dispatcher = MockGuestDispatcher {
        inspect: rpc_inspect::RpcServer::new(MockInspect {
            counters: Arc::clone(&counters),
            delay,
        }),
        instances: rpc_instances::RpcServer::new(MockInstances {
            counters: Arc::clone(&counters),
            delay,
        }),
        tracing: rpc_tracing::RpcServer::new(MockTracing),
        profiling: rpc_profiling::RpcServer::new(MockProfiling),
        preopens: rpc_preopens::RpcServer::new(MockPreopens),
        fs: rpc_fs::RpcServer::new(MockFs {
            counters: Arc::clone(&counters),
        }),
    };

    let endpoint = Endpoint::new(reader, writer, dispatcher);
    let handle = tokio::spawn(async move {
        let _ = endpoint.drive().await;
    });

    (session, counters, handle)
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

    // 7. Live remote VFS paths (over `wasi:filesystem/{preopens,types}`)
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

    // Guard against async future state-machine bloat that would overflow 2 MiB debug stacks.
    let probe_fut = eval_command(env.clone(), "inspect", OutputFormat::Json);
    let eval_fut_bytes = std::mem::size_of_val(&probe_fut);
    assert!(
        eval_fut_bytes < 16 * 1024,
        "eval_command future grew too large for debug thread stacks: {eval_fut_bytes} bytes"
    );
    drop(probe_fut);

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
