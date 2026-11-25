use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::{BTreeMap, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use async_channel::{Receiver, Sender};
use helios_component_manager::{
    BoundSocket, CapabilityCeiling, ChildProcess, ComponentNode, ComponentStateRecord,
    ComponentStatus, ComponentTopology, Criticality, EscalationAction, ExecRunnerSpec, ExitOutcome,
    ExposeSpec, FatalEscalation, FsRights, HardwareInventorySnapshot, HardwarePredicates,
    IpAddrSpec, IpcChannelEnd, LifecycleKind, MachineRights, MountRights, MountSharingSpec,
    MountSourceSpec, MountSpec, NameCeiling, NetRights, OciRunnerSpec, OomTier, PortCeiling,
    ProviderEndpoint, ProviderOutcome, ProviderSlot, RestartPolicy, RouteSpec, RunnerSpec,
    RuntimeError, SIGKILL, SIGTERM, SocketActivationSpec, SpawnComponentArgs, StartupPolicy,
    Supervisor, SupervisorError, SupervisorRuntime, TcpSocketListener, VmRunnerSpec,
    VsockSocketListener, WasmRunnerSpec, WasmSharding,
};

type LocalTask = Pin<Box<dyn Future<Output = ()> + 'static>>;

/// Deterministic single-threaded async harness driving spawned supervisor tasks
/// without real wall-clock waits.
#[derive(Clone, Default)]
struct LocalTasks {
    queue: Rc<RefCell<VecDeque<LocalTask>>>,
}

impl LocalTasks {
    fn spawn<F: Future<Output = ()> + 'static>(&self, fut: F) {
        self.queue.borrow_mut().push_back(Box::pin(fut));
    }

    /// Polls all ready tasks until quiescence.
    fn pump(&self) {
        let mut cx = Context::from_waker(Waker::noop());
        for _round in 0..128 {
            let count = self.queue.borrow().len();
            if count == 0 {
                break;
            }
            let mut progressed = false;
            for _ in 0..count {
                let Some(mut task) = self.queue.borrow_mut().pop_front() else {
                    break;
                };
                match task.as_mut().poll(&mut cx) {
                    Poll::Ready(()) => progressed = true,
                    Poll::Pending => self.queue.borrow_mut().push_back(task),
                }
            }
            if !progressed {
                break;
            }
        }
    }

    /// Drives `fut` to completion while pumping spawned background tasks.
    fn run_to_completion<T>(&self, fut: impl Future<Output = T>) -> T {
        let mut cx = Context::from_waker(Waker::noop());
        let mut fut = std::pin::pin!(fut);
        for _ in 0..2048 {
            self.pump();
            if let Poll::Ready(val) = fut.as_mut().poll(&mut cx) {
                self.pump();
                return val;
            }
        }
        panic!("test future did not complete after 2048 deterministic pump rounds");
    }
}

#[derive(Clone)]
struct MockIpcEnd {
    tx: Sender<Vec<u8>>,
    rx: Receiver<Vec<u8>>,
}

impl IpcChannelEnd for MockIpcEnd {
    async fn read(&self, _max_bytes: u32) -> Result<Option<Vec<u8>>, RuntimeError> {
        match self.rx.recv().await {
            Ok(bytes) => Ok(Some(bytes)),
            Err(_) => Ok(None),
        }
    }

    async fn write(&self, bytes: Vec<u8>) -> Result<(), RuntimeError> {
        self.tx.send(bytes).await.map_err(|_| RuntimeError::Other {
            detail: "peer closed".to_owned(),
        })
    }

    fn close_write(&self) {
        self.tx.close();
    }
}

#[derive(Clone)]
struct MockTcpListener {
    port: u16,
    ready_rx: Receiver<()>,
    queued_packets: Rc<RefCell<VecDeque<Vec<u8>>>>,
}

impl TcpSocketListener for MockTcpListener {
    async fn wait_readable(&self) -> Result<bool, RuntimeError> {
        match self.ready_rx.recv().await {
            Ok(()) => Ok(true),
            Err(_) => Err(RuntimeError::Other {
                detail: "listener closed".to_owned(),
            }),
        }
    }
}

#[derive(Clone)]
struct MockVsockListener {
    port: u32,
    ready_rx: Receiver<()>,
    queued_packets: Rc<RefCell<VecDeque<Vec<u8>>>>,
}

impl VsockSocketListener for MockVsockListener {
    async fn wait_readable(&self) -> Result<bool, RuntimeError> {
        match self.ready_rx.recv().await {
            Ok(()) => Ok(true),
            Err(_) => Err(RuntimeError::Other {
                detail: "vsock listener closed".to_owned(),
            }),
        }
    }
}

struct MockChild {
    id: u64,
    signals: Rc<RefCell<Vec<u8>>>,
    exit_rx: Receiver<ExitOutcome>,
    exit_tx: Sender<ExitOutcome>,
    honors_sigterm: bool,
}

impl ChildProcess for MockChild {
    fn instance_id(&self) -> Option<u64> {
        Some(self.id)
    }

    fn signal(&self, signal: u8) -> Result<(), RuntimeError> {
        self.signals.borrow_mut().push(signal);
        if (signal == SIGTERM && self.honors_sigterm) || signal == SIGKILL {
            let _ = self.exit_tx.try_send(ExitOutcome::Signaled(signal));
        }
        Ok(())
    }

    async fn wait(&self) -> Result<ExitOutcome, RuntimeError> {
        self.exit_rx.recv().await.map_err(|_| RuntimeError::Other {
            detail: "child wait channel closed".to_owned(),
        })
    }
}

struct MockProvider {
    id: Option<u64>,
    exit_rx: Receiver<ProviderOutcome>,
    stopped: Rc<RefCell<bool>>,
}

impl ProviderEndpoint for MockProvider {
    fn instance_id(&self) -> Option<u64> {
        self.id
    }

    async fn wait_exit(&self) -> ProviderOutcome {
        self.exit_rx
            .recv()
            .await
            .unwrap_or(ProviderOutcome::Stopped)
    }

    fn stop(&self) {
        *self.stopped.borrow_mut() = true;
    }
}

struct SpawnedRecord {
    moniker: String,
    instance_id: u64,
    runner_kind: &'static str,
    exit_tx: Sender<ExitOutcome>,
    signals: Rc<RefCell<Vec<u8>>>,
    sockets: Vec<BoundSocket<MockTcpListener, MockVsockListener>>,
    ipc: BTreeMap<String, MockIpcEnd>,
}

type SocketTrigger = (Sender<()>, Rc<RefCell<VecDeque<Vec<u8>>>>);

struct MockState {
    now_ms: u64,
    next_id: u64,
    hardware: HardwareInventorySnapshot,
    hw_tx: Option<Sender<HardwareInventorySnapshot>>,
    hw_rx: Option<Receiver<HardwareInventorySnapshot>>,
    events_log: Vec<String>,
    sleeps_ms: Vec<u64>,
    ready_signaled: bool,
    fatal_reports: Vec<FatalEscalation>,
    inspect_snapshots: Vec<Vec<ComponentStateRecord>>,
    tcp_triggers: BTreeMap<u16, SocketTrigger>,
    vsock_triggers: BTreeMap<u32, SocketTrigger>,
    spawned: Vec<SpawnedRecord>,
    providers: Vec<(ProviderSlot, String, Sender<ProviderOutcome>)>,
    ignore_sigterm_monikers: Vec<String>,
}

impl Default for MockState {
    fn default() -> Self {
        let (hw_tx, hw_rx) = async_channel::unbounded();
        Self {
            now_ms: 1_000,
            next_id: 1,
            hardware: HardwareInventorySnapshot::default(),
            hw_tx: Some(hw_tx),
            hw_rx: Some(hw_rx),
            events_log: Vec::new(),
            sleeps_ms: Vec::new(),
            ready_signaled: false,
            fatal_reports: Vec::new(),
            inspect_snapshots: Vec::new(),
            tcp_triggers: BTreeMap::new(),
            vsock_triggers: BTreeMap::new(),
            spawned: Vec::new(),
            providers: Vec::new(),
            ignore_sigterm_monikers: Vec::new(),
        }
    }
}

#[derive(Clone)]
struct MockRuntime {
    tasks: LocalTasks,
    state: Rc<RefCell<MockState>>,
}

impl MockRuntime {
    fn new(hardware: HardwareInventorySnapshot) -> Self {
        let st = MockState {
            hardware,
            ..Default::default()
        };
        Self {
            tasks: LocalTasks::default(),
            state: Rc::new(RefCell::new(st)),
        }
    }

    fn deliver_tcp_packet(&self, port: u16, payload: &[u8]) {
        let (tx, queue) = self
            .state
            .borrow()
            .tcp_triggers
            .get(&port)
            .expect("TCP port was pre-bound")
            .clone();
        queue.borrow_mut().push_back(payload.to_vec());
        let _ = tx.try_send(());
    }

    fn deliver_vsock_packet(&self, port: u32, payload: &[u8]) {
        let (tx, queue) = self
            .state
            .borrow()
            .vsock_triggers
            .get(&port)
            .expect("vsock port was pre-bound")
            .clone();
        queue.borrow_mut().push_back(payload.to_vec());
        let _ = tx.try_send(());
    }

    fn push_hardware(&self, inv: HardwareInventorySnapshot) {
        self.state.borrow_mut().hardware = inv;
        let tx = self.state.borrow().hw_tx.clone().unwrap();
        let _ = tx.try_send(inv);
    }

    fn last_spawned_for(&self, moniker: &str) -> usize {
        self.state
            .borrow()
            .spawned
            .iter()
            .rposition(|s| s.moniker == moniker)
            .expect("component must have been spawned")
    }

    fn spawn_count(&self, moniker: &str) -> usize {
        self.state
            .borrow()
            .spawned
            .iter()
            .filter(|s| s.moniker == moniker)
            .count()
    }

    fn finish_child(&self, moniker: &str, outcome: ExitOutcome) {
        let idx = self.last_spawned_for(moniker);
        let tx = self.state.borrow().spawned[idx].exit_tx.clone();
        let _ = tx.try_send(outcome);
    }
}

impl SupervisorRuntime for MockRuntime {
    type Child = MockChild;
    type Provider = MockProvider;
    type IpcEnd = MockIpcEnd;
    type TcpListener = MockTcpListener;
    type VsockListener = MockVsockListener;

    fn now_ms(&self) -> u64 {
        self.state.borrow().now_ms
    }

    async fn sleep(&self, duration: Duration) {
        let ms = u64::try_from(duration.as_millis()).unwrap_or(u64::MAX);
        {
            let mut st = self.state.borrow_mut();
            st.sleeps_ms.push(ms);
            st.now_ms = st.now_ms.saturating_add(ms);
        }
        futures_lite::future::yield_now().await;
    }

    fn spawn_task<F: Future<Output = ()> + 'static>(&self, future: F) {
        self.tasks.spawn(future);
    }

    fn path_exists(&self, _path: &str) -> bool {
        true
    }

    fn hardware_inventory(&self) -> Result<HardwareInventorySnapshot, RuntimeError> {
        Ok(self.state.borrow().hardware)
    }

    fn subscribe_hardware(&self) -> Option<Receiver<HardwareInventorySnapshot>> {
        self.state.borrow_mut().hw_rx.take()
    }

    async fn mount(&self, spec: &MountSpec) -> Result<(), RuntimeError> {
        self.state
            .borrow_mut()
            .events_log
            .push(format!("mount:{}", spec.path));
        Ok(())
    }

    fn ipc_channel(&self) -> (Self::IpcEnd, Self::IpcEnd) {
        let (a_tx, b_rx) = async_channel::unbounded();
        let (b_tx, a_rx) = async_channel::unbounded();
        (
            MockIpcEnd { tx: a_tx, rx: a_rx },
            MockIpcEnd { tx: b_tx, rx: b_rx },
        )
    }

    async fn bind_tcp(
        &self,
        _address: IpAddrSpec,
        port: u16,
        _backlog: u16,
    ) -> Result<Self::TcpListener, RuntimeError> {
        let (tx, rx) = async_channel::unbounded();
        let queue = Rc::new(RefCell::new(VecDeque::new()));
        self.state
            .borrow_mut()
            .tcp_triggers
            .insert(port, (tx, queue.clone()));
        Ok(MockTcpListener {
            port,
            ready_rx: rx,
            queued_packets: queue,
        })
    }

    async fn bind_vsock(
        &self,
        port: u32,
        _backlog: u32,
    ) -> Result<Self::VsockListener, RuntimeError> {
        let (tx, rx) = async_channel::unbounded();
        let queue = Rc::new(RefCell::new(VecDeque::new()));
        self.state
            .borrow_mut()
            .vsock_triggers
            .insert(port, (tx, queue.clone()));
        Ok(MockVsockListener {
            port,
            ready_rx: rx,
            queued_packets: queue,
        })
    }

    async fn install_provider(
        &self,
        slot: ProviderSlot,
        node: &ComponentNode,
    ) -> Result<Self::Provider, RuntimeError> {
        let (tx, rx) = async_channel::unbounded();
        let mut st = self.state.borrow_mut();
        st.events_log
            .push(format!("provider:{}:{}", slot.as_str(), node.moniker));
        let id = if slot == ProviderSlot::Surface {
            let id = st.next_id;
            st.next_id += 1;
            Some(id)
        } else {
            None
        };
        st.providers.push((slot, node.moniker.to_string(), tx));
        Ok(MockProvider {
            id,
            exit_rx: rx,
            stopped: Rc::new(RefCell::new(false)),
        })
    }

    async fn spawn_component(
        &self,
        args: SpawnComponentArgs<Self::TcpListener, Self::VsockListener, Self::IpcEnd>,
    ) -> Result<Self::Child, RuntimeError> {
        let (exit_tx, exit_rx) = async_channel::unbounded();
        let signals = Rc::new(RefCell::new(Vec::new()));
        let mut st = self.state.borrow_mut();
        let id = st.next_id;
        st.next_id += 1;
        let moniker = args.node.moniker.to_string();
        let honors_sigterm = !st.ignore_sigterm_monikers.contains(&moniker);
        st.events_log.push(format!("spawn:{moniker}"));
        let ipc: BTreeMap<String, MockIpcEnd> = args.ipc_channels.into_iter().collect();
        st.spawned.push(SpawnedRecord {
            moniker,
            instance_id: id,
            runner_kind: args.node.runner.kind_str(),
            exit_tx: exit_tx.clone(),
            signals: signals.clone(),
            sockets: args.sockets,
            ipc,
        });
        Ok(MockChild {
            id,
            signals,
            exit_rx,
            exit_tx,
            honors_sigterm,
        })
    }

    fn publish_inspect(&self, records: &[ComponentStateRecord]) {
        self.state
            .borrow_mut()
            .inspect_snapshots
            .push(records.to_vec());
    }

    async fn signal_ready(&self) -> Result<(), RuntimeError> {
        let mut st = self.state.borrow_mut();
        st.ready_signaled = true;
        st.events_log.push("signal_ready".to_owned());
        Ok(())
    }

    async fn escalate_fatal(&self, report: FatalEscalation) -> Result<(), RuntimeError> {
        self.state.borrow_mut().fatal_reports.push(report);
        Ok(())
    }
}

fn full_root_ceiling() -> CapabilityCeiling {
    CapabilityCeiling {
        directories: Cow::Owned(vec![helios_component_manager::DirectoryGrantSpec {
            source: Cow::Borrowed("/"),
            guest: Cow::Borrowed("/"),
            rights: FsRights::ALL,
        }]),
        network: NetRights::ALL,
        tcp_ports: PortCeiling::Any,
        vsock_ports: PortCeiling::Any,
        clock: helios_component_manager::ClockRights::ALL,
        terminal: helios_component_manager::TerminalRights::ALL,
        process: helios_component_manager::ProcessRights::ALL,
        link: helios_component_manager::LinkRights::ALL,
        mount: MountRights::ALL,
        devices: helios_component_manager::DeviceClasses::ALL,
        named_devices: NameCeiling::Any,
        inspect_read: helios_component_manager::AuthorityScopeSpec::Machine,
        trace_read: helios_component_manager::AuthorityScopeSpec::Machine,
        profile_read: helios_component_manager::AuthorityScopeSpec::Machine,
        diagnostics_control: true,
        instance_control: helios_component_manager::AuthorityScopeSpec::Machine,
        settings_write: true,
        machine: MachineRights::ALL,
        wit_interfaces: NameCeiling::Any,
    }
}

fn base_node(
    moniker: &'static str,
    parent_index: Option<usize>,
    runner: RunnerSpec,
) -> ComponentNode {
    ComponentNode {
        moniker: Cow::Borrowed(moniker),
        instance_name: Cow::Borrowed(moniker.trim_start_matches('/')),
        parent_index,
        children_indices: Cow::Borrowed(&[]),
        runner,
        startup: StartupPolicy::Lazy,
        lifecycle: LifecycleKind::Service,
        requires: HardwarePredicates::NONE,
        after: Cow::Borrowed(&[]),
        mounts: Cow::Borrowed(&[]),
        restart: RestartPolicy::Never,
        restart_backoff_ms: 100,
        restart_backoff_max_ms: 500,
        burst_limit: 3,
        burst_window_ms: 10_000,
        stop_timeout_ms: 200,
        critical: Criticality::None,
        escalation: EscalationAction::Halt,
        oom_tier: OomTier::User,
        dynamic_mount: false,
        capabilities: CapabilityCeiling::EMPTY,
        exposes: Cow::Borrowed(&[]),
        routes: Cow::Borrowed(&[]),
        sockets: Cow::Borrowed(&[]),
    }
}

#[test]
fn lazy_tcp_and_vsock_socket_activation_preserves_first_packet() {
    let mut root = base_node("/", None, RunnerSpec::Realm);
    root.children_indices = Cow::Borrowed(&[1, 2]);
    root.oom_tier = OomTier::Protected;
    root.capabilities = full_root_ceiling();

    let mut tcp_svc = base_node(
        "/svc/http",
        Some(0),
        RunnerSpec::Wasm(WasmRunnerSpec {
            program: Cow::Borrowed("/bin/http"),
            sharding: WasmSharding::Singleton,
            provider: None,
            args: Cow::Borrowed(&[]),
            env: Cow::Borrowed(&[]),
            cwd: None,
            optional: false,
        }),
    );
    tcp_svc.capabilities.network = NetRights::TCP;
    tcp_svc.capabilities.tcp_ports = PortCeiling::Set(Cow::Borrowed(&[8080]));
    tcp_svc.sockets = Cow::Borrowed(&[SocketActivationSpec::Tcp {
        address: IpAddrSpec::V4([0, 0, 0, 0]),
        port: 8080,
        backlog: 128,
    }]);

    let mut vsock_svc = base_node(
        "/svc/rpc",
        Some(0),
        RunnerSpec::Wasm(WasmRunnerSpec {
            program: Cow::Borrowed("/bin/rpc"),
            sharding: WasmSharding::Singleton,
            provider: None,
            args: Cow::Borrowed(&[]),
            env: Cow::Borrowed(&[]),
            cwd: None,
            optional: false,
        }),
    );
    vsock_svc.capabilities.vsock_ports = PortCeiling::Set(Cow::Borrowed(&[5555]));
    vsock_svc.sockets = Cow::Borrowed(&[SocketActivationSpec::Vsock {
        port: 5555,
        backlog: 64,
    }]);

    let rt = MockRuntime::new(HardwareInventorySnapshot::default());
    let tasks = rt.tasks.clone();
    let mut sup = Supervisor::new(
        rt.clone(),
        ComponentTopology {
            nodes: Cow::Owned(vec![root, tcp_svc, vsock_svc]),
        },
    )
    .expect("topology validates");

    tasks.run_to_completion(sup.boot()).expect("boot");

    // Zero stores allocated at boot for lazy services!
    assert_eq!(rt.spawn_count("/svc/http"), 0);
    assert_eq!(rt.spawn_count("/svc/rpc"), 0);
    assert_eq!(sup.status_of("/svc/http"), Some(ComponentStatus::Unstarted));
    assert_eq!(sup.status_of("/svc/rpc"), Some(ComponentStatus::Unstarted));

    // First inbound TCP packet wakes listener -> instantiates /svc/http with live listener intact.
    rt.deliver_tcp_packet(8080, b"GET / HTTP/1.1\r\n");
    tasks.run_to_completion(sup.step_once()).unwrap();
    assert_eq!(rt.spawn_count("/svc/http"), 1);
    assert_eq!(sup.status_of("/svc/http"), Some(ComponentStatus::Running));
    {
        let st = rt.state.borrow();
        let rec = &st.spawned[0];
        assert_eq!(rec.sockets.len(), 1);
        let BoundSocket::Tcp(listener) = &rec.sockets[0] else {
            panic!("expected TCP listener handoff");
        };
        assert_eq!(listener.port, 8080);
        assert_eq!(
            listener.queued_packets.borrow().front().map(Vec::as_slice),
            Some(&b"GET / HTTP/1.1\r\n"[..]),
            "first TCP packet must survive lazy activation intact"
        );
    }

    // First inbound vsock connection wakes listener -> instantiates /svc/rpc with zero packet loss.
    rt.deliver_vsock_packet(5555, b"RPC-HELLO");
    tasks.run_to_completion(sup.step_once()).unwrap();
    assert_eq!(rt.spawn_count("/svc/rpc"), 1);
    assert_eq!(sup.status_of("/svc/rpc"), Some(ComponentStatus::Running));
    {
        let st = rt.state.borrow();
        let rec = &st.spawned[1];
        let BoundSocket::Vsock(listener) = &rec.sockets[0] else {
            panic!("expected vsock listener handoff");
        };
        assert_eq!(listener.port, 5555);
        assert_eq!(
            listener.queued_packets.borrow().front().map(Vec::as_slice),
            Some(&b"RPC-HELLO"[..]),
            "first vsock packet must survive lazy activation intact"
        );
    }
}

#[test]
fn lazy_wit_ipc_channel_activates_provider_on_first_frame_with_zero_loss() {
    let mut root = base_node("/", None, RunnerSpec::Realm);
    root.children_indices = Cow::Borrowed(&[1, 2]);
    root.oom_tier = OomTier::Protected;
    root.capabilities = full_root_ceiling();

    let mut provider = base_node(
        "/svc/kv",
        Some(0),
        RunnerSpec::Wasm(WasmRunnerSpec {
            program: Cow::Borrowed("/bin/kv"),
            sharding: WasmSharding::Singleton,
            provider: None,
            args: Cow::Borrowed(&[]),
            env: Cow::Borrowed(&[]),
            cwd: None,
            optional: false,
        }),
    );
    provider.startup = StartupPolicy::Lazy;
    provider.exposes = Cow::Borrowed(&[ExposeSpec {
        interface: Cow::Borrowed("helios:demo/kv"),
        channel: Cow::Borrowed("kv-server"),
    }]);

    let mut consumer = base_node(
        "/app/cli",
        Some(0),
        RunnerSpec::Wasm(WasmRunnerSpec {
            program: Cow::Borrowed("/bin/cli"),
            sharding: WasmSharding::Singleton,
            provider: None,
            args: Cow::Borrowed(&[]),
            env: Cow::Borrowed(&[]),
            cwd: None,
            optional: false,
        }),
    );
    consumer.startup = StartupPolicy::Eager;
    consumer.capabilities.wit_interfaces =
        NameCeiling::Set(Cow::Borrowed(&[Cow::Borrowed("helios:demo/kv")]));
    consumer.routes = Cow::Borrowed(&[RouteSpec {
        interface: Cow::Borrowed("helios:demo/kv"),
        provider_index: 1,
        provider_moniker: Cow::Borrowed("/svc/kv"),
        provider_channel: Cow::Borrowed("kv-server"),
        consumer_channel: Cow::Borrowed("kv-client"),
    }]);

    let rt = MockRuntime::new(HardwareInventorySnapshot::default());
    let tasks = rt.tasks.clone();
    let mut sup = Supervisor::new(
        rt.clone(),
        ComponentTopology {
            nodes: Cow::Owned(vec![root, provider, consumer]),
        },
    )
    .expect("valid topology");

    tasks.run_to_completion(sup.boot()).expect("boot");

    // Consumer started eagerly; lazy provider has NOT been instantiated yet!
    assert_eq!(rt.spawn_count("/app/cli"), 1);
    assert_eq!(rt.spawn_count("/svc/kv"), 0);
    assert_eq!(sup.status_of("/svc/kv"), Some(ComponentStatus::Unstarted));

    // Consumer sends the first IPC/WIT frame across its pre-created channel.
    let cli_end = rt.state.borrow().spawned[0]
        .ipc
        .get("kv-client")
        .expect("consumer received pre-created IPC endpoint")
        .clone();
    tasks
        .run_to_completion(cli_end.write(b"SET k=v\n".to_vec()))
        .expect("write first frame");
    tasks.run_to_completion(sup.step_once()).unwrap();

    // First frame activated `/svc/kv` and delivered the exact first packet!
    assert_eq!(rt.spawn_count("/svc/kv"), 1);
    assert_eq!(sup.status_of("/svc/kv"), Some(ComponentStatus::Running));
    let srv_end = rt.state.borrow().spawned[1]
        .ipc
        .get("kv-server")
        .expect("provider received live endpoint")
        .clone();
    let received = tasks
        .run_to_completion(srv_end.read(1024))
        .expect("read first frame");
    assert_eq!(received.as_deref(), Some(&b"SET k=v\n"[..]));

    // Bidirectional reply flows seamlessly back through the live bridge.
    tasks
        .run_to_completion(srv_end.write(b"OK\n".to_vec()))
        .expect("write reply");
    let reply = tasks
        .run_to_completion(cli_end.read(1024))
        .expect("read reply");
    assert_eq!(reply.as_deref(), Some(&b"OK\n"[..]));
}

#[test]
fn eager_hardware_predicates_and_hotplug_plus_oneshot_mount_ordering() {
    let mut root = base_node("/", None, RunnerSpec::Realm);
    root.children_indices = Cow::Borrowed(&[1, 2, 3]);
    root.oom_tier = OomTier::Protected;
    root.capabilities = full_root_ceiling();
    root.mounts = Cow::Borrowed(&[MountSpec {
        source: MountSourceSpec::Memory,
        path: Cow::Borrowed("/var/data"),
        sharing: MountSharingSpec::Shared,
        read_only: false,
        compress: None,
        commit: None,
        max_inline: None,
    }]);

    let mut setup = base_node(
        "/setup",
        Some(0),
        RunnerSpec::Exec(ExecRunnerSpec {
            program: Cow::Borrowed("/bin/migrate"),
            args: Cow::Borrowed(&[]),
            env: Cow::Borrowed(&[]),
            cwd: None,
            optional: false,
        }),
    );
    setup.startup = StartupPolicy::Eager;
    setup.lifecycle = LifecycleKind::Oneshot;

    let mut server = base_node(
        "/server",
        Some(0),
        RunnerSpec::Oci(OciRunnerSpec {
            image: None,
            rootfs: Some(Cow::Borrowed("/oci/app")),
            store: None,
            hostname: Cow::Borrowed("app"),
            uid: 0,
            gid: 0,
            entrypoint: Cow::Borrowed(&[Cow::Borrowed("/bin/app")]),
            cmd: Cow::Borrowed(&[]),
            env: Cow::Borrowed(&[]),
            cwd: None,
            mounts: Cow::Borrowed(&[]),
        }),
    );
    server.capabilities.directories =
        Cow::Owned(vec![helios_component_manager::DirectoryGrantSpec {
            source: Cow::Borrowed("/oci/app"),
            guest: Cow::Borrowed("/oci/app"),
            rights: FsRights::READ.union(FsRights::EXECUTE),
        }]);
    server.startup = StartupPolicy::Eager;
    server.after = Cow::Borrowed(&[1]);

    let mut compositor = base_node(
        "/compositor",
        Some(0),
        RunnerSpec::Wasm(WasmRunnerSpec {
            program: Cow::Borrowed("/bin/compositor"),
            sharding: WasmSharding::Singleton,
            provider: Some(ProviderSlot::Surface),
            args: Cow::Borrowed(&[]),
            env: Cow::Borrowed(&[]),
            cwd: None,
            optional: false,
        }),
    );
    compositor.startup = StartupPolicy::Eager;
    compositor.requires = HardwarePredicates {
        display: true,
        input: true,
        ..HardwarePredicates::NONE
    };

    // Boot with display=true, input=false -> compositor must wait for hardware hotplug.
    let rt = MockRuntime::new(HardwareInventorySnapshot {
        display: true,
        input: false,
        ..HardwareInventorySnapshot::default()
    });
    let tasks = rt.tasks.clone();
    let mut sup = Supervisor::new(
        rt.clone(),
        ComponentTopology {
            nodes: Cow::Owned(vec![root, setup, server, compositor]),
        },
    )
    .expect("valid topology");

    // Schedule oneshot `/setup` to complete cleanly once spawned.
    let rt_finish = rt.clone();
    tasks.spawn(async move {
        loop {
            if rt_finish.spawn_count("/setup") == 1 {
                rt_finish.finish_child("/setup", ExitOutcome::Exited(0));
                break;
            }
            futures_lite::future::yield_now().await;
        }
    });

    tasks.run_to_completion(sup.boot()).expect("boot");

    // Verify exact ordering: mount `/var/data` -> oneshot `/setup` -> dependent OCI `/server` -> `signal_ready`.
    assert_eq!(
        rt.state.borrow().events_log,
        vec![
            "mount:/var/data",
            "spawn:/setup",
            "spawn:/server",
            "signal_ready"
        ]
    );
    assert_eq!(rt.state.borrow().spawned[0].runner_kind, "exec");
    assert_eq!(rt.state.borrow().spawned[1].runner_kind, "oci");
    assert!(rt.state.borrow().spawned[1].instance_id > 0);
    assert_eq!(sup.status_of("/setup"), Some(ComponentStatus::Completed));
    assert_eq!(sup.status_of("/server"), Some(ComponentStatus::Running));
    assert_eq!(
        sup.status_of("/compositor"),
        Some(ComponentStatus::Unstarted)
    );

    // Hotplug input device -> compositor activates!
    rt.push_hardware(HardwareInventorySnapshot {
        display: true,
        input: true,
        ..HardwareInventorySnapshot::default()
    });
    tasks.run_to_completion(sup.step_once()).unwrap();
    assert_eq!(sup.status_of("/compositor"), Some(ComponentStatus::Running));
}

#[test]
fn restart_exponential_backoff_burst_circuit_breaker_and_critical_system_escalation() {
    let mut root = base_node("/", None, RunnerSpec::Realm);
    root.children_indices = Cow::Borrowed(&[1]);
    root.oom_tier = OomTier::Protected;
    root.capabilities = full_root_ceiling();

    let mut drv = base_node(
        "/drivers/blk",
        Some(0),
        RunnerSpec::Vm(VmRunnerSpec {
            kernel: Cow::Borrowed("/boot/Image"),
            initramfs: None,
            disk: None,
            memory_mib: 64,
            cpus: 1,
            cmdline: None,
            rootfs_dir: None,
            share_dirs: Cow::Borrowed(&[]),
        }),
    );
    drv.capabilities.machine = MachineRights::VIRTUALIZE;
    drv.startup = StartupPolicy::Eager;
    drv.restart = RestartPolicy::OnFailure;
    drv.restart_backoff_ms = 100;
    drv.restart_backoff_max_ms = 250;
    drv.burst_limit = 3;
    drv.burst_window_ms = 10_000;
    drv.critical = Criticality::System;
    drv.escalation = EscalationAction::Reboot;

    let rt = MockRuntime::new(HardwareInventorySnapshot::default());
    let tasks = rt.tasks.clone();
    let mut sup = Supervisor::new(
        rt.clone(),
        ComponentTopology {
            nodes: Cow::Owned(vec![root, drv]),
        },
    )
    .expect("valid topology");

    tasks.run_to_completion(sup.boot()).expect("boot");
    assert_eq!(rt.spawn_count("/drivers/blk"), 1);

    // Crash 4 times -> 3 restarts with exponential backoff (100, 200, 250 capped), 4th trips circuit breaker!
    for attempt in 0..3 {
        rt.finish_child("/drivers/blk", ExitOutcome::Exited(1));
        tasks.run_to_completion(sup.step_once()).unwrap(); // ChildExited -> schedules restart
        tasks.run_to_completion(sup.step_once()).unwrap(); // RestartTimerFired -> respawns
        assert_eq!(rt.spawn_count("/drivers/blk"), attempt + 2);
    }
    assert_eq!(rt.state.borrow().sleeps_ms, vec![100, 200, 250]);

    // 4th crash trips burst_limit=3 -> critical="system" triggers escalate_fatal(Reboot).
    let expected_last_id = sup
        .instance_id_of("/drivers/blk")
        .expect("running child must have an instance_id before exiting");
    rt.finish_child("/drivers/blk", ExitOutcome::Exited(2));
    let err = tasks
        .run_to_completion(sup.step_once())
        .expect_err("4th crash must escalate fatally");
    assert!(matches!(err, SupervisorError::FatalEscalated { .. }));
    assert_eq!(sup.status_of("/drivers/blk"), Some(ComponentStatus::Failed));
    assert_eq!(sup.restarts_of("/drivers/blk"), Some(3));
    let reports = &rt.state.borrow().fatal_reports;
    assert_eq!(reports.len(), 1);
    assert_eq!(reports[0].component, "/drivers/blk");
    assert_eq!(reports[0].instance_id, Some(expected_last_id));
    assert_eq!(reports[0].restart_count, 3);
    assert_eq!(reports[0].action, EscalationAction::Reboot);
}

#[test]
fn critical_parent_tears_down_and_restarts_enclosing_realm_with_graceful_stop_timeout() {
    let mut root = base_node("/", None, RunnerSpec::Realm);
    root.children_indices = Cow::Borrowed(&[1]);
    root.oom_tier = OomTier::Protected;
    root.capabilities = full_root_ceiling();

    let mut realm = base_node("/apps", Some(0), RunnerSpec::Realm);
    realm.children_indices = Cow::Borrowed(&[2, 3]);
    realm.oom_tier = OomTier::User;

    let mut core = base_node(
        "/apps/core",
        Some(1),
        RunnerSpec::Wasm(WasmRunnerSpec {
            program: Cow::Borrowed("/bin/core"),
            sharding: WasmSharding::Singleton,
            provider: None,
            args: Cow::Borrowed(&[]),
            env: Cow::Borrowed(&[]),
            cwd: None,
            optional: false,
        }),
    );
    core.startup = StartupPolicy::Eager;
    core.restart = RestartPolicy::Never;
    core.critical = Criticality::Parent;

    let mut stubborn = base_node(
        "/apps/stubborn",
        Some(1),
        RunnerSpec::Wasm(WasmRunnerSpec {
            program: Cow::Borrowed("/bin/stubborn"),
            sharding: WasmSharding::Singleton,
            provider: None,
            args: Cow::Borrowed(&[]),
            env: Cow::Borrowed(&[]),
            cwd: None,
            optional: false,
        }),
    );
    stubborn.startup = StartupPolicy::Eager;
    stubborn.stop_timeout_ms = 150;

    let rt = MockRuntime::new(HardwareInventorySnapshot::default());
    // Make `/apps/stubborn` ignore SIGTERM to prove SIGTERM -> stop_timeout -> SIGKILL escalation!
    rt.state
        .borrow_mut()
        .ignore_sigterm_monikers
        .push("/apps/stubborn".to_owned());

    let tasks = rt.tasks.clone();
    let mut sup = Supervisor::new(
        rt.clone(),
        ComponentTopology {
            nodes: Cow::Owned(vec![root, realm, core, stubborn]),
        },
    )
    .expect("valid topology");

    tasks.run_to_completion(sup.boot()).expect("boot");
    assert_eq!(rt.spawn_count("/apps/core"), 1);
    assert_eq!(rt.spawn_count("/apps/stubborn"), 1);

    // `/apps/core` fails unrecoverably -> enclosing `/apps` realm is torn down and restarted!
    rt.finish_child("/apps/core", ExitOutcome::Trapped);
    tasks
        .run_to_completion(sup.step_once())
        .expect("parent realm reset succeeds");

    // Verify `/apps/stubborn` got SIGTERM, waited 150ms stop_timeout, then got SIGKILL!
    let first_stubborn_signals = rt.state.borrow().spawned[1].signals.borrow().clone();
    assert_eq!(first_stubborn_signals, vec![SIGTERM, SIGKILL]);
    assert!(rt.state.borrow().sleeps_ms.contains(&150));

    // Verify enclosing `/apps` realm restarted both children cleanly!
    assert_eq!(sup.restarts_of("/apps"), Some(1));
    assert_eq!(rt.spawn_count("/apps/core"), 2);
    assert_eq!(rt.spawn_count("/apps/stubborn"), 2);
    assert_eq!(sup.status_of("/apps/core"), Some(ComponentStatus::Running));
    assert_eq!(
        sup.status_of("/apps/stubborn"),
        Some(ComponentStatus::Running)
    );

    // Verify live inspect snapshots captured state transitions and instance IDs!
    let snapshots = &rt.state.borrow().inspect_snapshots;
    assert!(!snapshots.is_empty());
    let latest = snapshots.last().unwrap();
    let core_rec = latest.iter().find(|r| r.moniker == "/apps/core").unwrap();
    assert_eq!(core_rec.inspect_prefix, "apps/core");
    assert_eq!(core_rec.status, ComponentStatus::Running);
    assert!(core_rec.instance_id.is_some());
}

#[cfg(feature = "dynamic-components")]
#[test]
fn dynamic_components_mounts_bounded_subtree_rejects_escalation_and_unmounts_cleanly() {
    let mut root = base_node("/", None, RunnerSpec::Realm);
    root.children_indices = Cow::Borrowed(&[1, 2]);
    root.oom_tier = OomTier::Protected;
    root.capabilities = full_root_ceiling();

    let mut sandbox = base_node("/sandbox", Some(0), RunnerSpec::Realm);
    sandbox.oom_tier = OomTier::User;
    sandbox.dynamic_mount = true;
    sandbox.capabilities.network = NetRights::TCP;
    sandbox.capabilities.tcp_ports = PortCeiling::Set(Cow::Borrowed(&[9000]));

    let mut locked = base_node("/locked", Some(0), RunnerSpec::Realm);
    locked.dynamic_mount = false;

    let rt = MockRuntime::new(HardwareInventorySnapshot::default());
    let tasks = rt.tasks.clone();
    let mut sup = Supervisor::new(
        rt.clone(),
        ComponentTopology {
            nodes: Cow::Owned(vec![root, sandbox, locked]),
        },
    )
    .expect("valid topology");

    tasks.run_to_completion(sup.boot()).expect("boot");

    // Refuses dynamic mount on a realm without `dynamic_mount = true`.
    let mut denied_map = BTreeMap::new();
    denied_map.insert(
        "/locked/app".to_owned(),
        r#"
runner = "wasm"
program = "/bin/app"
"#
        .to_owned(),
    );
    let err = tasks
        .run_to_completion(sup.mount_dynamic_map("/locked", denied_map))
        .expect_err("dynamic mount must be rejected when dynamic_mount=false");
    assert!(err.to_string().contains("dynamic_mount = true"));

    // Refuses capability escalation in dynamic subtree (requests UDP & port 9999 outside /sandbox ceiling).
    let mut escalated_map = BTreeMap::new();
    escalated_map.insert(
        "/sandbox/bad".to_owned(),
        r#"
runner = "wasm"
program = "/bin/bad"
[capabilities]
network = ["tcp", "udp"]
tcp_ports = [9999]
"#
        .to_owned(),
    );
    let err = tasks
        .run_to_completion(sup.mount_dynamic_map("/sandbox", escalated_map))
        .expect_err("capability escalation in dynamic subtree must fail");
    assert!(err.to_string().contains("capability escalation"));

    // Accepts valid bounded dynamic subtree, starts eager child, publishes inspect, and unmounts cleanly.
    let mut valid_map = BTreeMap::new();
    valid_map.insert(
        "/sandbox/plugin".to_owned(),
        r#"
runner = "wasm"
program = "/bin/dyn-plugin"
startup = "eager"
[capabilities]
network = ["tcp"]
tcp_ports = [9000]
"#
        .to_owned(),
    );
    let mounted = tasks
        .run_to_completion(sup.mount_dynamic_map("/sandbox", valid_map))
        .expect("valid bounded dynamic subtree mounts");
    assert_eq!(mounted, "/sandbox/plugin");
    assert_eq!(rt.spawn_count("/sandbox/plugin"), 1);
    assert_eq!(
        sup.status_of("/sandbox/plugin"),
        Some(ComponentStatus::Running)
    );
    assert_eq!(sup.dynamic_subtree_monikers(), vec!["/sandbox/plugin"]);

    tasks
        .run_to_completion(sup.unmount_dynamic("/sandbox/plugin"))
        .expect("dynamic subtree unmounts cleanly");
    assert_eq!(sup.status_of("/sandbox/plugin"), None);
    assert!(
        !sup.inspect_records()
            .iter()
            .any(|rec| rec.moniker == "/sandbox/plugin"),
        "unmounted dynamic component must disappear from /components/* inspect"
    );
    assert!(sup.dynamic_subtree_monikers().is_empty());

    // Rejects moniker escape outside the parent realm (`/escape/app` under `/sandbox`).
    let mut escaped_map = BTreeMap::new();
    escaped_map.insert(
        "/escape/app".to_owned(),
        r#"
runner = "wasm"
program = "/bin/escape"
"#
        .to_owned(),
    );
    let err = tasks
        .run_to_completion(sup.mount_dynamic_map("/sandbox", escaped_map))
        .expect_err("moniker outside enclosing realm must be rejected");
    assert!(err.to_string().contains("direct child"));

    // Rejects out-of-bounds `node.after` index in `validate_dynamic_subtree` without panicking.
    let mut bad_after_node = base_node(
        "/sandbox/bad-after",
        None,
        RunnerSpec::Wasm(WasmRunnerSpec {
            program: Cow::Borrowed("/bin/bad-after"),
            sharding: WasmSharding::Singleton,
            provider: None,
            args: Cow::Borrowed(&[]),
            env: Cow::Borrowed(&[]),
            cwd: None,
            optional: false,
        }),
    );
    bad_after_node.after = Cow::Borrowed(&[99]);
    let bad_after_err = helios_component_manager::validate_dynamic_subtree(
        sup.node_by_moniker("/sandbox").unwrap(),
        &ComponentTopology {
            nodes: Cow::Owned(vec![bad_after_node]),
        },
    )
    .expect_err("out-of-bounds `after` index must return UnknownDependency");
    assert!(matches!(
        bad_after_err,
        helios_component_manager::ValidationError::UnknownDependency {
            dependency_index: 99,
            ..
        }
    ));

    // Remounting the previously unmounted moniker `/sandbox/plugin` succeeds cleanly,
    // and duplicate socket collision against an active dynamic component is rejected!
    let mut remount_map = BTreeMap::new();
    remount_map.insert(
        "/sandbox/plugin".to_owned(),
        r#"
runner = "wasm"
program = "/bin/dyn-plugin"
startup = "eager"
[capabilities]
network = ["tcp"]
tcp_ports = [9000]
[[sockets]]
kind = "tcp"
address = "0.0.0.0"
port = 9000
"#
        .to_owned(),
    );
    let remounted = tasks
        .run_to_completion(sup.mount_dynamic_map("/sandbox", remount_map))
        .expect("remount after unmount must succeed");
    assert_eq!(remounted, "/sandbox/plugin");
    assert_eq!(rt.spawn_count("/sandbox/plugin"), 2);

    let mut duplicate_sock_map = BTreeMap::new();
    duplicate_sock_map.insert(
        "/sandbox/clash".to_owned(),
        r#"
runner = "wasm"
program = "/bin/clash"
[capabilities]
network = ["tcp"]
tcp_ports = [9000]
[[sockets]]
kind = "tcp"
address = "0.0.0.0"
port = 9000
"#
        .to_owned(),
    );
    let clash_err = tasks
        .run_to_completion(sup.mount_dynamic_map("/sandbox", duplicate_sock_map))
        .expect_err("duplicate TCP socket against active component must fail");
    assert!(clash_err.to_string().contains("duplicate socket binding"));

    // Unmount `/sandbox/plugin`, then trigger a `critical = "parent"` failure on a sibling
    // inside `/sandbox` to prove parent realm reset does NOT revive the unmounted subtree!
    tasks
        .run_to_completion(sup.unmount_dynamic("/sandbox/plugin"))
        .expect("second unmount succeeds");
    let mut trigger_map = BTreeMap::new();
    trigger_map.insert(
        "/sandbox/trigger".to_owned(),
        r#"
runner = "wasm"
program = "/bin/trigger"
startup = "eager"
restart = "never"
critical = "parent"
"#
        .to_owned(),
    );
    tasks
        .run_to_completion(sup.mount_dynamic_map("/sandbox", trigger_map))
        .expect("mount trigger");
    rt.finish_child("/sandbox/trigger", ExitOutcome::Trapped);
    tasks
        .run_to_completion(sup.step_once())
        .expect("parent realm reset succeeds");
    assert_eq!(
        rt.spawn_count("/sandbox/plugin"),
        2,
        "parent realm reset must never revive an unmounted dynamic subtree"
    );
    assert_eq!(sup.status_of("/sandbox/plugin"), None);
}

#[test]
fn boot_with_pre_ready_hook_installs_providers_before_hook_and_services_after() {
    let mut root = base_node("/", None, RunnerSpec::Realm);
    root.children_indices = Cow::Borrowed(&[1, 2, 3]);
    root.oom_tier = OomTier::Protected;
    root.capabilities = full_root_ceiling();

    let mut compiler = base_node(
        "/compiler",
        Some(0),
        RunnerSpec::Wasm(WasmRunnerSpec {
            program: Cow::Borrowed("/bin/compiler.cwasm"),
            sharding: WasmSharding::Singleton,
            provider: Some(ProviderSlot::Compiler),
            args: Cow::Borrowed(&[]),
            env: Cow::Borrowed(&[]),
            cwd: None,
            optional: false,
        }),
    );
    compiler.startup = StartupPolicy::Lazy;

    let mut compositor = base_node(
        "/compositor",
        Some(0),
        RunnerSpec::Wasm(WasmRunnerSpec {
            program: Cow::Borrowed("/bin/compositor"),
            sharding: WasmSharding::Singleton,
            provider: Some(ProviderSlot::Surface),
            args: Cow::Borrowed(&[]),
            env: Cow::Borrowed(&[]),
            cwd: None,
            optional: false,
        }),
    );
    compositor.startup = StartupPolicy::Eager;
    compositor.restart = RestartPolicy::Always;
    compositor.restart_backoff_ms = 50;
    compositor.requires = HardwarePredicates {
        display: true,
        input: true,
        ..Default::default()
    };

    let mut debugger = base_node(
        "/debugger",
        Some(0),
        RunnerSpec::Wasm(WasmRunnerSpec {
            program: Cow::Borrowed("/bin/debugger"),
            sharding: WasmSharding::Singleton,
            provider: None,
            args: Cow::Borrowed(&[]),
            env: Cow::Borrowed(&[]),
            cwd: None,
            optional: false,
        }),
    );
    debugger.startup = StartupPolicy::Eager;

    let rt = MockRuntime::new(HardwareInventorySnapshot {
        display: true,
        input: true,
        ..Default::default()
    });
    let tasks = rt.tasks.clone();
    let mut sup = Supervisor::new(
        rt.clone(),
        ComponentTopology {
            nodes: Cow::Owned(vec![root, compiler, compositor, debugger]),
        },
    )
    .expect("valid topology");

    let rt_hook = rt.clone();
    tasks
        .run_to_completion(sup.boot_with_pre_ready_hook(|| async move {
            rt_hook
                .state
                .borrow_mut()
                .events_log
                .push("rc.nu".to_owned());
            Ok(())
        }))
        .expect("boot_with_pre_ready_hook succeeds");

    let log = rt.state.borrow().events_log.clone();
    let compiler_pos = log
        .iter()
        .position(|e| e == "provider:compiler:/compiler")
        .expect("compiler installed");
    let compositor_pos = log
        .iter()
        .position(|e| e == "provider:surface:/compositor")
        .expect("compositor installed");
    let rc_pos = log
        .iter()
        .position(|e| e == "rc.nu")
        .expect("pre-ready hook ran");
    let debugger_pos = log
        .iter()
        .position(|e| e == "spawn:/debugger")
        .expect("debugger spawned");
    let ready_pos = log
        .iter()
        .position(|e| e == "signal_ready")
        .expect("signal_ready emitted");

    assert!(compiler_pos < rc_pos && compositor_pos < rc_pos);
    assert!(rc_pos < debugger_pos && debugger_pos < ready_pos);

    // Unexpected `ProviderOutcome::Exited` restarts compositor when `restart = "always"`.
    let exit_tx = rt
        .state
        .borrow()
        .providers
        .iter()
        .find(|(slot, _, _)| *slot == ProviderSlot::Surface)
        .unwrap()
        .2
        .clone();
    exit_tx.try_send(ProviderOutcome::Exited).unwrap();
    tasks.run_to_completion(sup.step_once()).unwrap(); // ProviderExited -> schedules restart
    tasks.run_to_completion(sup.step_once()).unwrap(); // RestartTimerFired -> reinstalls
    assert_eq!(sup.restarts_of("/compositor"), Some(1));
    assert_eq!(
        rt.state
            .borrow()
            .providers
            .iter()
            .filter(|(slot, _, _)| *slot == ProviderSlot::Surface)
            .count(),
        2
    );
}

#[test]
fn lazy_socket_only_topology_stays_active_in_run_until_done() {
    let mut root = base_node("/", None, RunnerSpec::Realm);
    root.children_indices = Cow::Borrowed(&[1]);
    root.oom_tier = OomTier::Protected;
    root.capabilities = full_root_ceiling();

    let mut svc = base_node(
        "/svc",
        Some(0),
        RunnerSpec::Wasm(WasmRunnerSpec {
            program: Cow::Borrowed("/bin/svc"),
            sharding: WasmSharding::Singleton,
            provider: None,
            args: Cow::Borrowed(&[]),
            env: Cow::Borrowed(&[]),
            cwd: None,
            optional: false,
        }),
    );
    svc.startup = StartupPolicy::Lazy;
    svc.capabilities.network = NetRights::TCP;
    svc.capabilities.tcp_ports = PortCeiling::Set(Cow::Borrowed(&[8080]));
    svc.sockets = Cow::Borrowed(&[SocketActivationSpec::Tcp {
        address: IpAddrSpec::V4([0, 0, 0, 0]),
        port: 8080,
        backlog: 16,
    }]);

    let rt = MockRuntime::new(HardwareInventorySnapshot::default());
    let tasks = rt.tasks.clone();
    let mut sup = Supervisor::new(
        rt.clone(),
        ComponentTopology {
            nodes: Cow::Owned(vec![root, svc]),
        },
    )
    .expect("valid topology");

    tasks.run_to_completion(sup.boot()).expect("boot");
    assert_eq!(rt.spawn_count("/svc"), 0);

    // Drive `run_until_done` by one poll: it must stay Pending (not return Ready(()))
    // while `/svc`'s lazy listening socket is armed!
    {
        let mut cx = Context::from_waker(Waker::noop());
        let mut loop_fut = std::pin::pin!(sup.run_until_done());
        assert!(
            matches!(loop_fut.as_mut().poll(&mut cx), Poll::Pending),
            "lazy-socket-only topology must remain active in run_until_done()"
        );
    }

    // Deliver a TCP packet -> activates `/svc`; then stop `/svc` cleanly -> re-arms socket;
    // `run_until_done()` must STILL stay Pending!
    rt.deliver_tcp_packet(8080, b"PING");
    tasks.run_to_completion(sup.step_once()).unwrap();
    assert_eq!(rt.spawn_count("/svc"), 1);
    rt.finish_child("/svc", ExitOutcome::Exited(0));
    tasks.run_to_completion(sup.step_once()).unwrap();
    {
        let mut cx = Context::from_waker(Waker::noop());
        let mut loop_fut = std::pin::pin!(sup.run_until_done());
        assert!(
            matches!(loop_fut.as_mut().poll(&mut cx), Poll::Pending),
            "re-armed lazy socket must keep run_until_done() active"
        );
    }
}

#[test]
fn cancel_safe_event_loop_handles_control_and_exits_when_inactive() {
    use futures_lite::FutureExt as _;

    let mut root = base_node("/", None, RunnerSpec::Realm);
    root.children_indices = Cow::Borrowed(&[1]);
    root.oom_tier = OomTier::Protected;
    root.capabilities = full_root_ceiling();

    let mut svc = base_node(
        "/svc",
        Some(0),
        RunnerSpec::Wasm(WasmRunnerSpec {
            program: Cow::Borrowed("/bin/svc"),
            sharding: WasmSharding::Singleton,
            provider: None,
            args: Cow::Borrowed(&[]),
            env: Cow::Borrowed(&[]),
            cwd: None,
            optional: false,
        }),
    );
    svc.startup = StartupPolicy::Eager;
    svc.restart = RestartPolicy::Never;

    let rt = MockRuntime::new(HardwareInventorySnapshot::default());
    let tasks = rt.tasks.clone();
    let mut sup = Supervisor::new(
        rt.clone(),
        ComponentTopology {
            nodes: Cow::Owned(vec![root, svc]),
        },
    )
    .expect("supervisor");
    tasks.run_to_completion(sup.boot()).expect("boot");
    assert!(sup.has_active_work());
    assert_eq!(sup.status_of("/svc"), Some(ComponentStatus::Running));

    let (ctrl_tx, ctrl_rx) = async_channel::unbounded::<&'static str>();
    ctrl_tx.try_send("ping").expect("send control");

    // 1. Control message cancels only `recv_event()` (never mutates supervisor state).
    let mut handled_control = false;
    tasks.run_to_completion(async {
        enum Item<E> {
            Event(Option<E>),
            Control(&'static str),
        }
        let item = async { Item::Event(sup.recv_event().await) }
            .or(async { Item::Control(ctrl_rx.recv().await.expect("ctrl")) })
            .await;
        match item {
            Item::Control("ping") => handled_control = true,
            _ => panic!("expected control command first"),
        }
    });
    assert!(handled_control);
    assert!(sup.has_active_work());

    // 2. Child exits cleanly -> `handle_pending_event` runs to completion and `has_active_work()` becomes false.
    rt.finish_child("/svc", ExitOutcome::Exited(0));
    tasks.run_to_completion(async {
        while sup.has_active_work() {
            let Some(ev) = sup.recv_event().await else {
                break;
            };
            sup.handle_pending_event(ev).await.expect("handle event");
        }
    });
    assert!(!sup.has_active_work());
    assert_eq!(sup.status_of("/svc"), Some(ComponentStatus::Completed));
}
