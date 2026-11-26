//! Opt-in `helios:system/component-control` IPC server compiled into
//! `component-manager` ONLY when `--features dynamic-components` is enabled.

use std::collections::BTreeMap;
use std::future::Future;
use std::io;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use async_channel::{Receiver, Sender};
use futures_io::{AsyncRead, AsyncWrite};
use helios_api::ipc::Endpoint as IpcEndpoint;
use helios_api::task;
use helios_component_manager::{
    ComponentStateRecord, DynamicMountError, ManifestError, RuntimeError, Supervisor,
    SupervisorError, SupervisorRuntime, ValidationError,
};
use helios_wit_rpc::Endpoint;
use helios_wit_rpc::inspector::helios::system::component_control::{
    self as rpc_cc, ComponentStatus, ControlError, ControlErrorKind, DynamicDirSource,
    DynamicSubtreeSource,
};

type BoxIoFuture<T> = Pin<Box<dyn Future<Output = io::Result<T>>>>;

pub enum ControlCommand {
    List {
        reply: Sender<Result<Vec<ComponentStatus>, ControlError>>,
    },
    Start {
        moniker: String,
        reply: Sender<Result<ComponentStatus, ControlError>>,
    },
    Stop {
        moniker: String,
        reply: Sender<Result<(), ControlError>>,
    },
    Restart {
        moniker: String,
        reply: Sender<Result<ComponentStatus, ControlError>>,
    },
    MountDynamic {
        parent_moniker: String,
        source: DynamicSubtreeSource,
        reply: Sender<Result<String, ControlError>>,
    },
    UnmountDynamic {
        moniker: String,
        reply: Sender<Result<(), ControlError>>,
    },
}

pub fn spawn_control_endpoint(endpoint: IpcEndpoint, cmd_tx: Sender<ControlCommand>) {
    let ep = Arc::new(endpoint);
    let reader = IpcReader {
        endpoint: Arc::clone(&ep),
        buf: Vec::new(),
        offset: 0,
        eof: false,
        pending: None,
    };
    let writer = IpcWriter {
        endpoint: ep,
        pending: None,
    };
    let server = rpc_cc::RpcServer::new(ControlHandler { cmd_tx });
    let rpc = Endpoint::new(reader, writer, server);
    task::spawn(async move {
        let _ = rpc.drive().await;
    });
}

pub async fn handle_control_command<R: SupervisorRuntime>(
    supervisor: &mut Supervisor<R>,
    cmd: ControlCommand,
) {
    match cmd {
        ControlCommand::List { reply } => {
            let list = supervisor
                .inspect_records()
                .into_iter()
                .map(map_record)
                .collect();
            let _ = reply.send(Ok(list)).await;
        }
        ControlCommand::Start { moniker, reply } => {
            let res = supervisor
                .start_component(&moniker)
                .await
                .map(map_record)
                .map_err(map_supervisor_error);
            let _ = reply.send(res).await;
        }
        ControlCommand::Stop { moniker, reply } => {
            let res = supervisor
                .stop_component(&moniker)
                .await
                .map_err(map_supervisor_error);
            let _ = reply.send(res).await;
        }
        ControlCommand::Restart { moniker, reply } => {
            let res = supervisor
                .restart_component(&moniker)
                .await
                .map(map_record)
                .map_err(map_supervisor_error);
            let _ = reply.send(res).await;
        }
        ControlCommand::MountDynamic {
            parent_moniker,
            source,
            reply,
        } => {
            let res = match source {
                DynamicSubtreeSource::GuestDir(DynamicDirSource { subtree_name, path }) => {
                    supervisor
                        .mount_dynamic_dir(&parent_moniker, &subtree_name, Path::new(&path))
                        .await
                        .map_err(map_dynamic_mount_error)
                }
                DynamicSubtreeSource::Manifests(entries) => {
                    let mut map = BTreeMap::new();
                    let mut duplicate = None;
                    for (moniker, toml_text) in entries {
                        if map.insert(moniker.clone(), toml_text).is_some() {
                            duplicate = Some(moniker);
                            break;
                        }
                    }
                    if let Some(moniker) = duplicate {
                        Err(ControlError {
                            kind: ControlErrorKind::AlreadyExists,
                            detail: format!(
                                "duplicate component moniker `{moniker}` in dynamic manifests"
                            ),
                        })
                    } else {
                        supervisor
                            .mount_dynamic_map(&parent_moniker, map)
                            .await
                            .map_err(map_dynamic_mount_error)
                    }
                }
            };
            let _ = reply.send(res).await;
        }
        ControlCommand::UnmountDynamic { moniker, reply } => {
            let res = supervisor
                .unmount_dynamic(&moniker)
                .await
                .map_err(map_supervisor_error);
            let _ = reply.send(res).await;
        }
    }
}

fn map_record(rec: ComponentStateRecord) -> ComponentStatus {
    ComponentStatus {
        moniker: rec.moniker,
        program: rec.runner.to_owned(),
        state: rec.status.as_str().to_owned(),
        instance_id: rec.instance_id,
        restarts: rec.restarts,
    }
}

fn map_validation_error_kind(err: &ValidationError) -> ControlErrorKind {
    match err {
        ValidationError::DynamicMountNotPermitted { .. }
        | ValidationError::CapabilityEscalation { .. }
        | ValidationError::OomTierEscalation { .. }
        | ValidationError::SocketAuthorityDenied { .. }
        | ValidationError::MountAuthorityDenied { .. }
        | ValidationError::WitInterfaceDenied { .. }
        | ValidationError::DynamicCriticalityDenied { .. }
        | ValidationError::DynamicProviderDenied { .. } => ControlErrorKind::PermissionDenied,
        ValidationError::DuplicateMoniker { .. }
        | ValidationError::DuplicateExpose { .. }
        | ValidationError::DuplicateChannel { .. }
        | ValidationError::DuplicateSocket { .. }
        | ValidationError::DuplicateProviderSlot { .. } => ControlErrorKind::AlreadyExists,
        ValidationError::EmptyTopology
        | ValidationError::InvalidRootMoniker { .. }
        | ValidationError::InvalidMoniker { .. }
        | ValidationError::MissingParent { .. }
        | ValidationError::RoutingCycle { .. }
        | ValidationError::UnknownRouteTarget { .. }
        | ValidationError::UnexposedInterface { .. }
        | ValidationError::UnknownDependency { .. }
        | ValidationError::RootCriticalParent { .. }
        | ValidationError::InvalidRunnerConfig { .. } => ControlErrorKind::InvalidArgument,
    }
}

fn map_manifest_error(err: ManifestError) -> ControlError {
    let kind = match &err {
        ManifestError::Validation(v) => map_validation_error_kind(v),
        ManifestError::Io { source, .. } => match source.kind() {
            io::ErrorKind::NotFound => ControlErrorKind::NotFound,
            io::ErrorKind::PermissionDenied => ControlErrorKind::PermissionDenied,
            _ => ControlErrorKind::Internal,
        },
        ManifestError::RootNotDirectory { .. }
        | ManifestError::MissingManifest { .. }
        | ManifestError::Parse { .. }
        | ManifestError::InvalidField { .. }
        | ManifestError::NonUtf8Path { .. } => ControlErrorKind::InvalidArgument,
    };
    ControlError {
        kind,
        detail: err.to_string(),
    }
}

fn map_supervisor_error(err: SupervisorError) -> ControlError {
    let kind = match &err {
        SupervisorError::UnknownComponent { .. } => ControlErrorKind::NotFound,
        SupervisorError::Validation(v) => map_validation_error_kind(v),
        SupervisorError::Runtime(RuntimeError::PermissionDenied { .. }) => {
            ControlErrorKind::PermissionDenied
        }
        SupervisorError::Runtime(RuntimeError::NotFound { .. }) => ControlErrorKind::NotFound,
        SupervisorError::Runtime(RuntimeError::Unavailable { .. }) => ControlErrorKind::Unavailable,
        SupervisorError::Runtime(RuntimeError::Other { .. })
        | SupervisorError::FatalEscalated { .. } => ControlErrorKind::Internal,
    };
    ControlError {
        kind,
        detail: err.to_string(),
    }
}

fn map_dynamic_mount_error(err: DynamicMountError) -> ControlError {
    match err {
        DynamicMountError::Manifest(manifest) => map_manifest_error(manifest),
        DynamicMountError::Supervisor(supervisor) => map_supervisor_error(supervisor),
    }
}

struct ControlHandler {
    cmd_tx: Sender<ControlCommand>,
}

impl rpc_cc::RpcHandler for ControlHandler {
    async fn list_components(&self) -> Result<Vec<ComponentStatus>, ControlError> {
        let (tx, rx) = async_channel::bounded(1);
        self.cmd_tx
            .send(ControlCommand::List { reply: tx })
            .await
            .map_err(|_| unavailable())?;
        rx.recv().await.map_err(|_| unavailable())?
    }

    async fn start(&self, moniker: String) -> Result<ComponentStatus, ControlError> {
        let (tx, rx) = async_channel::bounded(1);
        self.cmd_tx
            .send(ControlCommand::Start { moniker, reply: tx })
            .await
            .map_err(|_| unavailable())?;
        rx.recv().await.map_err(|_| unavailable())?
    }

    async fn stop(&self, moniker: String) -> Result<(), ControlError> {
        let (tx, rx) = async_channel::bounded(1);
        self.cmd_tx
            .send(ControlCommand::Stop { moniker, reply: tx })
            .await
            .map_err(|_| unavailable())?;
        rx.recv().await.map_err(|_| unavailable())?
    }

    async fn restart(&self, moniker: String) -> Result<ComponentStatus, ControlError> {
        let (tx, rx) = async_channel::bounded(1);
        self.cmd_tx
            .send(ControlCommand::Restart { moniker, reply: tx })
            .await
            .map_err(|_| unavailable())?;
        rx.recv().await.map_err(|_| unavailable())?
    }

    async fn mount_dynamic(
        &self,
        parent_moniker: String,
        source: DynamicSubtreeSource,
    ) -> Result<String, ControlError> {
        let (tx, rx) = async_channel::bounded(1);
        self.cmd_tx
            .send(ControlCommand::MountDynamic {
                parent_moniker,
                source,
                reply: tx,
            })
            .await
            .map_err(|_| unavailable())?;
        rx.recv().await.map_err(|_| unavailable())?
    }

    async fn unmount_dynamic(&self, moniker: String) -> Result<(), ControlError> {
        let (tx, rx) = async_channel::bounded(1);
        self.cmd_tx
            .send(ControlCommand::UnmountDynamic { moniker, reply: tx })
            .await
            .map_err(|_| unavailable())?;
        rx.recv().await.map_err(|_| unavailable())?
    }
}

fn unavailable() -> ControlError {
    ControlError {
        kind: ControlErrorKind::Unavailable,
        detail: "component-manager supervisor event loop closed".to_owned(),
    }
}

pub fn new_control_queue() -> (Sender<ControlCommand>, Receiver<ControlCommand>) {
    async_channel::bounded(16)
}

struct IpcReader {
    endpoint: Arc<IpcEndpoint>,
    buf: Vec<u8>,
    offset: usize,
    eof: bool,
    pending: Option<BoxIoFuture<Vec<u8>>>,
}

impl AsyncRead for IpcReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        if out.is_empty() {
            return Poll::Ready(Ok(0));
        }
        loop {
            if self.offset < self.buf.len() {
                let n = (self.buf.len() - self.offset).min(out.len());
                out[..n].copy_from_slice(&self.buf[self.offset..self.offset + n]);
                self.offset += n;
                if self.offset == self.buf.len() {
                    self.buf.clear();
                    self.offset = 0;
                }
                return Poll::Ready(Ok(n));
            }
            if self.eof {
                return Poll::Ready(Ok(0));
            }
            if self.pending.is_none() {
                let ep = Arc::clone(&self.endpoint);
                self.pending = Some(Box::pin(async move {
                    match ep.read(16 * 1024).await {
                        Ok(Some(bytes)) => Ok(bytes),
                        Ok(None) | Err(_) => Ok(Vec::new()),
                    }
                }));
            }
            match self.pending.as_mut().expect("ipc read").as_mut().poll(cx) {
                Poll::Ready(Ok(bytes)) => {
                    self.pending = None;
                    if bytes.is_empty() {
                        self.eof = true;
                        return Poll::Ready(Ok(0));
                    }
                    self.buf = bytes;
                    self.offset = 0;
                }
                Poll::Ready(Err(err)) => {
                    self.pending = None;
                    return Poll::Ready(Err(err));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

struct IpcWriter {
    endpoint: Arc<IpcEndpoint>,
    pending: Option<(usize, BoxIoFuture<()>)>,
}

impl AsyncWrite for IpcWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if self.pending.is_none() {
            let ep = Arc::clone(&self.endpoint);
            let data = buf.to_vec();
            let len = data.len();
            self.pending = Some((
                len,
                Box::pin(async move {
                    ep.write(data)
                        .await
                        .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "IPC peer closed"))
                }),
            ));
        }
        let (len, fut) = self.pending.as_mut().expect("ipc write");
        match fut.as_mut().poll(cx) {
            Poll::Ready(Ok(())) => {
                let n = *len;
                self.pending = None;
                Poll::Ready(Ok(n))
            }
            Poll::Ready(Err(err)) => {
                self.pending = None;
                Poll::Ready(Err(err))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some((_, fut)) = self.pending.as_mut() {
            match fut.as_mut().poll(cx) {
                Poll::Ready(res) => {
                    self.pending = None;
                    return Poll::Ready(res);
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let _ = self.as_mut().poll_flush(cx);
        self.endpoint.close_write();
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;
    use std::cell::RefCell;
    use std::rc::Rc;
    use std::time::Duration;

    use async_channel::Receiver;
    use helios_component_manager::{
        CapabilityCeiling, ComponentNode, ComponentStateRecord, ComponentTopology, Criticality,
        EscalationAction, ExitOutcome, FatalEscalation, HardwareInventorySnapshot,
        HardwarePredicates, IpcChannelEnd, LifecycleKind, MountSpec, NetRights, OomTier,
        ProviderEndpoint, ProviderOutcome, ProviderSlot, RestartPolicy, RunnerSpec, RuntimeError,
        SpawnComponentArgs, StartupPolicy, Supervisor, SupervisorRuntime, TcpSocketListener,
        VsockSocketListener,
    };

    use super::*;

    struct MockChild;

    impl helios_component_manager::ChildProcess for MockChild {
        fn instance_id(&self) -> Option<u64> {
            Some(42)
        }

        fn signal(&self, _signal: u8) -> Result<(), RuntimeError> {
            Ok(())
        }

        async fn wait(&self) -> Result<ExitOutcome, RuntimeError> {
            std::future::pending().await
        }
    }

    struct MockProvider;

    impl ProviderEndpoint for MockProvider {
        fn instance_id(&self) -> Option<u64> {
            Some(1)
        }

        async fn wait_exit(&self) -> ProviderOutcome {
            std::future::pending().await
        }

        fn stop(&self) {}
    }

    struct MockIpc;

    impl IpcChannelEnd for MockIpc {
        async fn read(&self, _max_bytes: u32) -> Result<Option<Vec<u8>>, RuntimeError> {
            Ok(None)
        }

        async fn write(&self, _bytes: Vec<u8>) -> Result<(), RuntimeError> {
            Ok(())
        }

        fn close_write(&self) {}
    }

    struct MockTcp;

    impl TcpSocketListener for MockTcp {
        async fn wait_readable(&self) -> Result<bool, RuntimeError> {
            std::future::pending().await
        }
    }

    struct MockVsock;

    impl VsockSocketListener for MockVsock {
        async fn wait_readable(&self) -> Result<bool, RuntimeError> {
            std::future::pending().await
        }
    }

    #[derive(Clone, Default)]
    struct MockRuntime {
        records: Rc<RefCell<Vec<ComponentStateRecord>>>,
    }

    impl SupervisorRuntime for MockRuntime {
        type Child = MockChild;
        type Provider = MockProvider;
        type IpcEnd = MockIpc;
        type TcpListener = MockTcp;
        type VsockListener = MockVsock;

        fn now_ms(&self) -> u64 {
            0
        }

        async fn sleep(&self, _duration: Duration) {}

        fn spawn_task<F: Future<Output = ()> + 'static>(&self, _future: F) {}

        fn path_exists(&self, _path: &str) -> bool {
            true
        }

        fn hardware_inventory(&self) -> Result<HardwareInventorySnapshot, RuntimeError> {
            Ok(HardwareInventorySnapshot::default())
        }

        fn subscribe_hardware(&self) -> Option<Receiver<HardwareInventorySnapshot>> {
            None
        }

        async fn mount(&self, _spec: &MountSpec) -> Result<(), RuntimeError> {
            Ok(())
        }

        fn ipc_channel(&self) -> (Self::IpcEnd, Self::IpcEnd) {
            (MockIpc, MockIpc)
        }

        async fn bind_tcp(
            &self,
            _address: helios_component_manager::IpAddrSpec,
            _port: u16,
            _backlog: u16,
        ) -> Result<Self::TcpListener, RuntimeError> {
            Ok(MockTcp)
        }

        async fn bind_vsock(
            &self,
            _port: u32,
            _backlog: u32,
        ) -> Result<Self::VsockListener, RuntimeError> {
            Ok(MockVsock)
        }

        async fn install_provider(
            &self,
            _slot: ProviderSlot,
            _node: &ComponentNode,
        ) -> Result<Self::Provider, RuntimeError> {
            Ok(MockProvider)
        }

        async fn spawn_component(
            &self,
            _args: SpawnComponentArgs<Self::TcpListener, Self::VsockListener, Self::IpcEnd>,
        ) -> Result<Self::Child, RuntimeError> {
            Ok(MockChild)
        }

        fn publish_inspect(&self, records: &[ComponentStateRecord]) {
            *self.records.borrow_mut() = records.to_vec();
        }

        async fn signal_ready(&self) -> Result<(), RuntimeError> {
            Ok(())
        }

        async fn escalate_fatal(&self, _report: FatalEscalation) -> Result<(), RuntimeError> {
            Ok(())
        }
    }

    fn realm_node(
        moniker: &'static str,
        parent: Option<usize>,
        children: &'static [usize],
        dynamic_mount: bool,
        oom_tier: OomTier,
        capabilities: CapabilityCeiling,
    ) -> ComponentNode {
        ComponentNode {
            moniker: Cow::Borrowed(moniker),
            instance_name: Cow::Borrowed(moniker.trim_start_matches('/')),
            parent_index: parent,
            children_indices: Cow::Borrowed(children),
            runner: RunnerSpec::Realm,
            startup: StartupPolicy::Lazy,
            lifecycle: LifecycleKind::Service,
            requires: HardwarePredicates::NONE,
            after: Cow::Borrowed(&[]),
            mounts: Cow::Borrowed(&[]),
            restart: RestartPolicy::Never,
            restart_backoff_ms: 250,
            restart_backoff_max_ms: 30_000,
            burst_limit: 5,
            burst_window_ms: 60_000,
            stop_timeout_ms: 5_000,
            critical: Criticality::None,
            escalation: EscalationAction::Halt,
            oom_tier,
            dynamic_mount,
            capabilities,
            exposes: Cow::Borrowed(&[]),
            routes: Cow::Borrowed(&[]),
            sockets: Cow::Borrowed(&[]),
        }
    }

    fn make_supervisor() -> Supervisor<MockRuntime> {
        let mut root_cap = CapabilityCeiling::EMPTY;
        root_cap.network = NetRights::TCP;
        let mut apps_cap = CapabilityCeiling::EMPTY;
        apps_cap.network = NetRights::TCP;
        let topology = ComponentTopology {
            nodes: Cow::Owned(vec![
                realm_node(
                    "/",
                    None,
                    &[1, 2],
                    false,
                    OomTier::Protected,
                    root_cap.clone(),
                ),
                realm_node("/apps", Some(0), &[], true, OomTier::User, apps_cap),
                realm_node(
                    "/locked",
                    Some(0),
                    &[],
                    false,
                    OomTier::User,
                    CapabilityCeiling::EMPTY,
                ),
            ]),
        };
        Supervisor::new(MockRuntime::default(), topology).expect("supervisor initializes")
    }

    #[test]
    fn handle_control_command_mounts_unmounts_and_maps_errors() {
        futures_lite::future::block_on(async {
            let mut sup = make_supervisor();
            sup.boot().await.expect("boot");

            // 1. Mount via `Manifests` under opted-in `/apps` succeeds.
            let (tx, rx) = async_channel::bounded(1);
            handle_control_command(
                &mut sup,
                ControlCommand::MountDynamic {
                    parent_moniker: "/apps".to_owned(),
                    source: DynamicSubtreeSource::Manifests(vec![(
                        "/apps/hello".to_owned(),
                        "runner = \"wasm\"\nprogram = \"/bin/hello\"\noom_tier = \"user\"\n"
                            .to_owned(),
                    )]),
                    reply: tx,
                },
            )
            .await;
            let mounted = rx.recv().await.unwrap().expect("mount_dynamic succeeds");
            assert_eq!(mounted, "/apps/hello");

            // 2. Duplicate moniker maps to `AlreadyExists`.
            let (tx, rx) = async_channel::bounded(1);
            handle_control_command(
                &mut sup,
                ControlCommand::MountDynamic {
                    parent_moniker: "/apps".to_owned(),
                    source: DynamicSubtreeSource::Manifests(vec![(
                        "/apps/hello".to_owned(),
                        "runner = \"wasm\"\nprogram = \"/bin/hello\"\n".to_owned(),
                    )]),
                    reply: tx,
                },
            )
            .await;
            let err = rx.recv().await.unwrap().expect_err("duplicate must fail");
            assert_eq!(err.kind, ControlErrorKind::AlreadyExists);

            // 3. Mounting under `dynamic_mount = false` maps to `PermissionDenied`.
            let (tx, rx) = async_channel::bounded(1);
            handle_control_command(
                &mut sup,
                ControlCommand::MountDynamic {
                    parent_moniker: "/locked".to_owned(),
                    source: DynamicSubtreeSource::Manifests(vec![(
                        "/locked/svc".to_owned(),
                        "runner = \"wasm\"\nprogram = \"/bin/svc\"\n".to_owned(),
                    )]),
                    reply: tx,
                },
            )
            .await;
            let err = rx.recv().await.unwrap().expect_err("locked parent fails");
            assert_eq!(err.kind, ControlErrorKind::PermissionDenied);

            // 4. Exceeding parent capability or OOM ceiling maps to `PermissionDenied`.
            let (tx, rx) = async_channel::bounded(1);
            handle_control_command(
                &mut sup,
                ControlCommand::MountDynamic {
                    parent_moniker: "/apps".to_owned(),
                    source: DynamicSubtreeSource::Manifests(vec![(
                        "/apps/escalate".to_owned(),
                        "runner = \"wasm\"\nprogram = \"/bin/x\"\noom_tier = \"protected\"\n"
                            .to_owned(),
                    )]),
                    reply: tx,
                },
            )
            .await;
            let err = rx.recv().await.unwrap().expect_err("oom escalation fails");
            assert_eq!(err.kind, ControlErrorKind::PermissionDenied);

            // 5. Missing parent maps to `NotFound`.
            let (tx, rx) = async_channel::bounded(1);
            handle_control_command(
                &mut sup,
                ControlCommand::MountDynamic {
                    parent_moniker: "/missing".to_owned(),
                    source: DynamicSubtreeSource::Manifests(vec![(
                        "/missing/a".to_owned(),
                        "runner = \"realm\"\n".to_owned(),
                    )]),
                    reply: tx,
                },
            )
            .await;
            let err = rx.recv().await.unwrap().expect_err("missing parent fails");
            assert_eq!(err.kind, ControlErrorKind::NotFound);

            // 6. Malformed TOML maps to `InvalidArgument`.
            let (tx, rx) = async_channel::bounded(1);
            handle_control_command(
                &mut sup,
                ControlCommand::MountDynamic {
                    parent_moniker: "/apps".to_owned(),
                    source: DynamicSubtreeSource::Manifests(vec![(
                        "/apps/bad".to_owned(),
                        "unknown_field = 123\n".to_owned(),
                    )]),
                    reply: tx,
                },
            )
            .await;
            let err = rx.recv().await.unwrap().expect_err("bad manifest fails");
            assert_eq!(err.kind, ControlErrorKind::InvalidArgument);

            // 7. Unmount succeeds and second unmount returns `NotFound`.
            let (tx, rx) = async_channel::bounded(1);
            handle_control_command(
                &mut sup,
                ControlCommand::UnmountDynamic {
                    moniker: "/apps/hello".to_owned(),
                    reply: tx,
                },
            )
            .await;
            rx.recv().await.unwrap().expect("unmount succeeds");

            let (tx, rx) = async_channel::bounded(1);
            handle_control_command(
                &mut sup,
                ControlCommand::UnmountDynamic {
                    moniker: "/apps/hello".to_owned(),
                    reply: tx,
                },
            )
            .await;
            let err = rx.recv().await.unwrap().expect_err("second unmount fails");
            assert_eq!(err.kind, ControlErrorKind::NotFound);
        });
    }
}
