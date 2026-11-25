//! Auto-generated `helios-wit-rpc` server bridge forwarding every
//! `world inspector-rpc` interface straight to the worker's imported kernel
//! capabilities with zero user-space policy checks.
//!
//! Every boundary (directory rights, mount/btrfs rights, `programs`/`container`
//! spawning, `virtualize`, observation scopes, `instance-control`, `snapshot`,
//! `processors`, `net`, `serial`) is enforced directly by the kernel against
//! this worker's attenuated `ProcessAuthority`.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use async_channel::Sender;
use helios_api::bindings::helios::system as raw_sys;
use helios_api::bindings::wasi::clocks::system_clock as raw_clock;
use helios_api::bindings::wasi::filesystem::{preopens as raw_preopens, types as raw_fs};
use helios_api::bindings::wit_stream;
use helios_api::stream_closed;
use helios_wit_rpc::inspector::helios::system::{
    btrfs as rpc_btrfs, component_control as rpc_cc, filters as rpc_filters,
    inspect as rpc_inspect, instances as rpc_instances, ipc as rpc_ipc, memory as rpc_memory,
    mounts as rpc_mounts, net as rpc_net, processors as rpc_processors, profiling as rpc_profiling,
    programs as rpc_programs, serial as rpc_serial, snapshot as rpc_snapshot,
    tracing as rpc_tracing, vsock as rpc_vsock,
};
use helios_wit_rpc::inspector::wasi::clocks::system_clock as rpc_clock;
use helios_wit_rpc::inspector::wasi::filesystem::{preopens as rpc_preopens, types as rpc_fs};
use helios_wit_rpc::{
    Dispatcher, FutureReader, PeerHandle, ResourceEntry, ResourceSlotAccess, ServerInvocation,
    StreamReader, WireError, future as rpc_future, stream as rpc_stream,
};

#[cfg(target_arch = "wasm32")]
pub type LocalTask = Pin<Box<dyn Future<Output = ()>>>;
#[cfg(not(target_arch = "wasm32"))]
pub type LocalTask = Pin<Box<dyn Future<Output = ()> + Send>>;

/// Handle to queue stream-pumping futures onto the worker's single component
/// future loop (never uses `wit_bindgen::spawn`).
#[derive(Clone)]
pub struct TaskSpawner {
    tx: Sender<LocalTask>,
}

impl TaskSpawner {
    pub fn new(tx: Sender<LocalTask>) -> Self {
        Self { tx }
    }

    pub fn spawn(&self, fut: impl Future<Output = ()> + helios_wit_rpc::MaybeSend + 'static) {
        let _ = self.tx.try_send(Box::pin(fut));
    }
}

/// Connection-scoped resource table entry unifying every WIT resource across
/// `world inspector-rpc` so cross-interface resource passing (such as
/// `wasi:filesystem/preopens` -> `wasi:filesystem/types.descriptor`) shares
/// one handle table with zero dynamic dispatch.
pub enum WorkerResource {
    Child(Arc<raw_sys::programs::Child>),
    Container(Arc<raw_sys::programs::Container>),
    Endpoint(Arc<raw_sys::ipc::Endpoint>),
    TcpListener(Arc<raw_sys::net::TcpListener>),
    TcpStream(Arc<raw_sys::net::TcpStream>),
    UdpSocket(Arc<raw_sys::net::UdpSocket>),
    VsockListener(Arc<raw_sys::vsock::VsockListener>),
    VsockStream(Arc<raw_sys::vsock::VsockStream>),
    SerialPort(Arc<raw_sys::serial::SerialPort>),
    Publication(Arc<raw_sys::inspect::Publication>),
    SamplingSession(Arc<raw_sys::profiling::SamplingSession>),
    SnapshotHold(Arc<raw_sys::snapshot::SnapshotHold>),
    Descriptor(Arc<raw_fs::Descriptor>),
}

impl ResourceEntry for WorkerResource {
    fn kind_name(&self) -> &'static str {
        match self {
            Self::Child(_) => "child",
            Self::Container(_) => "container",
            Self::Endpoint(_) => "endpoint",
            Self::TcpListener(_) => "tcp-listener",
            Self::TcpStream(_) => "tcp-stream",
            Self::UdpSocket(_) => "udp-socket",
            Self::VsockListener(_) => "vsock-listener",
            Self::VsockStream(_) => "vsock-stream",
            Self::SerialPort(_) => "serial-port",
            Self::Publication(_) => "publication",
            Self::SamplingSession(_) => "sampling-session",
            Self::SnapshotHold(_) => "snapshot-hold",
            Self::Descriptor(_) => "descriptor",
        }
    }
}

macro_rules! impl_slot {
    ($marker:ty, $inner:ty, $variant:ident) => {
        impl ResourceSlotAccess<$marker, $inner> for WorkerResource {
            fn into_entry(arc: Arc<$inner>) -> Self {
                Self::$variant(arc)
            }

            fn borrow_entry(&self) -> Option<&Arc<$inner>> {
                match self {
                    Self::$variant(arc) => Some(arc),
                    _ => None,
                }
            }

            fn take_entry(self) -> Result<Arc<$inner>, Self> {
                match self {
                    Self::$variant(arc) => Ok(arc),
                    other => Err(other),
                }
            }
        }
    };
}

impl_slot!(rpc_programs::Child, raw_sys::programs::Child, Child);
impl_slot!(
    rpc_programs::Container,
    raw_sys::programs::Container,
    Container
);
impl_slot!(rpc_ipc::Endpoint, raw_sys::ipc::Endpoint, Endpoint);
impl_slot!(rpc_net::TcpListener, raw_sys::net::TcpListener, TcpListener);
impl_slot!(rpc_net::TcpStream, raw_sys::net::TcpStream, TcpStream);
impl_slot!(rpc_net::UdpSocket, raw_sys::net::UdpSocket, UdpSocket);
impl_slot!(
    rpc_vsock::VsockListener,
    raw_sys::vsock::VsockListener,
    VsockListener
);
impl_slot!(
    rpc_vsock::VsockStream,
    raw_sys::vsock::VsockStream,
    VsockStream
);
impl_slot!(
    rpc_serial::SerialPort,
    raw_sys::serial::SerialPort,
    SerialPort
);
impl_slot!(
    rpc_inspect::Publication,
    raw_sys::inspect::Publication,
    Publication
);
impl_slot!(
    rpc_profiling::SamplingSession,
    raw_sys::profiling::SamplingSession,
    SamplingSession
);
impl_slot!(
    rpc_snapshot::SnapshotHold,
    raw_sys::snapshot::SnapshotHold,
    SnapshotHold
);
impl_slot!(rpc_fs::Descriptor, raw_fs::Descriptor, Descriptor);

/// Unified dispatcher composing every generated `world inspector-rpc` server
/// over a single shared [`WorkerResource`] table.
pub struct WorkerDispatcher {
    programs: rpc_programs::RpcServer<ProgramsBridge>,
    mounts: rpc_mounts::RpcServer<MountsBridge>,
    btrfs: rpc_btrfs::RpcServer<BtrfsBridge>,
    inspect: rpc_inspect::RpcServer<InspectBridge>,
    tracing: rpc_tracing::RpcServer<TracingBridge>,
    profiling: rpc_profiling::RpcServer<ProfilingBridge>,
    instances: rpc_instances::RpcServer<InstancesBridge>,
    snapshot: rpc_snapshot::RpcServer<SnapshotBridge>,
    processors: rpc_processors::RpcServer<ProcessorsBridge>,
    net: rpc_net::RpcServer<NetBridge>,
    serial: rpc_serial::RpcServer<SerialBridge>,
    component_control: rpc_cc::RpcServer<ComponentControlBridge>,
    fs_preopens: rpc_preopens::RpcServer<PreopensBridge>,
    fs_types: rpc_fs::RpcServer<FilesystemBridge>,
}

impl WorkerDispatcher {
    pub fn new(spawner: TaskSpawner, component_control_peer: Option<PeerHandle>) -> Self {
        Self {
            programs: rpc_programs::RpcServer::new(ProgramsBridge {
                spawner: spawner.clone(),
            }),
            mounts: rpc_mounts::RpcServer::new(MountsBridge),
            btrfs: rpc_btrfs::RpcServer::new(BtrfsBridge),
            inspect: rpc_inspect::RpcServer::new(InspectBridge),
            tracing: rpc_tracing::RpcServer::new(TracingBridge {
                spawner: spawner.clone(),
            }),
            profiling: rpc_profiling::RpcServer::new(ProfilingBridge),
            instances: rpc_instances::RpcServer::new(InstancesBridge),
            snapshot: rpc_snapshot::RpcServer::new(SnapshotBridge),
            processors: rpc_processors::RpcServer::new(ProcessorsBridge),
            net: rpc_net::RpcServer::new(NetBridge),
            serial: rpc_serial::RpcServer::new(SerialBridge),
            component_control: rpc_cc::RpcServer::new(ComponentControlBridge {
                peer: component_control_peer,
            }),
            fs_preopens: rpc_preopens::RpcServer::new(PreopensBridge),
            fs_types: rpc_fs::RpcServer::new(FilesystemBridge { spawner }),
        }
    }
}

impl Dispatcher for WorkerDispatcher {
    type Resource = WorkerResource;

    fn supports(&self, instance: &str, func: &str) -> bool {
        self.programs.supports_call(instance, func)
            || self.mounts.supports_call(instance, func)
            || self.btrfs.supports_call(instance, func)
            || self.inspect.supports_call(instance, func)
            || self.tracing.supports_call(instance, func)
            || self.profiling.supports_call(instance, func)
            || self.instances.supports_call(instance, func)
            || self.snapshot.supports_call(instance, func)
            || self.processors.supports_call(instance, func)
            || self.net.supports_call(instance, func)
            || self.serial.supports_call(instance, func)
            || self.component_control.supports_call(instance, func)
            || self.fs_preopens.supports_call(instance, func)
            || self.fs_types.supports_call(instance, func)
    }

    async fn dispatch<'a>(
        &'a self,
        ctx: ServerInvocation<'a, Self::Resource>,
        instance: &'a str,
        func: &'a str,
    ) -> Result<(), WireError> {
        if self.programs.supports_call(instance, func) {
            self.programs.dispatch_with(ctx, instance, func).await
        } else if self.mounts.supports_call(instance, func) {
            self.mounts.dispatch_with(ctx, instance, func).await
        } else if self.btrfs.supports_call(instance, func) {
            self.btrfs.dispatch_with(ctx, instance, func).await
        } else if self.inspect.supports_call(instance, func) {
            self.inspect.dispatch_with(ctx, instance, func).await
        } else if self.tracing.supports_call(instance, func) {
            self.tracing.dispatch_with(ctx, instance, func).await
        } else if self.profiling.supports_call(instance, func) {
            self.profiling.dispatch_with(ctx, instance, func).await
        } else if self.instances.supports_call(instance, func) {
            self.instances.dispatch_with(ctx, instance, func).await
        } else if self.snapshot.supports_call(instance, func) {
            self.snapshot.dispatch_with(ctx, instance, func).await
        } else if self.processors.supports_call(instance, func) {
            self.processors.dispatch_with(ctx, instance, func).await
        } else if self.net.supports_call(instance, func) {
            self.net.dispatch_with(ctx, instance, func).await
        } else if self.serial.supports_call(instance, func) {
            self.serial.dispatch_with(ctx, instance, func).await
        } else if self.component_control.supports_call(instance, func) {
            self.component_control
                .dispatch_with(ctx, instance, func)
                .await
        } else if self.fs_preopens.supports_call(instance, func) {
            self.fs_preopens.dispatch_with(ctx, instance, func).await
        } else if self.fs_types.supports_call(instance, func) {
            self.fs_types.dispatch_with(ctx, instance, func).await
        } else {
            Err(WireError::MalformedPayload {
                context: "WorkerDispatcher::dispatch".to_owned(),
                detail: format!("unsupported method {instance}.{func}"),
            })
        }
    }
}

// ---------------------------------------------------------------------------
// 1. helios:system/programs
// ---------------------------------------------------------------------------

struct ProgramsBridge {
    spawner: TaskSpawner,
}

impl rpc_programs::RpcHandler for ProgramsBridge {
    type Child = raw_sys::programs::Child;
    type Container = raw_sys::programs::Container;
    type Endpoint = raw_sys::ipc::Endpoint;
    type TcpListener = raw_sys::net::TcpListener;
    type TcpStream = raw_sys::net::TcpStream;
    type SerialPort = raw_sys::serial::SerialPort;
    type VsockListener = raw_sys::vsock::VsockListener;
    type VsockStream = raw_sys::vsock::VsockStream;

    async fn child_stdin(
        &self,
        self_: &Self::Child,
        mut data: StreamReader<u8>,
    ) -> FutureReader<Result<(), ()>> {
        let (mut wit_tx, wit_rx) = wit_stream::new::<u8>();
        let done_wit = self_.stdin(wit_rx);
        let (fut_tx, fut_rx) = rpc_future::<Result<(), ()>>();
        self.spawner.spawn(async move {
            while let Ok(Some(chunk)) = data.next_batch().await {
                if !chunk.is_empty() {
                    let remaining = wit_tx.write_all(chunk).await;
                    if !remaining.is_empty() {
                        break;
                    }
                }
            }
            drop(wit_tx);
            let outcome = done_wit.await;
            let _ = fut_tx.resolve(outcome).await;
        });
        fut_rx
    }

    async fn child_stdout(
        &self,
        self_: &Self::Child,
    ) -> (StreamReader<u8>, FutureReader<Result<(), ()>>) {
        let (mut wit_rx, done_wit) = self_.stdout();
        let (mut rpc_tx, rpc_rx) = rpc_stream::<u8>();
        let (fut_tx, fut_rx) = rpc_future::<Result<(), ()>>();
        self.spawner.spawn(async move {
            let mut buf = Vec::with_capacity(16 * 1024);
            loop {
                let (res, chunk) = wit_rx.read(buf).await;
                if !chunk.is_empty() {
                    if rpc_tx.send_batch(chunk).await.is_err() {
                        break;
                    }
                    buf = Vec::with_capacity(16 * 1024);
                } else {
                    buf = chunk;
                }
                if stream_closed(res) {
                    break;
                }
            }
            let _ = rpc_tx.close().await;
            let outcome = done_wit.await;
            let _ = fut_tx.resolve(outcome).await;
        });
        (rpc_rx, fut_rx)
    }

    async fn child_stderr(
        &self,
        self_: &Self::Child,
    ) -> (StreamReader<u8>, FutureReader<Result<(), ()>>) {
        let (mut wit_rx, done_wit) = self_.stderr();
        let (mut rpc_tx, rpc_rx) = rpc_stream::<u8>();
        let (fut_tx, fut_rx) = rpc_future::<Result<(), ()>>();
        self.spawner.spawn(async move {
            let mut buf = Vec::with_capacity(16 * 1024);
            loop {
                let (res, chunk) = wit_rx.read(buf).await;
                if !chunk.is_empty() {
                    if rpc_tx.send_batch(chunk).await.is_err() {
                        break;
                    }
                    buf = Vec::with_capacity(16 * 1024);
                } else {
                    buf = chunk;
                }
                if stream_closed(res) {
                    break;
                }
            }
            let _ = rpc_tx.close().await;
            let outcome = done_wit.await;
            let _ = fut_tx.resolve(outcome).await;
        });
        (rpc_rx, fut_rx)
    }

    async fn child_instance_id(&self, self_: &Self::Child) -> u64 {
        self_.instance_id()
    }

    async fn child_signal(
        &self,
        self_: &Self::Child,
        signal: u8,
    ) -> Result<(), rpc_programs::SpawnError> {
        self_.signal(signal).map_err(map_spawn_error)
    }

    async fn child_wait(
        &self,
        self_: &Self::Child,
    ) -> Result<rpc_programs::ExitStatus, rpc_programs::SpawnError> {
        self_
            .wait()
            .await
            .map(map_exit_status)
            .map_err(map_spawn_error)
    }

    async fn container_spawn(
        &self,
        self_: &Self::Container,
        request: rpc_programs::ContainerSpawnRequest<
            Self::TcpListener,
            Self::VsockListener,
            Self::TcpStream,
            Self::VsockStream,
            Self::SerialPort,
        >,
    ) -> Result<Self::Child, rpc_programs::SpawnError> {
        self_
            .spawn(raw_sys::programs::ContainerSpawnRequest {
                name: request.name,
                args: request.args,
                env: request.env,
                path: request.path,
                cwd: request.cwd,
                sockets: request
                    .sockets
                    .into_iter()
                    .map(map_inherited_socket_in)
                    .collect(),
                credentials: request.credentials.map(map_container_creds_in),
            })
            .await
            .map_err(map_spawn_error)
    }

    async fn container_exec(
        &self,
        self_: &Self::Container,
        request: rpc_programs::ContainerExecRequest,
    ) -> Result<rpc_programs::ExecResult, rpc_programs::ExecError> {
        self_
            .exec(raw_sys::programs::ContainerExecRequest {
                name: request.name,
                args: request.args,
                env: request.env,
                path: request.path,
                cwd: request.cwd,
                stdin: request.stdin,
                credentials: request.credentials.map(map_container_creds_in),
            })
            .await
            .map(map_exec_result)
            .map_err(map_spawn_error)
    }

    async fn set_default_image(
        &self,
        image: Option<rpc_programs::DefaultLinuxImage>,
    ) -> Result<(), rpc_programs::SpawnError> {
        raw_sys::programs::set_default_image(image.map(|img| {
            raw_sys::programs::DefaultLinuxImage {
                root_path: img.root_path,
                env: img.env,
                credentials: img.credentials.map(map_container_creds_in),
            }
        }))
        .await
        .map_err(map_spawn_error)
    }

    async fn get_default_image(&self) -> Option<rpc_programs::DefaultLinuxImage> {
        raw_sys::programs::get_default_image().map(|img| rpc_programs::DefaultLinuxImage {
            root_path: img.root_path,
            env: img.env,
            credentials: img.credentials.map(map_container_creds_out),
        })
    }

    async fn take_inherited_sockets(
        &self,
    ) -> Vec<
        rpc_programs::InheritedSocket<
            Self::TcpListener,
            Self::VsockListener,
            Self::TcpStream,
            Self::VsockStream,
            Self::SerialPort,
        >,
    > {
        // Worker's own transport socket was already claimed at startup.
        Vec::new()
    }

    async fn create_container(
        &self,
        config: rpc_programs::ContainerConfig<Self::Endpoint>,
    ) -> Result<Self::Container, rpc_programs::SpawnError> {
        raw_sys::programs::create_container(raw_sys::programs::ContainerConfig {
            root: map_container_mount_in(config.root),
            mounts: config
                .mounts
                .into_iter()
                .map(map_container_mount_in)
                .collect(),
            shared_owner: raw_sys::programs::ContainerIdentity {
                uid: config.shared_owner.uid,
                gid: config.shared_owner.gid,
            },
            credentials: map_container_creds_in(config.credentials),
            hostname: config.hostname,
            domainname: config.domainname,
            capability_grants: config
                .capability_grants
                .into_iter()
                .map(map_capability_grant_in)
                .collect(),
        })
        .await
        .map_err(map_spawn_error)
    }

    async fn spawn(
        &self,
        request: rpc_programs::SpawnRequest<
            Self::TcpListener,
            Self::VsockListener,
            Self::TcpStream,
            Self::VsockStream,
            Self::SerialPort,
            Self::Endpoint,
        >,
    ) -> Result<Self::Child, rpc_programs::SpawnError> {
        raw_sys::programs::spawn(raw_sys::programs::SpawnRequest {
            name: request.name,
            args: request.args,
            env: request.env,
            path: request.path,
            cwd: request.cwd,
            sockets: request
                .sockets
                .into_iter()
                .map(map_inherited_socket_in)
                .collect(),
            capability_grants: request
                .capability_grants
                .into_iter()
                .map(map_capability_grant_in)
                .collect(),
        })
        .await
        .map_err(map_spawn_error)
    }

    async fn exec(
        &self,
        request: rpc_programs::ExecRequest<Self::Endpoint>,
    ) -> Result<rpc_programs::ExecResult, rpc_programs::ExecError> {
        raw_sys::programs::exec(raw_sys::programs::ExecRequest {
            name: request.name,
            args: request.args,
            env: request.env,
            path: request.path,
            cwd: request.cwd,
            stdin: request.stdin,
            hint: request.hint.map(map_aot_hint_in),
            capability_grants: request
                .capability_grants
                .into_iter()
                .map(map_capability_grant_in)
                .collect(),
        })
        .await
        .map(map_exec_result)
        .map_err(map_spawn_error)
    }

    async fn aot(
        &self,
        request: rpc_programs::AotRequest,
    ) -> Result<rpc_programs::AotResult, rpc_programs::ExecError> {
        raw_sys::programs::aot(raw_sys::programs::AotRequest {
            source_path: request.source_path,
            destination_path: request.destination_path,
            hint: map_aot_hint_in(request.hint),
            profile: request.profile,
        })
        .await
        .map(|res| rpc_programs::AotResult {
            destination_path: res.destination_path,
            worker_threads: res.worker_threads,
        })
        .map_err(map_spawn_error)
    }
}

// ---------------------------------------------------------------------------
// 2. helios:system/mounts
// ---------------------------------------------------------------------------

struct MountsBridge;

impl rpc_mounts::RpcHandler for MountsBridge {
    async fn mount(&self, request: rpc_mounts::MountRequest) -> Result<(), rpc_mounts::MountError> {
        raw_sys::mounts::mount(raw_sys::mounts::MountRequest {
            source: match request.source {
                rpc_mounts::MountSource::Memory => raw_sys::mounts::MountSource::Memory,
                rpc_mounts::MountSource::BootImage => raw_sys::mounts::MountSource::BootImage,
                rpc_mounts::MountSource::HostShare => raw_sys::mounts::MountSource::HostShare,
                rpc_mounts::MountSource::Disk(s) => raw_sys::mounts::MountSource::Disk(s),
                rpc_mounts::MountSource::Btrfs(s) => raw_sys::mounts::MountSource::Btrfs(s),
            },
            path: request.path,
            read_only: request.read_only,
            sharing: match request.sharing {
                rpc_mounts::MountSharing::Private => raw_sys::mounts::MountSharing::Private,
                rpc_mounts::MountSharing::Shared => raw_sys::mounts::MountSharing::Shared,
            },
            compress: request.compress,
            commit: request.commit,
            max_inline: request.max_inline,
        })
        .await
        .map_err(map_mount_error)
    }

    async fn unmount(&self, path: String) -> Result<(), rpc_mounts::MountError> {
        raw_sys::mounts::unmount(path)
            .await
            .map_err(map_mount_error)
    }
}

// ---------------------------------------------------------------------------
// 3. helios:system/btrfs
// ---------------------------------------------------------------------------

struct BtrfsBridge;

impl rpc_btrfs::RpcHandler for BtrfsBridge {
    async fn create_subvolume(
        &self,
        path: String,
    ) -> Result<rpc_btrfs::SubvolumeInfo, rpc_btrfs::BtrfsError> {
        raw_sys::btrfs::create_subvolume(path)
            .await
            .map(map_subvol_info)
            .map_err(map_btrfs_error)
    }

    async fn delete_subvolume(&self, path: String) -> Result<(), rpc_btrfs::BtrfsError> {
        raw_sys::btrfs::delete_subvolume(path)
            .await
            .map_err(map_btrfs_error)
    }

    async fn snapshot_subvolume(
        &self,
        source: String,
        destination: String,
        read_only: bool,
    ) -> Result<rpc_btrfs::SubvolumeInfo, rpc_btrfs::BtrfsError> {
        raw_sys::btrfs::snapshot_subvolume(source, destination, read_only)
            .await
            .map(map_subvol_info)
            .map_err(map_btrfs_error)
    }

    async fn set_subvolume_read_only(
        &self,
        path: String,
        read_only: bool,
    ) -> Result<(), rpc_btrfs::BtrfsError> {
        raw_sys::btrfs::set_subvolume_read_only(path, read_only)
            .await
            .map_err(map_btrfs_error)
    }

    async fn get_subvolume_info(
        &self,
        path: String,
    ) -> Result<rpc_btrfs::SubvolumeInfo, rpc_btrfs::BtrfsError> {
        raw_sys::btrfs::get_subvolume_info(path)
            .await
            .map(map_subvol_info)
            .map_err(map_btrfs_error)
    }

    async fn list_subvolumes(
        &self,
        mount_point: String,
    ) -> Result<Vec<rpc_btrfs::SubvolumeInfo>, rpc_btrfs::BtrfsError> {
        raw_sys::btrfs::list_subvolumes(mount_point)
            .await
            .map(|v| v.into_iter().map(map_subvol_info).collect())
            .map_err(map_btrfs_error)
    }

    async fn send_subvolume(
        &self,
        subvolume: String,
        parent: Option<String>,
        clone_sources: Vec<String>,
    ) -> Result<Vec<u8>, rpc_btrfs::BtrfsError> {
        raw_sys::btrfs::send_subvolume(subvolume, parent, clone_sources)
            .await
            .map_err(map_btrfs_error)
    }

    async fn receive_subvolume(
        &self,
        destination: String,
        payload: Vec<u8>,
    ) -> Result<rpc_btrfs::SubvolumeInfo, rpc_btrfs::BtrfsError> {
        raw_sys::btrfs::receive_subvolume(destination, payload)
            .await
            .map(map_subvol_info)
            .map_err(map_btrfs_error)
    }

    async fn reflink(
        &self,
        source: String,
        source_offset: u64,
        destination: String,
        destination_offset: u64,
        length: u64,
    ) -> Result<(), rpc_btrfs::BtrfsError> {
        raw_sys::btrfs::reflink(
            source,
            source_offset,
            destination,
            destination_offset,
            length,
        )
        .await
        .map_err(map_btrfs_error)
    }

    async fn dedupe(
        &self,
        source: String,
        source_offset: u64,
        destination: String,
        destination_offset: u64,
        length: u64,
    ) -> Result<rpc_btrfs::DedupeOutcome, rpc_btrfs::BtrfsError> {
        raw_sys::btrfs::dedupe(
            source,
            source_offset,
            destination,
            destination_offset,
            length,
        )
        .await
        .map(|o| rpc_btrfs::DedupeOutcome {
            same: o.same,
            bytes_deduped: o.bytes_deduped,
        })
        .map_err(map_btrfs_error)
    }

    async fn list_devices(
        &self,
        mount_point: String,
    ) -> Result<Vec<rpc_btrfs::VolumeDeviceInfo>, rpc_btrfs::BtrfsError> {
        raw_sys::btrfs::list_devices(mount_point)
            .await
            .map(|v| v.into_iter().map(map_vol_dev).collect())
            .map_err(map_btrfs_error)
    }

    async fn add_device(
        &self,
        mount_point: String,
        device: String,
    ) -> Result<rpc_btrfs::VolumeDeviceInfo, rpc_btrfs::BtrfsError> {
        raw_sys::btrfs::add_device(mount_point, device)
            .await
            .map(map_vol_dev)
            .map_err(map_btrfs_error)
    }

    async fn remove_device(
        &self,
        mount_point: String,
        devid: u64,
    ) -> Result<(), rpc_btrfs::BtrfsError> {
        raw_sys::btrfs::remove_device(mount_point, devid)
            .await
            .map_err(map_btrfs_error)
    }

    async fn replace_device(
        &self,
        mount_point: String,
        source_devid: u64,
        target_device: String,
    ) -> Result<rpc_btrfs::VolumeDeviceInfo, rpc_btrfs::BtrfsError> {
        raw_sys::btrfs::replace_device(mount_point, source_devid, target_device)
            .await
            .map(map_vol_dev)
            .map_err(map_btrfs_error)
    }

    async fn resize_device(
        &self,
        mount_point: String,
        devid: Option<u64>,
        target: rpc_btrfs::ResizeTarget,
    ) -> Result<rpc_btrfs::VolumeDeviceInfo, rpc_btrfs::BtrfsError> {
        let target = match target {
            rpc_btrfs::ResizeTarget::Max => raw_sys::btrfs::ResizeTarget::Max,
            rpc_btrfs::ResizeTarget::Bytes(b) => raw_sys::btrfs::ResizeTarget::Bytes(b),
        };
        raw_sys::btrfs::resize_device(mount_point, devid, target)
            .await
            .map(map_vol_dev)
            .map_err(map_btrfs_error)
    }

    async fn balance(
        &self,
        mount_point: String,
        filter: rpc_btrfs::BalanceFilter,
    ) -> Result<rpc_btrfs::BalanceReport, rpc_btrfs::BtrfsError> {
        raw_sys::btrfs::balance(
            mount_point,
            raw_sys::btrfs::BalanceFilter {
                data: filter.data,
                metadata: filter.metadata,
                system: filter.system,
                usage_max_percent: filter.usage_max_percent,
                limit: filter.limit,
            },
        )
        .await
        .map(|r| rpc_btrfs::BalanceReport {
            considered: r.considered,
            relocated: r.relocated,
        })
        .map_err(map_btrfs_error)
    }

    async fn scrub(
        &self,
        mount_point: String,
        devid: Option<u64>,
        read_only: bool,
    ) -> Result<rpc_btrfs::ScrubReport, rpc_btrfs::BtrfsError> {
        raw_sys::btrfs::scrub(mount_point, devid, read_only)
            .await
            .map(|r| rpc_btrfs::ScrubReport {
                data_extents_scrubbed: r.data_extents_scrubbed,
                tree_extents_scrubbed: r.tree_extents_scrubbed,
                data_bytes_scrubbed: r.data_bytes_scrubbed,
                tree_bytes_scrubbed: r.tree_bytes_scrubbed,
                csum_errors: r.csum_errors,
                verify_errors: r.verify_errors,
                uncorrectable_errors: r.uncorrectable_errors,
                corrected_errors: r.corrected_errors,
                no_csum_sectors: r.no_csum_sectors,
            })
            .map_err(map_btrfs_error)
    }

    async fn quota_enable(&self, mount_point: String) -> Result<(), rpc_btrfs::BtrfsError> {
        raw_sys::btrfs::quota_enable(mount_point)
            .await
            .map_err(map_btrfs_error)
    }

    async fn quota_disable(&self, mount_point: String) -> Result<(), rpc_btrfs::BtrfsError> {
        raw_sys::btrfs::quota_disable(mount_point)
            .await
            .map_err(map_btrfs_error)
    }

    async fn quota_rescan(&self, mount_point: String) -> Result<(), rpc_btrfs::BtrfsError> {
        raw_sys::btrfs::quota_rescan(mount_point)
            .await
            .map_err(map_btrfs_error)
    }

    async fn get_quota_status(
        &self,
        mount_point: String,
    ) -> Result<rpc_btrfs::QuotaStatus, rpc_btrfs::BtrfsError> {
        raw_sys::btrfs::get_quota_status(mount_point)
            .await
            .map(|s| rpc_btrfs::QuotaStatus {
                enabled: s.enabled,
                rescanning: s.rescanning,
                inconsistent: s.inconsistent,
                generation: s.generation,
            })
            .map_err(map_btrfs_error)
    }

    async fn qgroup_list(
        &self,
        mount_point: String,
    ) -> Result<Vec<rpc_btrfs::QgroupInfo>, rpc_btrfs::BtrfsError> {
        raw_sys::btrfs::qgroup_list(mount_point)
            .await
            .map(|list| {
                list.into_iter()
                    .map(|q| rpc_btrfs::QgroupInfo {
                        id: rpc_btrfs::QgroupId {
                            level: q.id.level,
                            id: q.id.id,
                        },
                        referenced_bytes: q.referenced_bytes,
                        referenced_compressed_bytes: q.referenced_compressed_bytes,
                        exclusive_bytes: q.exclusive_bytes,
                        exclusive_compressed_bytes: q.exclusive_compressed_bytes,
                        limit: rpc_btrfs::QgroupLimit {
                            max_referenced: q.limit.max_referenced,
                            max_exclusive: q.limit.max_exclusive,
                        },
                        parents: q
                            .parents
                            .into_iter()
                            .map(|p| rpc_btrfs::QgroupId {
                                level: p.level,
                                id: p.id,
                            })
                            .collect(),
                    })
                    .collect()
            })
            .map_err(map_btrfs_error)
    }

    async fn qgroup_create(
        &self,
        mount_point: String,
        group: rpc_btrfs::QgroupId,
    ) -> Result<(), rpc_btrfs::BtrfsError> {
        raw_sys::btrfs::qgroup_create(
            mount_point,
            raw_sys::btrfs::QgroupId {
                level: group.level,
                id: group.id,
            },
        )
        .await
        .map_err(map_btrfs_error)
    }

    async fn qgroup_destroy(
        &self,
        mount_point: String,
        group: rpc_btrfs::QgroupId,
    ) -> Result<(), rpc_btrfs::BtrfsError> {
        raw_sys::btrfs::qgroup_destroy(
            mount_point,
            raw_sys::btrfs::QgroupId {
                level: group.level,
                id: group.id,
            },
        )
        .await
        .map_err(map_btrfs_error)
    }

    async fn qgroup_assign(
        &self,
        mount_point: String,
        member: rpc_btrfs::QgroupId,
        parent: rpc_btrfs::QgroupId,
    ) -> Result<(), rpc_btrfs::BtrfsError> {
        raw_sys::btrfs::qgroup_assign(
            mount_point,
            raw_sys::btrfs::QgroupId {
                level: member.level,
                id: member.id,
            },
            raw_sys::btrfs::QgroupId {
                level: parent.level,
                id: parent.id,
            },
        )
        .await
        .map_err(map_btrfs_error)
    }

    async fn qgroup_remove(
        &self,
        mount_point: String,
        member: rpc_btrfs::QgroupId,
        parent: rpc_btrfs::QgroupId,
    ) -> Result<(), rpc_btrfs::BtrfsError> {
        raw_sys::btrfs::qgroup_remove(
            mount_point,
            raw_sys::btrfs::QgroupId {
                level: member.level,
                id: member.id,
            },
            raw_sys::btrfs::QgroupId {
                level: parent.level,
                id: parent.id,
            },
        )
        .await
        .map_err(map_btrfs_error)
    }

    async fn set_qgroup_limit(
        &self,
        mount_point: String,
        group: rpc_btrfs::QgroupId,
        limit: rpc_btrfs::QgroupLimit,
    ) -> Result<(), rpc_btrfs::BtrfsError> {
        raw_sys::btrfs::set_qgroup_limit(
            mount_point,
            raw_sys::btrfs::QgroupId {
                level: group.level,
                id: group.id,
            },
            raw_sys::btrfs::QgroupLimit {
                max_referenced: limit.max_referenced,
                max_exclusive: limit.max_exclusive,
            },
        )
        .await
        .map_err(map_btrfs_error)
    }
}

// ---------------------------------------------------------------------------
// 4. helios:system/inspect
// ---------------------------------------------------------------------------

struct InspectBridge;

impl rpc_inspect::RpcHandler for InspectBridge {
    type Publication = raw_sys::inspect::Publication;

    async fn publish(
        &self,
        name: String,
        region: rpc_memory::Span,
    ) -> Result<Self::Publication, rpc_inspect::PublishError> {
        raw_sys::inspect::publish(
            &name,
            raw_sys::memory::Span {
                offset: region.offset,
                length: region.length,
            },
        )
        .map_err(|err| match err {
            raw_sys::inspect::PublishError::BadSpan => rpc_inspect::PublishError::BadSpan,
            raw_sys::inspect::PublishError::InvalidName => rpc_inspect::PublishError::InvalidName,
            raw_sys::inspect::PublishError::DuplicateName => {
                rpc_inspect::PublishError::DuplicateName
            }
            raw_sys::inspect::PublishError::TooManyPublications => {
                rpc_inspect::PublishError::TooManyPublications
            }
        })
    }

    async fn snapshot(
        &self,
        query: rpc_inspect::Query,
        limit: u32,
    ) -> Result<rpc_inspect::SnapshotResult, rpc_filters::FilterError> {
        raw_sys::inspect::snapshot(
            &raw_sys::inspect::Query {
                prefixes: query.prefixes,
            },
            limit,
        )
        .map(|snap| rpc_inspect::SnapshotResult {
            timestamp: snap.timestamp,
            entries: snap
                .entries
                .into_iter()
                .map(|e| rpc_inspect::Entry {
                    path: e.path,
                    value: match e.value {
                        raw_sys::inspect::Value::Boolean(v) => rpc_inspect::Value::Boolean(v),
                        raw_sys::inspect::Value::Signed64(v) => rpc_inspect::Value::Signed64(v),
                        raw_sys::inspect::Value::Unsigned64(v) => rpc_inspect::Value::Unsigned64(v),
                        raw_sys::inspect::Value::Float64(v) => rpc_inspect::Value::Float64(v),
                        raw_sys::inspect::Value::Text(v) => rpc_inspect::Value::Text(v),
                        raw_sys::inspect::Value::Blob(v) => rpc_inspect::Value::Blob(v),
                    },
                })
                .collect(),
            truncated: snap.truncated,
            publications: snap
                .publications
                .into_iter()
                .map(|p| rpc_inspect::ComponentPublication {
                    instance_id: p.instance_id,
                    instance_name: p.instance_name,
                    name: p.name,
                    generation: p.generation,
                    status: match p.status {
                        raw_sys::inspect::PublicationStatus::Ok => {
                            rpc_inspect::PublicationStatus::Ok
                        }
                        raw_sys::inspect::PublicationStatus::Busy => {
                            rpc_inspect::PublicationStatus::Busy
                        }
                        raw_sys::inspect::PublicationStatus::Corrupt => {
                            rpc_inspect::PublicationStatus::Corrupt
                        }
                        raw_sys::inspect::PublicationStatus::SwappedOut => {
                            rpc_inspect::PublicationStatus::SwappedOut
                        }
                    },
                })
                .collect(),
        })
        .map_err(map_filter_error)
    }
}

// ---------------------------------------------------------------------------
// 5. helios:system/tracing
// ---------------------------------------------------------------------------

struct TracingBridge {
    spawner: TaskSpawner,
}

impl rpc_tracing::RpcHandler for TracingBridge {
    async fn set_target_enabled(
        &self,
        target: String,
        enabled: bool,
    ) -> Result<(), rpc_tracing::TargetError> {
        raw_sys::tracing::set_target_enabled(&target, enabled).map_err(|err| match err {
            raw_sys::tracing::TargetError::UnknownTarget(s) => {
                rpc_tracing::TargetError::UnknownTarget(s)
            }
            raw_sys::tracing::TargetError::Denied => rpc_tracing::TargetError::Denied,
        })
    }

    async fn recent(
        &self,
        filter: rpc_tracing::Filter,
        limit: u32,
    ) -> Result<Vec<rpc_tracing::Event>, rpc_filters::FilterError> {
        raw_sys::tracing::recent(&map_trace_filter_in(filter), limit)
            .map(|events| events.into_iter().map(map_trace_event).collect())
            .map_err(map_filter_error)
    }

    async fn subscribe(
        &self,
        filter: rpc_tracing::Filter,
    ) -> Result<StreamReader<rpc_tracing::Event>, rpc_filters::FilterError> {
        let mut wit_rx =
            raw_sys::tracing::subscribe(&map_trace_filter_in(filter)).map_err(map_filter_error)?;
        let (mut rpc_tx, rpc_rx) = rpc_stream::<rpc_tracing::Event>();
        self.spawner.spawn(async move {
            let mut buf = Vec::with_capacity(16);
            loop {
                let (res, batch) = wit_rx.read(buf).await;
                if !batch.is_empty() {
                    let mapped: Vec<rpc_tracing::Event> =
                        batch.into_iter().map(map_trace_event).collect();
                    if rpc_tx.send_batch(mapped).await.is_err() {
                        break;
                    }
                    buf = Vec::with_capacity(16);
                } else {
                    buf = batch;
                }
                if stream_closed(res) {
                    break;
                }
            }
            let _ = rpc_tx.close().await;
        });
        Ok(rpc_rx)
    }
}

// ---------------------------------------------------------------------------
// 6. helios:system/profiling
// ---------------------------------------------------------------------------

struct ProfilingBridge;

impl rpc_profiling::RpcHandler for ProfilingBridge {
    type SamplingSession = raw_sys::profiling::SamplingSession;

    async fn set_enabled(&self, enabled: bool) -> Result<(), rpc_profiling::ControlError> {
        raw_sys::profiling::set_enabled(enabled).map_err(|err| match err {
            raw_sys::profiling::ControlError::Denied => rpc_profiling::ControlError::Denied,
        })
    }

    async fn clear(&self) -> Result<(), rpc_profiling::ControlError> {
        raw_sys::profiling::clear().map_err(|err| match err {
            raw_sys::profiling::ControlError::Denied => rpc_profiling::ControlError::Denied,
        })
    }

    async fn folded(
        &self,
        filter: rpc_profiling::Filter,
        limit: u32,
    ) -> Result<Vec<rpc_profiling::FoldedSample>, rpc_filters::FilterError> {
        raw_sys::profiling::folded(
            &raw_sys::profiling::Filter {
                scope: filter.scope.map(map_prof_scope_in),
                stack_prefixes: filter.stack_prefixes,
            },
            limit,
        )
        .map(|samples| {
            samples
                .into_iter()
                .map(|s| rpc_profiling::FoldedSample {
                    scope: map_prof_scope_out(s.scope),
                    stack: s.stack,
                    weight: s.weight,
                })
                .collect()
        })
        .map_err(map_filter_error)
    }

    async fn metrics(
        &self,
        filter: rpc_profiling::MetricFilter,
        limit: u32,
    ) -> Result<Vec<rpc_profiling::MetricSample>, rpc_filters::FilterError> {
        raw_sys::profiling::metrics(
            &raw_sys::profiling::MetricFilter {
                name_prefixes: filter.name_prefixes,
            },
            limit,
        )
        .map(|samples| {
            samples
                .into_iter()
                .map(|s| rpc_profiling::MetricSample {
                    scope: map_prof_scope_out(s.scope),
                    name: s.name,
                    count: s.count,
                    total_events: s.total_events,
                    total_nanos: s.total_nanos,
                    min_nanos: s.min_nanos,
                    max_nanos: s.max_nanos,
                    total_bytes: s.total_bytes,
                    total_reference_cycles: s.total_reference_cycles,
                    total_cpu_cycles: s.total_cpu_cycles,
                    total_instructions_retired: s.total_instructions_retired,
                })
                .collect()
        })
        .map_err(map_filter_error)
    }

    async fn start_instruction_sampling(
        &self,
    ) -> Result<Self::SamplingSession, rpc_profiling::InstructionProfileError> {
        raw_sys::profiling::start_instruction_sampling().map_err(map_inst_prof_error)
    }

    async fn instruction_samples(
        &self,
    ) -> Result<rpc_profiling::InstructionProfile, rpc_profiling::InstructionProfileError> {
        raw_sys::profiling::instruction_samples()
            .map(|p| rpc_profiling::InstructionProfile {
                period_nanos: p.period_nanos,
                kernel_image_base: p.kernel_image_base,
                samples: p
                    .samples
                    .into_iter()
                    .map(|s| rpc_profiling::InstructionSample {
                        code: match s.code {
                            raw_sys::profiling::SampledCode::Wasm(f) => {
                                rpc_profiling::SampledCode::Wasm(rpc_profiling::WasmFunction {
                                    module: f.module,
                                    static_module: f.static_module,
                                    index: f.index,
                                    name: f.name,
                                })
                            }
                            raw_sys::profiling::SampledCode::WasmTrampoline(n) => {
                                rpc_profiling::SampledCode::WasmTrampoline(n)
                            }
                            raw_sys::profiling::SampledCode::Native(addr) => {
                                rpc_profiling::SampledCode::Native(addr)
                            }
                        },
                        count: s.count,
                    })
                    .collect(),
                dropped: p.dropped,
            })
            .map_err(map_inst_prof_error)
    }

    async fn raw_profile_size(&self) -> Result<u64, rpc_profiling::RawProfileError> {
        raw_sys::profiling::raw_profile_size().map_err(map_raw_prof_error)
    }

    async fn raw_profile_read(
        &self,
        offset: u64,
        length: u32,
    ) -> Result<Vec<u8>, rpc_profiling::RawProfileError> {
        raw_sys::profiling::raw_profile_read(offset, length).map_err(map_raw_prof_error)
    }
}

// ---------------------------------------------------------------------------
// 7. helios:system/instances
// ---------------------------------------------------------------------------

struct InstancesBridge;

impl rpc_instances::RpcHandler for InstancesBridge {
    async fn snapshot(&self) -> Vec<rpc_instances::Instance> {
        raw_sys::instances::snapshot()
            .into_iter()
            .map(|i| rpc_instances::Instance {
                id: i.id,
                name: i.name,
                started_at: i.started_at,
                uptime: i.uptime,
                memory_bytes: i.memory_bytes,
                storage_bytes: i.storage_bytes,
                cpu_busy: i.cpu_busy,
            })
            .collect()
    }

    async fn kill(&self, id: u64) -> Result<(), rpc_instances::KillError> {
        raw_sys::instances::kill(id).map_err(|err| match err {
            raw_sys::instances::KillError::NoSuchInstance => {
                rpc_instances::KillError::NoSuchInstance
            }
            raw_sys::instances::KillError::AlreadyStopping => {
                rpc_instances::KillError::AlreadyStopping
            }
            raw_sys::instances::KillError::Denied => rpc_instances::KillError::Denied,
        })
    }
}

// ---------------------------------------------------------------------------
// 8. helios:system/snapshot
// ---------------------------------------------------------------------------

struct SnapshotBridge;

impl rpc_snapshot::RpcHandler for SnapshotBridge {
    type SnapshotHold = raw_sys::snapshot::SnapshotHold;

    async fn snapshot_hold_has_generation_id(&self, self_: &Self::SnapshotHold) -> bool {
        self_.has_generation_id()
    }

    async fn prepare(&self) -> Result<Self::SnapshotHold, rpc_snapshot::SnapshotError> {
        raw_sys::snapshot::prepare().await.map_err(|err| match err {
            raw_sys::snapshot::SnapshotError::Denied => rpc_snapshot::SnapshotError::Denied,
            raw_sys::snapshot::SnapshotError::Busy => rpc_snapshot::SnapshotError::Busy,
        })
    }
}

// ---------------------------------------------------------------------------
// 9. helios:system/processors
// ---------------------------------------------------------------------------

struct ProcessorsBridge;

impl rpc_processors::RpcHandler for ProcessorsBridge {
    async fn sets(&self) -> rpc_processors::ProcessorSets {
        let s = raw_sys::processors::sets();
        rpc_processors::ProcessorSets {
            possible: s.possible,
            bootstrap: s.bootstrap,
            online: s.online,
        }
    }

    async fn offline(&self, processor: u32) -> Result<(), rpc_processors::OfflineError> {
        raw_sys::processors::offline(processor)
            .await
            .map_err(|err| match err {
                raw_sys::processors::OfflineError::NotPossible(n) => {
                    rpc_processors::OfflineError::NotPossible(n)
                }
                raw_sys::processors::OfflineError::Bootstrap => {
                    rpc_processors::OfflineError::Bootstrap
                }
                raw_sys::processors::OfflineError::CurrentProcessor => {
                    rpc_processors::OfflineError::CurrentProcessor
                }
                raw_sys::processors::OfflineError::NotOnline => {
                    rpc_processors::OfflineError::NotOnline
                }
                raw_sys::processors::OfflineError::Refused(r) => {
                    rpc_processors::OfflineError::Refused(match r {
                        raw_sys::processors::OfflineRefusal::PinnedTasks(n) => {
                            rpc_processors::OfflineRefusal::PinnedTasks(n)
                        }
                        raw_sys::processors::OfflineRefusal::NetworkStarting => {
                            rpc_processors::OfflineRefusal::NetworkStarting
                        }
                    })
                }
                raw_sys::processors::OfflineError::Denied => rpc_processors::OfflineError::Denied,
            })
    }

    async fn online(&self, processor: u32) -> Result<(), rpc_processors::OnlineError> {
        raw_sys::processors::online(processor)
            .await
            .map_err(|err| match err {
                raw_sys::processors::OnlineError::NotPossible(n) => {
                    rpc_processors::OnlineError::NotPossible(n)
                }
                raw_sys::processors::OnlineError::NotOffline => {
                    rpc_processors::OnlineError::NotOffline
                }
                raw_sys::processors::OnlineError::Denied => rpc_processors::OnlineError::Denied,
            })
    }
}

// ---------------------------------------------------------------------------
// 10. helios:system/net
// ---------------------------------------------------------------------------

struct NetBridge;

impl rpc_net::RpcHandler for NetBridge {
    type TcpStream = raw_sys::net::TcpStream;
    type TcpListener = raw_sys::net::TcpListener;
    type UdpSocket = raw_sys::net::UdpSocket;

    async fn tcp_stream_read(
        &self,
        self_: &Self::TcpStream,
        max_bytes: u32,
        timeout: u64,
    ) -> Result<Option<Vec<u8>>, rpc_net::TcpError> {
        self_.read(max_bytes, timeout).await.map_err(map_tcp_error)
    }

    async fn tcp_stream_write(
        &self,
        self_: &Self::TcpStream,
        bytes: Vec<u8>,
        timeout: u64,
    ) -> Result<u64, rpc_net::TcpError> {
        self_.write(bytes, timeout).await.map_err(map_tcp_error)
    }

    async fn tcp_stream_close(&self, self_: &Self::TcpStream) -> Result<(), rpc_net::TcpError> {
        self_.close().await.map_err(map_tcp_error)
    }

    async fn tcp_listener_local_address(
        &self,
        self_: &Self::TcpListener,
    ) -> (rpc_net::IpAddress, u16) {
        let (ip, port) = self_.local_address();
        (map_ip_out(ip), port)
    }

    async fn tcp_listener_wait_readable(
        &self,
        self_: &Self::TcpListener,
        timeout: u64,
    ) -> Result<bool, rpc_net::TcpError> {
        self_.wait_readable(timeout).await.map_err(map_tcp_error)
    }

    async fn tcp_listener_accept(
        &self,
        self_: &Self::TcpListener,
        timeout: u64,
    ) -> Result<Self::TcpStream, rpc_net::TcpError> {
        self_.accept(timeout).await.map_err(map_tcp_error)
    }

    async fn tcp_listener_close(&self, self_: &Self::TcpListener) -> Result<(), rpc_net::TcpError> {
        self_.close().await.map_err(map_tcp_error)
    }

    async fn udp_socket_receive(
        &self,
        self_: &Self::UdpSocket,
        max_bytes: u32,
        timeout: u64,
    ) -> Result<Option<rpc_net::UdpDatagram>, rpc_net::UdpError> {
        self_
            .receive(max_bytes, timeout)
            .await
            .map(|opt| {
                opt.map(|d| rpc_net::UdpDatagram {
                    address: map_ip_out(d.address),
                    port: d.port,
                    bytes: d.bytes,
                })
            })
            .map_err(map_udp_error)
    }

    async fn udp_socket_send(
        &self,
        self_: &Self::UdpSocket,
        host: String,
        port: u16,
        bytes: Vec<u8>,
        timeout: u64,
    ) -> Result<u64, rpc_net::UdpError> {
        self_
            .send(host, port, bytes, timeout)
            .await
            .map_err(map_udp_error)
    }

    async fn udp_socket_close(&self, self_: &Self::UdpSocket) -> Result<(), rpc_net::UdpError> {
        self_.close().await.map_err(map_udp_error)
    }

    async fn ping(
        &self,
        host: String,
        timeout: u64,
    ) -> Result<rpc_net::PingReply, rpc_net::PingError> {
        raw_sys::net::ping(host, timeout)
            .await
            .map(|r| rpc_net::PingReply {
                address: map_ip_out(r.address),
                round_trip: r.round_trip,
                payload_bytes: r.payload_bytes,
            })
            .map_err(|e| rpc_net::PingError {
                kind: match e.kind {
                    raw_sys::net::PingErrorKind::UnresolvedHost => {
                        rpc_net::PingErrorKind::UnresolvedHost
                    }
                    raw_sys::net::PingErrorKind::Timeout => rpc_net::PingErrorKind::Timeout,
                    raw_sys::net::PingErrorKind::Unavailable => rpc_net::PingErrorKind::Unavailable,
                    raw_sys::net::PingErrorKind::Internal => rpc_net::PingErrorKind::Internal,
                },
                detail: e.detail,
            })
    }

    async fn tcp_connect(
        &self,
        host: String,
        port: u16,
        timeout: u64,
    ) -> Result<Self::TcpStream, rpc_net::TcpError> {
        raw_sys::net::tcp_connect(host, port, timeout)
            .await
            .map_err(map_tcp_error)
    }

    async fn tcp_listen(
        &self,
        local_address: rpc_net::IpAddress,
        local_port: u16,
        backlog: u16,
    ) -> Result<Self::TcpListener, rpc_net::TcpError> {
        raw_sys::net::tcp_listen(map_ip_in(local_address), local_port, backlog)
            .await
            .map_err(map_tcp_error)
    }

    async fn udp_bind(&self, local_port: u16) -> Result<Self::UdpSocket, rpc_net::UdpError> {
        raw_sys::net::udp_bind(local_port)
            .await
            .map_err(map_udp_error)
    }

    async fn resolve_https(
        &self,
        host: String,
        port: u16,
        timeout: u64,
    ) -> Result<Option<rpc_net::HttpsRecord>, rpc_net::DnsError> {
        raw_sys::net::resolve_https(host, port, timeout)
            .await
            .map(|opt| {
                opt.map(|r| rpc_net::HttpsRecord {
                    alpn: r.alpn,
                    port: r.port,
                    ttl: r.ttl,
                })
            })
            .map_err(|e| rpc_net::DnsError {
                kind: match e.kind {
                    raw_sys::net::DnsErrorKind::UnresolvedHost => {
                        rpc_net::DnsErrorKind::UnresolvedHost
                    }
                    raw_sys::net::DnsErrorKind::Timeout => rpc_net::DnsErrorKind::Timeout,
                    raw_sys::net::DnsErrorKind::PermissionDenied => {
                        rpc_net::DnsErrorKind::PermissionDenied
                    }
                    raw_sys::net::DnsErrorKind::Unavailable => rpc_net::DnsErrorKind::Unavailable,
                    raw_sys::net::DnsErrorKind::Internal => rpc_net::DnsErrorKind::Internal,
                },
                detail: e.detail,
            })
    }
}

// ---------------------------------------------------------------------------
// 11. helios:system/serial
// ---------------------------------------------------------------------------

struct SerialBridge;

impl rpc_serial::RpcHandler for SerialBridge {
    type SerialPort = raw_sys::serial::SerialPort;

    async fn serial_port_rights(&self, self_: &Self::SerialPort) -> rpc_serial::SerialRights {
        let raw = self_.rights().await;
        let mut out = rpc_serial::SerialRights::empty();
        if (raw & raw_sys::serial::SerialRights::READ).bits() != 0 {
            out |= rpc_serial::SerialRights::READ;
        }
        if (raw & raw_sys::serial::SerialRights::WRITE).bits() != 0 {
            out |= rpc_serial::SerialRights::WRITE;
        }
        if (raw & raw_sys::serial::SerialRights::FLUSH).bits() != 0 {
            out |= rpc_serial::SerialRights::FLUSH;
        }
        out
    }

    async fn serial_port_read(&self, self_: &Self::SerialPort, max_bytes: u32) -> Vec<u8> {
        self_.read(max_bytes).await
    }

    async fn serial_port_write(&self, self_: &Self::SerialPort, bytes: Vec<u8>) {
        self_.write(bytes).await
    }

    async fn serial_port_flush(&self, self_: &Self::SerialPort) {
        self_.flush().await
    }

    async fn debug_port(&self) -> Option<Self::SerialPort> {
        raw_sys::serial::debug_port().await
    }
}

// ---------------------------------------------------------------------------
// 12. helios:system/component-control (forwarded over granted IPC capability)
// ---------------------------------------------------------------------------

struct ComponentControlBridge {
    peer: Option<PeerHandle>,
}

impl ComponentControlBridge {
    fn client(&self) -> Result<rpc_cc::RpcClient, rpc_cc::ControlError> {
        self.peer
            .clone()
            .map(rpc_cc::RpcClient::new)
            .ok_or_else(|| rpc_cc::ControlError {
                kind: rpc_cc::ControlErrorKind::PermissionDenied,
                detail: "component-control capability not granted to this session".to_owned(),
            })
    }
}

impl rpc_cc::RpcHandler for ComponentControlBridge {
    async fn list_components(&self) -> Result<Vec<rpc_cc::ComponentStatus>, rpc_cc::ControlError> {
        self.client()?
            .list_components()
            .await
            .map_err(|err| rpc_cc::ControlError {
                kind: rpc_cc::ControlErrorKind::Unavailable,
                detail: err.to_string(),
            })?
    }

    async fn start(
        &self,
        moniker: String,
    ) -> Result<rpc_cc::ComponentStatus, rpc_cc::ControlError> {
        self.client()?
            .start(moniker)
            .await
            .map_err(|err| rpc_cc::ControlError {
                kind: rpc_cc::ControlErrorKind::Unavailable,
                detail: err.to_string(),
            })?
    }

    async fn stop(&self, moniker: String) -> Result<(), rpc_cc::ControlError> {
        self.client()?
            .stop(moniker)
            .await
            .map_err(|err| rpc_cc::ControlError {
                kind: rpc_cc::ControlErrorKind::Unavailable,
                detail: err.to_string(),
            })?
    }

    async fn restart(
        &self,
        moniker: String,
    ) -> Result<rpc_cc::ComponentStatus, rpc_cc::ControlError> {
        self.client()?
            .restart(moniker)
            .await
            .map_err(|err| rpc_cc::ControlError {
                kind: rpc_cc::ControlErrorKind::Unavailable,
                detail: err.to_string(),
            })?
    }
}

// ---------------------------------------------------------------------------
// 13 & 14. wasi:filesystem/{preopens, types}@0.3.0
// ---------------------------------------------------------------------------

struct PreopensBridge;

impl rpc_preopens::RpcHandler for PreopensBridge {
    type Descriptor = raw_fs::Descriptor;

    async fn get_directories(&self) -> Vec<(Self::Descriptor, String)> {
        raw_preopens::get_directories()
    }
}

struct FilesystemBridge {
    spawner: TaskSpawner,
}

impl rpc_fs::RpcHandler for FilesystemBridge {
    type Descriptor = raw_fs::Descriptor;

    async fn descriptor_read_via_stream(
        &self,
        self_: &Self::Descriptor,
        offset: u64,
    ) -> (
        StreamReader<u8>,
        FutureReader<Result<(), rpc_fs::ErrorCode>>,
    ) {
        let (mut wit_rx, done_wit) = self_.read_via_stream(offset);
        let (mut rpc_tx, rpc_rx) = rpc_stream::<u8>();
        let (fut_tx, fut_rx) = rpc_future::<Result<(), rpc_fs::ErrorCode>>();
        self.spawner.spawn(async move {
            let mut buf = Vec::with_capacity(32 * 1024);
            loop {
                let (res, chunk) = wit_rx.read(buf).await;
                if !chunk.is_empty() {
                    if rpc_tx.send_batch(chunk).await.is_err() {
                        break;
                    }
                    buf = Vec::with_capacity(32 * 1024);
                } else {
                    buf = chunk;
                }
                if stream_closed(res) {
                    break;
                }
            }
            let _ = rpc_tx.close().await;
            let outcome = done_wit.await.map_err(map_fs_error);
            let _ = fut_tx.resolve(outcome).await;
        });
        (rpc_rx, fut_rx)
    }

    async fn descriptor_write_via_stream(
        &self,
        self_: &Self::Descriptor,
        mut data: StreamReader<u8>,
        offset: u64,
    ) -> FutureReader<Result<(), rpc_fs::ErrorCode>> {
        let (mut wit_tx, wit_rx) = wit_stream::new::<u8>();
        let done_wit = self_.write_via_stream(wit_rx, offset);
        let (fut_tx, fut_rx) = rpc_future::<Result<(), rpc_fs::ErrorCode>>();
        self.spawner.spawn(async move {
            while let Ok(Some(chunk)) = data.next_batch().await {
                if !chunk.is_empty() {
                    let remaining = wit_tx.write_all(chunk).await;
                    if !remaining.is_empty() {
                        break;
                    }
                }
            }
            drop(wit_tx);
            let outcome = done_wit.await.map_err(map_fs_error);
            let _ = fut_tx.resolve(outcome).await;
        });
        fut_rx
    }

    async fn descriptor_append_via_stream(
        &self,
        self_: &Self::Descriptor,
        mut data: StreamReader<u8>,
    ) -> FutureReader<Result<(), rpc_fs::ErrorCode>> {
        let (mut wit_tx, wit_rx) = wit_stream::new::<u8>();
        let done_wit = self_.append_via_stream(wit_rx);
        let (fut_tx, fut_rx) = rpc_future::<Result<(), rpc_fs::ErrorCode>>();
        self.spawner.spawn(async move {
            while let Ok(Some(chunk)) = data.next_batch().await {
                if !chunk.is_empty() {
                    let remaining = wit_tx.write_all(chunk).await;
                    if !remaining.is_empty() {
                        break;
                    }
                }
            }
            drop(wit_tx);
            let outcome = done_wit.await.map_err(map_fs_error);
            let _ = fut_tx.resolve(outcome).await;
        });
        fut_rx
    }

    async fn descriptor_advise(
        &self,
        self_: &Self::Descriptor,
        offset: u64,
        length: u64,
        advice: rpc_fs::Advice,
    ) -> Result<(), rpc_fs::ErrorCode> {
        let advice = match advice {
            rpc_fs::Advice::Normal => raw_fs::Advice::Normal,
            rpc_fs::Advice::Sequential => raw_fs::Advice::Sequential,
            rpc_fs::Advice::Random => raw_fs::Advice::Random,
            rpc_fs::Advice::WillNeed => raw_fs::Advice::WillNeed,
            rpc_fs::Advice::DontNeed => raw_fs::Advice::DontNeed,
            rpc_fs::Advice::NoReuse => raw_fs::Advice::NoReuse,
        };
        self_
            .advise(offset, length, advice)
            .await
            .map_err(map_fs_error)
    }

    async fn descriptor_sync_data(
        &self,
        self_: &Self::Descriptor,
    ) -> Result<(), rpc_fs::ErrorCode> {
        self_.sync_data().await.map_err(map_fs_error)
    }

    async fn descriptor_get_flags(
        &self,
        self_: &Self::Descriptor,
    ) -> Result<rpc_fs::DescriptorFlags, rpc_fs::ErrorCode> {
        self_
            .get_flags()
            .await
            .map(map_desc_flags_out)
            .map_err(map_fs_error)
    }

    async fn descriptor_get_type(
        &self,
        self_: &Self::Descriptor,
    ) -> Result<rpc_fs::DescriptorType, rpc_fs::ErrorCode> {
        self_
            .get_type()
            .await
            .map(map_desc_type_out)
            .map_err(map_fs_error)
    }

    async fn descriptor_set_size(
        &self,
        self_: &Self::Descriptor,
        size: u64,
    ) -> Result<(), rpc_fs::ErrorCode> {
        self_.set_size(size).await.map_err(map_fs_error)
    }

    async fn descriptor_set_times(
        &self,
        self_: &Self::Descriptor,
        data_access_timestamp: rpc_fs::NewTimestamp,
        data_modification_timestamp: rpc_fs::NewTimestamp,
    ) -> Result<(), rpc_fs::ErrorCode> {
        self_
            .set_times(
                map_new_timestamp_in(data_access_timestamp),
                map_new_timestamp_in(data_modification_timestamp),
            )
            .await
            .map_err(map_fs_error)
    }

    async fn descriptor_read_directory(
        &self,
        self_: &Self::Descriptor,
    ) -> (
        StreamReader<rpc_fs::DirectoryEntry>,
        FutureReader<Result<(), rpc_fs::ErrorCode>>,
    ) {
        let (mut wit_rx, done_wit) = self_.read_directory();
        let (mut rpc_tx, rpc_rx) = rpc_stream::<rpc_fs::DirectoryEntry>();
        let (fut_tx, fut_rx) = rpc_future::<Result<(), rpc_fs::ErrorCode>>();
        self.spawner.spawn(async move {
            let mut buf = Vec::with_capacity(64);
            loop {
                let (res, entries) = wit_rx.read(buf).await;
                if !entries.is_empty() {
                    let mapped: Vec<rpc_fs::DirectoryEntry> = entries
                        .into_iter()
                        .map(|e| rpc_fs::DirectoryEntry {
                            r#type: map_desc_type_out(e.type_),
                            name: e.name,
                        })
                        .collect();
                    if rpc_tx.send_batch(mapped).await.is_err() {
                        break;
                    }
                    buf = Vec::with_capacity(64);
                } else {
                    buf = entries;
                }
                if stream_closed(res) {
                    break;
                }
            }
            let _ = rpc_tx.close().await;
            let outcome = done_wit.await.map_err(map_fs_error);
            let _ = fut_tx.resolve(outcome).await;
        });
        (rpc_rx, fut_rx)
    }

    async fn descriptor_sync(&self, self_: &Self::Descriptor) -> Result<(), rpc_fs::ErrorCode> {
        self_.sync().await.map_err(map_fs_error)
    }

    async fn descriptor_create_directory_at(
        &self,
        self_: &Self::Descriptor,
        path: String,
    ) -> Result<(), rpc_fs::ErrorCode> {
        self_.create_directory_at(path).await.map_err(map_fs_error)
    }

    async fn descriptor_stat(
        &self,
        self_: &Self::Descriptor,
    ) -> Result<rpc_fs::DescriptorStat, rpc_fs::ErrorCode> {
        self_
            .stat()
            .await
            .map(map_desc_stat_out)
            .map_err(map_fs_error)
    }

    async fn descriptor_stat_at(
        &self,
        self_: &Self::Descriptor,
        path_flags: rpc_fs::PathFlags,
        path: String,
    ) -> Result<rpc_fs::DescriptorStat, rpc_fs::ErrorCode> {
        self_
            .stat_at(map_path_flags_in(path_flags), path)
            .await
            .map(map_desc_stat_out)
            .map_err(map_fs_error)
    }

    async fn descriptor_set_times_at(
        &self,
        self_: &Self::Descriptor,
        path_flags: rpc_fs::PathFlags,
        path: String,
        data_access_timestamp: rpc_fs::NewTimestamp,
        data_modification_timestamp: rpc_fs::NewTimestamp,
    ) -> Result<(), rpc_fs::ErrorCode> {
        self_
            .set_times_at(
                map_path_flags_in(path_flags),
                path,
                map_new_timestamp_in(data_access_timestamp),
                map_new_timestamp_in(data_modification_timestamp),
            )
            .await
            .map_err(map_fs_error)
    }

    async fn descriptor_link_at(
        &self,
        self_: &Self::Descriptor,
        old_path_flags: rpc_fs::PathFlags,
        old_path: String,
        new_descriptor: &Self::Descriptor,
        new_path: String,
    ) -> Result<(), rpc_fs::ErrorCode> {
        self_
            .link_at(
                map_path_flags_in(old_path_flags),
                old_path,
                new_descriptor,
                new_path,
            )
            .await
            .map_err(map_fs_error)
    }

    async fn descriptor_open_at(
        &self,
        self_: &Self::Descriptor,
        path_flags: rpc_fs::PathFlags,
        path: String,
        open_flags: rpc_fs::OpenFlags,
        flags: rpc_fs::DescriptorFlags,
    ) -> Result<Self::Descriptor, rpc_fs::ErrorCode> {
        self_
            .open_at(
                map_path_flags_in(path_flags),
                path,
                map_open_flags_in(open_flags),
                map_desc_flags_in(flags),
            )
            .await
            .map_err(map_fs_error)
    }

    async fn descriptor_readlink_at(
        &self,
        self_: &Self::Descriptor,
        path: String,
    ) -> Result<String, rpc_fs::ErrorCode> {
        self_.readlink_at(path).await.map_err(map_fs_error)
    }

    async fn descriptor_remove_directory_at(
        &self,
        self_: &Self::Descriptor,
        path: String,
    ) -> Result<(), rpc_fs::ErrorCode> {
        self_.remove_directory_at(path).await.map_err(map_fs_error)
    }

    async fn descriptor_rename_at(
        &self,
        self_: &Self::Descriptor,
        old_path: String,
        new_descriptor: &Self::Descriptor,
        new_path: String,
    ) -> Result<(), rpc_fs::ErrorCode> {
        self_
            .rename_at(old_path, new_descriptor, new_path)
            .await
            .map_err(map_fs_error)
    }

    async fn descriptor_symlink_at(
        &self,
        self_: &Self::Descriptor,
        old_path: String,
        new_path: String,
    ) -> Result<(), rpc_fs::ErrorCode> {
        self_
            .symlink_at(old_path, new_path)
            .await
            .map_err(map_fs_error)
    }

    async fn descriptor_unlink_file_at(
        &self,
        self_: &Self::Descriptor,
        path: String,
    ) -> Result<(), rpc_fs::ErrorCode> {
        self_.unlink_file_at(path).await.map_err(map_fs_error)
    }

    async fn descriptor_is_same_object(
        &self,
        self_: &Self::Descriptor,
        other: &Self::Descriptor,
    ) -> bool {
        self_.is_same_object(other).await
    }

    async fn descriptor_metadata_hash(
        &self,
        self_: &Self::Descriptor,
    ) -> Result<rpc_fs::MetadataHashValue, rpc_fs::ErrorCode> {
        self_
            .metadata_hash()
            .await
            .map(|h| rpc_fs::MetadataHashValue {
                lower: h.lower,
                upper: h.upper,
            })
            .map_err(map_fs_error)
    }

    async fn descriptor_metadata_hash_at(
        &self,
        self_: &Self::Descriptor,
        path_flags: rpc_fs::PathFlags,
        path: String,
    ) -> Result<rpc_fs::MetadataHashValue, rpc_fs::ErrorCode> {
        self_
            .metadata_hash_at(map_path_flags_in(path_flags), path)
            .await
            .map(|h| rpc_fs::MetadataHashValue {
                lower: h.lower,
                upper: h.upper,
            })
            .map_err(map_fs_error)
    }
}

// ---------------------------------------------------------------------------
// Mechanical WIT value conversions (zero policy logic)
// ---------------------------------------------------------------------------

fn map_filter_error(err: raw_sys::filters::FilterError) -> rpc_filters::FilterError {
    match err {
        raw_sys::filters::FilterError::TooManyPrefixes(n) => {
            rpc_filters::FilterError::TooManyPrefixes(n)
        }
        raw_sys::filters::FilterError::PrefixTooLong(n) => {
            rpc_filters::FilterError::PrefixTooLong(n)
        }
    }
}

fn map_aot_hint_in(hint: rpc_programs::AotHint) -> raw_sys::programs::AotHint {
    match hint {
        rpc_programs::AotHint::Fast => raw_sys::programs::AotHint::Fast,
        rpc_programs::AotHint::Balanced => raw_sys::programs::AotHint::Balanced,
        rpc_programs::AotHint::Performance => raw_sys::programs::AotHint::Performance,
    }
}

fn map_fs_right_in(r: rpc_programs::FilesystemRight) -> raw_sys::programs::FilesystemRight {
    match r {
        rpc_programs::FilesystemRight::Read => raw_sys::programs::FilesystemRight::Read,
        rpc_programs::FilesystemRight::Write => raw_sys::programs::FilesystemRight::Write,
        rpc_programs::FilesystemRight::MutateDirectory => {
            raw_sys::programs::FilesystemRight::MutateDirectory
        }
        rpc_programs::FilesystemRight::Execute => raw_sys::programs::FilesystemRight::Execute,
    }
}

fn map_authority_scope_in(s: rpc_programs::AuthorityScope) -> raw_sys::programs::AuthorityScope {
    match s {
        rpc_programs::AuthorityScope::Own => raw_sys::programs::AuthorityScope::Own,
        rpc_programs::AuthorityScope::Subtree(id) => raw_sys::programs::AuthorityScope::Subtree(id),
        rpc_programs::AuthorityScope::Machine => raw_sys::programs::AuthorityScope::Machine,
    }
}

fn map_capability_grant_in(
    g: rpc_programs::CapabilityGrant<raw_sys::ipc::Endpoint>,
) -> raw_sys::programs::CapabilityGrant {
    match g {
        rpc_programs::CapabilityGrant::Directory(d) => {
            raw_sys::programs::CapabilityGrant::Directory(raw_sys::programs::DirectoryGrant {
                source_path: d.source_path,
                guest_name: d.guest_name,
                rights: d.rights.into_iter().map(map_fs_right_in).collect(),
            })
        }
        rpc_programs::CapabilityGrant::Network(n) => {
            raw_sys::programs::CapabilityGrant::Network(raw_sys::programs::NetworkGrant {
                rights: n
                    .rights
                    .into_iter()
                    .map(|r| match r {
                        rpc_programs::NetworkRight::Tcp => raw_sys::programs::NetworkRight::Tcp,
                        rpc_programs::NetworkRight::Udp => raw_sys::programs::NetworkRight::Udp,
                        rpc_programs::NetworkRight::Dns => raw_sys::programs::NetworkRight::Dns,
                        rpc_programs::NetworkRight::PrivilegedBind => {
                            raw_sys::programs::NetworkRight::PrivilegedBind
                        }
                        rpc_programs::NetworkRight::Multicast => {
                            raw_sys::programs::NetworkRight::Multicast
                        }
                        rpc_programs::NetworkRight::Admin => raw_sys::programs::NetworkRight::Admin,
                    })
                    .collect(),
            })
        }
        rpc_programs::CapabilityGrant::Clock(c) => {
            raw_sys::programs::CapabilityGrant::Clock(raw_sys::programs::ClockGrant {
                rights: c
                    .rights
                    .into_iter()
                    .map(|r| match r {
                        rpc_programs::ClockRight::SetWallClock => {
                            raw_sys::programs::ClockRight::SetWallClock
                        }
                    })
                    .collect(),
            })
        }
        rpc_programs::CapabilityGrant::Terminal(t) => {
            raw_sys::programs::CapabilityGrant::Terminal(raw_sys::programs::TerminalGrant {
                rights: t
                    .rights
                    .into_iter()
                    .map(|r| match r {
                        rpc_programs::TerminalRight::Input => {
                            raw_sys::programs::TerminalRight::Input
                        }
                        rpc_programs::TerminalRight::Output => {
                            raw_sys::programs::TerminalRight::Output
                        }
                        rpc_programs::TerminalRight::Control => {
                            raw_sys::programs::TerminalRight::Control
                        }
                    })
                    .collect(),
            })
        }
        rpc_programs::CapabilityGrant::Process(p) => {
            raw_sys::programs::CapabilityGrant::Process(raw_sys::programs::ProcessGrant {
                rights: p
                    .rights
                    .into_iter()
                    .map(|r| match r {
                        rpc_programs::ProcessRight::Spawn => raw_sys::programs::ProcessRight::Spawn,
                        rpc_programs::ProcessRight::Exec => raw_sys::programs::ProcessRight::Exec,
                        rpc_programs::ProcessRight::Fork => raw_sys::programs::ProcessRight::Fork,
                        rpc_programs::ProcessRight::Join => raw_sys::programs::ProcessRight::Join,
                        rpc_programs::ProcessRight::Signal => {
                            raw_sys::programs::ProcessRight::Signal
                        }
                    })
                    .collect(),
            })
        }
        rpc_programs::CapabilityGrant::Link(l) => {
            raw_sys::programs::CapabilityGrant::Link(raw_sys::programs::LinkGrant {
                rights: l
                    .rights
                    .into_iter()
                    .map(|r| match r {
                        rpc_programs::LinkRight::Source => raw_sys::programs::LinkRight::Source,
                        rpc_programs::LinkRight::TargetDirectory => {
                            raw_sys::programs::LinkRight::TargetDirectory
                        }
                        rpc_programs::LinkRight::SymlinkCreate => {
                            raw_sys::programs::LinkRight::SymlinkCreate
                        }
                        rpc_programs::LinkRight::SymlinkRead => {
                            raw_sys::programs::LinkRight::SymlinkRead
                        }
                    })
                    .collect(),
            })
        }
        rpc_programs::CapabilityGrant::Mount(m) => {
            raw_sys::programs::CapabilityGrant::Mount(raw_sys::programs::MountGrant {
                rights: m
                    .rights
                    .into_iter()
                    .map(|r| match r {
                        rpc_programs::MountRight::Mount => raw_sys::programs::MountRight::Mount,
                        rpc_programs::MountRight::Unmount => raw_sys::programs::MountRight::Unmount,
                    })
                    .collect(),
            })
        }
        rpc_programs::CapabilityGrant::Device(d) => {
            raw_sys::programs::CapabilityGrant::Device(raw_sys::programs::DeviceGrant {
                classes: d
                    .classes
                    .into_iter()
                    .map(|c| match c {
                        rpc_programs::DeviceClass::Display => {
                            raw_sys::programs::DeviceClass::Display
                        }
                        rpc_programs::DeviceClass::Input => raw_sys::programs::DeviceClass::Input,
                        rpc_programs::DeviceClass::Gpu => raw_sys::programs::DeviceClass::Gpu,
                        rpc_programs::DeviceClass::Audio => raw_sys::programs::DeviceClass::Audio,
                    })
                    .collect(),
            })
        }
        rpc_programs::CapabilityGrant::Diagnostics(d) => {
            raw_sys::programs::CapabilityGrant::Diagnostics(match d {
                rpc_programs::DiagnosticsGrant::InspectRead(s) => {
                    raw_sys::programs::DiagnosticsGrant::InspectRead(map_authority_scope_in(s))
                }
                rpc_programs::DiagnosticsGrant::TraceRead(s) => {
                    raw_sys::programs::DiagnosticsGrant::TraceRead(map_authority_scope_in(s))
                }
                rpc_programs::DiagnosticsGrant::ProfileRead(s) => {
                    raw_sys::programs::DiagnosticsGrant::ProfileRead(map_authority_scope_in(s))
                }
                rpc_programs::DiagnosticsGrant::Control => {
                    raw_sys::programs::DiagnosticsGrant::Control
                }
            })
        }
        rpc_programs::CapabilityGrant::InstanceControl(s) => {
            raw_sys::programs::CapabilityGrant::InstanceControl(map_authority_scope_in(s))
        }
        rpc_programs::CapabilityGrant::Settings(s) => {
            raw_sys::programs::CapabilityGrant::Settings(raw_sys::programs::SettingsGrant {
                rights: s
                    .rights
                    .into_iter()
                    .map(|r| match r {
                        rpc_programs::SettingsRight::Write => {
                            raw_sys::programs::SettingsRight::Write
                        }
                    })
                    .collect(),
            })
        }
        rpc_programs::CapabilityGrant::Machine(m) => {
            raw_sys::programs::CapabilityGrant::Machine(raw_sys::programs::MachineGrant {
                rights: m
                    .rights
                    .into_iter()
                    .map(|r| match r {
                        rpc_programs::MachineRight::Control => {
                            raw_sys::programs::MachineRight::Control
                        }
                        rpc_programs::MachineRight::Identity => {
                            raw_sys::programs::MachineRight::Identity
                        }
                        rpc_programs::MachineRight::Virtualize => {
                            raw_sys::programs::MachineRight::Virtualize
                        }
                    })
                    .collect(),
            })
        }
        rpc_programs::CapabilityGrant::Ipc(i) => {
            raw_sys::programs::CapabilityGrant::Ipc(raw_sys::programs::IpcGrant {
                name: i.name,
                endpoint: i.endpoint,
            })
        }
    }
}

fn map_inherited_socket_in(
    s: rpc_programs::InheritedSocket<
        raw_sys::net::TcpListener,
        raw_sys::vsock::VsockListener,
        raw_sys::net::TcpStream,
        raw_sys::vsock::VsockStream,
        raw_sys::serial::SerialPort,
    >,
) -> raw_sys::programs::InheritedSocket {
    match s {
        rpc_programs::InheritedSocket::Tcp(l) => raw_sys::programs::InheritedSocket::Tcp(l),
        rpc_programs::InheritedSocket::Vsock(l) => raw_sys::programs::InheritedSocket::Vsock(l),
        rpc_programs::InheritedSocket::TcpStream(st) => {
            raw_sys::programs::InheritedSocket::TcpStream(st)
        }
        rpc_programs::InheritedSocket::VsockStream(st) => {
            raw_sys::programs::InheritedSocket::VsockStream(st)
        }
        rpc_programs::InheritedSocket::Serial(p) => raw_sys::programs::InheritedSocket::Serial(p),
    }
}

fn map_container_mount_in(m: rpc_programs::ContainerMount) -> raw_sys::programs::ContainerMount {
    raw_sys::programs::ContainerMount {
        source_path: m.source_path,
        target_path: m.target_path,
        rights: m.rights.into_iter().map(map_fs_right_in).collect(),
        sharing: match m.sharing {
            rpc_programs::ContainerMountSharing::Private => {
                raw_sys::programs::ContainerMountSharing::Private
            }
            rpc_programs::ContainerMountSharing::Shared => {
                raw_sys::programs::ContainerMountSharing::Shared
            }
            rpc_programs::ContainerMountSharing::EphemeralOverlay => {
                raw_sys::programs::ContainerMountSharing::EphemeralOverlay
            }
        },
    }
}

fn map_container_creds_in(
    c: rpc_programs::ContainerCredentials,
) -> raw_sys::programs::ContainerCredentials {
    raw_sys::programs::ContainerCredentials {
        uid: c.uid,
        gid: c.gid,
        supplementary_groups: c.supplementary_groups,
    }
}

fn map_container_creds_out(
    c: raw_sys::programs::ContainerCredentials,
) -> rpc_programs::ContainerCredentials {
    rpc_programs::ContainerCredentials {
        uid: c.uid,
        gid: c.gid,
        supplementary_groups: c.supplementary_groups,
    }
}

fn map_exec_result(r: raw_sys::programs::ExecResult) -> rpc_programs::ExecResult {
    rpc_programs::ExecResult {
        instance_id: r.instance_id,
        exit_code: r.exit_code,
        output: rpc_programs::ExecOutput {
            stdout: r.output.stdout,
            stderr: r.output.stderr,
        },
        launch_nanos: r.launch_nanos,
    }
}

fn map_exit_status(s: raw_sys::programs::ExitStatus) -> rpc_programs::ExitStatus {
    rpc_programs::ExitStatus {
        instance_id: s.instance_id,
        termination: match s.termination {
            raw_sys::programs::ChildTermination::Exited(code) => {
                rpc_programs::ChildTermination::Exited(code)
            }
            raw_sys::programs::ChildTermination::Signaled(sig) => {
                rpc_programs::ChildTermination::Signaled(rpc_programs::SignalTermination {
                    signal: sig.signal,
                    core_dumped: sig.core_dumped,
                })
            }
            raw_sys::programs::ChildTermination::Trapped => rpc_programs::ChildTermination::Trapped,
            raw_sys::programs::ChildTermination::Killed => rpc_programs::ChildTermination::Killed,
        },
    }
}

fn map_spawn_error(err: raw_sys::programs::SpawnError) -> rpc_programs::SpawnError {
    rpc_programs::SpawnError {
        kind: match err.kind {
            raw_sys::programs::SpawnErrorKind::InvalidBinary => {
                rpc_programs::SpawnErrorKind::InvalidBinary
            }
            raw_sys::programs::SpawnErrorKind::MissingEntry => {
                rpc_programs::SpawnErrorKind::MissingEntry
            }
            raw_sys::programs::SpawnErrorKind::UnsupportedImport => {
                rpc_programs::SpawnErrorKind::UnsupportedImport
            }
            raw_sys::programs::SpawnErrorKind::InvalidSignature => {
                rpc_programs::SpawnErrorKind::InvalidSignature
            }
            raw_sys::programs::SpawnErrorKind::InvalidPath => {
                rpc_programs::SpawnErrorKind::InvalidPath
            }
            raw_sys::programs::SpawnErrorKind::PermissionDenied => {
                rpc_programs::SpawnErrorKind::PermissionDenied
            }
            raw_sys::programs::SpawnErrorKind::InvalidHint => {
                rpc_programs::SpawnErrorKind::InvalidHint
            }
            raw_sys::programs::SpawnErrorKind::OutOfMemory => {
                rpc_programs::SpawnErrorKind::OutOfMemory
            }
            raw_sys::programs::SpawnErrorKind::Unavailable => {
                rpc_programs::SpawnErrorKind::Unavailable
            }
            raw_sys::programs::SpawnErrorKind::Internal => rpc_programs::SpawnErrorKind::Internal,
            raw_sys::programs::SpawnErrorKind::NotFound => rpc_programs::SpawnErrorKind::NotFound,
            raw_sys::programs::SpawnErrorKind::Io => rpc_programs::SpawnErrorKind::Io,
        },
        detail: err.detail,
    }
}

fn map_mount_error(err: raw_sys::mounts::MountError) -> rpc_mounts::MountError {
    rpc_mounts::MountError {
        kind: match err.kind {
            raw_sys::mounts::MountErrorKind::PermissionDenied => {
                rpc_mounts::MountErrorKind::PermissionDenied
            }
            raw_sys::mounts::MountErrorKind::InvalidPoint => {
                rpc_mounts::MountErrorKind::InvalidPoint
            }
            raw_sys::mounts::MountErrorKind::AlreadyMounted => {
                rpc_mounts::MountErrorKind::AlreadyMounted
            }
            raw_sys::mounts::MountErrorKind::NotMounted => rpc_mounts::MountErrorKind::NotMounted,
            raw_sys::mounts::MountErrorKind::Busy => rpc_mounts::MountErrorKind::Busy,
            raw_sys::mounts::MountErrorKind::TableFull => rpc_mounts::MountErrorKind::TableFull,
            raw_sys::mounts::MountErrorKind::Unavailable => rpc_mounts::MountErrorKind::Unavailable,
            raw_sys::mounts::MountErrorKind::InvalidPath => rpc_mounts::MountErrorKind::InvalidPath,
            raw_sys::mounts::MountErrorKind::InvalidFilesystem => {
                rpc_mounts::MountErrorKind::InvalidFilesystem
            }
            raw_sys::mounts::MountErrorKind::Io => rpc_mounts::MountErrorKind::Io,
            raw_sys::mounts::MountErrorKind::InvalidOption => {
                rpc_mounts::MountErrorKind::InvalidOption
            }
        },
        detail: err.detail,
    }
}

fn map_subvol_info(info: raw_sys::btrfs::SubvolumeInfo) -> rpc_btrfs::SubvolumeInfo {
    rpc_btrfs::SubvolumeInfo {
        id: info.id,
        parent_id: info.parent_id,
        path: info.path,
        uuid: info.uuid,
        parent_uuid: info.parent_uuid,
        received_uuid: info.received_uuid,
        generation: info.generation,
        ctransid: info.ctransid,
        otransid: info.otransid,
        stransid: info.stransid,
        rtransid: info.rtransid,
        read_only: info.read_only,
    }
}

fn map_vol_dev(dev: raw_sys::btrfs::VolumeDeviceInfo) -> rpc_btrfs::VolumeDeviceInfo {
    rpc_btrfs::VolumeDeviceInfo {
        devid: dev.devid,
        uuid: dev.uuid,
        total_bytes: dev.total_bytes,
        bytes_used: dev.bytes_used,
        serial: dev.serial,
    }
}

fn map_btrfs_error(err: raw_sys::btrfs::BtrfsError) -> rpc_btrfs::BtrfsError {
    use raw_sys::btrfs::BtrfsErrorKind as Raw;
    use rpc_btrfs::BtrfsErrorKind as Rpc;
    rpc_btrfs::BtrfsError {
        kind: match err.kind {
            Raw::PermissionDenied => Rpc::PermissionDenied,
            Raw::NotBtrfs => Rpc::NotBtrfs,
            Raw::NotFound => Rpc::NotFound,
            Raw::AlreadyExists => Rpc::AlreadyExists,
            Raw::ReadOnlyFilesystem => Rpc::ReadOnlyFilesystem,
            Raw::NotDirectory => Rpc::NotDirectory,
            Raw::IsDirectory => Rpc::IsDirectory,
            Raw::NotEmpty => Rpc::NotEmpty,
            Raw::NoSpace => Rpc::NoSpace,
            Raw::InvalidArgument => Rpc::InvalidArgument,
            Raw::CrossDevice => Rpc::CrossDevice,
            Raw::Busy => Rpc::Busy,
            Raw::Io => Rpc::Io,
            Raw::NotSubvolume => Rpc::NotSubvolume,
            Raw::ReadOnlySubvolume => Rpc::ReadOnlySubvolume,
            Raw::SubvolumeNotReadOnly => Rpc::SubvolumeNotReadOnly,
            Raw::SubvolumeNotEmpty => Rpc::SubvolumeNotEmpty,
            Raw::DefaultSubvolume => Rpc::DefaultSubvolume,
            Raw::QuotaNotEnabled => Rpc::QuotaNotEnabled,
            Raw::QuotaAlreadyEnabled => Rpc::QuotaAlreadyEnabled,
            Raw::QuotaExceeded => Rpc::QuotaExceeded,
            Raw::QgroupNotFound => Rpc::QgroupNotFound,
            Raw::QgroupExists => Rpc::QgroupExists,
            Raw::QgroupInvalidRelation => Rpc::QgroupInvalidRelation,
            Raw::DeviceNotFound => Rpc::DeviceNotFound,
            Raw::LastDevice => Rpc::LastDevice,
            Raw::DeviceTooSmall => Rpc::DeviceTooSmall,
            Raw::InvalidStream => Rpc::InvalidStream,
            Raw::Alignment => Rpc::Alignment,
            Raw::Overlap => Rpc::Overlap,
            Raw::ChecksumPolicyMismatch => Rpc::ChecksumPolicyMismatch,
            Raw::CloneSourceOutOfRange => Rpc::CloneSourceOutOfRange,
        },
        detail: err.detail,
    }
}

fn map_trace_filter_in(f: rpc_tracing::Filter) -> raw_sys::tracing::Filter {
    raw_sys::tracing::Filter {
        min_level: f.min_level.map(|l| match l {
            rpc_tracing::Level::Error => raw_sys::tracing::Level::Error,
            rpc_tracing::Level::Warn => raw_sys::tracing::Level::Warn,
            rpc_tracing::Level::Info => raw_sys::tracing::Level::Info,
            rpc_tracing::Level::Debug => raw_sys::tracing::Level::Debug,
            rpc_tracing::Level::Trace => raw_sys::tracing::Level::Trace,
        }),
        target_prefixes: f.target_prefixes,
    }
}

fn map_trace_event(e: raw_sys::tracing::Event) -> rpc_tracing::Event {
    rpc_tracing::Event {
        timestamp: e.timestamp,
        level: match e.level {
            raw_sys::tracing::Level::Error => rpc_tracing::Level::Error,
            raw_sys::tracing::Level::Warn => rpc_tracing::Level::Warn,
            raw_sys::tracing::Level::Info => rpc_tracing::Level::Info,
            raw_sys::tracing::Level::Debug => rpc_tracing::Level::Debug,
            raw_sys::tracing::Level::Trace => rpc_tracing::Level::Trace,
        },
        target: e.target,
        fields: e
            .fields
            .into_iter()
            .map(|f| rpc_tracing::Field {
                key: f.key,
                value: match f.value {
                    raw_sys::tracing::Value::Boolean(v) => rpc_tracing::Value::Boolean(v),
                    raw_sys::tracing::Value::Signed64(v) => rpc_tracing::Value::Signed64(v),
                    raw_sys::tracing::Value::Unsigned64(v) => rpc_tracing::Value::Unsigned64(v),
                    raw_sys::tracing::Value::Float64(v) => rpc_tracing::Value::Float64(v),
                    raw_sys::tracing::Value::Text(v) => rpc_tracing::Value::Text(v),
                    raw_sys::tracing::Value::Blob(v) => rpc_tracing::Value::Blob(v),
                },
            })
            .collect(),
    }
}

fn map_prof_scope_in(s: rpc_profiling::Scope) -> raw_sys::profiling::Scope {
    match s {
        rpc_profiling::Scope::Kernel => raw_sys::profiling::Scope::Kernel,
        rpc_profiling::Scope::User => raw_sys::profiling::Scope::User,
    }
}

fn map_prof_scope_out(s: raw_sys::profiling::Scope) -> rpc_profiling::Scope {
    match s {
        raw_sys::profiling::Scope::Kernel => rpc_profiling::Scope::Kernel,
        raw_sys::profiling::Scope::User => rpc_profiling::Scope::User,
    }
}

fn map_inst_prof_error(
    e: raw_sys::profiling::InstructionProfileError,
) -> rpc_profiling::InstructionProfileError {
    match e {
        raw_sys::profiling::InstructionProfileError::NotCaptured => {
            rpc_profiling::InstructionProfileError::NotCaptured
        }
        raw_sys::profiling::InstructionProfileError::Denied => {
            rpc_profiling::InstructionProfileError::Denied
        }
        raw_sys::profiling::InstructionProfileError::Busy => {
            rpc_profiling::InstructionProfileError::Busy
        }
    }
}

fn map_raw_prof_error(e: raw_sys::profiling::RawProfileError) -> rpc_profiling::RawProfileError {
    match e {
        raw_sys::profiling::RawProfileError::NotInstrumented => {
            rpc_profiling::RawProfileError::NotInstrumented
        }
        raw_sys::profiling::RawProfileError::UnsupportedVersion(v) => {
            rpc_profiling::RawProfileError::UnsupportedVersion(v)
        }
        raw_sys::profiling::RawProfileError::MalformedSection(s) => {
            rpc_profiling::RawProfileError::MalformedSection(match s {
                raw_sys::profiling::ProfileSection::Counters => {
                    rpc_profiling::ProfileSection::Counters
                }
                raw_sys::profiling::ProfileSection::Data => rpc_profiling::ProfileSection::Data,
                raw_sys::profiling::ProfileSection::Names => rpc_profiling::ProfileSection::Names,
            })
        }
        raw_sys::profiling::RawProfileError::OutOfRange(n) => {
            rpc_profiling::RawProfileError::OutOfRange(n)
        }
        raw_sys::profiling::RawProfileError::ReadTooLarge(n) => {
            rpc_profiling::RawProfileError::ReadTooLarge(n)
        }
        raw_sys::profiling::RawProfileError::Denied => rpc_profiling::RawProfileError::Denied,
    }
}

fn map_ip_in(ip: rpc_net::IpAddress) -> raw_sys::net::IpAddress {
    match ip {
        rpc_net::IpAddress::Ipv4(v) => raw_sys::net::IpAddress::Ipv4(v),
        rpc_net::IpAddress::Ipv6(v) => raw_sys::net::IpAddress::Ipv6(v),
    }
}

fn map_ip_out(ip: raw_sys::net::IpAddress) -> rpc_net::IpAddress {
    match ip {
        raw_sys::net::IpAddress::Ipv4(v) => rpc_net::IpAddress::Ipv4(v),
        raw_sys::net::IpAddress::Ipv6(v) => rpc_net::IpAddress::Ipv6(v),
    }
}

fn map_tcp_error(e: raw_sys::net::TcpError) -> rpc_net::TcpError {
    rpc_net::TcpError {
        kind: match e.kind {
            raw_sys::net::TcpErrorKind::UnresolvedHost => rpc_net::TcpErrorKind::UnresolvedHost,
            raw_sys::net::TcpErrorKind::Timeout => rpc_net::TcpErrorKind::Timeout,
            raw_sys::net::TcpErrorKind::ConnectionReset => rpc_net::TcpErrorKind::ConnectionReset,
            raw_sys::net::TcpErrorKind::ConnectionAborted => {
                rpc_net::TcpErrorKind::ConnectionAborted
            }
            raw_sys::net::TcpErrorKind::PermissionDenied => rpc_net::TcpErrorKind::PermissionDenied,
            raw_sys::net::TcpErrorKind::AddressInUse => rpc_net::TcpErrorKind::AddressInUse,
            raw_sys::net::TcpErrorKind::Unavailable => rpc_net::TcpErrorKind::Unavailable,
            raw_sys::net::TcpErrorKind::Internal => rpc_net::TcpErrorKind::Internal,
        },
        detail: e.detail,
    }
}

fn map_udp_error(e: raw_sys::net::UdpError) -> rpc_net::UdpError {
    rpc_net::UdpError {
        kind: match e.kind {
            raw_sys::net::UdpErrorKind::UnresolvedHost => rpc_net::UdpErrorKind::UnresolvedHost,
            raw_sys::net::UdpErrorKind::Timeout => rpc_net::UdpErrorKind::Timeout,
            raw_sys::net::UdpErrorKind::PermissionDenied => rpc_net::UdpErrorKind::PermissionDenied,
            raw_sys::net::UdpErrorKind::Unavailable => rpc_net::UdpErrorKind::Unavailable,
            raw_sys::net::UdpErrorKind::Internal => rpc_net::UdpErrorKind::Internal,
        },
        detail: e.detail,
    }
}

fn map_path_flags_in(flags: rpc_fs::PathFlags) -> raw_fs::PathFlags {
    let mut out = raw_fs::PathFlags::empty();
    if flags.contains(rpc_fs::PathFlags::SYMLINK_FOLLOW) {
        out = out | raw_fs::PathFlags::SYMLINK_FOLLOW;
    }
    out
}

fn map_open_flags_in(flags: rpc_fs::OpenFlags) -> raw_fs::OpenFlags {
    let mut out = raw_fs::OpenFlags::empty();
    if flags.contains(rpc_fs::OpenFlags::CREATE) {
        out = out | raw_fs::OpenFlags::CREATE;
    }
    if flags.contains(rpc_fs::OpenFlags::DIRECTORY) {
        out = out | raw_fs::OpenFlags::DIRECTORY;
    }
    if flags.contains(rpc_fs::OpenFlags::EXCLUSIVE) {
        out = out | raw_fs::OpenFlags::EXCLUSIVE;
    }
    if flags.contains(rpc_fs::OpenFlags::TRUNCATE) {
        out = out | raw_fs::OpenFlags::TRUNCATE;
    }
    out
}

fn map_desc_flags_in(flags: rpc_fs::DescriptorFlags) -> raw_fs::DescriptorFlags {
    let mut out = raw_fs::DescriptorFlags::empty();
    if flags.contains(rpc_fs::DescriptorFlags::READ) {
        out = out | raw_fs::DescriptorFlags::READ;
    }
    if flags.contains(rpc_fs::DescriptorFlags::WRITE) {
        out = out | raw_fs::DescriptorFlags::WRITE;
    }
    if flags.contains(rpc_fs::DescriptorFlags::FILE_INTEGRITY_SYNC) {
        out = out | raw_fs::DescriptorFlags::FILE_INTEGRITY_SYNC;
    }
    if flags.contains(rpc_fs::DescriptorFlags::DATA_INTEGRITY_SYNC) {
        out = out | raw_fs::DescriptorFlags::DATA_INTEGRITY_SYNC;
    }
    if flags.contains(rpc_fs::DescriptorFlags::REQUESTED_WRITE_SYNC) {
        out = out | raw_fs::DescriptorFlags::REQUESTED_WRITE_SYNC;
    }
    if flags.contains(rpc_fs::DescriptorFlags::MUTATE_DIRECTORY) {
        out = out | raw_fs::DescriptorFlags::MUTATE_DIRECTORY;
    }
    out
}

fn map_desc_flags_out(flags: raw_fs::DescriptorFlags) -> rpc_fs::DescriptorFlags {
    let mut out = rpc_fs::DescriptorFlags::empty();
    if (flags & raw_fs::DescriptorFlags::READ).bits() != 0 {
        out |= rpc_fs::DescriptorFlags::READ;
    }
    if (flags & raw_fs::DescriptorFlags::WRITE).bits() != 0 {
        out |= rpc_fs::DescriptorFlags::WRITE;
    }
    if (flags & raw_fs::DescriptorFlags::FILE_INTEGRITY_SYNC).bits() != 0 {
        out |= rpc_fs::DescriptorFlags::FILE_INTEGRITY_SYNC;
    }
    if (flags & raw_fs::DescriptorFlags::DATA_INTEGRITY_SYNC).bits() != 0 {
        out |= rpc_fs::DescriptorFlags::DATA_INTEGRITY_SYNC;
    }
    if (flags & raw_fs::DescriptorFlags::REQUESTED_WRITE_SYNC).bits() != 0 {
        out |= rpc_fs::DescriptorFlags::REQUESTED_WRITE_SYNC;
    }
    if (flags & raw_fs::DescriptorFlags::MUTATE_DIRECTORY).bits() != 0 {
        out |= rpc_fs::DescriptorFlags::MUTATE_DIRECTORY;
    }
    out
}

fn map_desc_type_out(ty: raw_fs::DescriptorType) -> rpc_fs::DescriptorType {
    match ty {
        raw_fs::DescriptorType::BlockDevice => rpc_fs::DescriptorType::BlockDevice,
        raw_fs::DescriptorType::CharacterDevice => rpc_fs::DescriptorType::CharacterDevice,
        raw_fs::DescriptorType::Directory => rpc_fs::DescriptorType::Directory,
        raw_fs::DescriptorType::Fifo => rpc_fs::DescriptorType::Fifo,
        raw_fs::DescriptorType::SymbolicLink => rpc_fs::DescriptorType::SymbolicLink,
        raw_fs::DescriptorType::RegularFile => rpc_fs::DescriptorType::RegularFile,
        raw_fs::DescriptorType::Socket => rpc_fs::DescriptorType::Socket,
        raw_fs::DescriptorType::Other(s) => rpc_fs::DescriptorType::Other(s),
    }
}

fn map_instant_in(i: rpc_clock::Instant) -> raw_clock::Instant {
    raw_clock::Instant {
        seconds: i.seconds,
        nanoseconds: i.nanoseconds,
    }
}

fn map_instant_out(i: raw_clock::Instant) -> rpc_clock::Instant {
    rpc_clock::Instant {
        seconds: i.seconds,
        nanoseconds: i.nanoseconds,
    }
}

fn map_new_timestamp_in(ts: rpc_fs::NewTimestamp) -> raw_fs::NewTimestamp {
    match ts {
        rpc_fs::NewTimestamp::NoChange => raw_fs::NewTimestamp::NoChange,
        rpc_fs::NewTimestamp::Now => raw_fs::NewTimestamp::Now,
        rpc_fs::NewTimestamp::Timestamp(i) => raw_fs::NewTimestamp::Timestamp(map_instant_in(i)),
    }
}

fn map_desc_stat_out(s: raw_fs::DescriptorStat) -> rpc_fs::DescriptorStat {
    rpc_fs::DescriptorStat {
        r#type: map_desc_type_out(s.type_),
        link_count: s.link_count,
        size: s.size,
        data_access_timestamp: s.data_access_timestamp.map(map_instant_out),
        data_modification_timestamp: s.data_modification_timestamp.map(map_instant_out),
        status_change_timestamp: s.status_change_timestamp.map(map_instant_out),
    }
}

fn map_fs_error(err: raw_fs::ErrorCode) -> rpc_fs::ErrorCode {
    use raw_fs::ErrorCode as Raw;
    use rpc_fs::ErrorCode as Rpc;
    match err {
        Raw::Access => Rpc::Access,
        Raw::Already => Rpc::Already,
        Raw::BadDescriptor => Rpc::BadDescriptor,
        Raw::Busy => Rpc::Busy,
        Raw::Deadlock => Rpc::Deadlock,
        Raw::Quota => Rpc::Quota,
        Raw::Exist => Rpc::Exist,
        Raw::FileTooLarge => Rpc::FileTooLarge,
        Raw::IllegalByteSequence => Rpc::IllegalByteSequence,
        Raw::InProgress => Rpc::InProgress,
        Raw::Interrupted => Rpc::Interrupted,
        Raw::Invalid => Rpc::Invalid,
        Raw::Io => Rpc::Io,
        Raw::IsDirectory => Rpc::IsDirectory,
        Raw::Loop => Rpc::Loop,
        Raw::TooManyLinks => Rpc::TooManyLinks,
        Raw::MessageSize => Rpc::MessageSize,
        Raw::NameTooLong => Rpc::NameTooLong,
        Raw::NoDevice => Rpc::NoDevice,
        Raw::NoEntry => Rpc::NoEntry,
        Raw::NoLock => Rpc::NoLock,
        Raw::InsufficientMemory => Rpc::InsufficientMemory,
        Raw::InsufficientSpace => Rpc::InsufficientSpace,
        Raw::NotDirectory => Rpc::NotDirectory,
        Raw::NotEmpty => Rpc::NotEmpty,
        Raw::NotRecoverable => Rpc::NotRecoverable,
        Raw::Unsupported => Rpc::Unsupported,
        Raw::NoTty => Rpc::NoTty,
        Raw::NoSuchDevice => Rpc::NoSuchDevice,
        Raw::Overflow => Rpc::Overflow,
        Raw::NotPermitted => Rpc::NotPermitted,
        Raw::Pipe => Rpc::Pipe,
        Raw::ReadOnly => Rpc::ReadOnly,
        Raw::InvalidSeek => Rpc::InvalidSeek,
        Raw::TextFileBusy => Rpc::TextFileBusy,
        Raw::CrossDevice => Rpc::CrossDevice,
        Raw::Other(s) => Rpc::Other(s),
    }
}
