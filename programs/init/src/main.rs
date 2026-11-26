//! Root `component-manager` (`SystemComponent`) booted by the Helios kernel.
//!
//! Supervises the compile-time generated static component topology over
//! `helios:system/root-supervisor`, `helios:system/programs`,
//! `helios:system/mounts`, `helios:system/ipc`, `helios:system/net`,
//! `helios:system/vsock`, and publishes live component state under
//! `/components/*` via lock-free `helios:system/inspect`.
//!
//! By default this binary contains **zero** TOML parser code: all component
//! manifests are validated and compiled into static native Rust tables on the
//! host by `helios-cli`. Enabling `--features dynamic-components` opts into
//! bounded runtime dynamic subtree mounting.

#[cfg(feature = "dynamic-components")]
mod component_control;

mod generated_topology {
    #![expect(
        unused_imports,
        reason = "generated static topology imports the full model vocabulary for arbitrary manifests"
    )]
    include!(concat!(env!("OUT_DIR"), "/generated_topology.rs"));
}

use std::cell::RefCell;
use std::fs;
use std::io::{self, Write};
use std::path::Path;
use std::rc::Rc;
use std::time::Duration;

use async_channel::Receiver;
use helios_api::inspect::InspectPublisher;
use helios_api::ipc::{self, Endpoint};
use helios_api::linux::{Container, ContainerBuilder};
use helios_api::mounts::{self, MountRequest, MountSharing, MountSource};
use helios_api::net::{IpAddress, TcpListener};
use helios_api::oci::{ImageReference, open_image_store};
use helios_api::programs::{
    self, AuthorityScope, CapabilityGrant, Child, ChildTermination, ClockRight, ContainerMount,
    ContainerMountSharing, DeviceClass, FilesystemRight, InheritedSocket, LinkRight, MachineRight,
    MountRight, NetworkRight, NonFsGrant, NonFsGrants, ProcessRight, SettingsRight, TerminalRight,
};
use helios_api::root_supervisor::{
    self, DeviceGrantInfo, EscalationAction as ApiEscalationAction, FatalReport, HardwareInventory,
    ManagedSpawnRequest, OomPolicy, ProviderExit, ProviderHandle, ProviderRequest,
};
use helios_api::task;
use helios_api::vsock::VsockListener;
use helios_component_manager::{
    AuthorityScopeSpec, BoundSocket, CapabilityCeiling, ChildProcess, ClockRights, ComponentNode,
    ComponentStateRecord, ContainerMountSharingSpec, DEFAULT_OCI_STORE_PATH, DeviceClasses,
    EscalationAction, ExitOutcome, FatalEscalation, FsRights, HardwareInventorySnapshot,
    IpAddrSpec, IpcChannelEnd, LifecycleKind, LinkRights, MachineRights, MountRights,
    MountSharingSpec, MountSourceSpec, MountSpec, NameCeiling, NetRights, OciRunnerSpec, OomTier,
    ProcessRights, ProviderEndpoint, ProviderOutcome, ProviderSlot, RunnerSpec, RuntimeError,
    SpawnComponentArgs, Supervisor, SupervisorRuntime, TcpSocketListener, TerminalRights,
    VmRunnerSpec, VsockSocketListener, directory_covered_by, normalize_abs_path, path_is_prefix,
};

const VMM_BINARY_PATH: &str = "/bin/vmm";
const INSPECT_BUFFER_BYTES: u64 = 64 * 1024;
/// Infinite wait slice for non-consuming listener `wait_readable` (matches `vsock::NO_DEADLINE`).
const LISTENER_WAIT_SLICE: Duration = Duration::from_secs(3_600);

fn list_dir(directory: &Path) -> io::Result<()> {
    let mut entries = fs::read_dir(directory)?.collect::<io::Result<Vec<_>>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let file_type = entry.file_type()?;
        let kind = if file_type.is_dir() {
            "dir"
        } else if file_type.is_file() {
            "file"
        } else {
            "other"
        };
        println!("{kind} {}", entry.file_name().to_string_lossy());
    }
    Ok(())
}

fn forward_child_stream(
    mut stream: helios_api::wit_bindgen::StreamReader<u8>,
    future: helios_api::wit_bindgen::FutureReader<Result<(), ()>>,
    to_stderr: bool,
) -> Receiver<()> {
    let (done_tx, done_rx) = async_channel::bounded(1);
    task::spawn(async move {
        const CHUNK: usize = 8 * 1024;
        loop {
            let buf = Vec::with_capacity(CHUNK);
            let (result, chunk) = stream.read(buf).await;
            if !chunk.is_empty() {
                if to_stderr {
                    let _ = io::stderr().write_all(&chunk);
                    let _ = io::stderr().flush();
                } else {
                    let _ = io::stdout().write_all(&chunk);
                    let _ = io::stdout().flush();
                }
            }
            if helios_api::stream_closed(result) {
                break;
            }
        }
        let _ = std::future::IntoFuture::into_future(future).await;
        let _ = done_tx.send(()).await;
    });
    done_rx
}

fn attach_child_stdio(child: &Child) -> Vec<Receiver<()>> {
    let (out_stream, out_future) = child.stdout();
    let (err_stream, err_future) = child.stderr();
    vec![
        forward_child_stream(out_stream, out_future, false),
        forward_child_stream(err_stream, err_future, true),
    ]
}

/// Wrapper keeping an optional OCI `Container` and stdio forwarder completion
/// signals alive beside a running `Child`.
struct HeliosChild {
    child: Child,
    _container: Option<Container>,
    stream_drains: Vec<Receiver<()>>,
}

impl ChildProcess for HeliosChild {
    fn instance_id(&self) -> Option<u64> {
        Some(self.child.instance_id())
    }

    fn signal(&self, signal: u8) -> Result<(), RuntimeError> {
        self.child
            .signal(signal)
            .map_err(|error| RuntimeError::Other {
                detail: format!("{:?}: {}", error.kind, error.detail),
            })
    }

    async fn wait(&self) -> Result<ExitOutcome, RuntimeError> {
        let status = self
            .child
            .wait_exit()
            .await
            .map_err(|error| RuntimeError::Other {
                detail: format!("{:?}: {}", error.kind, error.detail),
            })?;
        for drain in &self.stream_drains {
            let _ = drain.recv().await;
        }
        Ok(match status.termination {
            ChildTermination::Exited(code) => ExitOutcome::Exited(code),
            ChildTermination::Signaled(sig) => ExitOutcome::Signaled(sig.signal),
            ChildTermination::Trapped => ExitOutcome::Trapped,
            ChildTermination::Killed => ExitOutcome::Killed,
        })
    }
}

struct HeliosProvider {
    slot: ProviderSlot,
    handle: ProviderHandle,
}

impl ProviderEndpoint for HeliosProvider {
    fn instance_id(&self) -> Option<u64> {
        self.handle.instance_id()
    }

    async fn wait_exit(&self) -> ProviderOutcome {
        match self.handle.wait_exit().await {
            ProviderExit::Exited => {
                if self.slot == ProviderSlot::Surface {
                    println!("the compositor died; rebuilding it");
                    let _ = io::stdout().flush();
                }
                ProviderOutcome::Exited
            }
            ProviderExit::Replaced => ProviderOutcome::Replaced,
            ProviderExit::Stopped => ProviderOutcome::Stopped,
            ProviderExit::Faulted(msg) => {
                if self.slot == ProviderSlot::Surface {
                    println!("the compositor died; rebuilding it");
                    let _ = io::stdout().flush();
                }
                ProviderOutcome::Faulted(msg)
            }
        }
    }

    fn stop(&self) {
        self.handle.stop();
    }
}

struct HeliosIpcEnd(Endpoint);

impl IpcChannelEnd for HeliosIpcEnd {
    async fn read(&self, max_bytes: u32) -> Result<Option<Vec<u8>>, RuntimeError> {
        self.0
            .read(max_bytes)
            .await
            .map_err(|error| RuntimeError::Other {
                detail: format!("ipc read failed: {error:?}"),
            })
    }

    async fn write(&self, bytes: Vec<u8>) -> Result<(), RuntimeError> {
        self.0
            .write(bytes)
            .await
            .map_err(|error| RuntimeError::Other {
                detail: format!("ipc write failed: {error:?}"),
            })
    }

    fn close_write(&self) {
        self.0.close_write();
    }
}

struct HeliosTcpListener(TcpListener);

impl TcpSocketListener for HeliosTcpListener {
    async fn wait_readable(&self) -> Result<bool, RuntimeError> {
        self.0
            .wait_readable(LISTENER_WAIT_SLICE)
            .await
            .map_err(|error| RuntimeError::Other {
                detail: format!("tcp wait_readable failed: {error}"),
            })
    }
}

struct HeliosVsockListener(VsockListener);

impl VsockSocketListener for HeliosVsockListener {
    async fn wait_readable(&self) -> Result<bool, RuntimeError> {
        self.0
            .wait_readable(LISTENER_WAIT_SLICE)
            .await
            .map_err(|error| RuntimeError::Other {
                detail: format!("vsock wait_readable failed: {error}"),
            })
    }
}

/// Concrete [`SupervisorRuntime`] backed by Helios WASI/WIT root-supervisor bindings.
#[derive(Clone)]
struct HeliosRuntime {
    inspect: Rc<RefCell<Option<InspectPublisher>>>,
    start_instant: std::time::Instant,
    vsock_available: bool,
    #[cfg(feature = "dynamic-components")]
    control_tx: async_channel::Sender<component_control::ControlCommand>,
}

impl HeliosRuntime {
    #[cfg(not(feature = "dynamic-components"))]
    fn new(vsock_available: bool) -> Self {
        let publisher = match InspectPublisher::create("components", INSPECT_BUFFER_BYTES) {
            Ok(publisher) => Some(publisher),
            Err(error) => {
                eprintln!(
                    "helios component-manager: failed to publish /components inspect: {error}"
                );
                None
            }
        };
        Self {
            inspect: Rc::new(RefCell::new(publisher)),
            start_instant: std::time::Instant::now(),
            vsock_available,
        }
    }

    #[cfg(feature = "dynamic-components")]
    fn new(
        vsock_available: bool,
        control_tx: async_channel::Sender<component_control::ControlCommand>,
    ) -> Self {
        let publisher = match InspectPublisher::create("components", INSPECT_BUFFER_BYTES) {
            Ok(publisher) => Some(publisher),
            Err(error) => {
                eprintln!(
                    "helios component-manager: failed to publish /components inspect: {error}"
                );
                None
            }
        };
        Self {
            inspect: Rc::new(RefCell::new(publisher)),
            start_instant: std::time::Instant::now(),
            vsock_available,
            control_tx,
        }
    }
}

impl SupervisorRuntime for HeliosRuntime {
    type Child = HeliosChild;
    type Provider = HeliosProvider;
    type IpcEnd = HeliosIpcEnd;
    type TcpListener = HeliosTcpListener;
    type VsockListener = HeliosVsockListener;

    fn now_ms(&self) -> u64 {
        u64::try_from(self.start_instant.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    async fn sleep(&self, duration: Duration) {
        task::sleep(duration).await;
    }

    fn spawn_task<F: std::future::Future<Output = ()> + 'static>(&self, future: F) {
        task::spawn(future);
    }

    fn path_exists(&self, path: &str) -> bool {
        Path::new(path).exists()
    }

    fn hardware_inventory(&self) -> Result<HardwareInventorySnapshot, RuntimeError> {
        let inv = root_supervisor::hardware_inventory().map_err(|error| RuntimeError::Other {
            detail: format!("reading hardware inventory: {error}"),
        })?;
        Ok(map_hardware_inventory(&inv))
    }

    fn subscribe_hardware(&self) -> Option<Receiver<HardwareInventorySnapshot>> {
        let mut stream = root_supervisor::subscribe_hardware().ok()?;
        let (tx, rx) = async_channel::bounded(8);
        task::spawn(async move {
            loop {
                let (result, items) = stream.read(Vec::with_capacity(4)).await;
                for inv in items {
                    if tx.send(map_hardware_inventory(&inv)).await.is_err() {
                        return;
                    }
                }
                if helios_api::stream_closed(result) {
                    break;
                }
            }
        });
        Some(rx)
    }

    async fn mount(&self, spec: &MountSpec) -> Result<(), RuntimeError> {
        let (source, label) = match &spec.source {
            MountSourceSpec::Memory => (MountSource::Memory, "memory".to_owned()),
            MountSourceSpec::BootImage => (MountSource::BootImage, "boot-image".to_owned()),
            MountSourceSpec::HostShare => (MountSource::HostShare, "host-share".to_owned()),
            MountSourceSpec::Disk(s) => (MountSource::Disk(s.to_string()), format!("disk:{s}")),
            MountSourceSpec::Btrfs(s) => (MountSource::Btrfs(s.to_string()), format!("btrfs:{s}")),
        };
        let sharing = match spec.sharing {
            MountSharingSpec::Private => MountSharing::Private,
            MountSharingSpec::Shared => MountSharing::Shared,
        };
        mounts::mount(MountRequest {
            source,
            path: spec.path.to_string(),
            read_only: spec.read_only,
            sharing,
            compress: spec.compress.as_deref().map(str::to_owned),
            commit: spec.commit,
            max_inline: spec.max_inline,
        })
        .await
        .map_err(|error| RuntimeError::Other {
            detail: format!(
                "mounting {label} at {}: {:?}: {}",
                spec.path, error.kind, error.detail
            ),
        })?;
        println!("helios init: mounted {label} at {}", spec.path);
        println!("helios init: listing {}", spec.path);
        list_dir(Path::new(spec.path.as_ref())).map_err(|error| RuntimeError::Other {
            detail: format!("listing {}: {error}", spec.path),
        })?;
        let _ = io::stdout().flush();
        Ok(())
    }

    fn ipc_channel(&self) -> (Self::IpcEnd, Self::IpcEnd) {
        let (a, b) = ipc::channel();
        (HeliosIpcEnd(a), HeliosIpcEnd(b))
    }

    async fn bind_tcp(
        &self,
        address: IpAddrSpec,
        port: u16,
        backlog: u16,
    ) -> Result<Self::TcpListener, RuntimeError> {
        let ip = match address {
            IpAddrSpec::V4([a, b, c, d]) => IpAddress::Ipv4((a, b, c, d)),
            IpAddrSpec::V6([a, b, c, d, e, f, g, h]) => IpAddress::Ipv6((a, b, c, d, e, f, g, h)),
        };
        let listener = TcpListener::listen(ip, port, backlog)
            .await
            .map_err(|error| RuntimeError::Other {
                detail: format!("tcp_listen {address}:{port}: {error}"),
            })?;
        Ok(HeliosTcpListener(listener))
    }

    async fn bind_vsock(
        &self,
        port: u32,
        backlog: u32,
    ) -> Result<Self::VsockListener, RuntimeError> {
        let listener =
            VsockListener::bind(port, backlog)
                .await
                .map_err(|error| RuntimeError::Other {
                    detail: format!("vsock_listen :{port}: {error}"),
                })?;
        Ok(HeliosVsockListener(listener))
    }

    async fn install_provider(
        &self,
        slot: ProviderSlot,
        node: &ComponentNode,
    ) -> Result<Self::Provider, RuntimeError> {
        let RunnerSpec::Wasm(wasm) = &node.runner else {
            return Err(RuntimeError::Other {
                detail: format!("provider `{}` must use wasm runner", node.moniker),
            });
        };
        let (capability_grants, named_devices) = if slot == ProviderSlot::Compiler {
            (Vec::new(), Vec::new())
        } else {
            (
                build_capability_grants(&node.capabilities),
                extract_named_devices(&node.capabilities.named_devices)?,
            )
        };
        let request = ProviderRequest {
            name: node.instance_name.to_string(),
            path: wasm.program.to_string(),
            capability_grants,
            named_devices,
            oom_policy: map_oom_policy(node.oom_tier),
        };
        let handle = match slot {
            ProviderSlot::Compiler => root_supervisor::install_compiler_provider(request).await,
            ProviderSlot::HttpClient => root_supervisor::install_http_provider(request).await,
            ProviderSlot::Surface => root_supervisor::install_surface_provider(request).await,
        }
        .map_err(|error| RuntimeError::Other {
            detail: format!("installing {} provider: {error}", slot.as_str()),
        })?;
        Ok(HeliosProvider { slot, handle })
    }

    async fn spawn_component(
        &self,
        args: SpawnComponentArgs<Self::TcpListener, Self::VsockListener, Self::IpcEnd>,
    ) -> Result<Self::Child, RuntimeError> {
        let sockets: Vec<InheritedSocket> = args
            .sockets
            .into_iter()
            .map(|socket| match socket {
                BoundSocket::Tcp(HeliosTcpListener(tcp)) => InheritedSocket::Tcp(tcp.into_raw()),
                BoundSocket::Vsock(HeliosVsockListener(vsock)) => {
                    InheritedSocket::Vsock(vsock.into_raw())
                }
            })
            .collect();

        match &args.node.runner {
            RunnerSpec::Wasm(wasm) => {
                let mut grants = build_capability_grants(&args.node.capabilities);
                for (name, HeliosIpcEnd(endpoint)) in args.ipc_channels {
                    grants.push(programs::ipc_grant(name, endpoint));
                }
                #[cfg(feature = "dynamic-components")]
                if args.node.moniker.as_ref() == "/inspector" {
                    let (srv_ep, cli_ep) = ipc::channel();
                    component_control::spawn_control_endpoint(srv_ep, self.control_tx.clone());
                    grants.push(programs::ipc_grant("component-control", cli_ep));
                }
                let child = root_supervisor::spawn(ManagedSpawnRequest {
                    name: args.node.instance_name.to_string(),
                    args: wasm.args.iter().map(|s| s.to_string()).collect(),
                    env: wasm
                        .env
                        .iter()
                        .map(|e| (e.key.to_string(), e.value.to_string()))
                        .collect(),
                    path: wasm.program.to_string(),
                    cwd: wasm.cwd.as_deref().map(str::to_owned),
                    sockets,
                    capability_grants: grants,
                    named_devices: extract_named_devices(&args.node.capabilities.named_devices)?,
                    oom_policy: map_oom_policy(args.node.oom_tier),
                })
                .await
                .map_err(|error| RuntimeError::Other {
                    detail: format!("spawning `{}`: {error}", args.node.moniker),
                })?;
                let stream_drains = if args.node.lifecycle == LifecycleKind::Oneshot
                    || (args.node.instance_name.as_ref() == "inspector-host"
                        && self.vsock_available)
                {
                    attach_child_stdio(&child)
                } else {
                    Vec::new()
                };
                Ok(HeliosChild {
                    child,
                    _container: None,
                    stream_drains,
                })
            }
            RunnerSpec::Exec(exec) => {
                let mut grants = build_capability_grants(&args.node.capabilities);
                for (name, HeliosIpcEnd(endpoint)) in args.ipc_channels {
                    grants.push(programs::ipc_grant(name, endpoint));
                }
                let child = root_supervisor::spawn(ManagedSpawnRequest {
                    name: args.node.instance_name.to_string(),
                    args: exec.args.iter().map(|s| s.to_string()).collect(),
                    env: exec
                        .env
                        .iter()
                        .map(|e| (e.key.to_string(), e.value.to_string()))
                        .collect(),
                    path: exec.program.to_string(),
                    cwd: exec.cwd.as_deref().map(str::to_owned),
                    sockets,
                    capability_grants: grants,
                    named_devices: extract_named_devices(&args.node.capabilities.named_devices)?,
                    oom_policy: map_oom_policy(args.node.oom_tier),
                })
                .await
                .map_err(|error| RuntimeError::Other {
                    detail: format!("spawning exec `{}`: {error}", args.node.moniker),
                })?;
                let stream_drains = if args.node.lifecycle == LifecycleKind::Oneshot {
                    attach_child_stdio(&child)
                } else {
                    Vec::new()
                };
                Ok(HeliosChild {
                    child,
                    _container: None,
                    stream_drains,
                })
            }
            RunnerSpec::Oci(oci) => {
                spawn_oci_component(&args.node, oci, sockets, args.ipc_channels).await
            }
            RunnerSpec::Vm(vm) => {
                spawn_vm_component(&args.node, vm, sockets, args.ipc_channels).await
            }
            RunnerSpec::Realm => Err(RuntimeError::Other {
                detail: format!("cannot spawn pure realm `{}`", args.node.moniker),
            }),
        }
    }

    fn publish_inspect(&self, records: &[ComponentStateRecord]) {
        if let Some(publisher) = self.inspect.borrow_mut().as_mut() {
            let _ = publisher.update(|writer| {
                for rec in records {
                    let p = &rec.inspect_prefix;
                    writer
                        .text(&format!("{p}/state"), rec.status.as_str())
                        .u64(&format!("{p}/restarts"), rec.restarts)
                        .u64(&format!("{p}/instance_id"), rec.instance_id.unwrap_or(0))
                        .text(&format!("{p}/runner"), rec.runner)
                        .text(&format!("{p}/oom_tier"), rec.oom_tier);
                }
            });
        }
    }

    async fn signal_ready(&self) -> Result<(), RuntimeError> {
        root_supervisor::signal_ready()
            .await
            .map_err(|error| RuntimeError::Other {
                detail: format!("signaling root readiness: {error}"),
            })
    }

    async fn escalate_fatal(&self, report: FatalEscalation) -> Result<(), RuntimeError> {
        let action = match report.action {
            EscalationAction::Halt => ApiEscalationAction::Halt,
            EscalationAction::Reboot => ApiEscalationAction::Reboot,
        };
        root_supervisor::escalate_fatal(FatalReport {
            component: report.component,
            instance_id: report.instance_id,
            reason: report.reason,
            restart_count: report.restart_count,
            action,
        })
        .await
        .map_err(|error| RuntimeError::Other {
            detail: format!("fatal escalation failed: {error}"),
        })
    }
}

fn validate_oci_runtime_authority(
    node: &ComponentNode,
    oci: &OciRunnerSpec,
) -> Result<Option<String>, RuntimeError> {
    if node.oom_tier != OomTier::User {
        return Err(RuntimeError::PermissionDenied {
            detail: format!(
                "oci component `{}` requested unsupported oom_tier `{}` (only `user` is supported)",
                node.moniker,
                node.oom_tier.as_str()
            ),
        });
    }
    if !node.capabilities.named_devices.is_empty() {
        return Err(RuntimeError::PermissionDenied {
            detail: format!(
                "oci component `{}` cannot receive raw `named_devices` grants",
                node.moniker
            ),
        });
    }
    let store_root = if oci.image.is_some() {
        let raw_store = oci.store.as_deref().unwrap_or(DEFAULT_OCI_STORE_PATH);
        let normalized_store =
            normalize_abs_path(raw_store).map_err(|reason| RuntimeError::PermissionDenied {
                detail: format!(
                    "oci component `{}` has invalid store path `{raw_store}`: {reason}",
                    node.moniker
                ),
            })?;
        if !directory_covered_by(
            node.capabilities.directories.as_ref(),
            &normalized_store,
            FsRights::READ,
        ) {
            return Err(RuntimeError::PermissionDenied {
                detail: format!(
                    "oci component `{}` lacks read authority for store `{normalized_store}`",
                    node.moniker
                ),
            });
        }
        Some(normalized_store)
    } else if let Some(raw_store) = &oci.store {
        let normalized_store = normalize_abs_path(raw_store.as_ref()).map_err(|reason| {
            RuntimeError::PermissionDenied {
                detail: format!(
                    "oci component `{}` has invalid store path `{raw_store}`: {reason}",
                    node.moniker
                ),
            }
        })?;
        if !directory_covered_by(
            node.capabilities.directories.as_ref(),
            &normalized_store,
            FsRights::READ,
        ) {
            return Err(RuntimeError::PermissionDenied {
                detail: format!(
                    "oci component `{}` lacks read authority for store `{normalized_store}`",
                    node.moniker
                ),
            });
        }
        Some(normalized_store)
    } else {
        None
    };

    if let Some(rootfs) = &oci.rootfs {
        let normalized_rootfs = normalize_abs_path(rootfs.as_ref()).map_err(|reason| {
            RuntimeError::PermissionDenied {
                detail: format!(
                    "oci component `{}` has invalid rootfs path `{rootfs}`: {reason}",
                    node.moniker
                ),
            }
        })?;
        if !directory_covered_by(
            node.capabilities.directories.as_ref(),
            &normalized_rootfs,
            FsRights::READ.union(FsRights::EXECUTE),
        ) {
            return Err(RuntimeError::PermissionDenied {
                detail: format!(
                    "oci component `{}` lacks read+execute authority for rootfs `{normalized_rootfs}`",
                    node.moniker
                ),
            });
        }
    }

    for mount in oci.mounts.iter() {
        let normalized_source = normalize_abs_path(mount.source.as_ref()).map_err(|reason| {
            RuntimeError::PermissionDenied {
                detail: format!(
                    "oci component `{}` has invalid mount source `{}`: {reason}",
                    node.moniker, mount.source
                ),
            }
        })?;
        normalize_abs_path(mount.target.as_ref()).map_err(|reason| {
            RuntimeError::PermissionDenied {
                detail: format!(
                    "oci component `{}` has invalid mount target `{}`: {reason}",
                    node.moniker, mount.target
                ),
            }
        })?;
        if !directory_covered_by(
            node.capabilities.directories.as_ref(),
            &normalized_source,
            mount.rights,
        ) {
            return Err(RuntimeError::PermissionDenied {
                detail: format!(
                    "oci component `{}` mount source `{normalized_source}` exceeds directory ceiling",
                    node.moniker
                ),
            });
        }
    }

    Ok(store_root)
}

fn validate_oci_resolved_rootfs(
    moniker: &str,
    store_root: &str,
    rootfs_path: &Path,
) -> Result<String, RuntimeError> {
    let raw = rootfs_path
        .to_str()
        .ok_or_else(|| RuntimeError::PermissionDenied {
            detail: format!("oci component `{moniker}` resolved non-UTF-8 image rootfs path"),
        })?;
    let normalized = normalize_abs_path(raw).map_err(|reason| RuntimeError::PermissionDenied {
        detail: format!(
            "oci component `{moniker}` resolved invalid image rootfs path `{raw}`: {reason}"
        ),
    })?;
    if !path_is_prefix(store_root, &normalized) {
        return Err(RuntimeError::PermissionDenied {
            detail: format!(
                "oci component `{moniker}` resolved image rootfs `{normalized}` escapes store `{store_root}`"
            ),
        });
    }
    Ok(normalized)
}

async fn spawn_oci_component(
    node: &ComponentNode,
    oci: &OciRunnerSpec,
    sockets: Vec<InheritedSocket>,
    ipc_channels: Vec<(String, HeliosIpcEnd)>,
) -> Result<HeliosChild, RuntimeError> {
    let verified_store_root = validate_oci_runtime_authority(node, oci)?;
    let mut builder = if let Some(image_ref) = &oci.image {
        let store_root = verified_store_root
            .as_deref()
            .unwrap_or(DEFAULT_OCI_STORE_PATH);
        let store = open_image_store(store_root).map_err(|error| RuntimeError::Other {
            detail: format!("opening OCI store `{store_root}`: {error}"),
        })?;
        let parsed_ref =
            ImageReference::parse(image_ref.as_ref()).map_err(|error| RuntimeError::Other {
                detail: format!("parsing OCI image `{image_ref}`: {error}"),
            })?;
        let pulled = store
            .get_image(&parsed_ref)
            .map_err(|error| RuntimeError::Other {
                detail: format!("reading OCI image `{image_ref}`: {error}"),
            })?
            .ok_or_else(|| RuntimeError::NotFound {
                detail: format!("OCI image `{image_ref}` not present in `{store_root}`"),
            })?;
        validate_oci_resolved_rootfs(node.moniker.as_ref(), store_root, pulled.rootfs_path())?;
        ContainerBuilder::from_image(&pulled).map_err(|error| RuntimeError::Other {
            detail: format!("configuring container from OCI image `{image_ref}`: {error}"),
        })?
    } else if let Some(rootfs) = &oci.rootfs {
        Container::ephemeral(rootfs.as_ref())
            .user(oci.uid, oci.gid)
            .shared_owner(oci.uid, oci.gid)
    } else {
        return Err(RuntimeError::Other {
            detail: format!(
                "oci component `{}` requires `image` or `rootfs`",
                node.moniker
            ),
        });
    };

    builder = builder.hostname(oci.hostname.as_ref());
    if !oci.entrypoint.is_empty() {
        builder = builder.entrypoint(oci.entrypoint.iter().map(|s| s.as_ref()));
    }
    if !oci.cmd.is_empty() {
        builder = builder.default_cmd(oci.cmd.iter().map(|s| s.as_ref()));
    }
    if let Some(cwd) = &oci.cwd {
        builder = builder.working_dir(cwd.as_ref());
    }
    for e in oci.env.iter() {
        builder = builder.env(e.key.as_ref(), e.value.as_ref());
    }
    for m in oci.mounts.iter() {
        builder = builder.mount(ContainerMount {
            source_path: m.source.to_string(),
            target_path: m.target.to_string(),
            rights: map_fs_rights(m.rights),
            sharing: match m.sharing {
                ContainerMountSharingSpec::Private => ContainerMountSharing::Private,
                ContainerMountSharingSpec::Shared => ContainerMountSharing::Shared,
                ContainerMountSharingSpec::EphemeralOverlay => {
                    ContainerMountSharing::EphemeralOverlay
                }
            },
        });
    }

    let mut non_fs = build_non_fs_grants(&node.capabilities);
    for (name, HeliosIpcEnd(endpoint)) in ipc_channels {
        non_fs = non_fs.ipc(name, endpoint);
    }
    builder = builder.grants(non_fs);

    let container = builder
        .create()
        .await
        .map_err(|error| RuntimeError::Other {
            detail: format!(
                "creating OCI container for `{}`: {:?}",
                node.moniker, error.kind
            ),
        })?;
    let mut cmd = container
        .default_command(None)
        .map_err(|error| RuntimeError::Other {
            detail: format!("resolving OCI command for `{}`: {error}", node.moniker),
        })?
        .name(node.instance_name.as_ref());
    for socket in sockets {
        cmd = cmd.socket(socket);
    }
    let child = cmd.spawn().await.map_err(|error| RuntimeError::Other {
        detail: format!(
            "spawning OCI container `{}`: {:?}",
            node.moniker, error.kind
        ),
    })?;
    let stream_drains = if node.lifecycle == LifecycleKind::Oneshot {
        attach_child_stdio(&child)
    } else {
        Vec::new()
    };
    Ok(HeliosChild {
        child,
        _container: Some(container),
        stream_drains,
    })
}

async fn spawn_vm_component(
    node: &ComponentNode,
    vm: &VmRunnerSpec,
    sockets: Vec<InheritedSocket>,
    ipc_channels: Vec<(String, HeliosIpcEnd)>,
) -> Result<HeliosChild, RuntimeError> {
    let mut vm_args = vec![
        "--kernel".to_owned(),
        vm.kernel.to_string(),
        "--memory-mib".to_owned(),
        vm.memory_mib.to_string(),
        "--cpus".to_owned(),
        vm.cpus.to_string(),
    ];
    if let Some(initramfs) = &vm.initramfs {
        vm_args.push("--initramfs".to_owned());
        vm_args.push(initramfs.to_string());
    }
    if let Some(disk) = &vm.disk {
        vm_args.push("--disk".to_owned());
        vm_args.push(disk.to_string());
    }
    if let Some(cmdline) = &vm.cmdline {
        vm_args.push("--cmdline".to_owned());
        vm_args.push(cmdline.to_string());
    }
    if let Some(rootfs) = &vm.rootfs_dir {
        vm_args.push("--rootfs-dir".to_owned());
        vm_args.push(rootfs.to_string());
    }
    for share in vm.share_dirs.iter() {
        vm_args.push("--share-dir".to_owned());
        vm_args.push(format!("{}:{}", share.tag, share.host_path));
    }

    let mut grants = build_capability_grants(&node.capabilities);
    for (name, HeliosIpcEnd(endpoint)) in ipc_channels {
        grants.push(programs::ipc_grant(name, endpoint));
    }
    let child = root_supervisor::spawn(ManagedSpawnRequest {
        name: node.instance_name.to_string(),
        args: vm_args,
        env: Vec::new(),
        path: VMM_BINARY_PATH.to_owned(),
        cwd: None,
        sockets,
        capability_grants: grants,
        named_devices: extract_named_devices(&node.capabilities.named_devices)?,
        oom_policy: map_oom_policy(node.oom_tier),
    })
    .await
    .map_err(|error| RuntimeError::Other {
        detail: format!("spawning MicroVm `{}`: {error}", node.moniker),
    })?;
    Ok(HeliosChild {
        child,
        _container: None,
        stream_drains: Vec::new(),
    })
}

fn map_hardware_inventory(inv: &HardwareInventory) -> HardwareInventorySnapshot {
    HardwareInventorySnapshot {
        display: inv.display,
        input: inv.input,
        gpu: inv.gpu,
        audio: inv.audio,
        hv: inv.hv,
        native: inv.native,
        vsock: inv.vsock,
    }
}

fn map_oom_policy(tier: OomTier) -> OomPolicy {
    match tier {
        OomTier::User => OomPolicy::UserProgram,
        OomTier::Plugin => OomPolicy::KernelPlugin,
        OomTier::Protected => OomPolicy::SystemComponent,
    }
}

fn map_fs_rights(rights: FsRights) -> Vec<FilesystemRight> {
    let mut out = Vec::new();
    if rights.contains(FsRights::READ) {
        out.push(FilesystemRight::Read);
    }
    if rights.contains(FsRights::WRITE) {
        out.push(FilesystemRight::Write);
    }
    if rights.contains(FsRights::MUTATE_DIRECTORY) {
        out.push(FilesystemRight::MutateDirectory);
    }
    if rights.contains(FsRights::EXECUTE) {
        out.push(FilesystemRight::Execute);
    }
    out
}

fn map_scope(scope: AuthorityScopeSpec) -> Option<AuthorityScope> {
    match scope {
        AuthorityScopeSpec::None => None,
        AuthorityScopeSpec::Own => Some(AuthorityScope::Own),
        AuthorityScopeSpec::Subtree => Some(AuthorityScope::Subtree(None)),
        AuthorityScopeSpec::Machine => Some(AuthorityScope::Machine),
    }
}

fn resolve_named_devices(ceiling: &NameCeiling, discovered: &[DeviceGrantInfo]) -> Vec<String> {
    match ceiling {
        NameCeiling::Any => discovered.iter().map(|d| d.name.clone()).collect(),
        NameCeiling::Set(names) => names.iter().map(|s| s.to_string()).collect(),
    }
}

fn extract_named_devices(ceiling: &NameCeiling) -> Result<Vec<String>, RuntimeError> {
    match ceiling {
        NameCeiling::Any => {
            let inv =
                root_supervisor::hardware_inventory().map_err(|error| RuntimeError::Other {
                    detail: format!("reading hardware inventory for named devices: {error}"),
                })?;
            Ok(resolve_named_devices(ceiling, &inv.devices))
        }
        NameCeiling::Set(_) => Ok(resolve_named_devices(ceiling, &[])),
    }
}

fn build_non_fs_grants(cap: &CapabilityCeiling) -> NonFsGrants {
    let mut grants = NonFsGrants::new();

    if !cap.network.is_empty() {
        let mut net = Vec::new();
        if cap.network.contains(NetRights::TCP) {
            net.push(NetworkRight::Tcp);
        }
        if cap.network.contains(NetRights::UDP) {
            net.push(NetworkRight::Udp);
        }
        if cap.network.contains(NetRights::DNS) {
            net.push(NetworkRight::Dns);
        }
        if cap.network.contains(NetRights::PRIVILEGED_BIND) {
            net.push(NetworkRight::PrivilegedBind);
        }
        if cap.network.contains(NetRights::MULTICAST) {
            net.push(NetworkRight::Multicast);
        }
        if cap.network.contains(NetRights::ADMIN) {
            net.push(NetworkRight::Admin);
        }
        grants = grants.network(net);
    }
    if cap.clock.contains(ClockRights::SET_WALL_CLOCK) {
        grants = grants.clock(vec![ClockRight::SetWallClock]);
    }
    if !cap.terminal.is_empty() {
        let mut term = Vec::new();
        if cap.terminal.contains(TerminalRights::INPUT) {
            term.push(TerminalRight::Input);
        }
        if cap.terminal.contains(TerminalRights::OUTPUT) {
            term.push(TerminalRight::Output);
        }
        if cap.terminal.contains(TerminalRights::CONTROL) {
            term.push(TerminalRight::Control);
        }
        grants = grants.terminal(term);
    }
    if !cap.process.is_empty() {
        let mut proc_r = Vec::new();
        if cap.process.contains(ProcessRights::SPAWN) {
            proc_r.push(ProcessRight::Spawn);
        }
        if cap.process.contains(ProcessRights::EXEC) {
            proc_r.push(ProcessRight::Exec);
        }
        if cap.process.contains(ProcessRights::FORK) {
            proc_r.push(ProcessRight::Fork);
        }
        if cap.process.contains(ProcessRights::JOIN) {
            proc_r.push(ProcessRight::Join);
        }
        if cap.process.contains(ProcessRights::SIGNAL) {
            proc_r.push(ProcessRight::Signal);
        }
        grants = grants.process(proc_r);
    }
    if !cap.link.is_empty() {
        let mut link = Vec::new();
        if cap.link.contains(LinkRights::SOURCE) {
            link.push(LinkRight::Source);
        }
        if cap.link.contains(LinkRights::TARGET_DIRECTORY) {
            link.push(LinkRight::TargetDirectory);
        }
        if cap.link.contains(LinkRights::SYMLINK_CREATE) {
            link.push(LinkRight::SymlinkCreate);
        }
        if cap.link.contains(LinkRights::SYMLINK_READ) {
            link.push(LinkRight::SymlinkRead);
        }
        grants = grants.link(link);
    }
    if !cap.mount.is_empty() {
        let mut mount = Vec::new();
        if cap.mount.contains(MountRights::MOUNT) {
            mount.push(MountRight::Mount);
        }
        if cap.mount.contains(MountRights::UNMOUNT) {
            mount.push(MountRight::Unmount);
        }
        grants = grants.mount(mount);
    }
    if !cap.devices.is_empty() {
        let mut devs = Vec::new();
        if cap.devices.contains(DeviceClasses::DISPLAY) {
            devs.push(DeviceClass::Display);
        }
        if cap.devices.contains(DeviceClasses::INPUT) {
            devs.push(DeviceClass::Input);
        }
        if cap.devices.contains(DeviceClasses::GPU) {
            devs.push(DeviceClass::Gpu);
        }
        if cap.devices.contains(DeviceClasses::AUDIO) {
            devs.push(DeviceClass::Audio);
        }
        grants = grants.device(devs);
    }
    if let Some(scope) = map_scope(cap.inspect_read) {
        grants = grants.inspect_read(scope);
    }
    if let Some(scope) = map_scope(cap.trace_read) {
        grants = grants.trace_read(scope);
    }
    if let Some(scope) = map_scope(cap.profile_read) {
        grants = grants.profile_read(scope);
    }
    if cap.diagnostics_control {
        grants = grants.diagnostics_control();
    }
    if let Some(scope) = map_scope(cap.instance_control) {
        grants = grants.instance_control(scope);
    }
    if cap.settings_write {
        grants = grants.grant(NonFsGrant::Settings(programs::SettingsGrant {
            rights: vec![SettingsRight::Write],
        }));
    }
    if !cap.machine.is_empty() {
        let mut m = Vec::new();
        if cap.machine.contains(MachineRights::CONTROL) {
            m.push(MachineRight::Control);
        }
        if cap.machine.contains(MachineRights::IDENTITY) {
            m.push(MachineRight::Identity);
        }
        if cap.machine.contains(MachineRights::VIRTUALIZE) {
            m.push(MachineRight::Virtualize);
        }
        grants = grants.machine(m);
    }
    grants
}

fn build_capability_grants(cap: &CapabilityCeiling) -> Vec<CapabilityGrant> {
    let mut grants: Vec<CapabilityGrant> = cap
        .directories
        .iter()
        .map(|d| {
            programs::directory_grant(d.source.as_ref(), d.guest.as_ref(), map_fs_rights(d.rights))
        })
        .collect();
    grants.extend(build_non_fs_grants(cap).into_capability_grants());
    grants
}

#[helios_api::main]
async fn main() -> io::Result<()> {
    let root = Path::new("/");
    println!("helios init: online root={}", root.display());

    list_dir(root)?;

    if Path::new("/init.txt").exists() {
        let text = fs::read_to_string("/init.txt")?;
        print!("{text}");
    }

    let _ = io::stdout().flush();
    let _ = io::stderr().flush();

    let inventory = root_supervisor::hardware_inventory()
        .map_err(|error| io::Error::other(format!("reading hardware inventory: {error}")))?;
    #[cfg(feature = "dynamic-components")]
    let (control_tx, control_rx) = component_control::new_control_queue();
    #[cfg(feature = "dynamic-components")]
    let runtime = HeliosRuntime::new(inventory.vsock, control_tx);
    #[cfg(not(feature = "dynamic-components"))]
    let runtime = HeliosRuntime::new(inventory.vsock);
    let mut supervisor = Supervisor::new(runtime, generated_topology::GENERATED_TOPOLOGY)
        .map_err(|error| io::Error::other(format!("initializing component-manager: {error}")))?;

    supervisor
        .boot()
        .await
        .map_err(|error| io::Error::other(format!("booting component topology: {error}")))?;
    #[cfg(feature = "dynamic-components")]
    {
        use futures_lite::future::FutureExt as _;
        enum LoopItem {
            Event(Option<helios_component_manager::PendingEvent<HeliosRuntime>>),
            Control(Result<component_control::ControlCommand, async_channel::RecvError>),
        }
        while supervisor.has_active_work() {
            let item = async { LoopItem::Event(supervisor.recv_event().await) }
                .or(async { LoopItem::Control(control_rx.recv().await) })
                .await;
            match item {
                LoopItem::Event(Some(event)) => {
                    supervisor
                        .handle_pending_event(event)
                        .await
                        .map_err(|error| {
                            io::Error::other(format!("supervising component topology: {error}"))
                        })?;
                }
                LoopItem::Event(None) => break,
                LoopItem::Control(Ok(cmd)) => {
                    component_control::handle_control_command(&mut supervisor, cmd).await;
                }
                LoopItem::Control(Err(_)) => break,
            }
        }
    }
    #[cfg(not(feature = "dynamic-components"))]
    supervisor
        .run_until_done()
        .await
        .map_err(|error| io::Error::other(format!("supervising component topology: {error}")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;
    use std::path::Path;

    use helios_api::root_supervisor::DeviceGrantInfo;
    use helios_component_manager::{
        CapabilityCeiling, ComponentNode, Criticality, DirectoryGrantSpec, EscalationAction,
        FsRights, HardwarePredicates, LifecycleKind, NameCeiling, OciRunnerSpec, OomTier,
        RestartPolicy, RunnerSpec, RuntimeError, StartupPolicy,
    };

    use super::{
        generated_topology, resolve_named_devices, validate_oci_resolved_rootfs,
        validate_oci_runtime_authority,
    };

    #[test]
    fn default_generated_topology_is_valid_and_contains_core_components() {
        let topology = &generated_topology::GENERATED_TOPOLOGY;
        helios_component_manager::validate_topology(topology)
            .expect("generated static topology must satisfy monotonic capability validation");
        assert!(topology.find_by_moniker("/").is_some());
        assert!(topology.find_by_moniker("/plugins/compiler").is_some());
        assert!(topology.find_by_moniker("/plugins/http-client").is_some());
        assert!(topology.find_by_moniker("/plugins/compositor").is_some());
        assert!(topology.find_by_moniker("/debugger").is_none());
        let inspector = &topology.nodes[topology
            .find_by_moniker("/inspector")
            .expect("/inspector manifest must exist")];
        let tls = &topology.nodes[topology
            .find_by_moniker("/inspector/tls")
            .expect("/inspector/tls manifest must exist")];
        let worker = &topology.nodes[topology
            .find_by_moniker("/inspector/worker")
            .expect("/inspector/worker manifest must exist")];
        assert_eq!(
            tls.capabilities,
            helios_component_manager::CapabilityCeiling::EMPTY
        );
        assert!(
            inspector
                .capabilities
                .machine
                .contains(helios_component_manager::MachineRights::IDENTITY)
        );
        assert!(
            !worker
                .capabilities
                .machine
                .contains(helios_component_manager::MachineRights::IDENTITY)
        );
    }

    #[test]
    fn resolve_named_devices_expands_any_ceiling_and_preserves_explicit_set() {
        let discovered = vec![
            DeviceGrantInfo {
                name: "pci:00:02.0".to_owned(),
                regions: 1,
                interrupt_count: 1,
                dma_budget_bytes: 4096,
                confined: true,
                claimed: false,
            },
            DeviceGrantInfo {
                name: "pci:00:03.0".to_owned(),
                regions: 2,
                interrupt_count: 2,
                dma_budget_bytes: 8192,
                confined: true,
                claimed: false,
            },
        ];
        assert_eq!(
            resolve_named_devices(&NameCeiling::Any, &discovered),
            vec!["pci:00:02.0".to_owned(), "pci:00:03.0".to_owned()]
        );
        assert_eq!(
            resolve_named_devices(
                &NameCeiling::Set(Cow::Borrowed(&[Cow::Borrowed("pci:00:02.0")])),
                &discovered
            ),
            vec!["pci:00:02.0".to_owned()]
        );
    }

    #[test]
    fn oci_runtime_authority_and_resolved_rootfs_enforce_ceilings() {
        let oci = OciRunnerSpec {
            image: Some(Cow::Borrowed("alpine:3.20")),
            rootfs: None,
            store: Some(Cow::Borrowed("/var/lib/oci")),
            hostname: Cow::Borrowed("app"),
            uid: 0,
            gid: 0,
            entrypoint: Cow::Borrowed(&[]),
            cmd: Cow::Borrowed(&[]),
            env: Cow::Borrowed(&[]),
            cwd: None,
            mounts: Cow::Borrowed(&[]),
        };
        let mut node = ComponentNode {
            moniker: Cow::Borrowed("/apps/web"),
            instance_name: Cow::Borrowed("web"),
            parent_index: Some(0),
            children_indices: Cow::Borrowed(&[]),
            runner: RunnerSpec::Oci(oci.clone()),
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
            oom_tier: OomTier::User,
            dynamic_mount: false,
            capabilities: CapabilityCeiling::EMPTY,
            exposes: Cow::Borrowed(&[]),
            routes: Cow::Borrowed(&[]),
            sockets: Cow::Borrowed(&[]),
        };

        // Missing directory read grant for `/var/lib/oci` -> denied.
        assert!(matches!(
            validate_oci_runtime_authority(&node, &oci),
            Err(RuntimeError::PermissionDenied { .. })
        ));

        // Grant read on `/var/lib/oci` -> accepted.
        node.capabilities.directories = Cow::Owned(vec![DirectoryGrantSpec {
            source: Cow::Borrowed("/var/lib/oci"),
            guest: Cow::Borrowed("/var/lib/oci"),
            rights: FsRights::READ,
        }]);
        assert_eq!(
            validate_oci_runtime_authority(&node, &oci).expect("authorized store"),
            Some("/var/lib/oci".to_owned())
        );

        // Elevated oom_tier or named_devices -> denied.
        node.oom_tier = OomTier::Plugin;
        assert!(matches!(
            validate_oci_runtime_authority(&node, &oci),
            Err(RuntimeError::PermissionDenied { .. })
        ));
        node.oom_tier = OomTier::User;
        node.capabilities.named_devices = NameCeiling::Any;
        assert!(matches!(
            validate_oci_runtime_authority(&node, &oci),
            Err(RuntimeError::PermissionDenied { .. })
        ));

        // Resolved rootfs inside store -> accepted; sibling prefix or escape -> denied.
        assert_eq!(
            validate_oci_resolved_rootfs(
                "/apps/web",
                "/var/lib/oci",
                Path::new("/var/lib/oci/images/abc/rootfs")
            )
            .expect("inside store"),
            "/var/lib/oci/images/abc/rootfs"
        );
        assert!(matches!(
            validate_oci_resolved_rootfs(
                "/apps/web",
                "/var/lib/oci",
                Path::new("/var/lib/oci2/evil")
            ),
            Err(RuntimeError::PermissionDenied { .. })
        ));
        assert!(matches!(
            validate_oci_resolved_rootfs(
                "/apps/web",
                "/var/lib/oci",
                Path::new("/var/lib/oci/../etc")
            ),
            Err(RuntimeError::PermissionDenied { .. })
        ));
    }
}
