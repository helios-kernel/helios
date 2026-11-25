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
use std::io::{self, ErrorKind, Write};
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
    ContainerMountSharing, DeviceClass, ExecRequest, FilesystemRight, InheritedSocket, LinkRight,
    MachineRight, MountRight, NetworkRight, NonFsGrant, NonFsGrants, ProcessRight, SettingsRight,
    TerminalRight,
};
use helios_api::root_supervisor::{
    self, EscalationAction as ApiEscalationAction, FatalReport, HardwareInventory,
    ManagedSpawnRequest, OomPolicy, ProviderExit, ProviderHandle, ProviderRequest,
};
use helios_api::task;
use helios_api::vsock::VsockListener;
use helios_component_manager::{
    AuthorityScopeSpec, BoundSocket, CapabilityCeiling, ChildProcess, ClockRights, ComponentNode,
    ComponentStateRecord, ContainerMountSharingSpec, DeviceClasses, EscalationAction, ExitOutcome,
    FatalEscalation, FsRights, HardwareInventorySnapshot, IpAddrSpec, IpcChannelEnd, LinkRights,
    MachineRights, MountRights, MountSharingSpec, MountSourceSpec, MountSpec, NameCeiling,
    NetRights, OciRunnerSpec, OomTier, ProcessRights, ProviderEndpoint, ProviderOutcome,
    ProviderSlot, RunnerSpec, RuntimeError, SpawnComponentArgs, Supervisor, SupervisorRuntime,
    TcpSocketListener, TerminalRights, VmRunnerSpec, VsockSocketListener,
};

const FSTAB: &str = "/etc/fstab";
const RC: &str = "/etc/rc.nu";
const SHELL: &str = "/bin/nu";
const VMM_BINARY_PATH: &str = "/bin/vmm";
const INSPECT_BUFFER_BYTES: u64 = 64 * 1024;
/// Infinite wait slice for non-consuming listener `wait_readable` (matches `vsock::NO_DEADLINE`).
const LISTENER_WAIT_SLICE: Duration = Duration::from_secs(3_600);

/// One line of `/etc/fstab` (kept for existing bootfs filesystem smoke images).
struct FstabMount {
    source: MountSource,
    label: String,
    point: String,
    read_only: bool,
    sharing: MountSharing,
    compress: Option<String>,
    commit: Option<u32>,
    max_inline: Option<u64>,
}

fn number_base_0(value: &str) -> Option<(&str, u32, &str)> {
    let (digits, radix) = if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        (hex, 16)
    } else if value
        .strip_prefix('0')
        .is_some_and(|rest| rest.starts_with(|c: char| c.is_ascii_digit()))
    {
        (&value[1..], 8)
    } else {
        (value, 10)
    };
    let end = digits
        .find(|c: char| !c.is_digit(radix))
        .unwrap_or(digits.len());
    if end == 0 {
        return None;
    }
    Some((&digits[..end], radix, &digits[end..]))
}

fn max_inline_bytes(value: &str) -> Option<u64> {
    let (digits, radix, rest) = number_base_0(value)?;
    let number = u64::from_str_radix(digits, radix).ok()?;
    let shift = match rest {
        "" => 0,
        "k" | "K" => 10,
        "m" | "M" => 20,
        "g" | "G" => 30,
        "t" | "T" => 40,
        "p" | "P" => 50,
        "e" | "E" => 60,
        _ => return None,
    };
    let scaled = number.checked_shl(shift)?;
    (scaled >> shift == number).then_some(scaled)
}

fn commit_seconds(value: &str) -> Option<u32> {
    let value = value.strip_prefix('+').unwrap_or(value);
    match number_base_0(value)? {
        (digits, radix, "") => u32::from_str_radix(digits, radix).ok(),
        _ => None,
    }
}

fn invalid_fstab(line: usize, detail: impl std::fmt::Display) -> io::Error {
    io::Error::new(ErrorKind::InvalidData, format!("{FSTAB}:{line}: {detail}"))
}

fn parse_fstab(text: &str) -> io::Result<Vec<FstabMount>> {
    let mut mounts = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let number = index + 1;
        let line = line.split('#').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        let [label, point, options] = fields.as_slice() else {
            return Err(invalid_fstab(
                number,
                "expected `<source> <mount point> <option>[,<option>]...`",
            ));
        };
        let (label, point, options) = (*label, *point, *options);
        let source = match label {
            "memory" => MountSource::Memory,
            "boot-image" => MountSource::BootImage,
            "host-share" => MountSource::HostShare,
            _ if label.starts_with("btrfs:") => {
                let serial = &label["btrfs:".len()..];
                if serial.is_empty() {
                    return Err(invalid_fstab(number, "empty btrfs disk serial"));
                }
                MountSource::Btrfs(serial.to_owned())
            }
            _ => match label.strip_prefix("disk:") {
                Some(serial) if !serial.is_empty() => MountSource::Disk(serial.to_owned()),
                _ => return Err(invalid_fstab(number, format!("unknown source `{label}`"))),
            },
        };
        let mut read_only = false;
        let mut sharing = None;
        let mut compress = None;
        let mut commit = None;
        let mut max_inline = None;
        for option in options.split(',') {
            match option {
                "ro" => read_only = true,
                "rw" => read_only = false,
                "private" | "shared" => {
                    let chosen = if option == "private" {
                        MountSharing::Private
                    } else {
                        MountSharing::Shared
                    };
                    if sharing.is_some_and(|earlier| earlier != chosen) {
                        return Err(invalid_fstab(
                            number,
                            "a mount is `private` or `shared`, not both",
                        ));
                    }
                    sharing = Some(chosen);
                }
                "compress" => compress = Some("zlib".to_owned()),
                _ => {
                    if let Some(value) = option.strip_prefix("compress=") {
                        compress = Some(value.to_owned());
                    } else if let Some(value) = option.strip_prefix("commit=") {
                        commit = Some(commit_seconds(value).ok_or_else(|| {
                            invalid_fstab(number, format!("`{option}` is not a number of seconds"))
                        })?);
                    } else if let Some(value) = option.strip_prefix("max_inline=") {
                        max_inline = Some(max_inline_bytes(value).ok_or_else(|| {
                            invalid_fstab(number, format!("`{option}` is not a size in bytes"))
                        })?);
                    } else {
                        return Err(invalid_fstab(number, format!("unknown option `{option}`")));
                    }
                }
            }
        }
        let sharing = sharing.ok_or_else(|| {
            invalid_fstab(
                number,
                "the options name neither `private` nor `shared`, which every mount is granted as",
            )
        })?;
        mounts.push(FstabMount {
            source,
            label: label.to_owned(),
            point: point.to_owned(),
            read_only,
            sharing,
            compress,
            commit,
            max_inline,
        });
    }
    Ok(mounts)
}

fn fstab() -> io::Result<Vec<FstabMount>> {
    match fs::read_to_string(FSTAB) {
        Ok(text) => parse_fstab(&text),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(Vec::new()),
        Err(error) => Err(error),
    }
}

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

async fn run_rc() -> io::Result<()> {
    let result = programs::exec(ExecRequest {
        name: "rc".to_owned(),
        args: vec![RC.to_owned()],
        env: vec![("PATH".to_owned(), "/bin".to_owned())],
        path: SHELL.to_owned(),
        cwd: None,
        stdin: Vec::new(),
        hint: None,
        capability_grants: vec![
            programs::root_directory_grant(),
            programs::root_link_grant(),
            programs::root_process_grant(),
        ],
    })
    .await
    .map_err(|error| {
        io::Error::other(format!(
            "running {RC} with {SHELL}: {:?}: {}",
            error.kind, error.detail
        ))
    })?;
    io::stdout().write_all(&result.output.stdout)?;
    io::stderr().write_all(&result.output.stderr)?;
    if result.exit_code != 0 {
        return Err(io::Error::other(format!(
            "{RC} exited with status {}",
            result.exit_code
        )));
    }
    Ok(())
}

fn forward_child_stream(
    mut stream: helios_api::wit_bindgen::StreamReader<u8>,
    future: helios_api::wit_bindgen::FutureReader<Result<(), ()>>,
    to_stderr: bool,
) {
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
    });
}

/// Wrapper keeping an optional OCI `Container` alive beside its running `Child`.
struct HeliosChild {
    child: Child,
    _container: Option<Container>,
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
        let source = match &spec.source {
            MountSourceSpec::Memory => MountSource::Memory,
            MountSourceSpec::BootImage => MountSource::BootImage,
            MountSourceSpec::HostShare => MountSource::HostShare,
            MountSourceSpec::Disk(s) => MountSource::Disk(s.to_string()),
            MountSourceSpec::Btrfs(s) => MountSource::Btrfs(s.to_string()),
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
            detail: format!("mounting {}: {:?}: {}", spec.path, error.kind, error.detail),
        })
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
                extract_named_devices(&node.capabilities.named_devices),
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
                    named_devices: extract_named_devices(&args.node.capabilities.named_devices),
                    oom_policy: map_oom_policy(args.node.oom_tier),
                })
                .await
                .map_err(|error| RuntimeError::Other {
                    detail: format!("spawning `{}`: {error}", args.node.moniker),
                })?;
                if args.node.instance_name.as_ref() == "inspector-host" && self.vsock_available {
                    let (out_stream, out_future) = child.stdout();
                    let (err_stream, err_future) = child.stderr();
                    forward_child_stream(out_stream, out_future, false);
                    forward_child_stream(err_stream, err_future, true);
                }
                Ok(HeliosChild {
                    child,
                    _container: None,
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
                    named_devices: extract_named_devices(&args.node.capabilities.named_devices),
                    oom_policy: map_oom_policy(args.node.oom_tier),
                })
                .await
                .map_err(|error| RuntimeError::Other {
                    detail: format!("spawning exec `{}`: {error}", args.node.moniker),
                })?;
                Ok(HeliosChild {
                    child,
                    _container: None,
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

async fn spawn_oci_component(
    node: &ComponentNode,
    oci: &OciRunnerSpec,
    sockets: Vec<InheritedSocket>,
    ipc_channels: Vec<(String, HeliosIpcEnd)>,
) -> Result<HeliosChild, RuntimeError> {
    let mut builder = if let Some(image_ref) = &oci.image {
        let store_root = oci.store.as_deref().unwrap_or("/var/lib/oci");
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
    Ok(HeliosChild {
        child,
        _container: Some(container),
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
        named_devices: extract_named_devices(&node.capabilities.named_devices),
        oom_policy: map_oom_policy(node.oom_tier),
    })
    .await
    .map_err(|error| RuntimeError::Other {
        detail: format!("spawning MicroVm `{}`: {error}", node.moniker),
    })?;
    Ok(HeliosChild {
        child,
        _container: None,
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

fn extract_named_devices(ceiling: &NameCeiling) -> Vec<String> {
    match ceiling {
        NameCeiling::Any => Vec::new(),
        NameCeiling::Set(names) => names.iter().map(|s| s.to_string()).collect(),
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

    let mounts = fstab()?;
    for mount in &mounts {
        mounts::mount(MountRequest {
            source: mount.source.clone(),
            path: mount.point.clone(),
            read_only: mount.read_only,
            sharing: mount.sharing,
            compress: mount.compress.clone(),
            commit: mount.commit,
            max_inline: mount.max_inline,
        })
        .await
        .map_err(|error| {
            io::Error::other(format!(
                "mounting {} at {}: {:?}: {}",
                mount.label, mount.point, error.kind, error.detail
            ))
        })?;
        println!("helios init: mounted {} at {}", mount.label, mount.point);
    }

    list_dir(root)?;
    for mount in &mounts {
        println!("helios init: listing {}", mount.point);
        list_dir(Path::new(&mount.point))?;
    }

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
        .boot_with_pre_ready_hook(|| async {
            if Path::new(RC).exists() {
                run_rc()
                    .await
                    .map_err(|error| helios_component_manager::RuntimeError::Other {
                        detail: format!("running {RC}: {error}"),
                    })?;
                let _ = io::stdout().flush();
                let _ = io::stderr().flush();
            }
            Ok(())
        })
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
    use helios_api::mounts::MountSharing;

    use super::{commit_seconds, generated_topology, max_inline_bytes, parse_fstab};

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
    fn max_inline_values_read_as_linux_memparse_reads_them() {
        for (value, bytes) in [
            ("2048", 2048),
            ("0", 0),
            ("0k", 0),
            ("04000", 2048),
            ("0x800", 2048),
            ("2k", 2048),
            ("2K", 2048),
            ("1M", 1 << 20),
            ("1g", 1 << 30),
            ("1T", 1 << 40),
            ("1p", 1 << 50),
            ("1E", 1 << 60),
            ("18446744073709551615", u64::MAX),
        ] {
            assert_eq!(max_inline_bytes(value), Some(bytes), "{value}");
        }
        for value in [
            "",
            "k",
            "+2048",
            "-1",
            "0x",
            "08",
            "2KB",
            "2 K",
            "16E",
            "18446744073709551616",
        ] {
            assert_eq!(max_inline_bytes(value), None, "{value}");
        }
    }

    #[test]
    fn an_fstab_line_carries_its_inline_limit() {
        let mounts = parse_fstab(
            "btrfs:数据-データ-데이터 /btrfs rw,shared,compress=zstd:3,max_inline=4k\n",
        )
        .unwrap();
        assert_eq!(mounts[0].max_inline, Some(4096));
        assert_eq!(mounts[0].compress.as_deref(), Some("zstd:3"));
        assert!(parse_fstab("btrfs:disk /btrfs shared,max_inline=big\n").is_err());
        assert_eq!(
            parse_fstab("memory /tmp shared\n").unwrap()[0].max_inline,
            None
        );
    }

    #[test]
    fn commit_values_read_as_linux_reads_them() {
        for (value, seconds) in [
            ("5", 5),
            ("+5", 5),
            ("0", 0),
            ("010", 8),
            ("0x1e", 30),
            ("0X1E", 30),
            ("4294967295", u32::MAX),
        ] {
            assert_eq!(commit_seconds(value), Some(seconds), "{value}");
        }
        for value in ["", "+", "-1", "0x", "0x+5", "08", "4294967296", "5s", " 5"] {
            assert_eq!(commit_seconds(value), None, "{value}");
        }
    }

    #[test]
    fn an_fstab_line_carries_its_commit_interval() {
        let mounts =
            parse_fstab("btrfs:数据-データ-데이터 /btrfs rw,shared,compress=zstd:3,commit=120\n")
                .unwrap();
        assert_eq!(mounts[0].commit, Some(120));
        assert_eq!(mounts[0].compress.as_deref(), Some("zstd:3"));
        assert!(parse_fstab("btrfs:disk /btrfs shared,commit=soon\n").is_err());
        assert_eq!(parse_fstab("memory /tmp shared\n").unwrap()[0].commit, None);
    }

    #[test]
    fn every_fstab_line_names_whether_its_mount_is_private_or_shared() {
        let text = "\
btrfs:中文磁盘 /中文 private,rw
btrfs:日本語ディスク /日本語 shared
host-share /한국어 ro,shared
";
        let mounts = parse_fstab(text).unwrap();
        let granted: Vec<_> = mounts
            .iter()
            .map(|mount| (mount.point.as_str(), mount.sharing, mount.read_only))
            .collect();
        assert_eq!(
            granted,
            [
                ("/中文", MountSharing::Private, false),
                ("/日本語", MountSharing::Shared, false),
                ("/한국어", MountSharing::Shared, true),
            ]
        );
        for line in [
            "memory /tmp\n",
            "memory /tmp rw\n",
            "memory /tmp private,shared\n",
            "memory /tmp shared,private\n",
        ] {
            assert!(parse_fstab(line).is_err(), "{line:?}");
        }
        let twice = parse_fstab("memory /tmp shared,shared\n").unwrap();
        assert_eq!(twice[0].sharing, MountSharing::Shared);
    }
}
