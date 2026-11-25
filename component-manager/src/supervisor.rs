//! Async-first, zero-`dyn`, zero-`block_on` component supervisor state machine.
//!
//! Drives static topologies generated at compile time (and optional bounded
//! dynamic subtrees under `--features dynamic-components`) over any concrete
//! [`SupervisorRuntime`] implementation.

use std::collections::{BTreeMap, VecDeque};
use std::future::Future;
use std::rc::Rc;
use std::time::Duration;

use async_channel::{Receiver, Sender};
use futures_lite::future::{self, FutureExt as _};
use thiserror::Error;

use crate::authority::{ValidationError, validate_topology};
use crate::model::{
    ComponentNode, ComponentStateRecord, ComponentStatus, ComponentTopology, Criticality,
    EscalationAction, HardwareInventorySnapshot, IpAddrSpec, LifecycleKind, MountSpec,
    ProviderSlot, RestartPolicy, RunnerSpec, SocketActivationSpec, StartupPolicy,
};

/// POSIX `SIGTERM` signal number used for graceful component shutdown.
pub const SIGTERM: u8 = 15;
/// POSIX `SIGKILL` signal number used after `stop_timeout` expires.
pub const SIGKILL: u8 = 9;
/// Buffer chunk size used by the lazy IPC activation proxy.
const IPC_PROXY_CHUNK_BYTES: u32 = 64 * 1024;

/// Why a runtime operation performed by the supervisor failed.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum RuntimeError {
    #[error("permission denied: {detail}")]
    PermissionDenied { detail: String },
    #[error("not found: {detail}")]
    NotFound { detail: String },
    #[error("unavailable: {detail}")]
    Unavailable { detail: String },
    #[error("runtime error: {detail}")]
    Other { detail: String },
}

/// Termination outcome of a spawned child component (`wasm`, `oci`, `exec`, or `vm`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExitOutcome {
    Exited(u32),
    Signaled(u8),
    Trapped,
    Killed,
}

impl ExitOutcome {
    #[must_use]
    pub const fn is_clean_success(&self) -> bool {
        matches!(self, Self::Exited(0))
    }

    #[must_use]
    pub const fn is_operator_kill(&self) -> bool {
        matches!(self, Self::Killed)
    }

    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::Exited(code) => format!("exited with code {code}"),
            Self::Signaled(sig) => format!("terminated by signal {sig}"),
            Self::Trapped => "trapped".to_owned(),
            Self::Killed => "killed".to_owned(),
        }
    }
}

/// Termination outcome of an installed kernel provider slot (`compiler`, `http-client`, `surface`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProviderOutcome {
    Exited,
    Replaced,
    Stopped,
    Faulted(String),
}

/// Pre-bound listening socket held by the supervisor until first-packet activation.
pub enum BoundSocket<T, V> {
    Tcp(T),
    Vsock(V),
}

/// Fatal escalation payload handed to `helios:system/root-supervisor.escalate-fatal`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FatalEscalation {
    pub component: String,
    pub instance_id: Option<u64>,
    pub reason: String,
    pub restart_count: u32,
    pub action: EscalationAction,
}

/// Arguments handed to [`SupervisorRuntime::spawn_component`] on activation.
pub struct SpawnComponentArgs<T, V, I> {
    pub node: ComponentNode,
    pub sockets: Vec<BoundSocket<T, V>>,
    pub ipc_channels: Vec<(String, I)>,
}

/// Concrete handle to a live supervised child component.
pub trait ChildProcess: 'static {
    fn instance_id(&self) -> Option<u64>;
    fn signal(&self, signal: u8) -> Result<(), RuntimeError>;
    fn wait(&self) -> impl Future<Output = Result<ExitOutcome, RuntimeError>>;
}

/// Concrete handle to an installed kernel provider slot.
pub trait ProviderEndpoint: 'static {
    fn instance_id(&self) -> Option<u64>;
    fn wait_exit(&self) -> impl Future<Output = ProviderOutcome>;
    fn stop(&self);
}

/// Concrete duplex IPC channel endpoint (`helios:system/ipc.endpoint`).
pub trait IpcChannelEnd: 'static {
    fn read(&self, max_bytes: u32) -> impl Future<Output = Result<Option<Vec<u8>>, RuntimeError>>;
    fn write(&self, bytes: Vec<u8>) -> impl Future<Output = Result<(), RuntimeError>>;
    fn close_write(&self);
}

/// Concrete pre-bound TCP listener supporting non-consuming `wait_readable`.
pub trait TcpSocketListener: 'static {
    fn wait_readable(&self) -> impl Future<Output = Result<bool, RuntimeError>>;
}

/// Concrete pre-bound vsock listener supporting non-consuming `wait_readable`.
pub trait VsockSocketListener: 'static {
    fn wait_readable(&self) -> impl Future<Output = Result<bool, RuntimeError>>;
}

/// Concrete platform runtime adapter driving the supervisor with zero `dyn` dispatch.
pub trait SupervisorRuntime: Clone + 'static {
    type Child: ChildProcess;
    type Provider: ProviderEndpoint;
    type IpcEnd: IpcChannelEnd;
    type TcpListener: TcpSocketListener;
    type VsockListener: VsockSocketListener;

    /// Monotonic clock reading in milliseconds.
    fn now_ms(&self) -> u64;

    /// Sleeps for `duration` without blocking the executor.
    fn sleep(&self, duration: Duration) -> impl Future<Output = ()>;

    /// Spawns a concurrent task on the component's local async executor.
    fn spawn_task<F: Future<Output = ()> + 'static>(&self, future: F);

    /// Returns true if the artifact path exists in the guest filesystem (used
    /// only for components declared `optional = true` in subset boot images).
    fn path_exists(&self, path: &str) -> bool;

    /// Reads the current platform hardware inventory.
    fn hardware_inventory(&self) -> Result<HardwareInventorySnapshot, RuntimeError>;

    /// Subscribes to hardware inventory updates (hotplug / bring-up).
    /// Returns a channel receiving subsequent snapshots, or `None` when static.
    fn subscribe_hardware(&self) -> Option<Receiver<HardwareInventorySnapshot>>;

    /// Attaches one declarative volume mount.
    fn mount(&self, spec: &MountSpec) -> impl Future<Output = Result<(), RuntimeError>>;

    /// Mints a connected pair of duplex IPC channel endpoints.
    fn ipc_channel(&self) -> (Self::IpcEnd, Self::IpcEnd);

    /// Pre-binds a TCP listening socket for lazy socket activation.
    fn bind_tcp(
        &self,
        address: IpAddrSpec,
        port: u16,
        backlog: u16,
    ) -> impl Future<Output = Result<Self::TcpListener, RuntimeError>>;

    /// Pre-binds a vsock listening socket for lazy socket activation.
    fn bind_vsock(
        &self,
        port: u32,
        backlog: u32,
    ) -> impl Future<Output = Result<Self::VsockListener, RuntimeError>>;

    /// Installs a kernel provider slot (`compiler`, `http-client`, `surface`).
    fn install_provider(
        &self,
        slot: ProviderSlot,
        node: &ComponentNode,
    ) -> impl Future<Output = Result<Self::Provider, RuntimeError>>;

    /// Spawns a `wasm`, `oci`, `exec`, or `vm` component with attenuated authority,
    /// pre-bound listening sockets, and routed IPC channel endpoints.
    fn spawn_component(
        &self,
        args: SpawnComponentArgs<Self::TcpListener, Self::VsockListener, Self::IpcEnd>,
    ) -> impl Future<Output = Result<Self::Child, RuntimeError>>;

    /// Publishes the full live `/components/*` inspect state snapshot atomically.
    fn publish_inspect(&self, records: &[ComponentStateRecord]);

    /// Signals root bring-up readiness (`root-supervisor::signal-ready`).
    fn signal_ready(&self) -> impl Future<Output = Result<(), RuntimeError>>;

    /// Escalates an unrecoverable `critical = "system"` component failure.
    fn escalate_fatal(
        &self,
        report: FatalEscalation,
    ) -> impl Future<Output = Result<(), RuntimeError>>;
}

/// Errors returned by [`Supervisor`] operations.
#[derive(Debug, Error)]
pub enum SupervisorError {
    #[error(transparent)]
    Validation(#[from] ValidationError),
    #[error(transparent)]
    Runtime(#[from] RuntimeError),
    #[error("critical=system component `{component}` failed unrecoverably: {reason}")]
    FatalEscalated { component: String, reason: String },
    #[error("unknown component moniker `{moniker}`")]
    UnknownComponent { moniker: String },
}

/// Internal events sent from per-component monitor/watcher tasks to the supervisor loop.
enum SupervisorEvent<R: SupervisorRuntime> {
    ChildExited {
        index: usize,
        generation: u64,
        outcome: Result<ExitOutcome, RuntimeError>,
    },
    ProviderExited {
        index: usize,
        generation: u64,
        outcome: ProviderOutcome,
    },
    SocketActivated {
        index: usize,
        generation: u64,
        sockets: Vec<BoundSocket<R::TcpListener, R::VsockListener>>,
    },
    IpcActivated {
        index: usize,
        generation: u64,
    },
    RestartTimerFired {
        index: usize,
        generation: u64,
    },
    HardwareUpdated(HardwareInventorySnapshot),
}

/// Control messages sent to a per-exposed-channel IPC bridge task.
enum BridgeMsg<I> {
    AttachConsumer(I),
    AttachProvider { generation: u64, proxy_end: I },
    DetachProvider { next_generation: u64 },
    ConsumerData { id: u64, bytes: Vec<u8> },
    ConsumerClosed { id: u64 },
    ProviderData { generation: u64, bytes: Vec<u8> },
    ProviderClosed { generation: u64 },
    Shutdown,
}

struct ExposedBridgeHandle<I> {
    tx: Sender<BridgeMsg<I>>,
}

impl<I> Drop for ExposedBridgeHandle<I> {
    fn drop(&mut self) {
        let _ = self.tx.try_send(BridgeMsg::Shutdown);
    }
}

type SocketReclaimReply<R> = Sender<
    Vec<
        BoundSocket<<R as SupervisorRuntime>::TcpListener, <R as SupervisorRuntime>::VsockListener>,
    >,
>;

struct ArmedSockets<R: SupervisorRuntime> {
    /// Send `Some(reply_tx)` to disarm and reclaim the bound sockets without rebinding,
    /// or `None` to disarm and drop the bound sockets on component stop/teardown.
    disarm_tx: Sender<Option<SocketReclaimReply<R>>>,
    stopped_rx: Receiver<()>,
}

struct ManagedComponent<R: SupervisorRuntime> {
    node: ComponentNode,
    /// `false` once a dynamically mounted subtree has been unmounted so its
    /// slot is excluded from lookups, inspect, realm resets, and collision checks.
    active: bool,
    status: ComponentStatus,
    restarts: u64,
    instance_id: Option<u64>,
    generation: u64,
    consecutive_failures: u32,
    /// Monotonic timestamp when this component last entered `Running`, used to
    /// reset `consecutive_failures` after surviving at least `burst_window_ms`.
    started_at_ms: Option<u64>,
    burst_timestamps_ms: VecDeque<u64>,
    mounted: bool,
    /// True while a kernel provider slot handle is installed and monitored.
    provider_installed: bool,
    /// Active stop signal sender for the running child or provider watcher task.
    stop_tx: Option<Sender<()>>,
    /// Confirmation receiver resolved once the running child/provider task finishes stopping.
    stopped_rx: Option<Receiver<()>>,
    /// Persistent IPC bridge tasks keyed by exposed channel name.
    exposed_bridges: BTreeMap<String, ExposedBridgeHandle<R::IpcEnd>>,
    /// Active lazy socket activation watcher holding pre-bound listening sockets.
    armed_sockets: Option<ArmedSockets<R>>,
}

impl<R: SupervisorRuntime> ManagedComponent<R> {
    fn new(node: ComponentNode) -> Self {
        Self {
            node,
            active: true,
            status: ComponentStatus::Unstarted,
            restarts: 0,
            instance_id: None,
            generation: 1,
            consecutive_failures: 0,
            started_at_ms: None,
            burst_timestamps_ms: VecDeque::new(),
            mounted: false,
            provider_installed: false,
            stop_tx: None,
            stopped_rx: None,
            exposed_bridges: BTreeMap::new(),
            armed_sockets: None,
        }
    }

    fn record(&self) -> ComponentStateRecord {
        ComponentStateRecord {
            moniker: self.node.moniker.to_string(),
            inspect_prefix: self.node.inspect_prefix().to_owned(),
            status: self.status,
            restarts: self.restarts,
            instance_id: self.instance_id,
            runner: self.node.runner.kind_str(),
            oom_tier: self.node.oom_tier.as_str(),
        }
    }
}

/// Computes exponential backoff `min(base * 2^attempt, max)` without overflow.
#[must_use]
pub const fn exponential_backoff_ms(base_ms: u64, max_ms: u64, attempt: u32) -> u64 {
    let shift = if attempt >= 63 { 63 } else { attempt };
    let factor = 1_u64 << shift;
    let scaled = base_ms.saturating_mul(factor);
    if max_ms == 0 || scaled <= max_ms {
        scaled
    } else {
        max_ms
    }
}

/// Opaque pending event returned by [`Supervisor::recv_event`] and consumed by
/// [`Supervisor::handle_pending_event`].
pub struct PendingEvent<R: SupervisorRuntime>(SupervisorEvent<R>);

/// Stateful, async-first component supervisor driving a validated [`ComponentTopology`].
pub struct Supervisor<R: SupervisorRuntime> {
    runtime: R,
    components: Vec<ManagedComponent<R>>,
    hardware: HardwareInventorySnapshot,
    event_tx: Sender<SupervisorEvent<R>>,
    event_rx: Receiver<SupervisorEvent<R>>,
    /// Track whether `signal_ready` has been emitted.
    ready_signaled: bool,
    /// True once `shutdown_all` has been invoked so `has_active_work()` returns `false`.
    shutting_down: bool,
    /// Enclosing parent realm indices queued for teardown + restart after a
    /// `critical = "parent"` failure (drained iteratively to avoid async recursion).
    pending_realm_resets: VecDeque<usize>,
    /// Eager dependents unblocked by a `oneshot` completion (drained iteratively
    /// to avoid async recursion between `activate_index` and `handle_termination`).
    pending_eager_activations: VecDeque<usize>,
    /// Maps dynamic subtree root moniker -> list of component indices in `self.components`.
    #[cfg(feature = "dynamic-components")]
    dynamic_subtrees: BTreeMap<String, Vec<usize>>,
}

impl<R: SupervisorRuntime> Supervisor<R> {
    /// Validates `topology` and constructs a fresh supervisor with every component
    /// initialized to `unstarted` (allocating zero Wasm stores, containers, or VMs).
    pub fn new(runtime: R, topology: ComponentTopology) -> Result<Self, SupervisorError> {
        validate_topology(&topology)?;
        let hardware = runtime.hardware_inventory()?;
        let (event_tx, event_rx) = async_channel::unbounded();
        let components = topology
            .nodes
            .into_owned()
            .into_iter()
            .map(ManagedComponent::new)
            .collect();
        let supervisor = Self {
            runtime,
            components,
            hardware,
            event_tx,
            event_rx,
            ready_signaled: false,
            shutting_down: false,
            pending_realm_resets: VecDeque::new(),
            pending_eager_activations: VecDeque::new(),
            #[cfg(feature = "dynamic-components")]
            dynamic_subtrees: BTreeMap::new(),
        };
        supervisor.publish_inspect();
        Ok(supervisor)
    }

    /// Returns a snapshot of every active component's live inspect record.
    #[must_use]
    pub fn inspect_records(&self) -> Vec<ComponentStateRecord> {
        self.components
            .iter()
            .filter(|c| c.active)
            .map(ManagedComponent::record)
            .collect()
    }

    /// Looks up a component's current lifecycle status by moniker.
    #[must_use]
    pub fn status_of(&self, moniker: &str) -> Option<ComponentStatus> {
        self.find_index(moniker)
            .map(|idx| self.components[idx].status)
    }

    /// Looks up a component's restart counter by moniker.
    #[must_use]
    pub fn restarts_of(&self, moniker: &str) -> Option<u64> {
        self.find_index(moniker)
            .map(|idx| self.components[idx].restarts)
    }

    /// Looks up a component's active instance ID by moniker.
    #[must_use]
    pub fn instance_id_of(&self, moniker: &str) -> Option<u64> {
        self.find_index(moniker)
            .and_then(|idx| self.components[idx].instance_id)
    }

    /// Returns a reference to the component node at `moniker`.
    #[must_use]
    pub fn node_by_moniker(&self, moniker: &str) -> Option<&ComponentNode> {
        self.find_index(moniker)
            .map(|idx| &self.components[idx].node)
    }

    /// Finds the index of `moniker` in the live topology.
    #[must_use]
    pub fn find_index(&self, moniker: &str) -> Option<usize> {
        self.components
            .iter()
            .position(|c| c.active && c.node.moniker.as_ref() == moniker)
    }

    /// Brings up the root realm:
    /// 1. Subscribes to hardware hotplug updates (`subscribe_hardware`),
    /// 2. Attaches declarative `[[mounts]]` in realm hierarchy order,
    /// 3. Pre-registers lazy kernel provider slots, arms lazy listening sockets (`wait_readable`),
    ///    and starts eager kernel providers whose hardware predicates are satisfied,
    /// 4. Starts remaining `startup = "eager"` components whose `requires` predicates and `after`
    ///    dependencies are satisfied,
    /// 5. Publishes live `/components/*` inspect state and invokes `signal_ready()`.
    pub async fn boot(&mut self) -> Result<(), SupervisorError> {
        self.boot_with_pre_ready_hook(|| async { Ok(()) }).await
    }

    /// Like [`Self::boot`], running `after_providers` once mounts and kernel
    /// providers (`compiler`, `http-client`, `compositor`) are installed and
    /// before remaining eager components (e.g. `/inspector`) start and
    /// `signal_ready()` is emitted.
    pub async fn boot_with_pre_ready_hook<F, Fut>(
        &mut self,
        after_providers: F,
    ) -> Result<(), SupervisorError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<(), RuntimeError>>,
    {
        if let Some(hw_rx) = self.runtime.subscribe_hardware() {
            let tx = self.event_tx.clone();
            self.runtime.spawn_task(async move {
                while let Ok(snapshot) = hw_rx.recv().await {
                    if tx
                        .send(SupervisorEvent::HardwareUpdated(snapshot))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            });
        }

        let all_indices: Vec<usize> = (0..self.components.len())
            .filter(|&idx| self.components[idx].active)
            .collect();
        self.bring_up_mounts_and_providers(&all_indices).await?;
        self.drain_pending_work().await?;

        after_providers().await?;

        self.bring_up_remaining_eager(&all_indices).await?;
        self.drain_pending_work().await?;

        if !self.ready_signaled {
            self.runtime.signal_ready().await?;
            self.ready_signaled = true;
        }
        Ok(())
    }

    /// Runs the supervision event loop until all eager/active work terminates cleanly
    /// or a `critical = "system"` component escalates fatally.
    pub async fn run_until_done(&mut self) -> Result<(), SupervisorError> {
        while self.has_active_work() {
            let Some(event) = self.recv_event().await else {
                break;
            };
            self.handle_pending_event(event).await?;
        }
        Ok(())
    }

    /// Cancel-safely awaits the next internal supervisor event without mutating
    /// supervisor state.
    ///
    /// Callers multiplexing external control channels (such as
    /// `helios:system/component-control`) should race `recv_event()` against
    /// their control channel and then pass any received [`PendingEvent`] to
    /// [`Self::handle_pending_event`] uninterrupted.
    pub async fn recv_event(&self) -> Option<PendingEvent<R>> {
        self.event_rx.recv().await.ok().map(PendingEvent)
    }

    /// Applies one event received from [`Self::recv_event`] and drains any
    /// resulting eager activations or realm resets to completion.
    pub async fn handle_pending_event(
        &mut self,
        event: PendingEvent<R>,
    ) -> Result<(), SupervisorError> {
        self.handle_event(event.0).await?;
        self.drain_pending_work().await
    }

    /// Processes a single pending supervisor event (useful for deterministic step-by-step tests).
    pub async fn step_once(&mut self) -> Result<bool, SupervisorError> {
        match self.recv_event().await {
            Some(event) => {
                self.handle_pending_event(event).await?;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    /// Drains any already-queued supervisor events without blocking.
    pub async fn drain_ready_events(&mut self) -> Result<usize, SupervisorError> {
        let mut count = 0;
        while let Ok(event) = self.event_rx.try_recv() {
            self.handle_event(event).await?;
            self.drain_pending_work().await?;
            count += 1;
        }
        Ok(count)
    }

    /// Starts a configured non-realm component by moniker if not already running.
    pub async fn start_component(
        &mut self,
        moniker: &str,
    ) -> Result<ComponentStateRecord, SupervisorError> {
        let idx = self
            .find_index(moniker)
            .ok_or_else(|| SupervisorError::UnknownComponent {
                moniker: moniker.to_owned(),
            })?;
        if !self.components[idx].active {
            return Err(SupervisorError::UnknownComponent {
                moniker: moniker.to_owned(),
            });
        }
        if !self.components[idx].node.runner.is_realm()
            && !matches!(
                self.components[idx].status,
                ComponentStatus::Starting | ComponentStatus::Running
            )
        {
            let sockets = self.acquire_sockets_for(idx).await?;
            let ipc = self.prepare_consumer_routes(idx);
            self.activate_index(idx, sockets, ipc).await?;
            self.drain_pending_work().await?;
        }
        self.inspect_records()
            .into_iter()
            .find(|rec| rec.moniker == moniker)
            .ok_or_else(|| SupervisorError::UnknownComponent {
                moniker: moniker.to_owned(),
            })
    }

    /// Gracefully stops a single component (sending `SIGTERM`, waiting up to `stop_timeout_ms`,
    /// then force-killing if needed).
    pub async fn stop_component(&mut self, moniker: &str) -> Result<(), SupervisorError> {
        let idx = self
            .find_index(moniker)
            .ok_or_else(|| SupervisorError::UnknownComponent {
                moniker: moniker.to_owned(),
            })?;
        self.stop_index(idx).await;
        self.publish_inspect();
        Ok(())
    }

    /// Stops and re-starts a configured component by moniker.
    pub async fn restart_component(
        &mut self,
        moniker: &str,
    ) -> Result<ComponentStateRecord, SupervisorError> {
        self.stop_component(moniker).await?;
        self.start_component(moniker).await
    }

    /// Gracefully stops every active running component in the topology.
    pub async fn shutdown_all(&mut self) {
        self.shutting_down = true;
        let indices: Vec<usize> = (0..self.components.len())
            .rev()
            .filter(|&idx| self.components[idx].active)
            .collect();
        for idx in indices {
            self.stop_index(idx).await;
            self.components[idx].exposed_bridges.clear();
        }
        self.publish_inspect();
    }

    /// Returns `true` while any active component is running, starting, holding an
    /// installed kernel provider slot, holding an armed lazy socket listener,
    /// reachable via lazy IPC routes, or hosting dynamic mounts.
    #[must_use]
    pub fn has_active_work(&self) -> bool {
        if self.shutting_down {
            return false;
        }
        self.components.iter().enumerate().any(|(idx, c)| {
            if !c.active {
                return false;
            }
            if c.node.dynamic_mount && self.ready_signaled {
                return true;
            }
            if c.node.runner.is_realm() {
                return false;
            }
            c.armed_sockets.is_some()
                || c.provider_installed
                || matches!(
                    c.status,
                    ComponentStatus::Starting | ComponentStatus::Running
                )
                || (c.node.startup == StartupPolicy::Lazy
                    && (!c.exposed_bridges.is_empty() || self.is_ipc_route_target(idx)))
        })
    }

    fn is_ipc_route_target(&self, provider_idx: usize) -> bool {
        self.components.iter().any(|other| {
            other.active
                && other
                    .node
                    .routes
                    .iter()
                    .any(|r| r.provider_index == provider_idx)
        })
    }

    fn publish_inspect(&self) {
        let records = self.inspect_records();
        self.runtime.publish_inspect(&records);
    }

    #[cfg(feature = "dynamic-components")]
    async fn bring_up_indices(&mut self, indices: &[usize]) -> Result<(), SupervisorError> {
        self.bring_up_batch(indices).await?;
        self.drain_pending_work().await
    }

    /// Drains any queued unblocked eager activations and `critical = "parent"` realm
    /// resets iteratively (eliminating all async recursion).
    async fn drain_pending_work(&mut self) -> Result<(), SupervisorError> {
        loop {
            if let Some(idx) = self.pending_eager_activations.pop_front() {
                if idx < self.components.len()
                    && self.components[idx].active
                    && !self.components[idx].node.runner.is_realm()
                    && self.components[idx].node.startup == StartupPolicy::Eager
                    && self.components[idx].status == ComponentStatus::Unstarted
                    && self.components[idx]
                        .node
                        .requires
                        .satisfied_by(&self.hardware)
                    && self.dependencies_satisfied(idx)
                {
                    let sockets = self.acquire_sockets_for(idx).await?;
                    let ipc = self.prepare_consumer_routes(idx);
                    self.activate_index(idx, sockets, ipc).await?;
                }
                continue;
            }
            if let Some(parent_idx) = self.pending_realm_resets.pop_front() {
                if parent_idx < self.components.len() && self.components[parent_idx].active {
                    let subtree = self.teardown_parent_realm(parent_idx).await;
                    self.bring_up_batch(&subtree).await?;
                }
                continue;
            }
            break;
        }
        Ok(())
    }

    async fn bring_up_batch(&mut self, indices: &[usize]) -> Result<(), SupervisorError> {
        self.bring_up_mounts_and_providers(indices).await?;
        self.bring_up_remaining_eager(indices).await
    }

    async fn bring_up_mounts_and_providers(
        &mut self,
        indices: &[usize],
    ) -> Result<(), SupervisorError> {
        // Phase 1: Mount declarative volumes in hierarchy order before starting any component.
        for &idx in indices {
            if !self.components[idx].active {
                continue;
            }
            self.ensure_mounts(idx).await?;
            if self.components[idx].node.runner.is_realm() {
                self.components[idx].status = ComponentStatus::Running;
            }
        }
        self.publish_inspect();

        // Phase 2: Pre-arm lazy listening sockets, register lazy kernel provider slots,
        // and bring up eager kernel providers whose hardware requirements and dependencies
        // are already satisfied.
        for &idx in indices {
            if !self.components[idx].active || self.components[idx].node.runner.is_realm() {
                continue;
            }
            if is_lazy_provider_slot(&self.components[idx].node) {
                self.activate_index(idx, Vec::new(), Vec::new()).await?;
            } else if is_provider_component(&self.components[idx].node)
                && self.components[idx].node.startup == StartupPolicy::Eager
                && self.components[idx].status == ComponentStatus::Unstarted
                && self.components[idx]
                    .node
                    .requires
                    .satisfied_by(&self.hardware)
                && self.dependencies_satisfied(idx)
            {
                let sockets = self.acquire_sockets_for(idx).await?;
                let ipc = self.prepare_consumer_routes(idx);
                self.activate_index(idx, sockets, ipc).await?;
            } else if self.components[idx].node.startup == StartupPolicy::Lazy
                && !self.components[idx].node.sockets.is_empty()
            {
                self.arm_lazy_sockets(idx).await?;
            }
        }
        Ok(())
    }

    async fn bring_up_remaining_eager(&mut self, indices: &[usize]) -> Result<(), SupervisorError> {
        // Phase 3: Start remaining eager components in topological `after` order (including
        // waiting for eager `oneshot` dependencies before dependents launch!).
        let ordered = self.topological_order(indices);
        for idx in ordered {
            if !self.components[idx].active || self.components[idx].node.runner.is_realm() {
                continue;
            }
            if self.components[idx].node.startup != StartupPolicy::Eager {
                continue;
            }
            if self.components[idx].status != ComponentStatus::Unstarted {
                continue;
            }
            if !self.components[idx]
                .node
                .requires
                .satisfied_by(&self.hardware)
            {
                continue;
            }
            if !self.dependencies_satisfied(idx) {
                continue;
            }
            let sockets = self.acquire_sockets_for(idx).await?;
            let ipc = self.prepare_consumer_routes(idx);
            self.activate_index(idx, sockets, ipc).await?;

            // If this eager component is a `oneshot`, wait for it to reach `Completed`
            // (or fail) before starting components that depend on it via `after`.
            if self.components[idx].node.lifecycle == LifecycleKind::Oneshot
                && matches!(
                    self.components[idx].status,
                    ComponentStatus::Starting | ComponentStatus::Running
                )
            {
                self.wait_for_oneshot(idx).await?;
            }
        }
        Ok(())
    }

    async fn wait_for_oneshot(&mut self, idx: usize) -> Result<(), SupervisorError> {
        while matches!(
            self.components[idx].status,
            ComponentStatus::Starting | ComponentStatus::Running
        ) {
            let Ok(event) = self.event_rx.recv().await else {
                break;
            };
            self.handle_event(event).await?;
        }
        Ok(())
    }

    fn dependencies_satisfied(&self, idx: usize) -> bool {
        self.components[idx].node.after.iter().all(|&dep_idx| {
            let dep = &self.components[dep_idx];
            match dep.node.lifecycle {
                LifecycleKind::Oneshot => dep.status == ComponentStatus::Completed,
                LifecycleKind::Service => dep.status == ComponentStatus::Running,
            }
        })
    }

    fn topological_order(&self, indices: &[usize]) -> Vec<usize> {
        let mut visited = BTreeMap::<usize, bool>::new();
        let mut out = Vec::with_capacity(indices.len());
        for &idx in indices {
            self.topo_visit(idx, indices, &mut visited, &mut out);
        }
        out
    }

    fn topo_visit(
        &self,
        idx: usize,
        scope: &[usize],
        visited: &mut BTreeMap<usize, bool>,
        out: &mut Vec<usize>,
    ) {
        if visited.get(&idx).copied().unwrap_or(false) {
            return;
        }
        visited.insert(idx, true);
        for &dep in self.components[idx].node.after.iter() {
            if scope.contains(&dep) {
                self.topo_visit(dep, scope, visited, out);
            }
        }
        out.push(idx);
    }

    async fn ensure_mounts(&mut self, idx: usize) -> Result<(), SupervisorError> {
        if self.components[idx].mounted || self.components[idx].node.mounts.is_empty() {
            return Ok(());
        }
        let mounts: Vec<MountSpec> = self.components[idx].node.mounts.iter().cloned().collect();
        for mount in &mounts {
            self.runtime.mount(mount).await?;
        }
        self.components[idx].mounted = true;
        Ok(())
    }

    async fn bind_sockets_for(
        &self,
        idx: usize,
    ) -> Result<Vec<BoundSocket<R::TcpListener, R::VsockListener>>, SupervisorError> {
        let mut bound = Vec::with_capacity(self.components[idx].node.sockets.len());
        for &spec in self.components[idx].node.sockets.iter() {
            match spec {
                SocketActivationSpec::Tcp {
                    address,
                    port,
                    backlog,
                } => {
                    let listener = self.runtime.bind_tcp(address, port, backlog).await?;
                    bound.push(BoundSocket::Tcp(listener));
                }
                SocketActivationSpec::Vsock { port, backlog } => {
                    let listener = self.runtime.bind_vsock(port, backlog).await?;
                    bound.push(BoundSocket::Vsock(listener));
                }
            }
        }
        Ok(bound)
    }

    /// Reclaims already-bound listening sockets from an armed lazy socket watcher
    /// when present (avoiding `AddrInUse`), or binds fresh sockets otherwise.
    async fn acquire_sockets_for(
        &mut self,
        idx: usize,
    ) -> Result<Vec<BoundSocket<R::TcpListener, R::VsockListener>>, SupervisorError> {
        if let Some(armed) = self.components[idx].armed_sockets.take() {
            let generation = self.components[idx].generation;
            let (reply_tx, reply_rx) = async_channel::bounded(1);
            let _ = armed.disarm_tx.send(Some(reply_tx)).await;
            let reclaimed = reply_rx.recv().await.ok();
            let _ = armed.stopped_rx.recv().await;
            if let Some(sockets) = reclaimed {
                return Ok(sockets);
            }
            // The watcher may have observed readiness and posted `SocketActivated`
            // just before receiving disarm; recover those exact sockets from the queue.
            if let Some(sockets) = self.take_queued_socket_activation(idx, generation) {
                return Ok(sockets);
            }
        }
        self.bind_sockets_for(idx).await
    }

    fn take_queued_socket_activation(
        &self,
        target_idx: usize,
        target_generation: u64,
    ) -> Option<Vec<BoundSocket<R::TcpListener, R::VsockListener>>> {
        let mut preserved = Vec::new();
        let mut found = None;
        while let Ok(event) = self.event_rx.try_recv() {
            match event {
                SupervisorEvent::SocketActivated {
                    index,
                    generation,
                    sockets,
                } if index == target_idx && generation == target_generation && found.is_none() => {
                    found = Some(sockets);
                }
                other => preserved.push(other),
            }
        }
        for event in preserved {
            let _ = self.event_tx.try_send(event);
        }
        found
    }

    async fn disarm_lazy_sockets(&mut self, idx: usize) {
        if let Some(armed) = self.components[idx].armed_sockets.take() {
            let _ = armed.disarm_tx.send(None).await;
            let _ = armed.stopped_rx.recv().await;
        }
    }

    async fn arm_lazy_sockets(&mut self, idx: usize) -> Result<(), SupervisorError> {
        if self.components[idx].armed_sockets.is_some()
            || self.components[idx].node.sockets.is_empty()
        {
            return Ok(());
        }
        let bound = self.bind_sockets_for(idx).await?;
        if bound.is_empty() {
            return Ok(());
        }
        let generation = self.components[idx].generation;
        let (disarm_tx, disarm_rx) = async_channel::bounded::<Option<SocketReclaimReply<R>>>(1);
        let (stopped_tx, stopped_rx) = async_channel::bounded::<()>(1);
        self.components[idx].armed_sockets = Some(ArmedSockets {
            disarm_tx,
            stopped_rx,
        });
        let event_tx = self.event_tx.clone();

        self.runtime.spawn_task(async move {
            enum SocketWatchOutcome<T, V> {
                Readable,
                Disarmed(Option<Sender<Vec<BoundSocket<T, V>>>>),
            }

            let mut sockets = bound;
            let outcome = async {
                if wait_any_socket_readable(&sockets).await {
                    SocketWatchOutcome::Readable
                } else {
                    SocketWatchOutcome::Disarmed(None)
                }
            }
            .or(async {
                let reply = disarm_rx.recv().await.ok().flatten();
                SocketWatchOutcome::Disarmed(reply)
            })
            .await;

            match outcome {
                SocketWatchOutcome::Readable => {
                    let _ = event_tx
                        .send(SupervisorEvent::SocketActivated {
                            index: idx,
                            generation,
                            sockets: std::mem::take(&mut sockets),
                        })
                        .await;
                }
                SocketWatchOutcome::Disarmed(Some(reply_tx)) => {
                    let _ = reply_tx.send(std::mem::take(&mut sockets)).await;
                }
                SocketWatchOutcome::Disarmed(None) => {}
            }
            let _ = stopped_tx.send(()).await;
        });
        Ok(())
    }

    /// Returns (creating on demand) the persistent supervisor-side IPC bridge
    /// for `(provider_idx, channel_name)`.
    fn ensure_exposed_bridge(
        &mut self,
        provider_idx: usize,
        channel_name: &str,
    ) -> Sender<BridgeMsg<R::IpcEnd>> {
        if let Some(handle) = self.components[provider_idx]
            .exposed_bridges
            .get(channel_name)
        {
            return handle.tx.clone();
        }
        let generation = self.components[provider_idx].generation;
        let (tx, rx) = async_channel::unbounded();
        let bridge_tx = tx.clone();
        let runtime = self.runtime.clone();
        let event_tx = self.event_tx.clone();
        self.runtime.spawn_task(run_exposed_channel_bridge(
            provider_idx,
            generation,
            bridge_tx,
            rx,
            runtime,
            event_tx,
        ));
        self.components[provider_idx].exposed_bridges.insert(
            channel_name.to_owned(),
            ExposedBridgeHandle { tx: tx.clone() },
        );
        tx
    }

    fn detach_exposed_bridges(&self, idx: usize) {
        let next_generation = self.components[idx].generation;
        for handle in self.components[idx].exposed_bridges.values() {
            let _ = handle
                .tx
                .try_send(BridgeMsg::DetachProvider { next_generation });
        }
    }

    /// Pre-creates duplex IPC channels for every `[[use]]` route declared by `consumer_idx`
    /// and attaches each provider-side end to the target provider's persistent channel bridge.
    ///
    /// Frames sent to an unstarted lazy provider are buffered with zero loss and trigger
    /// lazy activation; frames sent to an already-running or restarted provider flow
    /// immediately without stranding endpoints.
    fn prepare_consumer_routes(&mut self, consumer_idx: usize) -> Vec<(String, R::IpcEnd)> {
        let routes = self.components[consumer_idx].node.routes.clone();
        let mut consumer_ends = Vec::with_capacity(routes.len());
        for route in routes.iter() {
            let (client_end, server_end) = self.runtime.ipc_channel();
            consumer_ends.push((route.consumer_channel.to_string(), client_end));

            let bridge_tx =
                self.ensure_exposed_bridge(route.provider_index, route.provider_channel.as_ref());
            let _ = bridge_tx.try_send(BridgeMsg::AttachConsumer(server_end));
        }
        consumer_ends
    }

    async fn activate_index(
        &mut self,
        idx: usize,
        sockets: Vec<BoundSocket<R::TcpListener, R::VsockListener>>,
        mut ipc_channels: Vec<(String, R::IpcEnd)>,
    ) -> Result<(), SupervisorError> {
        // Optional bootfs components (such as plugins in minimal subset tests) skip cleanly when absent.
        if let Some(program) = optional_program_path(&self.components[idx].node.runner)
            && !self.runtime.path_exists(program)
        {
            self.components[idx].status = ComponentStatus::Unstarted;
            self.publish_inspect();
            return Ok(());
        }

        self.components[idx].status = ComponentStatus::Starting;
        self.publish_inspect();

        let generation = self.components[idx].generation;
        let node = self.components[idx].node.clone();

        // Kernel provider slots (`compiler`, `http-client`, `surface`) install via `root-supervisor`.
        if let RunnerSpec::Wasm(wasm) = &node.runner
            && let Some(slot) = wasm.provider
        {
            match self.runtime.install_provider(slot, &node).await {
                Ok(provider) => {
                    let instance_id = provider.instance_id();
                    // Lazy provider slots (`compiler`, `http-client`) have no Wasm Store until first request.
                    self.components[idx].instance_id = instance_id;
                    self.components[idx].provider_installed = true;
                    self.components[idx].status = if instance_id.is_some() {
                        self.components[idx].started_at_ms = Some(self.runtime.now_ms());
                        ComponentStatus::Running
                    } else {
                        self.components[idx].started_at_ms = None;
                        ComponentStatus::Unstarted
                    };
                    let (stop_tx, stop_rx) = async_channel::bounded::<()>(1);
                    let (stopped_tx, stopped_rx) = async_channel::bounded::<()>(1);
                    self.components[idx].stop_tx = Some(stop_tx);
                    self.components[idx].stopped_rx = Some(stopped_rx);
                    self.publish_inspect();

                    let event_tx = self.event_tx.clone();
                    self.runtime.spawn_task(async move {
                        enum ProviderWait {
                            Exited(ProviderOutcome),
                            StopRequested,
                        }
                        let outcome = async { ProviderWait::Exited(provider.wait_exit().await) }
                            .or(async {
                                let _ = stop_rx.recv().await;
                                ProviderWait::StopRequested
                            })
                            .await;
                        match outcome {
                            ProviderWait::Exited(exit) => {
                                let _ = event_tx
                                    .send(SupervisorEvent::ProviderExited {
                                        index: idx,
                                        generation,
                                        outcome: exit,
                                    })
                                    .await;
                            }
                            ProviderWait::StopRequested => {
                                provider.stop();
                            }
                        }
                        let _ = stopped_tx.send(()).await;
                    });
                    return Ok(());
                }
                Err(error) => {
                    self.components[idx].provider_installed = false;
                    self.components[idx].started_at_ms = None;
                    self.components[idx].status = ComponentStatus::Failed;
                    self.publish_inspect();
                    return self
                        .handle_unrecoverable_failure(
                            idx,
                            format!("provider install failed: {error}"),
                            None,
                        )
                        .await;
                }
            }
        }

        // Wire every exposed channel on this component through its persistent bridge so
        // pre-existing, concurrent, and future consumers all deliver seamlessly.
        let mut pending_bridge_attachments = Vec::with_capacity(node.exposes.len());
        for expose in node.exposes.iter() {
            let channel_name = expose.channel.to_string();
            let bridge_tx = self.ensure_exposed_bridge(idx, &channel_name);
            let (proxy_end, provider_end) = self.runtime.ipc_channel();
            ipc_channels.push((channel_name, provider_end));
            pending_bridge_attachments.push((bridge_tx, proxy_end));
        }

        // Standard component spawn (`wasm`, `oci`, `exec`, `vm`).
        let args = SpawnComponentArgs {
            node: node.clone(),
            sockets,
            ipc_channels,
        };
        match self.runtime.spawn_component(args).await {
            Ok(child) => {
                let instance_id = child.instance_id();
                self.components[idx].instance_id = instance_id;
                self.components[idx].started_at_ms = Some(self.runtime.now_ms());
                self.components[idx].status = ComponentStatus::Running;
                for (bridge_tx, proxy_end) in pending_bridge_attachments {
                    let _ = bridge_tx.try_send(BridgeMsg::AttachProvider {
                        generation,
                        proxy_end,
                    });
                }
                let (stop_tx, stop_rx) = async_channel::bounded::<()>(1);
                let (stopped_tx, stopped_rx) = async_channel::bounded::<()>(1);
                self.components[idx].stop_tx = Some(stop_tx);
                self.components[idx].stopped_rx = Some(stopped_rx);
                self.publish_inspect();

                let stop_timeout = Duration::from_millis(node.stop_timeout_ms);
                let runtime = self.runtime.clone();
                let event_tx = self.event_tx.clone();
                self.runtime.spawn_task(async move {
                    let wait_fut =
                        child_wait_with_graceful_stop(child, stop_rx, stop_timeout, runtime);
                    if let Some(outcome) = wait_fut.await {
                        let _ = event_tx
                            .send(SupervisorEvent::ChildExited {
                                index: idx,
                                generation,
                                outcome,
                            })
                            .await;
                    }
                    let _ = stopped_tx.send(()).await;
                });
                Ok(())
            }
            Err(error) => {
                self.components[idx].status = ComponentStatus::Failed;
                self.components[idx].instance_id = None;
                self.components[idx].started_at_ms = None;
                self.publish_inspect();
                self.handle_termination(idx, false, format!("spawn failed: {error}"), None)
                    .await
            }
        }
    }

    async fn handle_event(&mut self, event: SupervisorEvent<R>) -> Result<(), SupervisorError> {
        match event {
            SupervisorEvent::HardwareUpdated(snapshot) => {
                self.hardware = snapshot;
                let candidates: Vec<usize> = (0..self.components.len())
                    .filter(|&idx| {
                        let c = &self.components[idx];
                        c.active
                            && !c.node.runner.is_realm()
                            && c.node.startup == StartupPolicy::Eager
                            && c.status == ComponentStatus::Unstarted
                            && c.node.requires.satisfied_by(&self.hardware)
                            && self.dependencies_satisfied(idx)
                    })
                    .collect();
                for idx in candidates {
                    let sockets = self.acquire_sockets_for(idx).await?;
                    let ipc = self.prepare_consumer_routes(idx);
                    self.activate_index(idx, sockets, ipc).await?;
                }
                Ok(())
            }
            SupervisorEvent::SocketActivated {
                index,
                generation,
                sockets,
            } => {
                if index >= self.components.len()
                    || !self.components[index].active
                    || self.components[index].generation != generation
                {
                    return Ok(());
                }
                self.components[index].armed_sockets = None;
                let ipc = self.prepare_consumer_routes(index);
                self.activate_index(index, sockets, ipc).await
            }
            SupervisorEvent::IpcActivated { index, generation } => {
                if index >= self.components.len()
                    || !self.components[index].active
                    || self.components[index].generation != generation
                {
                    return Ok(());
                }
                if matches!(
                    self.components[index].status,
                    ComponentStatus::Unstarted | ComponentStatus::Completed
                ) {
                    let sockets = self.acquire_sockets_for(index).await?;
                    let ipc = self.prepare_consumer_routes(index);
                    self.activate_index(index, sockets, ipc).await
                } else {
                    Ok(())
                }
            }
            SupervisorEvent::RestartTimerFired { index, generation } => {
                if index >= self.components.len()
                    || !self.components[index].active
                    || self.components[index].generation != generation
                {
                    return Ok(());
                }
                let sockets = self.acquire_sockets_for(index).await?;
                let ipc = self.prepare_consumer_routes(index);
                self.activate_index(index, sockets, ipc).await
            }
            SupervisorEvent::ProviderExited {
                index,
                generation,
                outcome,
            } => {
                if index >= self.components.len()
                    || !self.components[index].active
                    || self.components[index].generation != generation
                {
                    return Ok(());
                }
                self.components[index].provider_installed = false;
                self.components[index].stop_tx = None;
                self.components[index].stopped_rx = None;
                let last_instance_id = self.components[index].instance_id.take();
                match outcome {
                    ProviderOutcome::Replaced | ProviderOutcome::Stopped => {
                        self.components[index].started_at_ms = None;
                        self.components[index].status = ComponentStatus::Unstarted;
                        self.publish_inspect();
                        Ok(())
                    }
                    ProviderOutcome::Exited => {
                        self.handle_termination(
                            index,
                            true,
                            "provider exited".to_owned(),
                            last_instance_id,
                        )
                        .await
                    }
                    ProviderOutcome::Faulted(reason) => {
                        self.handle_termination(
                            index,
                            false,
                            format!("provider faulted: {reason}"),
                            last_instance_id,
                        )
                        .await
                    }
                }
            }
            SupervisorEvent::ChildExited {
                index,
                generation,
                outcome,
            } => {
                if index >= self.components.len()
                    || !self.components[index].active
                    || self.components[index].generation != generation
                {
                    return Ok(());
                }
                self.components[index].stop_tx = None;
                self.components[index].stopped_rx = None;
                self.detach_exposed_bridges(index);
                let last_instance_id = self.components[index].instance_id.take();
                match outcome {
                    Ok(exit) if exit.is_operator_kill() => {
                        self.components[index].started_at_ms = None;
                        self.components[index].status = ComponentStatus::Completed;
                        self.publish_inspect();
                        Ok(())
                    }
                    Ok(exit) => {
                        let clean = exit.is_clean_success();
                        self.handle_termination(index, clean, exit.describe(), last_instance_id)
                            .await
                    }
                    Err(error) => {
                        self.handle_termination(
                            index,
                            false,
                            format!("wait failed: {error}"),
                            last_instance_id,
                        )
                        .await
                    }
                }
            }
        }
    }

    async fn handle_termination(
        &mut self,
        idx: usize,
        clean_success: bool,
        reason: String,
        last_instance_id: Option<u64>,
    ) -> Result<(), SupervisorError> {
        let now = self.runtime.now_ms();
        let window_ms = self.components[idx].node.burst_window_ms;
        if let Some(started_at_ms) = self.components[idx].started_at_ms.take()
            && now.saturating_sub(started_at_ms) >= window_ms
        {
            self.components[idx].consecutive_failures = 0;
        }

        let lifecycle = self.components[idx].node.lifecycle;
        let restart_policy = self.components[idx].node.restart;

        if clean_success
            && lifecycle == LifecycleKind::Oneshot
            && restart_policy != RestartPolicy::Always
        {
            self.components[idx].status = ComponentStatus::Completed;
            self.components[idx].consecutive_failures = 0;
            self.publish_inspect();
            self.enqueue_newly_unblocked_dependents(idx);
            return Ok(());
        }

        let should_restart = match restart_policy {
            RestartPolicy::Never => false,
            RestartPolicy::OnFailure => !clean_success,
            RestartPolicy::Always => true,
        };

        if !should_restart {
            if clean_success {
                self.components[idx].status = ComponentStatus::Completed;
                self.components[idx].consecutive_failures = 0;
                self.publish_inspect();
                // Re-arm lazy listening sockets when a lazy service stops cleanly.
                if self.components[idx].node.startup == StartupPolicy::Lazy
                    && !self.components[idx].node.sockets.is_empty()
                {
                    self.arm_lazy_sockets(idx).await?;
                }
                return Ok(());
            }
            self.components[idx].status = ComponentStatus::Failed;
            self.publish_inspect();
            return self
                .handle_unrecoverable_failure(idx, reason, last_instance_id)
                .await;
        }

        // Enforce burst-window circuit breaker before scheduling a restart.
        let limit = self.components[idx].node.burst_limit;
        let burst = &mut self.components[idx].burst_timestamps_ms;
        while let Some(&oldest) = burst.front() {
            if now.saturating_sub(oldest) >= window_ms {
                burst.pop_front();
            } else {
                break;
            }
        }
        if burst.len() as u32 >= limit {
            self.components[idx].status = ComponentStatus::Failed;
            self.publish_inspect();
            return self
                .handle_unrecoverable_failure(
                    idx,
                    format!(
                        "restart burst limit ({limit} restarts within {window_ms}ms) exceeded; last exit: {reason}"
                    ),
                    last_instance_id,
                )
                .await;
        }
        burst.push_back(now);

        let attempt = self.components[idx].consecutive_failures;
        self.components[idx].consecutive_failures = attempt.saturating_add(1);
        self.components[idx].restarts = self.components[idx].restarts.saturating_add(1);
        self.components[idx].status = ComponentStatus::Starting;
        let delay_ms = exponential_backoff_ms(
            self.components[idx].node.restart_backoff_ms,
            self.components[idx].node.restart_backoff_max_ms,
            attempt,
        );
        let generation = self.components[idx].generation;
        self.publish_inspect();

        let runtime = self.runtime.clone();
        let event_tx = self.event_tx.clone();
        self.runtime.spawn_task(async move {
            if delay_ms > 0 {
                runtime.sleep(Duration::from_millis(delay_ms)).await;
            }
            let _ = event_tx
                .send(SupervisorEvent::RestartTimerFired {
                    index: idx,
                    generation,
                })
                .await;
        });
        Ok(())
    }

    fn enqueue_newly_unblocked_dependents(&mut self, completed_idx: usize) {
        let dependents: Vec<usize> = (0..self.components.len())
            .filter(|&idx| {
                let c = &self.components[idx];
                c.active
                    && !c.node.runner.is_realm()
                    && c.node.startup == StartupPolicy::Eager
                    && c.status == ComponentStatus::Unstarted
                    && c.node.after.contains(&completed_idx)
                    && c.node.requires.satisfied_by(&self.hardware)
                    && self.dependencies_satisfied(idx)
            })
            .collect();
        for idx in dependents {
            self.pending_eager_activations.push_back(idx);
        }
    }

    async fn handle_unrecoverable_failure(
        &mut self,
        idx: usize,
        reason: String,
        last_instance_id: Option<u64>,
    ) -> Result<(), SupervisorError> {
        let criticality = self.components[idx].node.critical;
        match criticality {
            Criticality::None => Ok(()),
            Criticality::Parent => {
                if let Some(parent_idx) = self.components[idx].node.parent_index {
                    self.pending_realm_resets.push_back(parent_idx);
                }
                Ok(())
            }
            Criticality::System => {
                let component = self.components[idx].node.moniker.to_string();
                let instance_id = last_instance_id.or(self.components[idx].instance_id);
                let restart_count =
                    u32::try_from(self.components[idx].restarts).unwrap_or(u32::MAX);
                let action = self.components[idx].node.escalation;
                self.runtime
                    .escalate_fatal(FatalEscalation {
                        component: component.clone(),
                        instance_id,
                        reason: reason.clone(),
                        restart_count,
                        action,
                    })
                    .await?;
                Err(SupervisorError::FatalEscalated { component, reason })
            }
        }
    }

    /// Tears down every component inside `parent_idx`'s realm (honoring `stop_timeout_ms`),
    /// resets their restart/burst state, and returns the subtree indices ready for bring-up.
    async fn teardown_parent_realm(&mut self, parent_idx: usize) -> Vec<usize> {
        let mut subtree = Vec::new();
        self.collect_subtree(parent_idx, &mut subtree);

        // Stop descendants first, then parent.
        for &idx in subtree.iter().rev() {
            self.stop_index(idx).await;
            self.components[idx].status = ComponentStatus::Unstarted;
            self.components[idx].instance_id = None;
            self.components[idx].consecutive_failures = 0;
            self.components[idx].started_at_ms = None;
            self.components[idx].burst_timestamps_ms.clear();
            self.components[idx].provider_installed = false;
        }
        self.components[parent_idx].restarts =
            self.components[parent_idx].restarts.saturating_add(1);
        self.publish_inspect();
        subtree
    }

    fn collect_subtree(&self, root_idx: usize, out: &mut Vec<usize>) {
        if root_idx >= self.components.len() || !self.components[root_idx].active {
            return;
        }
        out.push(root_idx);
        let children: Vec<usize> = self.components[root_idx]
            .node
            .children_indices
            .iter()
            .copied()
            .collect();
        for child_idx in children {
            if child_idx < self.components.len() && self.components[child_idx].active {
                self.collect_subtree(child_idx, out);
            }
        }
    }

    async fn stop_index(&mut self, idx: usize) {
        self.components[idx].generation = self.components[idx].generation.wrapping_add(1);
        self.disarm_lazy_sockets(idx).await;
        self.detach_exposed_bridges(idx);
        self.components[idx].provider_installed = false;
        self.components[idx].started_at_ms = None;
        let stop_tx = self.components[idx].stop_tx.take();
        let stopped_rx = self.components[idx].stopped_rx.take();
        if let Some(tx) = stop_tx {
            let _ = tx.send(()).await;
        }
        if let Some(rx) = stopped_rx {
            let _ = rx.recv().await;
        }
        self.components[idx].instance_id = None;
        if !self.components[idx].node.runner.is_realm() {
            self.components[idx].status = ComponentStatus::Unstarted;
        }
    }

    #[cfg(feature = "dynamic-components")]
    pub(crate) async fn mount_validated_dynamic_subtree(
        &mut self,
        parent_moniker: &str,
        subtree: ComponentTopology,
    ) -> Result<String, SupervisorError> {
        let parent_idx =
            self.find_index(parent_moniker)
                .ok_or_else(|| SupervisorError::UnknownComponent {
                    moniker: parent_moniker.to_owned(),
                })?;
        crate::authority::validate_dynamic_subtree(&self.components[parent_idx].node, &subtree)?;

        // Check every incoming node (root AND descendants) for collisions against
        // all currently active components: monikers, provider slots, TCP/vsock sockets.
        let mut active_tcp: BTreeMap<(IpAddrSpec, u16), &str> = BTreeMap::new();
        let mut active_vsock: BTreeMap<u32, &str> = BTreeMap::new();
        let mut active_providers: BTreeMap<&'static str, &str> = BTreeMap::new();
        for existing in self.components.iter().filter(|c| c.active) {
            let existing_moniker = existing.node.moniker.as_ref();
            if let RunnerSpec::Wasm(wasm) = &existing.node.runner
                && let Some(slot) = wasm.provider
            {
                active_providers.insert(slot.as_str(), existing_moniker);
            }
            for sock in existing.node.sockets.iter() {
                match *sock {
                    SocketActivationSpec::Tcp { address, port, .. } => {
                        active_tcp.insert((address, port), existing_moniker);
                    }
                    SocketActivationSpec::Vsock { port, .. } => {
                        active_vsock.insert(port, existing_moniker);
                    }
                }
            }
        }
        for node in subtree.nodes.iter() {
            if self.find_index(node.moniker.as_ref()).is_some() {
                return Err(ValidationError::DuplicateMoniker {
                    moniker: node.moniker.to_string(),
                }
                .into());
            }
            if let RunnerSpec::Wasm(wasm) = &node.runner
                && let Some(slot) = wasm.provider
                && let Some(&first) = active_providers.get(slot.as_str())
            {
                return Err(ValidationError::DuplicateProviderSlot {
                    slot: slot.as_str(),
                    first: first.to_owned(),
                    second: node.moniker.to_string(),
                }
                .into());
            }
            for sock in node.sockets.iter() {
                match *sock {
                    SocketActivationSpec::Tcp { address, port, .. } => {
                        if let Some(&first) = active_tcp.get(&(address, port)) {
                            return Err(ValidationError::DuplicateSocket {
                                socket: format!("tcp:{address}:{port}"),
                                first: first.to_owned(),
                                second: node.moniker.to_string(),
                            }
                            .into());
                        }
                    }
                    SocketActivationSpec::Vsock { port, .. } => {
                        if let Some(&first) = active_vsock.get(&port) {
                            return Err(ValidationError::DuplicateSocket {
                                socket: format!("vsock:{port}"),
                                first: first.to_owned(),
                                second: node.moniker.to_string(),
                            }
                            .into());
                        }
                    }
                }
            }
        }

        let base_idx = self.components.len();
        let root_moniker = subtree.nodes[0].moniker.to_string();

        let mut added_indices = Vec::with_capacity(subtree.nodes.len());
        for (offset, mut node) in subtree.nodes.into_owned().into_iter().enumerate() {
            let new_idx = base_idx + offset;
            if offset == 0 {
                node.parent_index = Some(parent_idx);
            } else if let Some(rel_parent) = node.parent_index {
                node.parent_index = Some(base_idx + rel_parent);
            }
            let shifted_children: Vec<usize> = node
                .children_indices
                .iter()
                .map(|&c| base_idx + c)
                .collect();
            node.children_indices = std::borrow::Cow::Owned(shifted_children);
            let shifted_after: Vec<usize> = node.after.iter().map(|&d| base_idx + d).collect();
            node.after = std::borrow::Cow::Owned(shifted_after);
            let mut shifted_routes = node.routes.into_owned();
            for route in &mut shifted_routes {
                route.provider_index += base_idx;
            }
            node.routes = std::borrow::Cow::Owned(shifted_routes);
            self.components.push(ManagedComponent::new(node));
            added_indices.push(new_idx);
        }

        let mut parent_children = self.components[parent_idx].node.children_indices.to_vec();
        parent_children.push(base_idx);
        self.components[parent_idx].node.children_indices =
            std::borrow::Cow::Owned(parent_children);

        self.dynamic_subtrees
            .insert(root_moniker.clone(), added_indices.clone());
        self.bring_up_indices(&added_indices).await?;
        Ok(root_moniker)
    }

    #[cfg(feature = "dynamic-components")]
    pub(crate) async fn unmount_dynamic_subtree_by_moniker(
        &mut self,
        subtree_root_moniker: &str,
    ) -> Result<(), SupervisorError> {
        let Some(indices) = self.dynamic_subtrees.remove(subtree_root_moniker) else {
            return Err(SupervisorError::UnknownComponent {
                moniker: subtree_root_moniker.to_owned(),
            });
        };
        if let Some(&root_idx) = indices.first()
            && let Some(parent_idx) = self.components[root_idx].node.parent_index
        {
            let mut parent_children = self.components[parent_idx].node.children_indices.to_vec();
            parent_children.retain(|&c| c != root_idx);
            self.components[parent_idx].node.children_indices =
                std::borrow::Cow::Owned(parent_children);
        }
        for &idx in indices.iter().rev() {
            self.stop_index(idx).await;
            self.components[idx].active = false;
            self.components[idx].status = ComponentStatus::Completed;
            self.components[idx].exposed_bridges.clear();
        }
        self.publish_inspect();
        Ok(())
    }

    #[cfg(feature = "dynamic-components")]
    #[must_use]
    pub fn dynamic_subtree_monikers(&self) -> Vec<String> {
        self.dynamic_subtrees.keys().cloned().collect()
    }
}

fn is_provider_component(node: &ComponentNode) -> bool {
    matches!(
        &node.runner,
        RunnerSpec::Wasm(wasm) if wasm.provider.is_some()
    )
}

fn is_lazy_provider_slot(node: &ComponentNode) -> bool {
    matches!(
        &node.runner,
        RunnerSpec::Wasm(wasm)
            if matches!(
                wasm.provider,
                Some(ProviderSlot::Compiler | ProviderSlot::HttpClient)
            )
    )
}

fn optional_program_path(runner: &RunnerSpec) -> Option<&str> {
    match runner {
        RunnerSpec::Wasm(wasm) if wasm.optional => Some(wasm.program.as_ref()),
        RunnerSpec::Exec(exec) if exec.optional => Some(exec.program.as_ref()),
        _ => None,
    }
}

/// Awaits `wait_readable` across all pre-bound listening sockets without consuming
/// any queued connection, using concrete pinned futures with zero `dyn` dispatch.
async fn wait_any_socket_readable<T: TcpSocketListener, V: VsockSocketListener>(
    sockets: &[BoundSocket<T, V>],
) -> bool {
    if sockets.is_empty() {
        return false;
    }
    if sockets.len() == 1 {
        return wait_one_socket(&sockets[0]).await;
    }
    let mut futs: Vec<_> = sockets
        .iter()
        .map(|socket| Box::pin(wait_one_socket(socket)))
        .collect();
    future::poll_fn(|cx| {
        for fut in &mut futs {
            if let std::task::Poll::Ready(ready) = fut.as_mut().poll(cx) {
                return std::task::Poll::Ready(ready);
            }
        }
        std::task::Poll::Pending
    })
    .await
}

async fn wait_one_socket<T: TcpSocketListener, V: VsockSocketListener>(
    socket: &BoundSocket<T, V>,
) -> bool {
    loop {
        let res = match socket {
            BoundSocket::Tcp(tcp) => tcp.wait_readable().await,
            BoundSocket::Vsock(vsock) => vsock.wait_readable().await,
        };
        match res {
            Ok(true) => return true,
            Ok(false) => continue,
            Err(_) => return false,
        }
    }
}

/// Persistent supervisor-side duplex IPC bridge for one exposed channel on a provider.
///
/// Decouples consumer connections from provider process lifetimes so:
/// - Lazy unstarted providers activate on the first incoming consumer frame with zero byte loss,
/// - Concurrent consumers attaching before or during activation all deliver cleanly,
/// - Consumers connecting to an already-running or restarted provider route immediately without hanging.
async fn run_exposed_channel_bridge<R: SupervisorRuntime>(
    provider_idx: usize,
    initial_generation: u64,
    bridge_tx: Sender<BridgeMsg<R::IpcEnd>>,
    bridge_rx: Receiver<BridgeMsg<R::IpcEnd>>,
    runtime: R,
    event_tx: Sender<SupervisorEvent<R>>,
) {
    struct ActiveProvider {
        generation: u64,
        write_tx: Sender<Vec<u8>>,
    }

    let mut expected_generation = initial_generation;
    let mut activation_requested = false;
    let mut active_provider: Option<ActiveProvider> = None;
    let mut next_consumer_id: u64 = 1;
    let mut consumers: BTreeMap<u64, Sender<Vec<u8>>> = BTreeMap::new();
    let mut active_consumer: Option<u64> = None;
    let mut pending_frames: VecDeque<(u64, Vec<u8>)> = VecDeque::new();

    while let Ok(msg) = bridge_rx.recv().await {
        match msg {
            BridgeMsg::Shutdown => break,
            BridgeMsg::AttachConsumer(server_end) => {
                let id = next_consumer_id;
                next_consumer_id = next_consumer_id.saturating_add(1);
                let ep = Rc::new(server_end);
                let (reply_tx, reply_rx) = async_channel::unbounded::<Vec<u8>>();
                consumers.insert(id, reply_tx);

                let reader_ep = Rc::clone(&ep);
                let reader_tx = bridge_tx.clone();
                runtime.spawn_task(async move {
                    while let Ok(Some(bytes)) = reader_ep.read(IPC_PROXY_CHUNK_BYTES).await {
                        if bytes.is_empty() {
                            continue;
                        }
                        if reader_tx
                            .send(BridgeMsg::ConsumerData { id, bytes })
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    let _ = reader_tx.send(BridgeMsg::ConsumerClosed { id }).await;
                });

                runtime.spawn_task(async move {
                    while let Ok(bytes) = reply_rx.recv().await {
                        if ep.write(bytes).await.is_err() {
                            break;
                        }
                    }
                    ep.close_write();
                });
            }
            BridgeMsg::ConsumerData { id, bytes } => {
                if !consumers.contains_key(&id) {
                    continue;
                }
                if let Some(provider) = active_provider.as_ref() {
                    active_consumer = Some(id);
                    if provider.write_tx.send(bytes.clone()).await.is_err() {
                        active_provider = None;
                        pending_frames.push_back((id, bytes));
                        if !activation_requested {
                            activation_requested = true;
                            let _ = event_tx
                                .send(SupervisorEvent::IpcActivated {
                                    index: provider_idx,
                                    generation: expected_generation,
                                })
                                .await;
                        }
                    }
                } else {
                    pending_frames.push_back((id, bytes));
                    if !activation_requested {
                        activation_requested = true;
                        let _ = event_tx
                            .send(SupervisorEvent::IpcActivated {
                                index: provider_idx,
                                generation: expected_generation,
                            })
                            .await;
                    }
                }
            }
            BridgeMsg::ConsumerClosed { id } => {
                consumers.remove(&id);
                if active_consumer == Some(id) {
                    active_consumer = consumers.keys().next().copied();
                }
            }
            BridgeMsg::AttachProvider {
                generation,
                proxy_end,
            } => {
                expected_generation = generation;
                activation_requested = false;
                drop(active_provider.take());

                let ep = Rc::new(proxy_end);
                let (write_tx, write_rx) = async_channel::unbounded::<Vec<u8>>();

                let reader_ep = Rc::clone(&ep);
                let reader_tx = bridge_tx.clone();
                runtime.spawn_task(async move {
                    while let Ok(Some(bytes)) = reader_ep.read(IPC_PROXY_CHUNK_BYTES).await {
                        if bytes.is_empty() {
                            continue;
                        }
                        if reader_tx
                            .send(BridgeMsg::ProviderData { generation, bytes })
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    let _ = reader_tx
                        .send(BridgeMsg::ProviderClosed { generation })
                        .await;
                });

                runtime.spawn_task(async move {
                    while let Ok(bytes) = write_rx.recv().await {
                        if ep.write(bytes).await.is_err() {
                            break;
                        }
                    }
                    ep.close_write();
                });

                while let Some((cid, frame)) = pending_frames.pop_front() {
                    if consumers.contains_key(&cid) {
                        active_consumer = Some(cid);
                    }
                    if write_tx.send(frame).await.is_err() {
                        break;
                    }
                }
                active_provider = Some(ActiveProvider {
                    generation,
                    write_tx,
                });
            }
            BridgeMsg::DetachProvider { next_generation } => {
                expected_generation = next_generation;
                active_provider = None;
                activation_requested = false;
            }
            BridgeMsg::ProviderData { generation, bytes } => {
                if !active_provider
                    .as_ref()
                    .is_some_and(|provider| provider.generation == generation)
                {
                    continue;
                }
                let target = active_consumer.or_else(|| consumers.keys().next().copied());
                if let Some(cid) = target
                    && let Some(reply_tx) = consumers.get(&cid)
                {
                    let _ = reply_tx.send(bytes).await;
                }
            }
            BridgeMsg::ProviderClosed { generation } => {
                if active_provider
                    .as_ref()
                    .is_some_and(|provider| provider.generation == generation)
                {
                    active_provider = None;
                }
            }
        }
    }
}

/// Drives a running child handle until it exits naturally OR `stop_rx` triggers
/// graceful `SIGTERM` + `stop_timeout` + forced `SIGKILL` teardown.
async fn child_wait_with_graceful_stop<R: SupervisorRuntime>(
    child: R::Child,
    stop_rx: Receiver<()>,
    stop_timeout: Duration,
    runtime: R,
) -> Option<Result<ExitOutcome, RuntimeError>> {
    enum RaceResult {
        Exited(Result<ExitOutcome, RuntimeError>),
        StopRequested,
    }

    let wait_outcome = async { RaceResult::Exited(child.wait().await) }
        .or(async {
            let _ = stop_rx.recv().await;
            RaceResult::StopRequested
        })
        .await;

    match wait_outcome {
        RaceResult::Exited(res) => Some(res),
        RaceResult::StopRequested => {
            let _ = child.signal(SIGTERM);
            // Allow graceful exit within `stop_timeout`; force-kill on expiry.
            let _ = async {
                let _ = child.wait().await;
            }
            .or(async {
                runtime.sleep(stop_timeout).await;
                let _ = child.signal(SIGKILL);
            })
            .await;
            drop(child);
            None
        }
    }
}
