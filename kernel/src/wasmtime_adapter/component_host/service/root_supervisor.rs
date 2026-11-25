//! Host implementation of `helios:system/root-supervisor@0.1.0`.
//!
//! Granted exclusively to the single signed root component booted by the
//! kernel (`ComponentBindingSet::RootSupervisor` + non-delegable
//! [`crate::RootSupervisorCap`]). Every ordinary component linker omits this
//! interface altogether, and every host method checks `RootSupervisorCap` on
//! entry as defense in depth.
//!
//! # Concurrency contract
//!
//! - Provider installations (`surface`, `http-client`, `compiler`) assign a
//!   monotonic `u64` generation so stale [`ProviderHandle`] stops or drops
//!   never displace a newer provider endpoint.
//! - Surface provider replacement waits for any displaced compositor instance
//!   to unwind and drop its `Store` (releasing exclusive display and input
//!   claims) before launching the replacement instance.
//! - Hardware inventory subscriptions arm both `RuntimeState` and
//!   `DeviceGrantRegistry` [`crate::NotifyWaiter`]s before comparing the
//!   combined hardware generation, so no discovery publication or service
//!   bring-up is missed.

use alloc::borrow::ToOwned;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::pin::{Pin, pin};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use core::task::{Context, Poll};
use core::time::Duration;

use bytes::Bytes;
use helios_hal::cpu::Cpu;
use spin::Mutex;
use wasmtime::StoreContextMut;
use wasmtime::component::{
    Access, Accessor, Destination, HasSelf, Linker, Resource, ResourceAny, StreamProducer,
    StreamReader, StreamResult,
};

use super::component_plugin::{HTTP_PROVIDER_QUEUE_DEPTH, ProviderStoreSpec, open_provider_store};
use super::*;
use crate::buffer::Span;
use crate::surface::{
    SURFACE_REQUEST_QUEUE_DEPTH, SurfaceCreate, SurfaceId, SurfaceRequest, SurfaceService,
    SurfaceServiceError,
};
use crate::wasmtime_adapter::bindings::compositor::bindings::{CompositorHost, exports};
use crate::wasmtime_adapter::bindings::root_supervisor::bindings::helios::system::root_supervisor as rs_wit;
use crate::wasmtime_adapter::component_host::{guest_memory, view_trap};
use crate::{
    ComponentHostNetwork, DeviceClassRights, DeviceName, DiagnosticAuthorityRights,
    FatalEscalationAction, FatalEscalationRecord, InstanceId, MachineAuthorityRights, Notify,
    NotifyWaiter, OomPolicy, ProcessAuthority, ProviderReceiver, ProviderSender,
    SettingsAuthorityRights, provider_channel,
};

/// Maximum time fatal escalation waits for writable mounts to flush before
/// proceeding to halt/reboot, so a wedged block device cannot hang escalation.
const FATAL_MOUNT_FLUSH_TIMEOUT: Duration = Duration::from_secs(5);

/// Builds the exclusive authority granted to the single signed root component
/// booted by the kernel.
///
/// Carries all standard root rights, every device class, every discovered raw
/// `DeviceName` grant, full machine observation/control/settings/virtualize
/// rights, and the non-delegable `root_supervisor` capability.
pub(crate) fn root_supervisor_authority<CpuImpl, Net, StorageImpl>(
    runtime_state: &HostRuntimeState<CpuImpl, Net, StorageImpl>,
) -> ProcessAuthority
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let mut authority = ProcessAuthority::root();
    authority.grant_device_classes(DeviceClassRights::all());
    for device in runtime_state.device_grants().devices() {
        let _ = authority.grant_device(*device.grant().name());
    }
    authority.grant_inspect_read(AuthorityScope::Machine);
    authority.grant_trace_read(AuthorityScope::Machine);
    authority.grant_profile_read(AuthorityScope::Machine);
    authority.grant_diagnostic_rights(DiagnosticAuthorityRights::CONTROL);
    authority.grant_instance_control(AuthorityScope::Machine);
    authority.grant_settings_rights(SettingsAuthorityRights::WRITE);
    authority.grant_machine_rights(
        MachineAuthorityRights::CONTROL
            | MachineAuthorityRights::IDENTITY
            | MachineAuthorityRights::VIRTUALIZE,
    );
    authority.grant_root_supervisor();
    authority
}

/// Register `helios:system/root-supervisor@0.1.0` into the linker.
///
/// Called ONLY for `ComponentBindingSet::RootSupervisor` (the single signed
/// root component). Never called for `ComponentBindingSet::Program`.
pub(in crate::wasmtime_adapter::component_host) fn add_root_supervisor_to_linker<
    CpuImpl,
    Net,
    StorageImpl,
>(
    linker: &mut Linker<StoreData<CpuImpl, Net, StorageImpl>>,
) -> wasmtime::Result<()>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    rs_wit::add_to_linker::<_, HasSelf<StoreData<CpuImpl, Net, StorageImpl>>>(linker, |state| state)
}

/// Why a root-supervisor-managed provider ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ProviderExitReason {
    Exited,
    Replaced,
    Stopped,
    Faulted(String),
}

/// Shared lifecycle state between a [`ProviderHandle`] and the kernel slot or
/// runner task backing that provider generation.
pub(crate) struct ProviderControl {
    instance_id: AtomicU64,
    stop_requested: AtomicBool,
    stop_notify: Notify,
    done: AtomicBool,
    done_notify: Notify,
    exit: Mutex<Option<ProviderExitReason>>,
    exit_notify: Notify,
}

impl ProviderControl {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            instance_id: AtomicU64::new(0),
            stop_requested: AtomicBool::new(false),
            stop_notify: Notify::new(),
            done: AtomicBool::new(false),
            done_notify: Notify::new(),
            exit: Mutex::new(None),
            exit_notify: Notify::new(),
        })
    }

    pub(crate) fn set_instance_id(&self, id: InstanceId) {
        self.instance_id.store(id.raw(), Ordering::Release);
    }

    pub(crate) fn instance_id(&self) -> Option<InstanceId> {
        let raw = self.instance_id.load(Ordering::Acquire);
        (raw != 0).then(|| InstanceId::from_raw(raw))
    }

    pub(crate) fn request_stop(&self) {
        self.stop_requested.store(true, Ordering::Release);
        self.stop_notify.notify_all();
    }

    pub(crate) fn is_stop_requested(&self) -> bool {
        self.stop_requested.load(Ordering::Acquire)
    }

    pub(crate) fn record_exit(&self, reason: ProviderExitReason) {
        let mut slot = self.exit.lock();
        if slot.is_none() {
            *slot = Some(reason);
        }
        drop(slot);
        self.exit_notify.notify_all();
    }

    pub(crate) fn finish_faulted(&self, message: String) {
        self.record_exit(ProviderExitReason::Faulted(message));
        self.mark_done();
    }

    pub(crate) fn mark_done(&self) {
        self.done.store(true, Ordering::Release);
        self.done_notify.notify_all();
    }

    pub(crate) async fn wait_done(&self) {
        loop {
            let notified = self.done_notify.notified();
            if self.done.load(Ordering::Acquire) {
                return;
            }
            notified.await;
        }
    }

    pub(crate) async fn wait_exit(&self) -> ProviderExitReason {
        loop {
            let notified = self.exit_notify.notified();
            if let Some(reason) = self.exit.lock().clone() {
                return reason;
            }
            notified.await;
        }
    }
}

/// Which kernel provider slot a [`ProviderHandle`] governs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProviderSlotKind {
    Surface { generation: u64 },
    Http { generation: u64 },
    Compiler { generation: u64 },
}

/// Owned handle to a root-supervisor-installed kernel provider endpoint.
///
/// Non-generic so `bindgen!` maps `helios:system/root-supervisor.provider-handle`
/// directly to it without dynamic dispatch.
pub struct ProviderHandle {
    kind: ProviderSlotKind,
    control: Arc<ProviderControl>,
}

impl ProviderHandle {
    pub(crate) fn new(kind: ProviderSlotKind, control: Arc<ProviderControl>) -> Self {
        Self { kind, control }
    }

    pub(crate) fn kind(&self) -> ProviderSlotKind {
        self.kind
    }

    pub(crate) fn control(&self) -> &Arc<ProviderControl> {
        &self.control
    }
}

impl Drop for ProviderHandle {
    fn drop(&mut self) {
        self.control.request_stop();
        self.control.record_exit(ProviderExitReason::Stopped);
    }
}

/// Active singleton `surface` (compositor) provider registration owned by
/// [`UserProgramService`].
pub(super) struct SurfaceProviderRegistration {
    pub(super) generation: u64,
    pub(super) sender: ProviderSender<SurfaceRequest>,
    pub(super) control: Arc<ProviderControl>,
}

/// Active per-processor `wasi:http/client` provider registration owned by
/// [`UserProgramService`].
pub(super) struct HttpProviderRegistration<CpuImpl, Net, StorageImpl>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    pub(super) generation: u64,
    pub(super) name: String,
    pub(super) path: String,
    pub(super) authority: ProcessAuthority,
    pub(super) oom_policy: OomPolicy,
    pub(super) parent_instance_id: Option<InstanceId>,
    pub(super) precompiled: PreparedComponent<CpuImpl, Net, StorageImpl>,
    pub(super) control: Arc<ProviderControl>,
}

/// Active AOT `compiler` provider registration owned by [`UserProgramService`].
#[derive(Clone)]
pub(super) struct CompilerProviderRegistration {
    pub(super) generation: u64,
    pub(super) name: String,
    pub(super) path: String,
    pub(super) payload: Bytes,
    pub(super) oom_policy: OomPolicy,
    pub(super) parent_instance_id: Option<InstanceId>,
    pub(super) control: Arc<ProviderControl>,
}

fn supervisor_error(
    kind: rs_wit::SupervisorErrorKind,
    detail: impl Into<String>,
) -> rs_wit::SupervisorError {
    rs_wit::SupervisorError {
        kind,
        detail: detail.into(),
    }
}

fn permission_denied(detail: impl Into<String>) -> rs_wit::SupervisorError {
    supervisor_error(rs_wit::SupervisorErrorKind::PermissionDenied, detail)
}

fn from_wit_oom_policy(policy: rs_wit::OomPolicy) -> OomPolicy {
    match policy {
        rs_wit::OomPolicy::UserProgram => OomPolicy::UserProgram,
        rs_wit::OomPolicy::KernelPlugin => OomPolicy::KernelPlugin,
        rs_wit::OomPolicy::SystemComponent => OomPolicy::SystemComponent,
    }
}

fn map_exec_error(error: ProgramExecError) -> rs_wit::SupervisorError {
    let kind = match error.kind {
        ProgramExecErrorKind::PermissionDenied => rs_wit::SupervisorErrorKind::PermissionDenied,
        ProgramExecErrorKind::InvalidBinary
        | ProgramExecErrorKind::MissingEntry
        | ProgramExecErrorKind::UnsupportedImport
        | ProgramExecErrorKind::InvalidSignature => rs_wit::SupervisorErrorKind::InvalidBinary,
        ProgramExecErrorKind::InvalidPath => rs_wit::SupervisorErrorKind::InvalidPath,
        ProgramExecErrorKind::InvalidHint => rs_wit::SupervisorErrorKind::InvalidArgument,
        ProgramExecErrorKind::NotFound => rs_wit::SupervisorErrorKind::NotFound,
        ProgramExecErrorKind::Io => rs_wit::SupervisorErrorKind::Io,
        ProgramExecErrorKind::OutOfMemory => rs_wit::SupervisorErrorKind::OutOfMemory,
        ProgramExecErrorKind::Unavailable => rs_wit::SupervisorErrorKind::Unavailable,
        ProgramExecErrorKind::Internal => rs_wit::SupervisorErrorKind::Internal,
    };
    supervisor_error(kind, error.detail.as_str())
}

fn require_root_supervisor<CpuImpl, Net, StorageImpl>(
    data: &StoreData<CpuImpl, Net, StorageImpl>,
) -> Result<crate::RootSupervisorCap, rs_wit::SupervisorError>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    data.process_authority()
        .derive_root_supervisor_cap()
        .map_err(|error| permission_denied(error.to_string()))
}

fn check_oom_ceiling(
    caller_policy: OomPolicy,
    requested: OomPolicy,
) -> Result<(), rs_wit::SupervisorError> {
    if caller_policy.admits(requested) {
        Ok(())
    } else {
        Err(permission_denied(format!(
            "requested OOM policy {requested:?} exceeds caller ceiling {caller_policy:?}"
        )))
    }
}

fn snapshot_hardware_inventory<CpuImpl, Net, StorageImpl>(
    cpu: &CpuImpl,
    runtime_state: &HostRuntimeState<CpuImpl, Net, StorageImpl>,
) -> rs_wit::HardwareInventory
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let devices = runtime_state
        .device_grants()
        .snapshot()
        .into_iter()
        .map(|device| rs_wit::DeviceGrantInfo {
            name: device.name.as_str().to_owned(),
            regions: device.regions,
            interrupt_count: device.interrupt_count,
            dma_budget_bytes: device.dma_budget_bytes,
            confined: device.confined,
            claimed: device.claimed,
        })
        .collect();
    let input_device_count = runtime_state
        .input_service()
        .map_or(0, |service| service.device_count() as u32);
    rs_wit::HardwareInventory {
        devices,
        display: runtime_state.display_service().is_some(),
        input: input_device_count > 0,
        input_device_count,
        gpu: runtime_state
            .gpu3d_service()
            .is_some_and(|service| service.renders()),
        audio: runtime_state.audio_service().is_some(),
        hv: cpu.hv().is_some(),
        native: cpu.native().is_ok(),
        vsock: runtime_state.vsock_service().is_some(),
    }
}

fn grant_named_devices<CpuImpl, Net, StorageImpl>(
    runtime_state: &HostRuntimeState<CpuImpl, Net, StorageImpl>,
    child_authority: &mut ProcessAuthority,
    named_devices: &[String],
) -> Result<(), rs_wit::SupervisorError>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    for raw_name in named_devices {
        let name = DeviceName::new(raw_name).map_err(|_| {
            supervisor_error(
                rs_wit::SupervisorErrorKind::InvalidArgument,
                format!("device name `{raw_name}` exceeds maximum length"),
            )
        })?;
        if runtime_state
            .device_grants()
            .device(name.as_str())
            .is_none()
        {
            return Err(supervisor_error(
                rs_wit::SupervisorErrorKind::NotFound,
                format!("device `{raw_name}` is not published in the device grant registry"),
            ));
        }
        child_authority.grant_device(name).map_err(|error| {
            supervisor_error(
                rs_wit::SupervisorErrorKind::InvalidArgument,
                error.to_string(),
            )
        })?;
    }
    Ok(())
}

/// Async stream yielding the initial [`rs_wit::HardwareInventory`] immediately
/// and a fresh snapshot whenever hardware services or device grants change.
struct HardwareInventoryStreamProducer<T, CpuImpl, Net, StorageImpl>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    getter: fn(&mut T) -> &mut StoreData<CpuImpl, Net, StorageImpl>,
    emitted_initial: bool,
    seen_generation: u64,
    waiters: Option<(NotifyWaiter, NotifyWaiter)>,
}

impl<T, CpuImpl, Net, StorageImpl> Unpin
    for HardwareInventoryStreamProducer<T, CpuImpl, Net, StorageImpl>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
}

impl<T, CpuImpl, Net, StorageImpl> HardwareInventoryStreamProducer<T, CpuImpl, Net, StorageImpl>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    const fn new(getter: fn(&mut T) -> &mut StoreData<CpuImpl, Net, StorageImpl>) -> Self {
        Self {
            getter,
            emitted_initial: false,
            seen_generation: 0,
            waiters: None,
        }
    }
}

impl<T, CpuImpl, Net, StorageImpl> StreamProducer<T>
    for HardwareInventoryStreamProducer<T, CpuImpl, Net, StorageImpl>
where
    T: 'static,
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    type Item = rs_wit::HardwareInventory;
    type Buffer = Option<Self::Item>;

    fn poll_produce<'a>(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut store: StoreContextMut<'_, T>,
        mut destination: Destination<'a, Self::Item, Self::Buffer>,
        finish: bool,
    ) -> Poll<wasmtime::Result<StreamResult>> {
        if finish {
            return Poll::Ready(Ok(StreamResult::Cancelled));
        }
        let producer = &mut *self;
        let data = (producer.getter)(store.data_mut());
        if !producer.emitted_initial {
            producer.emitted_initial = true;
            producer.seen_generation = data.runtime_state.hardware_generation();
            destination.set_buffer(Some(snapshot_hardware_inventory(
                &data.cpu,
                &data.runtime_state,
            )));
            return Poll::Ready(Ok(StreamResult::Completed));
        }
        let (service_waiter, device_waiter) = producer
            .waiters
            .get_or_insert_with(|| data.runtime_state.hardware_waiters());
        match data.runtime_state.poll_hardware_changed(
            cx,
            service_waiter,
            device_waiter,
            producer.seen_generation,
        ) {
            Poll::Ready(generation) => {
                producer.seen_generation = generation;
                destination.set_buffer(Some(snapshot_hardware_inventory(
                    &data.cpu,
                    &data.runtime_state,
                )));
                Poll::Ready(Ok(StreamResult::Completed))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

fn stop_provider_in_store<CpuImpl, Net, StorageImpl>(
    data: &StoreData<CpuImpl, Net, StorageImpl>,
    handle: &ProviderHandle,
) where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    handle.control().request_stop();
    handle.control().record_exit(ProviderExitReason::Stopped);
    let Some(service) = data.runtime_state.program_service() else {
        return;
    };
    match handle.kind() {
        ProviderSlotKind::Surface { generation } => {
            service.stop_surface_provider(&data.runtime_state, generation);
        }
        ProviderSlotKind::Http { generation } => {
            service.stop_http_provider(&data.runtime_state, generation);
        }
        ProviderSlotKind::Compiler { generation } => {
            service.stop_compiler_provider(generation);
        }
    }
}

impl<CpuImpl, Net, StorageImpl> rs_wit::HostProviderHandle for StoreData<CpuImpl, Net, StorageImpl>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    fn instance_id(&mut self, handle: Resource<ProviderHandle>) -> wasmtime::Result<Option<u64>> {
        let provider = self.table.get(&handle)?;
        Ok(provider.control().instance_id().map(InstanceId::raw))
    }

    fn stop(&mut self, handle: Resource<ProviderHandle>) -> wasmtime::Result<()> {
        let provider = self.table.get(&handle)?;
        let kind = provider.kind();
        let control = provider.control().clone();
        stop_provider_in_store(self, &ProviderHandle::new(kind, control));
        Ok(())
    }

    fn drop(&mut self, handle: Resource<ProviderHandle>) -> wasmtime::Result<()> {
        let provider = self.table.delete(handle)?;
        stop_provider_in_store(self, &provider);
        Ok(())
    }
}

impl<CpuImpl, Net, StorageImpl, U> rs_wit::HostProviderHandleWithStore<U>
    for HasSelf<StoreData<CpuImpl, Net, StorageImpl>>
where
    U: 'static,
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    async fn wait_exit(
        accessor: &Accessor<U, Self>,
        handle: Resource<ProviderHandle>,
    ) -> wasmtime::Result<rs_wit::ProviderExit> {
        let control = accessor.with(|mut access| {
            let provider = access.get().table.get(&handle)?;
            Ok::<_, wasmtime::Error>(provider.control().clone())
        })?;
        Ok(match control.wait_exit().await {
            ProviderExitReason::Exited => rs_wit::ProviderExit::Exited,
            ProviderExitReason::Replaced => rs_wit::ProviderExit::Replaced,
            ProviderExitReason::Stopped => rs_wit::ProviderExit::Stopped,
            ProviderExitReason::Faulted(detail) => rs_wit::ProviderExit::Faulted(detail),
        })
    }
}

impl<CpuImpl, Net, StorageImpl> rs_wit::Host for StoreData<CpuImpl, Net, StorageImpl>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    fn get_hardware_inventory(
        &mut self,
    ) -> wasmtime::Result<Result<rs_wit::HardwareInventory, rs_wit::SupervisorError>> {
        if let Err(error) = require_root_supervisor(self) {
            return Ok(Err(error));
        }
        Ok(Ok(snapshot_hardware_inventory(
            &self.cpu,
            &self.runtime_state,
        )))
    }
}

impl<CpuImpl, Net, StorageImpl, U> rs_wit::HostWithStore<U>
    for HasSelf<StoreData<CpuImpl, Net, StorageImpl>>
where
    U: 'static,
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    fn subscribe_hardware(
        mut access: Access<'_, U, Self>,
    ) -> wasmtime::Result<Result<StreamReader<rs_wit::HardwareInventory>, rs_wit::SupervisorError>>
    {
        if let Err(error) = require_root_supervisor(access.get()) {
            return Ok(Err(error));
        }
        let getter = access.getter();
        let reader = StreamReader::new(&mut access, HardwareInventoryStreamProducer::new(getter))?;
        Ok(Ok(reader))
    }

    async fn spawn(
        accessor: &Accessor<U, Self>,
        request: rs_wit::ManagedSpawnRequest,
    ) -> wasmtime::Result<Result<Resource<ChildHandle>, rs_wit::SupervisorError>> {
        let rs_wit::ManagedSpawnRequest {
            name,
            args,
            env,
            path,
            cwd,
            sockets,
            capability_grants,
            named_devices,
            oom_policy,
        } = request;
        let requested_policy = from_wit_oom_policy(oom_policy);
        let snapshot = accessor.with(|mut access| {
            let data = access.get();
            if let Err(error) = require_root_supervisor(data) {
                return Ok::<_, wasmtime::Error>(Err(error));
            }
            let caller_policy = data.instance().oom_policy();
            if let Err(error) = check_oom_ceiling(caller_policy, requested_policy) {
                return Ok(Err(error));
            }
            let service = data.runtime_state.program_service();
            let context = ProgramExecContext::from_store(data);
            let caller_authority = data.process_authority().clone();
            let caller_id = data.instance().id();
            let caller_filesystem = data.filesystem().clone();
            let caller_default_linux_image = data.default_linux_image();
            let runtime_state = data.runtime_state.clone();
            let (remaining_grants, ipc_grants, _had_ipc) =
                extract_program_ipc_grants(&mut data.table, capability_grants)?;
            let ipc_grants = match ipc_grants {
                Ok(grants) => grants,
                Err(error) => return Ok(Err(map_exec_error(error))),
            };
            let mut extracted_sockets = Vec::with_capacity(sockets.len());
            for socket in sockets {
                match socket {
                    program_bindings::helios::system::programs::InheritedSocket::Tcp(res) => {
                        let mut listener = data.table.delete(res)?;
                        match crate::InheritedSocket::from_tcp_listener(&mut listener) {
                            Some(inherited) => extracted_sockets.push(inherited),
                            None => {
                                return Ok(Err(supervisor_error(
                                    rs_wit::SupervisorErrorKind::Unavailable,
                                    "inherited TCP listener is closed",
                                )));
                            }
                        }
                    }
                    program_bindings::helios::system::programs::InheritedSocket::Vsock(res) => {
                        let mut listener = data.table.delete(res)?;
                        match listener.take() {
                            Some((vsock_service, id)) => {
                                extracted_sockets.push(
                                    crate::InheritedSocket::from_vsock_listener(vsock_service, id),
                                );
                            }
                            None => {
                                return Ok(Err(supervisor_error(
                                    rs_wit::SupervisorErrorKind::Unavailable,
                                    "inherited vsock listener is closed",
                                )));
                            }
                        }
                    }
                }
            }
            Ok(Ok((
                service,
                context,
                caller_authority,
                caller_id,
                caller_filesystem,
                caller_default_linux_image,
                runtime_state,
                ipc_grants,
                remaining_grants,
                crate::InheritedSockets::from_vec(extracted_sockets),
            )))
        })?;
        let (
            service,
            context,
            caller_authority,
            caller_id,
            caller_filesystem,
            caller_default_linux_image,
            runtime_state,
            ipc_grants,
            remaining_grants,
            inherited_sockets,
        ) = match snapshot {
            Ok(values) => values,
            Err(error) => return Ok(Err(error)),
        };
        let Some(service) = service else {
            return Ok(Err(supervisor_error(
                rs_wit::SupervisorErrorKind::Unavailable,
                "program service is unavailable on this machine",
            )));
        };
        let spawn_authority = match caller_authority.derive_spawn_authority() {
            Ok(auth) => auth,
            Err(error) => {
                return Ok(Err(permission_denied(error.to_string())));
            }
        };
        let compile_authority = CompileAuthority::from(&spawn_authority);
        let child_instance = context.instance_registry().register_child_with_policy(
            context.parent_instance_id(),
            name.clone(),
            context.now_uptime_nanos(),
            requested_policy,
        );
        let mut child_authority = match build_program_child_authority(
            &caller_authority,
            caller_id,
            Some(child_instance.id()),
            context.instance_registry(),
            remaining_grants,
        ) {
            Ok(authority) => authority,
            Err(error) => return Ok(Err(map_exec_error(error))),
        };
        if let Err(error) =
            grant_named_devices(&runtime_state, &mut child_authority, &named_devices)
        {
            return Ok(Err(error));
        }
        let source = match read_program_source(accessor, &path, &caller_authority).await? {
            Ok(source) => source,
            Err(error) => return Ok(Err(map_exec_error(error))),
        };
        let launch = ProgramLaunch::new(
            ProgramArgv::launched(name, args),
            env,
            child_authority,
            Some(caller_filesystem.descend()),
        )
        .with_launched_instance(child_instance)
        .with_oom_policy(requested_policy)
        .with_ipc_grants(ipc_grants)
        .with_default_linux_image(caller_default_linux_image)
        .with_inherited_sockets(inherited_sockets)
        .with_cwd(cwd);
        let child = match service
            .spawn(&compile_authority, context, source, None, launch)
            .await
        {
            Ok(child) => child,
            Err(error) => return Ok(Err(map_exec_error(error))),
        };
        let handle = accessor.with(|mut access| access.get().table.push(child))?;
        Ok(Ok(handle))
    }

    async fn install_surface_provider(
        accessor: &Accessor<U, Self>,
        request: rs_wit::ProviderRequest,
    ) -> wasmtime::Result<Result<Resource<ProviderHandle>, rs_wit::SupervisorError>> {
        let prepared = match prepare_component_provider(accessor, request).await? {
            Ok(prepared) => prepared,
            Err(error) => return Ok(Err(error)),
        };
        let handle = match prepared
            .service
            .install_surface_provider(
                prepared.context,
                prepared.name,
                prepared.path,
                prepared.authority,
                prepared.oom_policy,
                prepared.precompiled,
            )
            .await
        {
            Ok(handle) => handle,
            Err(error) => return Ok(Err(error)),
        };
        let resource = accessor.with(|mut access| access.get().table.push(handle))?;
        Ok(Ok(resource))
    }

    async fn install_http_provider(
        accessor: &Accessor<U, Self>,
        request: rs_wit::ProviderRequest,
    ) -> wasmtime::Result<Result<Resource<ProviderHandle>, rs_wit::SupervisorError>> {
        let prepared = match prepare_component_provider(accessor, request).await? {
            Ok(prepared) => prepared,
            Err(error) => return Ok(Err(error)),
        };
        if prepared
            .precompiled
            .component()
            .component_type()
            .get_export(prepared.service.engine().raw(), "wasi:http/handler@0.3.0")
            .is_none()
        {
            return Ok(Err(supervisor_error(
                rs_wit::SupervisorErrorKind::InvalidBinary,
                format!(
                    "component `{}` does not export wasi:http/handler@0.3.0",
                    prepared.path
                ),
            )));
        }
        let service = prepared.service.clone();
        let handle = service.install_http_provider(prepared);
        let resource = accessor.with(|mut access| access.get().table.push(handle))?;
        Ok(Ok(resource))
    }

    async fn install_compiler_provider(
        accessor: &Accessor<U, Self>,
        request: rs_wit::ProviderRequest,
    ) -> wasmtime::Result<Result<Resource<ProviderHandle>, rs_wit::SupervisorError>> {
        let rs_wit::ProviderRequest {
            name,
            path,
            capability_grants,
            named_devices,
            oom_policy,
        } = request;
        if name.is_empty() {
            return Ok(Err(supervisor_error(
                rs_wit::SupervisorErrorKind::InvalidArgument,
                "provider name must not be empty",
            )));
        }
        let requested_policy = from_wit_oom_policy(oom_policy);
        let snapshot = accessor.with(|mut access| {
            let data = access.get();
            // Always drain any owned IPC resource handles from the caller's
            // resource table so rejected requests never leak table entries.
            let (remaining_grants, ipc_grants, had_ipc) =
                extract_program_ipc_grants(&mut data.table, capability_grants)?;
            if let Err(error) = require_root_supervisor(data) {
                return Ok::<_, wasmtime::Error>(Err(error));
            }
            if let Err(error) = check_oom_ceiling(data.instance().oom_policy(), requested_policy) {
                return Ok(Err(error));
            }
            if !remaining_grants.is_empty()
                || had_ipc
                || ipc_grants.is_err()
                || !named_devices.is_empty()
            {
                return Ok(Err(supervisor_error(
                    rs_wit::SupervisorErrorKind::InvalidArgument,
                    "compiler provider runs as an isolated core module and accepts neither capability grants nor named device grants",
                )));
            }
            let service = data.runtime_state.program_service();
            let context = ProgramExecContext::from_store(data);
            let caller_authority = data.process_authority().clone();
            Ok(Ok((service, context, caller_authority)))
        })?;
        let (service, context, caller_authority) = match snapshot {
            Ok(values) => values,
            Err(error) => return Ok(Err(error)),
        };
        let Some(service) = service else {
            return Ok(Err(supervisor_error(
                rs_wit::SupervisorErrorKind::Unavailable,
                "program service is unavailable on this machine",
            )));
        };
        let source = match read_program_source(accessor, &path, &caller_authority).await? {
            Ok(source) => source,
            Err(error) => return Ok(Err(map_exec_error(error))),
        };
        let payload = match service.verify_compiler_provider_source(&source) {
            Ok(payload) => payload,
            Err(error) => return Ok(Err(map_exec_error(error))),
        };
        let handle = service.install_compiler_provider(
            name,
            path,
            payload,
            requested_policy,
            context.parent_instance_id,
        );
        let resource = accessor.with(|mut access| access.get().table.push(handle))?;
        Ok(Ok(resource))
    }

    async fn signal_ready(
        accessor: &Accessor<U, Self>,
    ) -> wasmtime::Result<Result<(), rs_wit::SupervisorError>> {
        let snapshot = accessor.with(|mut access| {
            let data = access.get();
            if let Err(error) = require_root_supervisor(data) {
                return Ok::<_, wasmtime::Error>(Err(error));
            }
            Ok(Ok((
                data.runtime_state.root_namespace().clone(),
                data.serial_writer(),
            )))
        })?;
        let (namespace, write_serial) = match snapshot {
            Ok(values) => values,
            Err(error) => return Ok(Err(error)),
        };
        namespace.sync_writable_mounts().await;
        write_serial.emit_stage_marker("run:begin");
        Ok(Ok(()))
    }

    async fn escalate_fatal(
        accessor: &Accessor<U, Self>,
        report: rs_wit::FatalReport,
    ) -> wasmtime::Result<Result<(), rs_wit::SupervisorError>> {
        let snapshot = accessor.with(|mut access| {
            let data = access.get();
            if let Err(error) = require_root_supervisor(data) {
                return Ok::<_, wasmtime::Error>(Err(error));
            }
            if report.component.trim().is_empty() || report.reason.trim().is_empty() {
                return Ok(Err(supervisor_error(
                    rs_wit::SupervisorErrorKind::InvalidArgument,
                    "fatal escalation report requires non-empty component name and reason",
                )));
            }
            Ok(Ok((
                data.cpu.clone(),
                data.timer().clone(),
                data.runtime_state.clone(),
                data.serial_writer(),
            )))
        })?;
        let (cpu, timer, runtime_state, write_serial) = match snapshot {
            Ok(values) => values,
            Err(error) => return Ok(Err(error)),
        };
        let action = match report.action {
            rs_wit::EscalationAction::Halt => FatalEscalationAction::Halt,
            rs_wit::EscalationAction::Reboot => FatalEscalationAction::Reboot,
        };
        execute_fatal_escalation(
            &cpu,
            &timer,
            &runtime_state,
            write_serial,
            report.component,
            report.instance_id.map(InstanceId::from_raw),
            report.reason,
            report.restart_count,
            action,
        )
        .await;
    }
}

/// Flushes writable mounts within [`FATAL_MOUNT_FLUSH_TIMEOUT`], emits a
/// structured fatal diagnostic report to `tracing` and `write_serial`, records
/// the report on `runtime_state`, and halts or reboots the machine through
/// [`Cpu::shutdown`] / [`Cpu::reboot`].
#[expect(
    clippy::too_many_arguments,
    reason = "fatal escalation binds platform handles alongside structured report fields"
)]
pub(crate) async fn execute_fatal_escalation<CpuImpl, Net, StorageImpl>(
    cpu: &CpuImpl,
    timer: &crate::Timer<CpuImpl>,
    runtime_state: &HostRuntimeState<CpuImpl, Net, StorageImpl>,
    write_serial: crate::DebugSerialWriter,
    component: String,
    instance_id: Option<InstanceId>,
    reason: String,
    restart_count: u32,
    action: FatalEscalationAction,
) -> !
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let action_label = match action {
        FatalEscalationAction::Halt => "halt",
        FatalEscalationAction::Reboot => "reboot",
    };
    tracing::error!(
        target: "helios_kernel::supervisor",
        component = component.as_str(),
        instance = instance_id.map(InstanceId::raw),
        restarts = restart_count,
        action = action_label,
        reason = reason.as_str(),
        "unrecoverable failure of critical=system component; flushing writable mounts and escalating"
    );

    let namespace = runtime_state.root_namespace().clone();
    let mounts_flushed = matches!(
        futures::future::select(
            pin!(namespace.sync_writable_mounts()),
            pin!(timer.sleep_for(FATAL_MOUNT_FLUSH_TIMEOUT)),
        )
        .await,
        futures::future::Either::Left(((), _))
    );
    if !mounts_flushed {
        tracing::error!(
            target: "helios_kernel::supervisor",
            component = component.as_str(),
            "timed out flushing writable mounts during fatal escalation"
        );
    }

    write_serial.emit_fmt(format_args!(
        "\n[FATAL critical=system component={component} instance={} restarts={restart_count} action={action_label} mounts_flushed={mounts_flushed}] {reason}\n",
        instance_id.map_or(0, InstanceId::raw),
    ));
    write_serial.emit_error_marker(
        "error critical-system-component",
        format_args!("component={component} action={action_label} reason={reason}"),
    );

    runtime_state.record_fatal_escalation(FatalEscalationRecord {
        component,
        instance_id,
        reason,
        restart_count,
        action,
        mounts_flushed,
    });

    match action {
        FatalEscalationAction::Halt => cpu.shutdown(),
        FatalEscalationAction::Reboot => cpu.reboot(),
    }
}

struct PreparedComponentProvider<CpuImpl, Net, StorageImpl>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    service: UserProgramService<CpuImpl, Net, StorageImpl>,
    context: ProgramExecContext<CpuImpl, Net, StorageImpl>,
    name: String,
    path: String,
    authority: ProcessAuthority,
    oom_policy: OomPolicy,
    precompiled: PreparedComponent<CpuImpl, Net, StorageImpl>,
}

async fn prepare_component_provider<CpuImpl, Net, StorageImpl, U>(
    accessor: &Accessor<U, HasSelf<StoreData<CpuImpl, Net, StorageImpl>>>,
    request: rs_wit::ProviderRequest,
) -> wasmtime::Result<
    Result<PreparedComponentProvider<CpuImpl, Net, StorageImpl>, rs_wit::SupervisorError>,
>
where
    U: 'static,
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let rs_wit::ProviderRequest {
        name,
        path,
        capability_grants,
        named_devices,
        oom_policy,
    } = request;
    if name.is_empty() {
        return Ok(Err(supervisor_error(
            rs_wit::SupervisorErrorKind::InvalidArgument,
            "provider name must not be empty",
        )));
    }
    let requested_policy = from_wit_oom_policy(oom_policy);
    let snapshot = accessor.with(|mut access| {
        let data = access.get();
        if let Err(error) = require_root_supervisor(data) {
            return Ok::<_, wasmtime::Error>(Err(error));
        }
        if let Err(error) = check_oom_ceiling(data.instance().oom_policy(), requested_policy) {
            return Ok(Err(error));
        }
        let service = data.runtime_state.program_service();
        let context = ProgramExecContext::from_store(data);
        let caller_authority = data.process_authority().clone();
        let caller_id = data.instance().id();
        let runtime_state = data.runtime_state.clone();
        let (remaining_grants, ipc_grants, had_ipc) =
            extract_program_ipc_grants(&mut data.table, capability_grants)?;
        if let Err(error) = ipc_grants {
            return Ok(Err(map_exec_error(error)));
        }
        if had_ipc {
            return Ok(Err(supervisor_error(
                rs_wit::SupervisorErrorKind::InvalidArgument,
                "kernel provider endpoints do not accept IPC capability grants",
            )));
        }
        Ok(Ok((
            service,
            context,
            caller_authority,
            caller_id,
            runtime_state,
            remaining_grants,
        )))
    })?;
    let (service, context, caller_authority, caller_id, runtime_state, remaining_grants) =
        match snapshot {
            Ok(values) => values,
            Err(error) => return Ok(Err(error)),
        };
    let Some(service) = service else {
        return Ok(Err(supervisor_error(
            rs_wit::SupervisorErrorKind::Unavailable,
            "program service is unavailable on this machine",
        )));
    };
    let spawn_authority = match caller_authority.derive_spawn_authority() {
        Ok(auth) => auth,
        Err(error) => return Ok(Err(permission_denied(error.to_string()))),
    };
    let compile_authority = CompileAuthority::from(&spawn_authority);
    let mut authority = match build_program_child_authority(
        &caller_authority,
        caller_id,
        None,
        context.instance_registry(),
        remaining_grants,
    ) {
        Ok(authority) => authority,
        Err(error) => return Ok(Err(map_exec_error(error))),
    };
    if let Err(error) = grant_named_devices(&runtime_state, &mut authority, &named_devices) {
        return Ok(Err(error));
    }
    let source = match read_program_source(accessor, &path, &caller_authority).await? {
        Ok(source) => source,
        Err(error) => return Ok(Err(map_exec_error(error))),
    };
    let executable = match service
        .load_executable(
            &compile_authority,
            &context,
            &name,
            &source,
            None,
            &phases::Timeline::disabled(),
        )
        .await
    {
        Ok(executable) => executable,
        Err(error) => return Ok(Err(map_exec_error(error))),
    };
    let ProgramExecutable::Component(precompiled) = executable else {
        return Ok(Err(supervisor_error(
            rs_wit::SupervisorErrorKind::InvalidBinary,
            format!("provider `{path}` must be a Wasm component"),
        )));
    };
    Ok(Ok(PreparedComponentProvider {
        service,
        context,
        name,
        path,
        authority,
        oom_policy: requested_policy,
        precompiled,
    }))
}

impl<CpuImpl, Net, StorageImpl> UserProgramService<CpuImpl, Net, StorageImpl>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    pub(super) fn engine(&self) -> &crate::wasmtime_adapter::WasmtimeEngine {
        &self.inner.engine
    }

    pub(super) fn verify_compiler_provider_source(
        &self,
        source: &ProgramSource,
    ) -> Result<Bytes, ProgramExecError> {
        let payload = match source {
            ProgramSource::BootfsArtifact(bytes) => trusted_bootfs_payload(bytes),
            ProgramSource::SignedArtifact(bytes) => {
                let trusted = cwasm::verify_signed_artifact(
                    UntrustedCwasm::new(bytes),
                    &self.inner.cwasm_signing_key,
                )
                .map_err(map_artifact_trust_error)?;
                Bytes::copy_from_slice(trusted.payload())
            }
            _ => {
                return Err(ProgramExecError {
                    kind: ProgramExecErrorKind::InvalidBinary,
                    detail: ProgramExecErrorDetail::CompilerPluginInvalid,
                });
            }
        };
        if !matches!(
            WasmtimePrecompiledKind::detect(&payload),
            Some(WasmtimePrecompiledKind::CoreModule)
        ) {
            return Err(ProgramExecError {
                kind: ProgramExecErrorKind::InvalidBinary,
                detail: ProgramExecErrorDetail::CompilerPluginInvalid,
            });
        }
        Ok(payload)
    }

    pub(super) fn install_compiler_provider(
        &self,
        name: String,
        path: String,
        payload: Bytes,
        oom_policy: OomPolicy,
        parent_instance_id: Option<InstanceId>,
    ) -> ProviderHandle {
        let generation = self
            .inner
            .next_provider_generation
            .fetch_add(1, Ordering::AcqRel);
        let control = ProviderControl::new();
        let registration = CompilerProviderRegistration {
            generation,
            name,
            path,
            payload,
            oom_policy,
            parent_instance_id,
            control: control.clone(),
        };
        let previous = self
            .inner
            .compiler_registration
            .lock()
            .replace(registration);
        // Drop any cached compiler runtime so the next compile session loads
        // the newly installed artifact.
        *self.inner.compiler_plugin.lock() = None;
        if let Some(prev) = previous {
            prev.control.request_stop();
            prev.control.record_exit(ProviderExitReason::Replaced);
            prev.control.mark_done();
        }
        ProviderHandle::new(ProviderSlotKind::Compiler { generation }, control)
    }

    pub(super) fn stop_compiler_provider(&self, generation: u64) {
        let mut slot = self.inner.compiler_registration.lock();
        if slot
            .as_ref()
            .is_some_and(|reg| reg.generation == generation)
        {
            if let Some(prev) = slot.take() {
                prev.control.request_stop();
                prev.control.record_exit(ProviderExitReason::Stopped);
                prev.control.mark_done();
            }
            *self.inner.compiler_plugin.lock() = None;
        }
    }

    pub(super) fn compiler_provider_registration(&self) -> Option<CompilerProviderRegistration> {
        self.inner.compiler_registration.lock().clone()
    }

    fn install_http_provider(
        &self,
        prepared: PreparedComponentProvider<CpuImpl, Net, StorageImpl>,
    ) -> ProviderHandle {
        let PreparedComponentProvider {
            service: _,
            context,
            name,
            path,
            authority,
            oom_policy,
            precompiled,
        } = prepared;
        let generation = context
            .runtime_state
            .http_client()
            .install_or_activate(crate::memory::user_memory_pool(), HTTP_PROVIDER_QUEUE_DEPTH);
        let control = ProviderControl::new();
        let registration = Arc::new(HttpProviderRegistration {
            generation,
            name,
            path,
            authority,
            oom_policy,
            parent_instance_id: context.parent_instance_id,
            precompiled,
            control: control.clone(),
        });
        let previous = self.inner.http_provider.lock().replace(registration);
        if let Some(prev) = previous {
            prev.control.request_stop();
            prev.control.record_exit(ProviderExitReason::Replaced);
            prev.control.mark_done();
        }
        ProviderHandle::new(ProviderSlotKind::Http { generation }, control)
    }

    pub(super) fn http_provider_registration(
        &self,
    ) -> Option<Arc<HttpProviderRegistration<CpuImpl, Net, StorageImpl>>> {
        self.inner.http_provider.lock().clone()
    }

    pub(super) fn stop_http_provider(
        &self,
        runtime_state: &HostRuntimeState<CpuImpl, Net, StorageImpl>,
        generation: u64,
    ) {
        let removed = {
            let mut slot = self.inner.http_provider.lock();
            if slot
                .as_ref()
                .is_some_and(|reg| reg.generation == generation)
            {
                slot.take()
            } else {
                None
            }
        };
        if let Some(prev) = removed {
            runtime_state.http_client().deactivate(generation);
            prev.control.request_stop();
            prev.control.record_exit(ProviderExitReason::Stopped);
            prev.control.mark_done();
        }
    }

    pub(super) fn fault_http_provider(
        &self,
        runtime_state: &HostRuntimeState<CpuImpl, Net, StorageImpl>,
        generation: u64,
        detail: String,
    ) {
        let removed = {
            let mut slot = self.inner.http_provider.lock();
            if slot
                .as_ref()
                .is_some_and(|reg| reg.generation == generation)
            {
                slot.take()
            } else {
                None
            }
        };
        if let Some(prev) = removed {
            runtime_state.http_client().deactivate(generation);
            prev.control.finish_faulted(detail);
        }
    }

    pub(super) async fn install_surface_provider(
        &self,
        exec_context: ProgramExecContext<CpuImpl, Net, StorageImpl>,
        name: String,
        path: String,
        authority: ProcessAuthority,
        oom_policy: OomPolicy,
        precompiled: PreparedComponent<CpuImpl, Net, StorageImpl>,
    ) -> Result<ProviderHandle, rs_wit::SupervisorError> {
        if precompiled
            .component()
            .component_type()
            .get_export(self.inner.engine.raw(), "helios:system/compositor@0.1.0")
            .is_none()
        {
            return Err(supervisor_error(
                rs_wit::SupervisorErrorKind::InvalidBinary,
                format!("component `{path}` does not export helios:system/compositor@0.1.0"),
            ));
        }

        // Displace any existing surface provider and wait for its store to
        // drop (releasing exclusive display/input claims) before starting the
        // replacement.
        let displaced = self.inner.surface_provider.lock().take();
        if let Some(prev) = displaced {
            prev.control.request_stop();
            prev.control.record_exit(ProviderExitReason::Replaced);
            exec_context
                .runtime_state
                .compositor()
                .uninstall_if_same(&prev.sender);
            if let Some(id) = prev.control.instance_id() {
                let residency = crate::wasmtime_adapter::store::user_residency();
                let now = exec_context
                    .runtime_state
                    .uptime_nanos(exec_context.cpu.now().ticks());
                exec_context.instance_registry.request_kill(
                    id,
                    crate::KillReason::SupervisorRestart,
                    now,
                    &residency,
                );
                self.interrupt_instance(id);
            }
            prev.control.wait_done().await;
        }

        let generation = self
            .inner
            .next_provider_generation
            .fetch_add(1, Ordering::AcqRel);
        let control = ProviderControl::new();
        let (sender, receiver) = provider_channel(SURFACE_REQUEST_QUEUE_DEPTH);
        let started_at = exec_context
            .runtime_state
            .uptime_nanos(exec_context.cpu.now().ticks());

        let (mut store, interrupts, instance_id) = open_provider_store(
            self,
            &exec_context,
            ProviderStoreSpec {
                instance_name: &name,
                bootfs_path: &path,
                authority,
                oom_policy,
                started_at,
            },
        );
        let turns = store.data().guest_turns();
        let wasm_instance = interrupts
            .drive(turns.drive(precompiled.instantiate_async(&mut store)))
            .await
            .map_err(map_program_runtime_error)
            .map_err(map_exec_error)?;
        let memory = wasm_instance.get_default_memory(&mut store);
        let host = CompositorHost::new(&mut store, &wasm_instance)
            .map_err(map_program_runtime_error)
            .map_err(map_exec_error)?;
        let guest = host.helios_system_compositor().clone();

        control.set_instance_id(instance_id);
        let registry = exec_context.runtime_state.surface_service();
        registry.set_compositor(instance_id);
        exec_context
            .runtime_state
            .compositor()
            .replace(sender.clone());
        *self.inner.surface_provider.lock() = Some(SurfaceProviderRegistration {
            generation,
            sender: sender.clone(),
            control: control.clone(),
        });

        tracing::info!(
            target: "helios_kernel::supervisor",
            instance = instance_id.raw(),
            "compositor online"
        );

        let spawner = exec_context.spawner();
        let service = self.clone();
        let run_control = control.clone();
        let runtime_state = exec_context.runtime_state.clone();
        spawner.spawn_local_detached(async move {
            let outcome = run_surface_provider_instance(
                store,
                interrupts,
                guest,
                memory,
                registry.clone(),
                receiver,
            )
            .await;
            registry.retire_compositor();
            runtime_state.compositor().uninstall_if_same(&sender);
            {
                let mut slot = service.inner.surface_provider.lock();
                if slot
                    .as_ref()
                    .is_some_and(|reg| reg.generation == generation)
                {
                    slot.take();
                }
            }
            if !run_control.is_stop_requested() {
                match outcome {
                    Ok(()) => run_control.record_exit(ProviderExitReason::Exited),
                    Err(error) => {
                        run_control.record_exit(ProviderExitReason::Faulted(format!("{error:?}")))
                    }
                }
            }
            run_control.mark_done();
        });

        Ok(ProviderHandle::new(
            ProviderSlotKind::Surface { generation },
            control,
        ))
    }

    pub(super) fn stop_surface_provider(
        &self,
        runtime_state: &HostRuntimeState<CpuImpl, Net, StorageImpl>,
        generation: u64,
    ) {
        let removed = {
            let mut slot = self.inner.surface_provider.lock();
            if slot
                .as_ref()
                .is_some_and(|reg| reg.generation == generation)
            {
                slot.take()
            } else {
                None
            }
        };
        if let Some(prev) = removed {
            prev.control.request_stop();
            prev.control.record_exit(ProviderExitReason::Stopped);
            runtime_state.compositor().uninstall_if_same(&prev.sender);
            if let Some(id) = prev.control.instance_id() {
                let residency = crate::wasmtime_adapter::store::user_residency();
                let now = runtime_state.uptime_nanos(self.inner.clock_cpu.now().ticks());
                runtime_state.instance_registry().request_kill(
                    id,
                    crate::KillReason::SupervisorRestart,
                    now,
                    &residency,
                );
                self.interrupt_instance(id);
            }
        }
    }
}

/// Drives one instantiated `world compositor` store until `desktop.run`
/// returns, traps, or the provider channel closes. Never restarts on its own:
/// restart policy lives in the root supervisor.
async fn run_surface_provider_instance<CpuImpl, Net, StorageImpl>(
    mut store: wasmtime::Store<StoreData<CpuImpl, Net, StorageImpl>>,
    interrupts: StoreInterrupts<CpuImpl>,
    guest: exports::helios::system::compositor::Guest,
    memory: Option<wasmtime::Memory>,
    registry: SurfaceService,
    receiver: ProviderReceiver<SurfaceRequest>,
) -> Result<(), ProgramExecError>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let serve_registry = registry.clone();
    let serve_guest = guest.clone();
    let turns = store.data().guest_turns();
    interrupts
        .drive(turns.drive(store.run_concurrent(async move |accessor| {
            let desktop = guest.desktop().call_constructor(accessor).await?;
            let run_guest = guest.clone();
            accessor.spawn(async move |accessor| {
                run_desktop::<CpuImpl, Net, StorageImpl>(accessor, run_guest, desktop).await
            })?;
            let drain_guest = guest.clone();
            let drain_registry = serve_registry.clone();
            accessor.spawn(async move |accessor| {
                drain_returned_surfaces::<CpuImpl, Net, StorageImpl>(
                    accessor,
                    drain_guest,
                    desktop,
                    drain_registry,
                )
                .await
            })?;
            while let Some(request) = receiver.recv().await {
                serve_surface_request(
                    accessor,
                    &serve_guest,
                    desktop,
                    memory,
                    &serve_registry,
                    request,
                )
                .await?;
            }
            Ok::<(), wasmtime::Error>(())
        })))
        .await
        .and_then(|result| result)
        .map_err(map_program_runtime_error)
}

async fn serve_surface_request<CpuImpl, Net, StorageImpl>(
    accessor: &Accessor<StoreData<CpuImpl, Net, StorageImpl>>,
    guest: &exports::helios::system::compositor::Guest,
    desktop: ResourceAny,
    memory: Option<wasmtime::Memory>,
    registry: &SurfaceService,
    request: SurfaceRequest,
) -> wasmtime::Result<()>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    match request {
        SurfaceRequest::CreateImage(create) => {
            let SurfaceCreate {
                id,
                geometry,
                reply,
                ..
            } = create;
            if registry.lookup(id).is_none() {
                let _ = reply.send(Err(SurfaceServiceError::Gone));
                return Ok(());
            }
            let answer = guest
                .desktop()
                .call_create_image(
                    accessor,
                    desktop,
                    id.raw(),
                    exports::helios::system::compositor::Rect {
                        x: 0,
                        y: 0,
                        width: geometry.width,
                        height: geometry.height,
                    },
                )
                .await?;
            if registry.lookup(id).is_none() {
                guest
                    .desktop()
                    .call_destroy(accessor, desktop, id.raw())
                    .await?;
                let _ = reply.send(Err(SurfaceServiceError::Gone));
            } else {
                let _ = reply.send(answer.map_err(from_guest_surface_error));
            }
            Ok(())
        }
        SurfaceRequest::PresentImage {
            id,
            image,
            retired,
            reply,
        } => {
            if registry.lookup(id).is_none() {
                let _ = reply.send(Err(SurfaceServiceError::Gone));
                return Ok(());
            }
            let (image, retired) = accessor.with(|mut access| {
                let data = access.get();
                Ok::<_, wasmtime::Error>((data.table.push(image)?, data.table.push(retired)?))
            })?;
            let answer = guest
                .desktop()
                .call_present_image(accessor, desktop, id.raw(), image, retired)
                .await?;
            let _ = reply.send(answer.map_err(from_guest_surface_error));
            Ok(())
        }
        SurfaceRequest::Create(create) => {
            serve_surface_create(accessor, guest, desktop, memory, registry, create).await
        }
        SurfaceRequest::Commit { id, region, reply } => {
            let answer = guest
                .desktop()
                .call_commit(
                    accessor,
                    desktop,
                    id.raw(),
                    exports::helios::system::compositor::Rect {
                        x: region.x,
                        y: region.y,
                        width: region.width,
                        height: region.height,
                    },
                )
                .await?;
            let _ = reply.send(answer.map_err(from_guest_surface_error));
            Ok(())
        }
    }
}

async fn serve_surface_create<CpuImpl, Net, StorageImpl>(
    accessor: &Accessor<StoreData<CpuImpl, Net, StorageImpl>>,
    guest: &exports::helios::system::compositor::Guest,
    desktop: ResourceAny,
    memory: Option<wasmtime::Memory>,
    registry: &SurfaceService,
    create: SurfaceCreate,
) -> wasmtime::Result<()>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let SurfaceCreate {
        id,
        geometry,
        buffer,
        reply,
    } = create;
    if registry.lookup(id).is_none() {
        let _ = reply.send(Err(SurfaceServiceError::Gone));
        return Ok(());
    }
    let answer = guest
        .desktop()
        .call_create(
            accessor,
            desktop,
            id.raw(),
            exports::helios::system::compositor::Rect {
                x: 0,
                y: 0,
                width: geometry.width,
                height: geometry.height,
            },
        )
        .await?;
    let span = match answer {
        Ok(span) => Span::new(span.offset, span.length),
        Err(error) => {
            let _ = reply.send(Err(from_guest_surface_error(error)));
            return Ok(());
        }
    };
    let shown = accessor.with(|mut access| {
        if registry.lookup(id).is_none() {
            return Err(SurfaceServiceError::Gone);
        }
        let memory = guest_memory(memory, &access)?;
        let data = access.get();
        data.device
            .surfaces_mut()
            .show_view(&mut data.views, memory, span, id, &buffer)
    });
    if let Err(SurfaceServiceError::Gone) = shown {
        guest
            .desktop()
            .call_destroy(accessor, desktop, id.raw())
            .await?;
        let _ = reply.send(Err(SurfaceServiceError::Gone));
        return Ok(());
    }
    if let Err(error) = shown {
        tracing::warn!(
            target: "helios_kernel::supervisor",
            surface = id.raw(),
            %error,
            "the compositor answered create with a span the window cannot be shown at"
        );
        guest
            .desktop()
            .call_destroy(accessor, desktop, id.raw())
            .await?;
        let _ = reply.send(Err(error));
        return Ok(());
    }
    let _ = reply.send(Ok(()));
    Ok(())
}

async fn destroy_surface<CpuImpl, Net, StorageImpl>(
    accessor: &Accessor<StoreData<CpuImpl, Net, StorageImpl>>,
    guest: &exports::helios::system::compositor::Guest,
    desktop: ResourceAny,
    id: SurfaceId,
) -> wasmtime::Result<()>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    accessor
        .with(|mut access| {
            let data = access.get();
            data.device.surfaces_mut().end_view(id, &mut data.views)
        })
        .map_err(view_trap)?;
    guest
        .desktop()
        .call_destroy(accessor, desktop, id.raw())
        .await?;
    Ok(())
}

const fn from_guest_surface_error(
    error: exports::helios::system::compositor::Error,
) -> SurfaceServiceError {
    use exports::helios::system::compositor::Error as GuestError;
    match error {
        GuestError::RenderFailed => SurfaceServiceError::RenderFailed,
        GuestError::Unavailable => SurfaceServiceError::Unavailable,
        GuestError::NoCompositor => SurfaceServiceError::NoCompositor,
        GuestError::UnsupportedSize => SurfaceServiceError::UnsupportedSize,
        GuestError::TooManySurfaces => SurfaceServiceError::TooManySurfaces,
        GuestError::OutOfBounds => SurfaceServiceError::OutOfBounds,
        GuestError::BadSpan => SurfaceServiceError::CompositorBadSpan,
        GuestError::OutOfMemory => SurfaceServiceError::OutOfMemory,
        GuestError::Gone => SurfaceServiceError::Gone,
        GuestError::NotTheCompositor => SurfaceServiceError::NotTheCompositor,
    }
}

async fn run_desktop<CpuImpl, Net, StorageImpl>(
    accessor: &Accessor<StoreData<CpuImpl, Net, StorageImpl>>,
    guest: exports::helios::system::compositor::Guest,
    desktop: ResourceAny,
) -> wasmtime::Result<()>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let outcome = guest.desktop().call_run(accessor, desktop).await?;
    Err(match outcome {
        Ok(()) => wasmtime::Error::msg("the compositor returned from run"),
        Err(error) => {
            wasmtime::Error::msg(format!("the compositor gave up the desktop: {error:?}"))
        }
    })
}

async fn drain_returned_surfaces<CpuImpl, Net, StorageImpl>(
    accessor: &Accessor<StoreData<CpuImpl, Net, StorageImpl>>,
    guest: exports::helios::system::compositor::Guest,
    desktop: ResourceAny,
    registry: SurfaceService,
) -> wasmtime::Result<()>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let mut waiter = registry.returns_waiter();
    loop {
        for returned in registry.take_returned() {
            destroy_surface(accessor, &guest, desktop, returned.id()).await?;
            returned.drained();
        }
        core::future::poll_fn(|cx| registry.poll_returns(cx, &mut waiter)).await;
    }
}

#[cfg(test)]
mod tests {
    use core::sync::atomic::{AtomicU8, Ordering};
    use core::task::{Context, Poll, Waker};

    use futures_lite::future::block_on;
    use helios_hal::cpu::{Cpu, Instant, ProcessorId, Timebase};
    use helios_hal::device::DmaCapability;
    use helios_hal::iommu::DmaTranslation;
    use helios_hal::numa::SingleNode;
    use helios_hal::serial::ByteSerial;
    use helios_hal::{
        DeviceInventory, DmaModel, Platform, ProcessorStartupPolicy, ProcessorTopology,
    };
    use spin::Mutex;

    use super::*;
    use crate::device::test_hooks;
    use crate::test_support::{TestCpu, TestNetworkService, UnsupportedStorage};
    use crate::wasmtime_adapter::component_host::service::test_store;
    use crate::{
        DebugConsole, DebugSerialAccess, DebugSerialWriter, DeviceGrant, DmaBudget,
        FatalEscalationAction, OomPolicy, ProcessAuthority, ProviderError,
    };

    #[test]
    fn root_supervisor_authority_is_exclusive_and_non_delegable() {
        let mut root = ProcessAuthority::root();
        assert!(!root.is_root_supervisor());
        assert!(root.derive_root_supervisor_cap().is_err());

        root.grant_root_supervisor();
        assert!(root.is_root_supervisor());
        assert!(root.derive_root_supervisor_cap().is_ok());

        // Fork and exec strip root-supervisor unconditionally.
        assert!(!root.fork_inherited().is_root_supervisor());
        assert!(root.fork_inherited().derive_root_supervisor_cap().is_err());
        assert!(!root.exec_preserved().is_root_supervisor());
        assert!(root.exec_preserved().derive_root_supervisor_cap().is_err());

        // Non-root stores calling host methods are rejected with PermissionDenied.
        let mut ordinary = test_store::store_data_authorized(ProcessAuthority::root(), |_| {});
        let denied =
            <test_store::TestStoreData as rs_wit::Host>::get_hardware_inventory(&mut ordinary)
                .expect("host call returns typed error");
        assert_eq!(
            denied.unwrap_err().kind,
            rs_wit::SupervisorErrorKind::PermissionDenied
        );
    }

    #[test]
    fn oom_policy_ceiling_enforces_monotonic_bounds() {
        assert!(check_oom_ceiling(OomPolicy::SystemComponent, OomPolicy::SystemComponent).is_ok());
        assert!(check_oom_ceiling(OomPolicy::SystemComponent, OomPolicy::KernelPlugin).is_ok());
        assert!(check_oom_ceiling(OomPolicy::SystemComponent, OomPolicy::UserProgram).is_ok());

        assert!(check_oom_ceiling(OomPolicy::KernelPlugin, OomPolicy::KernelPlugin).is_ok());
        assert!(check_oom_ceiling(OomPolicy::KernelPlugin, OomPolicy::UserProgram).is_ok());
        assert_eq!(
            check_oom_ceiling(OomPolicy::KernelPlugin, OomPolicy::SystemComponent)
                .unwrap_err()
                .kind,
            rs_wit::SupervisorErrorKind::PermissionDenied
        );

        assert!(check_oom_ceiling(OomPolicy::UserProgram, OomPolicy::UserProgram).is_ok());
        assert_eq!(
            check_oom_ceiling(OomPolicy::UserProgram, OomPolicy::KernelPlugin)
                .unwrap_err()
                .kind,
            rs_wit::SupervisorErrorKind::PermissionDenied
        );
        assert_eq!(
            check_oom_ceiling(OomPolicy::UserProgram, OomPolicy::SystemComponent)
                .unwrap_err()
                .kind,
            rs_wit::SupervisorErrorKind::PermissionDenied
        );
    }

    #[test]
    fn provider_slot_supports_atomic_replacement_and_uninstall() {
        let slot = crate::ProviderSlot::<u32>::new();
        let (tx1, rx1) = provider_channel(2);
        let (tx2, rx2) = provider_channel(2);

        slot.replace(tx1.clone());
        block_on(slot.send(10)).expect("send to first provider");
        assert_eq!(block_on(rx1.recv()), Some(10));

        // Replacing closes the displaced channel and routes subsequent work to tx2.
        assert!(slot.replace(tx2.clone()).is_some());
        assert_eq!(block_on(rx1.recv()), None);
        block_on(slot.send(20)).expect("send to replacement provider");
        assert_eq!(block_on(rx2.recv()), Some(20));

        // Stale uninstall with tx1 does not disturb tx2.
        assert!(!slot.uninstall_if_same(&tx1));
        assert!(slot.is_installed());

        // Matching uninstall detaches tx2 and returns slot to Unavailable.
        assert!(slot.uninstall_if_same(&tx2));
        assert!(!slot.is_installed());
        assert_eq!(block_on(slot.send(30)), Err(ProviderError::Unavailable));
    }

    #[test]
    fn hardware_inventory_reports_device_grants_and_notifies_waiters_on_publish() {
        test_hooks::install();
        let mut auth = ProcessAuthority::root();
        auth.grant_root_supervisor();
        let mut store = test_store::store_data_authorized(auth, |_| {});

        let initial =
            <test_store::TestStoreData as rs_wit::Host>::get_hardware_inventory(&mut store)
                .expect("authorized root supervisor reads inventory")
                .expect("inventory succeeds");
        assert!(initial.devices.is_empty());
        assert!(!initial.display);
        assert!(!initial.input);
        assert!(!initial.gpu);
        assert!(!initial.audio);
        assert!(!initial.hv);
        assert!(!initial.native);

        let seen = store.runtime_state.hardware_generation();
        let (mut svc_waiter, mut dev_waiter) = store.runtime_state.hardware_waiters();
        let mut cx = Context::from_waker(Waker::noop());
        assert!(matches!(
            store.runtime_state.poll_hardware_changed(
                &mut cx,
                &mut svc_waiter,
                &mut dev_waiter,
                seen,
            ),
            Poll::Pending
        ));

        let grant = DeviceGrant::new(
            DeviceName::new("pci:00:05.0").expect("valid device name"),
            DmaBudget {
                capability: DmaCapability {
                    address_bits: 64,
                    coherent: true,
                    translation: DmaTranslation::direct(),
                },
                byte_budget: 1 << 20,
            },
        );
        store
            .runtime_state
            .device_grants()
            .publish([grant])
            .expect("publish device grant");

        let next = match store.runtime_state.poll_hardware_changed(
            &mut cx,
            &mut svc_waiter,
            &mut dev_waiter,
            seen,
        ) {
            Poll::Ready(generation) => generation,
            Poll::Pending => panic!("hardware subscription must wake on device grant publish"),
        };
        assert_ne!(next, seen);

        let updated =
            <test_store::TestStoreData as rs_wit::Host>::get_hardware_inventory(&mut store)
                .expect("authorized root supervisor reads updated inventory")
                .expect("inventory succeeds");
        assert_eq!(updated.devices.len(), 1);
        assert_eq!(updated.devices[0].name, "pci:00:05.0");
    }

    #[test]
    fn program_linker_never_exposes_root_supervisor_interface() {
        let mut comp = wasm_encoder::Component::new();
        let mut imports = wasm_encoder::ComponentImportSection::new();
        let mut types = wasm_encoder::ComponentTypeSection::new();
        types.instance(&wasm_encoder::InstanceType::new());
        comp.section(&types);
        imports.import(
            "helios:system/root-supervisor@0.1.0",
            wasm_encoder::ComponentTypeRef::Instance(0),
        );
        comp.section(&imports);
        let bytes = comp.finish();

        // Layer 1: raw wasm artifact profile classification refuses root-supervisor imports.
        assert!(
            matches!(
                artifact_profile::classify_raw_wasm(&bytes),
                Err(ArtifactProfileError::UnknownComponentImport { ref name })
                    if name == "helios:system/root-supervisor@0.1.0"
            ),
            "ordinary component profile classification must refuse root-supervisor imports"
        );

        // Layer 2: Program linker never defines `helios:system/root-supervisor@0.1.0`,
        // while RootSupervisor linker does.
        let cpu = TestCpu::with_entropy(0x42);
        let runtime = crate::wasmtime_adapter::WasmtimeComponentRuntime::new(cpu);
        let engine = <crate::wasmtime_adapter::WasmtimeComponentRuntime<TestCpu> as crate::ComponentRuntimeFactory<
            TestCpu,
            HostRuntimeState<TestCpu, TestNetworkService, UnsupportedStorage>,
            UnsupportedStorage,
        >>::create_engine(&runtime)
        .expect("engine creates");

        let mut program_linker =
            Linker::<StoreData<TestCpu, TestNetworkService, UnsupportedStorage>>::new(engine.raw());
        add_program_world_to_linker(&mut program_linker).expect("program world links");
        program_linker.allow_shadowing(false);
        assert!(
            program_linker
                .instance("helios:system/root-supervisor@0.1.0")
                .and_then(|mut inst| inst.func_wrap("get-hardware-inventory", |_, (): ()| Ok(())))
                .is_ok(),
            "Program linker must not pre-define helios:system/root-supervisor@0.1.0"
        );

        let mut root_linker =
            Linker::<StoreData<TestCpu, TestNetworkService, UnsupportedStorage>>::new(engine.raw());
        add_program_world_to_linker(&mut root_linker).expect("program world links");
        add_root_supervisor_to_linker(&mut root_linker).expect("root-supervisor links");
        root_linker.allow_shadowing(false);
        assert!(
            root_linker
                .instance("helios:system/root-supervisor@0.1.0")
                .and_then(|mut inst| inst.func_wrap("get-hardware-inventory", |_, (): ()| Ok(())))
                .is_err(),
            "RootSupervisor linker must already define helios:system/root-supervisor@0.1.0"
        );
    }

    #[test]
    fn compiler_provider_install_replace_and_stop_manage_slot() {
        let backing: &'static mut [u8] =
            alloc::boxed::Box::leak(alloc::vec![0u8; 64 * 1024 * 1024].into_boxed_slice());
        let region = unsafe {
            helios_hal::memory::MemoryRegion::new(
                core::ptr::NonNull::from(backing),
                helios_hal::numa::NodeId::FIRST,
            )
        };
        let bootstrap = ProcessorId::new(0);
        crate::test_processor_identity::set(bootstrap);
        crate::prime_bootstrap_allocator(core::iter::once(region), &SingleNode::new(1), bootstrap);

        let cpu = TestCpu::with_entropy(0x55);
        #[derive(Default)]
        struct NullConsole;
        impl core::fmt::Write for NullConsole {
            fn write_str(&mut self, _: &str) -> core::fmt::Result {
                Ok(())
            }
        }
        let platform = Platform::new(NullConsole, cpu)
            .with_topology(
                ProcessorTopology::start_all_secondaries(bootstrap, 1)
                    .with_startup_policy(ProcessorStartupPolicy::BootstrapOnly),
            )
            .with_dma_model(DmaModel::Translated)
            .with_devices(DeviceInventory::new());
        let kernel = crate::init(platform);
        let state: HostRuntimeState<TestCpu, TestNetworkService, UnsupportedStorage> =
            crate::RuntimeState::new(
                cpu.timebase(),
                1,
                0,
                crate::BootPayload::for_tests(),
                GuestIsa::for_build_target(cpu.native_feature_probe()),
            );
        let generation = crate::MachineGeneration::new(None);
        state.install_machine_generation(generation.clone());
        state.install_root_entropy(crate::seed_root_entropy(
            &cpu,
            None,
            None::<&crate::NoEntropyDevice>,
            generation,
        ));

        let service = install_program_service(
            &kernel,
            &cpu,
            &state,
            |_, _| {},
            DebugSerialWriter::of::<test_store::DiscardPort>(),
        );
        assert!(service.compiler_provider_registration().is_none());

        let first = service.install_compiler_provider(
            String::from("compiler-v1"),
            String::from("/bin/compiler.cwasm"),
            Bytes::from_static(b"v1"),
            OomPolicy::KernelPlugin,
            None,
        );
        assert_eq!(
            service
                .compiler_provider_registration()
                .expect("v1 installed")
                .name,
            "compiler-v1"
        );

        let second = service.install_compiler_provider(
            String::from("compiler-v2"),
            String::from("/bin/compiler-v2.cwasm"),
            Bytes::from_static(b"v2"),
            OomPolicy::KernelPlugin,
            None,
        );
        assert_eq!(
            block_on(first.control().wait_exit()),
            ProviderExitReason::Replaced
        );
        assert_eq!(
            service
                .compiler_provider_registration()
                .expect("v2 active")
                .name,
            "compiler-v2"
        );

        // Stale stop of v1 must not clear v2.
        if let ProviderSlotKind::Compiler { generation } = first.kind() {
            service.stop_compiler_provider(generation);
        }
        assert!(service.compiler_provider_registration().is_some());

        // Stopping v2 clears the slot cleanly.
        if let ProviderSlotKind::Compiler { generation } = second.kind() {
            service.stop_compiler_provider(generation);
        }
        assert!(service.compiler_provider_registration().is_none());
        assert_eq!(
            block_on(second.control().wait_exit()),
            ProviderExitReason::Stopped
        );
    }

    static ESCALATION_SERIAL: Mutex<Vec<u8>> = Mutex::new(Vec::new());
    static ESCALATION_CONSOLE: DebugConsole = DebugConsole::new();

    struct EscalationSerialPort;

    impl ByteSerial for EscalationSerialPort {
        fn try_read_byte(&self) -> Option<u8> {
            None
        }
        fn write_bytes(&self, bytes: &[u8]) {
            ESCALATION_SERIAL.lock().extend_from_slice(bytes);
        }
        fn enable_receive_interrupt(&self) {}
        fn disable_receive_interrupt(&self) {}
    }

    impl DebugSerialAccess for EscalationSerialPort {
        type Port = Self;
        fn port() -> Self {
            Self
        }
        fn console() -> &'static DebugConsole {
            &ESCALATION_CONSOLE
        }
    }

    const ESCALATION_WRITER: DebugSerialWriter = DebugSerialWriter::of::<EscalationSerialPort>();

    #[derive(Clone)]
    struct RecordingEscalationCpu {
        inner: TestCpu,
        action: Arc<AtomicU8>,
    }

    impl Cpu for RecordingEscalationCpu {
        type Hypervisor = <TestCpu as Cpu>::Hypervisor;
        type Native = <TestCpu as Cpu>::Native;
        const TIMER_INTERRUPT: helios_hal::cpu::TimerInterrupt = <TestCpu as Cpu>::TIMER_INTERRUPT;
        type WakeOnlyMask = <TestCpu as Cpu>::WakeOnlyMask;

        fn has_lazy_commit_virtual_memory(&self) -> bool {
            self.inner.has_lazy_commit_virtual_memory()
        }
        fn timebase(&self) -> Timebase {
            self.inner.timebase()
        }
        fn now(&self) -> Instant {
            self.inner.now()
        }
        fn set_deadline(&self, deadline: Instant) {
            self.inner.set_deadline(deadline);
        }
        fn park_current(&self) {
            self.inner.park_current();
        }
        fn mask_to_wake_only(&self) -> Self::WakeOnlyMask {
            self.inner.mask_to_wake_only()
        }
        fn park_wake_only(&self, flag: &AtomicU8, expected: u8) {
            self.inner.park_wake_only(flag, expected);
        }
        fn wake_processor(&self, target: ProcessorId) {
            self.inner.wake_processor(target);
        }
        fn processor_count(&self) -> usize {
            self.inner.processor_count()
        }
        fn bootstrap_processor(&self) -> ProcessorId {
            self.inner.bootstrap_processor()
        }
        fn start_processor(&self, target: ProcessorId) {
            self.inner.start_processor(target);
        }
        fn stop_current(&self) {
            self.inner.stop_current();
        }
        fn restart_processor(&self, target: ProcessorId) {
            self.inner.restart_processor(target);
        }
        fn publish_executable(&self, ptr: *const u8, len: usize) {
            self.inner.publish_executable(ptr, len);
        }
        fn unpublish_executable(&self, ptr: *const u8, len: usize) {
            self.inner.unpublish_executable(ptr, len);
        }
        fn native_feature_probe(&self) -> Option<fn(&str) -> Option<bool>> {
            self.inner.native_feature_probe()
        }
        fn shutdown(&self) -> ! {
            self.action.store(1, Ordering::SeqCst);
            panic!("escalation-cpu-halt")
        }
        fn reboot(&self) -> ! {
            self.action.store(2, Ordering::SeqCst);
            panic!("escalation-cpu-reboot")
        }
    }

    #[test]
    fn critical_system_escalation_flushes_mounts_emits_report_and_halts_or_reboots() {
        let bootstrap = ProcessorId::new(0);
        crate::test_processor_identity::set(bootstrap);

        for (action, expected_code, expected_label) in [
            (FatalEscalationAction::Halt, 1_u8, "action=halt"),
            (FatalEscalationAction::Reboot, 2_u8, "action=reboot"),
        ] {
            ESCALATION_SERIAL.lock().clear();
            let action_flag = Arc::new(AtomicU8::new(0));
            let cpu = RecordingEscalationCpu {
                inner: TestCpu::with_entropy(0x77),
                action: action_flag.clone(),
            };
            let executor = crate::Executor::isolated(
                helios_hal::watchdog::ProgressCounter::new(),
                crate::test_support::single_node_pool(1),
                bootstrap,
            );
            let timer = executor.timer(cpu.clone());
            let state: HostRuntimeState<
                RecordingEscalationCpu,
                TestNetworkService,
                UnsupportedStorage,
            > = crate::RuntimeState::new(
                cpu.timebase(),
                1,
                0,
                crate::BootPayload::for_tests(),
                GuestIsa::for_build_target(cpu.native_feature_probe()),
            );

            let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                block_on(execute_fatal_escalation(
                    &cpu,
                    &timer,
                    &state,
                    ESCALATION_WRITER,
                    String::from("debugger"),
                    Some(InstanceId::from_raw(7)),
                    String::from("unrecoverable trap after 3 restarts"),
                    3,
                    action,
                ))
            }));
            assert!(
                panicked.is_err(),
                "escalation must invoke terminal CPU hook"
            );
            assert_eq!(action_flag.load(Ordering::SeqCst), expected_code);

            let record = state
                .last_fatal_escalation()
                .expect("escalation record persisted");
            assert_eq!(record.component, "debugger");
            assert_eq!(record.instance_id, Some(InstanceId::from_raw(7)));
            assert_eq!(record.restart_count, 3);
            assert_eq!(record.action, action);
            assert!(record.mounts_flushed);

            let serial =
                String::from_utf8(ESCALATION_SERIAL.lock().clone()).expect("fatal report is UTF-8");
            assert!(serial.contains("[FATAL critical=system component=debugger"));
            assert!(serial.contains(expected_label));
            assert!(serial.contains("mounts_flushed=true"));
            assert!(serial.contains("unrecoverable trap after 3 restarts"));
        }
    }

    #[test]
    fn provider_install_fails_fast_on_unsupported_grants_without_leaking_ipc_handles() {
        use program_bindings::helios::system::programs as prog_wit;
        use wasmtime::Store;
        use wasmtime::component::HasSelf;

        let cpu = TestCpu::with_entropy(0x88);
        let runtime = crate::wasmtime_adapter::WasmtimeComponentRuntime::new(cpu);
        let engine = <crate::wasmtime_adapter::WasmtimeComponentRuntime<TestCpu> as crate::ComponentRuntimeFactory<
            TestCpu,
            HostRuntimeState<TestCpu, TestNetworkService, UnsupportedStorage>,
            UnsupportedStorage,
        >>::create_engine(&runtime)
        .expect("engine creates");

        let mut root_auth = ProcessAuthority::root();
        root_auth.grant_root_supervisor();
        let mut store = Store::new(
            engine.raw(),
            test_store::store_data_authorized(root_auth, |_| {}),
        );

        // 1. Compiler provider rejects non-empty capability grants (and drains owned IPC handles).
        let (ep_a, _ep_b) = crate::ipc_channel();
        let ipc_res = store
            .data_mut()
            .table
            .push(ep_a)
            .expect("push ipc endpoint");
        let ipc_rep = ipc_res.rep();
        let compiler_ipc_err = block_on(store.run_concurrent(async move |accessor| {
            <HasSelf<test_store::TestStoreData> as rs_wit::HostWithStore<_>>::install_compiler_provider(
                accessor,
                rs_wit::ProviderRequest {
                    name: String::from("compiler"),
                    path: String::from("/bin/compiler.cwasm"),
                    capability_grants: alloc::vec![prog_wit::CapabilityGrant::Ipc(
                        prog_wit::IpcGrant {
                            name: String::from("chan"),
                            endpoint: ipc_res,
                        }
                    )],
                    named_devices: Vec::new(),
                    oom_policy: rs_wit::OomPolicy::UserProgram,
                },
            )
            .await
        }))
        .unwrap()
        .unwrap()
        .expect_err("compiler provider must reject capability grants");
        assert_eq!(
            compiler_ipc_err.kind,
            rs_wit::SupervisorErrorKind::InvalidArgument
        );
        assert!(
            store
                .data()
                .table
                .get(&Resource::<crate::IpcEndpoint>::new_borrow(ipc_rep))
                .is_err(),
            "rejected compiler provider request must not leak IPC endpoint in resource table"
        );

        // 2. Compiler provider rejects non-empty named devices.
        let compiler_dev_err = block_on(store.run_concurrent(async move |accessor| {
            <HasSelf<test_store::TestStoreData> as rs_wit::HostWithStore<_>>::install_compiler_provider(
                accessor,
                rs_wit::ProviderRequest {
                    name: String::from("compiler"),
                    path: String::from("/bin/compiler.cwasm"),
                    capability_grants: Vec::new(),
                    named_devices: alloc::vec![String::from("pci:00:05.0")],
                    oom_policy: rs_wit::OomPolicy::UserProgram,
                },
            )
            .await
        }))
        .unwrap()
        .unwrap()
        .expect_err("compiler provider must reject named devices");
        assert_eq!(
            compiler_dev_err.kind,
            rs_wit::SupervisorErrorKind::InvalidArgument
        );

        // 3. Component providers (http/surface) reject IPC grants and drain the handle.
        let (ep_c, _ep_d) = crate::ipc_channel();
        let ipc_res2 = store
            .data_mut()
            .table
            .push(ep_c)
            .expect("push second ipc endpoint");
        let ipc_rep2 = ipc_res2.rep();
        let http_ipc_err = block_on(store.run_concurrent(async move |accessor| {
            <HasSelf<test_store::TestStoreData> as rs_wit::HostWithStore<_>>::install_http_provider(
                accessor,
                rs_wit::ProviderRequest {
                    name: String::from("http-client"),
                    path: String::from("/bin/http-client"),
                    capability_grants: alloc::vec![prog_wit::CapabilityGrant::Ipc(
                        prog_wit::IpcGrant {
                            name: String::from("chan"),
                            endpoint: ipc_res2,
                        }
                    )],
                    named_devices: Vec::new(),
                    oom_policy: rs_wit::OomPolicy::UserProgram,
                },
            )
            .await
        }))
        .unwrap()
        .unwrap()
        .expect_err("component provider must reject IPC grants");
        assert_eq!(
            http_ipc_err.kind,
            rs_wit::SupervisorErrorKind::InvalidArgument
        );
        assert!(
            store
                .data()
                .table
                .get(&Resource::<crate::IpcEndpoint>::new_borrow(ipc_rep2))
                .is_err(),
            "rejected component provider request must not leak IPC endpoint in resource table"
        );
    }
}
