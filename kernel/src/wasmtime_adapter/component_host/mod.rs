use crate::ComponentHostNetwork;
extern crate alloc;

use alloc::borrow::ToOwned;
use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::Write;
use core::num::NonZeroU64;
use core::pin::Pin;
use core::task::{Context, Poll};
use core::time::Duration;

use crate::wasmtime_adapter::wasi::net::ipv6_address_groups;

use bytes::Bytes;

use crate::{
    AuthorityScope, ClockAuthorityRights, CompileAuthority, DeviceClassRights,
    DiagnosticAuthorityRights, DirectoryAuthorityRights, ExecAuthority, IpcEndpointGrants,
    IpcGrantError, LinkAuthorityRights, NetworkAuthorityRights, ProcessAuthority,
    ProcessAuthorityError, RequestedAuthorityScope, SettingsAuthorityRights, SpawnAuthority,
    TerminalAuthorityRights,
};
use crate::{
    ComponentCache, ComponentOutputMode, ComponentOutputRoute, ComponentOutputStreamKind,
    ComponentStoreData, ExecResult, InstanceId, ProgramExecError, ProgramExecErrorDetail,
    ProgramExecErrorKind, RawMutex, RawMutexGuardResource, RawMutexResource, RawRwLock,
    RawRwLockReadGuardResource, RawRwLockResource, RawRwLockWriteGuardResource, SerialPortResource,
    elapsed_millis, largest_servable_user_bytes, monotonic_nanos, user_heap_stats,
};
use helios_hal::cpu::Cpu;
use smallvec::SmallVec;
use spin::Mutex;
use thiserror::Error;
use wasmtime::component::{
    Access, Accessor, Component, Destination, FutureReader, HasSelf, Linker, Resource,
    ResourceTable, ResourceType, StreamProducer, StreamReader, StreamResult, WasmList, WasmStr,
};
use wasmtime::{self, Engine, Store, StoreContextMut};

use crate::exec::phases::{self, LaunchPhase};
use crate::wasmtime_adapter::bindings::program::bindings as program_bindings;
use crate::wasmtime_adapter::config::AotCompileHint;
use crate::wasmtime_adapter::cwasm;
use crate::wasmtime_adapter::wasi::ChannelStreamProducer;
use crate::{
    HeapStats, LlvmProfile, PerfSample, ProfileScope, TraceEvent, TraceField, TraceFilter,
    TraceLevel, TraceValue,
};
use filters::{MetricFilterView, ProfileFilterView, TraceFilterView};
use observation::{Denied, Refused, TargetRefusal, Visibility};
use program_bindings::helios::system as program_wit;

const SYNC_INSTANCE: &str = "helios:system/sync@0.1.0";
const NET_INSTANCE: &str = "helios:system/net@0.1.0";
const TRACING_INSTANCE: &str = "helios:system/tracing@0.1.0";
const PROFILING_INSTANCE: &str = "helios:system/profiling@0.1.0";
const SETTINGS_INSTANCE: &str = "helios:system/settings@0.1.0";
/// The share of the machine's free memory the compiled-component cache
/// may hold.
///
/// It used to be an eighth of the kernel heap's free space, back when
/// the kernel heap was a fixed quarter of the machine — a thirty-second
/// of the machine, arrived at through a share of a share. The kernel
/// heap's size is demand-driven now (see `memory::policy`), so the same
/// budget has to be expressed against the thing that does not move.
const COMPONENT_CACHE_FRACTION: usize = 32;
const COMPONENT_PHASE_HEARTBEAT_INTERVAL_NANOS: u64 = 5_000_000_000;

fn lower_bytes_to_vec(bytes: Bytes) -> Vec<u8> {
    // `Bytes::to_vec` always copies. The owned conversion can reuse unique
    // receive buffers, which matters in the profiled component-host TCP read
    // lowering path (`program-net-tcp-read-lower-bytes`).
    Vec::from(bytes)
}

mod device;
mod filters;
pub(crate) mod inspect;
pub use inspect::InspectPublicationHandle;
mod instances_snapshot;
mod ipc;
mod machine_identity;
mod mounts;
mod observation;
mod pending;
pub(crate) use pending::PendingReply;
pub mod service;
mod settings;
mod timeline;
mod topology;
mod views;
mod vsock;
pub(crate) use views::{caller_memory, guest_memory, view_trap};

pub use helios_unix::{ChildTermination, SignalTermination};
pub use service::{
    BlobHandle, ChildExit, ChildHandle, ClientImageSurfaceHandle, ClientSurfaceHandle,
    CommandBufferHandle, ContainerHandle, ContextHandle, DisplayHandle, GpuHandle,
    InputDeviceHandle, PlaybackHandle, ProviderHandle, SurfaceHandle, UserProgramService,
    install_component_host_program_service, install_program_service,
    run_component_host_processor_forever, run_program_workers_forever, run_root_component_forever,
    run_root_component_once,
};
pub(crate) use service::{
    Preview1SignalExit, ProgramArgv, ProgramExecContext, ProgramSource, WasixSignalState,
};
pub use topology::{
    ComponentHostProcessorRole, component_host_processor_role, component_host_processors_to_start,
    component_host_system_processor, component_host_worker_count, system_component_should_run_on,
};

pub type SbiSerialPort = crate::ComponentSerialPort;

pub use vsock::{ComponentVsockListener, ComponentVsockStream};

pub type NetworkUdpBackend<Net> = crate::ComponentUdpBackend<Net>;
pub type SbiUdpSocket<Net> = crate::ComponentUdpSocket<NetworkUdpBackend<Net>>;
pub type HostRuntimeState<CpuImpl, Net, StorageImpl> =
    crate::RuntimeState<UserProgramService<CpuImpl, Net, StorageImpl>, Net, StorageImpl>;
pub type StoreData<CpuImpl, Net, StorageImpl> = ComponentStoreData<
    CpuImpl,
    HostRuntimeState<CpuImpl, Net, StorageImpl>,
    crate::Namespace<StorageImpl>,
    ResourceTable,
>;
pub type OutputMode = ComponentOutputMode;
pub type OutputRoute = ComponentOutputRoute;
pub type OutputStreamKind = ComponentOutputStreamKind;

/// A long-running bring-up phase the heartbeat reports on.
///
/// The name and its start are one description of the same phase, so
/// they travel together. When the phase ends is not part of the
/// description: that is the guard's job, see [`ComponentPhaseHeartbeat`].
pub(super) struct ComponentPhase {
    pub(super) name: &'static str,
    pub(super) started_at: u64,
}

/// Owns the heartbeat task for exactly as long as its phase lasts.
///
/// The heartbeat is instance-funded, so it holds a block of the
/// executor's per-processor instance share (#101) while it runs.
/// Dropping this guard cancels the task, and cancelling drops the
/// future, which returns that block. The release is therefore tied to
/// a value going out of scope — it happens on every way a phase can
/// end, including an early `?`, an instance condemned mid-run, and a
/// run future dropped on its fiber.
///
/// The shape this replaces was a detached task polling an
/// `Arc<AtomicBool>` that the run path had to remember to set after
/// its own sleep interval had elapsed. It returned the block one
/// heartbeat interval late on the paths that did set the flag and
/// never on the paths that returned before reaching it, so a burst of
/// short-lived instances left the instance share full of heartbeats
/// for instances that were already gone (#132).
#[must_use = "the phase heartbeat runs until its guard is dropped"]
pub(super) struct ComponentPhaseHeartbeat {
    _task: crate::JoinHandle<()>,
}

fn spawn_component_phase_heartbeat<CpuImpl>(
    spawner: &crate::InstanceSpawner<CpuImpl>,
    cpu: &CpuImpl,
    timer: &crate::Timer<CpuImpl>,
    progress: &helios_hal::watchdog::ProgressCounter,
    write_serial: crate::DebugSerialWriter,
    phase: ComponentPhase,
) -> Result<ComponentPhaseHeartbeat, crate::TaskCapacityError>
where
    CpuImpl: Cpu + Clone,
{
    let ComponentPhase {
        name: phase,
        started_at,
    } = phase;
    let task = spawner.try_spawn({
        let cpu = cpu.clone();
        let timer = timer.clone();
        let progress = progress.clone();
        async move {
            let interval = Duration::from_nanos(COMPONENT_PHASE_HEARTBEAT_INTERVAL_NANOS);
            loop {
                timer.sleep_for(interval).await;

                let now = monotonic_nanos(&cpu);
                progress.record_progress();
                if cfg!(debug_assertions) {
                    let elapsed_ms = elapsed_millis(started_at, now);
                    write_serial.emit_fmt(format_args!(
                        "\n[KDBG {phase}-progress elapsed_ms={elapsed_ms}]\n"
                    ));
                }
            }
        }
    })?;
    Ok(ComponentPhaseHeartbeat { _task: task })
}

#[derive(Clone, Copy)]
pub enum ComponentBindingSet {
    RootSupervisor,
    Program,
}
pub type SbiRawMutex = crate::ComponentRawMutex;
pub type SbiRawMutexGuard = crate::ComponentRawMutexGuard;
pub type SbiRawRwLock = crate::ComponentRawRwLock;
pub type SbiRawRwLockReadGuard = crate::ComponentRawRwLockReadGuard;
pub type SbiRawRwLockWriteGuard = crate::ComponentRawRwLockWriteGuard;

/// A WIT `aot-hint` a program request carries, taken into the kernel's own
/// hint. The one place a hint the kernel cannot compile for is refused, so a
/// request that names it fails before its source is read or anything is
/// compiled.
trait RequestedAotHint {
    fn compile_hint(self) -> Result<AotCompileHint, ProgramExecError>;
}

macro_rules! impl_requested_aot_hint {
    ($bindings:ident) => {
        impl RequestedAotHint for $bindings::helios::system::programs::AotHint {
            fn compile_hint(self) -> Result<AotCompileHint, ProgramExecError> {
                match self {
                    Self::Fast => Err(ProgramExecError {
                        kind: ProgramExecErrorKind::InvalidHint,
                        detail: ProgramExecErrorDetail::UnsupportedAotHint,
                    }),
                    Self::Balanced => Ok(AotCompileHint::Balanced),
                    Self::Performance => Ok(AotCompileHint::Performance),
                }
            }
        }
    };
}

impl_requested_aot_hint!(program_bindings);

macro_rules! impl_program_bindings {
    (
        $bindings:ident,
        $convert_result:ident,
        $convert_error:ident,
        $extract_grants:ident,
        $build_authority:ident,
        $convert_container_config:ident,
        $convert_container_credentials:ident
    ) => {
        impl<CpuImpl, Net, StorageImpl> $bindings::helios::system::programs::Host
            for StoreData<CpuImpl, Net, StorageImpl>
        where
            CpuImpl: Cpu + Clone,
            Net: ComponentHostNetwork,
            StorageImpl: crate::Storage,
        {
        }

        impl<CpuImpl, Net, StorageImpl> $bindings::helios::system::programs::HostContainer
            for StoreData<CpuImpl, Net, StorageImpl>
        where
            CpuImpl: Cpu + Clone,
            Net: ComponentHostNetwork,
            StorageImpl: crate::Storage,
        {
        }

        impl<CpuImpl, Net, StorageImpl, U>
            $bindings::helios::system::programs::HostContainerWithStore<U>
            for HasSelf<StoreData<CpuImpl, Net, StorageImpl>>
        where
            CpuImpl: Cpu + Clone,
            Net: ComponentHostNetwork,
            StorageImpl: crate::Storage,
        {
            fn drop(
                mut access: Access<'_, U, Self>,
                container: wasmtime::component::Resource<ContainerHandle>,
            ) -> wasmtime::Result<()> {
                let mut handle = access.get().table.delete(container)?;
                if let Some(service) = access.get().runtime_state.program_service() {
                    service.remove_container(&mut handle);
                }
                Ok(())
            }

            fn spawn(
                accessor: &Accessor<U, Self>,
                container: wasmtime::component::Resource<ContainerHandle>,
                request: $bindings::helios::system::programs::ContainerSpawnRequest,
            ) -> impl core::future::Future<
                Output = wasmtime::Result<
                    Result<
                        wasmtime::component::Resource<ChildHandle>,
                        $bindings::helios::system::programs::SpawnError,
                    >,
                >,
            > + Send {
                #[cfg(not(feature = "linux"))]
                {
                    let _ = (accessor, container, request);
                    async move {
                        Ok(Err($bindings::helios::system::programs::SpawnError {
                            kind: $bindings::helios::system::programs::SpawnErrorKind::Unavailable,
                            detail: "linux subsystem is not enabled in this kernel".to_owned(),
                        }))
                    }
                }
                #[cfg(feature = "linux")]
                {
                    let $bindings::helios::system::programs::ContainerSpawnRequest {
                        name,
                        args,
                        env,
                        path,
                        cwd,
                        sockets,
                        credentials,
                    } = request;
                    let snapshot = accessor.with(|mut access| {
                        let service = access.get().runtime_state.program_service();
                        let context = ProgramExecContext::from_store(access.get());
                        let caller_authority = access.get().process_authority().clone();
                        let cpu = access.get().cpu.clone();
                        let resolved_container = match service.as_ref() {
                            Some(service) => {
                                let handle = access
                                    .get()
                                    .table
                                    .get(&container)
                                    .map_err(wasmtime::Error::from)?;
                                Some(service.get_container(handle))
                            }
                            None => None,
                        };
                        let mut extracted_sockets = Vec::with_capacity(sockets.len());
                        let mut socket_error: Option<ProgramExecError> = None;
                        for socket in sockets {
                            match socket {
                                $bindings::helios::system::programs::InheritedSocket::Tcp(res) => {
                                    let mut listener = access
                                        .get()
                                        .table
                                        .delete(res)
                                        .map_err(wasmtime::Error::from)?;
                                    if socket_error.is_none() {
                                        match crate::InheritedSocket::from_tcp_listener(
                                            &mut listener,
                                        ) {
                                            Some(inherited) => extracted_sockets.push(inherited),
                                            None => {
                                                socket_error = Some(ProgramExecError {
                                                    kind: ProgramExecErrorKind::Unavailable,
                                                    detail:
                                                        ProgramExecErrorDetail::HostOperationFailed,
                                                });
                                            }
                                        }
                                    }
                                }
                                $bindings::helios::system::programs::InheritedSocket::Vsock(
                                    res,
                                ) => {
                                    let mut listener = access
                                        .get()
                                        .table
                                        .delete(res)
                                        .map_err(wasmtime::Error::from)?;
                                    if socket_error.is_none() {
                                        match listener.take() {
                                            Some((vsock_service, id)) => {
                                                extracted_sockets.push(
                                                    crate::InheritedSocket::from_vsock_listener(
                                                        vsock_service,
                                                        id,
                                                    ),
                                                );
                                            }
                                            None => {
                                                socket_error = Some(ProgramExecError {
                                                    kind: ProgramExecErrorKind::Unavailable,
                                                    detail:
                                                        ProgramExecErrorDetail::HostOperationFailed,
                                                });
                                            }
                                        }
                                    }
                                }
                                $bindings::helios::system::programs::InheritedSocket::TcpStream(
                                    res,
                                ) => {
                                    let mut stream = access
                                        .get()
                                        .table
                                        .delete(res)
                                        .map_err(wasmtime::Error::from)?;
                                    if socket_error.is_none() {
                                        match crate::InheritedSocket::from_tcp_stream(&mut stream) {
                                            Some(inherited) => extracted_sockets.push(inherited),
                                            None => {
                                                socket_error = Some(ProgramExecError {
                                                    kind: ProgramExecErrorKind::Unavailable,
                                                    detail:
                                                        ProgramExecErrorDetail::HostOperationFailed,
                                                });
                                            }
                                        }
                                    }
                                }
                                $bindings::helios::system::programs::InheritedSocket::VsockStream(
                                    res,
                                ) => {
                                    let mut stream = access
                                        .get()
                                        .table
                                        .delete(res)
                                        .map_err(wasmtime::Error::from)?;
                                    if socket_error.is_none() {
                                        match stream.take() {
                                            Some((vsock_service, id)) => {
                                                extracted_sockets.push(
                                                    crate::InheritedSocket::from_vsock_stream(
                                                        vsock_service,
                                                        id,
                                                    ),
                                                );
                                            }
                                            None => {
                                                socket_error = Some(ProgramExecError {
                                                    kind: ProgramExecErrorKind::Unavailable,
                                                    detail:
                                                        ProgramExecErrorDetail::HostOperationFailed,
                                                });
                                            }
                                        }
                                    }
                                }
                                $bindings::helios::system::programs::InheritedSocket::Serial(
                                    res,
                                ) => {
                                    let port = access
                                        .get()
                                        .table
                                        .delete(res)
                                        .map_err(wasmtime::Error::from)?;
                                    if socket_error.is_none() {
                                        extracted_sockets
                                            .push(crate::InheritedSocket::from_serial_port(port));
                                    }
                                }
                            }
                        }
                        let inherited_sockets = match socket_error {
                            Some(error) => Err(error),
                            None => Ok(crate::InheritedSockets::from_vec(extracted_sockets)),
                        };
                        Ok::<_, wasmtime::Error>((
                            service,
                            context,
                            caller_authority,
                            cpu,
                            resolved_container,
                            inherited_sockets,
                        ))
                    });
                    async move {
                        let (
                            service,
                            context,
                            caller_authority,
                            cpu,
                            resolved_container,
                            inherited_sockets,
                        ) = snapshot?;
                        let mut launch = phases::Trace::begin(cpu, "container-spawn", &path);
                        let (Some(service), Some(container_result)) =
                            (service, resolved_container)
                        else {
                            launch.refused(ProgramExecErrorKind::Unavailable);
                            return Ok(Err($bindings::helios::system::programs::SpawnError {
                                kind:
                                    $bindings::helios::system::programs::SpawnErrorKind::Unavailable,
                                detail: "program spawn is unavailable on this machine".to_owned(),
                            }));
                        };
                        if let Err(error) = require_spawn_authority(&caller_authority) {
                            launch.refused(error.kind);
                            return Ok(Err($convert_error(error)));
                        }
                        let inherited_sockets = match inherited_sockets {
                            Ok(sockets) => sockets,
                            Err(error) => {
                                launch.refused(error.kind);
                                return Ok(Err($convert_error(error)));
                            }
                        };
                        let container = match container_result {
                            Ok(container) => container,
                            Err(error) => {
                                launch.refused(error.kind);
                                return Ok(Err($convert_error(error)));
                            }
                        };
                        let credentials = match credentials
                            .map($convert_container_credentials)
                            .transpose()
                        {
                            Ok(credentials) => credentials,
                            Err(error) => {
                                launch.refused(error.kind);
                                return Ok(Err($convert_error(error)));
                            }
                        };
                        let spawned = match service
                            .spawn_in_container(
                                context,
                                &path,
                                service::ProgramLaunch::in_container(
                                    ProgramArgv::launched(name, args),
                                    env,
                                    container,
                                    credentials,
                                )
                                .with_cwd(cwd)
                                .with_inherited_sockets(inherited_sockets)
                                .with_timeline(launch.timeline().for_task()),
                            )
                            .await
                        {
                            Ok(child) => {
                                launch.set_instance(child.instance_id);
                                launch.disarm();
                                let handle = accessor.with(|mut access| {
                                    access
                                        .get()
                                        .table
                                        .push(child)
                                        .map_err(wasmtime::Error::from)
                                })?;
                                Ok(Ok(handle))
                            }
                            Err(error) => {
                                launch.exit_error(&error);
                                Ok(Err($convert_error(error)))
                            }
                        };
                        launch.record(LaunchPhase::Reply);
                        spawned
                    }
                }
            }

            fn exec(
                accessor: &Accessor<U, Self>,
                container: wasmtime::component::Resource<ContainerHandle>,
                request: $bindings::helios::system::programs::ContainerExecRequest,
            ) -> impl core::future::Future<
                Output = wasmtime::Result<
                    Result<
                        $bindings::helios::system::programs::ExecResult,
                        $bindings::helios::system::programs::ExecError,
                    >,
                >,
            > + Send {
                #[cfg(not(feature = "linux"))]
                {
                    let _ = (accessor, container, request);
                    async move {
                        Ok(Err($bindings::helios::system::programs::ExecError {
                            kind: $bindings::helios::system::programs::ExecErrorKind::Unavailable,
                            detail: "linux subsystem is not enabled in this kernel".to_owned(),
                        }))
                    }
                }
                #[cfg(feature = "linux")]
                {
                    let snapshot = accessor.with(|mut access| {
                        let service = access.get().runtime_state.program_service();
                        let context = ProgramExecContext::from_store(access.get());
                        let caller_authority = access.get().process_authority().clone();
                        let cpu = access.get().cpu.clone();
                        let resolved_container = match service.as_ref() {
                            Some(service) => {
                                let handle = access
                                    .get()
                                    .table
                                    .get(&container)
                                    .map_err(wasmtime::Error::from)?;
                                Some(service.get_container(handle))
                            }
                            None => None,
                        };
                        Ok::<_, wasmtime::Error>((
                            service,
                            context,
                            caller_authority,
                            cpu,
                            resolved_container,
                        ))
                    });
                    async move {
                        let (service, context, caller_authority, cpu, resolved_container) =
                            snapshot?;
                        let clock = phases::LaunchClock::arrive(&cpu);
                        let launch = phases::Trace::begin_timed(
                            cpu,
                            "container-exec",
                            &request.path,
                            &clock,
                        );
                        let (Some(service), Some(container_result)) =
                            (service, resolved_container)
                        else {
                            launch.refused(ProgramExecErrorKind::Unavailable);
                            return Ok(Err($bindings::helios::system::programs::ExecError {
                                kind:
                                    $bindings::helios::system::programs::ExecErrorKind::Unavailable,
                                detail: "program exec is unavailable on this machine".to_owned(),
                            }));
                        };
                        if let Err(error) = require_exec_authority(&caller_authority) {
                            launch.refused(error.kind);
                            return Ok(Err($convert_error(error)));
                        }
                        let container = match container_result {
                            Ok(container) => container,
                            Err(error) => {
                                launch.refused(error.kind);
                                return Ok(Err($convert_error(error)));
                            }
                        };
                        let credentials = match request
                            .credentials
                            .map($convert_container_credentials)
                            .transpose()
                        {
                            Ok(credentials) => credentials,
                            Err(error) => {
                                launch.refused(error.kind);
                                return Ok(Err($convert_error(error)));
                            }
                        };
                        let executed = service
                            .exec_in_container(
                                context,
                                &request.path,
                                request.stdin,
                                service::ProgramLaunch::in_container(
                                    ProgramArgv::launched(request.name, request.args),
                                    request.env,
                                    container,
                                    credentials,
                                )
                                .with_cwd(request.cwd)
                                .with_timeline(launch.timeline().clone()),
                            )
                            .await;
                        match &executed {
                            Ok(result) => launch.set_instance(result.instance_id),
                            Err(error) => launch.exit_error(error),
                        }
                        let launch_nanos = launch.replied(&clock);
                        Ok(executed
                            .map(|result| $convert_result(result, launch_nanos))
                            .map_err($convert_error))
                    }
                }
            }
        }

        impl<CpuImpl, Net, StorageImpl> $bindings::helios::system::programs::HostChild
            for StoreData<CpuImpl, Net, StorageImpl>
        where
            CpuImpl: Cpu + Clone,
            Net: ComponentHostNetwork,
            StorageImpl: crate::Storage,
        {
        }

        impl<CpuImpl, Net, StorageImpl, U>
            $bindings::helios::system::programs::HostChildWithStore<U>
            for HasSelf<StoreData<CpuImpl, Net, StorageImpl>>
        where
            CpuImpl: Cpu + Clone,
            Net: ComponentHostNetwork,
            StorageImpl: crate::Storage,
        {
            fn drop(
                mut access: Access<'_, U, Self>,
                child: wasmtime::component::Resource<ChildHandle>,
            ) -> wasmtime::Result<()> {
                let _ = access.get().table.delete(child)?;
                Ok(())
            }

            fn instance_id(
                mut access: Access<'_, U, Self>,
                child: wasmtime::component::Resource<ChildHandle>,
            ) -> wasmtime::Result<u64> {
                let handle = access
                    .get()
                    .table
                    .get(&child)
                    .map_err(wasmtime::Error::from)?;
                Ok(handle.instance_id.raw())
            }

            fn signal(
                mut access: Access<'_, U, Self>,
                child: wasmtime::component::Resource<ChildHandle>,
                signal: u8,
            ) -> wasmtime::Result<Result<(), $bindings::helios::system::programs::SpawnError>> {
                let caller_authority = access.get().process_authority().clone();
                if let Err(error) = caller_authority
                    .derive_signal_authority()
                    .map_err(map_process_authority_error)
                {
                    return Ok(Err($convert_error(error)));
                }
                let Some(sig) = helios_unix::Signal::new(signal) else {
                    return Ok(Err($bindings::helios::system::programs::SpawnError {
                        kind: $bindings::helios::system::programs::SpawnErrorKind::InvalidHint,
                        detail: alloc::format!(
                            "invalid POSIX signal number {signal}; expected 1..=64"
                        ),
                    }));
                };
                let handle = access
                    .get()
                    .table
                    .get(&child)
                    .map_err(wasmtime::Error::from)?;
                handle.signal(sig);
                Ok(Ok(()))
            }

            async fn wait(
                accessor: &Accessor<U, Self>,
                child: wasmtime::component::Resource<ChildHandle>,
            ) -> wasmtime::Result<
                Result<
                    $bindings::helios::system::programs::ExitStatus,
                    $bindings::helios::system::programs::SpawnError,
                >,
            > {
                // Per WIT, `wait` borrows the child; we must not remove
                // it from the table here — the guest's `Drop` impl does
                // that separately once it releases the handle.
                let wait_future = accessor.with(|mut access| {
                    let handle = access
                        .get()
                        .table
                        .get_mut(&child)
                        .map_err(wasmtime::Error::from)?;
                    Ok::<_, wasmtime::Error>(handle.take_wait())
                })?;
                let Some(wait_future) = wait_future else {
                    return Ok(Err($bindings::helios::system::programs::SpawnError {
                        kind: $bindings::helios::system::programs::SpawnErrorKind::Internal,
                        detail: "wait was already consumed for this child".to_owned(),
                    }));
                };
                match wait_future.await {
                    Ok(result) => match result {
                        Ok(exit) => {
                            let termination = match exit.termination {
                                ChildTermination::Exited(code) => {
                                    $bindings::helios::system::programs::ChildTermination::Exited(
                                        code,
                                    )
                                }
                                ChildTermination::Signaled(SignalTermination {
                                    signal,
                                    core_dumped,
                                }) => {
                                    $bindings::helios::system::programs::ChildTermination::Signaled(
                                        $bindings::helios::system::programs::SignalTermination {
                                            signal,
                                            core_dumped,
                                        },
                                    )
                                }
                                ChildTermination::Trapped => {
                                    $bindings::helios::system::programs::ChildTermination::Trapped
                                }
                                ChildTermination::Killed => {
                                    $bindings::helios::system::programs::ChildTermination::Killed
                                }
                            };
                            Ok(Ok($bindings::helios::system::programs::ExitStatus {
                                instance_id: exit.instance_id.raw(),
                                termination,
                            }))
                        }
                        Err(error) => Ok(Err($convert_error(error))),
                    },
                    Err(_) => Ok(Err($bindings::helios::system::programs::SpawnError {
                        kind: $bindings::helios::system::programs::SpawnErrorKind::Internal,
                        detail: "child exit channel dropped before signalling completion"
                            .to_owned(),
                    })),
                }
            }

            fn stdin(
                mut access: Access<'_, U, Self>,
                child: wasmtime::component::Resource<ChildHandle>,
                data: StreamReader<u8>,
            ) -> wasmtime::Result<FutureReader<core::result::Result<(), ()>>> {
                use futures::channel::oneshot;
                let handle = access
                    .get()
                    .table
                    .get_mut(&child)
                    .map_err(wasmtime::Error::from)?;
                let writer = handle.take_stdin();
                let Some(writer) = writer else {
                    return FutureReader::new(&mut access, async move {
                        Ok::<_, wasmtime::Error>(Ok::<(), ()>(()))
                    });
                };
                let (tx, rx) = oneshot::channel();
                data.pipe(
                    &mut access,
                    crate::wasmtime_adapter::wasi::ChannelStreamConsumer::new(writer, tx),
                )?;
                FutureReader::new(&mut access, async move {
                    match rx.await {
                        Ok(result) => Ok::<_, wasmtime::Error>(result),
                        Err(_) => Ok::<_, wasmtime::Error>(Ok::<(), ()>(())),
                    }
                })
            }

            fn stdout(
                mut access: Access<'_, U, Self>,
                child: wasmtime::component::Resource<ChildHandle>,
            ) -> wasmtime::Result<(StreamReader<u8>, FutureReader<core::result::Result<(), ()>>)>
            {
                use futures::channel::oneshot;

                let handle = access
                    .get()
                    .table
                    .get_mut(&child)
                    .map_err(wasmtime::Error::from)?;
                let reader = handle.take_stdout();
                let stream = match reader {
                    Some(reader) => {
                        let (tx, rx) = oneshot::channel();
                        let stream = StreamReader::new(
                            &mut access,
                            ChannelStreamProducer::new_with_completion(reader, tx),
                        )?;
                        let future = FutureReader::new(&mut access, async move {
                            match rx.await {
                                Ok(()) => Ok::<_, wasmtime::Error>(Ok::<(), ()>(())),
                                Err(_) => Ok::<_, wasmtime::Error>(Ok::<(), ()>(())),
                            }
                        })?;
                        return Ok((stream, future));
                    }
                    None => StreamReader::new(&mut access, Vec::<u8>::new())?,
                };
                let future = FutureReader::new(&mut access, async {
                    Ok::<_, wasmtime::Error>(Ok::<(), ()>(()))
                })?;
                Ok((stream, future))
            }

            fn stderr(
                mut access: Access<'_, U, Self>,
                child: wasmtime::component::Resource<ChildHandle>,
            ) -> wasmtime::Result<(StreamReader<u8>, FutureReader<core::result::Result<(), ()>>)>
            {
                use futures::channel::oneshot;

                let handle = access
                    .get()
                    .table
                    .get_mut(&child)
                    .map_err(wasmtime::Error::from)?;
                let reader = handle.take_stderr();
                let stream = match reader {
                    Some(reader) => {
                        let (tx, rx) = oneshot::channel();
                        let stream = StreamReader::new(
                            &mut access,
                            ChannelStreamProducer::new_with_completion(reader, tx),
                        )?;
                        let future = FutureReader::new(&mut access, async move {
                            match rx.await {
                                Ok(()) => Ok::<_, wasmtime::Error>(Ok::<(), ()>(())),
                                Err(_) => Ok::<_, wasmtime::Error>(Ok::<(), ()>(())),
                            }
                        })?;
                        return Ok((stream, future));
                    }
                    None => StreamReader::new(&mut access, Vec::<u8>::new())?,
                };
                let future = FutureReader::new(&mut access, async {
                    Ok::<_, wasmtime::Error>(Ok::<(), ()>(()))
                })?;
                Ok((stream, future))
            }
        }

        impl<CpuImpl, Net, StorageImpl, U> $bindings::helios::system::programs::HostWithStore<U>
            for HasSelf<StoreData<CpuImpl, Net, StorageImpl>>
        where
            CpuImpl: Cpu + Clone,
            Net: ComponentHostNetwork,
            StorageImpl: crate::Storage,
        {
            fn set_default_image(
                accessor: &Accessor<U, Self>,
                image: Option<$bindings::helios::system::programs::DefaultLinuxImage>,
            ) -> impl core::future::Future<
                Output = wasmtime::Result<
                    Result<(), $bindings::helios::system::programs::SpawnError>,
                >,
            > + Send {
                async move {
                    let Some(image) = image else {
                        accessor.with(|mut access| {
                            access.get().set_default_linux_image(None);
                        });
                        return Ok(Ok(()));
                    };
                    let absolute = match crate::resolve_guest_path("/", &image.root_path) {
                        Ok(path) => path,
                        Err(error) => {
                            return Ok(Err($convert_error(map_program_host_error(
                                ProgramHostOperation::ReadSpawnSource,
                                map_component_fs_path_error_to_wasmtime(error),
                            ))));
                        }
                    };
                    let credentials = match image.credentials {
                        Some(creds) => {
                            if creds.supplementary_groups.len() > 65_536 {
                                return Ok(Err($bindings::helios::system::programs::SpawnError {
                                    kind:
                                        $bindings::helios::system::programs::SpawnErrorKind::InvalidPath,
                                    detail: "too many supplementary groups in default-linux-image credentials".to_owned(),
                                }));
                            }
                            Some(crate::DefaultLinuxCredentials {
                                uid: creds.uid,
                                gid: creds.gid,
                                supplementary_groups: creds.supplementary_groups,
                            })
                        }
                        None => None,
                    };
                    let (caller_authority, caller_namespace) = accessor.with(|mut access| {
                        let store = access.get();
                        (store.process_authority().clone(), store.filesystem().clone())
                    });
                    if let Err(error) = caller_authority
                        .derive_directory_cap(
                            &absolute,
                            &absolute,
                            DirectoryAuthorityRights::READ | DirectoryAuthorityRights::EXECUTE,
                        )
                        .map_err(map_process_authority_error)
                    {
                        return Ok(Err($convert_error(error)));
                    }
                    let held = {
                        let floor = caller_authority
                            .program_load_floor(&absolute)
                            .unwrap_or(&absolute);
                        let resolved = match caller_namespace
                            .resolve_following(&absolute, crate::Follow::Within(floor))
                            .await
                        {
                            Ok(resolved) => resolved,
                            Err(error) => {
                                return Ok(Err($convert_error(
                                    ProgramExecError::from_source_read_error(error),
                                )));
                            }
                        };
                        resolved.held()
                    };
                    let metadata = match helios_hal::fs::FileSystem::stat(
                        held.resolved().fs(),
                        held.resolved().path(),
                    )
                    .await
                    {
                        Ok(metadata) => metadata,
                        Err(error) => {
                            return Ok(Err($convert_error(
                                ProgramExecError::from_source_read_error(error),
                            )));
                        }
                    };
                    if metadata.kind != helios_hal::fs::NodeKind::Directory {
                        return Ok(Err($bindings::helios::system::programs::SpawnError {
                            kind: $bindings::helios::system::programs::SpawnErrorKind::InvalidPath,
                            detail: alloc::format!(
                                "default Linux image root `{absolute}` is not a directory"
                            ),
                        }));
                    }
                    if let Err(error) = crate::PinnedLower::from_held(held.clone()) {
                        return Ok(Err($convert_error(
                            ProgramExecError::from_source_read_error(error),
                        )));
                    }
                    let pinned = crate::DefaultLinuxImage {
                        root_path: absolute,
                        lower: held,
                        env: image.env,
                        credentials,
                    };
                    accessor.with(|mut access| {
                        access.get().set_default_linux_image(Some(pinned));
                    });
                    Ok(Ok(()))
                }
            }

            fn get_default_image(
                mut access: Access<'_, U, Self>,
            ) -> wasmtime::Result<Option<$bindings::helios::system::programs::DefaultLinuxImage>>
            {
                Ok(access.get().default_linux_image().map(|img| {
                    $bindings::helios::system::programs::DefaultLinuxImage {
                        root_path: img.root_path,
                        env: img.env,
                        credentials: img.credentials.map(|creds| {
                            $bindings::helios::system::programs::ContainerCredentials {
                                uid: creds.uid,
                                gid: creds.gid,
                                supplementary_groups: creds.supplementary_groups,
                            }
                        }),
                    }
                }))
            }

            fn take_inherited_sockets(
                mut access: Access<'_, U, Self>,
            ) -> wasmtime::Result<Vec<$bindings::helios::system::programs::InheritedSocket>> {
                let store = access.get();
                let raw_sockets = store.inherited_sockets().take_all();
                let retire = store.retirement.sender();
                let mut result = Vec::with_capacity(raw_sockets.len());
                for mut sock in raw_sockets {
                    if let Some((raw, local_address, local_port, hop_limit)) = sock.take_tcp() {
                        let res = store
                            .table
                            .push(crate::ComponentTcpListener::new(
                                raw,
                                local_address,
                                local_port,
                                hop_limit,
                                retire.clone(),
                            ))
                            .map_err(wasmtime::Error::from)?;
                        result.push($bindings::helios::system::programs::InheritedSocket::Tcp(
                            res,
                        ));
                    } else if let Some((vsock_service, listener_id)) = sock.take_vsock() {
                        let res = store
                            .table
                            .push(vsock::ComponentVsockListener::new(
                                vsock_service,
                                listener_id,
                            ))
                            .map_err(wasmtime::Error::from)?;
                        result.push(
                            $bindings::helios::system::programs::InheritedSocket::Vsock(res),
                        );
                    } else if let Some(raw) = sock.take_tcp_stream() {
                        let res = store
                            .table
                            .push(crate::ComponentTcpStreamHandle::new(raw, retire.clone()))
                            .map_err(wasmtime::Error::from)?;
                        result.push(
                            $bindings::helios::system::programs::InheritedSocket::TcpStream(res),
                        );
                    } else if let Some((vsock_service, stream_id)) = sock.take_vsock_stream() {
                        let res = store
                            .table
                            .push(vsock::ComponentVsockStream::new(vsock_service, stream_id))
                            .map_err(wasmtime::Error::from)?;
                        result.push(
                            $bindings::helios::system::programs::InheritedSocket::VsockStream(res),
                        );
                    } else if let Some(port) = sock.take_serial() {
                        let res = store.table.push(port).map_err(wasmtime::Error::from)?;
                        result.push(
                            $bindings::helios::system::programs::InheritedSocket::Serial(res),
                        );
                    }
                }
                Ok(result)
            }

            fn create_container(
                accessor: &Accessor<U, Self>,
                config: $bindings::helios::system::programs::ContainerConfig,
            ) -> impl core::future::Future<
                Output = wasmtime::Result<
                    Result<
                        wasmtime::component::Resource<ContainerHandle>,
                        $bindings::helios::system::programs::SpawnError,
                    >,
                >,
            > + Send {
                #[cfg(not(feature = "linux"))]
                {
                    let _ = (accessor, config);
                    async move {
                        Ok(Err($bindings::helios::system::programs::SpawnError {
                            kind: $bindings::helios::system::programs::SpawnErrorKind::Unavailable,
                            detail: "linux subsystem is not enabled in this kernel".to_owned(),
                        }))
                    }
                }
                #[cfg(feature = "linux")]
                {
                    let $bindings::helios::system::programs::ContainerConfig {
                        root,
                        mounts,
                        shared_owner,
                        credentials,
                        hostname,
                        domainname,
                        capability_grants,
                    } = config;
                    let snapshot = accessor.with(|mut access| {
                        let extracted =
                            $extract_grants(&mut access.get().table, capability_grants)?;
                        Ok::<_, wasmtime::Error>((
                            access.get().runtime_state.program_service(),
                            access.get().process_authority().clone(),
                            access.get().instance().id(),
                            access.get().instance_registry.clone(),
                            access.get().filesystem().clone(),
                            extracted,
                        ))
                    });
                    async move {
                        let (
                            service,
                            caller_authority,
                            caller_id,
                            registry,
                            caller_namespace,
                            (non_ipc_grants, ipc_result, had_ipc),
                        ) = snapshot?;
                        let Some(service) = service else {
                            return Ok(Err($bindings::helios::system::programs::SpawnError {
                                kind:
                                    $bindings::helios::system::programs::SpawnErrorKind::Unavailable,
                                detail: "program service is unavailable on this machine".to_owned(),
                            }));
                        };
                        if let Err(error) = require_launch_authority(&caller_authority) {
                            return Ok(Err($convert_error(error)));
                        }
                        if let Err(error) = ipc_result {
                            return Ok(Err($convert_error(error)));
                        }
                        if had_ipc {
                            return Ok(Err($convert_error(ProgramExecError {
                                kind: ProgramExecErrorKind::PermissionDenied,
                                detail: ProgramExecErrorDetail::ContainerRefused(
                                    crate::RuntimeMessage::of(
                                        "container capability grants cannot include IPC endpoint grants",
                                    ),
                                ),
                            })));
                        }
                        let rebuilt_config = $bindings::helios::system::programs::ContainerConfig {
                            root,
                            mounts,
                            shared_owner,
                            credentials,
                            hostname,
                            domainname,
                            capability_grants: non_ipc_grants,
                        };
                        let (non_fs_authority, container_config) = match $convert_container_config(
                            &caller_authority,
                            caller_id,
                            &registry,
                            rebuilt_config,
                        ) {
                            Ok(pair) => pair,
                            Err(error) => return Ok(Err($convert_error(error))),
                        };
                        let container = match service
                            .create_container(
                                &caller_authority,
                                &caller_namespace,
                                non_fs_authority,
                                container_config,
                            )
                            .await
                        {
                            Ok(container) => container,
                            Err(error) => return Ok(Err($convert_error(error))),
                        };
                        let handle = accessor.with(|mut access| {
                            if let Ok(live) = service.get_container(&container) {
                                access.get().runtime_state.register_container(&live);
                            }
                            access
                                .get()
                                .table
                                .push(container)
                                .map_err(wasmtime::Error::from)
                        })?;
                        Ok(Ok(handle))
                    }
                }
            }

            fn spawn(
                accessor: &Accessor<U, Self>,
                request: $bindings::helios::system::programs::SpawnRequest,
            ) -> impl core::future::Future<
                Output = wasmtime::Result<
                    Result<
                        wasmtime::component::Resource<ChildHandle>,
                        $bindings::helios::system::programs::SpawnError,
                    >,
                >,
            > + Send {
                let $bindings::helios::system::programs::SpawnRequest {
                    name,
                    args,
                    env,
                    path,
                    cwd,
                    sockets,
                    capability_grants,
                } = request;
                let snapshot = accessor.with(|mut access| {
                    let extracted = $extract_grants(&mut access.get().table, capability_grants)?;
                    let mut extracted_sockets = Vec::with_capacity(sockets.len());
                    let mut socket_error: Option<ProgramExecError> = None;
                    for socket in sockets {
                        match socket {
                            $bindings::helios::system::programs::InheritedSocket::Tcp(res) => {
                                let mut listener = access
                                    .get()
                                    .table
                                    .delete(res)
                                    .map_err(wasmtime::Error::from)?;
                                if socket_error.is_none() {
                                    match crate::InheritedSocket::from_tcp_listener(&mut listener) {
                                        Some(inherited) => extracted_sockets.push(inherited),
                                        None => {
                                            socket_error = Some(ProgramExecError {
                                                kind: ProgramExecErrorKind::Unavailable,
                                                detail: ProgramExecErrorDetail::HostOperationFailed,
                                            });
                                        }
                                    }
                                }
                            }
                            $bindings::helios::system::programs::InheritedSocket::Vsock(res) => {
                                let mut listener = access
                                    .get()
                                    .table
                                    .delete(res)
                                    .map_err(wasmtime::Error::from)?;
                                if socket_error.is_none() {
                                    match listener.take() {
                                        Some((vsock_service, id)) => {
                                            extracted_sockets.push(
                                                crate::InheritedSocket::from_vsock_listener(
                                                    vsock_service,
                                                    id,
                                                ),
                                            );
                                        }
                                        None => {
                                            socket_error = Some(ProgramExecError {
                                                kind: ProgramExecErrorKind::Unavailable,
                                                detail: ProgramExecErrorDetail::HostOperationFailed,
                                            });
                                        }
                                    }
                                }
                            }
                            $bindings::helios::system::programs::InheritedSocket::TcpStream(
                                res,
                            ) => {
                                let mut stream = access
                                    .get()
                                    .table
                                    .delete(res)
                                    .map_err(wasmtime::Error::from)?;
                                if socket_error.is_none() {
                                    match crate::InheritedSocket::from_tcp_stream(&mut stream) {
                                        Some(inherited) => extracted_sockets.push(inherited),
                                        None => {
                                            socket_error = Some(ProgramExecError {
                                                kind: ProgramExecErrorKind::Unavailable,
                                                detail: ProgramExecErrorDetail::HostOperationFailed,
                                            });
                                        }
                                    }
                                }
                            }
                            $bindings::helios::system::programs::InheritedSocket::VsockStream(
                                res,
                            ) => {
                                let mut stream = access
                                    .get()
                                    .table
                                    .delete(res)
                                    .map_err(wasmtime::Error::from)?;
                                if socket_error.is_none() {
                                    match stream.take() {
                                        Some((vsock_service, id)) => {
                                            extracted_sockets.push(
                                                crate::InheritedSocket::from_vsock_stream(
                                                    vsock_service,
                                                    id,
                                                ),
                                            );
                                        }
                                        None => {
                                            socket_error = Some(ProgramExecError {
                                                kind: ProgramExecErrorKind::Unavailable,
                                                detail: ProgramExecErrorDetail::HostOperationFailed,
                                            });
                                        }
                                    }
                                }
                            }
                            $bindings::helios::system::programs::InheritedSocket::Serial(res) => {
                                let port = access
                                    .get()
                                    .table
                                    .delete(res)
                                    .map_err(wasmtime::Error::from)?;
                                if socket_error.is_none() {
                                    extracted_sockets
                                        .push(crate::InheritedSocket::from_serial_port(port));
                                }
                            }
                        }
                    }
                    let inherited_sockets = match socket_error {
                        Some(error) => Err(error),
                        None => Ok(crate::InheritedSockets::from_vec(extracted_sockets)),
                    };
                    Ok::<_, wasmtime::Error>((
                        access.get().runtime_state.program_service(),
                        ProgramExecContext::from_store(access.get()),
                        access.get().process_authority().clone(),
                        access.get().instance().id(),
                        access.get().cpu.clone(),
                        // The child starts a tree of its own below the
                        // caller's: it sees the caller's mounts, and its
                        // own stay its own.
                        access.get().filesystem().descend(),
                        access.get().default_linux_image(),
                        extracted,
                        inherited_sockets,
                    ))
                });
                async move {
                    let (
                        service,
                        context,
                        caller_authority,
                        caller_id,
                        cpu,
                        namespace,
                        caller_default_image,
                        (non_ipc_grants, ipc_result, _),
                        inherited_sockets,
                    ) = snapshot?;
                    let mut launch = phases::Trace::begin(cpu, "spawn", &path);
                    let Some(service) = service else {
                        launch.refused(ProgramExecErrorKind::Unavailable);
                        return Ok(Err($bindings::helios::system::programs::SpawnError {
                            kind: $bindings::helios::system::programs::SpawnErrorKind::Unavailable,
                            detail: "program spawn is unavailable on this machine".to_owned(),
                        }));
                    };
                    let spawn_authority = match require_spawn_authority(&caller_authority) {
                        Ok(authority) => authority,
                        Err(error) => {
                            launch.refused(error.kind);
                            return Ok(Err($convert_error(error)));
                        }
                    };
                    let ipc_grants = match ipc_result {
                        Ok(grants) => grants,
                        Err(error) => {
                            launch.refused(error.kind);
                            return Ok(Err($convert_error(error)));
                        }
                    };
                    let inherited_sockets = match inherited_sockets {
                        Ok(sockets) => sockets,
                        Err(error) => {
                            launch.refused(error.kind);
                            return Ok(Err($convert_error(error)));
                        }
                    };
                    let compile_authority = CompileAuthority::from(&spawn_authority);
                    let child_instance = context.instance_registry().register_child(
                        context.parent_instance_id(),
                        name.clone(),
                        context.now_uptime_nanos(),
                    );
                    let mut child_authority = match $build_authority(
                        &caller_authority,
                        caller_id,
                        Some(child_instance.id()),
                        context.instance_registry(),
                        non_ipc_grants,
                    ) {
                        Ok(authority) => authority,
                        Err(error) => {
                            launch.refused(error.kind);
                            return Ok(Err($convert_error(error)));
                        }
                    };
                    let host_read = read_program_source(accessor, &path, &caller_authority).await;
                    #[cfg_attr(
                        not(feature = "linux"),
                        expect(
                            unused_mut,
                            reason = "argv is mutated by host #! shebang rewriting when the linux feature is enabled"
                        )
                    )]
                    let mut argv = ProgramArgv::launched(name, args);
                    let use_default_overlay = match &host_read {
                        Ok(Ok(source)) => !source.is_wasm() && caller_default_image.is_some(),
                        _ => caller_default_image.is_some(),
                    };
                    #[cfg(feature = "linux")]
                    let spawned = if use_default_overlay {
                        let default_image = caller_default_image
                            .clone()
                            .expect("use_default_overlay implies Some");
                        let fallback_bytes = match host_read {
                            Ok(Ok(ProgramSource::LinuxElf(bytes))) => Some(bytes),
                            Ok(Ok(ProgramSource::RawWasm(bytes)))
                                if service::parse_shebang(&bytes).is_some() =>
                            {
                                Some(bytes)
                            }
                            _ => None,
                        };
                        let container = match service.create_ephemeral_overlay_container(
                            child_authority,
                            &namespace,
                            &default_image,
                        ) {
                            Ok(container) => container,
                            Err(error) => {
                                launch.refused(error.kind);
                                return Ok(Err($convert_error(error)));
                            }
                        };
                        accessor.with(|mut access| {
                            access.get().runtime_state.register_container(&container);
                        });
                        let merged_env = service::merge_default_image_env(&default_image.env, env);
                        match service
                            .spawn_in_overlay_container(
                                context,
                                &path,
                                fallback_bytes,
                                service::ProgramLaunch::in_container(argv, merged_env, container, None)
                                    .with_launched_instance(child_instance)
                                    .with_ipc_grants(ipc_grants)
                                    .with_default_linux_image(caller_default_image)
                                    .with_inherited_sockets(inherited_sockets)
                                    .with_cwd(cwd)
                                    .with_timeline(launch.timeline().for_task()),
                            )
                            .await
                        {
                            Ok(child) => {
                                launch.set_instance(child.instance_id);
                                launch.disarm();
                                let handle = accessor.with(|mut access| {
                                    access
                                        .get()
                                        .table
                                        .push(child)
                                        .map_err(wasmtime::Error::from)
                                })?;
                                Ok(Ok(handle))
                            }
                            Err(error) => {
                                launch.exit_error(&error);
                                Ok(Err($convert_error(error)))
                            }
                        }
                    } else {
                        let resolved_cwd =
                            match apply_requested_cwd(&mut child_authority, &namespace, cwd.as_deref()).await {
                                Ok(resolved_cwd) => resolved_cwd,
                                Err(error) => {
                                    launch.refused(error.kind);
                                    return Ok(Err($convert_error(error)));
                                }
                            };
                        let initial_source = match host_read {
                            Ok(Ok(source)) => source,
                            Ok(Err(error)) => {
                                launch.exit_error(&error);
                                return Ok(Err($convert_error(error)));
                            }
                            Err(error) => {
                                let error = map_program_host_error(
                                    ProgramHostOperation::ReadSpawnSource,
                                    error,
                                );
                                launch.exit_error(&error);
                                return Ok(Err($convert_error(error)));
                            }
                        };
                        let source = match resolve_host_shebang_source(
                            accessor,
                            &path,
                            &caller_authority,
                            initial_source,
                            &mut argv,
                            ProgramHostOperation::ReadSpawnSource,
                        )
                        .await
                        {
                            Ok(source) => source,
                            Err(error) => {
                                launch.exit_error(&error);
                                return Ok(Err($convert_error(error)));
                            }
                        };
                        launch.record(LaunchPhase::SourceRead);
                        launch.record_source_bytes(source.payload_len());
                        match service
                            .spawn(
                                &compile_authority,
                                context,
                                source,
                                None,
                                service::ProgramLaunch::new(
                                    argv,
                                    env,
                                    child_authority,
                                    Some(namespace),
                                )
                                .with_launched_instance(child_instance)
                                .with_ipc_grants(ipc_grants)
                                .with_default_linux_image(caller_default_image)
                                .with_inherited_sockets(inherited_sockets)
                                .with_cwd(resolved_cwd)
                                .with_timeline(launch.timeline().for_task()),
                            )
                            .await
                        {
                            Ok(child) => {
                                launch.set_instance(child.instance_id);
                                launch.disarm();
                                let handle = accessor.with(|mut access| {
                                    access
                                        .get()
                                        .table
                                        .push(child)
                                        .map_err(wasmtime::Error::from)
                                })?;
                                Ok(Ok(handle))
                            }
                            Err(error) => {
                                launch.exit_error(&error);
                                Ok(Err($convert_error(error)))
                            }
                        }
                    };
                    #[cfg(not(feature = "linux"))]
                    let spawned = {
                        let _ = use_default_overlay;
                        let resolved_cwd =
                            match apply_requested_cwd(&mut child_authority, &namespace, cwd.as_deref()).await {
                                Ok(resolved_cwd) => resolved_cwd,
                                Err(error) => {
                                    launch.refused(error.kind);
                                    return Ok(Err($convert_error(error)));
                                }
                            };
                        let source = match host_read {
                            Ok(Ok(source)) => source,
                            Ok(Err(error)) => {
                                launch.exit_error(&error);
                                return Ok(Err($convert_error(error)));
                            }
                            Err(error) => {
                                let error = map_program_host_error(
                                    ProgramHostOperation::ReadSpawnSource,
                                    error,
                                );
                                launch.exit_error(&error);
                                return Ok(Err($convert_error(error)));
                            }
                        };
                        launch.record(LaunchPhase::SourceRead);
                        launch.record_source_bytes(source.payload_len());
                        match service
                            .spawn(
                                &compile_authority,
                                context,
                                source,
                                None,
                                service::ProgramLaunch::new(
                                    argv,
                                    env,
                                    child_authority,
                                    Some(namespace),
                                )
                                .with_launched_instance(child_instance)
                                .with_ipc_grants(ipc_grants)
                                .with_default_linux_image(caller_default_image)
                                .with_inherited_sockets(inherited_sockets)
                                .with_cwd(resolved_cwd)
                                .with_timeline(launch.timeline().for_task()),
                            )
                            .await
                        {
                            Ok(child) => {
                                launch.set_instance(child.instance_id);
                                launch.disarm();
                                let handle = accessor.with(|mut access| {
                                    access
                                        .get()
                                        .table
                                        .push(child)
                                        .map_err(wasmtime::Error::from)
                                })?;
                                Ok(Ok(handle))
                            }
                            Err(error) => {
                                launch.exit_error(&error);
                                Ok(Err($convert_error(error)))
                            }
                        }
                    };
                    launch.record(LaunchPhase::Reply);
                    spawned
                }
            }

            fn exec(
                accessor: &Accessor<U, Self>,
                request: $bindings::helios::system::programs::ExecRequest,
            ) -> impl core::future::Future<
                Output = wasmtime::Result<
                    Result<
                        $bindings::helios::system::programs::ExecResult,
                        $bindings::helios::system::programs::ExecError,
                    >,
                >,
            > + Send {
                let $bindings::helios::system::programs::ExecRequest {
                    name,
                    args,
                    env,
                    path,
                    cwd,
                    stdin,
                    hint,
                    capability_grants,
                } = request;
                let snapshot = accessor.with(|mut access| {
                    let extracted = $extract_grants(&mut access.get().table, capability_grants)?;
                    Ok::<_, wasmtime::Error>((
                        access.get().runtime_state.program_service(),
                        ProgramExecContext::from_store(access.get()),
                        access.get().process_authority().clone(),
                        access.get().instance().id(),
                        access.get().cpu.clone(),
                        // The child starts a tree of its own below the
                        // caller's: it sees the caller's mounts, and its
                        // own stay its own.
                        access.get().filesystem().descend(),
                        access.get().default_linux_image(),
                        extracted,
                    ))
                });
                async move {
                    let (
                        service,
                        context,
                        caller_authority,
                        caller_id,
                        cpu,
                        namespace,
                        caller_default_image,
                        (non_ipc_grants, ipc_result, _),
                    ) = snapshot?;
                    // Read before anything else the call does, so the
                    // reported duration covers the whole launch.
                    let clock = phases::LaunchClock::arrive(&cpu);
                    let launch = phases::Trace::begin_timed(cpu, "exec", &path, &clock);
                    let Some(service) = service else {
                        launch.refused(ProgramExecErrorKind::Unavailable);
                        return Ok(Err($bindings::helios::system::programs::ExecError {
                            kind: $bindings::helios::system::programs::ExecErrorKind::Unavailable,
                            detail: "program exec is unavailable on this machine".to_owned(),
                        }));
                    };
                    let exec_authority = match require_exec_authority(&caller_authority) {
                        Ok(authority) => authority,
                        Err(error) => {
                            launch.refused(error.kind);
                            return Ok(Err($convert_error(error)));
                        }
                    };
                    let ipc_grants = match ipc_result {
                        Ok(grants) => grants,
                        Err(error) => {
                            launch.refused(error.kind);
                            return Ok(Err($convert_error(error)));
                        }
                    };
                    let compile_authority = CompileAuthority::from(&exec_authority);
                    let child_instance = context.instance_registry().register_child(
                        context.parent_instance_id(),
                        name.clone(),
                        context.now_uptime_nanos(),
                    );
                    let mut child_authority = match $build_authority(
                        &caller_authority,
                        caller_id,
                        Some(child_instance.id()),
                        context.instance_registry(),
                        non_ipc_grants,
                    ) {
                        Ok(authority) => authority,
                        Err(error) => {
                            launch.refused(error.kind);
                            return Ok(Err($convert_error(error)));
                        }
                    };
                    // Refused before the source is read: the hint is a
                    // property of the request alone.
                    let hint = match hint.map(RequestedAotHint::compile_hint).transpose() {
                        Ok(hint) => hint,
                        Err(error) => {
                            launch.refused(error.kind);
                            return Ok(Err($convert_error(error)));
                        }
                    };
                    let host_read = read_program_source(accessor, &path, &caller_authority).await;
                    #[cfg_attr(
                        not(feature = "linux"),
                        expect(
                            unused_mut,
                            reason = "argv is mutated by host #! shebang rewriting when the linux feature is enabled"
                        )
                    )]
                    let mut argv = ProgramArgv::launched(name, args);
                    let use_default_overlay = match &host_read {
                        Ok(Ok(source)) => !source.is_wasm() && caller_default_image.is_some(),
                        _ => caller_default_image.is_some(),
                    };
                    #[cfg(feature = "linux")]
                    let executed = if use_default_overlay {
                        let default_image = caller_default_image
                            .clone()
                            .expect("use_default_overlay implies Some");
                        let fallback_bytes = match host_read {
                            Ok(Ok(ProgramSource::LinuxElf(bytes))) => Some(bytes),
                            Ok(Ok(ProgramSource::RawWasm(bytes)))
                                if service::parse_shebang(&bytes).is_some() =>
                            {
                                Some(bytes)
                            }
                            _ => None,
                        };
                        match service.create_ephemeral_overlay_container(
                            child_authority,
                            &namespace,
                            &default_image,
                        ) {
                            Ok(container) => {
                                accessor.with(|mut access| {
                                    access.get().runtime_state.register_container(&container);
                                });
                                let merged_env =
                                    service::merge_default_image_env(&default_image.env, env);
                                service
                                    .exec_in_overlay_container(
                                        context,
                                        &path,
                                        fallback_bytes,
                                        stdin,
                                        service::ProgramLaunch::in_container(
                                            argv, merged_env, container, None,
                                        )
                                        .with_launched_instance(child_instance)
                                        .with_ipc_grants(ipc_grants)
                                        .with_default_linux_image(caller_default_image)
                                        .with_cwd(cwd)
                                        .with_timeline(launch.timeline().clone()),
                                    )
                                    .await
                            }
                            Err(error) => Err(error),
                        }
                    } else {
                        let resolved_cwd =
                            match apply_requested_cwd(&mut child_authority, &namespace, cwd.as_deref()).await {
                                Ok(resolved_cwd) => resolved_cwd,
                                Err(error) => {
                                    launch.refused(error.kind);
                                    return Ok(Err($convert_error(error)));
                                }
                            };
                        let initial_source = match host_read {
                            Ok(Ok(source)) => source,
                            Ok(Err(error)) => {
                                launch.exit_error(&error);
                                return Ok(Err($convert_error(error)));
                            }
                            Err(error) => {
                                let error = map_program_host_error(
                                    ProgramHostOperation::ReadExecSource,
                                    error,
                                );
                                launch.exit_error(&error);
                                return Ok(Err($convert_error(error)));
                            }
                        };
                        let source = match resolve_host_shebang_source(
                            accessor,
                            &path,
                            &caller_authority,
                            initial_source,
                            &mut argv,
                            ProgramHostOperation::ReadExecSource,
                        )
                        .await
                        {
                            Ok(source) => source,
                            Err(error) => {
                                launch.exit_error(&error);
                                return Ok(Err($convert_error(error)));
                            }
                        };
                        launch.record(LaunchPhase::SourceRead);
                        launch.record_source_bytes(source.payload_len());
                        service
                            .exec_buffered(
                                &compile_authority,
                                context,
                                source,
                                hint,
                                stdin,
                                service::ProgramLaunch::new(
                                    argv,
                                    env,
                                    child_authority,
                                    Some(namespace),
                                )
                                .with_launched_instance(child_instance)
                                .with_ipc_grants(ipc_grants)
                                .with_default_linux_image(caller_default_image)
                                .with_cwd(resolved_cwd)
                                .with_timeline(launch.timeline().clone()),
                            )
                            .await
                    };
                    #[cfg(not(feature = "linux"))]
                    let executed = {
                        let _ = use_default_overlay;
                        let resolved_cwd =
                            match apply_requested_cwd(&mut child_authority, &namespace, cwd.as_deref()).await {
                                Ok(resolved_cwd) => resolved_cwd,
                                Err(error) => {
                                    launch.refused(error.kind);
                                    return Ok(Err($convert_error(error)));
                                }
                            };
                        let source = match host_read {
                            Ok(Ok(source)) => source,
                            Ok(Err(error)) => {
                                launch.exit_error(&error);
                                return Ok(Err($convert_error(error)));
                            }
                            Err(error) => {
                                let error = map_program_host_error(
                                    ProgramHostOperation::ReadExecSource,
                                    error,
                                );
                                launch.exit_error(&error);
                                return Ok(Err($convert_error(error)));
                            }
                        };
                        launch.record(LaunchPhase::SourceRead);
                        launch.record_source_bytes(source.payload_len());
                        service
                            .exec_buffered(
                                &compile_authority,
                                context,
                                source,
                                hint,
                                stdin,
                                service::ProgramLaunch::new(
                                    argv,
                                    env,
                                    child_authority,
                                    Some(namespace),
                                )
                                .with_launched_instance(child_instance)
                                .with_ipc_grants(ipc_grants)
                                .with_default_linux_image(caller_default_image)
                                .with_cwd(resolved_cwd)
                                .with_timeline(launch.timeline().clone()),
                            )
                            .await
                    };
                    match &executed {
                        Ok(result) => launch.set_instance(result.instance_id),
                        // The run task already marked the end for a
                        // failure it produced — a guest trap — and an
                        // error this task produced, like the load, is
                        // the mark itself.
                        Err(error) => launch.exit_error(error),
                    }
                    let launch_nanos = launch.replied(&clock);
                    // The guard stays armed: it drops here and emits
                    // the line — `reply` included — for an exec the
                    // run task does not own emission.
                    Ok(executed
                        .map(|result| $convert_result(result, launch_nanos))
                        .map_err($convert_error))
                }
            }

            fn aot(
                accessor: &Accessor<U, Self>,
                request: $bindings::helios::system::programs::AotRequest,
            ) -> impl core::future::Future<
                Output = wasmtime::Result<
                    Result<
                        $bindings::helios::system::programs::AotResult,
                        $bindings::helios::system::programs::ExecError,
                    >,
                >,
            > + Send {
                let snapshot = accessor.with(|mut access| {
                    Ok::<_, wasmtime::Error>((
                        access.get().runtime_state.program_service(),
                        ProgramExecContext::from_store(access.get()),
                        access.get().process_authority().clone(),
                        access
                            .get()
                            .runtime_state
                            .settings()
                            .get::<crate::CompilerMaxInputBytesSetting>(),
                    ))
                });
                async move {
                    let (service, context, caller_authority, max_input_bytes) = snapshot?;
                    let Some(service) = service else {
                        return Ok(Err($bindings::helios::system::programs::ExecError {
                            kind: $bindings::helios::system::programs::ExecErrorKind::Unavailable,
                            detail: "program AOT is unavailable on this machine".to_owned(),
                        }));
                    };
                    let compile_authority = match require_compile_authority(&caller_authority) {
                        Ok(authority) => authority,
                        Err(error) => return Ok(Err($convert_error(error))),
                    };
                    // Refused before the source is read: the hint is a
                    // property of the request alone.
                    let hint = match request.hint.compile_hint() {
                        Ok(hint) => hint,
                        Err(error) => return Ok(Err($convert_error(error))),
                    };
                    // Validate the destination path and authority before
                    // reading the source or running the compiler.
                    let dest_absolute = match crate::resolve_guest_path(
                        "/",
                        &request.destination_path,
                    ) {
                        Ok(path) => path,
                        Err(error) => {
                            return Ok(Err($convert_error(map_program_host_error(
                                ProgramHostOperation::WriteAotArtifact,
                                map_component_fs_path_error_to_wasmtime(error),
                            ))));
                        }
                    };
                    if !caller_authority.can_create_or_replace_path(&dest_absolute) {
                        return Ok(Err($convert_error(ProgramExecError {
                            kind: ProgramExecErrorKind::PermissionDenied,
                            detail: ProgramExecErrorDetail::ProgramArtifactDestinationNotGranted,
                        })));
                    }
                    let source = match read_program_source_bounded(
                        accessor,
                        &request.source_path,
                        &caller_authority,
                        max_input_bytes,
                    )
                    .await
                    {
                        Ok(Ok(source)) => source,
                        Ok(Err(error)) => return Ok(Err($convert_error(error))),
                        Err(error) => {
                            return Ok(Err($convert_error(map_program_host_error(
                                ProgramHostOperation::ReadAotSource,
                                error,
                            ))));
                        }
                    };
                    let ProgramSource::RawWasm(wasm) = source else {
                        return Ok(Err($bindings::helios::system::programs::ExecError {
                            kind: $bindings::helios::system::programs::ExecErrorKind::InvalidHint,
                            detail: "aot only accepts raw wasm inputs".to_owned(),
                        }));
                    };
                    let (namespace, now_nanos, payer, requester) = accessor.with(|mut access| {
                        let store_data = access.get();
                        (
                            store_data.filesystem().clone(),
                            store_data.now_nanos(),
                            store_data.instance().storage_payer(),
                            store_data.instance().id(),
                        )
                    });
                    // The compile runs in its own session task, which stops
                    // the compile when this call is dropped, and streams the
                    // signed artifact directly from plugin memory to disk.
                    let written = match service
                        .aot_to_file(
                            &compile_authority,
                            &context,
                            &wasm,
                            hint,
                            request.profile,
                            service::AotDestination {
                                namespace,
                                absolute: dest_absolute,
                                now: now_nanos,
                                payer,
                                requester,
                            },
                        )
                        .await
                    {
                        Ok(written) => written,
                        Err(error) => return Ok(Err($convert_error(error))),
                    };
                    let _ = written.bytes;
                    Ok(Ok($bindings::helios::system::programs::AotResult {
                        destination_path: request.destination_path,
                        worker_threads: written.worker_threads,
                    }))
                }
            }
        }
    };
}

fn map_ipc_grant_error(error: IpcGrantError) -> ProgramExecError {
    tracing::error!(?error, "IPC endpoint grant rejected during program launch");
    let kind = match error {
        IpcGrantError::EmptyName
        | IpcGrantError::NameTooLong { .. }
        | IpcGrantError::DuplicateName(_) => ProgramExecErrorKind::InvalidPath,
        IpcGrantError::TooManyGrants { .. } => ProgramExecErrorKind::PermissionDenied,
    };
    ProgramExecError {
        kind,
        detail: ProgramExecErrorDetail::ProcessAuthorityDenied,
    }
}

macro_rules! impl_authority_conversion {
    ($extract_name:ident, $name:ident, $bindings:ident) => {
        fn $extract_name(
            table: &mut ResourceTable,
            grants: Vec<$bindings::helios::system::programs::CapabilityGrant>,
        ) -> wasmtime::Result<(
            Vec<$bindings::helios::system::programs::CapabilityGrant>,
            Result<IpcEndpointGrants, ProgramExecError>,
            bool,
        )> {
            let mut remaining = Vec::with_capacity(grants.len());
            let mut ipc_grants = IpcEndpointGrants::new();
            let mut first_error: Option<ProgramExecError> = None;
            let mut had_ipc = false;
            for grant in grants {
                match grant {
                    $bindings::helios::system::programs::CapabilityGrant::Ipc(ipc) => {
                        had_ipc = true;
                        let endpoint = table.delete(ipc.endpoint).map_err(wasmtime::Error::from)?;
                        if first_error.is_none()
                            && let Err(error) = ipc_grants.insert(&ipc.name, endpoint)
                        {
                            first_error = Some(map_ipc_grant_error(error));
                        }
                    }
                    other => remaining.push(other),
                }
            }
            let ipc_result = match first_error {
                Some(error) => Err(error),
                None => Ok(ipc_grants),
            };
            Ok((remaining, ipc_result, had_ipc))
        }

        fn $name(
            caller_authority: &ProcessAuthority,
            caller_id: InstanceId,
            child_id: Option<InstanceId>,
            registry: &crate::InstanceRegistry,
            grants: Vec<$bindings::helios::system::programs::CapabilityGrant>,
        ) -> Result<ProcessAuthority, ProgramExecError> {
            fn convert_scope(
                scope: $bindings::helios::system::programs::AuthorityScope,
                child_id: Option<InstanceId>,
            ) -> Result<(RequestedAuthorityScope, InstanceId), ProgramExecError> {
                match scope {
                    $bindings::helios::system::programs::AuthorityScope::Own => Ok((
                        RequestedAuthorityScope::Own,
                        child_id.unwrap_or_else(|| InstanceId::from_raw(0)),
                    )),
                    $bindings::helios::system::programs::AuthorityScope::Subtree(Some(id)) => Ok((
                        RequestedAuthorityScope::Subtree(Some(InstanceId::from_raw(id))),
                        child_id.unwrap_or_else(|| InstanceId::from_raw(id)),
                    )),
                    $bindings::helios::system::programs::AuthorityScope::Subtree(None) => {
                        let Some(target_child) = child_id else {
                            return Err(ProgramExecError {
                                kind: ProgramExecErrorKind::PermissionDenied,
                                detail: ProgramExecErrorDetail::ProcessAuthorityDenied,
                            });
                        };
                        Ok((RequestedAuthorityScope::Subtree(None), target_child))
                    }
                    $bindings::helios::system::programs::AuthorityScope::Machine => Ok((
                        RequestedAuthorityScope::Machine,
                        child_id.unwrap_or_else(|| InstanceId::from_raw(0)),
                    )),
                }
            }

            let mut authority = ProcessAuthority::empty();
            for grant in grants {
                match grant {
                    $bindings::helios::system::programs::CapabilityGrant::Directory(
                        directory,
                    ) => {
                        let mut rights = DirectoryAuthorityRights::empty();
                        for right in directory.rights {
                            rights |= match right {
                                $bindings::helios::system::programs::FilesystemRight::Read => {
                                    DirectoryAuthorityRights::READ
                                }
                                $bindings::helios::system::programs::FilesystemRight::Write => {
                                    DirectoryAuthorityRights::WRITE
                                }
                                $bindings::helios::system::programs::FilesystemRight::MutateDirectory => {
                                    DirectoryAuthorityRights::MUTATE_DIRECTORY
                                }
                                $bindings::helios::system::programs::FilesystemRight::Execute => {
                                    DirectoryAuthorityRights::EXECUTE
                                }
                            };
                        }
                        let preopen = caller_authority
                            .derive_directory_preopen(
                                directory.source_path,
                                directory.guest_name,
                                rights,
                            )
                            .map_err(map_process_authority_error)?;
                        if authority.cwd().is_none()
                            && preopen.guest_name() == "/"
                            && preopen.rights().contains(DirectoryAuthorityRights::READ)
                        {
                            let cwd = caller_authority
                                .derive_directory_cap(
                                    preopen.source_path(),
                                    preopen.guest_name(),
                                    DirectoryAuthorityRights::READ,
                                )
                                .map_err(map_process_authority_error)?;
                            authority.chdir(cwd);
                        }
                        authority.insert_directory_preopen(preopen);
                    }
                    $bindings::helios::system::programs::CapabilityGrant::Network(network) => {
                        let mut rights = NetworkAuthorityRights::empty();
                        for right in network.rights {
                            rights |= match right {
                                $bindings::helios::system::programs::NetworkRight::Tcp => {
                                    NetworkAuthorityRights::TCP
                                }
                                $bindings::helios::system::programs::NetworkRight::Udp => {
                                    NetworkAuthorityRights::UDP
                                }
                                $bindings::helios::system::programs::NetworkRight::Dns => {
                                    NetworkAuthorityRights::DNS
                                }
                                $bindings::helios::system::programs::NetworkRight::PrivilegedBind => {
                                    NetworkAuthorityRights::PRIVILEGED_BIND
                                }
                                $bindings::helios::system::programs::NetworkRight::Multicast => {
                                    NetworkAuthorityRights::MULTICAST
                                }
                                $bindings::helios::system::programs::NetworkRight::Admin => {
                                    NetworkAuthorityRights::ADMIN
                                }
                            };
                        }
                        let rights = caller_authority
                            .derive_network_rights(rights)
                            .map_err(map_process_authority_error)?;
                        authority.grant_network_rights(rights);
                    }
                    $bindings::helios::system::programs::CapabilityGrant::Clock(clock) => {
                        let mut rights = ClockAuthorityRights::empty();
                        for right in clock.rights {
                            rights |= match right {
                                $bindings::helios::system::programs::ClockRight::SetWallClock => {
                                    ClockAuthorityRights::SET_WALL_CLOCK
                                }
                            };
                        }
                        let rights = caller_authority
                            .derive_clock_rights(rights)
                            .map_err(map_process_authority_error)?;
                        authority.grant_clock_rights(rights);
                    }
                    $bindings::helios::system::programs::CapabilityGrant::Terminal(terminal) => {
                        let mut rights = TerminalAuthorityRights::empty();
                        for right in terminal.rights {
                            rights |= match right {
                                $bindings::helios::system::programs::TerminalRight::Input => {
                                    TerminalAuthorityRights::INPUT
                                }
                                $bindings::helios::system::programs::TerminalRight::Output => {
                                    TerminalAuthorityRights::OUTPUT
                                }
                                $bindings::helios::system::programs::TerminalRight::Control => {
                                    TerminalAuthorityRights::CONTROL
                                }
                            };
                        }
                        let rights = caller_authority
                            .derive_terminal_rights(rights)
                            .map_err(map_process_authority_error)?;
                        authority.grant_terminal_rights(rights);
                    }
                    $bindings::helios::system::programs::CapabilityGrant::Process(process) => {
                        let mut rights = crate::ProcessAuthorityRights::empty();
                        for right in process.rights {
                            rights |= match right {
                                $bindings::helios::system::programs::ProcessRight::Spawn => {
                                    crate::ProcessAuthorityRights::SPAWN
                                }
                                $bindings::helios::system::programs::ProcessRight::Exec => {
                                    crate::ProcessAuthorityRights::EXEC
                                }
                                $bindings::helios::system::programs::ProcessRight::Fork => {
                                    crate::ProcessAuthorityRights::FORK
                                }
                                $bindings::helios::system::programs::ProcessRight::Join => {
                                    crate::ProcessAuthorityRights::JOIN
                                }
                                $bindings::helios::system::programs::ProcessRight::Signal => {
                                    crate::ProcessAuthorityRights::SIGNAL
                                }
                            };
                        }
                        let rights = caller_authority
                            .derive_process_rights(rights)
                            .map_err(map_process_authority_error)?;
                        authority.grant_process_rights(rights);
                    }
                    $bindings::helios::system::programs::CapabilityGrant::Link(link) => {
                        let mut rights = LinkAuthorityRights::empty();
                        for right in link.rights {
                            rights |= match right {
                                $bindings::helios::system::programs::LinkRight::Source => {
                                    LinkAuthorityRights::SOURCE
                                }
                                $bindings::helios::system::programs::LinkRight::TargetDirectory => {
                                    LinkAuthorityRights::TARGET_DIRECTORY
                                }
                                $bindings::helios::system::programs::LinkRight::SymlinkCreate => {
                                    LinkAuthorityRights::SYMLINK_CREATE
                                }
                                $bindings::helios::system::programs::LinkRight::SymlinkRead => {
                                    LinkAuthorityRights::SYMLINK_READ
                                }
                            };
                        }
                        let rights = caller_authority
                            .derive_link_rights(rights)
                            .map_err(map_process_authority_error)?;
                        authority.grant_link_rights(rights);
                    }
                    $bindings::helios::system::programs::CapabilityGrant::Mount(mount) => {
                        let mut rights = crate::MountAuthorityRights::empty();
                        for right in mount.rights {
                            rights |= match right {
                                $bindings::helios::system::programs::MountRight::Mount => {
                                    crate::MountAuthorityRights::MOUNT
                                }
                                $bindings::helios::system::programs::MountRight::Unmount => {
                                    crate::MountAuthorityRights::UNMOUNT
                                }
                            };
                        }
                        let rights = caller_authority
                            .derive_mount_rights(rights)
                            .map_err(map_process_authority_error)?;
                        authority.grant_mount_rights(rights);
                    }
                    $bindings::helios::system::programs::CapabilityGrant::Device(device) => {
                        let mut rights = DeviceClassRights::empty();
                        for class in device.classes {
                            rights |= match class {
                                $bindings::helios::system::programs::DeviceClass::Display => {
                                    DeviceClassRights::DISPLAY
                                }
                                $bindings::helios::system::programs::DeviceClass::Input => {
                                    DeviceClassRights::INPUT
                                }
                                $bindings::helios::system::programs::DeviceClass::Gpu => {
                                    DeviceClassRights::GPU
                                }
                                $bindings::helios::system::programs::DeviceClass::Audio => {
                                    DeviceClassRights::AUDIO
                                }
                            };
                        }
                        let rights = caller_authority
                            .derive_device_class_rights(rights)
                            .map_err(map_process_authority_error)?;
                        authority.grant_device_classes(rights);
                    }
                    $bindings::helios::system::programs::CapabilityGrant::Diagnostics(
                        diagnostics,
                    ) => match diagnostics {
                        $bindings::helios::system::programs::DiagnosticsGrant::InspectRead(
                            scope,
                        ) => {
                            let (requested, target_child) = convert_scope(scope, child_id)?;
                            let cap = caller_authority
                                .derive_inspect_read_for_child(
                                    caller_id,
                                    target_child,
                                    requested,
                                    registry,
                                )
                                .map_err(map_process_authority_error)?;
                            authority.grant_inspect_read(cap.scope());
                        }
                        $bindings::helios::system::programs::DiagnosticsGrant::TraceRead(scope) => {
                            let (requested, target_child) = convert_scope(scope, child_id)?;
                            let cap = caller_authority
                                .derive_trace_read_for_child(
                                    caller_id,
                                    target_child,
                                    requested,
                                    registry,
                                )
                                .map_err(map_process_authority_error)?;
                            authority.grant_trace_read(cap.scope());
                        }
                        $bindings::helios::system::programs::DiagnosticsGrant::ProfileRead(
                            scope,
                        ) => {
                            let (requested, target_child) = convert_scope(scope, child_id)?;
                            let cap = caller_authority
                                .derive_profile_read_for_child(
                                    caller_id,
                                    target_child,
                                    requested,
                                    registry,
                                )
                                .map_err(map_process_authority_error)?;
                            authority.grant_profile_read(cap.scope());
                        }
                        $bindings::helios::system::programs::DiagnosticsGrant::Control => {
                            let rights = caller_authority
                                .derive_diagnostic_rights(DiagnosticAuthorityRights::CONTROL)
                                .map_err(map_process_authority_error)?;
                            authority.grant_diagnostic_rights(rights);
                        }
                    },
                    $bindings::helios::system::programs::CapabilityGrant::InstanceControl(
                        scope,
                    ) => {
                        let (requested, target_child) = convert_scope(scope, child_id)?;
                        let cap = caller_authority
                            .derive_instance_control_for_child(
                                caller_id,
                                target_child,
                                requested,
                                registry,
                            )
                            .map_err(map_process_authority_error)?;
                        authority.grant_instance_control(cap.scope());
                    }
                    $bindings::helios::system::programs::CapabilityGrant::Settings(settings) => {
                        let mut rights = SettingsAuthorityRights::empty();
                        for right in settings.rights {
                            rights |= match right {
                                $bindings::helios::system::programs::SettingsRight::Write => {
                                    SettingsAuthorityRights::WRITE
                                }
                            };
                        }
                        let rights = caller_authority
                            .derive_settings_rights(rights)
                            .map_err(map_process_authority_error)?;
                        authority.grant_settings_rights(rights);
                    }
                    $bindings::helios::system::programs::CapabilityGrant::Machine(machine) => {
                        let mut rights = crate::MachineAuthorityRights::empty();
                        for right in machine.rights {
                            rights |= match right {
                                $bindings::helios::system::programs::MachineRight::Control => {
                                    crate::MachineAuthorityRights::CONTROL
                                }
                                $bindings::helios::system::programs::MachineRight::Identity => {
                                    crate::MachineAuthorityRights::IDENTITY
                                }
                                $bindings::helios::system::programs::MachineRight::Virtualize => {
                                    crate::MachineAuthorityRights::VIRTUALIZE
                                }
                            };
                        }
                        let rights = caller_authority
                            .derive_machine_rights(rights)
                            .map_err(map_process_authority_error)?;
                        authority.grant_machine_rights(rights);
                    }
                    $bindings::helios::system::programs::CapabilityGrant::Ipc(_) => {
                        unreachable!(
                            "IPC endpoint grants are extracted from the caller's resource table before authority derivation"
                        )
                    }
                }
            }
            Ok(authority)
        }
    };
}

impl_authority_conversion!(
    extract_program_ipc_grants,
    build_program_child_authority,
    program_bindings
);

#[cfg(feature = "linux")]
macro_rules! impl_container_config_conversion {
    ($config_fn:ident, $creds_fn:ident, $bindings:ident, $build_authority:ident) => {
        fn $creds_fn(
            credentials: $bindings::helios::system::programs::ContainerCredentials,
        ) -> Result<helios_linux::syscall::Credentials, ProgramExecError> {
            helios_linux::syscall::Credentials::try_for_ids(
                credentials.uid,
                credentials.gid,
                credentials.supplementary_groups,
            )
            .map_err(|error| ProgramExecError {
                kind: ProgramExecErrorKind::InvalidPath,
                detail: ProgramExecErrorDetail::ContainerRefused(crate::RuntimeMessage::of(error)),
            })
        }

        fn $config_fn(
            caller_authority: &ProcessAuthority,
            caller_id: InstanceId,
            registry: &crate::InstanceRegistry,
            config: $bindings::helios::system::programs::ContainerConfig,
        ) -> Result<(ProcessAuthority, crate::ContainerConfig), ProgramExecError> {
            fn convert_mount(
                mount: $bindings::helios::system::programs::ContainerMount,
            ) -> crate::ContainerMountSpec {
                let mut rights = DirectoryAuthorityRights::empty();
                for right in mount.rights {
                    rights |= match right {
                        $bindings::helios::system::programs::FilesystemRight::Read => {
                            DirectoryAuthorityRights::READ
                        }
                        $bindings::helios::system::programs::FilesystemRight::Write => {
                            DirectoryAuthorityRights::WRITE
                        }
                        $bindings::helios::system::programs::FilesystemRight::MutateDirectory => {
                            DirectoryAuthorityRights::MUTATE_DIRECTORY
                        }
                        $bindings::helios::system::programs::FilesystemRight::Execute => {
                            DirectoryAuthorityRights::EXECUTE
                        }
                    };
                }
                let sharing = match mount.sharing {
                    $bindings::helios::system::programs::ContainerMountSharing::Private => {
                        crate::ContainerMountSharing::Private
                    }
                    $bindings::helios::system::programs::ContainerMountSharing::Shared => {
                        crate::ContainerMountSharing::Shared
                    }
                    $bindings::helios::system::programs::ContainerMountSharing::EphemeralOverlay => {
                        crate::ContainerMountSharing::EphemeralOverlay
                    }
                };
                crate::ContainerMountSpec {
                    source_path: mount.source_path,
                    target_path: mount.target_path,
                    rights,
                    sharing,
                }
            }

            if config.capability_grants.iter().any(|grant| {
                matches!(
                    grant,
                    $bindings::helios::system::programs::CapabilityGrant::Directory(_)
                )
            }) {
                return Err(ProgramExecError {
                    kind: ProgramExecErrorKind::PermissionDenied,
                    detail: ProgramExecErrorDetail::ContainerRefused(crate::RuntimeMessage::of(
                        "container capability grants cannot include directory grants; configure filesystem access via root and mounts",
                    )),
                });
            }
            let non_fs_authority = $build_authority(
                caller_authority,
                caller_id,
                None,
                registry,
                config.capability_grants,
            )?;
            let hostname = helios_linux::syscall::UtsField::from_configured(&config.hostname)
                .map_err(|error| ProgramExecError {
                    kind: ProgramExecErrorKind::InvalidPath,
                    detail: ProgramExecErrorDetail::ContainerRefused(crate::RuntimeMessage::of(
                        error,
                    )),
                })?;
            let domainname = helios_linux::syscall::UtsField::from_configured(&config.domainname)
                .map_err(|error| ProgramExecError {
                kind: ProgramExecErrorKind::InvalidPath,
                detail: ProgramExecErrorDetail::ContainerRefused(crate::RuntimeMessage::of(error)),
            })?;
            let credentials = $creds_fn(config.credentials)?;
            let container_config = crate::ContainerConfig {
                root: convert_mount(config.root),
                mounts: config.mounts.into_iter().map(convert_mount).collect(),
                shared_owner: crate::SharedOwner {
                    uid: config.shared_owner.uid,
                    gid: config.shared_owner.gid,
                },
                credentials,
                hostname,
                domainname,
            };
            Ok((non_fs_authority, container_config))
        }
    };
}

#[cfg(feature = "linux")]
impl_container_config_conversion!(
    convert_program_container_config,
    convert_program_container_credentials,
    program_bindings,
    build_program_child_authority
);

fn require_spawn_authority(
    caller_authority: &ProcessAuthority,
) -> Result<SpawnAuthority, crate::ProgramExecError> {
    caller_authority
        .derive_spawn_authority()
        .map_err(map_process_authority_error)
}

fn require_exec_authority(
    caller_authority: &ProcessAuthority,
) -> Result<ExecAuthority, crate::ProgramExecError> {
    caller_authority
        .derive_exec_authority()
        .map_err(map_process_authority_error)
}

/// A container creation or AOT compile may be started by a caller that holds
/// `SPAWN` or `EXEC`; a caller holding neither is refused as `spawn` and
/// `exec` refuse it.
#[cfg(feature = "linux")]
fn require_launch_authority(
    caller_authority: &ProcessAuthority,
) -> Result<(), crate::ProgramExecError> {
    if caller_authority.derive_spawn_authority().is_ok() {
        Ok(())
    } else {
        require_exec_authority(caller_authority).map(|_| ())
    }
}

/// A compile may be started by a caller that may spawn or exec; a caller
/// holding neither is refused as `spawn` and `exec` refuse it.
fn require_compile_authority(
    caller_authority: &ProcessAuthority,
) -> Result<CompileAuthority, crate::ProgramExecError> {
    match caller_authority.derive_spawn_authority() {
        Ok(spawn) => Ok(CompileAuthority::from(&spawn)),
        Err(_) => {
            require_exec_authority(caller_authority).map(|exec| CompileAuthority::from(&exec))
        }
    }
}

impl_program_bindings!(
    program_bindings,
    convert_program_launch_result,
    convert_program_launch_error,
    extract_program_ipc_grants,
    build_program_child_authority,
    convert_program_container_config,
    convert_program_container_credentials
);

#[cfg(test)]
mod lowering_tests {
    use alloc::vec::Vec;

    use bytes::{Bytes, BytesMut};

    use super::lower_bytes_to_vec;

    #[test]
    fn owned_bytes_lowering_reuses_unique_vec_buffer() {
        let source = Vec::from([1_u8, 2, 3, 4]);
        let source_ptr = source.as_ptr();
        let bytes = Bytes::from(source);

        let lowered = lower_bytes_to_vec(bytes);

        assert_eq!(lowered.as_slice(), [1, 2, 3, 4]);
        assert_eq!(lowered.as_ptr(), source_ptr);
    }

    #[test]
    fn frozen_bytes_mut_lowering_reuses_unique_vec_buffer() {
        let mut source = BytesMut::with_capacity(4096);
        source.extend_from_slice(&[1_u8, 2, 3, 4]);
        let source_ptr = source.as_ptr();
        let bytes = source.freeze();

        let lowered = lower_bytes_to_vec(bytes);

        assert_eq!(lowered.as_slice(), [1, 2, 3, 4]);
        assert_eq!(lowered.as_ptr(), source_ptr);
    }
}

#[cfg(test)]
mod hint_tests {
    use super::{
        AotCompileHint, ProgramExecErrorDetail, ProgramExecErrorKind, RequestedAotHint,
        program_bindings,
    };

    macro_rules! hint_cases {
        ($name:ident, $bindings:ident) => {
            mod $name {
                use super::*;
                use $bindings::helios::system::programs::AotHint;

                /// The conversion both the exec and the aot request make
                /// before the source is read and the compiler is asked.
                #[test]
                fn a_request_for_fast_is_refused() {
                    let error = AotHint::Fast
                        .compile_hint()
                        .expect_err("fast must be refused at the request");
                    assert_eq!(error.kind, ProgramExecErrorKind::InvalidHint);
                    assert_eq!(error.detail, ProgramExecErrorDetail::UnsupportedAotHint);
                }

                #[test]
                fn the_other_hints_convert() {
                    assert_eq!(
                        AotHint::Balanced.compile_hint(),
                        Ok(AotCompileHint::Balanced)
                    );
                    assert_eq!(
                        AotHint::Performance.compile_hint(),
                        Ok(AotCompileHint::Performance)
                    );
                }
            }
        };
    }

    hint_cases!(program, program_bindings);
}

#[cfg(test)]
mod authority_tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use super::{
        dns_network_rights, program_wit, require_compile_authority, require_exec_authority,
        require_spawn_authority, tcp_connect_network_rights, udp_bind_network_rights,
    };
    use crate::{
        AuthorityScope, ClockAuthorityRights, DeviceClassRights, DiagnosticAuthorityRights,
        DirectoryAuthorityRights, DirectoryPreopen, InstanceRegistry, LinkAuthorityRights,
        MachineAuthorityRights, NetworkAuthorityRights, ProcessAuthority, ProcessAuthorityRights,
        SettingsAuthorityRights, TerminalAuthorityRights,
    };

    use program_wit::programs::{
        AuthorityScope as WitScope, CapabilityGrant, ClockGrant, ClockRight, DeviceClass,
        DeviceGrant, DiagnosticsGrant, DirectoryGrant, FilesystemRight, LinkGrant, LinkRight,
        MachineGrant, MachineRight, NetworkGrant, NetworkRight, ProcessGrant, ProcessRight,
        SettingsGrant, SettingsRight, TerminalGrant, TerminalRight,
    };

    fn build_child_authority(
        caller: &ProcessAuthority,
        grants: Vec<CapabilityGrant>,
    ) -> Result<ProcessAuthority, crate::ProgramExecError> {
        let registry = InstanceRegistry::new();
        let parent_inst = registry.register("parent", 0);
        let child_inst = registry.register_child(Some(parent_inst.id()), "child", 1);
        super::build_program_child_authority(
            caller,
            parent_inst.id(),
            Some(child_inst.id()),
            &registry,
            grants,
        )
    }

    fn directory_grant(
        source_path: &str,
        guest_name: &str,
        rights: Vec<FilesystemRight>,
    ) -> CapabilityGrant {
        CapabilityGrant::Directory(DirectoryGrant {
            source_path: source_path.into(),
            guest_name: guest_name.into(),
            rights,
        })
    }

    fn network_grant(rights: Vec<NetworkRight>) -> CapabilityGrant {
        CapabilityGrant::Network(NetworkGrant { rights })
    }

    fn clock_grant(rights: Vec<ClockRight>) -> CapabilityGrant {
        CapabilityGrant::Clock(ClockGrant { rights })
    }

    fn terminal_grant(rights: Vec<TerminalRight>) -> CapabilityGrant {
        CapabilityGrant::Terminal(TerminalGrant { rights })
    }

    fn process_grant(rights: Vec<ProcessRight>) -> CapabilityGrant {
        CapabilityGrant::Process(ProcessGrant { rights })
    }

    fn link_grant(rights: Vec<LinkRight>) -> CapabilityGrant {
        CapabilityGrant::Link(LinkGrant { rights })
    }

    fn device_grant(classes: Vec<DeviceClass>) -> CapabilityGrant {
        CapabilityGrant::Device(DeviceGrant { classes })
    }

    fn machine_grant(rights: Vec<MachineRight>) -> CapabilityGrant {
        CapabilityGrant::Machine(MachineGrant { rights })
    }

    fn settings_grant(rights: Vec<SettingsRight>) -> CapabilityGrant {
        CapabilityGrant::Settings(SettingsGrant { rights })
    }

    #[test]
    fn empty_grants_create_zero_child_authority() {
        let child = build_child_authority(&ProcessAuthority::root(), Vec::new())
            .expect("empty grants must be a valid zero-authority child");

        assert!(child.directory_preopens().is_empty());
        assert!(child.network_rights().is_empty());
        assert!(child.clock_rights().is_empty());
        assert!(child.terminal_rights().is_empty());
        assert!(child.process_rights().is_empty());
        assert!(child.link_rights().is_empty());
        assert!(child.device_class_rights().is_empty());
        assert!(child.granted_devices().is_empty());
        assert!(child.inspect_read_scope().is_none());
        assert!(child.trace_read_scope().is_none());
        assert!(child.profile_read_scope().is_none());
        assert!(child.diagnostic_rights().is_empty());
        assert!(child.instance_control_scope().is_none());
        assert!(child.settings_rights().is_empty());
        assert!(child.machine_rights().is_empty());
        assert!(child.cwd().is_none());
    }

    #[test]
    fn orthogonal_diagnostics_instance_control_and_machine_grants_attenuate_monotonically() {
        let registry = InstanceRegistry::new();
        let parent_inst = registry.register("supervisor", 0);
        let child_inst = registry.register_child(Some(parent_inst.id()), "worker", 1);
        let sibling_inst = registry.register("sibling", 2);

        let mut caller = ProcessAuthority::empty();
        caller.grant_inspect_read(AuthorityScope::Machine);
        caller.grant_trace_read(AuthorityScope::Subtree(parent_inst.id()));
        caller.grant_profile_read(AuthorityScope::Own);
        caller.grant_diagnostic_rights(DiagnosticAuthorityRights::CONTROL);
        caller.grant_instance_control(AuthorityScope::Subtree(parent_inst.id()));
        caller.grant_machine_rights(MachineAuthorityRights::CONTROL);

        // `Subtree(None)` resolves to `Subtree(child_inst.id())`, strictly narrower
        // than `Machine` and `Subtree(parent_inst.id())`.
        let child = super::build_program_child_authority(
            &caller,
            parent_inst.id(),
            Some(child_inst.id()),
            &registry,
            vec![
                CapabilityGrant::Diagnostics(DiagnosticsGrant::InspectRead(WitScope::Subtree(
                    None,
                ))),
                CapabilityGrant::Diagnostics(DiagnosticsGrant::TraceRead(WitScope::Subtree(None))),
                CapabilityGrant::Diagnostics(DiagnosticsGrant::Control),
                CapabilityGrant::InstanceControl(WitScope::Own),
                machine_grant(vec![MachineRight::Control]),
            ],
        )
        .expect("narrowed orthogonal grants must succeed");

        assert_eq!(
            child.inspect_read_scope(),
            Some(AuthorityScope::Subtree(child_inst.id()))
        );
        assert_eq!(
            child.trace_read_scope(),
            Some(AuthorityScope::Subtree(child_inst.id()))
        );
        assert_eq!(child.profile_read_scope(), None);
        assert_eq!(
            child.diagnostic_rights(),
            DiagnosticAuthorityRights::CONTROL
        );
        assert_eq!(child.instance_control_scope(), Some(AuthorityScope::Own));
        assert_eq!(child.machine_rights(), MachineAuthorityRights::CONTROL);

        // Delegating `Own` profile-read to a child must fail (`Own` cannot transfer).
        let own_err = super::build_program_child_authority(
            &caller,
            parent_inst.id(),
            Some(child_inst.id()),
            &registry,
            vec![CapabilityGrant::Diagnostics(DiagnosticsGrant::ProfileRead(
                WitScope::Own,
            ))],
        )
        .expect_err("Own scope must never delegate to a child");
        assert_eq!(own_err.kind, crate::ProgramExecErrorKind::PermissionDenied);

        // Widening `Subtree(parent)` to `Machine` or `Subtree(sibling)` must fail.
        for bad_scope in [
            WitScope::Machine,
            WitScope::Subtree(Some(sibling_inst.id().raw())),
        ] {
            let err = super::build_program_child_authority(
                &caller,
                parent_inst.id(),
                Some(child_inst.id()),
                &registry,
                vec![CapabilityGrant::Diagnostics(DiagnosticsGrant::TraceRead(
                    bad_scope,
                ))],
            )
            .expect_err("scope widening must be refused");
            assert_eq!(err.kind, crate::ProgramExecErrorKind::PermissionDenied);
        }

        // `MachineRight::Identity` cannot be derived from `MachineRight::Control`.
        let id_err = super::build_program_child_authority(
            &caller,
            parent_inst.id(),
            Some(child_inst.id()),
            &registry,
            vec![machine_grant(vec![MachineRight::Identity])],
        )
        .expect_err("identity right must not derive from control right");
        assert_eq!(id_err.kind, crate::ProgramExecErrorKind::PermissionDenied);
    }

    #[test]
    fn diagnostics_and_machine_grants_exceeding_root_are_refused() {
        let error = build_child_authority(
            &ProcessAuthority::root(),
            vec![CapabilityGrant::Diagnostics(DiagnosticsGrant::Control)],
        )
        .expect_err("root authority holds no diagnostic right to hand on");
        assert_eq!(error.kind, crate::ProgramExecErrorKind::PermissionDenied);

        let error =
            build_child_authority(&ProcessAuthority::root(), vec![machine_grant(Vec::new())])
                .expect_err("an empty machine grant is refused");
        assert_eq!(error.kind, crate::ProgramExecErrorKind::PermissionDenied);
    }

    fn test_root_supervisor_authority() -> ProcessAuthority {
        use helios_hal::cpu::Cpu;
        let cpu = crate::test_support::TestCpu::with_entropy(0x42);
        let state: super::HostRuntimeState<
            crate::test_support::TestCpu,
            crate::test_support::TestNetworkService,
            crate::test_support::UnsupportedStorage,
        > = crate::RuntimeState::new(
            cpu.timebase(),
            1,
            0,
            crate::BootPayload::for_tests(),
            crate::GuestIsa::for_build_target(cpu.native_feature_probe()),
        );
        super::service::root_supervisor_authority(&state)
    }

    #[test]
    fn root_supervisor_authority_hands_explicit_observation_and_machine_rights_to_what_it_launches()
    {
        let root = test_root_supervisor_authority();
        assert!(root.is_root_supervisor());

        let child = build_child_authority(
            &root,
            vec![
                CapabilityGrant::Diagnostics(DiagnosticsGrant::InspectRead(WitScope::Machine)),
                CapabilityGrant::Diagnostics(DiagnosticsGrant::TraceRead(WitScope::Machine)),
                CapabilityGrant::Diagnostics(DiagnosticsGrant::ProfileRead(WitScope::Machine)),
                CapabilityGrant::Diagnostics(DiagnosticsGrant::Control),
                CapabilityGrant::InstanceControl(WitScope::Machine),
                machine_grant(vec![MachineRight::Control, MachineRight::Identity]),
            ],
        )
        .expect(
            "the root supervisor holds explicit machine observation, control, and identity rights",
        );

        assert!(!child.is_root_supervisor());
        assert_eq!(child.inspect_read_scope(), Some(AuthorityScope::Machine));
        assert_eq!(child.trace_read_scope(), Some(AuthorityScope::Machine));
        assert_eq!(child.profile_read_scope(), Some(AuthorityScope::Machine));
        assert_eq!(
            child.diagnostic_rights(),
            DiagnosticAuthorityRights::CONTROL
        );
        assert_eq!(
            child.instance_control_scope(),
            Some(AuthorityScope::Machine)
        );
        assert_eq!(
            child.machine_rights(),
            MachineAuthorityRights::CONTROL | MachineAuthorityRights::IDENTITY
        );
    }

    #[test]
    fn settings_grant_derives_from_caller_authority() {
        let mut caller = ProcessAuthority::empty();
        caller.grant_settings_rights(SettingsAuthorityRights::WRITE);

        let child =
            build_child_authority(&caller, vec![settings_grant(vec![SettingsRight::Write])])
                .expect("a caller holding the right may hand it on");

        assert_eq!(child.settings_rights(), SettingsAuthorityRights::WRITE);
    }

    #[test]
    fn settings_grant_exceeding_caller_is_refused() {
        let error = build_child_authority(
            &ProcessAuthority::root(),
            vec![settings_grant(vec![SettingsRight::Write])],
        )
        .expect_err("root authority holds no settings right to hand on");
        assert_eq!(error.kind, crate::ProgramExecErrorKind::PermissionDenied);

        let mut observer = ProcessAuthority::empty();
        observer.grant_diagnostic_rights(DiagnosticAuthorityRights::CONTROL);
        let error =
            build_child_authority(&observer, vec![settings_grant(vec![SettingsRight::Write])])
                .expect_err("the diagnostic control right is no settings right");
        assert_eq!(error.kind, crate::ProgramExecErrorKind::PermissionDenied);

        let error =
            build_child_authority(&ProcessAuthority::root(), vec![settings_grant(Vec::new())])
                .expect_err("an empty settings grant is a mistake");
        assert_eq!(error.kind, crate::ProgramExecErrorKind::PermissionDenied);
    }

    /// The inspector session's shell configures the machine through
    /// programs the debugger launches, so the debugger holds the right it
    /// hands on.
    #[test]
    fn root_supervisor_authority_hands_the_settings_right_to_what_it_launches() {
        let root = test_root_supervisor_authority();

        let child = build_child_authority(&root, vec![settings_grant(vec![SettingsRight::Write])])
            .expect("the root supervisor holds the settings right");

        assert_eq!(child.settings_rights(), SettingsAuthorityRights::WRITE);
        assert!(!child.is_root_supervisor());
    }

    #[test]
    fn virtualize_grant_derives_from_caller_authority_and_refuses_escalation() {
        let mut caller = ProcessAuthority::empty();
        caller.grant_machine_rights(MachineAuthorityRights::VIRTUALIZE);

        let child =
            build_child_authority(&caller, vec![machine_grant(vec![MachineRight::Virtualize])])
                .expect("a caller holding virtualize may hand it on");
        assert_eq!(child.machine_rights(), MachineAuthorityRights::VIRTUALIZE);

        let error = build_child_authority(
            &ProcessAuthority::root(),
            vec![machine_grant(vec![MachineRight::Virtualize])],
        )
        .expect_err("root authority holds no virtualize right to hand on");
        assert_eq!(error.kind, crate::ProgramExecErrorKind::PermissionDenied);

        let mut cpu_ctrl_only = ProcessAuthority::empty();
        cpu_ctrl_only.grant_machine_rights(MachineAuthorityRights::CONTROL);
        let error = build_child_authority(
            &cpu_ctrl_only,
            vec![machine_grant(vec![MachineRight::Virtualize])],
        )
        .expect_err("machine control right must not escalate to virtualize");
        assert_eq!(error.kind, crate::ProgramExecErrorKind::PermissionDenied);

        let error = build_child_authority(&caller, vec![machine_grant(Vec::new())])
            .expect_err("an empty machine grant is a mistake");
        assert_eq!(error.kind, crate::ProgramExecErrorKind::PermissionDenied);
    }

    #[test]
    fn root_supervisor_authority_hands_the_virtualize_right_to_what_it_launches() {
        let root = test_root_supervisor_authority();

        let child =
            build_child_authority(&root, vec![machine_grant(vec![MachineRight::Virtualize])])
                .expect("the root supervisor holds the virtualize right");

        assert_eq!(child.machine_rights(), MachineAuthorityRights::VIRTUALIZE);
        assert!(!child.is_root_supervisor());
    }

    #[test]
    fn device_grant_derives_subset_from_caller_authority() {
        let mut caller = ProcessAuthority::empty();
        caller.grant_device_classes(DeviceClassRights::DISPLAY | DeviceClassRights::INPUT);

        let child = build_child_authority(&caller, vec![device_grant(vec![DeviceClass::Input])])
            .expect("device child grant may derive a subset");

        assert_eq!(child.device_class_rights(), DeviceClassRights::INPUT);
        assert!(child.granted_devices().is_empty());
    }

    /// What the debugger passes down to the programs the inspector runs
    /// is bounded by what the debugger holds, which is every class and no
    /// named device.
    #[test]
    fn root_supervisor_authority_hands_every_device_class_to_what_it_launches() {
        let root = test_root_supervisor_authority();

        let child = build_child_authority(
            &root,
            vec![device_grant(vec![
                DeviceClass::Display,
                DeviceClass::Input,
                DeviceClass::Gpu,
                DeviceClass::Audio,
            ])],
        )
        .expect("the root supervisor holds every device class");

        assert_eq!(child.device_class_rights(), DeviceClassRights::all());
        assert!(child.granted_devices().is_empty());
        assert!(root.granted_devices().is_empty());
        assert!(!child.is_root_supervisor());
    }

    #[test]
    fn device_grant_exceeding_caller_is_refused() {
        let mut caller = ProcessAuthority::empty();
        caller.grant_device_classes(DeviceClassRights::DISPLAY);

        let error = build_child_authority(
            &caller,
            vec![device_grant(vec![DeviceClass::Display, DeviceClass::Gpu])],
        )
        .expect_err("GPU must not be created from display-only authority");
        assert_eq!(error.kind, crate::ProgramExecErrorKind::PermissionDenied);

        let error = build_child_authority(
            &ProcessAuthority::root(),
            vec![device_grant(vec![DeviceClass::Display])],
        )
        .expect_err("root authority holds no device class to hand on");
        assert_eq!(error.kind, crate::ProgramExecErrorKind::PermissionDenied);
    }

    #[test]
    fn explicit_grant_derives_subset_from_caller_authority() {
        let child = build_child_authority(
            &ProcessAuthority::root(),
            vec![directory_grant(
                "/bin",
                "/tools",
                vec![FilesystemRight::Read, FilesystemRight::Execute],
            )],
        )
        .expect("root authority may derive a narrower executable directory");

        let [preopen] = child.directory_preopens() else {
            panic!("expected exactly one derived preopen");
        };
        assert_eq!(preopen.source_path(), "/bin");
        assert_eq!(preopen.guest_name(), "/tools");
        assert_eq!(
            preopen.rights(),
            DirectoryAuthorityRights::READ | DirectoryAuthorityRights::EXECUTE
        );
        assert!(child.cwd().is_none());
    }

    #[test]
    fn explicit_root_directory_grant_sets_child_cwd_from_capability() {
        let child = build_child_authority(
            &ProcessAuthority::root(),
            vec![directory_grant("/", "/", vec![FilesystemRight::Read])],
        )
        .expect("explicit root directory grant may establish initial cwd");

        assert_eq!(
            child.cwd().expect("root directory grant should set cwd"),
            &DirectoryPreopen::new("/", "/", DirectoryAuthorityRights::READ)
                .expect("expected cwd should be valid")
        );
    }

    #[test]
    fn non_read_root_directory_grant_does_not_create_cwd() {
        let child = build_child_authority(
            &ProcessAuthority::root(),
            vec![directory_grant("/", "/", vec![FilesystemRight::Execute])],
        )
        .expect("executable root directory grant is valid");

        assert!(child.cwd().is_none());
    }

    #[test]
    fn explicit_grant_rejects_right_widening() {
        let mut caller = ProcessAuthority::empty();
        caller.insert_directory_preopen(
            DirectoryPreopen::new("/bin", "/", DirectoryAuthorityRights::READ)
                .expect("test authority must be valid"),
        );

        let error = build_child_authority(
            &caller,
            vec![directory_grant(
                "/bin",
                "/",
                vec![FilesystemRight::Read, FilesystemRight::Write],
            )],
        )
        .expect_err("write must not be derived from read-only caller authority");

        assert_eq!(error.kind, crate::ProgramExecErrorKind::PermissionDenied);
    }

    #[test]
    fn explicit_grant_rejects_path_escape() {
        let error = build_child_authority(
            &ProcessAuthority::root(),
            vec![directory_grant("../bin", "/", vec![FilesystemRight::Read])],
        )
        .expect_err("relative escape must not be accepted as a grant source");

        assert_eq!(error.kind, crate::ProgramExecErrorKind::InvalidPath);
    }

    #[test]
    fn network_grant_derives_subset_from_caller_authority() {
        let mut caller = ProcessAuthority::empty();
        caller.grant_network_rights(NetworkAuthorityRights::TCP | NetworkAuthorityRights::DNS);

        let child = build_child_authority(&caller, vec![network_grant(vec![NetworkRight::Tcp])])
            .expect("network child grant may derive a subset");

        assert_eq!(child.network_rights(), NetworkAuthorityRights::TCP);
    }

    #[test]
    fn network_grant_rejects_right_widening() {
        let mut caller = ProcessAuthority::empty();
        caller.grant_network_rights(NetworkAuthorityRights::DNS);

        let error = build_child_authority(&caller, vec![network_grant(vec![NetworkRight::Tcp])])
            .expect_err("TCP must not be created from DNS-only authority");

        assert_eq!(error.kind, crate::ProgramExecErrorKind::PermissionDenied);
    }

    #[test]
    fn clock_grant_derives_subset_from_caller_authority() {
        let mut caller = ProcessAuthority::empty();
        caller.grant_clock_rights(ClockAuthorityRights::SET_WALL_CLOCK);

        let child =
            build_child_authority(&caller, vec![clock_grant(vec![ClockRight::SetWallClock])])
                .expect("clock child grant may derive a subset");

        assert_eq!(child.clock_rights(), ClockAuthorityRights::SET_WALL_CLOCK);
    }

    #[test]
    fn terminal_grant_derives_subset_from_caller_authority() {
        let mut caller = ProcessAuthority::empty();
        caller.grant_terminal_rights(TerminalAuthorityRights::OUTPUT);

        let child =
            build_child_authority(&caller, vec![terminal_grant(vec![TerminalRight::Output])])
                .expect("terminal child grant may derive a subset");

        assert_eq!(child.terminal_rights(), TerminalAuthorityRights::OUTPUT);
    }

    #[test]
    fn process_grant_derives_subset_from_caller_authority() {
        let mut caller = ProcessAuthority::empty();
        caller.grant_process_rights(ProcessAuthorityRights::SPAWN | ProcessAuthorityRights::JOIN);

        let child = build_child_authority(&caller, vec![process_grant(vec![ProcessRight::Spawn])])
            .expect("process child grant may derive a subset");

        assert_eq!(child.process_rights(), ProcessAuthorityRights::SPAWN);
    }

    #[test]
    fn process_grant_rejects_right_widening() {
        let mut caller = ProcessAuthority::empty();
        caller.grant_process_rights(ProcessAuthorityRights::JOIN);

        let error = build_child_authority(&caller, vec![process_grant(vec![ProcessRight::Spawn])])
            .expect_err("spawn must not be created from join-only authority");

        assert_eq!(error.kind, crate::ProgramExecErrorKind::PermissionDenied);
    }

    #[test]
    fn link_grant_derives_subset_from_caller_authority() {
        let mut caller = ProcessAuthority::empty();
        caller.grant_link_rights(LinkAuthorityRights::SOURCE | LinkAuthorityRights::SYMLINK_READ);

        let child = build_child_authority(
            &caller,
            vec![link_grant(vec![LinkRight::Source, LinkRight::SymlinkRead])],
        )
        .expect("link child grant may derive a subset");

        assert_eq!(
            child.link_rights(),
            LinkAuthorityRights::SOURCE | LinkAuthorityRights::SYMLINK_READ
        );
    }

    #[test]
    fn link_grant_rejects_right_widening() {
        let mut caller = ProcessAuthority::empty();
        caller.grant_link_rights(LinkAuthorityRights::SYMLINK_READ);

        let error =
            build_child_authority(&caller, vec![link_grant(vec![LinkRight::SymlinkCreate])])
                .expect_err("symlink-create must not be created from readlink-only authority");

        assert_eq!(error.kind, crate::ProgramExecErrorKind::PermissionDenied);
    }

    #[test]
    fn network_operations_require_typed_capability_sets() {
        assert_eq!(dns_network_rights(), NetworkAuthorityRights::DNS);
        assert_eq!(
            tcp_connect_network_rights(),
            NetworkAuthorityRights::TCP | NetworkAuthorityRights::DNS
        );
        assert_eq!(udp_bind_network_rights(0), NetworkAuthorityRights::UDP);
        assert_eq!(udp_bind_network_rights(1024), NetworkAuthorityRights::UDP);
        assert_eq!(
            udp_bind_network_rights(80),
            NetworkAuthorityRights::UDP | NetworkAuthorityRights::PRIVILEGED_BIND
        );
    }

    #[test]
    fn program_spawn_and_exec_require_process_authority() {
        let caller = ProcessAuthority::empty();
        assert_eq!(
            require_spawn_authority(&caller)
                .expect_err("spawn authority must be explicit")
                .kind,
            crate::ProgramExecErrorKind::PermissionDenied
        );
        assert_eq!(
            require_exec_authority(&caller)
                .expect_err("exec authority must be explicit")
                .kind,
            crate::ProgramExecErrorKind::PermissionDenied
        );

        let mut caller = ProcessAuthority::empty();
        caller.grant_process_rights(ProcessAuthorityRights::SPAWN | ProcessAuthorityRights::EXEC);
        require_spawn_authority(&caller).expect("spawn authority should be accepted");
        require_exec_authority(&caller).expect("exec authority should be accepted");
    }

    #[test]
    fn aot_requires_a_process_right() {
        let caller = ProcessAuthority::empty();
        assert_eq!(
            require_compile_authority(&caller)
                .expect_err("aot must require a process right")
                .kind,
            crate::ProgramExecErrorKind::PermissionDenied
        );

        let mut caller = ProcessAuthority::empty();
        caller.grant_process_rights(ProcessAuthorityRights::EXEC);
        require_compile_authority(&caller).expect("an EXEC holder may start a compile");

        let mut caller = ProcessAuthority::empty();
        caller.grant_process_rights(ProcessAuthorityRights::SPAWN);
        require_compile_authority(&caller).expect("a SPAWN holder may start a compile");
    }

    #[test]
    fn resolve_https_enforces_dns_authority_and_converts_records_in_both_worlds() {
        fn poll_ready<F: core::future::Future>(future: F) -> F::Output {
            let waker = core::task::Waker::noop();
            let mut cx = core::task::Context::from_waker(waker);
            match core::pin::pin!(future).poll(&mut cx) {
                core::task::Poll::Ready(output) => output,
                core::task::Poll::Pending => panic!("ready test future unexpectedly parked"),
            }
        }

        let mut without_dns = ProcessAuthority::empty();
        without_dns.grant_network_rights(NetworkAuthorityRights::TCP | NetworkAuthorityRights::UDP);
        assert!(without_dns.derive_dns_cap().is_err());

        let denied = poll_ready(super::execute_net_resolve_https(
            without_dns.derive_dns_cap().is_ok(),
            Some(crate::test_support::TestNetworkService::new()),
            "example.com",
            443,
            5_000_000_000,
        ))
        .expect_err("TCP+UDP without DNS authority must be denied");
        let program_denied = super::convert_program_net_resolve_https_error(denied);
        assert!(matches!(
            program_denied.kind,
            program_wit::net::DnsErrorKind::PermissionDenied
        ));

        let mut with_dns = ProcessAuthority::empty();
        with_dns.grant_network_rights(NetworkAuthorityRights::DNS);
        assert!(with_dns.derive_dns_cap().is_ok());

        let absent = poll_ready(super::execute_net_resolve_https(
            with_dns.derive_dns_cap().is_ok(),
            Some(crate::test_support::TestNetworkService::new()),
            "example.com",
            443,
            5_000_000_000,
        ))
        .expect("DNS authority should permit resolve-https");
        assert_eq!(absent, None);

        let unavailable = poll_ready(super::execute_net_resolve_https::<
            crate::test_support::TestNetworkService,
        >(
            with_dns.derive_dns_cap().is_ok(),
            None,
            "example.com",
            443,
            5_000_000_000,
        ))
        .expect_err("missing network service must fail cleanly");
        let program_unavailable = super::convert_program_net_resolve_https_error(unavailable);
        assert!(matches!(
            program_unavailable.kind,
            super::program_wit::net::DnsErrorKind::Unavailable
        ));

        let sample = crate::HttpsRecord {
            alpn: alloc::vec!["h3".into(), "h2".into()],
            port: Some(8443),
            ttl_nanos: 120_000_000_000,
        };
        let prog = super::convert_program_https_record(sample);
        assert_eq!(prog.alpn, alloc::vec!["h3", "h2"]);
        assert_eq!(prog.port, Some(8443));
        assert_eq!(prog.ttl, 120_000_000_000);
    }
}

async fn read_program_source<T, CpuImpl, Net, StorageImpl>(
    accessor: &Accessor<T, HasSelf<StoreData<CpuImpl, Net, StorageImpl>>>,
    path: &str,
    authority: &ProcessAuthority,
) -> wasmtime::Result<Result<ProgramSource, crate::ProgramExecError>>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let absolute =
        crate::resolve_guest_path("/", path).map_err(map_component_fs_path_error_to_wasmtime)?;
    let Some(floor) = authority.program_load_floor(&absolute) else {
        return Ok(Err(ProgramExecError {
            kind: ProgramExecErrorKind::PermissionDenied,
            detail: ProgramExecErrorDetail::ProgramSourceNotGranted,
        }));
    };
    let namespace = accessor.with(|mut access| access.get().filesystem().clone());
    let contents = crate::wasmtime_adapter::wasi::read_program_file(&namespace, &absolute, floor)
        .await
        .map_err(ProgramExecError::from_source_read_error)?;
    Ok(Ok(ProgramSource::from_file(contents)))
}

async fn apply_requested_cwd<StorageImpl: crate::Storage>(
    child_authority: &mut ProcessAuthority,
    namespace: &crate::Namespace<StorageImpl>,
    raw_cwd: Option<&str>,
) -> Result<Option<String>, ProgramExecError> {
    let Some(raw_cwd) = raw_cwd else {
        return Ok(None);
    };
    let guest_cwd = crate::resolve_guest_path("/", raw_cwd).map_err(|_| ProgramExecError {
        kind: ProgramExecErrorKind::InvalidPath,
        detail: ProgramExecErrorDetail::InvalidProgramPath,
    })?;
    let covering = child_authority
        .directory_preopens()
        .iter()
        .filter(|preopen| {
            let name = preopen.guest_name();
            if name == "/" {
                true
            } else if let Some(rest) = guest_cwd.strip_prefix(name) {
                rest.is_empty() || rest.starts_with('/')
            } else {
                false
            }
        })
        .max_by_key(|preopen| preopen.guest_name().len())
        .cloned()
        .ok_or(ProgramExecError {
            kind: ProgramExecErrorKind::PermissionDenied,
            detail: ProgramExecErrorDetail::ProcessAuthorityDenied,
        })?;
    let suffix = if covering.guest_name() == "/" {
        guest_cwd.as_str()
    } else {
        guest_cwd.strip_prefix(covering.guest_name()).unwrap_or("")
    };
    let source_path = if suffix.is_empty() || suffix == "/" {
        covering.source_path().to_owned()
    } else if covering.source_path() == "/" {
        suffix.to_owned()
    } else {
        alloc::format!("{}{suffix}", covering.source_path())
    };
    let cap = child_authority
        .derive_directory_cap(&source_path, &guest_cwd, covering.rights())
        .map_err(map_process_authority_error)?;
    let resolved = namespace
        .resolve(&source_path)
        .map_err(ProgramExecError::from_source_read_error)?;
    let metadata = helios_hal::fs::FileSystem::stat(resolved.fs(), resolved.path())
        .await
        .map_err(ProgramExecError::from_source_read_error)?;
    if metadata.kind != helios_hal::fs::NodeKind::Directory {
        return Err(ProgramExecError {
            kind: ProgramExecErrorKind::InvalidPath,
            detail: ProgramExecErrorDetail::InvalidProgramPath,
        });
    }
    child_authority.chdir(cap);
    Ok(Some(guest_cwd))
}

#[cfg(feature = "linux")]
async fn resolve_host_shebang_source<T, CpuImpl, Net, StorageImpl>(
    accessor: &Accessor<T, HasSelf<StoreData<CpuImpl, Net, StorageImpl>>>,
    initial_path: &str,
    caller_authority: &ProcessAuthority,
    mut source: ProgramSource,
    argv: &mut ProgramArgv,
    operation: ProgramHostOperation,
) -> Result<ProgramSource, ProgramExecError>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let mut current_path = initial_path.to_owned();
    for depth in 0..=service::MAX_SHEBANG_DEPTH {
        let shebang = match &source {
            ProgramSource::RawWasm(bytes) => service::parse_shebang(bytes),
            _ => None,
        };
        let Some((interp, opt_arg)) = shebang else {
            return Ok(source);
        };
        if depth == service::MAX_SHEBANG_DEPTH {
            return Err(ProgramExecError {
                kind: ProgramExecErrorKind::InvalidPath,
                detail: ProgramExecErrorDetail::InvalidProgramPath,
            });
        }
        argv.rewrite_shebang(interp.clone(), opt_arg, current_path);
        current_path = interp;
        source = match read_program_source(accessor, &current_path, caller_authority).await {
            Ok(Ok(next)) => next,
            Ok(Err(error)) => return Err(error),
            Err(error) => return Err(map_program_host_error(operation, error)),
        };
    }
    Err(ProgramExecError {
        kind: ProgramExecErrorKind::InvalidPath,
        detail: ProgramExecErrorDetail::InvalidProgramPath,
    })
}

async fn read_program_source_bounded<T, CpuImpl, Net, StorageImpl>(
    accessor: &Accessor<T, HasSelf<StoreData<CpuImpl, Net, StorageImpl>>>,
    path: &str,
    authority: &ProcessAuthority,
    max_bytes: u64,
) -> wasmtime::Result<Result<ProgramSource, crate::ProgramExecError>>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let absolute =
        crate::resolve_guest_path("/", path).map_err(map_component_fs_path_error_to_wasmtime)?;
    let Some(floor) = authority.program_load_floor(&absolute) else {
        return Ok(Err(ProgramExecError {
            kind: ProgramExecErrorKind::PermissionDenied,
            detail: ProgramExecErrorDetail::ProgramSourceNotGranted,
        }));
    };
    let namespace = accessor.with(|mut access| access.get().filesystem().clone());
    match crate::wasmtime_adapter::wasi::read_program_file_bounded(
        &namespace, &absolute, floor, max_bytes,
    )
    .await
    {
        Ok(crate::wasmtime_adapter::wasi::BoundedProgramFile::Contents(contents)) => {
            Ok(Ok(ProgramSource::from_file(contents)))
        }
        Ok(crate::wasmtime_adapter::wasi::BoundedProgramFile::TooLarge(bytes)) => {
            Ok(Err(ProgramExecError {
                kind: ProgramExecErrorKind::InvalidBinary,
                detail: ProgramExecErrorDetail::CompilerInputTooLarge {
                    bytes,
                    limit: max_bytes,
                },
            }))
        }
        Err(error) => Ok(Err(ProgramExecError::from_source_read_error(error))),
    }
}

fn map_component_fs_path_error_to_wasmtime(error: crate::ComponentFsPathError) -> wasmtime::Error {
    wasmtime::Error::new(error)
}

fn map_process_authority_error(error: ProcessAuthorityError) -> crate::ProgramExecError {
    tracing::error!(?error, "process authority rejected program operation");
    let kind = match error {
        ProcessAuthorityError::InvalidPath(_) | ProcessAuthorityError::EmptyRights => {
            crate::ProgramExecErrorKind::InvalidPath
        }
        ProcessAuthorityError::EmptyNetworkRights
        | ProcessAuthorityError::EmptyClockRights
        | ProcessAuthorityError::EmptyTerminalRights
        | ProcessAuthorityError::EmptyProcessRights
        | ProcessAuthorityError::DirectoryGrantExceedsAuthority(_)
        | ProcessAuthorityError::NetworkGrantExceedsAuthority(_)
        | ProcessAuthorityError::ClockGrantExceedsAuthority(_)
        | ProcessAuthorityError::TerminalGrantExceedsAuthority(_)
        | ProcessAuthorityError::ProcessGrantExceedsAuthority(_)
        | ProcessAuthorityError::EmptyLinkRights
        | ProcessAuthorityError::LinkGrantExceedsAuthority(_)
        | ProcessAuthorityError::EmptyMountRights
        | ProcessAuthorityError::MountGrantExceedsAuthority(_)
        | ProcessAuthorityError::MountPointOutsideAuthority(_)
        | ProcessAuthorityError::EmptyDeviceClassRights
        | ProcessAuthorityError::DeviceClassGrantExceedsAuthority(_)
        | ProcessAuthorityError::DeviceGrantExceedsAuthority(_)
        | ProcessAuthorityError::DeviceNameTooLong
        | ProcessAuthorityError::TooManyDeviceGrants
        | ProcessAuthorityError::EmptyDiagnosticRights
        | ProcessAuthorityError::DiagnosticGrantExceedsAuthority(_)
        | ProcessAuthorityError::InspectReadMissing
        | ProcessAuthorityError::TraceReadMissing
        | ProcessAuthorityError::ProfileReadMissing
        | ProcessAuthorityError::InstanceControlMissing
        | ProcessAuthorityError::InspectReadExceedsAuthority { .. }
        | ProcessAuthorityError::TraceReadExceedsAuthority { .. }
        | ProcessAuthorityError::ProfileReadExceedsAuthority { .. }
        | ProcessAuthorityError::InstanceControlExceedsAuthority { .. }
        | ProcessAuthorityError::EmptySettingsRights
        | ProcessAuthorityError::SettingsGrantExceedsAuthority(_)
        | ProcessAuthorityError::EmptyMachineRights
        | ProcessAuthorityError::MachineGrantExceedsAuthority(_)
        | ProcessAuthorityError::RootSupervisorDenied => {
            crate::ProgramExecErrorKind::PermissionDenied
        }
    };
    crate::ProgramExecError {
        kind,
        detail: ProgramExecErrorDetail::ProcessAuthorityDenied,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProgramHostOperation {
    ReadSpawnSource,
    ReadExecSource,
    ReadAotSource,
    WriteAotArtifact,
}

fn map_program_host_error(
    operation: ProgramHostOperation,
    error: wasmtime::Error,
) -> crate::ProgramExecError {
    tracing::error!(?operation, ?error, "program host operation failed");
    crate::ProgramExecError {
        kind: crate::ProgramExecErrorKind::Internal,
        detail: ProgramExecErrorDetail::HostOperationFailed,
    }
}

/// The kernel handles a system component borrows for its whole run.
pub(super) struct SystemComponentHost<CpuImpl, Net, StorageImpl>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    pub(super) cpu: CpuImpl,
    pub(super) timer: crate::Timer<CpuImpl>,
    pub(super) spawner: crate::Spawner<CpuImpl>,
    pub(super) debug_state: HostRuntimeState<CpuImpl, Net, StorageImpl>,
    pub(super) read_serial: crate::SerialReader,
    pub(super) write_serial: crate::DebugSerialWriter,
}

/// Selects stdio routing for the single signed root component (`init` /
/// `component-manager`).
///
/// When the platform exposes a debug UART, the root component's stdout and
/// stderr write to the debug serial line as line-framed segments, while stdin
/// stays closed so the root supervisor never consumes incoming serial RPC bytes
/// meant for supervised children (such as `/bin/debugger`). On headless
/// platforms with no debug UART, output goes to observer trace records.
pub(crate) fn root_component_output_mode(has_debug_serial: bool) -> OutputMode {
    if has_debug_serial {
        OutputMode::RoutedChild {
            stdin: crate::ComponentInputRoute::Closed,
            stdout: crate::ComponentOutputRoute::Serial,
            stderr: crate::ComponentOutputRoute::Serial,
        }
    } else {
        OutputMode::Trace
    }
}

async fn run_root_component<CpuImpl, Net, StorageImpl>(
    init: crate::EmbeddedInit,
    host: SystemComponentHost<CpuImpl, Net, StorageImpl>,
    has_debug_serial: bool,
) -> Result<(), RootComponentError>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    use crate::{
        ComponentExecContext, ComponentExecutor, ComponentExitStatus, ComponentRuntimeFactory,
        ComponentWorld,
    };

    let SystemComponentHost {
        cpu,
        timer,
        spawner,
        debug_state,
        read_serial,
        write_serial,
    } = host;

    let component = init.component();
    let component_name = component.name();
    let argv0 = init.argv0();

    write_serial.emit_stage_marker("engine:new");
    tracing::info!(
        component = component_name,
        argv0,
        "borrowing shared component engine for root supervisor"
    );
    let program_service = debug_state.wait_for_program_service().await;
    let runtime = program_service.runtime();
    let engine = program_service.engine();
    write_serial.emit_stage_marker("engine:ok");

    tracing::info!(
        component = component_name,
        "loading signed root supervisor component artifact"
    );
    let artifact = component.bootfs_bytes();
    let trusted = cwasm::trust_bootfs_artifact(&artifact);
    // SAFETY: `trusted` comes from the signature-verified bootfs image
    // (`trust_bootfs_artifact`), built for `engine`'s target and configuration.
    let component =
        unsafe { wasmtime::component::Component::deserialize(engine.raw(), trusted.payload()) }
            .map_err(RootComponentError::LoadComponent)?;
    let compiled = crate::wasmtime_adapter::WasmtimeCompiledComponent { component };
    write_serial.emit_stage_marker("component:ok");

    write_serial.emit_stage_marker("instantiate:begin");
    tracing::info!(
        component = component_name,
        argv0,
        "instantiating root supervisor component"
    );
    let instance_registry = debug_state.instance_registry();
    let instance = instance_registry.register_with_policy(
        component_name,
        debug_state.uptime_nanos(cpu.now().ticks()),
        crate::OomPolicy::SystemComponent,
    );

    let instantiate_cpu = cpu.clone();
    let instantiate_timer = timer.clone();
    // The root supervisor is kernel infrastructure, so its tasks are funded
    // from the arena's kernel reserve: user-mode load fills the instance
    // share and stops there.
    let instantiate_spawner = spawner.instance_spawner(crate::TaskFunding::Kernel, &instance);

    let authority = service::root_supervisor_authority(&debug_state);
    let context = ComponentExecContext::new(
        cpu,
        timer,
        spawner,
        debug_state.clone(),
        instance_registry,
        instance,
        debug_state.clone(),
        alloc::vec![argv0.to_owned()],
        Vec::new(),
        authority,
        root_component_output_mode(has_debug_serial),
        read_serial,
        write_serial,
    );

    let executor = runtime.instantiate(engine, &compiled, ComponentWorld::RootSupervisor, context);
    let instantiate_started_at = monotonic_nanos(&instantiate_cpu);
    let instantiate_heartbeat = spawn_component_phase_heartbeat(
        &instantiate_spawner,
        &instantiate_cpu,
        &instantiate_timer,
        &instantiate_spawner.progress_counter(),
        write_serial,
        ComponentPhase {
            name: "instantiate",
            started_at: instantiate_started_at,
        },
    )
    .map_err(RootComponentError::TaskCapacity)?;
    let executor = executor.await;
    drop(instantiate_heartbeat);
    let executor = executor.map_err(RootComponentError::InstantiateComponent)?;
    write_serial.emit_stage_marker("instantiate:ok");

    tracing::info!(
        component = component_name,
        argv0,
        "entering root supervisor wasi:cli/run"
    );

    let result = executor
        .run()
        .await
        .map_err(RootComponentError::RunComponent)?;

    write_serial.emit_stage_marker("run:ok");
    tracing::info!(
        component = component_name,
        "root supervisor wasi:cli/run returned"
    );

    match result.status {
        ComponentExitStatus::Ok => Ok(()),
        ComponentExitStatus::Failed => Err(RootComponentError::GuestFailed),
    }
}

pub(crate) fn component_linker<CpuImpl, Net, StorageImpl>(
    engine: &Engine,
    world: ComponentBindingSet,
    component: &Component,
) -> wasmtime::Result<Linker<StoreData<CpuImpl, Net, StorageImpl>>>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let mut linker = Linker::<StoreData<CpuImpl, Net, StorageImpl>>::new(engine);
    let wasi_imports =
        crate::wasmtime_adapter::wasi::WasiImportSet::from_component(engine, component);
    linker.allow_shadowing(true);
    crate::wasmtime_adapter::wasi::preview3::add_to_linker(&mut linker, &wasi_imports)?;
    crate::wasmtime_adapter::wasi::http::add_to_linker(&mut linker, &wasi_imports)?;
    add_serial_to_linker(&mut linker)?;
    add_sync_to_linker(&mut linker)?;
    ipc::add_ipc_to_linker(&mut linker)?;
    machine_identity::add_machine_identity_to_linker(&mut linker)?;
    inspect::add_inspect_to_linker(&mut linker)?;
    instances_snapshot::add_instances_to_linker(&mut linker)?;
    instances_snapshot::add_snapshot_to_linker(&mut linker)?;
    add_program_world_to_linker(&mut linker)?;
    if matches!(world, ComponentBindingSet::RootSupervisor) {
        service::add_root_supervisor_to_linker(&mut linker)?;
    }
    Ok(linker)
}

/// Interrupts every store of `victim`, whose kill flag was just set, so
/// a guest that is running meets the condemnation at its next function
/// entry or loop header, and one in host code or suspended meets it the
/// moment it is back in wasm.
///
/// Programs and kernel plugins run on the program service's engine, and
/// so does every store a kill can interrupt; before that service is
/// installed there is none. A system component runs on an engine of its
/// own, which nothing interrupts: it meets a condemnation where its call
/// completes.
pub(crate) fn deliver_kill<CpuImpl, Net, StorageImpl>(
    runtime_state: &HostRuntimeState<CpuImpl, Net, StorageImpl>,
    victim: InstanceId,
) where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    if let Some(service) = runtime_state.program_service() {
        service.interrupt_instance(victim);
    }
}

/// Turn epilogue for a component store: drains retired sockets on every
/// turn and, when the component was launched as a child program, wakes and
/// stops the store on a pending signal raised by its parent.
pub(crate) struct ComponentStoreEpilogue {
    retirement: crate::SocketRetirementQueue,
    signal_state: Option<WasixSignalState>,
}

impl ComponentStoreEpilogue {
    pub(crate) fn new(
        retirement: crate::SocketRetirementQueue,
        signal_state: Option<WasixSignalState>,
    ) -> Self {
        Self {
            retirement,
            signal_state,
        }
    }
}

fn take_component_signal_stop(signal_state: &WasixSignalState) -> Option<wasmtime::Error> {
    signal_state
        .sweep_pending(|signal| match signal.default_action() {
            helios_unix::DefaultSignalAction::Ignore
            | helios_unix::DefaultSignalAction::Continue => helios_unix::SignalSweep::Drop,
            helios_unix::DefaultSignalAction::Terminate
            | helios_unix::DefaultSignalAction::CoreDump
            | helios_unix::DefaultSignalAction::Stop => helios_unix::SignalSweep::Take,
        })
        .map(|signal| {
            wasmtime::Error::new(Preview1SignalExit {
                signal: signal.raw(),
            })
        })
}

impl crate::component::StopWake for ComponentStoreEpilogue {
    type Wait = Option<crate::NotifyWaiter>;

    fn arm_stop_wait(&self) -> Self::Wait {
        self.signal_state.as_ref().map(WasixSignalState::wait_state)
    }

    fn poll_stop_wait(
        &self,
        cx: &mut core::task::Context<'_>,
        wait: &mut Self::Wait,
    ) -> core::task::Poll<()> {
        match (&self.signal_state, wait) {
            (Some(signals), Some(wait)) => signals.poll_changed(cx, wait),
            _ => core::task::Poll::Pending,
        }
    }
}

impl<RuntimeStateImpl> crate::component::TurnEpilogue<RuntimeStateImpl, wasmtime::Error>
    for ComponentStoreEpilogue
where
    RuntimeStateImpl: crate::ComponentRuntimeState,
{
    fn end_turn(&self, runtime_state: &RuntimeStateImpl) {
        if !self.retirement.is_empty() {
            runtime_state.retire_network_handles(&self.retirement);
        }
        self.retirement.drain_snapshot_releases(|token| {
            runtime_state.release_snapshot_hold(token);
        });
    }

    fn take_stop(&self) -> Option<wasmtime::Error> {
        self.signal_state
            .as_ref()
            .and_then(take_component_signal_stop)
    }
}

/// A component store on `engine`, with the interrupt route the
/// end of a time slice, a kill and the drive of its calls go through.
pub(crate) fn store_with_state<CpuImpl, Net, StorageImpl>(
    engine: &crate::wasmtime_adapter::WasmtimeEngine,
    state: StoreData<CpuImpl, Net, StorageImpl>,
) -> (
    Store<StoreData<CpuImpl, Net, StorageImpl>>,
    crate::wasmtime_adapter::preemption::StoreInterrupts<CpuImpl>,
)
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    store_with_signal_state(engine, state, None)
}

/// A component store on `engine` that also answers to `signal_state` when
/// launched as a child program.
pub(crate) fn store_with_signal_state<CpuImpl, Net, StorageImpl>(
    engine: &crate::wasmtime_adapter::WasmtimeEngine,
    mut state: StoreData<CpuImpl, Net, StorageImpl>,
    signal_state: Option<WasixSignalState>,
) -> (
    Store<StoreData<CpuImpl, Net, StorageImpl>>,
    crate::wasmtime_adapter::preemption::StoreInterrupts<CpuImpl>,
)
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    state.configure_resource_table();
    let instance = state.instance().id();
    let mut store = Store::new(engine.raw(), state);
    store.limiter(|state| state);
    // The runtime copies guest bytes for streams and futures off any
    // fiber, so on a machine that can swap every such copy waits until
    // its pages are present. A machine that cannot swap registers
    // nothing, and the copies pay a single branch.
    if let Some(residency) = crate::wasmtime_adapter::residency::SwapResidencyHook::installed() {
        store.set_guest_memory_residency(residency);
    }
    // No call hook. A host call that does not suspend changes nothing
    // the kernel accounts: the processor turn, the user-memory owner and
    // the socket retirements all change hands where the fiber does,
    // which is where `GuestTurns::drive` wraps the call that drives
    // this store.
    //
    // An interruption is where a pending signal or a condemned instance
    // stops a running guest: a CPU-bound guest makes no host call at all
    // (an AOT compile, say), and raising a signal or condemning an
    // instance interrupts every store of its target, so a guest that is
    // running meets this at its next function entry or loop header.
    // Cancelling the future instead would surface a bare interrupt trap
    // that loses the signal or kill reason. Any other interruption ends
    // a time slice, and the guest yields.
    store.interrupt_callback(move |caller| {
        if let Some(stop) = signal_state.as_ref().and_then(take_component_signal_stop) {
            return Err(stop);
        }
        crate::wasmtime_adapter::preemption::kill_or_yield(caller.data().pending_kill())
    });
    crate::wasmtime_adapter::store::install_stack_reserve(&mut store, |data, requested_bytes| {
        data.request_oom_kill_for_growth(crate::MemoryPool::User, requested_bytes);
    });
    let interrupts = engine
        .interrupts()
        .register(instance, &store, store.data().cpu.clone());
    (store, interrupts)
}

struct ComponentHostProfile<CpuImpl, Net, StorageImpl>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    runtime_state: HostRuntimeState<CpuImpl, Net, StorageImpl>,
    cpu: CpuImpl,
    started_ticks: u64,
    counters: helios_hal::cpu::HardwarePerfCounters,
    started_heap: HeapStats,
}

impl<CpuImpl, Net, StorageImpl> ComponentHostProfile<CpuImpl, Net, StorageImpl>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    fn restarted(&self) -> Self {
        Self {
            runtime_state: self.runtime_state.clone(),
            cpu: self.cpu.clone(),
            started_ticks: self.cpu.now().ticks(),
            counters: self.cpu.hardware_perf_counters(),
            started_heap: crate::heap_stats(),
        }
    }
}

fn component_host_profile<CpuImpl, Net, StorageImpl>(
    store: &StoreData<CpuImpl, Net, StorageImpl>,
) -> Option<ComponentHostProfile<CpuImpl, Net, StorageImpl>>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    store
        .runtime_state
        .profiling_enabled()
        .then(|| ComponentHostProfile {
            runtime_state: store.runtime_state.clone(),
            cpu: store.cpu.clone(),
            started_ticks: store.cpu.now().ticks(),
            counters: store.cpu.hardware_perf_counters(),
            started_heap: crate::heap_stats(),
        })
}

fn record_component_host_kernel_profile<CpuImpl, Net, StorageImpl>(
    profile: Option<ComponentHostProfile<CpuImpl, Net, StorageImpl>>,
    phase: &'static str,
) where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    if let Some(profile) = profile {
        profile.runtime_state.record_profile_stack_parts(
            ProfileScope::Kernel,
            "kernel;component-host;",
            phase,
            profile
                .cpu
                .now()
                .ticks()
                .saturating_sub(profile.started_ticks),
        );
    }
}

fn record_component_host_kernel_profile_events_bytes<CpuImpl, Net, StorageImpl>(
    profile: Option<ComponentHostProfile<CpuImpl, Net, StorageImpl>>,
    phase: &'static str,
    events: u64,
    bytes: u64,
) where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    if let Some(profile) = profile {
        let ended_ticks = profile.cpu.now().ticks();
        let elapsed_ticks = ended_ticks.saturating_sub(profile.started_ticks);
        profile.runtime_state.record_profile_stack_parts(
            ProfileScope::Kernel,
            "kernel;component-host;",
            phase,
            elapsed_ticks,
        );
        let elapsed_nanos = profile
            .runtime_state
            .uptime_nanos(ended_ticks)
            .saturating_sub(profile.runtime_state.uptime_nanos(profile.started_ticks));
        let counter_delta = profile
            .cpu
            .hardware_perf_counters()
            .delta_since(profile.counters);
        profile.runtime_state.record_perf_metric_parts(
            ProfileScope::Kernel,
            "kernel;component-host;",
            phase,
            PerfSample {
                events,
                elapsed_nanos,
                counters: counter_delta,
                bytes,
            },
        );
        let heap = crate::heap_stats();
        record_component_host_heap_delta(
            &profile.runtime_state,
            phase,
            "heap-alloc",
            heap.allocation_count
                .saturating_sub(profile.started_heap.allocation_count),
            heap.total_allocation_bytes
                .saturating_sub(profile.started_heap.total_allocation_bytes),
        );
        record_component_host_heap_delta(
            &profile.runtime_state,
            phase,
            "heap-realloc",
            heap.reallocation_count
                .saturating_sub(profile.started_heap.reallocation_count),
            heap.total_reallocation_bytes
                .saturating_sub(profile.started_heap.total_reallocation_bytes),
        );
        record_component_host_heap_delta(
            &profile.runtime_state,
            phase,
            "heap-dealloc",
            heap.deallocation_count
                .saturating_sub(profile.started_heap.deallocation_count),
            heap.total_deallocation_bytes
                .saturating_sub(profile.started_heap.total_deallocation_bytes),
        );
    }
}

fn record_component_host_heap_delta<CpuImpl, Net, StorageImpl>(
    runtime_state: &HostRuntimeState<CpuImpl, Net, StorageImpl>,
    phase: &'static str,
    kind: &'static str,
    events: u64,
    bytes: u64,
) where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    if events == 0 && bytes == 0 {
        return;
    }
    let phase_prefix = match kind {
        "heap-alloc" => "kernel;component-host-heap;alloc;",
        "heap-realloc" => "kernel;component-host-heap;realloc;",
        "heap-dealloc" => "kernel;component-host-heap;dealloc;",
        _ => panic!("unknown component-host heap metric kind {kind}"),
    };
    runtime_state.record_perf_metric_parts(
        ProfileScope::Kernel,
        phase_prefix,
        phase,
        PerfSample {
            events,
            elapsed_nanos: 0,
            counters: helios_hal::cpu::HardwarePerfCounterDelta::default(),
            bytes,
        },
    );
}

fn component_host_usize_to_u64(value: usize, label: &'static str) -> u64 {
    u64::try_from(value).unwrap_or_else(|_| panic!("{label} does not fit into u64"))
}

pub(crate) fn add_program_world_to_linker<CpuImpl, Net, StorageImpl>(
    linker: &mut Linker<StoreData<CpuImpl, Net, StorageImpl>>,
) -> wasmtime::Result<()>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    add_programs_to_program_linker(linker)?;
    mounts::add_mounts_to_program_linker(linker)?;
    service::add_btrfs_to_linker(linker)?;
    add_net_to_program_linker(linker)?;
    vsock::add_vsock_to_linker::<vsock::ProgramVsock, _, _, _>(linker)?;
    device::add_device_to_linker(linker)?;
    service::add_display_to_linker(linker)?;
    service::add_input_to_linker(linker)?;
    service::add_surface_to_linker(linker)?;
    service::add_gpu_to_linker(linker)?;
    service::add_audio_to_linker(linker)?;
    service::add_processors_to_linker(linker)?;
    service::add_hv_to_linker(linker)?;
    add_tracing_to_program_linker(linker)?;
    program_profiling::add_to_linker(linker)?;
    add_settings_to_linker(linker)?;
    Ok(())
}

pub(crate) fn add_serial_to_linker<CpuImpl, Net, StorageImpl>(
    linker: &mut Linker<StoreData<CpuImpl, Net, StorageImpl>>,
) -> wasmtime::Result<()>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    program_wit::serial::add_to_linker::<_, HasSelf<StoreData<CpuImpl, Net, StorageImpl>>>(
        linker,
        |state| state,
    )?;
    Ok(())
}

pub(crate) fn add_sync_to_linker<CpuImpl, Net, StorageImpl>(
    linker: &mut Linker<StoreData<CpuImpl, Net, StorageImpl>>,
) -> wasmtime::Result<()>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let mut instance = linker.instance(SYNC_INSTANCE)?;
    instance.resource(
        "raw-mutex",
        ResourceType::host::<SbiRawMutex>(),
        |mut caller, rep| {
            let resource = Resource::<SbiRawMutex>::new_own(rep);
            caller.data_mut().table.delete(resource)?;
            Ok(())
        },
    )?;
    instance.resource(
        "raw-mutex-guard",
        ResourceType::host::<SbiRawMutexGuard>(),
        |mut caller, rep| {
            let resource = Resource::<SbiRawMutexGuard>::new_own(rep);
            caller.data_mut().table.delete(resource)?;
            Ok(())
        },
    )?;
    instance.resource(
        "raw-rw-lock",
        ResourceType::host::<SbiRawRwLock>(),
        |mut caller, rep| {
            let resource = Resource::<SbiRawRwLock>::new_own(rep);
            caller.data_mut().table.delete(resource)?;
            Ok(())
        },
    )?;
    instance.resource(
        "raw-rw-lock-read-guard",
        ResourceType::host::<SbiRawRwLockReadGuard>(),
        |mut caller, rep| {
            let resource = Resource::<SbiRawRwLockReadGuard>::new_own(rep);
            caller.data_mut().table.delete(resource)?;
            Ok(())
        },
    )?;
    instance.resource(
        "raw-rw-lock-write-guard",
        ResourceType::host::<SbiRawRwLockWriteGuard>(),
        |mut caller, rep| {
            let resource = Resource::<SbiRawRwLockWriteGuard>::new_own(rep);
            caller.data_mut().table.delete(resource)?;
            Ok(())
        },
    )?;
    instance.func_wrap(
        "[constructor]raw-mutex",
        |mut caller: StoreContextMut<'_, StoreData<CpuImpl, Net, StorageImpl>>, (): ()| {
            let resource = caller.data_mut().table.push(SbiRawMutex {
                resource: RawMutexResource {
                    inner: Arc::new(RawMutex::new()),
                },
            })?;
            Ok((resource,))
        },
    )?;
    instance.func_wrap_concurrent(
        "[method]raw-mutex.lock",
        |accessor: &Accessor<StoreData<CpuImpl, Net, StorageImpl>>,
         (resource,): (Resource<SbiRawMutex>,)| {
            Box::pin(async move {
                let mutex = accessor.with(|mut access| {
                    Ok::<_, wasmtime::Error>(
                        access.get().table.get(&resource)?.resource.inner.clone(),
                    )
                })?;
                let lease = mutex.lock_owned().await;
                accessor.with(|mut access| {
                    let guard = access.get().table.push(SbiRawMutexGuard {
                        _resource: RawMutexGuardResource { _lease: lease },
                    })?;
                    Ok::<_, wasmtime::Error>((guard,))
                })
            })
        },
    )?;
    instance.func_wrap(
        "[constructor]raw-rw-lock",
        |mut caller: StoreContextMut<'_, StoreData<CpuImpl, Net, StorageImpl>>, (): ()| {
            let resource = caller.data_mut().table.push(SbiRawRwLock {
                resource: RawRwLockResource {
                    inner: Arc::new(RawRwLock::new()),
                },
            })?;
            Ok((resource,))
        },
    )?;
    instance.func_wrap_concurrent(
        "[method]raw-rw-lock.read",
        |accessor: &Accessor<StoreData<CpuImpl, Net, StorageImpl>>,
         (resource,): (Resource<SbiRawRwLock>,)| {
            Box::pin(async move {
                let rwlock = accessor.with(|mut access| {
                    Ok::<_, wasmtime::Error>(
                        access.get().table.get(&resource)?.resource.inner.clone(),
                    )
                })?;
                let lease = rwlock.read_owned().await;
                accessor.with(|mut access| {
                    let guard = access.get().table.push(SbiRawRwLockReadGuard {
                        _resource: RawRwLockReadGuardResource { _lease: lease },
                    })?;
                    Ok::<_, wasmtime::Error>((guard,))
                })
            })
        },
    )?;
    instance.func_wrap_concurrent(
        "[method]raw-rw-lock.write",
        |accessor: &Accessor<StoreData<CpuImpl, Net, StorageImpl>>,
         (resource,): (Resource<SbiRawRwLock>,)| {
            Box::pin(async move {
                let rwlock = accessor.with(|mut access| {
                    Ok::<_, wasmtime::Error>(
                        access.get().table.get(&resource)?.resource.inner.clone(),
                    )
                })?;
                let lease = rwlock.write_owned().await;
                accessor.with(|mut access| {
                    let guard = access.get().table.push(SbiRawRwLockWriteGuard {
                        _resource: RawRwLockWriteGuardResource { _lease: lease },
                    })?;
                    Ok::<_, wasmtime::Error>((guard,))
                })
            })
        },
    )?;
    timeline::add_to_linker(&mut instance)
}

fn add_programs_to_program_linker<CpuImpl, Net, StorageImpl>(
    linker: &mut Linker<StoreData<CpuImpl, Net, StorageImpl>>,
) -> wasmtime::Result<()>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    program_wit::programs::add_to_linker::<_, HasSelf<StoreData<CpuImpl, Net, StorageImpl>>>(
        linker,
        |state| state,
    )?;
    Ok(())
}

fn dns_network_rights() -> NetworkAuthorityRights {
    NetworkAuthorityRights::DNS
}

#[derive(Debug)]
enum NetResolveHttpsError {
    MissingDnsAuthority,
    ServiceUnavailable,
    Lookup(crate::DnsError),
}

async fn execute_net_resolve_https<Net: ComponentHostNetwork>(
    has_dns_authority: bool,
    service: Option<Net>,
    host: &str,
    port: u16,
    timeout: u64,
) -> Result<Option<crate::HttpsRecord>, NetResolveHttpsError> {
    if !has_dns_authority {
        return Err(NetResolveHttpsError::MissingDnsAuthority);
    }
    let Some(service) = service else {
        return Err(NetResolveHttpsError::ServiceUnavailable);
    };
    service
        .dns_resolve_https(host, port, timeout)
        .await
        .map_err(NetResolveHttpsError::Lookup)
}

fn tcp_connect_network_rights() -> NetworkAuthorityRights {
    NetworkAuthorityRights::TCP | NetworkAuthorityRights::DNS
}

fn tcp_bind_network_rights(local_port: u16) -> NetworkAuthorityRights {
    NetworkAuthorityRights::TCP.bind_rights(local_port)
}

fn udp_bind_network_rights(local_port: u16) -> NetworkAuthorityRights {
    NetworkAuthorityRights::UDP.bind_rights(local_port)
}

fn add_net_to_program_linker<CpuImpl, Net, StorageImpl>(
    linker: &mut Linker<StoreData<CpuImpl, Net, StorageImpl>>,
) -> wasmtime::Result<()>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let mut instance = linker.instance(NET_INSTANCE)?;
    instance.resource(
        "tcp-stream",
        ResourceType::host::<crate::ComponentTcpStreamHandle>(),
        |mut caller, rep| {
            let resource = Resource::<crate::ComponentTcpStreamHandle>::new_own(rep);
            caller.data_mut().table.delete(resource)?;
            caller.data().retire_sockets();
            Ok(())
        },
    )?;
    instance.resource(
        "tcp-listener",
        ResourceType::host::<crate::ComponentTcpListener>(),
        |mut caller, rep| {
            let resource = Resource::<crate::ComponentTcpListener>::new_own(rep);
            caller.data_mut().table.delete(resource)?;
            caller.data().retire_sockets();
            Ok(())
        },
    )?;
    instance.resource(
        "udp-socket",
        ResourceType::host::<SbiUdpSocket<Net>>(),
        |mut caller, rep| {
            let resource = Resource::<SbiUdpSocket<Net>>::new_own(rep);
            caller.data_mut().table.delete(resource)?;
            Ok(())
        },
    )?;
    instance.func_wrap_concurrent(
        "ping",
        |accessor: &Accessor<StoreData<CpuImpl, Net, StorageImpl>>,
         (host, timeout): (String, u64)| {
            Box::pin(async move {
                let has_authority = accessor.with(|mut access| {
                    Ok::<_, wasmtime::Error>(
                        access
                            .get()
                            .process_authority()
                            .network_rights()
                            .contains(dns_network_rights()),
                    )
                })?;
                if !has_authority {
                    return Ok::<_, wasmtime::Error>((Err(program_wit::net::PingError {
                        kind: program_wit::net::PingErrorKind::Unavailable,
                        detail: "network authority is missing DNS rights".to_owned(),
                    }),));
                }
                let service = accessor.with(|mut access| {
                    Ok::<_, wasmtime::Error>(access.get().runtime_state.network_service())
                })?;
                let Some(service) = service else {
                    return Ok::<_, wasmtime::Error>((Err(program_wit::net::PingError {
                        kind: program_wit::net::PingErrorKind::Unavailable,
                        detail: "network service is unavailable on this machine".to_owned(),
                    }),));
                };
                let response = service
                    .ping(&host, timeout)
                    .await
                    .map(convert_program_ping_reply)
                    .map_err(convert_program_ping_error);
                Ok::<_, wasmtime::Error>((response,))
            })
        },
    )?;
    instance.func_wrap_concurrent(
        "tcp-connect",
        |accessor: &Accessor<StoreData<CpuImpl, Net, StorageImpl>>,
         (host, port, timeout): (String, u16, u64)| {
            Box::pin(async move {
                let has_authority = accessor.with(|mut access| {
                    Ok::<_, wasmtime::Error>(
                        access
                            .get()
                            .process_authority()
                            .network_rights()
                            .contains(tcp_connect_network_rights()),
                    )
                })?;
                if !has_authority {
                    return Ok::<_, wasmtime::Error>((Err(
                        unavailable_program_tcp_authority_error(),
                    ),));
                }
                let (service, profile) = accessor.with(|mut access| {
                    let store = access.get();
                    Ok::<_, wasmtime::Error>((
                        store.runtime_state.network_service(),
                        component_host_profile(store),
                    ))
                })?;
                let Some(service) = service else {
                    return Ok::<_, wasmtime::Error>((Err(unavailable_program_tcp_error()),));
                };
                let connected = service.tcp_connect(&host, port, timeout).await;
                record_component_host_kernel_profile(profile, "program-net-tcp-connect");
                let response = match connected {
                    Ok(stream) => {
                        let raw = crate::NetworkHandle::into_raw(stream);
                        let resource = accessor.with(|mut access| {
                            let store = access.get();
                            let retire = store.retirement.sender();
                            store
                                .table
                                .push(crate::ComponentTcpStreamHandle::new(raw, retire))
                        })?;
                        Ok(resource)
                    }
                    Err(error) => Err(convert_program_tcp_error(error)),
                };
                Ok::<_, wasmtime::Error>((response,))
            })
        },
    )?;
    instance.func_wrap_concurrent(
        "udp-bind",
        |accessor: &Accessor<StoreData<CpuImpl, Net, StorageImpl>>, (local_port,): (u16,)| {
            Box::pin(async move {
                let required = udp_bind_network_rights(local_port);
                let has_authority = accessor.with(|mut access| {
                    Ok::<_, wasmtime::Error>(
                        access
                            .get()
                            .process_authority()
                            .network_rights()
                            .contains(required),
                    )
                })?;
                if !has_authority {
                    return Ok::<_, wasmtime::Error>((Err(
                        unavailable_program_udp_authority_error(),
                    ),));
                }
                let service = accessor.with(|mut access| {
                    Ok::<_, wasmtime::Error>(access.get().runtime_state.network_service())
                })?;
                let Some(service) = service else {
                    return Ok::<_, wasmtime::Error>((Err(unavailable_program_udp_error()),));
                };
                let bound = service
                    .udp_bind(
                        crate::NetworkIpAddress::Ipv4(crate::Ipv4Address::new([0, 0, 0, 0])),
                        local_port,
                    )
                    .await;
                let response =
                    match bound {
                        Ok(binding) => {
                            let resource =
                                accessor.with(|mut access| {
                                    access.get().table.push(SbiUdpSocket::new(
                                        NetworkUdpBackend::new(service.clone(), binding.socket),
                                    ))
                                })?;
                            Ok(resource)
                        }
                        Err(error) => Err(convert_program_udp_error(error)),
                    };
                Ok::<_, wasmtime::Error>((response,))
            })
        },
    )?;
    instance.func_wrap_concurrent(
        "resolve-https",
        |accessor: &Accessor<StoreData<CpuImpl, Net, StorageImpl>>,
         (host, port, timeout): (String, u16, u64)| {
            Box::pin(async move {
                let (has_authority, service) = accessor.with(|mut access| {
                    let store = access.get();
                    Ok::<_, wasmtime::Error>((
                        store.process_authority().derive_dns_cap().is_ok(),
                        store.runtime_state.network_service(),
                    ))
                })?;
                let response =
                    execute_net_resolve_https(has_authority, service, &host, port, timeout)
                        .await
                        .map(|record| record.map(convert_program_https_record))
                        .map_err(convert_program_net_resolve_https_error);
                Ok::<_, wasmtime::Error>((response,))
            })
        },
    )?;
    instance.func_wrap_concurrent(
        "[method]tcp-stream.read",
        |accessor: &Accessor<StoreData<CpuImpl, Net, StorageImpl>>,
         (resource, max_bytes, timeout): (Resource<crate::ComponentTcpStreamHandle>, u32, u64)| {
            Box::pin(async move {
                let (service, raw, profile) = accessor.with(|mut access| {
                    let store = access.get();
                    let socket = store.table.get(&resource)?;
                    Ok::<_, wasmtime::Error>((
                        store.runtime_state.network_service(),
                        socket.raw(),
                        component_host_profile(store),
                    ))
                })?;
                let service_profile = profile.as_ref().map(ComponentHostProfile::restarted);
                let Some(raw) = raw else {
                    return Ok::<_, wasmtime::Error>((Err(closed_program_tcp_error()),));
                };
                let Some(service) = service else {
                    return Ok::<_, wasmtime::Error>((Err(unavailable_program_tcp_error()),));
                };
                let stream = <Net::TcpStream as crate::NetworkHandle>::from_raw(raw);
                let response = service.tcp_read(stream, max_bytes, timeout).await;
                let bytes = response
                    .as_ref()
                    .ok()
                    .and_then(Option::as_ref)
                    .map_or(0, Bytes::len);
                record_component_host_kernel_profile_events_bytes(
                    service_profile,
                    "program-net-tcp-read-service",
                    1,
                    component_host_usize_to_u64(bytes, "program TCP read byte count"),
                );
                let lower_profile = profile.as_ref().map(ComponentHostProfile::restarted);
                let response = response
                    .map(|bytes| bytes.map(lower_bytes_to_vec))
                    .map_err(convert_program_tcp_error);
                record_component_host_kernel_profile_events_bytes(
                    lower_profile,
                    "program-net-tcp-read-lower-bytes",
                    1,
                    component_host_usize_to_u64(bytes, "program TCP read byte count"),
                );
                record_component_host_kernel_profile_events_bytes(
                    profile,
                    "program-net-tcp-read",
                    1,
                    component_host_usize_to_u64(bytes, "program TCP read byte count"),
                );
                Ok::<_, wasmtime::Error>((response,))
            })
        },
    )?;
    instance.func_wrap_concurrent(
        "[method]tcp-stream.write",
        |accessor: &Accessor<StoreData<CpuImpl, Net, StorageImpl>>,
         (resource, bytes, timeout): (
            Resource<crate::ComponentTcpStreamHandle>,
            WasmList<u8>,
            u64,
        )| {
            Box::pin(async move {
                let (service, raw, profile, payload) = accessor.with(|mut access| {
                    let store = access.get();
                    let socket = store.table.get(&resource)?;
                    let service = store.runtime_state.network_service();
                    let raw = socket.raw();
                    let profile = component_host_profile(store);
                    let payload = match (&service, raw) {
                        (Some(svc), Some(_)) => {
                            Some(sbi_tcp_payload(svc, bytes.as_le_slice(&access)))
                        }
                        _ => None,
                    };
                    Ok::<_, wasmtime::Error>((service, raw, profile, payload))
                })?;
                let Some(raw) = raw else {
                    return Ok::<_, wasmtime::Error>((Err(closed_program_tcp_error()),));
                };
                let (Some(service), Some(payload)) = (service, payload) else {
                    return Ok::<_, wasmtime::Error>((Err(unavailable_program_tcp_error()),));
                };
                let stream = <Net::TcpStream as crate::NetworkHandle>::from_raw(raw);
                let written = bytes.len() as u64;
                let response = match payload {
                    Ok(pieces) => service
                        .tcp_write_all(stream, pieces.into_iter().map(Ok), timeout)
                        .await
                        .map(|()| written),
                    Err(error) => Err(error),
                }
                .map_err(convert_program_tcp_error);
                record_component_host_kernel_profile(profile, "program-net-tcp-write");
                Ok::<_, wasmtime::Error>((response,))
            })
        },
    )?;
    instance.func_wrap_concurrent_immediate(
        "[method]tcp-stream.close",
        |mut caller: Access<'_, StoreData<CpuImpl, Net, StorageImpl>>,
         (resource,): (Resource<crate::ComponentTcpStreamHandle>,)| {
            let socket = caller.data_mut().table.get_mut(&resource)?;
            socket.close();
            caller.data().retire_sockets();
            Ok((Ok::<(), program_wit::net::TcpError>(()),))
        },
    )?;
    instance.func_wrap_concurrent(
        "tcp-listen",
        |accessor: &Accessor<StoreData<CpuImpl, Net, StorageImpl>>,
         (local_address, local_port, backlog): (program_wit::net::IpAddress, u16, u16)| {
            Box::pin(async move {
                let required = tcp_bind_network_rights(local_port);
                let (has_authority, service) = accessor.with(|mut access| {
                    let store = access.get();
                    Ok::<_, wasmtime::Error>((
                        store
                            .process_authority()
                            .network_rights()
                            .contains(required),
                        store.runtime_state.network_service(),
                    ))
                })?;
                if !has_authority {
                    return Ok::<_, wasmtime::Error>((Err(program_wit::net::TcpError {
                        kind: program_wit::net::TcpErrorKind::PermissionDenied,
                        detail: "network authority is missing TCP or privileged-bind rights"
                            .to_owned(),
                    }),));
                }
                let Some(service) = service else {
                    return Ok::<_, wasmtime::Error>((Err(unavailable_program_tcp_error()),));
                };
                let addr = from_program_wit_ip_address(local_address);
                let hop_limit = helios_netstack::DEFAULT_HOP_LIMIT;
                let response = match service
                    .tcp_listen(addr, local_port, backlog, hop_limit)
                    .await
                {
                    Ok(bound) => {
                        let resource = accessor.with(|mut access| {
                            let store = access.get();
                            let retire = store.retirement.sender();
                            store.table.push(crate::ComponentTcpListener::new(
                                <Net::TcpListener as crate::NetworkHandle>::into_raw(
                                    bound.listener,
                                ),
                                addr,
                                bound.local_port,
                                hop_limit,
                                retire,
                            ))
                        })?;
                        Ok(resource)
                    }
                    Err(error) => Err(convert_program_tcp_error(error)),
                };
                Ok::<_, wasmtime::Error>((response,))
            })
        },
    )?;
    instance.func_wrap(
        "[method]tcp-listener.local-address",
        |caller: wasmtime::StoreContextMut<'_, StoreData<CpuImpl, Net, StorageImpl>>,
         (resource,): (Resource<crate::ComponentTcpListener>,)| {
            let listener = caller.data().table.get(&resource)?;
            Ok(((
                convert_program_ip_address(listener.local_address()),
                listener.local_port(),
            ),))
        },
    )?;
    instance.func_wrap_concurrent(
        "[method]tcp-listener.wait-readable",
        |accessor: &Accessor<StoreData<CpuImpl, Net, StorageImpl>>,
         (resource, timeout): (Resource<crate::ComponentTcpListener>, u64)| {
            Box::pin(async move {
                let (service, raw) = accessor.with(|mut access| {
                    let store = access.get();
                    let listener = store.table.get(&resource)?;
                    Ok::<_, wasmtime::Error>((
                        store.runtime_state.network_service(),
                        listener.raw(),
                    ))
                })?;
                let Some(raw) = raw else {
                    return Ok::<_, wasmtime::Error>((Err(closed_program_tcp_listener_error()),));
                };
                let Some(service) = service else {
                    return Ok::<_, wasmtime::Error>((Err(unavailable_program_tcp_error()),));
                };
                let handle = <Net::TcpListener as crate::NetworkHandle>::from_raw(raw);
                let response = service
                    .tcp_listener_wait_readable(handle, timeout)
                    .await
                    .map_err(convert_program_tcp_error);
                Ok::<_, wasmtime::Error>((response,))
            })
        },
    )?;
    instance.func_wrap_concurrent(
        "[method]tcp-listener.accept",
        |accessor: &Accessor<StoreData<CpuImpl, Net, StorageImpl>>,
         (resource, timeout): (Resource<crate::ComponentTcpListener>, u64)| {
            Box::pin(async move {
                let (service, raw) = accessor.with(|mut access| {
                    let store = access.get();
                    let listener = store.table.get(&resource)?;
                    Ok::<_, wasmtime::Error>((
                        store.runtime_state.network_service(),
                        listener.raw(),
                    ))
                })?;
                let Some(raw) = raw else {
                    return Ok::<_, wasmtime::Error>((Err(closed_program_tcp_listener_error()),));
                };
                let Some(service) = service else {
                    return Ok::<_, wasmtime::Error>((Err(unavailable_program_tcp_error()),));
                };
                let handle = <Net::TcpListener as crate::NetworkHandle>::from_raw(raw);
                let response = match service.tcp_accept(handle, timeout).await {
                    Ok(accepted) => {
                        let raw = crate::NetworkHandle::into_raw(accepted.stream);
                        let resource = accessor.with(|mut access| {
                            let store = access.get();
                            let retire = store.retirement.sender();
                            store
                                .table
                                .push(crate::ComponentTcpStreamHandle::new(raw, retire))
                        })?;
                        Ok(resource)
                    }
                    Err(error) => Err(convert_program_tcp_error(error)),
                };
                Ok::<_, wasmtime::Error>((response,))
            })
        },
    )?;
    instance.func_wrap_concurrent_immediate(
        "[method]tcp-listener.close",
        |mut caller: Access<'_, StoreData<CpuImpl, Net, StorageImpl>>,
         (resource,): (Resource<crate::ComponentTcpListener>,)| {
            let listener = caller.data_mut().table.get_mut(&resource)?;
            listener.close();
            caller.data().retire_sockets();
            Ok((Ok::<(), program_wit::net::TcpError>(()),))
        },
    )?;
    instance.func_wrap_concurrent(
        "[method]udp-socket.receive",
        |accessor: &Accessor<StoreData<CpuImpl, Net, StorageImpl>>,
         (resource, max_bytes, timeout): (Resource<SbiUdpSocket<Net>>, u32, u64)| {
            Box::pin(async move {
                let socket = accessor.with(|mut access| {
                    let socket = access.get().table.get(&resource)?;
                    Ok::<_, wasmtime::Error>((
                        socket.resource.backend.service.clone(),
                        socket.resource.backend.socket(),
                    ))
                })?;
                let Some(handle) = socket.1 else {
                    return Ok::<_, wasmtime::Error>((Err(closed_program_udp_error()),));
                };
                let response = socket
                    .0
                    .udp_receive(handle, max_bytes, timeout)
                    .await
                    .map(|datagram| datagram.map(convert_program_udp_datagram))
                    .map_err(convert_program_udp_error);
                Ok::<_, wasmtime::Error>((response,))
            })
        },
    )?;
    instance.func_wrap_concurrent(
        "[method]udp-socket.send",
        |accessor: &Accessor<StoreData<CpuImpl, Net, StorageImpl>>,
         (resource, host, port, bytes, timeout): (
            Resource<SbiUdpSocket<Net>>,
            String,
            u16,
            Vec<u8>,
            u64,
        )| {
            Box::pin(async move {
                let socket = accessor.with(|mut access| {
                    let socket = access.get().table.get(&resource)?;
                    Ok::<_, wasmtime::Error>((
                        socket.resource.backend.service.clone(),
                        socket.resource.backend.socket(),
                    ))
                })?;
                let Some(handle) = socket.1 else {
                    return Ok::<_, wasmtime::Error>((Err(closed_program_udp_error()),));
                };
                let response = socket
                    .0
                    .udp_send(handle, &host, port, &bytes, timeout)
                    .await
                    .map_err(convert_program_udp_error);
                Ok::<_, wasmtime::Error>((response,))
            })
        },
    )?;
    instance.func_wrap_concurrent_immediate(
        "[method]udp-socket.close",
        |mut caller: Access<'_, StoreData<CpuImpl, Net, StorageImpl>>,
         (resource,): (Resource<SbiUdpSocket<Net>>,)| {
            let socket = caller.data_mut().table.get_mut(&resource)?;
            socket.resource.backend.close();
            Ok((Ok::<(), program_wit::net::UdpError>(()),))
        },
    )?;
    Ok(())
}

/// Registers `helios:system/settings`.
///
/// The listing, a row and the value cross as the views in `settings`, which
/// name the interface's records by their component model shape.
fn add_settings_to_linker<CpuImpl, Net, StorageImpl>(
    linker: &mut Linker<StoreData<CpuImpl, Net, StorageImpl>>,
) -> wasmtime::Result<()>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    use settings::{SettingView, ValueView, WriteErrorView};
    use wasmtime::AsContext;
    use wasmtime::component::WasmStr;

    let mut instance = linker.instance(SETTINGS_INSTANCE)?;
    // Reads need no right; a write needs the right to write settings and is
    // refused before the name is looked up. See `settings`.
    instance.func_wrap("list", |caller, (): ()| {
        Ok((settings::listing(caller.data()),))
    })?;
    // A name is compared where it sits in the caller's memory, so a
    // guest-chosen string is not copied onto the kernel heap for UTF-8.
    instance.func_wrap("read", |caller, (name,): (WasmStr,)| {
        let name = name.to_str(caller.as_context())?;
        let setting = settings::read(caller.data(), &name).map(SettingView::from);
        Ok((setting,))
    })?;
    instance.func_wrap("write", |caller, (name, value): (WasmStr, ValueView)| {
        let name = name.to_str(caller.as_context())?;
        let replaced = settings::write(caller.data(), &name, value.into())
            .map(ValueView::from)
            .map_err(WriteErrorView::from);
        Ok((replaced,))
    })?;
    Ok(())
}

/// Registers `helios:system/profiling` for one binding set.
///
/// The System and Program worlds see the same kernel-side profile state
/// through generated WIT types that differ only in the module they were
/// generated into, so the host functions and every conversion between the
/// kernel's own filter and sample types and the generated ones are written
/// once here and instantiated per binding set.
///
/// The whole interface is registered for both worlds. A world that imports
/// an interface and is handed only part of it fails to instantiate on the
/// first call to a missing function, which is the defect this macro exists
/// to remove rather than to relocate.
macro_rules! impl_profiling_bindings {
    ($module:ident, $wit:ident) => {
        mod $module {
            use super::*;

            pub(super) fn add_to_linker<CpuImpl, Net, StorageImpl>(
                linker: &mut Linker<StoreData<CpuImpl, Net, StorageImpl>>,
            ) -> wasmtime::Result<()>
            where
                CpuImpl: Cpu + Clone,
                Net: ComponentHostNetwork,
                StorageImpl: crate::Storage,
            {
                let mut instance = linker.instance(PROFILING_INSTANCE)?;
                instance.resource(
                    "sampling-session",
                    ResourceType::host::<crate::ComponentSamplingSession>(),
                    |mut caller, rep| {
                        let caller_id = caller.data().instance().id();
                        let resource = Resource::<crate::ComponentSamplingSession>::new_own(rep);
                        let _ = caller.data_mut().table.delete(resource)?;
                        crate::audit::diagnostic_gate_change(
                            caller_id,
                            "profiling.instruction-sampling",
                            "stopped",
                            true,
                        );
                        Ok(())
                    },
                )?;
                instance.func_wrap_data("set-enabled", |data, (enabled,): (bool,)| {
                    let result = observation::set_profiling_enabled(data, enabled)
                        .map_err(|Denied| $wit::profiling::ControlError::Denied);
                    Ok((result,))
                })?;
                instance.func_wrap_data("clear", |data, (): ()| {
                    let result = observation::clear_profile(data)
                        .map_err(|Denied| $wit::profiling::ControlError::Denied);
                    Ok((result,))
                })?;
                instance.func_wrap(
                    "folded",
                    |mut caller, (filter, limit): (ProfileFilterView, u32)| {
                        let samples = filter
                            .lift(&mut caller)?
                            .map(|filter| {
                                observation::folded_samples(caller.data(), &filter, limit)
                                    .into_iter()
                                    .map(convert_profile_sample)
                                    .collect::<Vec<_>>()
                            })
                            .map_err($wit::filters::FilterError::from);
                        Ok((samples,))
                    },
                )?;
                instance.func_wrap(
                    "metrics",
                    |mut caller, (filter, limit): (MetricFilterView, u32)| {
                        let samples = filter
                            .lift(&mut caller)?
                            .map(|filter| {
                                observation::metric_samples(caller.data(), &filter, limit)
                                    .into_iter()
                                    .map(convert_perf_metric_sample)
                                    .collect::<Vec<_>>()
                            })
                            .map_err($wit::filters::FilterError::from);
                        Ok((samples,))
                    },
                )?;
                instance.func_wrap("start-instruction-sampling", |mut caller, (): ()| {
                    let result = match observation::start_instruction_sampling(caller.data()) {
                        Ok(session) => {
                            let handle = caller.data_mut().table.push(session)?;
                            Ok(handle)
                        }
                        Err(refusal) => Err(convert_instruction_profile_refusal(refusal)),
                    };
                    Ok((result,))
                })?;
                instance.func_wrap_data("instruction-samples", |data, (): ()| {
                    let profile = observation::instruction_samples(data)?
                        .map(convert_instruction_profile)
                        .map_err(convert_instruction_profile_refusal);
                    Ok((profile,))
                })?;
                instance.func_wrap_data("raw-profile-size", |data, (): ()| {
                    let size =
                        observation::raw_profile_size(data).map_err(convert_raw_profile_refusal);
                    Ok((size,))
                })?;
                instance.func_wrap_data(
                    "raw-profile-read",
                    |data, (offset, length): (u64, u32)| {
                        let window = observation::raw_profile_read(data, offset, length)
                            .map_err(convert_raw_profile_refusal);
                        Ok((window,))
                    },
                )?;
                Ok(())
            }

            fn convert_profile_sample(
                sample: crate::FoldedProfileSample,
            ) -> $wit::profiling::FoldedSample {
                $wit::profiling::FoldedSample {
                    scope: convert_profile_scope_from_local(sample.scope),
                    stack: sample.stack.to_string(),
                    weight: sample.weight,
                }
            }

            fn convert_perf_metric_sample(
                sample: crate::PerfMetricSample,
            ) -> $wit::profiling::MetricSample {
                $wit::profiling::MetricSample {
                    scope: convert_profile_scope_from_local(sample.scope),
                    name: sample.name.to_string(),
                    count: sample.count,
                    total_events: sample.total_events,
                    total_nanos: sample.total_nanos,
                    min_nanos: sample.min_nanos,
                    max_nanos: sample.max_nanos,
                    total_bytes: sample.total_bytes,
                    total_reference_cycles: sample.total_reference_cycles,
                    total_cpu_cycles: sample.total_cpu_cycles,
                    total_instructions_retired: sample.total_instructions_retired,
                }
            }

            fn convert_profile_scope_from_local(scope: ProfileScope) -> $wit::profiling::Scope {
                match scope {
                    ProfileScope::Kernel => $wit::profiling::Scope::Kernel,
                    ProfileScope::User => $wit::profiling::Scope::User,
                }
            }

            fn convert_instruction_profile(
                profile: crate::InstructionProfile,
            ) -> $wit::profiling::InstructionProfile {
                $wit::profiling::InstructionProfile {
                    period_nanos: profile.capture.period_nanos,
                    kernel_image_base: profile.capture.kernel_image_base,
                    samples: profile
                        .samples
                        .into_iter()
                        .map(|(code, count)| $wit::profiling::InstructionSample {
                            code: convert_sampled_code(code),
                            count,
                        })
                        .collect(),
                    dropped: profile.dropped,
                }
            }

            fn convert_sampled_code(code: crate::SampledCode) -> $wit::profiling::SampledCode {
                use crate::SampledCode as Local;
                use $wit::profiling::SampledCode as Wit;

                match code {
                    Local::Wasm(function) => Wit::Wasm($wit::profiling::WasmFunction {
                        module: String::from(&*function.module),
                        static_module: function.static_module,
                        index: function.index,
                        name: function.name.map(|name| String::from(&*name)),
                    }),
                    Local::WasmTrampoline { module } => Wit::WasmTrampoline(String::from(&*module)),
                    Local::Native(address) => Wit::Native(address),
                }
            }

            fn convert_instruction_profile_refusal(
                refusal: Refused<crate::InstructionProfileError>,
            ) -> $wit::profiling::InstructionProfileError {
                match refusal {
                    Refused::Denied => $wit::profiling::InstructionProfileError::Denied,
                    Refused::Failed(crate::InstructionProfileError::NotCaptured) => {
                        $wit::profiling::InstructionProfileError::NotCaptured
                    }
                    Refused::Failed(crate::InstructionProfileError::Busy) => {
                        $wit::profiling::InstructionProfileError::Busy
                    }
                }
            }

            fn convert_raw_profile_refusal(
                refusal: Refused<crate::LlvmProfileError>,
            ) -> $wit::profiling::RawProfileError {
                use crate::LlvmProfileError as Local;
                use $wit::profiling::RawProfileError as Wit;

                match refusal {
                    Refused::Denied => Wit::Denied,
                    Refused::Failed(Local::NotInstrumented) => Wit::NotInstrumented,
                    Refused::Failed(Local::UnsupportedVersion { found, .. }) => {
                        Wit::UnsupportedVersion(found)
                    }
                    Refused::Failed(Local::MalformedSection { section, .. }) => {
                        Wit::MalformedSection(convert_profile_section(section))
                    }
                    Refused::Failed(Local::OutOfRange { len, .. }) => Wit::OutOfRange(len),
                    Refused::Failed(Local::ReadTooLarge { limit, .. }) => Wit::ReadTooLarge(limit),
                }
            }

            fn convert_profile_section(
                section: crate::ProfileSection,
            ) -> $wit::profiling::ProfileSection {
                use crate::ProfileSection as Local;
                use $wit::profiling::ProfileSection as Wit;

                match section {
                    Local::Counters => Wit::Counters,
                    Local::Data => Wit::Data,
                    Local::Names => Wit::Names,
                }
            }
        }
    };
}

impl_profiling_bindings!(program_profiling, program_wit);

/// Copies one window of the kernel's own LLVM raw profile out of the image.
///
/// The returned buffer is the one transient allocation this export makes —
/// the component ABI lowers a `list<u8>` from owned bytes — and the window
/// is capped by the interface rather than by what the caller asks for, so a
/// profile in the tens of megabytes leaves the kernel a bounded piece at a
/// time.
fn read_raw_profile(offset: u64, length: u32) -> Result<Vec<u8>, crate::LlvmProfileError> {
    if length > crate::MAX_PROFILE_READ {
        return Err(crate::LlvmProfileError::ReadTooLarge {
            requested: u64::from(length),
            limit: crate::MAX_PROFILE_READ,
        });
    }
    let profile = crate::KernelLlvmProfile;
    let remaining = profile.size()?.saturating_sub(offset);
    let mut bytes = alloc::vec![0u8; remaining.min(u64::from(length)) as usize];
    let written = profile.read(offset, &mut bytes)?;
    bytes.truncate(written);
    Ok(bytes)
}

fn add_tracing_to_program_linker<CpuImpl, Net, StorageImpl>(
    linker: &mut Linker<StoreData<CpuImpl, Net, StorageImpl>>,
) -> wasmtime::Result<()>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let mut instance = linker.instance(TRACING_INSTANCE)?;
    instance.func_wrap_data_memory(
        "set-target-enabled",
        |data, memory, (target, enabled): (WasmStr, bool)| {
            let target = target.to_str_in(memory)?;
            let result =
                observation::set_target_enabled(data, &target, enabled).map_err(|refusal| {
                    match refusal {
                        TargetRefusal::Denied => program_wit::tracing::TargetError::Denied,
                        TargetRefusal::Unknown(error) => {
                            program_wit::tracing::TargetError::UnknownTarget(error)
                        }
                    }
                });
            Ok((result,))
        },
    )?;
    instance.func_wrap(
        "recent",
        |mut caller, (filter, limit): (TraceFilterView, u32)| {
            let events = filter
                .lift(&mut caller)?
                .map(|filter| {
                    observation::recent_events(caller.data(), &filter, limit)
                        .into_iter()
                        .map(|event| convert_program_event(&event))
                        .collect::<Vec<_>>()
                })
                .map_err(program_wit::filters::FilterError::from);
            Ok((events,))
        },
    )?;
    instance.func_wrap("subscribe", |mut caller, (filter,): (TraceFilterView,)| {
        let filter = match filter.lift(&mut caller)? {
            Ok(filter) => filter,
            Err(refusal) => {
                return Ok((Err(program_wit::filters::FilterError::from(refusal)),));
            }
        };
        // The stream fixes its scope here and keeps it for its life, arming its
        // trace waiter before any poll so no event recorded after subscribe can
        // lose its wake.
        let visibility = Visibility::trace_of(caller.data());
        let waiter = caller.data().runtime_state.trace_waiter();
        let reader = match visibility {
            Visibility::None(scope) => StreamReader::new(
                &mut caller,
                ProgramTracingStreamProducer::new(filter, scope, waiter),
            )?,
            Visibility::Own(scope) => StreamReader::new(
                &mut caller,
                ProgramTracingStreamProducer::new(filter, scope, waiter),
            )?,
            Visibility::Subtree(scope) => StreamReader::new(
                &mut caller,
                ProgramTracingStreamProducer::new(filter, scope, waiter),
            )?,
            Visibility::Machine(scope) => StreamReader::new(
                &mut caller,
                ProgramTracingStreamProducer::new(filter, scope, waiter),
            )?,
        };
        Ok((Ok(reader),))
    })?;
    Ok(())
}

fn convert_program_launch_error(
    error: crate::ProgramExecError,
) -> program_wit::programs::ExecError {
    program_wit::programs::ExecError {
        kind: match error.kind {
            ProgramExecErrorKind::InvalidBinary => {
                program_wit::programs::ExecErrorKind::InvalidBinary
            }
            ProgramExecErrorKind::MissingEntry => {
                program_wit::programs::ExecErrorKind::MissingEntry
            }
            ProgramExecErrorKind::UnsupportedImport => {
                program_wit::programs::ExecErrorKind::UnsupportedImport
            }
            ProgramExecErrorKind::InvalidSignature => {
                program_wit::programs::ExecErrorKind::InvalidSignature
            }
            ProgramExecErrorKind::InvalidPath => program_wit::programs::ExecErrorKind::InvalidPath,
            ProgramExecErrorKind::PermissionDenied => {
                program_wit::programs::ExecErrorKind::PermissionDenied
            }
            ProgramExecErrorKind::InvalidHint => program_wit::programs::ExecErrorKind::InvalidHint,
            ProgramExecErrorKind::OutOfMemory => program_wit::programs::ExecErrorKind::OutOfMemory,
            ProgramExecErrorKind::Unavailable => program_wit::programs::ExecErrorKind::Unavailable,
            ProgramExecErrorKind::Internal => program_wit::programs::ExecErrorKind::Internal,
            ProgramExecErrorKind::NotFound => program_wit::programs::ExecErrorKind::NotFound,
            ProgramExecErrorKind::Io => program_wit::programs::ExecErrorKind::Io,
        },
        detail: error.detail.as_str().to_owned(),
    }
}

fn convert_program_launch_result(
    result: crate::ExecResult,
    launch_nanos: u64,
) -> program_wit::programs::ExecResult {
    program_wit::programs::ExecResult {
        instance_id: result.instance_id.raw(),
        exit_code: result.exit_code,
        output: program_wit::programs::ExecOutput {
            stdout: result.output.stdout,
            stderr: result.output.stderr,
        },
        launch_nanos,
    }
}

fn convert_program_ip_address(address: crate::NetworkIpAddress) -> program_wit::net::IpAddress {
    match address {
        crate::NetworkIpAddress::Ipv4(address) => {
            let octets = address.octets();
            program_wit::net::IpAddress::Ipv4((octets[0], octets[1], octets[2], octets[3]))
        }
        crate::NetworkIpAddress::Ipv6(address) => {
            program_wit::net::IpAddress::Ipv6(ipv6_address_groups(address))
        }
    }
}

fn ipv6_from_groups(
    groups: (u16, u16, u16, u16, u16, u16, u16, u16),
) -> helios_netstack::Ipv6Address {
    let words = [
        groups.0, groups.1, groups.2, groups.3, groups.4, groups.5, groups.6, groups.7,
    ];
    let mut octets = [0_u8; 16];
    for (index, word) in words.into_iter().enumerate() {
        let bytes = word.to_be_bytes();
        octets[index * 2] = bytes[0];
        octets[index * 2 + 1] = bytes[1];
    }
    helios_netstack::Ipv6Address::new(octets)
}

fn from_program_wit_ip_address(address: program_wit::net::IpAddress) -> crate::NetworkIpAddress {
    match address {
        program_wit::net::IpAddress::Ipv4((a, b, c, d)) => {
            crate::NetworkIpAddress::Ipv4(crate::Ipv4Address::new([a, b, c, d]))
        }
        program_wit::net::IpAddress::Ipv6(groups) => {
            crate::NetworkIpAddress::Ipv6(ipv6_from_groups(groups))
        }
    }
}

fn convert_program_ping_reply(reply: crate::PingReply) -> program_wit::net::PingReply {
    program_wit::net::PingReply {
        address: convert_program_ip_address(reply.address),
        round_trip: reply.round_trip_nanos,
        payload_bytes: reply.payload_bytes,
    }
}

fn convert_program_ping_error(error: crate::PingError) -> program_wit::net::PingError {
    program_wit::net::PingError {
        kind: match error.kind {
            crate::PingErrorKind::UnresolvedHost => program_wit::net::PingErrorKind::UnresolvedHost,
            crate::PingErrorKind::Timeout => program_wit::net::PingErrorKind::Timeout,
            crate::PingErrorKind::Unavailable => program_wit::net::PingErrorKind::Unavailable,
            crate::PingErrorKind::Internal => program_wit::net::PingErrorKind::Internal,
        },
        detail: error.detail.as_str().to_owned(),
    }
}

fn convert_program_https_record(record: crate::HttpsRecord) -> program_wit::net::HttpsRecord {
    program_wit::net::HttpsRecord {
        alpn: record.alpn,
        port: record.port,
        ttl: record.ttl_nanos,
    }
}

fn convert_program_net_resolve_https_error(
    error: NetResolveHttpsError,
) -> program_wit::net::DnsError {
    match error {
        NetResolveHttpsError::MissingDnsAuthority => program_wit::net::DnsError {
            kind: program_wit::net::DnsErrorKind::PermissionDenied,
            detail: "network authority is missing DNS rights".to_owned(),
        },
        NetResolveHttpsError::ServiceUnavailable => program_wit::net::DnsError {
            kind: program_wit::net::DnsErrorKind::Unavailable,
            detail: "network service is unavailable on this machine".to_owned(),
        },
        NetResolveHttpsError::Lookup(error) => program_wit::net::DnsError {
            kind: match error.kind {
                crate::DnsErrorKind::UnresolvedHost => {
                    program_wit::net::DnsErrorKind::UnresolvedHost
                }
                crate::DnsErrorKind::Timeout => program_wit::net::DnsErrorKind::Timeout,
                crate::DnsErrorKind::Unavailable => program_wit::net::DnsErrorKind::Unavailable,
                crate::DnsErrorKind::Internal => program_wit::net::DnsErrorKind::Internal,
            },
            detail: error.detail.as_str().to_owned(),
        },
    }
}

/// The error a `tcp-stream` method answers once the guest has closed
/// the stream but still holds its handle.
fn closed_program_tcp_error() -> program_wit::net::TcpError {
    program_wit::net::TcpError {
        kind: program_wit::net::TcpErrorKind::Unavailable,
        detail: "TCP stream is closed".to_owned(),
    }
}

fn closed_program_tcp_listener_error() -> program_wit::net::TcpError {
    program_wit::net::TcpError {
        kind: program_wit::net::TcpErrorKind::Unavailable,
        detail: "TCP listener is closed".to_owned(),
    }
}

/// A `tcp-stream.write` list copied into transmit memory, one send buffer
/// per piece.
///
/// The whole list is copied on the call's first poll, before it can
/// yield: a guest that lowered the call asynchronously runs on once that
/// poll returns and may reuse the list's memory, so nothing may read it
/// later. This is the copy the lifted `list<u8>` used to make into the
/// kernel heap, now made into memory the interface transmits from.
fn sbi_tcp_payload<Net: crate::ComponentNetworkService>(
    service: &Net,
    bytes: &[u8],
) -> Result<SmallVec<[Bytes; 2]>, crate::TcpError> {
    bytes
        .chunks(helios_netstack::TCP_TRANSMIT_BUFFER_BYTES)
        .map(|chunk| service.tcp_payload(chunk.len(), |piece| piece.copy_from_slice(chunk)))
        .collect()
}

fn unavailable_program_tcp_error() -> program_wit::net::TcpError {
    program_wit::net::TcpError {
        kind: program_wit::net::TcpErrorKind::Unavailable,
        detail: "network service is unavailable on this machine".to_owned(),
    }
}

fn unavailable_program_tcp_authority_error() -> program_wit::net::TcpError {
    program_wit::net::TcpError {
        kind: program_wit::net::TcpErrorKind::Unavailable,
        detail: "network authority is missing TCP or DNS rights".to_owned(),
    }
}

/// The error a `udp-socket` method answers once the guest has closed
/// the socket but still holds its handle.
fn closed_program_udp_error() -> program_wit::net::UdpError {
    program_wit::net::UdpError {
        kind: program_wit::net::UdpErrorKind::Unavailable,
        detail: "UDP socket is closed".to_owned(),
    }
}

fn unavailable_program_udp_error() -> program_wit::net::UdpError {
    program_wit::net::UdpError {
        kind: program_wit::net::UdpErrorKind::Unavailable,
        detail: "network service is unavailable on this machine".to_owned(),
    }
}

fn unavailable_program_udp_authority_error() -> program_wit::net::UdpError {
    program_wit::net::UdpError {
        kind: program_wit::net::UdpErrorKind::Unavailable,
        detail: "network authority is missing UDP or privileged-bind rights".to_owned(),
    }
}

fn convert_program_tcp_error(error: crate::TcpError) -> program_wit::net::TcpError {
    program_wit::net::TcpError {
        kind: match error.kind {
            crate::TcpErrorKind::UnresolvedHost => program_wit::net::TcpErrorKind::UnresolvedHost,
            crate::TcpErrorKind::Timeout => program_wit::net::TcpErrorKind::Timeout,
            crate::TcpErrorKind::ConnectionReset => program_wit::net::TcpErrorKind::ConnectionReset,
            crate::TcpErrorKind::ConnectionAborted => {
                program_wit::net::TcpErrorKind::ConnectionAborted
            }
            crate::TcpErrorKind::PermissionDenied => {
                program_wit::net::TcpErrorKind::PermissionDenied
            }
            crate::TcpErrorKind::Unavailable
                if error.detail == crate::NetworkErrorDetail::TcpListenStartFailed =>
            {
                program_wit::net::TcpErrorKind::AddressInUse
            }
            crate::TcpErrorKind::Unavailable => program_wit::net::TcpErrorKind::Unavailable,
            crate::TcpErrorKind::Internal => program_wit::net::TcpErrorKind::Internal,
        },
        detail: error.detail.as_str().to_owned(),
    }
}

fn convert_program_udp_datagram(datagram: crate::UdpDatagram) -> program_wit::net::UdpDatagram {
    program_wit::net::UdpDatagram {
        address: convert_program_ip_address(datagram.address),
        port: datagram.port,
        bytes: lower_bytes_to_vec(datagram.bytes),
    }
}

fn convert_program_udp_error(error: crate::UdpError) -> program_wit::net::UdpError {
    program_wit::net::UdpError {
        kind: match error.kind {
            crate::UdpErrorKind::UnresolvedHost => program_wit::net::UdpErrorKind::UnresolvedHost,
            crate::UdpErrorKind::Unsupported => program_wit::net::UdpErrorKind::Unavailable,
            crate::UdpErrorKind::Timeout => program_wit::net::UdpErrorKind::Timeout,
            crate::UdpErrorKind::PermissionDenied => {
                program_wit::net::UdpErrorKind::PermissionDenied
            }
            crate::UdpErrorKind::Unavailable => program_wit::net::UdpErrorKind::Unavailable,
            crate::UdpErrorKind::Internal => program_wit::net::UdpErrorKind::Internal,
        },
        detail: error.detail.as_str().to_owned(),
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
#[error("serial port handle lacks {operation} authority")]
struct SerialPermissionDenied {
    operation: &'static str,
}

impl<CpuImpl, Net, StorageImpl> program_wit::serial::Host for StoreData<CpuImpl, Net, StorageImpl>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
}

impl<CpuImpl, Net, StorageImpl, U> program_wit::serial::HostWithStore<U>
    for HasSelf<StoreData<CpuImpl, Net, StorageImpl>>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    fn debug_port(
        mut access: Access<'_, U, Self>,
    ) -> wasmtime::Result<Option<Resource<SbiSerialPort>>> {
        let authority = access.get().process_authority();
        let can_read = authority.derive_terminal_input_cap().is_ok();
        let can_write = authority.derive_terminal_output_cap().is_ok();
        if !can_read && !can_write {
            return Ok(None);
        }
        Ok(Some(access.get().table.push(SbiSerialPort {
            can_read,
            can_write,
            _resource: SerialPortResource,
        })?))
    }
}

impl<CpuImpl, Net, StorageImpl> program_wit::serial::HostSerialPort
    for StoreData<CpuImpl, Net, StorageImpl>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
}

impl<CpuImpl, Net, StorageImpl, U> program_wit::serial::HostSerialPortWithStore<U>
    for HasSelf<StoreData<CpuImpl, Net, StorageImpl>>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    fn rights(
        mut access: Access<'_, U, Self>,
        resource: Resource<SbiSerialPort>,
    ) -> wasmtime::Result<program_wit::serial::SerialRights> {
        let port = access.get().table.get(&resource)?;
        let mut rights = program_wit::serial::SerialRights::empty();
        if port.can_read {
            rights |= program_wit::serial::SerialRights::READ;
        }
        if port.can_write {
            rights |=
                program_wit::serial::SerialRights::WRITE | program_wit::serial::SerialRights::FLUSH;
        }
        Ok(rights)
    }

    fn drop(
        mut access: Access<'_, U, Self>,
        resource: Resource<SbiSerialPort>,
    ) -> wasmtime::Result<()> {
        let _ = access.get().table.delete(resource)?;
        Ok(())
    }

    async fn read(
        accessor: &Accessor<U, Self>,
        resource: Resource<SbiSerialPort>,
        max_bytes: u32,
    ) -> wasmtime::Result<Vec<u8>> {
        let writer = accessor.with(|mut access| {
            let port = access.get().table.get(&resource)?;
            if !port.can_read {
                return Err(wasmtime::Error::new(SerialPermissionDenied {
                    operation: "read",
                }));
            }
            Ok::<_, wasmtime::Error>(access.get().serial_writer())
        })?;
        // Arm the console's receive wait before polling the
        // non-blocking serial reader so a byte that lands between the
        // two is never lost, then park on it when the port was empty.
        loop {
            let wait = writer.wait_for_debug_serial_input();
            let bytes = accessor.with(|mut access| access.get().try_read_serial_port(max_bytes));
            if !bytes.is_empty() {
                return Ok(bytes);
            }
            wait.await;
        }
    }

    async fn write(
        accessor: &Accessor<U, Self>,
        resource: Resource<SbiSerialPort>,
        bytes: Vec<u8>,
    ) -> wasmtime::Result<()> {
        let writer = accessor.with(|mut access| {
            let port = access.get().table.get(&resource)?;
            if !port.can_write {
                return Err(wasmtime::Error::new(SerialPermissionDenied {
                    operation: "write",
                }));
            }
            Ok::<_, wasmtime::Error>(access.get().serial_writer())
        })?;
        // One call is one segment. The debugger's transport puts a
        // whole RPC frame on the wire with a single write, and the
        // console keeps a segment indivisible, which is what stops a
        // kernel console record from landing inside a frame (#103).
        // Another processor may own the port, so the attempt waits on
        // the console's transmit signal rather than on the executor.
        loop {
            let wait = writer.wait_for_debug_serial_output_ready();
            if writer.try_write(&bytes) {
                return Ok(());
            }
            wait.await;
        }
    }

    fn flush(
        mut access: Access<'_, U, Self>,
        resource: Resource<SbiSerialPort>,
    ) -> wasmtime::Result<()> {
        let port = access.get().table.get(&resource)?;
        if !port.can_write {
            return Err(wasmtime::Error::new(SerialPermissionDenied {
                operation: "flush",
            }));
        }
        Ok(())
    }
}

impl<CpuImpl, Net, StorageImpl> program_wit::sync::Host for StoreData<CpuImpl, Net, StorageImpl>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
}

impl<CpuImpl, Net, StorageImpl> program_wit::sync::HostRawMutex
    for StoreData<CpuImpl, Net, StorageImpl>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
}

impl<CpuImpl, Net, StorageImpl, U> program_wit::sync::HostRawMutexWithStore<U>
    for HasSelf<StoreData<CpuImpl, Net, StorageImpl>>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    fn new(mut access: Access<'_, U, Self>) -> wasmtime::Result<Resource<SbiRawMutex>> {
        let pushed = access.get().table.push(SbiRawMutex {
            resource: RawMutexResource {
                inner: Arc::new(RawMutex::new()),
            },
        });
        Ok(pushed?)
    }

    fn drop(
        mut access: Access<'_, U, Self>,
        resource: Resource<SbiRawMutex>,
    ) -> wasmtime::Result<()> {
        let _ = access.get().table.delete(resource)?;
        Ok(())
    }

    async fn lock(
        accessor: &Accessor<U, Self>,
        resource: Resource<SbiRawMutex>,
    ) -> wasmtime::Result<Resource<SbiRawMutexGuard>> {
        let mutex = accessor.with(|mut access| {
            Ok::<_, wasmtime::Error>(access.get().table.get(&resource)?.resource.inner.clone())
        })?;
        let lease = mutex.lock_owned().await;
        accessor.with(|mut access| {
            Ok(access.get().table.push(SbiRawMutexGuard {
                _resource: RawMutexGuardResource { _lease: lease },
            })?)
        })
    }
}

impl<CpuImpl, Net, StorageImpl> program_wit::sync::HostRawMutexGuard
    for StoreData<CpuImpl, Net, StorageImpl>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
}

impl<CpuImpl, Net, StorageImpl, U> program_wit::sync::HostRawMutexGuardWithStore<U>
    for HasSelf<StoreData<CpuImpl, Net, StorageImpl>>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    fn drop(
        mut access: Access<'_, U, Self>,
        resource: Resource<SbiRawMutexGuard>,
    ) -> wasmtime::Result<()> {
        let _ = access.get().table.delete(resource)?;
        Ok(())
    }
}

impl<CpuImpl, Net, StorageImpl> program_wit::sync::HostRawRwLock
    for StoreData<CpuImpl, Net, StorageImpl>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
}

impl<CpuImpl, Net, StorageImpl, U> program_wit::sync::HostRawRwLockWithStore<U>
    for HasSelf<StoreData<CpuImpl, Net, StorageImpl>>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    fn new(mut access: Access<'_, U, Self>) -> wasmtime::Result<Resource<SbiRawRwLock>> {
        let pushed = access.get().table.push(SbiRawRwLock {
            resource: RawRwLockResource {
                inner: Arc::new(RawRwLock::new()),
            },
        });
        Ok(pushed?)
    }

    fn drop(
        mut access: Access<'_, U, Self>,
        resource: Resource<SbiRawRwLock>,
    ) -> wasmtime::Result<()> {
        let _ = access.get().table.delete(resource)?;
        Ok(())
    }

    async fn read(
        accessor: &Accessor<U, Self>,
        resource: Resource<SbiRawRwLock>,
    ) -> wasmtime::Result<Resource<SbiRawRwLockReadGuard>> {
        let rwlock = accessor.with(|mut access| {
            Ok::<_, wasmtime::Error>(access.get().table.get(&resource)?.resource.inner.clone())
        })?;
        let lease = rwlock.read_owned().await;
        accessor.with(|mut access| {
            Ok(access.get().table.push(SbiRawRwLockReadGuard {
                _resource: RawRwLockReadGuardResource { _lease: lease },
            })?)
        })
    }

    async fn write(
        accessor: &Accessor<U, Self>,
        resource: Resource<SbiRawRwLock>,
    ) -> wasmtime::Result<Resource<SbiRawRwLockWriteGuard>> {
        let rwlock = accessor.with(|mut access| {
            Ok::<_, wasmtime::Error>(access.get().table.get(&resource)?.resource.inner.clone())
        })?;
        let lease = rwlock.write_owned().await;
        accessor.with(|mut access| {
            Ok(access.get().table.push(SbiRawRwLockWriteGuard {
                _resource: RawRwLockWriteGuardResource { _lease: lease },
            })?)
        })
    }
}

impl<CpuImpl, Net, StorageImpl> program_wit::sync::HostRawRwLockReadGuard
    for StoreData<CpuImpl, Net, StorageImpl>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
}

impl<CpuImpl, Net, StorageImpl, U> program_wit::sync::HostRawRwLockReadGuardWithStore<U>
    for HasSelf<StoreData<CpuImpl, Net, StorageImpl>>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    fn drop(
        mut access: Access<'_, U, Self>,
        resource: Resource<SbiRawRwLockReadGuard>,
    ) -> wasmtime::Result<()> {
        let _ = access.get().table.delete(resource)?;
        Ok(())
    }
}

impl<CpuImpl, Net, StorageImpl> program_wit::sync::HostRawRwLockWriteGuard
    for StoreData<CpuImpl, Net, StorageImpl>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
}

impl<CpuImpl, Net, StorageImpl, U> program_wit::sync::HostRawRwLockWriteGuardWithStore<U>
    for HasSelf<StoreData<CpuImpl, Net, StorageImpl>>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    fn drop(
        mut access: Access<'_, U, Self>,
        resource: Resource<SbiRawRwLockWriteGuard>,
    ) -> wasmtime::Result<()> {
        let _ = access.get().table.delete(resource)?;
        Ok(())
    }
}

/// The program world's trace stream. It owns a filter, the scope it was
/// created with and a cursor, and no buffer: each poll runs on the store's
/// task and asks the trace log for the next event the scope admits and the
/// filter matches, which copies a bounded batch of pointers under the
/// log's lock and matches after releasing it.
///
/// The scope is fixed when the stream is created, from the creator's
/// authority at that moment, and the stream keeps it for its life.
struct ProgramTracingStreamProducer<Scope> {
    scope: Scope,
    filter: TraceFilter,
    cursor: u64,
    waiter: crate::NotifyWaiter,
}

impl<Scope> ProgramTracingStreamProducer<Scope> {
    fn new(filter: TraceFilter, scope: Scope, waiter: crate::NotifyWaiter) -> Self {
        Self {
            scope,
            filter,
            cursor: 0,
            waiter,
        }
    }
}

impl<Scope, CpuImpl, Net, StorageImpl> StreamProducer<StoreData<CpuImpl, Net, StorageImpl>>
    for ProgramTracingStreamProducer<Scope>
where
    Scope: crate::ObservationScope + Send + Unpin + 'static,
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    type Item = program_wit::tracing::Event;
    type Buffer = Option<Self::Item>;

    fn poll_produce<'a>(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        store: StoreContextMut<'_, StoreData<CpuImpl, Net, StorageImpl>>,
        mut destination: Destination<'a, Self::Item, Self::Buffer>,
        finish: bool,
    ) -> Poll<wasmtime::Result<StreamResult>> {
        if finish {
            return Poll::Ready(Ok(StreamResult::Cancelled));
        }

        let this = &mut *self;
        match store.data().runtime_state.poll_next_after(
            cx,
            &mut this.waiter,
            &this.scope,
            &mut this.cursor,
            &this.filter,
        ) {
            Poll::Ready(event) => {
                destination.set_buffer(Some(convert_program_event(&event)));
                Poll::Ready(Ok(StreamResult::Completed))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Lowers a shared history event. The history keeps its copy for other
/// readers, so the guest's copy of each string is made here, after the
/// history's lock is released.
fn convert_program_event(event: &TraceEvent) -> program_wit::tracing::Event {
    program_wit::tracing::Event {
        timestamp: event.timestamp,
        level: convert_program_level_from_local(event.level),
        target: event.target.clone(),
        fields: event.fields.iter().map(convert_program_field).collect(),
    }
}

fn convert_program_field(field: &TraceField) -> program_wit::tracing::Field {
    program_wit::tracing::Field {
        key: field.key.clone(),
        value: convert_program_value(&field.value),
    }
}

fn convert_program_value(value: &TraceValue) -> program_wit::tracing::Value {
    match value {
        TraceValue::Boolean(value) => program_wit::tracing::Value::Boolean(*value),
        TraceValue::Signed64(value) => program_wit::tracing::Value::Signed64(*value),
        TraceValue::Unsigned64(value) => program_wit::tracing::Value::Unsigned64(*value),
        TraceValue::Float64(value) => program_wit::tracing::Value::Float64(*value),
        TraceValue::Text(value) => program_wit::tracing::Value::Text(value.clone()),
        TraceValue::Blob(value) => program_wit::tracing::Value::Blob(value.clone()),
    }
}

fn convert_program_level_from_local(level: TraceLevel) -> program_wit::tracing::Level {
    match level {
        TraceLevel::Error => program_wit::tracing::Level::Error,
        TraceLevel::Warn => program_wit::tracing::Level::Warn,
        TraceLevel::Info => program_wit::tracing::Level::Info,
        TraceLevel::Debug => program_wit::tracing::Level::Debug,
        TraceLevel::Trace => program_wit::tracing::Level::Trace,
    }
}

/// A stage marker a release kernel does not print.
///
/// The per-program markers are the noisiest of them and exist for
/// bring-up, so they stay behind the debug build the way they always
/// have.
fn emit_program_stage_marker(write_serial: crate::DebugSerialWriter, stage: &str) {
    if cfg!(debug_assertions) {
        write_serial.emit_stage_marker(stage);
    }
}

#[derive(Debug, Error)]
pub enum RootComponentError {
    #[error("failed to load root supervisor component: {0:#}")]
    LoadComponent(wasmtime::Error),
    #[error("failed to instantiate root supervisor component: {0:#}")]
    InstantiateComponent(wasmtime::Error),
    #[error("root supervisor component trapped: {0:#}")]
    RunComponent(wasmtime::Error),
    #[error("root supervisor component returned a non-zero result")]
    GuestFailed,
    #[error("the executor has no task capacity left for the root supervisor component: {0}")]
    TaskCapacity(crate::TaskCapacityError),
}

#[cfg(test)]
mod tests {
    use helios_hal::cpu::ProcessorId;
    use helios_hal::watchdog::ProgressCounter;

    use super::{ComponentPhase, ComponentPhaseHeartbeat, spawn_component_phase_heartbeat};
    use crate::test_support::TestCpu;
    use crate::{Executor, InstanceSpawner, TaskCapacityError, TaskFunding, Timer};

    /// One block per 64-byte granule is the most blocks an instance
    /// share can ever hold, so a run this long outlives the share
    /// whatever size class the heartbeat future lands in. The share is
    /// the arena's floor here — a host test installs no boot memory
    /// plan, so every arena is `TASK_ARENA_MIN_BYTES`, of which the
    /// share is all but the kernel reserve. Nothing in the loop tells a
    /// heartbeat its phase is over; the only thing that ends one is its
    /// guard going out of scope.
    const PHASES_PAST_THE_SHARE: usize = crate::TASK_ARENA_MIN_BYTES / 64 + 1;

    /// An exec whose program image the user pool could not hold is a
    /// memory failure.
    #[test]
    fn exec_maps_a_refused_frame_to_out_of_memory() {
        let memory = super::service::map_aot_fs_error(
            crate::wasmtime_adapter::wasi::bindings::filesystem::types::ErrorCode::InsufficientMemory,
        );
        assert_eq!(memory.kind, crate::ProgramExecErrorKind::OutOfMemory);
    }

    /// The heartbeat only writes in debug builds, and where it writes is
    /// not what these tests are about, so the port it reaches drops
    /// every byte.
    struct DiscardPort;

    impl helios_hal::serial::ByteSerial for DiscardPort {
        fn try_read_byte(&self) -> Option<u8> {
            None
        }

        fn write_bytes(&self, _bytes: &[u8]) {}

        fn enable_receive_interrupt(&self) {}

        fn disable_receive_interrupt(&self) {}
    }

    static DISCARD_CONSOLE: crate::DebugConsole = crate::DebugConsole::new();

    impl crate::DebugSerialAccess for DiscardPort {
        type Port = Self;

        fn port() -> Self {
            Self
        }

        fn console() -> &'static crate::DebugConsole {
            &DISCARD_CONSOLE
        }
    }

    const DISCARD_SERIAL: crate::DebugSerialWriter = crate::DebugSerialWriter::of::<DiscardPort>();

    struct PhaseFixture {
        executor: Executor,
        spawner: InstanceSpawner<TestCpu>,
        timer: Timer<TestCpu>,
        progress: ProgressCounter,
        cpu: TestCpu,
    }

    impl PhaseFixture {
        fn new() -> Self {
            let cpu = TestCpu::without_entropy();
            let executor = Executor::new(
                ProgressCounter::new(),
                crate::test_support::single_node_pool(1),
                ProcessorId::new(0),
            );
            let instance = crate::InstanceRegistry::new().register("phase", 0);
            let spawner = executor
                .spawner(cpu)
                .instance_spawner(TaskFunding::Instance, &instance);
            let timer = executor.timer(cpu);
            Self {
                executor,
                spawner,
                timer,
                progress: ProgressCounter::new(),
                cpu,
            }
        }

        fn start_phase(&self) -> Result<ComponentPhaseHeartbeat, TaskCapacityError> {
            spawn_component_phase_heartbeat(
                &self.spawner,
                &self.cpu,
                &self.timer,
                &self.progress,
                DISCARD_SERIAL,
                ComponentPhase {
                    name: "test:phase",
                    started_at: 0,
                },
            )
        }

        /// Runs the executor until it stalls. The fixture's clock never
        /// advances, so a heartbeat polled here parks on its sleep
        /// exactly as it does while a real instance runs, and a
        /// heartbeat whose guard has been dropped is cancelled here —
        /// which is where its arena block goes back.
        fn drain(&self) {
            self.executor.run_until_stalled_with_stats(&self.timer);
        }

        /// One phase, started and ended, with its heartbeat parked on
        /// its sleep in between — the shape every instance's run phase
        /// has. The cancelled heartbeat's sleep leaves its timer's
        /// wheel as it is dropped, so nothing is left for a fire to
        /// clear.
        fn run_phase(&self) -> Result<(), TaskCapacityError> {
            let heartbeat = self.start_phase()?;
            self.drain();
            drop(heartbeat);
            self.drain();
            assert_eq!(self.timer.registered_sleeps(), 0);
            Ok(())
        }
    }

    /// Issue #132: after two workloads had spawned instances, every
    /// later spawn on that processor was refused because the arena
    /// still held a task per instance that had already exited. Those
    /// tasks were phase heartbeats: detached, instance-funded, and
    /// ended only by an `AtomicBool` they re-read after a five-second
    /// sleep. Ending a phase must return its heartbeat's block now.
    #[test]
    fn a_phase_that_ends_returns_its_heartbeat_block_to_the_instance_share() {
        let _serialized = crate::exec::executor_test_guard();
        let fixture = PhaseFixture::new();

        for phase in 0..PHASES_PAST_THE_SHARE {
            fixture
                .run_phase()
                .unwrap_or_else(|error| panic!("phase {phase} was refused: {error}"));
        }
    }

    /// The exit a condemned instance takes: the run returns an error
    /// and nothing on the way out signals the heartbeat. The guard is
    /// the signal, so the share comes back on this path too — the path
    /// the old `run_done.store(true)` was skipped on entirely, which
    /// left the block held for the rest of the kernel's life.
    #[test]
    fn a_phase_that_ends_in_an_error_returns_its_heartbeat_block() {
        let _serialized = crate::exec::executor_test_guard();
        let fixture = PhaseFixture::new();

        fn run_condemned_phase(fixture: &PhaseFixture) -> Result<(), &'static str> {
            let _heartbeat = fixture.start_phase().map_err(|_| "refused")?;
            fixture.drain();
            Err("instance condemned mid-run")
        }

        for phase in 0..PHASES_PAST_THE_SHARE {
            assert_eq!(
                run_condemned_phase(&fixture),
                Err("instance condemned mid-run"),
                "phase {phase} did not reach its error exit",
            );
            fixture.drain();
            assert_eq!(fixture.timer.registered_sleeps(), 0);
        }
    }

    #[test]
    fn serial_debug_port_enforces_terminal_input_and_output_rights_independently() {
        use super::program_wit::serial::{HostSerialPortWithStore, HostWithStore, SerialRights};
        use crate::wasmtime_adapter::component_host::service::test_store::{
            TestStoreData, store_data_authorized,
        };
        use crate::wasmtime_adapter::engine::build_component_engine_for_platform;
        use crate::{ProcessAuthority, TerminalAuthorityRights};
        use futures_lite::future::block_on;
        use wasmtime::Store;
        use wasmtime::component::{HasSelf, Resource};

        let engine =
            build_component_engine_for_platform(&crate::test_support::TestCpu::with_entropy(0x66))
                .unwrap();

        // 1. Empty authority gets no serial port.
        let mut empty_store = Store::new(
            &engine,
            store_data_authorized(ProcessAuthority::empty(), |_| {}),
        );
        let none_port = block_on(empty_store.run_concurrent(async |accessor| {
            accessor.with(<HasSelf<TestStoreData> as HostWithStore<_>>::debug_port)
        }))
        .unwrap()
        .unwrap();
        assert!(none_port.is_none());

        // 2. `INPUT`-only authority gets READ right only; write and flush are refused.
        let mut input_only = ProcessAuthority::empty();
        input_only.grant_terminal_rights(TerminalAuthorityRights::INPUT);
        let mut input_store = Store::new(&engine, store_data_authorized(input_only, |_| {}));
        block_on(input_store.run_concurrent(async |accessor| {
            let port = accessor
                .with(<HasSelf<TestStoreData> as HostWithStore<_>>::debug_port)
                .unwrap()
                .expect("INPUT authority must obtain a read-only serial port");
            let rights = accessor
                .with(|access| {
                    <HasSelf<TestStoreData> as HostSerialPortWithStore<_>>::rights(
                        access,
                        Resource::new_borrow(port.rep()),
                    )
                })
                .unwrap();
            assert_eq!(rights, SerialRights::READ);
            assert!(
                <HasSelf<TestStoreData> as HostSerialPortWithStore<_>>::write(
                    accessor,
                    Resource::new_borrow(port.rep()),
                    b"blocked".to_vec(),
                )
                .await
                .is_err(),
                "INPUT-only serial port must refuse write"
            );
            assert!(
                accessor
                    .with(|access| {
                        <HasSelf<TestStoreData> as HostSerialPortWithStore<_>>::flush(
                            access,
                            Resource::new_borrow(port.rep()),
                        )
                    })
                    .is_err(),
                "INPUT-only serial port must refuse flush"
            );
            accessor
                .with(|access| {
                    <HasSelf<TestStoreData> as HostSerialPortWithStore<_>>::drop(access, port)
                })
                .unwrap();
        }))
        .unwrap();

        // 3. `OUTPUT`-only authority gets WRITE | FLUSH only; read is refused, write & flush succeed.
        let mut output_only = ProcessAuthority::empty();
        output_only.grant_terminal_rights(TerminalAuthorityRights::OUTPUT);
        let mut output_store = Store::new(&engine, store_data_authorized(output_only, |_| {}));
        block_on(output_store.run_concurrent(async |accessor| {
            let port = accessor
                .with(<HasSelf<TestStoreData> as HostWithStore<_>>::debug_port)
                .unwrap()
                .expect("OUTPUT authority must obtain a write-only serial port");
            let rights = accessor
                .with(|access| {
                    <HasSelf<TestStoreData> as HostSerialPortWithStore<_>>::rights(
                        access,
                        Resource::new_borrow(port.rep()),
                    )
                })
                .unwrap();
            assert_eq!(rights, SerialRights::WRITE | SerialRights::FLUSH);
            assert!(
                <HasSelf<TestStoreData> as HostSerialPortWithStore<_>>::read(
                    accessor,
                    Resource::new_borrow(port.rep()),
                    16,
                )
                .await
                .is_err(),
                "OUTPUT-only serial port must refuse read"
            );
            <HasSelf<TestStoreData> as HostSerialPortWithStore<_>>::write(
                accessor,
                Resource::new_borrow(port.rep()),
                b"ok".to_vec(),
            )
            .await
            .expect("OUTPUT-only serial port must allow write");
            accessor
                .with(|access| {
                    <HasSelf<TestStoreData> as HostSerialPortWithStore<_>>::flush(
                        access,
                        Resource::new_borrow(port.rep()),
                    )
                })
                .expect("OUTPUT-only serial port must allow flush");
            accessor
                .with(|access| {
                    <HasSelf<TestStoreData> as HostSerialPortWithStore<_>>::drop(access, port)
                })
                .unwrap();
        }))
        .unwrap();

        // 4. `INPUT | OUTPUT` gets READ | WRITE | FLUSH.
        let mut both = ProcessAuthority::empty();
        both.grant_terminal_rights(
            TerminalAuthorityRights::INPUT | TerminalAuthorityRights::OUTPUT,
        );
        let mut both_store = Store::new(&engine, store_data_authorized(both, |_| {}));
        block_on(both_store.run_concurrent(async |accessor| {
            let port = accessor
                .with(<HasSelf<TestStoreData> as HostWithStore<_>>::debug_port)
                .unwrap()
                .expect("INPUT | OUTPUT authority must obtain a full serial port");
            let rights = accessor
                .with(|access| {
                    <HasSelf<TestStoreData> as HostSerialPortWithStore<_>>::rights(
                        access,
                        Resource::new_borrow(port.rep()),
                    )
                })
                .unwrap();
            assert_eq!(
                rights,
                SerialRights::READ | SerialRights::WRITE | SerialRights::FLUSH
            );
            accessor
                .with(|access| {
                    <HasSelf<TestStoreData> as HostSerialPortWithStore<_>>::drop(access, port)
                })
                .unwrap();
        }))
        .unwrap();
    }

    #[test]
    fn tracing_stream_producer_registers_waker_and_delivers_events_after_parking() {
        use alloc::sync::Arc as StdArc;
        use alloc::task::Wake;
        use alloc::vec::Vec;
        use core::future::Future;
        use core::pin::Pin;
        use core::sync::atomic::{AtomicUsize, Ordering};
        use core::task::{Context, Poll, Waker};

        use super::ProgramTracingStreamProducer;
        use crate::wasmtime_adapter::component_host::service::test_store::{
            TestStoreData, store_data_authorized,
        };
        use crate::wasmtime_adapter::engine::build_component_engine_for_platform;
        use crate::{AuthorityScope, MachineObservation, PrefixSet, ProcessAuthority, TraceFilter};
        use futures::channel::oneshot;
        use spin::Mutex;
        use wasmtime::component::{Source, StreamConsumer, StreamReader, StreamResult};
        use wasmtime::{Store, StoreContextMut};

        struct CountingWake(StdArc<AtomicUsize>);

        impl Wake for CountingWake {
            fn wake(self: StdArc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }

            fn wake_by_ref(self: &StdArc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        struct EventCollectorConsumer {
            received: StdArc<Mutex<Vec<super::program_wit::tracing::Event>>>,
            target_count: usize,
            done: Option<oneshot::Sender<()>>,
        }

        impl StreamConsumer<TestStoreData> for EventCollectorConsumer {
            type Item = super::program_wit::tracing::Event;

            fn poll_consume(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                mut store: StoreContextMut<TestStoreData>,
                mut source: Source<'_, Self::Item>,
                finish: bool,
            ) -> Poll<wasmtime::Result<StreamResult>> {
                if finish {
                    return Poll::Ready(Ok(StreamResult::Cancelled));
                }
                let mut batch = Vec::with_capacity(4);
                source.read(&mut store, &mut batch)?;
                let this = self.get_mut();
                let len = {
                    let mut guard = this.received.lock();
                    guard.extend(batch);
                    guard.len()
                };
                if len >= this.target_count {
                    if let Some(done) = this.done.take() {
                        let _ = done.send(());
                    }
                    Poll::Ready(Ok(StreamResult::Dropped))
                } else {
                    Poll::Ready(Ok(StreamResult::Completed))
                }
            }
        }

        let wakes = StdArc::new(AtomicUsize::new(0));
        let waker = Waker::from(StdArc::new(CountingWake(StdArc::clone(&wakes))));
        let mut cx = Context::from_waker(&waker);

        let engine =
            build_component_engine_for_platform(&crate::test_support::TestCpu::with_entropy(0x77))
                .unwrap();

        let mut authority = ProcessAuthority::empty();
        authority.grant_trace_read(AuthorityScope::Machine);
        let store_data = store_data_authorized(authority, |state| {
            state.record_console_text(1, None, "INFO [stream-test] initial\n");
        });
        let runtime_state = store_data.runtime_state.clone();
        let mut store = Store::new(&engine, store_data);

        let filter = TraceFilter {
            min_level: None,
            target_prefixes: PrefixSet::from_prefixes(["stream-test"]).unwrap(),
        };
        let received = StdArc::new(Mutex::new(Vec::new()));
        let (done_tx, done_rx) = oneshot::channel();
        let consumer = EventCollectorConsumer {
            received: StdArc::clone(&received),
            target_count: 2,
            done: Some(done_tx),
        };

        let run = store.run_concurrent(async move |accessor| {
            accessor
                .with(|mut access| {
                    let waiter = access.get().runtime_state.trace_waiter();
                    StreamReader::new(
                        &mut access,
                        ProgramTracingStreamProducer::new(filter, MachineObservation, waiter),
                    )?
                    .pipe(access, consumer)
                })
                .expect("connect tracing stream reader");
            done_rx.await.expect("tracing stream delivered all events");
        });
        let mut run = core::pin::pin!(run);

        fn poll_until_parked<F: Future>(
            run: &mut Pin<&mut F>,
            cx: &mut Context<'_>,
            wakes: &AtomicUsize,
        ) {
            for _ in 0..8 {
                let before = wakes.load(Ordering::SeqCst);
                assert!(
                    matches!(run.as_mut().poll(cx), Poll::Pending),
                    "stream task must stay pending before the second matching event"
                );
                if wakes.load(Ordering::SeqCst) == before {
                    return;
                }
            }
            panic!("stream task kept self-waking instead of parking cleanly");
        }

        // Drain the initial event and settle into a quiescent parked state.
        poll_until_parked(&mut run, &mut cx, &wakes);
        assert_eq!(received.lock().len(), 1);

        // A non-matching event wakes the stream, which skips it and re-parks.
        let wakes_before_unrelated = wakes.load(Ordering::SeqCst);
        runtime_state.record_console_text(2, None, "INFO [unrelated] filtered-out\n");
        assert!(
            wakes.load(Ordering::SeqCst) > wakes_before_unrelated,
            "recording an event must wake the parked tracing stream task"
        );
        poll_until_parked(&mut run, &mut cx, &wakes);
        assert_eq!(received.lock().len(), 1);

        let wakes_before = wakes.load(Ordering::SeqCst);

        // Record a matching event with nothing else polling the stream task.
        runtime_state.record_console_text(3, None, "INFO [stream-test] after-park\n");
        assert!(
            wakes.load(Ordering::SeqCst) > wakes_before,
            "recording a matching trace event must wake the parked tracing stream task"
        );

        let mut completed = false;
        for _ in 0..8 {
            match run.as_mut().poll(&mut cx) {
                Poll::Ready(result) => {
                    result.expect("run_concurrent succeeded");
                    completed = true;
                    break;
                }
                Poll::Pending => {
                    // `run_concurrent` may wake once between producer delivery
                    // and `done_rx` completion.
                    assert!(
                        wakes.load(Ordering::SeqCst) > wakes_before,
                        "stream task parked without delivering the new event"
                    );
                }
            }
        }
        assert!(
            completed,
            "woken tracing stream must deliver the new event and complete"
        );

        let events = received.lock();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].target, "stream-test");
        assert_eq!(events[1].target, "stream-test");
        assert!(events[1].fields.iter().any(|field| {
            field.key == "message"
                && matches!(
                    &field.value,
                    super::program_wit::tracing::Value::Text(text) if text == "after-park"
                )
        }));
    }
}
