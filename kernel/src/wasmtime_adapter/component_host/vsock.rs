//! `helios:system/vsock` for the component host.
//!
//! The two worlds the kernel serves — `init` for ordinary programs and
//! `debugger` for the system component — generate their own Rust types
//! for the same WIT interface, so the registration is written once and
//! parameterised over a [`VsockBindings`] marker that names each world's
//! value types. The alternative the network interface took, one copy of
//! every host function per world, is exactly the duplication this
//! avoids.
//!
//! Capability: vsock is the machine's link to whatever is hosting it,
//! and the capability that says a component may talk to its host
//! controller is the same one that hands out the debug serial port. A
//! component without it gets `permission-denied` from every entry point
//! rather than a device that quietly is not there.

use crate::ComponentHostNetwork;
use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use helios_hal::cpu::Cpu;
use helios_hal::vsock::{VsockAddress, VsockShutdown};
use wasmtime::component::{
    Access, Accessor, ComponentType, Lift, Linker, Lower, Resource, ResourceType,
};

use crate::wasmtime_adapter::bindings::program::bindings as program_bindings;
use crate::{ComponentHostVsockService, VsockError, VsockListenerId, VsockStreamId};

use super::StoreData;

pub(super) const VSOCK_INSTANCE: &str = "helios:system/vsock@0.1.0";

/// The kernel-side view of an open `vsock-stream` resource.
pub struct ComponentVsockStream {
    pub service: ComponentHostVsockService,
    pub stream: Option<VsockStreamId>,
}

impl ComponentVsockStream {
    pub fn new(service: ComponentHostVsockService, stream: VsockStreamId) -> Self {
        Self {
            service,
            stream: Some(stream),
        }
    }

    pub fn take(&mut self) -> Option<(ComponentHostVsockService, VsockStreamId)> {
        self.stream.take().map(|id| (self.service.clone(), id))
    }
}

/// The kernel-side view of a bound `vsock-listener` resource.
pub struct ComponentVsockListener {
    pub service: ComponentHostVsockService,
    pub listener: Option<VsockListenerId>,
}

impl ComponentVsockListener {
    pub fn new(service: ComponentHostVsockService, listener: VsockListenerId) -> Self {
        Self {
            service,
            listener: Some(listener),
        }
    }

    pub fn take(&mut self) -> Option<(ComponentHostVsockService, VsockListenerId)> {
        self.listener.take().map(|id| (self.service.clone(), id))
    }

    pub fn close(&mut self) -> Result<(), VsockError> {
        let id = self.listener.take().ok_or(VsockError::Closed)?;
        self.service.close_listener(id)
    }
}

impl Drop for ComponentVsockListener {
    fn drop(&mut self) {
        if let Some(id) = self.listener.take()
            && let Err(error) = self.service.close_listener(id)
        {
            tracing::debug!(%error, "dropped vsock listener was already gone");
        }
    }
}

/// One world's generated types for `helios:system/vsock`.
///
/// Implementors are zero-sized markers; everything they carry is in the
/// associated types and the two constructors that build them.
pub(super) trait VsockBindings: Send + Sync + 'static {
    type Error: ComponentType + Lower + Send + Sync + 'static;
    type Address: ComponentType + Lower + Lift + Send + Sync + 'static;

    fn error(kind: VsockErrorKind, detail: String) -> Self::Error;
    fn address(address: VsockAddress) -> Self::Address;
    fn to_address(address: &Self::Address) -> VsockAddress;
}

/// The error kinds the WIT interface names, independent of which world's
/// enum they are lowered into.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum VsockErrorKind {
    Unavailable,
    AddressInUse,
    ConnectionRefused,
    ConnectionReset,
    Closed,
    Timeout,
    PermissionDenied,
    Internal,
}

impl VsockErrorKind {
    /// Which kind a kernel-side error reports as.
    fn of(error: VsockError) -> Self {
        match error {
            VsockError::Unavailable => Self::Unavailable,
            VsockError::PortInUse { .. }
            | VsockError::NoEphemeralPort
            | VsockError::ListenerTableFull
            | VsockError::ConnectionTableFull => Self::AddressInUse,
            VsockError::ConnectionRefused => Self::ConnectionRefused,
            VsockError::ConnectionReset => Self::ConnectionReset,
            VsockError::Closed | VsockError::UnknownHandle => Self::Closed,
            VsockError::Timeout => Self::Timeout,
            VsockError::Device(_) => Self::Internal,
        }
    }
}

/// Lowers a kernel error into a world's error record, keeping the
/// kernel's own message as the detail so provenance survives the
/// boundary.
fn convert_error<Bindings: VsockBindings>(error: VsockError) -> Bindings::Error {
    Bindings::error(VsockErrorKind::of(error), error.to_string())
}

fn unavailable<Bindings: VsockBindings>() -> Bindings::Error {
    Bindings::error(
        VsockErrorKind::Unavailable,
        "this machine has no vsock device".to_string(),
    )
}

fn denied<Bindings: VsockBindings>() -> Bindings::Error {
    Bindings::error(
        VsockErrorKind::PermissionDenied,
        "this component does not hold the host-link capability".to_string(),
    )
}

/// Marker for the `init` world's generated vsock types.
pub(super) struct ProgramVsock;

impl VsockBindings for ProgramVsock {
    type Error = program_bindings::helios::system::vsock::VsockError;
    type Address = program_bindings::helios::system::vsock::VsockAddress;

    fn error(kind: VsockErrorKind, detail: String) -> Self::Error {
        use program_bindings::helios::system::vsock::VsockErrorKind as Wit;
        Self::Error {
            kind: match kind {
                VsockErrorKind::Unavailable => Wit::Unavailable,
                VsockErrorKind::AddressInUse => Wit::AddressInUse,
                VsockErrorKind::ConnectionRefused => Wit::ConnectionRefused,
                VsockErrorKind::ConnectionReset => Wit::ConnectionReset,
                VsockErrorKind::Closed => Wit::Closed,
                VsockErrorKind::Timeout => Wit::Timeout,
                VsockErrorKind::PermissionDenied => Wit::PermissionDenied,
                VsockErrorKind::Internal => Wit::Internal,
            },
            detail,
        }
    }

    fn address(address: VsockAddress) -> Self::Address {
        Self::Address {
            cid: address.cid,
            port: address.port,
        }
    }

    fn to_address(address: &Self::Address) -> VsockAddress {
        VsockAddress::new(address.cid, address.port)
    }
}

/// The service a call may use, once the caller's capability and the
/// machine's device have both been checked.
type Authorised<Bindings> = Result<ComponentHostVsockService, <Bindings as VsockBindings>::Error>;

fn has_host_link_authority<CpuImpl, Net, StorageImpl>(
    store: &StoreData<CpuImpl, Net, StorageImpl>,
) -> bool
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    store
        .process_authority()
        .derive_machine_control_cap()
        .is_ok()
}

fn authorise<Bindings, CpuImpl, Net, StorageImpl>(
    store: &StoreData<CpuImpl, Net, StorageImpl>,
) -> Authorised<Bindings>
where
    Bindings: VsockBindings,
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    if !has_host_link_authority(store) {
        return Err(denied::<Bindings>());
    }
    store
        .runtime_state
        .vsock_service()
        .ok_or_else(unavailable::<Bindings>)
}

pub(super) fn add_vsock_to_linker<Bindings, CpuImpl, Net, StorageImpl>(
    linker: &mut Linker<StoreData<CpuImpl, Net, StorageImpl>>,
) -> wasmtime::Result<()>
where
    Bindings: VsockBindings,
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    let mut instance = linker.instance(VSOCK_INSTANCE)?;
    instance.resource_concurrent(
        "vsock-stream",
        ResourceType::host::<ComponentVsockStream>(),
        |accessor, rep| {
            Box::pin(async move {
                let stream = accessor.with(|mut access| {
                    let resource = Resource::<ComponentVsockStream>::new_own(rep);
                    access.get().table.delete(resource)
                })?;
                // A dropped handle is a closed connection; the peer is
                // told rather than left waiting on a stream nothing will
                // ever read again.
                if let Some(id) = stream.stream
                    && let Err(error) = stream.service.close(id).await
                {
                    tracing::debug!(%error, "dropped vsock stream could not be closed cleanly");
                }
                Ok::<_, wasmtime::Error>(())
            })
        },
    )?;
    instance.resource(
        "vsock-listener",
        ResourceType::host::<ComponentVsockListener>(),
        |mut caller, rep| {
            let resource = Resource::<ComponentVsockListener>::new_own(rep);
            let _ = caller.data_mut().table.delete(resource)?;
            Ok(())
        },
    )?;
    instance.func_wrap_concurrent_immediate(
        "guest-cid",
        |caller: Access<'_, StoreData<CpuImpl, Net, StorageImpl>>, (): ()| {
            let store = caller.data();
            let cid = has_host_link_authority(store)
                .then(|| store.runtime_state.vsock_service())
                .flatten()
                .map(|service| service.guest_cid());
            Ok((cid,))
        },
    )?;
    instance.func_wrap_concurrent_immediate(
        "listen",
        |mut caller: Access<'_, StoreData<CpuImpl, Net, StorageImpl>>,
         (port, backlog): (u32, u32)| {
            let service = match authorise::<Bindings, _, _, _>(caller.data()) {
                Ok(service) => service,
                Err(error) => return Ok((Err(error),)),
            };
            let listener = match service.listen(port, backlog as usize) {
                Ok(listener) => listener,
                Err(error) => return Ok((Err(convert_error::<Bindings>(error)),)),
            };
            let resource = caller
                .data_mut()
                .table
                .push(ComponentVsockListener::new(service, listener))?;
            Ok((Ok(resource),))
        },
    )?;
    instance.func_wrap_concurrent(
        "connect",
        |accessor: &Accessor<StoreData<CpuImpl, Net, StorageImpl>>,
         (address, timeout): (Bindings::Address, u64)| {
            Box::pin(async move {
                let peer = Bindings::to_address(&address);
                let service = accessor.with(|mut access| {
                    Ok::<_, wasmtime::Error>(authorise::<Bindings, _, _, _>(access.get()))
                })?;
                let service = match service {
                    Ok(service) => service,
                    Err(error) => return Ok::<_, wasmtime::Error>((Err(error),)),
                };
                let response = match service.connect(peer, timeout).await {
                    Ok(stream) => {
                        let pushed = accessor.with(|mut access| {
                            access
                                .get()
                                .table
                                .push(ComponentVsockStream::new(service.clone(), stream))
                        })?;
                        Ok(pushed)
                    }
                    Err(error) => Err(convert_error::<Bindings>(error)),
                };
                Ok::<_, wasmtime::Error>((response,))
            })
        },
    )?;
    instance.func_wrap_concurrent_immediate(
        "[method]vsock-listener.port",
        |caller: Access<'_, StoreData<CpuImpl, Net, StorageImpl>>,
         (resource,): (Resource<ComponentVsockListener>,)| {
            let listener = caller.data().table.get(&resource)?;
            let result = match listener.listener {
                Some(id) => listener
                    .service
                    .listener_port(id)
                    .map_err(convert_error::<Bindings>),
                None => Err(convert_error::<Bindings>(VsockError::Closed)),
            };
            Ok((result,))
        },
    )?;
    instance.func_wrap_concurrent(
        "[method]vsock-listener.wait-readable",
        |accessor: &Accessor<StoreData<CpuImpl, Net, StorageImpl>>,
         (resource, timeout): (Resource<ComponentVsockListener>, u64)| {
            Box::pin(async move {
                let listener = accessor.with(|mut access| {
                    let listener = access.get().table.get(&resource)?;
                    Ok::<_, wasmtime::Error>((listener.service.clone(), listener.listener))
                })?;
                let Some(id) = listener.1 else {
                    return Ok::<_, wasmtime::Error>((Err(convert_error::<Bindings>(
                        VsockError::Closed,
                    )),));
                };
                let response = listener
                    .0
                    .wait_readable(id, timeout)
                    .await
                    .map_err(convert_error::<Bindings>);
                Ok::<_, wasmtime::Error>((response,))
            })
        },
    )?;
    instance.func_wrap_concurrent(
        "[method]vsock-listener.accept",
        |accessor: &Accessor<StoreData<CpuImpl, Net, StorageImpl>>,
         (resource, timeout): (Resource<ComponentVsockListener>, u64)| {
            Box::pin(async move {
                let listener = accessor.with(|mut access| {
                    let listener = access.get().table.get(&resource)?;
                    Ok::<_, wasmtime::Error>((listener.service.clone(), listener.listener))
                })?;
                let Some(id) = listener.1 else {
                    return Ok::<_, wasmtime::Error>((Err(convert_error::<Bindings>(
                        VsockError::Closed,
                    )),));
                };
                tracing::debug!(timeout, "vsock listener accept requested");
                let accepted = listener.0.accept(id, timeout).await;
                tracing::debug!(ok = accepted.is_ok(), "vsock listener accept returned");
                let response = match accepted {
                    Ok(stream) => {
                        let pushed = accessor.with(|mut access| {
                            access
                                .get()
                                .table
                                .push(ComponentVsockStream::new(listener.0.clone(), stream))
                        })?;
                        Ok(pushed)
                    }
                    Err(error) => Err(convert_error::<Bindings>(error)),
                };
                Ok::<_, wasmtime::Error>((response,))
            })
        },
    )?;
    instance.func_wrap_concurrent_immediate(
        "[method]vsock-listener.close",
        |mut caller: Access<'_, StoreData<CpuImpl, Net, StorageImpl>>,
         (resource,): (Resource<ComponentVsockListener>,)| {
            let listener = caller.data_mut().table.get_mut(&resource)?;
            Ok((listener.close().map_err(convert_error::<Bindings>),))
        },
    )?;
    instance.func_wrap_concurrent_immediate(
        "[method]vsock-stream.peer",
        |caller: Access<'_, StoreData<CpuImpl, Net, StorageImpl>>,
         (resource,): (Resource<ComponentVsockStream>,)| {
            let stream = caller.data().table.get(&resource)?;
            let result = match stream.stream {
                Some(id) => stream
                    .service
                    .peer(id)
                    .map(Bindings::address)
                    .map_err(convert_error::<Bindings>),
                None => Err(convert_error::<Bindings>(VsockError::Closed)),
            };
            Ok((result,))
        },
    )?;
    instance.func_wrap_concurrent(
        "[method]vsock-stream.read",
        |accessor: &Accessor<StoreData<CpuImpl, Net, StorageImpl>>,
         (resource, max_bytes, timeout): (Resource<ComponentVsockStream>, u32, u64)| {
            Box::pin(async move {
                let stream = accessor.with(|mut access| {
                    let stream = access.get().table.get(&resource)?;
                    Ok::<_, wasmtime::Error>((stream.service.clone(), stream.stream))
                })?;
                let Some(id) = stream.1 else {
                    return Ok::<_, wasmtime::Error>((Err(convert_error::<Bindings>(
                        VsockError::Closed,
                    )),));
                };
                tracing::debug!(max_bytes, timeout, "vsock stream read requested");
                let response = stream
                    .0
                    .read(id, max_bytes as usize, timeout)
                    .await
                    .map_err(convert_error::<Bindings>);
                match &response {
                    Ok(Some(bytes)) => {
                        tracing::debug!(len = bytes.len(), "vsock stream read returned");
                    }
                    Ok(None) => tracing::debug!("vsock stream read reached end of file"),
                    Err(_) => tracing::debug!("vsock stream read failed"),
                }
                Ok::<_, wasmtime::Error>((response,))
            })
        },
    )?;
    instance.func_wrap_concurrent(
        "[method]vsock-stream.write",
        |accessor: &Accessor<StoreData<CpuImpl, Net, StorageImpl>>,
         (resource, bytes, timeout): (Resource<ComponentVsockStream>, Vec<u8>, u64)| {
            Box::pin(async move {
                let stream = accessor.with(|mut access| {
                    let stream = access.get().table.get(&resource)?;
                    Ok::<_, wasmtime::Error>((stream.service.clone(), stream.stream))
                })?;
                let Some(id) = stream.1 else {
                    return Ok::<_, wasmtime::Error>((Err(convert_error::<Bindings>(
                        VsockError::Closed,
                    )),));
                };
                tracing::debug!(len = bytes.len(), timeout, "vsock stream write requested");
                let response = stream
                    .0
                    .write(id, &bytes, timeout)
                    .await
                    .map(|written| written as u64)
                    .map_err(convert_error::<Bindings>);
                tracing::debug!(
                    written = response.as_ref().ok().copied(),
                    "vsock stream write returned"
                );
                Ok::<_, wasmtime::Error>((response,))
            })
        },
    )?;
    instance.func_wrap_concurrent(
        "[method]vsock-stream.shutdown-send",
        |accessor: &Accessor<StoreData<CpuImpl, Net, StorageImpl>>,
         (resource,): (Resource<ComponentVsockStream>,)| {
            Box::pin(async move {
                let stream = accessor.with(|mut access| {
                    let stream = access.get().table.get(&resource)?;
                    Ok::<_, wasmtime::Error>((stream.service.clone(), stream.stream))
                })?;
                let Some(id) = stream.1 else {
                    return Ok::<_, wasmtime::Error>((Err(convert_error::<Bindings>(
                        VsockError::Closed,
                    )),));
                };
                let response = stream
                    .0
                    .shutdown(
                        id,
                        VsockShutdown {
                            receive: false,
                            send: true,
                        },
                    )
                    .await
                    .map_err(convert_error::<Bindings>);
                Ok::<_, wasmtime::Error>((response,))
            })
        },
    )?;
    instance.func_wrap_concurrent(
        "[method]vsock-stream.close",
        |accessor: &Accessor<StoreData<CpuImpl, Net, StorageImpl>>,
         (resource,): (Resource<ComponentVsockStream>,)| {
            Box::pin(async move {
                let stream = accessor.with(|mut access| {
                    let stream = access.get().table.get_mut(&resource)?;
                    Ok::<_, wasmtime::Error>(stream.take())
                })?;
                let Some((service, id)) = stream else {
                    return Ok::<_, wasmtime::Error>((Err(convert_error::<Bindings>(
                        VsockError::Closed,
                    )),));
                };
                let response = service.close(id).await.map_err(convert_error::<Bindings>);
                Ok::<_, wasmtime::Error>((response,))
            })
        },
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{ProgramVsock, authorise, program_bindings};
    use crate::wasmtime_adapter::component_host::service::test_store::store_data_authorized;
    use crate::{MachineAuthorityRights, ProcessAuthority, TerminalAuthorityRights};

    #[test]
    fn vsock_denies_root_and_terminal_authorities_and_requires_machine_control() {
        let root_store = store_data_authorized(ProcessAuthority::root(), |_| {});
        assert!(matches!(
            authorise::<ProgramVsock, _, _, _>(&root_store),
            Err(program_bindings::helios::system::vsock::VsockError {
                kind: program_bindings::helios::system::vsock::VsockErrorKind::PermissionDenied,
                ..
            })
        ));

        let mut terminal_only = ProcessAuthority::empty();
        terminal_only.grant_terminal_rights(TerminalAuthorityRights::all());
        let terminal_store = store_data_authorized(terminal_only, |_| {});
        assert!(matches!(
            authorise::<ProgramVsock, _, _, _>(&terminal_store),
            Err(program_bindings::helios::system::vsock::VsockError {
                kind: program_bindings::helios::system::vsock::VsockErrorKind::PermissionDenied,
                ..
            })
        ));

        let mut machine_control = ProcessAuthority::empty();
        machine_control.grant_machine_rights(MachineAuthorityRights::CONTROL);
        let control_store = store_data_authorized(machine_control, |_| {});
        assert!(matches!(
            authorise::<ProgramVsock, _, _, _>(&control_store),
            Err(program_bindings::helios::system::vsock::VsockError {
                kind: program_bindings::helios::system::vsock::VsockErrorKind::Unavailable,
                ..
            })
        ));
    }
}
