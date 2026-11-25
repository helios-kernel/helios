use alloc::string::String;
use alloc::vec::Vec;

use crate::{
    ComponentNetworkService, RawMutexGuardResource, RawMutexResource, RawRwLockReadGuardResource,
    RawRwLockResource, RawRwLockWriteGuardResource, SerialPortResource, TcpStreamResource,
    UdpSocketResource,
};

pub struct ComponentSerialPort {
    pub can_read: bool,
    pub can_write: bool,
    pub _resource: SerialPortResource,
}

/// Active instruction-sampling lease held in a component's resource table.
/// Dropping the handle (by guest drop or store teardown) stops sampling.
pub struct ComponentSamplingSession(pub crate::SamplingSession);

/// Active snapshot-hold lease held in a component's resource table.
///
/// Explicit guest drop calls [`Self::release_now`] and releases the runtime
/// state's hold immediately; an unclosed handle dropped during store teardown
/// marks [`crate::SnapshotRetirementSender`], which [`crate::StoreSocketRetirement`]
/// drains right after the resource table drops.
pub struct ComponentSnapshotHold {
    token: u64,
    has_generation_id: bool,
    retirement: crate::SnapshotRetirementSender,
    released: bool,
}

impl ComponentSnapshotHold {
    pub fn new(
        token: u64,
        has_generation_id: bool,
        retirement: crate::SnapshotRetirementSender,
    ) -> Self {
        Self {
            token,
            has_generation_id,
            retirement,
            released: false,
        }
    }

    pub const fn has_generation_id(&self) -> bool {
        self.has_generation_id
    }

    pub fn release_now(&mut self) -> Option<u64> {
        if self.released {
            return None;
        }
        self.released = true;
        Some(self.token)
    }
}

impl Drop for ComponentSnapshotHold {
    fn drop(&mut self) {
        if !self.released {
            self.released = true;
            self.retirement.mark_released(self.token);
        }
    }
}

pub struct ComponentTcpStream<Backend> {
    pub resource: TcpStreamResource<Backend>,
}

impl<Backend> ComponentTcpStream<Backend> {
    pub fn new(backend: Backend) -> Self {
        Self {
            resource: TcpStreamResource::new(backend),
        }
    }
}

pub struct ComponentUdpSocket<Backend> {
    pub resource: UdpSocketResource<Backend>,
}

impl<Backend> ComponentUdpSocket<Backend> {
    pub fn new(backend: Backend) -> Self {
        Self {
            resource: UdpSocketResource::new(backend),
        }
    }
}

/// The kernel stream a `helios:system/net` `tcp-stream` resource owns.
///
/// The stream is retired when this backend is dropped, whichever way
/// the resource's life ends: the guest dropping the handle, the store
/// being torn down with the handle still open, or a launch unwinding.
/// Deferring the close to a task the guest's own destructor spawns
/// loses it whenever the instance goes away first, which is how a
/// connection outlived the program that opened it in #184.
pub struct ComponentTcpBackend<Service>
where
    Service: ComponentNetworkService,
{
    pub service: Service,
    stream: Option<Service::TcpStream>,
}

impl<Service> ComponentTcpBackend<Service>
where
    Service: ComponentNetworkService,
{
    pub fn new(service: Service, stream: Service::TcpStream) -> Self {
        Self {
            service,
            stream: Some(stream),
        }
    }

    /// The stream this resource still owns, or `None` once `close` has
    /// retired it.
    pub fn stream(&self) -> Option<Service::TcpStream> {
        self.stream
    }

    /// Retires the stream now. A second call, and the drop that follows
    /// it, do nothing: a handle is retired exactly once, because its
    /// slab slot is reused by the next connection.
    pub fn close(&mut self) {
        if let Some(stream) = self.stream.take() {
            self.service.tcp_close(stream);
        }
    }
}

impl<Service> Drop for ComponentTcpBackend<Service>
where
    Service: ComponentNetworkService,
{
    fn drop(&mut self) {
        self.close();
    }
}

/// The kernel socket a `helios:system/net` `udp-socket` resource owns.
///
/// The same rule as [`ComponentTcpBackend`], for the same reason: the
/// socket is retired when this backend is dropped, whichever way the
/// resource's life ends. A datagram socket is replicated on every
/// shard and holds a slot in `udp_slots`, so one left behind by a
/// program that exited costs every shard, which is what #190 saw.
pub struct ComponentUdpBackend<Service>
where
    Service: ComponentNetworkService,
{
    pub service: Service,
    socket: Option<Service::UdpSocket>,
}

impl<Service> ComponentUdpBackend<Service>
where
    Service: ComponentNetworkService,
{
    pub fn new(service: Service, socket: Service::UdpSocket) -> Self {
        Self {
            service,
            socket: Some(socket),
        }
    }

    /// The socket this resource still owns, or `None` once `close` has
    /// retired it.
    pub fn socket(&self) -> Option<Service::UdpSocket> {
        self.socket
    }

    /// Retires the socket now. A second call, and the drop that follows
    /// it, do nothing: a handle is retired exactly once, because its
    /// slab slot is reused by the next bind.
    pub fn close(&mut self) {
        if let Some(socket) = self.socket.take() {
            self.service.udp_close(socket);
        }
    }
}

impl<Service> Drop for ComponentUdpBackend<Service>
where
    Service: ComponentNetworkService,
{
    fn drop(&mut self) {
        self.close();
    }
}

pub struct ComponentRawMutex {
    pub resource: RawMutexResource,
}

pub struct ComponentRawMutexGuard {
    pub _resource: RawMutexGuardResource,
}

pub struct ComponentRawRwLock {
    pub resource: RawRwLockResource,
}

pub struct ComponentRawRwLockReadGuard {
    pub _resource: RawRwLockReadGuardResource,
}

pub struct ComponentRawRwLockWriteGuard {
    pub _resource: RawRwLockWriteGuardResource,
}

/// Concrete TCP listener resource for `helios:system/net.tcp-listener`.
///
/// Non-generic so `bindgen!` maps `helios:system/net.tcp-listener` directly to
/// it across both component worlds; retires the underlying listener handle via
/// [`crate::SocketRetirementSender`] on drop unless disarmed for hand-off.
pub struct ComponentTcpListener {
    raw: Option<u64>,
    local_address: crate::NetworkIpAddress,
    local_port: u16,
    hop_limit: u8,
    retire: crate::SocketRetirementSender,
}

impl ComponentTcpListener {
    pub fn new(
        raw: u64,
        local_address: crate::NetworkIpAddress,
        local_port: u16,
        hop_limit: u8,
        retire: crate::SocketRetirementSender,
    ) -> Self {
        Self {
            raw: Some(raw),
            local_address,
            local_port,
            hop_limit,
            retire,
        }
    }

    pub const fn raw(&self) -> Option<u64> {
        self.raw
    }

    pub const fn local_address(&self) -> crate::NetworkIpAddress {
        self.local_address
    }

    pub const fn local_port(&self) -> u16 {
        self.local_port
    }

    pub const fn hop_limit(&self) -> u8 {
        self.hop_limit
    }

    pub fn retirement(&self) -> crate::SocketRetirementSender {
        self.retire.clone()
    }

    /// Disarms retirement and moves the underlying raw listener handle out.
    pub fn take_raw(&mut self) -> Option<u64> {
        self.raw.take()
    }

    /// Retires the listener immediately if still open.
    pub fn close(&mut self) {
        if let Some(raw) = self.raw.take() {
            self.retire
                .push(crate::RetiredNetworkHandle::TcpListener(raw));
        }
    }
}

impl Drop for ComponentTcpListener {
    fn drop(&mut self) {
        self.close();
    }
}

/// Pre-bound listening socket transferred to a spawned child at launch.
///
/// Retires the listener on drop if unclaimed or if the launch fails before the
/// child adopts ownership.
pub enum InheritedSocket {
    Tcp {
        raw: Option<u64>,
        local_address: crate::NetworkIpAddress,
        local_port: u16,
        hop_limit: u8,
        retire: crate::SocketRetirementSender,
    },
    Vsock {
        service: crate::ComponentHostVsockService,
        listener: Option<crate::VsockListenerId>,
    },
}

impl InheritedSocket {
    pub fn from_tcp_listener(listener: &mut ComponentTcpListener) -> Option<Self> {
        let raw = listener.take_raw()?;
        Some(Self::Tcp {
            raw: Some(raw),
            local_address: listener.local_address(),
            local_port: listener.local_port(),
            hop_limit: listener.hop_limit(),
            retire: listener.retirement(),
        })
    }

    pub fn from_vsock_listener(
        service: crate::ComponentHostVsockService,
        listener: crate::VsockListenerId,
    ) -> Self {
        Self::Vsock {
            service,
            listener: Some(listener),
        }
    }

    pub fn rebind_retirement(&mut self, new_retire: crate::SocketRetirementSender) {
        if let Self::Tcp { retire, .. } = self {
            *retire = new_retire;
        }
    }

    pub fn take_tcp(&mut self) -> Option<(u64, crate::NetworkIpAddress, u16, u8)> {
        match self {
            Self::Tcp {
                raw,
                local_address,
                local_port,
                hop_limit,
                ..
            } => raw
                .take()
                .map(|id| (id, *local_address, *local_port, *hop_limit)),
            Self::Vsock { .. } => None,
        }
    }

    pub fn take_vsock(
        &mut self,
    ) -> Option<(crate::ComponentHostVsockService, crate::VsockListenerId)> {
        match self {
            Self::Vsock { service, listener } => listener.take().map(|id| (service.clone(), id)),
            Self::Tcp { .. } => None,
        }
    }
}

impl Drop for InheritedSocket {
    fn drop(&mut self) {
        match self {
            Self::Tcp { raw, retire, .. } => {
                if let Some(id) = raw.take() {
                    retire.push(crate::RetiredNetworkHandle::TcpListener(id));
                }
            }
            Self::Vsock { service, listener } => {
                if let Some(id) = listener.take() {
                    let _ = service.close_listener(id);
                }
            }
        }
    }
}

/// Ordered list of pre-bound listening sockets handed to a newly spawned child.
///
/// Claimed at most once (installed at `fd = 3+` for POSIX-descriptor processes,
/// or returned to component guests via `take-inherited-sockets`).
#[derive(Default)]
pub struct InheritedSockets {
    entries: spin::Mutex<Vec<InheritedSocket>>,
}

impl InheritedSockets {
    pub const fn new() -> Self {
        Self {
            entries: spin::Mutex::new(Vec::new()),
        }
    }

    pub fn from_vec(sockets: Vec<InheritedSocket>) -> Self {
        Self {
            entries: spin::Mutex::new(sockets),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.entries.lock().is_empty()
    }

    pub fn len(&self) -> usize {
        self.entries.lock().len()
    }

    pub fn rebind_retirement(&self, retire: crate::SocketRetirementSender) {
        for socket in self.entries.lock().iter_mut() {
            socket.rebind_retirement(retire.clone());
        }
    }

    pub fn take_all(&self) -> Vec<InheritedSocket> {
        core::mem::take(&mut *self.entries.lock())
    }
}

/// Default Linux credentials carried by an instance's [`DefaultLinuxImage`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DefaultLinuxCredentials {
    pub uid: u32,
    pub gid: u32,
    pub supplementary_groups: Vec<u32>,
}

/// Per-instance pinned read-only Linux root image inherited across child
/// `spawn` and `exec` launches.
pub struct DefaultLinuxImage<S: crate::Storage> {
    pub root_path: String,
    pub lower: crate::HeldPath<S>,
    pub env: Vec<(String, String)>,
    pub credentials: Option<DefaultLinuxCredentials>,
}

impl<S: crate::Storage> Clone for DefaultLinuxImage<S> {
    fn clone(&self) -> Self {
        Self {
            root_path: self.root_path.clone(),
            lower: self.lower.clone(),
            env: self.env.clone(),
            credentials: self.credentials.clone(),
        }
    }
}

#[cfg(all(test, feature = "wasmtime-runtime"))]
mod tests {
    use super::{ComponentTcpBackend, ComponentUdpBackend};
    use crate::test_support::TestNetworkService;

    /// A `helios:system/net` stream resource retires its kernel stream
    /// when it is dropped.
    ///
    /// The resource destructor the component model runs fires only when
    /// the *guest* drops the handle; a store torn down with the handle
    /// still open runs nothing. Closing from the destructor alone
    /// therefore left the connection behind whenever the instance went
    /// first, which is what #184 saw.
    #[test]
    fn a_system_net_stream_retires_itself_when_its_resource_is_dropped() {
        let service = TestNetworkService::new();
        let closed = service.closed();
        let backend = ComponentTcpBackend::new(service, 5);

        assert_eq!(backend.stream(), Some(5));
        assert_eq!(closed.count(), 0);
        drop(backend);
        assert_eq!(closed.count(), 1, "the backend owns the stream it holds");
        assert_eq!(closed.last(), 5);
    }

    /// `tcp-stream.close` retires the stream once, and the drop that
    /// follows it does nothing: the slab slot a retired handle frees is
    /// handed to the next connection, so a second close would retire
    /// somebody else's stream.
    #[test]
    fn a_closed_system_net_stream_is_not_retired_a_second_time() {
        let service = TestNetworkService::new();
        let closed = service.closed();
        let mut backend = ComponentTcpBackend::new(service, 5);

        backend.close();
        assert_eq!(closed.count(), 1);
        assert_eq!(
            backend.stream(),
            None,
            "a closed stream is gone from the resource"
        );
        backend.close();
        drop(backend);
        assert_eq!(closed.count(), 1, "a stream is retired exactly once");
    }

    /// A `helios:system/net` datagram-socket resource retires its
    /// kernel socket when it is dropped.
    ///
    /// `udp-socket`'s destructor is reached only when the *guest* drops
    /// the handle; a store torn down with the handle still open runs
    /// nothing. Closing from the destructor alone therefore left the
    /// socket bound on every shard, and its slot in `udp_slots` taken,
    /// for the rest of the boot (#190).
    #[test]
    fn a_system_net_udp_socket_retires_itself_when_its_resource_is_dropped() {
        let service = TestNetworkService::new();
        let closed = service.closed_udp_sockets();
        let backend = ComponentUdpBackend::new(service, 9);

        assert_eq!(backend.socket(), Some(9));
        assert_eq!(closed.count(), 0);
        drop(backend);
        assert_eq!(closed.count(), 1, "the backend owns the socket it holds");
        assert_eq!(closed.last(), 9);
    }

    /// `udp-socket.close` retires the socket once, and the drop that
    /// follows it does nothing: the slab slot a retired handle frees is
    /// handed to the next bind, so a second close would retire somebody
    /// else's socket.
    #[test]
    fn a_closed_system_net_udp_socket_is_not_retired_a_second_time() {
        let service = TestNetworkService::new();
        let closed = service.closed_udp_sockets();
        let mut backend = ComponentUdpBackend::new(service, 9);

        backend.close();
        assert_eq!(closed.count(), 1);
        assert_eq!(
            backend.socket(),
            None,
            "a closed socket is gone from the resource"
        );
        backend.close();
        drop(backend);
        assert_eq!(closed.count(), 1, "a socket is retired exactly once");
    }
}
