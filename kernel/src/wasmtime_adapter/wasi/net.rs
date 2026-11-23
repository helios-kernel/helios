use core::convert::Infallible;
use core::task::Waker;
use pin_project_lite::pin_project;

use wasmtime::AsContextMut;

use crate::{ComponentHostNetwork, NetworkHandle, RetiredNetworkHandle, SocketRetirementSender};

use super::*;

pub(crate) fn has_wasi_network_rights(
    authority: &crate::ProcessAuthority,
    rights: crate::NetworkAuthorityRights,
) -> bool {
    authority.network_rights().contains(rights)
}

pub(crate) fn wasi_udp_bind_rights(local_port: u16) -> crate::NetworkAuthorityRights {
    crate::NetworkAuthorityRights::UDP.bind_rights(local_port)
}

pub(crate) fn wasi_tcp_bind_rights(local_port: u16) -> crate::NetworkAuthorityRights {
    crate::NetworkAuthorityRights::TCP.bind_rights(local_port)
}

/// A kernel network handle a `wasi:sockets` socket owns: dropping it
/// queues the handle's close.
///
/// `wasi:sockets` hands the guest a resource, and the guest is free to
/// exit while still holding it: a component's resource destructors run
/// when the *guest* drops a handle, and never when the store around it
/// is torn down. Retiring a stream from a task spawned by the
/// destructor loses it in exactly that case, and lost it in #184 — a
/// connection stayed in its shard, holding its receive queue and its
/// slab slot, after the program that opened it had exited. Ownership
/// lives on the handle instead: whatever ends this value's life ends
/// the kernel handle's, with nothing to schedule and nothing to await.
///
/// Every kernel handle a socket can come to hold is one of these from
/// the moment the network service returns it: the connected stream
/// (#184), the listener (#191), a connection a background accept
/// produced before anyone adopted it (#225), a datagram socket (#190)
/// and its unfinished bind. A background task whose socket died in
/// the meantime cannot deliver its answer, and dropping the answer
/// retires what it carried.
///
/// The close happens on the store, not here. A socket cannot hold the
/// network service: it is a `wasi:sockets` resource type, so it reaches
/// `bindgen!` through `with:` as a plain path and cannot carry the
/// service's type parameter. The id goes to the store's retirement
/// queue, and the store closes it on its next turn — the entry to the
/// next `wasi:sockets` host call at the latest, and its own teardown if
/// there is no next call.
pub(super) struct OwnedNetworkHandle {
    handle: RetiredNetworkHandle,
    retire: SocketRetirementSender,
}

impl OwnedNetworkHandle {
    pub(super) fn new(retire: SocketRetirementSender, handle: RetiredNetworkHandle) -> Self {
        Self { handle, retire }
    }

    /// The network service's id for the handle.
    pub(super) fn raw(&self) -> u64 {
        match self.handle {
            RetiredNetworkHandle::TcpStream(raw)
            | RetiredNetworkHandle::TcpListener(raw)
            | RetiredNetworkHandle::UdpSocket(raw) => raw,
        }
    }
}

impl Drop for OwnedNetworkHandle {
    fn drop(&mut self) {
        self.retire.push(self.handle);
    }
}

/// One connected TCP stream: the part of a socket that outlives a
/// borrow of it.
///
/// # Ownership and concurrency
///
/// The socket holds one reference, and the `send` and `receive`
/// streams over the connection each hold another: the guest may keep
/// using them after it dropped the socket resource. The kernel stream
/// is retired when the last reference goes. Nothing in it changes after
/// construction.
pub(super) struct TcpConnection {
    stream: OwnedNetworkHandle,
}

impl TcpConnection {
    pub(super) fn new(retire: SocketRetirementSender, stream: u64) -> Self {
        Self {
            stream: OwnedNetworkHandle::new(retire, RetiredNetworkHandle::TcpStream(stream)),
        }
    }

    pub(super) fn stream(&self) -> u64 {
        self.stream.raw()
    }
}

/// A TCP listener a socket opened.
///
/// Shared by the socket, the task running each accept on it, and the
/// p3 listen stream; it is retired when the last of them goes. Nothing
/// in it changes after construction.
pub(super) struct OwnedTcpListener {
    listener: OwnedNetworkHandle,
    pub(super) local_port: u16,
}

impl OwnedTcpListener {
    pub(super) fn new(retire: SocketRetirementSender, listener: crate::TcpListener<u64>) -> Self {
        Self {
            listener: OwnedNetworkHandle::new(
                retire,
                RetiredNetworkHandle::TcpListener(listener.listener),
            ),
            local_port: listener.local_port,
        }
    }

    pub(super) fn raw(&self) -> u64 {
        self.listener.raw()
    }
}

/// What one completed accept hands back: a connection that already
/// owns its stream, and the addresses the socket made from it reports.
///
/// The accept runs on a detached task, so what the network service
/// returns has to belong to somebody the moment it exists. While the
/// answer was a bare stream id, nothing owned the connection between
/// the task storing it and the accept path adopting it, and a socket
/// that died in that window left it in its shard for the rest of the
/// boot (#225).
pub(super) struct AcceptedConnection {
    pub(super) connection: TcpConnection,
    pub(super) local_address: WasiTcpSocketAddress,
    pub(super) remote_address: WasiTcpSocketAddress,
}

impl AcceptedConnection {
    pub(super) fn new<Stream: NetworkHandle>(
        retire: SocketRetirementSender,
        family: WasiTcpSocketFamily,
        local_address: WasiTcpSocketAddress,
        accepted: crate::TcpAccepted<Stream>,
    ) -> Self {
        let remote_address = match accepted.address {
            crate::NetworkIpAddress::Ipv4(address) => WasiTcpIpAddress::Ipv4(address),
            crate::NetworkIpAddress::Ipv6(address) => WasiTcpIpAddress::Ipv6(address),
        };
        assert_eq!(
            remote_address.family(),
            family,
            "tcp accept returned a peer address for the wrong socket family"
        );
        Self {
            connection: TcpConnection::new(retire, accepted.stream.into_raw()),
            local_address,
            remote_address: WasiTcpSocketAddress {
                address: remote_address,
                port: accepted.port,
            },
        }
    }
}

/// A background task's answer, as the side that waits for it holds it.
pub(super) type TcpAnswer<T> = oneshot::Receiver<core::result::Result<T, crate::TcpError>>;

/// Takes a background task's answer once it has arrived.
///
/// Every task owns the only sender of its answer and sends before it
/// ends, so a cancelled channel means the executor dropped the task
/// unanswered, which happens only while the instance is being torn
/// down around the socket.
fn poll_answer<T>(
    answer: &mut TcpAnswer<T>,
    cx: &mut Context<'_>,
    task: &'static str,
) -> Poll<core::result::Result<T, crate::TcpError>> {
    Pin::new(answer).poll(cx).map(|answer| {
        answer.unwrap_or_else(|oneshot::Canceled| {
            debug_assert!(false, "a tcp {task} task ended without answering");
            tracing::error!(
                target: "helios_kernel::program",
                task,
                "a tcp task ended without answering its socket"
            );
            Err(crate::TcpError {
                kind: crate::TcpErrorKind::Internal,
                detail: crate::NetworkErrorDetail::InternalInvariant,
            })
        })
    })
}

/// An operation that runs without holding the socket whose state it
/// changes.
///
/// A p3 host call yields the store while it awaits, so it gives the
/// socket back and cannot leave a mark in it that its own drop would
/// clear. The marker is the receiving end of a channel nothing ever
/// sends on: it reads as live while the operation's future holds the
/// [`InFlightGuard`], and the guard's drop — the operation finishing,
/// or its future being cancelled — ends it. A cancelled call therefore
/// never leaves the socket stuck in a state no one will finish.
pub(super) struct InFlight(oneshot::Receiver<Infallible>);

/// The operation's end of an [`InFlight`] marker.
pub(super) struct InFlightGuard {
    _sender: oneshot::Sender<Infallible>,
}

impl InFlight {
    pub(super) fn start() -> (Self, InFlightGuard) {
        let (sender, receiver) = oneshot::channel();
        (Self(receiver), InFlightGuard { _sender: sender })
    }

    /// Whether the operation's future still holds its guard.
    fn is_live(&mut self) -> bool {
        matches!(self.0.try_recv(), Ok(None))
    }
}

/// Whether a marker slot holds a live operation.
fn in_flight(marker: &mut Option<InFlight>) -> bool {
    marker.as_mut().is_some_and(InFlight::is_live)
}

/// A `wasi:sockets` TCP socket.
///
/// # Ownership and concurrency
///
/// The socket has one owner, its resource-table entry; nothing clones
/// it and nothing locks it. A host call borrows it from the table for
/// a synchronous stretch. A call that awaits yields the store, so it
/// gives the socket back first and fetches it again to apply what the
/// await produced.
///
/// What has to outlive a borrow is split off into objects of its own
/// that hold no lock: the [`TcpConnection`] the streams share and the
/// [`OwnedTcpListener`] the accept tasks and the listen stream share.
///
/// A listen runs on a detached task that hands its answer back through
/// a oneshot the socket keeps (`pending_listen`). Every accessor that
/// reads state that answer changes settles it first, on the calling
/// task. The listen stream keeps its own accept answers.
pub struct TcpSocket {
    /// Where the handles this socket comes to own go when they die.
    pub(super) retire: SocketRetirementSender,
    pub(super) family: WasiTcpSocketFamily,
    pub(super) connection: Option<Arc<TcpConnection>>,
    pub(super) listener: Option<Arc<OwnedTcpListener>>,
    pub(super) local_address: Option<WasiTcpSocketAddress>,
    pub(super) remote_address: Option<WasiTcpSocketAddress>,
    /// A p3 `connect` under way.
    pub(super) p3_connect: Option<InFlight>,
    /// A `listen`'s answer, which the socket takes in on arrival; the
    /// listen stream, which has its own copy of the answer, reports a
    /// failure.
    pub(super) pending_listen: Option<TcpAnswer<Arc<OwnedTcpListener>>>,
    pub(super) listen_backlog: u16,
    pub(super) keep_alive_enabled: bool,
    pub(super) keep_alive_idle_time: u64,
    pub(super) keep_alive_interval: u64,
    pub(super) keep_alive_count: u32,
    pub(super) hop_limit: u8,
    pub(super) receive_buffer_size: u64,
    pub(super) send_buffer_size: u64,
}

/// A p3 `connect` the socket admitted, carried across the await that
/// runs it.
pub(super) struct P3Connect {
    guard: InFlightGuard,
    retire: SocketRetirementSender,
    local_port: u16,
    hop_limit: u8,
}

impl P3Connect {
    /// Runs the connect with the socket released. The guard comes back
    /// for [`TcpSocket::finish_p3_connect`].
    pub(super) async fn run<Net: ComponentHostNetwork>(
        self,
        service: &Net,
        remote_address: WasiTcpSocketAddress,
    ) -> (
        InFlightGuard,
        core::result::Result<TcpConnection, socket_types::ErrorCode>,
    ) {
        let Self {
            guard,
            retire,
            local_port,
            hop_limit,
        } = self;
        let outcome = service
            .tcp_connect_address(
                remote_address.address.network_address(),
                remote_address.port,
                local_port,
                hop_limit,
                u64::MAX,
            )
            .await
            .map(|stream| TcpConnection::new(retire, stream.into_raw()))
            .map_err(map_p3_tcp_error);
        (guard, outcome)
    }
}

/// Runs one accept on a detached task and answers through the returned
/// receiver.
///
/// The task holds the listener, so the listener stays open until the
/// accept has answered, and it builds the [`AcceptedConnection`]
/// itself: the answer owns its stream whether the receiver adopts it
/// or has gone (#225).
///
/// The service comes from the host call that starts the accept, not
/// from the socket: a socket resource holds none. The task therefore
/// carries a clone of the concrete service and calls it directly, with
/// no erased handle anywhere on the path.
pub(super) fn spawn_accept<CpuImpl, Net>(
    spawner: &crate::InstanceSpawner<CpuImpl>,
    service: Net,
    retire: SocketRetirementSender,
    listener: Arc<OwnedTcpListener>,
    family: WasiTcpSocketFamily,
    local_address: WasiTcpSocketAddress,
) -> core::result::Result<TcpAnswer<AcceptedConnection>, crate::TaskCapacityError>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
{
    let (answer, receiver) = oneshot::channel();
    let spawned = spawner.try_spawn_detached(async move {
        let accepted = service
            .tcp_accept(NetworkHandle::from_raw(listener.raw()), u64::MAX)
            .await
            .map(|accepted| AcceptedConnection::new(retire, family, local_address, accepted));
        // A receiver that has gone drops the connection, which retires
        // it.
        let _ = answer.send(accepted);
        drop(listener);
    });
    if let Err(error) = spawned {
        tracing::warn!(
            target: "helios_kernel::program",
            %error,
            "refused a tcp accept task: the executor's instance share is full"
        );
        return Err(error);
    }
    Ok(receiver)
}

/// What a listen task opens a listener with.
#[derive(Clone, Copy, Debug)]
pub(super) struct ListenRequest {
    pub(super) local_address: WasiTcpSocketAddress,
    pub(super) backlog: u16,
    pub(super) hop_limit: u8,
}

/// Opens a listener on a detached task and answers through the
/// returned receiver, and through `stream` as well: the listen stream
/// waits for the same listener.
pub(super) fn spawn_listen<CpuImpl, Net>(
    spawner: &crate::InstanceSpawner<CpuImpl>,
    service: Net,
    retire: SocketRetirementSender,
    request: ListenRequest,
    stream: oneshot::Sender<core::result::Result<Arc<OwnedTcpListener>, crate::TcpError>>,
) -> core::result::Result<TcpAnswer<Arc<OwnedTcpListener>>, crate::TaskCapacityError>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
{
    let (answer, receiver) = oneshot::channel();
    let spawned = spawner.try_spawn_detached(async move {
        let result = service
            .tcp_listen(
                request.local_address.address.network_address(),
                request.local_address.port,
                request.backlog,
                request.hop_limit,
            )
            .await
            .map(|listener| {
                Arc::new(OwnedTcpListener::new(
                    retire,
                    crate::TcpListener {
                        listener: listener.listener.into_raw(),
                        local_port: listener.local_port,
                    },
                ))
            });
        let _ = stream.send(result.clone());
        let _ = answer.send(result);
    });
    if let Err(error) = spawned {
        tracing::warn!(
            target: "helios_kernel::program",
            %error,
            "refused a tcp listen task: the executor's instance share is full"
        );
        return Err(error);
    }
    Ok(receiver)
}

/// One read on a connection, as a future the producer can own by
/// value.
///
/// A free `async fn` rather than a method so its future has a type the
/// producer can name through a `Fut` parameter: everything it needs is
/// owned, so the future borrows nothing and outlives any one poll.
/// `None` is a socket that had no connection when `receive` was
/// called.
pub(super) async fn read_socket<Net: ComponentHostNetwork>(
    connection: Option<Arc<TcpConnection>>,
    service: Net,
    max_bytes: u32,
) -> TcpReadResult {
    let Some(connection) = connection else {
        return Err(socket_types::ErrorCode::InvalidState);
    };
    service
        .tcp_read(
            NetworkHandle::from_raw(connection.stream()),
            max_bytes,
            u64::MAX,
        )
        .await
        .map_err(map_p3_tcp_error)
}

/// One write on a connection, as a future the consumer can own by
/// value.
pub(super) async fn write_socket<Net: ComponentHostNetwork>(
    connection: Option<Arc<TcpConnection>>,
    service: Net,
    bytes: Bytes,
) -> TcpWriteResult {
    if bytes.is_empty() {
        return Ok(());
    }
    let Some(connection) = connection else {
        return Err(socket_types::ErrorCode::InvalidState);
    };
    service
        .tcp_write_all_bytes(
            NetworkHandle::from_raw(connection.stream()),
            bytes,
            u64::MAX,
        )
        .await
        .map_err(map_p3_tcp_error)
}

pin_project! {
    /// The `wasi:sockets` `receive` stream, reading through the
    /// machine's own network service.
    ///
    /// The in-flight read is held by value under a `Fut` parameter that
    /// [`tcp_read_producer`] infers from [`read_socket`], and `start`
    /// is the function pointer that mints the next one. A boxed
    /// `dyn Future` here would erase the service the whole component
    /// host is generic over for the sake of one field.
    pub(super) struct TcpReadStreamProducer<Net, Fut>
    where
        Net: ComponentHostNetwork,
    {
        pub(super) connection: Option<Arc<TcpConnection>>,
        pub(super) service: Net,
        pub(super) start: fn(Option<Arc<TcpConnection>>, Net, u32) -> Fut,
        #[pin]
        pub(super) pending: Option<Fut>,
        pub(super) completion:
            Option<oneshot::Sender<core::result::Result<(), socket_types::ErrorCode>>>,
    }

    impl<Net, Fut> PinnedDrop for TcpReadStreamProducer<Net, Fut>
    where
        Net: ComponentHostNetwork,
    {
        fn drop(this: Pin<&mut Self>) {
            complete_socket_transfer(this.project().completion, Ok(()));
        }
    }
}

pin_project! {
    /// The `wasi:sockets` `send` stream, writing through the machine's
    /// own network service. The mirror of [`TcpReadStreamProducer`].
    pub(super) struct TcpWriteConsumer<Net, Fut>
    where
        Net: ComponentHostNetwork,
    {
        pub(super) connection: Option<Arc<TcpConnection>>,
        pub(super) service: Net,
        pub(super) start: fn(Option<Arc<TcpConnection>>, Net, Bytes) -> Fut,
        #[pin]
        pub(super) pending: Option<Fut>,
        pub(super) completion:
            Option<oneshot::Sender<core::result::Result<(), socket_types::ErrorCode>>>,
    }

    impl<Net, Fut> PinnedDrop for TcpWriteConsumer<Net, Fut>
    where
        Net: ComponentHostNetwork,
    {
        fn drop(this: Pin<&mut Self>) {
            complete_socket_transfer(this.project().completion, Ok(()));
        }
    }
}

/// Answers the `future<result>` a `send` or `receive` handed the guest,
/// once. A dropped receiver means the guest stopped caring, which is
/// not this side's problem.
fn complete_socket_transfer(
    completion: &mut Option<oneshot::Sender<core::result::Result<(), socket_types::ErrorCode>>>,
    result: core::result::Result<(), socket_types::ErrorCode>,
) {
    if let Some(sender) = completion.take() {
        let _ = sender.send(result);
    }
}

/// The p3 `listen` stream.
///
/// # Ownership and concurrency
///
/// The stream holds no socket. It waits for the listener on its own
/// copy of the listen task's answer, shares the [`OwnedTcpListener`]
/// with the socket once it has arrived, and keeps each accept's answer
/// itself, so it goes on accepting after the guest dropped the socket
/// resource, and its accept dies with it when the guest drops the
/// stream. Everything it reads from the socket was copied when the
/// listen began; the socket cannot be rebound while it listens.
pub(super) struct TcpListenStreamProducer<T, CpuImpl, Net, StorageImpl>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    /// The service every accept this stream starts runs on, taken from
    /// the store when the listen began.
    pub(super) service: Net,
    pub(super) get_store_data:
        for<'a> fn(&'a mut T) -> &'a mut StoreData<CpuImpl, Net, StorageImpl>,
    pub(super) spawner: crate::InstanceSpawner<CpuImpl>,
    /// Where the accepted sockets' handles go when they die.
    pub(super) retire: SocketRetirementSender,
    pub(super) family: WasiTcpSocketFamily,
    /// The socket's own address when the listen began, if it was bound.
    pub(super) bound_address: Option<WasiTcpSocketAddress>,
    pub(super) listen: P3ListenState,
    pub(super) accept: Option<TcpAnswer<AcceptedConnection>>,
}

/// Where a p3 listen stream's listener is.
pub(super) enum P3ListenState {
    /// The listen task has not answered.
    Opening(TcpAnswer<Arc<OwnedTcpListener>>),
    Listening {
        listener: Arc<OwnedTcpListener>,
        /// The address every accepted socket reports as its own.
        local_address: WasiTcpSocketAddress,
    },
    /// The listen failed and the stream reported it.
    Failed,
}

impl<T, CpuImpl, Net, StorageImpl> Unpin for TcpListenStreamProducer<T, CpuImpl, Net, StorageImpl>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum P3TcpListenStreamOperation {
    Listen,
    Accept,
    InvalidState,
    /// The executor had no task left for this instance to run the
    /// accept on.
    TaskCapacity,
}

#[derive(Clone, Debug, Error)]
#[error("preview3 TCP listener stream {operation:?} failed")]
pub(super) struct P3TcpListenStreamError {
    pub(super) operation: P3TcpListenStreamOperation,
    #[source]
    pub(super) source: Option<crate::TcpError>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum WasiTcpSocketFamily {
    Ipv4,
    Ipv6,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum WasiTcpIpAddress {
    Ipv4(crate::Ipv4Address),
    Ipv6(Ipv6Address),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct WasiTcpSocketAddress {
    pub(super) address: WasiTcpIpAddress,
    pub(super) port: u16,
}

impl WasiTcpSocketFamily {
    pub(super) const fn unspecified_address(self) -> WasiTcpIpAddress {
        match self {
            Self::Ipv4 => WasiTcpIpAddress::Ipv4(crate::Ipv4Address::new([0, 0, 0, 0])),
            Self::Ipv6 => WasiTcpIpAddress::Ipv6(Ipv6Address::UNSPECIFIED),
        }
    }
}

impl WasiTcpIpAddress {
    pub(super) const fn family(self) -> WasiTcpSocketFamily {
        match self {
            Self::Ipv4(_) => WasiTcpSocketFamily::Ipv4,
            Self::Ipv6(_) => WasiTcpSocketFamily::Ipv6,
        }
    }

    pub(super) const fn network_address(self) -> crate::NetworkIpAddress {
        match self {
            Self::Ipv4(address) => crate::NetworkIpAddress::Ipv4(address),
            Self::Ipv6(address) => crate::NetworkIpAddress::Ipv6(address),
        }
    }
}

impl TcpSocket {
    pub(super) fn new(retire: SocketRetirementSender, family: WasiTcpSocketFamily) -> Self {
        Self {
            retire,
            family,
            connection: None,
            listener: None,
            local_address: None,
            remote_address: None,
            p3_connect: None,
            pending_listen: None,
            listen_backlog: DEFAULT_WASI_TCP_LISTEN_BACKLOG,
            keep_alive_enabled: false,
            keep_alive_idle_time: DEFAULT_WASI_TCP_KEEP_ALIVE_IDLE_NANOS,
            keep_alive_interval: DEFAULT_WASI_TCP_KEEP_ALIVE_INTERVAL_NANOS,
            keep_alive_count: DEFAULT_WASI_TCP_KEEP_ALIVE_COUNT,
            hop_limit: DEFAULT_WASI_TCP_HOP_LIMIT,
            receive_buffer_size: WASI_TCP_RECEIVE_BUFFER_BYTES,
            send_buffer_size: WASI_TCP_SEND_BUFFER_BYTES,
        }
    }

    /// The socket one completed accept produced, and the connection it
    /// now owns, for the streams the caller opens on it.
    pub(super) fn accepted(
        retire: SocketRetirementSender,
        family: WasiTcpSocketFamily,
        accepted: AcceptedConnection,
    ) -> (Self, Arc<TcpConnection>) {
        let connection = Arc::new(accepted.connection);
        let mut socket = Self::new(retire, family);
        socket.connection = Some(connection.clone());
        socket.local_address = Some(accepted.local_address);
        socket.remote_address = Some(accepted.remote_address);
        (socket, connection)
    }

    /// Takes in the listen answer if it has already arrived.
    ///
    /// A receiver that answered leaves its slot, so the answer is taken
    /// in exactly once.
    pub(super) fn settle(&mut self) {
        if let Some(answer) = &mut self.pending_listen
            && let Poll::Ready(answer) =
                poll_answer(answer, &mut Context::from_waker(Waker::noop()), "listen")
        {
            self.pending_listen = None;
            if let Ok(listener) = answer {
                self.adopt_listener(listener);
            }
        }
    }

    /// Makes a listener that opened this socket's own.
    pub(super) fn adopt_listener(&mut self, listener: Arc<OwnedTcpListener>) {
        let local_address = WasiTcpSocketAddress {
            address: self.family.unspecified_address(),
            port: listener.local_port,
        };
        self.listener = Some(listener);
        self.local_address.get_or_insert(local_address);
    }

    pub(super) fn family(&self) -> WasiTcpSocketFamily {
        self.family
    }

    pub(super) fn address_family(&self) -> socket_types::IpAddressFamily {
        match self.family() {
            WasiTcpSocketFamily::Ipv4 => socket_types::IpAddressFamily::Ipv4,
            WasiTcpSocketFamily::Ipv6 => socket_types::IpAddressFamily::Ipv6,
        }
    }

    pub(super) fn remote_address(
        &mut self,
    ) -> core::result::Result<WasiTcpSocketAddress, socket_types::ErrorCode> {
        self.settle();
        self.remote_address
            .ok_or(socket_types::ErrorCode::InvalidState)
    }

    pub(super) fn local_address(
        &mut self,
    ) -> core::result::Result<WasiTcpSocketAddress, socket_types::ErrorCode> {
        self.settle();
        self.local_address
            .ok_or(socket_types::ErrorCode::InvalidState)
    }

    pub(super) fn bind_local(
        &mut self,
        local_address: WasiTcpSocketAddress,
    ) -> core::result::Result<(), socket_types::ErrorCode> {
        self.settle();
        if self.connection.is_some() || self.listener.is_some() || self.pending_listen.is_some() {
            return Err(socket_types::ErrorCode::InvalidState);
        }
        self.local_address = Some(local_address);
        Ok(())
    }

    pub(super) fn is_listening(&mut self) -> bool {
        self.settle();
        self.listener.is_some()
    }

    #[cfg(test)]
    pub(super) fn listen_backlog(&self) -> u16 {
        self.listen_backlog
    }

    pub(super) fn set_listen_backlog_size(
        &mut self,
        value: u64,
    ) -> core::result::Result<(), socket_types::ErrorCode> {
        let backlog = u16::try_from(value).map_err(|_| socket_types::ErrorCode::InvalidArgument)?;
        if backlog == 0 {
            return Err(socket_types::ErrorCode::InvalidArgument);
        }
        self.settle();
        if self.connection.is_some() || self.listener.is_some() || self.pending_listen.is_some() {
            return Err(socket_types::ErrorCode::InvalidState);
        }
        self.listen_backlog = backlog;
        Ok(())
    }

    /// Whether a `listen` may begin.
    pub(super) fn may_listen(&mut self) -> bool {
        self.settle();
        !(self.connection.is_some() || self.listener.is_some() || self.pending_listen.is_some())
    }

    /// What a listen on this socket opens its listener with: the bound
    /// address, or the unspecified address with an ephemeral port.
    pub(super) fn listen_request(&self) -> ListenRequest {
        ListenRequest {
            local_address: self.local_address.unwrap_or(WasiTcpSocketAddress {
                address: self.family.unspecified_address(),
                port: 0,
            }),
            backlog: self.listen_backlog,
            hop_limit: self.hop_limit,
        }
    }

    pub(super) fn keep_alive_enabled(&self) -> core::result::Result<bool, socket_types::ErrorCode> {
        Ok(self.keep_alive_enabled)
    }

    /// Enabling keepalive is rejected rather than recorded.
    ///
    /// The netstack has no keepalive timer, so accepting `true` would make a
    /// guest believe idle connections are being probed and dead peers
    /// detected when neither happens. Disabling it is the state the stack is
    /// already in, so that direction succeeds.
    pub(super) fn set_keep_alive_enabled(
        &mut self,
        value: bool,
    ) -> core::result::Result<(), socket_types::ErrorCode> {
        if value {
            return Err(socket_types::ErrorCode::NotSupported);
        }
        self.keep_alive_enabled = value;
        Ok(())
    }

    pub(super) fn keep_alive_idle_time(
        &self,
    ) -> core::result::Result<u64, socket_types::ErrorCode> {
        Ok(self.keep_alive_idle_time)
    }

    pub(super) fn set_keep_alive_idle_time(
        &mut self,
        value: u64,
    ) -> core::result::Result<(), socket_types::ErrorCode> {
        if value == 0 {
            return Err(socket_types::ErrorCode::InvalidArgument);
        }
        self.keep_alive_idle_time = value;
        Ok(())
    }

    pub(super) fn keep_alive_interval(&self) -> core::result::Result<u64, socket_types::ErrorCode> {
        Ok(self.keep_alive_interval)
    }

    pub(super) fn set_keep_alive_interval(
        &mut self,
        value: u64,
    ) -> core::result::Result<(), socket_types::ErrorCode> {
        if value == 0 {
            return Err(socket_types::ErrorCode::InvalidArgument);
        }
        self.keep_alive_interval = value;
        Ok(())
    }

    pub(super) fn keep_alive_count(&self) -> core::result::Result<u32, socket_types::ErrorCode> {
        Ok(self.keep_alive_count)
    }

    pub(super) fn set_keep_alive_count(
        &mut self,
        value: u32,
    ) -> core::result::Result<(), socket_types::ErrorCode> {
        if value == 0 {
            return Err(socket_types::ErrorCode::InvalidArgument);
        }
        self.keep_alive_count = value;
        Ok(())
    }

    pub(super) fn receive_buffer_size(&self) -> core::result::Result<u64, socket_types::ErrorCode> {
        Ok(self.receive_buffer_size)
    }

    /// Records a receive-buffer request clamped to what the stack reserves.
    ///
    /// `wasi:sockets` allows an implementation to clamp this hint, and reading
    /// the option back is documented to return the effective value. The
    /// netstack's per-socket receive window is fixed, so the effective value
    /// is that window and the getter reports it instead of echoing whatever
    /// the guest asked for.
    pub(super) fn set_receive_buffer_size(
        &mut self,
        value: u64,
    ) -> core::result::Result<(), socket_types::ErrorCode> {
        if value == 0 {
            return Err(socket_types::ErrorCode::InvalidArgument);
        }
        self.receive_buffer_size = value.min(WASI_TCP_RECEIVE_BUFFER_BYTES);
        Ok(())
    }

    pub(super) fn send_buffer_size(&self) -> core::result::Result<u64, socket_types::ErrorCode> {
        Ok(self.send_buffer_size)
    }

    /// Records a send-buffer request clamped to the stack's transmit buffer.
    pub(super) fn set_send_buffer_size(
        &mut self,
        value: u64,
    ) -> core::result::Result<(), socket_types::ErrorCode> {
        if value == 0 {
            return Err(socket_types::ErrorCode::InvalidArgument);
        }
        self.send_buffer_size = value.min(WASI_TCP_SEND_BUFFER_BYTES);
        Ok(())
    }

    pub(super) fn hop_limit(&self) -> core::result::Result<u8, socket_types::ErrorCode> {
        Ok(self.hop_limit)
    }

    /// Sets the IPv4 TTL / IPv6 hop limit and pushes it into the netstack.
    ///
    /// An unbound socket has nothing to push to yet, so the value is held on
    /// the descriptor and handed to `connect`/`listen`, which apply it before
    /// the first packet leaves. Once a stream or listener exists the change
    /// takes effect on the live socket.
    pub(super) fn set_hop_limit<Net: ComponentHostNetwork>(
        &mut self,
        service: &Net,
        value: u8,
    ) -> core::result::Result<(), socket_types::ErrorCode> {
        if value == 0 {
            return Err(socket_types::ErrorCode::InvalidArgument);
        }
        self.settle();
        self.hop_limit = value;
        if let Some(connection) = &self.connection {
            service
                .tcp_set_hop_limit(NetworkHandle::from_raw(connection.stream()), value)
                .map_err(map_p3_tcp_error)?;
        }
        if let Some(listener) = &self.listener {
            service
                .tcp_listener_set_hop_limit(NetworkHandle::from_raw(listener.raw()), value)
                .map_err(map_p3_tcp_error)?;
        }
        Ok(())
    }

    /// Admits a p3 `connect`, which then runs with the socket released.
    ///
    /// A second `connect` while one is still running answers
    /// `invalid-state`, which `wasi:sockets` documents for "The socket
    /// is already in the `connecting` state. (EALREADY)". Before the
    /// socket kept a mark of the running connect, the second one went
    /// ahead and the later of the two to finish overwrote the other's
    /// stream.
    pub(super) fn start_p3_connect(
        &mut self,
    ) -> core::result::Result<P3Connect, socket_types::ErrorCode> {
        self.settle();
        if self.connection.is_some() || in_flight(&mut self.p3_connect) {
            return Err(socket_types::ErrorCode::InvalidState);
        }
        let (marker, guard) = InFlight::start();
        self.p3_connect = Some(marker);
        Ok(P3Connect {
            guard,
            retire: self.retire.clone(),
            local_port: self.local_address.map_or(0, |address| address.port),
            hop_limit: self.hop_limit,
        })
    }

    /// Applies what a p3 `connect` admitted by
    /// [`Self::start_p3_connect`] produced.
    ///
    /// The admission's mark is this call's own: no other connect is
    /// admitted while it lives, and a cancelled connect never gets
    /// here.
    pub(super) fn finish_p3_connect(
        &mut self,
        guard: InFlightGuard,
        remote_address: WasiTcpSocketAddress,
        outcome: core::result::Result<TcpConnection, socket_types::ErrorCode>,
    ) -> core::result::Result<(), socket_types::ErrorCode> {
        drop(guard);
        self.p3_connect = None;
        self.connection = Some(Arc::new(outcome?));
        self.remote_address = Some(remote_address);
        Ok(())
    }

    /// The whole p3 `connect` on a socket the caller holds throughout.
    #[cfg(test)]
    pub(super) async fn connect<Net: ComponentHostNetwork>(
        &mut self,
        service: &Net,
        remote_address: WasiTcpSocketAddress,
    ) -> core::result::Result<(), socket_types::ErrorCode> {
        let (guard, outcome) = self.start_p3_connect()?.run(service, remote_address).await;
        self.finish_p3_connect(guard, remote_address, outcome)
    }

    /// The connection, if the socket has one.
    pub(super) fn connection(&mut self) -> Option<Arc<TcpConnection>> {
        self.settle();
        self.connection.clone()
    }
}

impl<T, CpuImpl, Net, StorageImpl> TcpListenStreamProducer<T, CpuImpl, Net, StorageImpl>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    /// A listen stream on `socket`, waiting on `listen` for the
    /// listener the listen task opens.
    pub(super) fn new(
        socket: &TcpSocket,
        listen: TcpAnswer<Arc<OwnedTcpListener>>,
        service: Net,
        get_store_data: for<'a> fn(&'a mut T) -> &'a mut StoreData<CpuImpl, Net, StorageImpl>,
        spawner: crate::InstanceSpawner<CpuImpl>,
    ) -> Self {
        Self {
            service,
            get_store_data,
            spawner,
            retire: socket.retire.clone(),
            family: socket.family,
            bound_address: socket.local_address,
            listen: P3ListenState::Opening(listen),
            accept: None,
        }
    }
}

/// Why a p3 listen stream ended, as the error its poll returns.
fn listen_stream_error(
    operation: P3TcpListenStreamOperation,
    source: Option<crate::TcpError>,
) -> wasmtime::Error {
    wasmtime::Error::new(P3TcpListenStreamError { operation, source })
}

impl<T, CpuImpl, Net, StorageImpl> StreamProducer<T>
    for TcpListenStreamProducer<T, CpuImpl, Net, StorageImpl>
where
    T: 'static,
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    type Item = Resource<TcpSocket>;
    type Buffer = Option<Self::Item>;

    fn poll_produce<'a>(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut store: StoreContextMut<'a, T>,
        mut destination: Destination<'a, Self::Item, Self::Buffer>,
        finish: bool,
    ) -> Poll<Result<StreamResult>> {
        if finish {
            return Poll::Ready(Ok(StreamResult::Cancelled));
        }
        if destination.remaining(&mut store)? == Some(0) {
            return Poll::Ready(Ok(StreamResult::Completed));
        }
        let this = self.as_mut().get_mut();

        loop {
            let (listener, local_address) = match &mut this.listen {
                P3ListenState::Opening(answer) => match poll_answer(answer, cx, "listen") {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Ok(listener)) => {
                        let local_address = this.bound_address.unwrap_or(WasiTcpSocketAddress {
                            address: this.family.unspecified_address(),
                            port: listener.local_port,
                        });
                        this.listen = P3ListenState::Listening {
                            listener,
                            local_address,
                        };
                        continue;
                    }
                    Poll::Ready(Err(error)) => {
                        this.listen = P3ListenState::Failed;
                        return Poll::Ready(Err(listen_stream_error(
                            P3TcpListenStreamOperation::Listen,
                            Some(error),
                        )));
                    }
                },
                P3ListenState::Listening {
                    listener,
                    local_address,
                } => (listener, *local_address),
                P3ListenState::Failed => {
                    return Poll::Ready(Err(listen_stream_error(
                        P3TcpListenStreamOperation::InvalidState,
                        None,
                    )));
                }
            };

            let Some(answer) = &mut this.accept else {
                match spawn_accept(
                    &this.spawner,
                    this.service.clone(),
                    this.retire.clone(),
                    listener.clone(),
                    this.family,
                    local_address,
                ) {
                    Ok(answer) => this.accept = Some(answer),
                    Err(_) => {
                        return Poll::Ready(Err(listen_stream_error(
                            P3TcpListenStreamOperation::TaskCapacity,
                            None,
                        )));
                    }
                }
                continue;
            };
            let accepted = match poll_answer(answer, cx, "accept") {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(accepted) => accepted,
            };
            this.accept = None;
            let accepted = accepted.map_err(|error| {
                listen_stream_error(P3TcpListenStreamOperation::Accept, Some(error))
            })?;
            let (socket, _) = TcpSocket::accepted(this.retire.clone(), this.family, accepted);
            let store_data = (this.get_store_data)(store.data_mut());
            let resource = store_data.table.push(socket)?;
            destination.set_buffer(Some(resource));
            return Poll::Ready(Ok(StreamResult::Completed));
        }
    }
}

/// The `receive` stream for one socket, with the read future's type
/// inferred here and carried by the producer.
pub(super) fn tcp_read_producer<Net: ComponentHostNetwork>(
    connection: Option<Arc<TcpConnection>>,
    service: Net,
    completion: oneshot::Sender<core::result::Result<(), socket_types::ErrorCode>>,
) -> TcpReadStreamProducer<Net, impl core::future::Future<Output = TcpReadResult> + Send> {
    TcpReadStreamProducer {
        connection,
        service,
        start: read_socket::<Net>,
        pending: None,
        completion: Some(completion),
    }
}

impl<T, Net, Fut> StreamProducer<T> for TcpReadStreamProducer<Net, Fut>
where
    T: 'static,
    Net: ComponentHostNetwork,
    Fut: core::future::Future<Output = TcpReadResult> + Send + 'static,
{
    type Item = u8;
    type Buffer = BytesStreamBuffer;

    fn poll_produce(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut store: wasmtime::StoreContextMut<'_, T>,
        mut destination: Destination<'_, Self::Item, Self::Buffer>,
        finish: bool,
    ) -> Poll<Result<StreamResult>> {
        let mut this = self.project();
        if finish {
            complete_socket_transfer(this.completion, Ok(()));
            return Poll::Ready(Ok(StreamResult::Cancelled));
        }

        loop {
            if this.pending.is_none() {
                let capacity = destination.remaining(&mut store)?;
                if capacity == Some(0) {
                    return Poll::Ready(Ok(StreamResult::Completed));
                }
                let capacity = capacity.unwrap_or(FILE_READ_CHUNK_BYTES);
                let max_bytes = u32::try_from(capacity).unwrap_or(u32::MAX);
                let read = (*this.start)(this.connection.clone(), this.service.clone(), max_bytes);
                this.pending.set(Some(read));
            }

            let result = match this.pending.as_mut().as_pin_mut() {
                Some(pending) => match pending.poll(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(result) => result,
                },
                None => unreachable!("tcp read future must be present before polling"),
            };
            this.pending.set(None);
            match result {
                Ok(Some(bytes)) if bytes.is_empty() => continue,
                Ok(Some(bytes)) => {
                    destination.set_buffer(BytesStreamBuffer::new(bytes));
                    return Poll::Ready(Ok(StreamResult::Completed));
                }
                Ok(None) => {
                    complete_socket_transfer(this.completion, Ok(()));
                    return Poll::Ready(Ok(StreamResult::Dropped));
                }
                Err(error) => {
                    complete_socket_transfer(this.completion, Err(error));
                    return Poll::Ready(Ok(StreamResult::Dropped));
                }
            }
        }
    }
}

/// The `send` stream for one socket, with the write future's type
/// inferred here and carried by the consumer.
pub(super) fn tcp_write_consumer<Net: ComponentHostNetwork>(
    connection: Option<Arc<TcpConnection>>,
    service: Net,
    completion: oneshot::Sender<core::result::Result<(), socket_types::ErrorCode>>,
) -> TcpWriteConsumer<Net, impl core::future::Future<Output = TcpWriteResult> + Send> {
    TcpWriteConsumer {
        connection,
        service,
        start: write_socket::<Net>,
        pending: None,
        completion: Some(completion),
    }
}

impl<T, Net, Fut> StreamConsumer<T> for TcpWriteConsumer<Net, Fut>
where
    T: 'static,
    Net: ComponentHostNetwork,
    Fut: core::future::Future<Output = TcpWriteResult> + Send + 'static,
{
    type Item = u8;

    fn poll_consume(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut store: wasmtime::StoreContextMut<'_, T>,
        mut source: Source<'_, Self::Item>,
        _: bool,
    ) -> Poll<Result<StreamResult>> {
        let mut this = self.project();
        // The guest's whole write, one chunk at a time: `Completed` ends its
        // `stream.write`, so it is reported only once the source is empty.
        loop {
            if this.pending.is_none() {
                // The guest's buffer stays lent to the stream until it is
                // marked read, so one chunk of it at a time (at most
                // `GUEST_IO_CHUNK_BYTES`, matching preview1's `sock_send`,
                // and never more than one send buffer) is copied straight
                // into transmit memory, and the rest waits in place for the
                // next pass of this loop.
                let mut source = source.reborrow().as_direct(store.as_context_mut());
                let bytes = source.remaining()?;
                let available = bytes.len();
                if available == 0 {
                    complete_socket_transfer(this.completion, Ok(()));
                    return Poll::Ready(Ok(StreamResult::Completed));
                }
                let len = bounded_chunk_len(
                    available,
                    GUEST_IO_CHUNK_BYTES.min(helios_netstack::TCP_TRANSMIT_BUFFER_BYTES),
                );
                let piece = match this.service.tcp_payload(len, |piece| {
                    piece.copy_from_slice(&bytes[..len]);
                }) {
                    Ok(piece) => piece,
                    Err(error) => {
                        complete_socket_transfer(this.completion, Err(map_p3_tcp_error(error)));
                        return Poll::Ready(Ok(StreamResult::Dropped));
                    }
                };
                source.mark_read(len);
                let write = (*this.start)(
                    this.connection.clone(),
                    this.service.clone(),
                    piece,
                );
                this.pending.set(Some(write));
            }

            let result = match this.pending.as_mut().as_pin_mut() {
                Some(pending) => match pending.poll(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(result) => result,
                },
                None => unreachable!("tcp write future must be present before polling"),
            };
            this.pending.set(None);
            if let Err(error) = result {
                // The error is reported through `completion`, the chunk in
                // hand is lost and the rest of the write stays unread.
                complete_socket_transfer(this.completion, Err(error));
                return Poll::Ready(Ok(StreamResult::Dropped));
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum WasiUdpSocketFamily {
    Ipv4,
    Ipv6,
}

impl WasiUdpSocketFamily {
    pub(super) const fn unspecified_address(self) -> crate::NetworkIpAddress {
        match self {
            Self::Ipv4 => crate::NetworkIpAddress::Ipv4(crate::Ipv4Address::new([0, 0, 0, 0])),
            Self::Ipv6 => crate::NetworkIpAddress::Ipv6(Ipv6Address::UNSPECIFIED),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct WasiUdpSocketAddress {
    pub(super) address: crate::NetworkIpAddress,
    pub(super) port: u16,
}

/// The kernel datagram socket a `wasi:sockets` UDP socket is bound to.
///
/// The kernel socket is an [`OwnedNetworkHandle`]: a datagram socket
/// is installed on every shard and holds a slot in `udp_slots`, so one
/// a program left behind cost the whole set (#190). It is shared, and
/// immutable, between the socket and each send or receive running on
/// it with the socket released, so an operation in flight keeps the
/// kernel socket it is using open.
#[derive(Clone)]
pub(super) struct UdpBinding {
    socket: Arc<OwnedNetworkHandle>,
    pub(super) local_address: crate::NetworkIpAddress,
    pub(super) local_port: u16,
}

impl UdpBinding {
    pub(super) fn socket(&self) -> u64 {
        self.socket.raw()
    }
}

/// What a bind opens its kernel socket with.
#[derive(Clone)]
pub(super) struct UdpBindRequest {
    retire: SocketRetirementSender,
    hop_limit: u8,
}

/// Binds a kernel datagram socket, owned from the moment the service
/// returns it.
async fn bind_kernel_socket<Net: ComponentHostNetwork>(
    service: &Net,
    request: UdpBindRequest,
    local_address: crate::NetworkIpAddress,
    local_port: u16,
) -> core::result::Result<UdpBinding, WasiUdpSocketError> {
    let binding = service
        .udp_bind(local_address, local_port)
        .await
        .map_err(WasiUdpSocketError::Backend)?;
    let local_port = binding.local_port;
    let raw = binding.socket.into_raw();
    let socket = OwnedNetworkHandle::new(request.retire, RetiredNetworkHandle::UdpSocket(raw));
    // A datagram socket cannot emit anything before its bind completes,
    // so applying the descriptor's hop limit here covers every packet it
    // will ever send. A failure drops `socket`, which retires it.
    service
        .udp_set_hop_limit(binding.socket, request.hop_limit)
        .map_err(WasiUdpSocketError::Backend)?;
    Ok(UdpBinding {
        socket: Arc::new(socket),
        local_address,
        local_port,
    })
}

/// The implicit bind a p3 `send` on an unbound socket admitted, carried
/// across the await that runs it.
pub(super) struct ImplicitUdpBind {
    guard: InFlightGuard,
    request: UdpBindRequest,
    local_address: crate::NetworkIpAddress,
}

impl ImplicitUdpBind {
    /// Binds with the socket released. The guard comes back for
    /// [`UdpSocket::finish_implicit_bind`].
    pub(super) async fn run<Net: ComponentHostNetwork>(
        self,
        service: &Net,
    ) -> (
        InFlightGuard,
        core::result::Result<UdpBinding, WasiUdpSocketError>,
    ) {
        let outcome = bind_kernel_socket(service, self.request, self.local_address, 0).await;
        (self.guard, outcome)
    }
}

/// The binding a send goes out on.
pub(super) enum UdpSendBinding {
    Bound(UdpBinding),
    /// The socket was unbound: the send binds it first.
    Unbound(ImplicitUdpBind),
}

/// A send the socket admitted.
pub(super) struct UdpSend {
    pub(super) target: WasiUdpSocketAddress,
    pub(super) binding: UdpSendBinding,
}

/// A receive the socket admitted.
pub(super) struct UdpReceive {
    binding: UdpBinding,
    family: WasiUdpSocketFamily,
    filter: Option<WasiUdpSocketAddress>,
}

/// A `wasi:sockets` UDP socket.
///
/// # Ownership and concurrency
///
/// One owner, its resource-table entry, with no clone and no lock, as
/// for [`TcpSocket`]. The `bind` and `connect` hold the store, and the
/// socket, across their awaits. The `send` and `receive` release it:
/// they take the [`UdpBinding`] they need, and a `send` on an unbound
/// socket marks its implicit bind in `implicit_bind` and fetches the
/// socket again to install the result.
pub struct UdpSocket {
    /// Where the kernel socket goes when it dies.
    pub(super) retire: SocketRetirementSender,
    pub(super) family: WasiUdpSocketFamily,
    pub(super) bound: Option<UdpBinding>,
    /// A `send`'s implicit bind under way.
    pub(super) implicit_bind: Option<InFlight>,
    pub(super) remote_address: Option<WasiUdpSocketAddress>,
    pub(super) hop_limit: u8,
    pub(super) receive_buffer_size: u64,
    pub(super) send_buffer_size: u64,
}

#[derive(Debug)]
pub(super) enum WasiUdpSocketError {
    NotSupported,
    InvalidArgument,
    InvalidState,
    AddressNotBindable,
    DatagramTooLarge,
    WouldBlock,
    Backend(crate::UdpError),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct WasiUdpSocketDatagram {
    pub(super) bytes: Bytes,
    pub(super) remote_address: WasiUdpSocketAddress,
}

impl UdpSocket {
    pub(super) fn new(retire: SocketRetirementSender, family: WasiUdpSocketFamily) -> Self {
        Self {
            retire,
            family,
            bound: None,
            implicit_bind: None,
            remote_address: None,
            hop_limit: DEFAULT_WASI_UDP_HOP_LIMIT,
            receive_buffer_size: DEFAULT_WASI_UDP_BUFFER_BYTES,
            send_buffer_size: DEFAULT_WASI_UDP_BUFFER_BYTES,
        }
    }

    pub(super) fn family(&self) -> WasiUdpSocketFamily {
        self.family
    }

    pub(super) fn local_address(
        &self,
    ) -> core::result::Result<WasiUdpSocketAddress, WasiUdpSocketError> {
        let Some(bound) = &self.bound else {
            return Err(WasiUdpSocketError::InvalidState);
        };
        Ok(WasiUdpSocketAddress {
            address: bound.local_address,
            port: bound.local_port,
        })
    }

    pub(super) fn remote_address(
        &self,
    ) -> core::result::Result<WasiUdpSocketAddress, WasiUdpSocketError> {
        self.remote_address.ok_or(WasiUdpSocketError::InvalidState)
    }

    pub(super) fn unicast_hop_limit(&self) -> core::result::Result<u8, WasiUdpSocketError> {
        Ok(self.hop_limit)
    }

    /// Sets the datagram TTL / hop limit and pushes it into the netstack.
    ///
    /// An unbound socket has no stack socket yet, so the value is applied when
    /// the bind completes; a bound socket takes it immediately.
    pub(super) fn set_unicast_hop_limit<Net: ComponentHostNetwork>(
        &mut self,
        service: &Net,
        value: u8,
    ) -> core::result::Result<(), WasiUdpSocketError> {
        if value == 0 {
            return Err(WasiUdpSocketError::InvalidArgument);
        }
        self.hop_limit = value;
        if let Some(bound) = &self.bound {
            service
                .udp_set_hop_limit(NetworkHandle::from_raw(bound.socket()), value)
                .map_err(WasiUdpSocketError::Backend)?;
        }
        Ok(())
    }

    pub(super) fn receive_buffer_size(&self) -> core::result::Result<u64, WasiUdpSocketError> {
        Ok(self.receive_buffer_size)
    }

    pub(super) fn set_receive_buffer_size(
        &mut self,
        value: u64,
    ) -> core::result::Result<(), WasiUdpSocketError> {
        if value == 0 {
            return Err(WasiUdpSocketError::InvalidArgument);
        }
        self.receive_buffer_size = value;
        Ok(())
    }

    pub(super) fn send_buffer_size(&self) -> core::result::Result<u64, WasiUdpSocketError> {
        Ok(self.send_buffer_size)
    }

    pub(super) fn set_send_buffer_size(
        &mut self,
        value: u64,
    ) -> core::result::Result<(), WasiUdpSocketError> {
        if value == 0 {
            return Err(WasiUdpSocketError::InvalidArgument);
        }
        self.send_buffer_size = value;
        Ok(())
    }

    pub(super) async fn bind<Net: ComponentHostNetwork>(
        &mut self,
        service: &Net,
        local_address: WasiUdpSocketAddress,
    ) -> core::result::Result<(), WasiUdpSocketError> {
        validate_udp_local_address(self.family, local_address)?;
        self.bind_backend(service, local_address.address, local_address.port)
            .await
    }

    pub(super) async fn connect<Net: ComponentHostNetwork>(
        &mut self,
        service: &Net,
        remote_address: WasiUdpSocketAddress,
    ) -> core::result::Result<(), WasiUdpSocketError> {
        validate_udp_remote_address(self.family, remote_address)?;
        let bound = self
            .ensure_bound(service, self.family.unspecified_address(), 0)
            .await?;
        service
            .udp_connect(
                NetworkHandle::from_raw(bound.socket()),
                remote_address.address,
                remote_address.port,
            )
            .map_err(WasiUdpSocketError::Backend)?;
        self.remote_address = Some(remote_address);
        Ok(())
    }

    pub(super) fn disconnect<Net: ComponentHostNetwork>(
        &mut self,
        service: &Net,
    ) -> core::result::Result<(), WasiUdpSocketError> {
        if self.remote_address.is_none() {
            return Err(WasiUdpSocketError::InvalidState);
        }
        let bound = self
            .bound
            .as_ref()
            .ok_or(WasiUdpSocketError::InvalidState)?;
        service
            .udp_disconnect(NetworkHandle::from_raw(bound.socket()))
            .map_err(WasiUdpSocketError::Backend)?;
        self.remote_address = None;
        Ok(())
    }

    /// Admits a send: checks the datagram and its target, and answers
    /// the binding it goes out on, or the implicit bind that makes one.
    ///
    /// A send on a socket whose bind is still under way answers
    /// `invalid-state`, the code `wasi:sockets` documents for a bind on
    /// "The socket is already bound. (EINVAL)". Before the socket kept
    /// a mark of the running bind, two p3 sends on an unbound socket
    /// both bound it, and the later one to finish failed the assertion
    /// "udp bind raced with a concurrent state transition".
    pub(super) fn start_send(
        &mut self,
        length: usize,
        remote_address: Option<WasiUdpSocketAddress>,
    ) -> core::result::Result<UdpSend, WasiUdpSocketError> {
        if length > MAX_WASI_UDP_DATAGRAM_BYTES {
            return Err(WasiUdpSocketError::DatagramTooLarge);
        }
        let target = self.resolve_send_target(remote_address)?;
        if let Some(bound) = &self.bound {
            return Ok(UdpSend {
                target,
                binding: UdpSendBinding::Bound(bound.clone()),
            });
        }
        let request = self.start_bind()?;
        let (marker, guard) = InFlight::start();
        self.implicit_bind = Some(marker);
        Ok(UdpSend {
            target,
            binding: UdpSendBinding::Unbound(ImplicitUdpBind {
                guard,
                request,
                local_address: self.family.unspecified_address(),
            }),
        })
    }

    /// Installs what an implicit bind admitted by
    /// [`Self::start_send`] produced.
    ///
    /// While the bind's mark lives every other bind on the socket is
    /// refused, so the socket is still unbound here; a binding that
    /// failed, or arrived on a socket that is somehow bound after all,
    /// is dropped, which retires it.
    pub(super) fn finish_implicit_bind(
        &mut self,
        guard: InFlightGuard,
        outcome: core::result::Result<UdpBinding, WasiUdpSocketError>,
    ) -> core::result::Result<UdpBinding, WasiUdpSocketError> {
        drop(guard);
        self.implicit_bind = None;
        let binding = outcome?;
        if self.bound.is_some() {
            return Err(WasiUdpSocketError::InvalidState);
        }
        self.bound = Some(binding.clone());
        Ok(binding)
    }

    /// Admits a receive and answers what it reads with.
    pub(super) fn start_receive(
        &self,
        remote_address: Option<WasiUdpSocketAddress>,
    ) -> core::result::Result<UdpReceive, WasiUdpSocketError> {
        let binding = self.bound.clone().ok_or(WasiUdpSocketError::InvalidState)?;
        Ok(UdpReceive {
            binding,
            family: self.family,
            filter: remote_address.or(self.remote_address),
        })
    }

    /// Admits a bind, refusing one on a socket that is bound or has a
    /// send's implicit bind under way.
    fn start_bind(&mut self) -> core::result::Result<UdpBindRequest, WasiUdpSocketError> {
        if self.bound.is_some() || in_flight(&mut self.implicit_bind) {
            return Err(WasiUdpSocketError::InvalidState);
        }
        Ok(UdpBindRequest {
            retire: self.retire.clone(),
            hop_limit: self.hop_limit,
        })
    }

    /// Binds on a socket the caller holds across the bind.
    pub(super) async fn bind_backend<Net: ComponentHostNetwork>(
        &mut self,
        service: &Net,
        local_address: crate::NetworkIpAddress,
        local_port: u16,
    ) -> core::result::Result<(), WasiUdpSocketError> {
        let request = self.start_bind()?;
        self.bound = Some(bind_kernel_socket(service, request, local_address, local_port).await?);
        Ok(())
    }

    pub(super) async fn ensure_bound<Net: ComponentHostNetwork>(
        &mut self,
        service: &Net,
        local_address: crate::NetworkIpAddress,
        local_port: u16,
    ) -> core::result::Result<UdpBinding, WasiUdpSocketError> {
        if let Some(bound) = &self.bound {
            return Ok(bound.clone());
        }
        self.bind_backend(service, local_address, local_port)
            .await?;
        self.bound.clone().ok_or(WasiUdpSocketError::InvalidState)
    }

    fn resolve_send_target(
        &self,
        remote_address: Option<WasiUdpSocketAddress>,
    ) -> core::result::Result<WasiUdpSocketAddress, WasiUdpSocketError> {
        match (self.remote_address, remote_address) {
            (Some(connected), None) => Ok(connected),
            (Some(connected), Some(provided)) if connected == provided => Ok(connected),
            (None, Some(provided)) => {
                validate_udp_remote_address(self.family, provided)?;
                Ok(provided)
            }
            _ => Err(WasiUdpSocketError::InvalidArgument),
        }
    }
}

/// Sends one datagram on a binding, with the socket released.
pub(super) async fn send_on<Net: ComponentHostNetwork>(
    service: &Net,
    binding: &UdpBinding,
    target: WasiUdpSocketAddress,
    bytes: &[u8],
    timeout_nanos: u64,
) -> core::result::Result<(), WasiUdpSocketError> {
    let written = service
        .udp_send_address(
            NetworkHandle::from_raw(binding.socket()),
            target.address,
            target.port,
            bytes,
            timeout_nanos,
        )
        .await
        .map_err(WasiUdpSocketError::Backend)?;
    assert!(
        usize::try_from(written).ok() == Some(bytes.len()),
        "kernel udp service reported a partial datagram write"
    );
    Ok(())
}

/// Receives one datagram a receive admitted, with the socket released.
pub(super) async fn receive_on<Net: ComponentHostNetwork>(
    service: &Net,
    receive: UdpReceive,
    timeout_nanos: u64,
) -> core::result::Result<WasiUdpSocketDatagram, WasiUdpSocketError> {
    let UdpReceive {
        binding,
        family,
        filter,
    } = receive;
    loop {
        let datagram = service
            .udp_receive(
                NetworkHandle::from_raw(binding.socket()),
                MAX_WASI_UDP_DATAGRAM_BYTES as u32,
                timeout_nanos,
            )
            .await
            .map_err(|error| {
                if timeout_nanos == 0 && matches!(error.kind, crate::UdpErrorKind::Timeout) {
                    WasiUdpSocketError::WouldBlock
                } else {
                    WasiUdpSocketError::Backend(error)
                }
            })?
            .ok_or(WasiUdpSocketError::InvalidState)?;
        let remote = WasiUdpSocketAddress {
            address: datagram.address,
            port: datagram.port,
        };
        if !udp_address_matches_family(family, remote.address) {
            continue;
        }
        if filter.is_some_and(|expected| expected != remote) {
            continue;
        }
        return Ok(WasiUdpSocketDatagram {
            bytes: datagram.bytes,
            remote_address: remote,
        });
    }
}

pub(super) fn validate_udp_local_address(
    family: WasiUdpSocketFamily,
    local_address: WasiUdpSocketAddress,
) -> core::result::Result<(), WasiUdpSocketError> {
    if !udp_address_matches_family(family, local_address.address) {
        return Err(WasiUdpSocketError::NotSupported);
    }
    if !network_ip_address_is_unspecified(local_address.address) {
        return Err(WasiUdpSocketError::AddressNotBindable);
    }
    Ok(())
}

pub(super) fn validate_udp_remote_address(
    family: WasiUdpSocketFamily,
    remote_address: WasiUdpSocketAddress,
) -> core::result::Result<(), WasiUdpSocketError> {
    if !udp_address_matches_family(family, remote_address.address) {
        return Err(WasiUdpSocketError::NotSupported);
    }
    if network_ip_address_is_unspecified(remote_address.address) || remote_address.port == 0 {
        return Err(WasiUdpSocketError::InvalidArgument);
    }
    Ok(())
}

pub(super) fn udp_address_matches_family(
    family: WasiUdpSocketFamily,
    address: crate::NetworkIpAddress,
) -> bool {
    matches!(
        (family, address),
        (WasiUdpSocketFamily::Ipv4, crate::NetworkIpAddress::Ipv4(_))
            | (WasiUdpSocketFamily::Ipv6, crate::NetworkIpAddress::Ipv6(_))
    )
}

pub(super) fn network_ip_address_is_unspecified(address: crate::NetworkIpAddress) -> bool {
    match address {
        crate::NetworkIpAddress::Ipv4(address) => address.octets() == [0, 0, 0, 0],
        crate::NetworkIpAddress::Ipv6(address) => address.is_unspecified(),
    }
}

impl<CpuImpl, Net, StorageImpl> wasi::sockets::types::Host for StoreData<CpuImpl, Net, StorageImpl>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
}
impl<CpuImpl, Net, StorageImpl> wasi::sockets::types::HostTcpSocket
    for StoreData<CpuImpl, Net, StorageImpl>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    async fn bind(
        &mut self,
        socket: Resource<TcpSocket>,
        local_address: socket_types::IpSocketAddress,
    ) -> Result<core::result::Result<(), socket_types::ErrorCode>> {
        let family = self.table.get(&socket)?.family();
        let local_address = match parse_p3_tcp_socket_address(local_address, family) {
            Ok(address) => address,
            Err(error) => return Ok(Err(error)),
        };
        if !has_wasi_network_rights(
            self.process_authority(),
            wasi_tcp_bind_rights(local_address.port),
        ) {
            return Ok(Err(socket_types::ErrorCode::AccessDenied));
        }
        Ok(self.table.get_mut(&socket)?.bind_local(local_address))
    }

    fn create(
        &mut self,
        address_family: socket_types::IpAddressFamily,
    ) -> Result<core::result::Result<Resource<TcpSocket>, socket_types::ErrorCode>> {
        if !has_wasi_network_rights(self.process_authority(), crate::NetworkAuthorityRights::TCP) {
            return Ok(Err(socket_types::ErrorCode::AccessDenied));
        }
        let family = match address_family {
            socket_types::IpAddressFamily::Ipv4 => WasiTcpSocketFamily::Ipv4,
            socket_types::IpAddressFamily::Ipv6 => WasiTcpSocketFamily::Ipv6,
        };
        if self.runtime_state.network_service().is_none() {
            return Ok(Err(socket_types::ErrorCode::Other(None)));
        }
        let resource = self
            .table
            .push(TcpSocket::new(self.retirement.sender(), family))?;
        Ok(Ok(resource))
    }

    fn get_local_address(
        &mut self,
        socket: Resource<TcpSocket>,
    ) -> Result<core::result::Result<socket_types::IpSocketAddress, socket_types::ErrorCode>> {
        let socket = self.table.get_mut(&socket)?;
        Ok(socket.local_address().map(format_p3_tcp_socket_address))
    }

    fn get_remote_address(
        &mut self,
        socket: Resource<TcpSocket>,
    ) -> Result<core::result::Result<socket_types::IpSocketAddress, socket_types::ErrorCode>> {
        let socket = self.table.get_mut(&socket)?;
        Ok(socket.remote_address().map(format_p3_tcp_socket_address))
    }

    fn get_is_listening(&mut self, socket: Resource<TcpSocket>) -> Result<bool> {
        let socket = self.table.get_mut(&socket)?;
        Ok(socket.is_listening())
    }

    fn get_address_family(
        &mut self,
        socket: Resource<TcpSocket>,
    ) -> Result<socket_types::IpAddressFamily> {
        let socket = self.table.get_mut(&socket)?;
        Ok(socket.address_family())
    }

    fn set_listen_backlog_size(
        &mut self,
        socket: Resource<TcpSocket>,
        value: u64,
    ) -> Result<core::result::Result<(), socket_types::ErrorCode>> {
        let socket = self.table.get_mut(&socket)?;
        Ok(socket.set_listen_backlog_size(value))
    }

    fn get_keep_alive_enabled(
        &mut self,
        socket: Resource<TcpSocket>,
    ) -> Result<core::result::Result<bool, socket_types::ErrorCode>> {
        let socket = self.table.get_mut(&socket)?;
        Ok(socket.keep_alive_enabled())
    }

    fn set_keep_alive_enabled(
        &mut self,
        socket: Resource<TcpSocket>,
        value: bool,
    ) -> Result<core::result::Result<(), socket_types::ErrorCode>> {
        let socket = self.table.get_mut(&socket)?;
        Ok(socket.set_keep_alive_enabled(value))
    }

    fn get_keep_alive_idle_time(
        &mut self,
        socket: Resource<TcpSocket>,
    ) -> Result<core::result::Result<wasi::clocks::types::Duration, socket_types::ErrorCode>> {
        let socket = self.table.get_mut(&socket)?;
        Ok(socket.keep_alive_idle_time())
    }

    fn set_keep_alive_idle_time(
        &mut self,
        socket: Resource<TcpSocket>,
        value: wasi::clocks::types::Duration,
    ) -> Result<core::result::Result<(), socket_types::ErrorCode>> {
        let socket = self.table.get_mut(&socket)?;
        Ok(socket.set_keep_alive_idle_time(value))
    }

    fn get_keep_alive_interval(
        &mut self,
        socket: Resource<TcpSocket>,
    ) -> Result<core::result::Result<wasi::clocks::types::Duration, socket_types::ErrorCode>> {
        let socket = self.table.get_mut(&socket)?;
        Ok(socket.keep_alive_interval())
    }

    fn set_keep_alive_interval(
        &mut self,
        socket: Resource<TcpSocket>,
        value: wasi::clocks::types::Duration,
    ) -> Result<core::result::Result<(), socket_types::ErrorCode>> {
        let socket = self.table.get_mut(&socket)?;
        Ok(socket.set_keep_alive_interval(value))
    }

    fn get_keep_alive_count(
        &mut self,
        socket: Resource<TcpSocket>,
    ) -> Result<core::result::Result<u32, socket_types::ErrorCode>> {
        let socket = self.table.get_mut(&socket)?;
        Ok(socket.keep_alive_count())
    }

    fn set_keep_alive_count(
        &mut self,
        socket: Resource<TcpSocket>,
        value: u32,
    ) -> Result<core::result::Result<(), socket_types::ErrorCode>> {
        let socket = self.table.get_mut(&socket)?;
        Ok(socket.set_keep_alive_count(value))
    }

    fn get_hop_limit(
        &mut self,
        socket: Resource<TcpSocket>,
    ) -> Result<core::result::Result<u8, socket_types::ErrorCode>> {
        let socket = self.table.get_mut(&socket)?;
        Ok(socket.hop_limit())
    }

    fn set_hop_limit(
        &mut self,
        socket: Resource<TcpSocket>,
        value: u8,
    ) -> Result<core::result::Result<(), socket_types::ErrorCode>> {
        let Some(service) = self.runtime_state.network_service() else {
            return Ok(Err(socket_types::ErrorCode::Other(None)));
        };
        let socket = self.table.get_mut(&socket)?;
        Ok(socket.set_hop_limit(&service, value))
    }

    fn get_receive_buffer_size(
        &mut self,
        socket: Resource<TcpSocket>,
    ) -> Result<core::result::Result<u64, socket_types::ErrorCode>> {
        let socket = self.table.get_mut(&socket)?;
        Ok(socket.receive_buffer_size())
    }

    fn set_receive_buffer_size(
        &mut self,
        socket: Resource<TcpSocket>,
        value: u64,
    ) -> Result<core::result::Result<(), socket_types::ErrorCode>> {
        let socket = self.table.get_mut(&socket)?;
        Ok(socket.set_receive_buffer_size(value))
    }

    fn get_send_buffer_size(
        &mut self,
        socket: Resource<TcpSocket>,
    ) -> Result<core::result::Result<u64, socket_types::ErrorCode>> {
        let socket = self.table.get_mut(&socket)?;
        Ok(socket.send_buffer_size())
    }

    fn set_send_buffer_size(
        &mut self,
        socket: Resource<TcpSocket>,
        value: u64,
    ) -> Result<core::result::Result<(), socket_types::ErrorCode>> {
        let socket = self.table.get_mut(&socket)?;
        Ok(socket.set_send_buffer_size(value))
    }

    fn drop(&mut self, resource: Resource<TcpSocket>) -> Result<()> {
        // Deleting the handle ends the socket's life: the stream is
        // owned by its `TcpConnection`, which queues it when the last
        // stream over it goes too. Draining right afterwards is
        // what turns that into a close on this very call, so the FIN
        // of a guest that closed its connection leaves now rather than
        // on the guest's next socket call.
        self.table.delete(resource)?;
        self.retire_sockets();
        Ok(())
    }
}

impl<CpuImpl, Net, StorageImpl> wasi::sockets::types::HostUdpSocket
    for StoreData<CpuImpl, Net, StorageImpl>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    async fn bind(
        &mut self,
        socket: Resource<UdpSocket>,
        local_address: socket_types::IpSocketAddress,
    ) -> Result<core::result::Result<(), socket_types::ErrorCode>> {
        if !has_wasi_network_rights(self.process_authority(), crate::NetworkAuthorityRights::UDP) {
            return Ok(Err(socket_types::ErrorCode::AccessDenied));
        }
        let family = self.table.get(&socket)?.family();
        let local_address = match parse_p3_udp_socket_address(local_address, family) {
            Ok(address) => address,
            Err(error) => return Ok(Err(map_p3_udp_socket_error(error))),
        };
        if !has_wasi_network_rights(
            self.process_authority(),
            wasi_udp_bind_rights(local_address.port),
        ) {
            return Ok(Err(socket_types::ErrorCode::AccessDenied));
        }
        let Some(service) = self.runtime_state.network_service() else {
            return Ok(Err(socket_types::ErrorCode::Other(None)));
        };
        // The bind holds the store, and the socket with it, until it
        // returns.
        let socket = self.table.get_mut(&socket)?;
        let result = socket
            .bind(&service, local_address)
            .await
            .map_err(map_p3_udp_socket_error);
        Ok(result)
    }

    async fn connect(
        &mut self,
        socket: Resource<UdpSocket>,
        remote_address: socket_types::IpSocketAddress,
    ) -> Result<core::result::Result<(), socket_types::ErrorCode>> {
        if !has_wasi_network_rights(self.process_authority(), crate::NetworkAuthorityRights::UDP) {
            return Ok(Err(socket_types::ErrorCode::AccessDenied));
        }
        let family = self.table.get(&socket)?.family();
        let remote_address = match parse_p3_udp_socket_address(remote_address, family) {
            Ok(address) => address,
            Err(error) => return Ok(Err(map_p3_udp_socket_error(error))),
        };
        let Some(service) = self.runtime_state.network_service() else {
            return Ok(Err(socket_types::ErrorCode::Other(None)));
        };
        // The connect holds the store, and the socket with it, until it
        // returns.
        let socket = self.table.get_mut(&socket)?;
        let result = socket
            .connect(&service, remote_address)
            .await
            .map_err(map_p3_udp_socket_error);
        Ok(result)
    }

    fn create(
        &mut self,
        address_family: socket_types::IpAddressFamily,
    ) -> Result<core::result::Result<Resource<UdpSocket>, socket_types::ErrorCode>> {
        if !has_wasi_network_rights(self.process_authority(), crate::NetworkAuthorityRights::UDP) {
            return Ok(Err(socket_types::ErrorCode::AccessDenied));
        }
        let family = match map_p3_udp_family(address_family) {
            Ok(family) => family,
            Err(error) => return Ok(Err(map_p3_udp_socket_error(error))),
        };
        if self.runtime_state.network_service().is_none() {
            return Ok(Err(socket_types::ErrorCode::Other(None)));
        }
        let resource = self
            .table
            .push(UdpSocket::new(self.retirement.sender(), family))?;
        Ok(Ok(resource))
    }

    fn disconnect(
        &mut self,
        socket: Resource<UdpSocket>,
    ) -> Result<core::result::Result<(), socket_types::ErrorCode>> {
        let Some(service) = self.runtime_state.network_service() else {
            return Ok(Err(socket_types::ErrorCode::Other(None)));
        };
        let socket = self.table.get_mut(&socket)?;
        Ok(socket.disconnect(&service).map_err(map_p3_udp_socket_error))
    }

    fn get_local_address(
        &mut self,
        socket: Resource<UdpSocket>,
    ) -> Result<core::result::Result<socket_types::IpSocketAddress, socket_types::ErrorCode>> {
        let socket = self.table.get_mut(&socket)?;
        Ok(socket
            .local_address()
            .map(format_p3_udp_socket_address)
            .map_err(map_p3_udp_socket_error))
    }

    fn get_remote_address(
        &mut self,
        socket: Resource<UdpSocket>,
    ) -> Result<core::result::Result<socket_types::IpSocketAddress, socket_types::ErrorCode>> {
        let socket = self.table.get_mut(&socket)?;
        Ok(socket
            .remote_address()
            .map(format_p3_udp_socket_address)
            .map_err(map_p3_udp_socket_error))
    }

    fn get_address_family(
        &mut self,
        socket: Resource<UdpSocket>,
    ) -> Result<socket_types::IpAddressFamily> {
        let socket = self.table.get_mut(&socket)?;
        Ok(format_p3_udp_family(socket.family()))
    }

    fn get_unicast_hop_limit(
        &mut self,
        socket: Resource<UdpSocket>,
    ) -> Result<core::result::Result<u8, socket_types::ErrorCode>> {
        let socket = self.table.get_mut(&socket)?;
        Ok(socket.unicast_hop_limit().map_err(map_p3_udp_socket_error))
    }

    fn set_unicast_hop_limit(
        &mut self,
        socket: Resource<UdpSocket>,
        value: u8,
    ) -> Result<core::result::Result<(), socket_types::ErrorCode>> {
        let Some(service) = self.runtime_state.network_service() else {
            return Ok(Err(socket_types::ErrorCode::Other(None)));
        };
        let socket = self.table.get_mut(&socket)?;
        Ok(socket
            .set_unicast_hop_limit(&service, value)
            .map_err(map_p3_udp_socket_error))
    }

    fn get_receive_buffer_size(
        &mut self,
        socket: Resource<UdpSocket>,
    ) -> Result<core::result::Result<u64, socket_types::ErrorCode>> {
        let socket = self.table.get_mut(&socket)?;
        Ok(socket
            .receive_buffer_size()
            .map_err(map_p3_udp_socket_error))
    }

    fn set_receive_buffer_size(
        &mut self,
        socket: Resource<UdpSocket>,
        value: u64,
    ) -> Result<core::result::Result<(), socket_types::ErrorCode>> {
        let socket = self.table.get_mut(&socket)?;
        Ok(socket
            .set_receive_buffer_size(value)
            .map_err(map_p3_udp_socket_error))
    }

    fn get_send_buffer_size(
        &mut self,
        socket: Resource<UdpSocket>,
    ) -> Result<core::result::Result<u64, socket_types::ErrorCode>> {
        let socket = self.table.get_mut(&socket)?;
        Ok(socket.send_buffer_size().map_err(map_p3_udp_socket_error))
    }

    fn set_send_buffer_size(
        &mut self,
        socket: Resource<UdpSocket>,
        value: u64,
    ) -> Result<core::result::Result<(), socket_types::ErrorCode>> {
        let socket = self.table.get_mut(&socket)?;
        Ok(socket
            .set_send_buffer_size(value)
            .map_err(map_p3_udp_socket_error))
    }

    fn drop(&mut self, resource: Resource<UdpSocket>) -> Result<()> {
        self.table.delete(resource)?;
        self.retire_sockets();
        Ok(())
    }
}

impl<CpuImpl, Net, StorageImpl, U> wasi::sockets::types::HostTcpSocketWithStore<U>
    for HasSelf<StoreData<CpuImpl, Net, StorageImpl>>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    async fn connect(
        accessor: &Accessor<U, Self>,
        socket: Resource<TcpSocket>,
        remote_address: socket_types::IpSocketAddress,
    ) -> Result<core::result::Result<(), socket_types::ErrorCode>> {
        // The connect runs with the store, and the socket, released:
        // the socket is admitted and marked here, and fetched again to
        // take the connection the await produced.
        let admitted = accessor.with(|mut access| {
            let store = access.get();
            let has_tcp_authority = has_wasi_network_rights(
                store.process_authority(),
                crate::NetworkAuthorityRights::TCP,
            );
            let service = store.runtime_state.network_service();
            let socket = store.table.get_mut(&socket)?;
            if !has_tcp_authority {
                return Ok(Err(socket_types::ErrorCode::AccessDenied));
            }
            let Some(service) = service else {
                return Ok(Err(socket_types::ErrorCode::Other(None)));
            };
            let remote_address = match parse_p3_tcp_socket_address(remote_address, socket.family) {
                Ok(address) => address,
                Err(error) => return Ok(Err(error)),
            };
            Ok::<_, wasmtime::Error>(
                socket
                    .start_p3_connect()
                    .map(|connect| (connect, service, remote_address)),
            )
        })?;
        let (connect, service, remote_address) = match admitted {
            Ok(admitted) => admitted,
            Err(error) => return Ok(Err(error)),
        };
        let (guard, outcome) = connect.run(&service, remote_address).await;
        accessor.with(|mut access| {
            // A socket the guest dropped meanwhile takes the failed
            // lookup's trap, and `outcome` its connection with it, which
            // retires the stream.
            let socket = access.get().table.get_mut(&socket)?;
            Ok(socket.finish_p3_connect(guard, remote_address, outcome))
        })
    }

    fn listen(
        mut access: Access<'_, U, Self>,
        socket_resource: Resource<TcpSocket>,
    ) -> Result<core::result::Result<StreamReader<Resource<TcpSocket>>, socket_types::ErrorCode>>
    {
        let socket = access.get().table.get_mut(&socket_resource)?;
        if !socket.may_listen() {
            return Ok(Err(socket_types::ErrorCode::InvalidState));
        }
        let request = socket.listen_request();
        if !has_wasi_network_rights(
            access.get().process_authority(),
            wasi_tcp_bind_rights(request.local_address.port),
        ) {
            return Ok(Err(socket_types::ErrorCode::AccessDenied));
        }
        let Some(service) = access.get().runtime_state.network_service() else {
            return Ok(Err(socket_types::ErrorCode::Other(None)));
        };
        let spawner = access.get().spawner().clone();
        let getter = access.getter();
        // The listen task answers the socket, which adopts the listener
        // on arrival, and the stream, which accepts on it.
        let (stream_answer, stream_listen) = oneshot::channel();
        let producer = TcpListenStreamProducer::new(
            access.get().table.get(&socket_resource)?,
            stream_listen,
            service.clone(),
            getter,
            spawner.clone(),
        );
        let stream = StreamReader::new(&mut access, producer)?;
        let retire = access.get().table.get(&socket_resource)?.retire.clone();
        let Ok(answer) = spawn_listen(&spawner, service, retire, request, stream_answer) else {
            return Ok(Err(socket_types::ErrorCode::OutOfMemory));
        };
        access.get().table.get_mut(&socket_resource)?.pending_listen = Some(answer);
        Ok(Ok(stream))
    }

    fn send(
        mut access: Access<'_, U, Self>,
        socket: Resource<TcpSocket>,
        mut bytes: StreamReader<u8>,
    ) -> Result<FutureReader<core::result::Result<(), socket_types::ErrorCode>>> {
        if !has_wasi_network_rights(
            access.get().process_authority(),
            crate::NetworkAuthorityRights::TCP,
        ) {
            bytes.close(&mut access)?;
            return FutureReader::new(&mut access, async {
                Ok::<_, wasmtime::Error>(Err::<(), socket_types::ErrorCode>(
                    socket_types::ErrorCode::AccessDenied,
                ))
            });
        }
        let connection = access.get().table.get_mut(&socket)?.connection();
        let Some(service) = access.get().runtime_state.network_service() else {
            bytes.close(&mut access)?;
            return FutureReader::new(&mut access, async {
                Ok::<_, wasmtime::Error>(Err::<(), socket_types::ErrorCode>(
                    socket_types::ErrorCode::Other(None),
                ))
            });
        };
        let (tx, rx) = oneshot::channel();
        bytes.pipe(&mut access, tcp_write_consumer(connection, service, tx))?;
        FutureReader::new(&mut access, async move {
            match rx.await {
                Ok(result) => Ok::<_, wasmtime::Error>(result),
                Err(_) => Ok::<_, wasmtime::Error>(Ok::<(), socket_types::ErrorCode>(())),
            }
        })
    }

    fn receive(
        mut access: Access<'_, U, Self>,
        socket: Resource<TcpSocket>,
    ) -> Result<(
        StreamReader<u8>,
        FutureReader<core::result::Result<(), socket_types::ErrorCode>>,
    )> {
        if !has_wasi_network_rights(
            access.get().process_authority(),
            crate::NetworkAuthorityRights::TCP,
        ) {
            let stream = StreamReader::new(&mut access, Vec::<u8>::new())?;
            let future = FutureReader::new(&mut access, async {
                Ok::<_, wasmtime::Error>(Err::<(), socket_types::ErrorCode>(
                    socket_types::ErrorCode::AccessDenied,
                ))
            })?;
            return Ok((stream, future));
        }
        let connection = access.get().table.get_mut(&socket)?.connection();
        let Some(service) = access.get().runtime_state.network_service() else {
            let stream = StreamReader::new(&mut access, Vec::<u8>::new())?;
            let future = FutureReader::new(&mut access, async {
                Ok::<_, wasmtime::Error>(Err::<(), socket_types::ErrorCode>(
                    socket_types::ErrorCode::Other(None),
                ))
            })?;
            return Ok((stream, future));
        };
        let (tx, rx) = oneshot::channel();
        let stream = StreamReader::new(&mut access, tcp_read_producer(connection, service, tx))?;
        let future = FutureReader::new(&mut access, async move {
            match rx.await {
                Ok(result) => Ok::<_, wasmtime::Error>(result),
                Err(_) => Ok::<_, wasmtime::Error>(Ok::<(), socket_types::ErrorCode>(())),
            }
        })?;
        Ok((stream, future))
    }
}

impl<CpuImpl, Net, StorageImpl, U> wasi::sockets::types::HostUdpSocketWithStore<U>
    for HasSelf<StoreData<CpuImpl, Net, StorageImpl>>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    async fn send(
        accessor: &Accessor<U, Self>,
        socket: Resource<UdpSocket>,
        bytes: Vec<u8>,
        remote_address: Option<socket_types::IpSocketAddress>,
    ) -> Result<core::result::Result<(), socket_types::ErrorCode>> {
        let has_udp_authority = accessor.with(|mut access| {
            Ok::<_, wasmtime::Error>(has_wasi_network_rights(
                access.get().process_authority(),
                crate::NetworkAuthorityRights::UDP,
            ))
        })?;
        if !has_udp_authority {
            return Ok(Err(socket_types::ErrorCode::AccessDenied));
        }
        // The send runs with the store, and the socket, released: it is
        // admitted here, and an implicit bind it needs fetches the socket
        // again to install the binding the await produced.
        let admitted = accessor.with(|mut access| {
            let store = access.get();
            let service = store.runtime_state.network_service();
            let socket = store.table.get_mut(&socket)?;
            let Some(service) = service else {
                return Ok(Err(socket_types::ErrorCode::Other(None)));
            };
            let remote_address = match remote_address {
                Some(address) => match parse_p3_udp_socket_address(address, socket.family) {
                    Ok(address) => Some(address),
                    Err(error) => return Ok(Err(map_p3_udp_socket_error(error))),
                },
                None => None,
            };
            Ok::<_, wasmtime::Error>(
                socket
                    .start_send(bytes.len(), remote_address)
                    .map(|send| (send, service))
                    .map_err(map_p3_udp_socket_error),
            )
        })?;
        let (UdpSend { target, binding }, service) = match admitted {
            Ok(admitted) => admitted,
            Err(error) => return Ok(Err(error)),
        };
        let binding = match binding {
            UdpSendBinding::Bound(binding) => binding,
            UdpSendBinding::Unbound(bind) => {
                let (guard, outcome) = bind.run(&service).await;
                let installed = accessor.with(|mut access| {
                    // A socket the guest dropped meanwhile takes the
                    // failed lookup's trap, and `outcome` its binding
                    // with it, which retires the kernel socket.
                    let socket = access.get().table.get_mut(&socket)?;
                    Ok::<_, wasmtime::Error>(socket.finish_implicit_bind(guard, outcome))
                })?;
                match installed {
                    Ok(binding) => binding,
                    Err(error) => return Ok(Err(map_p3_udp_socket_error(error))),
                }
            }
        };
        Ok(send_on(&service, &binding, target, &bytes, u64::MAX)
            .await
            .map_err(map_p3_udp_socket_error))
    }

    async fn receive(
        accessor: &Accessor<U, Self>,
        socket: Resource<UdpSocket>,
    ) -> Result<
        core::result::Result<(Vec<u8>, socket_types::IpSocketAddress), socket_types::ErrorCode>,
    > {
        let has_udp_authority = accessor.with(|mut access| {
            Ok::<_, wasmtime::Error>(has_wasi_network_rights(
                access.get().process_authority(),
                crate::NetworkAuthorityRights::UDP,
            ))
        })?;
        if !has_udp_authority {
            return Ok(Err(socket_types::ErrorCode::AccessDenied));
        }
        let admitted = accessor.with(|mut access| {
            let store = access.get();
            let service = store.runtime_state.network_service();
            let socket = store.table.get(&socket)?;
            let Some(service) = service else {
                return Ok(Err(socket_types::ErrorCode::Other(None)));
            };
            Ok::<_, wasmtime::Error>(
                socket
                    .start_receive(None)
                    .map(|receive| (receive, service))
                    .map_err(map_p3_udp_socket_error),
            )
        })?;
        let (receive, service) = match admitted {
            Ok(admitted) => admitted,
            Err(error) => return Ok(Err(error)),
        };
        let result = receive_on(&service, receive, u64::MAX)
            .await
            .map(|datagram| {
                (
                    Vec::from(datagram.bytes),
                    format_p3_udp_socket_address(datagram.remote_address),
                )
            })
            .map_err(map_p3_udp_socket_error);
        Ok(result)
    }
}

pub(super) fn parse_p3_tcp_socket_address(
    address: socket_types::IpSocketAddress,
    family: WasiTcpSocketFamily,
) -> core::result::Result<WasiTcpSocketAddress, socket_types::ErrorCode> {
    match (family, address) {
        (WasiTcpSocketFamily::Ipv4, socket_types::IpSocketAddress::Ipv4(address)) => {
            Ok(WasiTcpSocketAddress {
                address: WasiTcpIpAddress::Ipv4(crate::Ipv4Address::new([
                    address.address.0,
                    address.address.1,
                    address.address.2,
                    address.address.3,
                ])),
                port: address.port,
            })
        }
        (WasiTcpSocketFamily::Ipv6, socket_types::IpSocketAddress::Ipv6(address)) => {
            let segments = [
                address.address.0,
                address.address.1,
                address.address.2,
                address.address.3,
                address.address.4,
                address.address.5,
                address.address.6,
                address.address.7,
            ];
            let mut octets = [0; 16];
            for (index, segment) in segments.into_iter().enumerate() {
                let [high, low] = segment.to_be_bytes();
                octets[index * 2] = high;
                octets[index * 2 + 1] = low;
            }
            Ok(WasiTcpSocketAddress {
                address: WasiTcpIpAddress::Ipv6(Ipv6Address::new(octets)),
                port: address.port,
            })
        }
        (WasiTcpSocketFamily::Ipv4, socket_types::IpSocketAddress::Ipv6(_)) => {
            Err(socket_types::ErrorCode::NotSupported)
        }
        (WasiTcpSocketFamily::Ipv6, socket_types::IpSocketAddress::Ipv4(_)) => {
            Err(socket_types::ErrorCode::NotSupported)
        }
    }
}

pub(super) fn format_p3_tcp_socket_address(
    address: WasiTcpSocketAddress,
) -> socket_types::IpSocketAddress {
    match address.address {
        WasiTcpIpAddress::Ipv4(ip) => {
            let [a, b, c, d] = ip.octets();
            socket_types::IpSocketAddress::Ipv4(socket_types::Ipv4SocketAddress {
                port: address.port,
                address: (a, b, c, d),
            })
        }
        WasiTcpIpAddress::Ipv6(ip) => {
            let octets = ip.octets();
            let segment =
                |index: usize| u16::from_be_bytes([octets[index * 2], octets[index * 2 + 1]]);
            socket_types::IpSocketAddress::Ipv6(socket_types::Ipv6SocketAddress {
                port: address.port,
                flow_info: 0,
                address: (
                    segment(0),
                    segment(1),
                    segment(2),
                    segment(3),
                    segment(4),
                    segment(5),
                    segment(6),
                    segment(7),
                ),
                scope_id: 0,
            })
        }
    }
}

pub(super) fn map_p3_tcp_error(error: crate::TcpError) -> socket_types::ErrorCode {
    match error.kind {
        crate::TcpErrorKind::UnresolvedHost | crate::TcpErrorKind::Unavailable => {
            socket_types::ErrorCode::RemoteUnreachable
        }
        crate::TcpErrorKind::Timeout => socket_types::ErrorCode::Timeout,
        crate::TcpErrorKind::ConnectionReset => socket_types::ErrorCode::ConnectionReset,
        crate::TcpErrorKind::ConnectionAborted => socket_types::ErrorCode::ConnectionAborted,
        crate::TcpErrorKind::PermissionDenied => socket_types::ErrorCode::AccessDenied,
        crate::TcpErrorKind::Internal => socket_types::ErrorCode::Other(None),
    }
}

pub(super) fn map_p3_udp_family(
    family: socket_types::IpAddressFamily,
) -> core::result::Result<WasiUdpSocketFamily, WasiUdpSocketError> {
    match family {
        socket_types::IpAddressFamily::Ipv4 => Ok(WasiUdpSocketFamily::Ipv4),
        socket_types::IpAddressFamily::Ipv6 => Ok(WasiUdpSocketFamily::Ipv6),
    }
}

pub(super) fn format_p3_udp_family(family: WasiUdpSocketFamily) -> socket_types::IpAddressFamily {
    match family {
        WasiUdpSocketFamily::Ipv4 => socket_types::IpAddressFamily::Ipv4,
        WasiUdpSocketFamily::Ipv6 => socket_types::IpAddressFamily::Ipv6,
    }
}

pub(super) fn parse_p3_udp_socket_address(
    address: socket_types::IpSocketAddress,
    family: WasiUdpSocketFamily,
) -> core::result::Result<WasiUdpSocketAddress, WasiUdpSocketError> {
    match (family, address) {
        (WasiUdpSocketFamily::Ipv4, socket_types::IpSocketAddress::Ipv4(address)) => {
            Ok(WasiUdpSocketAddress {
                address: crate::NetworkIpAddress::Ipv4(crate::Ipv4Address::new([
                    address.address.0,
                    address.address.1,
                    address.address.2,
                    address.address.3,
                ])),
                port: address.port,
            })
        }
        (WasiUdpSocketFamily::Ipv6, socket_types::IpSocketAddress::Ipv6(address)) => {
            let segments = [
                address.address.0,
                address.address.1,
                address.address.2,
                address.address.3,
                address.address.4,
                address.address.5,
                address.address.6,
                address.address.7,
            ];
            let mut octets = [0; 16];
            for (index, segment) in segments.into_iter().enumerate() {
                let [high, low] = segment.to_be_bytes();
                octets[index * 2] = high;
                octets[index * 2 + 1] = low;
            }
            Ok(WasiUdpSocketAddress {
                address: crate::NetworkIpAddress::Ipv6(Ipv6Address::new(octets)),
                port: address.port,
            })
        }
        (WasiUdpSocketFamily::Ipv4, socket_types::IpSocketAddress::Ipv6(_)) => {
            Err(WasiUdpSocketError::NotSupported)
        }
        (WasiUdpSocketFamily::Ipv6, socket_types::IpSocketAddress::Ipv4(_)) => {
            Err(WasiUdpSocketError::NotSupported)
        }
    }
}

pub(super) fn format_p3_udp_socket_address(
    address: WasiUdpSocketAddress,
) -> socket_types::IpSocketAddress {
    match address.address {
        crate::NetworkIpAddress::Ipv4(ip) => {
            let [a, b, c, d] = ip.octets();
            socket_types::IpSocketAddress::Ipv4(socket_types::Ipv4SocketAddress {
                port: address.port,
                address: (a, b, c, d),
            })
        }
        crate::NetworkIpAddress::Ipv6(ip) => {
            let octets = ip.octets();
            let segments: [u16; 8] = core::array::from_fn(|index| {
                u16::from_be_bytes([octets[index * 2], octets[index * 2 + 1]])
            });
            socket_types::IpSocketAddress::Ipv6(socket_types::Ipv6SocketAddress {
                port: address.port,
                flow_info: 0,
                address: (
                    segments[0],
                    segments[1],
                    segments[2],
                    segments[3],
                    segments[4],
                    segments[5],
                    segments[6],
                    segments[7],
                ),
                scope_id: 0,
            })
        }
    }
}

pub(super) fn map_p3_udp_socket_error(error: WasiUdpSocketError) -> socket_types::ErrorCode {
    match error {
        WasiUdpSocketError::NotSupported => socket_types::ErrorCode::NotSupported,
        WasiUdpSocketError::InvalidArgument => socket_types::ErrorCode::InvalidArgument,
        WasiUdpSocketError::InvalidState => socket_types::ErrorCode::InvalidState,
        WasiUdpSocketError::AddressNotBindable => socket_types::ErrorCode::AddressNotBindable,
        WasiUdpSocketError::DatagramTooLarge => socket_types::ErrorCode::DatagramTooLarge,
        WasiUdpSocketError::WouldBlock
        | WasiUdpSocketError::Backend(crate::UdpError {
            kind: crate::UdpErrorKind::Timeout,
            ..
        }) => socket_types::ErrorCode::Timeout,
        WasiUdpSocketError::Backend(_) => socket_types::ErrorCode::Other(None),
    }
}

impl<CpuImpl, Net, StorageImpl> wasi::sockets::ip_name_lookup::Host
    for StoreData<CpuImpl, Net, StorageImpl>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
}

impl<CpuImpl, Net, StorageImpl, U> wasi::sockets::ip_name_lookup::HostWithStore<U>
    for HasSelf<StoreData<CpuImpl, Net, StorageImpl>>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    async fn resolve_addresses(
        accessor: &Accessor<U, Self>,
        name: String,
    ) -> Result<core::result::Result<Vec<socket_types::IpAddress>, ip_name_lookup::ErrorCode>> {
        let (has_dns_authority, service) = accessor.with(|mut access| {
            let store = access.get();
            Ok::<_, wasmtime::Error>((
                has_wasi_network_rights(
                    store.process_authority(),
                    crate::NetworkAuthorityRights::DNS,
                ),
                store.runtime_state.network_service(),
            ))
        })?;
        if !has_dns_authority {
            return Ok(Err(ip_name_lookup::ErrorCode::AccessDenied));
        }
        let Some(service) = service else {
            return Ok(Err(ip_name_lookup::ErrorCode::TemporaryResolverFailure));
        };
        Ok(service
            .dns_resolve(&name, u64::MAX)
            .await
            .map(|addresses| addresses.into_iter().map(format_p3_ip_address).collect())
            .map_err(map_p3_dns_error))
    }
}

pub(super) fn format_p3_ip_address(address: crate::NetworkIpAddress) -> socket_types::IpAddress {
    match address {
        crate::NetworkIpAddress::Ipv4(address) => {
            let [a, b, c, d] = address.octets();
            socket_types::IpAddress::Ipv4((a, b, c, d))
        }
        crate::NetworkIpAddress::Ipv6(address) => {
            socket_types::IpAddress::Ipv6(ipv6_address_groups(address))
        }
    }
}

/// Splits an IPv6 address into the eight big-endian 16-bit groups the
/// `wasi:sockets` `ipv6-address` tuple carries.
pub(in crate::wasmtime_adapter) fn ipv6_address_groups(
    address: helios_netstack::Ipv6Address,
) -> (u16, u16, u16, u16, u16, u16, u16, u16) {
    let octets = address.octets();
    let group = |index: usize| u16::from_be_bytes([octets[index * 2], octets[index * 2 + 1]]);
    (
        group(0),
        group(1),
        group(2),
        group(3),
        group(4),
        group(5),
        group(6),
        group(7),
    )
}

pub(super) fn map_p3_dns_error(error: crate::DnsError) -> ip_name_lookup::ErrorCode {
    match error.kind {
        crate::DnsErrorKind::UnresolvedHost => ip_name_lookup::ErrorCode::NameUnresolvable,
        crate::DnsErrorKind::Timeout | crate::DnsErrorKind::Unavailable => {
            ip_name_lookup::ErrorCode::TemporaryResolverFailure
        }
        crate::DnsErrorKind::Internal => ip_name_lookup::ErrorCode::Other(None),
    }
}
