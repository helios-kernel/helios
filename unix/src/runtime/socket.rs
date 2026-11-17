//! Socket objects shared by every ABI: TCP, UDP and socket-pair
//! descriptors, their family and their options, over the network boundary
//! [`SocketNetwork`] a platform implements.
//!
//! # Ownership and concurrency
//!
//! A [`Socket`] is a value a descriptor slot owns. Its state (which
//! endpoint it has, its options) changes only through `&mut` on that slot,
//! so the descriptor table's owner serialises every change and no lock is
//! involved. What duplicated slots share is the network endpoint itself:
//! each endpoint is held through an [`Arc`] of its owner type, and the
//! endpoint is retired when the last slot holding it is dropped.
//!
//! Option numbers, socket type numbers and error codes are ABI encodings;
//! each ABI maps its own onto the typed [`SocketFlag`], [`SocketSize`],
//! [`SocketTime`] and [`SocketOptionError`] here.

use alloc::sync::Arc;
use bytes::Bytes;
use core::convert::Infallible;
use helios_sync::{ByteReader, ByteWriter, byte_channel};
use thiserror::Error;

/// What a platform's network gives the socket objects: its endpoint
/// handles, its address type, the per-socket limits its stack has, and
/// the retirement of an endpoint when its last owner goes away.
///
/// Every other socket operation (connect, send, receive, readiness) is the
/// platform's own call on the handle a socket reports through
/// [`Socket::handle`]; the objects here never perform I/O.
///
/// The close calls are synchronous because the owner that ends an
/// endpoint's life is a `Drop`, which cannot await. They are called from
/// whichever processor drops the last owner.
pub trait SocketNetwork: Clone + Send + Sync + 'static {
    /// A remote or local IP address on this network.
    type Address: Copy + Send + Sync + 'static;
    type TcpStream: Copy + Send + Sync + 'static;
    type TcpListener: Copy + Send + Sync + 'static;
    type UdpSocket: Copy + Send + Sync + 'static;

    /// What the stack reserves and stamps per socket.
    const LIMITS: SocketLimits;

    /// Retires a connected stream.
    fn tcp_close(&self, stream: Self::TcpStream);

    /// Retires a listener, releasing its local port.
    fn tcp_listener_close(&self, listener: Self::TcpListener);

    /// Retires a datagram socket.
    fn udp_close(&self, socket: Self::UdpSocket);
}

/// The per-socket facts of a network stack that options report.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SocketLimits {
    /// The receive buffer the stack really reserves; a larger requested
    /// receive buffer is clamped to it so a read-back reports the
    /// effective size.
    pub receive_buffer_bytes: u64,
    /// The stack's per-socket transmit buffer, the ceiling of a requested
    /// send buffer.
    pub send_buffer_bytes: u64,
    /// The TTL / hop limit a new socket's packets carry.
    pub default_hop_limit: u8,
}

/// A network with no endpoints, for a descriptor table whose platform has
/// no network. Its sockets can still be socket pairs, which need none.
#[derive(Clone, Copy, Debug)]
pub enum NoNetwork {}

impl SocketNetwork for NoNetwork {
    type Address = Infallible;
    type TcpStream = Infallible;
    type TcpListener = Infallible;
    type UdpSocket = Infallible;

    /// No stack reserves anything, so nothing clamps a requested buffer;
    /// 64 is the default TTL Linux's `ip_default_ttl` and RFC 1700 give.
    const LIMITS: SocketLimits = SocketLimits {
        receive_buffer_bytes: u64::MAX,
        send_buffer_bytes: u64::MAX,
        default_hop_limit: 64,
    };

    fn tcp_close(&self, stream: Infallible) {
        match stream {}
    }

    fn tcp_listener_close(&self, listener: Infallible) {
        match listener {}
    }

    fn udp_close(&self, socket: Infallible) {
        match socket {}
    }
}

/// The address family a socket was opened with.
///
/// `socket(AF_INET6, ...)` and `socket(AF_INET, ...)` produce sockets that
/// differ in what a wildcard bind means and in which peer addresses they
/// accept, so the family is socket identity and travels with the socket
/// through every state transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SocketFamily {
    Ipv4,
    Ipv6,
}

/// Whether a socket carries a byte stream or datagrams.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SocketKind {
    Stream,
    Datagram,
}

/// The transport protocol an IP socket speaks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportProtocol {
    Tcp,
    Udp,
}

impl TransportProtocol {
    /// The protocol's IANA-assigned IP protocol number, the value every
    /// socket ABI reports for it (TCP 6, UDP 17).
    pub const fn number(self) -> u8 {
        match self {
            Self::Tcp => 6,
            Self::Udp => 17,
        }
    }
}

/// A TCP stream a socket owns, retired when the last socket holding it
/// goes away: closing the descriptor, replacing its state, and dropping
/// the table a process takes with it when it exits all end here.
pub struct OwnedTcpStream<Net: SocketNetwork> {
    network: Net,
    stream: Net::TcpStream,
}

impl<Net: SocketNetwork> OwnedTcpStream<Net> {
    pub fn new(network: Net, stream: Net::TcpStream) -> Arc<Self> {
        Arc::new(Self { network, stream })
    }

    pub fn id(&self) -> Net::TcpStream {
        self.stream
    }
}

impl<Net: SocketNetwork> Drop for OwnedTcpStream<Net> {
    fn drop(&mut self) {
        self.network.tcp_close(self.stream);
    }
}

/// A TCP listener a socket owns, with the lifetime rule of
/// [`OwnedTcpStream`]; retiring it releases its local port.
pub struct OwnedTcpListener<Net: SocketNetwork> {
    network: Net,
    listener: Net::TcpListener,
}

impl<Net: SocketNetwork> OwnedTcpListener<Net> {
    pub fn new(network: Net, listener: Net::TcpListener) -> Arc<Self> {
        Arc::new(Self { network, listener })
    }

    pub fn id(&self) -> Net::TcpListener {
        self.listener
    }
}

impl<Net: SocketNetwork> Drop for OwnedTcpListener<Net> {
    fn drop(&mut self) {
        self.network.tcp_listener_close(self.listener);
    }
}

/// A datagram socket a socket owns, with the lifetime rule of
/// [`OwnedTcpStream`].
pub struct OwnedUdpSocket<Net: SocketNetwork> {
    network: Net,
    socket: Net::UdpSocket,
}

impl<Net: SocketNetwork> OwnedUdpSocket<Net> {
    pub fn new(network: Net, socket: Net::UdpSocket) -> Arc<Self> {
        Arc::new(Self { network, socket })
    }

    pub fn id(&self) -> Net::UdpSocket {
        self.socket
    }
}

impl<Net: SocketNetwork> Drop for OwnedUdpSocket<Net> {
    fn drop(&mut self) {
        self.network.udp_close(self.socket);
    }
}

#[derive(Clone)]
pub enum TcpSocket<Net: SocketNetwork> {
    Unconnected {
        family: SocketFamily,
        options: SocketOptions,
    },
    Bound {
        family: SocketFamily,
        local_port: u16,
        options: SocketOptions,
    },
    Listening {
        family: SocketFamily,
        listener: Arc<OwnedTcpListener<Net>>,
        local_port: u16,
        options: SocketOptions,
    },
    Connected {
        family: SocketFamily,
        stream: Arc<OwnedTcpStream<Net>>,
        peer_address: Net::Address,
        peer_port: u16,
        options: SocketOptions,
    },
}

#[derive(Clone)]
pub enum UdpSocket<Net: SocketNetwork> {
    Unbound {
        family: SocketFamily,
        options: SocketOptions,
    },
    Bound {
        family: SocketFamily,
        socket: Arc<OwnedUdpSocket<Net>>,
        local_port: u16,
        options: SocketOptions,
    },
}

/// A socket descriptor's object.
#[derive(Clone)]
pub enum Socket<Net: SocketNetwork> {
    Tcp(TcpSocket<Net>),
    Udp(UdpSocket<Net>),
    /// One end of a connected pair: what it reads is what the other end
    /// writes. `carry` holds bytes a read took from the channel and did
    /// not hand over yet.
    Pair {
        reader: ByteReader,
        writer: ByteWriter,
        carry: Bytes,
        options: SocketOptions,
        kind: SocketKind,
    },
}

/// The network endpoint a socket currently owns.
///
/// Its traits are written out because a derive would bound them on the
/// network itself rather than on its handle types.
pub enum SocketHandle<Net: SocketNetwork> {
    TcpStream(Net::TcpStream),
    TcpListener(Net::TcpListener),
    UdpSocket(Net::UdpSocket),
}

impl<Net: SocketNetwork> Clone for SocketHandle<Net> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<Net: SocketNetwork> Copy for SocketHandle<Net> {}

impl<Net: SocketNetwork> PartialEq for SocketHandle<Net>
where
    Net::TcpStream: PartialEq,
    Net::TcpListener: PartialEq,
    Net::UdpSocket: PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::TcpStream(a), Self::TcpStream(b)) => a == b,
            (Self::TcpListener(a), Self::TcpListener(b)) => a == b,
            (Self::UdpSocket(a), Self::UdpSocket(b)) => a == b,
            _ => false,
        }
    }
}

impl<Net: SocketNetwork> Eq for SocketHandle<Net>
where
    Net::TcpStream: Eq,
    Net::TcpListener: Eq,
    Net::UdpSocket: Eq,
{
}

impl<Net: SocketNetwork> core::fmt::Debug for SocketHandle<Net>
where
    Net::TcpStream: core::fmt::Debug,
    Net::TcpListener: core::fmt::Debug,
    Net::UdpSocket: core::fmt::Debug,
{
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TcpStream(stream) => formatter.debug_tuple("TcpStream").field(stream).finish(),
            Self::TcpListener(listener) => formatter
                .debug_tuple("TcpListener")
                .field(listener)
                .finish(),
            Self::UdpSocket(socket) => formatter.debug_tuple("UdpSocket").field(socket).finish(),
        }
    }
}

impl<Net: SocketNetwork> Socket<Net> {
    /// A TCP socket with no endpoint yet.
    pub fn tcp(family: SocketFamily) -> Self {
        Self::Tcp(TcpSocket::Unconnected {
            family,
            options: SocketOptions::for_network::<Net>(),
        })
    }

    /// A UDP socket with no endpoint yet.
    pub fn udp(family: SocketFamily) -> Self {
        Self::Udp(UdpSocket::Unbound {
            family,
            options: SocketOptions::for_network::<Net>(),
        })
    }

    /// Two connected ends of a socket pair.
    pub fn pair(kind: SocketKind) -> (Self, Self) {
        let (left_writer, right_reader) = byte_channel();
        let (right_writer, left_reader) = byte_channel();
        let end = |reader, writer| Self::Pair {
            reader,
            writer,
            carry: Bytes::new(),
            options: SocketOptions::for_network::<Net>(),
            kind,
        };
        (
            end(left_reader, left_writer),
            end(right_reader, right_writer),
        )
    }

    pub fn options(&self) -> &SocketOptions {
        match self {
            Self::Tcp(socket) => socket.options(),
            Self::Udp(socket) => socket.options(),
            Self::Pair { options, .. } => options,
        }
    }

    fn options_mut(&mut self) -> &mut SocketOptions {
        match self {
            Self::Tcp(socket) => socket.options_mut(),
            Self::Udp(socket) => socket.options_mut(),
            Self::Pair { options, .. } => options,
        }
    }

    pub fn kind(&self) -> SocketKind {
        match self {
            Self::Tcp(_) => SocketKind::Stream,
            Self::Udp(_) => SocketKind::Datagram,
            Self::Pair { kind, .. } => *kind,
        }
    }

    /// The IP transport the socket speaks; a socket pair speaks none.
    pub fn protocol(&self) -> Option<TransportProtocol> {
        match self {
            Self::Tcp(_) => Some(TransportProtocol::Tcp),
            Self::Udp(_) => Some(TransportProtocol::Udp),
            Self::Pair { .. } => None,
        }
    }

    /// The network endpoint the socket owns, or `None` before it has
    /// connected, listened or bound, and for a socket pair.
    pub fn handle(&self) -> Option<SocketHandle<Net>> {
        match self {
            Self::Tcp(TcpSocket::Connected { stream, .. }) => {
                Some(SocketHandle::TcpStream(stream.id()))
            }
            Self::Tcp(TcpSocket::Listening { listener, .. }) => {
                Some(SocketHandle::TcpListener(listener.id()))
            }
            Self::Udp(UdpSocket::Bound { socket, .. }) => {
                Some(SocketHandle::UdpSocket(socket.id()))
            }
            Self::Tcp(TcpSocket::Unconnected { .. } | TcpSocket::Bound { .. })
            | Self::Udp(UdpSocket::Unbound { .. })
            | Self::Pair { .. } => None,
        }
    }

    /// Records a boolean option.
    ///
    /// `SO_KEEPALIVE` has no keepalive timer behind it, and `TCP_NODELAY`
    /// cleared is a request for Nagle's algorithm, which the stack does not
    /// implement: it transmits as soon as the window allows. Accepting
    /// either would report a behaviour change that never happens, so both
    /// are [`SocketOptionError::Unsupported`]; clearing keepalive and
    /// setting nodelay describe what the stack already does and succeed.
    pub fn set_flag(&mut self, flag: SocketFlag, value: bool) -> Result<(), SocketOptionError> {
        if matches!(
            (flag, value),
            (SocketFlag::KeepAlive, true) | (SocketFlag::NoDelay, false)
        ) {
            return Err(SocketOptionError::Unsupported);
        }
        self.options_mut().set_flag(flag, value);
        Ok(())
    }

    /// Records a sized option. Buffer sizes clamp to what the network
    /// reserves per socket ([`SocketNetwork::LIMITS`]), so a read-back
    /// reports the effective value; a TTL outside `1..=255` is refused.
    /// The new TTL reaches a live endpoint only through the platform's
    /// own call on [`Socket::handle`].
    pub fn set_size(&mut self, option: SocketSize, size: u64) -> Result<(), SocketOptionError> {
        let options = self.options_mut();
        match option {
            SocketSize::ReceiveBuffer => {
                options.receive_buffer_size = size.min(Net::LIMITS.receive_buffer_bytes);
            }
            SocketSize::SendBuffer => {
                options.send_buffer_size = size.min(Net::LIMITS.send_buffer_bytes);
            }
            SocketSize::ReceiveLowWater => options.receive_low_water = size,
            SocketSize::SendLowWater => options.send_low_water = size,
            SocketSize::Ttl => {
                options.ttl = u8::try_from(size)
                    .ok()
                    .filter(|ttl| *ttl != 0)
                    .ok_or(SocketOptionError::Invalid)?;
            }
            SocketSize::MulticastTtlV4 => options.multicast_ttl_v4 = size,
        }
        Ok(())
    }

    /// Records a timeout option; `None` clears it.
    pub fn set_time(&mut self, option: SocketTime, time: Option<u64>) {
        let options = self.options_mut();
        match option {
            SocketTime::ReceiveTimeout => options.receive_timeout = time,
            SocketTime::SendTimeout => options.send_timeout = time,
            SocketTime::ConnectTimeout => options.connect_timeout = time,
            SocketTime::AcceptTimeout => options.accept_timeout = time,
            SocketTime::Linger => options.linger = time,
        }
    }
}

impl<Net: SocketNetwork> TcpSocket<Net> {
    pub fn options(&self) -> &SocketOptions {
        match self {
            Self::Unconnected { options, .. }
            | Self::Bound { options, .. }
            | Self::Listening { options, .. }
            | Self::Connected { options, .. } => options,
        }
    }

    fn options_mut(&mut self) -> &mut SocketOptions {
        match self {
            Self::Unconnected { options, .. }
            | Self::Bound { options, .. }
            | Self::Listening { options, .. }
            | Self::Connected { options, .. } => options,
        }
    }

    pub fn family(&self) -> SocketFamily {
        match self {
            Self::Unconnected { family, .. }
            | Self::Bound { family, .. }
            | Self::Listening { family, .. }
            | Self::Connected { family, .. } => *family,
        }
    }
}

impl<Net: SocketNetwork> UdpSocket<Net> {
    pub fn options(&self) -> &SocketOptions {
        match self {
            Self::Unbound { options, .. } | Self::Bound { options, .. } => options,
        }
    }

    fn options_mut(&mut self) -> &mut SocketOptions {
        match self {
            Self::Unbound { options, .. } | Self::Bound { options, .. } => options,
        }
    }

    pub fn family(&self) -> SocketFamily {
        match self {
            Self::Unbound { family, .. } | Self::Bound { family, .. } => *family,
        }
    }
}

/// A boolean socket option.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SocketFlag {
    ReusePort,
    ReuseAddr,
    NoDelay,
    DontRoute,
    OnlyV6,
    Broadcast,
    MulticastLoopV4,
    MulticastLoopV6,
    Promiscuous,
    Listening,
    KeepAlive,
    OobInline,
}

impl SocketFlag {
    const fn bit(self) -> u16 {
        1 << self as u16
    }
}

/// A sized socket option.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SocketSize {
    ReceiveBuffer,
    SendBuffer,
    ReceiveLowWater,
    SendLowWater,
    Ttl,
    MulticastTtlV4,
}

/// A timeout socket option, in nanoseconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SocketTime {
    ReceiveTimeout,
    SendTimeout,
    ConnectTimeout,
    AcceptTimeout,
    Linger,
}

/// Why a socket refused an option.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum SocketOptionError {
    /// The stack has no mechanism for the requested behaviour.
    #[error("the network stack does not implement the requested socket behaviour")]
    Unsupported,
    /// The value is outside the option's range.
    #[error("socket option value out of range")]
    Invalid,
}

/// The default a new socket's send and receive buffers report: 64 KiB, the
/// value WASIX programs have always read back before setting one.
const DEFAULT_BUFFER_BYTES: u64 = 64 * 1024;
/// `SO_RCVLOWAT` and `SO_SNDLOWAT` default to 1 (socket(7)).
const DEFAULT_LOW_WATER_BYTES: u64 = 1;
/// `IP_MULTICAST_TTL` defaults to 1, keeping multicast on the local
/// network (ip(7)).
const DEFAULT_MULTICAST_TTL: u64 = 1;

/// A socket's options, as the socket records them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SocketOptions {
    flags: u16,
    receive_buffer_size: u64,
    send_buffer_size: u64,
    receive_low_water: u64,
    send_low_water: u64,
    ttl: u8,
    multicast_ttl_v4: u64,
    receive_timeout: Option<u64>,
    send_timeout: Option<u64>,
    connect_timeout: Option<u64>,
    accept_timeout: Option<u64>,
    linger: Option<u64>,
}

impl SocketOptions {
    /// The options a new socket on `Net` starts with.
    pub const fn for_network<Net: SocketNetwork>() -> Self {
        Self {
            flags: 0,
            receive_buffer_size: DEFAULT_BUFFER_BYTES,
            send_buffer_size: DEFAULT_BUFFER_BYTES,
            receive_low_water: DEFAULT_LOW_WATER_BYTES,
            send_low_water: DEFAULT_LOW_WATER_BYTES,
            ttl: Net::LIMITS.default_hop_limit,
            multicast_ttl_v4: DEFAULT_MULTICAST_TTL,
            receive_timeout: None,
            send_timeout: None,
            connect_timeout: None,
            accept_timeout: None,
            linger: None,
        }
    }

    fn set_flag(&mut self, flag: SocketFlag, value: bool) {
        if value {
            self.flags |= flag.bit();
        } else {
            self.flags &= !flag.bit();
        }
    }

    pub const fn flag(&self, flag: SocketFlag) -> bool {
        self.flags & flag.bit() != 0
    }

    pub const fn size(&self, option: SocketSize) -> u64 {
        match option {
            SocketSize::ReceiveBuffer => self.receive_buffer_size,
            SocketSize::SendBuffer => self.send_buffer_size,
            SocketSize::ReceiveLowWater => self.receive_low_water,
            SocketSize::SendLowWater => self.send_low_water,
            SocketSize::Ttl => self.ttl as u64,
            SocketSize::MulticastTtlV4 => self.multicast_ttl_v4,
        }
    }

    pub const fn time(&self, option: SocketTime) -> Option<u64> {
        match option {
            SocketTime::ReceiveTimeout => self.receive_timeout,
            SocketTime::SendTimeout => self.send_timeout,
            SocketTime::ConnectTimeout => self.connect_timeout,
            SocketTime::AcceptTimeout => self.accept_timeout,
            SocketTime::Linger => self.linger,
        }
    }

    /// The TTL / hop limit this socket's packets carry.
    pub const fn hop_limit(&self) -> u8 {
        self.ttl
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};

    /// A network whose endpoints are numbers and which counts closes.
    #[derive(Clone)]
    struct CountingNetwork(Arc<AtomicUsize>);

    impl SocketNetwork for CountingNetwork {
        type Address = [u8; 4];
        type TcpStream = u64;
        type TcpListener = u64;
        type UdpSocket = u64;

        const LIMITS: SocketLimits = SocketLimits {
            receive_buffer_bytes: 4096,
            send_buffer_bytes: 8192,
            default_hop_limit: 64,
        };

        fn tcp_close(&self, _: u64) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
        fn tcp_listener_close(&self, _: u64) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
        fn udp_close(&self, _: u64) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn the_endpoint_is_retired_when_the_last_duplicate_drops() {
        let closes = Arc::new(AtomicUsize::new(0));
        let network = CountingNetwork(closes.clone());
        let socket = Socket::Tcp(TcpSocket::Connected {
            family: SocketFamily::Ipv4,
            stream: OwnedTcpStream::new(network, 7),
            peer_address: [10, 0, 2, 2],
            peer_port: 80,
            options: SocketOptions::for_network::<CountingNetwork>(),
        });
        let duplicate = socket.clone();
        assert_eq!(socket.handle(), Some(SocketHandle::TcpStream(7)));
        drop(socket);
        assert_eq!(closes.load(Ordering::Relaxed), 0);
        drop(duplicate);
        assert_eq!(closes.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn buffer_sizes_clamp_to_the_network_and_ttl_is_range_checked() {
        let mut socket = Socket::<CountingNetwork>::udp(SocketFamily::Ipv6);
        socket
            .set_size(SocketSize::ReceiveBuffer, u64::MAX)
            .unwrap();
        socket.set_size(SocketSize::SendBuffer, 100).unwrap();
        assert_eq!(socket.options().size(SocketSize::ReceiveBuffer), 4096);
        assert_eq!(socket.options().size(SocketSize::SendBuffer), 100);
        assert_eq!(
            socket.set_size(SocketSize::Ttl, 0),
            Err(SocketOptionError::Invalid)
        );
        assert_eq!(
            socket.set_size(SocketSize::Ttl, 256),
            Err(SocketOptionError::Invalid)
        );
        assert_eq!(socket.options().hop_limit(), 64);
        socket.set_size(SocketSize::Ttl, 9).unwrap();
        assert_eq!(socket.options().hop_limit(), 9);
        assert_eq!(socket.handle(), None);
    }

    #[test]
    fn flags_refuse_behaviour_the_stack_lacks() {
        let mut socket = Socket::<CountingNetwork>::tcp(SocketFamily::Ipv4);
        assert_eq!(
            socket.set_flag(SocketFlag::KeepAlive, true),
            Err(SocketOptionError::Unsupported)
        );
        assert_eq!(
            socket.set_flag(SocketFlag::NoDelay, false),
            Err(SocketOptionError::Unsupported)
        );
        socket.set_flag(SocketFlag::NoDelay, true).unwrap();
        socket.set_flag(SocketFlag::Broadcast, true).unwrap();
        assert!(socket.options().flag(SocketFlag::NoDelay));
        assert!(socket.options().flag(SocketFlag::Broadcast));
        assert!(!socket.options().flag(SocketFlag::KeepAlive));
        socket.set_flag(SocketFlag::Broadcast, false).unwrap();
        assert!(!socket.options().flag(SocketFlag::Broadcast));
    }

    #[test]
    fn a_pair_without_a_network_carries_bytes_between_its_ends() {
        let (left, right) = Socket::<NoNetwork>::pair(SocketKind::Stream);
        let (Socket::Pair { writer, .. }, Socket::Pair { reader, kind, .. }) = (&left, &right)
        else {
            unreachable!("a pair's ends are pair sockets");
        };
        assert_eq!(*kind, SocketKind::Stream);
        assert!(writer.is_writable());
        assert!(!reader.is_readable());
        assert_eq!(left.protocol(), None);
        assert_eq!(left.handle(), None);
    }
}
