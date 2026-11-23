//! Socket objects shared by every ABI: TCP, UDP and socket-pair
//! descriptors, their family and their options, over the network boundary
//! [`SocketNetwork`] a platform implements.
//!
//! # Ownership and concurrency
//!
//! [`Socket`] is an `Arc`-shared open socket description, matching POSIX
//! `dup`/`dup2`/`fork` semantics: cloning a [`Socket`] shares the same
//! state machine, options, endpoint and socket-pair carry buffer across every
//! duplicate descriptor, and the endpoint is retired when the last owner
//! drops.
//!
//! - Synchronous state and option reads/transitions (`tcp_state`, `udp_state`,
//!   `with_tcp_mut`, `with_udp_mut`, `set_flag`, `set_size`, `set_time`,
//!   `pair_read_probe`, and `carry` updates) take a short `spin::Mutex` and
//!   never cross an `.await`.
//! - Async socket-pair receives (`recv_pair`) serialize concurrent readers
//!   across duplicates with a [`helios_sync::RawMutex`] (`try_lock` when
//!   non-blocking, `lock().await` when blocking) and take the short `carry`
//!   spin lock only before/after `.await`.
//!
//! Option numbers, socket type numbers and error codes are ABI encodings;
//! each ABI maps its own onto the typed [`SocketFlag`], [`SocketSize`],
//! [`SocketTime`] and [`SocketOptionError`] here.

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use bytes::Bytes;
use core::convert::Infallible;
use core::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use helios_sync::{ByteReader, ByteWriter, RawMutex, TryRead, byte_channel};
use spin::Mutex;
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
    type PacketSocket: Copy + Send + Sync + 'static;

    /// What the stack reserves and stamps per socket.
    const LIMITS: SocketLimits;

    /// Retires a connected stream.
    fn tcp_close(&self, stream: Self::TcpStream);

    /// Retires a listener, releasing its local port.
    fn tcp_listener_close(&self, listener: Self::TcpListener);

    /// Retires a datagram socket.
    fn udp_close(&self, socket: Self::UdpSocket);

    /// Retires a link-layer packet tap socket.
    fn packet_close(&self, socket: Self::PacketSocket);
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
    type PacketSocket = Infallible;

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

    fn packet_close(&self, socket: Infallible) {
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

/// Whether a socket carries a byte stream, datagrams, or raw link frames.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SocketKind {
    Stream,
    Datagram,
    Raw,
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

/// A link-layer packet socket tap retired when its last owner drops.
pub struct OwnedPacketSocket<Net: SocketNetwork> {
    network: Net,
    socket: Net::PacketSocket,
}

impl<Net: SocketNetwork> OwnedPacketSocket<Net> {
    pub fn new(network: Net, socket: Net::PacketSocket) -> Arc<Self> {
        Arc::new(Self { network, socket })
    }

    pub fn id(&self) -> Net::PacketSocket {
        self.socket
    }
}

impl<Net: SocketNetwork> Drop for OwnedPacketSocket<Net> {
    fn drop(&mut self) {
        self.network.packet_close(self.socket);
    }
}

/// Shared state of a netlink socket (`AF_NETLINK`).
#[derive(Clone, Debug)]
pub struct NetlinkSocket {
    pub protocol: u32,
    pub port_id: u32,
    pub groups: u32,
    pub rx_queue: VecDeque<Bytes>,
    pub options: SocketOptions,
}

/// Shared state of a link-layer packet socket (`AF_PACKET`).
#[derive(Clone)]
pub struct PacketSocket<Net: SocketNetwork> {
    pub handle: Arc<OwnedPacketSocket<Net>>,
    /// EtherType filter in host byte order (`0x0003` = `ETH_P_ALL`, `0x0800` = `ETH_P_IP`).
    pub protocol: u16,
    /// Bound interface index (`0` = any, `1` = `lo`, `2` = `eth0`).
    pub ifindex: u32,
    pub options: SocketOptions,
}

#[derive(Clone)]
pub enum TcpSocket<Net: SocketNetwork> {
    Unconnected {
        family: SocketFamily,
        options: SocketOptions,
    },
    Bound {
        family: SocketFamily,
        local_address: Net::Address,
        local_port: u16,
        options: SocketOptions,
    },
    Listening {
        family: SocketFamily,
        listener: Arc<OwnedTcpListener<Net>>,
        local_address: Net::Address,
        local_port: u16,
        options: SocketOptions,
    },
    Connecting {
        family: SocketFamily,
        stream: Arc<OwnedTcpStream<Net>>,
        peer_address: Net::Address,
        peer_port: u16,
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
        local_address: Net::Address,
        local_port: u16,
        peer: Option<(Net::Address, u16)>,
        options: SocketOptions,
    },
}

/// Error returned by [`Socket::recv_pair`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PairRecvError {
    /// The socket is not a socket pair.
    NotPair,
    /// Non-blocking receive found no buffered bytes and did not block.
    WouldBlock,
}

enum SocketBody<Net: SocketNetwork> {
    Tcp(Mutex<TcpSocket<Net>>),
    Udp(Mutex<UdpSocket<Net>>),
    Pair {
        reader: ByteReader,
        writer: ByteWriter,
        carry: Mutex<Bytes>,
        recv_lock: RawMutex,
        options: Mutex<SocketOptions>,
    },
    Netlink(Mutex<NetlinkSocket>),
    Packet(Mutex<PacketSocket<Net>>),
    UnixUnbound {
        options: Mutex<SocketOptions>,
    },
    RawIp {
        family: SocketFamily,
        protocol: i32,
        options: Mutex<SocketOptions>,
    },
}

struct SharedSocket<Net: SocketNetwork> {
    kind: SocketKind,
    protocol: Option<TransportProtocol>,
    nonblocking: AtomicBool,
    pending_error: AtomicI32,
    shutdown_read: AtomicBool,
    shutdown_write: AtomicBool,
    body: SocketBody<Net>,
}

/// Shared open socket description held in a descriptor entry.
///
/// # Concurrency contract
///
/// Clones share one [`SharedSocket`] via `Arc`. No operation fans out to other
/// processors, and no interrupt handler touches a `Socket` lock.
///
/// - **Lock-free**: immutable metadata, channel-end clones, and atomic status
///   words (`same_description`, `kind`, `protocol`, `is_tcp`, `is_udp`,
///   `is_pair`, `pair_ends`, `pair_writer`, `is_nonblocking`,
///   `set_nonblocking`, `take_pending_error`, `set_pending_error`,
///   `is_shutdown_read`, `mark_shutdown_read`, `is_shutdown_write`,
///   `mark_shutdown_write`).
/// - **Synchronous `spin::Mutex`** (short critical section, never held across
///   `.await`): state and option reads/transitions (`tcp_state`, `udp_state`,
///   `with_tcp_mut`, `with_udp_mut`, `options`, `set_flag`, `set_size`,
///   `set_time`, `handle`, `family`, `pair_read_probe`, and `carry` updates).
/// - **Async [`helios_sync::RawMutex`]**: `recv_pair` serializes concurrent
///   socket-pair readers across duplicates (`try_lock` when non-blocking,
///   `lock().await` when blocking) and acquires the `carry` spin lock only
///   synchronously before and after `.await`.
pub struct Socket<Net: SocketNetwork>(Arc<SharedSocket<Net>>);

impl<Net: SocketNetwork> Clone for Socket<Net> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

/// The network endpoint a socket currently owns.
///
/// Its traits are written out because a derive would bound them on the
/// network itself rather than on its handle types.
pub enum SocketHandle<Net: SocketNetwork> {
    TcpStream(Net::TcpStream),
    TcpListener(Net::TcpListener),
    UdpSocket(Net::UdpSocket),
    PacketSocket(Net::PacketSocket),
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
    Net::PacketSocket: PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::TcpStream(a), Self::TcpStream(b)) => a == b,
            (Self::TcpListener(a), Self::TcpListener(b)) => a == b,
            (Self::UdpSocket(a), Self::UdpSocket(b)) => a == b,
            (Self::PacketSocket(a), Self::PacketSocket(b)) => a == b,
            _ => false,
        }
    }
}

impl<Net: SocketNetwork> Eq for SocketHandle<Net>
where
    Net::TcpStream: Eq,
    Net::TcpListener: Eq,
    Net::UdpSocket: Eq,
    Net::PacketSocket: Eq,
{
}

impl<Net: SocketNetwork> core::fmt::Debug for SocketHandle<Net>
where
    Net::TcpStream: core::fmt::Debug,
    Net::TcpListener: core::fmt::Debug,
    Net::UdpSocket: core::fmt::Debug,
    Net::PacketSocket: core::fmt::Debug,
{
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TcpStream(stream) => formatter.debug_tuple("TcpStream").field(stream).finish(),
            Self::TcpListener(listener) => formatter
                .debug_tuple("TcpListener")
                .field(listener)
                .finish(),
            Self::UdpSocket(socket) => formatter.debug_tuple("UdpSocket").field(socket).finish(),
            Self::PacketSocket(socket) => {
                formatter.debug_tuple("PacketSocket").field(socket).finish()
            }
        }
    }
}

fn take_or_peek_carry(carry: &mut Bytes, max_bytes: usize, peek: bool) -> Bytes {
    if peek {
        carry.slice(..carry.len().min(max_bytes))
    } else if carry.len() <= max_bytes {
        core::mem::take(carry)
    } else {
        carry.split_to(max_bytes)
    }
}

impl<Net: SocketNetwork> Socket<Net> {
    /// A TCP socket with no endpoint yet.
    pub fn tcp(family: SocketFamily) -> Self {
        Self::from_tcp(TcpSocket::Unconnected {
            family,
            options: SocketOptions::for_network::<Net>(),
        })
    }

    /// A UDP socket with no endpoint yet.
    pub fn udp(family: SocketFamily) -> Self {
        Self::from_udp(UdpSocket::Unbound {
            family,
            options: SocketOptions::for_network::<Net>(),
        })
    }

    /// Wraps an existing TCP socket state in a shared open description.
    pub fn from_tcp(tcp: TcpSocket<Net>) -> Self {
        Self(Arc::new(SharedSocket {
            kind: SocketKind::Stream,
            protocol: Some(TransportProtocol::Tcp),
            nonblocking: AtomicBool::new(false),
            pending_error: AtomicI32::new(0),
            shutdown_read: AtomicBool::new(false),
            shutdown_write: AtomicBool::new(false),
            body: SocketBody::Tcp(Mutex::new(tcp)),
        }))
    }

    /// Wraps an existing UDP socket state in a shared open description.
    pub fn from_udp(udp: UdpSocket<Net>) -> Self {
        Self(Arc::new(SharedSocket {
            kind: SocketKind::Datagram,
            protocol: Some(TransportProtocol::Udp),
            nonblocking: AtomicBool::new(false),
            pending_error: AtomicI32::new(0),
            shutdown_read: AtomicBool::new(false),
            shutdown_write: AtomicBool::new(false),
            body: SocketBody::Udp(Mutex::new(udp)),
        }))
    }

    /// An unbound Unix-domain socket (e.g. `socket(AF_UNIX, SOCK_DGRAM, 0)`,
    /// used by `if_nametoindex` / `SIOCGIF*` ioctls).
    pub fn unix_unbound(kind: SocketKind) -> Self {
        Self(Arc::new(SharedSocket {
            kind,
            protocol: None,
            nonblocking: AtomicBool::new(false),
            pending_error: AtomicI32::new(0),
            shutdown_read: AtomicBool::new(false),
            shutdown_write: AtomicBool::new(false),
            body: SocketBody::UnixUnbound {
                options: Mutex::new(SocketOptions::for_network::<Net>()),
            },
        }))
    }

    /// Whether this socket is an unbound `AF_UNIX` socket.
    pub fn is_unix_unbound(&self) -> bool {
        matches!(self.0.body, SocketBody::UnixUnbound { .. })
    }

    /// A raw IP control socket (`socket(AF_INET|AF_INET6, SOCK_RAW, proto)`),
    /// used by `udhcpc` and similar tools for `SIOCGIF*` interface queries.
    pub fn raw_ip(family: SocketFamily, protocol: i32) -> Self {
        Self(Arc::new(SharedSocket {
            kind: SocketKind::Raw,
            protocol: None,
            nonblocking: AtomicBool::new(false),
            pending_error: AtomicI32::new(0),
            shutdown_read: AtomicBool::new(false),
            shutdown_write: AtomicBool::new(false),
            body: SocketBody::RawIp {
                family,
                protocol,
                options: Mutex::new(SocketOptions::for_network::<Net>()),
            },
        }))
    }

    /// Raw IP protocol number if this is a `RawIp` socket.
    pub fn raw_ip_protocol(&self) -> Option<i32> {
        match self.0.body {
            SocketBody::RawIp { protocol, .. } => Some(protocol),
            _ => None,
        }
    }

    /// Two connected ends of a socket pair.
    pub fn pair(kind: SocketKind) -> (Self, Self) {
        let (left_writer, right_reader) = byte_channel();
        let (right_writer, left_reader) = byte_channel();
        let end = |reader, writer| {
            Self(Arc::new(SharedSocket {
                kind,
                protocol: None,
                nonblocking: AtomicBool::new(false),
                pending_error: AtomicI32::new(0),
                shutdown_read: AtomicBool::new(false),
                shutdown_write: AtomicBool::new(false),
                body: SocketBody::Pair {
                    reader,
                    writer,
                    carry: Mutex::new(Bytes::new()),
                    recv_lock: RawMutex::new(),
                    options: Mutex::new(SocketOptions::for_network::<Net>()),
                },
            }))
        };
        (
            end(left_reader, left_writer),
            end(right_reader, right_writer),
        )
    }

    /// A netlink socket (`AF_NETLINK`) speaking `protocol` (e.g. `NETLINK_ROUTE`).
    pub fn netlink(kind: SocketKind, protocol: u32) -> Self {
        Self(Arc::new(SharedSocket {
            kind,
            protocol: None,
            nonblocking: AtomicBool::new(false),
            pending_error: AtomicI32::new(0),
            shutdown_read: AtomicBool::new(false),
            shutdown_write: AtomicBool::new(false),
            body: SocketBody::Netlink(Mutex::new(NetlinkSocket {
                protocol,
                port_id: 0,
                groups: 0,
                rx_queue: VecDeque::new(),
                options: SocketOptions::for_network::<Net>(),
            })),
        }))
    }

    /// A link-layer packet socket (`AF_PACKET`) backed by a host tap handle.
    pub fn packet(kind: SocketKind, handle: Arc<OwnedPacketSocket<Net>>, protocol: u16) -> Self {
        Self(Arc::new(SharedSocket {
            kind,
            protocol: None,
            nonblocking: AtomicBool::new(false),
            pending_error: AtomicI32::new(0),
            shutdown_read: AtomicBool::new(false),
            shutdown_write: AtomicBool::new(false),
            body: SocketBody::Packet(Mutex::new(PacketSocket {
                handle,
                protocol,
                ifindex: 0,
                options: SocketOptions::for_network::<Net>(),
            })),
        }))
    }

    /// Whether this socket is a netlink socket.
    pub fn is_netlink(&self) -> bool {
        matches!(self.0.body, SocketBody::Netlink(_))
    }

    /// Whether this socket is a link-layer packet socket.
    pub fn is_packet(&self) -> bool {
        matches!(self.0.body, SocketBody::Packet(_))
    }

    /// Snapshot of the netlink socket state, or `None` if not netlink.
    pub fn netlink_state(&self) -> Option<NetlinkSocket> {
        match &self.0.body {
            SocketBody::Netlink(nl) => Some(nl.lock().clone()),
            _ => None,
        }
    }

    /// Runs `f` with mutable access to the netlink socket state.
    pub fn with_netlink_mut<R>(&self, f: impl FnOnce(&mut NetlinkSocket) -> R) -> Option<R> {
        match &self.0.body {
            SocketBody::Netlink(nl) => Some(f(&mut nl.lock())),
            _ => None,
        }
    }

    /// Snapshot of the packet socket state, or `None` if not a packet socket.
    pub fn packet_state(&self) -> Option<PacketSocket<Net>> {
        match &self.0.body {
            SocketBody::Packet(pkt) => Some(pkt.lock().clone()),
            _ => None,
        }
    }

    /// Runs `f` with mutable access to the packet socket state.
    pub fn with_packet_mut<R>(&self, f: impl FnOnce(&mut PacketSocket<Net>) -> R) -> Option<R> {
        match &self.0.body {
            SocketBody::Packet(pkt) => Some(f(&mut pkt.lock())),
            _ => None,
        }
    }

    /// Whether `O_NONBLOCK` / `SOCK_NONBLOCK` is set on this open description.
    pub fn is_nonblocking(&self) -> bool {
        self.0.nonblocking.load(Ordering::Acquire)
    }

    /// Sets or clears `O_NONBLOCK` on this open description.
    pub fn set_nonblocking(&self, nonblocking: bool) {
        self.0.nonblocking.store(nonblocking, Ordering::Release);
    }

    /// Reads and clears the latched asynchronous socket error (`SO_ERROR`).
    pub fn take_pending_error(&self) -> i32 {
        self.0.pending_error.swap(0, Ordering::AcqRel)
    }

    /// Latches an asynchronous socket error (`SO_ERROR`) for a later read.
    pub fn set_pending_error(&self, errno: i32) {
        self.0.pending_error.store(errno, Ordering::Release);
    }

    /// Whether the receive half has been shut down locally (`SHUT_RD`).
    pub fn is_shutdown_read(&self) -> bool {
        self.0.shutdown_read.load(Ordering::Acquire)
    }

    /// Marks the receive half as locally shut down (`SHUT_RD`).
    pub fn mark_shutdown_read(&self) {
        self.0.shutdown_read.store(true, Ordering::Release);
    }

    /// Whether the send half has been shut down locally (`SHUT_WR`).
    pub fn is_shutdown_write(&self) -> bool {
        self.0.shutdown_write.load(Ordering::Acquire)
    }

    /// Marks the send half as locally shut down (`SHUT_WR`).
    pub fn mark_shutdown_write(&self) {
        self.0.shutdown_write.store(true, Ordering::Release);
    }

    /// The IP address family of this socket, or `None` for non-IP sockets.
    pub fn family(&self) -> Option<SocketFamily> {
        match &self.0.body {
            SocketBody::Tcp(tcp) => Some(tcp.lock().family()),
            SocketBody::Udp(udp) => Some(udp.lock().family()),
            SocketBody::RawIp { family, .. } => Some(*family),
            SocketBody::Pair { .. }
            | SocketBody::Netlink(_)
            | SocketBody::Packet(_)
            | SocketBody::UnixUnbound { .. } => None,
        }
    }

    /// Whether `self` and `other` refer to the same open socket description.
    pub fn same_description(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }

    /// Whether this socket is a TCP socket.
    pub fn is_tcp(&self) -> bool {
        matches!(self.0.body, SocketBody::Tcp(_))
    }

    /// Whether this socket is a UDP socket.
    pub fn is_udp(&self) -> bool {
        matches!(self.0.body, SocketBody::Udp(_))
    }

    /// Whether this socket is a socket pair.
    pub fn is_pair(&self) -> bool {
        matches!(self.0.body, SocketBody::Pair { .. })
    }

    /// Snapshot of the TCP socket state, or `None` if this is not a TCP socket.
    pub fn tcp_state(&self) -> Option<TcpSocket<Net>> {
        match &self.0.body {
            SocketBody::Tcp(tcp) => Some(tcp.lock().clone()),
            _ => None,
        }
    }

    /// Snapshot of the UDP socket state, or `None` if this is not a UDP socket.
    pub fn udp_state(&self) -> Option<UdpSocket<Net>> {
        match &self.0.body {
            SocketBody::Udp(udp) => Some(udp.lock().clone()),
            _ => None,
        }
    }

    /// Runs `f` synchronously against the TCP socket state under the short
    /// socket lock. Never `.await` inside `f`.
    pub fn with_tcp_mut<R>(&self, f: impl FnOnce(&mut TcpSocket<Net>) -> R) -> Option<R> {
        match &self.0.body {
            SocketBody::Tcp(tcp) => Some(f(&mut tcp.lock())),
            _ => None,
        }
    }

    /// Runs `f` synchronously against the UDP socket state under the short
    /// socket lock. Never `.await` inside `f`.
    pub fn with_udp_mut<R>(&self, f: impl FnOnce(&mut UdpSocket<Net>) -> R) -> Option<R> {
        match &self.0.body {
            SocketBody::Udp(udp) => Some(f(&mut udp.lock())),
            _ => None,
        }
    }

    /// The pair's channel ends, or `None` if this is not a socket pair.
    pub fn pair_ends(&self) -> Option<(ByteReader, ByteWriter)> {
        match &self.0.body {
            SocketBody::Pair { reader, writer, .. } => Some((reader.clone(), writer.clone())),
            _ => None,
        }
    }

    /// The pair's writer end, or `None` if this is not a socket pair.
    pub fn pair_writer(&self) -> Option<ByteWriter> {
        match &self.0.body {
            SocketBody::Pair { writer, .. } => Some(writer.clone()),
            _ => None,
        }
    }

    /// Synchronous probe of a socket pair's reader and currently buffered
    /// `carry` byte count.
    pub fn pair_read_probe(&self) -> Option<(ByteReader, usize)> {
        match &self.0.body {
            SocketBody::Pair { reader, carry, .. } => Some((reader.clone(), carry.lock().len())),
            _ => None,
        }
    }

    /// Receives up to `max_bytes` from a socket pair, consuming or peeking
    /// shared `carry` leftovers across all duplicate descriptors.
    pub async fn recv_pair(
        &self,
        max_bytes: usize,
        nonblocking: bool,
        peek: bool,
    ) -> Result<Bytes, PairRecvError> {
        let SocketBody::Pair {
            reader,
            carry,
            recv_lock,
            ..
        } = &self.0.body
        else {
            return Err(PairRecvError::NotPair);
        };
        if max_bytes == 0 {
            return Ok(Bytes::new());
        }

        let _guard = if nonblocking {
            let Some(guard) = recv_lock.try_lock() else {
                return Err(PairRecvError::WouldBlock);
            };
            guard
        } else {
            recv_lock.lock().await
        };

        {
            let mut carry_guard = carry.lock();
            if !carry_guard.is_empty() {
                return Ok(take_or_peek_carry(&mut carry_guard, max_bytes, peek));
            }
        }

        if nonblocking {
            return match reader.try_read() {
                TryRead::Ready(bytes) => {
                    let mut carry_guard = carry.lock();
                    *carry_guard = bytes;
                    Ok(take_or_peek_carry(&mut carry_guard, max_bytes, peek))
                }
                TryRead::Eof => Ok(Bytes::new()),
                TryRead::Pending => Err(PairRecvError::WouldBlock),
            };
        }

        let bytes = reader.read().await.unwrap_or_default();
        let mut carry_guard = carry.lock();
        *carry_guard = bytes;
        Ok(take_or_peek_carry(&mut carry_guard, max_bytes, peek))
    }

    pub fn options(&self) -> SocketOptions {
        match &self.0.body {
            SocketBody::Tcp(tcp) => *tcp.lock().options(),
            SocketBody::Udp(udp) => *udp.lock().options(),
            SocketBody::Pair { options, .. }
            | SocketBody::UnixUnbound { options }
            | SocketBody::RawIp { options, .. } => *options.lock(),
            SocketBody::Netlink(nl) => nl.lock().options,
            SocketBody::Packet(pkt) => pkt.lock().options,
        }
    }

    fn with_options_mut<R>(&self, f: impl FnOnce(&mut SocketOptions) -> R) -> R {
        match &self.0.body {
            SocketBody::Tcp(tcp) => f(tcp.lock().options_mut()),
            SocketBody::Udp(udp) => f(udp.lock().options_mut()),
            SocketBody::Pair { options, .. }
            | SocketBody::UnixUnbound { options }
            | SocketBody::RawIp { options, .. } => f(&mut options.lock()),
            SocketBody::Netlink(nl) => f(&mut nl.lock().options),
            SocketBody::Packet(pkt) => f(&mut pkt.lock().options),
        }
    }

    pub fn kind(&self) -> SocketKind {
        self.0.kind
    }

    /// The IP transport the socket speaks; a socket pair speaks none.
    pub fn protocol(&self) -> Option<TransportProtocol> {
        self.0.protocol
    }

    /// The network endpoint the socket owns, or `None` before it has
    /// connected, listened or bound, and for a socket pair.
    pub fn handle(&self) -> Option<SocketHandle<Net>> {
        match &self.0.body {
            SocketBody::Tcp(tcp) => match &*tcp.lock() {
                TcpSocket::Connected { stream, .. } | TcpSocket::Connecting { stream, .. } => {
                    Some(SocketHandle::TcpStream(stream.id()))
                }
                TcpSocket::Listening { listener, .. } => {
                    Some(SocketHandle::TcpListener(listener.id()))
                }
                TcpSocket::Unconnected { .. } | TcpSocket::Bound { .. } => None,
            },
            SocketBody::Udp(udp) => match &*udp.lock() {
                UdpSocket::Bound { socket, .. } => Some(SocketHandle::UdpSocket(socket.id())),
                UdpSocket::Unbound { .. } => None,
            },
            SocketBody::Pair { .. }
            | SocketBody::Netlink(_)
            | SocketBody::UnixUnbound { .. }
            | SocketBody::RawIp { .. } => None,
            SocketBody::Packet(pkt) => Some(SocketHandle::PacketSocket(pkt.lock().handle.id())),
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
    pub fn set_flag(&self, flag: SocketFlag, value: bool) -> Result<(), SocketOptionError> {
        if matches!(
            (flag, value),
            (SocketFlag::KeepAlive, true) | (SocketFlag::NoDelay, false)
        ) {
            return Err(SocketOptionError::Unsupported);
        }
        self.with_options_mut(|options| options.set_flag(flag, value));
        Ok(())
    }

    /// Records a sized option. Buffer sizes clamp to what the network
    /// reserves per socket ([`SocketNetwork::LIMITS`]), so a read-back
    /// reports the effective value; a TTL outside `1..=255` is refused.
    /// The new TTL reaches a live endpoint only through the platform's
    /// own call on [`Socket::handle`].
    pub fn set_size(&self, option: SocketSize, size: u64) -> Result<(), SocketOptionError> {
        self.with_options_mut(|options| {
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
        })
    }

    /// Records a timeout option; `None` clears it.
    pub fn set_time(&self, option: SocketTime, time: Option<u64>) {
        self.with_options_mut(|options| match option {
            SocketTime::ReceiveTimeout => options.receive_timeout = time,
            SocketTime::SendTimeout => options.send_timeout = time,
            SocketTime::ConnectTimeout => options.connect_timeout = time,
            SocketTime::AcceptTimeout => options.accept_timeout = time,
            SocketTime::Linger => options.linger = time,
        });
    }
}

impl<Net: SocketNetwork> TcpSocket<Net> {
    pub fn options(&self) -> &SocketOptions {
        match self {
            Self::Unconnected { options, .. }
            | Self::Bound { options, .. }
            | Self::Listening { options, .. }
            | Self::Connecting { options, .. }
            | Self::Connected { options, .. } => options,
        }
    }

    fn options_mut(&mut self) -> &mut SocketOptions {
        match self {
            Self::Unconnected { options, .. }
            | Self::Bound { options, .. }
            | Self::Listening { options, .. }
            | Self::Connecting { options, .. }
            | Self::Connected { options, .. } => options,
        }
    }

    pub fn family(&self) -> SocketFamily {
        match self {
            Self::Unconnected { family, .. }
            | Self::Bound { family, .. }
            | Self::Listening { family, .. }
            | Self::Connecting { family, .. }
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
        type PacketSocket = u64;

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
        fn packet_close(&self, _: u64) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn the_endpoint_is_retired_when_the_last_duplicate_drops() {
        let closes = Arc::new(AtomicUsize::new(0));
        let network = CountingNetwork(closes.clone());
        let socket = Socket::from_tcp(TcpSocket::Connected {
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
        let socket = Socket::<CountingNetwork>::udp(SocketFamily::Ipv6);
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
        let socket = Socket::<CountingNetwork>::tcp(SocketFamily::Ipv4);
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
        let writer = left.pair_writer().expect("left end has a writer");
        let (reader, carry_len) = right.pair_read_probe().expect("right end has a reader");
        assert_eq!(carry_len, 0);
        assert_eq!(right.kind(), SocketKind::Stream);
        assert!(writer.is_writable());
        assert!(!reader.is_readable());
        assert_eq!(left.protocol(), None);
        assert_eq!(left.handle(), None);
    }

    #[test]
    fn duplicates_share_state_options_and_pair_carry() {
        let tcp = Socket::<CountingNetwork>::tcp(SocketFamily::Ipv4);
        let tcp_dup = tcp.clone();
        assert!(tcp.same_description(&tcp_dup));
        tcp.set_flag(SocketFlag::ReuseAddr, true).unwrap();
        assert!(tcp_dup.options().flag(SocketFlag::ReuseAddr));
        tcp.with_tcp_mut(|slot| {
            *slot = TcpSocket::Bound {
                family: SocketFamily::Ipv4,
                local_address: [127, 0, 0, 1],
                local_port: 8080,
                options: *slot.options(),
            };
        });
        assert!(matches!(
            tcp_dup.tcp_state(),
            Some(TcpSocket::Bound {
                local_address: [127, 0, 0, 1],
                local_port: 8080,
                ..
            })
        ));

        let (left, right) = Socket::<NoNetwork>::pair(SocketKind::Stream);
        let right_dup = right.clone();
        let writer = left.pair_writer().unwrap();
        assert!(matches!(
            writer.try_write(Bytes::from_static(b"abcdef")),
            helios_sync::TryWrite::Written
        ));
        let first = futures_lite::future::block_on(right.recv_pair(2, false, false)).unwrap();
        assert_eq!(&first[..], b"ab");
        assert_eq!(right_dup.pair_read_probe().unwrap().1, 4);
        let second = futures_lite::future::block_on(right_dup.recv_pair(10, true, false)).unwrap();
        assert_eq!(&second[..], b"cdef");
    }
}
