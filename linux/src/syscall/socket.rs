//! Linux socket system calls over the shared [`helios_unix::Socket`] objects.
//!
//! `helios-linux` stays `#![no_std]` and independent of `helios-kernel`: this
//! module decodes the Linux ABI (`sockaddr`, `msghdr`, `mmsghdr`, `setsockopt`
//! / `getsockopt`, `MSG_*` and `SOCK_*` flags) and delegates network I/O and
//! container authority checks through the [`Network`] trait.

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use bytes::Bytes;
use core::future::Future;
use helios_hal::fs::WritePosition;
use helios_unix::{
    OwnedPacketSocket, OwnedTcpListener, OwnedTcpStream, OwnedUdpSocket, PairRecvError, Socket,
    SocketFamily, SocketFlag, SocketKind, SocketNetwork, SocketOptionError, SocketSize, SocketTime,
    TcpSocket, TransportProtocol, UdpSocket,
};

use super::io::descriptor_errno;
use super::netlink::{self, AF_NETLINK, NETLINK_ROUTE};
use super::packet::{self, AF_PACKET, SockaddrLl};
use super::{
    Descriptor, Descriptors, EACCES, EBADF, EFAULT, EINVAL, EPERM, Entry, MAX_RW_COUNT, Process,
    Resources, UserMemory, errno,
};

// Linux UAPI address families (`include/linux/socket.h`).
pub const AF_UNSPEC: u16 = 0;
pub const AF_UNIX: u16 = 1;
pub const AF_INET: u16 = 2;
pub const AF_INET6: u16 = 10;

// Linux UAPI socket types and creation flags (`include/linux/net.h`).
const SOCK_STREAM: u32 = 1;
const SOCK_DGRAM: u32 = 2;
const SOCK_RAW: u32 = 3;
const SOCK_TYPE_MASK: u32 = 0x0f;
pub(crate) const SOCK_NONBLOCK: u32 = 0x0800;
const SOCK_CLOEXEC: u32 = 0x80000;

// Linux UAPI IP protocols (`include/uapi/linux/in.h`).
const IPPROTO_IP: i32 = 0;
const IPPROTO_TCP: i32 = 6;
const IPPROTO_UDP: i32 = 17;
const IPPROTO_IPV6: i32 = 41;

// Linux UAPI `MSG_*` flags (`include/linux/socket.h`).
const MSG_OOB: u32 = 0x01;
pub(crate) const MSG_PEEK: u32 = 0x02;
pub(crate) const MSG_TRUNC: u32 = 0x20;
pub(crate) const MSG_DONTWAIT: u32 = 0x40;
const MSG_WAITALL: u32 = 0x100;
const MSG_WAITFORONE: u32 = 0x10000;
const MSG_CMSG_CLOEXEC: u32 = 0x4000_0000;

// Linux UAPI `SHUT_*` constants.
const SHUT_RD: u32 = 0;
const SHUT_WR: u32 = 1;
const SHUT_RDWR: u32 = 2;

// Linux UAPI socket option levels and names (`include/uapi/asm-generic/socket.h`,
// `include/uapi/linux/in.h`, `include/uapi/linux/in6.h`, `include/uapi/linux/tcp.h`).
const SOL_SOCKET: i32 = 1;
const SO_REUSEADDR: i32 = 2;
const SO_TYPE: i32 = 3;
const SO_ERROR: i32 = 4;
const SO_DONTROUTE: i32 = 5;
const SO_BROADCAST: i32 = 6;
const SO_SNDBUF: i32 = 7;
const SO_RCVBUF: i32 = 8;
const SO_KEEPALIVE: i32 = 9;
const SO_OOBINLINE: i32 = 10;
const SO_LINGER: i32 = 13;
const SO_REUSEPORT: i32 = 15;
const SO_RCVLOWAT: i32 = 18;
const SO_SNDLOWAT: i32 = 19;
const SO_RCVTIMEO: i32 = 20;
const SO_SNDTIMEO: i32 = 21;
const SO_BINDTODEVICE: i32 = 25;
const SO_ACCEPTCONN: i32 = 30;
const SO_PROTOCOL: i32 = 38;
const SO_DOMAIN: i32 = 39;

const SOL_PACKET: i32 = 263;
const PACKET_AUXDATA: i32 = 8;

const TCP_NODELAY: i32 = 1;

const IP_TTL: i32 = 2;
const IP_MULTICAST_TTL: i32 = 33;
const IP_MULTICAST_LOOP: i32 = 34;
const IP_ADD_MEMBERSHIP: i32 = 35;
const IP_DROP_MEMBERSHIP: i32 = 36;

const IPV6_UNICAST_HOPS: i32 = 16;
const IPV6_MULTICAST_LOOP: i32 = 19;
const IPV6_ADD_MEMBERSHIP: i32 = 20;
const IPV6_DROP_MEMBERSHIP: i32 = 21;
const IPV6_V6ONLY: i32 = 26;

// Linux errno values (`include/uapi/asm-generic/errno.h`).
pub const EAGAIN: u64 = 11;
pub const ENODEV: u64 = 19;
pub const ESPIPE: u64 = 29;
pub const EPIPE: u64 = 32;
pub const ENOTSOCK: u64 = 88;
pub const EDESTADDRREQ: u64 = 89;
pub const EMSGSIZE: u64 = 90;
pub const EPROTOTYPE: u64 = 91;
pub const ENOPROTOOPT: u64 = 92;
pub const EPROTONOSUPPORT: u64 = 93;
pub const EOPNOTSUPP: u64 = 95;
pub const EAFNOSUPPORT: u64 = 97;
pub const EADDRINUSE: u64 = 98;
pub const EADDRNOTAVAIL: u64 = 99;
pub const ENETDOWN: u64 = 100;
pub const ENETUNREACH: u64 = 101;
pub const ECONNABORTED: u64 = 103;
pub const ECONNRESET: u64 = 104;
pub const EISCONN: u64 = 106;
pub const ENOTCONN: u64 = 107;
pub const ETIMEDOUT: u64 = 110;
pub const ECONNREFUSED: u64 = 111;
pub const EHOSTUNREACH: u64 = 113;
pub const EALREADY: u64 = 114;
pub const EINPROGRESS: u64 = 115;

// Linux socket flags for `socket`/`socketpair`/`accept4`.

/// Maximum `iovec` entries accepted in one `sendmsg` / `recvmsg` (`UIO_MAXIOV`).
const UIO_MAXIOV: usize = 1024;
/// Maximum `mmsghdr` entries accepted in one `sendmmsg` / `recvmmsg` (`UIO_MAXIOV`).
const MAX_MMSG: usize = 1024;

/// Size of `struct sockaddr_in` (16 bytes).
const SOCKADDR_IN_LEN: usize = 16;
/// Size of `struct sockaddr_in6` (28 bytes).
const SOCKADDR_IN6_LEN: usize = 28;
/// Size of `struct msghdr` on 64-bit Linux (56 bytes).
const MSGHDR_LEN: usize = 56;
/// Size of `struct mmsghdr` on 64-bit Linux (64 bytes).
const MMSGHDR_LEN: usize = 64;
/// Size of `struct iovec` on 64-bit Linux (16 bytes).
const IOVEC_LEN: usize = 16;
/// Maximum payload bytes copied per `sendfile` iteration.
const SENDFILE_CHUNK: usize = 65_536;

/// IPv4 or IPv6 address in host-neutral octet form.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpAddr {
    V4([u8; 4]),
    V6([u8; 16]),
}

impl IpAddr {
    pub const fn unspecified(family: SocketFamily) -> Self {
        match family {
            SocketFamily::Ipv4 => Self::V4([0; 4]),
            SocketFamily::Ipv6 => Self::V6([0; 16]),
        }
    }

    pub const fn family(self) -> SocketFamily {
        match self {
            Self::V4(_) => SocketFamily::Ipv4,
            Self::V6(_) => SocketFamily::Ipv6,
        }
    }
}

/// IP address paired with a transport port.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SocketAddr {
    pub ip: IpAddr,
    pub port: u16,
}

/// Progress of a non-blocking TCP connection attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectProgress {
    Pending,
    Connected,
}

/// Non-destructive readiness of one network socket.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SocketReady {
    pub readable: bool,
    pub writable: bool,
    pub hangup: bool,
}

/// Process identity and Linux capability flags needed by socket operations.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct SocketContext {
    pub pid: u32,
    pub cap_net_admin: bool,
    pub cap_net_raw: bool,
}

/// One IPv4 address + prefix length configured on the primary interface (`eth0`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ipv4InterfaceAddress {
    pub address: [u8; 4],
    pub prefix: u8,
}

/// One IPv4 route entry in the shared kernel routing table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ipv4RouteEntry {
    pub destination: [u8; 4],
    pub prefix: u8,
    pub gateway: Option<[u8; 4]>,
}

/// One raw link-layer frame received on an `AF_PACKET` socket.
#[derive(Clone, Debug)]
pub struct PacketFrameData {
    pub ifindex: u32,
    pub protocol: u16,
    pub bytes: Bytes,
    pub original_len: usize,
}

/// Network and container-authority boundary the Linux socket syscalls call.
///
/// Every `Err(u64)` carries a positive Linux errno (e.g. `EACCES`, `EPERM`,
/// `ECONNREFUSED`, `EAGAIN`).
pub trait Network<N: SocketNetwork> {
    fn to_ip(&self, address: N::Address) -> IpAddr;
    fn encode_ip(&self, ip: IpAddr) -> N::Address;

    fn check_tcp_open(&self) -> Result<(), u64> {
        Err(ENETDOWN)
    }

    fn check_udp_open(&self) -> Result<(), u64> {
        Err(ENETDOWN)
    }

    fn check_tcp_bind(&self, local_port: u16) -> Result<(), u64> {
        let _ = local_port;
        Err(ENETDOWN)
    }

    fn check_udp_bind(&self, local_port: u16) -> Result<(), u64> {
        let _ = local_port;
        Err(ENETDOWN)
    }

    fn tcp_listen(
        &self,
        local: SocketAddr,
        backlog: u16,
        hop_limit: u8,
    ) -> impl Future<Output = Result<(Arc<OwnedTcpListener<N>>, u16), u64>> + Send + '_ {
        let _ = (local, backlog, hop_limit);
        core::future::ready(Err(ENETDOWN))
    }

    fn tcp_accept(
        &self,
        listener: N::TcpListener,
        timeout_nanos: u64,
    ) -> impl Future<Output = Result<(Arc<OwnedTcpStream<N>>, SocketAddr), u64>> + Send + '_ {
        let _ = (listener, timeout_nanos);
        core::future::ready(Err(ENETDOWN))
    }

    fn tcp_connect(
        &self,
        remote: SocketAddr,
        local_port: u16,
        hop_limit: u8,
        timeout_nanos: u64,
    ) -> impl Future<Output = Result<Arc<OwnedTcpStream<N>>, u64>> + Send + '_ {
        let _ = (remote, local_port, hop_limit, timeout_nanos);
        core::future::ready(Err(ENETDOWN))
    }

    fn tcp_connect_start(
        &self,
        remote: SocketAddr,
        local_port: u16,
        hop_limit: u8,
    ) -> impl Future<Output = Result<(Arc<OwnedTcpStream<N>>, ConnectProgress), u64>> + Send + '_
    {
        let _ = (remote, local_port, hop_limit);
        core::future::ready(Err(ENETDOWN))
    }

    fn tcp_connect_poll(
        &self,
        stream: N::TcpStream,
    ) -> impl Future<Output = Result<ConnectProgress, u64>> + Send + '_ {
        let _ = stream;
        core::future::ready(Err(ENETDOWN))
    }

    fn tcp_local_endpoint(&self, stream: N::TcpStream) -> Result<Option<SocketAddr>, u64> {
        let _ = stream;
        Ok(None)
    }

    fn tcp_set_hop_limit(&self, stream: N::TcpStream, hop_limit: u8) -> Result<(), u64> {
        let _ = (stream, hop_limit);
        Ok(())
    }

    fn tcp_listener_set_hop_limit(
        &self,
        listener: N::TcpListener,
        hop_limit: u8,
    ) -> Result<(), u64> {
        let _ = (listener, hop_limit);
        Ok(())
    }

    fn tcp_read(
        &self,
        stream: N::TcpStream,
        max_bytes: u32,
        timeout_nanos: u64,
        peek: bool,
    ) -> impl Future<Output = Result<Option<Bytes>, u64>> + Send + '_ {
        let _ = (stream, max_bytes, timeout_nanos, peek);
        core::future::ready(Err(ENETDOWN))
    }

    fn tcp_write(
        &self,
        stream: N::TcpStream,
        bytes: Bytes,
        timeout_nanos: u64,
    ) -> impl Future<Output = Result<usize, u64>> + Send + '_ {
        let _ = (stream, bytes, timeout_nanos);
        core::future::ready(Err(ENETDOWN))
    }

    fn tcp_shutdown_send(
        &self,
        stream: N::TcpStream,
    ) -> impl Future<Output = Result<(), u64>> + Send + '_ {
        let _ = stream;
        core::future::ready(Err(ENETDOWN))
    }

    fn tcp_readiness(
        &self,
        stream: N::TcpStream,
    ) -> impl Future<Output = Result<SocketReady, u64>> + Send + '_ {
        let _ = stream;
        core::future::ready(Err(ENETDOWN))
    }

    fn tcp_listener_readiness(
        &self,
        listener: N::TcpListener,
    ) -> impl Future<Output = Result<SocketReady, u64>> + Send + '_ {
        let _ = listener;
        core::future::ready(Err(ENETDOWN))
    }

    fn udp_bind(
        &self,
        local: SocketAddr,
        hop_limit: u8,
    ) -> impl Future<Output = Result<(Arc<OwnedUdpSocket<N>>, u16), u64>> + Send + '_ {
        let _ = (local, hop_limit);
        core::future::ready(Err(ENETDOWN))
    }

    fn udp_connect(&self, socket: N::UdpSocket, remote: SocketAddr) -> Result<(), u64> {
        let _ = (socket, remote);
        Err(ENETDOWN)
    }

    fn udp_disconnect(&self, socket: N::UdpSocket) -> Result<(), u64> {
        let _ = socket;
        Err(ENETDOWN)
    }

    fn udp_set_hop_limit(&self, socket: N::UdpSocket, hop_limit: u8) -> Result<(), u64> {
        let _ = (socket, hop_limit);
        Ok(())
    }

    fn udp_send<'a>(
        &'a self,
        socket: N::UdpSocket,
        remote: SocketAddr,
        bytes: &'a [u8],
        timeout_nanos: u64,
    ) -> impl Future<Output = Result<usize, u64>> + Send + 'a {
        let _ = (socket, remote, bytes, timeout_nanos);
        core::future::ready(Err(ENETDOWN))
    }

    fn udp_receive(
        &self,
        socket: N::UdpSocket,
        max_bytes: u32,
        timeout_nanos: u64,
        peek: bool,
    ) -> impl Future<Output = Result<Option<(Bytes, SocketAddr, usize)>, u64>> + Send + '_ {
        let _ = (socket, max_bytes, timeout_nanos, peek);
        core::future::ready(Err(ENETDOWN))
    }

    fn udp_readiness(
        &self,
        socket: N::UdpSocket,
    ) -> impl Future<Output = Result<SocketReady, u64>> + Send + '_ {
        let _ = socket;
        core::future::ready(Err(ENETDOWN))
    }

    fn udp_join_multicast_v4(
        &self,
        group: [u8; 4],
        interface: [u8; 4],
    ) -> impl Future<Output = Result<(), u64>> + Send + '_ {
        let _ = (group, interface);
        core::future::ready(Err(ENETDOWN))
    }

    fn udp_leave_multicast_v4(
        &self,
        group: [u8; 4],
        interface: [u8; 4],
    ) -> impl Future<Output = Result<(), u64>> + Send + '_ {
        let _ = (group, interface);
        core::future::ready(Err(ENETDOWN))
    }

    fn check_multicast_v6(&self) -> Result<(), u64> {
        Err(ENETDOWN)
    }

    fn interface_mac(&self) -> impl Future<Output = Result<[u8; 6], u64>> + Send + '_ {
        core::future::ready(Err(ENETDOWN))
    }

    fn list_ipv4_addresses(
        &self,
    ) -> impl Future<Output = Result<Vec<Ipv4InterfaceAddress>, u64>> + Send + '_ {
        core::future::ready(Err(ENETDOWN))
    }

    fn add_ipv4_address(
        &self,
        address: Ipv4InterfaceAddress,
    ) -> impl Future<Output = Result<(), u64>> + Send + '_ {
        let _ = address;
        core::future::ready(Err(EPERM))
    }

    fn remove_ipv4_address(
        &self,
        address: Ipv4InterfaceAddress,
    ) -> impl Future<Output = Result<(), u64>> + Send + '_ {
        let _ = address;
        core::future::ready(Err(EPERM))
    }

    fn list_ipv4_routes(
        &self,
    ) -> impl Future<Output = Result<Vec<Ipv4RouteEntry>, u64>> + Send + '_ {
        core::future::ready(Err(ENETDOWN))
    }

    fn add_ipv4_route(
        &self,
        route: Ipv4RouteEntry,
    ) -> impl Future<Output = Result<(), u64>> + Send + '_ {
        let _ = route;
        core::future::ready(Err(EPERM))
    }

    fn remove_ipv4_route(
        &self,
        route: Ipv4RouteEntry,
    ) -> impl Future<Output = Result<(), u64>> + Send + '_ {
        let _ = route;
        core::future::ready(Err(EPERM))
    }

    fn check_net_admin(&self) -> Result<(), u64> {
        Err(EPERM)
    }

    fn packet_open(&self, protocol: u16) -> Result<Arc<OwnedPacketSocket<N>>, u64> {
        let _ = protocol;
        Err(EPERM)
    }

    fn packet_bind(&self, socket: N::PacketSocket, protocol: u16, ifindex: u32) -> Result<(), u64> {
        let _ = (socket, protocol, ifindex);
        Err(ENETDOWN)
    }

    fn packet_send<'a>(
        &'a self,
        socket: N::PacketSocket,
        ifindex: u32,
        frame: &'a [u8],
    ) -> impl Future<Output = Result<usize, u64>> + Send + 'a {
        let _ = (socket, ifindex, frame);
        core::future::ready(Err(ENETDOWN))
    }

    fn packet_receive(
        &self,
        socket: N::PacketSocket,
        max_bytes: u32,
        timeout_nanos: u64,
        peek: bool,
    ) -> impl Future<Output = Result<Option<PacketFrameData>, u64>> + Send + '_ {
        let _ = (socket, max_bytes, timeout_nanos, peek);
        core::future::ready(Err(ENETDOWN))
    }

    fn packet_readiness(
        &self,
        socket: N::PacketSocket,
    ) -> impl Future<Output = Result<SocketReady, u64>> + Send + '_ {
        let _ = socket;
        core::future::ready(Err(ENETDOWN))
    }
}

fn get_socket<R: Resources>(
    descriptors: &spin::Mutex<Descriptors<R>>,
    fd: i32,
) -> Result<Socket<R::Network>, u64> {
    match descriptors.lock().get_entry(fd) {
        Some(entry) => match &entry.descriptor {
            Descriptor::<R>::Socket(socket) => Ok(socket.clone()),
            _ => Err(ENOTSOCK),
        },
        None => Err(EBADF),
    }
}

fn parse_sockaddr<M: UserMemory>(
    memory: &M,
    addr: u64,
    addrlen: u32,
) -> Result<Option<SocketAddr>, u64> {
    if addrlen < 2 {
        return Err(EINVAL);
    }
    let mut family_bytes = [0u8; 2];
    memory.read(addr, &mut family_bytes).map_err(|_| EFAULT)?;
    let family = u16::from_le_bytes(family_bytes);
    match family {
        AF_UNSPEC => Ok(None),
        AF_INET => {
            if (addrlen as usize) < SOCKADDR_IN_LEN {
                return Err(EINVAL);
            }
            let mut raw = [0u8; SOCKADDR_IN_LEN];
            memory.read(addr, &mut raw).map_err(|_| EFAULT)?;
            let port = u16::from_be_bytes([raw[2], raw[3]]);
            let ip = IpAddr::V4([raw[4], raw[5], raw[6], raw[7]]);
            Ok(Some(SocketAddr { ip, port }))
        }
        AF_INET6 => {
            if (addrlen as usize) < SOCKADDR_IN6_LEN {
                return Err(EINVAL);
            }
            let mut raw = [0u8; SOCKADDR_IN6_LEN];
            memory.read(addr, &mut raw).map_err(|_| EFAULT)?;
            let port = u16::from_be_bytes([raw[2], raw[3]]);
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&raw[8..24]);
            Ok(Some(SocketAddr {
                ip: IpAddr::V6(octets),
                port,
            }))
        }
        _ => Err(EAFNOSUPPORT),
    }
}

fn encode_sockaddr(addr: SocketAddr, out: &mut [u8; SOCKADDR_IN6_LEN]) -> usize {
    out.fill(0);
    match addr.ip {
        IpAddr::V4(octets) => {
            out[0..2].copy_from_slice(&AF_INET.to_le_bytes());
            out[2..4].copy_from_slice(&addr.port.to_be_bytes());
            out[4..8].copy_from_slice(&octets);
            SOCKADDR_IN_LEN
        }
        IpAddr::V6(octets) => {
            out[0..2].copy_from_slice(&AF_INET6.to_le_bytes());
            out[2..4].copy_from_slice(&addr.port.to_be_bytes());
            out[8..24].copy_from_slice(&octets);
            SOCKADDR_IN6_LEN
        }
    }
}

fn write_sockaddr_bytes<M: UserMemory>(
    memory: &mut M,
    addr_ptr: u64,
    addrlen_ptr: u64,
    encoded: &[u8],
) -> Result<(), u64> {
    if addr_ptr == 0 {
        return Ok(());
    }
    if addrlen_ptr == 0 {
        return Err(EFAULT);
    }
    let mut len_bytes = [0u8; 4];
    memory
        .read(addrlen_ptr, &mut len_bytes)
        .map_err(|_| EFAULT)?;
    let raw_len = i32::from_le_bytes(len_bytes);
    if raw_len < 0 {
        return Err(EINVAL);
    }
    let copy_len = (raw_len as usize).min(encoded.len());
    if copy_len > 0 {
        memory
            .write(addr_ptr, &encoded[..copy_len])
            .map_err(|_| EFAULT)?;
    }
    memory
        .write(addrlen_ptr, &(encoded.len() as u32).to_le_bytes())
        .map_err(|_| EFAULT)?;
    Ok(())
}

fn write_sockaddr<M: UserMemory>(
    memory: &mut M,
    addr_ptr: u64,
    addrlen_ptr: u64,
    addr: SocketAddr,
) -> Result<(), u64> {
    let mut buf = [0u8; SOCKADDR_IN6_LEN];
    let len = encode_sockaddr(addr, &mut buf);
    write_sockaddr_bytes(memory, addr_ptr, addrlen_ptr, &buf[..len])
}

fn effective_timeout(configured: Option<u64>, nonblocking: bool) -> u64 {
    effective_timeout_bounded(configured, nonblocking, None)
}

fn effective_timeout_bounded(
    configured: Option<u64>,
    nonblocking: bool,
    bound: Option<u64>,
) -> u64 {
    if nonblocking {
        0
    } else {
        let base = configured.unwrap_or(u64::MAX);
        match bound {
            Some(limit) => base.min(limit),
            None => base,
        }
    }
}

/// Polls an in-flight non-blocking TCP connection, transitioning the socket to
/// `Connected` on success or `Unconnected` (with `SO_ERROR` latched) on error.
pub(crate) async fn poll_connecting<N: SocketNetwork, Net: Network<N>>(
    socket: &Socket<N>,
    net: &Net,
) -> Option<Result<ConnectProgress, u64>> {
    let Some(TcpSocket::Connecting { stream, .. }) = socket.tcp_state() else {
        return None;
    };
    let stream_id = stream.id();
    match net.tcp_connect_poll(stream_id).await {
        Ok(ConnectProgress::Pending) => Some(Ok(ConnectProgress::Pending)),
        Ok(ConnectProgress::Connected) => {
            socket.with_tcp_mut(|slot| {
                if let TcpSocket::Connecting {
                    family,
                    stream,
                    peer_address,
                    peer_port,
                    options,
                } = slot.clone()
                {
                    *slot = TcpSocket::Connected {
                        family,
                        stream,
                        peer_address,
                        peer_port,
                        options,
                    };
                }
            });
            socket.set_pending_error(0);
            Some(Ok(ConnectProgress::Connected))
        }
        Err(err) => {
            socket.with_tcp_mut(|slot| {
                if let TcpSocket::Connecting {
                    family, options, ..
                } = slot
                {
                    let family = *family;
                    let options = *options;
                    *slot = TcpSocket::Unconnected { family, options };
                }
            });
            socket.set_pending_error(err as i32);
            Some(Err(err))
        }
    }
}

pub(crate) fn socket<R: Resources, Net: Network<R::Network>>(
    descriptors: &spin::Mutex<Descriptors<R>>,
    args: [u64; 6],
    ctx: SocketContext,
    net: &Net,
) -> u64 {
    let domain = args[0] as u32;
    let raw_type = args[1] as u32;
    let protocol = args[2] as i32;

    let flags = raw_type & !SOCK_TYPE_MASK;
    if flags & !(SOCK_NONBLOCK | SOCK_CLOEXEC) != 0 {
        return errno(EINVAL);
    }
    let nonblocking = flags & SOCK_NONBLOCK != 0;
    let cloexec = flags & SOCK_CLOEXEC != 0;
    let sock_type = raw_type & SOCK_TYPE_MASK;

    let sock = match domain as u16 {
        AF_INET | AF_INET6 => {
            let family = if domain as u16 == AF_INET {
                SocketFamily::Ipv4
            } else {
                SocketFamily::Ipv6
            };
            match sock_type {
                SOCK_STREAM => {
                    if protocol != 0 && protocol != IPPROTO_TCP {
                        return errno(EPROTONOSUPPORT);
                    }
                    if let Err(err) = net.check_tcp_open() {
                        return errno(err);
                    }
                    Socket::<R::Network>::tcp(family)
                }
                SOCK_DGRAM => {
                    if protocol != 0 && protocol != IPPROTO_UDP {
                        return errno(EPROTONOSUPPORT);
                    }
                    if let Err(err) = net.check_udp_open() {
                        return errno(err);
                    }
                    Socket::<R::Network>::udp(family)
                }
                _ => return errno(EINVAL),
            }
        }
        AF_NETLINK => {
            if sock_type != SOCK_RAW && sock_type != SOCK_DGRAM {
                return errno(EPROTOTYPE);
            }
            if protocol as u32 != NETLINK_ROUTE {
                return errno(EPROTONOSUPPORT);
            }
            let kind = if sock_type == SOCK_RAW {
                SocketKind::Raw
            } else {
                SocketKind::Datagram
            };
            Socket::<R::Network>::netlink(kind, NETLINK_ROUTE)
        }
        AF_PACKET => {
            let kind = match sock_type {
                SOCK_RAW => SocketKind::Raw,
                SOCK_DGRAM => SocketKind::Datagram,
                _ => return errno(EPROTOTYPE),
            };
            if !ctx.cap_net_raw {
                return errno(EPERM);
            }
            let host_protocol = u16::from_be(protocol as u16);
            let handle = match net.packet_open(host_protocol) {
                Ok(handle) => handle,
                Err(err) => return errno(err),
            };
            Socket::<R::Network>::packet(kind, handle, host_protocol)
        }
        _ => return errno(EAFNOSUPPORT),
    };
    if nonblocking {
        sock.set_nonblocking(true);
    }
    let entry = Entry::<R>::new(Descriptor::<R>::Socket(sock), cloexec);
    if nonblocking {
        entry.set_fdflags(helios_unix::FDFLAG_NONBLOCK);
    }
    match descriptors.lock().insert_entry(entry) {
        Ok(fd) => u64::from(fd),
        Err(err) => descriptor_errno(err),
    }
}

pub(crate) fn socketpair<R: Resources, M: UserMemory>(
    descriptors: &spin::Mutex<Descriptors<R>>,
    args: [u64; 6],
    memory: &mut M,
) -> u64 {
    let domain = args[0] as u32;
    let raw_type = args[1] as u32;
    let protocol = args[2] as i32;
    let sv_ptr = args[3];

    match domain as u16 {
        AF_UNIX => {}
        AF_INET | AF_INET6 => return errno(EOPNOTSUPP),
        _ => return errno(EAFNOSUPPORT),
    }
    let flags = raw_type & !SOCK_TYPE_MASK;
    if flags & !(SOCK_NONBLOCK | SOCK_CLOEXEC) != 0 {
        return errno(EINVAL);
    }
    let kind = match raw_type & SOCK_TYPE_MASK {
        SOCK_STREAM => SocketKind::Stream,
        SOCK_DGRAM => SocketKind::Datagram,
        _ => return errno(EINVAL),
    };
    if protocol != 0 {
        return errno(EPROTONOSUPPORT);
    }
    if memory.check_writable(sv_ptr, 8).is_err() {
        return errno(EFAULT);
    }
    let nonblocking = flags & SOCK_NONBLOCK != 0;
    let cloexec = flags & SOCK_CLOEXEC != 0;
    let (first, second) = Socket::<R::Network>::pair(kind);
    if nonblocking {
        first.set_nonblocking(true);
        second.set_nonblocking(true);
    }
    let entry0 = Entry::<R>::new(Descriptor::<R>::Socket(first), cloexec);
    let entry1 = Entry::<R>::new(Descriptor::<R>::Socket(second), cloexec);
    if nonblocking {
        entry0.set_fdflags(helios_unix::FDFLAG_NONBLOCK);
        entry1.set_fdflags(helios_unix::FDFLAG_NONBLOCK);
    }
    let mut table = descriptors.lock();
    let fd0 = match table.insert_entry(entry0) {
        Ok(fd) => fd,
        Err(err) => return descriptor_errno(err),
    };
    let fd1 = match table.insert_entry(entry1) {
        Ok(fd) => fd,
        Err(err) => {
            let _ = table.close(fd0 as i32);
            return descriptor_errno(err);
        }
    };
    let mut out = [0u8; 8];
    out[0..4].copy_from_slice(&(fd0 as i32).to_le_bytes());
    out[4..8].copy_from_slice(&(fd1 as i32).to_le_bytes());
    if memory.write(sv_ptr, &out).is_err() {
        let _ = table.close(fd0 as i32);
        let _ = table.close(fd1 as i32);
        return errno(EFAULT);
    }
    0
}

pub(crate) async fn bind<R: Resources, M: UserMemory, Net: Network<R::Network>>(
    descriptors: &spin::Mutex<Descriptors<R>>,
    args: [u64; 6],
    ctx: SocketContext,
    memory: &M,
    net: &Net,
) -> u64 {
    let fd = args[0] as u32 as i32;
    let addr_ptr = args[1];
    let addrlen = args[2] as u32;
    let sock = match get_socket::<R>(descriptors, fd) {
        Ok(sock) => sock,
        Err(err) => return errno(err),
    };
    if sock.is_netlink() {
        return match netlink::bind(&sock, addr_ptr, addrlen, ctx, memory) {
            Ok(()) => 0,
            Err(err) => errno(err),
        };
    }
    if sock.is_packet() {
        return match packet::bind(&sock, addr_ptr, addrlen, memory, net) {
            Ok(()) => 0,
            Err(err) => errno(err),
        };
    }
    let Some(target) = (match parse_sockaddr(memory, addr_ptr, addrlen) {
        Ok(target) => target,
        Err(err) => return errno(err),
    }) else {
        return errno(EAFNOSUPPORT);
    };

    if let Some(udp) = sock.udp_state() {
        let UdpSocket::Unbound { family, options } = udp else {
            return errno(EINVAL);
        };
        if target.ip.family() != family {
            return errno(EAFNOSUPPORT);
        }
        if let Err(err) = net.check_udp_bind(target.port) {
            return errno(err);
        }
        let (owned, local_port) = match net.udp_bind(target, options.hop_limit()).await {
            Ok(bound) => bound,
            Err(err) => return errno(err),
        };
        let local_address = net.encode_ip(target.ip);
        return sock
            .with_udp_mut(|slot| match *slot {
                UdpSocket::Unbound { family, options } => {
                    *slot = UdpSocket::Bound {
                        family,
                        socket: owned,
                        local_address,
                        local_port,
                        peer: None,
                        options,
                    };
                    0
                }
                UdpSocket::Bound { .. } => errno(EINVAL),
            })
            .unwrap_or_else(|| errno(EINVAL));
    }

    if let Some(tcp) = sock.tcp_state() {
        let TcpSocket::Unconnected { family, .. } = tcp else {
            return errno(EINVAL);
        };
        if target.ip.family() != family {
            return errno(EAFNOSUPPORT);
        }
        if let Err(err) = net.check_tcp_bind(target.port) {
            return errno(err);
        }
        let local_address = net.encode_ip(target.ip);
        return sock
            .with_tcp_mut(|slot| match *slot {
                TcpSocket::Unconnected { family, options } => {
                    *slot = TcpSocket::Bound {
                        family,
                        local_address,
                        local_port: target.port,
                        options,
                    };
                    0
                }
                _ => errno(EINVAL),
            })
            .unwrap_or_else(|| errno(EINVAL));
    }

    errno(EINVAL)
}

pub(crate) async fn listen<R: Resources, Net: Network<R::Network>>(
    descriptors: &spin::Mutex<Descriptors<R>>,
    args: [u64; 6],
    net: &Net,
) -> u64 {
    let fd = args[0] as u32 as i32;
    let raw_backlog = args[1] as i32;
    let sock = match get_socket::<R>(descriptors, fd) {
        Ok(sock) => sock,
        Err(err) => return errno(err),
    };
    let Some(tcp) = sock.tcp_state() else {
        return errno(EOPNOTSUPP);
    };
    let (local, hop_limit) = match tcp {
        TcpSocket::Unconnected { family, options } => (
            SocketAddr {
                ip: IpAddr::unspecified(family),
                port: 0,
            },
            options.hop_limit(),
        ),
        TcpSocket::Bound {
            local_address,
            local_port,
            options,
            ..
        } => (
            SocketAddr {
                ip: net.to_ip(local_address),
                port: local_port,
            },
            options.hop_limit(),
        ),
        TcpSocket::Listening { .. } => return 0,
        TcpSocket::Connecting { .. } | TcpSocket::Connected { .. } => return errno(EINVAL),
    };
    if let Err(err) = net.check_tcp_bind(local.port) {
        return errno(err);
    }
    let backlog = if raw_backlog <= 0 {
        1
    } else {
        u16::try_from(raw_backlog).unwrap_or(u16::MAX)
    };
    let (listener, local_port) = match net.tcp_listen(local, backlog, hop_limit).await {
        Ok(bound) => bound,
        Err(err) => return errno(err),
    };
    let local_address = net.encode_ip(local.ip);
    sock.with_tcp_mut(|slot| match *slot {
        TcpSocket::Unconnected { family, options }
        | TcpSocket::Bound {
            family, options, ..
        } => {
            *slot = TcpSocket::Listening {
                family,
                listener,
                local_address,
                local_port,
                options,
            };
            0
        }
        TcpSocket::Listening { .. } => 0,
        TcpSocket::Connecting { .. } | TcpSocket::Connected { .. } => errno(EINVAL),
    })
    .unwrap_or_else(|| errno(EINVAL))
}

pub(crate) async fn accept<R: Resources, M: UserMemory, Net: Network<R::Network>>(
    descriptors: &spin::Mutex<Descriptors<R>>,
    args: [u64; 6],
    memory: &mut M,
    net: &Net,
    with_flags: bool,
) -> u64 {
    let fd = args[0] as u32 as i32;
    let addr_ptr = args[1];
    let addrlen_ptr = args[2];
    let flags = if with_flags { args[3] as u32 } else { 0 };
    if flags & !(SOCK_NONBLOCK | SOCK_CLOEXEC) != 0 {
        return errno(EINVAL);
    }
    let sock = match get_socket::<R>(descriptors, fd) {
        Ok(sock) => sock,
        Err(err) => return errno(err),
    };
    let Some(tcp) = sock.tcp_state() else {
        return errno(EOPNOTSUPP);
    };
    let TcpSocket::Listening {
        family,
        listener,
        options,
        ..
    } = tcp
    else {
        return errno(EINVAL);
    };
    let nonblocking = sock.is_nonblocking();
    let timeout = effective_timeout(options.time(SocketTime::AcceptTimeout), nonblocking);
    let (stream, peer) = match net.tcp_accept(listener.id(), timeout).await {
        Ok(accepted) => accepted,
        Err(ETIMEDOUT) => return errno(EAGAIN),
        Err(err) => return errno(err),
    };
    if let Err(err) = write_sockaddr(memory, addr_ptr, addrlen_ptr, peer) {
        return errno(err);
    }
    let peer_address = net.encode_ip(peer.ip);
    let accepted = Socket::<R::Network>::from_tcp(TcpSocket::Connected {
        family,
        stream,
        peer_address,
        peer_port: peer.port,
        options,
    });
    if flags & SOCK_NONBLOCK != 0 {
        accepted.set_nonblocking(true);
    }
    let cloexec = flags & SOCK_CLOEXEC != 0;
    let entry = Entry::<R>::new(Descriptor::<R>::Socket(accepted), cloexec);
    if flags & SOCK_NONBLOCK != 0 {
        entry.set_fdflags(helios_unix::FDFLAG_NONBLOCK);
    }
    match descriptors.lock().insert_entry(entry) {
        Ok(new_fd) => u64::from(new_fd),
        Err(err) => descriptor_errno(err),
    }
}

pub(crate) async fn connect<R: Resources, M: UserMemory, Net: Network<R::Network>>(
    descriptors: &spin::Mutex<Descriptors<R>>,
    args: [u64; 6],
    memory: &M,
    net: &Net,
) -> u64 {
    let fd = args[0] as u32 as i32;
    let addr_ptr = args[1];
    let addrlen = args[2] as u32;
    let sock = match get_socket::<R>(descriptors, fd) {
        Ok(sock) => sock,
        Err(err) => return errno(err),
    };
    if sock.is_pair() {
        return errno(EISCONN);
    }
    let parsed = match parse_sockaddr(memory, addr_ptr, addrlen) {
        Ok(parsed) => parsed,
        Err(err) => return errno(err),
    };

    if let Some(udp) = sock.udp_state() {
        let Some(remote) = parsed else {
            // `connect(..., AF_UNSPEC)` dissolves a UDP association.
            if let UdpSocket::Bound { socket, .. } = udp {
                if let Err(err) = net.udp_disconnect(socket.id()) {
                    return errno(err);
                }
                sock.with_udp_mut(|slot| {
                    if let UdpSocket::Bound { peer, .. } = slot {
                        *peer = None;
                    }
                });
            }
            return 0;
        };
        let (udp_id, family) = match udp {
            UdpSocket::Bound { socket, family, .. } => (socket.id(), family),
            UdpSocket::Unbound { family, options } => {
                if remote.ip.family() != family {
                    return errno(EAFNOSUPPORT);
                }
                if let Err(err) = net.check_udp_bind(0) {
                    return errno(err);
                }
                let local = SocketAddr {
                    ip: IpAddr::unspecified(family),
                    port: 0,
                };
                let (owned, local_port) = match net.udp_bind(local, options.hop_limit()).await {
                    Ok(bound) => bound,
                    Err(err) => return errno(err),
                };
                let id = owned.id();
                let local_address = net.encode_ip(local.ip);
                sock.with_udp_mut(|slot| {
                    if let UdpSocket::Unbound { family, options } = *slot {
                        *slot = UdpSocket::Bound {
                            family,
                            socket: owned,
                            local_address,
                            local_port,
                            peer: None,
                            options,
                        };
                    }
                });
                (id, family)
            }
        };
        if remote.ip.family() != family {
            return errno(EAFNOSUPPORT);
        }
        if let Err(err) = net.udp_connect(udp_id, remote) {
            return errno(err);
        }
        let peer_addr = net.encode_ip(remote.ip);
        sock.with_udp_mut(|slot| {
            if let UdpSocket::Bound { peer, .. } = slot {
                *peer = Some((peer_addr, remote.port));
            }
        });
        return 0;
    }

    let Some(tcp) = sock.tcp_state() else {
        return errno(EOPNOTSUPP);
    };
    let Some(remote) = parsed else {
        return errno(EAFNOSUPPORT);
    };
    if matches!(tcp, TcpSocket::Connecting { .. }) {
        return match poll_connecting(&sock, net).await {
            Some(Ok(ConnectProgress::Pending)) => errno(EALREADY),
            Some(Ok(ConnectProgress::Connected)) => 0,
            Some(Err(err)) => {
                let _ = sock.take_pending_error();
                errno(err)
            }
            None => errno(EISCONN),
        };
    }
    let (local_port, family, options) = match tcp {
        TcpSocket::Unconnected { family, options } => (0, family, options),
        TcpSocket::Bound {
            local_port,
            family,
            options,
            ..
        } => (local_port, family, options),
        TcpSocket::Connected { .. } | TcpSocket::Listening { .. } => return errno(EISCONN),
        TcpSocket::Connecting { .. } => unreachable!(),
    };
    if remote.ip.family() != family {
        return errno(EAFNOSUPPORT);
    }
    if let Err(err) = net.check_tcp_open() {
        return errno(err);
    }
    let peer_address = net.encode_ip(remote.ip);
    if sock.is_nonblocking() {
        let (stream, progress) = match net
            .tcp_connect_start(remote, local_port, options.hop_limit())
            .await
        {
            Ok(started) => started,
            Err(err) => return errno(err),
        };
        let status = match progress {
            ConnectProgress::Connected => 0,
            ConnectProgress::Pending => errno(EINPROGRESS),
        };
        sock.with_tcp_mut(|slot| match *slot {
            TcpSocket::Unconnected { family, options }
            | TcpSocket::Bound {
                family, options, ..
            } => {
                *slot = match progress {
                    ConnectProgress::Connected => TcpSocket::Connected {
                        family,
                        stream,
                        peer_address,
                        peer_port: remote.port,
                        options,
                    },
                    ConnectProgress::Pending => TcpSocket::Connecting {
                        family,
                        stream,
                        peer_address,
                        peer_port: remote.port,
                        options,
                    },
                };
            }
            _ => {}
        });
        return status;
    }

    let timeout = effective_timeout(options.time(SocketTime::ConnectTimeout), false);
    let stream = match net
        .tcp_connect(remote, local_port, options.hop_limit(), timeout)
        .await
    {
        Ok(stream) => stream,
        Err(err) => return errno(err),
    };
    sock.with_tcp_mut(|slot| match *slot {
        TcpSocket::Unconnected { family, options }
        | TcpSocket::Bound {
            family, options, ..
        } => {
            *slot = TcpSocket::Connected {
                family,
                stream,
                peer_address,
                peer_port: remote.port,
                options,
            };
            0
        }
        _ => errno(EISCONN),
    })
    .unwrap_or_else(|| errno(EINVAL))
}

pub(crate) async fn getsockname<R: Resources, M: UserMemory, Net: Network<R::Network>>(
    descriptors: &spin::Mutex<Descriptors<R>>,
    args: [u64; 6],
    memory: &mut M,
    net: &Net,
) -> u64 {
    let fd = args[0] as u32 as i32;
    let addr_ptr = args[1];
    let addrlen_ptr = args[2];
    let sock = match get_socket::<R>(descriptors, fd) {
        Ok(sock) => sock,
        Err(err) => return errno(err),
    };
    if sock.is_pair() {
        return match write_sockaddr_bytes(memory, addr_ptr, addrlen_ptr, &AF_UNIX.to_le_bytes()) {
            Ok(()) => 0,
            Err(err) => errno(err),
        };
    }
    if sock.is_netlink() {
        return match netlink::getsockname(&sock, addr_ptr, addrlen_ptr, memory) {
            Ok(()) => 0,
            Err(err) => errno(err),
        };
    }
    if sock.is_packet() {
        return match packet::getsockname(&sock, addr_ptr, addrlen_ptr, memory, net).await {
            Ok(()) => 0,
            Err(err) => errno(err),
        };
    }
    let addr = if let Some(tcp) = sock.tcp_state() {
        match tcp {
            TcpSocket::Unconnected { family, .. } => SocketAddr {
                ip: IpAddr::unspecified(family),
                port: 0,
            },
            TcpSocket::Bound {
                local_address,
                local_port,
                ..
            }
            | TcpSocket::Listening {
                local_address,
                local_port,
                ..
            } => SocketAddr {
                ip: net.to_ip(local_address),
                port: local_port,
            },
            TcpSocket::Connecting { family, stream, .. }
            | TcpSocket::Connected { family, stream, .. } => {
                match net.tcp_local_endpoint(stream.id()) {
                    Ok(Some(endpoint)) => endpoint,
                    Ok(None) => SocketAddr {
                        ip: IpAddr::unspecified(family),
                        port: 0,
                    },
                    Err(err) => return errno(err),
                }
            }
        }
    } else if let Some(udp) = sock.udp_state() {
        match udp {
            UdpSocket::Unbound { family, .. } => SocketAddr {
                ip: IpAddr::unspecified(family),
                port: 0,
            },
            UdpSocket::Bound {
                local_address,
                local_port,
                ..
            } => SocketAddr {
                ip: net.to_ip(local_address),
                port: local_port,
            },
        }
    } else {
        return errno(ENOTSOCK);
    };
    match write_sockaddr(memory, addr_ptr, addrlen_ptr, addr) {
        Ok(()) => 0,
        Err(err) => errno(err),
    }
}

pub(crate) async fn getpeername<R: Resources, M: UserMemory, Net: Network<R::Network>>(
    descriptors: &spin::Mutex<Descriptors<R>>,
    args: [u64; 6],
    memory: &mut M,
    net: &Net,
) -> u64 {
    let fd = args[0] as u32 as i32;
    let addr_ptr = args[1];
    let addrlen_ptr = args[2];
    let sock = match get_socket::<R>(descriptors, fd) {
        Ok(sock) => sock,
        Err(err) => return errno(err),
    };
    if sock.is_pair() {
        return match write_sockaddr_bytes(memory, addr_ptr, addrlen_ptr, &AF_UNIX.to_le_bytes()) {
            Ok(()) => 0,
            Err(err) => errno(err),
        };
    }
    let _ = poll_connecting(&sock, net).await;
    let addr = if let Some(tcp) = sock.tcp_state() {
        match tcp {
            TcpSocket::Connected {
                peer_address,
                peer_port,
                ..
            } => SocketAddr {
                ip: net.to_ip(peer_address),
                port: peer_port,
            },
            _ => return errno(ENOTCONN),
        }
    } else if let Some(udp) = sock.udp_state() {
        match udp {
            UdpSocket::Bound {
                peer: Some((peer_address, peer_port)),
                ..
            } => SocketAddr {
                ip: net.to_ip(peer_address),
                port: peer_port,
            },
            _ => return errno(ENOTCONN),
        }
    } else {
        return errno(ENOTSOCK);
    };
    match write_sockaddr(memory, addr_ptr, addrlen_ptr, addr) {
        Ok(()) => 0,
        Err(err) => errno(err),
    }
}

/// Core send routine shared by `write`, `writev`, `sendto`, `sendmsg`,
/// `sendmmsg` and `sendfile`.
/// Optional destination address passed to [`socket_send`].
pub(crate) enum SendDest {
    Inet(SocketAddr),
    Netlink,
    Packet(SockaddrLl),
}

pub(crate) async fn socket_send<N: SocketNetwork, Net: Network<N>>(
    sock: &Socket<N>,
    data: Vec<u8>,
    flags: u32,
    dest: Option<SendDest>,
    ctx: SocketContext,
    net: &Net,
) -> Result<usize, u64> {
    if flags & MSG_OOB != 0 {
        return Err(EOPNOTSUPP);
    }
    if sock.is_shutdown_write() {
        return Err(EPIPE);
    }
    let nonblocking = sock.is_nonblocking() || (flags & MSG_DONTWAIT != 0);

    if sock.is_netlink() {
        return netlink::send(sock, &data, ctx, net).await;
    }

    if sock.is_packet() {
        let sll = match dest {
            Some(SendDest::Packet(sll)) => Some(sll),
            Some(_) => return Err(EAFNOSUPPORT),
            None => None,
        };
        return packet::send(sock, &data, sll, net).await;
    }

    let dest = match dest {
        Some(SendDest::Inet(addr)) => Some(addr),
        Some(_) => return Err(EAFNOSUPPORT),
        None => None,
    };

    if let Some(writer) = sock.pair_writer() {
        if dest.is_some() {
            return Err(EISCONN);
        }
        let len = data.len();
        if len == 0 {
            return if writer.is_reader_closed() {
                Err(EPIPE)
            } else {
                Ok(0)
            };
        }
        let bytes = Bytes::from(data);
        if nonblocking {
            return match writer.try_write(bytes) {
                helios_sync::TryWrite::Written => Ok(len),
                helios_sync::TryWrite::Full(_) => Err(EAGAIN),
                helios_sync::TryWrite::Closed => Err(EPIPE),
            };
        }
        return match writer.write(bytes).await {
            Ok(()) => Ok(len),
            Err(helios_sync::ClosedPeer) => Err(EPIPE),
        };
    }

    if sock.is_tcp() {
        if let Some(res) = poll_connecting(sock, net).await {
            match res {
                Ok(ConnectProgress::Pending) => return Err(EAGAIN),
                Ok(ConnectProgress::Connected) => {}
                Err(err) => {
                    let _ = sock.take_pending_error();
                    return Err(err);
                }
            }
        }
        let Some(TcpSocket::Connected {
            stream, options, ..
        }) = sock.tcp_state()
        else {
            return Err(EPIPE);
        };
        let timeout = effective_timeout(options.time(SocketTime::SendTimeout), nonblocking);
        return match net.tcp_write(stream.id(), Bytes::from(data), timeout).await {
            Ok(written) => Ok(written),
            Err(ETIMEDOUT) => Err(EAGAIN),
            Err(err) => Err(err),
        };
    }

    if let Some(udp) = sock.udp_state() {
        let (udp_id, remote, send_timeout) = match udp {
            UdpSocket::Bound {
                family,
                socket,
                peer,
                options,
                ..
            } => {
                let remote = match dest {
                    Some(addr) => {
                        if addr.ip.family() != family {
                            return Err(EAFNOSUPPORT);
                        }
                        addr
                    }
                    None => match peer {
                        Some((addr, port)) => SocketAddr {
                            ip: net.to_ip(addr),
                            port,
                        },
                        None => return Err(EDESTADDRREQ),
                    },
                };
                (socket.id(), remote, options.time(SocketTime::SendTimeout))
            }
            UdpSocket::Unbound { family, options } => {
                let Some(remote) = dest else {
                    return Err(EDESTADDRREQ);
                };
                if remote.ip.family() != family {
                    return Err(EAFNOSUPPORT);
                }
                net.check_udp_bind(0)?;
                let local = SocketAddr {
                    ip: IpAddr::unspecified(family),
                    port: 0,
                };
                let (owned, local_port) = net.udp_bind(local, options.hop_limit()).await?;
                let id = owned.id();
                let local_address = net.encode_ip(local.ip);
                sock.with_udp_mut(|slot| {
                    if let UdpSocket::Unbound { family, options } = *slot {
                        *slot = UdpSocket::Bound {
                            family,
                            socket: owned,
                            local_address,
                            local_port,
                            peer: None,
                            options,
                        };
                    }
                });
                (id, remote, options.time(SocketTime::SendTimeout))
            }
        };
        let timeout = effective_timeout(send_timeout, nonblocking);
        return match net.udp_send(udp_id, remote, &data, timeout).await {
            Ok(sent) => Ok(sent),
            Err(ETIMEDOUT) => Err(EAGAIN),
            Err(err) => Err(err),
        };
    }

    Err(ENOTSOCK)
}

/// Result of [`socket_recv`]: received bytes, optional peer address, and
/// original datagram length before truncation (for `MSG_TRUNC`).
pub(crate) enum RecvPeer {
    Inet(SocketAddr),
    Netlink { pid: u32, groups: u32 },
    Packet(SockaddrLl),
}

pub(crate) struct RecvResult {
    pub data: Bytes,
    pub peer: Option<RecvPeer>,
    pub full_len: usize,
    pub truncated: bool,
}

/// Core receive routine shared by `read`, `recvfrom`, `recvmsg`, `recvmmsg`
/// and `sendfile`.
pub(crate) async fn socket_recv<N: SocketNetwork, Net: Network<N>>(
    sock: &Socket<N>,
    max_len: usize,
    flags: u32,
    net: &Net,
) -> Result<RecvResult, u64> {
    socket_recv_bounded(sock, max_len, flags, None, net).await
}

async fn socket_recv_bounded<N: SocketNetwork, Net: Network<N>>(
    sock: &Socket<N>,
    max_len: usize,
    flags: u32,
    timeout_bound: Option<u64>,
    net: &Net,
) -> Result<RecvResult, u64> {
    if flags & MSG_OOB != 0 {
        return Err(EOPNOTSUPP);
    }
    if sock.is_shutdown_read() {
        return Ok(RecvResult {
            data: Bytes::new(),
            peer: None,
            full_len: 0,
            truncated: false,
        });
    }
    let nonblocking = sock.is_nonblocking() || (flags & MSG_DONTWAIT != 0);
    let peek = flags & MSG_PEEK != 0;
    let waitall = flags & MSG_WAITALL != 0 && !nonblocking && !peek;

    if sock.is_netlink() {
        let (data, orig_len) = netlink::recv(sock, max_len, flags)?;
        let truncated = orig_len > data.len();
        return Ok(RecvResult {
            data: Bytes::from(data),
            peer: Some(RecvPeer::Netlink { pid: 0, groups: 0 }),
            full_len: orig_len,
            truncated,
        });
    }

    if sock.is_packet() {
        let options = sock.options();
        let timeout = effective_timeout_bounded(
            options.time(SocketTime::ReceiveTimeout),
            nonblocking,
            timeout_bound,
        );
        let (data, orig_len, sll) = packet::recv(sock, max_len, flags, timeout, net).await?;
        let truncated = orig_len > data.len();
        return Ok(RecvResult {
            data: Bytes::from(data),
            peer: Some(RecvPeer::Packet(sll)),
            full_len: orig_len,
            truncated,
        });
    }

    if sock.is_pair() {
        if max_len == 0 {
            return Ok(RecvResult {
                data: Bytes::new(),
                peer: None,
                full_len: 0,
                truncated: false,
            });
        }
        let mut received = Vec::new();
        loop {
            let need = max_len.saturating_sub(received.len());
            if need == 0 {
                break;
            }
            let chunk = match sock.recv_pair(need, nonblocking, peek).await {
                Ok(chunk) => chunk,
                Err(PairRecvError::WouldBlock) => {
                    if received.is_empty() {
                        return Err(EAGAIN);
                    }
                    break;
                }
                Err(PairRecvError::NotPair) => return Err(ENOTSOCK),
            };
            if chunk.is_empty() {
                break;
            }
            received.extend_from_slice(&chunk);
            if !waitall {
                break;
            }
        }
        let len = received.len();
        return Ok(RecvResult {
            data: Bytes::from(received),
            peer: None,
            full_len: len,
            truncated: false,
        });
    }

    if sock.is_tcp() {
        if let Some(res) = poll_connecting(sock, net).await {
            match res {
                Ok(ConnectProgress::Pending) => return Err(EAGAIN),
                Ok(ConnectProgress::Connected) => {}
                Err(err) => {
                    let _ = sock.take_pending_error();
                    return Err(err);
                }
            }
        }
        let Some(TcpSocket::Connected {
            stream, options, ..
        }) = sock.tcp_state()
        else {
            return Err(ENOTCONN);
        };
        if max_len == 0 {
            return Ok(RecvResult {
                data: Bytes::new(),
                peer: None,
                full_len: 0,
                truncated: false,
            });
        }
        let timeout = effective_timeout_bounded(
            options.time(SocketTime::ReceiveTimeout),
            nonblocking,
            timeout_bound,
        );
        let mut received = Vec::new();
        loop {
            let need = max_len.saturating_sub(received.len());
            if need == 0 {
                break;
            }
            let req = u32::try_from(need).unwrap_or(u32::MAX);
            match net.tcp_read(stream.id(), req, timeout, peek).await {
                Ok(Some(chunk)) if !chunk.is_empty() => {
                    received.extend_from_slice(&chunk);
                    if !waitall {
                        break;
                    }
                }
                Ok(_) => break,
                Err(ETIMEDOUT) => {
                    if received.is_empty() {
                        return Err(EAGAIN);
                    }
                    break;
                }
                Err(err) => {
                    if received.is_empty() {
                        return Err(err);
                    }
                    break;
                }
            }
        }
        let len = received.len();
        return Ok(RecvResult {
            data: Bytes::from(received),
            peer: None,
            full_len: len,
            truncated: false,
        });
    }

    if let Some(udp) = sock.udp_state() {
        let UdpSocket::Bound {
            socket, options, ..
        } = udp
        else {
            return Err(EAGAIN);
        };
        let timeout = effective_timeout_bounded(
            options.time(SocketTime::ReceiveTimeout),
            nonblocking,
            timeout_bound,
        );
        let req = u32::try_from(max_len).unwrap_or(u32::MAX);
        match net.udp_receive(socket.id(), req, timeout, peek).await {
            Ok(Some((payload, peer, original_len))) => {
                let truncated = original_len > max_len;
                let data = if payload.len() > max_len {
                    payload.slice(..max_len)
                } else {
                    payload
                };
                return Ok(RecvResult {
                    data,
                    peer: Some(RecvPeer::Inet(peer)),
                    full_len: original_len,
                    truncated,
                });
            }
            Ok(None) => return Err(EAGAIN),
            Err(ETIMEDOUT) => return Err(EAGAIN),
            Err(err) => return Err(err),
        }
    }

    Err(ENOTSOCK)
}

fn parse_send_dest<N: SocketNetwork, M: UserMemory>(
    sock: &Socket<N>,
    memory: &M,
    addr: u64,
    addrlen: u32,
) -> Result<Option<SendDest>, u64> {
    if addr == 0 || addrlen == 0 {
        return Ok(None);
    }
    if sock.is_netlink() {
        let _ = netlink::read_sockaddr_nl(memory, addr, addrlen)?;
        return Ok(Some(SendDest::Netlink));
    }
    if sock.is_packet() {
        let sll = packet::read_sockaddr_ll(memory, addr, addrlen)?;
        return Ok(Some(SendDest::Packet(sll)));
    }
    match parse_sockaddr(memory, addr, addrlen)? {
        Some(a) => Ok(Some(SendDest::Inet(a))),
        None => Err(EAFNOSUPPORT),
    }
}

fn write_recv_peer<M: UserMemory>(
    memory: &mut M,
    addr: u64,
    addrlen_ptr: u64,
    peer: RecvPeer,
) -> Result<(), u64> {
    match peer {
        RecvPeer::Inet(a) => write_sockaddr(memory, addr, addrlen_ptr, a),
        RecvPeer::Netlink { pid, groups } => {
            netlink::write_sockaddr_nl(memory, addr, addrlen_ptr, pid, groups)
        }
        RecvPeer::Packet(sll) => packet::write_sockaddr_ll(memory, addr, addrlen_ptr, sll),
    }
}

pub(crate) async fn sendto<R: Resources, M: UserMemory, Net: Network<R::Network>>(
    descriptors: &spin::Mutex<Descriptors<R>>,
    args: [u64; 6],
    ctx: SocketContext,
    memory: &M,
    net: &Net,
) -> u64 {
    let fd = args[0] as u32 as i32;
    let buf_ptr = args[1];
    let len = args[2].min(MAX_RW_COUNT) as usize;
    let flags = args[3] as u32;
    let dest_ptr = args[4];
    let addrlen = args[5] as u32;

    let sock = match get_socket::<R>(descriptors, fd) {
        Ok(sock) => sock,
        Err(err) => return errno(err),
    };
    let dest = match parse_send_dest(&sock, memory, dest_ptr, addrlen) {
        Ok(dest) => dest,
        Err(err) => return errno(err),
    };
    let mut data = vec![0u8; len];
    if len > 0 && memory.read(buf_ptr, &mut data).is_err() {
        return errno(EFAULT);
    }
    match socket_send(&sock, data, flags, dest, ctx, net).await {
        Ok(sent) => sent as u64,
        Err(err) => errno(err),
    }
}

pub(crate) async fn recvfrom<R: Resources, M: UserMemory, Net: Network<R::Network>>(
    descriptors: &spin::Mutex<Descriptors<R>>,
    args: [u64; 6],
    memory: &mut M,
    net: &Net,
) -> u64 {
    let fd = args[0] as u32 as i32;
    let buf_ptr = args[1];
    let len = args[2].min(MAX_RW_COUNT) as usize;
    let flags = args[3] as u32;
    let src_ptr = args[4];
    let addrlen_ptr = args[5];

    let sock = match get_socket::<R>(descriptors, fd) {
        Ok(sock) => sock,
        Err(err) => return errno(err),
    };
    if len > 0 && memory.check_writable(buf_ptr, len).is_err() {
        return errno(EFAULT);
    }
    let result = match socket_recv(&sock, len, flags, net).await {
        Ok(result) => result,
        Err(err) => return errno(err),
    };
    if !result.data.is_empty() && memory.write(buf_ptr, &result.data).is_err() {
        return errno(EFAULT);
    }
    if let Some(peer) = result.peer
        && let Err(err) = write_recv_peer(memory, src_ptr, addrlen_ptr, peer)
    {
        return errno(err);
    }
    let reported = if flags & MSG_TRUNC != 0 {
        result.full_len
    } else {
        result.data.len()
    };
    reported as u64
}

struct MsgHdr {
    msg_name: u64,
    msg_namelen: u32,
    msg_iov: u64,
    msg_iovlen: usize,
    msg_flags: u32,
}

fn read_msghdr<M: UserMemory>(memory: &M, ptr: u64) -> Result<MsgHdr, u64> {
    let mut raw = [0u8; MSGHDR_LEN];
    memory.read(ptr, &mut raw).map_err(|_| EFAULT)?;
    let msg_name = u64::from_le_bytes(raw[0..8].try_into().unwrap());
    let msg_namelen = u32::from_le_bytes(raw[8..12].try_into().unwrap());
    let msg_iov = u64::from_le_bytes(raw[16..24].try_into().unwrap());
    let raw_iovlen = u64::from_le_bytes(raw[24..32].try_into().unwrap());
    if raw_iovlen > UIO_MAXIOV as u64 {
        return Err(EMSGSIZE);
    }
    let msg_flags = u32::from_le_bytes(raw[48..52].try_into().unwrap());
    Ok(MsgHdr {
        msg_name,
        msg_namelen,
        msg_iov,
        msg_iovlen: raw_iovlen as usize,
        msg_flags,
    })
}

fn read_iovecs<M: UserMemory>(
    memory: &M,
    iov_ptr: u64,
    iovlen: usize,
) -> Result<Vec<(u64, usize)>, u64> {
    let mut iovecs = Vec::with_capacity(iovlen);
    let mut total = 0usize;
    for index in 0..iovlen {
        let mut raw = [0u8; IOVEC_LEN];
        let offset = (index as u64)
            .checked_mul(IOVEC_LEN as u64)
            .and_then(|o| iov_ptr.checked_add(o))
            .ok_or(EFAULT)?;
        memory.read(offset, &mut raw).map_err(|_| EFAULT)?;
        let base = u64::from_le_bytes(raw[0..8].try_into().unwrap());
        let len = u64::from_le_bytes(raw[8..16].try_into().unwrap());
        let len = usize::try_from(len).map_err(|_| EINVAL)?;
        total = total.checked_add(len).ok_or(EINVAL)?;
        if total as u64 > MAX_RW_COUNT {
            return Err(EINVAL);
        }
        iovecs.push((base, len));
    }
    Ok(iovecs)
}

async fn sendmsg_one<N: SocketNetwork, M: UserMemory, Net: Network<N>>(
    sock: &Socket<N>,
    msg_ptr: u64,
    flags: u32,
    ctx: SocketContext,
    memory: &M,
    net: &Net,
) -> Result<usize, u64> {
    let hdr = read_msghdr(memory, msg_ptr)?;
    let dest = parse_send_dest(sock, memory, hdr.msg_name, hdr.msg_namelen)?;
    let iovecs = read_iovecs(memory, hdr.msg_iov, hdr.msg_iovlen)?;
    let total: usize = iovecs.iter().map(|(_, len)| *len).sum();
    let mut data = Vec::with_capacity(total);
    for (base, len) in iovecs {
        if len == 0 {
            continue;
        }
        let start = data.len();
        data.resize(start + len, 0);
        memory.read(base, &mut data[start..]).map_err(|_| EFAULT)?;
    }
    socket_send(sock, data, flags, dest, ctx, net).await
}

async fn recvmsg_one<N: SocketNetwork, M: UserMemory, Net: Network<N>>(
    sock: &Socket<N>,
    msg_ptr: u64,
    flags: u32,
    timeout_bound: Option<u64>,
    memory: &mut M,
    net: &Net,
) -> Result<usize, u64> {
    let hdr = read_msghdr(memory, msg_ptr)?;
    let iovecs = read_iovecs(memory, hdr.msg_iov, hdr.msg_iovlen)?;
    let total: usize = iovecs.iter().map(|(_, len)| *len).sum();
    for &(base, len) in &iovecs {
        if len > 0 && memory.check_writable(base, len).is_err() {
            return Err(EFAULT);
        }
    }
    let result =
        socket_recv_bounded(sock, total, flags & !MSG_CMSG_CLOEXEC, timeout_bound, net).await?;
    let mut offset = 0usize;
    for (base, len) in iovecs {
        if offset >= result.data.len() {
            break;
        }
        let take = len.min(result.data.len() - offset);
        if take > 0 {
            memory
                .write(base, &result.data[offset..offset + take])
                .map_err(|_| EFAULT)?;
            offset += take;
        }
    }
    let out_namelen = if let Some(peer) = result.peer {
        if hdr.msg_name != 0 {
            let mut encoded = [0u8; SOCKADDR_IN6_LEN];
            let full = match peer {
                RecvPeer::Inet(addr) => encode_sockaddr(addr, &mut encoded),
                RecvPeer::Netlink { pid, groups } => {
                    encoded[0..2].copy_from_slice(&AF_NETLINK.to_ne_bytes());
                    encoded[4..8].copy_from_slice(&pid.to_ne_bytes());
                    encoded[8..12].copy_from_slice(&groups.to_ne_bytes());
                    netlink::SOCKADDR_NL_LEN
                }
                RecvPeer::Packet(sll) => {
                    encoded[0..2].copy_from_slice(&AF_PACKET.to_ne_bytes());
                    encoded[2..4].copy_from_slice(&sll.protocol.to_be_bytes());
                    encoded[4..8].copy_from_slice(&(sll.ifindex as i32).to_ne_bytes());
                    encoded[8..10].copy_from_slice(&sll.hatype.to_ne_bytes());
                    encoded[10] = sll.pkttype;
                    encoded[11] = sll.halen;
                    encoded[12..20].copy_from_slice(&sll.addr);
                    packet::SOCKADDR_LL_LEN
                }
            };
            let copy = (hdr.msg_namelen as usize).min(full);
            if copy > 0 {
                memory
                    .write(hdr.msg_name, &encoded[..copy])
                    .map_err(|_| EFAULT)?;
            }
            full as u32
        } else {
            0
        }
    } else {
        0
    };
    let out_flags = if result.truncated { MSG_TRUNC } else { 0 };
    // Write back `msg_namelen`, `msg_controllen = 0`, and `msg_flags`.
    memory
        .write(msg_ptr + 8, &out_namelen.to_le_bytes())
        .map_err(|_| EFAULT)?;
    memory
        .write(msg_ptr + 40, &0u64.to_le_bytes())
        .map_err(|_| EFAULT)?;
    memory
        .write(msg_ptr + 48, &out_flags.to_le_bytes())
        .map_err(|_| EFAULT)?;
    let _ = hdr.msg_flags;
    Ok(if flags & MSG_TRUNC != 0 {
        result.full_len
    } else {
        result.data.len()
    })
}

pub(crate) async fn sendmsg<R: Resources, M: UserMemory, Net: Network<R::Network>>(
    descriptors: &spin::Mutex<Descriptors<R>>,
    args: [u64; 6],
    ctx: SocketContext,
    memory: &M,
    net: &Net,
) -> u64 {
    let fd = args[0] as u32 as i32;
    let msg_ptr = args[1];
    let flags = args[2] as u32;
    let sock = match get_socket::<R>(descriptors, fd) {
        Ok(sock) => sock,
        Err(err) => return errno(err),
    };
    match sendmsg_one(&sock, msg_ptr, flags, ctx, memory, net).await {
        Ok(sent) => sent as u64,
        Err(err) => errno(err),
    }
}

pub(crate) async fn recvmsg<R: Resources, M: UserMemory, Net: Network<R::Network>>(
    descriptors: &spin::Mutex<Descriptors<R>>,
    args: [u64; 6],
    memory: &mut M,
    net: &Net,
) -> u64 {
    let fd = args[0] as u32 as i32;
    let msg_ptr = args[1];
    let flags = args[2] as u32;
    let sock = match get_socket::<R>(descriptors, fd) {
        Ok(sock) => sock,
        Err(err) => return errno(err),
    };
    match recvmsg_one(&sock, msg_ptr, flags, None, memory, net).await {
        Ok(read) => read as u64,
        Err(err) => errno(err),
    }
}

pub(crate) async fn sendmmsg<R: Resources, M: UserMemory, Net: Network<R::Network>>(
    descriptors: &spin::Mutex<Descriptors<R>>,
    args: [u64; 6],
    ctx: SocketContext,
    memory: &mut M,
    net: &Net,
) -> u64 {
    let fd = args[0] as u32 as i32;
    let vec_ptr = args[1];
    let vlen = (args[2] as u32 as usize).min(MAX_MMSG);
    let flags = args[3] as u32;
    let sock = match get_socket::<R>(descriptors, fd) {
        Ok(sock) => sock,
        Err(err) => return errno(err),
    };
    let mut sent_count = 0usize;
    for index in 0..vlen {
        let Some(entry_ptr) = (index as u64)
            .checked_mul(MMSGHDR_LEN as u64)
            .and_then(|o| vec_ptr.checked_add(o))
        else {
            return if sent_count > 0 {
                sent_count as u64
            } else {
                errno(EFAULT)
            };
        };
        match sendmsg_one(&sock, entry_ptr, flags, ctx, memory, net).await {
            Ok(bytes) => {
                if memory
                    .write(entry_ptr + 56, &(bytes as u32).to_le_bytes())
                    .is_err()
                {
                    return if sent_count > 0 {
                        sent_count as u64
                    } else {
                        errno(EFAULT)
                    };
                }
                sent_count += 1;
            }
            Err(err) => {
                return if sent_count > 0 {
                    sent_count as u64
                } else {
                    errno(err)
                };
            }
        }
    }
    sent_count as u64
}

pub(crate) async fn recvmmsg<
    R: Resources,
    M: UserMemory,
    Net: Network<R::Network> + super::Clock,
>(
    descriptors: &spin::Mutex<Descriptors<R>>,
    args: [u64; 6],
    memory: &mut M,
    net: &Net,
) -> u64 {
    let fd = args[0] as u32 as i32;
    let vec_ptr = args[1];
    let vlen = (args[2] as u32 as usize).min(MAX_MMSG);
    let mut flags = args[3] as u32;
    let timeout_ptr = args[4];
    let deadline = if timeout_ptr != 0 {
        let mut raw = [0u8; 16];
        if memory.read(timeout_ptr, &mut raw).is_err() {
            return errno(EFAULT);
        }
        let sec = i64::from_le_bytes(raw[0..8].try_into().unwrap());
        let nsec = i64::from_le_bytes(raw[8..16].try_into().unwrap());
        if sec < 0 || !(0..1_000_000_000).contains(&nsec) {
            return errno(EINVAL);
        }
        let timeout_nanos = (sec as u64)
            .saturating_mul(1_000_000_000)
            .saturating_add(nsec as u64);
        Some(net.now_nanos().saturating_add(timeout_nanos))
    } else {
        None
    };
    let sock = match get_socket::<R>(descriptors, fd) {
        Ok(sock) => sock,
        Err(err) => return errno(err),
    };
    let wait_for_one = flags & MSG_WAITFORONE != 0;
    flags &= !MSG_WAITFORONE;
    let mut recv_count = 0usize;
    for index in 0..vlen {
        let timeout_bound = if let Some(end) = deadline {
            let rem = end.saturating_sub(net.now_nanos());
            if rem == 0 && recv_count > 0 {
                break;
            }
            Some(rem)
        } else {
            None
        };
        let Some(entry_ptr) = (index as u64)
            .checked_mul(MMSGHDR_LEN as u64)
            .and_then(|o| vec_ptr.checked_add(o))
        else {
            return if recv_count > 0 {
                recv_count as u64
            } else {
                errno(EFAULT)
            };
        };
        let iter_flags = if (wait_for_one && recv_count > 0) || timeout_bound == Some(0) {
            flags | MSG_DONTWAIT
        } else {
            flags
        };
        match recvmsg_one(&sock, entry_ptr, iter_flags, timeout_bound, memory, net).await {
            Ok(bytes) => {
                if memory
                    .write(entry_ptr + 56, &(bytes as u32).to_le_bytes())
                    .is_err()
                {
                    return if recv_count > 0 {
                        recv_count as u64
                    } else {
                        errno(EFAULT)
                    };
                }
                recv_count += 1;
            }
            Err(err) => {
                return if recv_count > 0 {
                    recv_count as u64
                } else {
                    errno(err)
                };
            }
        }
    }
    recv_count as u64
}

pub(crate) async fn shutdown<R: Resources, Net: Network<R::Network>>(
    descriptors: &spin::Mutex<Descriptors<R>>,
    args: [u64; 6],
    net: &Net,
) -> u64 {
    let fd = args[0] as u32 as i32;
    let how = args[1] as u32;
    if !matches!(how, SHUT_RD | SHUT_WR | SHUT_RDWR) {
        return errno(EINVAL);
    }
    let sock = match get_socket::<R>(descriptors, fd) {
        Ok(sock) => sock,
        Err(err) => return errno(err),
    };
    let shut_rd = matches!(how, SHUT_RD | SHUT_RDWR);
    let shut_wr = matches!(how, SHUT_WR | SHUT_RDWR);

    if let Some((reader, writer)) = sock.pair_ends() {
        if shut_rd {
            sock.mark_shutdown_read();
            reader.close();
        }
        if shut_wr {
            sock.mark_shutdown_write();
            writer.close();
        }
        return 0;
    }

    if let Some(tcp) = sock.tcp_state() {
        let TcpSocket::Connected { stream, .. } = tcp else {
            return errno(ENOTCONN);
        };
        if shut_rd {
            sock.mark_shutdown_read();
        }
        if shut_wr {
            sock.mark_shutdown_write();
            if let Err(err) = net.tcp_shutdown_send(stream.id()).await {
                return errno(err);
            }
        }
        return 0;
    }

    if let Some(udp) = sock.udp_state() {
        if !matches!(udp, UdpSocket::Bound { peer: Some(_), .. }) {
            return errno(ENOTCONN);
        }
        if shut_rd {
            sock.mark_shutdown_read();
        }
        if shut_wr {
            sock.mark_shutdown_write();
        }
        return 0;
    }

    errno(ENOTSOCK)
}

pub(crate) async fn sendfile<
    R: Resources,
    M: super::VirtualMemory,
    O: Network<R::Network> + super::Stdio + super::Filesystem<R>,
>(
    process: &Process<R>,
    args: [u64; 6],
    memory: &mut M,
    output: &mut O,
) -> u64 {
    let out_fd = args[0] as u32 as i32;
    let in_fd = args[1] as u32 as i32;
    let offset_ptr = args[2];
    let count = args[3].min(MAX_RW_COUNT) as usize;

    let (out_entry, in_entry) = {
        let table = process.shared.descriptors.lock();
        let Some(out_entry) = table.get_entry(out_fd).cloned() else {
            return errno(EBADF);
        };
        let Some(in_entry) = table.get_entry(in_fd).cloned() else {
            return errno(EBADF);
        };
        (out_entry, in_entry)
    };

    // Linux `fs/read_write.c:do_sendfile`: `in_fd` must be a readable regular
    // file (mmap-capable). Non-seekable inputs (pipes, sockets, stdin) fail
    // with `ESPIPE` when `offset != NULL` and `EINVAL` when `offset == NULL`.
    let in_open = match &in_entry.descriptor {
        Descriptor::<R>::File(open) => {
            if !matches!(
                output.file_access(open.node()),
                super::FileAccess::ReadOnly | super::FileAccess::ReadWrite
            ) {
                return errno(EBADF);
            }
            if output.file_is_directory(open.node()) {
                return errno(EINVAL);
            }
            open.clone()
        }
        _ => {
            return if offset_ptr != 0 {
                errno(ESPIPE)
            } else {
                errno(EINVAL)
            };
        }
    };

    let explicit_offset = if offset_ptr != 0 {
        if memory.check_writable(offset_ptr, 8).is_err() {
            return errno(EFAULT);
        }
        let mut raw = [0u8; 8];
        if memory.read(offset_ptr, &mut raw).is_err() {
            return errno(EFAULT);
        }
        let off = i64::from_le_bytes(raw);
        if off < 0 {
            return errno(EINVAL);
        }
        Some(off as u64)
    } else {
        None
    };

    match &out_entry.descriptor {
        Descriptor::<R>::Socket(_)
        | Descriptor::<R>::PipeWrite { .. }
        | Descriptor::<R>::Stdout
        | Descriptor::<R>::Stderr => {}
        Descriptor::<R>::File(out_open) => {
            if !matches!(
                output.file_access(out_open.node()),
                super::FileAccess::WriteOnly | super::FileAccess::ReadWrite
            ) {
                return errno(EBADF);
            }
            if output.file_is_directory(out_open.node()) {
                return errno(EINVAL);
            }
            // Linux `fs/read_write.c:do_sendfile` rejects `O_APPEND` on `out_fd`.
            if out_entry.fdflags() & helios_unix::FDFLAG_APPEND != 0 {
                return errno(EINVAL);
            }
        }
        _ => return errno(EINVAL),
    }

    if count == 0 {
        return 0;
    }

    super::memory::flush_file_shared_mappings(process, in_open.node(), memory, output).await;

    let out_nonblocking = out_entry.fdflags() & helios_unix::FDFLAG_NONBLOCK != 0;
    let mut total_sent = 0usize;

    while total_sent < count {
        let chunk_len = (count - total_sent).min(SENDFILE_CHUNK);
        // Never hold `in_open`'s position lock across `out_fd` I/O or
        // `out_open.lock_position()` — holding both deadlocks `sendfile(fd, fd, NULL, n)`
        // and concurrent opposite-direction transfers.
        let read_pos = match explicit_offset {
            Some(base) => base.saturating_add(total_sent as u64),
            None => in_open.lock_position().await.get(),
        };
        let chunk = match output.read_at(in_open.node(), read_pos, chunk_len).await {
            Ok(bytes) => bytes,
            Err(_) => {
                if total_sent > 0 {
                    break;
                }
                return errno(super::EIO);
            }
        };
        if chunk.is_empty() {
            break;
        }
        let sent = match &out_entry.descriptor {
            Descriptor::<R>::Socket(sock) => {
                match socket_send(
                    sock,
                    chunk.to_vec(),
                    0,
                    None,
                    SocketContext::default(),
                    output,
                )
                .await
                {
                    Ok(n) => n,
                    Err(err) => {
                        if total_sent > 0 {
                            break;
                        }
                        return errno(err);
                    }
                }
            }
            Descriptor::<R>::PipeWrite { writer } => {
                let len = chunk.len();
                if out_nonblocking {
                    match writer.try_write(chunk) {
                        helios_sync::TryWrite::Written => len,
                        helios_sync::TryWrite::Full(_) => {
                            if total_sent > 0 {
                                break;
                            }
                            return errno(EAGAIN);
                        }
                        helios_sync::TryWrite::Closed => {
                            if total_sent > 0 {
                                break;
                            }
                            return errno(EPIPE);
                        }
                    }
                } else {
                    match writer.write(chunk).await {
                        Ok(()) => len,
                        Err(helios_sync::ClosedPeer) => {
                            if total_sent > 0 {
                                break;
                            }
                            return errno(EPIPE);
                        }
                    }
                }
            }
            Descriptor::<R>::Stdout => match output.write(super::Stream::Stdout, &chunk).await {
                Ok(n) => n,
                Err(err) => {
                    if total_sent > 0 {
                        break;
                    }
                    return errno(match err {
                        super::WriteError::Denied => EACCES,
                        super::WriteError::Io => EPIPE,
                        super::WriteError::Interrupted => super::EINTR,
                        super::WriteError::WouldBlock => EAGAIN,
                    });
                }
            },
            Descriptor::<R>::Stderr => match output.write(super::Stream::Stderr, &chunk).await {
                Ok(n) => n,
                Err(err) => {
                    if total_sent > 0 {
                        break;
                    }
                    return errno(match err {
                        super::WriteError::Denied => EACCES,
                        super::WriteError::Io => EPIPE,
                        super::WriteError::Interrupted => super::EINTR,
                        super::WriteError::WouldBlock => EAGAIN,
                    });
                }
            },
            Descriptor::<R>::File(out_open) => {
                let landed = {
                    let mut out_pos = out_open.lock_position().await;
                    let pos = WritePosition::At(out_pos.get());
                    match output.write_at(out_open.node(), pos, &chunk).await {
                        Ok(landed) => {
                            out_pos.set(landed.offset.saturating_add(landed.len as u64));
                            landed
                        }
                        Err(_) => {
                            if total_sent > 0 {
                                break;
                            }
                            return errno(super::EIO);
                        }
                    }
                };
                if landed.len > 0 {
                    super::memory::sync_write_to_shared_mappings(
                        process,
                        out_open.node(),
                        landed.offset,
                        &chunk[..landed.len],
                        memory,
                        output,
                    );
                }
                landed.len
            }
            _ => unreachable!(),
        };
        if explicit_offset.is_none() && sent > 0 {
            let mut pos = in_open.lock_position().await;
            pos.set(read_pos.saturating_add(sent as u64));
        }
        total_sent += sent;
        if sent < chunk_len {
            break;
        }
    }

    if let Some(base) = explicit_offset {
        let updated = base.saturating_add(total_sent as u64) as i64;
        if memory.write(offset_ptr, &updated.to_le_bytes()).is_err() {
            return errno(EFAULT);
        }
    }
    total_sent as u64
}

fn read_opt_i32<M: UserMemory>(memory: &M, ptr: u64, len: u32) -> Result<i32, u64> {
    if (len as usize) < 4 {
        return Err(EINVAL);
    }
    let mut raw = [0u8; 4];
    memory.read(ptr, &mut raw).map_err(|_| EFAULT)?;
    Ok(i32::from_le_bytes(raw))
}

/// Reads an option value that Linux (`ip(7)`) accepts as either a 1-byte
/// `unsigned char` (`optlen == 1`) or a 4-byte `int` (`optlen >= 4`).
fn read_opt_i32_or_u8<M: UserMemory>(memory: &M, ptr: u64, len: u32) -> Result<i32, u64> {
    if len == 1 {
        let mut raw = [0u8; 1];
        memory.read(ptr, &mut raw).map_err(|_| EFAULT)?;
        Ok(i32::from(raw[0]))
    } else {
        read_opt_i32(memory, ptr, len)
    }
}

fn write_opt_bytes<M: UserMemory>(
    memory: &mut M,
    val_ptr: u64,
    len_ptr: u64,
    bytes: &[u8],
) -> Result<(), u64> {
    let mut len_raw = [0u8; 4];
    memory.read(len_ptr, &mut len_raw).map_err(|_| EFAULT)?;
    let avail = i32::from_le_bytes(len_raw);
    if avail < 0 {
        return Err(EINVAL);
    }
    let copy = (avail as usize).min(bytes.len());
    if copy > 0 {
        memory.write(val_ptr, &bytes[..copy]).map_err(|_| EFAULT)?;
    }
    memory
        .write(len_ptr, &(copy as u32).to_le_bytes())
        .map_err(|_| EFAULT)?;
    Ok(())
}

fn option_error_errno(err: SocketOptionError) -> u64 {
    match err {
        SocketOptionError::Unsupported => EOPNOTSUPP,
        SocketOptionError::Invalid => EINVAL,
    }
}

fn apply_hop_limit<N: SocketNetwork, Net: Network<N>>(
    sock: &Socket<N>,
    hop_limit: u8,
    net: &Net,
) -> Result<(), u64> {
    if let Some(tcp) = sock.tcp_state() {
        match tcp {
            TcpSocket::Connected { stream, .. } | TcpSocket::Connecting { stream, .. } => {
                net.tcp_set_hop_limit(stream.id(), hop_limit)?;
            }
            TcpSocket::Listening { listener, .. } => {
                net.tcp_listener_set_hop_limit(listener.id(), hop_limit)?;
            }
            TcpSocket::Unconnected { .. } | TcpSocket::Bound { .. } => {}
        }
    } else if let Some(UdpSocket::Bound { socket, .. }) = sock.udp_state() {
        net.udp_set_hop_limit(socket.id(), hop_limit)?;
    }
    Ok(())
}

pub(crate) async fn setsockopt<R: Resources, M: UserMemory, Net: Network<R::Network>>(
    descriptors: &spin::Mutex<Descriptors<R>>,
    args: [u64; 6],
    memory: &M,
    net: &Net,
) -> u64 {
    let fd = args[0] as u32 as i32;
    let level = args[1] as i32;
    let optname = args[2] as i32;
    let optval = args[3];
    let optlen = args[4] as u32;

    let sock = match get_socket::<R>(descriptors, fd) {
        Ok(sock) => sock,
        Err(err) => return errno(err),
    };

    match (level, optname) {
        (SOL_SOCKET, SO_REUSEADDR)
        | (SOL_SOCKET, SO_REUSEPORT)
        | (SOL_SOCKET, SO_KEEPALIVE)
        | (SOL_SOCKET, SO_BROADCAST)
        | (SOL_SOCKET, SO_DONTROUTE)
        | (SOL_SOCKET, SO_OOBINLINE)
        | (IPPROTO_TCP, TCP_NODELAY)
        | (IPPROTO_IP, IP_MULTICAST_LOOP)
        | (IPPROTO_IPV6, IPV6_V6ONLY)
        | (IPPROTO_IPV6, IPV6_MULTICAST_LOOP) => {
            if level == IPPROTO_TCP && !sock.is_tcp() {
                return errno(EOPNOTSUPP);
            }
            let raw_val = if (level, optname) == (IPPROTO_IP, IP_MULTICAST_LOOP) {
                read_opt_i32_or_u8(memory, optval, optlen)
            } else {
                read_opt_i32(memory, optval, optlen)
            };
            let val = match raw_val {
                Ok(v) => v != 0,
                Err(err) => return errno(err),
            };
            let flag = match (level, optname) {
                (SOL_SOCKET, SO_REUSEADDR) => SocketFlag::ReuseAddr,
                (SOL_SOCKET, SO_REUSEPORT) => SocketFlag::ReusePort,
                (SOL_SOCKET, SO_KEEPALIVE) => SocketFlag::KeepAlive,
                (SOL_SOCKET, SO_BROADCAST) => SocketFlag::Broadcast,
                (SOL_SOCKET, SO_DONTROUTE) => SocketFlag::DontRoute,
                (SOL_SOCKET, SO_OOBINLINE) => SocketFlag::OobInline,
                (IPPROTO_TCP, TCP_NODELAY) => SocketFlag::NoDelay,
                (IPPROTO_IP, IP_MULTICAST_LOOP) => SocketFlag::MulticastLoopV4,
                (IPPROTO_IPV6, IPV6_V6ONLY) => SocketFlag::OnlyV6,
                (IPPROTO_IPV6, IPV6_MULTICAST_LOOP) => SocketFlag::MulticastLoopV6,
                _ => unreachable!(),
            };
            match sock.set_flag(flag, val) {
                Ok(()) => 0,
                Err(err) => errno(option_error_errno(err)),
            }
        }
        (SOL_SOCKET, SO_BINDTODEVICE) => {
            let unbind = if optlen == 0 {
                true
            } else {
                let len = (optlen as usize).min(16);
                let mut name = vec![0u8; len];
                if memory.read(optval, &mut name).is_err() {
                    return errno(EFAULT);
                }
                let nul = name.iter().position(|&b| b == 0).unwrap_or(name.len());
                if nul == 0 {
                    true
                } else {
                    let ifindex = match netlink::lookup_ifindex(&name[..nul]) {
                        Ok(idx) => idx,
                        Err(err) => return errno(err),
                    };
                    if let Some(pkt) = sock.packet_state() {
                        if let Err(err) = net.packet_bind(pkt.handle.id(), pkt.protocol, ifindex) {
                            return errno(err);
                        }
                        let _ = sock.with_packet_mut(|p| p.ifindex = ifindex);
                        return 0;
                    }
                    return errno(EOPNOTSUPP);
                }
            };
            if unbind {
                if let Some(pkt) = sock.packet_state() {
                    if let Err(err) = net.packet_bind(pkt.handle.id(), pkt.protocol, 0) {
                        return errno(err);
                    }
                    let _ = sock.with_packet_mut(|p| p.ifindex = 0);
                }
                0
            } else {
                0
            }
        }
        (SOL_PACKET, PACKET_AUXDATA) if sock.is_packet() => {
            let val = match read_opt_i32(memory, optval, optlen) {
                Ok(v) => v,
                Err(err) => return errno(err),
            };
            if val == 0 { 0 } else { errno(EOPNOTSUPP) }
        }
        (SOL_SOCKET, SO_RCVBUF)
        | (SOL_SOCKET, SO_SNDBUF)
        | (SOL_SOCKET, SO_RCVLOWAT)
        | (SOL_SOCKET, SO_SNDLOWAT) => {
            let val = match read_opt_i32(memory, optval, optlen) {
                Ok(v) if v >= 0 => v as u64,
                Ok(_) => return errno(EINVAL),
                Err(err) => return errno(err),
            };
            let size = match optname {
                SO_RCVBUF => SocketSize::ReceiveBuffer,
                SO_SNDBUF => SocketSize::SendBuffer,
                SO_RCVLOWAT => SocketSize::ReceiveLowWater,
                SO_SNDLOWAT => SocketSize::SendLowWater,
                _ => unreachable!(),
            };
            match sock.set_size(size, val) {
                Ok(()) => 0,
                Err(err) => errno(option_error_errno(err)),
            }
        }
        (IPPROTO_IP, IP_TTL) | (IPPROTO_IPV6, IPV6_UNICAST_HOPS) => {
            let val = match read_opt_i32(memory, optval, optlen) {
                Ok(-1) => 64u64,
                Ok(v) if (1..=255).contains(&v) => v as u64,
                Ok(_) => return errno(EINVAL),
                Err(err) => return errno(err),
            };
            if let Err(err) = sock.set_size(SocketSize::Ttl, val) {
                return errno(option_error_errno(err));
            }
            match apply_hop_limit(&sock, val as u8, net) {
                Ok(()) => 0,
                Err(err) => errno(err),
            }
        }
        (IPPROTO_IP, IP_MULTICAST_TTL) => {
            let val = match read_opt_i32_or_u8(memory, optval, optlen) {
                Ok(-1) => 1u64,
                Ok(v) if (0..=255).contains(&v) => v as u64,
                Ok(_) => return errno(EINVAL),
                Err(err) => return errno(err),
            };
            match sock.set_size(SocketSize::MulticastTtlV4, val) {
                Ok(()) => 0,
                Err(err) => errno(option_error_errno(err)),
            }
        }
        (SOL_SOCKET, SO_RCVTIMEO) | (SOL_SOCKET, SO_SNDTIMEO) => {
            if (optlen as usize) < 16 {
                return errno(EINVAL);
            }
            let mut raw = [0u8; 16];
            if memory.read(optval, &mut raw).is_err() {
                return errno(EFAULT);
            }
            let sec = i64::from_le_bytes(raw[0..8].try_into().unwrap());
            let usec = i64::from_le_bytes(raw[8..16].try_into().unwrap());
            if sec < 0 || !(0..1_000_000).contains(&usec) {
                return errno(EINVAL);
            }
            let nanos = if sec == 0 && usec == 0 {
                None
            } else {
                Some(
                    (sec as u64)
                        .saturating_mul(1_000_000_000)
                        .saturating_add((usec as u64).saturating_mul(1_000)),
                )
            };
            let opt = if optname == SO_RCVTIMEO {
                SocketTime::ReceiveTimeout
            } else {
                SocketTime::SendTimeout
            };
            sock.set_time(opt, nanos);
            0
        }
        (SOL_SOCKET, SO_LINGER) => {
            if (optlen as usize) < 8 {
                return errno(EINVAL);
            }
            let mut raw = [0u8; 8];
            if memory.read(optval, &mut raw).is_err() {
                return errno(EFAULT);
            }
            let onoff = i32::from_le_bytes(raw[0..4].try_into().unwrap());
            let linger_sec = i32::from_le_bytes(raw[4..8].try_into().unwrap());
            if onoff != 0 && linger_sec < 0 {
                return errno(EINVAL);
            }
            let nanos = if onoff == 0 {
                None
            } else {
                Some((linger_sec as u64).saturating_mul(1_000_000_000))
            };
            sock.set_time(SocketTime::Linger, nanos);
            0
        }
        (IPPROTO_IP, IP_ADD_MEMBERSHIP) | (IPPROTO_IP, IP_DROP_MEMBERSHIP) => {
            if !sock.is_udp() {
                return errno(ENOPROTOOPT);
            }
            if (optlen as usize) < 8 {
                return errno(EINVAL);
            }
            let mut raw = [0u8; 8];
            if memory.read(optval, &mut raw).is_err() {
                return errno(EFAULT);
            }
            let group = [raw[0], raw[1], raw[2], raw[3]];
            let interface = [raw[4], raw[5], raw[6], raw[7]];
            let res = if optname == IP_ADD_MEMBERSHIP {
                net.udp_join_multicast_v4(group, interface).await
            } else {
                net.udp_leave_multicast_v4(group, interface).await
            };
            match res {
                Ok(()) => 0,
                Err(err) => errno(err),
            }
        }
        (IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP) | (IPPROTO_IPV6, IPV6_DROP_MEMBERSHIP) => {
            if !sock.is_udp() {
                return errno(ENOPROTOOPT);
            }
            if (optlen as usize) < 20 {
                return errno(EINVAL);
            }
            let mut raw = [0u8; 20];
            if memory.read(optval, &mut raw).is_err() {
                return errno(EFAULT);
            }
            match net.check_multicast_v6() {
                Ok(()) => errno(EOPNOTSUPP),
                Err(err) => errno(err),
            }
        }
        _ => errno(ENOPROTOOPT),
    }
}

pub(crate) async fn getsockopt<R: Resources, M: UserMemory, Net: Network<R::Network>>(
    descriptors: &spin::Mutex<Descriptors<R>>,
    args: [u64; 6],
    memory: &mut M,
    net: &Net,
) -> u64 {
    let fd = args[0] as u32 as i32;
    let level = args[1] as i32;
    let optname = args[2] as i32;
    let optval = args[3];
    let optlen_ptr = args[4];

    let sock = match get_socket::<R>(descriptors, fd) {
        Ok(sock) => sock,
        Err(err) => return errno(err),
    };
    let options = sock.options();

    match (level, optname) {
        (SOL_SOCKET, SO_ERROR) => {
            let _ = poll_connecting(&sock, net).await;
            let err = sock.take_pending_error();
            match write_opt_bytes(memory, optval, optlen_ptr, &err.to_le_bytes()) {
                Ok(()) => 0,
                Err(e) => errno(e),
            }
        }
        (SOL_SOCKET, SO_TYPE) => {
            let ty: i32 = match sock.kind() {
                SocketKind::Stream => SOCK_STREAM as i32,
                SocketKind::Datagram => SOCK_DGRAM as i32,
                SocketKind::Raw => SOCK_RAW as i32,
            };
            match write_opt_bytes(memory, optval, optlen_ptr, &ty.to_le_bytes()) {
                Ok(()) => 0,
                Err(e) => errno(e),
            }
        }
        (SOL_SOCKET, SO_PROTOCOL) => {
            let proto: i32 = if let Some(nl) = sock.netlink_state() {
                nl.protocol as i32
            } else if let Some(pkt) = sock.packet_state() {
                i32::from(pkt.protocol.to_be())
            } else {
                match sock.protocol() {
                    Some(TransportProtocol::Tcp) => IPPROTO_TCP,
                    Some(TransportProtocol::Udp) => IPPROTO_UDP,
                    None => 0,
                }
            };
            match write_opt_bytes(memory, optval, optlen_ptr, &proto.to_le_bytes()) {
                Ok(()) => 0,
                Err(e) => errno(e),
            }
        }
        (SOL_SOCKET, SO_DOMAIN) => {
            let domain: i32 = if sock.is_netlink() {
                i32::from(AF_NETLINK)
            } else if sock.is_packet() {
                i32::from(AF_PACKET)
            } else {
                match sock.family() {
                    Some(SocketFamily::Ipv4) => i32::from(AF_INET),
                    Some(SocketFamily::Ipv6) => i32::from(AF_INET6),
                    None => i32::from(AF_UNIX),
                }
            };
            match write_opt_bytes(memory, optval, optlen_ptr, &domain.to_le_bytes()) {
                Ok(()) => 0,
                Err(e) => errno(e),
            }
        }
        (SOL_SOCKET, SO_ACCEPTCONN) => {
            let listening: i32 = i32::from(matches!(
                sock.tcp_state(),
                Some(TcpSocket::Listening { .. })
            ));
            match write_opt_bytes(memory, optval, optlen_ptr, &listening.to_le_bytes()) {
                Ok(()) => 0,
                Err(e) => errno(e),
            }
        }
        (SOL_SOCKET, SO_REUSEADDR)
        | (SOL_SOCKET, SO_REUSEPORT)
        | (SOL_SOCKET, SO_KEEPALIVE)
        | (SOL_SOCKET, SO_BROADCAST)
        | (SOL_SOCKET, SO_DONTROUTE)
        | (SOL_SOCKET, SO_OOBINLINE)
        | (IPPROTO_TCP, TCP_NODELAY)
        | (IPPROTO_IP, IP_MULTICAST_LOOP)
        | (IPPROTO_IPV6, IPV6_V6ONLY)
        | (IPPROTO_IPV6, IPV6_MULTICAST_LOOP) => {
            if level == IPPROTO_TCP && !sock.is_tcp() {
                return errno(EOPNOTSUPP);
            }
            let flag = match (level, optname) {
                (SOL_SOCKET, SO_REUSEADDR) => SocketFlag::ReuseAddr,
                (SOL_SOCKET, SO_REUSEPORT) => SocketFlag::ReusePort,
                (SOL_SOCKET, SO_KEEPALIVE) => SocketFlag::KeepAlive,
                (SOL_SOCKET, SO_BROADCAST) => SocketFlag::Broadcast,
                (SOL_SOCKET, SO_DONTROUTE) => SocketFlag::DontRoute,
                (SOL_SOCKET, SO_OOBINLINE) => SocketFlag::OobInline,
                (IPPROTO_TCP, TCP_NODELAY) => SocketFlag::NoDelay,
                (IPPROTO_IP, IP_MULTICAST_LOOP) => SocketFlag::MulticastLoopV4,
                (IPPROTO_IPV6, IPV6_V6ONLY) => SocketFlag::OnlyV6,
                (IPPROTO_IPV6, IPV6_MULTICAST_LOOP) => SocketFlag::MulticastLoopV6,
                _ => unreachable!(),
            };
            let val: i32 = i32::from(options.flag(flag));
            match write_opt_bytes(memory, optval, optlen_ptr, &val.to_le_bytes()) {
                Ok(()) => 0,
                Err(e) => errno(e),
            }
        }
        (SOL_SOCKET, SO_RCVBUF)
        | (SOL_SOCKET, SO_SNDBUF)
        | (SOL_SOCKET, SO_RCVLOWAT)
        | (SOL_SOCKET, SO_SNDLOWAT)
        | (IPPROTO_IP, IP_TTL)
        | (IPPROTO_IPV6, IPV6_UNICAST_HOPS)
        | (IPPROTO_IP, IP_MULTICAST_TTL) => {
            let size = match (level, optname) {
                (SOL_SOCKET, SO_RCVBUF) => SocketSize::ReceiveBuffer,
                (SOL_SOCKET, SO_SNDBUF) => SocketSize::SendBuffer,
                (SOL_SOCKET, SO_RCVLOWAT) => SocketSize::ReceiveLowWater,
                (SOL_SOCKET, SO_SNDLOWAT) => SocketSize::SendLowWater,
                (IPPROTO_IP, IP_TTL) | (IPPROTO_IPV6, IPV6_UNICAST_HOPS) => SocketSize::Ttl,
                (IPPROTO_IP, IP_MULTICAST_TTL) => SocketSize::MulticastTtlV4,
                _ => unreachable!(),
            };
            let val = options.size(size).min(i32::MAX as u64) as i32;
            match write_opt_bytes(memory, optval, optlen_ptr, &val.to_le_bytes()) {
                Ok(()) => 0,
                Err(e) => errno(e),
            }
        }
        (SOL_SOCKET, SO_RCVTIMEO) | (SOL_SOCKET, SO_SNDTIMEO) => {
            let opt = if optname == SO_RCVTIMEO {
                SocketTime::ReceiveTimeout
            } else {
                SocketTime::SendTimeout
            };
            let nanos = options.time(opt).unwrap_or(0);
            let sec = (nanos / 1_000_000_000) as i64;
            let usec = ((nanos % 1_000_000_000) / 1_000) as i64;
            let mut raw = [0u8; 16];
            raw[0..8].copy_from_slice(&sec.to_le_bytes());
            raw[8..16].copy_from_slice(&usec.to_le_bytes());
            match write_opt_bytes(memory, optval, optlen_ptr, &raw) {
                Ok(()) => 0,
                Err(e) => errno(e),
            }
        }
        (SOL_SOCKET, SO_LINGER) => {
            let mut raw = [0u8; 8];
            if let Some(nanos) = options.time(SocketTime::Linger) {
                raw[0..4].copy_from_slice(&1i32.to_le_bytes());
                raw[4..8].copy_from_slice(&((nanos / 1_000_000_000) as i32).to_le_bytes());
            }
            match write_opt_bytes(memory, optval, optlen_ptr, &raw) {
                Ok(()) => 0,
                Err(e) => errno(e),
            }
        }
        _ => errno(ENOPROTOOPT),
    }
}

/// Computes the Linux `epoll` readiness bitmask for a socket descriptor.
pub(crate) async fn socket_epoll_ready<N: SocketNetwork, Net: Network<N>>(
    sock: &Socket<N>,
    interest: u32,
    net: &Net,
) -> u32 {
    const EPOLLIN: u32 = 0x001;
    const EPOLLOUT: u32 = 0x004;
    const EPOLLERR: u32 = 0x008;
    const EPOLLHUP: u32 = 0x010;
    const EPOLLRDHUP: u32 = 0x2000;

    if let Some((reader, carry_len)) = sock.pair_read_probe() {
        let mut ready = 0;
        if carry_len > 0 || reader.has_buffered_data() {
            ready |= EPOLLIN;
        }
        if reader.is_writer_closed() {
            ready |= EPOLLIN | EPOLLHUP | EPOLLRDHUP;
        }
        if let Some(writer) = sock.pair_writer() {
            if writer.is_reader_closed() {
                ready |= EPOLLHUP;
            } else if writer.is_writable() {
                ready |= EPOLLOUT;
            }
        }
        return ready & (interest | EPOLLERR | EPOLLHUP);
    }

    if let Some(res) = poll_connecting(sock, net).await {
        return match res {
            Ok(ConnectProgress::Pending) => 0,
            Ok(ConnectProgress::Connected) => EPOLLOUT & (interest | EPOLLERR | EPOLLHUP),
            Err(_) => (EPOLLOUT | EPOLLERR | EPOLLHUP) & (interest | EPOLLERR | EPOLLHUP),
        };
    }

    if let Some(tcp) = sock.tcp_state() {
        let ready = match tcp {
            TcpSocket::Connected { stream, .. } => match net.tcp_readiness(stream.id()).await {
                Ok(state) => {
                    let mut mask = 0;
                    if state.readable || sock.is_shutdown_read() {
                        mask |= EPOLLIN;
                    }
                    if state.writable && !sock.is_shutdown_write() {
                        mask |= EPOLLOUT;
                    }
                    if state.hangup {
                        mask |= EPOLLIN | EPOLLRDHUP;
                        if sock.is_shutdown_write() || !state.writable {
                            mask |= EPOLLHUP;
                        }
                    }
                    mask
                }
                Err(_) => EPOLLERR | EPOLLHUP,
            },
            TcpSocket::Listening { listener, .. } => {
                match net.tcp_listener_readiness(listener.id()).await {
                    Ok(state) if state.readable => EPOLLIN,
                    Ok(_) => 0,
                    Err(_) => EPOLLERR,
                }
            }
            TcpSocket::Unconnected { .. } | TcpSocket::Bound { .. } => EPOLLOUT | EPOLLHUP,
            TcpSocket::Connecting { .. } => 0,
        };
        return ready & (interest | EPOLLERR | EPOLLHUP);
    }

    if let Some(udp) = sock.udp_state() {
        let ready = match udp {
            UdpSocket::Bound { socket, .. } => match net.udp_readiness(socket.id()).await {
                Ok(state) => {
                    let mut mask = 0;
                    if state.readable {
                        mask |= EPOLLIN;
                    }
                    if state.writable {
                        mask |= EPOLLOUT;
                    }
                    mask
                }
                Err(_) => EPOLLERR,
            },
            UdpSocket::Unbound { .. } => EPOLLOUT,
        };
        return ready & (interest | EPOLLERR | EPOLLHUP);
    }

    if sock.is_netlink() {
        let state = netlink::readiness(sock);
        let mut mask = 0;
        if state.readable {
            mask |= EPOLLIN;
        }
        if state.writable {
            mask |= EPOLLOUT;
        }
        return mask & (interest | EPOLLERR | EPOLLHUP);
    }

    if sock.is_packet() {
        let ready = match packet::readiness(sock, net).await {
            Ok(state) => {
                let mut mask = 0;
                if state.readable {
                    mask |= EPOLLIN;
                }
                if state.writable {
                    mask |= EPOLLOUT;
                }
                mask
            }
            Err(_) => EPOLLERR,
        };
        return ready & (interest | EPOLLERR | EPOLLHUP);
    }

    0
}
