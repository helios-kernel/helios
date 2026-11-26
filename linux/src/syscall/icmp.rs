//! `AF_INET` / `AF_INET6` `IPPROTO_ICMP` (`1`) and `IPPROTO_ICMPV6` (`58`)
//! echo sockets (`SOCK_DGRAM` unprivileged ping sockets and `SOCK_RAW` raw ICMP
//! sockets), matching Linux v6.12 (`net/ipv4/ping.c`, `net/ipv4/raw.c`,
//! `net/ipv6/ping.c`, `net/ipv6/raw.c`).

use alloc::vec::Vec;
use bytes::Bytes;
use helios_unix::{Socket, SocketFamily, SocketNetwork};

use super::EINVAL;
use super::socket::{
    EAFNOSUPPORT, EAGAIN, EDESTADDRREQ, EMSGSIZE, ENOTCONN, ENOTSOCK, ETIMEDOUT, IpAddr, Network,
    SocketAddr, SocketReady,
};

/// Linux UAPI `IPPROTO_ICMP` (`include/uapi/linux/in.h`).
pub const IPPROTO_ICMP: i32 = 1;
/// Linux UAPI `IPPROTO_ICMPV6` (`include/uapi/linux/in6.h`).
pub const IPPROTO_ICMPV6: i32 = 58;

/// ICMPv4 Echo Request type (RFC 792).
const ICMPV4_ECHO_REQUEST: u8 = 8;
/// ICMPv6 Echo Request type (RFC 4443).
const ICMPV6_ECHO_REQUEST: u8 = 128;
/// Minimum ICMP echo header length (`type`, `code`, `checksum`, `id`, `seq`).
const ICMP_HEADER_LEN: usize = 8;

/// One received ICMP / ICMPv6 datagram delivered by [`Network::icmp_receive`].
#[derive(Clone, Debug)]
pub struct IcmpDatagram {
    /// Source IP address of the peer that replied.
    pub source: IpAddr,
    /// Local destination IP address of the reply (used when synthesizing IPv4
    /// headers for `AF_INET` `SOCK_RAW` sockets).
    pub destination: IpAddr,
    /// Received IPv4 TTL or IPv6 hop limit.
    pub ttl: u8,
    /// Raw ICMP / ICMPv6 message bytes (starting at the ICMP type byte).
    pub payload: Bytes,
}

/// Computes RFC 1071 16-bit one's-complement Internet checksum.
fn internet_checksum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let (chunks, remainder) = bytes.as_chunks::<2>();
    for &chunk in chunks {
        sum = sum.wrapping_add(u32::from(u16::from_be_bytes(chunk)));
    }
    if let Some(&last) = remainder.first() {
        sum = sum.wrapping_add(u32::from(u16::from_be_bytes([last, 0])));
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Prepends a 20-byte IPv4 header for `AF_INET` `SOCK_RAW` `IPPROTO_ICMP`
/// reads (`net/ipv4/raw.c` delivers the IP header + ICMP payload).
fn prepend_ipv4_header(datagram: &IcmpDatagram) -> Vec<u8> {
    let total_len = 20usize.saturating_add(datagram.payload.len());
    let mut packet = Vec::with_capacity(total_len);
    let mut hdr = [0u8; 20];
    hdr[0] = 0x45; // version 4, IHL 5 (20 bytes)
    hdr[2..4].copy_from_slice(&(total_len.min(u16::MAX as usize) as u16).to_be_bytes());
    hdr[8] = if datagram.ttl == 0 { 64 } else { datagram.ttl };
    hdr[9] = IPPROTO_ICMP as u8;
    if let IpAddr::V4(src) = datagram.source {
        hdr[12..16].copy_from_slice(&src);
    }
    if let IpAddr::V4(dst) = datagram.destination {
        hdr[16..20].copy_from_slice(&dst);
    }
    let csum = internet_checksum(&hdr);
    hdr[10..12].copy_from_slice(&csum.to_be_bytes());
    packet.extend_from_slice(&hdr);
    packet.extend_from_slice(&datagram.payload);
    packet
}

/// Rewrites the ICMPv4 echo identifier (bytes 4..6) and recomputes the ICMPv4
/// checksum when delivering a `SOCK_DGRAM` reply to match the socket's local ID.
fn stamp_dgram_icmp_id(family: SocketFamily, local_id: u16, payload: &Bytes) -> Bytes {
    if payload.len() < ICMP_HEADER_LEN {
        return payload.clone();
    }
    let mut buf = payload.to_vec();
    buf[4..6].copy_from_slice(&local_id.to_be_bytes());
    if family == SocketFamily::Ipv4 {
        buf[2] = 0;
        buf[3] = 0;
        let csum = internet_checksum(&buf);
        buf[2..4].copy_from_slice(&csum.to_be_bytes());
    }
    Bytes::from(buf)
}

pub(crate) async fn send<N: SocketNetwork, Net: Network<N>>(
    sock: &Socket<N>,
    data: &[u8],
    dest: Option<SocketAddr>,
    net: &Net,
) -> Result<usize, u64> {
    let Some(state) = sock.icmp_state() else {
        return Err(ENOTSOCK);
    };
    let target_ip = match dest {
        Some(addr) => {
            if addr.ip.family() != state.family {
                return Err(EAFNOSUPPORT);
            }
            addr.ip
        }
        None => match state.peer {
            Some(peer) => net.to_ip(peer),
            None => return Err(EDESTADDRREQ),
        },
    };
    if data.len() < ICMP_HEADER_LEN {
        return Err(EINVAL);
    }
    if data.len() > 65_507 {
        return Err(EMSGSIZE);
    }
    let msg_type = data[0];
    let msg_code = data[1];
    let expected_type = match state.family {
        SocketFamily::Ipv4 => ICMPV4_ECHO_REQUEST,
        SocketFamily::Ipv6 => ICMPV6_ECHO_REQUEST,
    };
    if !state.is_raw && (msg_type != expected_type || msg_code != 0) {
        // Linux `net/ipv4/ping.c` `ping_check_bind_addr`/`ping_v4_sendmsg`:
        // unprivileged `SOCK_DGRAM` ping sockets only send Echo Requests.
        return Err(EINVAL);
    }
    let identifier = if state.is_raw {
        u16::from_be_bytes([data[4], data[5]])
    } else {
        state.local_id
    };
    let sequence = u16::from_be_bytes([data[6], data[7]]);
    let payload = &data[ICMP_HEADER_LEN..];
    net.icmp_send(
        state.handle.id(),
        target_ip,
        identifier,
        sequence,
        payload,
        state.options.hop_limit(),
    )
    .await?;
    Ok(data.len())
}

pub(crate) async fn recv<N: SocketNetwork, Net: Network<N>>(
    sock: &Socket<N>,
    max_len: usize,
    timeout_nanos: u64,
    peek: bool,
    net: &Net,
) -> Result<(Bytes, SocketAddr, usize, u8), u64> {
    let Some(state) = sock.icmp_state() else {
        return Err(ENOTSOCK);
    };
    let received = match net
        .icmp_receive(state.handle.id(), timeout_nanos, peek)
        .await
    {
        Ok(Some(datagram)) => datagram,
        Ok(None) | Err(ETIMEDOUT) => return Err(EAGAIN),
        Err(err) => return Err(err),
    };
    let ttl = received.ttl;
    let source = received.source;
    let wire_bytes: Bytes = if state.is_raw && state.family == SocketFamily::Ipv4 {
        Bytes::from(prepend_ipv4_header(&received))
    } else if !state.is_raw {
        stamp_dgram_icmp_id(state.family, state.local_id, &received.payload)
    } else {
        received.payload
    };
    let full_len = wire_bytes.len();
    let truncated = if full_len > max_len {
        wire_bytes.slice(..max_len)
    } else {
        wire_bytes
    };
    let peer = SocketAddr {
        ip: source,
        port: if state.is_raw { 0 } else { state.local_id },
    };
    Ok((truncated, peer, full_len, ttl))
}

pub(crate) fn bind<N: SocketNetwork, Net: Network<N>>(
    sock: &Socket<N>,
    addr: SocketAddr,
    net: &Net,
) -> Result<(), u64> {
    let Some(state) = sock.icmp_state() else {
        return Err(ENOTSOCK);
    };
    if addr.ip.family() != state.family {
        return Err(EAFNOSUPPORT);
    }
    let requested_id = if !state.is_raw && addr.port != 0 {
        addr.port
    } else {
        state.local_id
    };
    let assigned_id = net.icmp_bind(state.handle.id(), requested_id)?;
    let encoded_ip = net.encode_ip(addr.ip);
    sock.with_icmp_mut(|slot| {
        slot.local_address = Some(encoded_ip);
        slot.local_id = assigned_id;
    });
    Ok(())
}

pub(crate) fn connect<N: SocketNetwork, Net: Network<N>>(
    sock: &Socket<N>,
    remote: Option<SocketAddr>,
    net: &Net,
) -> Result<(), u64> {
    let Some(state) = sock.icmp_state() else {
        return Err(ENOTSOCK);
    };
    let Some(addr) = remote else {
        sock.with_icmp_mut(|slot| slot.peer = None);
        return Ok(());
    };
    if addr.ip.family() != state.family {
        return Err(EAFNOSUPPORT);
    }
    let encoded = net.encode_ip(addr.ip);
    sock.with_icmp_mut(|slot| slot.peer = Some(encoded));
    Ok(())
}

pub(crate) fn getsockname<N: SocketNetwork, Net: Network<N>>(
    sock: &Socket<N>,
    net: &Net,
) -> Result<SocketAddr, u64> {
    let Some(state) = sock.icmp_state() else {
        return Err(ENOTSOCK);
    };
    let ip = match state.local_address {
        Some(local) => net.to_ip(local),
        None => IpAddr::unspecified(state.family),
    };
    let port = if state.is_raw { 0 } else { state.local_id };
    Ok(SocketAddr { ip, port })
}

pub(crate) fn getpeername<N: SocketNetwork, Net: Network<N>>(
    sock: &Socket<N>,
    net: &Net,
) -> Result<SocketAddr, u64> {
    let Some(state) = sock.icmp_state() else {
        return Err(ENOTSOCK);
    };
    let Some(peer) = state.peer else {
        return Err(ENOTCONN);
    };
    Ok(SocketAddr {
        ip: net.to_ip(peer),
        port: if state.is_raw { 0 } else { state.local_id },
    })
}

pub(crate) async fn readiness<N: SocketNetwork, Net: Network<N>>(
    sock: &Socket<N>,
    net: &Net,
) -> Result<SocketReady, u64> {
    let Some(state) = sock.icmp_state() else {
        return Err(ENOTSOCK);
    };
    net.icmp_readiness(state.handle.id()).await
}
