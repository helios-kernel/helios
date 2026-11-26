//! Linux `AF_PACKET` (`SOCK_RAW` / `SOCK_DGRAM`) raw link-layer sockets.

use alloc::vec::Vec;
use helios_unix::{Socket, SocketKind, SocketNetwork};

use super::netlink::{ARPHRD_ETHER, ARPHRD_LOOPBACK, IFINDEX_ETH0, IFINDEX_LO};
use super::socket::{
    EAGAIN, EMSGSIZE, ENODEV, ETIMEDOUT, MSG_DONTWAIT, MSG_PEEK, Network, SocketReady,
};
use super::{EFAULT, EINVAL, UserMemory};

/// Linux UAPI `AF_PACKET` (`include/linux/socket.h`).
pub const AF_PACKET: u16 = 17;
/// Size of `struct sockaddr_ll` (20 bytes).
pub const SOCKADDR_LL_LEN: usize = 20;
/// Ethernet II header length.
const ETH_HEADER_LEN: usize = 14;

// Linux `sll_pkttype` values (`include/uapi/linux/if_packet.h`).
const PACKET_HOST: u8 = 0;
const PACKET_BROADCAST: u8 = 1;
const PACKET_MULTICAST: u8 = 2;

/// Decoded `struct sockaddr_ll`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SockaddrLl {
    /// Ethernet protocol in host byte order.
    pub protocol: u16,
    /// Interface index (`0` = any, `1` = `lo`, `2` = `eth0`).
    pub ifindex: u32,
    pub hatype: u16,
    pub pkttype: u8,
    pub halen: u8,
    pub addr: [u8; 8],
}

/// Decodes a `struct sockaddr_ll` from user memory.
pub(crate) async fn read_sockaddr_ll<M: UserMemory>(
    memory: &M,
    addr: u64,
    addrlen: u32,
) -> Result<SockaddrLl, u64> {
    if (addrlen as usize) < SOCKADDR_LL_LEN {
        return Err(EINVAL);
    }
    let mut buf = [0u8; SOCKADDR_LL_LEN];
    memory.read(addr, &mut buf).await.map_err(|_| EFAULT)?;
    let family = u16::from_ne_bytes([buf[0], buf[1]]);
    if family != AF_PACKET {
        return Err(EINVAL);
    }
    let protocol = u16::from_be_bytes([buf[2], buf[3]]);
    let ifindex_i32 = i32::from_ne_bytes([buf[4], buf[5], buf[6], buf[7]]);
    if ifindex_i32 < 0 {
        return Err(ENODEV);
    }
    let hatype = u16::from_ne_bytes([buf[8], buf[9]]);
    let pkttype = buf[10];
    let halen = buf[11];
    let mut sll_addr = [0u8; 8];
    sll_addr.copy_from_slice(&buf[12..20]);
    Ok(SockaddrLl {
        protocol,
        ifindex: ifindex_i32 as u32,
        hatype,
        pkttype,
        halen,
        addr: sll_addr,
    })
}

/// Encodes a `struct sockaddr_ll` into user memory and updates `*addrlen`.
pub(crate) async fn write_sockaddr_ll<M: UserMemory>(
    memory: &mut M,
    addr: u64,
    addrlen_ptr: u64,
    sll: SockaddrLl,
) -> Result<(), u64> {
    if addr == 0 || addrlen_ptr == 0 {
        return Ok(());
    }
    let mut len_bytes = [0u8; 4];
    memory
        .read(addrlen_ptr, &mut len_bytes)
        .await
        .map_err(|_| EFAULT)?;
    let cap = u32::from_ne_bytes(len_bytes) as usize;
    let mut buf = [0u8; SOCKADDR_LL_LEN];
    buf[0..2].copy_from_slice(&AF_PACKET.to_ne_bytes());
    buf[2..4].copy_from_slice(&sll.protocol.to_be_bytes());
    buf[4..8].copy_from_slice(&(sll.ifindex as i32).to_ne_bytes());
    buf[8..10].copy_from_slice(&sll.hatype.to_ne_bytes());
    buf[10] = sll.pkttype;
    buf[11] = sll.halen;
    buf[12..20].copy_from_slice(&sll.addr);
    let copy = cap.min(SOCKADDR_LL_LEN);
    if copy > 0 {
        memory.write(addr, &buf[..copy]).await.map_err(|_| EFAULT)?;
    }
    memory
        .write(addrlen_ptr, &(SOCKADDR_LL_LEN as u32).to_ne_bytes())
        .await
        .map_err(|_| EFAULT)?;
    Ok(())
}

/// Handles `bind()` on an `AF_PACKET` socket.
pub(crate) async fn bind<N: SocketNetwork, M: UserMemory, Net: Network<N>>(
    sock: &Socket<N>,
    addr: u64,
    addrlen: u32,
    memory: &M,
    net: &Net,
) -> Result<(), u64> {
    let sll = read_sockaddr_ll(memory, addr, addrlen).await?;
    if sll.ifindex != 0 && sll.ifindex != IFINDEX_LO && sll.ifindex != IFINDEX_ETH0 {
        return Err(ENODEV);
    }
    let pkt = sock.packet_state().ok_or(EINVAL)?;
    let handle = pkt.handle.id();
    let current_proto = pkt.protocol;
    let protocol = if sll.protocol == 0 {
        current_proto
    } else {
        sll.protocol
    };
    net.packet_bind(handle, protocol, sll.ifindex)?;
    let _ = sock.with_packet_mut(|p| {
        p.protocol = protocol;
        p.ifindex = sll.ifindex;
    });
    Ok(())
}

/// Handles `getsockname()` on an `AF_PACKET` socket.
pub(crate) async fn getsockname<N: SocketNetwork, M: UserMemory, Net: Network<N>>(
    sock: &Socket<N>,
    addr: u64,
    addrlen_ptr: u64,
    memory: &mut M,
    net: &Net,
) -> Result<(), u64> {
    let pkt = sock.packet_state().ok_or(EINVAL)?;
    let (protocol, ifindex) = (pkt.protocol, pkt.ifindex);
    let (hatype, halen, mut hwaddr) = match ifindex {
        IFINDEX_LO => (ARPHRD_LOOPBACK, 6u8, [0u8; 8]),
        IFINDEX_ETH0 => {
            let mac = net.interface_mac().await.unwrap_or([0; 6]);
            let mut a = [0u8; 8];
            a[..6].copy_from_slice(&mac);
            (ARPHRD_ETHER, 6u8, a)
        }
        _ => (0u16, 0u8, [0u8; 8]),
    };
    if ifindex == IFINDEX_LO {
        hwaddr.fill(0);
    }
    write_sockaddr_ll(
        memory,
        addr,
        addrlen_ptr,
        SockaddrLl {
            protocol,
            ifindex,
            hatype,
            pkttype: PACKET_HOST,
            halen,
            addr: hwaddr,
        },
    )
    .await
}

/// Sends a raw Ethernet frame (`SOCK_RAW`) or L3 packet (`SOCK_DGRAM`, synthesizing
/// the Ethernet header from `dest` and the interface MAC).
pub(crate) async fn send<N: SocketNetwork, Net: Network<N>>(
    sock: &Socket<N>,
    data: &[u8],
    dest: Option<SockaddrLl>,
    net: &Net,
) -> Result<usize, u64> {
    let pkt = sock.packet_state().ok_or(EINVAL)?;
    let (kind, handle, bound_proto, bound_ifindex) =
        (sock.kind(), pkt.handle.id(), pkt.protocol, pkt.ifindex);
    let target_ifindex = dest
        .map(|d| d.ifindex)
        .filter(|&idx| idx != 0)
        .unwrap_or(bound_ifindex);
    if target_ifindex != 0 && target_ifindex != IFINDEX_LO && target_ifindex != IFINDEX_ETH0 {
        return Err(ENODEV);
    }
    let resolved_ifindex = if target_ifindex == 0 {
        IFINDEX_ETH0
    } else {
        target_ifindex
    };
    match kind {
        SocketKind::Raw => {
            if data.len() < ETH_HEADER_LEN {
                return Err(EMSGSIZE);
            }
            net.packet_send(handle, resolved_ifindex, data).await
        }
        SocketKind::Datagram => {
            let protocol = dest
                .map(|d| d.protocol)
                .filter(|&p| p != 0)
                .unwrap_or(bound_proto);
            let dst_mac = dest
                .map(|d| {
                    [
                        d.addr[0], d.addr[1], d.addr[2], d.addr[3], d.addr[4], d.addr[5],
                    ]
                })
                .unwrap_or([0xff; 6]);
            let src_mac = if resolved_ifindex == IFINDEX_LO {
                [0u8; 6]
            } else {
                net.interface_mac().await.unwrap_or([0; 6])
            };
            let mut frame = Vec::with_capacity(ETH_HEADER_LEN + data.len());
            frame.extend_from_slice(&dst_mac);
            frame.extend_from_slice(&src_mac);
            frame.extend_from_slice(&protocol.to_be_bytes());
            frame.extend_from_slice(data);
            let _ = net.packet_send(handle, resolved_ifindex, &frame).await?;
            Ok(data.len())
        }
        SocketKind::Stream => Err(EINVAL),
    }
}

/// Receives one frame on an `AF_PACKET` socket.
///
/// Returns `(payload_bytes, reported_len, sender_sockaddr_ll)`.
pub(crate) async fn recv<N: SocketNetwork, Net: Network<N>>(
    sock: &Socket<N>,
    max_len: usize,
    flags: u32,
    timeout_nanos: u64,
    net: &Net,
) -> Result<(Vec<u8>, usize, SockaddrLl), u64> {
    let pkt = sock.packet_state().ok_or(EINVAL)?;
    let (kind, handle) = (sock.kind(), pkt.handle.id());
    let nonblocking = sock.is_nonblocking() || flags & MSG_DONTWAIT != 0;
    let effective_timeout = if nonblocking { 0 } else { timeout_nanos };
    let peek = flags & MSG_PEEK != 0;
    // For SOCK_DGRAM we strip the 14-byte Ethernet header, so ask the kernel
    // for 14 extra bytes to preserve the full requested payload length.
    let fetch_max = match kind {
        SocketKind::Datagram => max_len
            .saturating_add(ETH_HEADER_LEN)
            .min(u32::MAX as usize) as u32,
        _ => max_len.min(u32::MAX as usize) as u32,
    };
    let received = match net
        .packet_receive(handle, fetch_max, effective_timeout, peek)
        .await
    {
        Ok(Some(frame)) => frame,
        Ok(None) | Err(ETIMEDOUT) => return Err(EAGAIN),
        Err(err) => return Err(err),
    };

    let raw = received.bytes.as_ref();
    let mut src_mac = [0u8; 8];
    let mut pkttype = PACKET_HOST;
    if raw.len() >= ETH_HEADER_LEN {
        src_mac[..6].copy_from_slice(&raw[6..12]);
        if raw[0..6] == [0xff; 6] {
            pkttype = PACKET_BROADCAST;
        } else if raw[0] & 0x01 != 0 {
            pkttype = PACKET_MULTICAST;
        }
    }
    let hatype = if received.ifindex == IFINDEX_LO {
        ARPHRD_LOOPBACK
    } else {
        ARPHRD_ETHER
    };
    let sll = SockaddrLl {
        protocol: received.protocol,
        ifindex: received.ifindex,
        hatype,
        pkttype,
        halen: 6,
        addr: src_mac,
    };

    let (payload, full_len) = match kind {
        SocketKind::Datagram => {
            let body = if raw.len() > ETH_HEADER_LEN {
                &raw[ETH_HEADER_LEN..]
            } else {
                &[]
            };
            let copy_len = body.len().min(max_len);
            let orig = received.original_len.saturating_sub(ETH_HEADER_LEN);
            (body[..copy_len].to_vec(), orig)
        }
        _ => {
            let copy_len = raw.len().min(max_len);
            (raw[..copy_len].to_vec(), received.original_len)
        }
    };
    Ok((payload, full_len, sll))
}

/// Non-destructive readiness of an `AF_PACKET` socket.
pub(crate) async fn readiness<N: SocketNetwork, Net: Network<N>>(
    sock: &Socket<N>,
    net: &Net,
) -> Result<SocketReady, u64> {
    let handle = sock.packet_state().ok_or(EINVAL)?.handle.id();
    net.packet_readiness(handle).await
}
