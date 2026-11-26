//! Linux `NETLINK_ROUTE` sockets and `SIOCGIF*` / `SIOCSIF*` / `SIOC*RT`
//! network interface ioctls over the shared kernel network control plane.

use alloc::vec;
use alloc::vec::Vec;
use bytes::Bytes;
use helios_unix::{Socket, SocketNetwork};

use super::socket::{
    AF_INET, AF_INET6, AF_UNSPEC, EAGAIN, ENODEV, EOPNOTSUPP, Ipv4InterfaceAddress, Ipv4RouteEntry,
    MSG_DONTWAIT, MSG_PEEK, Network, SocketContext, SocketReady,
};
use super::{EFAULT, EINVAL, EPERM, UserMemory};

// Linux UAPI address family & netlink protocol (`include/uapi/linux/netlink.h`).
pub const AF_NETLINK: u16 = 16;
pub const NETLINK_ROUTE: u32 = 0;

/// Size of `struct sockaddr_nl` (12 bytes).
pub const SOCKADDR_NL_LEN: usize = 12;
/// Size of `struct nlmsghdr` (16 bytes).
const NLMSG_HDRLEN: usize = 16;

// Standard netlink message types.
const NLMSG_NOOP: u16 = 1;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;

// Netlink message flags.
const NLM_F_MULTI: u16 = 0x0002;
const NLM_F_ACK: u16 = 0x0004;
const NLM_F_ROOT: u16 = 0x0100;
const NLM_F_MATCH: u16 = 0x0200;
const NLM_F_DUMP: u16 = NLM_F_ROOT | NLM_F_MATCH;

// `NETLINK_ROUTE` message types (`include/uapi/linux/rtnetlink.h`).
const RTM_NEWLINK: u16 = 16;
const RTM_GETLINK: u16 = 18;
const RTM_SETLINK: u16 = 19;
const RTM_NEWADDR: u16 = 20;
const RTM_DELADDR: u16 = 21;
const RTM_GETADDR: u16 = 22;
const RTM_NEWROUTE: u16 = 24;
const RTM_DELROUTE: u16 = 25;
const RTM_GETROUTE: u16 = 26;

// Link attributes (`IFLA_*`).
const IFLA_ADDRESS: u16 = 1;
const IFLA_BROADCAST: u16 = 2;
const IFLA_IFNAME: u16 = 3;
const IFLA_MTU: u16 = 4;
const IFLA_OPERSTATE: u16 = 16;

// Address attributes (`IFA_*`).
const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
const IFA_LABEL: u16 = 3;
const IFA_BROADCAST: u16 = 4;

// Route attributes (`RTA_*`).
const RTA_DST: u16 = 1;
const RTA_OIF: u16 = 4;
const RTA_GATEWAY: u16 = 5;

// Interface constants (`include/uapi/linux/if.h`, `if_arp.h`, `rtnetlink.h`).
pub const IFINDEX_LO: u32 = 1;
pub const IFINDEX_ETH0: u32 = 2;

pub const ARPHRD_ETHER: u16 = 1;
pub const ARPHRD_LOOPBACK: u16 = 772;

const IFF_UP: u32 = 0x1;
const IFF_BROADCAST: u32 = 0x2;
const IFF_LOOPBACK: u32 = 0x8;
const IFF_RUNNING: u32 = 0x40;
const IFF_MULTICAST: u32 = 0x1000;

const LO_FLAGS: u32 = IFF_UP | IFF_LOOPBACK | IFF_RUNNING;
const ETH0_FLAGS: u32 = IFF_UP | IFF_BROADCAST | IFF_RUNNING | IFF_MULTICAST;
const LO_MTU: u32 = 65_536;
const ETH0_MTU: u32 = 1500;

const IF_OPER_UNKNOWN: u8 = 0;
const IF_OPER_UP: u8 = 6;

const RT_SCOPE_UNIVERSE: u8 = 0;
const RT_SCOPE_LINK: u8 = 253;
const RT_SCOPE_HOST: u8 = 254;
const RT_TABLE_MAIN: u8 = 254;
const RTPROT_KERNEL: u8 = 2;
const RTPROT_BOOT: u8 = 3;
const RTN_UNICAST: u8 = 1;

// Linux UAPI socket/interface ioctl numbers (`include/uapi/linux/sockios.h`).
const SIOCADDRT: u32 = 0x890B;
const SIOCDELRT: u32 = 0x890C;
const SIOCGIFNAME: u32 = 0x8910;
const SIOCGIFCONF: u32 = 0x8912;
const SIOCGIFFLAGS: u32 = 0x8913;
const SIOCSIFFLAGS: u32 = 0x8914;
const SIOCGIFADDR: u32 = 0x8915;
const SIOCSIFADDR: u32 = 0x8916;
const SIOCGIFBRDADDR: u32 = 0x8919;
const SIOCSIFBRDADDR: u32 = 0x891A;
const SIOCGIFNETMASK: u32 = 0x891B;
const SIOCSIFNETMASK: u32 = 0x891C;
const SIOCGIFMTU: u32 = 0x8921;
const SIOCSIFMTU: u32 = 0x8922;
const SIOCGIFHWADDR: u32 = 0x8927;
const SIOCGIFINDEX: u32 = 0x8933;
const SIOCGIFTXQLEN: u32 = 0x8942;

const DEFAULT_TXQLEN: i32 = 1000;

const IFREQ_LEN: usize = 40;
const IFCONF_LEN: usize = 16;
const RTENTRY_LEN: usize = 120;
const RTF_GATEWAY: u16 = 0x0002;
const RTF_HOST: u16 = 0x0004;

/// Decodes a `struct sockaddr_nl` from user memory.
pub(crate) async fn read_sockaddr_nl<M: UserMemory>(
    memory: &M,
    addr: u64,
    addrlen: u32,
) -> Result<(u32, u32), u64> {
    if (addrlen as usize) < SOCKADDR_NL_LEN {
        return Err(EINVAL);
    }
    let mut buf = [0u8; SOCKADDR_NL_LEN];
    memory.read(addr, &mut buf).await.map_err(|_| EFAULT)?;
    let family = u16::from_ne_bytes([buf[0], buf[1]]);
    if family != AF_NETLINK {
        return Err(EINVAL);
    }
    let nl_pid = u32::from_ne_bytes([buf[4], buf[5], buf[6], buf[7]]);
    let nl_groups = u32::from_ne_bytes([buf[8], buf[9], buf[10], buf[11]]);
    Ok((nl_pid, nl_groups))
}

/// Encodes a `struct sockaddr_nl` into user memory and updates `*addrlen`.
pub(crate) async fn write_sockaddr_nl<M: UserMemory>(
    memory: &mut M,
    addr: u64,
    addrlen_ptr: u64,
    nl_pid: u32,
    nl_groups: u32,
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
    let mut buf = [0u8; SOCKADDR_NL_LEN];
    buf[0..2].copy_from_slice(&AF_NETLINK.to_ne_bytes());
    buf[4..8].copy_from_slice(&nl_pid.to_ne_bytes());
    buf[8..12].copy_from_slice(&nl_groups.to_ne_bytes());
    let copy = cap.min(SOCKADDR_NL_LEN);
    if copy > 0 {
        memory.write(addr, &buf[..copy]).await.map_err(|_| EFAULT)?;
    }
    memory
        .write(addrlen_ptr, &(SOCKADDR_NL_LEN as u32).to_ne_bytes())
        .await
        .map_err(|_| EFAULT)?;
    Ok(())
}

/// Handles `bind()` on an `AF_NETLINK` socket.
pub(crate) async fn bind<N: SocketNetwork, M: UserMemory>(
    sock: &Socket<N>,
    addr: u64,
    addrlen: u32,
    ctx: SocketContext,
    memory: &M,
) -> Result<(), u64> {
    let (nl_pid, nl_groups) = read_sockaddr_nl(memory, addr, addrlen).await?;
    let assigned_pid = if nl_pid == 0 { ctx.pid } else { nl_pid };
    let _ = sock.with_netlink_mut(|nl| {
        nl.port_id = assigned_pid;
        nl.groups = nl_groups;
    });
    Ok(())
}

/// Handles `getsockname()` on an `AF_NETLINK` socket.
pub(crate) async fn getsockname<N: SocketNetwork, M: UserMemory>(
    sock: &Socket<N>,
    addr: u64,
    addrlen_ptr: u64,
    memory: &mut M,
) -> Result<(), u64> {
    let nl = sock.netlink_state().ok_or(EINVAL)?;
    write_sockaddr_nl(memory, addr, addrlen_ptr, nl.port_id, nl.groups).await
}

/// Processes a `NETLINK_ROUTE` request datagram and queues the reply on `sock`.
pub(crate) async fn send<N: SocketNetwork, Net: Network<N>>(
    sock: &Socket<N>,
    data: &[u8],
    ctx: SocketContext,
    net: &Net,
) -> Result<usize, u64> {
    let nl = sock.netlink_state().ok_or(EINVAL)?;
    let protocol = nl.protocol;
    let mut port_id = nl.port_id;
    if protocol != NETLINK_ROUTE {
        return Err(EOPNOTSUPP);
    }
    if port_id == 0 {
        port_id = ctx.pid;
        let _ = sock.with_netlink_mut(|nl| {
            if nl.port_id == 0 {
                nl.port_id = port_id;
            }
        });
    }

    let mut offset = 0usize;
    let mut responses = Vec::new();
    while offset + NLMSG_HDRLEN <= data.len() {
        let hdr = parse_nlmsghdr(&data[offset..]);
        let msg_len = hdr.len as usize;
        if msg_len < NLMSG_HDRLEN || offset + msg_len > data.len() {
            break;
        }
        let payload = &data[offset + NLMSG_HDRLEN..offset + msg_len];
        let reply = handle_rtnetlink_message(hdr, payload, port_id, ctx, net).await;
        if !reply.is_empty() {
            responses.push(reply);
        }
        let step = align4(msg_len);
        if step == 0 {
            break;
        }
        offset = offset.saturating_add(step);
    }

    if !responses.is_empty() {
        let _ = sock.with_netlink_mut(|nl| {
            for response in responses {
                nl.rx_queue.push_back(Bytes::from(response));
            }
        });
    }
    Ok(data.len())
}

/// Pops (or peeks) one queued `NETLINK_ROUTE` reply datagram.
///
/// Returns `(copied_bytes, original_len)` so callers can honour `MSG_TRUNC`.
pub(crate) fn recv<N: SocketNetwork>(
    sock: &Socket<N>,
    max_len: usize,
    flags: u32,
) -> Result<(Vec<u8>, usize), u64> {
    let peek = flags & MSG_PEEK != 0;
    let msg = sock
        .with_netlink_mut(|nl| {
            if peek {
                nl.rx_queue.front().cloned()
            } else {
                nl.rx_queue.pop_front()
            }
        })
        .flatten();
    match msg {
        Some(full) => {
            let orig_len = full.len();
            let copy_len = orig_len.min(max_len);
            let out = full[..copy_len].to_vec();
            Ok((out, orig_len))
        }
        None => {
            if sock.is_nonblocking() || flags & MSG_DONTWAIT != 0 {
                Err(EAGAIN)
            } else {
                // Netlink replies are generated synchronously during send; an
                // empty queue has no pending kernel event to wait for.
                Err(EAGAIN)
            }
        }
    }
}

/// Non-destructive readiness of a netlink socket.
pub(crate) fn readiness<N: SocketNetwork>(sock: &Socket<N>) -> SocketReady {
    let readable = sock
        .netlink_state()
        .is_some_and(|nl| !nl.rx_queue.is_empty());
    SocketReady {
        readable,
        writable: true,
        hangup: false,
    }
}

/// Handles `SIOCGIF*` / `SIOCSIF*` / `SIOCADDRT` / `SIOCDELRT` ioctls on any socket.
///
/// Returns `Ok(Some(ret))` if `request` was a handled network ioctl, or
/// `Ok(None)` if `request` is not a network ioctl (caller falls back to `ENOTTY`).
pub(crate) async fn socket_ioctl<N: SocketNetwork, M: UserMemory, Net: Network<N>>(
    request: u32,
    arg: u64,
    ctx: SocketContext,
    memory: &mut M,
    net: &Net,
) -> Result<Option<u64>, u64> {
    match request {
        SIOCGIFNAME => {
            let mut req = [0u8; IFREQ_LEN];
            memory.read(arg, &mut req).await.map_err(|_| EFAULT)?;
            let ifindex = i32::from_ne_bytes([req[16], req[17], req[18], req[19]]);
            let name: &[u8] = match ifindex as u32 {
                IFINDEX_LO => b"lo",
                IFINDEX_ETH0 => b"eth0",
                _ => return Err(ENODEV),
            };
            req[0..16].fill(0);
            req[..name.len()].copy_from_slice(name);
            memory.write(arg, &req).await.map_err(|_| EFAULT)?;
            Ok(Some(0))
        }
        SIOCGIFINDEX => {
            let mut req = [0u8; IFREQ_LEN];
            memory.read(arg, &mut req).await.map_err(|_| EFAULT)?;
            let ifindex = lookup_ifindex(&req[0..16])?;
            req[16..20].copy_from_slice(&(ifindex as i32).to_ne_bytes());
            memory.write(arg, &req).await.map_err(|_| EFAULT)?;
            Ok(Some(0))
        }
        SIOCGIFTXQLEN => {
            let mut req = [0u8; IFREQ_LEN];
            memory.read(arg, &mut req).await.map_err(|_| EFAULT)?;
            let _ifindex = lookup_ifindex(&req[0..16])?;
            req[16..20].copy_from_slice(&DEFAULT_TXQLEN.to_ne_bytes());
            memory.write(arg, &req).await.map_err(|_| EFAULT)?;
            Ok(Some(0))
        }
        SIOCGIFFLAGS => {
            let mut req = [0u8; IFREQ_LEN];
            memory.read(arg, &mut req).await.map_err(|_| EFAULT)?;
            let ifindex = lookup_ifindex(&req[0..16])?;
            let flags = if ifindex == IFINDEX_LO {
                LO_FLAGS as i16
            } else {
                ETH0_FLAGS as i16
            };
            req[16..18].copy_from_slice(&flags.to_ne_bytes());
            memory.write(arg, &req).await.map_err(|_| EFAULT)?;
            Ok(Some(0))
        }
        SIOCSIFFLAGS => {
            require_admin(ctx, net)?;
            let mut req = [0u8; IFREQ_LEN];
            memory.read(arg, &mut req).await.map_err(|_| EFAULT)?;
            let ifindex = lookup_ifindex(&req[0..16])?;
            let requested = u32::from(u16::from_ne_bytes([req[16], req[17]]));
            let current = if ifindex == IFINDEX_LO {
                LO_FLAGS
            } else {
                ETH0_FLAGS
            };
            // Bringing an already-up interface up is idempotent; taking an
            // interface down or toggling unsupported link flags fails fast.
            if (requested & IFF_UP) == 0 || (requested & !current) != 0 {
                return Err(EOPNOTSUPP);
            }
            Ok(Some(0))
        }
        SIOCGIFMTU => {
            let mut req = [0u8; IFREQ_LEN];
            memory.read(arg, &mut req).await.map_err(|_| EFAULT)?;
            let ifindex = lookup_ifindex(&req[0..16])?;
            let mtu = if ifindex == IFINDEX_LO {
                LO_MTU as i32
            } else {
                ETH0_MTU as i32
            };
            req[16..20].copy_from_slice(&mtu.to_ne_bytes());
            memory.write(arg, &req).await.map_err(|_| EFAULT)?;
            Ok(Some(0))
        }
        SIOCSIFMTU => {
            require_admin(ctx, net)?;
            let mut req = [0u8; IFREQ_LEN];
            memory.read(arg, &mut req).await.map_err(|_| EFAULT)?;
            let ifindex = lookup_ifindex(&req[0..16])?;
            let mtu = i32::from_ne_bytes([req[16], req[17], req[18], req[19]]);
            if !(68..=65_536).contains(&mtu) {
                return Err(EINVAL);
            }
            let current_mtu = if ifindex == IFINDEX_LO {
                LO_MTU as i32
            } else {
                ETH0_MTU as i32
            };
            if mtu != current_mtu {
                return Err(EOPNOTSUPP);
            }
            Ok(Some(0))
        }
        SIOCGIFHWADDR => {
            let mut req = [0u8; IFREQ_LEN];
            memory.read(arg, &mut req).await.map_err(|_| EFAULT)?;
            let ifindex = lookup_ifindex(&req[0..16])?;
            req[16..32].fill(0);
            if ifindex == IFINDEX_LO {
                req[16..18].copy_from_slice(&ARPHRD_LOOPBACK.to_ne_bytes());
            } else {
                let mac = net.interface_mac().await?;
                req[16..18].copy_from_slice(&ARPHRD_ETHER.to_ne_bytes());
                req[18..24].copy_from_slice(&mac);
            }
            memory.write(arg, &req).await.map_err(|_| EFAULT)?;
            Ok(Some(0))
        }
        SIOCGIFADDR => {
            let mut req = [0u8; IFREQ_LEN];
            memory.read(arg, &mut req).await.map_err(|_| EFAULT)?;
            let ifindex = lookup_ifindex(&req[0..16])?;
            let ip = primary_ipv4_for(ifindex, net).await?;
            write_sockaddr_in_slice(&mut req[16..32], ip.address);
            memory.write(arg, &req).await.map_err(|_| EFAULT)?;
            Ok(Some(0))
        }
        SIOCGIFNETMASK => {
            let mut req = [0u8; IFREQ_LEN];
            memory.read(arg, &mut req).await.map_err(|_| EFAULT)?;
            let ifindex = lookup_ifindex(&req[0..16])?;
            let ip = primary_ipv4_for(ifindex, net).await?;
            write_sockaddr_in_slice(&mut req[16..32], prefix_to_netmask(ip.prefix));
            memory.write(arg, &req).await.map_err(|_| EFAULT)?;
            Ok(Some(0))
        }
        SIOCGIFBRDADDR => {
            let mut req = [0u8; IFREQ_LEN];
            memory.read(arg, &mut req).await.map_err(|_| EFAULT)?;
            let ifindex = lookup_ifindex(&req[0..16])?;
            let ip = primary_ipv4_for(ifindex, net).await?;
            write_sockaddr_in_slice(&mut req[16..32], broadcast_ipv4(ip.address, ip.prefix));
            memory.write(arg, &req).await.map_err(|_| EFAULT)?;
            Ok(Some(0))
        }
        SIOCSIFADDR => {
            require_admin(ctx, net)?;
            let mut req = [0u8; IFREQ_LEN];
            memory.read(arg, &mut req).await.map_err(|_| EFAULT)?;
            let ifindex = lookup_ifindex(&req[0..16])?;
            if ifindex != IFINDEX_ETH0 {
                return Err(EOPNOTSUPP);
            }
            let addr = read_sockaddr_in_slice(&req[16..32])?;
            let prefix = default_ipv4_prefix(addr);
            // Replace the existing primary IPv4 address (matching Linux
            // `SIOCSIFADDR`) so a subsequent `SIOCSIFNETMASK` updates the
            // address just installed rather than an older primary entry.
            if let Some(previous) = net.list_ipv4_addresses().await?.first().copied() {
                net.remove_ipv4_address(previous).await?;
            }
            net.add_ipv4_address(Ipv4InterfaceAddress {
                address: addr,
                prefix,
            })
            .await?;
            Ok(Some(0))
        }
        SIOCSIFNETMASK => {
            require_admin(ctx, net)?;
            let mut req = [0u8; IFREQ_LEN];
            memory.read(arg, &mut req).await.map_err(|_| EFAULT)?;
            let ifindex = lookup_ifindex(&req[0..16])?;
            if ifindex != IFINDEX_ETH0 {
                return Err(EOPNOTSUPP);
            }
            let mask = read_sockaddr_in_slice(&req[16..32])?;
            let prefix = netmask_to_prefix(mask)?;
            let existing = net.list_ipv4_addresses().await?;
            let Some(primary) = existing.first().copied() else {
                return Err(super::socket::EADDRNOTAVAIL);
            };
            if primary.prefix != prefix {
                net.remove_ipv4_address(primary).await?;
                net.add_ipv4_address(Ipv4InterfaceAddress {
                    address: primary.address,
                    prefix,
                })
                .await?;
            }
            Ok(Some(0))
        }
        SIOCSIFBRDADDR => {
            require_admin(ctx, net)?;
            let mut req = [0u8; IFREQ_LEN];
            memory.read(arg, &mut req).await.map_err(|_| EFAULT)?;
            let ifindex = lookup_ifindex(&req[0..16])?;
            if ifindex != IFINDEX_ETH0 {
                return Err(EOPNOTSUPP);
            }
            let brd = read_sockaddr_in_slice(&req[16..32])?;
            let primary = primary_ipv4_for(IFINDEX_ETH0, net).await?;
            if brd != broadcast_ipv4(primary.address, primary.prefix) {
                return Err(EOPNOTSUPP);
            }
            Ok(Some(0))
        }
        SIOCGIFCONF => {
            let mut ifc = [0u8; IFCONF_LEN];
            memory.read(arg, &mut ifc).await.map_err(|_| EFAULT)?;
            let ifc_len = i32::from_ne_bytes([ifc[0], ifc[1], ifc[2], ifc[3]]);
            let ifc_buf = u64::from_ne_bytes([
                ifc[8], ifc[9], ifc[10], ifc[11], ifc[12], ifc[13], ifc[14], ifc[15],
            ]);
            let mut entries: Vec<(&[u8], [u8; 4])> = vec![(b"lo", [127, 0, 0, 1])];
            if let Ok(addrs) = net.list_ipv4_addresses().await {
                for addr in addrs {
                    entries.push((b"eth0", addr.address));
                }
            }
            let total_bytes = entries.len().saturating_mul(IFREQ_LEN);
            if ifc_buf == 0 {
                ifc[0..4].copy_from_slice(&(total_bytes as i32).to_ne_bytes());
                memory.write(arg, &ifc).await.map_err(|_| EFAULT)?;
                return Ok(Some(0));
            }
            if ifc_len < 0 {
                return Err(EINVAL);
            }
            let max_entries = (ifc_len as usize) / IFREQ_LEN;
            let count = entries.len().min(max_entries);
            for (i, (name, ip)) in entries.into_iter().take(count).enumerate() {
                let mut req = [0u8; IFREQ_LEN];
                req[..name.len()].copy_from_slice(name);
                write_sockaddr_in_slice(&mut req[16..32], ip);
                let dst = ifc_buf.checked_add((i * IFREQ_LEN) as u64).ok_or(EFAULT)?;
                memory.write(dst, &req).await.map_err(|_| EFAULT)?;
            }
            let written_bytes = (count * IFREQ_LEN) as i32;
            ifc[0..4].copy_from_slice(&written_bytes.to_ne_bytes());
            memory.write(arg, &ifc).await.map_err(|_| EFAULT)?;
            Ok(Some(0))
        }
        SIOCADDRT | SIOCDELRT => {
            require_admin(ctx, net)?;
            let mut rt = [0u8; RTENTRY_LEN];
            memory.read(arg, &mut rt).await.map_err(|_| EFAULT)?;
            let dst = read_sockaddr_in_slice(&rt[8..24])?;
            let flags = u16::from_ne_bytes([rt[56], rt[57]]);
            let gateway = if flags & RTF_GATEWAY != 0 {
                Some(read_sockaddr_in_slice(&rt[24..40])?)
            } else {
                None
            };
            let prefix = if flags & RTF_HOST != 0 {
                32
            } else {
                let mask_family = u16::from_ne_bytes([rt[40], rt[41]]);
                if mask_family == AF_INET {
                    netmask_to_prefix([rt[44], rt[45], rt[46], rt[47]])?
                } else {
                    0
                }
            };
            let entry = Ipv4RouteEntry {
                destination: dst,
                prefix,
                gateway,
            };
            if request == SIOCADDRT {
                net.add_ipv4_route(entry).await?;
            } else {
                net.remove_ipv4_route(entry).await?;
            }
            Ok(Some(0))
        }
        _ => Ok(None),
    }
}

fn require_admin<N: SocketNetwork, Net: Network<N>>(
    ctx: SocketContext,
    net: &Net,
) -> Result<(), u64> {
    if !ctx.cap_net_admin {
        return Err(EPERM);
    }
    net.check_net_admin()
}

#[derive(Clone, Copy)]
struct NlMsgHdr {
    len: u32,
    kind: u16,
    flags: u16,
    seq: u32,
    pid: u32,
}

fn parse_nlmsghdr(buf: &[u8]) -> NlMsgHdr {
    NlMsgHdr {
        len: u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]),
        kind: u16::from_ne_bytes([buf[4], buf[5]]),
        flags: u16::from_ne_bytes([buf[6], buf[7]]),
        seq: u32::from_ne_bytes([buf[8], buf[9], buf[10], buf[11]]),
        pid: u32::from_ne_bytes([buf[12], buf[13], buf[14], buf[15]]),
    }
}

async fn handle_rtnetlink_message<N: SocketNetwork, Net: Network<N>>(
    hdr: NlMsgHdr,
    payload: &[u8],
    port_id: u32,
    ctx: SocketContext,
    net: &Net,
) -> Vec<u8> {
    let mut out = Vec::new();
    let is_dump = hdr.flags & NLM_F_DUMP == NLM_F_DUMP;
    match hdr.kind {
        NLMSG_NOOP => {
            if hdr.flags & NLM_F_ACK != 0 {
                append_nlmsg_error(&mut out, 0, hdr, port_id);
            }
        }
        RTM_GETLINK => {
            let mac = net.interface_mac().await.unwrap_or([0; 6]);
            if is_dump {
                append_link_msg(&mut out, IFINDEX_LO, [0; 6], NLM_F_MULTI, hdr.seq, port_id);
                append_link_msg(&mut out, IFINDEX_ETH0, mac, NLM_F_MULTI, hdr.seq, port_id);
                append_nlmsg_done(&mut out, hdr.seq, port_id);
            } else {
                match resolve_link_query(payload) {
                    Ok(IFINDEX_LO) => {
                        append_link_msg(&mut out, IFINDEX_LO, [0; 6], 0, hdr.seq, port_id);
                    }
                    Ok(IFINDEX_ETH0) => {
                        append_link_msg(&mut out, IFINDEX_ETH0, mac, 0, hdr.seq, port_id);
                    }
                    Ok(_) => append_nlmsg_error(&mut out, -(ENODEV as i32), hdr, port_id),
                    Err(err) => append_nlmsg_error(&mut out, -(err as i32), hdr, port_id),
                }
            }
        }
        RTM_NEWLINK | RTM_SETLINK => {
            let result = if !ctx.cap_net_admin {
                Err(EPERM)
            } else if let Err(err) = net.check_net_admin() {
                Err(err)
            } else {
                validate_link_mutation(payload, net).await
            };
            match result {
                Ok(()) => {
                    if hdr.flags & NLM_F_ACK != 0 {
                        append_nlmsg_error(&mut out, 0, hdr, port_id);
                    }
                }
                Err(err) => append_nlmsg_error(&mut out, -(err as i32), hdr, port_id),
            }
        }
        RTM_GETADDR => {
            let filter_family = payload.first().copied().unwrap_or(AF_UNSPEC as u8);
            let msg_flags = if is_dump { NLM_F_MULTI } else { 0 };
            if filter_family == AF_UNSPEC as u8 || filter_family == AF_INET as u8 {
                append_ipv4_addr_msg(
                    &mut out,
                    IFINDEX_LO,
                    "lo",
                    Ipv4InterfaceAddress {
                        address: [127, 0, 0, 1],
                        prefix: 8,
                    },
                    RT_SCOPE_HOST,
                    msg_flags,
                    hdr.seq,
                    port_id,
                );
                if let Ok(addrs) = net.list_ipv4_addresses().await {
                    for addr in addrs {
                        append_ipv4_addr_msg(
                            &mut out,
                            IFINDEX_ETH0,
                            "eth0",
                            addr,
                            RT_SCOPE_UNIVERSE,
                            msg_flags,
                            hdr.seq,
                            port_id,
                        );
                    }
                }
            }
            if filter_family == AF_UNSPEC as u8 || filter_family == AF_INET6 as u8 {
                append_ipv6_addr_msg(
                    &mut out,
                    IFINDEX_LO,
                    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                    128,
                    RT_SCOPE_HOST,
                    msg_flags,
                    hdr.seq,
                    port_id,
                );
            }
            if is_dump {
                append_nlmsg_done(&mut out, hdr.seq, port_id);
            }
        }
        RTM_NEWADDR | RTM_DELADDR => {
            let result = if !ctx.cap_net_admin {
                Err(EPERM)
            } else {
                match parse_ifaddrmsg(payload) {
                    Ok((ifindex, addr)) => {
                        if ifindex != IFINDEX_ETH0 {
                            Err(if ifindex == IFINDEX_LO {
                                EOPNOTSUPP
                            } else {
                                ENODEV
                            })
                        } else if hdr.kind == RTM_NEWADDR {
                            net.add_ipv4_address(addr).await
                        } else {
                            net.remove_ipv4_address(addr).await
                        }
                    }
                    Err(err) => Err(err),
                }
            };
            match result {
                Ok(()) => {
                    if hdr.flags & NLM_F_ACK != 0 {
                        append_nlmsg_error(&mut out, 0, hdr, port_id);
                    }
                }
                Err(err) => append_nlmsg_error(&mut out, -(err as i32), hdr, port_id),
            }
        }
        RTM_GETROUTE => {
            let filter_family = payload.first().copied().unwrap_or(AF_UNSPEC as u8);
            let msg_flags = if is_dump { NLM_F_MULTI } else { 0 };
            if (filter_family == AF_UNSPEC as u8 || filter_family == AF_INET as u8)
                && let Ok(routes) = net.list_ipv4_routes().await
            {
                for route in routes {
                    append_ipv4_route_msg(&mut out, route, msg_flags, hdr.seq, port_id);
                }
            }
            if is_dump {
                append_nlmsg_done(&mut out, hdr.seq, port_id);
            }
        }
        RTM_NEWROUTE | RTM_DELROUTE => {
            let result = if !ctx.cap_net_admin {
                Err(EPERM)
            } else {
                match parse_rtmsg(payload) {
                    Ok((oif, route)) => {
                        if let Some(ifindex) = oif
                            && ifindex != IFINDEX_ETH0
                        {
                            Err(if ifindex == IFINDEX_LO {
                                EOPNOTSUPP
                            } else {
                                ENODEV
                            })
                        } else if hdr.kind == RTM_NEWROUTE {
                            net.add_ipv4_route(route).await
                        } else {
                            net.remove_ipv4_route(route).await
                        }
                    }
                    Err(err) => Err(err),
                }
            };
            match result {
                Ok(()) => {
                    if hdr.flags & NLM_F_ACK != 0 {
                        append_nlmsg_error(&mut out, 0, hdr, port_id);
                    }
                }
                Err(err) => append_nlmsg_error(&mut out, -(err as i32), hdr, port_id),
            }
        }
        _ => {
            append_nlmsg_error(&mut out, -(EOPNOTSUPP as i32), hdr, port_id);
        }
    }
    out
}

async fn validate_link_mutation<N: SocketNetwork, Net: Network<N>>(
    payload: &[u8],
    net: &Net,
) -> Result<(), u64> {
    let ifindex = resolve_link_query(payload)?;
    let ifi_flags = u32::from_ne_bytes([payload[8], payload[9], payload[10], payload[11]]);
    let ifi_change = u32::from_ne_bytes([payload[12], payload[13], payload[14], payload[15]]);
    let (current_flags, current_mtu) = if ifindex == IFINDEX_LO {
        (LO_FLAGS, LO_MTU)
    } else {
        (ETH0_FLAGS, ETH0_MTU)
    };
    if (ifi_change & IFF_UP) != 0 && (ifi_flags & IFF_UP) == 0 {
        return Err(EOPNOTSUPP);
    }
    if (ifi_change & !current_flags & ifi_flags) != 0 {
        return Err(EOPNOTSUPP);
    }
    for (rta_type, rta_val) in parse_rtattrs(&payload[16..]) {
        match rta_type {
            IFLA_IFNAME => {}
            IFLA_MTU => {
                if rta_val.len() < 4 {
                    return Err(EINVAL);
                }
                let mtu = u32::from_ne_bytes([rta_val[0], rta_val[1], rta_val[2], rta_val[3]]);
                if mtu != current_mtu {
                    return Err(EOPNOTSUPP);
                }
            }
            IFLA_ADDRESS => {
                let current_mac = if ifindex == IFINDEX_LO {
                    [0u8; 6]
                } else {
                    net.interface_mac().await.unwrap_or([0; 6])
                };
                if rta_val != current_mac.as_slice() {
                    return Err(EOPNOTSUPP);
                }
            }
            _ => return Err(EOPNOTSUPP),
        }
    }
    Ok(())
}

fn resolve_link_query(payload: &[u8]) -> Result<u32, u64> {
    if payload.len() < 16 {
        return Err(EINVAL);
    }
    let ifi_index = i32::from_ne_bytes([payload[4], payload[5], payload[6], payload[7]]);
    if ifi_index > 0 {
        return match ifi_index as u32 {
            IFINDEX_LO => Ok(IFINDEX_LO),
            IFINDEX_ETH0 => Ok(IFINDEX_ETH0),
            _ => Err(ENODEV),
        };
    }
    for (rta_type, rta_val) in parse_rtattrs(&payload[16..]) {
        if rta_type == IFLA_IFNAME {
            return lookup_ifindex(rta_val);
        }
    }
    Err(ENODEV)
}

fn parse_ifaddrmsg(payload: &[u8]) -> Result<(u32, Ipv4InterfaceAddress), u64> {
    if payload.len() < 8 {
        return Err(EINVAL);
    }
    let family = payload[0];
    let prefix = payload[1];
    let ifindex = u32::from_ne_bytes([payload[4], payload[5], payload[6], payload[7]]);
    if family != AF_INET as u8 || prefix > 32 {
        return Err(EINVAL);
    }
    let mut local: Option<[u8; 4]> = None;
    let mut addr: Option<[u8; 4]> = None;
    for (rta_type, rta_val) in parse_rtattrs(&payload[8..]) {
        if rta_val.len() >= 4 {
            let ip = [rta_val[0], rta_val[1], rta_val[2], rta_val[3]];
            match rta_type {
                IFA_LOCAL => local = Some(ip),
                IFA_ADDRESS => addr = Some(ip),
                _ => {}
            }
        }
    }
    let address = local.or(addr).ok_or(EINVAL)?;
    Ok((ifindex, Ipv4InterfaceAddress { address, prefix }))
}

fn parse_rtmsg(payload: &[u8]) -> Result<(Option<u32>, Ipv4RouteEntry), u64> {
    if payload.len() < 12 {
        return Err(EINVAL);
    }
    let family = payload[0];
    let dst_len = payload[1];
    if family != AF_INET as u8 || dst_len > 32 {
        return Err(EINVAL);
    }
    let mut destination = [0u8; 4];
    let mut gateway: Option<[u8; 4]> = None;
    let mut oif: Option<u32> = None;
    for (rta_type, rta_val) in parse_rtattrs(&payload[12..]) {
        if rta_val.len() >= 4 {
            match rta_type {
                RTA_DST => destination = [rta_val[0], rta_val[1], rta_val[2], rta_val[3]],
                RTA_GATEWAY => {
                    gateway = Some([rta_val[0], rta_val[1], rta_val[2], rta_val[3]]);
                }
                RTA_OIF => {
                    oif = Some(u32::from_ne_bytes([
                        rta_val[0], rta_val[1], rta_val[2], rta_val[3],
                    ]));
                }
                _ => {}
            }
        }
    }
    Ok((
        oif,
        Ipv4RouteEntry {
            destination,
            prefix: dst_len,
            gateway,
        },
    ))
}

fn parse_rtattrs(mut data: &[u8]) -> Vec<(u16, &[u8])> {
    let mut out = Vec::new();
    while data.len() >= 4 {
        let len = u16::from_ne_bytes([data[0], data[1]]) as usize;
        let kind = u16::from_ne_bytes([data[2], data[3]]) & 0x3fff;
        if len < 4 || len > data.len() {
            break;
        }
        out.push((kind, &data[4..len]));
        let step = align4(len);
        if step == 0 || step >= data.len() {
            break;
        }
        data = &data[step..];
    }
    out
}

fn append_nlmsg(out: &mut Vec<u8>, kind: u16, flags: u16, seq: u32, pid: u32, body: &[u8]) {
    let start = out.len();
    let total_len = (NLMSG_HDRLEN + body.len()) as u32;
    out.extend_from_slice(&total_len.to_ne_bytes());
    out.extend_from_slice(&kind.to_ne_bytes());
    out.extend_from_slice(&flags.to_ne_bytes());
    out.extend_from_slice(&seq.to_ne_bytes());
    out.extend_from_slice(&pid.to_ne_bytes());
    out.extend_from_slice(body);
    let padded = align4(out.len() - start);
    out.resize(start + padded, 0);
}

fn append_rta(buf: &mut Vec<u8>, kind: u16, value: &[u8]) {
    let start = buf.len();
    let len = (4 + value.len()) as u16;
    buf.extend_from_slice(&len.to_ne_bytes());
    buf.extend_from_slice(&kind.to_ne_bytes());
    buf.extend_from_slice(value);
    let padded = align4(buf.len() - start);
    buf.resize(start + padded, 0);
}

fn append_nlmsg_done(out: &mut Vec<u8>, seq: u32, pid: u32) {
    append_nlmsg(out, NLMSG_DONE, NLM_F_MULTI, seq, pid, &0i32.to_ne_bytes());
}

fn append_nlmsg_error(out: &mut Vec<u8>, err_code: i32, req: NlMsgHdr, pid: u32) {
    let mut body = Vec::with_capacity(20);
    body.extend_from_slice(&err_code.to_ne_bytes());
    body.extend_from_slice(&req.len.to_ne_bytes());
    body.extend_from_slice(&req.kind.to_ne_bytes());
    body.extend_from_slice(&req.flags.to_ne_bytes());
    body.extend_from_slice(&req.seq.to_ne_bytes());
    body.extend_from_slice(&req.pid.to_ne_bytes());
    append_nlmsg(out, NLMSG_ERROR, 0, req.seq, pid, &body);
}

fn append_link_msg(out: &mut Vec<u8>, ifindex: u32, mac: [u8; 6], flags: u16, seq: u32, pid: u32) {
    let (ifname, arphrd, if_flags, mtu, broadcast, operstate) = if ifindex == IFINDEX_LO {
        (
            b"lo\0".as_slice(),
            ARPHRD_LOOPBACK,
            LO_FLAGS,
            LO_MTU,
            [0u8; 6],
            IF_OPER_UNKNOWN,
        )
    } else {
        (
            b"eth0\0".as_slice(),
            ARPHRD_ETHER,
            ETH0_FLAGS,
            ETH0_MTU,
            [0xffu8; 6],
            IF_OPER_UP,
        )
    };
    let mut body = Vec::with_capacity(64);
    body.push(AF_UNSPEC as u8);
    body.push(0);
    body.extend_from_slice(&arphrd.to_ne_bytes());
    body.extend_from_slice(&(ifindex as i32).to_ne_bytes());
    body.extend_from_slice(&if_flags.to_ne_bytes());
    body.extend_from_slice(&0u32.to_ne_bytes());
    append_rta(&mut body, IFLA_IFNAME, ifname);
    append_rta(&mut body, IFLA_MTU, &mtu.to_ne_bytes());
    append_rta(&mut body, IFLA_OPERSTATE, &[operstate]);
    append_rta(&mut body, IFLA_ADDRESS, &mac);
    append_rta(&mut body, IFLA_BROADCAST, &broadcast);
    append_nlmsg(out, RTM_NEWLINK, flags, seq, pid, &body);
}

#[allow(clippy::too_many_arguments)]
fn append_ipv4_addr_msg(
    out: &mut Vec<u8>,
    ifindex: u32,
    label: &str,
    addr: Ipv4InterfaceAddress,
    scope: u8,
    flags: u16,
    seq: u32,
    pid: u32,
) {
    let mut body = Vec::with_capacity(48);
    body.push(AF_INET as u8);
    body.push(addr.prefix);
    body.push(0);
    body.push(scope);
    body.extend_from_slice(&ifindex.to_ne_bytes());
    append_rta(&mut body, IFA_ADDRESS, &addr.address);
    append_rta(&mut body, IFA_LOCAL, &addr.address);
    if ifindex != IFINDEX_LO && addr.prefix < 31 {
        let brd = broadcast_ipv4(addr.address, addr.prefix);
        append_rta(&mut body, IFA_BROADCAST, &brd);
    }
    let mut label_bytes = Vec::with_capacity(label.len() + 1);
    label_bytes.extend_from_slice(label.as_bytes());
    label_bytes.push(0);
    append_rta(&mut body, IFA_LABEL, &label_bytes);
    append_nlmsg(out, RTM_NEWADDR, flags, seq, pid, &body);
}

#[allow(clippy::too_many_arguments)]
fn append_ipv6_addr_msg(
    out: &mut Vec<u8>,
    ifindex: u32,
    addr: [u8; 16],
    prefix: u8,
    scope: u8,
    flags: u16,
    seq: u32,
    pid: u32,
) {
    let mut body = Vec::with_capacity(32);
    body.push(AF_INET6 as u8);
    body.push(prefix);
    body.push(0);
    body.push(scope);
    body.extend_from_slice(&ifindex.to_ne_bytes());
    append_rta(&mut body, IFA_ADDRESS, &addr);
    append_nlmsg(out, RTM_NEWADDR, flags, seq, pid, &body);
}

fn append_ipv4_route_msg(out: &mut Vec<u8>, route: Ipv4RouteEntry, flags: u16, seq: u32, pid: u32) {
    let (protocol, scope) = if route.gateway.is_some() {
        (RTPROT_BOOT, RT_SCOPE_UNIVERSE)
    } else {
        (RTPROT_KERNEL, RT_SCOPE_LINK)
    };
    let mut body = Vec::with_capacity(48);
    body.push(AF_INET as u8);
    body.push(route.prefix);
    body.push(0);
    body.push(0);
    body.push(RT_TABLE_MAIN);
    body.push(protocol);
    body.push(scope);
    body.push(RTN_UNICAST);
    body.extend_from_slice(&0u32.to_ne_bytes());
    if route.prefix > 0 {
        append_rta(&mut body, RTA_DST, &route.destination);
    }
    if let Some(gw) = route.gateway {
        append_rta(&mut body, RTA_GATEWAY, &gw);
    }
    append_rta(&mut body, RTA_OIF, &IFINDEX_ETH0.to_ne_bytes());
    append_nlmsg(out, RTM_NEWROUTE, flags, seq, pid, &body);
}

const fn align4(len: usize) -> usize {
    (len + 3) & !3
}

pub(crate) fn lookup_ifindex(raw_name: &[u8]) -> Result<u32, u64> {
    let nul = raw_name
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(raw_name.len());
    match &raw_name[..nul] {
        b"lo" => Ok(IFINDEX_LO),
        b"eth0" => Ok(IFINDEX_ETH0),
        _ => Err(ENODEV),
    }
}

async fn primary_ipv4_for<N: SocketNetwork, Net: Network<N>>(
    ifindex: u32,
    net: &Net,
) -> Result<Ipv4InterfaceAddress, u64> {
    if ifindex == IFINDEX_LO {
        return Ok(Ipv4InterfaceAddress {
            address: [127, 0, 0, 1],
            prefix: 8,
        });
    }
    let addrs = net.list_ipv4_addresses().await?;
    addrs.into_iter().next().ok_or(super::socket::EADDRNOTAVAIL)
}

fn write_sockaddr_in_slice(dst: &mut [u8], ip: [u8; 4]) {
    dst.fill(0);
    dst[0..2].copy_from_slice(&AF_INET.to_ne_bytes());
    dst[4..8].copy_from_slice(&ip);
}

fn read_sockaddr_in_slice(src: &[u8]) -> Result<[u8; 4], u64> {
    if src.len() < 8 {
        return Err(EINVAL);
    }
    let family = u16::from_ne_bytes([src[0], src[1]]);
    if family != AF_INET {
        return Err(EINVAL);
    }
    Ok([src[4], src[5], src[6], src[7]])
}

fn prefix_to_netmask(prefix: u8) -> [u8; 4] {
    if prefix == 0 {
        [0, 0, 0, 0]
    } else if prefix >= 32 {
        [255, 255, 255, 255]
    } else {
        (!0u32 << (32 - prefix)).to_be_bytes()
    }
}

fn netmask_to_prefix(mask: [u8; 4]) -> Result<u8, u64> {
    let val = u32::from_be_bytes(mask);
    let ones = val.leading_ones();
    let expected = if ones == 0 {
        0
    } else if ones == 32 {
        !0u32
    } else {
        !0u32 << (32 - ones)
    };
    if val != expected {
        return Err(EINVAL);
    }
    Ok(ones as u8)
}

fn broadcast_ipv4(ip: [u8; 4], prefix: u8) -> [u8; 4] {
    let ip_u32 = u32::from_be_bytes(ip);
    let mask_u32 = u32::from_be_bytes(prefix_to_netmask(prefix));
    (ip_u32 | !mask_u32).to_be_bytes()
}

fn default_ipv4_prefix(ip: [u8; 4]) -> u8 {
    match ip[0] {
        0..=127 => 8,
        128..=191 => 16,
        _ => 24,
    }
}
