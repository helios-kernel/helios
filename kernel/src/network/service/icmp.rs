use alloc::collections::VecDeque;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU16, AtomicU64, AtomicUsize, Ordering as AtomicOrdering};
use core::time::Duration;

use bytes::Bytes;
use helios_hal::cpu::Cpu;
use helios_netstack::{
    EthernetFrame, EthernetProtocol, IcmpEchoKey, IpAddress, IpProtocol, Ipv4Packet, Ipv6Packet,
    NetworkInterface as NetworkDevice, StackInstant,
};
use spin::Mutex as SpinMutex;

use super::{NETWORK_RETRANSMIT_WAIT, NetworkService};
use crate::{
    IcmpEchoDatagram, Ipv4Address as KernelIpv4Address, NetworkErrorDetail, NetworkIpAddress,
    SocketReadiness, UdpError, UdpErrorKind,
};

const MAX_ICMP_SOCKETS: usize = 64;
const MAX_QUEUED_ICMP_PER_SOCKET: usize = 64;
/// Maximum time `icmp_send` waits for ARP/NDP next-hop resolution when the
/// neighbor cache has no entry for a remote target yet.
const ICMP_NEIGHBOR_RESOLVE_TIMEOUT_NANOS: u64 = 500_000_000;

const ICMPV4_ECHO_REPLY: u8 = 0;
const ICMPV6_ECHO_REPLY: u8 = 129;

struct IcmpSocketEntry {
    id: u64,
    ipv6: bool,
    is_raw: bool,
    local_id: u16,
    queue: VecDeque<IcmpEchoDatagram>,
}

/// Registry of active `IPPROTO_ICMP` / `IPPROTO_ICMPV6` echo sockets attached
/// to a [`NetworkService`].
///
/// # Concurrency contract
///
/// `active_count` is checked with acquire/release ordering on the RX hot path
/// so that when no ICMP socket is open, `tap_rx_frame` takes no lock and
/// allocates nothing. When sockets are open, `sockets` is held only for header
/// parsing and a single `Bytes::copy_from_slice` of the ICMP payload (never
/// retaining the borrowed `RxFrame` past the receive pass), and is never held
/// across `.await`.
pub(super) struct IcmpSocketRegistry {
    active_count: AtomicUsize,
    next_id: AtomicU64,
    next_ephemeral_id: AtomicU16,
    sockets: SpinMutex<Vec<IcmpSocketEntry>>,
}

impl IcmpSocketRegistry {
    pub(super) const fn new() -> Self {
        Self {
            active_count: AtomicUsize::new(0),
            next_id: AtomicU64::new(1),
            next_ephemeral_id: AtomicU16::new(0x1000),
            sockets: SpinMutex::new(Vec::new()),
        }
    }

    fn alloc_ephemeral_id(&self, sockets: &[IcmpSocketEntry], ipv6: bool) -> Result<u16, UdpError> {
        for _ in 0..u16::MAX {
            let candidate = self.next_ephemeral_id.fetch_add(1, AtomicOrdering::Relaxed);
            if candidate == 0 {
                continue;
            }
            let in_use = sockets
                .iter()
                .any(|entry| !entry.is_raw && entry.ipv6 == ipv6 && entry.local_id == candidate);
            if !in_use {
                return Ok(candidate);
            }
        }
        Err(UdpError {
            kind: UdpErrorKind::Unavailable,
            detail: NetworkErrorDetail::UdpNoEphemeralPorts,
        })
    }

    pub(super) fn open(&self, ipv6: bool, is_raw: bool) -> Result<(u64, u16), UdpError> {
        let mut sockets = self.sockets.lock();
        if sockets.len() >= MAX_ICMP_SOCKETS {
            return Err(UdpError {
                kind: UdpErrorKind::Unavailable,
                detail: NetworkErrorDetail::UdpNoEphemeralPorts,
            });
        }
        let local_id = if is_raw {
            0
        } else {
            self.alloc_ephemeral_id(&sockets, ipv6)?
        };
        let id = self.next_id.fetch_add(1, AtomicOrdering::Relaxed);
        sockets.push(IcmpSocketEntry {
            id,
            ipv6,
            is_raw,
            local_id,
            queue: VecDeque::new(),
        });
        self.active_count
            .store(sockets.len(), AtomicOrdering::Release);
        Ok((id, local_id))
    }

    pub(super) fn bind(&self, id: u64, requested_id: u16) -> Result<u16, UdpError> {
        let mut sockets = self.sockets.lock();
        let idx = sockets
            .iter()
            .position(|entry| entry.id == id)
            .ok_or(UdpError {
                kind: UdpErrorKind::Internal,
                detail: NetworkErrorDetail::UnknownUdpSocket,
            })?;
        if sockets[idx].is_raw {
            return Ok(0);
        }
        let ipv6 = sockets[idx].ipv6;
        let assigned = if requested_id == 0 {
            if sockets[idx].local_id != 0 {
                sockets[idx].local_id
            } else {
                self.alloc_ephemeral_id(&sockets, ipv6)?
            }
        } else {
            let conflict = sockets.iter().enumerate().any(|(i, entry)| {
                i != idx && !entry.is_raw && entry.ipv6 == ipv6 && entry.local_id == requested_id
            });
            if conflict {
                return Err(UdpError {
                    kind: UdpErrorKind::Unavailable,
                    detail: NetworkErrorDetail::UdpPortInUse,
                });
            }
            requested_id
        };
        sockets[idx].local_id = assigned;
        Ok(assigned)
    }

    pub(super) fn socket_family(&self, id: u64) -> Result<(bool, bool, u16), UdpError> {
        let sockets = self.sockets.lock();
        let entry = sockets
            .iter()
            .find(|entry| entry.id == id)
            .ok_or(UdpError {
                kind: UdpErrorKind::Internal,
                detail: NetworkErrorDetail::UnknownUdpSocket,
            })?;
        Ok((entry.ipv6, entry.is_raw, entry.local_id))
    }

    /// Inspects an incoming Ethernet frame and copies matching ICMP / ICMPv6
    /// packets into open ICMP sockets' receive queues.
    pub(super) fn tap_rx_frame(&self, frame: &[u8]) -> bool {
        if self.active_count.load(AtomicOrdering::Acquire) == 0 {
            return false;
        }
        let Some(eth) = EthernetFrame::parse(frame) else {
            return false;
        };
        let (ipv6, source, destination, ttl, icmp_bytes) = match eth.protocol {
            EthernetProtocol::Ipv4 => {
                let Some(ip) = Ipv4Packet::parse_without_checksum(eth.payload) else {
                    return false;
                };
                if ip.protocol != IpProtocol::Icmp || ip.payload.len() < 8 {
                    return false;
                }
                (
                    false,
                    NetworkIpAddress::Ipv4(KernelIpv4Address::new(ip.source.octets())),
                    NetworkIpAddress::Ipv4(KernelIpv4Address::new(ip.destination.octets())),
                    ip.hop_limit,
                    ip.payload,
                )
            }
            EthernetProtocol::Ipv6 => {
                let Some(ip) = Ipv6Packet::parse(eth.payload) else {
                    return false;
                };
                if ip.next_header != IpProtocol::Icmpv6 || ip.payload.len() < 8 {
                    return false;
                }
                (
                    true,
                    NetworkIpAddress::Ipv6(ip.source),
                    NetworkIpAddress::Ipv6(ip.destination),
                    ip.hop_limit,
                    ip.payload,
                )
            }
            _ => return false,
        };
        self.deliver_datagram(ipv6, source, destination, ttl, icmp_bytes)
    }

    fn deliver_datagram(
        &self,
        ipv6: bool,
        source: NetworkIpAddress,
        destination: NetworkIpAddress,
        ttl: u8,
        icmp_bytes: &[u8],
    ) -> bool {
        if icmp_bytes.len() < 8 {
            return false;
        }
        let msg_type = icmp_bytes[0];
        let echo_id = u16::from_be_bytes([icmp_bytes[4], icmp_bytes[5]]);
        let expected_reply_type = if ipv6 {
            ICMPV6_ECHO_REPLY
        } else {
            ICMPV4_ECHO_REPLY
        };
        let mut sockets = self.sockets.lock();
        let mut shared_payload: Option<Bytes> = None;
        for entry in sockets.iter_mut() {
            if entry.ipv6 != ipv6 {
                continue;
            }
            if !entry.is_raw && (msg_type != expected_reply_type || entry.local_id != echo_id) {
                continue;
            }
            let payload = shared_payload
                .get_or_insert_with(|| Bytes::copy_from_slice(icmp_bytes))
                .clone();
            if entry.queue.len() >= MAX_QUEUED_ICMP_PER_SOCKET {
                let _ = entry.queue.pop_front();
            }
            entry.queue.push_back(IcmpEchoDatagram {
                source,
                destination,
                ttl,
                payload,
            });
        }
        shared_payload.is_some()
    }

    /// Synthesizes an ICMPv4 / ICMPv6 Echo Reply for loopback or local
    /// interface destinations and queues it for matching open ICMP sockets.
    pub(super) fn deliver_local_reply(
        &self,
        source: NetworkIpAddress,
        destination: NetworkIpAddress,
        ttl: u8,
        identifier: u16,
        sequence: u16,
        payload: &[u8],
    ) -> bool {
        let ipv6 = matches!(source, NetworkIpAddress::Ipv6(_));
        let mut icmp = vec![0u8; 8 + payload.len()];
        icmp[0] = if ipv6 {
            ICMPV6_ECHO_REPLY
        } else {
            ICMPV4_ECHO_REPLY
        };
        icmp[1] = 0;
        icmp[4..6].copy_from_slice(&identifier.to_be_bytes());
        icmp[6..8].copy_from_slice(&sequence.to_be_bytes());
        icmp[8..].copy_from_slice(payload);
        let csum = match (source, destination) {
            (NetworkIpAddress::Ipv4(_), NetworkIpAddress::Ipv4(_)) => internet_checksum(&icmp),
            (NetworkIpAddress::Ipv6(src), NetworkIpAddress::Ipv6(dst)) => {
                icmpv6_checksum(src.octets(), dst.octets(), &icmp)
            }
            _ => return false,
        };
        icmp[2..4].copy_from_slice(&csum.to_be_bytes());
        self.deliver_datagram(ipv6, source, destination, ttl, &icmp)
    }

    pub(super) fn pop_datagram(
        &self,
        id: u64,
        peek: bool,
    ) -> Result<Option<IcmpEchoDatagram>, UdpError> {
        let mut sockets = self.sockets.lock();
        let entry = sockets
            .iter_mut()
            .find(|entry| entry.id == id)
            .ok_or(UdpError {
                kind: UdpErrorKind::Internal,
                detail: NetworkErrorDetail::UnknownUdpSocket,
            })?;
        Ok(if peek {
            entry.queue.front().cloned()
        } else {
            entry.queue.pop_front()
        })
    }

    pub(super) fn readiness(&self, id: u64) -> SocketReadiness {
        let sockets = self.sockets.lock();
        match sockets.iter().find(|entry| entry.id == id) {
            Some(entry) => SocketReadiness {
                readable: !entry.queue.is_empty(),
                writable: true,
                hangup: false,
            },
            None => SocketReadiness::default(),
        }
    }

    pub(super) fn close(&self, id: u64) {
        let mut sockets = self.sockets.lock();
        if let Some(pos) = sockets.iter().position(|entry| entry.id == id) {
            sockets.swap_remove(pos);
            self.active_count
                .store(sockets.len(), AtomicOrdering::Release);
        }
    }
}

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

fn icmpv6_checksum(src: [u8; 16], dst: [u8; 16], icmp: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let add_slice = |sum: &mut u32, slice: &[u8]| {
        let (chunks, remainder) = slice.as_chunks::<2>();
        for &chunk in chunks {
            *sum = sum.wrapping_add(u32::from(u16::from_be_bytes(chunk)));
        }
        if let Some(&last) = remainder.first() {
            *sum = sum.wrapping_add(u32::from(u16::from_be_bytes([last, 0])));
        }
    };
    add_slice(&mut sum, &src);
    add_slice(&mut sum, &dst);
    let len_bytes = (icmp.len() as u32).to_be_bytes();
    add_slice(&mut sum, &len_bytes);
    add_slice(&mut sum, &[0, 0, 0, IpProtocol::Icmpv6.number()]);
    add_slice(&mut sum, icmp);
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

impl<CpuImpl, DeviceImpl> NetworkService<CpuImpl, DeviceImpl>
where
    CpuImpl: Cpu + Clone,
    DeviceImpl: NetworkDevice,
{
    pub fn icmp_open(&self, ipv6: bool, is_raw: bool) -> Result<(u64, u16), UdpError> {
        self.inner.icmp_sockets.open(ipv6, is_raw)
    }

    pub fn icmp_bind(&self, socket: u64, requested_id: u16) -> Result<u16, UdpError> {
        self.inner.icmp_sockets.bind(socket, requested_id)
    }

    fn is_self_or_loopback(&self, destination: IpAddress) -> bool {
        match destination {
            IpAddress::Ipv4(ipv4) => {
                if ipv4.is_loopback() {
                    return true;
                }
                self.inner
                    .control
                    .ipv4_addresses
                    .load_full()
                    .entries
                    .iter()
                    .any(|cidr| cidr.address() == ipv4)
            }
            IpAddress::Ipv6(ipv6) => {
                if ipv6.is_loopback() {
                    return true;
                }
                self.inner
                    .control
                    .ipv6_addresses
                    .load_full()
                    .entries
                    .iter()
                    .any(|entry| entry.cidr().address() == ipv6)
            }
        }
    }

    pub async fn icmp_send(
        &self,
        socket: u64,
        destination: NetworkIpAddress,
        identifier: u16,
        sequence: u16,
        payload: &[u8],
        hop_limit: u8,
    ) -> Result<(), UdpError> {
        let (ipv6, _is_raw, _local_id) = self.inner.icmp_sockets.socket_family(socket)?;
        let dest_is_v6 = matches!(destination, NetworkIpAddress::Ipv6(_));
        if ipv6 != dest_is_v6 {
            return Err(UdpError {
                kind: UdpErrorKind::Unsupported,
                detail: NetworkErrorDetail::UnsupportedAddressFamily,
            });
        }
        let target = match destination {
            NetworkIpAddress::Ipv4(v4) => {
                IpAddress::Ipv4(helios_netstack::Ipv4Address::new(v4.octets()))
            }
            NetworkIpAddress::Ipv6(v6) => IpAddress::Ipv6(v6),
        };
        if self.is_self_or_loopback(target) {
            let ttl = if hop_limit == 0 { 64 } else { hop_limit };
            if self.inner.icmp_sockets.deliver_local_reply(
                destination,
                destination,
                ttl,
                identifier,
                sequence,
                payload,
            ) {
                self.inner.state.any_arrival.signal();
            }
            return Ok(());
        }
        let key = IcmpEchoKey {
            destination: target,
            identifier,
            sequence,
        };
        let deadline = self
            .now_nanos()
            .saturating_add(ICMP_NEIGHBOR_RESOLVE_TIMEOUT_NANOS);
        loop {
            let wait = self.default_shard_wait();
            let now = StackInstant::from_nanos(self.now_nanos());
            let transmitted = self
                .inner
                .state
                .with_mut(|state| state.send_icmp_echo_request(key, payload, now))
                .map_err(|_| UdpError {
                    kind: UdpErrorKind::Unavailable,
                    detail: NetworkErrorDetail::IcmpQueueFailed,
                })?;
            self.drive_udp().await?;
            if transmitted {
                return Ok(());
            }
            if self.now_nanos() >= deadline {
                // Neighbor resolution packet went out; return Ok so the caller's
                // receive loop can observe either the reply or timeout as Linux
                // `ping_v4_sendmsg` does.
                return Ok(());
            }
            let bound = self.retransmit_wait(
                deadline,
                NETWORK_RETRANSMIT_WAIT.min(Duration::from_millis(50)),
            );
            self.wait_for_shard_progress(wait, bound).await;
        }
    }

    pub async fn icmp_receive(
        &self,
        socket: u64,
        timeout_nanos: u64,
        peek: bool,
    ) -> Result<Option<IcmpEchoDatagram>, UdpError> {
        let deadline_nanos = self.now_nanos().saturating_add(timeout_nanos);
        loop {
            if let Some(datagram) = self.inner.icmp_sockets.pop_datagram(socket, peek)? {
                return Ok(Some(datagram));
            }
            let wait = self.any_shard_wait();
            self.drive_udp().await?;
            if let Some(datagram) = self.inner.icmp_sockets.pop_datagram(socket, peek)? {
                return Ok(Some(datagram));
            }
            if timeout_nanos == 0 {
                return Ok(None);
            }
            if self.now_nanos() >= deadline_nanos {
                return Err(UdpError {
                    kind: UdpErrorKind::Timeout,
                    detail: NetworkErrorDetail::UdpReceiveTimeout,
                });
            }
            self.wait_for_shard_progress(wait, self.deadline_wait(deadline_nanos))
                .await;
        }
    }

    pub async fn icmp_readiness(&self, socket: u64) -> Result<SocketReadiness, UdpError> {
        self.drive_udp().await?;
        Ok(self.inner.icmp_sockets.readiness(socket))
    }

    pub fn icmp_close(&self, socket: u64) {
        self.inner.icmp_sockets.close(socket);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use helios_netstack::{Ipv4Address, Ipv6Address};

    #[test]
    fn icmp_registry_loopback_dgram_and_raw_delivery() {
        let registry = IcmpSocketRegistry::new();
        let (dgram_id, local_id) = registry.open(false, false).unwrap();
        let (raw_id, _) = registry.open(false, true).unwrap();
        let lo = NetworkIpAddress::Ipv4(KernelIpv4Address::new([127, 0, 0, 1]));

        assert!(registry.deliver_local_reply(lo, lo, 64, local_id, 7, b"hello"));

        let dgram = registry.pop_datagram(dgram_id, false).unwrap().unwrap();
        assert_eq!(dgram.source, lo);
        assert_eq!(dgram.ttl, 64);
        assert_eq!(dgram.payload[0], ICMPV4_ECHO_REPLY);
        assert_eq!(
            u16::from_be_bytes([dgram.payload[4], dgram.payload[5]]),
            local_id
        );
        assert_eq!(u16::from_be_bytes([dgram.payload[6], dgram.payload[7]]), 7);
        assert_eq!(&dgram.payload[8..], b"hello");

        let raw = registry.pop_datagram(raw_id, false).unwrap().unwrap();
        assert_eq!(raw.payload, dgram.payload);

        // Non-matching echo ID does not reach the dgram socket, but reaches raw.
        let other_id = local_id.wrapping_add(1).max(1);
        assert!(registry.deliver_local_reply(lo, lo, 64, other_id, 8, b"other"));
        assert!(registry.pop_datagram(dgram_id, false).unwrap().is_none());
        assert!(registry.pop_datagram(raw_id, false).unwrap().is_some());

        registry.close(dgram_id);
        registry.close(raw_id);
    }

    #[test]
    fn icmp_registry_taps_ipv4_and_ipv6_rx_frames() {
        let registry = IcmpSocketRegistry::new();
        let (v4_sock, v4_id) = registry.open(false, false).unwrap();
        let (v6_sock, v6_id) = registry.open(true, false).unwrap();

        // Build an IPv4 Ethernet frame carrying an ICMP Echo Reply for v4_id.
        let mut icmp4 = vec![0u8; 12];
        icmp4[0] = ICMPV4_ECHO_REPLY;
        icmp4[4..6].copy_from_slice(&v4_id.to_be_bytes());
        icmp4[6..8].copy_from_slice(&1u16.to_be_bytes());
        icmp4[8..12].copy_from_slice(b"ping");
        let csum4 = internet_checksum(&icmp4);
        icmp4[2..4].copy_from_slice(&csum4.to_be_bytes());

        let mut frame4 =
            vec![0u8; EthernetFrame::HEADER_LEN + Ipv4Packet::MIN_HEADER_LEN + icmp4.len()];
        EthernetFrame::encode_header(&mut frame4, [0; 6], [0; 6], EthernetProtocol::Ipv4).unwrap();
        Ipv4Packet::encode_header(
            &mut frame4[EthernetFrame::HEADER_LEN..],
            Ipv4Address::new([1, 1, 1, 1]),
            Ipv4Address::new([10, 0, 2, 15]),
            IpProtocol::Icmp,
            icmp4.len(),
            1,
            55,
        )
        .unwrap();
        frame4[EthernetFrame::HEADER_LEN + Ipv4Packet::MIN_HEADER_LEN..].copy_from_slice(&icmp4);
        assert!(registry.tap_rx_frame(&frame4));
        let got4 = registry.pop_datagram(v4_sock, false).unwrap().unwrap();
        assert_eq!(
            got4.source,
            NetworkIpAddress::Ipv4(KernelIpv4Address::new([1, 1, 1, 1]))
        );
        assert_eq!(got4.ttl, 55);
        assert_eq!(&got4.payload[8..], b"ping");

        // Build an IPv6 Ethernet frame carrying an ICMPv6 Echo Reply for v6_id.
        let src6 = Ipv6Address::new([
            0x20, 0x01, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0x88,
        ]);
        let dst6 = Ipv6Address::new([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        let mut icmp6 = vec![0u8; 12];
        icmp6[0] = ICMPV6_ECHO_REPLY;
        icmp6[4..6].copy_from_slice(&v6_id.to_be_bytes());
        icmp6[6..8].copy_from_slice(&2u16.to_be_bytes());
        icmp6[8..12].copy_from_slice(b"v6ok");
        let csum6 = icmpv6_checksum(src6.octets(), dst6.octets(), &icmp6);
        icmp6[2..4].copy_from_slice(&csum6.to_be_bytes());

        let mut frame6 =
            vec![0u8; EthernetFrame::HEADER_LEN + Ipv6Packet::HEADER_LEN + icmp6.len()];
        EthernetFrame::encode_header(&mut frame6, [0; 6], [0; 6], EthernetProtocol::Ipv6).unwrap();
        Ipv6Packet::encode_header(
            &mut frame6[EthernetFrame::HEADER_LEN..],
            src6,
            dst6,
            IpProtocol::Icmpv6,
            icmp6.len(),
            59,
        )
        .unwrap();
        frame6[EthernetFrame::HEADER_LEN + Ipv6Packet::HEADER_LEN..].copy_from_slice(&icmp6);
        assert!(registry.tap_rx_frame(&frame6));
        let got6 = registry.pop_datagram(v6_sock, false).unwrap().unwrap();
        assert_eq!(got6.source, NetworkIpAddress::Ipv6(src6));
        assert_eq!(got6.ttl, 59);
        assert_eq!(&got6.payload[8..], b"v6ok");

        registry.close(v4_sock);
        registry.close(v6_sock);
    }
}
