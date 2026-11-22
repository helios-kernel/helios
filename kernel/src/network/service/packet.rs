use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering as AtomicOrdering};

use bytes::Bytes;
use helios_hal::cpu::Cpu;
use helios_netstack::{NetworkInterface as NetworkDevice, TxFrameRef};
use spin::Mutex as SpinMutex;

use super::{DEFAULT_SHARD_IDX, NetworkService};
use crate::{NetworkErrorDetail, PacketFrame, SocketReadiness, UdpError, UdpErrorKind};

/// Linux `ETH_P_ALL` in host byte order: matches every EtherType.
pub(super) const ETH_P_ALL: u16 = 0x0003;
/// Minimum valid Ethernet II frame header length (dst + src + ethertype).
pub(super) const ETH_HEADER_LEN: usize = 14;
/// Linux interface index for wildcard ("any interface").
pub(super) const IFINDEX_ANY: u32 = 0;
/// Linux interface index for the loopback interface (`lo`).
pub(super) const IFINDEX_LO: u32 = 1;
/// Linux interface index for the primary NIC (`eth0`).
pub(super) const IFINDEX_ETH0: u32 = 2;

const MAX_PACKET_TAPS: usize = 64;
const MAX_QUEUED_FRAMES_PER_TAP: usize = 128;
const MAX_TX_SUBMIT_ATTEMPTS: usize = 16;

struct QueuedPacketFrame {
    ifindex: u32,
    protocol: u16,
    bytes: Bytes,
}

struct PacketTap {
    id: u64,
    protocol: u16,
    ifindex: u32,
    queue: VecDeque<QueuedPacketFrame>,
}

impl PacketTap {
    const fn matches(&self, ifindex: u32, ethertype: u16) -> bool {
        if self.protocol == 0 {
            return false;
        }
        if self.ifindex != IFINDEX_ANY && self.ifindex != ifindex {
            return false;
        }
        self.protocol == ETH_P_ALL || self.protocol == ethertype
    }
}

/// Registry of active `AF_PACKET` taps attached to a [`NetworkService`].
///
/// # Concurrency contract
///
/// `active_count` is checked with relaxed ordering on the RX hot path so that
/// when no packet socket is open, `tap_rx_frame` performs zero locks and zero
/// allocations. When at least one tap is open, `taps` is held only for the
/// duration of the protocol filter and a single `Bytes::copy_from_slice` of the
/// lent `RxFrame` (never retaining the borrowed `RxFrame` beyond the receive
/// pass), and is never held across `.await`.
pub(super) struct PacketTapRegistry {
    active_count: AtomicUsize,
    next_id: AtomicU64,
    taps: SpinMutex<Vec<PacketTap>>,
}

impl PacketTapRegistry {
    pub(super) const fn new() -> Self {
        Self {
            active_count: AtomicUsize::new(0),
            next_id: AtomicU64::new(1),
            taps: SpinMutex::new(Vec::new()),
        }
    }

    pub(super) fn open(&self, protocol: u16) -> Result<u64, UdpError> {
        let mut taps = self.taps.lock();
        if taps.len() >= MAX_PACKET_TAPS {
            return Err(UdpError {
                kind: UdpErrorKind::Unavailable,
                detail: NetworkErrorDetail::UdpNoEphemeralPorts,
            });
        }
        let id = self.next_id.fetch_add(1, AtomicOrdering::Relaxed);
        taps.push(PacketTap {
            id,
            protocol,
            ifindex: IFINDEX_ANY,
            queue: VecDeque::new(),
        });
        self.active_count.store(taps.len(), AtomicOrdering::Release);
        Ok(id)
    }

    pub(super) fn bind(&self, id: u64, protocol: u16, ifindex: u32) -> Result<(), UdpError> {
        if ifindex != IFINDEX_ANY && ifindex != IFINDEX_LO && ifindex != IFINDEX_ETH0 {
            return Err(UdpError {
                kind: UdpErrorKind::Unsupported,
                detail: NetworkErrorDetail::UnsupportedAddressFamily,
            });
        }
        let mut taps = self.taps.lock();
        let tap = taps.iter_mut().find(|tap| tap.id == id).ok_or(UdpError {
            kind: UdpErrorKind::Internal,
            detail: NetworkErrorDetail::UnknownUdpSocket,
        })?;
        tap.protocol = protocol;
        tap.ifindex = ifindex;
        Ok(())
    }

    pub(super) fn bound_ifindex(&self, id: u64) -> Result<u32, UdpError> {
        let taps = self.taps.lock();
        let tap = taps.iter().find(|tap| tap.id == id).ok_or(UdpError {
            kind: UdpErrorKind::Internal,
            detail: NetworkErrorDetail::UnknownUdpSocket,
        })?;
        Ok(tap.ifindex)
    }

    /// Copies `frame` into every matching tap's bounded receive queue.
    ///
    /// Returns `true` if at least one tap accepted a copy.
    pub(super) fn tap_rx_frame(&self, ifindex: u32, frame: &[u8]) -> bool {
        if self.active_count.load(AtomicOrdering::Relaxed) == 0 || frame.len() < ETH_HEADER_LEN {
            return false;
        }
        let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
        let mut taps = self.taps.lock();
        let mut shared: Option<Bytes> = None;
        for tap in taps.iter_mut() {
            if !tap.matches(ifindex, ethertype) {
                continue;
            }
            let bytes = shared
                .get_or_insert_with(|| Bytes::copy_from_slice(frame))
                .clone();
            if tap.queue.len() >= MAX_QUEUED_FRAMES_PER_TAP {
                let _ = tap.queue.pop_front();
            }
            tap.queue.push_back(QueuedPacketFrame {
                ifindex,
                protocol: ethertype,
                bytes,
            });
        }
        shared.is_some()
    }

    pub(super) fn pop_frame(
        &self,
        id: u64,
        max_bytes: usize,
        peek: bool,
    ) -> Result<Option<PacketFrame>, UdpError> {
        let mut taps = self.taps.lock();
        let tap = taps.iter_mut().find(|tap| tap.id == id).ok_or(UdpError {
            kind: UdpErrorKind::Internal,
            detail: NetworkErrorDetail::UnknownUdpSocket,
        })?;
        let frame = if peek {
            tap.queue.front().map(|queued| QueuedPacketFrame {
                ifindex: queued.ifindex,
                protocol: queued.protocol,
                bytes: queued.bytes.clone(),
            })
        } else {
            tap.queue.pop_front()
        };
        Ok(frame.map(|queued| {
            let original_len = queued.bytes.len();
            let bytes = if original_len > max_bytes {
                queued.bytes.slice(..max_bytes)
            } else {
                queued.bytes
            };
            PacketFrame {
                ifindex: queued.ifindex,
                protocol: queued.protocol,
                bytes,
                original_len,
            }
        }))
    }

    pub(super) fn readiness(&self, id: u64) -> SocketReadiness {
        let taps = self.taps.lock();
        match taps.iter().find(|tap| tap.id == id) {
            Some(tap) => SocketReadiness {
                readable: !tap.queue.is_empty(),
                writable: true,
                hangup: false,
            },
            None => SocketReadiness::default(),
        }
    }

    pub(super) fn close(&self, id: u64) {
        let mut taps = self.taps.lock();
        if let Some(pos) = taps.iter().position(|tap| tap.id == id) {
            taps.swap_remove(pos);
            self.active_count.store(taps.len(), AtomicOrdering::Release);
        }
    }
}

impl<CpuImpl, DeviceImpl> NetworkService<CpuImpl, DeviceImpl>
where
    CpuImpl: Cpu + Clone,
    DeviceImpl: NetworkDevice,
{
    pub fn packet_open(&self, protocol: u16) -> Result<u64, UdpError> {
        self.inner.packet_taps.open(protocol)
    }

    pub fn packet_bind(&self, socket: u64, protocol: u16, ifindex: u32) -> Result<(), UdpError> {
        self.inner.packet_taps.bind(socket, protocol, ifindex)
    }

    pub async fn packet_send(
        &self,
        socket: u64,
        ifindex: u32,
        frame: &[u8],
    ) -> Result<usize, UdpError> {
        let bound_ifindex = self.inner.packet_taps.bound_ifindex(socket)?;
        let target_ifindex = if ifindex != IFINDEX_ANY {
            ifindex
        } else if bound_ifindex != IFINDEX_ANY {
            bound_ifindex
        } else {
            IFINDEX_ETH0
        };
        if frame.len() < ETH_HEADER_LEN || frame.len() > self.inner.device.max_frame_len() {
            return Err(UdpError {
                kind: UdpErrorKind::Internal,
                detail: NetworkErrorDetail::UdpDatagramTooLarge,
            });
        }
        match target_ifindex {
            IFINDEX_LO => {
                if self.inner.packet_taps.tap_rx_frame(IFINDEX_LO, frame) {
                    self.inner.state.any_arrival.signal();
                }
                Ok(frame.len())
            }
            IFINDEX_ETH0 => {
                let tx_frames = [TxFrameRef {
                    bytes: frame,
                    payload: None,
                    checksum: None,
                    segmentation: None,
                }];
                for _ in 0..MAX_TX_SUBMIT_ATTEMPTS {
                    let _ = self
                        .inner
                        .device
                        .reclaim_transmit_completions_immediate_on(DEFAULT_SHARD_IDX, 32);
                    match self
                        .inner
                        .device
                        .try_transmit_scatter_immediate_on(DEFAULT_SHARD_IDX, &tx_frames)
                    {
                        Ok(Some(1)) => {
                            self.inner.state.record_transmitted(DEFAULT_SHARD_IDX, 1);
                            return Ok(frame.len());
                        }
                        Ok(Some(0) | None) => {
                            crate::yield_now().await;
                        }
                        Ok(Some(_)) => {
                            self.inner.state.record_transmitted(DEFAULT_SHARD_IDX, 1);
                            return Ok(frame.len());
                        }
                        Err(error) => {
                            return Err(UdpError::from_io(
                                error,
                                NetworkErrorDetail::VirtioAdvanceFailed,
                            ));
                        }
                    }
                }
                Err(UdpError {
                    kind: UdpErrorKind::Unavailable,
                    detail: NetworkErrorDetail::VirtioAdvanceFailed,
                })
            }
            _ => Err(UdpError {
                kind: UdpErrorKind::Unsupported,
                detail: NetworkErrorDetail::UnsupportedAddressFamily,
            }),
        }
    }

    pub async fn packet_receive(
        &self,
        socket: u64,
        max_bytes: u32,
        timeout_nanos: u64,
        peek: bool,
    ) -> Result<Option<PacketFrame>, UdpError> {
        let deadline_nanos = self.now_nanos().saturating_add(timeout_nanos);
        loop {
            if let Some(frame) =
                self.inner
                    .packet_taps
                    .pop_frame(socket, max_bytes as usize, peek)?
            {
                return Ok(Some(frame));
            }
            let wait = self.any_shard_wait();
            self.drive_udp().await?;
            if let Some(frame) =
                self.inner
                    .packet_taps
                    .pop_frame(socket, max_bytes as usize, peek)?
            {
                return Ok(Some(frame));
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

    pub fn packet_readiness(&self, socket: u64) -> SocketReadiness {
        self.inner.packet_taps.readiness(socket)
    }

    pub fn packet_close(&self, socket: u64) {
        self.inner.packet_taps.close(socket);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_ethernet_frame(ethertype: u16, payload: &[u8]) -> Vec<u8> {
        let mut frame = Vec::with_capacity(ETH_HEADER_LEN + payload.len());
        frame.extend_from_slice(&[0xff; 6]);
        frame.extend_from_slice(&[0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
        frame.extend_from_slice(&ethertype.to_be_bytes());
        frame.extend_from_slice(payload);
        frame
    }

    #[test]
    fn packet_tap_registry_filters_by_protocol_and_interface_and_copies_bytes() {
        let registry = PacketTapRegistry::new();
        let ipv4_frame = sample_ethernet_frame(0x0800, b"dhcp");
        let arp_frame = sample_ethernet_frame(0x0806, b"arp");

        // Zero active taps -> fast path returns false without locking.
        assert!(!registry.tap_rx_frame(IFINDEX_ETH0, &ipv4_frame));

        let tap_all = registry.open(ETH_P_ALL).unwrap();
        let tap_ip = registry.open(0x0800).unwrap();
        let tap_tx_only = registry.open(0).unwrap();
        registry.bind(tap_ip, 0x0800, IFINDEX_ETH0).unwrap();

        assert!(registry.tap_rx_frame(IFINDEX_ETH0, &ipv4_frame));
        assert!(registry.tap_rx_frame(IFINDEX_ETH0, &arp_frame));
        assert!(registry.tap_rx_frame(IFINDEX_LO, &ipv4_frame));

        assert!(registry.readiness(tap_all).readable);
        assert!(registry.readiness(tap_ip).readable);
        assert!(!registry.readiness(tap_tx_only).readable);

        // tap_ip only saw the single IPv4 frame on eth0 (not ARP, not lo).
        let peeked = registry.pop_frame(tap_ip, 16, true).unwrap().unwrap();
        assert_eq!(peeked.ifindex, IFINDEX_ETH0);
        assert_eq!(peeked.protocol, 0x0800);
        assert_eq!(peeked.bytes.len(), 16);
        assert_eq!(peeked.original_len, ipv4_frame.len());

        let popped = registry.pop_frame(tap_ip, 256, false).unwrap().unwrap();
        assert_eq!(popped.bytes.as_ref(), ipv4_frame.as_slice());
        assert!(registry.pop_frame(tap_ip, 256, false).unwrap().is_none());

        // tap_all saw all 3 frames.
        assert!(registry.pop_frame(tap_all, 256, false).unwrap().is_some());
        assert!(registry.pop_frame(tap_all, 256, false).unwrap().is_some());
        assert!(registry.pop_frame(tap_all, 256, false).unwrap().is_some());
        assert!(registry.pop_frame(tap_all, 256, false).unwrap().is_none());

        registry.close(tap_all);
        registry.close(tap_ip);
        registry.close(tap_tx_only);
        assert!(!registry.tap_rx_frame(IFINDEX_ETH0, &ipv4_frame));
    }
}
