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
        if self.active_count.load(AtomicOrdering::Acquire) == 0 || frame.len() < ETH_HEADER_LEN {
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

    pub async fn packet_readiness(&self, socket: u64) -> Result<SocketReadiness, UdpError> {
        self.drive_udp().await?;
        Ok(self.inner.packet_taps.readiness(socket))
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

    #[cfg(feature = "linux")]
    #[test]
    fn linux_rtnetlink_ioctls_and_network_admin_share_one_network_service() {
        use core::future::Future;
        use core::num::NonZeroU32;
        use core::ops::ControlFlow;
        use core::task::{Context, Poll, Waker};
        use helios_hal::vmm::PageFlags;
        use helios_linux::abi::Abi;
        use helios_linux::syscall::{
            AF_NETLINK, Call, Clock, Credentials, Denied, Descriptors, IpAddr,
            Ipv4InterfaceAddress, Ipv4RouteEntry, MapError, MemoryFault, MemoryTotals,
            NETLINK_ROUTE, Network, Process, Region, Resources, SpawnError, SpawnedThread, Start,
            Stdio, Stream, SyscallOutcome, System, Thread, UserMemory, UtsField, VirtualMemory,
            WriteError, dispatch,
        };

        use crate::test_support::{
            ManualClockCpu, RecordingNetworkInterface, single_node_pool, test_profile_sink,
            test_root_entropy, test_timer, test_uptime_clock,
        };
        use crate::{Ipv4Address, Ipv4Cidr, Ipv4Route, NetworkAdminBackend, NetworkPortId};

        fn drive<F: Future>(future: F) -> F::Output {
            let waker = Waker::noop();
            let mut cx = Context::from_waker(waker);
            let mut future = core::pin::pin!(future);
            for _ in 0..128 {
                if let Poll::Ready(value) = future.as_mut().poll(&mut cx) {
                    return value;
                }
            }
            panic!("test future did not complete")
        }

        type TestService = NetworkService<ManualClockCpu, RecordingNetworkInterface>;

        struct KernelTestResources;
        impl Resources for KernelTestResources {
            type File = core::convert::Infallible;
            type Network = crate::UnixNetwork<TestService>;
            type Data = u64;
        }

        struct KernelTestPlatform {
            service: TestService,
        }

        impl Stdio for KernelTestPlatform {
            async fn write(&mut self, _: Stream, bytes: &[u8]) -> Result<usize, WriteError> {
                Ok(bytes.len())
            }
            async fn read_input(&mut self, _: usize) -> Result<Bytes, Denied> {
                Ok(Bytes::new())
            }
        }

        impl helios_linux::syscall::Filesystem<KernelTestResources> for KernelTestPlatform {}
        impl helios_linux::syscall::Tty for KernelTestPlatform {}

        impl Clock for KernelTestPlatform {
            fn now_nanos(&self) -> u64 {
                0
            }
            async fn sleep_until(&self, _: u64) {}
        }

        impl System for KernelTestPlatform {
            fn realtime_nanos(&self) -> u64 {
                0
            }
            fn set_realtime_nanos(&mut self, _: u64) -> Result<(), Denied> {
                Err(Denied)
            }
            fn cpu_nanos(&self) -> u64 {
                0
            }
            fn process_cpu_nanos(&self) -> u64 {
                0
            }
            fn processor_count(&self) -> u32 {
                1
            }
            fn fill_random(&mut self, out: &mut [u8]) {
                out.fill(0x5a);
            }
            fn memory(&self) -> MemoryTotals {
                MemoryTotals {
                    total_bytes: 1024 * 1024,
                    free_bytes: 512 * 1024,
                }
            }
            fn process_count(&self) -> u32 {
                1
            }
            fn kernel_version(&self) -> &str {
                "#1 Helios test"
            }
            fn hostname(&self) -> UtsField {
                UtsField::from_bytes(b"helios").unwrap()
            }
            fn domainname(&self) -> UtsField {
                UtsField::from_bytes(b"(none)").unwrap()
            }
            fn set_hostname(&mut self, _: UtsField) -> Result<(), Denied> {
                Err(Denied)
            }
            fn set_domainname(&mut self, _: UtsField) -> Result<(), Denied> {
                Err(Denied)
            }
        }

        impl Network<crate::UnixNetwork<TestService>> for KernelTestPlatform {
            fn to_ip(&self, address: crate::NetworkIpAddress) -> IpAddr {
                match address {
                    crate::NetworkIpAddress::Ipv4(ip) => IpAddr::V4(ip.octets()),
                    crate::NetworkIpAddress::Ipv6(ip) => IpAddr::V6(ip.octets()),
                }
            }

            fn encode_ip(&self, ip: IpAddr) -> crate::NetworkIpAddress {
                match ip {
                    IpAddr::V4(octets) => crate::NetworkIpAddress::Ipv4(Ipv4Address::new(octets)),
                    IpAddr::V6(octets) => {
                        crate::NetworkIpAddress::Ipv6(helios_netstack::Ipv6Address::new(octets))
                    }
                }
            }

            async fn interface_mac(&self) -> Result<[u8; 6], u64> {
                Ok(self
                    .service
                    .mac_address(NetworkPortId::new(0))
                    .await
                    .unwrap()
                    .octets())
            }

            async fn list_ipv4_addresses(&self) -> Result<Vec<Ipv4InterfaceAddress>, u64> {
                Ok(self
                    .service
                    .list_addresses(NetworkPortId::new(0))
                    .await
                    .unwrap()
                    .into_iter()
                    .map(|cidr| Ipv4InterfaceAddress {
                        address: cidr.address().octets(),
                        prefix: cidr.prefix_len(),
                    })
                    .collect())
            }

            async fn add_ipv4_address(&self, address: Ipv4InterfaceAddress) -> Result<(), u64> {
                self.service
                    .add_address(
                        NetworkPortId::new(0),
                        Ipv4Cidr::new(Ipv4Address::new(address.address), address.prefix),
                    )
                    .await
                    .map_err(|_| 22u64)
            }

            async fn remove_ipv4_address(&self, address: Ipv4InterfaceAddress) -> Result<(), u64> {
                self.service
                    .remove_address(
                        NetworkPortId::new(0),
                        Ipv4Cidr::new(Ipv4Address::new(address.address), address.prefix),
                    )
                    .await
                    .map_err(|_| 22u64)
            }

            async fn list_ipv4_routes(&self) -> Result<Vec<Ipv4RouteEntry>, u64> {
                Ok(self
                    .service
                    .list_routes(NetworkPortId::new(0))
                    .await
                    .unwrap()
                    .into_iter()
                    .map(|route| {
                        let gw = route.gateway().octets();
                        Ipv4RouteEntry {
                            destination: route.destination().address().octets(),
                            prefix: route.destination().prefix_len(),
                            gateway: if gw == [0, 0, 0, 0] { None } else { Some(gw) },
                        }
                    })
                    .collect())
            }

            async fn add_ipv4_route(&self, route: Ipv4RouteEntry) -> Result<(), u64> {
                self.service
                    .add_route(
                        NetworkPortId::new(0),
                        Ipv4Route::new(
                            Ipv4Cidr::new(Ipv4Address::new(route.destination), route.prefix),
                            Ipv4Address::new(route.gateway.unwrap_or([0, 0, 0, 0])),
                        ),
                    )
                    .await
                    .map_err(|_| 22u64)
            }

            async fn remove_ipv4_route(&self, route: Ipv4RouteEntry) -> Result<(), u64> {
                self.service
                    .remove_route(
                        NetworkPortId::new(0),
                        Ipv4Route::new(
                            Ipv4Cidr::new(Ipv4Address::new(route.destination), route.prefix),
                            Ipv4Address::new(route.gateway.unwrap_or([0, 0, 0, 0])),
                        ),
                    )
                    .await
                    .map_err(|_| 22u64)
            }

            fn check_net_admin(&self) -> Result<(), u64> {
                Ok(())
            }
        }

        struct FlatMemory(Vec<u8>);
        impl FlatMemory {
            fn read(&self, address: u64, into: &mut [u8]) -> Result<(), MemoryFault> {
                let start = usize::try_from(address).map_err(|_| MemoryFault)?;
                let end = start.checked_add(into.len()).ok_or(MemoryFault)?;
                into.copy_from_slice(self.0.get(start..end).ok_or(MemoryFault)?);
                Ok(())
            }
            fn check_writable(&self, address: u64, length: usize) -> Result<(), MemoryFault> {
                let start = usize::try_from(address).map_err(|_| MemoryFault)?;
                let end = start.checked_add(length).ok_or(MemoryFault)?;
                if end <= self.0.len() {
                    Ok(())
                } else {
                    Err(MemoryFault)
                }
            }
            fn write(&mut self, address: u64, from: &[u8]) -> Result<(), MemoryFault> {
                let start = usize::try_from(address).map_err(|_| MemoryFault)?;
                let end = start.checked_add(from.len()).ok_or(MemoryFault)?;
                self.0
                    .get_mut(start..end)
                    .ok_or(MemoryFault)?
                    .copy_from_slice(from);
                Ok(())
            }
        }
        impl UserMemory for FlatMemory {
            async fn read(&self, address: u64, into: &mut [u8]) -> Result<(), MemoryFault> {
                Self::read(self, address, into)
            }
            async fn check_writable(&self, address: u64, length: usize) -> Result<(), MemoryFault> {
                Self::check_writable(self, address, length)
            }
            async fn write(&mut self, address: u64, from: &[u8]) -> Result<(), MemoryFault> {
                Self::write(self, address, from)
            }
            async fn atomic_load_u32(&self, address: u64) -> Result<u32, MemoryFault> {
                self.try_atomic_load_u32(address)?.ok_or(MemoryFault)
            }
            fn try_atomic_load_u32(&self, address: u64) -> Result<Option<u32>, MemoryFault> {
                let mut raw = [0; 4];
                Self::read(self, address, &mut raw)?;
                Ok(Some(u32::from_le_bytes(raw)))
            }
            async fn atomic_store_u32(
                &mut self,
                address: u64,
                value: u32,
            ) -> Result<(), MemoryFault> {
                Self::write(self, address, &value.to_le_bytes())
            }
            async fn atomic_compare_exchange_u32(
                &mut self,
                address: u64,
                expected: u32,
                desired: u32,
            ) -> Result<Result<u32, u32>, MemoryFault> {
                let cur = self.atomic_load_u32(address).await?;
                if cur == expected {
                    self.atomic_store_u32(address, desired).await?;
                    Ok(Ok(cur))
                } else {
                    Ok(Err(cur))
                }
            }
        }
        impl VirtualMemory for FlatMemory {
            fn lowest_address(&self) -> u64 {
                0x1000
            }
            fn map_anywhere(&mut self, _: u64, _: u64, _: PageFlags) -> Result<u64, MapError> {
                Err(MapError::OutOfMemory)
            }
            fn map_at(&mut self, _: u64, _: u64, _: PageFlags) -> Result<(), MapError> {
                Err(MapError::OutOfMemory)
            }
            fn unmap(&mut self, _: u64, _: u64) {}
            fn protect(&mut self, _: u64, _: u64, _: PageFlags) -> Result<(), MapError> {
                Ok(())
            }
            fn discard(&mut self, _: u64, _: u64) {}
            fn remap(&mut self, _: u64, _: u64, _: u64, _: u64) -> Result<(), MapError> {
                Err(MapError::OutOfMemory)
            }
            fn region(&self, _: u64, _: u64) -> Option<Region> {
                None
            }
            fn free_range(&self, _: u64, _: u64) -> Option<u64> {
                None
            }
        }

        struct NoThread;
        impl Thread<KernelTestResources> for NoThread {
            fn thread_pointer(&self) -> u64 {
                0
            }
            fn set_thread_pointer(&mut self, _: u64) -> Result<(), Denied> {
                Ok(())
            }
            fn stack_pointer(&self) -> u64 {
                0
            }
            fn spawn_thread(
                &mut self,
                _: Process<KernelTestResources>,
                _: SpawnedThread,
            ) -> Result<(), SpawnError> {
                Err(SpawnError::Busy)
            }
        }

        let device = RecordingNetworkInterface::new(1);
        let clock = ManualClockCpu::new();
        let service = NetworkService::new(
            clock.clone(),
            single_node_pool(1),
            test_profile_sink(),
            test_uptime_clock(),
            test_timer(clock),
            device.clone(),
            test_root_entropy(),
        );
        let mut platform = KernelTestPlatform {
            service: service.clone(),
        };
        let mut mem = FlatMemory(alloc::vec![0u8; 32 * 1024]);
        let start = Start {
            credentials: Credentials::root(),
            ..Start::default()
        };
        let mut process = Process::with_descriptors(
            Abi::X86_64,
            NonZeroU32::new(1).unwrap(),
            0x10_0000,
            Descriptors::<KernelTestResources>::new(),
            start,
        );

        let mut run_call = |mem: &mut FlatMemory, number: u64, arguments: [u64; 6]| -> i64 {
            let mut thread = NoThread;
            match drive(dispatch(
                &mut process,
                Call { number, arguments },
                mem,
                &mut thread,
                &mut platform,
            )) {
                ControlFlow::Continue(SyscallOutcome::Return(v)) => v as i64,
                other => panic!("unexpected outcome: {other:?}"),
            }
        };

        // Open NETLINK_ROUTE socket (SYS_SOCKET = 41, SOCK_RAW = 3).
        let fd = run_call(
            &mut mem,
            41,
            [AF_NETLINK as u64, 3, NETLINK_ROUTE as u64, 0, 0, 0],
        ) as u64;

        // 1. Linux RTM_NEWADDR adds 10.42.0.9/24 on eth0 (index 2).
        let mut nl_addr = Vec::new();
        let body_len = 8 + 8; // ifaddrmsg (8) + IFA_LOCAL rta (8)
        nl_addr.extend_from_slice(&((16 + body_len) as u32).to_ne_bytes());
        nl_addr.extend_from_slice(&20u16.to_ne_bytes()); // RTM_NEWADDR
        nl_addr.extend_from_slice(&0x0005u16.to_ne_bytes()); // NLM_F_REQUEST | NLM_F_ACK
        nl_addr.extend_from_slice(&1u32.to_ne_bytes());
        nl_addr.extend_from_slice(&0u32.to_ne_bytes());
        nl_addr.extend_from_slice(&[2, 24, 0, 0]); // AF_INET, /24
        nl_addr.extend_from_slice(&2u32.to_ne_bytes()); // ifindex 2
        nl_addr.extend_from_slice(&8u16.to_ne_bytes()); // rta_len = 8
        nl_addr.extend_from_slice(&2u16.to_ne_bytes()); // IFA_LOCAL
        nl_addr.extend_from_slice(&[10, 42, 0, 9]);
        mem.write(0x1000, &nl_addr).unwrap();
        assert_eq!(
            run_call(&mut mem, 44, [fd, 0x1000, nl_addr.len() as u64, 0, 0, 0]),
            nl_addr.len() as i64
        );
        assert!(run_call(&mut mem, 45, [fd, 0x2000, 256, 0, 0, 0]) >= 20);

        // 2. Linux RTM_NEWROUTE adds default route via 10.42.0.1.
        let mut nl_rt = Vec::new();
        let rt_body_len = 12 + 8 + 8; // rtmsg (12) + RTA_GATEWAY (8) + RTA_OIF (8)
        nl_rt.extend_from_slice(&((16 + rt_body_len) as u32).to_ne_bytes());
        nl_rt.extend_from_slice(&24u16.to_ne_bytes()); // RTM_NEWROUTE
        nl_rt.extend_from_slice(&0x0005u16.to_ne_bytes());
        nl_rt.extend_from_slice(&2u32.to_ne_bytes());
        nl_rt.extend_from_slice(&0u32.to_ne_bytes());
        nl_rt.extend_from_slice(&[2, 0, 0, 0, 254, 3, 0, 1, 0, 0, 0, 0]);
        nl_rt.extend_from_slice(&8u16.to_ne_bytes());
        nl_rt.extend_from_slice(&5u16.to_ne_bytes()); // RTA_GATEWAY
        nl_rt.extend_from_slice(&[10, 42, 0, 1]);
        nl_rt.extend_from_slice(&8u16.to_ne_bytes());
        nl_rt.extend_from_slice(&4u16.to_ne_bytes()); // RTA_OIF
        nl_rt.extend_from_slice(&2u32.to_ne_bytes());
        mem.write(0x1000, &nl_rt).unwrap();
        assert_eq!(
            run_call(&mut mem, 44, [fd, 0x1000, nl_rt.len() as u64, 0, 0, 0]),
            nl_rt.len() as i64
        );
        assert!(run_call(&mut mem, 45, [fd, 0x2000, 256, 0, 0, 0]) >= 20);

        // 3. Verify the shared NetworkAdminBackend sees both mutations on the same NetworkService.
        let admin_addrs = drive(service.list_addresses(NetworkPortId::new(0))).unwrap();
        assert!(admin_addrs.contains(&Ipv4Cidr::new(Ipv4Address::new([10, 42, 0, 9]), 24)));
        let admin_routes = drive(service.list_routes(NetworkPortId::new(0))).unwrap();
        assert!(admin_routes.iter().any(|r| {
            r.destination() == Ipv4Cidr::new(Ipv4Address::new([0, 0, 0, 0]), 0)
                && r.gateway() == Ipv4Address::new([10, 42, 0, 1])
        }));

        // 4. Reverse direction: NetworkAdminBackend::add_address is immediately visible to Linux RTM_GETADDR.
        drive(service.add_address(
            NetworkPortId::new(0),
            Ipv4Cidr::new(Ipv4Address::new([192, 168, 77, 5]), 24),
        ))
        .unwrap();
        let mut get_addr = Vec::new();
        get_addr.extend_from_slice(&24u32.to_ne_bytes());
        get_addr.extend_from_slice(&22u16.to_ne_bytes()); // RTM_GETADDR
        get_addr.extend_from_slice(&0x0301u16.to_ne_bytes()); // NLM_F_REQUEST | NLM_F_DUMP
        get_addr.extend_from_slice(&3u32.to_ne_bytes());
        get_addr.extend_from_slice(&0u32.to_ne_bytes());
        get_addr.extend_from_slice(&[2, 0, 0, 0, 0, 0, 0, 0]);
        mem.write(0x1000, &get_addr).unwrap();
        assert_eq!(
            run_call(&mut mem, 44, [fd, 0x1000, get_addr.len() as u64, 0, 0, 0]),
            get_addr.len() as i64
        );
        let got = run_call(&mut mem, 45, [fd, 0x2000, 4096, 0, 0, 0]) as usize;
        let mut dump = alloc::vec![0u8; got];
        mem.read(0x2000, &mut dump).unwrap();
        assert!(dump.windows(4).any(|w| w == [192, 168, 77, 5]));

        // 5. packet_readiness drives the device RX ring and surfaces incoming frames.
        let tap = service.packet_open(ETH_P_ALL).unwrap();
        assert!(!drive(service.packet_readiness(tap)).unwrap().readable);
        device.deliver_on(0, &sample_ethernet_frame(0x0800, b"dhcp-offer"));
        assert!(drive(service.packet_readiness(tap)).unwrap().readable);
        service.packet_close(tap);
    }
}
