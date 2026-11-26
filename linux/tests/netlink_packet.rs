#![cfg(feature = "runtime")]

use bytes::Bytes;
use core::future::Future;
use core::num::NonZeroU32;
use core::ops::ControlFlow;
use core::task::{Context, Poll, Waker};
use helios_hal::vmm::PageFlags;
use helios_linux::abi::Abi;
use helios_linux::syscall::{
    AF_NETLINK, AF_PACKET, CAP_NET_ADMIN, CAP_NET_RAW, Call, Clock, Credentials, Denied,
    Descriptors, IpAddr, Ipv4InterfaceAddress, Ipv4RouteEntry, LinuxCapabilities, MapError,
    MemoryFault, MemoryTotals, NETLINK_ROUTE, Network, PacketFrameData, Process, Region, Resources,
    SocketReady, SpawnError, SpawnedThread, Start, Stdio, Stream, SyscallOutcome, System, Thread,
    UserMemory, UtsField, VirtualMemory, WriteError, dispatch,
};
use helios_unix::{OwnedPacketSocket, SocketLimits, SocketNetwork};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

const SOCK_DGRAM: u64 = 2;
const SOCK_RAW: u64 = 3;
const MSG_PEEK: u64 = 0x02;
const MSG_TRUNC: u64 = 0x20;
const MSG_DONTWAIT: u64 = 0x40;

const AF_INET: u16 = 2;
const ETH_P_ALL: u16 = 0x0003;
const ETH_P_IP: u16 = 0x0800;

const NLM_F_REQUEST: u16 = 0x0001;
const NLM_F_ACK: u16 = 0x0004;
const NLM_F_DUMP: u16 = 0x0300;

const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const RTM_NEWLINK: u16 = 16;
const RTM_GETLINK: u16 = 18;
const RTM_SETLINK: u16 = 19;
const RTM_NEWADDR: u16 = 20;
const RTM_DELADDR: u16 = 21;
const RTM_NEWROUTE: u16 = 24;
const RTM_GETROUTE: u16 = 26;

const SIOCADDRT: u64 = 0x890B;
const SIOCDELRT: u64 = 0x890C;
const SIOCGIFNAME: u64 = 0x8910;
const SIOCGIFCONF: u64 = 0x8912;
const SIOCGIFFLAGS: u64 = 0x8913;
const SIOCSIFFLAGS: u64 = 0x8914;
const SIOCGIFADDR: u64 = 0x8915;
const SIOCSIFADDR: u64 = 0x8916;
const SIOCGIFBRDADDR: u64 = 0x8919;
const SIOCGIFNETMASK: u64 = 0x891B;
const SIOCSIFNETMASK: u64 = 0x891C;
const SIOCGIFMTU: u64 = 0x8921;
const SIOCSIFMTU: u64 = 0x8922;
const SIOCGIFHWADDR: u64 = 0x8927;
const SIOCGIFINDEX: u64 = 0x8933;

const SYS_IOCTL: u64 = 16;
const SYS_SOCKET: u64 = 41;
const SYS_SENDTO: u64 = 44;
const SYS_RECVFROM: u64 = 45;
const SYS_RECVMSG: u64 = 47;
const SYS_BIND: u64 = 49;
const SYS_GETSOCKNAME: u64 = 51;
const SYS_SETSOCKOPT: u64 = 54;
const SYS_GETSOCKOPT: u64 = 55;
const SYS_EPOLL_CTL: u64 = 233;
const SYS_EPOLL_CREATE1: u64 = 291;
const SYS_EPOLL_PWAIT: u64 = 281;

const EPERM: u64 = 1;
const EAGAIN: u64 = 11;
const ENODEV: u64 = 19;
const EOPNOTSUPP: u64 = 95;
const ETIMEDOUT: u64 = 110;

fn drive<F: Future>(future: F) -> F::Output {
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    let mut future = core::pin::pin!(future);
    for _ in 0..64 {
        if let Poll::Ready(value) = future.as_mut().poll(&mut cx) {
            return value;
        }
    }
    panic!("test future did not complete")
}

#[derive(Clone, Default)]
struct MockNet;

impl SocketNetwork for MockNet {
    type TcpStream = u64;
    type TcpListener = u64;
    type UdpSocket = u64;
    type PacketSocket = u64;
    type Address = IpAddr;
    const LIMITS: SocketLimits = SocketLimits {
        receive_buffer_bytes: 256 * 1024,
        send_buffer_bytes: 256 * 1024,
        default_hop_limit: 64,
    };
    fn tcp_close(&self, _: u64) {}
    fn tcp_listener_close(&self, _: u64) {}
    fn udp_close(&self, _: u64) {}
    fn packet_close(&self, _: u64) {}
}

struct MockResources;
impl Resources for MockResources {
    type File = core::convert::Infallible;
    type Network = MockNet;
    type Data = u64;
}

#[derive(Default)]
struct MockNetState {
    mac: [u8; 6],
    addresses: Vec<Ipv4InterfaceAddress>,
    routes: Vec<Ipv4RouteEntry>,
    container_admin: bool,
    sent_frames: Vec<(u32, Vec<u8>)>,
    rx_frames: VecDeque<PacketFrameData>,
    bound_packet: Option<(u16, u32)>,
}

struct MockPlatform {
    state: Arc<Mutex<MockNetState>>,
}

impl MockPlatform {
    fn new(container_admin: bool) -> Self {
        Self {
            state: Arc::new(Mutex::new(MockNetState {
                mac: [0x52, 0x54, 0x00, 0x12, 0x34, 0x56],
                addresses: vec![Ipv4InterfaceAddress {
                    address: [10, 0, 2, 15],
                    prefix: 24,
                }],
                routes: vec![
                    Ipv4RouteEntry {
                        destination: [10, 0, 2, 0],
                        prefix: 24,
                        gateway: None,
                    },
                    Ipv4RouteEntry {
                        destination: [0, 0, 0, 0],
                        prefix: 0,
                        gateway: Some([10, 0, 2, 2]),
                    },
                ],
                container_admin,
                ..Default::default()
            })),
        }
    }
}

impl Stdio for MockPlatform {
    async fn write(&mut self, _: Stream, bytes: &[u8]) -> Result<usize, WriteError> {
        Ok(bytes.len())
    }
    async fn read_input(&mut self, _: usize) -> Result<Bytes, Denied> {
        Ok(Bytes::new())
    }
}

impl helios_linux::syscall::Filesystem<MockResources> for MockPlatform {}
impl helios_linux::syscall::Tty for MockPlatform {}

impl Clock for MockPlatform {
    fn now_nanos(&self) -> u64 {
        0
    }
    async fn sleep_until(&self, _: u64) {}
}

impl System for MockPlatform {
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

impl Network<MockNet> for MockPlatform {
    fn to_ip(&self, address: IpAddr) -> IpAddr {
        address
    }

    fn encode_ip(&self, ip: IpAddr) -> IpAddr {
        ip
    }

    async fn interface_mac(&self) -> Result<[u8; 6], u64> {
        Ok(self.state.lock().unwrap().mac)
    }

    async fn list_ipv4_addresses(&self) -> Result<Vec<Ipv4InterfaceAddress>, u64> {
        Ok(self.state.lock().unwrap().addresses.clone())
    }

    async fn add_ipv4_address(&self, address: Ipv4InterfaceAddress) -> Result<(), u64> {
        let mut st = self.state.lock().unwrap();
        if !st.container_admin {
            return Err(EPERM);
        }
        if !st.addresses.contains(&address) {
            st.addresses.push(address);
        }
        Ok(())
    }

    async fn remove_ipv4_address(&self, address: Ipv4InterfaceAddress) -> Result<(), u64> {
        let mut st = self.state.lock().unwrap();
        if !st.container_admin {
            return Err(EPERM);
        }
        st.addresses.retain(|a| a != &address);
        Ok(())
    }

    async fn list_ipv4_routes(&self) -> Result<Vec<Ipv4RouteEntry>, u64> {
        Ok(self.state.lock().unwrap().routes.clone())
    }

    async fn add_ipv4_route(&self, route: Ipv4RouteEntry) -> Result<(), u64> {
        let mut st = self.state.lock().unwrap();
        if !st.container_admin {
            return Err(EPERM);
        }
        if !st.routes.contains(&route) {
            st.routes.push(route);
        }
        Ok(())
    }

    async fn remove_ipv4_route(&self, route: Ipv4RouteEntry) -> Result<(), u64> {
        let mut st = self.state.lock().unwrap();
        if !st.container_admin {
            return Err(EPERM);
        }
        st.routes.retain(|r| r != &route);
        Ok(())
    }

    fn check_net_admin(&self) -> Result<(), u64> {
        if self.state.lock().unwrap().container_admin {
            Ok(())
        } else {
            Err(EPERM)
        }
    }

    fn packet_open(&self, protocol: u16) -> Result<Arc<OwnedPacketSocket<MockNet>>, u64> {
        self.check_net_admin()?;
        self.state.lock().unwrap().bound_packet = Some((protocol, 0));
        Ok(OwnedPacketSocket::new(MockNet, 1))
    }

    fn packet_bind(&self, _socket: u64, protocol: u16, ifindex: u32) -> Result<(), u64> {
        self.state.lock().unwrap().bound_packet = Some((protocol, ifindex));
        Ok(())
    }

    async fn packet_send<'a>(
        &'a self,
        _socket: u64,
        ifindex: u32,
        frame: &'a [u8],
    ) -> Result<usize, u64> {
        let mut st = self.state.lock().unwrap();
        st.sent_frames.push((ifindex, frame.to_vec()));
        let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
        st.rx_frames.push_back(PacketFrameData {
            ifindex,
            protocol: ethertype,
            bytes: Bytes::copy_from_slice(frame),
            original_len: frame.len(),
        });
        Ok(frame.len())
    }

    async fn packet_receive(
        &self,
        _socket: u64,
        max_bytes: u32,
        timeout_nanos: u64,
        peek: bool,
    ) -> Result<Option<PacketFrameData>, u64> {
        let mut st = self.state.lock().unwrap();
        let frame = if peek {
            st.rx_frames.front().cloned()
        } else {
            st.rx_frames.pop_front()
        };
        match frame {
            Some(mut f) => {
                let max = max_bytes as usize;
                if f.bytes.len() > max {
                    f.bytes = f.bytes.slice(..max);
                }
                Ok(Some(f))
            }
            None if timeout_nanos > 0 => Err(ETIMEDOUT),
            None => Ok(None),
        }
    }

    async fn packet_readiness(&self, _socket: u64) -> Result<SocketReady, u64> {
        let st = self.state.lock().unwrap();
        Ok(SocketReady {
            readable: !st.rx_frames.is_empty(),
            writable: true,
            hangup: false,
        })
    }
}

struct FlatMemory {
    bytes: Vec<u8>,
}

impl FlatMemory {
    fn new(size: usize) -> Self {
        Self {
            bytes: vec![0u8; size],
        }
    }

    fn read(&self, address: u64, into: &mut [u8]) -> Result<(), MemoryFault> {
        let start = usize::try_from(address).map_err(|_| MemoryFault)?;
        let end = start.checked_add(into.len()).ok_or(MemoryFault)?;
        let slice = self.bytes.get(start..end).ok_or(MemoryFault)?;
        into.copy_from_slice(slice);
        Ok(())
    }

    fn check_writable(&self, address: u64, length: usize) -> Result<(), MemoryFault> {
        let start = usize::try_from(address).map_err(|_| MemoryFault)?;
        let end = start.checked_add(length).ok_or(MemoryFault)?;
        if end <= self.bytes.len() {
            Ok(())
        } else {
            Err(MemoryFault)
        }
    }

    fn write(&mut self, address: u64, from: &[u8]) -> Result<(), MemoryFault> {
        let start = usize::try_from(address).map_err(|_| MemoryFault)?;
        let end = start.checked_add(from.len()).ok_or(MemoryFault)?;
        let slice = self.bytes.get_mut(start..end).ok_or(MemoryFault)?;
        slice.copy_from_slice(from);
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

    async fn atomic_store_u32(&mut self, address: u64, value: u32) -> Result<(), MemoryFault> {
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

struct DummyThread;
impl Thread<MockResources> for DummyThread {
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
        _: Process<MockResources>,
        _: SpawnedThread,
    ) -> Result<(), SpawnError> {
        Err(SpawnError::Busy)
    }
}

fn new_process(creds: Credentials) -> Process<MockResources> {
    let start = Start {
        credentials: creds,
        ..Start::default()
    };
    Process::with_descriptors(
        Abi::X86_64,
        NonZeroU32::new(1).unwrap(),
        0x10_0000,
        Descriptors::<MockResources>::new(),
        start,
    )
}

fn creds_without(cap: u32) -> Credentials {
    let mut creds = Credentials::root();
    let mask = !(1u64 << cap);
    creds.capabilities = LinuxCapabilities {
        effective: creds.capabilities.effective & mask,
        permitted: creds.capabilities.permitted & mask,
        inheritable: creds.capabilities.inheritable & mask,
        bounding: creds.capabilities.bounding & mask,
        ambient: creds.capabilities.ambient & mask,
    };
    creds
}

fn call(
    process: &mut Process<MockResources>,
    memory: &mut FlatMemory,
    platform: &mut MockPlatform,
    number: u64,
    arguments: [u64; 6],
) -> i64 {
    let mut thread = DummyThread;
    match drive(dispatch(
        process,
        Call { number, arguments },
        memory,
        &mut thread,
        platform,
    )) {
        ControlFlow::Continue(SyscallOutcome::Return(val)) => val as i64,
        other => panic!("unexpected syscall outcome: {other:?}"),
    }
}

fn build_nlmsg(kind: u16, flags: u16, seq: u32, body: &[u8]) -> Vec<u8> {
    let total = 16 + body.len();
    let mut buf = Vec::with_capacity((total + 3) & !3);
    buf.extend_from_slice(&(total as u32).to_ne_bytes());
    buf.extend_from_slice(&kind.to_ne_bytes());
    buf.extend_from_slice(&flags.to_ne_bytes());
    buf.extend_from_slice(&seq.to_ne_bytes());
    buf.extend_from_slice(&0u32.to_ne_bytes());
    buf.extend_from_slice(body);
    while buf.len() % 4 != 0 {
        buf.push(0);
    }
    buf
}

fn append_rta(buf: &mut Vec<u8>, kind: u16, val: &[u8]) {
    let start = buf.len();
    let len = (4 + val.len()) as u16;
    buf.extend_from_slice(&len.to_ne_bytes());
    buf.extend_from_slice(&kind.to_ne_bytes());
    buf.extend_from_slice(val);
    let padded = ((buf.len() - start) + 3) & !3;
    buf.resize(start + padded, 0);
}

fn nlmsg_error_code(reply: &[u8]) -> i32 {
    assert!(reply.len() >= 20);
    let kind = u16::from_ne_bytes([reply[4], reply[5]]);
    assert_eq!(kind, NLMSG_ERROR);
    i32::from_ne_bytes([reply[16], reply[17], reply[18], reply[19]])
}

#[test]
fn rtnetlink_link_addr_route_roundtrip_and_authority() {
    let mut process = new_process(Credentials::root());
    let mut mem = FlatMemory::new(64 * 1024);
    let mut plat = MockPlatform::new(true);

    let fd = call(
        &mut process,
        &mut mem,
        &mut plat,
        SYS_SOCKET,
        [AF_NETLINK as u64, SOCK_RAW, NETLINK_ROUTE as u64, 0, 0, 0],
    );
    assert!(fd >= 0);
    let fd = fd as u64;

    // bind with nl_pid = 0 assigns the process PID.
    let mut nl_addr = [0u8; 12];
    nl_addr[0..2].copy_from_slice(&AF_NETLINK.to_ne_bytes());
    mem.write(0x100, &nl_addr).unwrap();
    assert_eq!(
        call(
            &mut process,
            &mut mem,
            &mut plat,
            SYS_BIND,
            [fd, 0x100, 12, 0, 0, 0]
        ),
        0
    );
    mem.write(0x120, &12u32.to_ne_bytes()).unwrap();
    assert_eq!(
        call(
            &mut process,
            &mut mem,
            &mut plat,
            SYS_GETSOCKNAME,
            [fd, 0x110, 0x120, 0, 0, 0]
        ),
        0
    );
    let mut bound_nl = [0u8; 12];
    mem.read(0x110, &mut bound_nl).unwrap();
    assert_eq!(u16::from_ne_bytes([bound_nl[0], bound_nl[1]]), AF_NETLINK);
    assert_ne!(
        u32::from_ne_bytes([bound_nl[4], bound_nl[5], bound_nl[6], bound_nl[7]]),
        0
    );

    // 1. RTM_GETLINK dump -> lo + eth0 + NLMSG_DONE, verified with MSG_PEEK | MSG_TRUNC.
    let req = build_nlmsg(RTM_GETLINK, NLM_F_REQUEST | NLM_F_DUMP, 1, &[0u8; 16]);
    mem.write(0x1000, &req).unwrap();
    assert_eq!(
        call(
            &mut process,
            &mut mem,
            &mut plat,
            SYS_SENDTO,
            [fd, 0x1000, req.len() as u64, 0, 0, 0]
        ),
        req.len() as i64
    );
    let peek_len = call(
        &mut process,
        &mut mem,
        &mut plat,
        SYS_RECVFROM,
        [fd, 0x2000, 0, MSG_PEEK | MSG_TRUNC, 0, 0],
    );
    assert!(peek_len > 32);
    let got = call(
        &mut process,
        &mut mem,
        &mut plat,
        SYS_RECVFROM,
        [fd, 0x2000, 4096, 0, 0, 0],
    );
    assert_eq!(got, peek_len);
    let mut reply = vec![0u8; got as usize];
    mem.read(0x2000, &mut reply).unwrap();
    let mut kinds = Vec::new();
    let mut off = 0usize;
    while off + 16 <= reply.len() {
        let len = u32::from_ne_bytes(reply[off..off + 4].try_into().unwrap()) as usize;
        let kind = u16::from_ne_bytes(reply[off + 4..off + 6].try_into().unwrap());
        kinds.push(kind);
        off += (len + 3) & !3;
    }
    assert_eq!(kinds, vec![RTM_NEWLINK, RTM_NEWLINK, NLMSG_DONE]);

    // 2. RTM_NEWADDR adds 10.0.2.20/24 on eth0 (index 2).
    let mut body = vec![AF_INET as u8, 24, 0, 0];
    body.extend_from_slice(&2u32.to_ne_bytes());
    append_rta(&mut body, 2, &[10, 0, 2, 20]); // IFA_LOCAL
    let req = build_nlmsg(RTM_NEWADDR, NLM_F_REQUEST | NLM_F_ACK, 2, &body);
    mem.write(0x1000, &req).unwrap();
    call(
        &mut process,
        &mut mem,
        &mut plat,
        SYS_SENDTO,
        [fd, 0x1000, req.len() as u64, 0, 0, 0],
    );
    let got = call(
        &mut process,
        &mut mem,
        &mut plat,
        SYS_RECVFROM,
        [fd, 0x2000, 4096, 0, 0, 0],
    );
    let mut ack = vec![0u8; got as usize];
    mem.read(0x2000, &mut ack).unwrap();
    assert_eq!(nlmsg_error_code(&ack), 0);
    assert!(
        plat.state
            .lock()
            .unwrap()
            .addresses
            .contains(&Ipv4InterfaceAddress {
                address: [10, 0, 2, 20],
                prefix: 24,
            })
    );

    // 3. RTM_DELADDR removes 10.0.2.20/24.
    let req = build_nlmsg(RTM_DELADDR, NLM_F_REQUEST | NLM_F_ACK, 3, &body);
    mem.write(0x1000, &req).unwrap();
    call(
        &mut process,
        &mut mem,
        &mut plat,
        SYS_SENDTO,
        [fd, 0x1000, req.len() as u64, 0, 0, 0],
    );
    let got = call(
        &mut process,
        &mut mem,
        &mut plat,
        SYS_RECVFROM,
        [fd, 0x2000, 4096, 0, 0, 0],
    );
    let mut ack = vec![0u8; got as usize];
    mem.read(0x2000, &mut ack).unwrap();
    assert_eq!(nlmsg_error_code(&ack), 0);
    assert!(
        !plat
            .state
            .lock()
            .unwrap()
            .addresses
            .contains(&Ipv4InterfaceAddress {
                address: [10, 0, 2, 20],
                prefix: 24,
            })
    );

    // 4. RTM_NEWROUTE + RTM_GETROUTE.
    let mut rt_body = vec![AF_INET as u8, 24, 0, 0, 254, 3, 0, 1, 0, 0, 0, 0];
    append_rta(&mut rt_body, 1, &[192, 168, 50, 0]); // RTA_DST
    append_rta(&mut rt_body, 5, &[10, 0, 2, 2]); // RTA_GATEWAY
    append_rta(&mut rt_body, 4, &2u32.to_ne_bytes()); // RTA_OIF
    let req = build_nlmsg(RTM_NEWROUTE, NLM_F_REQUEST | NLM_F_ACK, 4, &rt_body);
    mem.write(0x1000, &req).unwrap();
    call(
        &mut process,
        &mut mem,
        &mut plat,
        SYS_SENDTO,
        [fd, 0x1000, req.len() as u64, 0, 0, 0],
    );
    let got = call(
        &mut process,
        &mut mem,
        &mut plat,
        SYS_RECVFROM,
        [fd, 0x2000, 4096, 0, 0, 0],
    );
    let mut ack = vec![0u8; got as usize];
    mem.read(0x2000, &mut ack).unwrap();
    assert_eq!(nlmsg_error_code(&ack), 0);
    assert!(plat.state.lock().unwrap().routes.contains(&Ipv4RouteEntry {
        destination: [192, 168, 50, 0],
        prefix: 24,
        gateway: Some([10, 0, 2, 2]),
    }));

    // Dump routes and verify 3 RTM_NEWROUTE + NLMSG_DONE.
    let req = build_nlmsg(
        RTM_GETROUTE,
        NLM_F_REQUEST | NLM_F_DUMP,
        5,
        &[AF_INET as u8; 12],
    );
    mem.write(0x1000, &req).unwrap();
    call(
        &mut process,
        &mut mem,
        &mut plat,
        SYS_SENDTO,
        [fd, 0x1000, req.len() as u64, 0, 0, 0],
    );
    let got = call(
        &mut process,
        &mut mem,
        &mut plat,
        SYS_RECVFROM,
        [fd, 0x2000, 4096, 0, 0, 0],
    );
    let mut dump = vec![0u8; got as usize];
    mem.read(0x2000, &mut dump).unwrap();
    let mut r_kinds = Vec::new();
    let mut off = 0usize;
    while off + 16 <= dump.len() {
        let len = u32::from_ne_bytes(dump[off..off + 4].try_into().unwrap()) as usize;
        r_kinds.push(u16::from_ne_bytes(
            dump[off + 4..off + 6].try_into().unwrap(),
        ));
        off += (len + 3) & !3;
    }
    assert_eq!(
        r_kinds,
        vec![RTM_NEWROUTE, RTM_NEWROUTE, RTM_NEWROUTE, NLMSG_DONE]
    );

    // 5. Authority check: container without NetworkAdminCap denies RTM_NEWADDR even for uid 0.
    plat.state.lock().unwrap().container_admin = false;
    let req = build_nlmsg(RTM_NEWADDR, NLM_F_REQUEST | NLM_F_ACK, 6, &body);
    mem.write(0x1000, &req).unwrap();
    call(
        &mut process,
        &mut mem,
        &mut plat,
        SYS_SENDTO,
        [fd, 0x1000, req.len() as u64, 0, 0, 0],
    );
    let got = call(
        &mut process,
        &mut mem,
        &mut plat,
        SYS_RECVFROM,
        [fd, 0x2000, 4096, 0, 0, 0],
    );
    let mut ack = vec![0u8; got as usize];
    mem.read(0x2000, &mut ack).unwrap();
    assert_eq!(nlmsg_error_code(&ack), -(EPERM as i32));

    // 6. Authority check: process without CAP_NET_ADMIN is denied RTM_SETLINK even with container admin.
    plat.state.lock().unwrap().container_admin = true;
    let mut unpriv = new_process(creds_without(CAP_NET_ADMIN));
    let ufd = call(
        &mut unpriv,
        &mut mem,
        &mut plat,
        SYS_SOCKET,
        [AF_NETLINK as u64, SOCK_RAW, NETLINK_ROUTE as u64, 0, 0, 0],
    ) as u64;
    let mut link_body = [0u8; 16];
    link_body[4..8].copy_from_slice(&2i32.to_ne_bytes());
    let req = build_nlmsg(RTM_SETLINK, NLM_F_REQUEST | NLM_F_ACK, 7, &link_body);
    mem.write(0x1000, &req).unwrap();
    call(
        &mut unpriv,
        &mut mem,
        &mut plat,
        SYS_SENDTO,
        [ufd, 0x1000, req.len() as u64, 0, 0, 0],
    );
    let got = call(
        &mut unpriv,
        &mut mem,
        &mut plat,
        SYS_RECVFROM,
        [ufd, 0x2000, 4096, 0, 0, 0],
    );
    let mut ack = vec![0u8; got as usize];
    mem.read(0x2000, &mut ack).unwrap();
    assert_eq!(nlmsg_error_code(&ack), -(EPERM as i32));
}

#[test]
fn interface_ioctls_read_write_and_authority() {
    let mut process = new_process(Credentials::root());
    let mut mem = FlatMemory::new(64 * 1024);
    let mut plat = MockPlatform::new(true);

    let fd = call(
        &mut process,
        &mut mem,
        &mut plat,
        SYS_SOCKET,
        [AF_NETLINK as u64, SOCK_DGRAM, NETLINK_ROUTE as u64, 0, 0, 0],
    ) as u64;

    // SIOCGIFINDEX for eth0 -> 2, unknown -> -ENODEV.
    let mut req = [0u8; 40];
    req[..4].copy_from_slice(b"eth0");
    mem.write(0x100, &req).unwrap();
    assert_eq!(
        call(
            &mut process,
            &mut mem,
            &mut plat,
            SYS_IOCTL,
            [fd, SIOCGIFINDEX, 0x100, 0, 0, 0]
        ),
        0
    );
    mem.read(0x100, &mut req).unwrap();
    assert_eq!(i32::from_ne_bytes(req[16..20].try_into().unwrap()), 2);

    req.fill(0);
    req[..4].copy_from_slice(b"eth9");
    mem.write(0x100, &req).unwrap();
    assert_eq!(
        call(
            &mut process,
            &mut mem,
            &mut plat,
            SYS_IOCTL,
            [fd, SIOCGIFINDEX, 0x100, 0, 0, 0]
        ),
        -(ENODEV as i64)
    );

    // SIOCGIFNAME for index 2 -> "eth0".
    req.fill(0);
    req[16..20].copy_from_slice(&2i32.to_ne_bytes());
    mem.write(0x100, &req).unwrap();
    assert_eq!(
        call(
            &mut process,
            &mut mem,
            &mut plat,
            SYS_IOCTL,
            [fd, SIOCGIFNAME, 0x100, 0, 0, 0]
        ),
        0
    );
    mem.read(0x100, &mut req).unwrap();
    assert_eq!(&req[..5], b"eth0\0");

    // SIOCGIFHWADDR -> MAC [0x52, 0x54, 0x00, 0x12, 0x34, 0x56].
    req.fill(0);
    req[..4].copy_from_slice(b"eth0");
    mem.write(0x100, &req).unwrap();
    assert_eq!(
        call(
            &mut process,
            &mut mem,
            &mut plat,
            SYS_IOCTL,
            [fd, SIOCGIFHWADDR, 0x100, 0, 0, 0]
        ),
        0
    );
    mem.read(0x100, &mut req).unwrap();
    assert_eq!(&req[18..24], &[0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);

    // SIOCGIFFLAGS, SIOCGIFMTU, SIOCGIFADDR, SIOCGIFNETMASK, SIOCGIFBRDADDR.
    assert_eq!(
        call(
            &mut process,
            &mut mem,
            &mut plat,
            SYS_IOCTL,
            [fd, SIOCGIFFLAGS, 0x100, 0, 0, 0]
        ),
        0
    );
    mem.read(0x100, &mut req).unwrap();
    let flags = i16::from_ne_bytes(req[16..18].try_into().unwrap());
    assert_ne!(flags & 0x1, 0);

    assert_eq!(
        call(
            &mut process,
            &mut mem,
            &mut plat,
            SYS_IOCTL,
            [fd, SIOCGIFMTU, 0x100, 0, 0, 0]
        ),
        0
    );
    mem.read(0x100, &mut req).unwrap();
    assert_eq!(i32::from_ne_bytes(req[16..20].try_into().unwrap()), 1500);

    assert_eq!(
        call(
            &mut process,
            &mut mem,
            &mut plat,
            SYS_IOCTL,
            [fd, SIOCGIFADDR, 0x100, 0, 0, 0]
        ),
        0
    );
    mem.read(0x100, &mut req).unwrap();
    assert_eq!(&req[20..24], &[10, 0, 2, 15]);

    assert_eq!(
        call(
            &mut process,
            &mut mem,
            &mut plat,
            SYS_IOCTL,
            [fd, SIOCGIFNETMASK, 0x100, 0, 0, 0]
        ),
        0
    );
    mem.read(0x100, &mut req).unwrap();
    assert_eq!(&req[20..24], &[255, 255, 255, 0]);

    assert_eq!(
        call(
            &mut process,
            &mut mem,
            &mut plat,
            SYS_IOCTL,
            [fd, SIOCGIFBRDADDR, 0x100, 0, 0, 0]
        ),
        0
    );
    mem.read(0x100, &mut req).unwrap();
    assert_eq!(&req[20..24], &[10, 0, 2, 255]);

    // SIOCGIFCONF returns lo + eth0.
    let mut ifc = [0u8; 16];
    ifc[0..4].copy_from_slice(&400i32.to_ne_bytes());
    ifc[8..16].copy_from_slice(&0x500u64.to_ne_bytes());
    mem.write(0x200, &ifc).unwrap();
    assert_eq!(
        call(
            &mut process,
            &mut mem,
            &mut plat,
            SYS_IOCTL,
            [fd, SIOCGIFCONF, 0x200, 0, 0, 0]
        ),
        0
    );
    mem.read(0x200, &mut ifc).unwrap();
    assert_eq!(i32::from_ne_bytes(ifc[0..4].try_into().unwrap()), 80);

    // SIOCSIFADDR + SIOCADDRT / SIOCDELRT.
    req.fill(0);
    req[..4].copy_from_slice(b"eth0");
    req[16..18].copy_from_slice(&AF_INET.to_ne_bytes());
    req[20..24].copy_from_slice(&[192, 168, 1, 10]);
    mem.write(0x100, &req).unwrap();
    assert_eq!(
        call(
            &mut process,
            &mut mem,
            &mut plat,
            SYS_IOCTL,
            [fd, SIOCSIFADDR, 0x100, 0, 0, 0]
        ),
        0
    );
    assert!(
        plat.state
            .lock()
            .unwrap()
            .addresses
            .contains(&Ipv4InterfaceAddress {
                address: [192, 168, 1, 10],
                prefix: 24,
            })
    );

    let mut rt = [0u8; 120];
    rt[8..10].copy_from_slice(&AF_INET.to_ne_bytes());
    rt[12..16].copy_from_slice(&[172, 16, 0, 0]);
    rt[24..26].copy_from_slice(&AF_INET.to_ne_bytes());
    rt[28..32].copy_from_slice(&[10, 0, 2, 2]);
    rt[40..42].copy_from_slice(&AF_INET.to_ne_bytes());
    rt[44..48].copy_from_slice(&[255, 255, 0, 0]);
    rt[56..58].copy_from_slice(&0x0003u16.to_ne_bytes());
    mem.write(0x300, &rt).unwrap();
    assert_eq!(
        call(
            &mut process,
            &mut mem,
            &mut plat,
            SYS_IOCTL,
            [fd, SIOCADDRT, 0x300, 0, 0, 0]
        ),
        0
    );
    assert!(plat.state.lock().unwrap().routes.contains(&Ipv4RouteEntry {
        destination: [172, 16, 0, 0],
        prefix: 16,
        gateway: Some([10, 0, 2, 2]),
    }));
    assert_eq!(
        call(
            &mut process,
            &mut mem,
            &mut plat,
            SYS_IOCTL,
            [fd, SIOCDELRT, 0x300, 0, 0, 0]
        ),
        0
    );
    assert!(
        !plat.state.lock().unwrap().routes.contains(&Ipv4RouteEntry {
            destination: [172, 16, 0, 0],
            prefix: 16,
            gateway: Some([10, 0, 2, 2]),
        })
    );

    // Authority check: SIOCSIF* fail with EPERM without container admin.
    plat.state.lock().unwrap().container_admin = false;
    assert_eq!(
        call(
            &mut process,
            &mut mem,
            &mut plat,
            SYS_IOCTL,
            [fd, SIOCSIFFLAGS, 0x100, 0, 0, 0]
        ),
        -(EPERM as i64)
    );
    assert_eq!(
        call(
            &mut process,
            &mut mem,
            &mut plat,
            SYS_IOCTL,
            [fd, SIOCSIFMTU, 0x100, 0, 0, 0]
        ),
        -(EPERM as i64)
    );
    assert_eq!(
        call(
            &mut process,
            &mut mem,
            &mut plat,
            SYS_IOCTL,
            [fd, SIOCSIFNETMASK, 0x100, 0, 0, 0]
        ),
        -(EPERM as i64)
    );
}

#[test]
fn af_packet_raw_dgram_epoll_and_authority() {
    let mut process = new_process(Credentials::root());
    let mut mem = FlatMemory::new(64 * 1024);
    let mut plat = MockPlatform::new(true);

    // 1. SOCK_DGRAM with htons(ETH_P_IP) — the exact udhcpc path.
    let fd = call(
        &mut process,
        &mut mem,
        &mut plat,
        SYS_SOCKET,
        [
            AF_PACKET as u64,
            SOCK_DGRAM,
            u64::from(ETH_P_IP.to_be()),
            0,
            0,
            0,
        ],
    );
    assert!(fd >= 0);
    let fd = fd as u64;

    // bind to eth0 (ifindex 2).
    let mut sll = [0u8; 20];
    sll[0..2].copy_from_slice(&AF_PACKET.to_ne_bytes());
    sll[2..4].copy_from_slice(&ETH_P_IP.to_be_bytes());
    sll[4..8].copy_from_slice(&2i32.to_ne_bytes());
    mem.write(0x100, &sll).unwrap();
    assert_eq!(
        call(
            &mut process,
            &mut mem,
            &mut plat,
            SYS_BIND,
            [fd, 0x100, 20, 0, 0, 0]
        ),
        0
    );

    // getsockname returns eth0 MAC + ARPHRD_ETHER.
    mem.write(0x130, &20u32.to_ne_bytes()).unwrap();
    assert_eq!(
        call(
            &mut process,
            &mut mem,
            &mut plat,
            SYS_GETSOCKNAME,
            [fd, 0x110, 0x130, 0, 0, 0]
        ),
        0
    );
    let mut out_sll = [0u8; 20];
    mem.read(0x110, &mut out_sll).unwrap();
    assert_eq!(u16::from_ne_bytes([out_sll[0], out_sll[1]]), AF_PACKET);
    assert_eq!(i32::from_ne_bytes(out_sll[4..8].try_into().unwrap()), 2);
    assert_eq!(&out_sll[12..18], &[0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);

    // sendto broadcast L3 payload -> synthesizes 14-byte Ethernet header.
    let mut dst_sll = [0u8; 20];
    dst_sll[0..2].copy_from_slice(&AF_PACKET.to_ne_bytes());
    dst_sll[2..4].copy_from_slice(&ETH_P_IP.to_be_bytes());
    dst_sll[4..8].copy_from_slice(&2i32.to_ne_bytes());
    dst_sll[11] = 6;
    dst_sll[12..18].copy_from_slice(&[0xff; 6]);
    mem.write(0x200, &dst_sll).unwrap();
    let l3_payload = b"DHCPDISCOVER-PAYLOAD";
    mem.write(0x300, l3_payload).unwrap();
    assert_eq!(
        call(
            &mut process,
            &mut mem,
            &mut plat,
            SYS_SENDTO,
            [fd, 0x300, l3_payload.len() as u64, 0, 0x200, 20]
        ),
        l3_payload.len() as i64
    );
    {
        let st = plat.state.lock().unwrap();
        assert_eq!(st.sent_frames.len(), 1);
        let (ifindex, ref frame) = st.sent_frames[0];
        assert_eq!(ifindex, 2);
        assert_eq!(&frame[0..6], &[0xff; 6]);
        assert_eq!(&frame[6..12], &[0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
        assert_eq!(&frame[12..14], &ETH_P_IP.to_be_bytes());
        assert_eq!(&frame[14..], l3_payload);
    }

    // epoll sees EPOLLIN ready now that MockPlatform looped the frame into rx_frames.
    let epfd = call(&mut process, &mut mem, &mut plat, SYS_EPOLL_CREATE1, [0; 6]) as u64;
    let mut ev = [0u8; 12];
    ev[0..4].copy_from_slice(&0x001u32.to_le_bytes());
    ev[4..12].copy_from_slice(&42u64.to_le_bytes());
    mem.write(0x400, &ev).unwrap();
    assert_eq!(
        call(
            &mut process,
            &mut mem,
            &mut plat,
            SYS_EPOLL_CTL,
            [epfd, 1, fd, 0x400, 0, 0]
        ),
        0
    );
    assert_eq!(
        call(
            &mut process,
            &mut mem,
            &mut plat,
            SYS_EPOLL_PWAIT,
            [epfd, 0x420, 4, 0, 0, 0]
        ),
        1
    );

    // recvfrom strips the 14-byte Ethernet header for SOCK_DGRAM and populates sockaddr_ll.
    mem.write(0x560, &20u32.to_ne_bytes()).unwrap();
    let got = call(
        &mut process,
        &mut mem,
        &mut plat,
        SYS_RECVFROM,
        [fd, 0x500, 256, MSG_DONTWAIT, 0x540, 0x560],
    );
    assert_eq!(got, l3_payload.len() as i64);
    let mut recv_buf = vec![0u8; got as usize];
    mem.read(0x500, &mut recv_buf).unwrap();
    assert_eq!(recv_buf, l3_payload);
    let mut src_sll = [0u8; 20];
    mem.read(0x540, &mut src_sll).unwrap();
    assert_eq!(src_sll[10], 1); // PACKET_BROADCAST
    assert_eq!(&src_sll[12..18], &[0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);

    // setsockopt SO_BINDTODEVICE & getsockopt SO_DOMAIN.
    mem.write(0x600, b"eth0\0").unwrap();
    assert_eq!(
        call(
            &mut process,
            &mut mem,
            &mut plat,
            SYS_SETSOCKOPT,
            [fd, 1, 25, 0x600, 5, 0]
        ),
        0
    );
    mem.write(0x614, &4u32.to_le_bytes()).unwrap();
    assert_eq!(
        call(
            &mut process,
            &mut mem,
            &mut plat,
            SYS_GETSOCKOPT,
            [fd, 1, 39, 0x610, 0x614, 0]
        ),
        0
    );
    let mut dom = [0u8; 4];
    mem.read(0x610, &mut dom).unwrap();
    assert_eq!(i32::from_le_bytes(dom), i32::from(AF_PACKET));

    // 2. Authority enforcement: container without admin cap denies AF_PACKET even for uid 0.
    plat.state.lock().unwrap().container_admin = false;
    assert_eq!(
        call(
            &mut process,
            &mut mem,
            &mut plat,
            SYS_SOCKET,
            [
                AF_PACKET as u64,
                SOCK_RAW,
                u64::from(ETH_P_ALL.to_be()),
                0,
                0,
                0
            ]
        ),
        -(EPERM as i64)
    );

    // 3. Authority enforcement: process without CAP_NET_RAW is denied AF_PACKET even with container admin.
    plat.state.lock().unwrap().container_admin = true;
    let mut unpriv = new_process(creds_without(CAP_NET_RAW));
    assert_eq!(
        call(
            &mut unpriv,
            &mut mem,
            &mut plat,
            SYS_SOCKET,
            [
                AF_PACKET as u64,
                SOCK_RAW,
                u64::from(ETH_P_ALL.to_be()),
                0,
                0,
                0
            ]
        ),
        -(EPERM as i64)
    );
}

#[test]
fn recvmsg_truncation_flags_rcvtimeo_eagain_and_fail_fast_mutations() {
    let mut process = new_process(Credentials::root());
    let mut mem = FlatMemory::new(64 * 1024);
    let mut plat = MockPlatform::new(true);

    // 1. Truncated recvmsg(..., 0) on AF_NETLINK sets MSG_TRUNC in msg_flags.
    let nl_fd = call(
        &mut process,
        &mut mem,
        &mut plat,
        SYS_SOCKET,
        [AF_NETLINK as u64, SOCK_RAW, NETLINK_ROUTE as u64, 0, 0, 0],
    ) as u64;
    let req = build_nlmsg(RTM_GETLINK, NLM_F_REQUEST | NLM_F_DUMP, 1, &[0u8; 16]);
    mem.write(0x1000, &req).unwrap();
    assert_eq!(
        call(
            &mut process,
            &mut mem,
            &mut plat,
            SYS_SENDTO,
            [nl_fd, 0x1000, req.len() as u64, 0, 0, 0]
        ),
        req.len() as i64
    );
    // Prepare iovec of 8 bytes (much smaller than RTM_GETLINK dump) and msghdr.
    let mut iov = [0u8; 16];
    iov[0..8].copy_from_slice(&0x2000u64.to_le_bytes());
    iov[8..16].copy_from_slice(&8u64.to_le_bytes());
    mem.write(0x1800, &iov).unwrap();
    let mut msg = [0u8; 56];
    msg[16..24].copy_from_slice(&0x1800u64.to_le_bytes());
    msg[24..32].copy_from_slice(&1u64.to_le_bytes());
    mem.write(0x1900, &msg).unwrap();
    let got = call(
        &mut process,
        &mut mem,
        &mut plat,
        SYS_RECVMSG,
        [nl_fd, 0x1900, 0, 0, 0, 0],
    );
    assert_eq!(got, 8);
    let mut out_flags = [0u8; 4];
    mem.read(0x1900 + 48, &mut out_flags).unwrap();
    assert_ne!(u32::from_le_bytes(out_flags) & (MSG_TRUNC as u32), 0);

    // 2. Truncated recvmsg(..., 0) on AF_PACKET sets MSG_TRUNC in msg_flags.
    let pkt_fd = call(
        &mut process,
        &mut mem,
        &mut plat,
        SYS_SOCKET,
        [
            AF_PACKET as u64,
            SOCK_DGRAM,
            u64::from(ETH_P_IP.to_be()),
            0,
            0,
            0,
        ],
    ) as u64;
    let payload = b"0123456789abcdef0123456789";
    mem.write(0x3000, payload).unwrap();
    assert_eq!(
        call(
            &mut process,
            &mut mem,
            &mut plat,
            SYS_SENDTO,
            [pkt_fd, 0x3000, payload.len() as u64, 0, 0, 0]
        ),
        payload.len() as i64
    );
    mem.write(0x1900, &msg).unwrap();
    let got = call(
        &mut process,
        &mut mem,
        &mut plat,
        SYS_RECVMSG,
        [pkt_fd, 0x1900, 0, 0, 0, 0],
    );
    assert_eq!(got, 8);
    mem.read(0x1900 + 48, &mut out_flags).unwrap();
    assert_ne!(u32::from_le_bytes(out_flags) & (MSG_TRUNC as u32), 0);

    // 3. Blocking AF_PACKET recvfrom with SO_RCVTIMEO returns -EAGAIN on timeout.
    let mut tv = [0u8; 16];
    tv[0..8].copy_from_slice(&1i64.to_le_bytes()); // 1 second
    mem.write(0x3200, &tv).unwrap();
    assert_eq!(
        call(
            &mut process,
            &mut mem,
            &mut plat,
            SYS_SETSOCKOPT,
            [pkt_fd, 1, 20, 0x3200, 16, 0]
        ),
        0
    );
    assert_eq!(
        call(
            &mut process,
            &mut mem,
            &mut plat,
            SYS_RECVFROM,
            [pkt_fd, 0x3300, 64, 0, 0, 0]
        ),
        -(EAGAIN as i64)
    );

    // 4. SO_BINDTODEVICE unbind resets AF_PACKET ifindex to 0, non-packet rejects binding,
    //    and non-zero PACKET_AUXDATA fails fast with EOPNOTSUPP.
    mem.write(0x3400, b"eth0\0").unwrap();
    assert_eq!(
        call(
            &mut process,
            &mut mem,
            &mut plat,
            SYS_SETSOCKOPT,
            [pkt_fd, 1, 25, 0x3400, 5, 0]
        ),
        0
    );
    assert_eq!(plat.state.lock().unwrap().bound_packet, Some((ETH_P_IP, 2)));
    assert_eq!(
        call(
            &mut process,
            &mut mem,
            &mut plat,
            SYS_SETSOCKOPT,
            [pkt_fd, 1, 25, 0, 0, 0]
        ),
        0
    );
    assert_eq!(plat.state.lock().unwrap().bound_packet, Some((ETH_P_IP, 0)));
    assert_eq!(
        call(
            &mut process,
            &mut mem,
            &mut plat,
            SYS_SETSOCKOPT,
            [nl_fd, 1, 25, 0x3400, 5, 0]
        ),
        -(EOPNOTSUPP as i64)
    );
    mem.write(0x3420, &1i32.to_le_bytes()).unwrap();
    assert_eq!(
        call(
            &mut process,
            &mut mem,
            &mut plat,
            SYS_SETSOCKOPT,
            [pkt_fd, 263, 8, 0x3420, 4, 0]
        ),
        -(EOPNOTSUPP as i64)
    );

    // 5. SIOCSIFADDR replaces primary address so SIOCSIFNETMASK updates the new address.
    let mut req = [0u8; 40];
    req[..4].copy_from_slice(b"eth0");
    req[16..18].copy_from_slice(&AF_INET.to_ne_bytes());
    req[20..24].copy_from_slice(&[192, 168, 10, 5]);
    mem.write(0x3500, &req).unwrap();
    assert_eq!(
        call(
            &mut process,
            &mut mem,
            &mut plat,
            SYS_IOCTL,
            [nl_fd, SIOCSIFADDR, 0x3500, 0, 0, 0]
        ),
        0
    );
    req[20..24].copy_from_slice(&[192, 168, 20, 6]);
    mem.write(0x3500, &req).unwrap();
    assert_eq!(
        call(
            &mut process,
            &mut mem,
            &mut plat,
            SYS_IOCTL,
            [nl_fd, SIOCSIFADDR, 0x3500, 0, 0, 0]
        ),
        0
    );
    req[20..24].copy_from_slice(&[255, 255, 0, 0]);
    mem.write(0x3500, &req).unwrap();
    assert_eq!(
        call(
            &mut process,
            &mut mem,
            &mut plat,
            SYS_IOCTL,
            [nl_fd, SIOCSIFNETMASK, 0x3500, 0, 0, 0]
        ),
        0
    );
    assert_eq!(
        call(
            &mut process,
            &mut mem,
            &mut plat,
            SYS_IOCTL,
            [nl_fd, SIOCGIFADDR, 0x3500, 0, 0, 0]
        ),
        0
    );
    mem.read(0x3500, &mut req).unwrap();
    assert_eq!(&req[20..24], &[192, 168, 20, 6]);
    assert_eq!(
        call(
            &mut process,
            &mut mem,
            &mut plat,
            SYS_IOCTL,
            [nl_fd, SIOCGIFNETMASK, 0x3500, 0, 0, 0]
        ),
        0
    );
    mem.read(0x3500, &mut req).unwrap();
    assert_eq!(&req[20..24], &[255, 255, 0, 0]);

    // 6. Unsupported link/MTU mutations fail fast with EOPNOTSUPP.
    req.fill(0);
    req[..4].copy_from_slice(b"eth0");
    req[16..18].copy_from_slice(&0i16.to_ne_bytes()); // clearing IFF_UP
    mem.write(0x3500, &req).unwrap();
    assert_eq!(
        call(
            &mut process,
            &mut mem,
            &mut plat,
            SYS_IOCTL,
            [nl_fd, SIOCSIFFLAGS, 0x3500, 0, 0, 0]
        ),
        -(EOPNOTSUPP as i64)
    );
    req[16..20].copy_from_slice(&1400i32.to_ne_bytes());
    mem.write(0x3500, &req).unwrap();
    assert_eq!(
        call(
            &mut process,
            &mut mem,
            &mut plat,
            SYS_IOCTL,
            [nl_fd, SIOCSIFMTU, 0x3500, 0, 0, 0]
        ),
        -(EOPNOTSUPP as i64)
    );
    let mut link_body = vec![0u8; 16];
    link_body[4..8].copy_from_slice(&2i32.to_ne_bytes());
    append_rta(&mut link_body, 4, &1400u32.to_ne_bytes()); // IFLA_MTU = 1400
    let req = build_nlmsg(RTM_SETLINK, NLM_F_REQUEST | NLM_F_ACK, 9, &link_body);
    mem.write(0x1000, &req).unwrap();
    call(
        &mut process,
        &mut mem,
        &mut plat,
        SYS_SENDTO,
        [nl_fd, 0x1000, req.len() as u64, 0, 0, 0],
    );
    let got = call(
        &mut process,
        &mut mem,
        &mut plat,
        SYS_RECVFROM,
        [nl_fd, 0x2000, 4096, 0, 0, 0],
    );
    let mut ack = vec![0u8; got as usize];
    mem.read(0x2000, &mut ack).unwrap();
    assert_eq!(nlmsg_error_code(&ack), -(EOPNOTSUPP as i32));
}

#[test]
fn unix_dgram_and_inet_raw_sockets_support_interface_ioctls_and_cap_net_raw() {
    const AF_UNIX: u64 = 1;
    const SOCK_DGRAM: u64 = 2;
    const SOCK_RAW: u64 = 3;
    const IPPROTO_RAW: u64 = 255;
    const SIOCGIFTXQLEN: u64 = 0x8942;

    let mut process = new_process(Credentials::root());
    let mut mem = FlatMemory::new(64 * 1024);
    let mut plat = MockPlatform::new(true);

    // 1. musl if_nametoindex opens AF_UNIX SOCK_DGRAM and calls SIOCGIFINDEX / SIOCGIFTXQLEN.
    let unix_fd = call(
        &mut process,
        &mut mem,
        &mut plat,
        SYS_SOCKET,
        [AF_UNIX, SOCK_DGRAM, 0, 0, 0, 0],
    );
    assert!(unix_fd >= 0);
    let unix_fd = unix_fd as u64;

    let mut req = [0u8; 40];
    req[0..4].copy_from_slice(b"eth0");
    mem.write(0x100, &req).unwrap();
    assert_eq!(
        call(
            &mut process,
            &mut mem,
            &mut plat,
            SYS_IOCTL,
            [unix_fd, SIOCGIFINDEX, 0x100, 0, 0, 0]
        ),
        0
    );
    mem.read(0x100, &mut req).unwrap();
    assert_eq!(i32::from_ne_bytes(req[16..20].try_into().unwrap()), 2);

    req[16..20].fill(0);
    mem.write(0x100, &req).unwrap();
    assert_eq!(
        call(
            &mut process,
            &mut mem,
            &mut plat,
            SYS_IOCTL,
            [unix_fd, SIOCGIFTXQLEN, 0x100, 0, 0, 0]
        ),
        0
    );
    mem.read(0x100, &mut req).unwrap();
    assert_eq!(i32::from_ne_bytes(req[16..20].try_into().unwrap()), 1000);

    // 2. BusyBox udhcpc opens AF_INET SOCK_RAW IPPROTO_RAW for SIOCGIFINDEX / SIOCGIFHWADDR.
    //    Requires CAP_NET_RAW: rejected with EPERM without it.
    let mut unpriv = new_process(creds_without(CAP_NET_RAW));
    assert_eq!(
        call(
            &mut unpriv,
            &mut mem,
            &mut plat,
            SYS_SOCKET,
            [AF_INET as u64, SOCK_RAW, IPPROTO_RAW, 0, 0, 0]
        ),
        -(EPERM as i64)
    );

    let raw_fd = call(
        &mut process,
        &mut mem,
        &mut plat,
        SYS_SOCKET,
        [AF_INET as u64, SOCK_RAW, IPPROTO_RAW, 0, 0, 0],
    );
    assert!(raw_fd >= 0);
    let raw_fd = raw_fd as u64;
    req[16..20].fill(0);
    mem.write(0x100, &req).unwrap();
    assert_eq!(
        call(
            &mut process,
            &mut mem,
            &mut plat,
            SYS_IOCTL,
            [raw_fd, SIOCGIFHWADDR, 0x100, 0, 0, 0]
        ),
        0
    );
    mem.read(0x100, &mut req).unwrap();
    assert_eq!(&req[18..24], &[0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);

    // 3. getsockopt(SO_PROTOCOL) reports IPPROTO_RAW on raw IP sockets, and
    //    getpeername / shutdown / sendto return ENOTCONN / EOPNOTSUPP (never ENOTSOCK).
    const SYS_GETPEERNAME: u64 = 52;
    const SYS_SHUTDOWN: u64 = 48;
    const SYS_GETSOCKOPT: u64 = 55;
    const SOL_SOCKET: u64 = 1;
    const SO_PROTOCOL: u64 = 38;
    const ENOTCONN: u64 = 107;

    mem.write(0x210, &4u32.to_le_bytes()).unwrap();
    assert_eq!(
        call(
            &mut process,
            &mut mem,
            &mut plat,
            SYS_GETSOCKOPT,
            [raw_fd, SOL_SOCKET, SO_PROTOCOL, 0x200, 0x210, 0]
        ),
        0
    );
    let mut proto_bytes = [0u8; 4];
    mem.read(0x200, &mut proto_bytes).unwrap();
    assert_eq!(i32::from_le_bytes(proto_bytes), IPPROTO_RAW as i32);

    mem.write(0x220, &16u32.to_le_bytes()).unwrap();
    assert_eq!(
        call(
            &mut process,
            &mut mem,
            &mut plat,
            SYS_GETPEERNAME,
            [unix_fd, 0x230, 0x220, 0, 0, 0]
        ),
        -(ENOTCONN as i64)
    );
    assert_eq!(
        call(
            &mut process,
            &mut mem,
            &mut plat,
            SYS_GETPEERNAME,
            [raw_fd, 0x230, 0x220, 0, 0, 0]
        ),
        -(ENOTCONN as i64)
    );
    assert_eq!(
        call(
            &mut process,
            &mut mem,
            &mut plat,
            SYS_SHUTDOWN,
            [unix_fd, 2, 0, 0, 0, 0]
        ),
        -(ENOTCONN as i64)
    );
    assert_eq!(
        call(
            &mut process,
            &mut mem,
            &mut plat,
            SYS_SHUTDOWN,
            [raw_fd, 2, 0, 0, 0, 0]
        ),
        -(ENOTCONN as i64)
    );
    mem.write(0x240, b"hi").unwrap();
    assert_eq!(
        call(
            &mut process,
            &mut mem,
            &mut plat,
            SYS_SENDTO,
            [unix_fd, 0x240, 2, 0, 0, 0]
        ),
        -(EOPNOTSUPP as i64)
    );
    assert_eq!(
        call(
            &mut process,
            &mut mem,
            &mut plat,
            SYS_SENDTO,
            [raw_fd, 0x240, 2, 0, 0, 0]
        ),
        -(EOPNOTSUPP as i64)
    );
}
