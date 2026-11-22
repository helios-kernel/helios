#![cfg(feature = "runtime")]

use alloc::sync::Arc;
use bytes::Bytes;
use core::future::Future;
use core::num::NonZeroU32;
use core::ops::ControlFlow;
use core::task::{Context, Poll, Waker};
use helios_hal::vmm::PageFlags;
use helios_linux::abi::{Abi, Operation};
use helios_linux::syscall::{
    Call, Clock, ConnectProgress, Denied, EAGAIN, EINPROGRESS, ENOTCONN, ENOTSOCK, EPIPE,
    EPROTONOSUPPORT, IpAddr, MapError, MemoryFault, MemoryTotals, Network, Process, Region,
    Resources, SocketAddr, SocketReady, SpawnError, SpawnedThread, Stdio, Stream, System, Thread,
    UserMemory, UtsField, VirtualMemory, WriteError, dispatch,
};
use helios_unix::{OwnedTcpListener, OwnedTcpStream, OwnedUdpSocket, SocketLimits, SocketNetwork};
use spin::Mutex;

extern crate alloc;

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

#[derive(Clone)]
struct Memory(Vec<u8>);

impl Memory {
    fn new(size: usize) -> Self {
        Self(vec![0; size])
    }
}

impl UserMemory for Memory {
    fn read(&self, address: u64, output: &mut [u8]) -> Result<(), MemoryFault> {
        let start = usize::try_from(address).map_err(|_| MemoryFault)?;
        let end = start.checked_add(output.len()).ok_or(MemoryFault)?;
        if end > self.0.len() {
            return Err(MemoryFault);
        }
        output.copy_from_slice(&self.0[start..end]);
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

    fn write(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryFault> {
        let start = usize::try_from(address).map_err(|_| MemoryFault)?;
        let end = start.checked_add(bytes.len()).ok_or(MemoryFault)?;
        if end > self.0.len() {
            return Err(MemoryFault);
        }
        self.0[start..end].copy_from_slice(bytes);
        Ok(())
    }

    fn atomic_load_u32(&self, address: u64) -> Result<u32, MemoryFault> {
        let mut raw = [0; 4];
        self.read(address, &mut raw)?;
        Ok(u32::from_le_bytes(raw))
    }

    fn atomic_store_u32(&mut self, address: u64, value: u32) -> Result<(), MemoryFault> {
        self.write(address, &value.to_le_bytes())
    }

    fn atomic_compare_exchange_u32(
        &mut self,
        address: u64,
        expected: u32,
        desired: u32,
    ) -> Result<Result<u32, u32>, MemoryFault> {
        let cur = self.atomic_load_u32(address)?;
        if cur == expected {
            self.atomic_store_u32(address, desired)?;
            Ok(Ok(cur))
        } else {
            Ok(Err(cur))
        }
    }
}

impl VirtualMemory for Memory {
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
impl<R: Resources> Thread<R> for NoThread {
    fn thread_pointer(&self) -> u64 {
        0
    }
    fn set_thread_pointer(&mut self, _: u64) -> Result<(), Denied> {
        Ok(())
    }
    fn stack_pointer(&self) -> u64 {
        0
    }
    fn spawn_thread(&mut self, _: Process<R>, _: SpawnedThread) -> Result<(), SpawnError> {
        Err(SpawnError::Busy)
    }
}

type MulticastJoin = ([u8; 4], [u8; 4]);

#[derive(Clone)]
struct MockNet {
    allow_tcp: bool,
    allow_udp: bool,
    allow_priv_bind: bool,
    allow_multicast: bool,
    connect_state: Arc<Mutex<ConnectProgress>>,
    multicast_joins: Arc<Mutex<Vec<MulticastJoin>>>,
    udp_queue: Arc<Mutex<Vec<(Bytes, SocketAddr, usize)>>>,
    last_udp_timeout: Arc<Mutex<Option<u64>>>,
}

impl Default for MockNet {
    fn default() -> Self {
        Self {
            allow_tcp: false,
            allow_udp: false,
            allow_priv_bind: false,
            allow_multicast: false,
            connect_state: Arc::new(Mutex::new(ConnectProgress::Pending)),
            multicast_joins: Arc::new(Mutex::new(Vec::new())),
            udp_queue: Arc::new(Mutex::new(Vec::new())),
            last_udp_timeout: Arc::new(Mutex::new(None)),
        }
    }
}

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

struct Platform {
    net: MockNet,
    now: u64,
}

impl Stdio for Platform {
    async fn write(&mut self, _: Stream, bytes: &[u8]) -> Result<usize, WriteError> {
        Ok(bytes.len())
    }
    async fn read_input(&mut self, _: usize) -> Result<Bytes, Denied> {
        Ok(Bytes::new())
    }
}

impl Clock for Platform {
    fn now_nanos(&self) -> u64 {
        self.now
    }
    async fn sleep_until(&self, _: u64) {}
}

impl System for Platform {
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

impl Network<MockNet> for Platform {
    fn to_ip(&self, address: IpAddr) -> IpAddr {
        address
    }
    fn encode_ip(&self, ip: IpAddr) -> IpAddr {
        ip
    }
    fn check_tcp_open(&self) -> Result<(), u64> {
        if self.net.allow_tcp { Ok(()) } else { Err(13) }
    }
    fn check_udp_open(&self) -> Result<(), u64> {
        if self.net.allow_udp { Ok(()) } else { Err(13) }
    }
    fn check_tcp_bind(&self, local_port: u16) -> Result<(), u64> {
        self.check_tcp_open()?;
        if local_port != 0 && local_port < 1024 && !self.net.allow_priv_bind {
            return Err(13);
        }
        Ok(())
    }
    fn check_udp_bind(&self, local_port: u16) -> Result<(), u64> {
        self.check_udp_open()?;
        if local_port != 0 && local_port < 1024 && !self.net.allow_priv_bind {
            return Err(13);
        }
        Ok(())
    }
    async fn tcp_listen(
        &self,
        local: SocketAddr,
        _: u16,
        _: u8,
    ) -> Result<(Arc<OwnedTcpListener<MockNet>>, u16), u64> {
        self.check_tcp_bind(local.port)?;
        let port = if local.port == 0 { 42000 } else { local.port };
        Ok((OwnedTcpListener::new(self.net.clone(), 1), port))
    }
    async fn tcp_connect_start(
        &self,
        _: SocketAddr,
        _: u16,
        _: u8,
    ) -> Result<(Arc<OwnedTcpStream<MockNet>>, ConnectProgress), u64> {
        self.check_tcp_open()?;
        let state = *self.net.connect_state.lock();
        Ok((OwnedTcpStream::new(self.net.clone(), 2), state))
    }
    async fn tcp_connect_poll(&self, _: u64) -> Result<ConnectProgress, u64> {
        Ok(*self.net.connect_state.lock())
    }
    fn tcp_local_endpoint(&self, _: u64) -> Result<Option<SocketAddr>, u64> {
        Ok(Some(SocketAddr {
            ip: IpAddr::V4([127, 0, 0, 1]),
            port: 43000,
        }))
    }
    async fn tcp_readiness(&self, _: u64) -> Result<SocketReady, u64> {
        Ok(SocketReady {
            readable: true,
            writable: true,
            hangup: false,
        })
    }
    async fn udp_bind(
        &self,
        local: SocketAddr,
        _: u8,
    ) -> Result<(Arc<OwnedUdpSocket<MockNet>>, u16), u64> {
        self.check_udp_bind(local.port)?;
        let port = if local.port == 0 { 44000 } else { local.port };
        Ok((OwnedUdpSocket::new(self.net.clone(), 3), port))
    }
    fn udp_connect(&self, _: u64, _: SocketAddr) -> Result<(), u64> {
        self.check_udp_open()
    }
    fn udp_disconnect(&self, _: u64) -> Result<(), u64> {
        self.check_udp_open()
    }
    async fn udp_receive(
        &self,
        _: u64,
        max_bytes: u32,
        timeout_nanos: u64,
        _: bool,
    ) -> Result<Option<(Bytes, SocketAddr, usize)>, u64> {
        self.check_udp_open()?;
        *self.net.last_udp_timeout.lock() = Some(timeout_nanos);
        let mut queue = self.net.udp_queue.lock();
        if queue.is_empty() {
            return Err(110); // ETIMEDOUT -> mapped to EAGAIN
        }
        let (bytes, peer, original_len) = queue.remove(0);
        let take = (max_bytes as usize).min(bytes.len());
        Ok(Some((bytes.slice(..take), peer, original_len)))
    }
    async fn udp_join_multicast_v4(&self, group: [u8; 4], interface: [u8; 4]) -> Result<(), u64> {
        if !self.net.allow_multicast {
            return Err(13);
        }
        self.net.multicast_joins.lock().push((group, interface));
        Ok(())
    }
    async fn udp_leave_multicast_v4(&self, _: [u8; 4], _: [u8; 4]) -> Result<(), u64> {
        if !self.net.allow_multicast {
            return Err(13);
        }
        Ok(())
    }
    fn check_multicast_v6(&self) -> Result<(), u64> {
        if !self.net.allow_multicast {
            return Err(13);
        }
        self.check_udp_open()
    }
}

fn syscall_num(abi: Abi, op: Operation) -> u64 {
    for n in 0..500u64 {
        if abi.operation(n) == op {
            return n;
        }
    }
    panic!("missing syscall number for {op:?} on {abi:?}")
}

fn call_op(
    process: &mut Process<MockResources>,
    abi: Abi,
    op: Operation,
    arguments: [u64; 6],
    memory: &mut Memory,
    platform: &mut Platform,
) -> u64 {
    let call = Call {
        number: syscall_num(abi, op),
        arguments,
    };
    let mut thread = NoThread;
    match drive(dispatch(process, call, memory, &mut thread, platform)) {
        ControlFlow::Continue(helios_linux::syscall::SyscallOutcome::Return(value)) => value,
        ControlFlow::Continue(other) => panic!("unexpected syscall outcome: {other:?}"),
        ControlFlow::Break(exit) => panic!("unexpected exit: {exit:?}"),
    }
}

fn new_process(abi: Abi) -> Process<MockResources> {
    Process::new(abi, NonZeroU32::new(1).unwrap(), 0x10_0000)
}

#[test]
fn socket_syscall_numbers_match_both_abis() {
    let cases = [
        (Operation::Sendfile, 40, 71),
        (Operation::Socket, 41, 198),
        (Operation::Socketpair, 53, 199),
        (Operation::Bind, 49, 200),
        (Operation::Listen, 50, 201),
        (Operation::Accept, 43, 202),
        (Operation::Accept4, 288, 242),
        (Operation::Connect, 42, 203),
        (Operation::Getsockname, 51, 204),
        (Operation::Getpeername, 52, 205),
        (Operation::Sendto, 44, 206),
        (Operation::Recvfrom, 45, 207),
        (Operation::Setsockopt, 54, 208),
        (Operation::Getsockopt, 55, 209),
        (Operation::Shutdown, 48, 210),
        (Operation::Sendmsg, 46, 211),
        (Operation::Recvmsg, 47, 212),
        (Operation::Sendmmsg, 307, 269),
        (Operation::Recvmmsg, 299, 243),
    ];
    for (op, x86, arm) in cases {
        assert_eq!(Abi::X86_64.operation(x86), op);
        assert_eq!(Abi::Aarch64.operation(arm), op);
    }
}

#[test]
fn authority_denials_return_eacces_even_for_uid_zero() {
    for abi in [Abi::X86_64, Abi::Aarch64] {
        let mut proc = new_process(abi);
        let mut mem = Memory::new(4096);
        let mut plat = Platform {
            net: MockNet {
                allow_tcp: false,
                allow_udp: false,
                allow_priv_bind: false,
                allow_multicast: false,
                ..Default::default()
            },
            now: 0,
        };
        assert_eq!(
            call_op(
                &mut proc,
                abi,
                Operation::Socket,
                [2, 1, 0, 0, 0, 0],
                &mut mem,
                &mut plat
            ),
            13u64.wrapping_neg()
        );
        assert_eq!(
            call_op(
                &mut proc,
                abi,
                Operation::Socket,
                [2, 2, 0, 0, 0, 0],
                &mut mem,
                &mut plat
            ),
            13u64.wrapping_neg()
        );

        // Allow TCP/UDP without privileged bind or multicast.
        plat.net.allow_tcp = true;
        plat.net.allow_udp = true;
        let tcp_fd = call_op(
            &mut proc,
            abi,
            Operation::Socket,
            [2, 1, 0, 0, 0, 0],
            &mut mem,
            &mut plat,
        );
        assert_eq!(tcp_fd, 3);
        // Bind to privileged port 80 -> EACCES.
        let mut sa = [0u8; 16];
        sa[0..2].copy_from_slice(&2u16.to_le_bytes());
        sa[2..4].copy_from_slice(&80u16.to_be_bytes());
        sa[4..8].copy_from_slice(&[127, 0, 0, 1]);
        mem.write(64, &sa).unwrap();
        assert_eq!(
            call_op(
                &mut proc,
                abi,
                Operation::Bind,
                [tcp_fd, 64, 16, 0, 0, 0],
                &mut mem,
                &mut plat
            ),
            13u64.wrapping_neg()
        );

        // UDP multicast join without MulticastCap -> EACCES.
        let udp_fd = call_op(
            &mut proc,
            abi,
            Operation::Socket,
            [2, 2, 0, 0, 0, 0],
            &mut mem,
            &mut plat,
        );
        mem.write(128, &[224, 0, 0, 251, 0, 0, 0, 0]).unwrap();
        assert_eq!(
            call_op(
                &mut proc,
                abi,
                Operation::Setsockopt,
                [udp_fd, 0, 35, 128, 8, 0],
                &mut mem,
                &mut plat
            ),
            13u64.wrapping_neg()
        );
    }
}

#[test]
fn nonblocking_connect_transitions_through_einprogress_epoll_and_so_error() {
    for abi in [Abi::X86_64, Abi::Aarch64] {
        let mut proc = new_process(abi);
        let mut mem = Memory::new(4096);
        let mut plat = Platform {
            net: MockNet {
                allow_tcp: true,
                allow_udp: true,
                allow_priv_bind: false,
                allow_multicast: true,
                connect_state: Arc::new(Mutex::new(ConnectProgress::Pending)),
                multicast_joins: Arc::new(Mutex::new(Vec::new())),
                ..Default::default()
            },
            now: 0,
        };
        // socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0)
        let fd = call_op(
            &mut proc,
            abi,
            Operation::Socket,
            [2, 1 | 0x0800, 0, 0, 0, 0],
            &mut mem,
            &mut plat,
        );
        assert_eq!(fd, 3);

        let mut sa = [0u8; 16];
        sa[0..2].copy_from_slice(&2u16.to_le_bytes());
        sa[2..4].copy_from_slice(&8080u16.to_be_bytes());
        sa[4..8].copy_from_slice(&[127, 0, 0, 1]);
        mem.write(64, &sa).unwrap();

        assert_eq!(
            call_op(
                &mut proc,
                abi,
                Operation::Connect,
                [fd, 64, 16, 0, 0, 0],
                &mut mem,
                &mut plat
            ),
            EINPROGRESS.wrapping_neg()
        );

        // epoll_wait(timeout=0) sees nothing while Pending.
        let ep = call_op(
            &mut proc,
            abi,
            Operation::EpollCreate1,
            [0; 6],
            &mut mem,
            &mut plat,
        );
        let mut ev = [0u8; 16];
        ev[0..4].copy_from_slice(&0x004u32.to_le_bytes()); // EPOLLOUT
        ev[abi.epoll_data_offset()..abi.epoll_data_offset() + 8].copy_from_slice(&fd.to_le_bytes());
        mem.write(128, &ev).unwrap();
        assert_eq!(
            call_op(
                &mut proc,
                abi,
                Operation::EpollCtl,
                [ep, 1, fd, 128, 0, 0],
                &mut mem,
                &mut plat
            ),
            0
        );
        assert_eq!(
            call_op(
                &mut proc,
                abi,
                Operation::EpollPwait,
                [ep, 256, 1, 0, 0, 0],
                &mut mem,
                &mut plat
            ),
            0
        );

        // Complete the handshake -> epoll_wait reports EPOLLOUT and SO_ERROR is 0.
        *plat.net.connect_state.lock() = ConnectProgress::Connected;
        assert_eq!(
            call_op(
                &mut proc,
                abi,
                Operation::EpollPwait,
                [ep, 256, 1, 0, 0, 0],
                &mut mem,
                &mut plat
            ),
            1
        );
        let mut out_ev = [0u8; 4];
        mem.read(256, &mut out_ev).unwrap();
        assert_eq!(u32::from_le_bytes(out_ev), 0x004);

        mem.write(320, &4u32.to_le_bytes()).unwrap();
        assert_eq!(
            call_op(
                &mut proc,
                abi,
                Operation::Getsockopt,
                [fd, 1, 4, 300, 320, 0],
                &mut mem,
                &mut plat
            ),
            0
        );
        let mut so_err = [0u8; 4];
        mem.read(300, &mut so_err).unwrap();
        assert_eq!(i32::from_le_bytes(so_err), 0);

        // IPv6 multicast returns EOPNOTSUPP (95) when multicast authority is granted.
        let udp_fd = call_op(
            &mut proc,
            abi,
            Operation::Socket,
            [10, 2, 0, 0, 0, 0],
            &mut mem,
            &mut plat,
        );
        assert_eq!(
            call_op(
                &mut proc,
                abi,
                Operation::Setsockopt,
                [udp_fd, 41, 20, 400, 20, 0],
                &mut mem,
                &mut plat
            ),
            95u64.wrapping_neg()
        );

        // Bad protocol and ENOTSOCK checks.
        assert_eq!(
            call_op(
                &mut proc,
                abi,
                Operation::Socket,
                [2, 1, 17, 0, 0, 0],
                &mut mem,
                &mut plat
            ),
            EPROTONOSUPPORT.wrapping_neg()
        );
        assert_eq!(
            call_op(
                &mut proc,
                abi,
                Operation::Listen,
                [ep, 1, 0, 0, 0, 0],
                &mut mem,
                &mut plat
            ),
            ENOTSOCK.wrapping_neg()
        );
    }
}

#[test]
fn socketpair_supports_nonblocking_peek_shutdown_and_pipe_sendfile() {
    let mut proc = new_process(Abi::X86_64);
    let mut mem = Memory::new(4096);
    let mut plat = Platform {
        net: MockNet::default(),
        now: 0,
    };
    assert_eq!(
        call_op(
            &mut proc,
            Abi::X86_64,
            Operation::Socketpair,
            [1, 1 | 0x0800, 0, 64, 0, 0],
            &mut mem,
            &mut plat,
        ),
        0
    );
    let mut fds = [0u8; 8];
    mem.read(64, &mut fds).unwrap();
    let fd0 = i32::from_le_bytes(fds[0..4].try_into().unwrap()) as u64;
    let fd1 = i32::from_le_bytes(fds[4..8].try_into().unwrap()) as u64;

    assert_eq!(
        call_op(
            &mut proc,
            Abi::X86_64,
            Operation::Recvfrom,
            [fd1, 128, 16, 0, 0, 0],
            &mut mem,
            &mut plat
        ),
        EAGAIN.wrapping_neg()
    );
    mem.write(200, b"hello").unwrap();
    assert_eq!(
        call_op(
            &mut proc,
            Abi::X86_64,
            Operation::Sendto,
            [fd0, 200, 5, 0, 0, 0],
            &mut mem,
            &mut plat
        ),
        5
    );
    // Peek leaves bytes intact.
    assert_eq!(
        call_op(
            &mut proc,
            Abi::X86_64,
            Operation::Recvfrom,
            [fd1, 128, 5, 0x02, 0, 0],
            &mut mem,
            &mut plat
        ),
        5
    );
    let mut out = [0u8; 5];
    mem.read(128, &mut out).unwrap();
    assert_eq!(&out, b"hello");
    assert_eq!(
        call_op(
            &mut proc,
            Abi::X86_64,
            Operation::Read,
            [fd1, 140, 5, 0, 0, 0],
            &mut mem,
            &mut plat
        ),
        5
    );
    mem.read(140, &mut out).unwrap();
    assert_eq!(&out, b"hello");

    // Shutdown write -> send returns EPIPE and peer reads EOF.
    assert_eq!(
        call_op(
            &mut proc,
            Abi::X86_64,
            Operation::Shutdown,
            [fd0, 1, 0, 0, 0, 0],
            &mut mem,
            &mut plat
        ),
        0
    );
    assert_eq!(
        call_op(
            &mut proc,
            Abi::X86_64,
            Operation::Sendto,
            [fd0, 200, 1, 0, 0, 0],
            &mut mem,
            &mut plat
        ),
        EPIPE.wrapping_neg()
    );
    assert_eq!(
        call_op(
            &mut proc,
            Abi::X86_64,
            Operation::Read,
            [fd1, 140, 5, 0, 0, 0],
            &mut mem,
            &mut plat
        ),
        0
    );
    // getpeername on unconnected UDP -> ENOTCONN.
    plat.net.allow_udp = true;
    let udp = call_op(
        &mut proc,
        Abi::X86_64,
        Operation::Socket,
        [2, 2, 0, 0, 0, 0],
        &mut mem,
        &mut plat,
    );
    mem.write(300, &16u32.to_le_bytes()).unwrap();
    assert_eq!(
        call_op(
            &mut proc,
            Abi::X86_64,
            Operation::Getpeername,
            [udp, 256, 300, 0, 0, 0],
            &mut mem,
            &mut plat
        ),
        ENOTCONN.wrapping_neg()
    );
}

#[test]
fn udp_recvmsg_sets_msg_trunc_and_recvmmsg_enforces_timeout_and_multicast_u8_options() {
    let mut proc = new_process(Abi::X86_64);
    let mut mem = Memory::new(4096);
    let mut plat = Platform {
        net: MockNet {
            allow_udp: true,
            allow_multicast: true,
            ..Default::default()
        },
        now: 1_000_000,
    };
    let udp = call_op(
        &mut proc,
        Abi::X86_64,
        Operation::Socket,
        [2, 2, 0, 0, 0, 0],
        &mut mem,
        &mut plat,
    );
    let mut sa = [0u8; 16];
    sa[0..2].copy_from_slice(&2u16.to_le_bytes());
    sa[4..8].copy_from_slice(&[127, 0, 0, 1]);
    mem.write(64, &sa).unwrap();
    assert_eq!(
        call_op(
            &mut proc,
            Abi::X86_64,
            Operation::Bind,
            [udp, 64, 16, 0, 0, 0],
            &mut mem,
            &mut plat,
        ),
        0
    );

    // 1-byte u8 options for IP_MULTICAST_TTL (33) and IP_MULTICAST_LOOP (34).
    mem.write(96, &[7u8]).unwrap();
    assert_eq!(
        call_op(
            &mut proc,
            Abi::X86_64,
            Operation::Setsockopt,
            [udp, 0, 33, 96, 1, 0],
            &mut mem,
            &mut plat,
        ),
        0
    );
    mem.write(97, &[0u8]).unwrap();
    assert_eq!(
        call_op(
            &mut proc,
            Abi::X86_64,
            Operation::Setsockopt,
            [udp, 0, 34, 97, 1, 0],
            &mut mem,
            &mut plat,
        ),
        0
    );
    mem.write(104, &4u32.to_le_bytes()).unwrap();
    assert_eq!(
        call_op(
            &mut proc,
            Abi::X86_64,
            Operation::Getsockopt,
            [udp, 0, 33, 100, 104, 0],
            &mut mem,
            &mut plat,
        ),
        0
    );
    let mut ttl_out = [0u8; 4];
    mem.read(100, &mut ttl_out).unwrap();
    assert_eq!(i32::from_le_bytes(ttl_out), 7);

    // Queue a 10-byte datagram and receive into a 4-byte iovec without MSG_TRUNC in input flags:
    // recvmsg must return 4 and set MSG_TRUNC (0x20) in msghdr.msg_flags.
    plat.net.udp_queue.lock().push((
        Bytes::from_static(b"0123456789"),
        SocketAddr {
            ip: IpAddr::V4([127, 0, 0, 1]),
            port: 5555,
        },
        10,
    ));
    let mut iov = [0u8; 16];
    iov[0..8].copy_from_slice(&300u64.to_le_bytes());
    iov[8..16].copy_from_slice(&4u64.to_le_bytes());
    mem.write(200, &iov).unwrap();
    let mut hdr = [0u8; 56];
    hdr[16..24].copy_from_slice(&200u64.to_le_bytes());
    hdr[24..32].copy_from_slice(&1u64.to_le_bytes());
    mem.write(400, &hdr).unwrap();
    assert_eq!(
        call_op(
            &mut proc,
            Abi::X86_64,
            Operation::Recvmsg,
            [udp, 400, 0, 0, 0, 0],
            &mut mem,
            &mut plat,
        ),
        4
    );
    let mut flags_out = [0u8; 4];
    mem.read(448, &mut flags_out).unwrap();
    assert_eq!(u32::from_le_bytes(flags_out) & 0x20, 0x20);
    // Blocking socket with no SO_RCVTIMEO passes u64::MAX (indefinite).
    assert_eq!(*plat.net.last_udp_timeout.lock(), Some(u64::MAX));

    // recvmmsg with a 500ms timespec passes 500_000_000ns and maps ETIMEDOUT -> EAGAIN.
    let mut ts = [0u8; 16];
    ts[0..8].copy_from_slice(&0i64.to_le_bytes());
    ts[8..16].copy_from_slice(&500_000_000i64.to_le_bytes());
    mem.write(600, &ts).unwrap();
    mem.write(700, &hdr).unwrap();
    assert_eq!(
        call_op(
            &mut proc,
            Abi::X86_64,
            Operation::Recvmmsg,
            [udp, 700, 1, 0, 600, 0],
            &mut mem,
            &mut plat,
        ),
        EAGAIN.wrapping_neg()
    );
    assert_eq!(*plat.net.last_udp_timeout.lock(), Some(500_000_000));
}

#[test]
fn sendfile_validates_fds_before_reading_and_honours_nonblocking_pipes() {
    let mut proc = new_process(Abi::X86_64);
    let mut mem = Memory::new(4096);
    let mut plat = Platform {
        net: MockNet::default(),
        now: 0,
    };
    // pipe2(fds, O_NONBLOCK)
    assert_eq!(
        call_op(
            &mut proc,
            Abi::X86_64,
            Operation::Pipe2,
            [64, 0x0800, 0, 0, 0, 0],
            &mut mem,
            &mut plat,
        ),
        0
    );
    let mut pfds = [0u8; 8];
    mem.read(64, &mut pfds).unwrap();
    let pr = i32::from_le_bytes(pfds[0..4].try_into().unwrap()) as u64;
    let pw = i32::from_le_bytes(pfds[4..8].try_into().unwrap()) as u64;

    // Non-blocking empty pipe -> sendfile returns EAGAIN instead of blocking.
    assert_eq!(
        call_op(
            &mut proc,
            Abi::X86_64,
            Operation::Sendfile,
            [1, pr, 0, 8, 0, 0],
            &mut mem,
            &mut plat,
        ),
        EAGAIN.wrapping_neg()
    );

    // Write bytes to pipe, then call sendfile with an invalid out_fd (pr is read-only):
    // must return EINVAL (22) without consuming bytes from the pipe.
    mem.write(128, b"keep").unwrap();
    assert_eq!(
        call_op(
            &mut proc,
            Abi::X86_64,
            Operation::Write,
            [pw, 128, 4, 0, 0, 0],
            &mut mem,
            &mut plat,
        ),
        4
    );
    assert_eq!(
        call_op(
            &mut proc,
            Abi::X86_64,
            Operation::Sendfile,
            [pr, pr, 0, 4, 0, 0],
            &mut mem,
            &mut plat,
        ),
        22u64.wrapping_neg()
    );
    // Bytes are still intact in the pipe.
    assert_eq!(
        call_op(
            &mut proc,
            Abi::X86_64,
            Operation::Read,
            [pr, 200, 4, 0, 0, 0],
            &mut mem,
            &mut plat,
        ),
        4
    );
    let mut kept = [0u8; 4];
    mem.read(200, &mut kept).unwrap();
    assert_eq!(&kept, b"keep");
}
