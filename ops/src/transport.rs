//! Unified async RPC transport layer (`serial://`, `vsock://`, `helios://`, `helios+tls://`,
//! `tcp://`) driving `helios-wit-rpc` (`Endpoint` + `PeerHandle`) with unified Ed25519 +
//! `postcard` authentication and pure-Rust TLS 1.3 + RFC 8446 channel binding.

use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::os::unix::fs::FileTypeExt as _;
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_io::Async;
use async_net::TcpStream;
use futures_io::{AsyncRead, AsyncWrite};
use futures_util::AsyncReadExt as _;
use helios_inspector_protocol::auth::{ClientIdentity, TransportKind, client_handshake};
use helios_inspector_protocol::tls::{TlsClientStream, build_client_config};
use helios_wit_rpc::{Endpoint, PeerHandle};

use crate::error::TransportError;
use crate::target::TargetUri;

const SOCKET_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const SOCKET_CONNECT_POLL: Duration = Duration::from_millis(50);

/// Read half of an async RPC byte transport.
pub trait RpcRead: AsyncRead + Unpin + Send {}
/// Write half of an async RPC byte transport.
pub trait RpcWrite: AsyncWrite + Unpin + Send {}

impl<T> RpcRead for T where T: AsyncRead + Unpin + Send {}
impl<T> RpcWrite for T where T: AsyncWrite + Unpin + Send {}

/// Boxed async read half shared across serial, Unix socket, vsock, and TCP/TLS transports.
pub type RpcReader = Box<dyn RpcRead>;
/// Boxed async write half shared across serial, Unix socket, vsock, and TCP/TLS transports.
pub type RpcWriter = Box<dyn RpcWrite>;

/// Underlying `helios-wit-rpc` connection handle used by [`RpcConnection`].
pub type ProtocolClient = PeerHandle;

/// Authentication and transport security mode for [`RpcConnection::connect`].
#[derive(Debug, Clone, Default)]
pub enum SecurityMode {
    /// Direct unauthenticated stream (for local mock tests or pre-authenticated links).
    ///
    /// `helios://` and `helios+tls://` refuse `Plain` with [`TransportError::AuthRequired`]
    /// rather than downgrading to cleartext.
    #[default]
    Plain,
    /// Unified Ed25519 + `postcard` authentication (static key or CA-signed short-lived
    /// `CapabilityCert` with optional offline monotonic attenuation), paired with pure-Rust
    /// TLS 1.3 + RFC 8446 `tls-exporter` channel binding on `helios://` / `helios+tls://`.
    Authenticated {
        identity: Box<ClientIdentity>,
        expected_machine_public_key: Option<[u8; 32]>,
    },
}

/// Guard keeping the connection's background frame router alive until the last
/// [`RpcConnection`] handle is dropped.
enum FrameDriver {
    /// Tokio async task spawned on the active runtime (zero `block_on`).
    TokioTask(tokio::task::JoinHandle<()>),
    /// External driver already owned by the caller (e.g. `inspector`'s `FrameReader`).
    External(
        #[expect(dead_code, reason = "opaque guard held for drop lifetime")] Arc<dyn Send + Sync>,
    ),
}

impl Drop for FrameDriver {
    fn drop(&mut self) {
        if let Self::TokioTask(handle) = self {
            handle.abort();
        }
    }
}

/// Live, cheaply cloneable async RPC connection to a Helios guest or node.
#[derive(Clone)]
pub struct RpcConnection {
    client: ProtocolClient,
    _driver: Arc<FrameDriver>,
}

impl RpcConnection {
    /// Construct an [`RpcConnection`] from raw async read/write halves and spawn
    /// the WIT-RPC frame multiplexer on the current Tokio runtime (zero `block_on`).
    #[must_use]
    pub fn from_split(read: RpcReader, write: RpcWriter) -> Self {
        let endpoint = Endpoint::new(read, write, ());
        let client = endpoint.handle();
        let handle = tokio::spawn(async move {
            let _ = endpoint.drive().await;
        });
        Self {
            client,
            _driver: Arc::new(FrameDriver::TokioTask(handle)),
        }
    }

    /// Wrap an already-driven [`ProtocolClient`] along with its driver lifetime guard.
    #[must_use]
    pub fn from_external(client: ProtocolClient, driver_guard: Arc<dyn Send + Sync>) -> Self {
        Self {
            client,
            _driver: Arc::new(FrameDriver::External(driver_guard)),
        }
    }

    /// Connect asynchronously to `uri` using the requested [`SecurityMode`].
    pub async fn connect(uri: &TargetUri, security: &SecurityMode) -> Result<Self, TransportError> {
        match uri {
            TargetUri::Serial { path, baud } => {
                let (mut read, mut write) = open_serial(path, *baud).await?;
                if let SecurityMode::Authenticated {
                    identity,
                    expected_machine_public_key,
                } = security
                {
                    client_handshake(
                        &mut read,
                        &mut write,
                        TransportKind::Serial,
                        identity,
                        *expected_machine_public_key,
                        None,
                        None,
                    )
                    .await
                    .map_err(|source| TransportError::AuthHandshake {
                        endpoint: uri.to_uri_string(),
                        source,
                    })?;
                }
                Ok(Self::from_split(read, write))
            }
            TargetUri::Vsock { cid, port } => {
                let (mut read, mut write) = open_vsock(*cid, *port).await?;
                if let SecurityMode::Authenticated {
                    identity,
                    expected_machine_public_key,
                } = security
                {
                    client_handshake(
                        &mut read,
                        &mut write,
                        TransportKind::Vsock,
                        identity,
                        *expected_machine_public_key,
                        None,
                        None,
                    )
                    .await
                    .map_err(|source| TransportError::AuthHandshake {
                        endpoint: uri.to_uri_string(),
                        source,
                    })?;
                }
                Ok(Self::from_split(read, write))
            }
            TargetUri::Helios { host, port, tls } => {
                if *tls {
                    let SecurityMode::Authenticated {
                        identity,
                        expected_machine_public_key,
                    } = security
                    else {
                        return Err(TransportError::AuthRequired {
                            host: host.clone(),
                            port: *port,
                        });
                    };
                    let address = format_tcp_addr(host, *port);
                    let tcp = TcpStream::connect(&address).await.map_err(|source| {
                        TransportError::ConnectTcp {
                            address: address.clone(),
                            source,
                        }
                    })?;
                    let tls_cfg =
                        build_client_config().map_err(|source| TransportError::TlsHandshake {
                            address: address.clone(),
                            source,
                        })?;
                    let tls_stream = TlsClientStream::connect(tcp.clone(), tcp, tls_cfg, host)
                        .await
                        .map_err(|source| TransportError::TlsHandshake {
                            address: address.clone(),
                            source,
                        })?;
                    let tls_binding = tls_stream.binding();
                    let (mut read, mut write) = tls_stream.split();
                    client_handshake(
                        &mut read,
                        &mut write,
                        TransportKind::TcpTls,
                        identity,
                        *expected_machine_public_key,
                        Some(tls_binding.channel_binding),
                        Some(tls_binding.peer_cert_sha256),
                    )
                    .await
                    .map_err(|source| TransportError::AuthHandshake {
                        endpoint: uri.to_uri_string(),
                        source,
                    })?;
                    Ok(Self::from_split(Box::new(read), Box::new(write)))
                } else {
                    let (mut read, mut write) = open_tcp(host, *port).await?;
                    if let SecurityMode::Authenticated {
                        identity,
                        expected_machine_public_key,
                    } = security
                    {
                        client_handshake(
                            &mut read,
                            &mut write,
                            TransportKind::Vsock,
                            identity,
                            *expected_machine_public_key,
                            None,
                            None,
                        )
                        .await
                        .map_err(|source| {
                            TransportError::AuthHandshake {
                                endpoint: uri.to_uri_string(),
                                source,
                            }
                        })?;
                    }
                    Ok(Self::from_split(read, write))
                }
            }
        }
    }

    /// Borrow the underlying `helios-wit-rpc` [`PeerHandle`].
    #[must_use]
    pub fn client(&self) -> &ProtocolClient {
        &self.client
    }
}

fn format_tcp_addr(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

async fn open_tcp(host: &str, port: u16) -> Result<(RpcReader, RpcWriter), TransportError> {
    let address = format_tcp_addr(host, port);
    let stream =
        TcpStream::connect(&address)
            .await
            .map_err(|source| TransportError::ConnectTcp {
                address: address.clone(),
                source,
            })?;
    let read_stream = stream.clone();
    Ok((Box::new(read_stream), Box::new(stream)))
}

async fn open_serial(device: &str, baud: u32) -> Result<(RpcReader, RpcWriter), TransportError> {
    let is_socket = match std::fs::metadata(device) {
        Ok(metadata) => metadata.file_type().is_socket(),
        Err(err) if err.kind() == io::ErrorKind::NotFound => device.ends_with(".sock"),
        Err(source) => {
            return Err(TransportError::InspectSerial {
                device: device.to_owned(),
                source,
            });
        }
    };

    if is_socket {
        open_unix_socket(device).await
    } else {
        open_tty(device, baud)
    }
}

async fn open_unix_socket(path: &str) -> Result<(RpcReader, RpcWriter), TransportError> {
    let deadline = Instant::now() + SOCKET_CONNECT_TIMEOUT;
    let socket = loop {
        match UnixStream::connect(path) {
            Ok(socket) => break socket,
            Err(err)
                if matches!(
                    err.kind(),
                    io::ErrorKind::ConnectionRefused
                        | io::ErrorKind::NotFound
                        | io::ErrorKind::AddrNotAvailable
                ) && Instant::now() < deadline =>
            {
                tokio::time::sleep(SOCKET_CONNECT_POLL).await;
            }
            Err(source) => {
                return Err(TransportError::ConnectUnix {
                    path: path.to_owned(),
                    source,
                });
            }
        }
    };
    socket
        .set_nonblocking(true)
        .map_err(|source| TransportError::ConfigureNonblocking {
            endpoint: path.to_owned(),
            source,
        })?;
    let read = socket
        .try_clone()
        .map_err(|source| TransportError::CloneHandle {
            endpoint: path.to_owned(),
            source,
        })?;
    Ok((
        Box::new(Async::new(AsyncUnixSocket(read)).map_err(|source| {
            TransportError::RegisterAsync {
                endpoint: path.to_owned(),
                source,
            }
        })?),
        Box::new(Async::new(AsyncUnixSocket(socket)).map_err(|source| {
            TransportError::RegisterAsync {
                endpoint: path.to_owned(),
                source,
            }
        })?),
    ))
}

fn open_tty(device: &str, baud: u32) -> Result<(RpcReader, RpcWriter), TransportError> {
    let port = serialport::new(device, baud)
        .open_native()
        .map_err(|source| TransportError::OpenTty {
            device: device.to_owned(),
            source,
        })?;
    let read_port = port
        .try_clone_native()
        .map_err(|source| TransportError::CloneTty {
            device: device.to_owned(),
            source,
        })?;
    Ok((
        Box::new(Async::new(AsyncSerialPort(read_port)).map_err(|source| {
            TransportError::RegisterAsync {
                endpoint: device.to_owned(),
                source,
            }
        })?),
        Box::new(Async::new(AsyncSerialPort(port)).map_err(|source| {
            TransportError::RegisterAsync {
                endpoint: device.to_owned(),
                source,
            }
        })?),
    ))
}

#[cfg(target_os = "linux")]
async fn open_vsock(cid: u32, port: u32) -> Result<(RpcReader, RpcWriter), TransportError> {
    let deadline = Instant::now() + SOCKET_CONNECT_TIMEOUT;
    let stream = loop {
        match vsock::VsockStream::connect_with_cid_port(cid, port) {
            Ok(stream) => break stream,
            Err(err)
                if matches!(
                    err.kind(),
                    io::ErrorKind::ConnectionRefused
                        | io::ErrorKind::ConnectionReset
                        | io::ErrorKind::NotFound
                        | io::ErrorKind::AddrNotAvailable
                ) && Instant::now() < deadline =>
            {
                tokio::time::sleep(SOCKET_CONNECT_POLL).await;
            }
            Err(source) => return Err(TransportError::ConnectVsock { cid, port, source }),
        }
    };
    stream
        .set_nonblocking(true)
        .map_err(|source| TransportError::ConfigureNonblocking {
            endpoint: format!("vsock://{cid}:{port}"),
            source,
        })?;
    let read = stream
        .try_clone()
        .map_err(|source| TransportError::CloneHandle {
            endpoint: format!("vsock://{cid}:{port}"),
            source,
        })?;
    Ok((
        Box::new(Async::new(AsyncVsockStream(read)).map_err(|source| {
            TransportError::RegisterAsync {
                endpoint: format!("vsock://{cid}:{port}"),
                source,
            }
        })?),
        Box::new(Async::new(AsyncVsockStream(stream)).map_err(|source| {
            TransportError::RegisterAsync {
                endpoint: format!("vsock://{cid}:{port}"),
                source,
            }
        })?),
    ))
}

#[cfg(not(target_os = "linux"))]
async fn open_vsock(_cid: u32, _port: u32) -> Result<(RpcReader, RpcWriter), TransportError> {
    Err(TransportError::VsockUnsupported)
}

struct AsyncUnixSocket(UnixStream);

unsafe impl async_io::IoSafe for AsyncUnixSocket {}

impl AsFd for AsyncUnixSocket {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}

impl io::Read for AsyncUnixSocket {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        io::Read::read(&mut self.0, buf)
    }
}

impl io::Write for AsyncUnixSocket {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        io::Write::write(&mut self.0, buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        io::Write::flush(&mut self.0)
    }
}

struct AsyncSerialPort(serialport::TTYPort);

unsafe impl async_io::IoSafe for AsyncSerialPort {}

impl AsFd for AsyncSerialPort {
    fn as_fd(&self) -> BorrowedFd<'_> {
        // SAFETY: `self.0` stays alive for the borrow lifetime of `&self`.
        unsafe { BorrowedFd::borrow_raw(self.0.as_raw_fd()) }
    }
}

impl io::Read for AsyncSerialPort {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        io::Read::read(&mut self.0, buf)
    }
}

impl io::Write for AsyncSerialPort {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        io::Write::write(&mut self.0, buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        io::Write::flush(&mut self.0)
    }
}

#[cfg(target_os = "linux")]
struct AsyncVsockStream(vsock::VsockStream);

#[cfg(target_os = "linux")]
unsafe impl async_io::IoSafe for AsyncVsockStream {}

#[cfg(target_os = "linux")]
impl AsFd for AsyncVsockStream {
    fn as_fd(&self) -> BorrowedFd<'_> {
        unsafe { BorrowedFd::borrow_raw(self.0.as_raw_fd()) }
    }
}

#[cfg(target_os = "linux")]
impl io::Read for AsyncVsockStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        io::Read::read(&mut self.0, buf)
    }
}

#[cfg(target_os = "linux")]
impl io::Write for AsyncVsockStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        io::Write::write(&mut self.0, buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        io::Write::flush(&mut self.0)
    }
}
