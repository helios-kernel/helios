//! Async networking helpers for Helios component programs.

use std::io;
use std::string::String;
use std::time::Duration;
use std::vec::Vec;

use crate::bindings::helios::system::net as raw;

const DEFAULT_TCP_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_DNS_TIMEOUT: Duration = Duration::from_secs(5);
/// Default TCP read size used by convenience readers.
pub const DEFAULT_READ_CHUNK_BYTES: usize = 1024 * 1024;

pub use crate::bindings::helios::system::net::{
    DnsError, DnsErrorKind, IpAddress, Ipv4Address, Ipv6Address, PingErrorKind, PingReply,
    TcpErrorKind, UdpDatagram, UdpErrorKind,
};

/// Usable RFC 9460 Type 65 (`HTTPS`) service parameters resolved for an origin.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpsRecord {
    /// ALPN protocol identifiers from `SvcParamKey` 1, e.g. `["h2", "h3"]`.
    pub alpn: Vec<String>,
    /// Alternative endpoint port from `SvcParamKey` 3, when overridden.
    pub port: Option<u16>,
    /// Minimum TTL across the answer chain.
    pub ttl: Duration,
}

/// Queries RFC 9460 Type 65 (`HTTPS`) DNS records for `host:port` using the
/// default DNS lookup timeout.
///
/// Returns `Ok(None)` when no usable `HTTPS` record exists (`NODATA`,
/// `NXDOMAIN`, IP literal, or `AliasMode` `.`).
pub async fn resolve_https(host: &str, port: u16) -> io::Result<Option<HttpsRecord>> {
    resolve_https_timeout(host, port, DEFAULT_DNS_TIMEOUT).await
}

/// Queries RFC 9460 Type 65 (`HTTPS`) DNS records for `host:port` bounded by
/// `timeout`.
pub async fn resolve_https_timeout(
    host: &str,
    port: u16,
    timeout: Duration,
) -> io::Result<Option<HttpsRecord>> {
    raw::resolve_https(host.to_owned(), port, duration_to_nanos(timeout))
        .await
        .map(|record| {
            record.map(|record| HttpsRecord {
                alpn: record.alpn,
                port: record.port,
                ttl: Duration::from_nanos(record.ttl),
            })
        })
        .map_err(map_dns_error)
}

/// Outbound TCP client stream backed by the kernel network service.
pub struct TcpStream {
    raw: raw::TcpStream,
    timeout: Duration,
}

/// Bound listening TCP socket backed by the kernel network service.
pub struct TcpListener {
    raw: raw::TcpListener,
    timeout: Duration,
}

/// Bound UDP socket backed by the kernel network service.
pub struct UdpSocket {
    raw: raw::UdpSocket,
    timeout: Duration,
}

pub async fn ping(host: &str, timeout: Duration) -> io::Result<PingReply> {
    raw::ping(host.to_owned(), duration_to_nanos(timeout))
        .await
        .map_err(map_ping_error)
}

impl TcpStream {
    /// Wraps a raw WIT `tcp-stream` resource (e.g. from `take_inherited_sockets`).
    pub fn from_raw(raw: raw::TcpStream) -> Self {
        Self {
            raw,
            timeout: DEFAULT_TCP_TIMEOUT,
        }
    }

    /// Unwraps the underlying WIT `tcp-stream` resource for transfer into a
    /// spawned child via `InheritedSocket::TcpStream`.
    pub fn into_raw(self) -> raw::TcpStream {
        self.raw
    }

    /// Connects to `host:port` using the default operation timeout.
    pub async fn connect(host: &str, port: u16) -> io::Result<Self> {
        Self::connect_timeout(host, port, DEFAULT_TCP_TIMEOUT).await
    }

    /// Connects to `host:port` and stores `timeout` as the default timeout for
    /// subsequent read and write operations.
    pub async fn connect_timeout(host: &str, port: u16, timeout: Duration) -> io::Result<Self> {
        let raw = raw::tcp_connect(host.to_owned(), port, duration_to_nanos(timeout))
            .await
            .map_err(map_tcp_error)?;
        Ok(Self { raw, timeout })
    }

    /// Returns a copy of the current default operation timeout.
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Replaces the default timeout used by [`read`](Self::read),
    /// [`read_to_end`](Self::read_to_end), and [`write_all`](Self::write_all).
    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
    }

    /// Reads one chunk from the peer.
    ///
    /// `Ok(None)` indicates EOF.
    pub async fn read(&self, max_bytes: usize) -> io::Result<Option<Vec<u8>>> {
        let max_bytes = u32::try_from(max_bytes).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "tcp read size does not fit into u32",
            )
        })?;
        self.raw
            .read(max_bytes, duration_to_nanos(self.timeout))
            .await
            .map_err(map_tcp_error)
    }

    /// Reads until EOF and returns the accumulated bytes.
    pub async fn read_to_end(&self) -> io::Result<Vec<u8>> {
        let mut output = Vec::new();
        loop {
            match self.read(DEFAULT_READ_CHUNK_BYTES).await? {
                Some(bytes) => output.extend_from_slice(&bytes),
                None => return Ok(output),
            }
        }
    }

    /// Writes `bytes` completely before returning.
    pub async fn write_all(&self, bytes: &[u8]) -> io::Result<()> {
        let written = self
            .raw
            .write(bytes.to_vec(), duration_to_nanos(self.timeout))
            .await
            .map_err(map_tcp_error)?;
        assert!(
            usize::try_from(written).ok() == Some(bytes.len()),
            "kernel tcp stream reported partial write for a complete write syscall"
        );
        Ok(())
    }

    /// Releases the kernel-side TCP socket immediately.
    pub async fn close(&self) -> io::Result<()> {
        self.raw.close().await.map_err(map_tcp_error)
    }
}

impl TcpListener {
    /// Binds a TCP listener to `local_address:local_port` (`0` requests an
    /// ephemeral port).
    pub async fn listen(
        local_address: IpAddress,
        local_port: u16,
        backlog: u16,
    ) -> io::Result<Self> {
        let raw = raw::tcp_listen(local_address, local_port, backlog)
            .await
            .map_err(map_tcp_error)?;
        Ok(Self {
            raw,
            timeout: DEFAULT_TCP_TIMEOUT,
        })
    }

    /// Wraps a raw WIT `tcp-listener` resource (e.g. from `take_inherited_sockets`).
    pub fn from_raw(raw: raw::TcpListener) -> Self {
        Self {
            raw,
            timeout: DEFAULT_TCP_TIMEOUT,
        }
    }

    /// Unwraps the underlying WIT `tcp-listener` resource for transfer into a
    /// spawned child via `InheritedSocket::Tcp`.
    pub fn into_raw(self) -> raw::TcpListener {
        self.raw
    }

    /// Returns the local IP address and port this listener is bound to.
    pub fn local_address(&self) -> (IpAddress, u16) {
        self.raw.local_address()
    }

    /// Returns a copy of the current default operation timeout.
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Replaces the default timeout used by [`accept`](Self::accept).
    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
    }

    /// Waits up to `timeout` for an incoming connection to be queued without
    /// consuming it. Returns `Ok(true)` when ready or `Ok(false)` on timeout.
    pub async fn wait_readable(&self, timeout: Duration) -> io::Result<bool> {
        self.raw
            .wait_readable(duration_to_nanos(timeout))
            .await
            .map_err(map_tcp_error)
    }

    /// Accepts the next incoming TCP connection.
    pub async fn accept(&self) -> io::Result<TcpStream> {
        let raw = self
            .raw
            .accept(duration_to_nanos(self.timeout))
            .await
            .map_err(map_tcp_error)?;
        Ok(TcpStream {
            raw,
            timeout: self.timeout,
        })
    }

    /// Releases the bound TCP listener immediately.
    pub async fn close(&self) -> io::Result<()> {
        self.raw.close().await.map_err(map_tcp_error)
    }
}

impl UdpSocket {
    /// Binds a UDP socket to `local_port` using the default operation timeout.
    pub async fn bind(local_port: u16) -> io::Result<Self> {
        let raw = raw::udp_bind(local_port).await.map_err(map_udp_error)?;
        Ok(Self {
            raw,
            timeout: DEFAULT_TCP_TIMEOUT,
        })
    }

    /// Returns a copy of the current default operation timeout.
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Replaces the default timeout used by [`receive`](Self::receive) and
    /// [`send`](Self::send).
    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
    }

    /// Receives at most one UDP datagram.
    ///
    /// `Ok(None)` indicates that the kernel-side socket was closed.
    pub async fn receive(&self, max_bytes: usize) -> io::Result<Option<UdpDatagram>> {
        let max_bytes = u32::try_from(max_bytes).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "udp read size does not fit into u32",
            )
        })?;
        self.raw
            .receive(max_bytes, duration_to_nanos(self.timeout))
            .await
            .map_err(map_udp_error)
    }

    /// Sends one UDP datagram to `host:port`.
    pub async fn send(&self, host: &str, port: u16, bytes: &[u8]) -> io::Result<()> {
        let written = self
            .raw
            .send(
                host.to_owned(),
                port,
                bytes.to_vec(),
                duration_to_nanos(self.timeout),
            )
            .await
            .map_err(map_udp_error)?;
        assert!(
            usize::try_from(written).ok() == Some(bytes.len()),
            "kernel udp socket reported partial datagram write"
        );
        Ok(())
    }

    /// Releases the kernel-side UDP socket immediately.
    pub async fn close(&self) -> io::Result<()> {
        self.raw.close().await.map_err(map_udp_error)
    }
}

fn duration_to_nanos(duration: Duration) -> u64 {
    duration
        .as_nanos()
        .try_into()
        .expect("duration does not fit into wasi nanoseconds")
}

fn map_ping_error(error: raw::PingError) -> io::Error {
    io::Error::other(format!("{:?}: {}", error.kind, error.detail))
}

fn map_tcp_error(error: raw::TcpError) -> io::Error {
    let kind = match error.kind {
        TcpErrorKind::Timeout => io::ErrorKind::TimedOut,
        TcpErrorKind::ConnectionReset => io::ErrorKind::ConnectionReset,
        TcpErrorKind::ConnectionAborted => io::ErrorKind::ConnectionAborted,
        TcpErrorKind::UnresolvedHost => io::ErrorKind::NotFound,
        TcpErrorKind::PermissionDenied => io::ErrorKind::PermissionDenied,
        TcpErrorKind::AddressInUse => io::ErrorKind::AddrInUse,
        TcpErrorKind::Unavailable => io::ErrorKind::ConnectionAborted,
        TcpErrorKind::Internal => io::ErrorKind::Other,
    };
    io::Error::new(kind, format!("{:?}: {}", error.kind, error.detail))
}

fn map_udp_error(error: raw::UdpError) -> io::Error {
    let kind = match error.kind {
        UdpErrorKind::Timeout => io::ErrorKind::TimedOut,
        UdpErrorKind::UnresolvedHost => io::ErrorKind::NotFound,
        UdpErrorKind::PermissionDenied => io::ErrorKind::PermissionDenied,
        UdpErrorKind::Unavailable => io::ErrorKind::ConnectionAborted,
        UdpErrorKind::Internal => io::ErrorKind::Other,
    };
    io::Error::new(kind, format!("{:?}: {}", error.kind, error.detail))
}

fn map_dns_error(error: raw::DnsError) -> io::Error {
    let kind = match error.kind {
        DnsErrorKind::Timeout => io::ErrorKind::TimedOut,
        DnsErrorKind::UnresolvedHost => io::ErrorKind::NotFound,
        DnsErrorKind::PermissionDenied => io::ErrorKind::PermissionDenied,
        DnsErrorKind::Unavailable => io::ErrorKind::ConnectionAborted,
        DnsErrorKind::Internal => io::ErrorKind::Other,
    };
    io::Error::new(kind, format!("{:?}: {}", error.kind, error.detail))
}
