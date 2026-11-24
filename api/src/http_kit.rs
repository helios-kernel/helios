//! `http-kit-io` over `wasi:sockets` and `wasi:clocks`.
//!
//! [`HeliosNet`] is the implementation of the capability traits an HTTP
//! client asks of its platform: [`Dial`] opens TCP connections, [`Datagram`]
//! binds UDP sockets, [`Resolve`] looks names up, and [`Timer`] waits on the
//! monotonic clock.
//! [`HeliosExecutor`] runs the client's local tasks on the component's
//! executor.
//!
//! Everything is a thin mapping onto the interfaces the kernel serves to a
//! component: nothing here buffers, retries or times out on its own, because
//! the client above it owns those policies. A connection reads through the
//! stream `tcp-socket.receive` returns and writes through the one handed to
//! `tcp-socket.send`; closing the write side is dropping that stream, which
//! `wasi:sockets` defines as `shutdown(SHUT_WR)`.

use std::borrow::Borrow;
use std::fs::File;
use std::future::Future;
use std::io::{self, Read as _, Seek as _, SeekFrom};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::num::NonZeroU16;
#[cfg(unix)]
use std::path::Path;
use std::rc::Rc;
use std::time::Instant;

use executor_core::LocalExecutor;
use executor_core::async_task::{AsyncTask, spawn_local};
use futures_lite::stream::{Stream, once_future};
#[cfg(unix)]
use http_kit_io::DialUnix;
#[cfg(any(target_os = "linux", target_os = "android"))]
use http_kit_io::splice::{FilledPipe, Pipe, Spliced};
use http_kit_io::{
    Answer, BufResult, Datagram, DatagramSocket, Dial, IoBuf, IoBufMut, IoVectoredBuf, NoBuf, Read,
    ReadAhead, ReadOwned, Received, RecvMeta, Resolve, SendFile, SpliceRead, SpliceWrite, Split,
    TcpOptions, Timer, Write,
};
use thiserror::Error;
use wit_bindgen::rt::async_support::{FutureReader, StreamReader, StreamWriter};

use crate::bindings::wasi::clocks::monotonic_clock;
use crate::bindings::wasi::sockets::ip_name_lookup::{self, ErrorCode as LookupCode};
use crate::bindings::wasi::sockets::types::{
    ErrorCode as SocketCode, IpAddress, IpAddressFamily, IpSocketAddress, Ipv4SocketAddress,
    Ipv6SocketAddress, TcpSocket, UdpSocket as WasiUdpSocket,
};
use crate::bindings::wit_stream;
use crate::stream_closed;

/// Bytes one read asks the receive stream for.
///
/// It bounds the buffer a read lends to its caller; a larger read is served
/// by several, as a socket would.
const RECEIVE_CHUNK_BYTES: usize = 64 * 1024;

/// A `wasi:sockets` failure, kept as the source of the [`io::Error`] it
/// became so a caller can still ask which code the host answered.
#[derive(Debug, Error)]
pub enum SocketError {
    /// A `wasi:sockets/types` operation failed.
    #[error("wasi:sockets: {0:?}")]
    Socket(SocketCode),
    /// A `wasi:sockets/ip-name-lookup` operation failed.
    #[error("wasi:sockets name lookup: {0:?}")]
    Lookup(LookupCode),
}

/// The [`io::ErrorKind`] each `wasi:sockets/types` error code stands for.
///
/// Callers above this layer decide on the kind alone: `remote-unreachable` is
/// a host or network that cannot be reached, `access-denied` is a refusal by
/// policy, and `timeout` is the host's own deadline.
fn socket_error(code: SocketCode) -> io::Error {
    let kind = match &code {
        SocketCode::AccessDenied => io::ErrorKind::PermissionDenied,
        SocketCode::NotSupported => io::ErrorKind::Unsupported,
        SocketCode::InvalidArgument => io::ErrorKind::InvalidInput,
        SocketCode::OutOfMemory => io::ErrorKind::OutOfMemory,
        SocketCode::Timeout => io::ErrorKind::TimedOut,
        SocketCode::InvalidState => io::ErrorKind::InvalidInput,
        SocketCode::AddressNotBindable => io::ErrorKind::AddrNotAvailable,
        SocketCode::AddressInUse => io::ErrorKind::AddrInUse,
        SocketCode::RemoteUnreachable => io::ErrorKind::HostUnreachable,
        SocketCode::ConnectionRefused => io::ErrorKind::ConnectionRefused,
        SocketCode::ConnectionBroken => io::ErrorKind::BrokenPipe,
        SocketCode::ConnectionReset => io::ErrorKind::ConnectionReset,
        SocketCode::ConnectionAborted => io::ErrorKind::ConnectionAborted,
        SocketCode::DatagramTooLarge => io::ErrorKind::InvalidInput,
        SocketCode::Other(_) => io::ErrorKind::Other,
    };
    io::Error::new(kind, SocketError::Socket(code))
}

/// The [`io::ErrorKind`] each `wasi:sockets/ip-name-lookup` error code stands
/// for. A name that does not exist is [`io::ErrorKind::NotFound`], as
/// [`Resolve`] requires.
fn lookup_error(code: LookupCode) -> io::Error {
    let kind = match &code {
        LookupCode::AccessDenied => io::ErrorKind::PermissionDenied,
        LookupCode::InvalidArgument => io::ErrorKind::InvalidInput,
        LookupCode::NameUnresolvable => io::ErrorKind::NotFound,
        LookupCode::TemporaryResolverFailure
        | LookupCode::PermanentResolverFailure
        | LookupCode::Other(_) => io::ErrorKind::Other,
    };
    io::Error::new(kind, SocketError::Lookup(code))
}

/// The `http-kit-io` implementation of a Helios component: a zero-sized
/// handle, free to copy, over the host's `wasi:sockets` and monotonic clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct HeliosNet;

impl Dial for HeliosNet {
    type Connection = TcpConnection;

    async fn connect(&self, addr: SocketAddr) -> io::Result<TcpConnection> {
        let socket = TcpSocket::create(address_family(addr)).map_err(socket_error)?;
        socket
            .connect(to_wasi_address(addr))
            .await
            .map_err(socket_error)?;
        let (receive, received) = socket.receive();
        let (sender, outgoing) = wit_stream::new::<u8>();
        let sent = socket.send(outgoing);
        let socket = Rc::new(socket);
        Ok(TcpConnection {
            reader: ReadHalf {
                stream: receive,
                outcome: Some(received),
                _socket: Rc::clone(&socket),
            },
            writer: WriteHalf {
                stream: Some(sender),
                outcome: Some(sent),
                _socket: socket,
            },
        })
    }
}

impl Datagram for HeliosNet {
    type UdpSocket = UdpSocket;

    async fn bind_udp(&self, addr: SocketAddr) -> io::Result<UdpSocket> {
        let socket = WasiUdpSocket::create(address_family(addr)).map_err(socket_error)?;
        socket.bind(to_wasi_address(addr)).map_err(socket_error)?;
        Ok(UdpSocket { socket })
    }
}

/// `wasi:sockets` has no Unix-domain sockets, so every dial is refused as
/// [`io::ErrorKind::Unsupported`]. The trait is asked for only where the
/// crate is built for a Unix host.
#[cfg(unix)]
impl DialUnix for HeliosNet {
    type UnixConnection = TcpConnection;

    async fn connect_unix(&self, _path: &Path) -> io::Result<TcpConnection> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "wasi:sockets has no Unix-domain sockets",
        ))
    }
}

impl Resolve for HeliosNet {
    /// One [`Answer::Ranked`]: `resolve-addresses` has no family parameter,
    /// and the host's answer is the addresses in the order it would connect
    /// to them.
    fn lookup(&self, host: &str) -> impl Stream<Item = Answer> {
        let host = host.to_owned();
        once_future(async move {
            Answer::Ranked(
                ip_name_lookup::resolve_addresses(host)
                    .await
                    .map(|addresses| addresses.into_iter().map(from_wasi_ip).collect())
                    .map_err(lookup_error),
            )
        })
    }
}

impl Timer for HeliosNet {
    async fn sleep_until(&self, deadline: Instant) {
        let wait = deadline.saturating_duration_since(Instant::now());
        // A wait longer than `u64` nanoseconds (584 years) is never reached.
        let nanos = u64::try_from(wait.as_nanos()).unwrap_or(u64::MAX);
        monotonic_clock::wait_for(nanos).await;
    }
}

fn address_family(addr: SocketAddr) -> IpAddressFamily {
    match addr {
        SocketAddr::V4(_) => IpAddressFamily::Ipv4,
        SocketAddr::V6(_) => IpAddressFamily::Ipv6,
    }
}

fn to_wasi_address(addr: SocketAddr) -> IpSocketAddress {
    match addr {
        SocketAddr::V4(addr) => IpSocketAddress::Ipv4(Ipv4SocketAddress {
            port: addr.port(),
            address: addr.ip().octets().into(),
        }),
        SocketAddr::V6(addr) => IpSocketAddress::Ipv6(Ipv6SocketAddress {
            port: addr.port(),
            flow_info: addr.flowinfo(),
            address: addr.ip().segments().into(),
            scope_id: addr.scope_id(),
        }),
    }
}

fn from_wasi_address(address: IpSocketAddress) -> SocketAddr {
    match address {
        IpSocketAddress::Ipv4(addr) => {
            let (a, b, c, d) = addr.address;
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(a, b, c, d), addr.port))
        }
        IpSocketAddress::Ipv6(addr) => {
            let (a, b, c, d, e, f, g, h) = addr.address;
            SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::new(a, b, c, d, e, f, g, h),
                addr.port,
                addr.flow_info,
                addr.scope_id,
            ))
        }
    }
}

fn from_wasi_ip(address: IpAddress) -> IpAddr {
    match address {
        IpAddress::Ipv4((a, b, c, d)) => IpAddr::V4(Ipv4Addr::new(a, b, c, d)),
        IpAddress::Ipv6((a, b, c, d, e, f, g, h)) => {
            IpAddr::V6(Ipv6Addr::new(a, b, c, d, e, f, g, h))
        }
    }
}

fn reject_explicit_source(source: Option<IpAddr>) -> io::Result<()> {
    if source.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "choosing a datagram's source address is not supported on wasi:sockets",
        ));
    }
    Ok(())
}

fn segment_chunks(bytes: &[u8], segment_size: NonZeroU16) -> std::slice::Chunks<'_, u8> {
    bytes.chunks(usize::from(segment_size.get()))
}

fn copy_datagram_into<B: IoBufMut>(bytes: &[u8], buf: &mut B) -> usize {
    let dst = buf.as_uninit();
    let copied = bytes.len().min(dst.len());
    for (slot, byte) in dst[..copied].iter_mut().zip(&bytes[..copied]) {
        slot.write(*byte);
    }
    // SAFETY: the first `copied` bytes of `buf` were initialized above, and
    // `copied <= dst.len()`.
    unsafe { buf.set_len(copied) };
    copied
}

/// An established TCP connection: the two halves of `wasi:sockets` streams
/// over one socket.
///
/// [`Split`] gives the halves up separately; the socket closes when both are
/// dropped.
#[derive(Debug)]
pub struct TcpConnection {
    reader: ReadHalf,
    writer: WriteHalf,
}

/// The receiving half of a [`TcpConnection`].
#[derive(Debug)]
pub struct ReadHalf {
    stream: StreamReader<u8>,
    /// How the stream ended, until it did; taken once it has.
    outcome: Option<FutureReader<Result<(), SocketCode>>>,
    _socket: Rc<TcpSocket>,
}

/// The sending half of a [`TcpConnection`].
#[derive(Debug)]
pub struct WriteHalf {
    /// Dropped to shut the write side down.
    stream: Option<StreamWriter<u8>>,
    /// How the send ended, until it did; taken once it has.
    outcome: Option<FutureReader<Result<(), SocketCode>>>,
    _socket: Rc<TcpSocket>,
}

impl ReadHalf {
    /// The next bytes the peer sent, at most `capacity`; empty at the end of
    /// the stream.
    async fn receive(&mut self, capacity: usize) -> io::Result<Vec<u8>> {
        // Once the stream has ended its outcome is taken, and nothing is read again.
        if self.outcome.is_none() {
            return Ok(Vec::new());
        }
        let (result, bytes) = self.stream.read(Vec::with_capacity(capacity)).await;
        if !stream_closed(result) {
            return Ok(bytes);
        }
        match self.outcome.take() {
            Some(outcome) => outcome.await.map(|()| bytes).map_err(socket_error),
            None => Ok(bytes),
        }
    }
}

impl WriteHalf {
    /// The error a closed send stream stands for: what the host reported, or
    /// a broken pipe if it reported success.
    async fn closed(&mut self) -> io::Error {
        let reported = match self.outcome.take() {
            Some(outcome) => outcome.await.err().map(socket_error),
            None => None,
        };
        reported.unwrap_or_else(|| {
            io::Error::new(io::ErrorKind::BrokenPipe, "the connection is closed")
        })
    }

    /// Sends all of `bytes`.
    async fn send(&mut self, bytes: Vec<u8>) -> io::Result<()> {
        let Some(stream) = &mut self.stream else {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "the write side is shut down",
            ));
        };
        if stream.write_all(bytes).await.is_empty() {
            Ok(())
        } else {
            Err(self.closed().await)
        }
    }
}

impl Read for ReadHalf {
    async fn read<B: IoBufMut>(&mut self, mut buf: B) -> BufResult<usize, B> {
        let capacity = buf.as_uninit().len().min(RECEIVE_CHUNK_BYTES);
        if capacity == 0 {
            return BufResult(Ok(0), buf);
        }
        match self.receive(capacity).await {
            Ok(bytes) => {
                let received = bytes.len();
                for (slot, byte) in buf.as_uninit().iter_mut().zip(&bytes) {
                    slot.write(*byte);
                }
                // SAFETY: `self.receive(capacity)` reads at most `capacity <=
                // buf.as_uninit().len()` bytes, so the `zip` loop above
                // initialized the first `received` bytes of `buf`.
                unsafe { buf.set_len(received) };
                BufResult(Ok(received), buf)
            }
            Err(error) => BufResult(Err(error), buf),
        }
    }
}

impl ReadOwned for ReadHalf {
    type Buf = NoBuf;

    /// Transfers the receive allocation so protocol bodies can retain it directly.
    async fn read_owned(&mut self) -> io::Result<Received<NoBuf>> {
        let bytes = self.receive(RECEIVE_CHUNK_BYTES).await?;
        Ok(if bytes.is_empty() {
            Received::End
        } else {
            Received::Owned(bytes.into())
        })
    }
}

impl ReadAhead for ReadHalf {
    /// A stream is read only when the reader asks, so nothing is ahead.
    async fn stop_read_ahead(&mut self) -> Vec<u8> {
        Vec::new()
    }
}

/// A connection's bytes cross the `wasi:sockets` streams, never a kernel
/// descriptor a pipe could take them from, so it never splices and is
/// forwarded by reading and writing.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn unsplicable() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "a wasi:sockets connection has no descriptor to splice",
    )
}

impl SpliceRead for ReadHalf {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn can_splice(&self) -> bool {
        false
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    async fn splice_to_pipe(
        &mut self,
        pipe: Pipe,
        _max: usize,
    ) -> Result<Spliced, (io::Error, Pipe)> {
        Err((unsplicable(), pipe))
    }
}

impl Write for WriteHalf {
    async fn write<B: IoBuf>(&mut self, buf: B) -> BufResult<usize, B> {
        let bytes = buf.as_init().to_vec();
        let written = bytes.len();
        let result = if bytes.is_empty() {
            Ok(0)
        } else {
            self.send(bytes).await.map(|()| written)
        };
        BufResult(result, buf)
    }

    async fn write_vectored<B: IoVectoredBuf>(&mut self, buf: B) -> BufResult<usize, B> {
        let bytes: Vec<u8> = buf.iter_slice().flatten().copied().collect();
        let written = bytes.len();
        let result = if bytes.is_empty() {
            Ok(0)
        } else {
            self.send(bytes).await.map(|()| written)
        };
        BufResult(result, buf)
    }

    /// Bytes are handed to the host as they are written.
    async fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }

    /// Drops the send stream, which `wasi:sockets` defines as
    /// `shutdown(SHUT_WR)`, and waits for the host to say how it went.
    async fn shutdown(&mut self) -> io::Result<()> {
        self.stream = None;
        match self.outcome.take() {
            Some(outcome) => outcome.await.map_err(socket_error),
            None => Ok(()),
        }
    }
}

impl SendFile for WriteHalf {
    /// One positioned read into a buffer, then a write of all of it: the
    /// host has no `sendfile`.
    async fn send_file<F: Borrow<File> + 'static>(
        &mut self,
        file: F,
        offset: u64,
        len: usize,
    ) -> BufResult<usize, F> {
        let mut chunk = vec![0; len.min(RECEIVE_CHUNK_BYTES)];
        let read = {
            // `std::os::wasi::fs::FileExt::read_at` is unstable, so this is a
            // seek and a read.
            let mut file: &File = file.borrow();
            file.seek(SeekFrom::Start(offset))
                .and_then(|_| file.read(&mut chunk))
        };
        let read = match read {
            Ok(read) => read,
            Err(error) => return BufResult(Err(error), file),
        };
        chunk.truncate(read);
        let result = self.send(chunk).await.map(|()| read);
        BufResult(result, file)
    }
}

impl SpliceWrite for WriteHalf {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn can_splice(&self) -> bool {
        false
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    async fn splice_from_pipe(&mut self, _filled: FilledPipe) -> io::Result<Pipe> {
        Err(unsplicable())
    }
}

impl Split for TcpConnection {
    type ReadHalf = ReadHalf;
    type WriteHalf = WriteHalf;

    fn split(self) -> (ReadHalf, WriteHalf) {
        (self.reader, self.writer)
    }
}

impl Read for TcpConnection {
    fn read<B: IoBufMut>(&mut self, buf: B) -> impl Future<Output = BufResult<usize, B>> {
        self.reader.read(buf)
    }
}

impl ReadOwned for TcpConnection {
    type Buf = NoBuf;

    fn read_owned(&mut self) -> impl Future<Output = io::Result<Received<NoBuf>>> {
        self.reader.read_owned()
    }
}

impl ReadAhead for TcpConnection {
    fn stop_read_ahead(&mut self) -> impl Future<Output = Vec<u8>> {
        self.reader.stop_read_ahead()
    }
}

impl Write for TcpConnection {
    fn write<B: IoBuf>(&mut self, buf: B) -> impl Future<Output = BufResult<usize, B>> {
        self.writer.write(buf)
    }

    fn write_vectored<B: IoVectoredBuf>(
        &mut self,
        buf: B,
    ) -> impl Future<Output = BufResult<usize, B>> {
        self.writer.write_vectored(buf)
    }

    fn flush(&mut self) -> impl Future<Output = io::Result<()>> {
        self.writer.flush()
    }

    fn shutdown(&mut self) -> impl Future<Output = io::Result<()>> {
        self.writer.shutdown()
    }
}

impl SendFile for TcpConnection {
    fn send_file<F: Borrow<File> + 'static>(
        &mut self,
        file: F,
        offset: u64,
        len: usize,
    ) -> impl Future<Output = BufResult<usize, F>> {
        self.writer.send_file(file, offset, len)
    }
}

impl SpliceRead for TcpConnection {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn can_splice(&self) -> bool {
        SpliceRead::can_splice(&self.reader)
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn splice_to_pipe(
        &mut self,
        pipe: Pipe,
        max: usize,
    ) -> impl Future<Output = Result<Spliced, (io::Error, Pipe)>> {
        self.reader.splice_to_pipe(pipe, max)
    }
}

impl SpliceWrite for TcpConnection {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn can_splice(&self) -> bool {
        SpliceWrite::can_splice(&self.writer)
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn splice_from_pipe(&mut self, filled: FilledPipe) -> impl Future<Output = io::Result<Pipe>> {
        self.writer.splice_from_pipe(filled)
    }
}

impl TcpOptions for TcpConnection {
    /// The Helios network stack has no Nagle algorithm: segments are sent as
    /// they are written, which is what `TCP_NODELAY` asks for.
    fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        if nodelay {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "the Helios network stack always sends without delay",
            ))
        }
    }

    fn nodelay(&self) -> io::Result<bool> {
        Ok(true)
    }
}

/// A bound `wasi:sockets` UDP socket implementing [`DatagramSocket`].
#[derive(Debug)]
pub struct UdpSocket {
    socket: WasiUdpSocket,
}

impl DatagramSocket for UdpSocket {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket
            .get_local_address()
            .map(from_wasi_address)
            .map_err(socket_error)
    }

    fn max_send_segments(&self) -> usize {
        1
    }

    async fn send_from<B: IoBuf>(
        &self,
        buf: B,
        target: SocketAddr,
        source: Option<IpAddr>,
    ) -> BufResult<usize, B> {
        if let Err(error) = reject_explicit_source(source) {
            return BufResult(Err(error), buf);
        }
        let bytes = buf.as_init().to_vec();
        let len = bytes.len();
        let result = self
            .socket
            .send(bytes, Some(to_wasi_address(target)))
            .await
            .map(|()| len)
            .map_err(socket_error);
        BufResult(result, buf)
    }

    async fn send_segments_from<B: IoBuf>(
        &self,
        buf: B,
        segment_size: NonZeroU16,
        target: SocketAddr,
        source: Option<IpAddr>,
    ) -> BufResult<usize, B> {
        if let Err(error) = reject_explicit_source(source) {
            return BufResult(Err(error), buf);
        }
        let wasi_target = to_wasi_address(target);
        let mut sent = 0usize;
        for chunk in segment_chunks(buf.as_init(), segment_size) {
            if let Err(code) = self.socket.send(chunk.to_vec(), Some(wasi_target)).await {
                return BufResult(Err(socket_error(code)), buf);
            }
            sent += chunk.len();
        }
        BufResult(Ok(sent), buf)
    }

    async fn recv_from<B: IoBufMut>(&self, mut buf: B) -> BufResult<RecvMeta, B> {
        match self.socket.receive().await {
            Ok((bytes, from)) => {
                let copied = copy_datagram_into(&bytes, &mut buf);
                BufResult(Ok(RecvMeta::single(copied, from_wasi_address(from))), buf)
            }
            Err(code) => BufResult(Err(socket_error(code)), buf),
        }
    }
}

/// Runs a client's local tasks on the component's executor.
///
/// A task polls on the component-model executor that drives the export
/// calling it, and keeps being polled after that call returns, as long as
/// something is waiting on it.
#[derive(Debug, Clone, Copy, Default)]
pub struct HeliosExecutor;

impl LocalExecutor for HeliosExecutor {
    type Task<T: 'static> = AsyncTask<T>;

    fn spawn_local<Fut>(&self, future: Fut) -> AsyncTask<Fut::Output>
    where
        Fut: Future + 'static,
    {
        // Each wake-up schedules the task's next poll as a task of the
        // component's own executor.
        let (runnable, task) = spawn_local(future, |runnable| {
            crate::task::spawn(async move {
                runnable.run();
            });
        });
        runnable.schedule();
        task
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
    use std::num::NonZeroU16;

    use http_kit_io::RecvMeta;

    use super::{
        SocketCode, SocketError, address_family, copy_datagram_into, from_wasi_address,
        reject_explicit_source, segment_chunks, socket_error, to_wasi_address,
    };
    use crate::bindings::wasi::sockets::types::IpAddressFamily;

    #[test]
    fn address_round_trip_ipv4() {
        let addresses = [
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 4433)),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::BROADCAST, u16::MAX)),
        ];
        for addr in addresses {
            assert_eq!(address_family(addr), IpAddressFamily::Ipv4);
            assert_eq!(from_wasi_address(to_wasi_address(addr)), addr);
        }
    }

    #[test]
    fn address_round_trip_ipv6_preserves_flowinfo_and_scope() {
        let addresses = [
            SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0)),
            SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 8443, 0x12345, 7)),
            SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::new(0xfe80, 0, 0, 0, 1, 2, 3, 4),
                5353,
                0xffff_ffff,
                42,
            )),
        ];
        for addr in addresses {
            assert_eq!(address_family(addr), IpAddressFamily::Ipv6);
            assert_eq!(from_wasi_address(to_wasi_address(addr)), addr);
        }
    }

    #[test]
    fn explicit_source_is_rejected_with_unsupported() {
        assert!(reject_explicit_source(None).is_ok());

        for source in [
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ] {
            let err = reject_explicit_source(Some(source)).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::Unsupported);
        }
    }

    #[test]
    fn segment_chunks_split_on_boundaries() {
        let seg_4 = NonZeroU16::new(4).unwrap();
        let empty: Vec<&[u8]> = segment_chunks(&[], seg_4).collect();
        assert!(empty.is_empty());

        let exact: Vec<&[u8]> = segment_chunks(b"abcdefgh", seg_4).collect();
        assert_eq!(exact, [b"abcd".as_slice(), b"efgh".as_slice()]);

        let with_tail: Vec<&[u8]> = segment_chunks(b"abcdefghi", seg_4).collect();
        assert_eq!(
            with_tail,
            [b"abcd".as_slice(), b"efgh".as_slice(), b"i".as_slice()]
        );

        let seg_1 = NonZeroU16::new(1).unwrap();
        let single_bytes: Vec<&[u8]> = segment_chunks(b"xyz", seg_1).collect();
        assert_eq!(
            single_bytes,
            [b"x".as_slice(), b"y".as_slice(), b"z".as_slice()]
        );

        let seg_max = NonZeroU16::new(u16::MAX).unwrap();
        let large: Vec<&[u8]> = segment_chunks(b"hello", seg_max).collect();
        assert_eq!(large, [b"hello".as_slice()]);
    }

    fn assert_single_segment(meta: RecvMeta, expected: std::ops::Range<usize>) {
        let segments: Vec<_> = meta.segments().collect();
        assert_eq!(segments.len(), 1);
        assert_eq!(segments[0], expected);
    }

    #[test]
    fn copy_datagram_into_copies_and_truncates() {
        let from: SocketAddr = "127.0.0.1:4433".parse().unwrap();

        // Pre-populated Vec gets reset to exact datagram length.
        let mut buf = vec![0xAAu8; 16];
        let copied = copy_datagram_into(b"hello", &mut buf);
        assert_eq!(copied, 5);
        assert_eq!(buf, b"hello");
        let meta = RecvMeta::single(copied, from);
        assert_eq!(meta.len(), 5);
        assert_eq!(meta.segment_size(), 5);
        assert_eq!(meta.from(), from);
        assert_eq!(meta.destination(), None);
        assert_single_segment(meta, 0..5);

        // Empty datagram sets length to 0 and produces one empty segment.
        let mut non_empty = vec![1, 2, 3];
        let copied = copy_datagram_into(b"", &mut non_empty);
        assert_eq!(copied, 0);
        assert!(non_empty.is_empty());
        let empty_meta = RecvMeta::single(copied, from);
        assert!(empty_meta.is_empty());
        assert_single_segment(empty_meta, 0..0);

        // Datagram larger than fixed-capacity buffer truncates cleanly.
        let mut small = [0u8; 4];
        let copied = copy_datagram_into(b"abcdefgh", &mut small);
        assert_eq!(copied, 4);
        assert_eq!(&small, b"abcd");
        let trunc_meta = RecvMeta::single(copied, from);
        assert_eq!(trunc_meta.len(), 4);
        assert_single_segment(trunc_meta, 0..4);

        // Zero-capacity buffer truncates to 0 without panic.
        let mut zero = [0u8; 0];
        let copied = copy_datagram_into(b"payload", &mut zero);
        assert_eq!(copied, 0);
    }

    #[test]
    fn socket_error_translates_codes_and_preserves_source() {
        let cases = [
            (SocketCode::AccessDenied, io::ErrorKind::PermissionDenied),
            (SocketCode::NotSupported, io::ErrorKind::Unsupported),
            (SocketCode::InvalidArgument, io::ErrorKind::InvalidInput),
            (SocketCode::OutOfMemory, io::ErrorKind::OutOfMemory),
            (SocketCode::Timeout, io::ErrorKind::TimedOut),
            (SocketCode::InvalidState, io::ErrorKind::InvalidInput),
            (
                SocketCode::AddressNotBindable,
                io::ErrorKind::AddrNotAvailable,
            ),
            (SocketCode::AddressInUse, io::ErrorKind::AddrInUse),
            (
                SocketCode::RemoteUnreachable,
                io::ErrorKind::HostUnreachable,
            ),
            (
                SocketCode::ConnectionRefused,
                io::ErrorKind::ConnectionRefused,
            ),
            (SocketCode::ConnectionBroken, io::ErrorKind::BrokenPipe),
            (SocketCode::ConnectionReset, io::ErrorKind::ConnectionReset),
            (
                SocketCode::ConnectionAborted,
                io::ErrorKind::ConnectionAborted,
            ),
            (SocketCode::DatagramTooLarge, io::ErrorKind::InvalidInput),
            (SocketCode::Other(None), io::ErrorKind::Other),
            (
                SocketCode::Other(Some("detail".to_owned())),
                io::ErrorKind::Other,
            ),
        ];

        for (code, expected_kind) in cases {
            let err = socket_error(code);
            assert_eq!(err.kind(), expected_kind);
            let inner = err
                .get_ref()
                .expect("socket_error preserves SocketError inner error");
            assert!(inner.downcast_ref::<SocketError>().is_some());
        }
    }
}
