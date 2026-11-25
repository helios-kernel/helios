//! Single-byte-read `futures_io` adapters used ONLY during `inspector-host`
//! pre-handoff authentication so ZERO excess bytes are ever buffered ahead of
//! handing a connected `VsockStream` or `DebugPort` directly to
//! `inspector-worker`.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use futures_io::{AsyncRead, AsyncWrite};
use helios_api::ipc::Endpoint as IpcEndpoint;
use helios_api::serial::DebugPort;
use helios_api::vsock::VsockStream;

type BoxIoFuture<T> = Pin<Box<dyn Future<Output = io::Result<T>>>>;

/// Exact-length unbuffered `AsyncRead`/`AsyncWrite` over `VsockStream` so no
/// post-handshake RPC frame byte is ever read ahead into user space before the
/// stream is moved into `inspector-worker`.
pub struct UnbufferedVsockIo {
    stream: Arc<VsockStream>,
    read_fut: Option<BoxIoFuture<Vec<u8>>>,
    write_fut: Option<(usize, BoxIoFuture<()>)>,
}

impl UnbufferedVsockIo {
    pub fn new(stream: VsockStream) -> Self {
        Self {
            stream: Arc::new(stream),
            read_fut: None,
            write_fut: None,
        }
    }

    pub fn into_inner(self) -> VsockStream {
        debug_assert!(self.read_fut.is_none() && self.write_fut.is_none());
        Arc::try_unwrap(self.stream)
            .ok()
            .expect("UnbufferedVsockIo has exclusive ownership of VsockStream")
    }
}

impl AsyncRead for UnbufferedVsockIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        if out.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if self.read_fut.is_none() {
            let stream = Arc::clone(&self.stream);
            let want = out.len();
            self.read_fut = Some(Box::pin(async move {
                Ok(stream.read(want).await?.unwrap_or_default())
            }));
        }
        match self.read_fut.as_mut().expect("read fut").as_mut().poll(cx) {
            Poll::Ready(Ok(bytes)) => {
                self.read_fut = None;
                let n = bytes.len().min(out.len());
                out[..n].copy_from_slice(&bytes[..n]);
                Poll::Ready(Ok(n))
            }
            Poll::Ready(Err(err)) => {
                self.read_fut = None;
                Poll::Ready(Err(err))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for UnbufferedVsockIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if self.write_fut.is_none() {
            let stream = Arc::clone(&self.stream);
            let data = buf.to_vec();
            let len = data.len();
            self.write_fut = Some((len, Box::pin(async move { stream.write_all(&data).await })));
        }
        let (len, fut) = self.write_fut.as_mut().expect("write fut");
        match fut.as_mut().poll(cx) {
            Poll::Ready(Ok(())) => {
                let n = *len;
                self.write_fut = None;
                Poll::Ready(Ok(n))
            }
            Poll::Ready(Err(err)) => {
                self.write_fut = None;
                Poll::Ready(Err(err))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some((_, fut)) = self.write_fut.as_mut() {
            match fut.as_mut().poll(cx) {
                Poll::Ready(res) => {
                    self.write_fut = None;
                    return Poll::Ready(res);
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_flush(cx)
    }
}

/// Exact-length unbuffered `AsyncRead`/`AsyncWrite` over `DebugPort` so no
/// post-handshake byte is ever buffered ahead of handing `DebugPort` to
/// `inspector-worker`.
pub struct UnbufferedSerialIo {
    port: Arc<DebugPort>,
    read_fut: Option<BoxIoFuture<Vec<u8>>>,
    write_fut: Option<(usize, BoxIoFuture<()>)>,
    flush_fut: Option<BoxIoFuture<()>>,
}

impl UnbufferedSerialIo {
    pub fn new(port: DebugPort) -> Self {
        Self {
            port: Arc::new(port),
            read_fut: None,
            write_fut: None,
            flush_fut: None,
        }
    }

    pub fn into_inner(self) -> DebugPort {
        debug_assert!(
            self.read_fut.is_none() && self.write_fut.is_none() && self.flush_fut.is_none()
        );
        Arc::try_unwrap(self.port)
            .ok()
            .expect("UnbufferedSerialIo has exclusive ownership of DebugPort")
    }
}

impl AsyncRead for UnbufferedSerialIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        if out.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if self.read_fut.is_none() {
            let port = Arc::clone(&self.port);
            let want = out.len();
            self.read_fut = Some(Box::pin(async move { port.read(want).await }));
        }
        match self.read_fut.as_mut().expect("read fut").as_mut().poll(cx) {
            Poll::Ready(Ok(bytes)) => {
                self.read_fut = None;
                let n = bytes.len().min(out.len());
                out[..n].copy_from_slice(&bytes[..n]);
                Poll::Ready(Ok(n))
            }
            Poll::Ready(Err(err)) => {
                self.read_fut = None;
                Poll::Ready(Err(err))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for UnbufferedSerialIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if self.write_fut.is_none() {
            let port = Arc::clone(&self.port);
            let data = buf.to_vec();
            let len = data.len();
            self.write_fut = Some((len, Box::pin(async move { port.write_all(&data).await })));
        }
        let (len, fut) = self.write_fut.as_mut().expect("write fut");
        match fut.as_mut().poll(cx) {
            Poll::Ready(Ok(())) => {
                let n = *len;
                self.write_fut = None;
                Poll::Ready(Ok(n))
            }
            Poll::Ready(Err(err)) => {
                self.write_fut = None;
                Poll::Ready(Err(err))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some((_, fut)) = self.write_fut.as_mut() {
            match fut.as_mut().poll(cx) {
                Poll::Ready(Ok(())) => self.write_fut = None,
                Poll::Ready(Err(err)) => {
                    self.write_fut = None;
                    return Poll::Ready(Err(err));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        if self.flush_fut.is_none() {
            let port = Arc::clone(&self.port);
            self.flush_fut = Some(Box::pin(async move { port.flush().await }));
        }
        match self
            .flush_fut
            .as_mut()
            .expect("flush fut")
            .as_mut()
            .poll(cx)
        {
            Poll::Ready(res) => {
                self.flush_fut = None;
                Poll::Ready(res)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_flush(cx)
    }
}

/// `AsyncRead`/`AsyncWrite` adapter over `helios_api::ipc::Endpoint` used on
/// the short-lived `control` channel between `inspector-host` and `inspector-tls`.
pub struct IpcIo {
    endpoint: Arc<IpcEndpoint>,
    buf: Vec<u8>,
    offset: usize,
    eof: bool,
    read_fut: Option<BoxIoFuture<Vec<u8>>>,
    write_fut: Option<(usize, BoxIoFuture<()>)>,
}

impl IpcIo {
    pub fn new(endpoint: IpcEndpoint) -> Self {
        Self {
            endpoint: Arc::new(endpoint),
            buf: Vec::new(),
            offset: 0,
            eof: false,
            read_fut: None,
            write_fut: None,
        }
    }
}

impl AsyncRead for IpcIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        if out.is_empty() {
            return Poll::Ready(Ok(0));
        }
        loop {
            if self.offset < self.buf.len() {
                let n = (self.buf.len() - self.offset).min(out.len());
                out[..n].copy_from_slice(&self.buf[self.offset..self.offset + n]);
                self.offset += n;
                if self.offset == self.buf.len() {
                    self.buf.clear();
                    self.offset = 0;
                }
                return Poll::Ready(Ok(n));
            }
            if self.eof {
                return Poll::Ready(Ok(0));
            }
            if self.read_fut.is_none() {
                let ep = Arc::clone(&self.endpoint);
                self.read_fut = Some(Box::pin(async move {
                    match ep.read(16 * 1024).await {
                        Ok(Some(bytes)) => Ok(bytes),
                        Ok(None) | Err(_) => Ok(Vec::new()),
                    }
                }));
            }
            match self.read_fut.as_mut().expect("ipc read").as_mut().poll(cx) {
                Poll::Ready(Ok(bytes)) => {
                    self.read_fut = None;
                    if bytes.is_empty() {
                        self.eof = true;
                        return Poll::Ready(Ok(0));
                    }
                    self.buf = bytes;
                    self.offset = 0;
                }
                Poll::Ready(Err(err)) => {
                    self.read_fut = None;
                    return Poll::Ready(Err(err));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for IpcIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if self.write_fut.is_none() {
            let ep = Arc::clone(&self.endpoint);
            let data = buf.to_vec();
            let len = data.len();
            self.write_fut = Some((
                len,
                Box::pin(async move {
                    ep.write(data)
                        .await
                        .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "IPC peer closed"))
                }),
            ));
        }
        let (len, fut) = self.write_fut.as_mut().expect("ipc write");
        match fut.as_mut().poll(cx) {
            Poll::Ready(Ok(())) => {
                let n = *len;
                self.write_fut = None;
                Poll::Ready(Ok(n))
            }
            Poll::Ready(Err(err)) => {
                self.write_fut = None;
                Poll::Ready(Err(err))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some((_, fut)) = self.write_fut.as_mut() {
            match fut.as_mut().poll(cx) {
                Poll::Ready(res) => {
                    self.write_fut = None;
                    return Poll::Ready(res);
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let _ = self.as_mut().poll_flush(cx);
        self.endpoint.close_write();
        Poll::Ready(Ok(()))
    }
}
