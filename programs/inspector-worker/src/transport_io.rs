//! `futures_io` adapters for `inspector-worker`'s session data transport
//! (`ipc::Endpoint`, `VsockStream`, or `DebugPort`).

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use futures_io::{AsyncRead, AsyncWrite};
use helios_api::ipc::Endpoint as IpcEndpoint;
use helios_api::serial::DebugPort;
use helios_api::vsock::VsockStream;

const READ_CHUNK_BYTES: usize = 32 * 1024;

#[cfg(target_arch = "wasm32")]
type BoxIoFuture<T> = Pin<Box<dyn Future<Output = io::Result<T>>>>;
#[cfg(not(target_arch = "wasm32"))]
type BoxIoFuture<T> = Pin<Box<dyn Future<Output = io::Result<T>> + Send>>;

pub enum WorkerTransport {
    Ipc(Arc<IpcEndpoint>),
    Vsock(Arc<VsockStream>),
    Serial(Arc<DebugPort>),
}

impl WorkerTransport {
    fn clone_arc(&self) -> Self {
        match self {
            Self::Ipc(ep) => Self::Ipc(Arc::clone(ep)),
            Self::Vsock(s) => Self::Vsock(Arc::clone(s)),
            Self::Serial(p) => Self::Serial(Arc::clone(p)),
        }
    }

    fn read_chunk(&self) -> BoxIoFuture<Vec<u8>> {
        match self {
            Self::Ipc(ep) => {
                let ep = Arc::clone(ep);
                Box::pin(async move {
                    match ep.read(READ_CHUNK_BYTES as u32).await {
                        Ok(Some(bytes)) => Ok(bytes),
                        Ok(None) | Err(_) => Ok(Vec::new()),
                    }
                })
            }
            Self::Vsock(stream) => {
                let stream = Arc::clone(stream);
                Box::pin(
                    async move { Ok(stream.read(READ_CHUNK_BYTES).await?.unwrap_or_default()) },
                )
            }
            Self::Serial(port) => {
                let port = Arc::clone(port);
                Box::pin(async move { port.read(READ_CHUNK_BYTES).await })
            }
        }
    }

    fn write_chunk(&self, bytes: Vec<u8>) -> BoxIoFuture<()> {
        match self {
            Self::Ipc(ep) => {
                let ep = Arc::clone(ep);
                Box::pin(async move {
                    ep.write(bytes)
                        .await
                        .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "IPC peer closed"))
                })
            }
            Self::Vsock(stream) => {
                let stream = Arc::clone(stream);
                Box::pin(async move { stream.write_all(&bytes).await })
            }
            Self::Serial(port) => {
                let port = Arc::clone(port);
                Box::pin(async move { port.write_all(&bytes).await })
            }
        }
    }

    fn flush_transport(&self) -> BoxIoFuture<()> {
        match self {
            Self::Ipc(_) | Self::Vsock(_) => Box::pin(async { Ok(()) }),
            Self::Serial(port) => {
                let port = Arc::clone(port);
                Box::pin(async move { port.flush().await })
            }
        }
    }
}

pub struct WorkerReader {
    transport: WorkerTransport,
    buf: Vec<u8>,
    offset: usize,
    eof: bool,
    pending: Option<BoxIoFuture<Vec<u8>>>,
}

pub struct WorkerWriter {
    transport: WorkerTransport,
    write: Option<(usize, BoxIoFuture<()>)>,
    flush: Option<BoxIoFuture<()>>,
}

pub fn split(transport: WorkerTransport) -> (WorkerReader, WorkerWriter) {
    (
        WorkerReader {
            transport: transport.clone_arc(),
            buf: Vec::new(),
            offset: 0,
            eof: false,
            pending: None,
        },
        WorkerWriter {
            transport,
            write: None,
            flush: None,
        },
    )
}

impl AsyncRead for WorkerReader {
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
            if self.pending.is_none() {
                self.pending = Some(self.transport.read_chunk());
            }
            match self
                .pending
                .as_mut()
                .expect("pending read")
                .as_mut()
                .poll(cx)
            {
                Poll::Ready(Ok(bytes)) => {
                    self.pending = None;
                    if bytes.is_empty() {
                        self.eof = true;
                        return Poll::Ready(Ok(0));
                    }
                    self.buf = bytes;
                    self.offset = 0;
                }
                Poll::Ready(Err(err)) => {
                    self.pending = None;
                    return Poll::Ready(Err(err));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for WorkerWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if self.write.is_none() {
            let len = buf.len();
            self.write = Some((len, self.transport.write_chunk(buf.to_vec())));
        }
        let (len, fut) = self.write.as_mut().expect("pending write");
        match fut.as_mut().poll(cx) {
            Poll::Ready(Ok(())) => {
                let n = *len;
                self.write = None;
                Poll::Ready(Ok(n))
            }
            Poll::Ready(Err(err)) => {
                self.write = None;
                Poll::Ready(Err(err))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some((_, fut)) = self.write.as_mut() {
            match fut.as_mut().poll(cx) {
                Poll::Ready(Ok(())) => self.write = None,
                Poll::Ready(Err(err)) => {
                    self.write = None;
                    return Poll::Ready(Err(err));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        if self.flush.is_none() {
            self.flush = Some(self.transport.flush_transport());
        }
        match self
            .flush
            .as_mut()
            .expect("pending flush")
            .as_mut()
            .poll(cx)
        {
            Poll::Ready(res) => {
                self.flush = None;
                Poll::Ready(res)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_flush(cx)
    }
}
