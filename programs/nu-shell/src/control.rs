//! Optional `helios:system/component-control` IPC client for `/bin/nu`.
//!
//! When `component-manager` or `inspector-host` grants the shell a
//! `component-control` IPC endpoint, this module drives a `helios-wit-rpc`
//! [`Endpoint`] over that channel and exposes a clonable [`PeerHandle`].

use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};
use std::io;
use std::sync::Arc;

use futures_io::{AsyncRead, AsyncWrite};
use helios_api::ipc::{self, Endpoint as IpcEndpoint};
use helios_api::task;
use helios_wit_rpc::{Endpoint, PeerHandle};

const READ_CHUNK_BYTES: u32 = 32 * 1024;

#[cfg(target_arch = "wasm32")]
type BoxIoFuture<T> = Pin<Box<dyn Future<Output = io::Result<T>>>>;
#[cfg(not(target_arch = "wasm32"))]
type BoxIoFuture<T> = Pin<Box<dyn Future<Output = io::Result<T>> + Send>>;

/// Claim the optional `"component-control"` IPC endpoint and spawn its RPC driver.
pub fn connect_component_control() -> Option<PeerHandle> {
    let ep = Arc::new(ipc::take("component-control")?);
    let reader = IpcReader {
        endpoint: Arc::clone(&ep),
        buf: Vec::new(),
        offset: 0,
        eof: false,
        pending: None,
    };
    let writer = IpcWriter {
        endpoint: ep,
        pending: None,
    };
    let endpoint = Endpoint::new(reader, writer, ());
    let handle = endpoint.handle();
    task::spawn(async move {
        let _ = endpoint.drive().await;
    });
    Some(handle)
}

struct IpcReader {
    endpoint: Arc<IpcEndpoint>,
    buf: Vec<u8>,
    offset: usize,
    eof: bool,
    pending: Option<BoxIoFuture<Vec<u8>>>,
}

impl AsyncRead for IpcReader {
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
                let ep = Arc::clone(&self.endpoint);
                self.pending = Some(Box::pin(async move {
                    match ep.read(READ_CHUNK_BYTES).await {
                        Ok(Some(bytes)) => Ok(bytes),
                        Ok(None) | Err(_) => Ok(Vec::new()),
                    }
                }));
            }
            match self.pending.as_mut().expect("ipc read").as_mut().poll(cx) {
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

struct IpcWriter {
    endpoint: Arc<IpcEndpoint>,
    pending: Option<(usize, BoxIoFuture<()>)>,
}

impl AsyncWrite for IpcWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if self.pending.is_none() {
            let ep = Arc::clone(&self.endpoint);
            let data = buf.to_vec();
            let len = data.len();
            self.pending = Some((
                len,
                Box::pin(async move {
                    ep.write(data)
                        .await
                        .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "IPC peer closed"))
                }),
            ));
        }
        let (len, fut) = self.pending.as_mut().expect("ipc write");
        match fut.as_mut().poll(cx) {
            Poll::Ready(Ok(())) => {
                let n = *len;
                self.pending = None;
                Poll::Ready(Ok(n))
            }
            Poll::Ready(Err(err)) => {
                self.pending = None;
                Poll::Ready(Err(err))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some((_, fut)) = self.pending.as_mut() {
            match fut.as_mut().poll(cx) {
                Poll::Ready(res) => {
                    self.pending = None;
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
