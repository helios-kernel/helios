//! Zero-authority TLS 1.3 terminator for inbound inspector TCP sessions
//! (`/inspector/tls`, `ProcessAuthority::empty()`).
//!
//! Security contract:
//! - Statically declares empty `[capabilities]` in `components/inspector/tls/component.toml`.
//! - Spawned by `inspector-host` with ZERO capability grants beyond:
//!   1. `InheritedSocket::TcpStream` (the accepted client TCP connection),
//!   2. `ipc::take("control")` (handshake signing & auth decision callback to `inspector-host`),
//!   3. `ipc::take("data")` (direct plaintext byte channel to the per-session `inspector-worker`).
//! - Performs TLS 1.3 with an ephemeral pure-Rust `rustls-pure` Ed25519 key pair,
//!   exports the RFC 8446 `tls-exporter` channel binding, asks `inspector-host`
//!   to sign the binding with `MachineIdentity` and verify `ClientAuth`, drops
//!   `control`, and splices plaintext directly between TLS and `data`.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use futures_io::{AsyncRead, AsyncWrite};
use futures_lite::io::{AsyncReadExt as _, AsyncWriteExt as _};
use helios_api::ipc::{self, Endpoint as IpcEndpoint};
use helios_api::net::TcpStream;
use helios_api::programs::{InheritedSocket, take_inherited_sockets};
use helios_inspector_protocol::auth::{
    AUTH_PROTOCOL_VERSION, ClientAuth, ClientHello, ServerAuthResult, TlsControlRequest,
    TlsControlResponse, random_32, read_auth_message, write_auth_message,
};
use helios_inspector_protocol::tls::{TlsServerStream, build_ephemeral_server_config};

const IO_CHUNK_BYTES: usize = 32 * 1024;

#[helios_api::main]
async fn main() -> Result<(), String> {
    let tcp = take_inherited_sockets()
        .into_iter()
        .find_map(|sock| match sock {
            InheritedSocket::TcpStream(raw) => Some(TcpStream::from_raw(raw)),
            _ => None,
        })
        .ok_or_else(|| "inspector-tls started without inherited TcpStream".to_owned())?;

    let control = ipc::take("control")
        .ok_or_else(|| "inspector-tls started without `control` IPC endpoint".to_owned())?;
    let data = ipc::take("data")
        .ok_or_else(|| "inspector-tls started without `data` IPC endpoint".to_owned())?;

    let (server_cfg, leaf_cert_sha256) =
        build_ephemeral_server_config().map_err(|err| format!("TLS config failed: {err}"))?;

    let tcp = Arc::new(tcp);
    let (tcp_read, tcp_write) = split_tcp(Arc::clone(&tcp));
    let mut tls = TlsServerStream::accept(tcp_read, tcp_write, server_cfg, leaf_cert_sha256)
        .await
        .map_err(|err| format!("TLS 1.3 accept failed: {err}"))?;
    let binding = tls.binding();
    let server_nonce = random_32().map_err(|err| format!("random_32 failed: {err}"))?;

    let control = Arc::new(control);
    let (mut ctrl_read, mut ctrl_write) = split_ipc(Arc::clone(&control));

    // Wait for the client's `ClientHello` before requesting the domain-separated
    // `MachineIdentity` signature from `inspector-host`.
    let client_hello: ClientHello = read_auth_message(&mut tls)
        .await
        .map_err(|err| format!("read ClientHello failed: {err}"))?;
    if client_hello.protocol_version != AUTH_PROTOCOL_VERSION {
        return Err(format!(
            "unsupported inspector auth protocol version {}",
            client_hello.protocol_version
        ));
    }

    // Step 1: Request domain-separated `MachineIdentity` signature over the
    // RFC 8446 `tls-exporter` channel binding and ephemeral cert digest.
    write_auth_message(
        &mut ctrl_write,
        &TlsControlRequest::SignHandshake {
            channel_binding: binding.channel_binding,
            tls_spki_sha256: binding.peer_cert_sha256,
            server_nonce,
        },
    )
    .await
    .map_err(|err| format!("control send SignHandshake failed: {err}"))?;

    let server_hello = match read_auth_message::<_, TlsControlResponse>(&mut ctrl_read)
        .await
        .map_err(|err| format!("control recv HandshakeSigned failed: {err}"))?
    {
        TlsControlResponse::HandshakeSigned(hello) => hello,
        TlsControlResponse::Error(detail) => {
            return Err(format!("sign handshake failed: {detail}"));
        }
        other => return Err(format!("unexpected control response: {other:?}")),
    };

    // Step 2: Send `ServerHello` and read `ClientAuth` inside the TLS 1.3 channel.
    write_auth_message(&mut tls, &server_hello)
        .await
        .map_err(|err| format!("write ServerHello failed: {err}"))?;

    let client_auth: ClientAuth = read_auth_message(&mut tls)
        .await
        .map_err(|err| format!("read ClientAuth failed: {err}"))?;

    // Step 3: Forward `ClientAuth` to `inspector-host` for Ed25519 verification
    // and attenuated `inspector-worker` launch bound to the peer half of `data`.
    write_auth_message(
        &mut ctrl_write,
        &TlsControlRequest::Authenticate {
            server_hello,
            channel_binding: binding.channel_binding,
            client_auth: Box::new(client_auth),
        },
    )
    .await
    .map_err(|err| format!("control send Authenticate failed: {err}"))?;

    let decision = match read_auth_message::<_, TlsControlResponse>(&mut ctrl_read)
        .await
        .map_err(|err| format!("control recv AuthDecision failed: {err}"))?
    {
        TlsControlResponse::AuthDecision(decision) => decision,
        TlsControlResponse::Error(detail) => return Err(format!("auth control error: {detail}")),
        other => return Err(format!("unexpected auth decision response: {other:?}")),
    };

    // Drop the `control` channel immediately so `inspector-host` exits the
    // session path permanently before post-handshake data flows.
    drop(ctrl_read);
    drop(ctrl_write);
    drop(control);

    write_auth_message(&mut tls, &decision)
        .await
        .map_err(|err| format!("write ServerAuthResult failed: {err}"))?;

    if !matches!(decision, ServerAuthResult::Accepted { .. }) {
        let _ = tls.close().await;
        return Ok(());
    }

    // Step 4: Splice plaintext directly between TLS 1.3 and `inspector-worker`
    // via `data` IPC endpoint inside a single future (wasm32-wasip3 safe).
    let (mut tls_read, mut tls_write) = futures_util::AsyncReadExt::split(tls);
    let data = Arc::new(data);
    let (mut ipc_read, mut ipc_write) = split_ipc(Arc::clone(&data));

    let net_to_worker = async {
        let mut buf = vec![0u8; IO_CHUNK_BYTES];
        loop {
            match tls_read.read(&mut buf).await {
                Ok(0) => {
                    data.close_write();
                    return Ok::<(), io::Error>(());
                }
                Ok(n) => {
                    ipc_write.write_all(&buf[..n]).await?;
                }
                Err(err) => return Err(err),
            }
        }
    };

    let worker_to_net = async {
        let mut buf = vec![0u8; IO_CHUNK_BYTES];
        loop {
            match ipc_read.read(&mut buf).await {
                Ok(0) => {
                    let _ = tls_write.close().await;
                    return Ok::<(), io::Error>(());
                }
                Ok(n) => {
                    tls_write.write_all(&buf[..n]).await?;
                    tls_write.flush().await?;
                }
                Err(err) => return Err(err),
            }
        }
    };

    let mut net_to_worker = std::pin::pin!(net_to_worker);
    let mut worker_to_net = std::pin::pin!(worker_to_net);
    match futures_util::future::select(net_to_worker.as_mut(), worker_to_net.as_mut()).await {
        // Worker exited and closed TLS: tear down immediately without waiting
        // forever on a stalled remote TCP peer.
        futures_util::future::Either::Right((_, _)) => {
            data.close_write();
        }
        // Client reached EOF/error: finish draining any final worker reply
        // through TLS before tearing down.
        futures_util::future::Either::Left((_, remaining_worker_to_net)) => {
            let _ = remaining_worker_to_net.await;
        }
    }
    Ok(())
}

type BoxIoFuture<T> = Pin<Box<dyn Future<Output = io::Result<T>>>>;

struct TcpReader {
    stream: Arc<TcpStream>,
    buf: Vec<u8>,
    offset: usize,
    eof: bool,
    pending: Option<BoxIoFuture<Vec<u8>>>,
}

struct TcpWriter {
    stream: Arc<TcpStream>,
    pending: Option<(usize, BoxIoFuture<()>)>,
}

fn split_tcp(stream: Arc<TcpStream>) -> (TcpReader, TcpWriter) {
    (
        TcpReader {
            stream: Arc::clone(&stream),
            buf: Vec::new(),
            offset: 0,
            eof: false,
            pending: None,
        },
        TcpWriter {
            stream,
            pending: None,
        },
    )
}

impl AsyncRead for TcpReader {
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
                let stream = Arc::clone(&self.stream);
                self.pending = Some(Box::pin(async move {
                    Ok(stream.read(IO_CHUNK_BYTES).await?.unwrap_or_default())
                }));
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

impl AsyncWrite for TcpWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if self.pending.is_none() {
            let stream = Arc::clone(&self.stream);
            let data = buf.to_vec();
            let len = data.len();
            self.pending = Some((len, Box::pin(async move { stream.write_all(&data).await })));
        }
        let (len, fut) = self.pending.as_mut().expect("pending write");
        match fut.as_mut().poll(cx) {
            Poll::Ready(Ok(())) => {
                let written = *len;
                self.pending = None;
                Poll::Ready(Ok(written))
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

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_flush(cx)
    }
}

struct IpcReader {
    endpoint: Arc<IpcEndpoint>,
    buf: Vec<u8>,
    offset: usize,
    eof: bool,
    pending: Option<BoxIoFuture<Vec<u8>>>,
}

struct IpcWriter {
    endpoint: Arc<IpcEndpoint>,
    pending: Option<(usize, BoxIoFuture<()>)>,
}

fn split_ipc(endpoint: Arc<IpcEndpoint>) -> (IpcReader, IpcWriter) {
    (
        IpcReader {
            endpoint: Arc::clone(&endpoint),
            buf: Vec::new(),
            offset: 0,
            eof: false,
            pending: None,
        },
        IpcWriter {
            endpoint,
            pending: None,
        },
    )
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
                    match ep.read(IO_CHUNK_BYTES as u32).await {
                        Ok(Some(bytes)) => Ok(bytes),
                        Ok(None) => Ok(Vec::new()),
                        Err(_) => Ok(Vec::new()),
                    }
                }));
            }
            match self
                .pending
                .as_mut()
                .expect("pending ipc read")
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
        let (len, fut) = self.pending.as_mut().expect("pending ipc write");
        match fut.as_mut().poll(cx) {
            Poll::Ready(Ok(())) => {
                let written = *len;
                self.pending = None;
                Poll::Ready(Ok(written))
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
