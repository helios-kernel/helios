//! Opt-in `helios:system/component-control` IPC server compiled into
//! `component-manager` ONLY when `--features dynamic-components` is enabled.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use async_channel::{Receiver, Sender};
use futures_io::{AsyncRead, AsyncWrite};
use helios_api::ipc::Endpoint as IpcEndpoint;
use helios_api::task;
use helios_component_manager::{
    ComponentStateRecord, Supervisor, SupervisorError, SupervisorRuntime,
};
use helios_wit_rpc::Endpoint;
use helios_wit_rpc::inspector::helios::system::component_control::{
    self as rpc_cc, ComponentStatus, ControlError, ControlErrorKind,
};

type BoxIoFuture<T> = Pin<Box<dyn Future<Output = io::Result<T>>>>;

pub enum ControlCommand {
    List {
        reply: Sender<Result<Vec<ComponentStatus>, ControlError>>,
    },
    Start {
        moniker: String,
        reply: Sender<Result<ComponentStatus, ControlError>>,
    },
    Stop {
        moniker: String,
        reply: Sender<Result<(), ControlError>>,
    },
    Restart {
        moniker: String,
        reply: Sender<Result<ComponentStatus, ControlError>>,
    },
}

pub fn spawn_control_endpoint(endpoint: IpcEndpoint, cmd_tx: Sender<ControlCommand>) {
    let ep = Arc::new(endpoint);
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
    let server = rpc_cc::RpcServer::new(ControlHandler { cmd_tx });
    let rpc = Endpoint::new(reader, writer, server);
    task::spawn(async move {
        let _ = rpc.drive().await;
    });
}

pub async fn handle_control_command<R: SupervisorRuntime>(
    supervisor: &mut Supervisor<R>,
    cmd: ControlCommand,
) {
    match cmd {
        ControlCommand::List { reply } => {
            let list = supervisor
                .inspect_records()
                .into_iter()
                .map(map_record)
                .collect();
            let _ = reply.send(Ok(list)).await;
        }
        ControlCommand::Start { moniker, reply } => {
            let res = supervisor
                .start_component(&moniker)
                .await
                .map(map_record)
                .map_err(map_supervisor_error);
            let _ = reply.send(res).await;
        }
        ControlCommand::Stop { moniker, reply } => {
            let res = supervisor
                .stop_component(&moniker)
                .await
                .map_err(map_supervisor_error);
            let _ = reply.send(res).await;
        }
        ControlCommand::Restart { moniker, reply } => {
            let res = supervisor
                .restart_component(&moniker)
                .await
                .map(map_record)
                .map_err(map_supervisor_error);
            let _ = reply.send(res).await;
        }
    }
}

fn map_record(rec: ComponentStateRecord) -> ComponentStatus {
    ComponentStatus {
        moniker: rec.moniker,
        program: rec.runner.to_owned(),
        state: rec.status.as_str().to_owned(),
        instance_id: rec.instance_id,
        restarts: rec.restarts,
    }
}

fn map_supervisor_error(err: SupervisorError) -> ControlError {
    let kind = match &err {
        SupervisorError::UnknownComponent { .. } => ControlErrorKind::NotFound,
        SupervisorError::Validation(_) => ControlErrorKind::PermissionDenied,
        _ => ControlErrorKind::Internal,
    };
    ControlError {
        kind,
        detail: err.to_string(),
    }
}

struct ControlHandler {
    cmd_tx: Sender<ControlCommand>,
}

impl rpc_cc::RpcHandler for ControlHandler {
    async fn list_components(&self) -> Result<Vec<ComponentStatus>, ControlError> {
        let (tx, rx) = async_channel::bounded(1);
        self.cmd_tx
            .send(ControlCommand::List { reply: tx })
            .await
            .map_err(|_| unavailable())?;
        rx.recv().await.map_err(|_| unavailable())?
    }

    async fn start(&self, moniker: String) -> Result<ComponentStatus, ControlError> {
        let (tx, rx) = async_channel::bounded(1);
        self.cmd_tx
            .send(ControlCommand::Start { moniker, reply: tx })
            .await
            .map_err(|_| unavailable())?;
        rx.recv().await.map_err(|_| unavailable())?
    }

    async fn stop(&self, moniker: String) -> Result<(), ControlError> {
        let (tx, rx) = async_channel::bounded(1);
        self.cmd_tx
            .send(ControlCommand::Stop { moniker, reply: tx })
            .await
            .map_err(|_| unavailable())?;
        rx.recv().await.map_err(|_| unavailable())?
    }

    async fn restart(&self, moniker: String) -> Result<ComponentStatus, ControlError> {
        let (tx, rx) = async_channel::bounded(1);
        self.cmd_tx
            .send(ControlCommand::Restart { moniker, reply: tx })
            .await
            .map_err(|_| unavailable())?;
        rx.recv().await.map_err(|_| unavailable())?
    }
}

fn unavailable() -> ControlError {
    ControlError {
        kind: ControlErrorKind::Unavailable,
        detail: "component-manager supervisor event loop closed".to_owned(),
    }
}

pub fn new_control_queue() -> (Sender<ControlCommand>, Receiver<ControlCommand>) {
    async_channel::bounded(16)
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
                    match ep.read(16 * 1024).await {
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
