//! Per-session attenuated inspector WIT-RPC worker (`/inspector/worker`).
//!
//! Runs inside a sandbox holding ONLY the authenticated credential's attenuated
//! `ProcessAuthority` (granted by `inspector-host` at spawn time) and bridges
//! incoming `helios-wit-rpc` invocations straight to its imported
//! `helios:system/*` and `wasi:filesystem/*` kernel capabilities with zero
//! user-space policy checks.

mod bridge;
mod transport_io;

use std::sync::Arc;

use futures_util::future::{Either, select};
use futures_util::stream::{FuturesUnordered, StreamExt as _};
use helios_api::ipc;
use helios_api::programs::{InheritedSocket, take_inherited_sockets};
use helios_api::serial::DebugPort;
use helios_api::vsock::{self, VsockStream};
use helios_wit_rpc::Endpoint;

use crate::bridge::{LocalTask, TaskSpawner, WorkerDispatcher};
use crate::transport_io::{WorkerTransport, split};

#[helios_api::main]
async fn main() -> Result<(), String> {
    let transport = claim_session_transport()?;
    let (task_tx, task_rx) = async_channel::unbounded::<LocalTask>();
    let spawner = TaskSpawner::new(task_tx);

    // Optional `component-control` IPC channel granted when dynamic component
    // control is enabled and authorized for this session.
    let cc_driver = ipc::take("component-control").map(|ep| {
        let (r, w) = split(WorkerTransport::Ipc(Arc::new(ep)));
        Endpoint::new(r, w, ())
    });
    let cc_peer = cc_driver.as_ref().map(Endpoint::handle);
    if let Some(driver) = cc_driver {
        spawner.spawn(async move {
            let _ = driver.drive().await;
        });
    }

    let (read, write) = split(transport);
    let dispatcher = WorkerDispatcher::new(spawner, cc_peer);
    let endpoint = Endpoint::new(read, write, dispatcher);

    let drive_fut = Box::pin(endpoint.drive());
    let pump_fut = Box::pin(drive_background_pumps(task_rx));

    match select(drive_fut, pump_fut).await {
        Either::Left((Ok(()), _)) => Ok(()),
        Either::Left((Err(err), _)) => Err(format!("inspector-worker RPC endpoint failed: {err}")),
        Either::Right(((), _)) => Ok(()),
    }
}

fn claim_session_transport() -> Result<WorkerTransport, String> {
    if let Some(ipc_ep) = ipc::take("rpc") {
        return Ok(WorkerTransport::Ipc(Arc::new(ipc_ep)));
    }
    for sock in take_inherited_sockets() {
        match sock {
            InheritedSocket::VsockStream(raw) => {
                let mut stream = VsockStream::from_raw(raw);
                stream.set_timeout(vsock::NO_DEADLINE);
                return Ok(WorkerTransport::Vsock(Arc::new(stream)));
            }
            InheritedSocket::Serial(raw) => {
                return Ok(WorkerTransport::Serial(Arc::new(DebugPort::from_raw(raw))));
            }
            _ => {}
        }
    }
    Err(
        "inspector-worker started without an `rpc` IPC channel or inherited session stream"
            .to_owned(),
    )
}

async fn drive_background_pumps(task_rx: async_channel::Receiver<LocalTask>) {
    let mut active = FuturesUnordered::<LocalTask>::new();
    let mut recv_fut = Box::pin(task_rx.recv());
    loop {
        if active.is_empty() {
            match recv_fut.await {
                Ok(task) => {
                    active.push(task);
                    recv_fut = Box::pin(task_rx.recv());
                }
                Err(_) => return,
            }
        } else {
            match select(recv_fut.as_mut(), active.next()).await {
                Either::Left((Ok(task), _)) => {
                    active.push(task);
                    recv_fut.set(task_rx.recv());
                }
                Either::Left((Err(_), _)) => {
                    while active.next().await.is_some() {}
                    return;
                }
                Either::Right((_, _)) => {}
            }
        }
    }
}
