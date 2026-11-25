//! Scoped `helios:system/component-control` IPC bridge from `inspector-worker`
//! to `component-manager` (`programs/init`) when `--dynamic-components` is
//! enabled and the session credential explicitly grants `component_control`.
//!
//! This control channel is completely separate from the session RPC data plane
//! (`inspector-tls <-> inspector-worker` or direct `vsock`/`serial`).

use std::sync::Arc;

use futures_util::AsyncReadExt as _;
use helios_api::ipc::Endpoint as IpcEndpoint;
use helios_inspector_protocol::auth::ScopeRule;
use helios_wit_rpc::inspector::helios::system::component_control::{
    self as rpc_cc, ComponentStatus, ControlError, ControlErrorKind,
};
use helios_wit_rpc::{Endpoint, PeerHandle};

use crate::transport_io::IpcIo;

pub struct ScopedComponentControl {
    upstream: PeerHandle,
    scope: ScopeRule,
}

impl ScopedComponentControl {
    pub fn new(upstream: PeerHandle, scope: ScopeRule) -> Self {
        Self { upstream, scope }
    }

    fn allows_moniker(&self, moniker: &str) -> bool {
        match &self.scope {
            ScopeRule::Machine => true,
            ScopeRule::Subtree(prefix) => {
                if prefix == "/" || prefix.is_empty() {
                    true
                } else {
                    let trimmed = prefix.trim_end_matches('/');
                    moniker == trimmed
                        || moniker
                            .strip_prefix(trimmed)
                            .is_some_and(|rest| rest.starts_with('/'))
                }
            }
            ScopeRule::Own => moniker == "/inspector" || moniker.starts_with("/inspector/"),
        }
    }

    fn client(&self) -> rpc_cc::RpcClient {
        rpc_cc::RpcClient::new(self.upstream.clone())
    }
}

impl rpc_cc::RpcHandler for ScopedComponentControl {
    async fn list_components(&self) -> Result<Vec<ComponentStatus>, ControlError> {
        let all = self
            .client()
            .list_components()
            .await
            .map_err(|err| ControlError {
                kind: ControlErrorKind::Unavailable,
                detail: err.to_string(),
            })??;
        Ok(all
            .into_iter()
            .filter(|st| self.allows_moniker(&st.moniker))
            .collect())
    }

    async fn start(&self, moniker: String) -> Result<ComponentStatus, ControlError> {
        if !self.allows_moniker(&moniker) {
            return Err(ControlError {
                kind: ControlErrorKind::PermissionDenied,
                detail: format!("component `{moniker}` outside granted scope"),
            });
        }
        self.client()
            .start(moniker)
            .await
            .map_err(|err| ControlError {
                kind: ControlErrorKind::Unavailable,
                detail: err.to_string(),
            })?
    }

    async fn stop(&self, moniker: String) -> Result<(), ControlError> {
        if !self.allows_moniker(&moniker) {
            return Err(ControlError {
                kind: ControlErrorKind::PermissionDenied,
                detail: format!("component `{moniker}` outside granted scope"),
            });
        }
        self.client()
            .stop(moniker)
            .await
            .map_err(|err| ControlError {
                kind: ControlErrorKind::Unavailable,
                detail: err.to_string(),
            })?
    }

    async fn restart(&self, moniker: String) -> Result<ComponentStatus, ControlError> {
        if !self.allows_moniker(&moniker) {
            return Err(ControlError {
                kind: ControlErrorKind::PermissionDenied,
                detail: format!("component `{moniker}` outside granted scope"),
            });
        }
        self.client()
            .restart(moniker)
            .await
            .map_err(|err| ControlError {
                kind: ControlErrorKind::Unavailable,
                detail: err.to_string(),
            })?
    }
}

/// Drives the upstream IPC endpoint to `component-manager` and returns its
/// clonable [`PeerHandle`].
pub fn connect_upstream(
    ep: IpcEndpoint,
) -> (PeerHandle, impl std::future::Future<Output = ()> + 'static) {
    let io = IpcIo::new(ep);
    let (read, write) = io.split();
    let endpoint = Endpoint::new(read, write, ());
    let handle = endpoint.handle();
    let driver = async move {
        let _ = endpoint.drive().await;
    };
    (handle, driver)
}

/// Drives a per-session scoped `component-control` endpoint for one
/// `inspector-worker`.
pub async fn serve_worker_control(ep: IpcEndpoint, upstream: Arc<PeerHandle>, scope: ScopeRule) {
    let io = IpcIo::new(ep);
    let (read, write) = io.split();
    let server = rpc_cc::RpcServer::new(ScopedComponentControl::new((*upstream).clone(), scope));
    let endpoint = Endpoint::new(read, write, server);
    let _ = endpoint.drive().await;
}
