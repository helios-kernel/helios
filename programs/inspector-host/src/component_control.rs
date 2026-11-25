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

fn normalize_moniker(moniker: &str) -> &str {
    let trimmed = moniker.trim_end_matches('/');
    if trimmed.is_empty() && moniker.starts_with('/') {
        "/"
    } else {
        trimmed
    }
}

fn moniker_in_subtree(prefix: &str, moniker: &str) -> bool {
    let norm_prefix = normalize_moniker(prefix);
    let norm_moniker = normalize_moniker(moniker);
    if norm_prefix == "/" || norm_prefix.is_empty() {
        true
    } else {
        norm_moniker == norm_prefix
            || norm_moniker
                .strip_prefix(norm_prefix)
                .is_some_and(|rest| rest.starts_with('/'))
    }
}

pub(crate) fn scope_allows_read(scope: &ScopeRule, moniker: &str) -> bool {
    match scope {
        ScopeRule::Machine => true,
        ScopeRule::Subtree(prefix) => moniker_in_subtree(prefix, moniker),
        ScopeRule::Own => {
            let norm = normalize_moniker(moniker);
            norm == "/inspector" || norm.starts_with("/inspector/")
        }
    }
}

pub(crate) fn scope_allows_mutate(scope: &ScopeRule, moniker: &str) -> bool {
    match scope {
        ScopeRule::Machine => true,
        ScopeRule::Subtree(prefix) => moniker_in_subtree(prefix, moniker),
        // A session's `Own` scope covers only its ephemeral `inspector-worker`
        // instance, NEVER the system-critical `/inspector` host daemon or other
        // managed `/inspector/*` components.
        ScopeRule::Own => false,
    }
}

impl ScopedComponentControl {
    pub fn new(upstream: PeerHandle, scope: ScopeRule) -> Self {
        Self { upstream, scope }
    }

    fn allows_read(&self, moniker: &str) -> bool {
        scope_allows_read(&self.scope, moniker)
    }

    fn allows_mutate(&self, moniker: &str) -> bool {
        scope_allows_mutate(&self.scope, moniker)
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
            .filter(|st| self.allows_read(&st.moniker))
            .collect())
    }

    async fn start(&self, moniker: String) -> Result<ComponentStatus, ControlError> {
        if !self.allows_mutate(&moniker) {
            return Err(ControlError {
                kind: ControlErrorKind::PermissionDenied,
                detail: format!("component `{moniker}` outside granted control scope"),
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
        if !self.allows_mutate(&moniker) {
            return Err(ControlError {
                kind: ControlErrorKind::PermissionDenied,
                detail: format!("component `{moniker}` outside granted control scope"),
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
        if !self.allows_mutate(&moniker) {
            return Err(ControlError {
                kind: ControlErrorKind::PermissionDenied,
                detail: format!("component `{moniker}` outside granted control scope"),
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

#[cfg(test)]
mod tests {
    use helios_inspector_protocol::mux::{MuxConfig, create_mux};
    use helios_wit_rpc::inspector::helios::system::component_control::RpcHandler as _;

    use super::*;

    #[test]
    fn scope_rule_own_refuses_mutating_inspector_components() {
        assert!(!scope_allows_mutate(&ScopeRule::Own, "/inspector"));
        assert!(!scope_allows_mutate(&ScopeRule::Own, "/inspector/"));
        assert!(!scope_allows_mutate(&ScopeRule::Own, "/inspector/tls"));
        assert!(!scope_allows_mutate(&ScopeRule::Own, "/inspector/worker"));
        assert!(!scope_allows_mutate(&ScopeRule::Own, "/core/http"));

        // Read-only visibility still permits inspecting `/inspector` status.
        assert!(scope_allows_read(&ScopeRule::Own, "/inspector"));
        assert!(scope_allows_read(&ScopeRule::Own, "/inspector/tls"));
        assert!(!scope_allows_read(&ScopeRule::Own, "/core/http"));

        // Subtree scope enforces strict `/` boundaries.
        let subtree = ScopeRule::Subtree("/core/http".to_owned());
        assert!(scope_allows_mutate(&subtree, "/core/http"));
        assert!(scope_allows_mutate(&subtree, "/core/http/"));
        assert!(scope_allows_mutate(&subtree, "/core/http/worker"));
        assert!(!scope_allows_mutate(&subtree, "/core/http-client"));
        assert!(!scope_allows_mutate(&subtree, "/inspector"));

        // End-to-end handler check: `stop("/inspector")` and `restart("/inspector")`
        // fail immediately with `PermissionDenied` before touching upstream.
        let (peer, _channels) = create_mux(MuxConfig::default());
        let control = ScopedComponentControl::new(peer, ScopeRule::Own);
        futures_lite::future::block_on(async {
            let stop_err = control
                .stop("/inspector".to_owned())
                .await
                .expect_err("ScopeRule::Own must refuse stop(/inspector)");
            assert_eq!(stop_err.kind, ControlErrorKind::PermissionDenied);

            let stop_slash_err = control
                .stop("/inspector/".to_owned())
                .await
                .expect_err("ScopeRule::Own must refuse stop(/inspector/)");
            assert_eq!(stop_slash_err.kind, ControlErrorKind::PermissionDenied);

            let restart_err = control
                .restart("/inspector".to_owned())
                .await
                .expect_err("ScopeRule::Own must refuse restart(/inspector)");
            assert_eq!(restart_err.kind, ControlErrorKind::PermissionDenied);

            let start_err = control
                .start("/inspector".to_owned())
                .await
                .expect_err("ScopeRule::Own must refuse start(/inspector)");
            assert_eq!(start_err.kind, ControlErrorKind::PermissionDenied);
        });
    }
}
