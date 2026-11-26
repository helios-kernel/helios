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
    self as rpc_cc, ComponentStatus, ControlError, ControlErrorKind, DynamicSubtreeSource,
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

fn is_valid_segment(seg: &str) -> bool {
    !seg.is_empty()
        && seg != "."
        && seg != ".."
        && seg
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

fn canonicalize_abs_moniker(raw: &str) -> Result<String, ControlError> {
    let trimmed = normalize_moniker(raw);
    if trimmed == "/" {
        return Ok("/".to_owned());
    }
    if !trimmed.starts_with('/') {
        return Err(ControlError {
            kind: ControlErrorKind::InvalidArgument,
            detail: format!("moniker `{raw}` must be absolute (start with `/`)"),
        });
    }
    for seg in trimmed[1..].split('/') {
        if seg == ".." {
            return Err(ControlError {
                kind: ControlErrorKind::PermissionDenied,
                detail: format!("moniker `{raw}` contains path traversal `..`"),
            });
        }
        if !is_valid_segment(seg) {
            return Err(ControlError {
                kind: ControlErrorKind::InvalidArgument,
                detail: format!("moniker `{raw}` contains invalid segment `{seg}`"),
            });
        }
    }
    Ok(trimmed.to_owned())
}

fn resolve_manifest_key(parent_norm: &str, key: &str) -> Result<String, ControlError> {
    if key.is_empty() {
        return Err(ControlError {
            kind: ControlErrorKind::InvalidArgument,
            detail: "dynamic manifest key must not be empty".to_owned(),
        });
    }
    if key.starts_with('/') {
        canonicalize_abs_moniker(key)
    } else {
        let trimmed = key.trim_end_matches('/');
        if trimmed.is_empty() {
            return Err(ControlError {
                kind: ControlErrorKind::InvalidArgument,
                detail: format!("invalid relative dynamic manifest key `{key}`"),
            });
        }
        for seg in trimmed.split('/') {
            if seg == ".." {
                return Err(ControlError {
                    kind: ControlErrorKind::PermissionDenied,
                    detail: format!("dynamic manifest key `{key}` contains path traversal `..`"),
                });
            }
            if !is_valid_segment(seg) {
                return Err(ControlError {
                    kind: ControlErrorKind::InvalidArgument,
                    detail: format!(
                        "dynamic manifest key `{key}` contains invalid segment `{seg}`"
                    ),
                });
            }
        }
        if parent_norm == "/" {
            Ok(format!("/{trimmed}"))
        } else {
            Ok(format!("{parent_norm}/{trimmed}"))
        }
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

fn moniker_strictly_under(parent_norm: &str, child_norm: &str) -> bool {
    if parent_norm == "/" {
        child_norm != "/" && child_norm.starts_with('/')
    } else {
        child_norm
            .strip_prefix(parent_norm)
            .is_some_and(|rest| rest.starts_with('/') && rest.len() > 1)
    }
}

fn is_protected_inspector_moniker(moniker: &str) -> bool {
    moniker_in_subtree("/inspector", moniker)
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

pub(crate) fn authorize_mount_dynamic(
    scope: &ScopeRule,
    parent_moniker: &str,
    source: &DynamicSubtreeSource,
) -> Result<(), ControlError> {
    let parent_norm = canonicalize_abs_moniker(parent_moniker)?;
    if is_protected_inspector_moniker(&parent_norm) {
        return Err(ControlError {
            kind: ControlErrorKind::PermissionDenied,
            detail: format!(
                "mounting dynamic components under protected `/inspector` realm (`{parent_moniker}`) is forbidden"
            ),
        });
    }
    if !scope_allows_mutate(scope, &parent_norm) {
        return Err(ControlError {
            kind: ControlErrorKind::PermissionDenied,
            detail: format!("parent realm `{parent_moniker}` outside granted control scope"),
        });
    }
    match source {
        DynamicSubtreeSource::GuestDir(dir) => {
            if dir.subtree_name == ".." || dir.subtree_name.contains('/') {
                return Err(ControlError {
                    kind: ControlErrorKind::PermissionDenied,
                    detail: format!(
                        "dynamic subtree name `{}` must be a single segment without `/` or `..`",
                        dir.subtree_name
                    ),
                });
            }
            if !is_valid_segment(&dir.subtree_name) {
                return Err(ControlError {
                    kind: ControlErrorKind::InvalidArgument,
                    detail: format!("invalid dynamic subtree name `{}`", dir.subtree_name),
                });
            }
            let target_root = if parent_norm == "/" {
                format!("/{}", dir.subtree_name)
            } else {
                format!("{parent_norm}/{}", dir.subtree_name)
            };
            if is_protected_inspector_moniker(&target_root) {
                return Err(ControlError {
                    kind: ControlErrorKind::PermissionDenied,
                    detail: format!(
                        "dynamic subtree target `{target_root}` collides with protected `/inspector` subtree"
                    ),
                });
            }
            if !scope_allows_mutate(scope, &target_root) {
                return Err(ControlError {
                    kind: ControlErrorKind::PermissionDenied,
                    detail: format!(
                        "dynamic subtree target `{target_root}` outside granted control scope"
                    ),
                });
            }
        }
        DynamicSubtreeSource::Manifests(entries) => {
            if entries.is_empty() {
                return Err(ControlError {
                    kind: ControlErrorKind::InvalidArgument,
                    detail: "dynamic manifests list must not be empty".to_owned(),
                });
            }
            for (key, _) in entries {
                let resolved = resolve_manifest_key(&parent_norm, key)?;
                if !moniker_strictly_under(&parent_norm, &resolved) {
                    return Err(ControlError {
                        kind: ControlErrorKind::PermissionDenied,
                        detail: format!(
                            "dynamic manifest key `{key}` escapes parent realm `{parent_norm}`"
                        ),
                    });
                }
                if is_protected_inspector_moniker(&resolved) {
                    return Err(ControlError {
                        kind: ControlErrorKind::PermissionDenied,
                        detail: format!(
                            "dynamic manifest key `{key}` targets protected `/inspector` subtree"
                        ),
                    });
                }
                if !scope_allows_mutate(scope, &resolved) {
                    return Err(ControlError {
                        kind: ControlErrorKind::PermissionDenied,
                        detail: format!(
                            "dynamic manifest key `{key}` outside granted control scope"
                        ),
                    });
                }
            }
        }
    }
    Ok(())
}

pub(crate) fn authorize_unmount_dynamic(
    scope: &ScopeRule,
    moniker: &str,
) -> Result<(), ControlError> {
    let norm = canonicalize_abs_moniker(moniker)?;
    if norm == "/" {
        return Err(ControlError {
            kind: ControlErrorKind::PermissionDenied,
            detail: "cannot unmount root realm `/`".to_owned(),
        });
    }
    if is_protected_inspector_moniker(&norm) {
        return Err(ControlError {
            kind: ControlErrorKind::PermissionDenied,
            detail: format!("cannot unmount protected `/inspector` component `{moniker}`"),
        });
    }
    if !scope_allows_mutate(scope, &norm) {
        return Err(ControlError {
            kind: ControlErrorKind::PermissionDenied,
            detail: format!("component `{moniker}` outside granted control scope"),
        });
    }
    Ok(())
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

    async fn mount_dynamic(
        &self,
        parent_moniker: String,
        source: DynamicSubtreeSource,
    ) -> Result<String, ControlError> {
        authorize_mount_dynamic(&self.scope, &parent_moniker, &source)?;
        self.client()
            .mount_dynamic(parent_moniker, source)
            .await
            .map_err(|err| ControlError {
                kind: ControlErrorKind::Unavailable,
                detail: err.to_string(),
            })?
    }

    async fn unmount_dynamic(&self, moniker: String) -> Result<(), ControlError> {
        authorize_unmount_dynamic(&self.scope, &moniker)?;
        self.client()
            .unmount_dynamic(moniker)
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

    #[test]
    fn mount_and_unmount_dynamic_enforce_scope_rules_and_protect_inspector() {
        use helios_wit_rpc::inspector::helios::system::component_control::DynamicDirSource;

        let dir_source = |name: &str| {
            DynamicSubtreeSource::GuestDir(DynamicDirSource {
                subtree_name: name.to_owned(),
                path: "/data/ext".to_owned(),
            })
        };
        let manifests_source = |entries: &[(&str, &str)]| {
            DynamicSubtreeSource::Manifests(
                entries
                    .iter()
                    .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                    .collect(),
            )
        };

        // 1. ScopeRule::Own denies all dynamic mount/unmount operations.
        let (peer_own, _ch_own) = create_mux(MuxConfig::default());
        let own_ctl = ScopedComponentControl::new(peer_own, ScopeRule::Own);
        futures_lite::future::block_on(async {
            for parent in ["/", "/apps", "/inspector", "/inspector/worker"] {
                let err = own_ctl
                    .mount_dynamic(parent.to_owned(), dir_source("ext"))
                    .await
                    .expect_err("ScopeRule::Own must refuse mount_dynamic");
                assert_eq!(err.kind, ControlErrorKind::PermissionDenied);
            }
            for target in ["/", "/apps/ext", "/inspector", "/inspector/tls"] {
                let err = own_ctl
                    .unmount_dynamic(target.to_owned())
                    .await
                    .expect_err("ScopeRule::Own must refuse unmount_dynamic");
                assert_eq!(err.kind, ControlErrorKind::PermissionDenied);
            }
        });

        // 2. ScopeRule::Subtree("/apps") allows mounting/unmounting strictly under `/apps`,
        //    rejects out-of-scope parents, sibling prefixes, `/inspector`, `/`, and escaping keys.
        let subtree = ScopeRule::Subtree("/apps".to_owned());
        assert!(authorize_mount_dynamic(&subtree, "/apps", &dir_source("svc")).is_ok());
        assert!(
            authorize_mount_dynamic(
                &subtree,
                "/apps",
                &manifests_source(&[
                    ("/apps/svc", "runner = \"realm\""),
                    ("/apps/svc/web", "runner = \"wasm\"\nprogram = \"/bin/web\""),
                ]),
            )
            .is_ok()
        );
        assert!(
            authorize_mount_dynamic(
                &subtree,
                "/apps",
                &manifests_source(&[("svc", "runner = \"realm\"")]),
            )
            .is_ok()
        );
        assert!(authorize_unmount_dynamic(&subtree, "/apps/svc").is_ok());

        let (peer_sub, _ch_sub) = create_mux(MuxConfig::default());
        let sub_ctl = ScopedComponentControl::new(peer_sub, subtree);
        futures_lite::future::block_on(async {
            // Out-of-scope parent, sibling prefix, and `/inspector`.
            for bad_parent in ["/", "/core", "/apps-evil", "/inspector", "/inspector/sub"] {
                let err = sub_ctl
                    .mount_dynamic(bad_parent.to_owned(), dir_source("svc"))
                    .await
                    .expect_err("Subtree(/apps) must reject out-of-scope parent");
                assert_eq!(err.kind, ControlErrorKind::PermissionDenied, "{bad_parent}");
            }
            // Manifest key escaping `/apps` (sibling, parent itself, `/inspector`, or `..`).
            for bad_key in [
                "/apps",
                "/apps-evil/svc",
                "/core/svc",
                "/inspector/svc",
                "../escape",
                "/apps/../inspector/svc",
            ] {
                let err = sub_ctl
                    .mount_dynamic(
                        "/apps".to_owned(),
                        manifests_source(&[(bad_key, "runner = \"realm\"")]),
                    )
                    .await
                    .expect_err("Subtree(/apps) must reject escaping manifest key");
                assert_eq!(err.kind, ControlErrorKind::PermissionDenied, "{bad_key}");
            }
            // Unmount refusals.
            for bad_target in [
                "/",
                "/inspector",
                "/inspector/worker",
                "/core/svc",
                "/apps-evil/x",
            ] {
                let err = sub_ctl
                    .unmount_dynamic(bad_target.to_owned())
                    .await
                    .expect_err("Subtree(/apps) must reject out-of-scope/protected unmount");
                assert_eq!(err.kind, ControlErrorKind::PermissionDenied, "{bad_target}");
            }
        });

        // 3. ScopeRule::Machine permits mounting/unmounting normal realms,
        //    but STILL refuses `/inspector`, `/inspector/*`, `/` unmount, or colliding targets.
        let machine = ScopeRule::Machine;
        assert!(authorize_mount_dynamic(&machine, "/", &dir_source("apps")).is_ok());
        assert!(authorize_mount_dynamic(&machine, "/apps", &dir_source("svc")).is_ok());
        assert!(
            authorize_mount_dynamic(
                &machine,
                "/apps",
                &manifests_source(&[("/apps/svc", "runner = \"realm\"")]),
            )
            .is_ok()
        );
        assert!(authorize_unmount_dynamic(&machine, "/apps/svc").is_ok());

        let (peer_mach, _ch_mach) = create_mux(MuxConfig::default());
        let mach_ctl = ScopedComponentControl::new(peer_mach, machine);
        futures_lite::future::block_on(async {
            for bad_parent in ["/inspector", "/inspector/", "/inspector/tls"] {
                let err = mach_ctl
                    .mount_dynamic(bad_parent.to_owned(), dir_source("ext"))
                    .await
                    .expect_err("Machine scope must still refuse mounting under /inspector");
                assert_eq!(err.kind, ControlErrorKind::PermissionDenied, "{bad_parent}");
            }
            // Mounting subtree named `inspector` under `/` must be refused.
            let err = mach_ctl
                .mount_dynamic("/".to_owned(), dir_source("inspector"))
                .await
                .expect_err("Machine scope must refuse mounting /inspector via subtree_name");
            assert_eq!(err.kind, ControlErrorKind::PermissionDenied);

            // Manifest key targeting `/inspector` under `/` must be refused.
            let err = mach_ctl
                .mount_dynamic(
                    "/".to_owned(),
                    manifests_source(&[("/inspector/evil", "runner = \"realm\"")]),
                )
                .await
                .expect_err("Machine scope must refuse manifest key under /inspector");
            assert_eq!(err.kind, ControlErrorKind::PermissionDenied);

            // Unmounting `/`, `/inspector`, `/inspector/tls`, `/inspector/worker` must be refused.
            for protected in [
                "/",
                "/inspector",
                "/inspector/",
                "/inspector/tls",
                "/inspector/worker",
            ] {
                let err = mach_ctl
                    .unmount_dynamic(protected.to_owned())
                    .await
                    .expect_err("Machine scope must refuse unmounting / or /inspector/*");
                assert_eq!(err.kind, ControlErrorKind::PermissionDenied, "{protected}");
            }
        });
    }
}
