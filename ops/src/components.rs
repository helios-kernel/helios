//! Remote component-topology inspection and lifecycle control over
//! `helios:system/component-control`.

use helios_wit_rpc::inspector::helios::system::component_control::{
    self as rpc_cc, ComponentStatus,
};
pub use helios_wit_rpc::inspector::helios::system::component_control::{
    DynamicDirSource, DynamicSubtreeSource,
};

use crate::error::OpsError;
use crate::session::Session;
use crate::target::{GrantRight, normalize_scope, scope_contains};

/// Component-control client bound to a [`Session`].
#[derive(Clone)]
pub struct ComponentsClient {
    session: Session,
}

impl ComponentsClient {
    #[must_use]
    pub const fn new(session: Session) -> Self {
        Self { session }
    }

    fn require_scope(&self, moniker: &str, right: GrantRight) -> Result<String, OpsError> {
        let normalized = normalize_scope(moniker);
        let active_scope = normalize_scope(self.session.options().attenuation.effective_scope());
        if !scope_contains(&active_scope, &normalized) {
            return Err(OpsError::AttenuationDenied {
                capability: right.as_str().to_owned(),
                scope: active_scope,
            });
        }
        Ok(normalized)
    }

    /// List live and configured components under the session's authorized scope.
    pub async fn list(&self) -> Result<Vec<ComponentStatus>, OpsError> {
        self.session.require_right(GrantRight::InstanceRead)?;
        let client = rpc_cc::RpcClient::new(self.session.protocol_client().clone());
        let mut items = self
            .session
            .call(
                "system.component-control.list-components",
                client.list_components(),
            )
            .await?
            .map_err(|err| OpsError::from_component_control("list-components", err))?;
        let active_scope = normalize_scope(self.session.options().attenuation.effective_scope());
        if active_scope != "/" {
            items.retain(|item| scope_contains(&active_scope, &normalize_scope(&item.moniker)));
        }
        Ok(items)
    }

    /// Inspect the current status of a single component by moniker.
    pub async fn status(&self, moniker: &str) -> Result<ComponentStatus, OpsError> {
        let normalized = self.require_scope(moniker, GrantRight::InstanceRead)?;
        let components = self.list().await?;
        components
            .into_iter()
            .find(|c| normalize_scope(&c.moniker) == normalized)
            .ok_or_else(|| OpsError::NotFound { path: normalized })
    }

    /// Start a configured component by moniker.
    pub async fn start(&self, moniker: &str) -> Result<ComponentStatus, OpsError> {
        self.session.require_right(GrantRight::InstanceControl)?;
        let _ = self.require_scope(moniker, GrantRight::InstanceControl)?;
        let client = rpc_cc::RpcClient::new(self.session.protocol_client().clone());
        self.session
            .call(
                "system.component-control.start",
                client.start(moniker.to_owned()),
            )
            .await?
            .map_err(|err| OpsError::from_component_control("start", err))
    }

    /// Stop a running component by moniker.
    pub async fn stop(&self, moniker: &str) -> Result<(), OpsError> {
        self.session.require_right(GrantRight::InstanceControl)?;
        let _ = self.require_scope(moniker, GrantRight::InstanceControl)?;
        let client = rpc_cc::RpcClient::new(self.session.protocol_client().clone());
        self.session
            .call(
                "system.component-control.stop",
                client.stop(moniker.to_owned()),
            )
            .await?
            .map_err(|err| OpsError::from_component_control("stop", err))
    }

    /// Restart a configured component by moniker.
    pub async fn restart(&self, moniker: &str) -> Result<ComponentStatus, OpsError> {
        self.session.require_right(GrantRight::InstanceControl)?;
        let _ = self.require_scope(moniker, GrantRight::InstanceControl)?;
        let client = rpc_cc::RpcClient::new(self.session.protocol_client().clone());
        self.session
            .call(
                "system.component-control.restart",
                client.restart(moniker.to_owned()),
            )
            .await?
            .map_err(|err| OpsError::from_component_control("restart", err))
    }

    /// Mount a validated dynamic component subtree under `parent_moniker`,
    /// returning the mounted subtree root moniker.
    pub async fn mount_dynamic(
        &self,
        parent_moniker: &str,
        source: DynamicSubtreeSource,
    ) -> Result<String, OpsError> {
        self.session.require_right(GrantRight::InstanceControl)?;
        let _ = self.require_scope(parent_moniker, GrantRight::InstanceControl)?;
        let client = rpc_cc::RpcClient::new(self.session.protocol_client().clone());
        self.session
            .call(
                "system.component-control.mount-dynamic",
                client.mount_dynamic(parent_moniker.to_owned(), source),
            )
            .await?
            .map_err(|err| OpsError::from_component_control("mount-dynamic", err))
    }

    /// Mount a dynamic component subtree from a guest directory holding `component.toml`.
    pub async fn mount_dynamic_dir(
        &self,
        parent_moniker: &str,
        subtree_name: &str,
        path: &str,
    ) -> Result<String, OpsError> {
        self.mount_dynamic(
            parent_moniker,
            DynamicSubtreeSource::GuestDir(DynamicDirSource {
                subtree_name: subtree_name.to_owned(),
                path: path.to_owned(),
            }),
        )
        .await
    }

    /// Mount a dynamic component subtree from inline `(relative_path, manifest_toml)` pairs.
    pub async fn mount_dynamic_manifests(
        &self,
        parent_moniker: &str,
        manifests: Vec<(String, String)>,
    ) -> Result<String, OpsError> {
        self.mount_dynamic(parent_moniker, DynamicSubtreeSource::Manifests(manifests))
            .await
    }

    /// Gracefully stop and unmount a previously mounted dynamic subtree.
    pub async fn unmount_dynamic(&self, moniker: &str) -> Result<(), OpsError> {
        self.session.require_right(GrantRight::InstanceControl)?;
        let _ = self.require_scope(moniker, GrantRight::InstanceControl)?;
        let client = rpc_cc::RpcClient::new(self.session.protocol_client().clone());
        self.session
            .call(
                "system.component-control.unmount-dynamic",
                client.unmount_dynamic(moniker.to_owned()),
            )
            .await?
            .map_err(|err| OpsError::from_component_control("unmount-dynamic", err))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::os::unix::net::UnixStream;
    use std::sync::Mutex;

    use async_io::Async;
    use helios_wit_rpc::Endpoint;
    use helios_wit_rpc::inspector::helios::system::component_control::{
        self as rpc_cc, ComponentStatus, ControlError, ControlErrorKind,
    };

    use crate::error::OpsError;
    use crate::session::{Session, SessionOptions};
    use crate::target::{Attenuation, Target};
    use crate::transport::RpcConnection;

    struct FakeComponents {
        items: Mutex<BTreeMap<String, ComponentStatus>>,
    }

    impl rpc_cc::RpcHandler for FakeComponents {
        async fn list_components(&self) -> Result<Vec<ComponentStatus>, ControlError> {
            Ok(self.items.lock().expect("lock").values().cloned().collect())
        }

        async fn start(&self, moniker: String) -> Result<ComponentStatus, ControlError> {
            let mut guard = self.items.lock().expect("lock");
            let entry = guard.get_mut(&moniker).ok_or(ControlError {
                kind: ControlErrorKind::NotFound,
                detail: moniker,
            })?;
            entry.state = "running".to_owned();
            entry.instance_id = Some(42);
            Ok(entry.clone())
        }

        async fn stop(&self, moniker: String) -> Result<(), ControlError> {
            let mut guard = self.items.lock().expect("lock");
            let entry = guard.get_mut(&moniker).ok_or(ControlError {
                kind: ControlErrorKind::NotFound,
                detail: moniker,
            })?;
            entry.state = "stopped".to_owned();
            entry.instance_id = None;
            Ok(())
        }

        async fn restart(&self, moniker: String) -> Result<ComponentStatus, ControlError> {
            let mut guard = self.items.lock().expect("lock");
            let entry = guard.get_mut(&moniker).ok_or(ControlError {
                kind: ControlErrorKind::NotFound,
                detail: moniker,
            })?;
            entry.state = "running".to_owned();
            entry.restarts += 1;
            Ok(entry.clone())
        }

        async fn mount_dynamic(
            &self,
            parent_moniker: String,
            source: super::DynamicSubtreeSource,
        ) -> Result<String, ControlError> {
            let name = match source {
                super::DynamicSubtreeSource::GuestDir(dir) => dir.subtree_name,
                super::DynamicSubtreeSource::Manifests(entries) => entries
                    .first()
                    .and_then(|(p, _)| p.split('/').next())
                    .filter(|seg| !seg.is_empty() && *seg != "component.toml")
                    .unwrap_or("dynamic")
                    .to_owned(),
            };
            let prefix = parent_moniker.trim_end_matches('/');
            let mounted = format!("{prefix}/{name}");
            let mut guard = self.items.lock().expect("lock");
            if guard.contains_key(&mounted) {
                return Err(ControlError {
                    kind: ControlErrorKind::AlreadyExists,
                    detail: mounted,
                });
            }
            guard.insert(
                mounted.clone(),
                ComponentStatus {
                    moniker: mounted.clone(),
                    program: "/bin/dynamic".to_owned(),
                    state: "running".to_owned(),
                    instance_id: Some(99),
                    restarts: 0,
                },
            );
            Ok(mounted)
        }

        async fn unmount_dynamic(&self, moniker: String) -> Result<(), ControlError> {
            let mut guard = self.items.lock().expect("lock");
            if guard.remove(&moniker).is_none() {
                return Err(ControlError {
                    kind: ControlErrorKind::NotFound,
                    detail: moniker,
                });
            }
            Ok(())
        }
    }

    #[tokio::test]
    async fn components_client_lifecycle_and_scope_attenuation() {
        let mut initial = BTreeMap::new();
        initial.insert(
            "/core/http".to_owned(),
            ComponentStatus {
                moniker: "/core/http".to_owned(),
                program: "/bin/http".to_owned(),
                state: "stopped".to_owned(),
                instance_id: None,
                restarts: 0,
            },
        );
        initial.insert(
            "/apps/worker".to_owned(),
            ComponentStatus {
                moniker: "/apps/worker".to_owned(),
                program: "/bin/worker".to_owned(),
                state: "running".to_owned(),
                instance_id: Some(7),
                restarts: 0,
            },
        );

        let (host, guest) = UnixStream::pair().expect("pair");
        host.set_nonblocking(true).expect("host nb");
        guest.set_nonblocking(true).expect("guest nb");
        let host_r = host.try_clone().expect("clone");
        let guest_r = guest.try_clone().expect("clone");
        let conn = RpcConnection::from_split(
            Box::new(Async::new(host_r).expect("async")),
            Box::new(Async::new(host).expect("async")),
        );
        let session = Session::from_connection(
            Target::new("comp-test", "serial:///tmp/comp.sock").expect("target"),
            conn,
            SessionOptions::default(),
        );
        let ep = Endpoint::new(
            Async::new(guest_r).expect("async"),
            Async::new(guest).expect("async"),
            rpc_cc::RpcServer::new(FakeComponents {
                items: Mutex::new(initial),
            }),
        );
        let server_task = tokio::spawn(async move {
            let _ = ep.drive().await;
        });

        let client = session.components();
        let all = client.list().await.expect("list");
        assert_eq!(all.len(), 2);

        let started = client.start("/core/http").await.expect("start");
        assert_eq!(started.state, "running");
        assert_eq!(started.instance_id, Some(42));

        let restarted = client.restart("/core/http").await.expect("restart");
        assert_eq!(restarted.restarts, 1);

        client.stop("/core/http").await.expect("stop");
        let st = client.status("/core/http").await.expect("status");
        assert_eq!(st.state, "stopped");

        // Dynamic mount (guest dir & inline manifests) + unmount.
        let mounted_dir = client
            .mount_dynamic_dir("/core", "edge", "/data/edge")
            .await
            .expect("mount_dynamic_dir");
        assert_eq!(mounted_dir, "/core/edge");
        let mounted_inline = client
            .mount_dynamic_manifests(
                "/core",
                vec![(
                    "helper/component.toml".to_owned(),
                    "program = \"/bin/helper\"\n".to_owned(),
                )],
            )
            .await
            .expect("mount_dynamic_manifests");
        assert_eq!(mounted_inline, "/core/helper");
        client
            .unmount_dynamic(&mounted_dir)
            .await
            .expect("unmount_dynamic dir");
        client
            .unmount_dynamic(&mounted_inline)
            .await
            .expect("unmount_dynamic inline");

        // Monotonic scope attenuation hides out-of-scope components and refuses control.
        let scoped = session
            .attenuated(Attenuation {
                scope: Some("/core".to_owned()),
                only: Default::default(),
            })
            .expect("attenuate");
        let scoped_list = scoped.components().list().await.expect("scoped list");
        assert_eq!(scoped_list.len(), 1);
        assert_eq!(scoped_list[0].moniker, "/core/http");
        assert!(matches!(
            scoped.components().start("/apps/worker").await,
            Err(OpsError::AttenuationDenied { .. })
        ));
        assert!(matches!(
            scoped
                .components()
                .mount_dynamic_dir("/apps", "x", "/data/x")
                .await,
            Err(OpsError::AttenuationDenied { .. })
        ));
        assert!(matches!(
            scoped.components().unmount_dynamic("/apps/worker").await,
            Err(OpsError::AttenuationDenied { .. })
        ));

        server_task.abort();
    }
}
