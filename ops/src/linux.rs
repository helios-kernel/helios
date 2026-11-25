//! Ergonomic Linux container builder and OCI deployment helpers for `helios-ops`,
//! symmetric with `helios_api::linux`.
//!
//! Enforces compile-time separation between non-filesystem container grants
//! ([`NonFsGrants`]) and filesystem mounts ([`ContainerMount`]).

use helios_oci::{OciError, PulledImage, ResolvedUser};
use helios_wit_rpc::inspector::helios::system::ipc::Endpoint;
use helios_wit_rpc::inspector::helios::system::programs::{
    self as rpc_programs, CapabilityGrant, ContainerConfig as WireContainerConfig,
    ContainerCredentials, ContainerExecRequest, ContainerIdentity,
    ContainerMount as WireContainerMount, ContainerMountSharing as WireContainerMountSharing,
    ExecResult, FilesystemRight,
};

use crate::error::OpsError;
use crate::grants::NonFsGrants;
use crate::session::Session;

/// How a container mount accesses its backing directory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContainerMountSharing {
    Private,
    Shared,
    EphemeralOverlay,
}

/// One filesystem mount inside a Linux container.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContainerMount {
    pub source_path: String,
    pub target_path: String,
    pub rights: Vec<FilesystemRight>,
    pub sharing: ContainerMountSharing,
}

/// Validated container configuration assembled by [`ContainerBuilder`].
#[derive(Debug)]
pub struct ContainerConfig {
    pub root: ContainerMount,
    pub mounts: Vec<ContainerMount>,
    pub shared_owner_uid: u32,
    pub shared_owner_gid: u32,
    pub credentials: ResolvedUser,
    pub hostname: String,
    pub domainname: String,
    pub grants: NonFsGrants,
    pub capability_grants: Vec<CapabilityGrant<Endpoint>>,
    pub default_env: Vec<(String, String)>,
    pub default_cwd: Option<String>,
    pub entrypoint: Vec<String>,
    pub cmd: Vec<String>,
    pub scratch_dir: Option<String>,
}

impl ContainerConfig {
    /// Resolve `(program, args)` from OCI `Entrypoint` / `Cmd` and optional override args.
    #[must_use]
    pub fn resolve_default_command(
        &self,
        override_args: Option<&[String]>,
    ) -> Option<(String, Vec<String>)> {
        let mut full = Vec::new();
        if !self.entrypoint.is_empty() {
            full.extend(self.entrypoint.iter().cloned());
            match override_args {
                Some(extra) => full.extend(extra.iter().cloned()),
                None => full.extend(self.cmd.iter().cloned()),
            }
        } else {
            match override_args {
                Some(extra) => full.extend(extra.iter().cloned()),
                None => full.extend(self.cmd.iter().cloned()),
            }
        }
        let mut iter = full.into_iter();
        let program = iter.next()?;
        Some((program, iter.collect()))
    }
}

/// Fluent Linux container builder for `helios-ops`.
///
/// Accepts [`NonFsGrants`] strictly: passing a `DirectoryGrant` or [`crate::ProcessGrants`]
/// into [`Self::grants`] fails to compile.
#[derive(Clone, Debug)]
pub struct ContainerBuilder {
    root: ContainerMount,
    mounts: Vec<ContainerMount>,
    shared_owner_uid: u32,
    shared_owner_gid: u32,
    credentials: ResolvedUser,
    hostname: String,
    domainname: String,
    grants: NonFsGrants,
    default_env: Vec<(String, String)>,
    default_cwd: Option<String>,
    entrypoint: Vec<String>,
    cmd: Vec<String>,
    scratch_dir: Option<String>,
}

impl ContainerBuilder {
    #[must_use]
    pub fn new(root: ContainerMount) -> Self {
        Self {
            root,
            mounts: Vec::new(),
            shared_owner_uid: 0,
            shared_owner_gid: 0,
            credentials: ResolvedUser::default(),
            hostname: "helios".to_owned(),
            domainname: String::new(),
            grants: NonFsGrants::new(),
            default_env: Vec::new(),
            default_cwd: None,
            entrypoint: Vec::new(),
            cmd: Vec::new(),
            scratch_dir: None,
        }
    }

    /// Start building a container whose `/` is an [`ContainerMountSharing::EphemeralOverlay`]
    /// over `lower_root`.
    #[must_use]
    pub fn ephemeral(lower_root: impl Into<String>) -> Self {
        Self::new(ContainerMount {
            source_path: lower_root.into(),
            target_path: "/".to_owned(),
            rights: vec![
                FilesystemRight::Read,
                FilesystemRight::Write,
                FilesystemRight::MutateDirectory,
                FilesystemRight::Execute,
            ],
            sharing: ContainerMountSharing::EphemeralOverlay,
        })
    }

    /// Build a container directly from a pulled OCI image (`Entrypoint`/`Cmd`, `Env`,
    /// `User`, `WorkingDir`, and ephemeral overlay rootfs).
    pub fn from_image(image: &PulledImage) -> Result<Self, OciError> {
        let rootfs = image.rootfs_path().to_string_lossy().into_owned();
        let resolved_user = image
            .config
            .config
            .resolve_user(Some(image.rootfs_path()))?;
        let mut builder = Self::ephemeral(rootfs);
        builder.shared_owner_uid = resolved_user.uid;
        builder.shared_owner_gid = resolved_user.gid;
        builder.credentials = resolved_user;
        builder.default_env = image.config.config.env_pairs();
        builder.default_cwd = image
            .config
            .config
            .effective_working_dir()
            .map(ToOwned::to_owned);
        builder.entrypoint = image.config.config.entrypoint.clone();
        builder.cmd = image.config.config.cmd.clone();
        Ok(builder)
    }

    #[must_use]
    pub fn mount(mut self, mount: ContainerMount) -> Self {
        self.mounts.push(mount);
        self
    }

    #[must_use]
    pub fn bind_shared_ro(
        self,
        source_path: impl Into<String>,
        target_path: impl Into<String>,
    ) -> Self {
        self.mount(ContainerMount {
            source_path: source_path.into(),
            target_path: target_path.into(),
            rights: vec![FilesystemRight::Read],
            sharing: ContainerMountSharing::Shared,
        })
    }

    #[must_use]
    pub fn bind_shared_rw(
        self,
        source_path: impl Into<String>,
        target_path: impl Into<String>,
    ) -> Self {
        self.mount(ContainerMount {
            source_path: source_path.into(),
            target_path: target_path.into(),
            rights: vec![
                FilesystemRight::Read,
                FilesystemRight::Write,
                FilesystemRight::MutateDirectory,
            ],
            sharing: ContainerMountSharing::Shared,
        })
    }

    #[must_use]
    pub fn bind_private_rwx(
        self,
        source_path: impl Into<String>,
        target_path: impl Into<String>,
    ) -> Self {
        self.mount(ContainerMount {
            source_path: source_path.into(),
            target_path: target_path.into(),
            rights: vec![
                FilesystemRight::Read,
                FilesystemRight::Write,
                FilesystemRight::MutateDirectory,
                FilesystemRight::Execute,
            ],
            sharing: ContainerMountSharing::Private,
        })
    }

    #[must_use]
    pub const fn shared_owner(mut self, uid: u32, gid: u32) -> Self {
        self.shared_owner_uid = uid;
        self.shared_owner_gid = gid;
        self
    }

    #[must_use]
    pub fn user(mut self, uid: u32, gid: u32) -> Self {
        self.credentials = ResolvedUser {
            uid,
            gid,
            supplementary_groups: Vec::new(),
        };
        self
    }

    #[must_use]
    pub fn hostname(mut self, hostname: impl Into<String>) -> Self {
        self.hostname = hostname.into();
        self
    }

    #[must_use]
    pub fn domainname(mut self, domainname: impl Into<String>) -> Self {
        self.domainname = domainname.into();
        self
    }

    /// Configure non-filesystem grants (rejects `DirectoryGrant` and `ProcessGrants` at compile time).
    #[must_use]
    pub fn grants(mut self, grants: NonFsGrants) -> Self {
        self.grants = grants;
        self
    }

    #[must_use]
    pub fn with_grants(mut self, configure: impl FnOnce(NonFsGrants) -> NonFsGrants) -> Self {
        self.grants = configure(self.grants);
        self
    }

    #[must_use]
    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.default_env.push((key.into(), value.into()));
        self
    }

    #[must_use]
    pub fn working_dir(mut self, cwd: impl Into<String>) -> Self {
        self.default_cwd = Some(cwd.into());
        self
    }

    #[must_use]
    pub fn scratch_dir(mut self, dir: impl Into<String>) -> Self {
        self.scratch_dir = Some(dir.into());
        self
    }

    #[must_use]
    pub fn build(self) -> ContainerConfig {
        ContainerConfig {
            root: self.root,
            mounts: self.mounts,
            shared_owner_uid: self.shared_owner_uid,
            shared_owner_gid: self.shared_owner_gid,
            credentials: self.credentials,
            hostname: self.hostname,
            domainname: self.domainname,
            capability_grants: self.grants.clone().into_capability_grants(),
            grants: self.grants,
            default_env: self.default_env,
            default_cwd: self.default_cwd,
            entrypoint: self.entrypoint,
            cmd: self.cmd,
            scratch_dir: self.scratch_dir,
        }
    }

    #[must_use]
    pub fn attach(self, session: Session) -> Container {
        Container {
            session,
            config: self.build(),
        }
    }
}

/// Remote Linux container handle bound to a [`Session`].
pub struct Container {
    session: Session,
    config: ContainerConfig,
}

impl Container {
    #[must_use]
    pub fn ephemeral(lower_root: impl Into<String>) -> ContainerBuilder {
        ContainerBuilder::ephemeral(lower_root)
    }

    pub fn from_image(image: &PulledImage) -> Result<ContainerBuilder, OciError> {
        ContainerBuilder::from_image(image)
    }

    #[must_use]
    pub const fn config(&self) -> &ContainerConfig {
        &self.config
    }

    /// Execute `path` with `args` inside this container over the remote `Session`
    /// using `helios:system/programs.create-container` + `container.exec`.
    pub async fn exec(
        &self,
        path: &str,
        args: &[String],
        extra_env: &[(String, String)],
    ) -> Result<ExecResult, OpsError> {
        let mut env = self.config.default_env.clone();
        for (k, v) in extra_env {
            if let Some(slot) = env.iter_mut().find(|(ek, _)| ek == k) {
                slot.1.clone_from(v);
            } else {
                env.push((k.clone(), v.clone()));
            }
        }
        let map_mount = |m: &ContainerMount| WireContainerMount {
            source_path: m.source_path.clone(),
            target_path: m.target_path.clone(),
            rights: m.rights.clone(),
            sharing: match m.sharing {
                ContainerMountSharing::Private => WireContainerMountSharing::Private,
                ContainerMountSharing::Shared => WireContainerMountSharing::Shared,
                ContainerMountSharing::EphemeralOverlay => {
                    WireContainerMountSharing::EphemeralOverlay
                }
            },
        };
        let wire_cfg = WireContainerConfig {
            root: map_mount(&self.config.root),
            mounts: self.config.mounts.iter().map(map_mount).collect(),
            shared_owner: ContainerIdentity {
                uid: self.config.shared_owner_uid,
                gid: self.config.shared_owner_gid,
            },
            credentials: ContainerCredentials {
                uid: self.config.credentials.uid,
                gid: self.config.credentials.gid,
                supplementary_groups: self.config.credentials.supplementary_groups.clone(),
            },
            hostname: self.config.hostname.clone(),
            domainname: self.config.domainname.clone(),
            capability_grants: self.config.grants.clone().into_capability_grants(),
        };
        let exec_req = ContainerExecRequest {
            name: path.to_owned(),
            args: args.to_vec(),
            env,
            path: path.to_owned(),
            cwd: self.config.default_cwd.clone(),
            stdin: Vec::new(),
            credentials: None,
        };
        let client = rpc_programs::RpcClient::new(self.session.protocol_client().clone());
        let container = client
            .create_container(wire_cfg)
            .await
            .map_err(|source| OpsError::Rpc {
                operation: "system.programs.create-container",
                source,
            })?
            .map_err(OpsError::from)?;
        let res = container
            .exec(exec_req)
            .await
            .map_err(|source| OpsError::Rpc {
                operation: "system.programs.container.exec",
                source,
            })?
            .map_err(OpsError::from)?;
        Ok(res)
    }

    /// Execute the container's OCI `Entrypoint` / `Cmd` (with optional `override_args`).
    pub async fn exec_default(
        &self,
        override_args: Option<&[String]>,
        extra_env: &[(String, String)],
    ) -> Result<ExecResult, OpsError> {
        let Some((program, args)) = self.config.resolve_default_command(override_args) else {
            return Err(OpsError::InvalidGrant {
                spec: "container".to_owned(),
                reason: "container has no Entrypoint or Cmd configured".to_owned(),
            });
        };
        self.exec(&program, &args, extra_env).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use helios_wit_rpc::inspector::helios::system::programs::NetworkRight;
    use std::collections::BTreeMap;
    use tempfile::TempDir;

    #[test]
    fn ops_container_builder_enforces_non_fs_grants_and_maps_oci_image() {
        let dir = TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join("etc")).unwrap();
        std::fs::write(
            dir.path().join("etc/passwd"),
            "root:x:0:0:root:/root:/bin/sh\nrunner:x:2000:2001:runner:/work:/bin/sh\n",
        )
        .unwrap();

        let pulled = PulledImage {
            reference: helios_oci::ImageReference::parse("ghcr.io/lexoliu/worker:v1").unwrap(),
            manifest_digest: helios_oci::Digest::sha256(b"manifest"),
            arch: helios_oci::Arch::Aarch64,
            config: helios_oci::ImageConfig {
                architecture: "arm64".to_owned(),
                os: "linux".to_owned(),
                config: helios_oci::ImageRuntimeConfig {
                    user: Some("runner".to_owned()),
                    env: vec!["PATH=/usr/bin:/bin".to_owned(), "MODE=fast".to_owned()],
                    entrypoint: vec!["/usr/bin/worker".to_owned()],
                    cmd: vec!["--threads".to_owned(), "4".to_owned()],
                    working_dir: Some("/work".to_owned()),
                    labels: BTreeMap::new(),
                    stop_signal: None,
                },
                rootfs: helios_oci::RootFs::default(),
            },
            layer_chain_ids: vec![helios_oci::Digest::sha256(b"layer0")],
            rootfs_path: dir.path().to_path_buf(),
            btrfs_backed: false,
        };

        let cfg = Container::from_image(&pulled)
            .unwrap()
            .bind_shared_rw("/host/data", "/work/data")
            .grants(
                NonFsGrants::new()
                    .network(vec![NetworkRight::Tcp, NetworkRight::Dns])
                    .all_process(),
            )
            .build();

        assert_eq!(cfg.root.sharing, ContainerMountSharing::EphemeralOverlay);
        assert_eq!(cfg.credentials.uid, 2000);
        assert_eq!(cfg.credentials.gid, 2001);
        assert_eq!(cfg.default_cwd.as_deref(), Some("/work"));
        assert_eq!(
            cfg.resolve_default_command(None),
            Some((
                "/usr/bin/worker".to_owned(),
                vec!["--threads".to_owned(), "4".to_owned()]
            ))
        );
        assert!(
            !cfg.capability_grants
                .iter()
                .any(|g| matches!(g, CapabilityGrant::Directory(_)))
        );
    }
}
