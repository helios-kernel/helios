//! Ergonomic RAII Linux container API (`Container`, `ContainerBuilder`, `ContainerCommand`).
//!
//! Enforces compile-time separation between non-filesystem capabilities ([`NonFsGrants`])
//! and filesystem mounts (`root` and `mounts`): passing a [`DirectoryGrant`] or
//! [`ProcessGrants`] into [`ContainerBuilder::grants`] is a compile error.
//!
//! When the `oci` feature is enabled, [`Container::from_image`] maps an OCI image's
//! `Entrypoint`/`Cmd`, `Env`, `User`, and `WorkingDir` directly onto a kernel
//! [`ContainerMountSharing::EphemeralOverlay`] container.

use thiserror::Error;

use crate::programs::{
    Child, Container as RawContainer, ContainerConfig, ContainerCredentials, ContainerExecRequest,
    ContainerIdentity, ContainerMount, ContainerMountSharing, ContainerSpawnRequest, ExecError,
    ExecResult, FilesystemRight, InheritedSocket, NonFsGrants, SpawnError,
};

/// Errors constructing a [`ContainerBuilder`] or resolving a container's default OCI command.
#[derive(Debug, Error)]
pub enum ContainerBuildError {
    #[cfg(feature = "oci")]
    #[error("failed to resolve OCI image config: {0}")]
    Oci(#[from] helios_oci::OciError),
    #[error("container has no default Entrypoint or Cmd configured")]
    NoDefaultCommand,
    #[error("container mount target `{target}` must be an absolute path")]
    InvalidMountTarget { target: String },
}

/// Complete specification built by [`ContainerBuilder`], useful for inspection and testing
/// before creating the kernel container handle.
#[derive(Debug)]
pub struct ContainerSpec {
    pub config: ContainerConfig,
    pub default_env: Vec<(String, String)>,
    pub default_cwd: Option<String>,
    pub entrypoint: Vec<String>,
    pub cmd: Vec<String>,
}

impl ContainerSpec {
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

/// Fluent builder for a kernel Linux [`Container`].
///
/// Filesystem access is configured strictly through `root` and `.bind_*` / `.mount(...)`;
/// non-filesystem capabilities are configured strictly through `.grants(NonFsGrants)` so
/// passing a [`crate::programs::DirectoryGrant`] is rejected at compile time.
pub struct ContainerBuilder {
    root: ContainerMount,
    mounts: Vec<ContainerMount>,
    shared_owner: ContainerIdentity,
    credentials: ContainerCredentials,
    hostname: String,
    domainname: String,
    grants: NonFsGrants,
    default_env: Vec<(String, String)>,
    default_cwd: Option<String>,
    entrypoint: Vec<String>,
    cmd: Vec<String>,
}

impl ContainerBuilder {
    /// Start building a container with an explicit root [`ContainerMount`].
    #[must_use]
    pub fn new(root: ContainerMount) -> Self {
        Self {
            root,
            mounts: Vec::new(),
            shared_owner: ContainerIdentity { uid: 0, gid: 0 },
            credentials: ContainerCredentials {
                uid: 0,
                gid: 0,
                supplementary_groups: Vec::new(),
            },
            hostname: "helios".to_owned(),
            domainname: String::new(),
            grants: NonFsGrants::new(),
            default_env: Vec::new(),
            default_cwd: None,
            entrypoint: Vec::new(),
            cmd: Vec::new(),
        }
    }

    /// Start building a container whose `/` is an [`ContainerMountSharing::EphemeralOverlay`]
    /// over a read-only lower directory `lower_root`.
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

    /// Build a container directly from a pulled OCI image, mapping its read-only rootfs as
    /// an [`ContainerMountSharing::EphemeralOverlay`] along with its `Entrypoint`, `Cmd`,
    /// `Env`, `User`, and `WorkingDir`.
    #[cfg(feature = "oci")]
    pub fn from_image(image: &helios_oci::PulledImage) -> Result<Self, ContainerBuildError> {
        let rootfs = image.rootfs_path().to_string_lossy().into_owned();
        let resolved_user = image
            .config
            .config
            .resolve_user(Some(image.rootfs_path()))?;
        let mut builder = Self::ephemeral(rootfs);
        builder.credentials = ContainerCredentials {
            uid: resolved_user.uid,
            gid: resolved_user.gid,
            supplementary_groups: resolved_user.supplementary_groups,
        };
        builder.shared_owner = ContainerIdentity {
            uid: resolved_user.uid,
            gid: resolved_user.gid,
        };
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

    /// Attach an explicit additional [`ContainerMount`].
    #[must_use]
    pub fn mount(mut self, mount: ContainerMount) -> Self {
        self.mounts.push(mount);
        self
    }

    /// Bind-mount a shared Helios host directory read-only at `target_path`.
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

    /// Bind-mount a shared Helios host directory read-write at `target_path`.
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

    /// Bind-mount a shared Helios host directory read-write-execute at `target_path`.
    #[must_use]
    pub fn bind_shared_rwx(
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
            sharing: ContainerMountSharing::Shared,
        })
    }

    /// Bind-mount an exclusive private Helios directory read-write-execute at `target_path`.
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

    /// Mount an ephemeral writable overlay over a read-only lower directory at `target_path`.
    #[must_use]
    pub fn bind_ephemeral_overlay(
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
            sharing: ContainerMountSharing::EphemeralOverlay,
        })
    }

    /// Set the owner/group presented for files on shared mounts inside this container.
    #[must_use]
    pub const fn shared_owner(mut self, uid: u32, gid: u32) -> Self {
        self.shared_owner = ContainerIdentity { uid, gid };
        self
    }

    /// Set default process credentials (`uid`, `gid`, no supplementary groups).
    #[must_use]
    pub fn user(mut self, uid: u32, gid: u32) -> Self {
        self.credentials = ContainerCredentials {
            uid,
            gid,
            supplementary_groups: Vec::new(),
        };
        self
    }

    /// Set full default process credentials.
    #[must_use]
    pub fn credentials(mut self, credentials: ContainerCredentials) -> Self {
        self.credentials = credentials;
        self
    }

    /// Set the container UTS hostname.
    #[must_use]
    pub fn hostname(mut self, hostname: impl Into<String>) -> Self {
        self.hostname = hostname.into();
        self
    }

    /// Set the container UTS domain name.
    #[must_use]
    pub fn domainname(mut self, domainname: impl Into<String>) -> Self {
        self.domainname = domainname.into();
        self
    }

    /// Configure non-filesystem capabilities for this container.
    ///
    /// Accepts [`NonFsGrants`] strictly: passing a [`crate::programs::DirectoryGrant`] or
    /// [`crate::programs::ProcessGrants`] is rejected at compile time.
    #[must_use]
    pub fn grants(mut self, grants: NonFsGrants) -> Self {
        self.grants = grants;
        self
    }

    /// Mutate the container's [`NonFsGrants`] inline.
    #[must_use]
    pub fn with_grants(mut self, configure: impl FnOnce(NonFsGrants) -> NonFsGrants) -> Self {
        self.grants = configure(self.grants);
        self
    }

    /// Add a container-wide default environment variable (merged underneath per-command `env`).
    #[must_use]
    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.default_env.push((key.into(), value.into()));
        self
    }

    /// Extend container-wide default environment variables.
    #[must_use]
    pub fn envs<I, K, V>(mut self, vars: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        for (k, v) in vars {
            self.default_env.push((k.into(), v.into()));
        }
        self
    }

    /// Set container-wide default working directory.
    #[must_use]
    pub fn working_dir(mut self, cwd: impl Into<String>) -> Self {
        self.default_cwd = Some(cwd.into());
        self
    }

    /// Override the container's default OCI `Entrypoint`.
    #[must_use]
    pub fn entrypoint<I, S>(mut self, entrypoint: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.entrypoint = entrypoint.into_iter().map(Into::into).collect();
        self
    }

    /// Override the container's default OCI `Cmd`.
    #[must_use]
    pub fn default_cmd<I, S>(mut self, cmd: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.cmd = cmd.into_iter().map(Into::into).collect();
        self
    }

    /// Consume the builder and return the validated [`ContainerSpec`] (without invoking the kernel).
    #[must_use]
    pub fn into_spec(self) -> ContainerSpec {
        let config = ContainerConfig {
            root: self.root,
            mounts: self.mounts,
            shared_owner: self.shared_owner,
            credentials: self.credentials,
            hostname: self.hostname,
            domainname: self.domainname,
            capability_grants: self.grants.into_capability_grants(),
        };
        ContainerSpec {
            config,
            default_env: self.default_env,
            default_cwd: self.default_cwd,
            entrypoint: self.entrypoint,
            cmd: self.cmd,
        }
    }

    /// Consume the builder and return the raw WIT [`ContainerConfig`].
    #[must_use]
    pub fn into_config(self) -> ContainerConfig {
        self.into_spec().config
    }

    /// Create the live kernel Linux [`Container`] RAII handle.
    pub async fn create(self) -> Result<Container, SpawnError> {
        let spec = self.into_spec();
        let inner = RawContainer::create(spec.config).await?;
        Ok(Container {
            inner,
            default_env: spec.default_env,
            default_cwd: spec.default_cwd,
            entrypoint: spec.entrypoint,
            cmd: spec.cmd,
        })
    }
}

/// RAII handle to a live kernel Linux container sharing one ephemeral overlay root,
/// PID namespace, `/tmp`, and UTS across all processes launched inside it.
///
/// Dropping this handle releases the kernel container resource and its ephemeral overlay.
pub struct Container {
    inner: RawContainer,
    default_env: Vec<(String, String)>,
    default_cwd: Option<String>,
    entrypoint: Vec<String>,
    cmd: Vec<String>,
}

impl Container {
    /// Start building a container with an explicit root [`ContainerMount`].
    #[must_use]
    pub fn builder(root: ContainerMount) -> ContainerBuilder {
        ContainerBuilder::new(root)
    }

    /// Start building a container over an ephemeral overlay of `lower_root`.
    #[must_use]
    pub fn ephemeral(lower_root: impl Into<String>) -> ContainerBuilder {
        ContainerBuilder::ephemeral(lower_root)
    }

    /// Start building a container directly from a pulled OCI image (`Entrypoint`/`Cmd`,
    /// `Env`, `User`, `WorkingDir`, and ephemeral overlay rootfs).
    #[cfg(feature = "oci")]
    pub fn from_image(
        image: &helios_oci::PulledImage,
    ) -> Result<ContainerBuilder, ContainerBuildError> {
        ContainerBuilder::from_image(image)
    }

    /// Construct a fluent [`ContainerCommand`] targeting `path` inside this container,
    /// pre-populated with the container's default environment and working directory.
    #[must_use]
    pub fn command(&self, path: impl Into<String>) -> ContainerCommand<'_> {
        ContainerCommand {
            container: self,
            path: path.into(),
            name: None,
            args: Vec::new(),
            env: self.default_env.clone(),
            cwd: self.default_cwd.clone(),
            stdin: Vec::new(),
            sockets: Vec::new(),
            credentials: None,
        }
    }

    /// Build a [`ContainerCommand`] for the container's OCI `Entrypoint` / `Cmd`
    /// (optionally overriding `Cmd` with `override_args`).
    pub fn default_command(
        &self,
        override_args: Option<&[String]>,
    ) -> Result<ContainerCommand<'_>, ContainerBuildError> {
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
        let program = iter.next().ok_or(ContainerBuildError::NoDefaultCommand)?;
        Ok(self.command(program).args(iter))
    }

    /// Spawn a Linux program inside this container using the raw WIT request.
    pub async fn spawn(&self, request: ContainerSpawnRequest) -> Result<Child, SpawnError> {
        self.inner.spawn(request).await
    }

    /// Execute a Linux program to completion inside this container using the raw WIT request.
    pub async fn exec(&self, request: ContainerExecRequest) -> Result<ExecResult, ExecError> {
        self.inner.exec(request).await
    }
}

/// Fluent command builder bound to a live [`Container`].
pub struct ContainerCommand<'a> {
    container: &'a Container,
    path: String,
    name: Option<String>,
    args: Vec<String>,
    env: Vec<(String, String)>,
    cwd: Option<String>,
    stdin: Vec<u8>,
    sockets: Vec<InheritedSocket>,
    credentials: Option<ContainerCredentials>,
}

impl ContainerCommand<'_> {
    #[must_use]
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    #[must_use]
    pub fn arg(mut self, arg: impl Into<String>) -> Self {
        self.args.push(arg.into());
        self
    }

    #[must_use]
    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    #[must_use]
    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        let key = key.into();
        let value = value.into();
        if let Some(existing) = self.env.iter_mut().find(|(k, _)| *k == key) {
            existing.1 = value;
        } else {
            self.env.push((key, value));
        }
        self
    }

    #[must_use]
    pub fn envs<I, K, V>(mut self, vars: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        for (k, v) in vars {
            self = self.env(k, v);
        }
        self
    }

    #[must_use]
    pub fn cwd(mut self, dir: impl Into<String>) -> Self {
        self.cwd = Some(dir.into());
        self
    }

    #[must_use]
    pub fn stdin(mut self, bytes: impl Into<Vec<u8>>) -> Self {
        self.stdin = bytes.into();
        self
    }

    #[must_use]
    pub fn socket(mut self, socket: InheritedSocket) -> Self {
        self.sockets.push(socket);
        self
    }

    #[must_use]
    pub fn credentials(mut self, credentials: ContainerCredentials) -> Self {
        self.credentials = Some(credentials);
        self
    }

    #[must_use]
    pub fn into_exec_request(self) -> ContainerExecRequest {
        ContainerExecRequest {
            name: self.name.unwrap_or_else(|| self.path.clone()),
            args: self.args,
            env: self.env,
            path: self.path,
            cwd: self.cwd,
            stdin: self.stdin,
            credentials: self.credentials,
        }
    }

    #[must_use]
    pub fn into_spawn_request(self) -> ContainerSpawnRequest {
        ContainerSpawnRequest {
            name: self.name.unwrap_or_else(|| self.path.clone()),
            args: self.args,
            env: self.env,
            path: self.path,
            cwd: self.cwd,
            sockets: self.sockets,
            credentials: self.credentials,
        }
    }

    /// Run this command to completion inside the container and collect buffered output.
    pub async fn exec(self) -> Result<ExecResult, ExecError> {
        let container = self.container;
        let request = self.into_exec_request();
        container.exec(request).await
    }

    /// Spawn this command inside the container and return a streaming [`Child`] handle.
    pub async fn spawn(self) -> Result<Child, SpawnError> {
        let container = self.container;
        let request = self.into_spawn_request();
        container.spawn(request).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::programs::{CapabilityGrant, NetworkRight};

    #[test]
    fn container_builder_accepts_only_non_fs_grants_and_builds_ephemeral_overlay() {
        let grants = NonFsGrants::new()
            .network(vec![NetworkRight::Tcp, NetworkRight::Dns])
            .all_process()
            .all_terminal();

        let spec = Container::ephemeral("/oci/layers/alpine")
            .bind_shared_rw("/workspace", "/workspace")
            .hostname("alpine-svc")
            .user(1000, 1000)
            .env("APP_ENV", "prod")
            .working_dir("/workspace")
            .entrypoint(["/usr/bin/env"])
            .default_cmd(["sh", "-c", "echo ok"])
            .grants(grants)
            .into_spec();

        assert_eq!(spec.config.root.source_path, "/oci/layers/alpine");
        assert_eq!(spec.config.root.target_path, "/");
        assert_eq!(
            spec.config.root.sharing,
            ContainerMountSharing::EphemeralOverlay
        );
        assert_eq!(spec.config.mounts.len(), 1);
        assert_eq!(spec.config.mounts[0].target_path, "/workspace");
        assert_eq!(spec.config.mounts[0].sharing, ContainerMountSharing::Shared);
        assert!(
            !spec
                .config
                .capability_grants
                .iter()
                .any(|g| matches!(g, CapabilityGrant::Directory(_))),
            "NonFsGrants statically guarantees no DirectoryGrant ever enters ContainerConfig"
        );
        assert_eq!(
            spec.resolve_default_command(None),
            Some((
                "/usr/bin/env".to_owned(),
                vec!["sh".to_owned(), "-c".to_owned(), "echo ok".to_owned()]
            ))
        );
    }

    #[cfg(feature = "oci")]
    #[test]
    fn container_from_oci_image_maps_entrypoint_cmd_env_user_and_workdir() {
        use std::collections::BTreeMap;
        use std::path::PathBuf;

        let dir = std::env::temp_dir().join(format!("helios-api-oci-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("etc")).unwrap();
        std::fs::write(
            dir.join("etc/passwd"),
            "root:x:0:0:root:/root:/bin/sh\napp:x:1001:1002:app:/app:/bin/sh\n",
        )
        .unwrap();

        let pulled = helios_oci::PulledImage {
            reference: helios_oci::ImageReference::parse("alpine:3.20").unwrap(),
            manifest_digest: helios_oci::Digest::sha256(b"manifest"),
            arch: helios_oci::Arch::X86_64,
            config: helios_oci::ImageConfig {
                architecture: "amd64".to_owned(),
                os: "linux".to_owned(),
                config: helios_oci::ImageRuntimeConfig {
                    user: Some("app".to_owned()),
                    env: vec![
                        "PATH=/usr/local/bin:/usr/bin:/bin".to_owned(),
                        "RUST_LOG=info".to_owned(),
                    ],
                    entrypoint: vec!["/bin/myapp".to_owned()],
                    cmd: vec!["--serve".to_owned(), ":8080".to_owned()],
                    working_dir: Some("/app".to_owned()),
                    labels: BTreeMap::new(),
                    stop_signal: None,
                },
                rootfs: helios_oci::RootFs::default(),
            },
            layer_chain_ids: vec![helios_oci::Digest::sha256(b"layer0")],
            rootfs_path: PathBuf::from(&dir),
            btrfs_backed: true,
        };

        let spec = Container::from_image(&pulled)
            .expect("from_image")
            .grants(NonFsGrants::new().full_network())
            .into_spec();

        assert_eq!(spec.config.credentials.uid, 1001);
        assert_eq!(spec.config.credentials.gid, 1002);
        assert_eq!(spec.default_cwd.as_deref(), Some("/app"));
        assert_eq!(
            spec.default_env,
            vec![
                ("PATH".to_owned(), "/usr/local/bin:/usr/bin:/bin".to_owned()),
                ("RUST_LOG".to_owned(), "info".to_owned()),
            ]
        );
        assert_eq!(
            spec.resolve_default_command(None),
            Some((
                "/bin/myapp".to_owned(),
                vec!["--serve".to_owned(), ":8080".to_owned()]
            ))
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
