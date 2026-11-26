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
    ContainerSpawnRequest, ExecResult, FilesystemRight,
};
use tokio::sync::OnceCell;

use crate::error::OpsError;
use crate::grants::NonFsGrants;
use crate::session::{Child, Session};
use crate::target::GrantRight;

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
            remote: OnceCell::new(),
        }
    }

    /// Create the remote container immediately and return a [`Container`] handle.
    pub async fn create(self, session: Session) -> Result<Container, OpsError> {
        let container = self.attach(session);
        let _ = container.ensure_container().await?;
        Ok(container)
    }
}

/// Remote Linux container handle bound to a [`Session`].
///
/// Lazily creates and holds one live `helios:system/programs.container` resource
/// so multiple [`Self::exec`] and [`Self::spawn`] calls share the same ephemeral
/// overlay `/`, `/tmp`, UTS, and PID namespace.
pub struct Container {
    session: Session,
    config: ContainerConfig,
    remote: OnceCell<rpc_programs::Container>,
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

    async fn ensure_container(&self) -> Result<&rpc_programs::Container, OpsError> {
        self.session.require_right(GrantRight::Exec)?;
        self.remote
            .get_or_try_init(|| async {
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
                let client = rpc_programs::RpcClient::new(self.session.protocol_client().clone());
                self.session
                    .call(
                        "system.programs.create-container",
                        client.create_container(wire_cfg),
                    )
                    .await?
                    .map_err(OpsError::from)
            })
            .await
    }

    fn merged_env(&self, extra_env: &[(String, String)]) -> Vec<(String, String)> {
        let mut env = self.config.default_env.clone();
        for (k, v) in extra_env {
            if let Some(slot) = env.iter_mut().find(|(ek, _)| ek == k) {
                slot.1.clone_from(v);
            } else {
                env.push((k.clone(), v.clone()));
            }
        }
        env
    }

    /// Execute `path` with `args` inside this shared container over the remote `Session`.
    pub async fn exec(
        &self,
        path: &str,
        args: &[String],
        extra_env: &[(String, String)],
    ) -> Result<ExecResult, OpsError> {
        let container = self.ensure_container().await?;
        let exec_req = ContainerExecRequest {
            name: path.to_owned(),
            args: args.to_vec(),
            env: self.merged_env(extra_env),
            path: path.to_owned(),
            cwd: self.config.default_cwd.clone(),
            stdin: Vec::new(),
            credentials: None,
        };
        self.session
            .call("system.programs.container.exec", container.exec(exec_req))
            .await?
            .map_err(OpsError::from)
    }

    /// Spawn `path` with `args` inside this shared container and return a streaming [`Child`].
    pub async fn spawn(
        &self,
        path: &str,
        args: &[String],
        extra_env: &[(String, String)],
    ) -> Result<Child, OpsError> {
        let container = self.ensure_container().await?;
        let spawn_req = ContainerSpawnRequest {
            name: path.to_owned(),
            args: args.to_vec(),
            env: self.merged_env(extra_env),
            path: path.to_owned(),
            cwd: self.config.default_cwd.clone(),
            sockets: Vec::new(),
            credentials: None,
        };
        let remote_child = self
            .session
            .call(
                "system.programs.container.spawn",
                container.spawn(spawn_req),
            )
            .await?
            .map_err(OpsError::from)?;
        Child::from_remote(self.session.clone(), remote_child, Vec::new()).await
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

    #[tokio::test]
    async fn ops_container_reuses_one_remote_container_across_exec_and_spawn() {
        use std::os::unix::net::UnixStream;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        use async_io::Async;
        use helios_wit_rpc::inspector::helios::system::programs::{
            AotRequest, AotResult, ChildTermination, ContainerConfig as WireContainerConfig,
            DefaultLinuxImage, ExecError, ExecOutput, ExecRequest, ExitStatus, InheritedSocket,
            SpawnError, SpawnRequest,
        };
        use helios_wit_rpc::{Endpoint, FutureReader, StreamReader};

        use crate::session::SessionOptions;
        use crate::target::{Attenuation, Target};
        use crate::transport::RpcConnection;

        struct FakeChild(u64);

        struct FakePrograms {
            create_calls: Arc<AtomicUsize>,
            exec_calls: Arc<AtomicUsize>,
            spawn_calls: Arc<AtomicUsize>,
        }

        impl rpc_programs::RpcHandler for FakePrograms {
            type Child = FakeChild;
            type Container = u64;
            type Endpoint = ();
            type TcpListener = ();
            type TcpStream = ();
            type SerialPort = ();
            type VsockListener = ();
            type VsockStream = ();

            async fn child_stdin(
                &self,
                _self_: &Self::Child,
                data: StreamReader<u8>,
            ) -> FutureReader<Result<(), ()>> {
                let _ = data.collect_all().await;
                FutureReader::ready(Ok(()))
            }

            async fn child_stdout(
                &self,
                _self_: &Self::Child,
            ) -> (StreamReader<u8>, FutureReader<Result<(), ()>>) {
                (
                    StreamReader::from_vec(b"container-child".to_vec()),
                    FutureReader::ready(Ok(())),
                )
            }

            async fn child_stderr(
                &self,
                _self_: &Self::Child,
            ) -> (StreamReader<u8>, FutureReader<Result<(), ()>>) {
                (StreamReader::empty(), FutureReader::ready(Ok(())))
            }

            async fn child_instance_id(&self, self_: &Self::Child) -> u64 {
                self_.0
            }

            async fn child_signal(&self, _self_: &Self::Child, _sig: u8) -> Result<(), SpawnError> {
                Ok(())
            }

            async fn child_wait(&self, self_: &Self::Child) -> Result<ExitStatus, SpawnError> {
                Ok(ExitStatus {
                    instance_id: self_.0,
                    termination: ChildTermination::Exited(0),
                })
            }

            async fn container_spawn(
                &self,
                self_: &Self::Container,
                _request: ContainerSpawnRequest<
                    Self::TcpListener,
                    Self::VsockListener,
                    Self::TcpStream,
                    Self::VsockStream,
                    Self::SerialPort,
                >,
            ) -> Result<Self::Child, SpawnError> {
                let n = self.spawn_calls.fetch_add(1, Ordering::AcqRel) + 1;
                Ok(FakeChild(*self_ * 10 + n as u64))
            }

            async fn container_exec(
                &self,
                _self_: &Self::Container,
                _request: ContainerExecRequest,
            ) -> Result<ExecResult, ExecError> {
                let n = self.exec_calls.fetch_add(1, Ordering::AcqRel) + 1;
                Ok(ExecResult {
                    instance_id: n as u64,
                    exit_code: 0,
                    output: ExecOutput {
                        stdout: format!("exec-{n}").into_bytes(),
                        stderr: Vec::new(),
                    },
                    launch_nanos: 1,
                })
            }

            async fn set_default_image(
                &self,
                _image: Option<DefaultLinuxImage>,
            ) -> Result<(), SpawnError> {
                Ok(())
            }

            async fn get_default_image(&self) -> Option<DefaultLinuxImage> {
                None
            }

            async fn take_inherited_sockets(
                &self,
            ) -> Vec<
                InheritedSocket<
                    Self::TcpListener,
                    Self::VsockListener,
                    Self::TcpStream,
                    Self::VsockStream,
                    Self::SerialPort,
                >,
            > {
                Vec::new()
            }

            async fn create_container(
                &self,
                _config: WireContainerConfig<Self::Endpoint>,
            ) -> Result<Self::Container, SpawnError> {
                let id = self.create_calls.fetch_add(1, Ordering::AcqRel) + 1;
                Ok(id as u64)
            }

            async fn spawn(
                &self,
                _request: SpawnRequest<
                    Self::TcpListener,
                    Self::VsockListener,
                    Self::TcpStream,
                    Self::VsockStream,
                    Self::SerialPort,
                    Self::Endpoint,
                >,
            ) -> Result<Self::Child, SpawnError> {
                unreachable!()
            }

            async fn exec(
                &self,
                _request: ExecRequest<Self::Endpoint>,
            ) -> Result<ExecResult, ExecError> {
                unreachable!()
            }

            async fn aot(&self, _request: AotRequest) -> Result<AotResult, ExecError> {
                unreachable!()
            }
        }

        let (host, guest) = UnixStream::pair().expect("pair");
        host.set_nonblocking(true).expect("nonblocking");
        guest.set_nonblocking(true).expect("nonblocking");
        let host_read = host.try_clone().expect("clone");
        let guest_read = guest.try_clone().expect("clone");
        let conn = RpcConnection::from_split(
            Box::new(Async::new(host_read).expect("async")),
            Box::new(Async::new(host).expect("async")),
        );
        let session = Session::from_connection(
            Target::new("ctr", "serial:///tmp/ctr.sock").expect("target"),
            conn,
            SessionOptions::default(),
        );

        let create_calls = Arc::new(AtomicUsize::new(0));
        let exec_calls = Arc::new(AtomicUsize::new(0));
        let spawn_calls = Arc::new(AtomicUsize::new(0));
        let ep = Endpoint::new(
            Async::new(guest_read).expect("async"),
            Async::new(guest).expect("async"),
            rpc_programs::RpcServer::new(FakePrograms {
                create_calls: Arc::clone(&create_calls),
                exec_calls: Arc::clone(&exec_calls),
                spawn_calls: Arc::clone(&spawn_calls),
            }),
        );
        let server_task = tokio::spawn(async move {
            let _ = ep.drive().await;
        });

        let ctr = Container::ephemeral("/rootfs")
            .create(session.clone())
            .await
            .expect("create container");
        let r1 = ctr
            .exec("/bin/echo", &["one".to_owned()], &[])
            .await
            .expect("exec 1");
        let r2 = ctr
            .exec("/bin/echo", &["two".to_owned()], &[])
            .await
            .expect("exec 2");
        assert_eq!(r1.output.stdout, b"exec-1");
        assert_eq!(r2.output.stdout, b"exec-2");

        let child = ctr
            .spawn("/bin/cat", &[], &[])
            .await
            .expect("spawn in container");
        assert_eq!(child.instance_id(), Some(11));
        let wait_res = child.wait().await.expect("wait");
        assert_eq!(wait_res.exit_code, 0);

        assert_eq!(create_calls.load(Ordering::Acquire), 1);
        assert_eq!(exec_calls.load(Ordering::Acquire), 2);
        assert_eq!(spawn_calls.load(Ordering::Acquire), 1);

        // Attenuated session without Exec right must be refused.
        let read_only = session
            .attenuated(Attenuation {
                scope: None,
                only: std::collections::BTreeSet::from([GrantRight::Inspect]),
            })
            .expect("attenuate");
        assert!(matches!(
            Container::ephemeral("/rootfs").create(read_only).await,
            Err(OpsError::AttenuationDenied { .. })
        ));

        server_task.abort();
    }
}
