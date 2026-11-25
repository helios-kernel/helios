//! Fluent, typed capability grant builders ([`NonFsGrants`] and [`ProcessGrants`]) and
//! unified [`Command`] builder for `helios-ops`, symmetric with `helios-api`.
//!
//! Enforces compile-time separation between non-filesystem container grants and
//! filesystem [`DirectoryGrant`]s: container builders accept [`NonFsGrants`] only.

use helios_wit_rpc::inspector::helios::system::ipc::Endpoint;
use helios_wit_rpc::inspector::helios::system::programs::{
    AotHint, AuthorityScope, CapabilityGrant, ClockGrant, ClockRight, DeviceClass, DeviceGrant,
    DiagnosticsGrant, DirectoryGrant, ExecRequest, ExecResult, FilesystemRight, LinkGrant,
    LinkRight, MachineGrant, MachineRight, MountGrant, MountRight, NetworkGrant, NetworkRight,
    ProcessGrant, ProcessRight, SettingsGrant, SettingsRight, TerminalGrant, TerminalRight,
};

use crate::error::OpsError;
use crate::session::{Child, Session, SpawnRequest};

/// Non-filesystem capability grant that may be attached to a Linux container.
///
/// Intentionally omits [`DirectoryGrant`]: filesystem authority on containers is
/// expressed exclusively through mounts, enforcing separation at compile time.
#[derive(Clone, Debug)]
pub enum NonFsGrant {
    Network(NetworkGrant),
    Clock(ClockGrant),
    Terminal(TerminalGrant),
    Process(ProcessGrant),
    Link(LinkGrant),
    Mount(MountGrant),
    Device(DeviceGrant),
    Diagnostics(DiagnosticsGrant),
    InstanceControl(AuthorityScope),
    Settings(SettingsGrant),
    Machine(MachineGrant),
}

impl From<NonFsGrant> for CapabilityGrant<Endpoint> {
    fn from(grant: NonFsGrant) -> Self {
        match grant {
            NonFsGrant::Network(g) => Self::Network(g),
            NonFsGrant::Clock(g) => Self::Clock(g),
            NonFsGrant::Terminal(g) => Self::Terminal(g),
            NonFsGrant::Process(g) => Self::Process(g),
            NonFsGrant::Link(g) => Self::Link(g),
            NonFsGrant::Mount(g) => Self::Mount(g),
            NonFsGrant::Device(g) => Self::Device(g),
            NonFsGrant::Diagnostics(g) => Self::Diagnostics(g),
            NonFsGrant::InstanceControl(s) => Self::InstanceControl(s),
            NonFsGrant::Settings(g) => Self::Settings(g),
            NonFsGrant::Machine(g) => Self::Machine(g),
        }
    }
}

/// Fluent, typed builder for non-filesystem capability grants.
///
/// Accepted by [`crate::linux::ContainerBuilder::grants`]; rejects [`DirectoryGrant`]
/// and [`ProcessGrants`] at compile time.
///
/// ```compile_fail
/// use helios_ops::linux::ContainerBuilder;
/// use helios_ops::ProcessGrants;
///
/// let grants = ProcessGrants::new().bind_dir_rw("/workspace");
/// let _ = ContainerBuilder::ephemeral("/oci/alpine").grants(grants);
/// ```
#[derive(Clone, Debug, Default)]
pub struct NonFsGrants {
    grants: Vec<NonFsGrant>,
}

impl NonFsGrants {
    #[must_use]
    pub const fn new() -> Self {
        Self { grants: Vec::new() }
    }

    #[must_use]
    pub fn grant(mut self, grant: NonFsGrant) -> Self {
        self.grants.push(grant);
        self
    }

    #[must_use]
    pub fn network(self, rights: Vec<NetworkRight>) -> Self {
        self.grant(NonFsGrant::Network(NetworkGrant { rights }))
    }

    #[must_use]
    pub fn full_network(self) -> Self {
        self.network(vec![
            NetworkRight::Tcp,
            NetworkRight::Udp,
            NetworkRight::Dns,
            NetworkRight::PrivilegedBind,
            NetworkRight::Multicast,
            NetworkRight::Admin,
        ])
    }

    #[must_use]
    pub fn clock(self, rights: Vec<ClockRight>) -> Self {
        self.grant(NonFsGrant::Clock(ClockGrant { rights }))
    }

    #[must_use]
    pub fn set_wall_clock(self) -> Self {
        self.clock(vec![ClockRight::SetWallClock])
    }

    #[must_use]
    pub fn terminal(self, rights: Vec<TerminalRight>) -> Self {
        self.grant(NonFsGrant::Terminal(TerminalGrant { rights }))
    }

    #[must_use]
    pub fn all_terminal(self) -> Self {
        self.terminal(vec![
            TerminalRight::Input,
            TerminalRight::Output,
            TerminalRight::Control,
        ])
    }

    #[must_use]
    pub fn process(self, rights: Vec<ProcessRight>) -> Self {
        self.grant(NonFsGrant::Process(ProcessGrant { rights }))
    }

    #[must_use]
    pub fn all_process(self) -> Self {
        self.process(vec![
            ProcessRight::Spawn,
            ProcessRight::Exec,
            ProcessRight::Fork,
            ProcessRight::Join,
            ProcessRight::Signal,
        ])
    }

    #[must_use]
    pub fn link(self, rights: Vec<LinkRight>) -> Self {
        self.grant(NonFsGrant::Link(LinkGrant { rights }))
    }

    #[must_use]
    pub fn all_link(self) -> Self {
        self.link(vec![
            LinkRight::Source,
            LinkRight::TargetDirectory,
            LinkRight::SymlinkCreate,
            LinkRight::SymlinkRead,
        ])
    }

    #[must_use]
    pub fn mount(self, rights: Vec<MountRight>) -> Self {
        self.grant(NonFsGrant::Mount(MountGrant { rights }))
    }

    #[must_use]
    pub fn all_mount(self) -> Self {
        self.mount(vec![MountRight::Mount, MountRight::Unmount])
    }

    #[must_use]
    pub fn device(self, classes: Vec<DeviceClass>) -> Self {
        self.grant(NonFsGrant::Device(DeviceGrant { classes }))
    }

    #[must_use]
    pub fn all_devices(self) -> Self {
        self.device(vec![
            DeviceClass::Display,
            DeviceClass::Input,
            DeviceClass::Gpu,
            DeviceClass::Audio,
        ])
    }

    #[must_use]
    pub fn diagnostics(self, grant: DiagnosticsGrant) -> Self {
        self.grant(NonFsGrant::Diagnostics(grant))
    }

    #[must_use]
    pub fn inspect_read(self, scope: AuthorityScope) -> Self {
        self.diagnostics(DiagnosticsGrant::InspectRead(scope))
    }

    #[must_use]
    pub fn trace_read(self, scope: AuthorityScope) -> Self {
        self.diagnostics(DiagnosticsGrant::TraceRead(scope))
    }

    #[must_use]
    pub fn profile_read(self, scope: AuthorityScope) -> Self {
        self.diagnostics(DiagnosticsGrant::ProfileRead(scope))
    }

    #[must_use]
    pub fn diagnostics_control(self) -> Self {
        self.diagnostics(DiagnosticsGrant::Control)
    }

    #[must_use]
    pub fn instance_control(self, scope: AuthorityScope) -> Self {
        self.grant(NonFsGrant::InstanceControl(scope))
    }

    #[must_use]
    pub fn settings(self, rights: Vec<SettingsRight>) -> Self {
        self.grant(NonFsGrant::Settings(SettingsGrant { rights }))
    }

    #[must_use]
    pub fn write_settings(self) -> Self {
        self.settings(vec![SettingsRight::Write])
    }

    #[must_use]
    pub fn machine(self, rights: Vec<MachineRight>) -> Self {
        self.grant(NonFsGrant::Machine(MachineGrant { rights }))
    }

    #[must_use]
    pub fn machine_control(self) -> Self {
        self.machine(vec![MachineRight::Control])
    }

    #[must_use]
    pub fn machine_identity(self) -> Self {
        self.machine(vec![MachineRight::Identity])
    }

    #[must_use]
    pub fn virtualize(self) -> Self {
        self.machine(vec![MachineRight::Virtualize])
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.grants.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.grants.is_empty()
    }

    #[must_use]
    pub fn into_capability_grants(self) -> Vec<CapabilityGrant<Endpoint>> {
        self.grants.into_iter().map(Into::into).collect()
    }
}

/// Fluent, typed capability builder for direct remote process launches (`Command`).
#[derive(Clone, Debug, Default)]
pub struct ProcessGrants {
    directories: Vec<DirectoryGrant>,
    non_fs: NonFsGrants,
}

impl From<NonFsGrants> for ProcessGrants {
    fn from(non_fs: NonFsGrants) -> Self {
        Self {
            directories: Vec::new(),
            non_fs,
        }
    }
}

impl ProcessGrants {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            directories: Vec::new(),
            non_fs: NonFsGrants::new(),
        }
    }

    #[must_use]
    pub fn directory_grant(mut self, grant: DirectoryGrant) -> Self {
        self.directories.push(grant);
        self
    }

    #[must_use]
    pub fn directory(
        self,
        source_path: impl Into<String>,
        guest_name: impl Into<String>,
        rights: Vec<FilesystemRight>,
    ) -> Self {
        self.directory_grant(DirectoryGrant {
            source_path: source_path.into(),
            guest_name: guest_name.into(),
            rights,
        })
    }

    #[must_use]
    pub fn directory_ro(
        self,
        source_path: impl Into<String>,
        guest_name: impl Into<String>,
    ) -> Self {
        self.directory(source_path, guest_name, vec![FilesystemRight::Read])
    }

    #[must_use]
    pub fn directory_rx(
        self,
        source_path: impl Into<String>,
        guest_name: impl Into<String>,
    ) -> Self {
        self.directory(
            source_path,
            guest_name,
            vec![FilesystemRight::Read, FilesystemRight::Execute],
        )
    }

    #[must_use]
    pub fn directory_rw(
        self,
        source_path: impl Into<String>,
        guest_name: impl Into<String>,
    ) -> Self {
        self.directory(
            source_path,
            guest_name,
            vec![
                FilesystemRight::Read,
                FilesystemRight::Write,
                FilesystemRight::MutateDirectory,
            ],
        )
    }

    #[must_use]
    pub fn directory_rwx(
        self,
        source_path: impl Into<String>,
        guest_name: impl Into<String>,
    ) -> Self {
        self.directory(
            source_path,
            guest_name,
            vec![
                FilesystemRight::Read,
                FilesystemRight::Write,
                FilesystemRight::MutateDirectory,
                FilesystemRight::Execute,
            ],
        )
    }

    #[must_use]
    pub fn bind_dir_ro(self, path: impl Into<String>) -> Self {
        let p = path.into();
        self.directory_ro(p.clone(), p)
    }

    #[must_use]
    pub fn bind_dir_rx(self, path: impl Into<String>) -> Self {
        let p = path.into();
        self.directory_rx(p.clone(), p)
    }

    #[must_use]
    pub fn bind_dir_rw(self, path: impl Into<String>) -> Self {
        let p = path.into();
        self.directory_rw(p.clone(), p)
    }

    #[must_use]
    pub fn bind_dir_rwx(self, path: impl Into<String>) -> Self {
        let p = path.into();
        self.directory_rwx(p.clone(), p)
    }

    #[must_use]
    pub fn root_directory(self) -> Self {
        self.directory_rwx("/", "/")
    }

    #[must_use]
    pub fn with_non_fs(mut self, non_fs: NonFsGrants) -> Self {
        self.non_fs.grants.extend(non_fs.grants);
        self
    }

    #[must_use]
    pub fn network(mut self, rights: Vec<NetworkRight>) -> Self {
        self.non_fs = self.non_fs.network(rights);
        self
    }

    #[must_use]
    pub fn full_network(mut self) -> Self {
        self.non_fs = self.non_fs.full_network();
        self
    }

    #[must_use]
    pub fn all_terminal(mut self) -> Self {
        self.non_fs = self.non_fs.all_terminal();
        self
    }

    #[must_use]
    pub fn all_process(mut self) -> Self {
        self.non_fs = self.non_fs.all_process();
        self
    }

    #[must_use]
    pub fn into_capability_grants(self) -> Vec<CapabilityGrant<Endpoint>> {
        let mut out = Vec::with_capacity(self.directories.len() + self.non_fs.len());
        out.extend(self.directories.into_iter().map(CapabilityGrant::Directory));
        out.extend(self.non_fs.into_capability_grants());
        out
    }
}

/// Fluent remote command builder symmetric with `helios_api::programs::Command`.
#[derive(Clone, Debug)]
pub struct Command {
    path: String,
    name: Option<String>,
    args: Vec<String>,
    env: Vec<(String, String)>,
    cwd: Option<String>,
    stdin: Vec<u8>,
    hint: Option<AotHint>,
    grants: ProcessGrants,
}

impl Command {
    #[must_use]
    pub fn new(path: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            name: None,
            args: Vec::new(),
            env: Vec::new(),
            cwd: None,
            stdin: Vec::new(),
            hint: None,
            grants: ProcessGrants::new(),
        }
    }

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
        self.env.push((key.into(), value.into()));
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
            self.env.push((k.into(), v.into()));
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
    pub const fn aot_hint(mut self, hint: AotHint) -> Self {
        self.hint = Some(hint);
        self
    }

    #[must_use]
    pub fn grants(mut self, grants: ProcessGrants) -> Self {
        self.grants = grants;
        self
    }

    #[must_use]
    pub fn with_grants(mut self, configure: impl FnOnce(ProcessGrants) -> ProcessGrants) -> Self {
        self.grants = configure(self.grants);
        self
    }

    #[must_use]
    pub fn dir_ro(mut self, path: impl Into<String>) -> Self {
        self.grants = self.grants.bind_dir_ro(path);
        self
    }

    #[must_use]
    pub fn dir_rw(mut self, path: impl Into<String>) -> Self {
        self.grants = self.grants.bind_dir_rw(path);
        self
    }

    #[must_use]
    pub fn dir_rwx(mut self, path: impl Into<String>) -> Self {
        self.grants = self.grants.bind_dir_rwx(path);
        self
    }

    /// Build the wire [`ExecRequest`] for inspection or `Session::exec_request`.
    #[must_use]
    pub fn into_exec_request(self) -> ExecRequest<Endpoint> {
        ExecRequest {
            name: self.name.unwrap_or_else(|| self.path.clone()),
            args: self.args,
            env: self.env,
            path: self.path,
            cwd: self.cwd,
            stdin: self.stdin,
            hint: self.hint,
            capability_grants: self.grants.into_capability_grants(),
        }
    }

    /// Build the [`SpawnRequest`] for `Session::spawn`.
    #[must_use]
    pub fn into_spawn_request(self) -> SpawnRequest {
        SpawnRequest {
            path: self.path,
            args: self.args,
            env: self.env,
            cwd: self.cwd,
            stdin: self.stdin,
            capability_grants: self.grants.into_capability_grants(),
        }
    }

    /// Execute this command to completion on `session`.
    pub async fn exec(self, session: &Session) -> Result<ExecResult, OpsError> {
        let req = self.into_exec_request();
        session.exec_request(req).await
    }

    /// Spawn this command on `session` and return a streaming [`Child`] handle.
    pub async fn spawn(self, session: &Session) -> Result<Child, OpsError> {
        session.spawn(self.into_spawn_request()).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ops_process_grants_and_command_preserve_cwd_and_grants() {
        let non_fs = NonFsGrants::new()
            .network(vec![NetworkRight::Tcp, NetworkRight::Dns])
            .all_terminal();
        let grants = ProcessGrants::from(non_fs)
            .bind_dir_rw("/workspace")
            .directory_ro("/etc", "/etc");

        let exec_req = Command::new("/usr/bin/env")
            .name("env")
            .arg("LANG=C.UTF-8")
            .env("FOO", "BAR")
            .cwd("/workspace")
            .stdin(b"hello".to_vec())
            .grants(grants)
            .into_exec_request();

        assert_eq!(exec_req.name, "env");
        assert_eq!(exec_req.path, "/usr/bin/env");
        assert_eq!(exec_req.cwd.as_deref(), Some("/workspace"));
        assert_eq!(exec_req.stdin, b"hello");
        assert_eq!(exec_req.capability_grants.len(), 4);
        assert!(matches!(
            &exec_req.capability_grants[0],
            CapabilityGrant::Directory(d) if d.source_path == "/workspace"
        ));

        let spawn_req = Command::new("/bin/sh")
            .args(["-c", "pwd"])
            .cwd("/data")
            .dir_rwx("/data")
            .into_spawn_request();
        assert_eq!(spawn_req.cwd.as_deref(), Some("/data"));
        assert_eq!(spawn_req.capability_grants.len(), 1);
    }
}
