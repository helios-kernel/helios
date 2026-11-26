use std::path::{Component, Path};

use helios_wit_rpc::RpcError;
use helios_wit_rpc::inspector::helios::system::ipc::Endpoint;
use helios_wit_rpc::inspector::helios::system::programs::{
    self as rpc_programs, AuthorityScope, CapabilityGrant, ContainerConfig, ContainerCredentials,
    ContainerExecRequest, ContainerIdentity, ContainerMount, ContainerMountSharing, DeviceClass,
    DeviceGrant, DiagnosticsGrant, DirectoryGrant, ExecError, ExecErrorKind, ExecRequest,
    ExecResult, FilesystemRight, LinkGrant, LinkRight, MachineGrant, MachineRight, MountGrant,
    MountRight, NetworkGrant, NetworkRight, ProcessGrant, ProcessRight, SettingsGrant,
    SettingsRight, TerminalGrant, TerminalRight,
};
use helios_wit_rpc::inspector_fs;

use crate::serial::RpcClient;

pub(crate) const REMOTE_SHELL_PATH: &str = "/bin/nu";

/// One container mount specification passed to [`exec_in_container`].
#[derive(Debug, Clone)]
pub(crate) struct ContainerMountBind {
    pub(crate) source_path: String,
    pub(crate) target_path: String,
    pub(crate) writable: bool,
    pub(crate) private: bool,
}

/// Request to execute a binary inside an isolated Linux container via
/// `helios:system/programs.create-container` + `container.exec`.
#[derive(Debug, Clone)]
pub(crate) struct ExecInContainerRequest {
    pub(crate) path: String,
    pub(crate) args: Vec<String>,
    pub(crate) env: Vec<(String, String)>,
    pub(crate) mounts: Vec<ContainerMountBind>,
    pub(crate) scratch_dir: Option<String>,
}

/// Why a program the inspector asked the guest to run did not run.
///
/// The path faults and the remote faults are separate variants because
/// they are answered differently: a path this side refuses never reaches
/// the guest, while a refusal from the guest carries the guest's own
/// classification of what went wrong.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ProgramError {
    #[error("path {input:?} contains a non-utf8 segment")]
    PathNotUtf8 { input: String },
    #[error("path {input:?} contains unsupported parent traversal")]
    PathParentTraversal { input: String },
    #[error("path {input:?} uses an unsupported path prefix")]
    PathPrefix { input: String },
    #[error("failed to invoke remote programs.exec: {source}")]
    Invoke {
        #[source]
        source: RpcError,
    },
    #[error("failed to prepare container scratch directory {path:?}: {source}")]
    PrepareScratchDir {
        path: String,
        #[source]
        source: inspector_fs::FsRpcError,
    },
    #[error("{kind:?}: {detail}")]
    Refused { kind: ExecErrorKind, detail: String },
}

impl ProgramError {
    /// The guest's panic report when this failure is a dead guest.
    ///
    /// The walk is typed rather than a downcast through an erased chain:
    /// only the RPC layer can carry a panic report, so only that variant
    /// is asked for one.
    pub(crate) fn guest_panic(&self) -> Option<&str> {
        match self {
            Self::Invoke { source } => source.guest_panic(),
            Self::PrepareScratchDir { source, .. } => source.guest_panic(),
            Self::PathNotUtf8 { .. }
            | Self::PathParentTraversal { .. }
            | Self::PathPrefix { .. }
            | Self::Refused { .. } => None,
        }
    }
}

impl From<ExecError> for ProgramError {
    fn from(error: ExecError) -> Self {
        Self::Refused {
            kind: error.kind,
            detail: error.detail,
        }
    }
}

/// Explicit grants requested by operator VM shell / harness commands.
///
/// The guest `inspector-worker` never synthesizes ambient grants; the kernel
/// strictly checks every entry against the worker's attenuated `ProcessAuthority`.
/// Wall-clock mutation (`ClockRight::SetWallClock`) is intentionally omitted so
/// shells and default containers run without `CAP_SYS_TIME`.
fn default_operator_grants() -> Vec<CapabilityGrant<Endpoint>> {
    vec![
        CapabilityGrant::Directory(DirectoryGrant {
            source_path: "/".to_owned(),
            guest_name: "/".to_owned(),
            rights: vec![
                FilesystemRight::Read,
                FilesystemRight::Write,
                FilesystemRight::MutateDirectory,
                FilesystemRight::Execute,
            ],
        }),
        CapabilityGrant::Network(NetworkGrant {
            rights: vec![
                NetworkRight::Tcp,
                NetworkRight::Udp,
                NetworkRight::Dns,
                NetworkRight::PrivilegedBind,
                NetworkRight::Multicast,
                NetworkRight::Admin,
            ],
        }),
        CapabilityGrant::Terminal(TerminalGrant {
            rights: vec![
                TerminalRight::Input,
                TerminalRight::Output,
                TerminalRight::Control,
            ],
        }),
        CapabilityGrant::Process(ProcessGrant {
            rights: vec![
                ProcessRight::Spawn,
                ProcessRight::Exec,
                ProcessRight::Fork,
                ProcessRight::Join,
                ProcessRight::Signal,
            ],
        }),
        CapabilityGrant::Link(LinkGrant {
            rights: vec![
                LinkRight::Source,
                LinkRight::TargetDirectory,
                LinkRight::SymlinkCreate,
                LinkRight::SymlinkRead,
            ],
        }),
        CapabilityGrant::Mount(MountGrant {
            rights: vec![MountRight::Mount, MountRight::Unmount],
        }),
        CapabilityGrant::Device(DeviceGrant {
            classes: vec![
                DeviceClass::Display,
                DeviceClass::Input,
                DeviceClass::Gpu,
                DeviceClass::Audio,
            ],
        }),
        CapabilityGrant::Diagnostics(DiagnosticsGrant::InspectRead(AuthorityScope::Machine)),
        CapabilityGrant::Diagnostics(DiagnosticsGrant::TraceRead(AuthorityScope::Machine)),
        CapabilityGrant::Diagnostics(DiagnosticsGrant::ProfileRead(AuthorityScope::Machine)),
        CapabilityGrant::Diagnostics(DiagnosticsGrant::Control),
        CapabilityGrant::InstanceControl(AuthorityScope::Machine),
        CapabilityGrant::Settings(SettingsGrant {
            rights: vec![SettingsRight::Write],
        }),
        CapabilityGrant::Machine(MachineGrant {
            rights: vec![MachineRight::Control, MachineRight::Virtualize],
        }),
    ]
}

fn default_container_non_fs_grants() -> Vec<CapabilityGrant<Endpoint>> {
    vec![
        CapabilityGrant::Network(NetworkGrant {
            rights: vec![
                NetworkRight::Tcp,
                NetworkRight::Udp,
                NetworkRight::Dns,
                NetworkRight::PrivilegedBind,
                NetworkRight::Multicast,
                NetworkRight::Admin,
            ],
        }),
        CapabilityGrant::Terminal(TerminalGrant {
            rights: vec![
                TerminalRight::Input,
                TerminalRight::Output,
                TerminalRight::Control,
            ],
        }),
        CapabilityGrant::Process(ProcessGrant {
            rights: vec![
                ProcessRight::Spawn,
                ProcessRight::Exec,
                ProcessRight::Fork,
                ProcessRight::Join,
                ProcessRight::Signal,
            ],
        }),
        CapabilityGrant::Link(LinkGrant {
            rights: vec![
                LinkRight::Source,
                LinkRight::TargetDirectory,
                LinkRight::SymlinkCreate,
                LinkRight::SymlinkRead,
            ],
        }),
    ]
}

pub async fn exec(
    client: &RpcClient,
    path: &str,
    args: &[String],
) -> Result<ExecResult, ProgramError> {
    let path = normalize_absolute(path)?;
    let request = ExecRequest {
        name: path.clone(),
        args: args.to_vec(),
        env: Vec::new(),
        path,
        cwd: None,
        stdin: Vec::new(),
        hint: None,
        capability_grants: default_operator_grants(),
    };
    let outcome = rpc_programs::RpcClient::new(client.peer())
        .exec(request)
        .await
        .map_err(|source| ProgramError::Invoke { source })?;
    outcome.map_err(ProgramError::from)
}

pub async fn exec_in_container(
    client: &RpcClient,
    mut request: ExecInContainerRequest,
) -> Result<ExecResult, ProgramError> {
    request.path = normalize_absolute(&request.path)?;
    if let Some(scratch) = &request.scratch_dir {
        inspector_fs::mkdir(client, scratch)
            .await
            .map_err(|source| ProgramError::PrepareScratchDir {
                path: scratch.clone(),
                source,
            })?;
    }
    let root = ContainerMount {
        source_path: "/".to_owned(),
        target_path: "/".to_owned(),
        rights: vec![FilesystemRight::Read, FilesystemRight::Execute],
        sharing: ContainerMountSharing::Shared,
    };
    let mounts = request
        .mounts
        .into_iter()
        .map(|bind| ContainerMount {
            source_path: bind.source_path,
            target_path: bind.target_path,
            rights: if bind.writable {
                vec![
                    FilesystemRight::Read,
                    FilesystemRight::Write,
                    FilesystemRight::MutateDirectory,
                    FilesystemRight::Execute,
                ]
            } else {
                vec![FilesystemRight::Read, FilesystemRight::Execute]
            },
            sharing: if bind.private {
                ContainerMountSharing::Private
            } else {
                ContainerMountSharing::Shared
            },
        })
        .collect();
    let config = ContainerConfig {
        root,
        mounts,
        shared_owner: ContainerIdentity { uid: 0, gid: 0 },
        credentials: ContainerCredentials {
            uid: 0,
            gid: 0,
            supplementary_groups: Vec::new(),
        },
        hostname: "helios-container".to_owned(),
        domainname: String::new(),
        capability_grants: default_container_non_fs_grants(),
    };
    let container = rpc_programs::RpcClient::new(client.peer())
        .create_container(config)
        .await
        .map_err(|source| ProgramError::Invoke { source })?
        .map_err(ProgramError::from)?;
    let exec_req = ContainerExecRequest {
        name: request.path.clone(),
        args: request.args,
        env: request.env,
        path: request.path,
        cwd: None,
        stdin: Vec::new(),
        credentials: None,
    };
    let outcome = container
        .exec(exec_req)
        .await
        .map_err(|source| ProgramError::Invoke { source })?;
    outcome.map_err(ProgramError::from)
}

fn normalize_absolute(input: &str) -> Result<String, ProgramError> {
    let mut segments = Vec::new();
    for component in Path::new(input).components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(segment) => segments.push(
                segment
                    .to_str()
                    .ok_or_else(|| ProgramError::PathNotUtf8 {
                        input: input.to_owned(),
                    })?
                    .to_owned(),
            ),
            Component::ParentDir => {
                return Err(ProgramError::PathParentTraversal {
                    input: input.to_owned(),
                });
            }
            Component::Prefix(_) => {
                return Err(ProgramError::PathPrefix {
                    input: input.to_owned(),
                });
            }
        }
    }

    if segments.is_empty() {
        return Ok("/".to_owned());
    }
    Ok(format!("/{}", segments.join("/")))
}

#[cfg(test)]
mod tests {
    use super::{
        CapabilityGrant, default_container_non_fs_grants, default_operator_grants,
        normalize_absolute,
    };

    #[test]
    fn normalizes_relative_paths_from_root() {
        assert_eq!(
            normalize_absolute("bin/dash").expect("relative path must normalize"),
            "/bin/dash"
        );
    }

    #[test]
    fn preserves_absolute_paths() {
        assert_eq!(
            normalize_absolute("/bin/dash").expect("absolute path must normalize"),
            "/bin/dash"
        );
    }

    #[test]
    fn rejects_parent_traversal() {
        assert!(normalize_absolute("../bin/dash").is_err());
    }

    #[test]
    fn default_grants_omit_set_wall_clock() {
        assert!(
            !default_operator_grants()
                .iter()
                .any(|grant| matches!(grant, CapabilityGrant::Clock(_))),
            "operator shell grants must not include wall-clock mutation by default"
        );
        assert!(
            !default_container_non_fs_grants()
                .iter()
                .any(|grant| matches!(grant, CapabilityGrant::Clock(_))),
            "default container grants must not include wall-clock mutation by default"
        );
    }
}
