use serde::{Deserialize, Serialize};

pub use crate::system::programs::{ExecError, ExecErrorKind, ExecResult};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ExecPathRequest {
    path: String,
    args: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainerMountBind {
    pub source_path: String,
    pub target_path: String,
    pub writable: bool,
    pub private: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecInContainerRequest {
    pub path: String,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
    pub mounts: Vec<ContainerMountBind>,
    pub scratch_dir: Option<String>,
}

#[cfg(feature = "host")]
mod host {
    use super::*;
    use crate::debugger::methods::{EXEC_IN_CONTAINER, EXEC_PATH, PROGRAMS_INSTANCE};
    use crate::error::{RpcError, TransportError};
    use crate::transport::Client;
    use futures_io::{AsyncRead, AsyncWrite};

    impl ExecPathRequest {
        pub(crate) fn new(path: &str, args: &[String]) -> Self {
            Self {
                path: path.to_owned(),
                args: args.to_vec(),
            }
        }
    }

    /// Outcome of `programs.exec-path`: outer `Result` covers transport /
    /// encode / decode faults, inner `Result` carries the typed service
    /// error contract.
    pub type ExecPathOutcome = Result<Result<ExecResult, ExecError>, RpcError>;

    pub async fn exec_path<R, W>(
        client: &Client<R, W>,
        path: &str,
        args: &[String],
    ) -> ExecPathOutcome
    where
        R: AsyncRead + Send + Unpin + 'static,
        W: AsyncWrite + Send + Unpin + 'static,
    {
        let request =
            postcard::to_allocvec(&ExecPathRequest::new(path, args)).map_err(|source| {
                RpcError::Encode {
                    instance: PROGRAMS_INSTANCE,
                    func: EXEC_PATH,
                    source,
                }
            })?;
        let bytes = client
            .invoke_raw(PROGRAMS_INSTANCE, EXEC_PATH, request)
            .await
            .map_err(|source: TransportError| RpcError::Invoke {
                instance: PROGRAMS_INSTANCE,
                func: EXEC_PATH,
                source,
            })?;
        postcard::from_bytes::<Result<ExecResult, ExecError>>(&bytes).map_err(|source| {
            RpcError::Decode {
                instance: PROGRAMS_INSTANCE,
                func: EXEC_PATH,
                source,
            }
        })
    }

    pub async fn exec_in_container<R, W>(
        client: &Client<R, W>,
        request: &ExecInContainerRequest,
    ) -> ExecPathOutcome
    where
        R: AsyncRead + Send + Unpin + 'static,
        W: AsyncWrite + Send + Unpin + 'static,
    {
        let payload = postcard::to_allocvec(request).map_err(|source| RpcError::Encode {
            instance: PROGRAMS_INSTANCE,
            func: EXEC_IN_CONTAINER,
            source,
        })?;
        let bytes = client
            .invoke_raw(PROGRAMS_INSTANCE, EXEC_IN_CONTAINER, payload)
            .await
            .map_err(|source: TransportError| RpcError::Invoke {
                instance: PROGRAMS_INSTANCE,
                func: EXEC_IN_CONTAINER,
                source,
            })?;
        postcard::from_bytes::<Result<ExecResult, ExecError>>(&bytes).map_err(|source| {
            RpcError::Decode {
                instance: PROGRAMS_INSTANCE,
                func: EXEC_IN_CONTAINER,
                source,
            }
        })
    }
}

#[cfg(feature = "host")]
pub use host::*;

#[cfg(feature = "guest")]
mod guest {
    use super::*;
    use crate::debugger::filesystem;
    use crate::debugger::methods::{EXEC_IN_CONTAINER, EXEC_PATH, PROGRAMS_INSTANCE};
    use crate::error::DispatchError;
    use helios_api::programs as host_programs;
    use std::path::{Path, PathBuf};

    pub(crate) fn supports(instance: &str, func: &str) -> bool {
        matches!(
            (instance, func),
            (PROGRAMS_INSTANCE, EXEC_PATH) | (PROGRAMS_INSTANCE, EXEC_IN_CONTAINER)
        )
    }

    pub(crate) async fn dispatch(func: &str, payload: &[u8]) -> Result<Vec<u8>, DispatchError> {
        match func {
            EXEC_PATH => {
                let request =
                    postcard::from_bytes::<ExecPathRequest>(payload).map_err(|source| {
                        DispatchError::Decode {
                            operation: "debugger programs.exec-path",
                            source,
                        }
                    })?;
                let path = validate_program_path(Path::new(&request.path))?;
                let response = host_programs::exec(host_programs::ExecRequest {
                    name: path.to_string_lossy().into_owned(),
                    args: request.args,
                    env: Vec::new(),
                    path: request.path,
                    stdin: Vec::new(),
                    hint: None,
                    capability_grants: vec![
                        host_programs::root_directory_grant(),
                        host_programs::root_link_grant(),
                        host_programs::network_grant(vec![
                            host_programs::NetworkRight::Tcp,
                            host_programs::NetworkRight::Udp,
                            host_programs::NetworkRight::Dns,
                            host_programs::NetworkRight::PrivilegedBind,
                            host_programs::NetworkRight::Multicast,
                            host_programs::NetworkRight::Admin,
                        ]),
                        host_programs::root_terminal_grant(),
                        host_programs::root_process_grant(),
                        host_programs::root_mount_grant(),
                        host_programs::all_device_classes_grant(),
                        host_programs::observe_machine_grant(),
                        host_programs::write_settings_grant(),
                        host_programs::control_processors_grant(),
                    ],
                })
                .await
                .map(|result| ExecResult {
                    instance_id: result.instance_id,
                    exit_code: result.exit_code,
                    output: crate::system::programs::ExecOutput {
                        stdout: result.output.stdout,
                        stderr: result.output.stderr,
                    },
                    launch_nanos: result.launch_nanos,
                })
                .map_err(|error| ExecError {
                    kind: convert_exec_error_kind(error.kind),
                    detail: error.detail.to_string(),
                });
                postcard::to_allocvec(&response).map_err(|source| DispatchError::Encode {
                    operation: "debugger programs.exec-path",
                    source,
                })
            }
            EXEC_IN_CONTAINER => {
                let request =
                    postcard::from_bytes::<ExecInContainerRequest>(payload).map_err(|source| {
                        DispatchError::Decode {
                            operation: "debugger programs.exec-in-container",
                            source,
                        }
                    })?;
                let response = run_in_container(request).await?;
                postcard::to_allocvec(&response).map_err(|source| DispatchError::Encode {
                    operation: "debugger programs.exec-in-container",
                    source,
                })
            }
            _ => unreachable!("supports must reject unsupported debugger program requests"),
        }
    }

    async fn run_in_container(
        request: ExecInContainerRequest,
    ) -> Result<Result<ExecResult, ExecError>, DispatchError> {
        let path = validate_program_path(Path::new(&request.path))?;
        for mount in &request.mounts {
            if mount.private {
                filesystem::ensure_directory_path(&mount.source_path).await?;
            }
            if let Some(parent) = Path::new(&mount.target_path).parent() {
                let parent = parent.to_string_lossy();
                if !parent.is_empty() && parent != "/" {
                    filesystem::ensure_directory_path(&parent).await?;
                }
            }
        }
        if let Some(dir) = request.scratch_dir.as_deref() {
            filesystem::remove_tree_best_effort(dir).await;
            filesystem::ensure_directory_path(dir).await?;
        }
        let all_rw_rights = vec![
            host_programs::FilesystemRight::Read,
            host_programs::FilesystemRight::Write,
            host_programs::FilesystemRight::MutateDirectory,
            host_programs::FilesystemRight::Execute,
        ];
        let ro_exec_rights = vec![
            host_programs::FilesystemRight::Read,
            host_programs::FilesystemRight::Execute,
        ];
        let mounts = request
            .mounts
            .into_iter()
            .map(|bind| host_programs::ContainerMount {
                source_path: bind.source_path,
                target_path: bind.target_path,
                rights: if bind.writable {
                    all_rw_rights.clone()
                } else {
                    ro_exec_rights.clone()
                },
                sharing: if bind.private {
                    host_programs::ContainerMountSharing::Private
                } else {
                    host_programs::ContainerMountSharing::Shared
                },
            })
            .collect();
        let config = host_programs::ContainerConfig {
            root: host_programs::ContainerMount {
                source_path: "/".to_owned(),
                target_path: "/".to_owned(),
                rights: all_rw_rights,
                sharing: host_programs::ContainerMountSharing::Shared,
            },
            mounts,
            shared_owner: host_programs::ContainerIdentity { uid: 0, gid: 0 },
            credentials: host_programs::ContainerCredentials {
                uid: 0,
                gid: 0,
                supplementary_groups: Vec::new(),
            },
            hostname: "helios".to_owned(),
            domainname: String::new(),
            capability_grants: vec![
                host_programs::root_link_grant(),
                host_programs::network_grant(vec![
                    host_programs::NetworkRight::Tcp,
                    host_programs::NetworkRight::Udp,
                    host_programs::NetworkRight::Dns,
                    host_programs::NetworkRight::PrivilegedBind,
                    host_programs::NetworkRight::Multicast,
                    host_programs::NetworkRight::Admin,
                ]),
                host_programs::root_terminal_grant(),
                host_programs::root_process_grant(),
                host_programs::root_mount_grant(),
                host_programs::all_device_classes_grant(),
                host_programs::observe_machine_grant(),
                host_programs::control_processors_grant(),
            ],
        };
        let container = match host_programs::create_container(config).await {
            Ok(container) => container,
            Err(error) => {
                if let Some(dir) = request.scratch_dir.as_deref() {
                    filesystem::remove_tree_best_effort(dir).await;
                }
                return Ok(Err(ExecError {
                    kind: convert_exec_error_kind(error.kind),
                    detail: error.detail.to_string(),
                }));
            }
        };
        let response = container
            .exec(host_programs::ContainerExecRequest {
                name: path.to_string_lossy().into_owned(),
                args: request.args,
                env: request.env,
                path: request.path,
                stdin: Vec::new(),
                credentials: None,
            })
            .await
            .map(|result| ExecResult {
                instance_id: result.instance_id,
                exit_code: result.exit_code,
                output: crate::system::programs::ExecOutput {
                    stdout: result.output.stdout,
                    stderr: result.output.stderr,
                },
                launch_nanos: result.launch_nanos,
            })
            .map_err(|error| ExecError {
                kind: convert_exec_error_kind(error.kind),
                detail: error.detail.to_string(),
            });
        // Release the container handle (and its private mount claims) before
        // cleaning up scratch files so the next case can claim `/tmp`.
        drop(container);
        if let Some(dir) = request.scratch_dir.as_deref() {
            filesystem::remove_tree_best_effort(dir).await;
        }
        Ok(response)
    }

    fn convert_exec_error_kind(kind: host_programs::ExecErrorKind) -> ExecErrorKind {
        match kind {
            host_programs::ExecErrorKind::InvalidBinary => ExecErrorKind::InvalidBinary,
            host_programs::ExecErrorKind::MissingEntry => ExecErrorKind::MissingEntry,
            host_programs::ExecErrorKind::UnsupportedImport => ExecErrorKind::UnsupportedImport,
            host_programs::ExecErrorKind::InvalidSignature => ExecErrorKind::InvalidSignature,
            host_programs::ExecErrorKind::InvalidPath => ExecErrorKind::InvalidPath,
            host_programs::ExecErrorKind::PermissionDenied => ExecErrorKind::PermissionDenied,
            host_programs::ExecErrorKind::InvalidHint => ExecErrorKind::InvalidHint,
            host_programs::ExecErrorKind::OutOfMemory => ExecErrorKind::OutOfMemory,
            host_programs::ExecErrorKind::Unavailable => ExecErrorKind::Unavailable,
            host_programs::ExecErrorKind::Internal => ExecErrorKind::Internal,
            host_programs::ExecErrorKind::NotFound => ExecErrorKind::NotFound,
            host_programs::ExecErrorKind::Io => ExecErrorKind::Io,
        }
    }

    fn validate_program_path(path: &Path) -> Result<PathBuf, DispatchError> {
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            return Err(DispatchError::protocol(
                "program path does not end with a valid utf-8 file name",
            ));
        };
        if name.is_empty() {
            return Err(DispatchError::protocol(
                "program path does not name an executable",
            ));
        }
        Ok(path.to_path_buf())
    }
}

#[cfg(feature = "guest")]
pub(crate) use guest::{dispatch, supports};
