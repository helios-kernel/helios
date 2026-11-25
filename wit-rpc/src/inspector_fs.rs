//! Standard WASI Preview 3 filesystem and mount helpers over `helios-wit-rpc`.
//!
//! Replaces the removed `helios:debugger/filesystem` custom interface: every
//! operation traverses the remote `inspector-worker`'s real
//! `wasi:filesystem/{preopens,types}` descriptors and `helios:system/mounts`,
//! so kernel-enforced `ProcessAuthority` directory rights apply directly.

use thiserror::Error;

use crate::error::RpcError;
use crate::inspector::helios::system::mounts::{
    self as rpc_mounts, MountErrorKind, MountRequest, MountSharing, MountSource,
};
use crate::inspector::wasi::filesystem::preopens as rpc_preopens;
use crate::inspector::wasi::filesystem::types::{
    Descriptor, DescriptorFlags, DescriptorType, DirectoryEntry, ErrorCode, OpenFlags, PathFlags,
};
use crate::{PeerHandle, stream};

const FILE_CHUNK_BYTES: usize = 64 * 1024;

/// Coarse entry classification returned by remote directory listings and stats.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryKind {
    File,
    Directory,
    Other,
}

impl From<DescriptorType> for EntryKind {
    fn from(ty: DescriptorType) -> Self {
        match ty {
            DescriptorType::Directory => Self::Directory,
            DescriptorType::RegularFile => Self::File,
            _ => Self::Other,
        }
    }
}

/// One directory entry returned by [`list_dir`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoteDirEntry {
    pub name: String,
    pub kind: EntryKind,
}

/// Metadata returned by [`stat`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoteFileStat {
    pub kind: EntryKind,
    pub size: u64,
}

/// Request to mount a btrfs disk via `helios:system/mounts.mount`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MountBtrfsRequest {
    pub disk: String,
    pub path: String,
    pub read_only: bool,
    pub shared: bool,
    pub compress: Option<String>,
    pub commit: Option<u32>,
    pub max_inline: Option<u64>,
}

/// Structured error returned by remote WASI filesystem / mount helpers.
#[derive(Debug, Error)]
pub enum FsRpcError {
    #[error("RPC failure during {operation} on `{path}`: {source}")]
    Rpc {
        operation: &'static str,
        path: String,
        #[source]
        source: RpcError,
    },
    #[error("filesystem {operation} on `{path}` failed: {code:?}")]
    Fs {
        operation: &'static str,
        path: String,
        code: ErrorCode,
    },
    #[error("no preopened directory covers `{path}` (permission denied)")]
    NoPreopen { path: String },
    #[error("mount `{path}` failed ({kind:?}): {detail}")]
    Mount {
        path: String,
        kind: MountErrorKind,
        detail: String,
    },
}

impl FsRpcError {
    pub fn guest_panic(&self) -> Option<&str> {
        match self {
            Self::Rpc { source, .. } => source.guest_panic(),
            Self::Fs { .. } | Self::NoPreopen { .. } | Self::Mount { .. } => None,
        }
    }
}

fn normalize_path(path: &str) -> String {
    let mut parts = Vec::new();
    for seg in path.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            other => parts.push(other),
        }
    }
    if parts.is_empty() {
        "/".to_owned()
    } else {
        format!("/{}", parts.join("/"))
    }
}

/// Resolves `abs_path` against the worker's `wasi:filesystem/preopens` list,
/// picking the longest matching directory prefix.
async fn resolve_preopen(
    peer: &PeerHandle,
    abs_path: &str,
    operation: &'static str,
) -> Result<(Descriptor, String), FsRpcError> {
    let target = normalize_path(abs_path);
    let preopens = rpc_preopens::RpcClient::new(peer.clone())
        .get_directories()
        .await
        .map_err(|source| FsRpcError::Rpc {
            operation,
            path: target.clone(),
            source,
        })?;

    let mut best_idx: Option<usize> = None;
    let mut best_len: usize = 0;
    let mut best_rel = String::new();

    for (idx, (_, guest_name)) in preopens.iter().enumerate() {
        let base = normalize_path(guest_name);
        let rel_opt = if base == "/" {
            Some(target.trim_start_matches('/').to_owned())
        } else if target == base {
            Some(String::new())
        } else {
            target
                .strip_prefix(&base)
                .and_then(|rest| rest.strip_prefix('/'))
                .map(ToOwned::to_owned)
        };
        if let Some(rel) = rel_opt
            && (best_idx.is_none() || base.len() > best_len)
        {
            best_idx = Some(idx);
            best_len = base.len();
            best_rel = rel;
        }
    }

    let Some(idx) = best_idx else {
        return Err(FsRpcError::NoPreopen { path: target });
    };
    let (desc, _) = preopens
        .into_iter()
        .nth(idx)
        .expect("selected preopen index exists");
    Ok((desc, best_rel))
}

/// Lists directory entries at `path`.
pub async fn list_dir(peer: &PeerHandle, path: &str) -> Result<Vec<RemoteDirEntry>, FsRpcError> {
    let target = normalize_path(path);
    let (base, rel) = resolve_preopen(peer, &target, "list_dir").await?;
    let dir_desc = if rel.is_empty() {
        base
    } else {
        base.open_at(
            PathFlags::SYMLINK_FOLLOW,
            rel,
            OpenFlags::DIRECTORY,
            DescriptorFlags::READ,
        )
        .await
        .map_err(|source| FsRpcError::Rpc {
            operation: "open_at(dir)",
            path: target.clone(),
            source,
        })?
        .map_err(|code| FsRpcError::Fs {
            operation: "open_at(dir)",
            path: target.clone(),
            code,
        })?
    };

    let (mut rx, done_fut) = dir_desc
        .read_directory()
        .await
        .map_err(|source| FsRpcError::Rpc {
            operation: "read_directory",
            path: target.clone(),
            source,
        })?;
    let (raw_res, done_res) = futures_lite::future::zip(
        async move {
            let mut out = Vec::new();
            while let Some(batch) = rx.next_batch().await? {
                out.extend(batch);
            }
            Ok::<Vec<DirectoryEntry>, RpcError>(out)
        },
        done_fut,
    )
    .await;

    let entries = raw_res.map_err(|source| FsRpcError::Rpc {
        operation: "read_directory(stream)",
        path: target.clone(),
        source,
    })?;
    done_res
        .map_err(|source| FsRpcError::Rpc {
            operation: "read_directory(done)",
            path: target.clone(),
            source,
        })?
        .map_err(|code| FsRpcError::Fs {
            operation: "read_directory",
            path: target,
            code,
        })?;

    Ok(entries
        .into_iter()
        .filter(|e| e.name != "." && e.name != "..")
        .map(|e| RemoteDirEntry {
            name: e.name,
            kind: e.r#type.into(),
        })
        .collect())
}

/// Stats `path` (following symlinks).
pub async fn stat(peer: &PeerHandle, path: &str) -> Result<RemoteFileStat, FsRpcError> {
    let target = normalize_path(path);
    let (base, rel) = resolve_preopen(peer, &target, "stat").await?;
    let st = if rel.is_empty() {
        base.stat()
            .await
            .map_err(|source| FsRpcError::Rpc {
                operation: "stat",
                path: target.clone(),
                source,
            })?
            .map_err(|code| FsRpcError::Fs {
                operation: "stat",
                path: target,
                code,
            })?
    } else {
        base.stat_at(PathFlags::SYMLINK_FOLLOW, rel)
            .await
            .map_err(|source| FsRpcError::Rpc {
                operation: "stat_at",
                path: target.clone(),
                source,
            })?
            .map_err(|code| FsRpcError::Fs {
                operation: "stat_at",
                path: target,
                code,
            })?
    };
    Ok(RemoteFileStat {
        kind: st.r#type.into(),
        size: st.size,
    })
}

/// Reads the full contents of file `path`.
pub async fn read_file(peer: &PeerHandle, path: &str) -> Result<Vec<u8>, FsRpcError> {
    let target = normalize_path(path);
    let (base, rel) = resolve_preopen(peer, &target, "read_file").await?;
    if rel.is_empty() {
        return Err(FsRpcError::Fs {
            operation: "read_file",
            path: target,
            code: ErrorCode::IsDirectory,
        });
    }
    let file = base
        .open_at(
            PathFlags::SYMLINK_FOLLOW,
            rel,
            OpenFlags::empty(),
            DescriptorFlags::READ,
        )
        .await
        .map_err(|source| FsRpcError::Rpc {
            operation: "open_at(read)",
            path: target.clone(),
            source,
        })?
        .map_err(|code| FsRpcError::Fs {
            operation: "open_at(read)",
            path: target.clone(),
            code,
        })?;

    let (mut rx, done_fut) = file
        .read_via_stream(0)
        .await
        .map_err(|source| FsRpcError::Rpc {
            operation: "read_via_stream",
            path: target.clone(),
            source,
        })?;
    let (bytes_res, done_res) = futures_lite::future::zip(
        async move {
            let mut out = Vec::new();
            while let Some(chunk) = rx.next_batch().await? {
                out.extend_from_slice(&chunk);
            }
            Ok::<Vec<u8>, RpcError>(out)
        },
        done_fut,
    )
    .await;

    let bytes = bytes_res.map_err(|source| FsRpcError::Rpc {
        operation: "read_via_stream(stream)",
        path: target.clone(),
        source,
    })?;
    done_res
        .map_err(|source| FsRpcError::Rpc {
            operation: "read_via_stream(done)",
            path: target.clone(),
            source,
        })?
        .map_err(|code| FsRpcError::Fs {
            operation: "read_via_stream",
            path: target,
            code,
        })?;
    Ok(bytes)
}

/// Writes or appends `data` to `path`, creating the file if it does not exist.
pub async fn write_file(
    peer: &PeerHandle,
    path: &str,
    data: &[u8],
    append: bool,
) -> Result<(), FsRpcError> {
    let target = normalize_path(path);
    let (base, rel) = resolve_preopen(peer, &target, "write_file").await?;
    if rel.is_empty() {
        return Err(FsRpcError::Fs {
            operation: "write_file",
            path: target,
            code: ErrorCode::IsDirectory,
        });
    }
    let open_flags = if append {
        OpenFlags::CREATE
    } else {
        OpenFlags::CREATE | OpenFlags::TRUNCATE
    };
    let file = base
        .open_at(
            PathFlags::SYMLINK_FOLLOW,
            rel,
            open_flags,
            DescriptorFlags::WRITE,
        )
        .await
        .map_err(|source| FsRpcError::Rpc {
            operation: "open_at(write)",
            path: target.clone(),
            source,
        })?
        .map_err(|code| FsRpcError::Fs {
            operation: "open_at(write)",
            path: target.clone(),
            code,
        })?;

    let (mut tx, rx) = stream::<u8>();
    let done_fut = if append {
        file.append_via_stream(rx).await
    } else {
        file.write_via_stream(rx, 0).await
    }
    .map_err(|source| FsRpcError::Rpc {
        operation: "write_via_stream",
        path: target.clone(),
        source,
    })?;

    let ((), done_res) = futures_lite::future::zip(
        async move {
            for chunk in data.chunks(FILE_CHUNK_BYTES) {
                if tx.send_batch(chunk.to_vec()).await.is_err() {
                    break;
                }
            }
            let _ = tx.close().await;
        },
        done_fut,
    )
    .await;

    done_res
        .map_err(|source| FsRpcError::Rpc {
            operation: "write_via_stream(done)",
            path: target.clone(),
            source,
        })?
        .map_err(|code| FsRpcError::Fs {
            operation: "write_via_stream",
            path: target,
            code,
        })?;
    Ok(())
}

/// Creates a directory at `path`.
pub async fn mkdir(peer: &PeerHandle, path: &str) -> Result<(), FsRpcError> {
    let target = normalize_path(path);
    let (base, rel) = resolve_preopen(peer, &target, "mkdir").await?;
    if rel.is_empty() {
        return Err(FsRpcError::Fs {
            operation: "mkdir",
            path: target,
            code: ErrorCode::Exist,
        });
    }
    base.create_directory_at(rel)
        .await
        .map_err(|source| FsRpcError::Rpc {
            operation: "create_directory_at",
            path: target.clone(),
            source,
        })?
        .map_err(|code| FsRpcError::Fs {
            operation: "create_directory_at",
            path: target,
            code,
        })
}

/// Removes a file or empty directory at `path`.
pub async fn remove(peer: &PeerHandle, path: &str) -> Result<(), FsRpcError> {
    let target = normalize_path(path);
    let (base, rel) = resolve_preopen(peer, &target, "remove").await?;
    if rel.is_empty() {
        return Err(FsRpcError::Fs {
            operation: "remove",
            path: target,
            code: ErrorCode::NotPermitted,
        });
    }
    let st = base
        .stat_at(PathFlags::empty(), rel.clone())
        .await
        .map_err(|source| FsRpcError::Rpc {
            operation: "stat_at",
            path: target.clone(),
            source,
        })?
        .map_err(|code| FsRpcError::Fs {
            operation: "stat_at",
            path: target.clone(),
            code,
        })?;
    if st.r#type == DescriptorType::Directory {
        base.remove_directory_at(rel)
            .await
            .map_err(|source| FsRpcError::Rpc {
                operation: "remove_directory_at",
                path: target.clone(),
                source,
            })?
            .map_err(|code| FsRpcError::Fs {
                operation: "remove_directory_at",
                path: target,
                code,
            })
    } else {
        base.unlink_file_at(rel)
            .await
            .map_err(|source| FsRpcError::Rpc {
                operation: "unlink_file_at",
                path: target.clone(),
                source,
            })?
            .map_err(|code| FsRpcError::Fs {
                operation: "unlink_file_at",
                path: target,
                code,
            })
    }
}

/// Copies a regular file from `source` to `destination`.
pub async fn copy(peer: &PeerHandle, source: &str, destination: &str) -> Result<(), FsRpcError> {
    let bytes = read_file(peer, source).await?;
    write_file(peer, destination, &bytes, false).await
}

/// Renames `source` to `destination`.
pub async fn rename(peer: &PeerHandle, source: &str, destination: &str) -> Result<(), FsRpcError> {
    let src = normalize_path(source);
    let dst = normalize_path(destination);
    let (src_base, src_rel) = resolve_preopen(peer, &src, "rename").await?;
    let (dst_base, dst_rel) = resolve_preopen(peer, &dst, "rename").await?;
    if src_rel.is_empty() || dst_rel.is_empty() {
        return Err(FsRpcError::Fs {
            operation: "rename_at",
            path: src,
            code: ErrorCode::NotPermitted,
        });
    }
    src_base
        .rename_at(src_rel, &dst_base, dst_rel)
        .await
        .map_err(|source| FsRpcError::Rpc {
            operation: "rename_at",
            path: src.clone(),
            source,
        })?
        .map_err(|code| FsRpcError::Fs {
            operation: "rename_at",
            path: src,
            code,
        })
}

/// Creates an empty file at `path` if it does not already exist.
pub async fn touch(peer: &PeerHandle, path: &str) -> Result<(), FsRpcError> {
    let target = normalize_path(path);
    let (base, rel) = resolve_preopen(peer, &target, "touch").await?;
    if rel.is_empty() {
        return Err(FsRpcError::Fs {
            operation: "touch",
            path: target,
            code: ErrorCode::IsDirectory,
        });
    }
    let _file = base
        .open_at(
            PathFlags::SYMLINK_FOLLOW,
            rel,
            OpenFlags::CREATE,
            DescriptorFlags::WRITE,
        )
        .await
        .map_err(|source| FsRpcError::Rpc {
            operation: "open_at(touch)",
            path: target.clone(),
            source,
        })?
        .map_err(|code| FsRpcError::Fs {
            operation: "open_at(touch)",
            path: target,
            code,
        })?;
    Ok(())
}

/// Mounts a btrfs disk via `helios:system/mounts.mount`.
pub async fn mount_btrfs(peer: &PeerHandle, request: &MountBtrfsRequest) -> Result<(), FsRpcError> {
    rpc_mounts::RpcClient::new(peer.clone())
        .mount(MountRequest {
            source: MountSource::Btrfs(request.disk.clone()),
            path: request.path.clone(),
            read_only: request.read_only,
            sharing: if request.shared {
                MountSharing::Shared
            } else {
                MountSharing::Private
            },
            compress: request.compress.clone(),
            commit: request.commit,
            max_inline: request.max_inline,
        })
        .await
        .map_err(|source| FsRpcError::Rpc {
            operation: "mounts.mount",
            path: request.path.clone(),
            source,
        })?
        .map_err(|err| FsRpcError::Mount {
            path: request.path.clone(),
            kind: err.kind,
            detail: err.detail,
        })
}
