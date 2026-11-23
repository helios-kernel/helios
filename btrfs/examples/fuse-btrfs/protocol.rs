//! Control socket path derivation and line protocol between a running
//! `fuse-btrfs` daemon and a remount invocation.

use std::fmt::Write as _;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

/// Optional directory for per-mount control sockets. When unset or empty,
/// defaults to [`DEFAULT_RUN_DIR`].
pub const RUN_DIR_ENV: &str = "HELIOS_FUSE_BTRFS_RUN_DIR";

/// Default directory for per-mount control sockets.
pub const DEFAULT_RUN_DIR: &str = "/run/helios-fuse-btrfs";

/// Resolves the directory holding per-mount control sockets.
pub fn run_dir() -> PathBuf {
    run_dir_from(std::env::var_os(RUN_DIR_ENV))
}

fn run_dir_from(env_value: Option<std::ffi::OsString>) -> PathBuf {
    match env_value {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ => PathBuf::from(DEFAULT_RUN_DIR),
    }
}

/// Deterministic control socket path for a canonicalized `mountpoint`.
///
/// Uses a 64-bit SHA-256 prefix (`16` hex characters + `.sock`) so the socket
/// path stays well within Linux's 108-byte `sockaddr_un.sun_path` bound even
/// under deep workspace paths.
pub fn socket_path(run_dir: &Path, mountpoint: &Path) -> PathBuf {
    let digest = Sha256::digest(mountpoint.as_os_str().as_bytes());
    let mut name = String::with_capacity(16 + 5);
    for byte in &digest[..8] {
        let _ = write!(name, "{byte:02x}");
    }
    name.push_str(".sock");
    run_dir.join(name)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlRequest {
    Status,
    RemountReadOnly,
    RemountReadWrite,
    RollbackReadOnly,
}

impl ControlRequest {
    pub fn encode(self) -> &'static str {
        match self {
            Self::Status => "status\n",
            Self::RemountReadOnly => "remount ro\n",
            Self::RemountReadWrite => "remount rw\n",
            Self::RollbackReadOnly => "rollback ro\n",
        }
    }

    pub fn decode(line: &str) -> Option<Self> {
        match line.trim_end_matches(['\r', '\n']) {
            "status" => Some(Self::Status),
            "remount ro" => Some(Self::RemountReadOnly),
            "remount rw" => Some(Self::RemountReadWrite),
            "rollback ro" => Some(Self::RollbackReadOnly),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ControlResponse {
    Ok,
    Status { read_only: bool, device: String },
    Error { errno: i32, message: String },
}

impl ControlResponse {
    pub fn encode(&self) -> String {
        match self {
            Self::Ok => "ok\n".to_owned(),
            Self::Status { read_only, device } => {
                let mode = if *read_only { "ro" } else { "rw" };
                format!("status {mode} {}\n", sanitize(device))
            }
            Self::Error { errno, message } => {
                format!("err {errno} {}\n", sanitize(message))
            }
        }
    }

    pub fn decode(line: &str) -> Option<Self> {
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed == "ok" {
            return Some(Self::Ok);
        }
        if let Some(rest) = trimmed.strip_prefix("status ") {
            let (mode, device) = rest.split_once(' ')?;
            let read_only = match mode {
                "ro" => true,
                "rw" => false,
                _ => return None,
            };
            return Some(Self::Status {
                read_only,
                device: device.to_owned(),
            });
        }
        if let Some(rest) = trimmed.strip_prefix("err ") {
            let (code, message) = rest.split_once(' ')?;
            let errno = code.parse().ok()?;
            return Some(Self::Error {
                errno,
                message: message.to_owned(),
            });
        }
        None
    }
}

fn sanitize(text: &str) -> String {
    text.replace(['\r', '\n'], " ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_dir_defaults_when_unset_or_empty() {
        assert_eq!(run_dir_from(None), PathBuf::from(DEFAULT_RUN_DIR));
        assert_eq!(
            run_dir_from(Some(std::ffi::OsString::new())),
            PathBuf::from(DEFAULT_RUN_DIR)
        );
        assert_eq!(
            run_dir_from(Some(std::ffi::OsString::from("/tmp/custom-run"))),
            PathBuf::from("/tmp/custom-run")
        );
        // Exercise `run_dir()` itself without mutating process env.
        assert!(!run_dir().as_os_str().is_empty());
    }

    #[test]
    fn socket_path_is_deterministic_and_short() {
        let dir = Path::new("/run/helios-fuse-btrfs");
        let a = socket_path(dir, Path::new("/mnt/helios-fstests/scratch"));
        let b = socket_path(dir, Path::new("/mnt/helios-fstests/scratch"));
        let c = socket_path(dir, Path::new("/mnt/helios-fstests/test"));
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.parent(), Some(dir));
        assert_eq!(a.file_name().unwrap().len(), 21);
    }

    #[test]
    fn request_roundtrip() {
        for req in [
            ControlRequest::Status,
            ControlRequest::RemountReadOnly,
            ControlRequest::RemountReadWrite,
            ControlRequest::RollbackReadOnly,
        ] {
            assert_eq!(ControlRequest::decode(req.encode()), Some(req));
        }
        assert_eq!(ControlRequest::decode("unknown\n"), None);
    }

    #[test]
    fn response_roundtrip() {
        let responses = [
            ControlResponse::Ok,
            ControlResponse::Status {
                read_only: true,
                device: "/dev/loop1".to_owned(),
            },
            ControlResponse::Status {
                read_only: false,
                device: "/dev/mapper/flakey test".to_owned(),
            },
            ControlResponse::Error {
                errno: 16,
                message: "device busy".to_owned(),
            },
        ];
        for resp in responses {
            assert_eq!(ControlResponse::decode(&resp.encode()), Some(resp));
        }
        let sanitized = ControlResponse::Error {
            errno: 5,
            message: "line1\nline2".to_owned(),
        }
        .encode();
        assert_eq!(sanitized, "err 5 line1 line2\n");
        assert_eq!(
            ControlResponse::decode(&sanitized),
            Some(ControlResponse::Error {
                errno: 5,
                message: "line1 line2".to_owned(),
            })
        );
    }
}
