//! In-place `-o remount,...` coordination between `mount(8)`, the kernel VFS
//! (`mount -i`), and the running `fuse-btrfs` daemon.

use std::path::Path;
use std::process::Command;

use tracing::{info, warn};

use crate::mountinfo;
use crate::options::MountOptions;
use crate::protocol::{self, ControlRequest, ControlResponse};

use super::Error;
use super::control;

const MOUNTINFO_PATH: &str = "/proc/self/mountinfo";

/// Remounts an active `fuse-btrfs` mount in place, keeping the kernel VFS mount
/// flags and the daemon's read-only/read-write state consistent.
///
/// Ordering matters:
/// - Transitioning to `ro` applies `mount -i -o remount,ro,...` FIRST so the
///   kernel's `sb_prepare_remount_readonly` rejects open writers with `EBUSY`
///   and `fuse_reconfigure`'s `sync_filesystem` flushes dirty page-cache data
///   while the daemon is still writable; only then does the daemon commit the
///   running btrfs transaction and flip `read_only = true`.
/// - Transitioning to `rw` notifies the daemon FIRST so `BLKROGET` read-only
///   block devices and unwritable images fail cleanly with `EACCES`/`EROFS`
///   before the kernel clears `SB_RDONLY`; if `mount -i` subsequently fails,
///   the daemon rolls back to `read_only = true`.
pub fn run(
    source_spec: &Path,
    target_spec: &Path,
    mountpoint: &Path,
    requested: &MountOptions,
) -> Result<(), Error> {
    let mountinfo_text = std::fs::read_to_string(MOUNTINFO_PATH).map_err(|error| {
        remount_error(
            target_spec,
            format!("mount.fuse.helios-btrfs: reading {MOUNTINFO_PATH}: {error}"),
        )
    })?;
    let entry = mountinfo::find_mount(&mountinfo_text, mountpoint).ok_or_else(|| {
        remount_error(
            target_spec,
            format!("mount: {}: not mounted.", target_spec.display()),
        )
    })?;
    if entry.fs_type != "fuse" {
        return Err(remount_error(
            target_spec,
            format!(
                "mount.fuse.helios-btrfs: {} is mounted as {}, not fuse",
                target_spec.display(),
                entry.fs_type
            ),
        ));
    }

    let socket = protocol::socket_path(&protocol::run_dir(), mountpoint);
    let was_read_only = match control::send(&socket, ControlRequest::Status) {
        Ok(ControlResponse::Status { read_only, .. }) => read_only,
        Ok(ControlResponse::Error { errno, message }) => {
            return Err(remount_error(
                target_spec,
                format_daemon_error(target_spec, &entry.source, false, errno, &message),
            ));
        }
        Ok(ControlResponse::Ok) => {
            return Err(remount_error(
                target_spec,
                format!(
                    "mount.fuse.helios-btrfs: unexpected status reply from daemon for {}",
                    target_spec.display()
                ),
            ));
        }
        Err(error) => {
            return Err(remount_error(
                target_spec,
                format!(
                    "mount.fuse.helios-btrfs: cannot reach fuse-btrfs daemon for {} at {}: {error}",
                    target_spec.display(),
                    socket.display()
                ),
            ));
        }
    };

    let target_read_only = requested.read_only.unwrap_or(was_read_only);
    let old_vfs_opts = entry.vfs_options.to_remount_option_string();
    let mut merged = entry.vfs_options.apply(requested);
    merged.read_only = Some(target_read_only);
    let new_vfs_opts = merged.to_remount_option_string();
    let mount_source = if entry.source.is_empty() {
        source_spec.to_string_lossy().into_owned()
    } else {
        entry.source.clone()
    };

    if target_read_only {
        apply_kernel_remount(&mount_source, mountpoint, &new_vfs_opts)
            .map_err(|detail| remount_error(target_spec, detail))?;
        match control::send(&socket, ControlRequest::RemountReadOnly) {
            Ok(ControlResponse::Ok) => {
                info!(mountpoint = %mountpoint.display(), options = %new_vfs_opts, "remounted read-only");
                Ok(())
            }
            Ok(ControlResponse::Error { errno, message }) => {
                if !was_read_only && errno != libc::EIO {
                    rollback_kernel(&mount_source, mountpoint, &old_vfs_opts);
                }
                Err(remount_error(
                    target_spec,
                    format_daemon_error(target_spec, &mount_source, true, errno, &message),
                ))
            }
            Ok(ControlResponse::Status { .. }) => {
                if !was_read_only {
                    rollback_kernel(&mount_source, mountpoint, &old_vfs_opts);
                }
                Err(remount_error(
                    target_spec,
                    format!(
                        "mount.fuse.helios-btrfs: unexpected reply from daemon while remounting {}",
                        target_spec.display()
                    ),
                ))
            }
            Err(error) => {
                if !was_read_only {
                    rollback_kernel(&mount_source, mountpoint, &old_vfs_opts);
                }
                Err(remount_error(
                    target_spec,
                    format!(
                        "mount.fuse.helios-btrfs: daemon communication failed during remount,ro of {}: {error}",
                        target_spec.display()
                    ),
                ))
            }
        }
    } else {
        match control::send(&socket, ControlRequest::RemountReadWrite) {
            Ok(ControlResponse::Ok) => {}
            Ok(ControlResponse::Error { errno, message }) => {
                return Err(remount_error(
                    target_spec,
                    format_daemon_error(target_spec, &mount_source, false, errno, &message),
                ));
            }
            Ok(ControlResponse::Status { .. }) => {
                return Err(remount_error(
                    target_spec,
                    format!(
                        "mount.fuse.helios-btrfs: unexpected reply from daemon while remounting {}",
                        target_spec.display()
                    ),
                ));
            }
            Err(error) => {
                return Err(remount_error(
                    target_spec,
                    format!(
                        "mount.fuse.helios-btrfs: daemon communication failed during remount,rw of {}: {error}",
                        target_spec.display()
                    ),
                ));
            }
        }

        if let Err(detail) = apply_kernel_remount(&mount_source, mountpoint, &new_vfs_opts) {
            if was_read_only
                && let Err(rollback_err) = control::send(&socket, ControlRequest::RollbackReadOnly)
            {
                warn!(
                    mountpoint = %mountpoint.display(),
                    %rollback_err,
                    "failed to roll back daemon to read-only after mount -i failure"
                );
            }
            return Err(remount_error(target_spec, detail));
        }

        info!(mountpoint = %mountpoint.display(), options = %new_vfs_opts, "remounted read-write");
        Ok(())
    }
}

fn apply_kernel_remount(source: &str, mountpoint: &Path, options: &str) -> Result<(), String> {
    let output = Command::new("mount")
        .arg("-i")
        .arg("-o")
        .arg(options)
        .arg(source)
        .arg(mountpoint)
        .output()
        .map_err(|error| format!("mount.fuse.helios-btrfs: executing mount -i: {error}"))?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    if !stderr.is_empty() {
        return Err(stderr);
    }
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if !stdout.is_empty() {
        return Err(stdout);
    }
    Err(format!(
        "mount.fuse.helios-btrfs: mount -i -o {options} {} failed with {}",
        mountpoint.display(),
        output.status
    ))
}

fn rollback_kernel(source: &str, mountpoint: &Path, old_options: &str) {
    if let Err(error) = apply_kernel_remount(source, mountpoint, old_options) {
        warn!(
            mountpoint = %mountpoint.display(),
            options = %old_options,
            %error,
            "failed to roll back kernel mount flags"
        );
    }
}

fn format_daemon_error(
    target: &Path,
    source: &str,
    to_read_only: bool,
    errno: i32,
    message: &str,
) -> String {
    match errno {
        libc::EBUSY => format!("mount: {}: mount point is busy.", target.display()),
        libc::EACCES | libc::EROFS if !to_read_only => format!(
            "mount: {}: cannot remount {source} read-write, is write-protected.",
            target.display()
        ),
        _ => format!("mount.fuse.helios-btrfs: {message}"),
    }
}

fn remount_error(target: &Path, detail: String) -> Error {
    Error::Remount {
        path: target.to_path_buf(),
        detail,
    }
}
