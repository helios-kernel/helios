//! Mounts a btrfs block device through FUSE and serves it with the writer.

mod control;
mod device;
mod errno;
mod filesystem;
mod inodes;
mod remount;
mod state;

use std::ffi::OsString;
use std::fs::File;
use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use fuser::{Config, MountOption, Session, SessionACL};
use helios_btrfs::write::WriteError;
use thiserror::Error;
use tracing::info;

use crate::options::{AtimeMode, MountOptions, SyncMode};

use control::ControlServer;
use device::{Claim, Hold};
use filesystem::Daemon;
use state::{SharedState, State};

/// `mount(8)` exit code for incorrect invocation (`MNT_EX_USAGE` in
/// `util-linux`'s `include/mount-api-utils.h`).
const MNT_EX_USAGE: u8 = 1;

/// `mount(8)` exit code for a failed mount (`MNT_EX_FAIL` in `util-linux`'s
/// `include/mount-api-utils.h`).
const MNT_EX_FAIL: u8 = 32;

#[derive(Debug, Error)]
pub enum OpenError {
    #[error(transparent)]
    Device(#[from] io::Error),
    #[error(transparent)]
    Write(#[from] WriteError),
    #[error(transparent)]
    Read(#[from] helios_btrfs::Error),
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("usage: fuse-btrfs <block-device> <mountpoint> [-o option[,option...]]; got {0:?}")]
    Usage(Vec<OsString>),
    #[error("unsupported mount option {0:?}")]
    Option(String),
    #[error("opening the block device {path}: {source}")]
    Device {
        path: PathBuf,
        mountpoint: PathBuf,
        source: io::Error,
    },
    #[error("locking the block device {path}: {source}")]
    Hold { path: PathBuf, source: io::Error },
    #[error("mounting the filesystem on {path}: {source}")]
    Open { path: PathBuf, source: OpenError },
    #[error("reading the processor count: {0}")]
    Parallelism(io::Error),
    #[error("mounting on {path}: {source}")]
    Mount {
        device: PathBuf,
        path: PathBuf,
        source: io::Error,
    },
    #[error("binding the control socket for {path}: {source}")]
    Control { path: PathBuf, source: io::Error },
    #[error("remounting {path}: {detail}")]
    Remount { path: PathBuf, detail: String },
    #[error("leaving the caller's working directory: {0}")]
    WorkingDirectory(io::Error),
    #[error("announcing the mount on stdout: {0}")]
    Announce(io::Error),
    #[error("serving the mount: {0}")]
    Serve(io::Error),
}

impl Error {
    fn exit_status(&self) -> u8 {
        match self {
            Self::Usage(_) => MNT_EX_USAGE,
            Self::Option(_)
            | Self::Device { .. }
            | Self::Hold { .. }
            | Self::Open { .. }
            | Self::Parallelism(_)
            | Self::Mount { .. }
            | Self::Control { .. }
            | Self::Remount { .. }
            | Self::WorkingDirectory(_)
            | Self::Announce(_)
            | Self::Serve(_) => MNT_EX_FAIL,
        }
    }

    pub fn exit_code(&self) -> ExitCode {
        ExitCode::from(self.exit_status())
    }

    /// The diagnostic line `mount.fuse.helios-btrfs` forwards to `mount(8)`'s
    /// stderr when startup or remount fails.
    fn mount_diagnostic(&self) -> String {
        match self {
            // Matches util-linux's `mount(8)` message for `EBUSY`
            // (`libmount/src/context_mount.c`, `sys-utils/mount.c`), which
            // fstests' `_filter_busy_mount` and `_filter_error_mount` match.
            Self::Device {
                path,
                mountpoint,
                source,
            }
            | Self::Mount {
                device: path,
                path: mountpoint,
                source,
            } if source.raw_os_error() == Some(libc::EBUSY) => {
                format!(
                    "mount: {}: {} already mounted or mount point busy.",
                    mountpoint.display(),
                    path.display(),
                )
            }
            Self::Remount { detail, .. } => detail.clone(),
            other => format!("mount.fuse.helios-btrfs: {other}"),
        }
    }
}

enum Invocation {
    Mount {
        source_spec: PathBuf,
        target_spec: PathBuf,
        device: PathBuf,
        mountpoint: PathBuf,
        read_only: bool,
        mount_options: Vec<MountOption>,
    },
    Remount {
        source_spec: PathBuf,
        target_spec: PathBuf,
        mountpoint: PathBuf,
        options: MountOptions,
    },
}

/// `fuse-btrfs <block-device> <mountpoint> [-o option[,option...]]`, the
/// shape `mount(8)` gives a `mount.<type>` helper.
fn parse(arguments: impl IntoIterator<Item = OsString>) -> Result<Invocation, Error> {
    let arguments: Vec<OsString> = arguments.into_iter().collect();
    let (device, mountpoint, options) = match arguments.as_slice() {
        [device, mountpoint] => (device, mountpoint, None),
        [device, mountpoint, flag, options] if flag == "-o" => (device, mountpoint, Some(options)),
        _ => return Err(Error::Usage(arguments)),
    };
    let source_spec = PathBuf::from(device);
    let target_spec = PathBuf::from(mountpoint);
    let raw_options = options.map(|options| options.to_string_lossy().into_owned());
    let parsed_options = MountOptions::parse(raw_options.as_deref()).map_err(Error::Option)?;
    let mountpoint = std::fs::canonicalize(&target_spec).map_err(|source| Error::Mount {
        device: source_spec.clone(),
        path: target_spec.clone(),
        source,
    })?;
    if parsed_options.remount {
        return Ok(Invocation::Remount {
            source_spec,
            target_spec,
            mountpoint,
            options: parsed_options,
        });
    }
    // Resolve `source_spec` to an absolute path without following symlinks for
    // `FSName` so `/proc/self/mountinfo` preserves device-mapper symlinks such
    // as `/dev/mapper/flakey-test.*` that `umount <dev>` matches literally,
    // while `umount.fuse` still sees an absolute block-device path from any
    // working directory. Canonicalize both paths as well to check they exist
    // and keep `Session`'s unmount target independent of the working directory.
    let fs_name = std::path::absolute(&source_spec).map_err(|source| Error::Device {
        path: source_spec.clone(),
        mountpoint: target_spec.clone(),
        source,
    })?;
    let device = std::fs::canonicalize(&source_spec).map_err(|source| Error::Device {
        path: source_spec.clone(),
        mountpoint: target_spec.clone(),
        source,
    })?;
    Ok(Invocation::Mount {
        mount_options: fuser_mount_options(&fs_name, &parsed_options),
        read_only: parsed_options.read_only.unwrap_or(false),
        source_spec,
        target_spec,
        device,
        mountpoint,
    })
}

fn fuser_mount_options(fs_name: &Path, options: &MountOptions) -> Vec<MountOption> {
    // The kernel checks permissions from the modes the filesystem reports, and
    // any user may reach the mount. The mount's type stays plain `fuse`, with
    // no subtype and no `blkdev`: fstests' init_rc refuses a TEST_DEV whose
    // `df -T` type is not exactly $FSTYP, so the kernel sends no DESTROY and
    // the unmount does not wait for the daemon. The device always holds a
    // complete committed tree, and the unmount's commit runs as the session
    // ends: what was written before the unmount is durable once the daemon
    // lets go of its `Hold`.
    let mut out = vec![
        MountOption::FSName(fs_name.to_string_lossy().into_owned()),
        MountOption::DefaultPermissions,
    ];
    if let Some(ro) = options.read_only {
        out.push(if ro { MountOption::RO } else { MountOption::RW });
    }
    if let Some(suid) = options.suid {
        out.push(if suid {
            MountOption::Suid
        } else {
            MountOption::NoSuid
        });
    }
    if let Some(dev) = options.dev {
        out.push(if dev {
            MountOption::Dev
        } else {
            MountOption::NoDev
        });
    }
    if let Some(exec) = options.exec {
        out.push(if exec {
            MountOption::Exec
        } else {
            MountOption::NoExec
        });
    }
    if let Some(atime) = options.atime {
        match atime {
            AtimeMode::Atime => out.push(MountOption::Atime),
            AtimeMode::NoAtime => out.push(MountOption::NoAtime),
            AtimeMode::Relatime
            | AtimeMode::NoRelatime
            | AtimeMode::StrictAtime
            | AtimeMode::NoStrictAtime => {}
        }
    }
    if let Some(sync) = options.sync {
        out.push(match sync {
            SyncMode::Sync => MountOption::Sync,
            SyncMode::Async => MountOption::Async,
        });
    }
    if options.dirsync {
        out.push(MountOption::DirSync);
    }
    out
}

struct Started {
    session: Session<Daemon>,
    control: ControlServer,
    hold: Hold,
    mountpoint: PathBuf,
}

/// Opens the device, mounts the FUSE session, binds the control socket and
/// announces readiness on stdout. Returning an error drops the control server,
/// session, `Device`/`Claim` and `Hold` in reverse order before the caller
/// reports the failure to `mount.fuse.helios-btrfs`.
fn start(
    source_spec: PathBuf,
    target_spec: PathBuf,
    device: PathBuf,
    mountpoint: PathBuf,
    read_only: bool,
    mount_options: Vec<MountOption>,
) -> Result<Started, Error> {
    // The claim first: a device another daemon still serves fails here with
    // `EBUSY`, before anything reads it.
    let claim = Claim::open(&device, read_only).map_err(|source| Error::Device {
        path: source_spec.clone(),
        mountpoint: target_spec.clone(),
        source,
    })?;
    let hold = Hold::acquire(&device).map_err(|source| Error::Hold {
        path: device.clone(),
        source,
    })?;
    let concurrency = std::thread::available_parallelism().map_err(Error::Parallelism)?;
    let state = State::open(claim, device.clone(), concurrency, read_only).map_err(|source| {
        Error::Open {
            path: device.clone(),
            source,
        }
    })?;
    let shared = Arc::new(SharedState::new(state));
    let mut config = Config::default();
    config.mount_options = mount_options;
    config.acl = SessionACL::All;
    // `Session::new` returns once the kernel has completed the INIT
    // handshake, so the mount serves requests from here on.
    let session =
        Session::new(Daemon::new(Arc::clone(&shared)), &mountpoint, &config).map_err(|source| {
            Error::Mount {
                device: source_spec,
                path: target_spec,
                source,
            }
        })?;
    let control =
        ControlServer::start(&mountpoint, &device, Arc::clone(&shared)).map_err(|source| {
            Error::Control {
                path: mountpoint.clone(),
                source,
            }
        })?;
    // Drop our local `Arc<SharedState>` so only `session` and `control` retain
    // references to `State` (and `Claim`/`Device`).
    drop(shared);
    std::env::set_current_dir("/").map_err(Error::WorkingDirectory)?;
    announce().map_err(Error::Announce)?;
    info!(device = %device.display(), mountpoint = %mountpoint.display(), read_only, "serving");
    Ok(Started {
        session,
        control,
        hold,
        mountpoint,
    })
}

/// Serves the filesystem in the foreground until it is unmounted, or handles
/// an in-place `-o remount,...` synchronously against the running daemon.
///
/// For initial mounts, writes one handshake line to stdout before replacing
/// stdout with `/dev/null`: `mounted` once the mount is up, or
/// `failed <code> <message>` if startup failed before then. For remounts,
/// writes nothing on success or `failed <code> <message>` on failure.
pub fn run(arguments: impl IntoIterator<Item = OsString>) -> Result<(), Error> {
    let invocation = match parse(arguments) {
        Ok(invocation) => invocation,
        Err(error) => {
            let _ = report_startup_failure(&error);
            return Err(error);
        }
    };
    match invocation {
        Invocation::Remount {
            source_spec,
            target_spec,
            mountpoint,
            options,
        } => {
            if let Err(error) = remount::run(&source_spec, &target_spec, &mountpoint, &options) {
                let _ = report_startup_failure(&error);
                return Err(error);
            }
            Ok(())
        }
        Invocation::Mount {
            source_spec,
            target_spec,
            device,
            mountpoint,
            read_only,
            mount_options,
        } => {
            let Started {
                session,
                control,
                hold,
                mountpoint,
            } = match start(
                source_spec,
                target_spec,
                device,
                mountpoint,
                read_only,
                mount_options,
            ) {
                Ok(started) => started,
                Err(error) => {
                    if !matches!(error, Error::Announce(_)) {
                        let _ = report_startup_failure(&error);
                    }
                    return Err(error);
                }
            };
            // The session ends with the unmount. By then `Filesystem::destroy`
            // has committed and dropped the filesystem, and fuser has finished
            // its own unmount of the mountpoint. Shut down the control server
            // next so its `Arc<SharedState>` (holding `Claim` and `Device`)
            // drops before `hold` is released for `umount.fuse`.
            let served = session.run().map_err(Error::Serve);
            control.shutdown();
            drop(hold);
            served?;
            info!(mountpoint = %mountpoint.display(), "unmounted");
            Ok(())
        }
    }
}

/// Writes `mounted\n` to stdout for `mount.fuse.helios-btrfs` and redirects
/// stdout to `/dev/null` so the readiness pipe closes before serving.
fn announce() -> io::Result<()> {
    let devnull = File::open("/dev/null")?;
    {
        let mut stdout = io::stdout().lock();
        stdout.write_all(b"mounted\n")?;
        stdout.flush()?;
    }
    // SAFETY: `devnull` is an open descriptor and `STDOUT_FILENO` is replaced
    // while no `StdoutLock` is held, closing the readiness pipe's write end
    // while keeping descriptor 1 allocated.
    if unsafe { libc::dup2(devnull.as_raw_fd(), libc::STDOUT_FILENO) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Reports a startup or remount failure on stdout so `mount.fuse.helios-btrfs`
/// can write it to `mount(8)`'s stderr and exit with `mount(8)`'s status code
/// while `tracing` stays routed to `HELIOS_FUSE_BTRFS_LOG`.
fn report_startup_failure(error: &Error) -> io::Result<()> {
    let code = error.exit_status();
    let message = error.mount_diagnostic().replace(['\r', '\n'], " ");
    let mut stdout = io::stdout().lock();
    writeln!(stdout, "failed {code} {message}")?;
    stdout.flush()
}
