//! Mounts a btrfs block device through FUSE and serves it with the writer.

mod device;
mod errno;
mod filesystem;
mod inodes;
mod state;

use std::ffi::OsString;
use std::fs::File;
use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::process::ExitCode;

use fuser::{Config, MountOption, Session, SessionACL};
use helios_btrfs::write::WriteError;
use thiserror::Error;
use tracing::info;

use device::{Device, Hold};
use filesystem::Daemon;
use state::State;

/// `mount(8)` exit code for incorrect invocation (`MNT_EX_USAGE` in
/// `util-linux`'s `include/mount-api-utils.h`).
const MNT_EX_USAGE: u8 = 1;

/// `mount(8)` exit code for a failed mount (`MNT_EX_FAIL` in `util-linux`'s
/// `include/mount-api-utils.h`).
const MNT_EX_FAIL: u8 = 32;

#[derive(Debug, Error)]
pub enum OpenError {
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
            | Self::WorkingDirectory(_)
            | Self::Announce(_)
            | Self::Serve(_) => MNT_EX_FAIL,
        }
    }

    pub fn exit_code(&self) -> ExitCode {
        ExitCode::from(self.exit_status())
    }

    /// The diagnostic line `mount.fuse.helios-btrfs` forwards to `mount(8)`'s
    /// stderr when startup fails before the mount is up.
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
            other => format!("mount.fuse.helios-btrfs: {other}"),
        }
    }
}

struct Arguments {
    source_spec: PathBuf,
    target_spec: PathBuf,
    device: PathBuf,
    mountpoint: PathBuf,
    read_only: bool,
    mount_options: Vec<MountOption>,
}

/// `fuse-btrfs <block-device> <mountpoint> [-o option[,option...]]`, the
/// shape `mount(8)` gives a `mount.<type>` helper.
fn parse(arguments: impl IntoIterator<Item = OsString>) -> Result<Arguments, Error> {
    let arguments: Vec<OsString> = arguments.into_iter().collect();
    let (device, mountpoint, options) = match arguments.as_slice() {
        [device, mountpoint] => (device, mountpoint, None),
        [device, mountpoint, flag, options] if flag == "-o" => (device, mountpoint, Some(options)),
        _ => return Err(Error::Usage(arguments)),
    };
    let source_spec = PathBuf::from(device);
    let target_spec = PathBuf::from(mountpoint);
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
    let mountpoint = std::fs::canonicalize(&target_spec).map_err(|source| Error::Mount {
        device: source_spec.clone(),
        path: target_spec.clone(),
        source,
    })?;
    let mut read_only = false;
    // Block-filesystem defaults (`mount(8)`): `suid`, `dev` and `exec` are on
    // unless `-o` clears them, whereas fuser's own default sets `MS_NOSUID`
    // and `MS_NODEV` unless told otherwise. Resolving the final state of each
    // pair also avoids handing conflicting flags to fuser.
    let mut suid = true;
    let mut dev = true;
    let mut exec = true;
    let mut atime: Option<bool> = None;
    let options = options.map(|options| options.to_string_lossy().into_owned());
    for option in options.iter().flat_map(|options| options.split(',')) {
        match option {
            "defaults" => {
                read_only = false;
                suid = true;
                dev = true;
                exec = true;
            }
            "ro" => read_only = true,
            "rw" => read_only = false,
            "suid" => suid = true,
            "nosuid" => suid = false,
            "dev" => dev = true,
            "nodev" => dev = false,
            "exec" => exec = true,
            "noexec" => exec = false,
            "atime" => atime = Some(true),
            "noatime" => atime = Some(false),
            other => return Err(Error::Option(other.to_owned())),
        }
    }
    // The kernel checks permissions from the modes the filesystem reports, and
    // any user may reach the mount. The mount's type stays plain `fuse`, with
    // no subtype and no `blkdev`: fstests' init_rc refuses a TEST_DEV whose
    // `df -T` type is not exactly $FSTYP, so the kernel sends no DESTROY and
    // the unmount does not wait for the daemon. The device always holds a
    // complete committed tree, and the unmount's commit runs as the session
    // ends: what was written before the unmount is durable once the daemon
    // lets go of its `Hold`.
    let mut mount_options = vec![
        MountOption::FSName(fs_name.to_string_lossy().into_owned()),
        MountOption::DefaultPermissions,
        if read_only {
            MountOption::RO
        } else {
            MountOption::RW
        },
        if suid {
            MountOption::Suid
        } else {
            MountOption::NoSuid
        },
        if dev {
            MountOption::Dev
        } else {
            MountOption::NoDev
        },
        if exec {
            MountOption::Exec
        } else {
            MountOption::NoExec
        },
    ];
    match atime {
        Some(true) => mount_options.push(MountOption::Atime),
        Some(false) => mount_options.push(MountOption::NoAtime),
        None => {}
    }
    Ok(Arguments {
        source_spec,
        target_spec,
        device,
        mountpoint,
        read_only,
        mount_options,
    })
}

/// Opens the device, mounts the FUSE session and announces readiness on
/// stdout. Returning an error drops any `Device` and `Hold` before the caller
/// reports the failure to `mount.fuse.helios-btrfs`.
fn start(
    arguments: impl IntoIterator<Item = OsString>,
) -> Result<(Session<Daemon>, Hold, PathBuf), Error> {
    let Arguments {
        source_spec,
        target_spec,
        device,
        mountpoint,
        read_only,
        mount_options,
    } = parse(arguments)?;
    // The claim first: a device another daemon still serves fails here with
    // `EBUSY`, before anything reads it.
    let block_device = Device::open(&device).map_err(|source| Error::Device {
        path: source_spec.clone(),
        mountpoint: target_spec.clone(),
        source,
    })?;
    let hold = Hold::acquire(&device).map_err(|source| Error::Hold {
        path: device.clone(),
        source,
    })?;
    let concurrency = std::thread::available_parallelism().map_err(Error::Parallelism)?;
    let state =
        State::open(block_device, concurrency, read_only).map_err(|source| Error::Open {
            path: device.clone(),
            source,
        })?;
    let mut config = Config::default();
    config.mount_options = mount_options;
    config.acl = SessionACL::All;
    // `Session::new` returns once the kernel has completed the INIT
    // handshake, so the mount serves requests from here on.
    let session =
        Session::new(Daemon::new(state), &mountpoint, &config).map_err(|source| Error::Mount {
            device: source_spec,
            path: target_spec,
            source,
        })?;
    std::env::set_current_dir("/").map_err(Error::WorkingDirectory)?;
    announce().map_err(Error::Announce)?;
    info!(device = %device.display(), mountpoint = %mountpoint.display(), "serving");
    Ok((session, hold, mountpoint))
}

/// Serves the filesystem in the foreground until it is unmounted. Writes one
/// handshake line to stdout before replacing stdout with `/dev/null`:
/// `mounted` once the mount is up, or `failed <code> <message>` if startup
/// failed before then.
pub fn run(arguments: impl IntoIterator<Item = OsString>) -> Result<(), Error> {
    let (session, hold, mountpoint) = match start(arguments) {
        Ok(started) => started,
        Err(error) => {
            if !matches!(error, Error::Announce(_)) {
                let _ = report_startup_failure(&error);
            }
            return Err(error);
        }
    };
    // The session ends with the unmount. By then `Filesystem::destroy` has
    // committed and dropped the filesystem, closing the device, and fuser
    // has finished its own unmount of the mountpoint, so letting go of the
    // hold only afterwards keeps that unmount from reaching a mount made
    // after this one.
    let served = session.run().map_err(Error::Serve);
    drop(hold);
    served?;
    info!(mountpoint = %mountpoint.display(), "unmounted");
    Ok(())
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

/// Reports a startup failure on stdout so `mount.fuse.helios-btrfs` can write
/// it to `mount(8)`'s stderr and exit with `mount(8)`'s status code while
/// `tracing` stays routed to `HELIOS_FUSE_BTRFS_LOG`.
fn report_startup_failure(error: &Error) -> io::Result<()> {
    let code = error.exit_status();
    let message = error.mount_diagnostic().replace(['\r', '\n'], " ");
    let mut stdout = io::stdout().lock();
    writeln!(stdout, "failed {code} {message}")?;
    stdout.flush()
}
