//! Mounts a btrfs block device through FUSE and serves it with the writer.

mod device;
mod errno;
mod filesystem;
mod inodes;
mod state;

use std::ffi::OsString;
use std::io;
use std::path::PathBuf;

use fuser::{Config, MountOption, SessionACL};
use helios_btrfs::write::WriteError;
use thiserror::Error;
use tracing::info;

use device::Device;
use filesystem::Daemon;
use state::State;

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
    Device { path: PathBuf, source: io::Error },
    #[error("mounting the filesystem on {path}: {source}")]
    Open { path: PathBuf, source: OpenError },
    #[error("reading the processor count: {0}")]
    Parallelism(io::Error),
    #[error("serving the mount: {0}")]
    Serve(io::Error),
}

struct Arguments {
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
    let mut parsed = Arguments {
        device: device.into(),
        mountpoint: mountpoint.into(),
        read_only: false,
        // The kernel checks permissions from the modes the filesystem
        // reports, and any user may reach the mount. The mount's type stays
        // plain `fuse`, with no subtype and no `blkdev`: fstests' init_rc
        // refuses a TEST_DEV whose `df -T` type is not exactly $FSTYP. Every
        // reply follows its commit, so the device is consistent the moment
        // the kernel unmounts it, whether or not this process has exited.
        mount_options: vec![
            MountOption::FSName(device.to_string_lossy().into_owned()),
            MountOption::DefaultPermissions,
        ],
    };
    let options = options.map(|options| options.to_string_lossy().into_owned());
    for option in options.iter().flat_map(|options| options.split(',')) {
        match option {
            "defaults" => {}
            "ro" => {
                parsed.read_only = true;
                parsed.mount_options.push(MountOption::RO);
            }
            "rw" => parsed.mount_options.push(MountOption::RW),
            "suid" => parsed.mount_options.push(MountOption::Suid),
            "nosuid" => parsed.mount_options.push(MountOption::NoSuid),
            "dev" => parsed.mount_options.push(MountOption::Dev),
            "nodev" => parsed.mount_options.push(MountOption::NoDev),
            "exec" => parsed.mount_options.push(MountOption::Exec),
            "noexec" => parsed.mount_options.push(MountOption::NoExec),
            "atime" => parsed.mount_options.push(MountOption::Atime),
            "noatime" => parsed.mount_options.push(MountOption::NoAtime),
            other => return Err(Error::Option(other.to_owned())),
        }
    }
    Ok(parsed)
}

/// Serves the filesystem in the foreground until it is unmounted.
pub fn run(arguments: impl IntoIterator<Item = OsString>) -> Result<(), Error> {
    let Arguments {
        device,
        mountpoint,
        read_only,
        mount_options,
    } = parse(arguments)?;
    let block_device = Device::open(&device).map_err(|source| Error::Device {
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
    info!(device = %device.display(), mountpoint = %mountpoint.display(), "serving");
    fuser::mount(Daemon::new(state), &mountpoint, &config).map_err(Error::Serve)?;
    info!(mountpoint = %mountpoint.display(), "unmounted");
    Ok(())
}
