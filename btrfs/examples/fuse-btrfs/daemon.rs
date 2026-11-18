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
    // The kernel checks permissions from the modes the filesystem reports,
    // and any user may reach the mount. The mount's type stays plain `fuse`,
    // with no subtype and no `blkdev`: fstests' init_rc refuses a TEST_DEV
    // whose `df -T` type is not exactly $FSTYP. The device always holds a
    // complete committed tree, and the unmount's commit runs as the session
    // ends: what was written before the unmount is durable once this process
    // has exited.
    let mut mount_options = vec![
        MountOption::FSName(device.to_string_lossy().into_owned()),
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
        device: device.into(),
        mountpoint: mountpoint.into(),
        read_only,
        mount_options,
    })
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
