//! The block device the daemon serves, as the writer's storage.

use std::fs::{File, OpenOptions};
use std::io::{self, Seek, SeekFrom};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileExt, OpenOptionsExt};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use helios_btrfs::{BlockSink, BlockSource, READ_ALIGNMENT};
use helios_hal::io::{IoError, IoResult};
use tracing::error;

const BLOCK: usize = READ_ALIGNMENT as usize;

/// Linux `BLKROGET` ioctl (`_IO(0x12, 94)` in `<linux/fs.h>`): writes `1` if
/// the block device is read-only and `0` if writable.
const BLKROGET: libc::Ioctl = 0x125e;

/// `O_DIRECT` needs a buffer aligned to the device's logical block size;
/// 4096 is at least that for every block device the format can live on.
#[repr(align(4096))]
struct Aligned([u8; BLOCK]);

/// Queries whether `file` refers to a read-only block device. Regular files
/// return `Ok(false)` (`ENOTTY`).
fn query_block_device_read_only(file: &File) -> io::Result<bool> {
    let mut ro: libc::c_int = 0;
    // SAFETY: `BLKROGET` takes a pointer to `c_int` and writes the device's
    // read-only flag without dereferencing anything else.
    let rc = unsafe { libc::ioctl(file.as_raw_fd(), BLKROGET, &raw mut ro) };
    if rc == 0 {
        return Ok(ro != 0);
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ENOTTY) {
        return Ok(false);
    }
    Err(error)
}

/// Exclusive `O_EXCL` claim on the underlying block device.
///
/// While it is open the kernel refuses every other exclusive claim on the
/// device, another daemon's included, with `EBUSY`, as it does for a mounted
/// device. So two daemons never write one device, and nothing that claims a
/// device before changing it (mkfs, `wipefs`, a device-mapper target) does so
/// under a running daemon. Keeping the claim in its own refcounted handle lets
/// a read-only mount upgrade to read-write on `remount,rw` without releasing
/// `O_EXCL`.
#[derive(Clone)]
pub struct Claim {
    file: Arc<File>,
    writable: bool,
}

impl Claim {
    /// Claims `path` exclusively (`O_EXCL`). A read-only mount falls back to
    /// `O_RDONLY | O_EXCL` only when `O_RDWR | O_EXCL` fails with `EROFS` or
    /// `EACCES` (a read-only block device or read-only image file).
    pub fn open(path: &Path, read_only: bool) -> io::Result<Self> {
        match OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_EXCL)
            .open(path)
        {
            Ok(file) => Ok(Self {
                file: Arc::new(file),
                writable: true,
            }),
            Err(error)
                if read_only
                    && matches!(error.raw_os_error(), Some(libc::EROFS | libc::EACCES)) =>
            {
                let file = OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_EXCL)
                    .open(path)?;
                Ok(Self {
                    file: Arc::new(file),
                    writable: false,
                })
            }
            Err(error) => Err(error),
        }
    }

    pub fn is_writable(&self) -> bool {
        self.writable
    }

    /// Queries the kernel's current read-only status for a block device
    /// (`BLKROGET`, mirroring Linux's `bdev_read_only` check in
    /// `reconfigure_super`).
    pub fn is_block_device_read_only(&self) -> io::Result<bool> {
        query_block_device_read_only(&self.file)
    }
}

/// A block device opened for the filesystem or writer.
///
/// Staged blocks and every read go through the page cache of `buffered`.
/// The superblock goes through `durable`, a descriptor opened
/// `O_DIRECT | O_DSYNC`: the kernel submits that write to the device as a
/// FUA write, after the flush that made every staged block durable, which is
/// the ordering [`BlockSink::commit`] promises and the only form of
/// superblock write a `dm-log-writes` replay can stop at.
pub struct Device {
    #[expect(dead_code, reason = "held for its O_EXCL claim across mount lifetime")]
    claim: Claim,
    buffered: File,
    durable: Option<File>,
    len: u64,
    /// Set when a commit failed part-way; the durable state is then unknown
    /// until the device is reopened.
    poisoned: AtomicBool,
}

impl Device {
    /// Opens `path` read-write under an already-acquired [`Claim`]. Fails with
    /// `EACCES` if the block device is currently read-only (`BLKROGET`).
    pub fn open_read_write(path: &Path, claim: Claim) -> io::Result<Self> {
        if claim.is_block_device_read_only()? {
            return Err(io::Error::from_raw_os_error(libc::EACCES));
        }
        // Not exclusive: `claim` already holds `O_EXCL` for this daemon.
        let buffered = OpenOptions::new().read(true).write(true).open(path)?;
        let durable = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_DIRECT | libc::O_DSYNC)
            .open(path)?;
        // A block device's metadata length is zero; its end is where it seeks to.
        let len = (&buffered).seek(SeekFrom::End(0))?;
        Ok(Self {
            claim,
            buffered,
            durable: Some(durable),
            len,
            poisoned: AtomicBool::new(false),
        })
    }

    /// Opens `path` read-only under an already-acquired [`Claim`].
    pub fn open_read_only(path: &Path, claim: Claim) -> io::Result<Self> {
        let buffered = OpenOptions::new().read(true).open(path)?;
        let len = (&buffered).seek(SeekFrom::End(0))?;
        Ok(Self {
            claim,
            buffered,
            durable: None,
            len,
            poisoned: AtomicBool::new(false),
        })
    }

    #[cfg(test)]
    pub fn open_for_test(path: &Path, claim: Claim) -> io::Result<Self> {
        if claim.is_block_device_read_only()? {
            return Err(io::Error::from_raw_os_error(libc::EACCES));
        }
        let buffered = OpenOptions::new().read(true).write(true).open(path)?;
        let durable = buffered.try_clone()?;
        let len = (&buffered).seek(SeekFrom::End(0))?;
        Ok(Self {
            claim,
            buffered,
            durable: Some(durable),
            len,
            poisoned: AtomicBool::new(false),
        })
    }

    fn check_alive(&self) -> IoResult<()> {
        if self.poisoned.load(Ordering::Acquire) {
            error!("the device is poisoned by an earlier failed commit");
            return Err(IoError::DeviceFault);
        }
        Ok(())
    }

    fn block_offset(&self, block: u64) -> IoResult<u64> {
        block
            .checked_mul(READ_ALIGNMENT)
            .filter(|offset| offset.saturating_add(READ_ALIGNMENT) <= self.len)
            .ok_or(IoError::OutOfBounds)
    }
}

/// The daemon's hold on its device, which whoever unmounts it waits for.
///
/// A plain FUSE unmount returns without waiting for the daemon, which
/// commits what it still holds as its session ends, and an exclusive open
/// cannot be waited for. So the daemon also holds an exclusive `flock` on
/// the device node, the lock systemd's block device locking protocol has a
/// writer take, from before it serves until after it has committed, closed
/// [`Device`] and ended its FUSE session. A shared `flock` on the node
/// returns once the daemon has let go of the device.
pub struct Hold(#[expect(dead_code, reason = "held for its lock, never read")] File);

impl Hold {
    /// Locks the node of the device [`Claim::open`] has already claimed, so
    /// only a daemon in the last moment of its exit, or a waiter's shared
    /// lock, can stand in the way, and either lets go at once.
    pub fn acquire(path: &Path) -> io::Result<Self> {
        let node = File::open(path)?;
        node.lock()?;
        Ok(Self(node))
    }
}

impl BlockSource for Device {
    fn size_bytes(&self) -> u64 {
        self.len
    }

    async fn read_at(&self, offset: u64, buf: &mut [u8]) -> IoResult<()> {
        if !offset
            .checked_add(buf.len() as u64)
            .is_some_and(|end| end <= self.len)
        {
            return Err(IoError::OutOfBounds);
        }
        self.buffered.read_exact_at(buf, offset).map_err(|source| {
            error!(offset, len = buf.len(), %source, "reading the device failed");
            IoError::DeviceFault
        })
    }
}

impl BlockSink for Device {
    async fn stage(&self, block: u64, bytes: &[u8; BLOCK]) -> IoResult<()> {
        self.check_alive()?;
        if self.durable.is_none() {
            error!("staging a block on a read-only device");
            return Err(IoError::DeviceFault);
        }
        let offset = self.block_offset(block)?;
        self.buffered.write_all_at(bytes, offset).map_err(|source| {
            error!(offset, %source, "staging a block on the device failed");
            IoError::DeviceFault
        })
    }

    async fn commit(&self, block: u64, bytes: &[u8; BLOCK]) -> IoResult<()> {
        self.check_alive()?;
        let Some(durable) = &self.durable else {
            error!("committing the superblock on a read-only device");
            return Err(IoError::DeviceFault);
        };
        let offset = self.block_offset(block)?;
        // Nothing here awaits, so a commit that has started always finishes
        // before the caller can cancel it.
        self.buffered
            .sync_data()
            .and_then(|()| {
                let mut aligned = Aligned([0; BLOCK]);
                aligned.0.copy_from_slice(bytes);
                durable.write_all_at(&aligned.0, offset)
            })
            .map_err(|source| {
                self.poisoned.store(true, Ordering::Release);
                error!(offset, %source, "committing the superblock failed; the device is poisoned");
                IoError::DeviceFault
            })
    }
}
