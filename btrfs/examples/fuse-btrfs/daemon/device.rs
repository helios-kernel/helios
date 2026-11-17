//! The block device the daemon serves, as the writer's storage.

use std::fs::{File, OpenOptions};
use std::io::{self, Seek, SeekFrom};
use std::os::unix::fs::{FileExt, OpenOptionsExt};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use helios_btrfs::{BlockSink, BlockSource, READ_ALIGNMENT};
use helios_hal::io::{IoError, IoResult};
use tracing::error;

const BLOCK: usize = READ_ALIGNMENT as usize;

/// `O_DIRECT` needs a buffer aligned to the device's logical block size;
/// 4096 is at least that for every block device the format can live on.
#[repr(align(4096))]
struct Aligned([u8; BLOCK]);

/// A block device opened for the writer.
///
/// Staged blocks and every read go through the page cache of `buffered`.
/// The superblock goes through `durable`, a descriptor opened
/// `O_DIRECT | O_DSYNC`: the kernel submits that write to the device as a
/// FUA write, after the flush that made every staged block durable, which is
/// the ordering [`BlockSink::commit`] promises and the only form of
/// superblock write a `dm-log-writes` replay can stop at.
pub struct Device {
    buffered: File,
    durable: File,
    len: u64,
    /// Set when a commit failed part-way; the durable state is then unknown
    /// until the device is reopened.
    poisoned: AtomicBool,
}

impl Device {
    pub fn open(path: &Path) -> io::Result<Self> {
        let buffered = OpenOptions::new().read(true).write(true).open(path)?;
        let durable = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_DIRECT | libc::O_DSYNC)
            .open(path)?;
        // A block device's metadata length is zero; its end is where it seeks to.
        let len = (&buffered).seek(SeekFrom::End(0))?;
        Ok(Self {
            buffered,
            durable,
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
        let offset = self.block_offset(block)?;
        self.buffered.write_all_at(bytes, offset).map_err(|source| {
            error!(offset, %source, "staging a block on the device failed");
            IoError::DeviceFault
        })
    }

    async fn commit(&self, block: u64, bytes: &[u8; BLOCK]) -> IoResult<()> {
        self.check_alive()?;
        let offset = self.block_offset(block)?;
        // Nothing here awaits, so a commit that has started always finishes
        // before the caller can cancel it.
        self.buffered
            .sync_data()
            .and_then(|()| {
                let mut aligned = Aligned([0; BLOCK]);
                aligned.0.copy_from_slice(bytes);
                self.durable.write_all_at(&aligned.0, offset)
            })
            .map_err(|source| {
                self.poisoned.store(true, Ordering::Release);
                error!(offset, %source, "committing the superblock failed; the device is poisoned");
                IoError::DeviceFault
            })
    }
}
