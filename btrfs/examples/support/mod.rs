use std::fs::File;
use std::os::unix::fs::FileExt;
use std::path::Path;

use helios_btrfs::BlockSource;
use helios_hal::io::{IoError, IoResult};

pub struct Image {
    file: File,
    len: u64,
}

impl Image {
    pub fn open(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let file = File::open(path)?;
        let len = file.metadata()?.len();
        Ok(Self { file, len })
    }
}

impl BlockSource for Image {
    fn size_bytes(&self) -> u64 {
        self.len
    }

    async fn read_at(&self, offset: u64, buf: &mut [u8]) -> IoResult<()> {
        // A test process owns the file; positional host I/O never shares a cursor.
        self.file.read_exact_at(buf, offset).map_err(|error| {
            if error.kind() == std::io::ErrorKind::UnexpectedEof {
                IoError::OutOfBounds
            } else {
                IoError::DeviceFault
            }
        })
    }
}
