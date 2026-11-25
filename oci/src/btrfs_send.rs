//! Pure-Rust Linux-compatible btrfs send stream (v1) encoder (`fs/btrfs/send.h`).
//!
//! Used by [`crate::ImageStore`] when a [`crate::SubvolumeBackend`] supports
//! `helios:system/btrfs.receive-subvolume`: a tar layer (including whiteouts,
//! regular files, directories, symlinks, hardlinks, device/FIFO nodes, Unix
//! `uid`/`gid`/`mode` with setuid/setgid/sticky bits, and `SCHILY.xattr.*`
//! capabilities such as `security.capability`) is encoded into a CRC32C-verified
//! v1 send stream so Helios's btrfs implementation materializes the layer into a
//! read-only subvolume with complete Unix metadata from WASI user space.

use crc::{CRC_32_ISCSI, Crc, Table};

use crate::error::{OciError, Result};

const CASTAGNOLI: Crc<u32, Table<16>> = Crc::<u32, Table<16>>::new(&CRC_32_ISCSI);
const STREAM_MAGIC: &[u8; 13] = b"btrfs-stream\0";
const STREAM_VERSION_1: u32 = 1;
/// Maximum data chunk per `WRITE` command (`BTRFS_SEND_READ_SIZE`, fits in `u16` TLV length).
const WRITE_CHUNK_BYTES: usize = 48 * 1024;

mod cmd {
    pub const SUBVOL: u16 = 1;
    pub const SNAPSHOT: u16 = 2;
    pub const MKFILE: u16 = 3;
    pub const MKDIR: u16 = 4;
    pub const MKNOD: u16 = 5;
    pub const MKFIFO: u16 = 6;
    pub const MKSOCK: u16 = 7;
    pub const SYMLINK: u16 = 8;
    pub const LINK: u16 = 10;
    pub const UNLINK: u16 = 11;
    pub const RMDIR: u16 = 12;
    pub const SET_XATTR: u16 = 13;
    pub const WRITE: u16 = 15;
    pub const TRUNCATE: u16 = 17;
    pub const CHMOD: u16 = 18;
    pub const CHOWN: u16 = 19;
    pub const UTIMES: u16 = 20;
    pub const END: u16 = 21;
}

mod attr {
    pub const UUID: u16 = 1;
    pub const CTRANSID: u16 = 2;
    pub const SIZE: u16 = 4;
    pub const MODE: u16 = 5;
    pub const UID: u16 = 6;
    pub const GID: u16 = 7;
    pub const RDEV: u16 = 8;
    pub const CTIME: u16 = 9;
    pub const MTIME: u16 = 10;
    pub const ATIME: u16 = 11;
    pub const XATTR_NAME: u16 = 13;
    pub const XATTR_DATA: u16 = 14;
    pub const PATH: u16 = 15;
    pub const PATH_LINK: u16 = 17;
    pub const FILE_OFFSET: u16 = 18;
    pub const DATA: u16 = 19;
    pub const CLONE_UUID: u16 = 20;
    pub const CLONE_CTRANSID: u16 = 21;
}

/// Linux btrfs send stream command CRC32C (`btrfs_crc32c(0, buf, len)`).
fn send_stream_crc(data: &[u8]) -> u32 {
    let mut digest = CASTAGNOLI.digest_with_initial(0);
    digest.update(data);
    !digest.finalize()
}

/// Parent subvolume reference for an incremental `SNAPSHOT` send stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParentSubvolumeRef {
    pub uuid: [u8; 16],
    pub ctransid: u64,
}

/// Builder for a CRC32C-framed Linux btrfs send stream (v1).
pub struct BtrfsSendBuilder {
    out: Vec<u8>,
}

impl BtrfsSendBuilder {
    /// Start a new base subvolume (`SUBVOL`) stream.
    pub fn new_subvol(name: &str, uuid: [u8; 16], ctransid: u64) -> Result<Self> {
        let mut builder = Self::with_header();
        builder.push_cmd(cmd::SUBVOL, |c| {
            c.bytes(attr::PATH, name.as_bytes())?;
            c.bytes(attr::UUID, &uuid)?;
            c.u64(attr::CTRANSID, ctransid);
            Ok(())
        })?;
        Ok(builder)
    }

    /// Start a new incremental snapshot (`SNAPSHOT`) stream cloning from `parent`.
    pub fn new_snapshot(
        name: &str,
        uuid: [u8; 16],
        ctransid: u64,
        parent: ParentSubvolumeRef,
    ) -> Result<Self> {
        let mut builder = Self::with_header();
        builder.push_cmd(cmd::SNAPSHOT, |c| {
            c.bytes(attr::PATH, name.as_bytes())?;
            c.bytes(attr::UUID, &uuid)?;
            c.u64(attr::CTRANSID, ctransid);
            c.bytes(attr::CLONE_UUID, &parent.uuid)?;
            c.u64(attr::CLONE_CTRANSID, parent.ctransid);
            Ok(())
        })?;
        Ok(builder)
    }

    fn with_header() -> Self {
        let mut out = Vec::with_capacity(4096);
        out.extend_from_slice(STREAM_MAGIC);
        out.extend_from_slice(&STREAM_VERSION_1.to_le_bytes());
        Self { out }
    }

    pub fn mkdir(&mut self, rel_path: &str) -> Result<()> {
        self.push_cmd(cmd::MKDIR, |c| c.bytes(attr::PATH, rel_path.as_bytes()))
    }

    pub fn mkfile(&mut self, rel_path: &str) -> Result<()> {
        self.push_cmd(cmd::MKFILE, |c| c.bytes(attr::PATH, rel_path.as_bytes()))
    }

    pub fn mkfifo(&mut self, rel_path: &str) -> Result<()> {
        self.push_cmd(cmd::MKFIFO, |c| c.bytes(attr::PATH, rel_path.as_bytes()))
    }

    pub fn mksock(&mut self, rel_path: &str) -> Result<()> {
        self.push_cmd(cmd::MKSOCK, |c| c.bytes(attr::PATH, rel_path.as_bytes()))
    }

    pub fn mknod(&mut self, rel_path: &str, mode: u32, rdev: u32) -> Result<()> {
        self.push_cmd(cmd::MKNOD, |c| {
            c.bytes(attr::PATH, rel_path.as_bytes())?;
            c.u64(attr::MODE, u64::from(mode));
            c.u64(attr::RDEV, u64::from(rdev));
            Ok(())
        })
    }

    pub fn symlink(&mut self, rel_path: &str, target: &str) -> Result<()> {
        self.push_cmd(cmd::SYMLINK, |c| {
            c.bytes(attr::PATH, rel_path.as_bytes())?;
            c.bytes(attr::PATH_LINK, target.as_bytes())
        })
    }

    pub fn hard_link(&mut self, rel_path: &str, existing_rel_path: &str) -> Result<()> {
        self.push_cmd(cmd::LINK, |c| {
            c.bytes(attr::PATH, rel_path.as_bytes())?;
            c.bytes(attr::PATH_LINK, existing_rel_path.as_bytes())
        })
    }

    pub fn unlink(&mut self, rel_path: &str) -> Result<()> {
        self.push_cmd(cmd::UNLINK, |c| c.bytes(attr::PATH, rel_path.as_bytes()))
    }

    pub fn rmdir(&mut self, rel_path: &str) -> Result<()> {
        self.push_cmd(cmd::RMDIR, |c| c.bytes(attr::PATH, rel_path.as_bytes()))
    }

    pub fn write_all(&mut self, rel_path: &str, data: &[u8]) -> Result<()> {
        let mut offset = 0u64;
        for chunk in data.chunks(WRITE_CHUNK_BYTES) {
            self.push_cmd(cmd::WRITE, |c| {
                c.bytes(attr::PATH, rel_path.as_bytes())?;
                c.u64(attr::FILE_OFFSET, offset);
                c.bytes(attr::DATA, chunk)
            })?;
            offset += chunk.len() as u64;
        }
        Ok(())
    }

    pub fn truncate(&mut self, rel_path: &str, size: u64) -> Result<()> {
        self.push_cmd(cmd::TRUNCATE, |c| {
            c.bytes(attr::PATH, rel_path.as_bytes())?;
            c.u64(attr::SIZE, size);
            Ok(())
        })
    }

    pub fn chown(&mut self, rel_path: &str, uid: u32, gid: u32) -> Result<()> {
        self.push_cmd(cmd::CHOWN, |c| {
            c.bytes(attr::PATH, rel_path.as_bytes())?;
            c.u64(attr::UID, u64::from(uid));
            c.u64(attr::GID, u64::from(gid));
            Ok(())
        })
    }

    pub fn chmod(&mut self, rel_path: &str, mode: u32) -> Result<()> {
        self.push_cmd(cmd::CHMOD, |c| {
            c.bytes(attr::PATH, rel_path.as_bytes())?;
            c.u64(attr::MODE, u64::from(mode & 0o7777));
            Ok(())
        })
    }

    pub fn set_xattr(&mut self, rel_path: &str, name: &[u8], value: &[u8]) -> Result<()> {
        self.push_cmd(cmd::SET_XATTR, |c| {
            c.bytes(attr::PATH, rel_path.as_bytes())?;
            c.bytes(attr::XATTR_NAME, name)?;
            c.bytes(attr::XATTR_DATA, value)
        })
    }

    pub fn utimes(&mut self, rel_path: &str, seconds: i64, nanoseconds: u32) -> Result<()> {
        let mut ts = [0u8; 12];
        ts[..8].copy_from_slice(&(seconds as u64).to_le_bytes());
        ts[8..12].copy_from_slice(&nanoseconds.min(999_999_999).to_le_bytes());
        self.push_cmd(cmd::UTIMES, |c| {
            c.bytes(attr::PATH, rel_path.as_bytes())?;
            c.bytes(attr::ATIME, &ts)?;
            c.bytes(attr::MTIME, &ts)?;
            c.bytes(attr::CTIME, &ts)
        })
    }

    /// Append `END` and return the completed send stream bytes.
    pub fn finish(mut self) -> Result<Vec<u8>> {
        self.push_cmd(cmd::END, |_| Ok(()))?;
        Ok(self.out)
    }

    fn push_cmd(
        &mut self,
        command: u16,
        build: impl FnOnce(&mut CmdEncoder) -> Result<()>,
    ) -> Result<()> {
        let mut body = CmdEncoder { buf: Vec::new() };
        build(&mut body)?;
        let len = u32::try_from(body.buf.len()).map_err(|_| OciError::SendStream {
            detail: format!("command {command} payload exceeds u32::MAX"),
        })?;
        let start = self.out.len();
        self.out.extend_from_slice(&len.to_le_bytes());
        self.out.extend_from_slice(&command.to_le_bytes());
        self.out.extend_from_slice(&0u32.to_le_bytes());
        self.out.extend_from_slice(&body.buf);
        let crc = send_stream_crc(&self.out[start..]);
        self.out[start + 6..start + 10].copy_from_slice(&crc.to_le_bytes());
        Ok(())
    }
}

struct CmdEncoder {
    buf: Vec<u8>,
}

impl CmdEncoder {
    fn bytes(&mut self, kind: u16, data: &[u8]) -> Result<()> {
        let len = u16::try_from(data.len()).map_err(|_| OciError::SendStream {
            detail: format!(
                "TLV attribute {kind} length {} exceeds u16::MAX",
                data.len()
            ),
        })?;
        self.buf.extend_from_slice(&kind.to_le_bytes());
        self.buf.extend_from_slice(&len.to_le_bytes());
        self.buf.extend_from_slice(data);
        Ok(())
    }

    fn u64(&mut self, kind: u16, value: u64) {
        self.buf.extend_from_slice(&kind.to_le_bytes());
        self.buf.extend_from_slice(&8u16.to_le_bytes());
        self.buf.extend_from_slice(&value.to_le_bytes());
    }
}

/// Encode Linux `new_encode_dev` (`mkdev`) for `MKNOD` `RDEV`.
#[must_use]
pub const fn encode_linux_dev(major: u32, minor: u32) -> u32 {
    (minor & 0xff) | (major << 8) | ((minor & !0xff) << 12)
}

#[cfg(test)]
mod tests {
    use super::*;
    use helios_btrfs::write::stream_referenced_sources;

    #[test]
    fn btrfs_send_stream_passes_helios_btrfs_crc_and_snapshot_parser() {
        let base_uuid = [0x42; 16];
        let mut builder = BtrfsSendBuilder::new_subvol("layer0", base_uuid, 10).unwrap();
        builder.mkdir("usr").unwrap();
        builder.mkdir("usr/bin").unwrap();
        builder.mkfile("usr/bin/ping").unwrap();
        builder
            .write_all("usr/bin/ping", b"#!/bin/sh\necho pong\n")
            .unwrap();
        builder.chown("usr/bin/ping", 0, 0).unwrap();
        builder.chmod("usr/bin/ping", 0o4755).unwrap();
        builder
            .set_xattr(
                "usr/bin/ping",
                b"security.capability",
                &[0x01, 0x00, 0x00, 0x02, 0x00, 0x20, 0x00, 0x00],
            )
            .unwrap();
        builder.symlink("usr/bin/ping6", "ping").unwrap();
        let base_stream = builder.finish().unwrap();

        // Real `helios-btrfs` parser verifies header, version, every TLV, every command CRC32C, and END.
        let base_refs = stream_referenced_sources(&base_stream).expect("valid base btrfs stream");
        assert!(base_refs.is_empty());

        let child_uuid = [0x99; 16];
        let mut snap = BtrfsSendBuilder::new_snapshot(
            "layer1",
            child_uuid,
            11,
            ParentSubvolumeRef {
                uuid: base_uuid,
                ctransid: 10,
            },
        )
        .unwrap();
        snap.unlink("usr/bin/ping6").unwrap();
        let snap_stream = snap.finish().unwrap();
        let snap_refs =
            stream_referenced_sources(&snap_stream).expect("valid snapshot btrfs stream");
        assert_eq!(snap_refs, vec![(base_uuid, 10)]);
    }
}
