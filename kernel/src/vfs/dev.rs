//! Container `/dev` synthetic device filesystem (`DevFs`) and UNIX98 PTY
//! registry (`/dev/ptmx` + `/dev/pts/<n>`).
//!
//! Exposes the standard Linux pseudo character devices (`null`, `zero`, `full`,
//! `random`, `urandom`, `tty`, `console`, `ptmx`), `/dev/pts/` populated live
//! from the container's [`PtyRegistry`], `/dev/shm/` (mount point for the
//! container's user-memory `MemoryFs`), and descriptor symlinks (`fd`, `stdin`,
//! `stdout`, `stderr`).
//!
//! # Concurrency contract
//!
//! [`PtyRegistry`] synchronizes allocation, lookup, and stale-entry cleanup
//! under a short synchronous `spin::Mutex`, never held across an `.await`.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::convert::Infallible;

use bytes::Bytes;
use helios_hal::fs::{
    DeviceId, DirCookie, DirEntry, DirStream, FileSystem, FsError, FsPath, FsResult, Metadata,
    NodeId, NodeKind, OpenFlags, Opened, OwnedFsPath, RenameMode, WritePosition,
};
use helios_unix::{
    CHAR_MAJOR_MEM, CHAR_MAJOR_TTY, CHAR_MAJOR_UNIX98_PTY_SLAVE, PtyMaster, PtyPair, encode_dev,
};
use triomphe::Arc;

use super::{UnixAttributes, UnixFsError, UnixNodeMetadata, delegate_path_handles};

/// Maximum concurrent UNIX98 PTY pairs in one container (`devpts`).
pub const MAX_CONTAINER_PTYS: u32 = 4096;

const INO_ROOT: u64 = 1;
const INO_NULL: u64 = 2;
const INO_ZERO: u64 = 3;
const INO_FULL: u64 = 4;
const INO_RANDOM: u64 = 5;
const INO_URANDOM: u64 = 6;
const INO_TTY: u64 = 7;
const INO_CONSOLE: u64 = 8;
const INO_PTMX: u64 = 9;
const INO_PTS_DIR: u64 = 10;
const INO_SHM_DIR: u64 = 11;
const INO_FD: u64 = 12;
const INO_STDIN: u64 = 13;
const INO_STDOUT: u64 = 14;
const INO_STDERR: u64 = 15;
const INO_PTS_BASE: u64 = 1000;

/// Per-container registry of live UNIX98 PTY pairs (`/dev/pts/<n>`).
#[derive(Clone, Default)]
pub struct PtyRegistry {
    pairs: Arc<spin::Mutex<BTreeMap<u32, PtyPair>>>,
}

impl PtyRegistry {
    pub fn new() -> Self {
        Self {
            pairs: Arc::new(spin::Mutex::new(BTreeMap::new())),
        }
    }

    /// Allocates the lowest unused PTY index in this container and returns its
    /// master descriptor.
    pub fn allocate(&self, uid: u32, gid: u32) -> FsResult<PtyMaster> {
        let mut map = self.pairs.lock();
        map.retain(|_, pair| pair.is_alive());
        let mut index = 0u32;
        while index < MAX_CONTAINER_PTYS {
            if let alloc::collections::btree_map::Entry::Vacant(slot) = map.entry(index) {
                let (master, pair) = PtyPair::create(index, uid, gid);
                slot.insert(pair);
                return Ok(master);
            }
            index += 1;
        }
        Err(FsError::NoSpace)
    }

    /// Looks up a live PTY pair by its `/dev/pts/<index>` number.
    pub fn get(&self, index: u32) -> Option<PtyPair> {
        let mut map = self.pairs.lock();
        map.retain(|_, pair| pair.is_alive());
        map.get(&index).cloned()
    }

    /// Returns sorted indices of all currently live PTY pairs.
    pub fn list_indices(&self) -> Vec<u32> {
        let mut map = self.pairs.lock();
        map.retain(|_, pair| pair.is_alive());
        map.keys().copied().collect()
    }
}

/// Synthetic `/dev` filesystem mounted inside a [`crate::LinuxContainer`].
#[derive(Clone)]
pub struct DevFs {
    device: DeviceId,
    ptys: PtyRegistry,
}

struct DevNode {
    ino: u64,
    kind: NodeKind,
    mode: u32,
    uid: u32,
    gid: u32,
    rdev: u32,
    link_target: Option<&'static str>,
}

impl DevFs {
    pub fn new(device: DeviceId, ptys: PtyRegistry) -> Self {
        Self { device, ptys }
    }

    pub fn ptys(&self) -> &PtyRegistry {
        &self.ptys
    }

    fn lookup(&self, path: FsPath<'_>) -> FsResult<DevNode> {
        let s = path.as_str();
        if s.is_empty() {
            return Ok(DevNode {
                ino: INO_ROOT,
                kind: NodeKind::Directory,
                mode: 0o755,
                uid: 0,
                gid: 0,
                rdev: 0,
                link_target: None,
            });
        }
        match s {
            "null" => Ok(DevNode {
                ino: INO_NULL,
                kind: NodeKind::CharacterDevice,
                mode: 0o666,
                uid: 0,
                gid: 0,
                rdev: encode_dev(CHAR_MAJOR_MEM, 3) as u32,
                link_target: None,
            }),
            "zero" => Ok(DevNode {
                ino: INO_ZERO,
                kind: NodeKind::CharacterDevice,
                mode: 0o666,
                uid: 0,
                gid: 0,
                rdev: encode_dev(CHAR_MAJOR_MEM, 5) as u32,
                link_target: None,
            }),
            "full" => Ok(DevNode {
                ino: INO_FULL,
                kind: NodeKind::CharacterDevice,
                mode: 0o666,
                uid: 0,
                gid: 0,
                rdev: encode_dev(CHAR_MAJOR_MEM, 7) as u32,
                link_target: None,
            }),
            "random" => Ok(DevNode {
                ino: INO_RANDOM,
                kind: NodeKind::CharacterDevice,
                mode: 0o666,
                uid: 0,
                gid: 0,
                rdev: encode_dev(CHAR_MAJOR_MEM, 8) as u32,
                link_target: None,
            }),
            "urandom" => Ok(DevNode {
                ino: INO_URANDOM,
                kind: NodeKind::CharacterDevice,
                mode: 0o666,
                uid: 0,
                gid: 0,
                rdev: encode_dev(CHAR_MAJOR_MEM, 9) as u32,
                link_target: None,
            }),
            "tty" => Ok(DevNode {
                ino: INO_TTY,
                kind: NodeKind::CharacterDevice,
                mode: 0o666,
                uid: 0,
                gid: 0,
                rdev: encode_dev(CHAR_MAJOR_TTY, 0) as u32,
                link_target: None,
            }),
            "console" => Ok(DevNode {
                ino: INO_CONSOLE,
                kind: NodeKind::CharacterDevice,
                mode: 0o600,
                uid: 0,
                gid: 0,
                rdev: encode_dev(CHAR_MAJOR_TTY, 1) as u32,
                link_target: None,
            }),
            "ptmx" => Ok(DevNode {
                ino: INO_PTMX,
                kind: NodeKind::CharacterDevice,
                mode: 0o666,
                uid: 0,
                gid: 0,
                rdev: encode_dev(CHAR_MAJOR_TTY, 2) as u32,
                link_target: None,
            }),
            "pts" => Ok(DevNode {
                ino: INO_PTS_DIR,
                kind: NodeKind::Directory,
                mode: 0o755,
                uid: 0,
                gid: 0,
                rdev: 0,
                link_target: None,
            }),
            "shm" => Ok(DevNode {
                ino: INO_SHM_DIR,
                kind: NodeKind::Directory,
                mode: 0o1777,
                uid: 0,
                gid: 0,
                rdev: 0,
                link_target: None,
            }),
            "fd" => Ok(DevNode {
                ino: INO_FD,
                kind: NodeKind::Symlink,
                mode: 0o777,
                uid: 0,
                gid: 0,
                rdev: 0,
                link_target: Some("/proc/self/fd"),
            }),
            "stdin" => Ok(DevNode {
                ino: INO_STDIN,
                kind: NodeKind::Symlink,
                mode: 0o777,
                uid: 0,
                gid: 0,
                rdev: 0,
                link_target: Some("/proc/self/fd/0"),
            }),
            "stdout" => Ok(DevNode {
                ino: INO_STDOUT,
                kind: NodeKind::Symlink,
                mode: 0o777,
                uid: 0,
                gid: 0,
                rdev: 0,
                link_target: Some("/proc/self/fd/1"),
            }),
            "stderr" => Ok(DevNode {
                ino: INO_STDERR,
                kind: NodeKind::Symlink,
                mode: 0o777,
                uid: 0,
                gid: 0,
                rdev: 0,
                link_target: Some("/proc/self/fd/2"),
            }),
            other => {
                if let Some(rest) = other.strip_prefix("pts/") {
                    if rest.contains('/') {
                        return Err(FsError::NotDirectory);
                    }
                    let index: u32 = rest.parse().map_err(|_| FsError::NoEntry)?;
                    let pair = self.ptys.get(index).ok_or(FsError::NoEntry)?;
                    let (uid, gid, mode) = pair.attrs();
                    return Ok(DevNode {
                        ino: INO_PTS_BASE + u64::from(index),
                        kind: NodeKind::CharacterDevice,
                        mode,
                        uid,
                        gid,
                        rdev: encode_dev(CHAR_MAJOR_UNIX98_PTY_SLAVE, index) as u32,
                        link_target: None,
                    });
                }
                Err(FsError::NoEntry)
            }
        }
    }

    pub fn unix_node_metadata(&self, path: FsPath<'_>) -> Result<UnixNodeMetadata, UnixFsError> {
        let node = self.lookup(path)?;
        Ok(UnixNodeMetadata {
            kind: node.kind,
            attributes: UnixAttributes {
                permissions: node.mode,
                uid: node.uid,
                gid: node.gid,
            },
            rdev: node.rdev,
        })
    }

    pub fn set_permissions(&self, path: FsPath<'_>, permissions: u32) -> Result<(), UnixFsError> {
        if let Some(rest) = path.as_str().strip_prefix("pts/")
            && let Ok(index) = rest.parse::<u32>()
            && let Some(pair) = self.ptys.get(index)
        {
            pair.set_mode(permissions);
            return Ok(());
        }
        Err(FsError::ReadOnly.into())
    }

    pub fn set_owner(
        &self,
        path: FsPath<'_>,
        uid: Option<u32>,
        gid: Option<u32>,
    ) -> Result<(), UnixFsError> {
        if let Some(rest) = path.as_str().strip_prefix("pts/")
            && let Ok(index) = rest.parse::<u32>()
            && let Some(pair) = self.ptys.get(index)
        {
            pair.set_owner(uid, gid);
            return Ok(());
        }
        Err(FsError::ReadOnly.into())
    }
    fn stat_sync(&self, path: FsPath<'_>) -> FsResult<Metadata> {
        let node = self.lookup(path)?;
        Ok(Metadata {
            id: NodeId::new(self.device, node.ino),
            kind: node.kind,
            link_count: if node.kind == NodeKind::Directory {
                2
            } else {
                1
            },
            size: node.link_target.map_or(0, |t| t.len() as u64),
            access_nanos: 0,
            modified_nanos: 0,
            status_nanos: 0,
        })
    }
}

pub struct DevDir {
    entries: Vec<(String, NodeKind, u64)>,
}

impl DirStream for DevDir {
    async fn read(&self, cookie: DirCookie, max_entries: usize) -> FsResult<Vec<DirEntry>> {
        let start = usize::try_from(cookie.raw()).unwrap_or(self.entries.len());
        if start >= self.entries.len() || max_entries == 0 {
            return Ok(Vec::new());
        }
        let end = start.saturating_add(max_entries).min(self.entries.len());
        let mut out = Vec::with_capacity(end - start);
        for (idx, (name, kind, inode)) in self.entries[start..end].iter().enumerate() {
            out.push(DirEntry {
                name: name.clone(),
                kind: *kind,
                inode: *inode,
                next: DirCookie::new((start + idx + 1) as u64),
            });
        }
        Ok(out)
    }

    async fn rewind(&mut self) -> FsResult<()> {
        Ok(())
    }
}

impl FileSystem for DevFs {
    type Payer = crate::StoragePayer;
    type Write = Infallible;
    type Dir = DevDir;

    delegate_path_handles!();

    async fn stat(&self, path: FsPath<'_>) -> FsResult<Metadata> {
        self.stat_sync(path)
    }

    async fn open(
        &self,
        path: FsPath<'_>,
        flags: OpenFlags,
        _now: u64,
        _payer: &Self::Payer,
    ) -> FsResult<Opened<OwnedFsPath>> {
        if flags.contains(OpenFlags::CREATE) || flags.contains(OpenFlags::TRUNCATE) {
            return Err(FsError::ReadOnly);
        }
        let metadata = self.stat_sync(path)?;
        if flags.contains(OpenFlags::DIRECTORY) && metadata.kind != NodeKind::Directory {
            return Err(FsError::NotDirectory);
        }
        Ok(Opened {
            metadata,
            handle: OwnedFsPath::from(path),
        })
    }

    async fn read_at(&self, path: FsPath<'_>, _offset: u64, _max_bytes: usize) -> FsResult<Bytes> {
        let node = self.lookup(path)?;
        node.kind.require_regular()?;
        Ok(Bytes::new())
    }

    async fn prepare_write<'a>(
        &'a self,
        _path: FsPath<'a>,
        _position: WritePosition,
        _len: usize,
        _now: u64,
        _payer: &'a Self::Payer,
    ) -> FsResult<Self::Write> {
        Err(FsError::ReadOnly)
    }

    async fn set_size(
        &self,
        _path: FsPath<'_>,
        _size: u64,
        _now: u64,
        _payer: &Self::Payer,
    ) -> FsResult<()> {
        Err(FsError::ReadOnly)
    }

    async fn set_times(
        &self,
        _path: FsPath<'_>,
        _access_nanos: Option<u64>,
        _modified_nanos: Option<u64>,
        _now: u64,
        _payer: &Self::Payer,
    ) -> FsResult<()> {
        Err(FsError::ReadOnly)
    }

    async fn open_dir(&self, path: FsPath<'_>) -> FsResult<Self::Dir> {
        let s = path.as_str();
        if s.is_empty() {
            return Ok(DevDir {
                entries: alloc::vec![
                    (
                        String::from("console"),
                        NodeKind::CharacterDevice,
                        INO_CONSOLE
                    ),
                    (String::from("fd"), NodeKind::Symlink, INO_FD),
                    (String::from("full"), NodeKind::CharacterDevice, INO_FULL),
                    (String::from("null"), NodeKind::CharacterDevice, INO_NULL),
                    (String::from("ptmx"), NodeKind::CharacterDevice, INO_PTMX),
                    (String::from("pts"), NodeKind::Directory, INO_PTS_DIR),
                    (
                        String::from("random"),
                        NodeKind::CharacterDevice,
                        INO_RANDOM
                    ),
                    (String::from("shm"), NodeKind::Directory, INO_SHM_DIR),
                    (String::from("stderr"), NodeKind::Symlink, INO_STDERR),
                    (String::from("stdin"), NodeKind::Symlink, INO_STDIN),
                    (String::from("stdout"), NodeKind::Symlink, INO_STDOUT),
                    (String::from("tty"), NodeKind::CharacterDevice, INO_TTY),
                    (
                        String::from("urandom"),
                        NodeKind::CharacterDevice,
                        INO_URANDOM
                    ),
                    (String::from("zero"), NodeKind::CharacterDevice, INO_ZERO),
                ],
            });
        }
        if s == "pts" {
            let entries = self
                .ptys
                .list_indices()
                .into_iter()
                .map(|idx| {
                    (
                        idx.to_string(),
                        NodeKind::CharacterDevice,
                        INO_PTS_BASE + u64::from(idx),
                    )
                })
                .collect();
            return Ok(DevDir { entries });
        }
        let node = self.lookup(path)?;
        if node.kind != NodeKind::Directory {
            return Err(FsError::NotDirectory);
        }
        Ok(DevDir {
            entries: Vec::new(),
        })
    }

    async fn create_directory(
        &self,
        _path: FsPath<'_>,
        _now: u64,
        _payer: &Self::Payer,
    ) -> FsResult<()> {
        Err(FsError::ReadOnly)
    }

    async fn remove_directory(
        &self,
        _path: FsPath<'_>,
        _now: u64,
        _payer: &Self::Payer,
    ) -> FsResult<()> {
        Err(FsError::ReadOnly)
    }

    async fn unlink(&self, _path: FsPath<'_>, _now: u64, _payer: &Self::Payer) -> FsResult<()> {
        Err(FsError::ReadOnly)
    }

    async fn rename(
        &self,
        _source: FsPath<'_>,
        _destination: FsPath<'_>,
        _mode: RenameMode,
        _now: u64,
        _payer: &Self::Payer,
    ) -> FsResult<()> {
        Err(FsError::ReadOnly)
    }

    async fn link(
        &self,
        _existing: FsPath<'_>,
        _link: FsPath<'_>,
        _now: u64,
        _payer: &Self::Payer,
    ) -> FsResult<()> {
        Err(FsError::ReadOnly)
    }

    async fn symlink(
        &self,
        _target: &str,
        _link: FsPath<'_>,
        _now: u64,
        _payer: &Self::Payer,
    ) -> FsResult<()> {
        Err(FsError::ReadOnly)
    }

    async fn read_link(&self, path: FsPath<'_>) -> FsResult<String> {
        let node = self.lookup(path)?;
        node.link_target.map(String::from).ok_or(FsError::Invalid)
    }

    async fn sync(&self, _path: FsPath<'_>) -> FsResult<()> {
        Ok(())
    }

    async fn sync_data(&self, _path: FsPath<'_>) -> FsResult<()> {
        Ok(())
    }
}
