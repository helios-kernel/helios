//! Linux-compatible btrfs send stream (v1) encoder, following `fs/btrfs/send.h`
//! and `fs/btrfs/send.c`.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec;
use alloc::vec::Vec;
use core::ops::ControlFlow;

use crate::csum::send_stream_crc;
use crate::fs::Filesystem;
use crate::items::{EntryTarget, ExtentData, FileExtent};
use crate::ondisk::{RawTimespec, item_type};
use crate::source::BlockSource;
use crate::transaction::Transaction;
use crate::tree::Cursor;
use crate::tree::write::WriteError;
use crate::{Error, FileKind, Key, Metadata, Timestamp};

/// Stream header magic (`BTRFS_SEND_STREAM_MAGIC`).
pub(crate) const STREAM_MAGIC: &[u8; 13] = b"btrfs-stream\0";
/// Stream protocol version 1 (`BTRFS_SEND_STREAM_VERSION`).
pub(crate) const STREAM_VERSION_1: u32 = 1;
/// Maximum payload bytes per `WRITE` command (48 KiB, matching Linux's
/// `BTRFS_SEND_READ_SIZE` so every TLV length fits comfortably in `u16`).
const WRITE_CHUNK_BYTES: usize = 48 * 1024;

/// Command codes (`enum btrfs_send_cmd` in `fs/btrfs/send.h`).
pub(crate) mod cmd {
    pub(crate) const SUBVOL: u16 = 1;
    pub(crate) const SNAPSHOT: u16 = 2;
    pub(crate) const MKFILE: u16 = 3;
    pub(crate) const MKDIR: u16 = 4;
    pub(crate) const MKNOD: u16 = 5;
    pub(crate) const MKFIFO: u16 = 6;
    pub(crate) const MKSOCK: u16 = 7;
    pub(crate) const SYMLINK: u16 = 8;
    pub(crate) const RENAME: u16 = 9;
    pub(crate) const LINK: u16 = 10;
    pub(crate) const UNLINK: u16 = 11;
    pub(crate) const RMDIR: u16 = 12;
    pub(crate) const SET_XATTR: u16 = 13;
    pub(crate) const REMOVE_XATTR: u16 = 14;
    pub(crate) const WRITE: u16 = 15;
    pub(crate) const CLONE: u16 = 16;
    pub(crate) const TRUNCATE: u16 = 17;
    pub(crate) const CHMOD: u16 = 18;
    pub(crate) const CHOWN: u16 = 19;
    pub(crate) const UTIMES: u16 = 20;
    pub(crate) const END: u16 = 21;
    pub(crate) const UPDATE_EXTENT: u16 = 22;
}

/// Attribute codes (`enum btrfs_send_attr` in `fs/btrfs/send.h`).
pub(crate) mod attr {
    pub(crate) const UUID: u16 = 1;
    pub(crate) const CTRANSID: u16 = 2;
    pub(crate) const INO: u16 = 3;
    pub(crate) const SIZE: u16 = 4;
    pub(crate) const MODE: u16 = 5;
    pub(crate) const UID: u16 = 6;
    pub(crate) const GID: u16 = 7;
    pub(crate) const RDEV: u16 = 8;
    pub(crate) const CTIME: u16 = 9;
    pub(crate) const MTIME: u16 = 10;
    pub(crate) const ATIME: u16 = 11;
    pub(crate) const XATTR_NAME: u16 = 13;
    pub(crate) const XATTR_DATA: u16 = 14;
    pub(crate) const PATH: u16 = 15;
    pub(crate) const PATH_TO: u16 = 16;
    pub(crate) const PATH_LINK: u16 = 17;
    pub(crate) const FILE_OFFSET: u16 = 18;
    pub(crate) const DATA: u16 = 19;
    pub(crate) const CLONE_UUID: u16 = 20;
    pub(crate) const CLONE_CTRANSID: u16 = 21;
    pub(crate) const CLONE_PATH: u16 = 22;
    pub(crate) const CLONE_OFFSET: u16 = 23;
    pub(crate) const CLONE_LEN: u16 = 24;
}

/// Helper for encoding framed, CRC32C-verified btrfs send commands.
struct StreamEncoder {
    out: Vec<u8>,
}

impl StreamEncoder {
    fn new() -> Self {
        let mut out = Vec::with_capacity(4096);
        out.extend_from_slice(STREAM_MAGIC);
        out.extend_from_slice(&STREAM_VERSION_1.to_le_bytes());
        Self { out }
    }

    fn push_cmd(&mut self, command: u16, build: impl FnOnce(&mut CmdEncoder)) {
        let mut body = CmdEncoder { buf: Vec::new() };
        build(&mut body);
        let len = body.buf.len() as u32;
        let start = self.out.len();
        self.out.extend_from_slice(&len.to_le_bytes());
        self.out.extend_from_slice(&command.to_le_bytes());
        self.out.extend_from_slice(&0_u32.to_le_bytes()); // CRC placeholder
        self.out.extend_from_slice(&body.buf);
        let crc = send_stream_crc(&self.out[start..]);
        self.out[start + 6..start + 10].copy_from_slice(&crc.to_le_bytes());
    }

    fn finish(mut self) -> Vec<u8> {
        self.push_cmd(cmd::END, |_| {});
        self.out
    }
}

struct CmdEncoder {
    buf: Vec<u8>,
}

impl CmdEncoder {
    fn bytes(&mut self, kind: u16, data: &[u8]) {
        debug_assert!(data.len() <= usize::from(u16::MAX));
        self.buf.extend_from_slice(&kind.to_le_bytes());
        self.buf
            .extend_from_slice(&(data.len() as u16).to_le_bytes());
        self.buf.extend_from_slice(data);
    }

    fn u64(&mut self, kind: u16, value: u64) {
        self.bytes(kind, &value.to_le_bytes());
    }

    fn timespec(&mut self, kind: u16, ts: Timestamp) {
        let raw = RawTimespec {
            sec: (ts.seconds as u64).into(),
            nsec: ts.nanoseconds.into(),
        };
        let mut bytes = [0_u8; 12];
        bytes[..8].copy_from_slice(&raw.sec.get().to_le_bytes());
        bytes[8..12].copy_from_slice(&raw.nsec.get().to_le_bytes());
        self.bytes(kind, &bytes);
    }
}

/// Complete materialized view of one subvolume's namespace and inodes for send.
struct SubvolSnapshot {
    root_dirid: u64,
    inodes: BTreeMap<u64, InodeSnap>,
    /// All relative paths (e.g. `""`, `"a"`, `"a/b"`) -> inode number.
    paths: BTreeMap<Vec<u8>, u64>,
    /// Per inode: sorted list of relative paths linking to it.
    inode_paths: BTreeMap<u64, Vec<Vec<u8>>>,
}

#[derive(Clone)]
struct InodeSnap {
    metadata: Metadata,
    symlink_target: Option<Vec<u8>>,
    xattrs: BTreeMap<Vec<u8>, Vec<u8>>,
    /// Non-hole data ranges `(offset, len, disk_bytenr, disk_offset)` for
    /// regular files so we skip holes and can emit `CLONE` when matching
    /// extents exist in parent or clone sources.
    extents: Vec<FileExtentSpan>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct FileExtentSpan {
    file_offset: u64,
    length: u64,
    /// `(disk_bytenr, disk_offset)` for regular extents, or `None` for inline.
    disk: Option<(u64, u64)>,
}

/// Index mapping `(disk_bytenr, disk_offset, length)` -> `(clone_uuid, clone_ctransid, path, file_offset)`.
type CloneIndex = BTreeMap<(u64, u64), Vec<([u8; 16], u64, Vec<u8>, u64, u64)>>;

/// Collects a full snapshot of `tree` from `fs` (an immutable view).
async fn collect_subvolume<S: BlockSource>(
    fs: &Filesystem<S>,
    tree: u64,
) -> Result<SubvolSnapshot, WriteError> {
    let root = fs.subvolume_root(tree).await?;
    let root_dirid = root.number();
    let mut inodes = BTreeMap::new();
    let mut paths = BTreeMap::new();
    let mut inode_paths: BTreeMap<u64, Vec<Vec<u8>>> = BTreeMap::new();

    // BFS from root directory so parent paths are always discovered before children.
    let mut queue = alloc::collections::VecDeque::new();
    paths.insert(Vec::new(), root_dirid);
    inode_paths.entry(root_dirid).or_default().push(Vec::new());
    queue.push_back((Vec::new(), root));

    let sector = fs.superblock().sectorsize();

    while let Some((rel_path, inode)) = queue.pop_front() {
        let ino = inode.number();
        let meta = *inode.metadata();
        let first_visit = !inodes.contains_key(&ino);
        if first_visit {
            let symlink_target = if meta.kind == FileKind::Symlink {
                let mut buf = vec![0_u8; (meta.size as usize).min(4096)];
                let n = fs.read_link(&inode, &mut buf).await?;
                buf.truncate(n);
                Some(buf)
            } else {
                None
            };
            let mut xattr_names = Vec::new();
            fs.list_xattrs(&inode, |name| {
                xattr_names.push(name.to_vec());
                ControlFlow::Continue(())
            })
            .await?;
            let mut xattrs = BTreeMap::new();
            for name in xattr_names {
                let mut val = vec![0_u8; 65536];
                if let Some(n) = fs.xattr(&inode, &name, &mut val).await? {
                    val.truncate(n);
                    xattrs.insert(name, val);
                }
            }
            let extents = if meta.kind == FileKind::Regular {
                collect_file_extents(fs, tree, ino, sector).await?
            } else {
                Vec::new()
            };
            inodes.insert(
                ino,
                InodeSnap {
                    metadata: meta,
                    symlink_target,
                    xattrs,
                    extents,
                },
            );
        }

        if meta.kind == FileKind::Directory && first_visit {
            let mut entries = Vec::new();
            fs.read_dir(
                &inode,
                crate::DirPosition::START,
                crate::DirBound::UNBOUNDED,
                |entry| {
                    entries.push((entry.name.to_vec(), entry.target));
                    ControlFlow::Continue(())
                },
            )
            .await?;
            for (name, target) in entries {
                // Nested subvolumes are separate roots and not traversed by
                // btrfs send (Linux omits nested subvolume contents and
                // represents a nested subvolume mountpoint as an empty dir, or
                // skips its tree).
                let EntryTarget::Inode(child_ino) = target else {
                    continue;
                };
                let mut child_path = rel_path.clone();
                if !child_path.is_empty() {
                    child_path.push(b'/');
                }
                child_path.extend_from_slice(&name);
                paths.insert(child_path.clone(), child_ino);
                inode_paths
                    .entry(child_ino)
                    .or_default()
                    .push(child_path.clone());
                let child = fs.inode(tree, child_ino).await?;
                queue.push_back((child_path, child));
            }
        }
    }

    for list in inode_paths.values_mut() {
        list.sort();
    }

    Ok(SubvolSnapshot {
        root_dirid,
        inodes,
        paths,
        inode_paths,
    })
}

async fn collect_file_extents<S: BlockSource>(
    fs: &Filesystem<S>,
    tree: u64,
    inode: u64,
    sector: u32,
) -> Result<Vec<FileExtentSpan>, WriteError> {
    let mut spans = Vec::new();
    let (volume, nodes, root) = fs.subvolume_tree_reader(tree).await?;
    let start = Key::new(inode, item_type::EXTENT_DATA, 0);
    let mut cursor = Cursor::ceiling(&nodes, root, start).await?;
    while let (Some(key), Some(bytes)) = (cursor.key(), cursor.item()) {
        if !key.is(inode, item_type::EXTENT_DATA) {
            break;
        }
        let extent = FileExtent::parse(key, bytes, sector).map_err(|defect| Error::Item {
            tree,
            key,
            defect,
        })?;
        let length = extent.end.saturating_sub(extent.start);
        if length > 0 {
            match extent.data {
                ExtentData::Inline { .. } => spans.push(FileExtentSpan {
                    file_offset: extent.start,
                    length,
                    disk: None,
                }),
                ExtentData::Regular {
                    disk_bytenr,
                    offset,
                    ..
                } => spans.push(FileExtentSpan {
                    file_offset: extent.start,
                    length,
                    disk: Some((disk_bytenr, offset)),
                }),
                ExtentData::Zero => {}
            }
        }
        cursor.advance(&nodes).await?;
    }
    let _ = volume;
    Ok(spans)
}

fn index_clone_sources(
    index: &mut CloneIndex,
    snap: &SubvolSnapshot,
    uuid: [u8; 16],
    ctransid: u64,
) {
    for (&ino, info) in &snap.inodes {
        if info.metadata.kind != FileKind::Regular {
            continue;
        }
        let Some(first_path) = snap.inode_paths.get(&ino).and_then(|v| v.first()) else {
            continue;
        };
        for span in &info.extents {
            if let Some((disk_bytenr, disk_offset)) = span.disk {
                index.entry((disk_bytenr, disk_offset)).or_default().push((
                    uuid,
                    ctransid,
                    first_path.clone(),
                    span.file_offset,
                    span.length,
                ));
            }
        }
    }
}

fn emit_create_inode(enc: &mut StreamEncoder, path: &[u8], ino: u64, snap: &InodeSnap) {
    match snap.metadata.kind {
        FileKind::Directory => enc.push_cmd(cmd::MKDIR, |c| {
            c.bytes(attr::PATH, path);
            c.u64(attr::INO, ino);
        }),
        FileKind::Regular => enc.push_cmd(cmd::MKFILE, |c| {
            c.bytes(attr::PATH, path);
            c.u64(attr::INO, ino);
        }),
        FileKind::Symlink => {
            let target = snap.symlink_target.as_deref().unwrap_or(b"");
            enc.push_cmd(cmd::SYMLINK, |c| {
                c.bytes(attr::PATH, path);
                c.u64(attr::INO, ino);
                c.bytes(attr::PATH_LINK, target);
            });
        }
        FileKind::CharDevice => enc.push_cmd(cmd::MKNOD, |c| {
            c.bytes(attr::PATH, path);
            c.u64(attr::INO, ino);
            c.u64(attr::RDEV, u64::from(snap.metadata.rdev.encode()));
            c.u64(attr::MODE, u64::from(0o020_000 | snap.metadata.permissions));
        }),
        FileKind::BlockDevice => enc.push_cmd(cmd::MKNOD, |c| {
            c.bytes(attr::PATH, path);
            c.u64(attr::INO, ino);
            c.u64(attr::RDEV, u64::from(snap.metadata.rdev.encode()));
            c.u64(attr::MODE, u64::from(0o060_000 | snap.metadata.permissions));
        }),
        FileKind::Fifo => enc.push_cmd(cmd::MKFIFO, |c| {
            c.bytes(attr::PATH, path);
            c.u64(attr::INO, ino);
        }),
        FileKind::Socket => enc.push_cmd(cmd::MKSOCK, |c| {
            c.bytes(attr::PATH, path);
            c.u64(attr::INO, ino);
        }),
    }
}

async fn emit_file_data<S: BlockSource>(
    enc: &mut StreamEncoder,
    fs: &Filesystem<S>,
    tree: u64,
    ino: u64,
    path: &[u8],
    snap: &InodeSnap,
    clone_index: &CloneIndex,
) -> Result<(), WriteError> {
    let file = fs.inode(tree, ino).await?;
    let size = snap.metadata.size;
    let sector = u64::from(fs.superblock().sectorsize());
    let mut buf = vec![0_u8; WRITE_CHUNK_BYTES];

    for span in &snap.extents {
        let start = span.file_offset;
        if start >= size {
            continue;
        }
        let end = (start + span.length).min(size);
        let len = end - start;
        if len == 0 {
            continue;
        }
        // Emit `CLONE` if an aligned identical extent exists in a clone source
        // (matching sector alignment rules of Linux `btrfs receive`).
        if let Some((disk_bytenr, disk_offset)) = span.disk
            && start.is_multiple_of(sector)
            && (len.is_multiple_of(sector) || end == size)
            && let Some(candidates) = clone_index.get(&(disk_bytenr, disk_offset))
            && let Some((clone_uuid, clone_ctransid, clone_path, clone_offset, _clone_avail)) =
                candidates
                    .iter()
                    .find(|(_, _, _, co, ca)| co.is_multiple_of(sector) && *ca >= len)
        {
            enc.push_cmd(cmd::CLONE, |c| {
                c.u64(attr::FILE_OFFSET, start);
                c.u64(attr::CLONE_LEN, len);
                c.bytes(attr::PATH, path);
                c.bytes(attr::CLONE_UUID, clone_uuid);
                c.u64(attr::CLONE_CTRANSID, *clone_ctransid);
                c.bytes(attr::CLONE_PATH, clone_path);
                c.u64(attr::CLONE_OFFSET, *clone_offset);
            });
            continue;
        }

        let mut at = start;
        while at < end {
            let chunk = ((end - at) as usize).min(buf.len());
            let n = fs.read(&file, at, &mut buf[..chunk]).await?;
            if n == 0 {
                break;
            }
            let offset_now = at;
            let slice = &buf[..n];
            enc.push_cmd(cmd::WRITE, |c| {
                c.bytes(attr::PATH, path);
                c.u64(attr::FILE_OFFSET, offset_now);
                c.bytes(attr::DATA, slice);
            });
            at += n as u64;
        }
    }

    enc.push_cmd(cmd::TRUNCATE, |c| {
        c.bytes(attr::PATH, path);
        c.u64(attr::SIZE, size);
    });
    Ok(())
}

fn emit_metadata(enc: &mut StreamEncoder, path: &[u8], snap: &InodeSnap, prev: Option<&InodeSnap>) {
    // 1. Ownership (`CHOWN` MUST precede `CHMOD` and `SET_XATTR` so setuid,
    //    setgid, and `security.capability` are preserved by Linux `btrfs receive`).
    let owner_changed = prev
        .is_none_or(|p| p.metadata.uid != snap.metadata.uid || p.metadata.gid != snap.metadata.gid);
    if owner_changed {
        enc.push_cmd(cmd::CHOWN, |c| {
            c.bytes(attr::PATH, path);
            c.u64(attr::UID, u64::from(snap.metadata.uid));
            c.u64(attr::GID, u64::from(snap.metadata.gid));
        });
    }

    // 2. Mode (`CHMOD` is never emitted for symlinks).
    if snap.metadata.kind != FileKind::Symlink {
        let mode_changed = prev.is_none_or(|p| p.metadata.permissions != snap.metadata.permissions)
            || owner_changed;
        if mode_changed {
            enc.push_cmd(cmd::CHMOD, |c| {
                c.bytes(attr::PATH, path);
                c.u64(attr::MODE, u64::from(snap.metadata.permissions));
            });
        }
    }

    // 3. Xattrs (remove obsolete ones first, then set new/changed ones;
    //    emitted after `CHOWN`/`CHMOD` so capabilities and POSIX ACLs stick).
    if let Some(prev) = prev {
        for name in prev.xattrs.keys() {
            if !snap.xattrs.contains_key(name) {
                enc.push_cmd(cmd::REMOVE_XATTR, |c| {
                    c.bytes(attr::PATH, path);
                    c.bytes(attr::XATTR_NAME, name);
                });
            }
        }
    }
    for (name, val) in &snap.xattrs {
        if prev.and_then(|p| p.xattrs.get(name)) != Some(val) {
            enc.push_cmd(cmd::SET_XATTR, |c| {
                c.bytes(attr::PATH, path);
                c.bytes(attr::XATTR_NAME, name);
                c.bytes(attr::XATTR_DATA, val);
            });
        }
    }

    // 4. Timestamps.
    enc.push_cmd(cmd::UTIMES, |c| {
        c.bytes(attr::PATH, path);
        c.timespec(attr::ATIME, snap.metadata.atime);
        c.timespec(attr::MTIME, snap.metadata.mtime);
        c.timespec(attr::CTIME, snap.metadata.ctime);
    });
}

fn path_depth(path: &[u8]) -> usize {
    if path.is_empty() {
        0
    } else {
        path.iter().filter(|&&b| b == b'/').count() + 1
    }
}

/// Produces a Linux-compatible btrfs send stream (v1) for read-only subvolume
/// `tree`, optionally incremental against `parent_tree` and cloning matching
/// extents from `clone_trees`.
pub(crate) async fn send_subvolume<S: BlockSource>(
    fs: &Filesystem<S>,
    tx_roots: &crate::roots::Roots,
    subvol_name: &[u8],
    tree: u64,
    parent_tree: Option<u64>,
    clone_trees: &[u64],
) -> Result<Vec<u8>, WriteError> {
    let meta = tx_roots.subvolume_meta(tree)?;
    if !meta.read_only {
        return Err(WriteError::SubvolumeNotReadOnly { tree });
    }
    let parent_meta = match parent_tree {
        Some(p) => {
            let pm = tx_roots.subvolume_meta(p)?;
            if !pm.read_only {
                return Err(WriteError::SubvolumeNotReadOnly { tree: p });
            }
            Some(pm)
        }
        None => None,
    };

    let target = collect_subvolume(fs, tree).await?;
    let mut clone_index = CloneIndex::new();
    for &ct in clone_trees {
        let cm = tx_roots.subvolume_meta(ct)?;
        if !cm.read_only {
            return Err(WriteError::SubvolumeNotReadOnly { tree: ct });
        }
        let csnap = collect_subvolume(fs, ct).await?;
        index_clone_sources(&mut clone_index, &csnap, cm.uuid, cm.ctransid);
    }

    let mut enc = StreamEncoder::new();
    let stream_name = if subvol_name.is_empty() {
        b"subvol".as_slice()
    } else {
        subvol_name
    };

    if let Some(pm) = parent_meta {
        let parent_snap = collect_subvolume(fs, pm.id).await?;
        index_clone_sources(&mut clone_index, &parent_snap, pm.uuid, pm.ctransid);
        enc.push_cmd(cmd::SNAPSHOT, |c| {
            c.bytes(attr::PATH, stream_name);
            c.bytes(attr::UUID, &meta.uuid);
            c.u64(attr::CTRANSID, meta.ctransid);
            c.bytes(attr::CLONE_UUID, &pm.uuid);
            c.u64(attr::CLONE_CTRANSID, pm.ctransid);
        });
        emit_incremental(&mut enc, fs, tree, &parent_snap, &target, &clone_index).await?;
    } else {
        enc.push_cmd(cmd::SUBVOL, |c| {
            c.bytes(attr::PATH, stream_name);
            c.bytes(attr::UUID, &meta.uuid);
            c.u64(attr::CTRANSID, meta.ctransid);
        });
        emit_full(&mut enc, fs, tree, &target, &clone_index).await?;
    }

    Ok(enc.finish())
}

async fn emit_full<S: BlockSource>(
    enc: &mut StreamEncoder,
    fs: &Filesystem<S>,
    tree: u64,
    snap: &SubvolSnapshot,
    clone_index: &CloneIndex,
) -> Result<(), WriteError> {
    // 1. Create all directories top-down (excluding root `""`).
    let mut dirs: Vec<(&[u8], u64)> = snap
        .paths
        .iter()
        .filter(|(p, ino)| !p.is_empty() && snap.inodes[*ino].metadata.kind == FileKind::Directory)
        .map(|(p, &ino)| (p.as_slice(), ino))
        .collect();
    dirs.sort_by_key(|(p, _)| (path_depth(p), *p));
    for &(path, ino) in &dirs {
        emit_create_inode(enc, path, ino, &snap.inodes[&ino]);
    }

    // 2. Create all non-directory inodes and their hardlinks, data, and metadata.
    let mut created = BTreeSet::new();
    let mut non_dirs: Vec<(&[u8], u64)> = snap
        .paths
        .iter()
        .filter(|(p, ino)| !p.is_empty() && snap.inodes[*ino].metadata.kind != FileKind::Directory)
        .map(|(p, &ino)| (p.as_slice(), ino))
        .collect();
    non_dirs.sort_by_key(|(p, _)| (path_depth(p), *p));

    for (path, ino) in non_dirs {
        let info = &snap.inodes[&ino];
        if created.insert(ino) {
            emit_create_inode(enc, path, ino, info);
            if info.metadata.kind == FileKind::Regular {
                emit_file_data(enc, fs, tree, ino, path, info, clone_index).await?;
            }
            emit_metadata(enc, path, info, None);
        } else {
            // Additional hardlink to an already-created inode.
            let primary = &snap.inode_paths[&ino][0];
            enc.push_cmd(cmd::LINK, |c| {
                c.bytes(attr::PATH, path);
                c.bytes(attr::PATH_LINK, primary);
            });
        }
    }

    // 3. Apply metadata to all directories bottom-up, ending with root `""` so
    //    creating children never overwrites a directory's recorded mtime.
    dirs.sort_by(|(a, _), (b, _)| path_depth(b).cmp(&path_depth(a)).then_with(|| a.cmp(b)));
    for (path, ino) in dirs {
        emit_metadata(enc, path, &snap.inodes[&ino], None);
    }
    emit_metadata(enc, b"", &snap.inodes[&snap.root_dirid], None);
    Ok(())
}

async fn emit_incremental<S: BlockSource>(
    enc: &mut StreamEncoder,
    fs: &Filesystem<S>,
    tree: u64,
    parent: &SubvolSnapshot,
    target: &SubvolSnapshot,
    clone_index: &CloneIndex,
) -> Result<(), WriteError> {
    // Determine which paths from `parent` must be removed before creating or
    // updating `target` paths:
    // - any path in `parent` absent in `target`, OR
    // - any path whose kind changed (e.g. file replaced by dir) or whose inode
    //   was replaced (different generation / different inode number with same
    //   path).
    let mut keep_paths: BTreeSet<&[u8]> = BTreeSet::new();
    let mut remove_non_dirs: Vec<&[u8]> = Vec::new();
    let mut remove_dirs: Vec<&[u8]> = Vec::new();

    for (path, &p_ino) in &parent.paths {
        if path.is_empty() {
            keep_paths.insert(path.as_slice());
            continue;
        }
        let p_info = &parent.inodes[&p_ino];
        let same_node = target.paths.get(path).is_some_and(|&t_ino| {
            let t_info = &target.inodes[&t_ino];
            t_ino == p_ino
                && t_info.metadata.kind == p_info.metadata.kind
                && t_info.metadata.generation == p_info.metadata.generation
                && (t_info.metadata.kind != FileKind::Symlink
                    || t_info.symlink_target == p_info.symlink_target)
                && (!matches!(
                    t_info.metadata.kind,
                    FileKind::CharDevice | FileKind::BlockDevice
                ) || t_info.metadata.rdev == p_info.metadata.rdev)
        });
        if same_node {
            keep_paths.insert(path.as_slice());
        } else if p_info.metadata.kind == FileKind::Directory {
            remove_dirs.push(path.as_slice());
        } else {
            remove_non_dirs.push(path.as_slice());
        }
    }

    // 1. Unlink removed non-directories first, then rmdir removed directories
    //    bottom-up.
    remove_non_dirs.sort_by(|a, b| path_depth(b).cmp(&path_depth(a)).then_with(|| a.cmp(b)));
    for path in remove_non_dirs {
        enc.push_cmd(cmd::UNLINK, |c| {
            c.bytes(attr::PATH, path);
        });
    }
    remove_dirs.sort_by(|a, b| path_depth(b).cmp(&path_depth(a)).then_with(|| a.cmp(b)));
    for path in remove_dirs {
        enc.push_cmd(cmd::RMDIR, |c| {
            c.bytes(attr::PATH, path);
        });
    }

    // 2. Create newly added directories top-down.
    let mut all_dirs: Vec<(&[u8], u64)> = target
        .paths
        .iter()
        .filter(|(p, ino)| {
            !p.is_empty() && target.inodes[*ino].metadata.kind == FileKind::Directory
        })
        .map(|(p, &ino)| (p.as_slice(), ino))
        .collect();
    all_dirs.sort_by_key(|(p, _)| (path_depth(p), *p));
    for &(path, ino) in &all_dirs {
        if !keep_paths.contains(path) {
            emit_create_inode(enc, path, ino, &target.inodes[&ino]);
        }
    }

    // 3. Create / update / link non-directories.
    let mut handled_inodes = BTreeSet::new();
    // Pre-mark inodes that already have at least one surviving path from parent
    // and record their surviving primary path for any new hardlinks.
    let mut existing_primary: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
    for (path, &ino) in &target.paths {
        if !path.is_empty()
            && keep_paths.contains(path.as_slice())
            && target.inodes[&ino].metadata.kind != FileKind::Directory
        {
            existing_primary.entry(ino).or_insert_with(|| path.clone());
        }
    }

    let mut non_dirs: Vec<(&[u8], u64)> = target
        .paths
        .iter()
        .filter(|(p, ino)| {
            !p.is_empty() && target.inodes[*ino].metadata.kind != FileKind::Directory
        })
        .map(|(p, &ino)| (p.as_slice(), ino))
        .collect();
    non_dirs.sort_by_key(|(p, _)| (path_depth(p), *p));

    for (path, ino) in non_dirs {
        let info = &target.inodes[&ino];
        if keep_paths.contains(path) {
            if handled_inodes.insert(ino) {
                let prev = &parent.inodes[&ino];
                if info.metadata.kind == FileKind::Regular
                    && (info.metadata.size != prev.metadata.size
                        || info.extents != prev.extents
                        || info.metadata.mtime != prev.metadata.mtime)
                {
                    // Truncate to 0 and rewrite / clone extents cleanly so
                    // holes and shrunk ranges match identically.
                    enc.push_cmd(cmd::TRUNCATE, |c| {
                        c.bytes(attr::PATH, path);
                        c.u64(attr::SIZE, 0);
                    });
                    emit_file_data(enc, fs, tree, ino, path, info, clone_index).await?;
                }
                emit_metadata(enc, path, info, Some(prev));
            }
        } else if let Some(primary) = existing_primary.get(&ino) {
            enc.push_cmd(cmd::LINK, |c| {
                c.bytes(attr::PATH, path);
                c.bytes(attr::PATH_LINK, primary);
            });
        } else if handled_inodes.insert(ino) {
            emit_create_inode(enc, path, ino, info);
            if info.metadata.kind == FileKind::Regular {
                emit_file_data(enc, fs, tree, ino, path, info, clone_index).await?;
            }
            emit_metadata(enc, path, info, None);
            existing_primary.insert(ino, path.to_vec());
        } else {
            let primary = &existing_primary[&ino];
            enc.push_cmd(cmd::LINK, |c| {
                c.bytes(attr::PATH, path);
                c.bytes(attr::PATH_LINK, primary);
            });
        }
    }

    // 4. Update all directory metadata bottom-up, ending with root `""`.
    all_dirs.sort_by(|(a, _), (b, _)| path_depth(b).cmp(&path_depth(a)).then_with(|| a.cmp(b)));
    for (path, ino) in all_dirs {
        let prev = keep_paths
            .contains(path)
            .then(|| parent.inodes.get(&ino))
            .flatten();
        emit_metadata(enc, path, &target.inodes[&ino], prev);
    }
    emit_metadata(
        enc,
        b"",
        &target.inodes[&target.root_dirid],
        parent.inodes.get(&parent.root_dirid),
    );
    Ok(())
}

/// Ensures `Transaction` import is kept clean if send helpers ever inspect tx state.
const _: fn(&Transaction<()>) = |_| {};
