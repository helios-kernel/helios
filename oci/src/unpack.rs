//! OCI tar layer unpacker with `.wh.*` / `.wh..wh..opq` whiteouts, Unix metadata,
//! PAX `SCHILY.xattr.*` capability preservation, and btrfs send stream generation.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use tar::{Archive, EntryType};

use crate::btrfs_send::{BtrfsSendBuilder, ParentSubvolumeRef, encode_linux_dev};
use crate::error::{OciError, Result};
use crate::reference::Digest;

const WHITEOUT_PREFIX: &str = ".wh.";
const OPAQUE_WHITEOUT: &str = ".wh..wh..opq";
const PAX_XATTR_PREFIX: &str = "SCHILY.xattr.";

/// Filesystem node kind recorded in [`LayerMetadataIndex`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NodeKind {
    File,
    Directory,
    Symlink,
    HardLink,
    Fifo,
    CharDevice,
    BlockDevice,
}

/// Complete Unix metadata captured from an OCI tar entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryUnixMetadata {
    pub kind: NodeKind,
    pub uid: u32,
    pub gid: u32,
    /// Full 12-bit Unix mode including setuid (`0o4000`), setgid (`0o2000`), and sticky (`0o1000`).
    pub mode: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtime: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link_target: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_major: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_minor: Option<u32>,
    /// Extended attributes parsed from PAX `SCHILY.xattr.<name>` (e.g. `security.capability`).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub xattrs: BTreeMap<String, Vec<u8>>,
}

/// Persisted metadata ledger for one materialized OCI layer (`chain-id`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LayerMetadataIndex {
    pub chain_id: Digest,
    pub diff_id: Digest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_chain_id: Option<Digest>,
    pub btrfs_backed: bool,
    /// Resulting effective entry metadata table (merged over parent with whiteouts applied).
    #[serde(default)]
    pub entries: BTreeMap<String, EntryUnixMetadata>,
}

/// Normalize a tar entry path into a relative slash-separated string with no `..` traversal.
///
/// Returns `Ok(None)` for the root directory entry itself (`"."` or `"/"` or `""`).
pub fn sanitize_tar_path(raw: &Path, digest: &str) -> Result<Option<String>> {
    let mut parts = Vec::new();
    for component in raw.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(seg) => {
                let s = seg.to_str().ok_or_else(|| OciError::UnsafePath {
                    digest: digest.to_owned(),
                    path: raw.display().to_string(),
                    reason: "non-UTF-8 path component",
                })?;
                if s.contains('\0') {
                    return Err(OciError::UnsafePath {
                        digest: digest.to_owned(),
                        path: raw.display().to_string(),
                        reason: "path contains NUL byte",
                    });
                }
                parts.push(s);
            }
            Component::ParentDir => {
                return Err(OciError::UnsafePath {
                    digest: digest.to_owned(),
                    path: raw.display().to_string(),
                    reason: "path escapes layer root via `..`",
                });
            }
            Component::Prefix(_) => {
                return Err(OciError::UnsafePath {
                    digest: digest.to_owned(),
                    path: raw.display().to_string(),
                    reason: "path contains platform prefix",
                });
            }
        }
    }
    if parts.is_empty() {
        Ok(None)
    } else {
        Ok(Some(parts.join("/")))
    }
}

fn parse_pax_metadata<R: Read>(
    entry: &mut tar::Entry<'_, R>,
) -> (Option<u32>, Option<u32>, BTreeMap<String, Vec<u8>>) {
    let mut pax_uid = None;
    let mut pax_gid = None;
    let mut xattrs = BTreeMap::new();
    if let Ok(Some(exts)) = entry.pax_extensions() {
        for ext in exts.flatten() {
            if let Ok(key) = ext.key() {
                if let Some(xattr_name) = key.strip_prefix(PAX_XATTR_PREFIX) {
                    xattrs.insert(xattr_name.to_owned(), ext.value_bytes().to_vec());
                } else if key == "uid" {
                    if let Ok(s) = ext.value()
                        && let Ok(v) = s.parse::<u32>()
                    {
                        pax_uid = Some(v);
                    }
                } else if key == "gid"
                    && let Ok(s) = ext.value()
                    && let Ok(v) = s.parse::<u32>()
                {
                    pax_gid = Some(v);
                }
            }
        }
    }
    (pax_uid, pax_gid, xattrs)
}

struct DeferredDirMode {
    path: PathBuf,
    uid: u32,
    gid: u32,
    mode: u32,
    xattrs: BTreeMap<String, Vec<u8>>,
}

struct DeferredSendDirMeta {
    rel_path: String,
    uid: u32,
    gid: u32,
    mode: u32,
    mtime: Option<i64>,
    xattrs: BTreeMap<String, Vec<u8>>,
}

/// Unpack a tar stream into an already-created writable `target_dir` (either an empty
/// base subvolume/dir or a writable snapshot/copy of the parent layer), applying OCI
/// `.wh.*` and `.wh..wh..opq` whiteouts, Unix ownership/modes/suid/sgid, and xattrs.
pub fn unpack_layer_into_dir<R: Read>(
    reader: R,
    target_dir: &Path,
    digest: &str,
    parent_entries: Option<&BTreeMap<String, EntryUnixMetadata>>,
) -> Result<BTreeMap<String, EntryUnixMetadata>> {
    let mut entries_meta = parent_entries.cloned().unwrap_or_default();
    let mut created_in_layer: BTreeSet<String> = BTreeSet::new();
    let mut deferred_dir_modes: Vec<DeferredDirMode> = Vec::new();

    let mut archive = Archive::new(reader);
    let tar_entries = archive.entries().map_err(|err| OciError::Tar {
        digest: digest.to_owned(),
        detail: err.to_string(),
    })?;

    for entry_res in tar_entries {
        let mut entry = entry_res.map_err(|err| OciError::Tar {
            digest: digest.to_owned(),
            detail: err.to_string(),
        })?;
        let raw_path = entry
            .path()
            .map_err(|err| OciError::Tar {
                digest: digest.to_owned(),
                detail: err.to_string(),
            })?
            .into_owned();

        let Some(rel_path) = sanitize_tar_path(&raw_path, digest)? else {
            continue;
        };

        let (parent_rel, file_name) = split_parent_name(&rel_path);

        // 1. Handle OCI whiteouts before extracting normal files.
        if file_name == OPAQUE_WHITEOUT {
            apply_opaque_whiteout(
                target_dir,
                parent_rel,
                digest,
                &created_in_layer,
                &mut entries_meta,
            )?;
            continue;
        }
        if let Some(target_name) = file_name.strip_prefix(WHITEOUT_PREFIX) {
            if !target_name.is_empty() {
                reject_symlink_components(target_dir, parent_rel, digest)?;
                let victim_rel = if parent_rel.is_empty() {
                    target_name.to_owned()
                } else {
                    format!("{parent_rel}/{target_name}")
                };
                if !created_in_layer.contains(&victim_rel) {
                    remove_path_recursive(&target_dir.join(&victim_rel))?;
                    remove_metadata_subtree(&mut entries_meta, &victim_rel);
                }
            }
            continue;
        }

        let entry_type = entry.header().entry_type();
        let header_uid = entry.header().uid().unwrap_or(0) as u32;
        let header_gid = entry.header().gid().unwrap_or(0) as u32;
        let mode = entry.header().mode().unwrap_or(0o644) & 0o7777;
        let mtime = entry.header().mtime().ok().map(|v| v as i64);
        let device_major = entry.header().device_major().ok().flatten();
        let device_minor = entry.header().device_minor().ok().flatten();
        let (pax_uid, pax_gid, xattrs) = parse_pax_metadata(&mut entry);
        let uid = pax_uid.unwrap_or(header_uid);
        let gid = pax_gid.unwrap_or(header_gid);

        let dest = target_dir.join(&rel_path);

        match entry_type {
            EntryType::Directory => {
                ensure_parent_dirs(target_dir, parent_rel, digest, &mut entries_meta)?;
                match fs::symlink_metadata(&dest) {
                    Ok(meta) if meta.is_dir() => {}
                    Ok(_) => {
                        remove_path_recursive(&dest)?;
                        fs::create_dir(&dest).map_err(|source| OciError::Io {
                            operation: "create directory",
                            path: dest.clone(),
                            source,
                        })?;
                    }
                    Err(err) if err.kind() == io::ErrorKind::NotFound => {
                        fs::create_dir(&dest).map_err(|source| OciError::Io {
                            operation: "create directory",
                            path: dest.clone(),
                            source,
                        })?;
                    }
                    Err(source) => {
                        return Err(OciError::Io {
                            operation: "stat directory",
                            path: dest.clone(),
                            source,
                        });
                    }
                }
                // Ensure writable while unpacking children; apply final mode after loop.
                set_writable_for_unpack(&dest);
                deferred_dir_modes.push(DeferredDirMode {
                    path: dest,
                    uid,
                    gid,
                    mode,
                    xattrs: xattrs.clone(),
                });
                entries_meta.insert(
                    rel_path.clone(),
                    EntryUnixMetadata {
                        kind: NodeKind::Directory,
                        uid,
                        gid,
                        mode,
                        mtime,
                        link_target: None,
                        device_major: None,
                        device_minor: None,
                        xattrs,
                    },
                );
                created_in_layer.insert(rel_path);
            }
            EntryType::Regular | EntryType::Continuous => {
                ensure_parent_dirs(target_dir, parent_rel, digest, &mut entries_meta)?;
                if fs::symlink_metadata(&dest).is_ok() {
                    remove_path_recursive(&dest)?;
                }
                let mut file = File::create(&dest).map_err(|source| OciError::Io {
                    operation: "create file",
                    path: dest.clone(),
                    source,
                })?;
                io::copy(&mut entry, &mut file).map_err(|source| OciError::Io {
                    operation: "extract file contents",
                    path: dest.clone(),
                    source,
                })?;
                drop(file);
                apply_unix_metadata(&dest, uid, gid, mode, &xattrs, false);
                entries_meta.insert(
                    rel_path.clone(),
                    EntryUnixMetadata {
                        kind: NodeKind::File,
                        uid,
                        gid,
                        mode,
                        mtime,
                        link_target: None,
                        device_major: None,
                        device_minor: None,
                        xattrs,
                    },
                );
                created_in_layer.insert(rel_path);
            }
            EntryType::Symlink => {
                let link_target = entry
                    .link_name()
                    .map_err(|err| OciError::Tar {
                        digest: digest.to_owned(),
                        detail: err.to_string(),
                    })?
                    .ok_or_else(|| OciError::Tar {
                        digest: digest.to_owned(),
                        detail: format!("symlink `{rel_path}` missing link target"),
                    })?
                    .to_string_lossy()
                    .into_owned();
                ensure_parent_dirs(target_dir, parent_rel, digest, &mut entries_meta)?;
                if fs::symlink_metadata(&dest).is_ok() {
                    remove_path_recursive(&dest)?;
                }
                create_symlink(&link_target, &dest)?;
                apply_unix_metadata(&dest, uid, gid, mode, &xattrs, true);
                entries_meta.insert(
                    rel_path.clone(),
                    EntryUnixMetadata {
                        kind: NodeKind::Symlink,
                        uid,
                        gid,
                        mode: 0o777,
                        mtime,
                        link_target: Some(link_target),
                        device_major: None,
                        device_minor: None,
                        xattrs,
                    },
                );
                created_in_layer.insert(rel_path);
            }
            EntryType::Link => {
                let raw_target = entry
                    .link_name()
                    .map_err(|err| OciError::Tar {
                        digest: digest.to_owned(),
                        detail: err.to_string(),
                    })?
                    .ok_or_else(|| OciError::Tar {
                        digest: digest.to_owned(),
                        detail: format!("hardlink `{rel_path}` missing link target"),
                    })?
                    .into_owned();
                let Some(target_rel) = sanitize_tar_path(&raw_target, digest)? else {
                    return Err(OciError::UnsafePath {
                        digest: digest.to_owned(),
                        path: raw_target.display().to_string(),
                        reason: "hardlink target points to root",
                    });
                };
                reject_symlink_components(target_dir, &target_rel, digest)?;
                ensure_parent_dirs(target_dir, parent_rel, digest, &mut entries_meta)?;
                if fs::symlink_metadata(&dest).is_ok() {
                    remove_path_recursive(&dest)?;
                }
                let src = target_dir.join(&target_rel);
                fs::hard_link(&src, &dest).map_err(|source| OciError::Io {
                    operation: "create hard link",
                    path: dest.clone(),
                    source,
                })?;
                entries_meta.insert(
                    rel_path.clone(),
                    EntryUnixMetadata {
                        kind: NodeKind::HardLink,
                        uid,
                        gid,
                        mode,
                        mtime,
                        link_target: Some(target_rel),
                        device_major: None,
                        device_minor: None,
                        xattrs,
                    },
                );
                created_in_layer.insert(rel_path);
            }
            EntryType::Fifo | EntryType::Char | EntryType::Block => {
                let kind = match entry_type {
                    EntryType::Fifo => NodeKind::Fifo,
                    EntryType::Char => NodeKind::CharDevice,
                    EntryType::Block => NodeKind::BlockDevice,
                    _ => unreachable!(),
                };
                ensure_parent_dirs(target_dir, parent_rel, digest, &mut entries_meta)?;
                // Record full device/FIFO metadata in the ledger; creating device nodes on
                // unprivileged host filesystems requires CAP_MKNOD so we record them faithfully
                // without failing unprivileged host extracts (btrfs send stream encodes real MKNOD/MKFIFO).
                entries_meta.insert(
                    rel_path.clone(),
                    EntryUnixMetadata {
                        kind,
                        uid,
                        gid,
                        mode,
                        mtime,
                        link_target: None,
                        device_major,
                        device_minor,
                        xattrs,
                    },
                );
                created_in_layer.insert(rel_path);
            }
            EntryType::XHeader
            | EntryType::XGlobalHeader
            | EntryType::GNULongName
            | EntryType::GNULongLink => {
                // Handled internally by `tar::Archive`.
            }
            _ => {}
        }
    }

    // Apply directory modes/owners/xattrs in reverse depth order so read-only directories
    // never block creating files inside them during extraction.
    deferred_dir_modes.sort_by_key(|dir| std::cmp::Reverse(dir.path.as_os_str().len()));
    for dir in deferred_dir_modes {
        apply_unix_metadata(&dir.path, dir.uid, dir.gid, dir.mode, &dir.xattrs, false);
    }

    Ok(entries_meta)
}

/// Compile a tar layer into a Linux-compatible btrfs send stream (v1) targeting `subvol_name`,
/// optionally incremental on `parent` (with `parent_entries` supplying the existing tree for
/// accurate whiteout and replacement `UNLINK`/`RMDIR` emission).
pub fn encode_layer_as_btrfs_send<R: Read>(
    reader: R,
    subvol_name: &str,
    subvol_uuid: [u8; 16],
    ctransid: u64,
    parent: Option<ParentSubvolumeRef>,
    digest: &str,
    parent_entries: Option<&BTreeMap<String, EntryUnixMetadata>>,
) -> Result<(Vec<u8>, BTreeMap<String, EntryUnixMetadata>)> {
    let mut entries_meta = parent_entries.cloned().unwrap_or_default();
    let mut created_in_layer: BTreeSet<String> = BTreeSet::new();
    let mut deferred_dir_meta: Vec<DeferredSendDirMeta> = Vec::new();

    let mut builder = match parent {
        Some(p) => BtrfsSendBuilder::new_snapshot(subvol_name, subvol_uuid, ctransid, p)?,
        None => BtrfsSendBuilder::new_subvol(subvol_name, subvol_uuid, ctransid)?,
    };

    let mut archive = Archive::new(reader);
    let tar_entries = archive.entries().map_err(|err| OciError::Tar {
        digest: digest.to_owned(),
        detail: err.to_string(),
    })?;

    for entry_res in tar_entries {
        let mut entry = entry_res.map_err(|err| OciError::Tar {
            digest: digest.to_owned(),
            detail: err.to_string(),
        })?;
        let raw_path = entry
            .path()
            .map_err(|err| OciError::Tar {
                digest: digest.to_owned(),
                detail: err.to_string(),
            })?
            .into_owned();
        let Some(rel_path) = sanitize_tar_path(&raw_path, digest)? else {
            continue;
        };

        let (parent_rel, file_name) = split_parent_name(&rel_path);

        if file_name == OPAQUE_WHITEOUT {
            emit_opaque_whiteout_send(
                &mut builder,
                parent_rel,
                &created_in_layer,
                &mut entries_meta,
            )?;
            continue;
        }
        if let Some(target_name) = file_name.strip_prefix(WHITEOUT_PREFIX) {
            if !target_name.is_empty() {
                let victim_rel = if parent_rel.is_empty() {
                    target_name.to_owned()
                } else {
                    format!("{parent_rel}/{target_name}")
                };
                if !created_in_layer.contains(&victim_rel) {
                    emit_remove_subtree_send(&mut builder, &mut entries_meta, &victim_rel)?;
                }
            }
            continue;
        }

        let entry_type = entry.header().entry_type();
        let header_uid = entry.header().uid().unwrap_or(0) as u32;
        let header_gid = entry.header().gid().unwrap_or(0) as u32;
        let mode = entry.header().mode().unwrap_or(0o644) & 0o7777;
        let mtime = entry.header().mtime().ok().map(|v| v as i64);
        let device_major = entry.header().device_major().ok().flatten();
        let device_minor = entry.header().device_minor().ok().flatten();
        let (pax_uid, pax_gid, xattrs) = parse_pax_metadata(&mut entry);
        let uid = pax_uid.unwrap_or(header_uid);
        let gid = pax_gid.unwrap_or(header_gid);

        match entry_type {
            EntryType::Directory => {
                ensure_parent_dirs_send(
                    &mut builder,
                    parent_rel,
                    &mut entries_meta,
                    &mut created_in_layer,
                )?;
                match entries_meta.get(&rel_path).map(|m| m.kind) {
                    Some(NodeKind::Directory) => {}
                    Some(_) => {
                        emit_remove_subtree_send(&mut builder, &mut entries_meta, &rel_path)?;
                        builder.mkdir(&rel_path)?;
                    }
                    None => {
                        builder.mkdir(&rel_path)?;
                    }
                }
                deferred_dir_meta.push(DeferredSendDirMeta {
                    rel_path: rel_path.clone(),
                    uid,
                    gid,
                    mode,
                    mtime,
                    xattrs: xattrs.clone(),
                });
                entries_meta.insert(
                    rel_path.clone(),
                    EntryUnixMetadata {
                        kind: NodeKind::Directory,
                        uid,
                        gid,
                        mode,
                        mtime,
                        link_target: None,
                        device_major: None,
                        device_minor: None,
                        xattrs,
                    },
                );
                created_in_layer.insert(rel_path);
            }
            EntryType::Regular | EntryType::Continuous => {
                ensure_parent_dirs_send(
                    &mut builder,
                    parent_rel,
                    &mut entries_meta,
                    &mut created_in_layer,
                )?;
                if entries_meta.contains_key(&rel_path) {
                    emit_remove_subtree_send(&mut builder, &mut entries_meta, &rel_path)?;
                }
                builder.mkfile(&rel_path)?;
                let mut data = Vec::new();
                entry
                    .read_to_end(&mut data)
                    .map_err(|source| OciError::Io {
                        operation: "read tar entry for btrfs send",
                        path: PathBuf::from(&rel_path),
                        source,
                    })?;
                if !data.is_empty() {
                    builder.write_all(&rel_path, &data)?;
                }
                builder.truncate(&rel_path, data.len() as u64)?;
                builder.chown(&rel_path, uid, gid)?;
                builder.chmod(&rel_path, mode)?;
                for (name, val) in &xattrs {
                    builder.set_xattr(&rel_path, name.as_bytes(), val)?;
                }
                if let Some(ts) = mtime {
                    builder.utimes(&rel_path, ts, 0)?;
                }
                entries_meta.insert(
                    rel_path.clone(),
                    EntryUnixMetadata {
                        kind: NodeKind::File,
                        uid,
                        gid,
                        mode,
                        mtime,
                        link_target: None,
                        device_major: None,
                        device_minor: None,
                        xattrs,
                    },
                );
                created_in_layer.insert(rel_path);
            }
            EntryType::Symlink => {
                let link_target = entry
                    .link_name()
                    .map_err(|err| OciError::Tar {
                        digest: digest.to_owned(),
                        detail: err.to_string(),
                    })?
                    .ok_or_else(|| OciError::Tar {
                        digest: digest.to_owned(),
                        detail: format!("symlink `{rel_path}` missing link target"),
                    })?
                    .to_string_lossy()
                    .into_owned();
                ensure_parent_dirs_send(
                    &mut builder,
                    parent_rel,
                    &mut entries_meta,
                    &mut created_in_layer,
                )?;
                if entries_meta.contains_key(&rel_path) {
                    emit_remove_subtree_send(&mut builder, &mut entries_meta, &rel_path)?;
                }
                builder.symlink(&rel_path, &link_target)?;
                builder.chown(&rel_path, uid, gid)?;
                if let Some(ts) = mtime {
                    builder.utimes(&rel_path, ts, 0)?;
                }
                entries_meta.insert(
                    rel_path.clone(),
                    EntryUnixMetadata {
                        kind: NodeKind::Symlink,
                        uid,
                        gid,
                        mode: 0o777,
                        mtime,
                        link_target: Some(link_target),
                        device_major: None,
                        device_minor: None,
                        xattrs,
                    },
                );
                created_in_layer.insert(rel_path);
            }
            EntryType::Link => {
                let raw_target = entry
                    .link_name()
                    .map_err(|err| OciError::Tar {
                        digest: digest.to_owned(),
                        detail: err.to_string(),
                    })?
                    .ok_or_else(|| OciError::Tar {
                        digest: digest.to_owned(),
                        detail: format!("hardlink `{rel_path}` missing link target"),
                    })?
                    .into_owned();
                let Some(target_rel) = sanitize_tar_path(&raw_target, digest)? else {
                    return Err(OciError::UnsafePath {
                        digest: digest.to_owned(),
                        path: raw_target.display().to_string(),
                        reason: "hardlink target points to root",
                    });
                };
                ensure_parent_dirs_send(
                    &mut builder,
                    parent_rel,
                    &mut entries_meta,
                    &mut created_in_layer,
                )?;
                if entries_meta.contains_key(&rel_path) {
                    emit_remove_subtree_send(&mut builder, &mut entries_meta, &rel_path)?;
                }
                builder.hard_link(&rel_path, &target_rel)?;
                entries_meta.insert(
                    rel_path.clone(),
                    EntryUnixMetadata {
                        kind: NodeKind::HardLink,
                        uid,
                        gid,
                        mode,
                        mtime,
                        link_target: Some(target_rel),
                        device_major: None,
                        device_minor: None,
                        xattrs,
                    },
                );
                created_in_layer.insert(rel_path);
            }
            EntryType::Fifo | EntryType::Char | EntryType::Block => {
                ensure_parent_dirs_send(
                    &mut builder,
                    parent_rel,
                    &mut entries_meta,
                    &mut created_in_layer,
                )?;
                if entries_meta.contains_key(&rel_path) {
                    emit_remove_subtree_send(&mut builder, &mut entries_meta, &rel_path)?;
                }
                let kind = match entry_type {
                    EntryType::Fifo => {
                        builder.mkfifo(&rel_path)?;
                        NodeKind::Fifo
                    }
                    EntryType::Char => {
                        let rdev =
                            encode_linux_dev(device_major.unwrap_or(0), device_minor.unwrap_or(0));
                        builder.mknod(&rel_path, 0o020_000 | mode, rdev)?;
                        NodeKind::CharDevice
                    }
                    EntryType::Block => {
                        let rdev =
                            encode_linux_dev(device_major.unwrap_or(0), device_minor.unwrap_or(0));
                        builder.mknod(&rel_path, 0o060_000 | mode, rdev)?;
                        NodeKind::BlockDevice
                    }
                    _ => unreachable!(),
                };
                builder.chown(&rel_path, uid, gid)?;
                builder.chmod(&rel_path, mode)?;
                for (name, val) in &xattrs {
                    builder.set_xattr(&rel_path, name.as_bytes(), val)?;
                }
                entries_meta.insert(
                    rel_path.clone(),
                    EntryUnixMetadata {
                        kind,
                        uid,
                        gid,
                        mode,
                        mtime,
                        link_target: None,
                        device_major,
                        device_minor,
                        xattrs,
                    },
                );
                created_in_layer.insert(rel_path);
            }
            _ => {}
        }
    }

    deferred_dir_meta.sort_by_key(|dir| std::cmp::Reverse(dir.rel_path.len()));
    for dir in deferred_dir_meta {
        builder.chown(&dir.rel_path, dir.uid, dir.gid)?;
        builder.chmod(&dir.rel_path, dir.mode)?;
        for (name, val) in &dir.xattrs {
            builder.set_xattr(&dir.rel_path, name.as_bytes(), val)?;
        }
        if let Some(ts) = dir.mtime {
            builder.utimes(&dir.rel_path, ts, 0)?;
        }
    }

    let stream = builder.finish()?;
    Ok((stream, entries_meta))
}

fn split_parent_name(rel_path: &str) -> (&str, &str) {
    match rel_path.rsplit_once('/') {
        Some((p, n)) => (p, n),
        None => ("", rel_path),
    }
}

/// Refuse any path whose existing components inside `target_dir` traverse a symlink.
fn reject_symlink_components(target_dir: &Path, rel_path: &str, digest: &str) -> Result<()> {
    if rel_path.is_empty() {
        return Ok(());
    }
    let mut cur = target_dir.to_path_buf();
    for seg in rel_path.split('/') {
        cur.push(seg);
        match fs::symlink_metadata(&cur) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(OciError::UnsafePath {
                    digest: digest.to_owned(),
                    path: rel_path.to_owned(),
                    reason: "path traverses a symlink inside layer root",
                });
            }
            Ok(_) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => break,
            Err(source) => {
                return Err(OciError::Io {
                    operation: "inspect path component for symlink confinement",
                    path: cur,
                    source,
                });
            }
        }
    }
    Ok(())
}

fn apply_opaque_whiteout(
    target_dir: &Path,
    dir_rel: &str,
    digest: &str,
    created_in_layer: &BTreeSet<String>,
    entries_meta: &mut BTreeMap<String, EntryUnixMetadata>,
) -> Result<()> {
    reject_symlink_components(target_dir, dir_rel, digest)?;
    let dir_path = if dir_rel.is_empty() {
        target_dir.to_path_buf()
    } else {
        target_dir.join(dir_rel)
    };
    let is_real_dir = match fs::symlink_metadata(&dir_path) {
        Ok(meta) => meta.is_dir() && !meta.file_type().is_symlink(),
        Err(err) if err.kind() == io::ErrorKind::NotFound => false,
        Err(source) => {
            return Err(OciError::Io {
                operation: "stat directory for opaque whiteout",
                path: dir_path.clone(),
                source,
            });
        }
    };
    if is_real_dir {
        let read_dir = fs::read_dir(&dir_path).map_err(|source| OciError::Io {
            operation: "read directory for opaque whiteout",
            path: dir_path.clone(),
            source,
        })?;
        for child in read_dir {
            let child = child.map_err(|source| OciError::Io {
                operation: "iterate directory for opaque whiteout",
                path: dir_path.clone(),
                source,
            })?;
            let child_name = child.file_name().to_string_lossy().into_owned();
            let child_rel = if dir_rel.is_empty() {
                child_name
            } else {
                format!("{dir_rel}/{child_name}")
            };
            if !created_in_layer.contains(&child_rel) {
                remove_path_recursive(&child.path())?;
                remove_metadata_subtree(entries_meta, &child_rel);
            }
        }
    }
    // Also purge any metadata-only entries (such as special nodes) under `dir_rel`.
    let prefix = if dir_rel.is_empty() {
        String::new()
    } else {
        format!("{dir_rel}/")
    };
    let to_remove: Vec<String> = entries_meta
        .keys()
        .filter(|k| {
            let is_descendant = if prefix.is_empty() {
                true
            } else {
                k.starts_with(&prefix)
            };
            is_descendant && !created_in_layer.contains(*k)
        })
        .cloned()
        .collect();
    for key in to_remove {
        entries_meta.remove(&key);
    }
    Ok(())
}

fn emit_opaque_whiteout_send(
    builder: &mut BtrfsSendBuilder,
    dir_rel: &str,
    created_in_layer: &BTreeSet<String>,
    entries_meta: &mut BTreeMap<String, EntryUnixMetadata>,
) -> Result<()> {
    let prefix = if dir_rel.is_empty() {
        String::new()
    } else {
        format!("{dir_rel}/")
    };
    let mut victims: Vec<(String, NodeKind)> = entries_meta
        .iter()
        .filter(|(k, _)| {
            let is_descendant = if prefix.is_empty() {
                true
            } else {
                k.starts_with(&prefix)
            };
            is_descendant && !created_in_layer.contains(*k)
        })
        .map(|(k, v)| (k.clone(), v.kind))
        .collect();
    // Remove deepest children before parent directories.
    victims.sort_by(|a, b| b.0.len().cmp(&a.0.len()).then_with(|| b.0.cmp(&a.0)));
    for (path, kind) in victims {
        if kind == NodeKind::Directory {
            builder.rmdir(&path)?;
        } else {
            builder.unlink(&path)?;
        }
        entries_meta.remove(&path);
    }
    Ok(())
}

fn emit_remove_subtree_send(
    builder: &mut BtrfsSendBuilder,
    entries_meta: &mut BTreeMap<String, EntryUnixMetadata>,
    victim_rel: &str,
) -> Result<()> {
    let prefix = format!("{victim_rel}/");
    let mut victims: Vec<(String, NodeKind)> = entries_meta
        .iter()
        .filter(|(k, _)| k.as_str() == victim_rel || k.starts_with(&prefix))
        .map(|(k, v)| (k.clone(), v.kind))
        .collect();
    victims.sort_by(|a, b| b.0.len().cmp(&a.0.len()).then_with(|| b.0.cmp(&a.0)));
    for (path, kind) in victims {
        if kind == NodeKind::Directory {
            builder.rmdir(&path)?;
        } else {
            builder.unlink(&path)?;
        }
        entries_meta.remove(&path);
    }
    Ok(())
}

fn remove_metadata_subtree(entries_meta: &mut BTreeMap<String, EntryUnixMetadata>, victim: &str) {
    let prefix = format!("{victim}/");
    let keys: Vec<String> = entries_meta
        .keys()
        .filter(|k| k.as_str() == victim || k.starts_with(&prefix))
        .cloned()
        .collect();
    for key in keys {
        entries_meta.remove(&key);
    }
}

fn ensure_parent_dirs(
    target_dir: &Path,
    parent_rel: &str,
    digest: &str,
    entries_meta: &mut BTreeMap<String, EntryUnixMetadata>,
) -> Result<()> {
    if parent_rel.is_empty() {
        return Ok(());
    }
    let mut acc = String::new();
    for seg in parent_rel.split('/') {
        if !acc.is_empty() {
            acc.push('/');
        }
        acc.push_str(seg);
        let full = target_dir.join(&acc);
        match fs::symlink_metadata(&full) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(OciError::UnsafePath {
                    digest: digest.to_owned(),
                    path: parent_rel.to_owned(),
                    reason: "parent path traverses a symlink inside layer root",
                });
            }
            Ok(meta) if meta.is_dir() => {}
            Ok(_) => {
                remove_path_recursive(&full)?;
                fs::create_dir(&full).map_err(|source| OciError::Io {
                    operation: "create implicit parent directory",
                    path: full.clone(),
                    source,
                })?;
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                fs::create_dir(&full).map_err(|source| OciError::Io {
                    operation: "create implicit parent directory",
                    path: full.clone(),
                    source,
                })?;
            }
            Err(source) => {
                return Err(OciError::Io {
                    operation: "stat implicit parent directory",
                    path: full,
                    source,
                });
            }
        }
        set_writable_for_unpack(&full);
        entries_meta
            .entry(acc.clone())
            .or_insert_with(|| EntryUnixMetadata {
                kind: NodeKind::Directory,
                uid: 0,
                gid: 0,
                mode: 0o755,
                mtime: None,
                link_target: None,
                device_major: None,
                device_minor: None,
                xattrs: BTreeMap::new(),
            });
    }
    Ok(())
}

fn ensure_parent_dirs_send(
    builder: &mut BtrfsSendBuilder,
    parent_rel: &str,
    entries_meta: &mut BTreeMap<String, EntryUnixMetadata>,
    created_in_layer: &mut BTreeSet<String>,
) -> Result<()> {
    if parent_rel.is_empty() {
        return Ok(());
    }
    let mut acc = String::new();
    for seg in parent_rel.split('/') {
        if !acc.is_empty() {
            acc.push('/');
        }
        acc.push_str(seg);
        match entries_meta.get(&acc).map(|m| m.kind) {
            Some(NodeKind::Directory) => {}
            Some(_) => {
                emit_remove_subtree_send(builder, entries_meta, &acc)?;
                builder.mkdir(&acc)?;
                entries_meta.insert(
                    acc.clone(),
                    EntryUnixMetadata {
                        kind: NodeKind::Directory,
                        uid: 0,
                        gid: 0,
                        mode: 0o755,
                        mtime: None,
                        link_target: None,
                        device_major: None,
                        device_minor: None,
                        xattrs: BTreeMap::new(),
                    },
                );
                created_in_layer.insert(acc.clone());
            }
            None => {
                builder.mkdir(&acc)?;
                entries_meta.insert(
                    acc.clone(),
                    EntryUnixMetadata {
                        kind: NodeKind::Directory,
                        uid: 0,
                        gid: 0,
                        mode: 0o755,
                        mtime: None,
                        link_target: None,
                        device_major: None,
                        device_minor: None,
                        xattrs: BTreeMap::new(),
                    },
                );
                created_in_layer.insert(acc.clone());
            }
        }
    }
    Ok(())
}

/// Recursively remove a file, symlink, or directory (relaxing read-only bits first on Unix).
pub fn remove_path_recursive(path: &Path) -> Result<()> {
    let meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(source) => {
            return Err(OciError::Io {
                operation: "stat path for removal",
                path: path.to_path_buf(),
                source,
            });
        }
    };
    if meta.is_dir() {
        make_tree_writable(path);
        fs::remove_dir_all(path).map_err(|source| OciError::Io {
            operation: "remove directory tree",
            path: path.to_path_buf(),
            source,
        })?;
    } else {
        if let Some(parent) = path.parent() {
            set_writable_for_unpack(parent);
        }
        fs::remove_file(path).map_err(|source| OciError::Io {
            operation: "remove file",
            path: path.to_path_buf(),
            source,
        })?;
    }
    Ok(())
}

/// Recursively copy a materialized directory tree (used for non-btrfs child layers and
/// ephemeral overlays when btrfs snapshots are unavailable).
pub fn copy_tree_recursive(src: &Path, dst: &Path) -> Result<()> {
    fs::create_dir_all(dst).map_err(|source| OciError::Io {
        operation: "create copy destination directory",
        path: dst.to_path_buf(),
        source,
    })?;
    set_writable_for_unpack(dst);
    let entries = fs::read_dir(src).map_err(|source| OciError::Io {
        operation: "read source directory",
        path: src.to_path_buf(),
        source,
    })?;
    for entry in entries {
        let entry = entry.map_err(|source| OciError::Io {
            operation: "iterate source directory",
            path: src.to_path_buf(),
            source,
        })?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        let meta = fs::symlink_metadata(&src_path).map_err(|source| OciError::Io {
            operation: "stat source entry",
            path: src_path.clone(),
            source,
        })?;
        if meta.file_type().is_symlink() {
            let target = fs::read_link(&src_path).map_err(|source| OciError::Io {
                operation: "read symlink",
                path: src_path.clone(),
                source,
            })?;
            create_symlink(&target.to_string_lossy(), &dst_path)?;
        } else if meta.is_dir() {
            copy_tree_recursive(&src_path, &dst_path)?;
        } else if meta.is_file() {
            let mut src_file = File::open(&src_path).map_err(|source| OciError::Io {
                operation: "open source file",
                path: src_path.clone(),
                source,
            })?;
            let mut dst_file = File::create(&dst_path).map_err(|source| OciError::Io {
                operation: "create destination file",
                path: dst_path.clone(),
                source,
            })?;
            io::copy(&mut src_file, &mut dst_file).map_err(|source| OciError::Io {
                operation: "copy file bytes",
                path: dst_path.clone(),
                source,
            })?;
            dst_file.flush().map_err(|source| OciError::Io {
                operation: "flush copied file",
                path: dst_path.clone(),
                source,
            })?;
            copy_permissions_if_unix(&meta, &dst_path);
        }
    }
    Ok(())
}

/// Mark a directory tree read-only (best-effort permission stripping on non-btrfs Unix hosts).
pub fn mark_tree_read_only(root: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let Ok(entries) = fs::read_dir(root) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if let Ok(meta) = fs::symlink_metadata(&path) {
                if meta.file_type().is_symlink() {
                    continue;
                }
                if meta.is_dir() {
                    mark_tree_read_only(&path);
                }
                let mode = meta.permissions().mode() & !0o222;
                let _ = fs::set_permissions(&path, fs::Permissions::from_mode(mode));
            }
        }
        if let Ok(meta) = fs::symlink_metadata(root) {
            let mode = meta.permissions().mode() & !0o222;
            let _ = fs::set_permissions(root, fs::Permissions::from_mode(mode));
        }
    }
    #[cfg(not(unix))]
    {
        let _ = root;
    }
}

pub(crate) fn make_tree_writable(root: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if let Ok(meta) = fs::symlink_metadata(root)
            && !meta.file_type().is_symlink()
        {
            let mode = meta.permissions().mode() | 0o700;
            let _ = fs::set_permissions(root, fs::Permissions::from_mode(mode));
        }
        let Ok(entries) = fs::read_dir(root) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if let Ok(meta) = fs::symlink_metadata(&path) {
                if meta.file_type().is_symlink() {
                    continue;
                }
                if meta.is_dir() {
                    make_tree_writable(&path);
                } else {
                    let mode = meta.permissions().mode() | 0o200;
                    let _ = fs::set_permissions(&path, fs::Permissions::from_mode(mode));
                }
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = root;
    }
}

fn set_writable_for_unpack(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if let Ok(meta) = fs::symlink_metadata(path)
            && !meta.file_type().is_symlink()
        {
            let mode = meta.permissions().mode() | 0o700;
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(mode));
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

fn copy_permissions_if_unix(meta: &fs::Metadata, dst: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = meta.permissions().mode() | 0o200;
        let _ = fs::set_permissions(dst, fs::Permissions::from_mode(mode));
    }
    #[cfg(not(unix))]
    {
        let _ = (meta, dst);
    }
}

fn create_symlink(target: &str, link_path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, link_path).map_err(|source| OciError::Io {
            operation: "create symlink",
            path: link_path.to_path_buf(),
            source,
        })
    }
    #[cfg(all(target_os = "wasi", not(unix)))]
    {
        std::os::wasi::fs::symlink_path(target, link_path).map_err(|source| OciError::Io {
            operation: "create symlink",
            path: link_path.to_path_buf(),
            source,
        })
    }
    #[cfg(not(any(unix, target_os = "wasi")))]
    {
        let _ = (target, link_path);
        Err(OciError::Io {
            operation: "create symlink",
            path: link_path.to_path_buf(),
            source: io::Error::new(io::ErrorKind::Unsupported, "symlinks unsupported on target"),
        })
    }
}

fn apply_unix_metadata(
    path: &Path,
    uid: u32,
    gid: u32,
    mode: u32,
    xattrs: &BTreeMap<String, Vec<u8>>,
    is_symlink: bool,
) {
    #[cfg(unix)]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt as _;
        use std::os::unix::fs::PermissionsExt as _;

        if let Ok(c_path) = CString::new(path.as_os_str().as_bytes()) {
            // Best-effort lchown (succeeds as root; unprivileged host processes lack CAP_CHOWN
            // while full uid/gid remain captured in `LayerMetadataIndex` and btrfs send streams).
            // SAFETY: `c_path` is a valid NUL-terminated C string.
            let _ = unsafe { libc::lchown(c_path.as_ptr(), uid, gid) };

            // Best-effort xattr application (e.g. `security.capability`, `user.*`).
            for (name, value) in xattrs {
                if let Ok(c_name) = CString::new(name.as_bytes()) {
                    #[cfg(target_os = "linux")]
                    {
                        // SAFETY: `c_path`, `c_name`, and `value` slice pointers are valid for the call.
                        let _ = unsafe {
                            libc::lsetxattr(
                                c_path.as_ptr(),
                                c_name.as_ptr(),
                                value.as_ptr().cast(),
                                value.len(),
                                0,
                            )
                        };
                    }
                    #[cfg(target_os = "macos")]
                    {
                        // SAFETY: `c_path`, `c_name`, and `value` slice pointers are valid for the call.
                        let _ = unsafe {
                            libc::setxattr(
                                c_path.as_ptr(),
                                c_name.as_ptr(),
                                value.as_ptr().cast(),
                                value.len(),
                                0,
                                libc::XATTR_NOFOLLOW,
                            )
                        };
                    }
                    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
                    {
                        let _ = (c_name, value);
                    }
                }
            }
        }

        if !is_symlink {
            // Apply mode AFTER chown so setuid/setgid bits are not cleared by the OS kernel.
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(mode & 0o7777));
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (path, uid, gid, mode, xattrs, is_symlink);
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn append_symlink(builder: &mut tar::Builder<Vec<u8>>, link: &str, target: &str) {
        let mut hdr = tar::Header::new_gnu();
        hdr.set_entry_type(EntryType::Symlink);
        hdr.set_size(0);
        hdr.set_mode(0o777);
        hdr.set_cksum();
        builder.append_link(&mut hdr, link, target).unwrap();
    }

    fn append_hardlink(builder: &mut tar::Builder<Vec<u8>>, link: &str, target: &str) {
        let mut hdr = tar::Header::new_gnu();
        hdr.set_entry_type(EntryType::Link);
        hdr.set_size(0);
        hdr.set_mode(0o644);
        hdr.set_cksum();
        builder.append_link(&mut hdr, link, target).unwrap();
    }

    fn append_dir(builder: &mut tar::Builder<Vec<u8>>, path: &str) {
        let mut hdr = tar::Header::new_gnu();
        hdr.set_entry_type(EntryType::Directory);
        hdr.set_size(0);
        hdr.set_mode(0o755);
        hdr.set_cksum();
        builder.append_data(&mut hdr, path, io::empty()).unwrap();
    }

    fn append_file(builder: &mut tar::Builder<Vec<u8>>, path: &str, body: &[u8]) {
        let mut hdr = tar::Header::new_gnu();
        hdr.set_entry_type(EntryType::Regular);
        hdr.set_size(body.len() as u64);
        hdr.set_mode(0o644);
        hdr.set_cksum();
        builder.append_data(&mut hdr, path, body).unwrap();
    }

    #[test]
    fn blocks_directory_creation_through_symlink_escape() {
        let outside = TempDir::new().unwrap();
        let layer_root = TempDir::new().unwrap();

        let mut tar = tar::Builder::new(Vec::new());
        append_symlink(&mut tar, "escape", outside.path().to_str().unwrap());
        append_dir(&mut tar, "escape/injected_dir");
        let bytes = tar.into_inner().unwrap();

        let err = unpack_layer_into_dir(bytes.as_slice(), layer_root.path(), "sha256:test", None)
            .unwrap_err();
        assert!(matches!(err, OciError::UnsafePath { .. }), "got {err:?}");
        assert!(!outside.path().join("injected_dir").exists());
    }

    #[test]
    fn blocks_hardlink_through_symlink_escape() {
        let outside = TempDir::new().unwrap();
        let secret = outside.path().join("secret.txt");
        fs::write(&secret, b"top-secret").unwrap();
        let layer_root = TempDir::new().unwrap();

        let mut tar = tar::Builder::new(Vec::new());
        append_symlink(&mut tar, "escape", outside.path().to_str().unwrap());
        append_hardlink(&mut tar, "stolen.txt", "escape/secret.txt");
        let bytes = tar.into_inner().unwrap();

        let err = unpack_layer_into_dir(bytes.as_slice(), layer_root.path(), "sha256:test", None)
            .unwrap_err();
        assert!(matches!(err, OciError::UnsafePath { .. }), "got {err:?}");
        assert!(!layer_root.path().join("stolen.txt").exists());
    }

    #[test]
    fn blocks_explicit_whiteout_deletion_through_symlink_escape() {
        let outside = TempDir::new().unwrap();
        let victim = outside.path().join("victim.txt");
        fs::write(&victim, b"do-not-delete").unwrap();
        let layer_root = TempDir::new().unwrap();

        let mut tar = tar::Builder::new(Vec::new());
        append_symlink(&mut tar, "escape", outside.path().to_str().unwrap());
        append_file(&mut tar, "escape/.wh.victim.txt", b"");
        let bytes = tar.into_inner().unwrap();

        let err = unpack_layer_into_dir(bytes.as_slice(), layer_root.path(), "sha256:test", None)
            .unwrap_err();
        assert!(matches!(err, OciError::UnsafePath { .. }), "got {err:?}");
        assert!(victim.exists());
    }

    #[test]
    fn blocks_opaque_whiteout_deletion_through_symlink_escape() {
        let outside = TempDir::new().unwrap();
        let victim = outside.path().join("keep.txt");
        fs::write(&victim, b"do-not-wipe").unwrap();
        let layer_root = TempDir::new().unwrap();

        let mut tar = tar::Builder::new(Vec::new());
        append_symlink(&mut tar, "escape", outside.path().to_str().unwrap());
        append_file(&mut tar, "escape/.wh..wh..opq", b"");
        let bytes = tar.into_inner().unwrap();

        let err = unpack_layer_into_dir(bytes.as_slice(), layer_root.path(), "sha256:test", None)
            .unwrap_err();
        assert!(matches!(err, OciError::UnsafePath { .. }), "got {err:?}");
        assert!(victim.exists());
    }
}
