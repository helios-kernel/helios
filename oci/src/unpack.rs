//! OCI tar layer unpacker with `.wh.*` / `.wh..wh..opq` whiteouts, Unix metadata,
//! PAX `SCHILY.xattr.*` capability preservation, and btrfs send stream generation.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use tar::{Archive, EntryType};

use crate::btrfs_send::{
    BtrfsSendBuilder, ParentSubvolumeRef, WRITE_CHUNK_BYTES, encode_linux_dev,
};
use crate::decompress::MAX_LAYER_BYTES as DECOMPRESS_MAX_LAYER_BYTES;
use crate::error::{OciError, Result};
use crate::reference::Digest;

const WHITEOUT_PREFIX: &str = ".wh.";
const OPAQUE_WHITEOUT: &str = ".wh..wh..opq";
const PAX_XATTR_PREFIX: &str = "SCHILY.xattr.";
const MAX_SYMLINK_HOPS: usize = 40;

/// Upper bound on total uncompressed file bytes extracted or encoded from a single layer.
pub const MAX_LAYER_BYTES: u64 = DECOMPRESS_MAX_LAYER_BYTES as u64;
/// Upper bound on tar entry count processed from a single layer.
pub const MAX_LAYER_ENTRIES: usize = 262_144;

/// Resource limits enforced while unpacking or encoding a single OCI tar layer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LayerLimits {
    pub max_bytes: u64,
    pub max_entries: usize,
}

impl Default for LayerLimits {
    fn default() -> Self {
        Self {
            max_bytes: MAX_LAYER_BYTES,
            max_entries: MAX_LAYER_ENTRIES,
        }
    }
}

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
    unpack_layer_into_dir_with_limits(
        reader,
        target_dir,
        digest,
        parent_entries,
        LayerLimits::default(),
    )
}

/// Unpack a tar stream into `target_dir` while enforcing explicit [`LayerLimits`].
pub fn unpack_layer_into_dir_with_limits<R: Read>(
    reader: R,
    target_dir: &Path,
    digest: &str,
    parent_entries: Option<&BTreeMap<String, EntryUnixMetadata>>,
    limits: LayerLimits,
) -> Result<BTreeMap<String, EntryUnixMetadata>> {
    let mut entries_meta = parent_entries.cloned().unwrap_or_default();
    let mut created_in_layer: BTreeSet<String> = BTreeSet::new();
    let mut deferred_dir_modes: Vec<DeferredDirMode> = Vec::new();
    let mut explicit_dir_paths: BTreeSet<PathBuf> = BTreeSet::new();
    let mut restored_dir_modes: BTreeMap<PathBuf, u32> = BTreeMap::new();
    let mut entry_count = 0usize;
    let mut total_bytes = 0u64;

    record_and_make_writable(target_dir, &mut restored_dir_modes);

    let mut archive = Archive::new(reader);
    let tar_entries = archive.entries().map_err(|err| OciError::Tar {
        digest: digest.to_owned(),
        detail: err.to_string(),
    })?;

    for entry_res in tar_entries {
        entry_count += 1;
        if entry_count > limits.max_entries {
            return Err(OciError::LayerTooLarge {
                digest: digest.to_owned(),
                kind: "entry count",
                limit: limits.max_entries as u64,
            });
        }

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
                &mut restored_dir_modes,
            )?;
            continue;
        }
        if let Some(target_name) = file_name.strip_prefix(WHITEOUT_PREFIX) {
            let target_name = validate_whiteout_target(target_name, &rel_path, digest)?;
            if let Some(resolved_parent) =
                resolve_confined_dir_lookup(target_dir, parent_rel, digest)?
            {
                let victim_rel = join_rel(&resolved_parent, target_name);
                if !created_in_layer.contains(&victim_rel) {
                    let victim_path = target_dir.join(&victim_rel);
                    if let Some(parent) = victim_path.parent() {
                        record_and_make_writable(parent, &mut restored_dir_modes);
                    }
                    remove_path_recursive(&victim_path)?;
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
        let declared_size = entry.header().size().unwrap_or(0);
        let device_major = entry.header().device_major().ok().flatten();
        let device_minor = entry.header().device_minor().ok().flatten();
        let (pax_uid, pax_gid, xattrs) = parse_pax_metadata(&mut entry);
        let uid = pax_uid.unwrap_or(header_uid);
        let gid = pax_gid.unwrap_or(header_gid);

        match entry_type {
            EntryType::Directory => {
                let resolved_parent = ensure_parent_dirs(
                    target_dir,
                    parent_rel,
                    digest,
                    &mut entries_meta,
                    &mut restored_dir_modes,
                )?;
                let resolved_rel = join_rel(&resolved_parent, file_name);
                let dest = target_dir.join(&resolved_rel);
                match fs::symlink_metadata(&dest) {
                    Ok(meta) if meta.is_dir() => {}
                    Ok(_) => {
                        remove_path_recursive(&dest)?;
                        remove_metadata_subtree(&mut entries_meta, &resolved_rel);
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
                explicit_dir_paths.insert(dest.clone());
                deferred_dir_modes.push(DeferredDirMode {
                    path: dest,
                    uid,
                    gid,
                    mode,
                    xattrs: xattrs.clone(),
                });
                entries_meta.insert(
                    resolved_rel.clone(),
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
                created_in_layer.insert(resolved_rel);
            }
            EntryType::Regular | EntryType::Continuous => {
                if total_bytes.saturating_add(declared_size) > limits.max_bytes {
                    return Err(OciError::LayerTooLarge {
                        digest: digest.to_owned(),
                        kind: "uncompressed byte",
                        limit: limits.max_bytes,
                    });
                }
                let resolved_parent = ensure_parent_dirs(
                    target_dir,
                    parent_rel,
                    digest,
                    &mut entries_meta,
                    &mut restored_dir_modes,
                )?;
                let resolved_rel = join_rel(&resolved_parent, file_name);
                let dest = target_dir.join(&resolved_rel);
                remove_existing_destination(&dest, &resolved_rel, &mut entries_meta)?;
                let mut file = File::create(&dest).map_err(|source| OciError::Io {
                    operation: "create file",
                    path: dest.clone(),
                    source,
                })?;
                let remaining = limits.max_bytes.saturating_sub(total_bytes);
                let mut bounded = (&mut entry).take(remaining.saturating_add(1));
                let copied = io::copy(&mut bounded, &mut file).map_err(|source| OciError::Io {
                    operation: "extract file contents",
                    path: dest.clone(),
                    source,
                })?;
                drop(file);
                if copied > remaining {
                    let _ = fs::remove_file(&dest);
                    return Err(OciError::LayerTooLarge {
                        digest: digest.to_owned(),
                        kind: "uncompressed byte",
                        limit: limits.max_bytes,
                    });
                }
                total_bytes += copied;
                apply_unix_metadata(&dest, uid, gid, mode, &xattrs, false)?;
                entries_meta.insert(
                    resolved_rel.clone(),
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
                created_in_layer.insert(resolved_rel);
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
                let resolved_parent = ensure_parent_dirs(
                    target_dir,
                    parent_rel,
                    digest,
                    &mut entries_meta,
                    &mut restored_dir_modes,
                )?;
                let resolved_rel = join_rel(&resolved_parent, file_name);
                let dest = target_dir.join(&resolved_rel);
                remove_existing_destination(&dest, &resolved_rel, &mut entries_meta)?;
                create_symlink(&link_target, &dest)?;
                apply_unix_metadata(&dest, uid, gid, mode, &xattrs, true)?;
                entries_meta.insert(
                    resolved_rel.clone(),
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
                created_in_layer.insert(resolved_rel);
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
                let (target_parent_rel, target_leaf) = split_parent_name(&target_rel);
                let resolved_target_parent =
                    resolve_confined_dir_lookup(target_dir, target_parent_rel, digest)?
                        .ok_or_else(|| OciError::UnsafePath {
                            digest: digest.to_owned(),
                            path: target_rel.clone(),
                            reason: "hardlink target parent is not a directory",
                        })?;
                let mut resolved_target_rel = join_rel(&resolved_target_parent, target_leaf);
                let mut src = target_dir.join(&resolved_target_rel);
                if let Ok(meta) = fs::symlink_metadata(&src)
                    && meta.file_type().is_symlink()
                {
                    let confined_leaf =
                        resolve_confined_dir_lookup(target_dir, &resolved_target_rel, digest)?
                            .ok_or_else(|| OciError::UnsafePath {
                                digest: digest.to_owned(),
                                path: target_rel.clone(),
                                reason: "hardlink symlink target is invalid",
                            })?;
                    resolved_target_rel = confined_leaf;
                    src = target_dir.join(&resolved_target_rel);
                }

                let resolved_parent = ensure_parent_dirs(
                    target_dir,
                    parent_rel,
                    digest,
                    &mut entries_meta,
                    &mut restored_dir_modes,
                )?;
                let resolved_rel = join_rel(&resolved_parent, file_name);
                let dest = target_dir.join(&resolved_rel);
                remove_existing_destination(&dest, &resolved_rel, &mut entries_meta)?;
                fs::hard_link(&src, &dest).map_err(|source| OciError::Io {
                    operation: "create hard link",
                    path: dest.clone(),
                    source,
                })?;
                entries_meta.insert(
                    resolved_rel.clone(),
                    EntryUnixMetadata {
                        kind: NodeKind::HardLink,
                        uid,
                        gid,
                        mode,
                        mtime,
                        link_target: Some(resolved_target_rel),
                        device_major: None,
                        device_minor: None,
                        xattrs,
                    },
                );
                created_in_layer.insert(resolved_rel);
            }
            EntryType::Fifo | EntryType::Char | EntryType::Block => {
                let kind = match entry_type {
                    EntryType::Fifo => NodeKind::Fifo,
                    EntryType::Char => NodeKind::CharDevice,
                    EntryType::Block => NodeKind::BlockDevice,
                    _ => unreachable!(),
                };
                let resolved_parent = ensure_parent_dirs(
                    target_dir,
                    parent_rel,
                    digest,
                    &mut entries_meta,
                    &mut restored_dir_modes,
                )?;
                let resolved_rel = join_rel(&resolved_parent, file_name);
                // Record full device/FIFO metadata in the ledger; creating device nodes on
                // unprivileged host filesystems requires CAP_MKNOD so we record them faithfully
                // without failing unprivileged host extracts (btrfs send stream encodes real MKNOD/MKFIFO).
                entries_meta.insert(
                    resolved_rel.clone(),
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
                created_in_layer.insert(resolved_rel);
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

    // Restore pre-existing traversed directories not explicitly overridden in this layer,
    // then apply explicit directory modes/owners/xattrs in reverse depth order.
    let mut restored: Vec<(PathBuf, u32)> = restored_dir_modes
        .into_iter()
        .filter(|(p, _)| !explicit_dir_paths.contains(p))
        .collect();
    restored.sort_by_key(|(p, _)| std::cmp::Reverse(p.as_os_str().len()));
    for (path, mode) in restored {
        restore_mode_best_effort(&path, mode)?;
    }

    deferred_dir_modes.sort_by_key(|dir| std::cmp::Reverse(dir.path.as_os_str().len()));
    for dir in deferred_dir_modes {
        apply_unix_metadata(&dir.path, dir.uid, dir.gid, dir.mode, &dir.xattrs, false)?;
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
    encode_layer_as_btrfs_send_with_limits(
        reader,
        subvol_name,
        subvol_uuid,
        ctransid,
        parent,
        digest,
        parent_entries,
        LayerLimits::default(),
    )
}

/// Compile a tar layer into a Linux-compatible btrfs send stream (v1) while enforcing explicit
/// [`LayerLimits`] on entry count, uncompressed file bytes, and total encoded stream bytes.
#[expect(
    clippy::too_many_arguments,
    reason = "matches encode_layer_as_btrfs_send with explicit LayerLimits for bounded tests"
)]
pub fn encode_layer_as_btrfs_send_with_limits<R: Read>(
    reader: R,
    subvol_name: &str,
    subvol_uuid: [u8; 16],
    ctransid: u64,
    parent: Option<ParentSubvolumeRef>,
    digest: &str,
    parent_entries: Option<&BTreeMap<String, EntryUnixMetadata>>,
    limits: LayerLimits,
) -> Result<(Vec<u8>, BTreeMap<String, EntryUnixMetadata>)> {
    let mut entries_meta = parent_entries.cloned().unwrap_or_default();
    let mut created_in_layer: BTreeSet<String> = BTreeSet::new();
    let mut deferred_dir_meta: Vec<DeferredSendDirMeta> = Vec::new();
    let mut entry_count = 0usize;
    let mut total_bytes = 0u64;
    let mut chunk_buf = vec![0u8; WRITE_CHUNK_BYTES];

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
        entry_count += 1;
        if entry_count > limits.max_entries {
            return Err(OciError::LayerTooLarge {
                digest: digest.to_owned(),
                kind: "entry count",
                limit: limits.max_entries as u64,
            });
        }

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
            if let Some(resolved_parent) =
                resolve_confined_dir_lookup_send(&entries_meta, parent_rel, digest)?
            {
                emit_opaque_whiteout_send(
                    &mut builder,
                    &resolved_parent,
                    &created_in_layer,
                    &mut entries_meta,
                )?;
            }
            continue;
        }
        if let Some(target_name) = file_name.strip_prefix(WHITEOUT_PREFIX) {
            let target_name = validate_whiteout_target(target_name, &rel_path, digest)?;
            if let Some(resolved_parent) =
                resolve_confined_dir_lookup_send(&entries_meta, parent_rel, digest)?
            {
                let victim_rel = join_rel(&resolved_parent, target_name);
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
        let declared_size = entry.header().size().unwrap_or(0);
        let device_major = entry.header().device_major().ok().flatten();
        let device_minor = entry.header().device_minor().ok().flatten();
        let (pax_uid, pax_gid, xattrs) = parse_pax_metadata(&mut entry);
        let uid = pax_uid.unwrap_or(header_uid);
        let gid = pax_gid.unwrap_or(header_gid);

        match entry_type {
            EntryType::Directory => {
                let resolved_parent = ensure_parent_dirs_send(
                    &mut builder,
                    parent_rel,
                    digest,
                    &mut entries_meta,
                    &mut created_in_layer,
                )?;
                let resolved_rel = join_rel(&resolved_parent, file_name);
                match entries_meta.get(&resolved_rel).map(|m| m.kind) {
                    Some(NodeKind::Directory) => {}
                    Some(_) => {
                        emit_remove_subtree_send(&mut builder, &mut entries_meta, &resolved_rel)?;
                        builder.mkdir(&resolved_rel)?;
                    }
                    None => {
                        builder.mkdir(&resolved_rel)?;
                    }
                }
                deferred_dir_meta.push(DeferredSendDirMeta {
                    rel_path: resolved_rel.clone(),
                    uid,
                    gid,
                    mode,
                    mtime,
                    xattrs: xattrs.clone(),
                });
                entries_meta.insert(
                    resolved_rel.clone(),
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
                created_in_layer.insert(resolved_rel);
            }
            EntryType::Regular | EntryType::Continuous => {
                if total_bytes.saturating_add(declared_size) > limits.max_bytes {
                    return Err(OciError::LayerTooLarge {
                        digest: digest.to_owned(),
                        kind: "uncompressed byte",
                        limit: limits.max_bytes,
                    });
                }
                let resolved_parent = ensure_parent_dirs_send(
                    &mut builder,
                    parent_rel,
                    digest,
                    &mut entries_meta,
                    &mut created_in_layer,
                )?;
                let resolved_rel = join_rel(&resolved_parent, file_name);
                if entries_meta.contains_key(&resolved_rel) {
                    emit_remove_subtree_send(&mut builder, &mut entries_meta, &resolved_rel)?;
                }
                builder.mkfile(&resolved_rel)?;
                let mut offset = 0u64;
                loop {
                    let n = read_chunk_or_eof(&mut entry, &mut chunk_buf).map_err(|source| {
                        OciError::Io {
                            operation: "read tar entry for btrfs send",
                            path: PathBuf::from(&resolved_rel),
                            source,
                        }
                    })?;
                    if n == 0 {
                        break;
                    }
                    total_bytes = total_bytes.saturating_add(n as u64);
                    if total_bytes > limits.max_bytes {
                        return Err(OciError::LayerTooLarge {
                            digest: digest.to_owned(),
                            kind: "uncompressed byte",
                            limit: limits.max_bytes,
                        });
                    }
                    builder.write_chunk(&resolved_rel, offset, &chunk_buf[..n])?;
                    if (builder.encoded_len() as u64) > limits.max_bytes {
                        return Err(OciError::LayerTooLarge {
                            digest: digest.to_owned(),
                            kind: "btrfs send stream byte",
                            limit: limits.max_bytes,
                        });
                    }
                    offset += n as u64;
                }
                builder.truncate(&resolved_rel, offset)?;
                builder.chown(&resolved_rel, uid, gid)?;
                builder.chmod(&resolved_rel, mode)?;
                for (name, val) in &xattrs {
                    builder.set_xattr(&resolved_rel, name.as_bytes(), val)?;
                }
                if let Some(ts) = mtime {
                    builder.utimes(&resolved_rel, ts, 0)?;
                }
                entries_meta.insert(
                    resolved_rel.clone(),
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
                created_in_layer.insert(resolved_rel);
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
                let resolved_parent = ensure_parent_dirs_send(
                    &mut builder,
                    parent_rel,
                    digest,
                    &mut entries_meta,
                    &mut created_in_layer,
                )?;
                let resolved_rel = join_rel(&resolved_parent, file_name);
                if entries_meta.contains_key(&resolved_rel) {
                    emit_remove_subtree_send(&mut builder, &mut entries_meta, &resolved_rel)?;
                }
                builder.symlink(&resolved_rel, &link_target)?;
                builder.chown(&resolved_rel, uid, gid)?;
                if let Some(ts) = mtime {
                    builder.utimes(&resolved_rel, ts, 0)?;
                }
                entries_meta.insert(
                    resolved_rel.clone(),
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
                created_in_layer.insert(resolved_rel);
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
                let (target_parent_rel, target_leaf) = split_parent_name(&target_rel);
                let resolved_target_parent =
                    resolve_confined_dir_lookup_send(&entries_meta, target_parent_rel, digest)?
                        .ok_or_else(|| OciError::UnsafePath {
                            digest: digest.to_owned(),
                            path: target_rel.clone(),
                            reason: "hardlink target parent is not a directory",
                        })?;
                let mut resolved_target_rel = join_rel(&resolved_target_parent, target_leaf);
                if entries_meta
                    .get(&resolved_target_rel)
                    .is_some_and(|m| m.kind == NodeKind::Symlink)
                {
                    resolved_target_rel = resolve_confined_dir_lookup_send(
                        &entries_meta,
                        &resolved_target_rel,
                        digest,
                    )?
                    .ok_or_else(|| OciError::UnsafePath {
                        digest: digest.to_owned(),
                        path: target_rel.clone(),
                        reason: "hardlink symlink target is invalid",
                    })?;
                }

                let resolved_parent = ensure_parent_dirs_send(
                    &mut builder,
                    parent_rel,
                    digest,
                    &mut entries_meta,
                    &mut created_in_layer,
                )?;
                let resolved_rel = join_rel(&resolved_parent, file_name);
                if entries_meta.contains_key(&resolved_rel) {
                    emit_remove_subtree_send(&mut builder, &mut entries_meta, &resolved_rel)?;
                }
                builder.hard_link(&resolved_rel, &resolved_target_rel)?;
                entries_meta.insert(
                    resolved_rel.clone(),
                    EntryUnixMetadata {
                        kind: NodeKind::HardLink,
                        uid,
                        gid,
                        mode,
                        mtime,
                        link_target: Some(resolved_target_rel),
                        device_major: None,
                        device_minor: None,
                        xattrs,
                    },
                );
                created_in_layer.insert(resolved_rel);
            }
            EntryType::Fifo | EntryType::Char | EntryType::Block => {
                let resolved_parent = ensure_parent_dirs_send(
                    &mut builder,
                    parent_rel,
                    digest,
                    &mut entries_meta,
                    &mut created_in_layer,
                )?;
                let resolved_rel = join_rel(&resolved_parent, file_name);
                if entries_meta.contains_key(&resolved_rel) {
                    emit_remove_subtree_send(&mut builder, &mut entries_meta, &resolved_rel)?;
                }
                let kind = match entry_type {
                    EntryType::Fifo => {
                        builder.mkfifo(&resolved_rel)?;
                        NodeKind::Fifo
                    }
                    EntryType::Char => {
                        let rdev =
                            encode_linux_dev(device_major.unwrap_or(0), device_minor.unwrap_or(0));
                        builder.mknod(&resolved_rel, 0o020_000 | mode, rdev)?;
                        NodeKind::CharDevice
                    }
                    EntryType::Block => {
                        let rdev =
                            encode_linux_dev(device_major.unwrap_or(0), device_minor.unwrap_or(0));
                        builder.mknod(&resolved_rel, 0o060_000 | mode, rdev)?;
                        NodeKind::BlockDevice
                    }
                    _ => unreachable!(),
                };
                builder.chown(&resolved_rel, uid, gid)?;
                builder.chmod(&resolved_rel, mode)?;
                for (name, val) in &xattrs {
                    builder.set_xattr(&resolved_rel, name.as_bytes(), val)?;
                }
                entries_meta.insert(
                    resolved_rel.clone(),
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
                created_in_layer.insert(resolved_rel);
            }
            _ => {}
        }

        if (builder.encoded_len() as u64) > limits.max_bytes {
            return Err(OciError::LayerTooLarge {
                digest: digest.to_owned(),
                kind: "btrfs send stream byte",
                limit: limits.max_bytes,
            });
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
    if (stream.len() as u64) > limits.max_bytes {
        return Err(OciError::LayerTooLarge {
            digest: digest.to_owned(),
            kind: "btrfs send stream byte",
            limit: limits.max_bytes,
        });
    }
    Ok((stream, entries_meta))
}

fn read_chunk_or_eof<R: Read>(reader: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0usize;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        }
    }
    Ok(filled)
}

fn validate_whiteout_target<'a>(
    target_name: &'a str,
    rel_path: &str,
    digest: &str,
) -> Result<&'a str> {
    if target_name.is_empty()
        || target_name == "."
        || target_name == ".."
        || target_name.contains(['/', '\\', '\0'])
    {
        return Err(OciError::UnsafePath {
            digest: digest.to_owned(),
            path: rel_path.to_owned(),
            reason: "whiteout target escapes layer root or is invalid",
        });
    }
    Ok(target_name)
}

fn join_rel(parent_rel: &str, name: &str) -> String {
    if parent_rel.is_empty() {
        name.to_owned()
    } else {
        format!("{parent_rel}/{name}")
    }
}

fn remove_existing_destination(
    dest: &Path,
    resolved_rel: &str,
    entries_meta: &mut BTreeMap<String, EntryUnixMetadata>,
) -> Result<()> {
    match fs::symlink_metadata(dest) {
        Ok(_) => {
            remove_path_recursive(dest)?;
            remove_metadata_subtree(entries_meta, resolved_rel);
            Ok(())
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(OciError::Io {
            operation: "stat destination path",
            path: dest.to_path_buf(),
            source,
        }),
    }
}

fn split_parent_name(rel_path: &str) -> (&str, &str) {
    match rel_path.rsplit_once('/') {
        Some((p, n)) => (p, n),
        None => ("", rel_path),
    }
}

enum PathNode {
    Directory,
    Symlink(String),
    Other,
    NotFound,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ResolveMode {
    Lookup,
    EnsureDirs,
}

trait ConfinedFs {
    fn inspect(&mut self, rel: &str) -> Result<PathNode>;
    fn replace_with_dir(&mut self, rel: &str, was_other: bool) -> Result<()>;
    fn on_dir_visited(&mut self, rel: &str) -> Result<()>;
}

fn resolve_confined_path<F: ConfinedFs>(
    rel_path: &str,
    digest: &str,
    mode: ResolveMode,
    fs_view: &mut F,
) -> Result<Option<String>> {
    if rel_path.is_empty() {
        return Ok(Some(String::new()));
    }
    let mut cur: Vec<String> = Vec::new();
    let mut pending: VecDeque<(String, bool)> = rel_path
        .split('/')
        .filter(|s| !s.is_empty())
        .map(|s| (s.to_owned(), false))
        .collect();
    let mut hops = 0usize;

    while let Some((seg, from_symlink)) = pending.pop_front() {
        if seg.is_empty() || seg == "." {
            continue;
        }
        if seg == ".." {
            if cur.pop().is_none() {
                return Err(OciError::UnsafePath {
                    digest: digest.to_owned(),
                    path: rel_path.to_owned(),
                    reason: "symlink target escapes layer root via `..`",
                });
            }
            continue;
        }
        let cand = if cur.is_empty() {
            seg.clone()
        } else {
            format!("{}/{seg}", cur.join("/"))
        };
        match fs_view.inspect(&cand)? {
            PathNode::Symlink(target) => {
                hops += 1;
                if hops > MAX_SYMLINK_HOPS {
                    return Err(OciError::UnsafePath {
                        digest: digest.to_owned(),
                        path: rel_path.to_owned(),
                        reason: "symlink resolution exceeded maximum hop limit",
                    });
                }
                if target.is_empty() || target.contains('\0') {
                    return Err(OciError::UnsafePath {
                        digest: digest.to_owned(),
                        path: rel_path.to_owned(),
                        reason: "symlink target is empty or contains NUL byte",
                    });
                }
                if target.starts_with('/') {
                    cur.clear();
                }
                for part in target.rsplit('/') {
                    if !part.is_empty() {
                        pending.push_front((part.to_owned(), true));
                    }
                }
            }
            PathNode::Directory => {
                fs_view.on_dir_visited(&cand)?;
                cur.push(seg);
            }
            PathNode::Other => {
                if from_symlink {
                    return Err(OciError::UnsafePath {
                        digest: digest.to_owned(),
                        path: rel_path.to_owned(),
                        reason: "symlink target traverses non-directory",
                    });
                }
                match mode {
                    ResolveMode::EnsureDirs => {
                        fs_view.replace_with_dir(&cand, true)?;
                        cur.push(seg);
                    }
                    ResolveMode::Lookup => return Ok(None),
                }
            }
            PathNode::NotFound => {
                if from_symlink {
                    return Err(OciError::UnsafePath {
                        digest: digest.to_owned(),
                        path: rel_path.to_owned(),
                        reason: "symlink target escapes or does not exist inside layer root",
                    });
                }
                match mode {
                    ResolveMode::EnsureDirs => {
                        fs_view.replace_with_dir(&cand, false)?;
                        cur.push(seg);
                    }
                    ResolveMode::Lookup => {
                        cur.push(seg);
                    }
                }
            }
        }
    }
    Ok(Some(cur.join("/")))
}

fn inspect_disk_node(target_dir: &Path, rel: &str, digest: &str) -> Result<PathNode> {
    let full = target_dir.join(rel);
    match fs::symlink_metadata(&full) {
        Ok(meta) if meta.file_type().is_symlink() => {
            let link = fs::read_link(&full).map_err(|source| OciError::Io {
                operation: "read symlink target for confinement",
                path: full,
                source,
            })?;
            let target = link
                .to_str()
                .ok_or_else(|| OciError::UnsafePath {
                    digest: digest.to_owned(),
                    path: rel.to_owned(),
                    reason: "non-UTF-8 symlink target",
                })?
                .to_owned();
            Ok(PathNode::Symlink(target))
        }
        Ok(meta) if meta.is_dir() => Ok(PathNode::Directory),
        Ok(_) => Ok(PathNode::Other),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(PathNode::NotFound),
        Err(source) => Err(OciError::Io {
            operation: "inspect path component for symlink confinement",
            path: full,
            source,
        }),
    }
}

fn inspect_send_node(entries_meta: &BTreeMap<String, EntryUnixMetadata>, rel: &str) -> PathNode {
    match entries_meta.get(rel) {
        Some(meta) if meta.kind == NodeKind::Symlink => {
            PathNode::Symlink(meta.link_target.clone().unwrap_or_default())
        }
        Some(meta) if meta.kind == NodeKind::Directory => PathNode::Directory,
        Some(_) => PathNode::Other,
        None => PathNode::NotFound,
    }
}

struct DiskLookupFs<'a> {
    target_dir: &'a Path,
    digest: &'a str,
}

impl ConfinedFs for DiskLookupFs<'_> {
    fn inspect(&mut self, rel: &str) -> Result<PathNode> {
        inspect_disk_node(self.target_dir, rel, self.digest)
    }

    fn replace_with_dir(&mut self, _rel: &str, _was_other: bool) -> Result<()> {
        Ok(())
    }

    fn on_dir_visited(&mut self, _rel: &str) -> Result<()> {
        Ok(())
    }
}

struct SendLookupFs<'a> {
    entries_meta: &'a BTreeMap<String, EntryUnixMetadata>,
}

impl ConfinedFs for SendLookupFs<'_> {
    fn inspect(&mut self, rel: &str) -> Result<PathNode> {
        Ok(inspect_send_node(self.entries_meta, rel))
    }

    fn replace_with_dir(&mut self, _rel: &str, _was_other: bool) -> Result<()> {
        Ok(())
    }

    fn on_dir_visited(&mut self, _rel: &str) -> Result<()> {
        Ok(())
    }
}

fn resolve_confined_dir_lookup(
    target_dir: &Path,
    rel_path: &str,
    digest: &str,
) -> Result<Option<String>> {
    let mut view = DiskLookupFs { target_dir, digest };
    resolve_confined_path(rel_path, digest, ResolveMode::Lookup, &mut view)
}

fn resolve_confined_dir_lookup_send(
    entries_meta: &BTreeMap<String, EntryUnixMetadata>,
    rel_path: &str,
    digest: &str,
) -> Result<Option<String>> {
    let mut view = SendLookupFs { entries_meta };
    resolve_confined_path(rel_path, digest, ResolveMode::Lookup, &mut view)
}

fn apply_opaque_whiteout(
    target_dir: &Path,
    dir_rel: &str,
    digest: &str,
    created_in_layer: &BTreeSet<String>,
    entries_meta: &mut BTreeMap<String, EntryUnixMetadata>,
    restored_dir_modes: &mut BTreeMap<PathBuf, u32>,
) -> Result<()> {
    let Some(resolved_dir_rel) = resolve_confined_dir_lookup(target_dir, dir_rel, digest)? else {
        return Ok(());
    };
    let dir_path = if resolved_dir_rel.is_empty() {
        target_dir.to_path_buf()
    } else {
        target_dir.join(&resolved_dir_rel)
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
        record_and_make_writable(&dir_path, restored_dir_modes);
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
            let child_rel = join_rel(&resolved_dir_rel, &child_name);
            if !created_in_layer.contains(&child_rel) {
                remove_path_recursive(&child.path())?;
                remove_metadata_subtree(entries_meta, &child_rel);
            }
        }
    }
    // Also purge any metadata-only entries (such as special nodes) under `resolved_dir_rel`.
    let prefix = if resolved_dir_rel.is_empty() {
        String::new()
    } else {
        format!("{resolved_dir_rel}/")
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

struct DiskEnsureFs<'a> {
    target_dir: &'a Path,
    digest: &'a str,
    entries_meta: &'a mut BTreeMap<String, EntryUnixMetadata>,
    restored_dir_modes: &'a mut BTreeMap<PathBuf, u32>,
}

impl ConfinedFs for DiskEnsureFs<'_> {
    fn inspect(&mut self, rel: &str) -> Result<PathNode> {
        inspect_disk_node(self.target_dir, rel, self.digest)
    }

    fn replace_with_dir(&mut self, cand: &str, was_other: bool) -> Result<()> {
        let full = self.target_dir.join(cand);
        if was_other {
            remove_path_recursive(&full)?;
            remove_metadata_subtree(self.entries_meta, cand);
        }
        fs::create_dir(&full).map_err(|source| OciError::Io {
            operation: "create implicit parent directory",
            path: full.clone(),
            source,
        })?;
        set_writable_for_unpack(&full);
        self.entries_meta
            .entry(cand.to_owned())
            .or_insert_with(default_dir_meta);
        Ok(())
    }

    fn on_dir_visited(&mut self, cand: &str) -> Result<()> {
        let full = self.target_dir.join(cand);
        record_and_make_writable(&full, self.restored_dir_modes);
        self.entries_meta
            .entry(cand.to_owned())
            .or_insert_with(default_dir_meta);
        Ok(())
    }
}

struct SendEnsureFs<'a> {
    builder: &'a mut BtrfsSendBuilder,
    entries_meta: &'a mut BTreeMap<String, EntryUnixMetadata>,
    created_in_layer: &'a mut BTreeSet<String>,
}

impl ConfinedFs for SendEnsureFs<'_> {
    fn inspect(&mut self, rel: &str) -> Result<PathNode> {
        Ok(inspect_send_node(self.entries_meta, rel))
    }

    fn replace_with_dir(&mut self, cand: &str, was_other: bool) -> Result<()> {
        if was_other {
            emit_remove_subtree_send(self.builder, self.entries_meta, cand)?;
        }
        self.builder.mkdir(cand)?;
        self.entries_meta
            .insert(cand.to_owned(), default_dir_meta());
        self.created_in_layer.insert(cand.to_owned());
        Ok(())
    }

    fn on_dir_visited(&mut self, _rel: &str) -> Result<()> {
        Ok(())
    }
}

fn default_dir_meta() -> EntryUnixMetadata {
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
    }
}

fn ensure_parent_dirs(
    target_dir: &Path,
    parent_rel: &str,
    digest: &str,
    entries_meta: &mut BTreeMap<String, EntryUnixMetadata>,
    restored_dir_modes: &mut BTreeMap<PathBuf, u32>,
) -> Result<String> {
    let mut view = DiskEnsureFs {
        target_dir,
        digest,
        entries_meta,
        restored_dir_modes,
    };
    let resolved = resolve_confined_path(parent_rel, digest, ResolveMode::EnsureDirs, &mut view)?;
    Ok(resolved.unwrap_or_default())
}

fn ensure_parent_dirs_send(
    builder: &mut BtrfsSendBuilder,
    parent_rel: &str,
    digest: &str,
    entries_meta: &mut BTreeMap<String, EntryUnixMetadata>,
    created_in_layer: &mut BTreeSet<String>,
) -> Result<String> {
    let mut view = SendEnsureFs {
        builder,
        entries_meta,
        created_in_layer,
    };
    let resolved = resolve_confined_path(parent_rel, digest, ResolveMode::EnsureDirs, &mut view)?;
    Ok(resolved.unwrap_or_default())
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
///
/// Preserves directory modes, Unix ownership, extended attributes, and hardlinks across the
/// copied tree while keeping directories writable during traversal and applying final directory
/// modes in reverse depth order at the end.
pub fn copy_tree_recursive(src: &Path, dst: &Path) -> Result<()> {
    let mut hardlinks: HashMap<(u64, u64), PathBuf> = HashMap::new();
    let mut deferred_dirs: Vec<DeferredDirMode> = Vec::new();
    copy_tree_inner(src, dst, &mut hardlinks, &mut deferred_dirs)?;
    deferred_dirs.sort_by_key(|dir| std::cmp::Reverse(dir.path.as_os_str().len()));
    for dir in deferred_dirs {
        apply_unix_metadata(&dir.path, dir.uid, dir.gid, dir.mode, &dir.xattrs, false)?;
    }
    Ok(())
}

struct RawUnixMetadata {
    uid: u32,
    gid: u32,
    mode: u32,
    xattrs: BTreeMap<String, Vec<u8>>,
}

fn copy_tree_inner(
    src: &Path,
    dst: &Path,
    hardlinks: &mut HashMap<(u64, u64), PathBuf>,
    deferred_dirs: &mut Vec<DeferredDirMode>,
) -> Result<()> {
    let src_dir_meta = fs::symlink_metadata(src).map_err(|source| OciError::Io {
        operation: "stat source directory",
        path: src.to_path_buf(),
        source,
    })?;
    let dir_meta = read_unix_metadata(src, &src_dir_meta)?;

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
            let raw_meta = read_unix_metadata(&src_path, &meta)?;
            apply_unix_metadata(
                &dst_path,
                raw_meta.uid,
                raw_meta.gid,
                raw_meta.mode,
                &raw_meta.xattrs,
                true,
            )?;
        } else if meta.is_dir() {
            copy_tree_inner(&src_path, &dst_path, hardlinks, deferred_dirs)?;
        } else if meta.is_file() {
            #[cfg(unix)]
            let file_id = {
                use std::os::unix::fs::MetadataExt as _;
                (meta.nlink() > 1).then(|| (meta.dev(), meta.ino()))
            };
            #[cfg(not(unix))]
            let file_id: Option<(u64, u64)> = None;

            if let Some(id) = file_id
                && let Some(existing_dst) = hardlinks.get(&id)
            {
                fs::hard_link(existing_dst, &dst_path).map_err(|source| OciError::Io {
                    operation: "preserve hard link during tree copy",
                    path: dst_path.clone(),
                    source,
                })?;
                continue;
            }

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
            drop(dst_file);

            let raw_meta = read_unix_metadata(&src_path, &meta)?;
            apply_unix_metadata(
                &dst_path,
                raw_meta.uid,
                raw_meta.gid,
                raw_meta.mode,
                &raw_meta.xattrs,
                false,
            )?;
            if let Some(id) = file_id {
                hardlinks.insert(id, dst_path);
            }
        }
    }

    deferred_dirs.push(DeferredDirMode {
        path: dst.to_path_buf(),
        uid: dir_meta.uid,
        gid: dir_meta.gid,
        mode: dir_meta.mode,
        xattrs: dir_meta.xattrs,
    });
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

fn record_and_make_writable(path: &Path, restored_dir_modes: &mut BTreeMap<PathBuf, u32>) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if let Ok(meta) = fs::symlink_metadata(path)
            && !meta.file_type().is_symlink()
            && meta.is_dir()
        {
            let orig_mode = meta.permissions().mode() & 0o7777;
            restored_dir_modes
                .entry(path.to_path_buf())
                .or_insert(orig_mode);
            let writable = orig_mode | 0o700;
            if writable != orig_mode {
                let _ = fs::set_permissions(path, fs::Permissions::from_mode(writable));
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (path, restored_dir_modes);
    }
}

fn restore_mode_best_effort(path: &Path, mode: u32) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if let Err(err) = fs::set_permissions(path, fs::Permissions::from_mode(mode & 0o7777))
            && !is_ignorable_metadata_error(&err)
        {
            return Err(OciError::Io {
                operation: "restore directory permissions",
                path: path.to_path_buf(),
                source: err,
            });
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
    }
    Ok(())
}

pub(crate) fn set_writable_for_unpack(path: &Path) {
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

#[cfg(unix)]
fn is_ignorable_metadata_error(err: &io::Error) -> bool {
    if matches!(
        err.kind(),
        io::ErrorKind::PermissionDenied | io::ErrorKind::Unsupported
    ) {
        return true;
    }
    match err.raw_os_error() {
        Some(raw) => {
            raw == libc::EPERM
                || raw == libc::EACCES
                || raw == libc::ENOTSUP
                || raw == libc::EOPNOTSUPP
                || raw == libc::ENOSYS
                || raw == libc::EROFS
        }
        None => false,
    }
}

#[cfg(unix)]
fn is_missing_xattr_error(err: &io::Error) -> bool {
    let Some(raw) = err.raw_os_error() else {
        return false;
    };
    #[cfg(target_os = "linux")]
    {
        raw == libc::ENODATA
    }
    #[cfg(target_os = "macos")]
    {
        raw == libc::ENOATTR
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = raw;
        false
    }
}

fn read_unix_metadata(path: &Path, meta: &fs::Metadata) -> Result<RawUnixMetadata> {
    #[cfg(unix)]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt as _;
        use std::os::unix::fs::MetadataExt as _;

        let uid = meta.uid();
        let gid = meta.gid();
        let mode = meta.mode() & 0o7777;
        let mut xattrs = BTreeMap::new();

        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            let c_path = CString::new(path.as_os_str().as_bytes()).map_err(|_| OciError::Io {
                operation: "encode path for xattr read",
                path: path.to_path_buf(),
                source: io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL byte"),
            })?;
            let names_buf = read_xattr_name_list(&c_path, path)?;
            for raw_name in names_buf.split(|b| *b == 0).filter(|s| !s.is_empty()) {
                let Ok(name_str) = core::str::from_utf8(raw_name) else {
                    continue;
                };
                let Ok(c_name) = CString::new(raw_name) else {
                    continue;
                };
                if let Some(value) = read_xattr_value(&c_path, &c_name, path)? {
                    xattrs.insert(name_str.to_owned(), value);
                }
            }
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        let _ = path;

        Ok(RawUnixMetadata {
            uid,
            gid,
            mode,
            xattrs,
        })
    }
    #[cfg(not(unix))]
    {
        let _ = (path, meta);
        Ok(RawUnixMetadata {
            uid: 0,
            gid: 0,
            mode: 0o644,
            xattrs: BTreeMap::new(),
        })
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn read_xattr_name_list(c_path: &std::ffi::CStr, path: &Path) -> Result<Vec<u8>> {
    loop {
        let len = {
            #[cfg(target_os = "linux")]
            {
                // SAFETY: `c_path` is a valid NUL-terminated C string and null buffer queries length.
                unsafe { libc::llistxattr(c_path.as_ptr(), core::ptr::null_mut(), 0) }
            }
            #[cfg(target_os = "macos")]
            {
                // SAFETY: `c_path` is a valid NUL-terminated C string and null buffer queries length.
                unsafe {
                    libc::listxattr(
                        c_path.as_ptr(),
                        core::ptr::null_mut(),
                        0,
                        libc::XATTR_NOFOLLOW,
                    )
                }
            }
        };
        if len < 0 {
            let err = io::Error::last_os_error();
            if is_ignorable_metadata_error(&err) {
                return Ok(Vec::new());
            }
            return Err(OciError::Io {
                operation: "list extended attributes",
                path: path.to_path_buf(),
                source: err,
            });
        }
        if len == 0 {
            return Ok(Vec::new());
        }
        let mut buf = vec![0u8; len as usize];
        let actual = {
            #[cfg(target_os = "linux")]
            {
                // SAFETY: `c_path` is valid and `buf` is writable for `buf.len()` bytes.
                unsafe { libc::llistxattr(c_path.as_ptr(), buf.as_mut_ptr().cast(), buf.len()) }
            }
            #[cfg(target_os = "macos")]
            {
                // SAFETY: `c_path` is valid and `buf` is writable for `buf.len()` bytes.
                unsafe {
                    libc::listxattr(
                        c_path.as_ptr(),
                        buf.as_mut_ptr().cast(),
                        buf.len(),
                        libc::XATTR_NOFOLLOW,
                    )
                }
            }
        };
        if actual < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ERANGE) {
                continue;
            }
            if is_ignorable_metadata_error(&err) {
                return Ok(Vec::new());
            }
            return Err(OciError::Io {
                operation: "read extended attribute names",
                path: path.to_path_buf(),
                source: err,
            });
        }
        buf.truncate(actual as usize);
        return Ok(buf);
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn read_xattr_value(
    c_path: &std::ffi::CStr,
    c_name: &std::ffi::CStr,
    path: &Path,
) -> Result<Option<Vec<u8>>> {
    loop {
        let len = {
            #[cfg(target_os = "linux")]
            {
                // SAFETY: `c_path` and `c_name` are valid C strings; null buffer queries value length.
                unsafe {
                    libc::lgetxattr(c_path.as_ptr(), c_name.as_ptr(), core::ptr::null_mut(), 0)
                }
            }
            #[cfg(target_os = "macos")]
            {
                // SAFETY: `c_path` and `c_name` are valid C strings; null buffer queries value length.
                unsafe {
                    libc::getxattr(
                        c_path.as_ptr(),
                        c_name.as_ptr(),
                        core::ptr::null_mut(),
                        0,
                        0,
                        libc::XATTR_NOFOLLOW,
                    )
                }
            }
        };
        if len < 0 {
            let err = io::Error::last_os_error();
            if is_missing_xattr_error(&err) || is_ignorable_metadata_error(&err) {
                return Ok(None);
            }
            return Err(OciError::Io {
                operation: "query extended attribute length",
                path: path.to_path_buf(),
                source: err,
            });
        }
        let mut buf = vec![0u8; len as usize];
        let actual = {
            #[cfg(target_os = "linux")]
            {
                // SAFETY: `c_path` and `c_name` are valid C strings and `buf` holds `buf.len()` bytes.
                unsafe {
                    libc::lgetxattr(
                        c_path.as_ptr(),
                        c_name.as_ptr(),
                        buf.as_mut_ptr().cast(),
                        buf.len(),
                    )
                }
            }
            #[cfg(target_os = "macos")]
            {
                // SAFETY: `c_path` and `c_name` are valid C strings and `buf` holds `buf.len()` bytes.
                unsafe {
                    libc::getxattr(
                        c_path.as_ptr(),
                        c_name.as_ptr(),
                        buf.as_mut_ptr().cast(),
                        buf.len(),
                        0,
                        libc::XATTR_NOFOLLOW,
                    )
                }
            }
        };
        if actual < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ERANGE) {
                continue;
            }
            if is_missing_xattr_error(&err) || is_ignorable_metadata_error(&err) {
                return Ok(None);
            }
            return Err(OciError::Io {
                operation: "read extended attribute value",
                path: path.to_path_buf(),
                source: err,
            });
        }
        buf.truncate(actual as usize);
        return Ok(Some(buf));
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
) -> Result<()> {
    #[cfg(unix)]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt as _;
        use std::os::unix::fs::PermissionsExt as _;

        let c_path = CString::new(path.as_os_str().as_bytes()).map_err(|_| OciError::Io {
            operation: "encode path for unix metadata",
            path: path.to_path_buf(),
            source: io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL byte"),
        })?;

        // Best-effort lchown (succeeds as root; unprivileged host processes lack CAP_CHOWN
        // while full uid/gid remain captured in `LayerMetadataIndex` and btrfs send streams).
        // SAFETY: `c_path` is a valid NUL-terminated C string.
        let chown_rc = unsafe { libc::lchown(c_path.as_ptr(), uid, gid) };
        if chown_rc != 0 {
            let err = io::Error::last_os_error();
            if !is_ignorable_metadata_error(&err) {
                return Err(OciError::Io {
                    operation: "set file ownership",
                    path: path.to_path_buf(),
                    source: err,
                });
            }
        }

        // Best-effort xattr application (e.g. `security.capability`, `user.*`).
        for (name, value) in xattrs {
            let c_name = CString::new(name.as_bytes()).map_err(|_| OciError::Io {
                operation: "encode xattr name",
                path: path.to_path_buf(),
                source: io::Error::new(io::ErrorKind::InvalidInput, "xattr name contains NUL byte"),
            })?;
            #[cfg(target_os = "linux")]
            {
                // SAFETY: `c_path`, `c_name`, and `value` slice pointers are valid for the call.
                let rc = unsafe {
                    libc::lsetxattr(
                        c_path.as_ptr(),
                        c_name.as_ptr(),
                        value.as_ptr().cast(),
                        value.len(),
                        0,
                    )
                };
                if rc != 0 {
                    let err = io::Error::last_os_error();
                    if !is_ignorable_metadata_error(&err) {
                        return Err(OciError::Io {
                            operation: "set extended attribute",
                            path: path.to_path_buf(),
                            source: err,
                        });
                    }
                }
            }
            #[cfg(target_os = "macos")]
            {
                // SAFETY: `c_path`, `c_name`, and `value` slice pointers are valid for the call.
                let rc = unsafe {
                    libc::setxattr(
                        c_path.as_ptr(),
                        c_name.as_ptr(),
                        value.as_ptr().cast(),
                        value.len(),
                        0,
                        libc::XATTR_NOFOLLOW,
                    )
                };
                if rc != 0 {
                    let err = io::Error::last_os_error();
                    if !is_ignorable_metadata_error(&err) {
                        return Err(OciError::Io {
                            operation: "set extended attribute",
                            path: path.to_path_buf(),
                            source: err,
                        });
                    }
                }
            }
            #[cfg(not(any(target_os = "linux", target_os = "macos")))]
            {
                let _ = (c_name, value);
            }
        }

        if !is_symlink {
            // Apply mode AFTER chown so setuid/setgid bits are not cleared by the OS kernel.
            if let Err(err) = fs::set_permissions(path, fs::Permissions::from_mode(mode & 0o7777))
                && !is_ignorable_metadata_error(&err)
            {
                return Err(OciError::Io {
                    operation: "set file permissions",
                    path: path.to_path_buf(),
                    source: err,
                });
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (path, uid, gid, mode, xattrs, is_symlink);
    }
    Ok(())
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

    #[test]
    fn rejects_whiteout_traversal_without_touching_parent_or_siblings() {
        let outer = TempDir::new().unwrap();
        let parent_keep = outer.path().join("keep_parent.txt");
        fs::write(&parent_keep, b"must-survive").unwrap();

        let layer_root = outer.path().join("layer");
        fs::create_dir_all(layer_root.join("sub")).unwrap();
        let sibling = layer_root.join("sibling.txt");
        let sub_keep = layer_root.join("sub/keep.txt");
        fs::write(&sibling, b"sibling-survives").unwrap();
        fs::write(&sub_keep, b"sub-survives").unwrap();

        let mut parent_entries = BTreeMap::new();
        parent_entries.insert(
            "sub".to_owned(),
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
        parent_entries.insert(
            "sub/keep.txt".to_owned(),
            EntryUnixMetadata {
                kind: NodeKind::File,
                uid: 0,
                gid: 0,
                mode: 0o644,
                mtime: None,
                link_target: None,
                device_major: None,
                device_minor: None,
                xattrs: BTreeMap::new(),
            },
        );

        for bad_whiteout in [
            ".wh...",
            ".wh..",
            ".wh.",
            "sub/.wh...",
            "sub/.wh..",
            ".wh.a\\b",
        ] {
            let mut tar = tar::Builder::new(Vec::new());
            append_file(&mut tar, bad_whiteout, b"");
            let bytes = tar.into_inner().unwrap();

            let err = unpack_layer_into_dir(
                bytes.as_slice(),
                &layer_root,
                "sha256:test",
                Some(&parent_entries),
            )
            .unwrap_err();
            assert!(
                matches!(err, OciError::UnsafePath { .. }),
                "unpack expected UnsafePath for {bad_whiteout}, got {err:?}"
            );

            let send_err = encode_layer_as_btrfs_send(
                bytes.as_slice(),
                "layer1",
                [0x11; 16],
                1,
                None,
                "sha256:test",
                Some(&parent_entries),
            )
            .unwrap_err();
            assert!(
                matches!(send_err, OciError::UnsafePath { .. }),
                "btrfs send expected UnsafePath for {bad_whiteout}, got {send_err:?}"
            );
        }

        assert_eq!(fs::read(&parent_keep).unwrap(), b"must-survive");
        assert_eq!(fs::read(&sibling).unwrap(), b"sibling-survives");
        assert_eq!(fs::read(&sub_keep).unwrap(), b"sub-survives");
    }

    #[test]
    fn enforces_entry_and_byte_limits_in_unpack_and_btrfs_send() {
        let mut tar = tar::Builder::new(Vec::new());
        append_dir(&mut tar, "etc");
        append_file(&mut tar, "etc/a.bin", &[b'a'; 60]);
        append_file(&mut tar, "etc/b.bin", &[b'b'; 60]);
        let bytes = tar.into_inner().unwrap();

        let dir1 = TempDir::new().unwrap();
        let entry_err = unpack_layer_into_dir_with_limits(
            bytes.as_slice(),
            dir1.path(),
            "sha256:test",
            None,
            LayerLimits {
                max_bytes: 1024,
                max_entries: 2,
            },
        )
        .unwrap_err();
        assert!(
            matches!(
                entry_err,
                OciError::LayerTooLarge {
                    kind: "entry count",
                    ..
                }
            ),
            "got {entry_err:?}"
        );

        let dir2 = TempDir::new().unwrap();
        let byte_err = unpack_layer_into_dir_with_limits(
            bytes.as_slice(),
            dir2.path(),
            "sha256:test",
            None,
            LayerLimits {
                max_bytes: 100,
                max_entries: 100,
            },
        )
        .unwrap_err();
        assert!(
            matches!(
                byte_err,
                OciError::LayerTooLarge {
                    kind: "uncompressed byte",
                    ..
                }
            ),
            "got {byte_err:?}"
        );

        let send_entry_err = encode_layer_as_btrfs_send_with_limits(
            bytes.as_slice(),
            "l0",
            [0x22; 16],
            1,
            None,
            "sha256:test",
            None,
            LayerLimits {
                max_bytes: 64 * 1024,
                max_entries: 2,
            },
        )
        .unwrap_err();
        assert!(matches!(
            send_entry_err,
            OciError::LayerTooLarge {
                kind: "entry count",
                ..
            }
        ));

        let send_byte_err = encode_layer_as_btrfs_send_with_limits(
            bytes.as_slice(),
            "l0",
            [0x22; 16],
            1,
            None,
            "sha256:test",
            None,
            LayerLimits {
                max_bytes: 100,
                max_entries: 100,
            },
        )
        .unwrap_err();
        assert!(matches!(send_byte_err, OciError::LayerTooLarge { .. }));
    }

    #[test]
    fn allows_confined_usrmerge_symlinks_and_rejects_escapes_and_loops() {
        let layer_root = TempDir::new().unwrap();

        let mut base = tar::Builder::new(Vec::new());
        append_dir(&mut base, "usr");
        append_dir(&mut base, "usr/bin");
        append_dir(&mut base, "usr/lib");
        append_file(&mut base, "usr/bin/old", b"old-tool");
        append_file(&mut base, "usr/lib/base.so", b"base-lib");
        append_symlink(&mut base, "bin", "usr/bin");
        append_symlink(&mut base, "lib", "/usr/lib");
        let base_bytes = base.into_inner().unwrap();

        let base_meta =
            unpack_layer_into_dir(base_bytes.as_slice(), layer_root.path(), "sha256:l0", None)
                .expect("unpack base usrmerge layer");

        let mut child = tar::Builder::new(Vec::new());
        append_file(&mut child, "bin/.wh.old", b"");
        append_file(&mut child, "bin/tool", b"new-tool");
        append_file(&mut child, "bin/sub/nested", b"nested-tool");
        append_file(&mut child, "lib/libc.so.6", b"libc");
        append_hardlink(&mut child, "bin/tool-alias", "bin/tool");
        let child_bytes = child.into_inner().unwrap();

        let child_meta = unpack_layer_into_dir(
            child_bytes.as_slice(),
            layer_root.path(),
            "sha256:l1",
            Some(&base_meta),
        )
        .expect("unpack child layer through confined usrmerge symlinks");

        assert!(!layer_root.path().join("usr/bin/old").exists());
        assert!(!child_meta.contains_key("usr/bin/old"));
        assert_eq!(
            fs::read(layer_root.path().join("usr/bin/tool")).unwrap(),
            b"new-tool"
        );
        assert_eq!(
            fs::read(layer_root.path().join("usr/bin/sub/nested")).unwrap(),
            b"nested-tool"
        );
        assert_eq!(
            fs::read(layer_root.path().join("usr/lib/libc.so.6")).unwrap(),
            b"libc"
        );
        assert_eq!(
            fs::read(layer_root.path().join("usr/bin/tool-alias")).unwrap(),
            b"new-tool"
        );
        assert!(child_meta.contains_key("usr/bin/tool"));
        assert!(child_meta.contains_key("usr/bin/sub/nested"));
        assert!(child_meta.contains_key("usr/lib/libc.so.6"));

        // Btrfs send stream encoder handles the identical usrmerge sequence without clobbering symlinks.
        let (_s0, send_base_meta) = encode_layer_as_btrfs_send(
            base_bytes.as_slice(),
            "l0",
            [0x10; 16],
            1,
            None,
            "sha256:l0",
            None,
        )
        .unwrap();
        let (_s1, send_child_meta) = encode_layer_as_btrfs_send(
            child_bytes.as_slice(),
            "l1",
            [0x11; 16],
            2,
            Some(ParentSubvolumeRef {
                uuid: [0x10; 16],
                ctransid: 1,
            }),
            "sha256:l1",
            Some(&send_base_meta),
        )
        .unwrap();
        assert!(!send_child_meta.contains_key("usr/bin/old"));
        assert!(send_child_meta.contains_key("usr/bin/tool"));
        assert!(send_child_meta.contains_key("usr/lib/libc.so.6"));

        // Relative escape above `target_dir` must be rejected in both unpack and send stream.
        let outside = TempDir::new().unwrap();
        let victim = outside.path().join("victim.txt");
        fs::write(&victim, b"safe").unwrap();
        let escape_root = TempDir::new().unwrap();

        let mut rel_escape = tar::Builder::new(Vec::new());
        append_symlink(&mut rel_escape, "escape", "../../outside");
        append_file(&mut rel_escape, "escape/injected", b"pwn");
        let rel_escape_bytes = rel_escape.into_inner().unwrap();
        let err = unpack_layer_into_dir(
            rel_escape_bytes.as_slice(),
            escape_root.path(),
            "sha256:esc",
            None,
        )
        .unwrap_err();
        assert!(matches!(err, OciError::UnsafePath { .. }), "got {err:?}");
        let send_err = encode_layer_as_btrfs_send(
            rel_escape_bytes.as_slice(),
            "esc",
            [0x33; 16],
            1,
            None,
            "sha256:esc",
            None,
        )
        .unwrap_err();
        assert!(
            matches!(send_err, OciError::UnsafePath { .. }),
            "got {send_err:?}"
        );

        // Symlink loop (> 40 hops) must be rejected cleanly with UnsafePath.
        let loop_root = TempDir::new().unwrap();
        let mut loop_tar = tar::Builder::new(Vec::new());
        append_symlink(&mut loop_tar, "a", "b");
        append_symlink(&mut loop_tar, "b", "a");
        append_file(&mut loop_tar, "a/file", b"never");
        let loop_bytes = loop_tar.into_inner().unwrap();
        let loop_err =
            unpack_layer_into_dir(loop_bytes.as_slice(), loop_root.path(), "sha256:loop", None)
                .unwrap_err();
        assert!(
            matches!(loop_err, OciError::UnsafePath { .. }),
            "got {loop_err:?}"
        );
    }

    #[test]
    fn copy_tree_recursive_preserves_dir_modes_and_hardlinks() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let src = TempDir::new().unwrap();
        let dst_parent = TempDir::new().unwrap();
        let dst = dst_parent.path().join("copied");

        let ro_dir = src.path().join("ro_dir");
        let sgid_dir = src.path().join("sgid_dir");
        fs::create_dir_all(&ro_dir).unwrap();
        fs::create_dir_all(&sgid_dir).unwrap();

        let f1 = ro_dir.join("alpha.bin");
        let f2 = sgid_dir.join("alpha-link.bin");
        fs::write(&f1, b"shared-inode-bytes").unwrap();
        fs::hard_link(&f1, &f2).unwrap();
        fs::set_permissions(&f1, fs::Permissions::from_mode(0o444)).unwrap();
        fs::set_permissions(&sgid_dir, fs::Permissions::from_mode(0o2755)).unwrap();
        fs::set_permissions(&ro_dir, fs::Permissions::from_mode(0o555)).unwrap();

        copy_tree_recursive(src.path(), &dst).expect("copy tree with ro_dir and hardlinks");

        let dst_ro_meta = fs::symlink_metadata(dst.join("ro_dir")).unwrap();
        assert_eq!(dst_ro_meta.permissions().mode() & 0o7777, 0o555);
        let dst_sgid_meta = fs::symlink_metadata(dst.join("sgid_dir")).unwrap();
        assert_eq!(dst_sgid_meta.permissions().mode() & 0o7777, 0o2755);

        let dst_f1_meta = fs::symlink_metadata(dst.join("ro_dir/alpha.bin")).unwrap();
        let dst_f2_meta = fs::symlink_metadata(dst.join("sgid_dir/alpha-link.bin")).unwrap();
        assert_eq!(dst_f1_meta.ino(), dst_f2_meta.ino());
        assert_eq!(dst_f1_meta.nlink(), 2);

        make_tree_writable(&dst);
        make_tree_writable(src.path());
    }

    #[test]
    fn apply_unix_metadata_propagates_non_permission_io_errors() {
        let dir = TempDir::new().unwrap();
        let missing = dir.path().join("does-not-exist/file.txt");
        let err = apply_unix_metadata(&missing, 0, 0, 0o644, &BTreeMap::new(), false)
            .expect_err("ENOENT must surface as OciError::Io");
        assert!(matches!(
            err,
            OciError::Io { ref source, .. } if source.kind() == io::ErrorKind::NotFound
        ));
    }
}
