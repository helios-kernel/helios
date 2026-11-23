//! Capability-bounded btrfs volume management over mounted namespaces.
//!
//! Every entry point resolves guest paths inside the caller's grant floor,
//! derives the required typed capabilities from [`ProcessAuthority`], verifies
//! subvolume root boundaries (refusing narrower grants inside a subvolume),
//! and forwards to [`VolumeManagement`] on the mounted [`BtrfsFs`].

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use helios_hal::fs::{BlockSerial, FileSystemRights, FsPath};
use helios_hal::fs_management::{
    BalanceFilter, BalanceReport, DedupeOutcome, QgroupId, QgroupInfo, QgroupLimit, QuotaStatus,
    ResizeTarget, ScrubReport, SubvolumeInfo, VolumeDeviceInfo, VolumeManagement,
    VolumeManagementError,
};
use thiserror::Error;

use super::{AttachedStorage, BtrfsFs, Follow, MountedFs, Namespace, Resolved, Storage};
use crate::{
    DirectoryAuthorityRights, ProcessAuthority, ProcessAuthorityError, resolve_absolute_path,
};

/// Errors produced by capability-gated btrfs volume management operations.
#[derive(Debug, Error)]
pub enum BtrfsManagementError {
    #[error("caller lacks authority for btrfs management: {0}")]
    Authority(#[from] ProcessAuthorityError),
    #[error(transparent)]
    Volume(#[from] VolumeManagementError),
    #[error("{0:?} is not on a btrfs mount")]
    NotBtrfs(String),
    #[error("source and destination are not on the same btrfs mount")]
    CrossDevice,
    #[error("invalid path {0:?}")]
    InvalidPath(String),
    #[error("mount is read-only")]
    ReadOnlyMount,
    #[error("invalid block device serial {0:?}")]
    InvalidSerial(String),
    #[error("no mount-source disk reported the serial {serial:?}")]
    DiskUnavailable { serial: BlockSerial },
    #[error("disk {serial:?} is read-only")]
    ReadOnlyDisk { serial: BlockSerial },
}

/// Shared execution context for btrfs volume management calls.
pub struct BtrfsVolumeRequest<'a, S: Storage> {
    pub authority: &'a ProcessAuthority,
    pub namespace: &'a Namespace<S>,
    pub attached: AttachedStorage<S>,
    pub now: u64,
}

fn join_abs(base: &str, rel: &str) -> String {
    if rel.is_empty() {
        String::from(base)
    } else if base == "/" {
        format!("/{rel}")
    } else {
        format!("{base}/{rel}")
    }
}

fn join_rel(parent: &str, name: &str) -> String {
    if parent.is_empty() {
        String::from(name)
    } else {
        format!("{parent}/{name}")
    }
}

fn normalize_abs(path: &str) -> Result<String, BtrfsManagementError> {
    resolve_absolute_path(path).map_err(|_| BtrfsManagementError::InvalidPath(String::from(path)))
}

fn split_parent_child(abs: &str) -> Result<(&str, &str), BtrfsManagementError> {
    if abs == "/" {
        return Err(BtrfsManagementError::InvalidPath(String::from(abs)));
    }
    let (parent, name) = abs
        .rsplit_once('/')
        .ok_or_else(|| BtrfsManagementError::InvalidPath(String::from(abs)))?;
    let parent = if parent.is_empty() { "/" } else { parent };
    if name.is_empty() || name == "." || name == ".." || name.contains('/') {
        return Err(BtrfsManagementError::InvalidPath(String::from(abs)));
    }
    Ok((parent, name))
}

fn require_btrfs<'a, S: Storage>(
    resolved: &'a Resolved<'a, S>,
) -> Result<&'a BtrfsFs<S::Disk>, BtrfsManagementError> {
    match resolved.fs() {
        MountedFs::Btrfs(btrfs) => Ok(btrfs),
        _ => Err(BtrfsManagementError::NotBtrfs(String::from(
            resolved.absolute(),
        ))),
    }
}

fn require_writable_mount<S: Storage>(
    resolved: &Resolved<'_, S>,
) -> Result<(), BtrfsManagementError> {
    if resolved.grant().rights.contains(FileSystemRights::WRITE) {
        Ok(())
    } else {
        Err(BtrfsManagementError::ReadOnlyMount)
    }
}

async fn resolve_normalized_with_rights<'a, S: Storage>(
    authority: &ProcessAuthority,
    namespace: &'a Namespace<S>,
    normalized: &'a str,
    rights: DirectoryAuthorityRights,
) -> Result<Resolved<'a, S>, BtrfsManagementError> {
    let floor = authority.directory_floor(normalized, rights).ok_or(
        ProcessAuthorityError::DirectoryGrantExceedsAuthority(rights),
    )?;
    let resolved = namespace
        .resolve_following(normalized, Follow::Within(floor))
        .await
        .map_err(|e| BtrfsManagementError::Volume(VolumeManagementError::Fs(e)))?;
    if authority
        .directory_floor(resolved.absolute(), rights)
        .is_none()
    {
        return Err(BtrfsManagementError::Authority(
            ProcessAuthorityError::DirectoryGrantExceedsAuthority(rights),
        ));
    }
    Ok(resolved)
}

fn require_device_serial_grant(
    authority: &ProcessAuthority,
    btrfs: &BtrfsFs<impl helios_hal::fs::BlockDevice<Buffer = crate::BlockPages>>,
    devid: u64,
) -> Result<(), BtrfsManagementError> {
    if let Some(serial) = btrfs.device_serial(devid) {
        let name = core::str::from_utf8(serial.as_bytes())
            .map_err(|_| BtrfsManagementError::InvalidSerial(String::new()))?;
        authority.derive_device_grant_cap(name)?;
    }
    Ok(())
}

impl<S: Storage> BtrfsVolumeRequest<'_, S> {
    /// Creates a new empty subvolume at `path`.
    ///
    /// Requires `MUTATE_DIRECTORY` at the parent directory.
    pub async fn create_subvolume(
        &self,
        path: &str,
    ) -> Result<SubvolumeInfo, BtrfsManagementError> {
        let normalized = normalize_abs(path)?;
        let (parent_abs, name) = split_parent_child(&normalized)?;
        let _cap = self.authority.derive_btrfs_subvol_create_cap(parent_abs)?;
        let parent_resolved = resolve_normalized_with_rights(
            self.authority,
            self.namespace,
            parent_abs,
            DirectoryAuthorityRights::MUTATE_DIRECTORY,
        )
        .await?;
        let _cap_resolved = self
            .authority
            .derive_btrfs_subvol_create_cap(parent_resolved.absolute())?;
        require_writable_mount(&parent_resolved)?;
        let btrfs = require_btrfs(&parent_resolved)?;
        let target_rel = join_rel(parent_resolved.path().as_str(), name);
        let rel = FsPath::new(&target_rel)
            .ok_or_else(|| BtrfsManagementError::InvalidPath(normalized.clone()))?;
        btrfs
            .create_subvolume(rel, self.now)
            .await
            .map_err(BtrfsManagementError::Volume)
    }

    /// Deletes the subvolume rooted at `path`.
    ///
    /// Requires `MUTATE_DIRECTORY` at the parent directory AND over the whole
    /// subvolume being removed.
    pub async fn delete_subvolume(&self, path: &str) -> Result<(), BtrfsManagementError> {
        let normalized = normalize_abs(path)?;
        let (parent_abs, name) = split_parent_child(&normalized)?;
        let _cap = self
            .authority
            .derive_btrfs_subvol_delete_cap(parent_abs, &normalized)?;
        let parent_resolved = resolve_normalized_with_rights(
            self.authority,
            self.namespace,
            parent_abs,
            DirectoryAuthorityRights::MUTATE_DIRECTORY,
        )
        .await?;
        require_writable_mount(&parent_resolved)?;
        let target_abs = join_abs(parent_resolved.absolute(), name);
        // Never follow a final symlink when deleting a subvolume.
        let target_resolved = self
            .namespace
            .resolve(&target_abs)
            .map_err(|e| BtrfsManagementError::Volume(VolumeManagementError::Fs(e)))?;
        if !parent_resolved.same_mount(&target_resolved) {
            return Err(BtrfsManagementError::CrossDevice);
        }
        let btrfs = require_btrfs(&target_resolved)?;
        let info = btrfs
            .subvolume_info(target_resolved.path())
            .await
            .map_err(BtrfsManagementError::Volume)?;
        let canonical_subvol = join_abs(target_resolved.mount_point(), &info.path);
        let _cap_canonical = self
            .authority
            .derive_btrfs_subvol_delete_cap(parent_resolved.absolute(), &canonical_subvol)?;
        btrfs
            .delete_subvolume(target_resolved.path(), self.now)
            .await
            .map_err(BtrfsManagementError::Volume)
    }

    /// Creates a snapshot of the subvolume rooted at `source` at `destination`.
    ///
    /// Requires `READ` over the WHOLE source subvolume root (refusing narrower
    /// grants inside the subvolume) and `MUTATE_DIRECTORY` at `destination`'s
    /// parent directory.
    pub async fn snapshot_subvolume(
        &self,
        source: &str,
        destination: &str,
        read_only: bool,
    ) -> Result<SubvolumeInfo, BtrfsManagementError> {
        let src_norm = normalize_abs(source)?;
        let dst_norm = normalize_abs(destination)?;
        let (dst_parent_abs, dst_name) = split_parent_child(&dst_norm)?;
        let _cap = self
            .authority
            .derive_btrfs_snapshot_cap(&src_norm, dst_parent_abs)?;

        let src_resolved = resolve_normalized_with_rights(
            self.authority,
            self.namespace,
            &src_norm,
            DirectoryAuthorityRights::READ,
        )
        .await?;
        let dst_parent_resolved = resolve_normalized_with_rights(
            self.authority,
            self.namespace,
            dst_parent_abs,
            DirectoryAuthorityRights::MUTATE_DIRECTORY,
        )
        .await?;
        if !src_resolved.same_mount(&dst_parent_resolved) {
            return Err(BtrfsManagementError::CrossDevice);
        }
        require_writable_mount(&dst_parent_resolved)?;
        let btrfs = require_btrfs(&src_resolved)?;
        let info = btrfs
            .subvolume_info(src_resolved.path())
            .await
            .map_err(BtrfsManagementError::Volume)?;
        let canonical_src = join_abs(src_resolved.mount_point(), &info.path);
        let _cap_canonical = self
            .authority
            .derive_btrfs_snapshot_cap(&canonical_src, dst_parent_resolved.absolute())?;

        let dst_rel_str = join_rel(dst_parent_resolved.path().as_str(), dst_name);
        let dst_rel = FsPath::new(&dst_rel_str)
            .ok_or_else(|| BtrfsManagementError::InvalidPath(dst_norm.clone()))?;
        btrfs
            .snapshot_subvolume(src_resolved.path(), dst_rel, read_only, self.now)
            .await
            .map_err(BtrfsManagementError::Volume)
    }

    /// Sets or clears the read-only flag on the subvolume rooted at `path`.
    ///
    /// Requires `MUTATE_DIRECTORY` over the whole subvolume root.
    pub async fn set_subvolume_read_only(
        &self,
        path: &str,
        read_only: bool,
    ) -> Result<(), BtrfsManagementError> {
        let normalized = normalize_abs(path)?;
        let _cap = self
            .authority
            .derive_btrfs_subvol_read_only_cap(&normalized)?;
        let resolved = resolve_normalized_with_rights(
            self.authority,
            self.namespace,
            &normalized,
            DirectoryAuthorityRights::MUTATE_DIRECTORY,
        )
        .await?;
        require_writable_mount(&resolved)?;
        let btrfs = require_btrfs(&resolved)?;
        let info = btrfs
            .subvolume_info(resolved.path())
            .await
            .map_err(BtrfsManagementError::Volume)?;
        let canonical = join_abs(resolved.mount_point(), &info.path);
        let _cap_canonical = self
            .authority
            .derive_btrfs_subvol_read_only_cap(&canonical)?;
        btrfs
            .set_subvolume_read_only(resolved.path(), read_only, self.now)
            .await
            .map_err(BtrfsManagementError::Volume)
    }

    /// Describes the subvolume rooted at `path` (`READ` over the subvolume root).
    pub async fn subvolume_info(&self, path: &str) -> Result<SubvolumeInfo, BtrfsManagementError> {
        let normalized = normalize_abs(path)?;
        let _cap = self.authority.derive_btrfs_subvol_read_cap(&normalized)?;
        let resolved = resolve_normalized_with_rights(
            self.authority,
            self.namespace,
            &normalized,
            DirectoryAuthorityRights::READ,
        )
        .await?;
        let btrfs = require_btrfs(&resolved)?;
        let info = btrfs
            .subvolume_info(resolved.path())
            .await
            .map_err(BtrfsManagementError::Volume)?;
        let canonical = join_abs(resolved.mount_point(), &info.path);
        let _cap_canonical = self.authority.derive_btrfs_subvol_read_cap(&canonical)?;
        Ok(info)
    }

    /// Lists every live subvolume in the btrfs volume mounted at `mount_point`.
    ///
    /// Requires `READ` over the whole mount point.
    pub async fn list_subvolumes(
        &self,
        mount_point: &str,
    ) -> Result<Vec<SubvolumeInfo>, BtrfsManagementError> {
        let normalized = normalize_abs(mount_point)?;
        let _cap = self.authority.derive_btrfs_subvol_read_cap(&normalized)?;
        let resolved = self
            .namespace
            .resolve(&normalized)
            .map_err(|e| BtrfsManagementError::Volume(VolumeManagementError::Fs(e)))?;
        if !resolved.is_mount_root() {
            return Err(BtrfsManagementError::InvalidPath(normalized.clone()));
        }
        let btrfs = require_btrfs(&resolved)?;
        btrfs
            .list_subvolumes()
            .await
            .map_err(BtrfsManagementError::Volume)
    }

    /// Produces a Linux-compatible btrfs send stream (v1) for `subvolume`,
    /// optionally incremental against `parent` and cloning from `clone_sources`.
    ///
    /// Requires `READ` over the whole `subvolume` root, `READ` over the whole
    /// `parent` subvolume root (if any), and `READ` over every clone source
    /// subvolume root.
    pub async fn send_subvolume(
        &self,
        subvolume: &str,
        parent: Option<&str>,
        clone_sources: &[String],
    ) -> Result<Vec<u8>, BtrfsManagementError> {
        let sub_norm = normalize_abs(subvolume)?;
        let parent_norm = match parent {
            Some(p) => Some(normalize_abs(p)?),
            None => None,
        };
        let mut clone_norms = Vec::with_capacity(clone_sources.len());
        for src in clone_sources {
            clone_norms.push(normalize_abs(src)?);
        }
        let clone_refs: Vec<&str> = clone_norms.iter().map(String::as_str).collect();
        let _cap =
            self.authority
                .derive_btrfs_send_cap(&sub_norm, parent_norm.as_deref(), &clone_refs)?;

        let sub_resolved = resolve_normalized_with_rights(
            self.authority,
            self.namespace,
            &sub_norm,
            DirectoryAuthorityRights::READ,
        )
        .await?;
        let btrfs = require_btrfs(&sub_resolved)?;
        let sub_info = btrfs
            .subvolume_info(sub_resolved.path())
            .await
            .map_err(BtrfsManagementError::Volume)?;
        let canonical_sub = join_abs(sub_resolved.mount_point(), &sub_info.path);
        let _ = self
            .authority
            .derive_btrfs_subvol_read_cap(&canonical_sub)?;

        let parent_rel = match parent_norm.as_deref() {
            Some(p) => {
                let p_res = resolve_normalized_with_rights(
                    self.authority,
                    self.namespace,
                    p,
                    DirectoryAuthorityRights::READ,
                )
                .await?;
                if !sub_resolved.same_mount(&p_res) {
                    return Err(BtrfsManagementError::CrossDevice);
                }
                let p_info = btrfs
                    .subvolume_info(p_res.path())
                    .await
                    .map_err(BtrfsManagementError::Volume)?;
                let canonical_p = join_abs(p_res.mount_point(), &p_info.path);
                let _ = self.authority.derive_btrfs_subvol_read_cap(&canonical_p)?;
                Some(String::from(p_res.path().as_str()))
            }
            None => None,
        };

        let mut clone_rels = Vec::with_capacity(clone_norms.len());
        for c in &clone_norms {
            let c_res = resolve_normalized_with_rights(
                self.authority,
                self.namespace,
                c,
                DirectoryAuthorityRights::READ,
            )
            .await?;
            if !sub_resolved.same_mount(&c_res) {
                return Err(BtrfsManagementError::CrossDevice);
            }
            let c_info = btrfs
                .subvolume_info(c_res.path())
                .await
                .map_err(BtrfsManagementError::Volume)?;
            let canonical_c = join_abs(c_res.mount_point(), &c_info.path);
            let _ = self.authority.derive_btrfs_subvol_read_cap(&canonical_c)?;
            clone_rels.push(String::from(c_res.path().as_str()));
        }

        let parent_fs = match parent_rel.as_deref() {
            Some(p) => {
                Some(FsPath::new(p).ok_or(BtrfsManagementError::InvalidPath(String::from(p)))?)
            }
            None => None,
        };
        let mut clone_fs = Vec::with_capacity(clone_rels.len());
        for rel in &clone_rels {
            clone_fs.push(
                FsPath::new(rel).ok_or_else(|| BtrfsManagementError::InvalidPath(rel.clone()))?,
            );
        }

        btrfs
            .send_subvolume(sub_resolved.path(), parent_fs, &clone_fs)
            .await
            .map_err(BtrfsManagementError::Volume)
    }

    /// Consumes a Linux-compatible btrfs send stream into `destination`.
    ///
    /// Requires `MUTATE_DIRECTORY` at `destination`, plus `READ` over the
    /// whole root of any source subvolume referenced by `SNAPSHOT` or `CLONE`
    /// commands in `stream`.
    pub async fn receive_subvolume(
        &self,
        destination: &str,
        stream: &[u8],
    ) -> Result<SubvolumeInfo, BtrfsManagementError> {
        let dst_norm = normalize_abs(destination)?;
        let _cap = self.authority.derive_btrfs_receive_cap(&dst_norm)?;
        let dst_resolved = resolve_normalized_with_rights(
            self.authority,
            self.namespace,
            &dst_norm,
            DirectoryAuthorityRights::MUTATE_DIRECTORY,
        )
        .await?;
        let _cap_resolved = self
            .authority
            .derive_btrfs_receive_cap(dst_resolved.absolute())?;
        require_writable_mount(&dst_resolved)?;
        let btrfs = require_btrfs(&dst_resolved)?;
        let mount_point = String::from(dst_resolved.mount_point());
        let authority = self.authority;
        btrfs
            .receive_subvolume(dst_resolved.path(), stream, self.now, |src_rel| {
                let abs = join_abs(&mount_point, src_rel.as_str());
                authority
                    .derive_btrfs_subvol_read_cap(&abs)
                    .map(|_| ())
                    .map_err(|_| VolumeManagementError::PermissionDenied)
            })
            .await
            .map_err(BtrfsManagementError::Volume)
    }

    /// Shares extents from `source` into `destination` (`READ` on source,
    /// `WRITE` on destination).
    pub async fn reflink(
        &self,
        source: &str,
        source_offset: u64,
        destination: &str,
        destination_offset: u64,
        length: u64,
    ) -> Result<(), BtrfsManagementError> {
        let src_norm = normalize_abs(source)?;
        let dst_norm = normalize_abs(destination)?;
        let _cap = self
            .authority
            .derive_btrfs_reflink_cap(&src_norm, &dst_norm)?;

        let src_resolved = resolve_normalized_with_rights(
            self.authority,
            self.namespace,
            &src_norm,
            DirectoryAuthorityRights::READ,
        )
        .await?;
        let dst_resolved = resolve_normalized_with_rights(
            self.authority,
            self.namespace,
            &dst_norm,
            DirectoryAuthorityRights::WRITE,
        )
        .await?;
        if !src_resolved.same_mount(&dst_resolved) {
            return Err(BtrfsManagementError::CrossDevice);
        }
        require_writable_mount(&dst_resolved)?;
        let _cap_resolved = self
            .authority
            .derive_btrfs_reflink_cap(src_resolved.absolute(), dst_resolved.absolute())?;
        let btrfs = require_btrfs(&dst_resolved)?;
        btrfs
            .reflink(
                src_resolved.path(),
                source_offset,
                dst_resolved.path(),
                destination_offset,
                length,
                self.now,
            )
            .await
            .map_err(BtrfsManagementError::Volume)
    }

    /// Deduplicates extents from `source` into `destination` if both ranges
    /// are byte-for-byte identical (`READ` on source, `WRITE` on destination).
    pub async fn dedupe(
        &self,
        source: &str,
        source_offset: u64,
        destination: &str,
        destination_offset: u64,
        length: u64,
    ) -> Result<DedupeOutcome, BtrfsManagementError> {
        let src_norm = normalize_abs(source)?;
        let dst_norm = normalize_abs(destination)?;
        let _cap = self
            .authority
            .derive_btrfs_dedupe_cap(&src_norm, &dst_norm)?;

        let src_resolved = resolve_normalized_with_rights(
            self.authority,
            self.namespace,
            &src_norm,
            DirectoryAuthorityRights::READ,
        )
        .await?;
        let dst_resolved = resolve_normalized_with_rights(
            self.authority,
            self.namespace,
            &dst_norm,
            DirectoryAuthorityRights::WRITE,
        )
        .await?;
        if !src_resolved.same_mount(&dst_resolved) {
            return Err(BtrfsManagementError::CrossDevice);
        }
        require_writable_mount(&dst_resolved)?;
        let _cap_resolved = self
            .authority
            .derive_btrfs_dedupe_cap(src_resolved.absolute(), dst_resolved.absolute())?;
        let btrfs = require_btrfs(&dst_resolved)?;
        btrfs
            .dedupe(
                src_resolved.path(),
                source_offset,
                dst_resolved.path(),
                destination_offset,
                length,
                self.now,
            )
            .await
            .map_err(BtrfsManagementError::Volume)
    }

    fn resolve_mount_admin_held(
        &self,
        mount_point: &str,
    ) -> Result<(BtrfsFs<S::Disk>, bool), BtrfsManagementError> {
        let cap = self.authority.derive_btrfs_mount_admin_cap(mount_point)?;
        let resolved = self
            .namespace
            .resolve(cap.point())
            .map_err(|e| BtrfsManagementError::Volume(VolumeManagementError::Fs(e)))?;
        if !resolved.is_mount_root() {
            return Err(BtrfsManagementError::InvalidPath(String::from(cap.point())));
        }
        let writable = resolved.grant().rights.contains(FileSystemRights::WRITE);
        let btrfs = require_btrfs(&resolved)?.clone();
        Ok((btrfs, writable))
    }

    pub async fn list_devices(
        &self,
        mount_point: &str,
    ) -> Result<Vec<VolumeDeviceInfo>, BtrfsManagementError> {
        let (btrfs, _) = self.resolve_mount_admin_held(mount_point)?;
        btrfs
            .list_devices()
            .await
            .map_err(BtrfsManagementError::Volume)
    }

    pub async fn add_device(
        &self,
        mount_point: &str,
        device: &str,
    ) -> Result<VolumeDeviceInfo, BtrfsManagementError> {
        let _cap = self
            .authority
            .derive_btrfs_device_admin_cap(mount_point, device)?;
        let (btrfs, writable) = self.resolve_mount_admin_held(mount_point)?;
        if !writable {
            return Err(BtrfsManagementError::ReadOnlyMount);
        }
        let serial = BlockSerial::new(device.as_bytes())
            .ok_or_else(|| BtrfsManagementError::InvalidSerial(String::from(device)))?;
        let disk = self
            .attached
            .disks
            .as_ref()
            .and_then(|disks| disks.disk_by_serial(serial.as_bytes()))
            .ok_or(BtrfsManagementError::DiskUnavailable { serial })?;
        if disk.is_read_only() {
            return Err(BtrfsManagementError::ReadOnlyDisk { serial });
        }
        btrfs
            .add_device(disk, self.now)
            .await
            .map_err(BtrfsManagementError::Volume)
    }

    pub async fn remove_device(
        &self,
        mount_point: &str,
        devid: u64,
    ) -> Result<(), BtrfsManagementError> {
        let (btrfs, writable) = self.resolve_mount_admin_held(mount_point)?;
        require_device_serial_grant(self.authority, &btrfs, devid)?;
        if !writable {
            return Err(BtrfsManagementError::ReadOnlyMount);
        }
        btrfs
            .remove_device(devid, self.now)
            .await
            .map_err(BtrfsManagementError::Volume)
    }

    pub async fn replace_device(
        &self,
        mount_point: &str,
        source_devid: u64,
        target_device: &str,
    ) -> Result<VolumeDeviceInfo, BtrfsManagementError> {
        let _cap = self
            .authority
            .derive_btrfs_device_admin_cap(mount_point, target_device)?;
        let (btrfs, writable) = self.resolve_mount_admin_held(mount_point)?;
        require_device_serial_grant(self.authority, &btrfs, source_devid)?;
        if !writable {
            return Err(BtrfsManagementError::ReadOnlyMount);
        }
        let serial = BlockSerial::new(target_device.as_bytes())
            .ok_or_else(|| BtrfsManagementError::InvalidSerial(String::from(target_device)))?;
        let target = self
            .attached
            .disks
            .as_ref()
            .and_then(|disks| disks.disk_by_serial(serial.as_bytes()))
            .ok_or(BtrfsManagementError::DiskUnavailable { serial })?;
        if target.is_read_only() {
            return Err(BtrfsManagementError::ReadOnlyDisk { serial });
        }
        btrfs
            .replace_device(source_devid, target, self.now)
            .await
            .map_err(BtrfsManagementError::Volume)
    }

    pub async fn resize_device(
        &self,
        mount_point: &str,
        devid: Option<u64>,
        target: ResizeTarget,
    ) -> Result<VolumeDeviceInfo, BtrfsManagementError> {
        let (btrfs, writable) = self.resolve_mount_admin_held(mount_point)?;
        if let Some(id) = devid {
            require_device_serial_grant(self.authority, &btrfs, id)?;
        }
        if !writable {
            return Err(BtrfsManagementError::ReadOnlyMount);
        }
        btrfs
            .resize_device(devid, target, self.now)
            .await
            .map_err(BtrfsManagementError::Volume)
    }

    pub async fn balance(
        &self,
        mount_point: &str,
        filter: BalanceFilter,
    ) -> Result<BalanceReport, BtrfsManagementError> {
        let (btrfs, writable) = self.resolve_mount_admin_held(mount_point)?;
        if !writable {
            return Err(BtrfsManagementError::ReadOnlyMount);
        }
        btrfs
            .balance(filter, self.now)
            .await
            .map_err(BtrfsManagementError::Volume)
    }

    pub async fn scrub(
        &self,
        mount_point: &str,
        devid: Option<u64>,
        read_only: bool,
    ) -> Result<ScrubReport, BtrfsManagementError> {
        let (btrfs, writable) = self.resolve_mount_admin_held(mount_point)?;
        if let Some(id) = devid {
            require_device_serial_grant(self.authority, &btrfs, id)?;
        }
        if !read_only && !writable {
            return Err(BtrfsManagementError::ReadOnlyMount);
        }
        btrfs
            .scrub(devid, read_only)
            .await
            .map_err(BtrfsManagementError::Volume)
    }

    pub async fn quota_enable(&self, mount_point: &str) -> Result<(), BtrfsManagementError> {
        let (btrfs, writable) = self.resolve_mount_admin_held(mount_point)?;
        if !writable {
            return Err(BtrfsManagementError::ReadOnlyMount);
        }
        btrfs
            .quota_enable(self.now)
            .await
            .map_err(BtrfsManagementError::Volume)
    }

    pub async fn quota_disable(&self, mount_point: &str) -> Result<(), BtrfsManagementError> {
        let (btrfs, writable) = self.resolve_mount_admin_held(mount_point)?;
        if !writable {
            return Err(BtrfsManagementError::ReadOnlyMount);
        }
        btrfs
            .quota_disable(self.now)
            .await
            .map_err(BtrfsManagementError::Volume)
    }

    pub async fn quota_rescan(&self, mount_point: &str) -> Result<(), BtrfsManagementError> {
        let (btrfs, writable) = self.resolve_mount_admin_held(mount_point)?;
        if !writable {
            return Err(BtrfsManagementError::ReadOnlyMount);
        }
        btrfs
            .quota_rescan(self.now)
            .await
            .map_err(BtrfsManagementError::Volume)
    }

    pub async fn quota_status(
        &self,
        mount_point: &str,
    ) -> Result<QuotaStatus, BtrfsManagementError> {
        let (btrfs, _) = self.resolve_mount_admin_held(mount_point)?;
        btrfs
            .quota_status()
            .await
            .map_err(BtrfsManagementError::Volume)
    }

    pub async fn list_qgroups(
        &self,
        mount_point: &str,
    ) -> Result<Vec<QgroupInfo>, BtrfsManagementError> {
        let (btrfs, _) = self.resolve_mount_admin_held(mount_point)?;
        btrfs
            .list_qgroups()
            .await
            .map_err(BtrfsManagementError::Volume)
    }

    pub async fn qgroup_create(
        &self,
        mount_point: &str,
        id: QgroupId,
    ) -> Result<(), BtrfsManagementError> {
        let (btrfs, writable) = self.resolve_mount_admin_held(mount_point)?;
        if !writable {
            return Err(BtrfsManagementError::ReadOnlyMount);
        }
        btrfs
            .qgroup_create(id, self.now)
            .await
            .map_err(BtrfsManagementError::Volume)
    }

    pub async fn qgroup_destroy(
        &self,
        mount_point: &str,
        id: QgroupId,
    ) -> Result<(), BtrfsManagementError> {
        let (btrfs, writable) = self.resolve_mount_admin_held(mount_point)?;
        if !writable {
            return Err(BtrfsManagementError::ReadOnlyMount);
        }
        btrfs
            .qgroup_destroy(id, self.now)
            .await
            .map_err(BtrfsManagementError::Volume)
    }

    pub async fn qgroup_assign(
        &self,
        mount_point: &str,
        member: QgroupId,
        parent: QgroupId,
    ) -> Result<(), BtrfsManagementError> {
        let (btrfs, writable) = self.resolve_mount_admin_held(mount_point)?;
        if !writable {
            return Err(BtrfsManagementError::ReadOnlyMount);
        }
        btrfs
            .qgroup_assign(member, parent, self.now)
            .await
            .map_err(BtrfsManagementError::Volume)
    }

    pub async fn qgroup_remove(
        &self,
        mount_point: &str,
        member: QgroupId,
        parent: QgroupId,
    ) -> Result<(), BtrfsManagementError> {
        let (btrfs, writable) = self.resolve_mount_admin_held(mount_point)?;
        if !writable {
            return Err(BtrfsManagementError::ReadOnlyMount);
        }
        btrfs
            .qgroup_remove(member, parent, self.now)
            .await
            .map_err(BtrfsManagementError::Volume)
    }

    pub async fn qgroup_limit(
        &self,
        mount_point: &str,
        id: QgroupId,
        limit: QgroupLimit,
    ) -> Result<(), BtrfsManagementError> {
        let (btrfs, writable) = self.resolve_mount_admin_held(mount_point)?;
        if !writable {
            return Err(BtrfsManagementError::ReadOnlyMount);
        }
        btrfs
            .qgroup_limit(id, limit, self.now)
            .await
            .map_err(BtrfsManagementError::Volume)
    }
}
