//! Helios guest integration for [`helios_oci`] over `helios:system/btrfs` and
//! `helios:system/programs`.

use std::path::{Path, PathBuf};

use thiserror::Error;

pub use helios_oci::*;

use crate::btrfs::{self, BtrfsError, BtrfsErrorKind, SubvolumeInfo};
use crate::programs::{self, ContainerCredentials, DefaultLinuxImage, SpawnError};

/// Errors applying an OCI image as the current instance's default Linux image.
#[derive(Debug, Error)]
pub enum OciDefaultImageError {
    #[error(transparent)]
    Oci(#[from] helios_oci::OciError),
    #[error("kernel refused set-default-image ({:?}): {}", .0.kind, .0.detail)]
    Spawn(SpawnError),
}

/// [`helios_oci::SubvolumeBackend`] backed by `helios:system/btrfs`.
///
/// Automatically translates [`BtrfsErrorKind::NotBtrfs`] into [`SubvolumeError::NotBtrfs`]
/// so [`ImageStore`] seamlessly falls back to read-only directories when running without
/// a mounted btrfs disk.
#[derive(Clone, Copy, Debug, Default)]
pub struct BtrfsSubvolumeBackend;

impl SubvolumeBackend for BtrfsSubvolumeBackend {
    async fn create_subvolume(
        &self,
        path: &Path,
    ) -> core::result::Result<SubvolumeMeta, SubvolumeError> {
        let p = path.to_string_lossy().into_owned();
        let info = btrfs::create_subvolume(p)
            .await
            .map_err(|err| map_btrfs_error("create-subvolume", path, err))?;
        Ok(map_subvol_info(info))
    }

    async fn snapshot_subvolume(
        &self,
        source: &Path,
        destination: &Path,
        read_only: bool,
    ) -> core::result::Result<SubvolumeMeta, SubvolumeError> {
        let src = source.to_string_lossy().into_owned();
        let dst = destination.to_string_lossy().into_owned();
        let info = btrfs::snapshot_subvolume(src, dst, read_only)
            .await
            .map_err(|err| map_btrfs_error("snapshot-subvolume", destination, err))?;
        Ok(map_subvol_info(info))
    }

    async fn set_subvolume_read_only(
        &self,
        path: &Path,
        read_only: bool,
    ) -> core::result::Result<(), SubvolumeError> {
        let p = path.to_string_lossy().into_owned();
        btrfs::set_subvolume_read_only(p, read_only)
            .await
            .map_err(|err| map_btrfs_error("set-subvolume-read-only", path, err))
    }

    async fn delete_subvolume(&self, path: &Path) -> core::result::Result<(), SubvolumeError> {
        let p = path.to_string_lossy().into_owned();
        btrfs::delete_subvolume(p)
            .await
            .map_err(|err| map_btrfs_error("delete-subvolume", path, err))
    }

    async fn subvolume_info(
        &self,
        path: &Path,
    ) -> core::result::Result<Option<SubvolumeMeta>, SubvolumeError> {
        let p = path.to_string_lossy().into_owned();
        match btrfs::subvolume_info(p).await {
            Ok(info) => Ok(Some(map_subvol_info(info))),
            Err(err) if err.kind == BtrfsErrorKind::NotFound => Ok(None),
            Err(err) => Err(map_btrfs_error("subvolume-info", path, err)),
        }
    }

    async fn receive_subvolume(
        &self,
        destination_parent: &Path,
        stream: Vec<u8>,
    ) -> core::result::Result<Option<SubvolumeMeta>, SubvolumeError> {
        let dst = destination_parent.to_string_lossy().into_owned();
        let info = btrfs::receive_subvolume(dst, stream)
            .await
            .map_err(|err| map_btrfs_error("receive-subvolume", destination_parent, err))?;
        Ok(Some(map_subvol_info(info)))
    }
}

/// Open an [`ImageStore`] rooted at `root` using [`BtrfsSubvolumeBackend`].
pub fn open_image_store(
    root: impl Into<PathBuf>,
) -> helios_oci::Result<ImageStore<BtrfsSubvolumeBackend>> {
    ImageStore::open(root, BtrfsSubvolumeBackend)
}

/// Convert a materialized [`PulledImage`] into a kernel [`DefaultLinuxImage`].
pub fn default_linux_image_from_oci(image: &PulledImage) -> helios_oci::Result<DefaultLinuxImage> {
    let user = image
        .config
        .config
        .resolve_user(Some(image.rootfs_path()))?;
    Ok(DefaultLinuxImage {
        root_path: image.rootfs_path().to_string_lossy().into_owned(),
        env: image.config.config.env_pairs(),
        credentials: Some(ContainerCredentials {
            uid: user.uid,
            gid: user.gid,
            supplementary_groups: user.supplementary_groups,
        }),
    })
}

/// Install a pulled OCI image as the current instance's process-tree-inherited
/// default Linux root image (`helios:system/programs.set-default-image`).
pub async fn set_default_image_from_oci(
    image: &PulledImage,
) -> core::result::Result<(), OciDefaultImageError> {
    let default_image = default_linux_image_from_oci(image)?;
    programs::set_default_image(Some(default_image))
        .await
        .map_err(OciDefaultImageError::Spawn)
}

fn map_subvol_info(info: SubvolumeInfo) -> SubvolumeMeta {
    let uuid = vec_to_uuid(&info.uuid).unwrap_or([0; 16]);
    let received_uuid = info.received_uuid.as_deref().and_then(vec_to_uuid);
    SubvolumeMeta {
        uuid,
        received_uuid,
        ctransid: info.ctransid,
        read_only: info.read_only,
    }
}

fn vec_to_uuid(bytes: &[u8]) -> Option<[u8; 16]> {
    bytes.try_into().ok()
}

fn map_btrfs_error(operation: &'static str, path: &Path, err: BtrfsError) -> SubvolumeError {
    match err.kind {
        BtrfsErrorKind::NotBtrfs | BtrfsErrorKind::NotSubvolume => SubvolumeError::NotBtrfs {
            path: path.to_path_buf(),
        },
        BtrfsErrorKind::AlreadyExists => SubvolumeError::AlreadyExists {
            path: path.to_path_buf(),
        },
        BtrfsErrorKind::NotFound => SubvolumeError::NotFound {
            path: path.to_path_buf(),
        },
        BtrfsErrorKind::PermissionDenied => SubvolumeError::PermissionDenied {
            path: path.to_path_buf(),
            detail: err.detail,
        },
        _ => SubvolumeError::Backend {
            operation,
            path: path.to_path_buf(),
            detail: format!("{:?}: {}", err.kind, err.detail),
        },
    }
}
