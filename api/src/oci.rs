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
        map_subvol_info("create-subvolume", path, info)
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
        map_subvol_info("snapshot-subvolume", destination, info)
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
            Ok(info) => Ok(Some(map_subvol_info("subvolume-info", path, info)?)),
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
        Ok(Some(map_subvol_info(
            "receive-subvolume",
            destination_parent,
            info,
        )?))
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

fn map_subvol_info(
    operation: &'static str,
    path: &Path,
    info: SubvolumeInfo,
) -> core::result::Result<SubvolumeMeta, SubvolumeError> {
    let uuid = parse_uuid(operation, path, "uuid", &info.uuid)?;
    let received_uuid = info
        .received_uuid
        .as_deref()
        .map(|bytes| parse_uuid(operation, path, "received_uuid", bytes))
        .transpose()?;
    Ok(SubvolumeMeta {
        uuid,
        received_uuid,
        ctransid: info.ctransid,
        read_only: info.read_only,
    })
}

fn parse_uuid(
    operation: &'static str,
    path: &Path,
    field: &'static str,
    bytes: &[u8],
) -> core::result::Result<[u8; 16], SubvolumeError> {
    bytes.try_into().map_err(|_| SubvolumeError::MalformedUuid {
        operation,
        path: path.to_path_buf(),
        field,
        actual_len: bytes.len(),
    })
}

fn map_btrfs_error(operation: &'static str, path: &Path, err: BtrfsError) -> SubvolumeError {
    match err.kind {
        BtrfsErrorKind::NotBtrfs => SubvolumeError::NotBtrfs {
            path: path.to_path_buf(),
        },
        BtrfsErrorKind::NotSubvolume => SubvolumeError::NotSubvolume {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn test_subvol_info(
        uuid: Vec<u8>,
        received_uuid: Option<Vec<u8>>,
        ctransid: u64,
        read_only: bool,
    ) -> SubvolumeInfo {
        SubvolumeInfo {
            id: 256,
            parent_id: None,
            path: String::from("layers/test"),
            uuid,
            parent_uuid: None,
            received_uuid,
            generation: ctransid,
            ctransid,
            otransid: ctransid,
            stransid: 0,
            rtransid: 0,
            read_only,
        }
    }

    #[test]
    fn map_subvol_info_rejects_malformed_uuids() {
        let ok = map_subvol_info(
            "subvolume-info",
            Path::new("/layers/base"),
            test_subvol_info(vec![0x11; 16], Some(vec![0x22; 16]), 42, true),
        )
        .expect("valid 16-byte uuids");
        assert_eq!(ok.uuid, [0x11; 16]);
        assert_eq!(ok.received_uuid, Some([0x22; 16]));

        let short_uuid = map_subvol_info(
            "create-subvolume",
            Path::new("/layers/bad"),
            test_subvol_info(vec![0x11; 4], None, 1, false),
        )
        .expect_err("short uuid must fail fast");
        assert!(matches!(
            short_uuid,
            SubvolumeError::MalformedUuid {
                operation: "create-subvolume",
                field: "uuid",
                actual_len: 4,
                ..
            }
        ));

        let bad_received = map_subvol_info(
            "receive-subvolume",
            Path::new("/layers"),
            test_subvol_info(vec![0x11; 16], Some(vec![0x33; 20]), 1, true),
        )
        .expect_err("malformed received_uuid must fail fast");
        assert!(matches!(
            bad_received,
            SubvolumeError::MalformedUuid {
                operation: "receive-subvolume",
                field: "received_uuid",
                actual_len: 20,
                ..
            }
        ));
    }
}
