//! Remote storage clients (`helios:system/mounts` and `helios:system/btrfs`)
//! bound to a [`Session`].

use std::collections::BTreeMap;
use std::path::Path;

use helios_oci::{SubvolumeBackend, SubvolumeError, SubvolumeMeta};
use helios_wit_rpc::inspector::helios::system::{
    btrfs::{
        self as rpc_btrfs, BalanceFilter, BalanceReport, BtrfsError, BtrfsErrorKind, DedupeOutcome,
        QgroupId, QgroupInfo, QgroupLimit, QuotaStatus, ResizeTarget, ScrubReport, SubvolumeInfo,
        VolumeDeviceInfo,
    },
    inspect::Value as InspectValue,
    mounts::{self as rpc_mounts, MountRequest, MountSharing, MountSource},
};
use helios_wit_rpc::inspector::wasi::filesystem::preopens as rpc_preopens;
use helios_wit_rpc::inspector_fs::MountBtrfsRequest;
use serde::{Deserialize, Serialize};

use crate::error::OpsError;
use crate::session::{Session, normalize_absolute_path};
use crate::target::GrantRight;

/// One active mount entry reported by [`MountsClient::list`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MountInfo {
    pub path: String,
    pub source: String,
    pub read_only: bool,
    pub sharing: String,
}

/// Mount-table client over `helios:system/mounts` and `wasi:filesystem/preopens`.
#[derive(Clone)]
pub struct MountsClient {
    session: Session,
}

impl MountsClient {
    #[must_use]
    pub const fn new(session: Session) -> Self {
        Self { session }
    }

    /// List visible filesystem mounts on the remote guest.
    ///
    /// Queries `wasi:filesystem/preopens.get-directories` for the session's
    /// mounted preopen roots and merges any `/kernel/mounts/*` telemetry entries
    /// published by the kernel when `inspect` is permitted.
    pub async fn list(&self) -> Result<Vec<MountInfo>, OpsError> {
        self.session.require_right(GrantRight::FilesystemRead)?;
        let preopens_client = rpc_preopens::RpcClient::new(self.session.protocol_client().clone());
        let preopens = self
            .session
            .call(
                "wasi:filesystem/preopens.get-directories",
                preopens_client.get_directories(),
            )
            .await?;

        let mut by_path: BTreeMap<String, MountInfo> = BTreeMap::new();
        for (_desc, guest_name) in preopens {
            let path = normalize_absolute_path(&guest_name)?;
            by_path.insert(
                path.clone(),
                MountInfo {
                    path,
                    source: "preopen".to_owned(),
                    read_only: false,
                    sharing: "shared".to_owned(),
                },
            );
        }

        if self
            .session
            .options()
            .attenuation
            .allows(GrantRight::Inspect)
            && let Ok(snap) = self.session.inspect(&["/kernel/mounts/"], 0).await
        {
            let mut indexed: BTreeMap<String, BTreeMap<String, &InspectValue>> = BTreeMap::new();
            for entry in &snap.entries {
                if let Some(rest) = entry.path.strip_prefix("/kernel/mounts/")
                    && let Some((idx, field)) = rest.split_once('/')
                {
                    indexed
                        .entry(idx.to_owned())
                        .or_default()
                        .insert(field.to_owned(), &entry.value);
                }
            }
            for fields in indexed.into_values() {
                let Some(InspectValue::Text(raw_path)) = fields.get("path") else {
                    continue;
                };
                let Ok(path) = normalize_absolute_path(raw_path) else {
                    continue;
                };
                let source = match fields.get("source").or_else(|| fields.get("kind")) {
                    Some(InspectValue::Text(s)) => s.clone(),
                    _ => "kernel".to_owned(),
                };
                let read_only =
                    matches!(fields.get("read-only"), Some(InspectValue::Boolean(true)));
                let sharing = match fields.get("sharing") {
                    Some(InspectValue::Text(s)) => s.clone(),
                    _ => "shared".to_owned(),
                };
                by_path.insert(
                    path.clone(),
                    MountInfo {
                        path,
                        source,
                        read_only,
                        sharing,
                    },
                );
            }
        }

        Ok(by_path.into_values().collect())
    }

    /// Attach a filesystem via `helios:system/mounts.mount`.
    pub async fn mount(&self, mut request: MountRequest) -> Result<(), OpsError> {
        self.session.require_right(GrantRight::FilesystemWrite)?;
        request.path = normalize_absolute_path(&request.path)?;
        let path = request.path.clone();
        let client = rpc_mounts::RpcClient::new(self.session.protocol_client().clone());
        self.session
            .call("system.mounts.mount", client.mount(request))
            .await?
            .map_err(|err| OpsError::from_mount("mount", path, err))
    }

    /// Attach a btrfs disk via `helios:system/mounts.mount`.
    pub async fn mount_btrfs(&self, request: &MountBtrfsRequest) -> Result<(), OpsError> {
        self.mount(MountRequest {
            source: MountSource::Btrfs(request.disk.clone()),
            path: request.path.clone(),
            read_only: request.read_only,
            sharing: if request.shared {
                MountSharing::Shared
            } else {
                MountSharing::Private
            },
            compress: request.compress.clone(),
            commit: request.commit,
            max_inline: request.max_inline,
        })
        .await
    }

    /// Detach the filesystem mounted at `path` via `helios:system/mounts.unmount`.
    pub async fn unmount(&self, path: &str) -> Result<(), OpsError> {
        self.session.require_right(GrantRight::FilesystemWrite)?;
        let normalized = normalize_absolute_path(path)?;
        let client = rpc_mounts::RpcClient::new(self.session.protocol_client().clone());
        self.session
            .call("system.mounts.unmount", client.unmount(normalized.clone()))
            .await?
            .map_err(|err| OpsError::from_mount("unmount", normalized, err))
    }
}

/// Full remote `helios:system/btrfs` client bound to a [`Session`].
#[derive(Clone)]
pub struct BtrfsClient {
    session: Session,
}

impl BtrfsClient {
    #[must_use]
    pub const fn new(session: Session) -> Self {
        Self { session }
    }

    fn client(&self) -> rpc_btrfs::RpcClient {
        rpc_btrfs::RpcClient::new(self.session.protocol_client().clone())
    }

    /// Create a new empty subvolume at `path`.
    pub async fn create_subvolume(&self, path: &str) -> Result<SubvolumeInfo, OpsError> {
        self.session.require_right(GrantRight::FilesystemWrite)?;
        let normalized = normalize_absolute_path(path)?;
        self.session
            .call(
                "system.btrfs.create-subvolume",
                self.client().create_subvolume(normalized.clone()),
            )
            .await?
            .map_err(|err| OpsError::from_btrfs("create-subvolume", normalized, err))
    }

    /// Delete the subvolume rooted at `path`.
    pub async fn delete_subvolume(&self, path: &str) -> Result<(), OpsError> {
        self.session.require_right(GrantRight::FilesystemWrite)?;
        let normalized = normalize_absolute_path(path)?;
        self.session
            .call(
                "system.btrfs.delete-subvolume",
                self.client().delete_subvolume(normalized.clone()),
            )
            .await?
            .map_err(|err| OpsError::from_btrfs("delete-subvolume", normalized, err))
    }

    /// Snapshot `source` to `destination` (optionally read-only).
    pub async fn snapshot_subvolume(
        &self,
        source: &str,
        destination: &str,
        read_only: bool,
    ) -> Result<SubvolumeInfo, OpsError> {
        self.session.require_right(GrantRight::FilesystemWrite)?;
        let src = normalize_absolute_path(source)?;
        let dst = normalize_absolute_path(destination)?;
        self.session
            .call(
                "system.btrfs.snapshot-subvolume",
                self.client()
                    .snapshot_subvolume(src, dst.clone(), read_only),
            )
            .await?
            .map_err(|err| OpsError::from_btrfs("snapshot-subvolume", dst, err))
    }

    /// Set or clear the read-only flag on the subvolume at `path`.
    pub async fn set_subvolume_read_only(
        &self,
        path: &str,
        read_only: bool,
    ) -> Result<(), OpsError> {
        self.session.require_right(GrantRight::FilesystemWrite)?;
        let normalized = normalize_absolute_path(path)?;
        self.session
            .call(
                "system.btrfs.set-subvolume-read-only",
                self.client()
                    .set_subvolume_read_only(normalized.clone(), read_only),
            )
            .await?
            .map_err(|err| OpsError::from_btrfs("set-subvolume-read-only", normalized, err))
    }

    /// Describe the subvolume rooted at `path`.
    pub async fn subvolume_info(&self, path: &str) -> Result<SubvolumeInfo, OpsError> {
        self.session.require_right(GrantRight::FilesystemRead)?;
        let normalized = normalize_absolute_path(path)?;
        self.session
            .call(
                "system.btrfs.get-subvolume-info",
                self.client().get_subvolume_info(normalized.clone()),
            )
            .await?
            .map_err(|err| OpsError::from_btrfs("get-subvolume-info", normalized, err))
    }

    /// List every live subvolume in the btrfs volume mounted at `mount_point`.
    pub async fn list_subvolumes(&self, mount_point: &str) -> Result<Vec<SubvolumeInfo>, OpsError> {
        self.session.require_right(GrantRight::FilesystemRead)?;
        let normalized = normalize_absolute_path(mount_point)?;
        self.session
            .call(
                "system.btrfs.list-subvolumes",
                self.client().list_subvolumes(normalized.clone()),
            )
            .await?
            .map_err(|err| OpsError::from_btrfs("list-subvolumes", normalized, err))
    }

    /// Produce a Linux-compatible btrfs send stream (v1) for `subvolume`.
    pub async fn send_subvolume(
        &self,
        subvolume: &str,
        parent: Option<&str>,
        clone_sources: &[String],
    ) -> Result<Vec<u8>, OpsError> {
        self.session.require_right(GrantRight::FilesystemRead)?;
        let subvol = normalize_absolute_path(subvolume)?;
        let parent = parent.map(normalize_absolute_path).transpose()?;
        let clones = clone_sources
            .iter()
            .map(|p| normalize_absolute_path(p))
            .collect::<Result<Vec<_>, _>>()?;
        self.session
            .call(
                "system.btrfs.send-subvolume",
                self.client().send_subvolume(subvol.clone(), parent, clones),
            )
            .await?
            .map_err(|err| OpsError::from_btrfs("send-subvolume", subvol, err))
    }

    /// Apply a Linux-compatible btrfs send stream into `destination`.
    pub async fn receive_subvolume(
        &self,
        destination: &str,
        payload: Vec<u8>,
    ) -> Result<SubvolumeInfo, OpsError> {
        self.session.require_right(GrantRight::FilesystemWrite)?;
        let dst = normalize_absolute_path(destination)?;
        self.session
            .call(
                "system.btrfs.receive-subvolume",
                self.client().receive_subvolume(dst.clone(), payload),
            )
            .await?
            .map_err(|err| OpsError::from_btrfs("receive-subvolume", dst, err))
    }

    /// Share extents from `source` into `destination` (reflink).
    pub async fn reflink(
        &self,
        source: &str,
        source_offset: u64,
        destination: &str,
        destination_offset: u64,
        length: u64,
    ) -> Result<(), OpsError> {
        self.session.require_right(GrantRight::FilesystemWrite)?;
        let src = normalize_absolute_path(source)?;
        let dst = normalize_absolute_path(destination)?;
        self.session
            .call(
                "system.btrfs.reflink",
                self.client()
                    .reflink(src, source_offset, dst.clone(), destination_offset, length),
            )
            .await?
            .map_err(|err| OpsError::from_btrfs("reflink", dst, err))
    }

    /// Share extents from `source` into `destination` when both ranges are identical.
    pub async fn dedupe(
        &self,
        source: &str,
        source_offset: u64,
        destination: &str,
        destination_offset: u64,
        length: u64,
    ) -> Result<DedupeOutcome, OpsError> {
        self.session.require_right(GrantRight::FilesystemWrite)?;
        let src = normalize_absolute_path(source)?;
        let dst = normalize_absolute_path(destination)?;
        self.session
            .call(
                "system.btrfs.dedupe",
                self.client()
                    .dedupe(src, source_offset, dst.clone(), destination_offset, length),
            )
            .await?
            .map_err(|err| OpsError::from_btrfs("dedupe", dst, err))
    }

    /// List backing devices participating in the btrfs volume mounted at `mount_point`.
    pub async fn list_devices(&self, mount_point: &str) -> Result<Vec<VolumeDeviceInfo>, OpsError> {
        self.session.require_right(GrantRight::FilesystemRead)?;
        let normalized = normalize_absolute_path(mount_point)?;
        self.session
            .call(
                "system.btrfs.list-devices",
                self.client().list_devices(normalized.clone()),
            )
            .await?
            .map_err(|err| OpsError::from_btrfs("list-devices", normalized, err))
    }

    /// Add block device `device` (by serial) to the volume at `mount_point`.
    pub async fn add_device(
        &self,
        mount_point: &str,
        device: &str,
    ) -> Result<VolumeDeviceInfo, OpsError> {
        self.session.require_right(GrantRight::FilesystemWrite)?;
        let normalized = normalize_absolute_path(mount_point)?;
        self.session
            .call(
                "system.btrfs.add-device",
                self.client()
                    .add_device(normalized.clone(), device.to_owned()),
            )
            .await?
            .map_err(|err| OpsError::from_btrfs("add-device", normalized, err))
    }

    /// Remove backing device `devid` from the volume at `mount_point`.
    pub async fn remove_device(&self, mount_point: &str, devid: u64) -> Result<(), OpsError> {
        self.session.require_right(GrantRight::FilesystemWrite)?;
        let normalized = normalize_absolute_path(mount_point)?;
        self.session
            .call(
                "system.btrfs.remove-device",
                self.client().remove_device(normalized.clone(), devid),
            )
            .await?
            .map_err(|err| OpsError::from_btrfs("remove-device", normalized, err))
    }

    /// Replace `source_devid` in place with `target_device` (serial).
    pub async fn replace_device(
        &self,
        mount_point: &str,
        source_devid: u64,
        target_device: &str,
    ) -> Result<VolumeDeviceInfo, OpsError> {
        self.session.require_right(GrantRight::FilesystemWrite)?;
        let normalized = normalize_absolute_path(mount_point)?;
        self.session
            .call(
                "system.btrfs.replace-device",
                self.client().replace_device(
                    normalized.clone(),
                    source_devid,
                    target_device.to_owned(),
                ),
            )
            .await?
            .map_err(|err| OpsError::from_btrfs("replace-device", normalized, err))
    }

    /// Resize a device in the volume at `mount_point`.
    pub async fn resize_device(
        &self,
        mount_point: &str,
        devid: Option<u64>,
        target: ResizeTarget,
    ) -> Result<VolumeDeviceInfo, OpsError> {
        self.session.require_right(GrantRight::FilesystemWrite)?;
        let normalized = normalize_absolute_path(mount_point)?;
        self.session
            .call(
                "system.btrfs.resize-device",
                self.client()
                    .resize_device(normalized.clone(), devid, target),
            )
            .await?
            .map_err(|err| OpsError::from_btrfs("resize-device", normalized, err))
    }

    /// Run a chunk balance pass matching `filter`.
    pub async fn balance(
        &self,
        mount_point: &str,
        filter: BalanceFilter,
    ) -> Result<BalanceReport, OpsError> {
        self.session.require_right(GrantRight::FilesystemWrite)?;
        let normalized = normalize_absolute_path(mount_point)?;
        self.session
            .call(
                "system.btrfs.balance",
                self.client().balance(normalized.clone(), filter),
            )
            .await?
            .map_err(|err| OpsError::from_btrfs("balance", normalized, err))
    }

    /// Scrub checksummed metadata and data extents on `mount_point`.
    pub async fn scrub(
        &self,
        mount_point: &str,
        devid: Option<u64>,
        read_only: bool,
    ) -> Result<ScrubReport, OpsError> {
        self.session.require_right(GrantRight::FilesystemWrite)?;
        let normalized = normalize_absolute_path(mount_point)?;
        self.session
            .call(
                "system.btrfs.scrub",
                self.client().scrub(normalized.clone(), devid, read_only),
            )
            .await?
            .map_err(|err| OpsError::from_btrfs("scrub", normalized, err))
    }

    /// Enable quota groups on `mount_point`.
    pub async fn quota_enable(&self, mount_point: &str) -> Result<(), OpsError> {
        self.session.require_right(GrantRight::FilesystemWrite)?;
        let normalized = normalize_absolute_path(mount_point)?;
        self.session
            .call(
                "system.btrfs.quota-enable",
                self.client().quota_enable(normalized.clone()),
            )
            .await?
            .map_err(|err| OpsError::from_btrfs("quota-enable", normalized, err))
    }

    /// Disable quota groups on `mount_point`.
    pub async fn quota_disable(&self, mount_point: &str) -> Result<(), OpsError> {
        self.session.require_right(GrantRight::FilesystemWrite)?;
        let normalized = normalize_absolute_path(mount_point)?;
        self.session
            .call(
                "system.btrfs.quota-disable",
                self.client().quota_disable(normalized.clone()),
            )
            .await?
            .map_err(|err| OpsError::from_btrfs("quota-disable", normalized, err))
    }

    /// Recompute quota group counts on `mount_point`.
    pub async fn quota_rescan(&self, mount_point: &str) -> Result<(), OpsError> {
        self.session.require_right(GrantRight::FilesystemWrite)?;
        let normalized = normalize_absolute_path(mount_point)?;
        self.session
            .call(
                "system.btrfs.quota-rescan",
                self.client().quota_rescan(normalized.clone()),
            )
            .await?
            .map_err(|err| OpsError::from_btrfs("quota-rescan", normalized, err))
    }

    /// Query quota subsystem status on `mount_point`.
    pub async fn quota_status(&self, mount_point: &str) -> Result<QuotaStatus, OpsError> {
        self.session.require_right(GrantRight::FilesystemRead)?;
        let normalized = normalize_absolute_path(mount_point)?;
        self.session
            .call(
                "system.btrfs.get-quota-status",
                self.client().get_quota_status(normalized.clone()),
            )
            .await?
            .map_err(|err| OpsError::from_btrfs("get-quota-status", normalized, err))
    }

    /// List every quota group on `mount_point`.
    pub async fn qgroup_list(&self, mount_point: &str) -> Result<Vec<QgroupInfo>, OpsError> {
        self.session.require_right(GrantRight::FilesystemRead)?;
        let normalized = normalize_absolute_path(mount_point)?;
        self.session
            .call(
                "system.btrfs.qgroup-list",
                self.client().qgroup_list(normalized.clone()),
            )
            .await?
            .map_err(|err| OpsError::from_btrfs("qgroup-list", normalized, err))
    }

    /// Create an explicit quota group `group`.
    pub async fn qgroup_create(&self, mount_point: &str, group: QgroupId) -> Result<(), OpsError> {
        self.session.require_right(GrantRight::FilesystemWrite)?;
        let normalized = normalize_absolute_path(mount_point)?;
        self.session
            .call(
                "system.btrfs.qgroup-create",
                self.client().qgroup_create(normalized.clone(), group),
            )
            .await?
            .map_err(|err| OpsError::from_btrfs("qgroup-create", normalized, err))
    }

    /// Destroy quota group `group`.
    pub async fn qgroup_destroy(&self, mount_point: &str, group: QgroupId) -> Result<(), OpsError> {
        self.session.require_right(GrantRight::FilesystemWrite)?;
        let normalized = normalize_absolute_path(mount_point)?;
        self.session
            .call(
                "system.btrfs.qgroup-destroy",
                self.client().qgroup_destroy(normalized.clone(), group),
            )
            .await?
            .map_err(|err| OpsError::from_btrfs("qgroup-destroy", normalized, err))
    }

    /// Assign `member` as a child of `parent`.
    pub async fn qgroup_assign(
        &self,
        mount_point: &str,
        member: QgroupId,
        parent: QgroupId,
    ) -> Result<(), OpsError> {
        self.session.require_right(GrantRight::FilesystemWrite)?;
        let normalized = normalize_absolute_path(mount_point)?;
        self.session
            .call(
                "system.btrfs.qgroup-assign",
                self.client()
                    .qgroup_assign(normalized.clone(), member, parent),
            )
            .await?
            .map_err(|err| OpsError::from_btrfs("qgroup-assign", normalized, err))
    }

    /// Remove `member` from `parent`.
    pub async fn qgroup_remove(
        &self,
        mount_point: &str,
        member: QgroupId,
        parent: QgroupId,
    ) -> Result<(), OpsError> {
        self.session.require_right(GrantRight::FilesystemWrite)?;
        let normalized = normalize_absolute_path(mount_point)?;
        self.session
            .call(
                "system.btrfs.qgroup-remove",
                self.client()
                    .qgroup_remove(normalized.clone(), member, parent),
            )
            .await?
            .map_err(|err| OpsError::from_btrfs("qgroup-remove", normalized, err))
    }

    /// Configure space limits on `group`.
    pub async fn set_qgroup_limit(
        &self,
        mount_point: &str,
        group: QgroupId,
        limit: QgroupLimit,
    ) -> Result<(), OpsError> {
        self.session.require_right(GrantRight::FilesystemWrite)?;
        let normalized = normalize_absolute_path(mount_point)?;
        self.session
            .call(
                "system.btrfs.set-qgroup-limit",
                self.client()
                    .set_qgroup_limit(normalized.clone(), group, limit),
            )
            .await?
            .map_err(|err| OpsError::from_btrfs("set-qgroup-limit", normalized, err))
    }
}

/// [`SubvolumeBackend`] adapter delegating to a remote [`BtrfsClient`] over `helios-wit-rpc`.
#[derive(Clone)]
pub struct RemoteBtrfsSubvolumeBackend {
    btrfs: BtrfsClient,
}

impl RemoteBtrfsSubvolumeBackend {
    #[must_use]
    pub const fn new(btrfs: BtrfsClient) -> Self {
        Self { btrfs }
    }
}

impl SubvolumeBackend for RemoteBtrfsSubvolumeBackend {
    async fn create_subvolume(&self, path: &Path) -> Result<SubvolumeMeta, SubvolumeError> {
        let p = path.to_string_lossy();
        let info = self
            .btrfs
            .create_subvolume(&p)
            .await
            .map_err(|err| map_ops_btrfs_error("create-subvolume", path, err))?;
        map_subvol_info("create-subvolume", path, info)
    }

    async fn snapshot_subvolume(
        &self,
        source: &Path,
        destination: &Path,
        read_only: bool,
    ) -> Result<SubvolumeMeta, SubvolumeError> {
        let src = source.to_string_lossy();
        let dst = destination.to_string_lossy();
        let info = self
            .btrfs
            .snapshot_subvolume(&src, &dst, read_only)
            .await
            .map_err(|err| map_ops_btrfs_error("snapshot-subvolume", destination, err))?;
        map_subvol_info("snapshot-subvolume", destination, info)
    }

    async fn set_subvolume_read_only(
        &self,
        path: &Path,
        read_only: bool,
    ) -> Result<(), SubvolumeError> {
        let p = path.to_string_lossy();
        self.btrfs
            .set_subvolume_read_only(&p, read_only)
            .await
            .map_err(|err| map_ops_btrfs_error("set-subvolume-read-only", path, err))
    }

    async fn delete_subvolume(&self, path: &Path) -> Result<(), SubvolumeError> {
        let p = path.to_string_lossy();
        self.btrfs
            .delete_subvolume(&p)
            .await
            .map_err(|err| map_ops_btrfs_error("delete-subvolume", path, err))
    }

    async fn subvolume_info(&self, path: &Path) -> Result<Option<SubvolumeMeta>, SubvolumeError> {
        let p = path.to_string_lossy();
        match self.btrfs.subvolume_info(&p).await {
            Ok(info) => Ok(Some(map_subvol_info("subvolume-info", path, info)?)),
            Err(OpsError::BtrfsRefused {
                kind: BtrfsErrorKind::NotFound,
                ..
            }) => Ok(None),
            Err(err) => Err(map_ops_btrfs_error("subvolume-info", path, err)),
        }
    }

    async fn receive_subvolume(
        &self,
        destination_parent: &Path,
        stream: Vec<u8>,
    ) -> Result<Option<SubvolumeMeta>, SubvolumeError> {
        let dst = destination_parent.to_string_lossy();
        let info = self
            .btrfs
            .receive_subvolume(&dst, stream)
            .await
            .map_err(|err| map_ops_btrfs_error("receive-subvolume", destination_parent, err))?;
        Ok(Some(map_subvol_info(
            "receive-subvolume",
            destination_parent,
            info,
        )?))
    }
}

fn map_subvol_info(
    operation: &'static str,
    path: &Path,
    info: SubvolumeInfo,
) -> Result<SubvolumeMeta, SubvolumeError> {
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
) -> Result<[u8; 16], SubvolumeError> {
    bytes.try_into().map_err(|_| SubvolumeError::MalformedUuid {
        operation,
        path: path.to_path_buf(),
        field,
        actual_len: bytes.len(),
    })
}

fn map_ops_btrfs_error(operation: &'static str, path: &Path, err: OpsError) -> SubvolumeError {
    match err {
        OpsError::BtrfsRefused { kind, detail, .. } => {
            map_btrfs_error(operation, path, BtrfsError { kind, detail })
        }
        other => SubvolumeError::Backend {
            operation,
            path: path.to_path_buf(),
            detail: other.to_string(),
        },
    }
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
    use std::os::unix::net::UnixStream;
    use std::sync::Mutex;

    use async_io::Async;
    use helios_wit_rpc::Endpoint;
    use helios_wit_rpc::inspector::helios::system::mounts::{
        self as rpc_mounts, MountError, MountErrorKind, MountRequest, MountSharing, MountSource,
    };

    use crate::session::{Session, SessionOptions};
    use crate::target::Target;
    use crate::transport::RpcConnection;

    struct FakeMounts {
        mounted: Mutex<Vec<String>>,
    }

    impl rpc_mounts::RpcHandler for FakeMounts {
        async fn mount(&self, request: MountRequest) -> Result<(), MountError> {
            self.mounted.lock().expect("lock").push(request.path);
            Ok(())
        }

        async fn unmount(&self, path: String) -> Result<(), MountError> {
            let mut guard = self.mounted.lock().expect("lock");
            if let Some(idx) = guard.iter().position(|p| p == &path) {
                guard.remove(idx);
                Ok(())
            } else {
                Err(MountError {
                    kind: MountErrorKind::NotMounted,
                    detail: path,
                })
            }
        }
    }

    #[tokio::test]
    async fn mounts_client_mount_and_unmount_round_trip() {
        let (host, guest) = UnixStream::pair().expect("pair");
        host.set_nonblocking(true).expect("host nb");
        guest.set_nonblocking(true).expect("guest nb");
        let host_r = host.try_clone().expect("clone");
        let guest_r = guest.try_clone().expect("clone");
        let conn = RpcConnection::from_split(
            Box::new(Async::new(host_r).expect("async")),
            Box::new(Async::new(host).expect("async")),
        );
        let session = Session::from_connection(
            Target::new("mnt-test", "serial:///tmp/mnt.sock").expect("target"),
            conn,
            SessionOptions::default(),
        );
        let ep = Endpoint::new(
            Async::new(guest_r).expect("async"),
            Async::new(guest).expect("async"),
            rpc_mounts::RpcServer::new(FakeMounts {
                mounted: Mutex::new(Vec::new()),
            }),
        );
        let server_task = tokio::spawn(async move {
            let _ = ep.drive().await;
        });

        let mounts = session.mounts();
        mounts
            .mount(MountRequest {
                source: MountSource::Memory,
                path: "/mnt/scratch".to_owned(),
                read_only: false,
                sharing: MountSharing::Private,
                compress: None,
                commit: None,
                max_inline: None,
            })
            .await
            .expect("mount");
        mounts.unmount("/mnt/scratch").await.expect("unmount");
        assert!(mounts.unmount("/mnt/scratch").await.is_err());

        server_task.abort();
    }
}
