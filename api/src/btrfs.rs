//! Copy-on-write volume management for mounted btrfs filesystems, bounded by
//! the caller's grants.

use crate::bindings::helios::system::btrfs as raw;
pub use crate::bindings::helios::system::btrfs::{
    BalanceFilter, BalanceReport, BtrfsError, BtrfsErrorKind, DedupeOutcome, QgroupId, QgroupInfo,
    QgroupLimit, QuotaStatus, ResizeTarget, ScrubReport, SubvolumeInfo, VolumeDeviceInfo,
};

pub async fn create_subvolume(path: impl Into<String>) -> Result<SubvolumeInfo, BtrfsError> {
    raw::create_subvolume(path.into()).await
}

pub async fn delete_subvolume(path: impl Into<String>) -> Result<(), BtrfsError> {
    raw::delete_subvolume(path.into()).await
}

pub async fn snapshot_subvolume(
    source: impl Into<String>,
    destination: impl Into<String>,
    read_only: bool,
) -> Result<SubvolumeInfo, BtrfsError> {
    raw::snapshot_subvolume(source.into(), destination.into(), read_only).await
}

pub async fn set_subvolume_read_only(
    path: impl Into<String>,
    read_only: bool,
) -> Result<(), BtrfsError> {
    raw::set_subvolume_read_only(path.into(), read_only).await
}

pub async fn subvolume_info(path: impl Into<String>) -> Result<SubvolumeInfo, BtrfsError> {
    raw::get_subvolume_info(path.into()).await
}

pub async fn list_subvolumes(
    mount_point: impl Into<String>,
) -> Result<Vec<SubvolumeInfo>, BtrfsError> {
    raw::list_subvolumes(mount_point.into()).await
}

pub async fn send_subvolume(
    subvolume: impl Into<String>,
    parent: Option<String>,
    clone_sources: Vec<String>,
) -> Result<Vec<u8>, BtrfsError> {
    raw::send_subvolume(subvolume.into(), parent, clone_sources).await
}

pub async fn receive_subvolume(
    destination: impl Into<String>,
    stream: Vec<u8>,
) -> Result<SubvolumeInfo, BtrfsError> {
    raw::receive_subvolume(destination.into(), stream).await
}

pub async fn reflink(
    source: impl Into<String>,
    source_offset: u64,
    destination: impl Into<String>,
    destination_offset: u64,
    length: u64,
) -> Result<(), BtrfsError> {
    raw::reflink(
        source.into(),
        source_offset,
        destination.into(),
        destination_offset,
        length,
    )
    .await
}

pub async fn dedupe(
    source: impl Into<String>,
    source_offset: u64,
    destination: impl Into<String>,
    destination_offset: u64,
    length: u64,
) -> Result<DedupeOutcome, BtrfsError> {
    raw::dedupe(
        source.into(),
        source_offset,
        destination.into(),
        destination_offset,
        length,
    )
    .await
}

pub async fn list_devices(
    mount_point: impl Into<String>,
) -> Result<Vec<VolumeDeviceInfo>, BtrfsError> {
    raw::list_devices(mount_point.into()).await
}

pub async fn add_device(
    mount_point: impl Into<String>,
    device: impl Into<String>,
) -> Result<VolumeDeviceInfo, BtrfsError> {
    raw::add_device(mount_point.into(), device.into()).await
}

pub async fn remove_device(mount_point: impl Into<String>, devid: u64) -> Result<(), BtrfsError> {
    raw::remove_device(mount_point.into(), devid).await
}

pub async fn replace_device(
    mount_point: impl Into<String>,
    source_devid: u64,
    target_device: impl Into<String>,
) -> Result<VolumeDeviceInfo, BtrfsError> {
    raw::replace_device(mount_point.into(), source_devid, target_device.into()).await
}

pub async fn resize_device(
    mount_point: impl Into<String>,
    devid: Option<u64>,
    target: ResizeTarget,
) -> Result<VolumeDeviceInfo, BtrfsError> {
    raw::resize_device(mount_point.into(), devid, target).await
}

pub async fn balance(
    mount_point: impl Into<String>,
    filter: BalanceFilter,
) -> Result<BalanceReport, BtrfsError> {
    raw::balance(mount_point.into(), filter).await
}

pub async fn scrub(
    mount_point: impl Into<String>,
    devid: Option<u64>,
    read_only: bool,
) -> Result<ScrubReport, BtrfsError> {
    raw::scrub(mount_point.into(), devid, read_only).await
}

pub async fn quota_enable(mount_point: impl Into<String>) -> Result<(), BtrfsError> {
    raw::quota_enable(mount_point.into()).await
}

pub async fn quota_disable(mount_point: impl Into<String>) -> Result<(), BtrfsError> {
    raw::quota_disable(mount_point.into()).await
}

pub async fn quota_rescan(mount_point: impl Into<String>) -> Result<(), BtrfsError> {
    raw::quota_rescan(mount_point.into()).await
}

pub async fn quota_status(mount_point: impl Into<String>) -> Result<QuotaStatus, BtrfsError> {
    raw::get_quota_status(mount_point.into()).await
}

pub async fn qgroup_list(mount_point: impl Into<String>) -> Result<Vec<QgroupInfo>, BtrfsError> {
    raw::qgroup_list(mount_point.into()).await
}

pub async fn qgroup_create(
    mount_point: impl Into<String>,
    group: QgroupId,
) -> Result<(), BtrfsError> {
    raw::qgroup_create(mount_point.into(), group).await
}

pub async fn qgroup_destroy(
    mount_point: impl Into<String>,
    group: QgroupId,
) -> Result<(), BtrfsError> {
    raw::qgroup_destroy(mount_point.into(), group).await
}

pub async fn qgroup_assign(
    mount_point: impl Into<String>,
    member: QgroupId,
    parent: QgroupId,
) -> Result<(), BtrfsError> {
    raw::qgroup_assign(mount_point.into(), member, parent).await
}

pub async fn qgroup_remove(
    mount_point: impl Into<String>,
    member: QgroupId,
    parent: QgroupId,
) -> Result<(), BtrfsError> {
    raw::qgroup_remove(mount_point.into(), member, parent).await
}

pub async fn qgroup_limit(
    mount_point: impl Into<String>,
    group: QgroupId,
    limit: QgroupLimit,
) -> Result<(), BtrfsError> {
    raw::set_qgroup_limit(mount_point.into(), group, limit).await
}
