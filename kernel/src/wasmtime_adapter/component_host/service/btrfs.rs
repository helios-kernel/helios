//! `helios:system/btrfs` for the component host.
//!
//! Every call takes the caller's [`crate::ProcessAuthority`], [`crate::Namespace`],
//! [`crate::AttachedStorage`] and current wall-clock timestamp out of the store,
//! releases the store, and executes through [`crate::BtrfsVolumeRequest`], which
//! derives the required typed capabilities before touching any mounted btrfs
//! volume.
//!
//! # Concurrency contract
//!
//! The store lock is held only to clone the authority, namespace, attached
//! storage handles, and timestamp, never across `.await`. Volume operations
//! serialize inside the target mount's `BtrfsService` without blocking other
//! mounts or other tasks on the same store.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use helios_hal::cpu::Cpu;
use helios_hal::fs::FsError;
use helios_hal::fs_management::{
    BalanceFilter, BalanceReport, DedupeOutcome, QgroupId, QgroupInfo, QgroupLimit, QuotaStatus,
    ResizeTarget, ScrubReport, SubvolumeInfo, VolumeDeviceInfo, VolumeManagementError,
};
use wasmtime::component::{Accessor, HasSelf, Linker};

use crate::wasmtime_adapter::bindings::btrfs::bindings::helios::system::btrfs as wit;
use crate::{BtrfsManagementError, BtrfsVolumeRequest, ComponentHostNetwork};

use super::super::StoreData;

/// Register `helios:system/btrfs` in a linker.
pub(in crate::wasmtime_adapter::component_host) fn add_btrfs_to_linker<CpuImpl, Net, StorageImpl>(
    linker: &mut Linker<StoreData<CpuImpl, Net, StorageImpl>>,
) -> wasmtime::Result<()>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    wit::add_to_linker::<_, HasSelf<StoreData<CpuImpl, Net, StorageImpl>>>(linker, |state| state)
}

fn wit_error(error: &BtrfsManagementError) -> wit::BtrfsError {
    use wit::BtrfsErrorKind as Kind;
    let kind = match error {
        BtrfsManagementError::Authority(_) => Kind::PermissionDenied,
        BtrfsManagementError::NotBtrfs(_) => Kind::NotBtrfs,
        BtrfsManagementError::CrossDevice => Kind::CrossDevice,
        BtrfsManagementError::InvalidPath(_) | BtrfsManagementError::InvalidSerial(_) => {
            Kind::InvalidArgument
        }
        BtrfsManagementError::ReadOnlyMount | BtrfsManagementError::ReadOnlyDisk { .. } => {
            Kind::ReadOnlyFilesystem
        }
        BtrfsManagementError::DiskUnavailable { .. } => Kind::DeviceNotFound,
        BtrfsManagementError::Volume(err) => match err {
            VolumeManagementError::Fs(fs) => match fs {
                FsError::NoEntry => Kind::NotFound,
                FsError::Exists => Kind::AlreadyExists,
                FsError::ReadOnly => Kind::ReadOnlyFilesystem,
                FsError::NotDirectory => Kind::NotDirectory,
                FsError::IsDirectory => Kind::IsDirectory,
                FsError::NotEmpty => Kind::NotEmpty,
                FsError::NoSpace => Kind::NoSpace,
                FsError::NotPermitted => Kind::PermissionDenied,
                FsError::CrossDevice => Kind::CrossDevice,
                FsError::Busy => Kind::Busy,
                FsError::Invalid
                | FsError::NameTooLong
                | FsError::IllegalByteSequence
                | FsError::Overflow
                | FsError::Loop
                | FsError::Unsupported => Kind::InvalidArgument,
                FsError::Io => Kind::Io,
            },
            VolumeManagementError::NotSubvolume => Kind::NotSubvolume,
            VolumeManagementError::ReadOnlySubvolume => Kind::ReadOnlySubvolume,
            VolumeManagementError::SubvolumeNotReadOnly => Kind::SubvolumeNotReadOnly,
            VolumeManagementError::SubvolumeNotEmpty => Kind::SubvolumeNotEmpty,
            VolumeManagementError::DefaultSubvolume => Kind::DefaultSubvolume,
            VolumeManagementError::QuotaNotEnabled => Kind::QuotaNotEnabled,
            VolumeManagementError::QuotaAlreadyEnabled => Kind::QuotaAlreadyEnabled,
            VolumeManagementError::QuotaExceeded => Kind::QuotaExceeded,
            VolumeManagementError::QgroupNotFound(_) => Kind::QgroupNotFound,
            VolumeManagementError::QgroupExists(_) => Kind::QgroupExists,
            VolumeManagementError::QgroupInvalidRelation => Kind::QgroupInvalidRelation,
            VolumeManagementError::DeviceNotFound(_) => Kind::DeviceNotFound,
            VolumeManagementError::LastDevice => Kind::LastDevice,
            VolumeManagementError::DeviceTooSmall => Kind::DeviceTooSmall,
            VolumeManagementError::InvalidStream(_) => Kind::InvalidStream,
            VolumeManagementError::Alignment => Kind::Alignment,
            VolumeManagementError::Overlap => Kind::Overlap,
            VolumeManagementError::ChecksumPolicyMismatch => Kind::ChecksumPolicyMismatch,
            VolumeManagementError::CloneSourceOutOfRange => Kind::CloneSourceOutOfRange,
            VolumeManagementError::PermissionDenied => Kind::PermissionDenied,
        },
    };
    wit::BtrfsError {
        kind,
        detail: format!("{error}"),
    }
}

fn wit_subvolume(info: SubvolumeInfo) -> wit::SubvolumeInfo {
    wit::SubvolumeInfo {
        id: info.id,
        parent_id: info.parent_id,
        path: info.path,
        uuid: info.uuid.to_vec(),
        parent_uuid: info.parent_uuid.map(|u| u.to_vec()),
        received_uuid: info.received_uuid.map(|u| u.to_vec()),
        generation: info.generation,
        ctransid: info.ctransid,
        otransid: info.otransid,
        stransid: info.stransid,
        rtransid: info.rtransid,
        read_only: info.read_only,
    }
}

fn wit_dedupe(outcome: DedupeOutcome) -> wit::DedupeOutcome {
    wit::DedupeOutcome {
        same: outcome.same,
        bytes_deduped: outcome.bytes_deduped,
    }
}

fn wit_device(info: VolumeDeviceInfo) -> wit::VolumeDeviceInfo {
    wit::VolumeDeviceInfo {
        devid: info.devid,
        uuid: info.uuid.to_vec(),
        total_bytes: info.total_bytes,
        bytes_used: info.bytes_used,
        serial: info
            .serial
            .and_then(|s| core::str::from_utf8(s.as_bytes()).ok().map(String::from)),
    }
}

fn wit_balance_report(report: BalanceReport) -> wit::BalanceReport {
    wit::BalanceReport {
        considered: report.considered,
        relocated: report.relocated,
    }
}

fn wit_scrub_report(report: ScrubReport) -> wit::ScrubReport {
    wit::ScrubReport {
        data_extents_scrubbed: report.data_extents_scrubbed,
        tree_extents_scrubbed: report.tree_extents_scrubbed,
        data_bytes_scrubbed: report.data_bytes_scrubbed,
        tree_bytes_scrubbed: report.tree_bytes_scrubbed,
        csum_errors: report.csum_errors,
        verify_errors: report.verify_errors,
        uncorrectable_errors: report.uncorrectable_errors,
        corrected_errors: report.corrected_errors,
        no_csum_sectors: report.no_csum_sectors,
    }
}

fn wit_qgroup_id(id: QgroupId) -> wit::QgroupId {
    wit::QgroupId {
        level: id.level,
        id: id.id,
    }
}

fn parse_qgroup_id(id: wit::QgroupId) -> Result<QgroupId, wit::BtrfsError> {
    QgroupId::new(id.level, id.id).ok_or_else(|| wit::BtrfsError {
        kind: wit::BtrfsErrorKind::InvalidArgument,
        detail: format!("qgroup id {} exceeds 48-bit range", id.id),
    })
}

fn wit_qgroup_limit(limit: QgroupLimit) -> wit::QgroupLimit {
    wit::QgroupLimit {
        max_referenced: limit.max_referenced,
        max_exclusive: limit.max_exclusive,
    }
}

fn from_wit_qgroup_limit(limit: wit::QgroupLimit) -> QgroupLimit {
    QgroupLimit {
        max_referenced: limit.max_referenced,
        max_exclusive: limit.max_exclusive,
    }
}

fn wit_qgroup_info(info: QgroupInfo) -> wit::QgroupInfo {
    wit::QgroupInfo {
        id: wit_qgroup_id(info.id),
        referenced_bytes: info.referenced_bytes,
        referenced_compressed_bytes: info.referenced_compressed_bytes,
        exclusive_bytes: info.exclusive_bytes,
        exclusive_compressed_bytes: info.exclusive_compressed_bytes,
        limit: wit_qgroup_limit(info.limit),
        parents: info.parents.into_iter().map(wit_qgroup_id).collect(),
    }
}

fn wit_quota_status(status: QuotaStatus) -> wit::QuotaStatus {
    wit::QuotaStatus {
        enabled: status.enabled,
        rescanning: status.rescanning,
        inconsistent: status.inconsistent,
        generation: status.generation,
    }
}

fn extract_context<CpuImpl, Net, StorageImpl, U>(
    accessor: &Accessor<U, HasSelf<StoreData<CpuImpl, Net, StorageImpl>>>,
) -> (
    crate::ProcessAuthority,
    crate::Namespace<StorageImpl>,
    crate::AttachedStorage<StorageImpl>,
    u64,
)
where
    U: 'static,
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    accessor.with(|mut access| {
        let store = access.get();
        (
            store.process_authority().clone(),
            store.filesystem().clone(),
            store.runtime_state.attached_storage(),
            store.now_nanos(),
        )
    })
}

impl<CpuImpl, Net, StorageImpl> wit::Host for StoreData<CpuImpl, Net, StorageImpl>
where
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
}

impl<CpuImpl, Net, StorageImpl, U> wit::HostWithStore<U>
    for HasSelf<StoreData<CpuImpl, Net, StorageImpl>>
where
    U: 'static,
    CpuImpl: Cpu + Clone,
    Net: ComponentHostNetwork,
    StorageImpl: crate::Storage,
{
    async fn create_subvolume(
        accessor: &Accessor<U, Self>,
        path: String,
    ) -> wasmtime::Result<Result<wit::SubvolumeInfo, wit::BtrfsError>> {
        let (authority, namespace, attached, now) = extract_context(accessor);
        let req = BtrfsVolumeRequest {
            authority: &authority,
            namespace: &namespace,
            attached,
            now,
        };
        Ok(req
            .create_subvolume(&path)
            .await
            .map(wit_subvolume)
            .map_err(|e| wit_error(&e)))
    }

    async fn delete_subvolume(
        accessor: &Accessor<U, Self>,
        path: String,
    ) -> wasmtime::Result<Result<(), wit::BtrfsError>> {
        let (authority, namespace, attached, now) = extract_context(accessor);
        let req = BtrfsVolumeRequest {
            authority: &authority,
            namespace: &namespace,
            attached,
            now,
        };
        Ok(req.delete_subvolume(&path).await.map_err(|e| wit_error(&e)))
    }

    async fn snapshot_subvolume(
        accessor: &Accessor<U, Self>,
        source: String,
        destination: String,
        read_only: bool,
    ) -> wasmtime::Result<Result<wit::SubvolumeInfo, wit::BtrfsError>> {
        let (authority, namespace, attached, now) = extract_context(accessor);
        let req = BtrfsVolumeRequest {
            authority: &authority,
            namespace: &namespace,
            attached,
            now,
        };
        Ok(req
            .snapshot_subvolume(&source, &destination, read_only)
            .await
            .map(wit_subvolume)
            .map_err(|e| wit_error(&e)))
    }

    async fn set_subvolume_read_only(
        accessor: &Accessor<U, Self>,
        path: String,
        read_only: bool,
    ) -> wasmtime::Result<Result<(), wit::BtrfsError>> {
        let (authority, namespace, attached, now) = extract_context(accessor);
        let req = BtrfsVolumeRequest {
            authority: &authority,
            namespace: &namespace,
            attached,
            now,
        };
        Ok(req
            .set_subvolume_read_only(&path, read_only)
            .await
            .map_err(|e| wit_error(&e)))
    }

    async fn get_subvolume_info(
        accessor: &Accessor<U, Self>,
        path: String,
    ) -> wasmtime::Result<Result<wit::SubvolumeInfo, wit::BtrfsError>> {
        let (authority, namespace, attached, now) = extract_context(accessor);
        let req = BtrfsVolumeRequest {
            authority: &authority,
            namespace: &namespace,
            attached,
            now,
        };
        Ok(req
            .subvolume_info(&path)
            .await
            .map(wit_subvolume)
            .map_err(|e| wit_error(&e)))
    }

    async fn list_subvolumes(
        accessor: &Accessor<U, Self>,
        mount_point: String,
    ) -> wasmtime::Result<Result<Vec<wit::SubvolumeInfo>, wit::BtrfsError>> {
        let (authority, namespace, attached, now) = extract_context(accessor);
        let req = BtrfsVolumeRequest {
            authority: &authority,
            namespace: &namespace,
            attached,
            now,
        };
        Ok(req
            .list_subvolumes(&mount_point)
            .await
            .map(|list| list.into_iter().map(wit_subvolume).collect())
            .map_err(|e| wit_error(&e)))
    }

    async fn send_subvolume(
        accessor: &Accessor<U, Self>,
        subvolume: String,
        parent: Option<String>,
        clone_sources: Vec<String>,
    ) -> wasmtime::Result<Result<Vec<u8>, wit::BtrfsError>> {
        let (authority, namespace, attached, now) = extract_context(accessor);
        let req = BtrfsVolumeRequest {
            authority: &authority,
            namespace: &namespace,
            attached,
            now,
        };
        Ok(req
            .send_subvolume(&subvolume, parent.as_deref(), &clone_sources)
            .await
            .map_err(|e| wit_error(&e)))
    }

    async fn receive_subvolume(
        accessor: &Accessor<U, Self>,
        destination: String,
        stream: Vec<u8>,
    ) -> wasmtime::Result<Result<wit::SubvolumeInfo, wit::BtrfsError>> {
        let (authority, namespace, attached, now) = extract_context(accessor);
        let req = BtrfsVolumeRequest {
            authority: &authority,
            namespace: &namespace,
            attached,
            now,
        };
        Ok(req
            .receive_subvolume(&destination, &stream)
            .await
            .map(wit_subvolume)
            .map_err(|e| wit_error(&e)))
    }

    async fn reflink(
        accessor: &Accessor<U, Self>,
        source: String,
        source_offset: u64,
        destination: String,
        destination_offset: u64,
        length: u64,
    ) -> wasmtime::Result<Result<(), wit::BtrfsError>> {
        let (authority, namespace, attached, now) = extract_context(accessor);
        let req = BtrfsVolumeRequest {
            authority: &authority,
            namespace: &namespace,
            attached,
            now,
        };
        Ok(req
            .reflink(
                &source,
                source_offset,
                &destination,
                destination_offset,
                length,
            )
            .await
            .map_err(|e| wit_error(&e)))
    }

    async fn dedupe(
        accessor: &Accessor<U, Self>,
        source: String,
        source_offset: u64,
        destination: String,
        destination_offset: u64,
        length: u64,
    ) -> wasmtime::Result<Result<wit::DedupeOutcome, wit::BtrfsError>> {
        let (authority, namespace, attached, now) = extract_context(accessor);
        let req = BtrfsVolumeRequest {
            authority: &authority,
            namespace: &namespace,
            attached,
            now,
        };
        Ok(req
            .dedupe(
                &source,
                source_offset,
                &destination,
                destination_offset,
                length,
            )
            .await
            .map(wit_dedupe)
            .map_err(|e| wit_error(&e)))
    }

    async fn list_devices(
        accessor: &Accessor<U, Self>,
        mount_point: String,
    ) -> wasmtime::Result<Result<Vec<wit::VolumeDeviceInfo>, wit::BtrfsError>> {
        let (authority, namespace, attached, now) = extract_context(accessor);
        let req = BtrfsVolumeRequest {
            authority: &authority,
            namespace: &namespace,
            attached,
            now,
        };
        Ok(req
            .list_devices(&mount_point)
            .await
            .map(|list| list.into_iter().map(wit_device).collect())
            .map_err(|e| wit_error(&e)))
    }

    async fn add_device(
        accessor: &Accessor<U, Self>,
        mount_point: String,
        device: String,
    ) -> wasmtime::Result<Result<wit::VolumeDeviceInfo, wit::BtrfsError>> {
        let (authority, namespace, attached, now) = extract_context(accessor);
        let req = BtrfsVolumeRequest {
            authority: &authority,
            namespace: &namespace,
            attached,
            now,
        };
        Ok(req
            .add_device(&mount_point, &device)
            .await
            .map(wit_device)
            .map_err(|e| wit_error(&e)))
    }

    async fn remove_device(
        accessor: &Accessor<U, Self>,
        mount_point: String,
        devid: u64,
    ) -> wasmtime::Result<Result<(), wit::BtrfsError>> {
        let (authority, namespace, attached, now) = extract_context(accessor);
        let req = BtrfsVolumeRequest {
            authority: &authority,
            namespace: &namespace,
            attached,
            now,
        };
        Ok(req
            .remove_device(&mount_point, devid)
            .await
            .map_err(|e| wit_error(&e)))
    }

    async fn replace_device(
        accessor: &Accessor<U, Self>,
        mount_point: String,
        source_devid: u64,
        target_device: String,
    ) -> wasmtime::Result<Result<wit::VolumeDeviceInfo, wit::BtrfsError>> {
        let (authority, namespace, attached, now) = extract_context(accessor);
        let req = BtrfsVolumeRequest {
            authority: &authority,
            namespace: &namespace,
            attached,
            now,
        };
        Ok(req
            .replace_device(&mount_point, source_devid, &target_device)
            .await
            .map(wit_device)
            .map_err(|e| wit_error(&e)))
    }

    async fn resize_device(
        accessor: &Accessor<U, Self>,
        mount_point: String,
        devid: Option<u64>,
        target: wit::ResizeTarget,
    ) -> wasmtime::Result<Result<wit::VolumeDeviceInfo, wit::BtrfsError>> {
        let (authority, namespace, attached, now) = extract_context(accessor);
        let req = BtrfsVolumeRequest {
            authority: &authority,
            namespace: &namespace,
            attached,
            now,
        };
        let target = match target {
            wit::ResizeTarget::Max => ResizeTarget::Max,
            wit::ResizeTarget::Bytes(bytes) => ResizeTarget::Bytes(bytes),
        };
        Ok(req
            .resize_device(&mount_point, devid, target)
            .await
            .map(wit_device)
            .map_err(|e| wit_error(&e)))
    }

    async fn balance(
        accessor: &Accessor<U, Self>,
        mount_point: String,
        filter: wit::BalanceFilter,
    ) -> wasmtime::Result<Result<wit::BalanceReport, wit::BtrfsError>> {
        let (authority, namespace, attached, now) = extract_context(accessor);
        let req = BtrfsVolumeRequest {
            authority: &authority,
            namespace: &namespace,
            attached,
            now,
        };
        let filter = BalanceFilter {
            data: filter.data,
            metadata: filter.metadata,
            system: filter.system,
            usage_max_percent: filter.usage_max_percent,
            limit: filter.limit,
        };
        Ok(req
            .balance(&mount_point, filter)
            .await
            .map(wit_balance_report)
            .map_err(|e| wit_error(&e)))
    }

    async fn scrub(
        accessor: &Accessor<U, Self>,
        mount_point: String,
        devid: Option<u64>,
        read_only: bool,
    ) -> wasmtime::Result<Result<wit::ScrubReport, wit::BtrfsError>> {
        let (authority, namespace, attached, now) = extract_context(accessor);
        let req = BtrfsVolumeRequest {
            authority: &authority,
            namespace: &namespace,
            attached,
            now,
        };
        Ok(req
            .scrub(&mount_point, devid, read_only)
            .await
            .map(wit_scrub_report)
            .map_err(|e| wit_error(&e)))
    }

    async fn quota_enable(
        accessor: &Accessor<U, Self>,
        mount_point: String,
    ) -> wasmtime::Result<Result<(), wit::BtrfsError>> {
        let (authority, namespace, attached, now) = extract_context(accessor);
        let req = BtrfsVolumeRequest {
            authority: &authority,
            namespace: &namespace,
            attached,
            now,
        };
        Ok(req
            .quota_enable(&mount_point)
            .await
            .map_err(|e| wit_error(&e)))
    }

    async fn quota_disable(
        accessor: &Accessor<U, Self>,
        mount_point: String,
    ) -> wasmtime::Result<Result<(), wit::BtrfsError>> {
        let (authority, namespace, attached, now) = extract_context(accessor);
        let req = BtrfsVolumeRequest {
            authority: &authority,
            namespace: &namespace,
            attached,
            now,
        };
        Ok(req
            .quota_disable(&mount_point)
            .await
            .map_err(|e| wit_error(&e)))
    }

    async fn quota_rescan(
        accessor: &Accessor<U, Self>,
        mount_point: String,
    ) -> wasmtime::Result<Result<(), wit::BtrfsError>> {
        let (authority, namespace, attached, now) = extract_context(accessor);
        let req = BtrfsVolumeRequest {
            authority: &authority,
            namespace: &namespace,
            attached,
            now,
        };
        Ok(req
            .quota_rescan(&mount_point)
            .await
            .map_err(|e| wit_error(&e)))
    }

    async fn get_quota_status(
        accessor: &Accessor<U, Self>,
        mount_point: String,
    ) -> wasmtime::Result<Result<wit::QuotaStatus, wit::BtrfsError>> {
        let (authority, namespace, attached, now) = extract_context(accessor);
        let req = BtrfsVolumeRequest {
            authority: &authority,
            namespace: &namespace,
            attached,
            now,
        };
        Ok(req
            .quota_status(&mount_point)
            .await
            .map(wit_quota_status)
            .map_err(|e| wit_error(&e)))
    }

    async fn qgroup_list(
        accessor: &Accessor<U, Self>,
        mount_point: String,
    ) -> wasmtime::Result<Result<Vec<wit::QgroupInfo>, wit::BtrfsError>> {
        let (authority, namespace, attached, now) = extract_context(accessor);
        let req = BtrfsVolumeRequest {
            authority: &authority,
            namespace: &namespace,
            attached,
            now,
        };
        Ok(req
            .list_qgroups(&mount_point)
            .await
            .map(|list| list.into_iter().map(wit_qgroup_info).collect())
            .map_err(|e| wit_error(&e)))
    }

    async fn qgroup_create(
        accessor: &Accessor<U, Self>,
        mount_point: String,
        group: wit::QgroupId,
    ) -> wasmtime::Result<Result<(), wit::BtrfsError>> {
        let group = match parse_qgroup_id(group) {
            Ok(id) => id,
            Err(err) => return Ok(Err(err)),
        };
        let (authority, namespace, attached, now) = extract_context(accessor);
        let req = BtrfsVolumeRequest {
            authority: &authority,
            namespace: &namespace,
            attached,
            now,
        };
        Ok(req
            .qgroup_create(&mount_point, group)
            .await
            .map_err(|e| wit_error(&e)))
    }

    async fn qgroup_destroy(
        accessor: &Accessor<U, Self>,
        mount_point: String,
        group: wit::QgroupId,
    ) -> wasmtime::Result<Result<(), wit::BtrfsError>> {
        let group = match parse_qgroup_id(group) {
            Ok(id) => id,
            Err(err) => return Ok(Err(err)),
        };
        let (authority, namespace, attached, now) = extract_context(accessor);
        let req = BtrfsVolumeRequest {
            authority: &authority,
            namespace: &namespace,
            attached,
            now,
        };
        Ok(req
            .qgroup_destroy(&mount_point, group)
            .await
            .map_err(|e| wit_error(&e)))
    }

    async fn qgroup_assign(
        accessor: &Accessor<U, Self>,
        mount_point: String,
        member: wit::QgroupId,
        parent: wit::QgroupId,
    ) -> wasmtime::Result<Result<(), wit::BtrfsError>> {
        let member = match parse_qgroup_id(member) {
            Ok(id) => id,
            Err(err) => return Ok(Err(err)),
        };
        let parent = match parse_qgroup_id(parent) {
            Ok(id) => id,
            Err(err) => return Ok(Err(err)),
        };
        let (authority, namespace, attached, now) = extract_context(accessor);
        let req = BtrfsVolumeRequest {
            authority: &authority,
            namespace: &namespace,
            attached,
            now,
        };
        Ok(req
            .qgroup_assign(&mount_point, member, parent)
            .await
            .map_err(|e| wit_error(&e)))
    }

    async fn qgroup_remove(
        accessor: &Accessor<U, Self>,
        mount_point: String,
        member: wit::QgroupId,
        parent: wit::QgroupId,
    ) -> wasmtime::Result<Result<(), wit::BtrfsError>> {
        let member = match parse_qgroup_id(member) {
            Ok(id) => id,
            Err(err) => return Ok(Err(err)),
        };
        let parent = match parse_qgroup_id(parent) {
            Ok(id) => id,
            Err(err) => return Ok(Err(err)),
        };
        let (authority, namespace, attached, now) = extract_context(accessor);
        let req = BtrfsVolumeRequest {
            authority: &authority,
            namespace: &namespace,
            attached,
            now,
        };
        Ok(req
            .qgroup_remove(&mount_point, member, parent)
            .await
            .map_err(|e| wit_error(&e)))
    }

    async fn set_qgroup_limit(
        accessor: &Accessor<U, Self>,
        mount_point: String,
        group: wit::QgroupId,
        limit: wit::QgroupLimit,
    ) -> wasmtime::Result<Result<(), wit::BtrfsError>> {
        let group = match parse_qgroup_id(group) {
            Ok(id) => id,
            Err(err) => return Ok(Err(err)),
        };
        let (authority, namespace, attached, now) = extract_context(accessor);
        let req = BtrfsVolumeRequest {
            authority: &authority,
            namespace: &namespace,
            attached,
            now,
        };
        Ok(req
            .qgroup_limit(&mount_point, group, from_wit_qgroup_limit(limit))
            .await
            .map_err(|e| wit_error(&e)))
    }
}
