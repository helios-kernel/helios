//! Custom Linux `MicroVm` orchestration helpers over [`Session`] (`/bin/vmm` +
//! `helios:hv/virtualization` + optional user-space OCI rootfs overlay).

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use helios_oci::DEFAULT_OCI_VM_CMDLINE;
use helios_wit_rpc::inspector::helios::system::programs::{
    CapabilityGrant, DirectoryGrant, ExecResult, FilesystemRight, MachineGrant, MachineRight,
};
use helios_wit_rpc::inspector_snapshot::HvVm;
use serde::{Deserialize, Serialize};

use crate::error::OpsError;
use crate::grants::NonFsGrants;
use crate::session::{Child, Session, SpawnRequest, normalize_absolute_path};
use crate::target::GrantRight;

/// Default guest binary implementing the `helios-vmm` micro-VM runner.
pub const DEFAULT_VMM_BINARY: &str = "/bin/vmm";

/// Virtio 1.2 §5.11.4 maximum UTF-8 byte length of a `virtio-fs` mount tag.
const MAX_VIRTIO_FS_TAG_BYTES: usize = 36;

static OVERLAY_SEQ: AtomicU64 = AtomicU64::new(1);

/// Backing raw disk image attached to a [`MicroVm`] over `virtio-blk`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmDisk {
    pub path: String,
    pub writable: bool,
}

impl VmDisk {
    #[must_use]
    pub fn new(path: impl Into<String>, writable: bool) -> Self {
        Self {
            path: path.into(),
            writable,
        }
    }
}

/// Pass-through host directory shared into a [`MicroVm`] over `virtio-fs`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmShare {
    pub tag: String,
    pub path: String,
    pub writable: bool,
}

impl VmShare {
    /// Construct a `virtio-fs` share with an explicit mount tag.
    pub fn new(
        tag: impl Into<String>,
        path: impl Into<String>,
        writable: bool,
    ) -> Result<Self, OpsError> {
        let tag = tag.into();
        let path = path.into();
        validate_share_tag(&tag)?;
        if path.trim().is_empty() {
            return Err(OpsError::InvalidVmConfig {
                detail: "virtio-fs share path must not be empty".to_owned(),
            });
        }
        Ok(Self {
            tag,
            path,
            writable,
        })
    }

    /// Construct a `virtio-fs` share deriving a valid mount tag from `path`'s basename.
    pub fn from_path(path: impl Into<String>, writable: bool) -> Result<Self, OpsError> {
        let path = path.into();
        let normalized = normalize_absolute_path(&path)?;
        let derived_tag = Path::new(&normalized)
            .file_name()
            .and_then(|n| n.to_str())
            .filter(|s| !s.is_empty() && *s != "rootfs")
            .unwrap_or("share");
        let tag: String = derived_tag.chars().take(MAX_VIRTIO_FS_TAG_BYTES).collect();
        Self::new(tag, normalized, writable)
    }
}

/// Complete launch configuration for a guest [`MicroVm`].
#[derive(Debug, Clone)]
pub struct MicroVmConfig {
    pub vmm_binary: String,
    pub kernel: String,
    pub initramfs: Option<String>,
    pub cpus: u32,
    pub memory_mib: u64,
    pub cmdline: Option<String>,
    pub disks: Vec<VmDisk>,
    pub shares: Vec<VmShare>,
    pub rootfs_dir: Option<String>,
    pub oci_image: Option<String>,
    pub extra_grants: NonFsGrants,
}

impl MicroVmConfig {
    #[must_use]
    pub fn builder(kernel: impl Into<String>) -> MicroVmBuilder {
        MicroVmBuilder::new(kernel)
    }

    /// Translate this configuration into a guest [`SpawnRequest`] targeting `vmm_binary`
    /// with minimal `MachineRight::Virtualize` + file/directory capability grants.
    pub fn to_spawn_request(
        &self,
        resolved_rootfs: Option<&str>,
    ) -> Result<SpawnRequest, OpsError> {
        if self.kernel.trim().is_empty() {
            return Err(OpsError::InvalidVmConfig {
                detail: "MicroVm requires a non-empty `kernel` path".to_owned(),
            });
        }
        if self.cpus == 0 || self.cpus > 256 {
            return Err(OpsError::InvalidVmConfig {
                detail: format!("MicroVm `cpus` must be in 1..=256, got {}", self.cpus),
            });
        }
        if self.memory_mib == 0 {
            return Err(OpsError::InvalidVmConfig {
                detail: "MicroVm `memory_mib` must be > 0".to_owned(),
            });
        }

        let kernel = normalize_absolute_path(&self.kernel)?;
        let mut args = vec![
            "--kernel".to_owned(),
            kernel.clone(),
            "--cpus".to_owned(),
            self.cpus.to_string(),
            "--memory-mib".to_owned(),
            self.memory_mib.to_string(),
        ];

        let mut dir_rights: BTreeMap<String, bool> = BTreeMap::new();
        grant_parent_dir(&mut dir_rights, &kernel, false);

        if let Some(initramfs) = &self.initramfs {
            let norm = normalize_absolute_path(initramfs)?;
            args.push("--initramfs".to_owned());
            args.push(norm.clone());
            grant_parent_dir(&mut dir_rights, &norm, false);
        }

        if let Some(cmdline) = &self.cmdline {
            args.push("--cmdline".to_owned());
            args.push(cmdline.clone());
        } else if resolved_rootfs.is_some() {
            args.push("--cmdline".to_owned());
            args.push(DEFAULT_OCI_VM_CMDLINE.to_owned());
        }

        for disk in &self.disks {
            let norm = normalize_absolute_path(&disk.path)?;
            args.push("--disk".to_owned());
            args.push(norm.clone());
            grant_parent_dir(&mut dir_rights, &norm, disk.writable);
        }

        if let Some(rootfs) = resolved_rootfs {
            let norm = normalize_absolute_path(rootfs)?;
            args.push("--rootfs-dir".to_owned());
            args.push(norm.clone());
            merge_dir_grant(&mut dir_rights, norm, true);
        }

        for share in &self.shares {
            validate_share_tag(&share.tag)?;
            let norm = normalize_absolute_path(&share.path)?;
            args.push("--share-dir".to_owned());
            args.push(format!("{}:{norm}", share.tag));
            merge_dir_grant(&mut dir_rights, norm, share.writable);
        }

        let mut capability_grants = Vec::new();
        capability_grants.push(CapabilityGrant::Machine(MachineGrant {
            rights: vec![MachineRight::Virtualize],
        }));
        capability_grants.extend(self.extra_grants.clone().into_capability_grants());
        for (dir, writable) in dir_rights {
            let rights = if writable {
                vec![
                    FilesystemRight::Read,
                    FilesystemRight::Write,
                    FilesystemRight::MutateDirectory,
                ]
            } else {
                vec![FilesystemRight::Read]
            };
            capability_grants.push(CapabilityGrant::Directory(DirectoryGrant {
                source_path: dir.clone(),
                guest_name: dir,
                rights,
            }));
        }

        Ok(SpawnRequest {
            path: self.vmm_binary.clone(),
            args,
            env: Vec::new(),
            cwd: None,
            stdin: Vec::new(),
            capability_grants,
        })
    }
}

/// Fluent builder for [`MicroVmConfig`].
#[derive(Debug, Clone)]
pub struct MicroVmBuilder {
    config: MicroVmConfig,
}

impl MicroVmBuilder {
    #[must_use]
    pub fn new(kernel: impl Into<String>) -> Self {
        Self {
            config: MicroVmConfig {
                vmm_binary: DEFAULT_VMM_BINARY.to_owned(),
                kernel: kernel.into(),
                initramfs: None,
                cpus: 1,
                memory_mib: 128,
                cmdline: None,
                disks: Vec::new(),
                shares: Vec::new(),
                rootfs_dir: None,
                oci_image: None,
                extra_grants: NonFsGrants::new(),
            },
        }
    }

    #[must_use]
    pub fn vmm_binary(mut self, path: impl Into<String>) -> Self {
        self.config.vmm_binary = path.into();
        self
    }

    #[must_use]
    pub fn initramfs(mut self, path: impl Into<String>) -> Self {
        self.config.initramfs = Some(path.into());
        self
    }

    #[must_use]
    pub const fn cpus(mut self, cpus: u32) -> Self {
        self.config.cpus = cpus;
        self
    }

    #[must_use]
    pub const fn memory_mib(mut self, memory_mib: u64) -> Self {
        self.config.memory_mib = memory_mib;
        self
    }

    #[must_use]
    pub fn cmdline(mut self, cmdline: impl Into<String>) -> Self {
        self.config.cmdline = Some(cmdline.into());
        self
    }

    #[must_use]
    pub fn disk(mut self, disk: VmDisk) -> Self {
        self.config.disks.push(disk);
        self
    }

    #[must_use]
    pub fn share(mut self, share: VmShare) -> Self {
        self.config.shares.push(share);
        self
    }

    #[must_use]
    pub fn rootfs_dir(mut self, path: impl Into<String>) -> Self {
        self.config.rootfs_dir = Some(path.into());
        self
    }

    #[must_use]
    pub fn oci_image(mut self, reference: impl Into<String>) -> Self {
        self.config.oci_image = Some(reference.into());
        self
    }

    #[must_use]
    pub fn extra_grants(mut self, grants: NonFsGrants) -> Self {
        self.config.extra_grants = grants;
        self
    }

    #[must_use]
    pub fn build(self) -> MicroVmConfig {
        self.config
    }

    /// Spawn this VM on `session`.
    pub async fn spawn(self, session: &Session) -> Result<MicroVm, OpsError> {
        session.vm().spawn(self.config).await
    }
}

/// Live handle to a remotely running custom Linux [`MicroVm`].
pub struct MicroVm {
    session: Session,
    config: MicroVmConfig,
    child: Option<Child>,
    console_stdout: async_channel::Receiver<Result<Vec<u8>, OpsError>>,
    console_stderr: async_channel::Receiver<Result<Vec<u8>, OpsError>>,
    ephemeral_btrfs_overlay: Option<String>,
}

impl MicroVm {
    /// Launch configuration used for this VM.
    #[must_use]
    pub const fn config(&self) -> &MicroVmConfig {
        &self.config
    }

    /// Live guest instance ID of the `vmm` host process, if running.
    #[must_use]
    pub fn instance_id(&self) -> Option<u64> {
        self.child.as_ref().and_then(Child::instance_id)
    }

    /// Streaming serial/virtio-console stdout channel from the VM.
    #[must_use]
    pub const fn console(&self) -> &async_channel::Receiver<Result<Vec<u8>, OpsError>> {
        &self.console_stdout
    }

    /// Streaming stderr channel from the `vmm` host process.
    #[must_use]
    pub const fn stderr(&self) -> &async_channel::Receiver<Result<Vec<u8>, OpsError>> {
        &self.console_stderr
    }

    /// Write raw bytes to the VM's console stdin stream.
    pub async fn write_console(&self, data: &[u8]) -> Result<(), OpsError> {
        let Some(child) = self.child.as_ref() else {
            return Err(OpsError::StdinClosed);
        };
        child.write_stdin(data).await
    }

    /// Wait for the VM to exit naturally and clean up any ephemeral OCI rootfs overlay.
    pub async fn wait(mut self) -> Result<ExecResult, OpsError> {
        let result = match self.child.take() {
            Some(child) => child.wait().await,
            None => Err(OpsError::StdinClosed),
        };
        self.cleanup_overlay().await;
        result
    }

    /// Request graceful shutdown (`SIGTERM`, falling back to `SIGKILL`) and clean up
    /// any ephemeral OCI rootfs overlay.
    pub async fn shutdown(mut self) -> Result<Option<ExecResult>, OpsError> {
        let result = if let Some(child) = self.child.take() {
            let _ = child.signal("SIGTERM").await;
            match child.wait().await {
                Ok(res) => Ok(Some(res)),
                Err(err) => Err(err),
            }
        } else {
            Ok(None)
        };
        self.cleanup_overlay().await;
        result
    }

    async fn cleanup_overlay(&mut self) {
        if let Some(overlay) = self.ephemeral_btrfs_overlay.take() {
            let _ = self.session.btrfs().delete_subvolume(&overlay).await;
        }
    }
}

/// Remote VM orchestration client bound to a [`Session`].
#[derive(Clone)]
pub struct VmClient {
    session: Session,
}

impl VmClient {
    #[must_use]
    pub const fn new(session: Session) -> Self {
        Self { session }
    }

    /// Start building a [`MicroVmConfig`] for `kernel`.
    #[must_use]
    pub fn builder(&self, kernel: impl Into<String>) -> MicroVmBuilder {
        MicroVmBuilder::new(kernel)
    }

    /// List live hardware VMs reported in `/kernel/hv/*`.
    pub async fn list(&self) -> Result<Vec<HvVm>, OpsError> {
        let snap = self.session.kernel_snapshot().await?;
        Ok(snap.hv_vms)
    }

    /// Launch a custom Linux [`MicroVm`] on the remote guest.
    ///
    /// When `config.oci_image` is set and `config.rootfs_dir` is unset, resolves
    /// the pulled OCI image in the remote store and prepares an ephemeral
    /// writable btrfs snapshot (when btrfs-backed) or uses the image rootfs
    /// directory directly over `virtio-fs`.
    pub async fn spawn(&self, config: MicroVmConfig) -> Result<MicroVm, OpsError> {
        self.session.require_right(GrantRight::Virtualize)?;
        self.session.require_right(GrantRight::Exec)?;

        let mut ephemeral_btrfs_overlay: Option<String> = None;
        let resolved_rootfs: Option<String> = if let Some(dir) = &config.rootfs_dir {
            Some(dir.clone())
        } else if let Some(oci_ref) = &config.oci_image {
            let oci = self.session.oci();
            let image = match oci.inspect(oci_ref).await {
                Ok(img) => img,
                Err(OpsError::NotFound { .. }) => oci.pull(oci_ref).await?,
                Err(err) => return Err(err),
            };
            let base_rootfs = image.rootfs_path().to_string_lossy().into_owned();
            if image.btrfs_backed {
                let seq = OVERLAY_SEQ.fetch_add(1, Ordering::Relaxed);
                let overlay_path = format!(
                    "{}/vm-overlays/vm-{seq}",
                    oci.store_root().trim_end_matches('/')
                );
                let _ = self
                    .session
                    .mkdir(&format!(
                        "{}/vm-overlays",
                        oci.store_root().trim_end_matches('/')
                    ))
                    .await;
                match self
                    .session
                    .btrfs()
                    .snapshot_subvolume(&base_rootfs, &overlay_path, false)
                    .await
                {
                    Ok(_) => {
                        ephemeral_btrfs_overlay = Some(overlay_path.clone());
                        Some(overlay_path)
                    }
                    Err(_) => Some(base_rootfs),
                }
            } else {
                Some(base_rootfs)
            }
        } else {
            None
        };

        let spawn_req = config.to_spawn_request(resolved_rootfs.as_deref())?;
        let child = match self.session.spawn(spawn_req).await {
            Ok(child) => child,
            Err(err) => {
                if let Some(overlay) = ephemeral_btrfs_overlay {
                    let _ = self.session.btrfs().delete_subvolume(&overlay).await;
                }
                return Err(err);
            }
        };
        let console_stdout = child.stdout.clone();
        let console_stderr = child.stderr.clone();

        Ok(MicroVm {
            session: self.session.clone(),
            config,
            child: Some(child),
            console_stdout,
            console_stderr,
            ephemeral_btrfs_overlay,
        })
    }
}

fn grant_parent_dir(map: &mut BTreeMap<String, bool>, file_path: &str, writable: bool) {
    let dir = Path::new(file_path)
        .parent()
        .and_then(|p| p.to_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("/")
        .to_owned();
    merge_dir_grant(map, dir, writable);
}

fn merge_dir_grant(map: &mut BTreeMap<String, bool>, dir: String, writable: bool) {
    map.entry(dir)
        .and_modify(|existing| *existing |= writable)
        .or_insert(writable);
}

fn validate_share_tag(tag: &str) -> Result<(), OpsError> {
    if tag.is_empty() {
        return Err(OpsError::InvalidVmConfig {
            detail: "virtio-fs share tag must not be empty".to_owned(),
        });
    }
    if tag.len() > MAX_VIRTIO_FS_TAG_BYTES {
        return Err(OpsError::InvalidVmConfig {
            detail: format!("virtio-fs share tag `{tag}` exceeds 36-byte limit"),
        });
    }
    if tag.contains('\0') || tag.contains('/') || tag.contains(':') {
        return Err(OpsError::InvalidVmConfig {
            detail: format!("virtio-fs share tag `{tag}` must not contain NUL, `/`, or `:`"),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn micro_vm_config_builds_minimal_vmm_spawn_request() {
        let cfg = MicroVmConfig::builder("/boot/Image")
            .initramfs("/boot/initramfs.cpio")
            .cpus(4)
            .memory_mib(512)
            .cmdline("console=hvc0")
            .disk(VmDisk::new("/var/data/root.img", true))
            .share(VmShare::from_path("/host/workspace", false).expect("share"))
            .build();

        let req = cfg
            .to_spawn_request(Some("/var/lib/helios/oci/vm-overlays/vm-1"))
            .expect("spawn request");

        assert_eq!(req.path, DEFAULT_VMM_BINARY);
        assert!(
            req.args
                .windows(2)
                .any(|w| w == ["--kernel", "/boot/Image"])
        );
        assert!(req.args.windows(2).any(|w| w == ["--cpus", "4"]));
        assert!(req.args.windows(2).any(|w| w == ["--memory-mib", "512"]));
        assert!(
            req.args
                .windows(2)
                .any(|w| w == ["--disk", "/var/data/root.img"])
        );
        assert!(
            req.args
                .windows(2)
                .any(|w| w == ["--share-dir", "workspace:/host/workspace"])
        );
        assert!(
            req.args
                .windows(2)
                .any(|w| { w == ["--rootfs-dir", "/var/lib/helios/oci/vm-overlays/vm-1",] })
        );
        assert!(req.capability_grants.iter().any(|g| matches!(
            g,
            CapabilityGrant::Machine(m) if m.rights.contains(&MachineRight::Virtualize)
        )));
    }
}
