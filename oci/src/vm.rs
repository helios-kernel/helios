//! Optional user-space OCI rootfs adapter for custom `MicroVm` instances.
//!
//! Layers an ephemeral writable overlay (a writable btrfs snapshot when backed by
//! btrfs, or an isolated working copy directory on non-btrfs storage) over a
//! read-only pulled OCI image, validates pass-through Helios host shares, and
//! supplies the `virtio-fs` rootfs, share specs, and Linux boot command line to
//! `helios_vmm::MicroVm::builder()` without coupling `helios-vmm` to OCI.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::error::{OciError, Result, SubvolumeError};
use crate::store::{DirectoryBackend, PulledImage, SubvolumeBackend};
use crate::unpack::{copy_tree_recursive, remove_path_recursive};

/// Virtio 1.2 §5.11.4 maximum UTF-8 byte length of a `virtio-fs` mount tag.
pub const MAX_VIRTIO_FS_TAG_BYTES: usize = 36;

/// Default `virtio-fs` mount tag expected by Linux `root=rootfs rootfstype=virtiofs`.
pub const ROOTFS_TAG: &str = "rootfs";

/// Default Linux kernel command line for booting an OCI rootfs over `virtio-fs`.
pub const DEFAULT_OCI_VM_CMDLINE: &str =
    "console=hvc0 earlycon=pl011,0x9000000 root=rootfs rootfstype=virtiofs rw panic=-1";

/// One pass-through Helios host directory shared into a VM over `virtio-fs`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VmHostShare {
    pub tag: String,
    pub host_path: String,
    pub read_only: bool,
}

impl VmHostShare {
    /// Construct and validate a pass-through `virtio-fs` share.
    pub fn new(
        tag: impl Into<String>,
        host_path: impl Into<String>,
        read_only: bool,
    ) -> Result<Self> {
        let tag = tag.into();
        let host_path = host_path.into();
        validate_share_tag(&tag)?;
        if host_path.is_empty() {
            return Err(OciError::InvalidShare {
                tag,
                reason: "host share path must not be empty",
            });
        }
        Ok(Self {
            tag,
            host_path,
            read_only,
        })
    }
}

/// RAII ephemeral writable VM rootfs layered over a read-only [`PulledImage`].
///
/// The read-only OCI image layer is never modified. Call [`Self::cleanup`] (for async
/// btrfs subvolume deletion) or drop the handle (best-effort directory cleanup) after
/// the VM exits.
pub struct OciVmRootfs {
    overlay_path: PathBuf,
    btrfs_snapshot: bool,
    host_shares: Vec<VmHostShare>,
    seen_tags: BTreeSet<String>,
    cmdline: String,
    cleaned_up: bool,
}

impl OciVmRootfs {
    /// Prepare an ephemeral writable overlay at `overlay_path` over `image`'s read-only
    /// rootfs using `backend` (writable btrfs snapshot when available, directory copy fallback
    /// when [`SubvolumeError::NotBtrfs`]).
    pub async fn prepare<B: SubvolumeBackend>(
        image: &PulledImage,
        overlay_path: impl Into<PathBuf>,
        backend: &B,
    ) -> Result<Self> {
        let overlay_path = overlay_path.into();
        if overlay_path.exists() {
            let _ = backend.delete_subvolume(&overlay_path).await;
            remove_path_recursive(&overlay_path)?;
        }
        if let Some(parent) = overlay_path.parent() {
            std::fs::create_dir_all(parent).map_err(|source| OciError::Io {
                operation: "create VM overlay parent directory",
                path: parent.to_path_buf(),
                source,
            })?;
        }

        let btrfs_snapshot = if image.btrfs_backed {
            match backend
                .snapshot_subvolume(&image.rootfs_path, &overlay_path, false)
                .await
            {
                Ok(_) => true,
                Err(SubvolumeError::NotBtrfs { .. }) => {
                    copy_tree_recursive(&image.rootfs_path, &overlay_path)?;
                    false
                }
                Err(err) => return Err(OciError::Subvolume(err)),
            }
        } else {
            copy_tree_recursive(&image.rootfs_path, &overlay_path)?;
            false
        };

        let mut seen_tags = BTreeSet::new();
        seen_tags.insert(ROOTFS_TAG.to_owned());

        let cmdline = build_oci_vm_cmdline(image);

        Ok(Self {
            overlay_path,
            btrfs_snapshot,
            host_shares: Vec::new(),
            seen_tags,
            cmdline,
            cleaned_up: false,
        })
    }

    /// Prepare an ephemeral directory overlay using [`DirectoryBackend`].
    pub async fn prepare_directory(
        image: &PulledImage,
        overlay_path: impl Into<PathBuf>,
    ) -> Result<Self> {
        Self::prepare(image, overlay_path, &DirectoryBackend).await
    }

    /// Attach a pass-through Helios host directory share alongside the OCI rootfs.
    pub fn with_host_share(
        mut self,
        tag: impl Into<String>,
        host_path: impl Into<String>,
        read_only: bool,
    ) -> Result<Self> {
        let share = VmHostShare::new(tag, host_path, read_only)?;
        if !self.seen_tags.insert(share.tag.clone()) {
            return Err(OciError::InvalidShare {
                tag: share.tag,
                reason: "duplicate virtio-fs share tag (note `rootfs` is reserved)",
            });
        }
        self.host_shares.push(share);
        Ok(self)
    }

    /// Override the generated Linux kernel command line.
    #[must_use]
    pub fn with_cmdline(mut self, cmdline: impl Into<String>) -> Self {
        self.cmdline = cmdline.into();
        self
    }

    /// Path to the ephemeral writable rootfs directory exposed as `virtio-fs` tag `"rootfs"`.
    #[must_use]
    pub fn rootfs_path(&self) -> &Path {
        &self.overlay_path
    }

    /// UTF-8 string path for passing into `MicroVmBuilder::rootfs_dir`.
    pub fn rootfs_path_str(&self) -> Result<&str> {
        self.overlay_path
            .to_str()
            .ok_or_else(|| OciError::InvalidShare {
                tag: ROOTFS_TAG.to_owned(),
                reason: "overlay rootfs path is not valid UTF-8",
            })
    }

    /// Whether the ephemeral overlay is a writable btrfs snapshot.
    #[must_use]
    pub const fn is_btrfs_snapshot(&self) -> bool {
        self.btrfs_snapshot
    }

    /// Pass-through Helios host shares configured alongside the OCI rootfs.
    #[must_use]
    pub fn host_shares(&self) -> &[VmHostShare] {
        &self.host_shares
    }

    /// Linux kernel boot command line configured for `virtio-fs` rootfs boot.
    #[must_use]
    pub fn cmdline(&self) -> &str {
        &self.cmdline
    }

    /// Generic zero-`dyn` adapter applying this OCI rootfs, pass-through Helios host shares,
    /// and kernel command line onto any VM builder (such as `helios_vmm::MicroVmBuilder`).
    pub fn configure_builder<B, E>(
        &self,
        mut builder: B,
        set_rootfs: impl FnOnce(B, &str) -> core::result::Result<B, E>,
        mut add_share: impl FnMut(B, &VmHostShare) -> core::result::Result<B, E>,
        set_cmdline: impl FnOnce(B, &str) -> B,
    ) -> core::result::Result<B, E>
    where
        E: From<OciError>,
    {
        let rootfs = self.rootfs_path_str()?;
        builder = set_rootfs(builder, rootfs)?;
        for share in &self.host_shares {
            builder = add_share(builder, share)?;
        }
        builder = set_cmdline(builder, &self.cmdline);
        Ok(builder)
    }

    /// Explicitly tear down the ephemeral overlay (deleting its btrfs subvolume when
    /// btrfs-backed, or removing its working directory otherwise).
    pub async fn cleanup<B: SubvolumeBackend>(mut self, backend: &B) -> Result<()> {
        self.cleaned_up = true;
        if self.btrfs_snapshot {
            match backend.delete_subvolume(&self.overlay_path).await {
                Ok(()) | Err(SubvolumeError::NotFound { .. }) => return Ok(()),
                Err(SubvolumeError::NotBtrfs { .. }) => {}
                Err(err) => return Err(OciError::Subvolume(err)),
            }
        }
        remove_path_recursive(&self.overlay_path)
    }
}

impl Drop for OciVmRootfs {
    fn drop(&mut self) {
        if !self.cleaned_up {
            let _ = remove_path_recursive(&self.overlay_path);
        }
    }
}

fn build_oci_vm_cmdline(image: &PulledImage) -> String {
    let mut cmdline = DEFAULT_OCI_VM_CMDLINE.to_owned();
    if let Some((init_path, _args)) = image.config.config.resolve_command(None)
        && init_path.starts_with('/')
        && !init_path.chars().any(char::is_whitespace)
    {
        cmdline.push_str(" init=");
        cmdline.push_str(&init_path);
    }
    cmdline
}

fn validate_share_tag(tag: &str) -> Result<()> {
    if tag.is_empty() {
        return Err(OciError::InvalidShare {
            tag: tag.to_owned(),
            reason: "tag must not be empty",
        });
    }
    if tag.len() > MAX_VIRTIO_FS_TAG_BYTES {
        return Err(OciError::InvalidShare {
            tag: tag.to_owned(),
            reason: "tag exceeds 36-byte virtio-fs limit",
        });
    }
    if tag.contains('\0') || tag.contains('/') {
        return Err(OciError::InvalidShare {
            tag: tag.to_owned(),
            reason: "tag must not contain NUL or '/'",
        });
    }
    Ok(())
}
