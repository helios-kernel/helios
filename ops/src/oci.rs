//! Remote user-space OCI image management client over [`Session`].
//!
//! Pulls images via [`helios_oci::RegistryClient`] (`zenwave`) on the host and
//! materializes layers onto the remote guest store (`DEFAULT_REMOTE_OCI_STORE`
//! by default) using `helios:system/btrfs.receive-subvolume` when the guest
//! store sits on btrfs, or falling back to remote `wasi:filesystem` directory
//! materialization otherwise.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};

use helios_oci::btrfs_send::ParentSubvolumeRef;
use helios_oci::decompress::{HashingReader, LayerDecoder};
use helios_oci::unpack::{
    EntryUnixMetadata, LayerMetadataIndex, encode_layer_as_btrfs_send, unpack_layer_into_dir,
};
use helios_oci::{
    Arch, Digest, ImageReference, LayerCompression, OciError, PulledImage, RegistryAuth,
    RegistryClient,
};
use helios_wit_rpc::inspector::helios::system::btrfs::BtrfsErrorKind;
use helios_wit_rpc::inspector::wasi::filesystem::types::ErrorCode as FsErrorCode;
use helios_wit_rpc::inspector_fs::{EntryKind, FsRpcError};
use tempfile::TempDir;
use zenwave::Client;

use crate::error::OpsError;
use crate::session::{Session, normalize_absolute_path};
use crate::target::GrantRight;

/// Default guest-side OCI store directory managed by [`OciClient`].
pub const DEFAULT_REMOTE_OCI_STORE: &str = "/var/lib/helios/oci";

/// Optional settings for [`OciClient::pull_with_options`].
#[derive(Clone, Debug, Default)]
pub struct PullOptions {
    /// Target architecture override; when `None`, inferred from the guest's
    /// `/kernel/processors/guest-isa-level` inspect entry (defaulting to the host arch).
    pub arch: Option<Arch>,
    /// Registry authentication credentials.
    pub auth: RegistryAuth,
}

/// Remote OCI image store client bound to a [`Session`].
#[derive(Clone)]
pub struct OciClient {
    session: Session,
    store_root: String,
}

impl OciClient {
    /// Construct an [`OciClient`] targeting [`DEFAULT_REMOTE_OCI_STORE`].
    #[must_use]
    pub fn new(session: Session) -> Self {
        Self {
            session,
            store_root: DEFAULT_REMOTE_OCI_STORE.to_owned(),
        }
    }

    /// Construct an [`OciClient`] targeting a custom guest `store_root`.
    pub fn with_store_root(
        session: Session,
        store_root: impl AsRef<str>,
    ) -> Result<Self, OpsError> {
        let normalized = normalize_absolute_path(store_root.as_ref())?;
        Ok(Self {
            session,
            store_root: normalized,
        })
    }

    /// Guest-side OCI store root path.
    #[must_use]
    pub fn store_root(&self) -> &str {
        &self.store_root
    }

    fn images_dir(&self) -> String {
        format!("{}/images", self.store_root.trim_end_matches('/'))
    }

    fn layers_dir(&self) -> String {
        format!("{}/layers", self.store_root.trim_end_matches('/'))
    }

    fn image_record_path(&self, reference: &ImageReference) -> String {
        format!("{}/{}.json", self.images_dir(), reference.storage_key())
    }

    fn layer_dir_path(&self, chain_id: &Digest) -> String {
        format!("{}/{}", self.layers_dir(), chain_id.hex())
    }

    fn layer_meta_path(&self, chain_id: &Digest) -> String {
        format!("{}/{}.meta.json", self.layers_dir(), chain_id.hex())
    }

    /// List all pulled OCI images recorded in the remote guest store.
    pub async fn list(&self) -> Result<Vec<PulledImage>, OpsError> {
        self.session.require_right(GrantRight::FilesystemRead)?;
        let entries = match self.session.list_dir(&self.images_dir()).await {
            Ok(entries) => entries,
            Err(err) if is_remote_not_found(&err) => return Ok(Vec::new()),
            Err(err) => return Err(err),
        };
        let mut images = Vec::new();
        for entry in entries {
            if entry.kind != EntryKind::File || !entry.name.ends_with(".json") {
                continue;
            }
            let raw = self.session.read_file(&entry.path).await?;
            let img: PulledImage =
                serde_json::from_slice(&raw).map_err(|source| OciError::Json {
                    subject: "remote pulled image record",
                    source,
                })?;
            images.push(img);
        }
        images.sort_by_key(|a| a.reference.to_string());
        Ok(images)
    }

    /// Inspect a pulled OCI image in the remote guest store by reference string.
    pub async fn inspect(&self, reference: &str) -> Result<PulledImage, OpsError> {
        self.session.require_right(GrantRight::FilesystemRead)?;
        let parsed = ImageReference::parse(reference)?;
        let record_path = self.image_record_path(&parsed);
        match self.session.read_file(&record_path).await {
            Ok(raw) => {
                let img: PulledImage =
                    serde_json::from_slice(&raw).map_err(|source| OciError::Json {
                        subject: "remote pulled image record",
                        source,
                    })?;
                Ok(img)
            }
            Err(err) if is_remote_not_found(&err) => Err(OpsError::NotFound {
                path: parsed.to_string(),
            }),
            Err(err) => Err(err),
        }
    }

    /// Remove an OCI image record (and any layers no longer referenced by other images)
    /// from the remote guest store.
    pub async fn remove(&self, reference: &str) -> Result<PulledImage, OpsError> {
        self.session.require_right(GrantRight::FilesystemWrite)?;
        let parsed = ImageReference::parse(reference)?;
        let existing = self.inspect(reference).await?;
        let record_path = self.image_record_path(&parsed);
        self.session.remove(&record_path).await?;

        let remaining = self.list().await?;
        let referenced_layers: BTreeSet<String> = remaining
            .iter()
            .flat_map(|img| img.layer_chain_ids.iter().map(|d| d.hex().to_owned()))
            .collect();

        let btrfs = self.session.btrfs();
        for chain_id in existing.layer_chain_ids.iter().rev() {
            if referenced_layers.contains(chain_id.hex()) {
                continue;
            }
            let layer_path = self.layer_dir_path(chain_id);
            let meta_path = self.layer_meta_path(chain_id);
            if existing.btrfs_backed {
                let _ = btrfs.set_subvolume_read_only(&layer_path, false).await;
                let _ = btrfs.delete_subvolume(&layer_path).await;
            } else {
                let _ = self.remove_remote_tree(&layer_path).await;
            }
            let _ = self.session.remove(&meta_path).await;
        }

        Ok(existing)
    }

    /// Pull `reference` using the default `zenwave` HTTP client and materialize it
    /// into the remote guest store.
    pub async fn pull(&self, reference: &str) -> Result<PulledImage, OpsError> {
        self.pull_with_options(reference, PullOptions::default())
            .await
    }

    /// Pull `reference` with explicit [`PullOptions`] (architecture override / auth).
    pub async fn pull_with_options(
        &self,
        reference: &str,
        options: PullOptions,
    ) -> Result<PulledImage, OpsError> {
        let mut client = RegistryClient::with_auth(options.auth);
        self.pull_with_client(&mut client, reference, options.arch)
            .await
    }

    /// Pull `reference` using an explicit [`RegistryClient`] (enabling deterministic
    /// in-process mock registry testing).
    pub async fn pull_with_client<C: Client>(
        &self,
        client: &mut RegistryClient<C>,
        reference: &str,
        arch_override: Option<Arch>,
    ) -> Result<PulledImage, OpsError> {
        self.session.require_right(GrantRight::FilesystemWrite)?;
        let parsed = ImageReference::parse(reference)?;
        let arch = match arch_override {
            Some(a) => a,
            None => self.detect_guest_arch().await,
        };

        let resolved = client.fetch_manifest(&parsed, arch).await?;
        let config = client
            .fetch_config(&parsed, &resolved.manifest.config)
            .await?;

        let layers = &resolved.manifest.layers;
        let diff_ids = &config.rootfs.diff_ids;
        if layers.len() != diff_ids.len() {
            return Err(OciError::LayerCountMismatch {
                manifest_layers: layers.len(),
                config_diff_ids: diff_ids.len(),
            }
            .into());
        }

        self.ensure_remote_dir(&self.store_root).await?;
        self.ensure_remote_dir(&self.layers_dir()).await?;
        self.ensure_remote_dir(&self.images_dir()).await?;

        let staging = TempDir::new().map_err(|source| OciError::Io {
            operation: "create host OCI pull staging directory",
            path: PathBuf::from("staging"),
            source,
        })?;
        let btrfs = self.session.btrfs();

        let mut layer_chain_ids = Vec::with_capacity(layers.len());
        let mut parent_chain: Option<Digest> = None;
        let mut parent_meta: Option<BTreeMap<String, EntryUnixMetadata>> = None;
        let mut parent_subvol: Option<ParentSubvolumeRef> = None;
        let mut btrfs_backed = false;

        for (index, (layer_desc, expected_diff_id)) in
            layers.iter().zip(diff_ids.iter()).enumerate()
        {
            let chain_id = Digest::chain_id(parent_chain.as_ref(), expected_diff_id);
            let meta_path = self.layer_meta_path(&chain_id);
            let remote_layer_dir = self.layer_dir_path(&chain_id);

            if let Ok(raw_meta) = self.session.read_file(&meta_path).await
                && let Ok(cached) = serde_json::from_slice::<LayerMetadataIndex>(&raw_meta)
            {
                btrfs_backed = cached.btrfs_backed;
                if btrfs_backed
                    && let Ok(info) = btrfs.subvolume_info(&remote_layer_dir).await
                    && let Ok(uuid) = <[u8; 16]>::try_from(info.uuid.as_slice())
                {
                    let received = info
                        .received_uuid
                        .as_deref()
                        .and_then(|u| <[u8; 16]>::try_from(u).ok())
                        .unwrap_or(uuid);
                    parent_subvol = Some(ParentSubvolumeRef {
                        uuid: received,
                        ctransid: info.ctransid,
                    });
                }
                parent_meta = Some(cached.entries);
                parent_chain = Some(chain_id.clone());
                layer_chain_ids.push(chain_id);
                continue;
            }

            let compression = LayerCompression::from_media_type(&layer_desc.media_type)?;
            let blob_path = staging.path().join(format!("layer-{index}.blob"));
            let mut blob_file = File::create(&blob_path).map_err(|source| OciError::Io {
                operation: "create staged OCI layer blob",
                path: blob_path.clone(),
                source,
            })?;
            client
                .stream_verified_blob(&parsed, &layer_desc.digest, &mut blob_file)
                .await?;
            drop(blob_file);

            // Try btrfs v1 send-stream receive first; fall back to remote WASI FS when not btrfs.
            let subvol_uuid = chain_id.to_uuid_bytes();
            let subvol_name = chain_id.hex().to_owned();
            let ctransid = (index as u64) + 1;
            let expected_diff_clone = expected_diff_id.clone();
            let blob_for_send = blob_path.clone();
            let parent_entries_for_send = parent_meta.clone();
            let parent_subvol_for_send = parent_subvol;
            let (send_stream, entries_meta) = tokio::task::spawn_blocking(move || {
                let file = File::open(&blob_for_send).map_err(|source| OciError::Io {
                    operation: "open staged OCI layer blob",
                    path: blob_for_send.clone(),
                    source,
                })?;
                let decoder = LayerDecoder::new(BufReader::new(file), compression);
                let mut hashing = HashingReader::new(decoder);
                let expected_diff_str = expected_diff_clone.as_str();
                let (stream, entries) = encode_layer_as_btrfs_send(
                    &mut hashing,
                    &subvol_name,
                    subvol_uuid,
                    ctransid,
                    parent_subvol_for_send,
                    &expected_diff_str,
                    parent_entries_for_send.as_ref(),
                )?;
                hashing.drain_to_eof().map_err(|err| OciError::Decompress {
                    compression: compression.as_str(),
                    digest: expected_diff_str.clone(),
                    detail: err.to_string(),
                })?;
                let (actual_diff, _) = hashing.finalize();
                if actual_diff != expected_diff_clone {
                    return Err(OciError::DigestMismatch {
                        subject: "uncompressed layer diff_id".to_owned(),
                        expected: expected_diff_str,
                        actual: actual_diff.as_str(),
                    });
                }
                Ok::<_, OciError>((stream, entries))
            })
            .await
            .expect("OCI layer send-stream encoding task panicked")?;

            match btrfs
                .receive_subvolume(&self.layers_dir(), send_stream)
                .await
            {
                Ok(info) => {
                    btrfs_backed = true;
                    let uuid = <[u8; 16]>::try_from(info.uuid.as_slice()).unwrap_or(subvol_uuid);
                    let received = info
                        .received_uuid
                        .as_deref()
                        .and_then(|u| <[u8; 16]>::try_from(u).ok())
                        .unwrap_or(uuid);
                    parent_subvol = Some(ParentSubvolumeRef {
                        uuid: received,
                        ctransid: info.ctransid,
                    });
                }
                Err(OpsError::BtrfsRefused {
                    kind: BtrfsErrorKind::NotBtrfs,
                    ..
                })
                | Err(OpsError::Rpc { .. }) => {
                    btrfs_backed = false;
                    parent_subvol = None;
                    let local_unpack = staging.path().join(format!("unpacked-{index}"));
                    std::fs::create_dir_all(&local_unpack).map_err(|source| OciError::Io {
                        operation: "create host unpack directory",
                        path: local_unpack.clone(),
                        source,
                    })?;
                    let blob_for_unpack = blob_path.clone();
                    let expected_for_unpack = expected_diff_id.clone();
                    let parent_for_unpack = parent_meta.clone();
                    let unpack_dir = local_unpack.clone();
                    tokio::task::spawn_blocking(move || {
                        let file = File::open(&blob_for_unpack).map_err(|source| OciError::Io {
                            operation: "open staged OCI layer blob",
                            path: blob_for_unpack.clone(),
                            source,
                        })?;
                        let decoder = LayerDecoder::new(BufReader::new(file), compression);
                        let mut hashing = HashingReader::new(decoder);
                        let expected_diff_str = expected_for_unpack.as_str();
                        let _ = unpack_layer_into_dir(
                            &mut hashing,
                            &unpack_dir,
                            &expected_diff_str,
                            parent_for_unpack.as_ref(),
                        )?;
                        hashing.drain_to_eof().map_err(|err| OciError::Decompress {
                            compression: compression.as_str(),
                            digest: expected_diff_str.clone(),
                            detail: err.to_string(),
                        })?;
                        let (actual_diff, _) = hashing.finalize();
                        if actual_diff != expected_for_unpack {
                            return Err(OciError::DigestMismatch {
                                subject: "uncompressed layer diff_id".to_owned(),
                                expected: expected_diff_str,
                                actual: actual_diff.as_str(),
                            });
                        }
                        Ok::<_, OciError>(())
                    })
                    .await
                    .expect("OCI layer unpack task panicked")?;

                    self.upload_local_tree(&local_unpack, &remote_layer_dir)
                        .await?;
                }
                Err(err) => return Err(err),
            }

            let meta_index = LayerMetadataIndex {
                chain_id: chain_id.clone(),
                diff_id: expected_diff_id.clone(),
                parent_chain_id: parent_chain.clone(),
                btrfs_backed,
                entries: entries_meta.clone(),
            };
            let meta_bytes =
                serde_json::to_vec_pretty(&meta_index).map_err(|source| OciError::Json {
                    subject: "layer metadata",
                    source,
                })?;
            self.session
                .write_file(&meta_path, &meta_bytes, false)
                .await?;

            parent_meta = Some(entries_meta);
            parent_chain = Some(chain_id.clone());
            layer_chain_ids.push(chain_id);
        }

        let rootfs_path = match layer_chain_ids.last() {
            Some(top) => PathBuf::from(self.layer_dir_path(top)),
            None => {
                let empty_id = Digest::sha256(b"empty-oci-scratch-layer");
                let empty_dir = self.layer_dir_path(&empty_id);
                self.ensure_remote_dir(&empty_dir).await?;
                PathBuf::from(empty_dir)
            }
        };

        let pulled = PulledImage {
            reference: parsed.clone(),
            manifest_digest: resolved.digest,
            arch,
            config,
            layer_chain_ids,
            rootfs_path,
            btrfs_backed,
        };
        let record_bytes = serde_json::to_vec_pretty(&pulled).map_err(|source| OciError::Json {
            subject: "pulled image record",
            source,
        })?;
        self.session
            .write_file(&self.image_record_path(&parsed), &record_bytes, false)
            .await?;
        Ok(pulled)
    }

    async fn detect_guest_arch(&self) -> Arch {
        if self
            .session
            .options()
            .attenuation
            .allows(GrantRight::Inspect)
            && let Ok(snap) = self.session.kernel_snapshot().await
        {
            let isa = snap.processors.guest_isa_level.to_ascii_lowercase();
            if isa.contains("aarch64") || isa.contains("arm64") {
                return Arch::Aarch64;
            }
            if isa.contains("x86") || isa.contains("amd64") {
                return Arch::X86_64;
            }
        }
        Arch::host_default()
    }

    async fn ensure_remote_dir(&self, path: &str) -> Result<(), OpsError> {
        let normalized = normalize_absolute_path(path)?;
        let mut current = String::new();
        for seg in normalized.split('/').filter(|s| !s.is_empty()) {
            current.push('/');
            current.push_str(seg);
            match self.session.mkdir(&current).await {
                Ok(()) => {}
                Err(OpsError::Fs(FsRpcError::Fs {
                    code: FsErrorCode::Exist,
                    ..
                })) => {}
                Err(err) => {
                    // Check if directory already exists if the remote returned a generic error.
                    if self
                        .session
                        .stat(&current)
                        .await
                        .is_ok_and(|st| st.kind == EntryKind::Directory)
                    {
                        continue;
                    }
                    return Err(err);
                }
            }
        }
        Ok(())
    }

    async fn upload_local_tree(
        &self,
        local_root: &Path,
        remote_root: &str,
    ) -> Result<(), OpsError> {
        self.ensure_remote_dir(remote_root).await?;
        let mut stack = vec![(local_root.to_path_buf(), remote_root.to_owned())];
        while let Some((local_dir, remote_dir)) = stack.pop() {
            let entries = std::fs::read_dir(&local_dir).map_err(|source| OciError::Io {
                operation: "read unpacked OCI layer directory",
                path: local_dir.clone(),
                source,
            })?;
            for entry_res in entries {
                let entry = entry_res.map_err(|source| OciError::Io {
                    operation: "read unpacked OCI directory entry",
                    path: local_dir.clone(),
                    source,
                })?;
                let file_name = entry.file_name();
                let Some(name_str) = file_name.to_str() else {
                    continue;
                };
                let remote_child = format!("{}/{}", remote_dir.trim_end_matches('/'), name_str);
                let file_type = entry.file_type().map_err(|source| OciError::Io {
                    operation: "stat unpacked OCI entry",
                    path: entry.path(),
                    source,
                })?;
                if file_type.is_dir() {
                    self.ensure_remote_dir(&remote_child).await?;
                    stack.push((entry.path(), remote_child));
                } else if file_type.is_file() {
                    let bytes = std::fs::read(entry.path()).map_err(|source| OciError::Io {
                        operation: "read unpacked OCI file",
                        path: entry.path(),
                        source,
                    })?;
                    self.session
                        .write_file(&remote_child, &bytes, false)
                        .await?;
                }
            }
        }
        Ok(())
    }

    async fn remove_remote_tree(&self, remote_root: &str) -> Result<(), OpsError> {
        let mut dirs_to_visit = vec![remote_root.to_owned()];
        let mut dirs_to_remove = Vec::new();
        while let Some(dir) = dirs_to_visit.pop() {
            let entries = match self.session.list_dir(&dir).await {
                Ok(e) => e,
                Err(err) if is_remote_not_found(&err) => continue,
                Err(err) => return Err(err),
            };
            dirs_to_remove.push(dir);
            for entry in entries {
                if entry.kind == EntryKind::Directory {
                    dirs_to_visit.push(entry.path);
                } else {
                    let _ = self.session.remove(&entry.path).await;
                }
            }
        }
        for dir in dirs_to_remove.into_iter().rev() {
            let _ = self.session.remove(&dir).await;
        }
        Ok(())
    }
}

fn is_remote_not_found(err: &OpsError) -> bool {
    matches!(
        err,
        OpsError::NotFound { .. }
            | OpsError::Fs(FsRpcError::Fs {
                code: FsErrorCode::NoEntry,
                ..
            })
    )
}
