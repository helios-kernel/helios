//! Content-addressed OCI image store materializing layers by `chain-id` into
//! read-only btrfs subvolumes (with read-only directory fallback when not on btrfs).

use core::future::Future;
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::BufReader;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tracing::{debug, info};
use zenwave::Client;

use crate::btrfs_send::ParentSubvolumeRef;
use crate::decompress::{HashingReader, LayerDecoder};
use crate::error::{OciError, Result, SubvolumeError};
use crate::prefs::DefaultImageStore;
use crate::reference::{Digest, ImageReference};
use crate::registry::RegistryClient;
use crate::spec::{Arch, ImageConfig, LayerCompression};
use crate::unpack::{
    EntryUnixMetadata, LayerMetadataIndex, copy_tree_recursive, encode_layer_as_btrfs_send,
    mark_tree_read_only, remove_path_recursive, unpack_layer_into_dir,
};

/// Metadata about a materialized btrfs subvolume.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubvolumeMeta {
    pub uuid: [u8; 16],
    pub received_uuid: Option<[u8; 16]>,
    pub ctransid: u64,
    pub read_only: bool,
}

/// Async btrfs subvolume backend contract.
///
/// Implemented by `helios-api::oci::BtrfsSubvolumeBackend` over `helios:system/btrfs`,
/// and by [`DirectoryBackend`] (which returns [`SubvolumeError::NotBtrfs`]) for host
/// and non-btrfs deployments.
pub trait SubvolumeBackend {
    fn create_subvolume(
        &self,
        path: &Path,
    ) -> impl Future<Output = core::result::Result<SubvolumeMeta, SubvolumeError>>;

    fn snapshot_subvolume(
        &self,
        source: &Path,
        destination: &Path,
        read_only: bool,
    ) -> impl Future<Output = core::result::Result<SubvolumeMeta, SubvolumeError>>;

    fn set_subvolume_read_only(
        &self,
        path: &Path,
        read_only: bool,
    ) -> impl Future<Output = core::result::Result<(), SubvolumeError>>;

    fn delete_subvolume(
        &self,
        path: &Path,
    ) -> impl Future<Output = core::result::Result<(), SubvolumeError>>;

    fn subvolume_info(
        &self,
        path: &Path,
    ) -> impl Future<Output = core::result::Result<Option<SubvolumeMeta>, SubvolumeError>>;

    /// Optional btrfs v1 send-stream receive support (`helios:system/btrfs.receive-subvolume`).
    ///
    /// Returning `Ok(None)` tells [`ImageStore`] to materialize via `create_subvolume` /
    /// `snapshot_subvolume` + tar extraction + `set_subvolume_read_only`.
    fn receive_subvolume(
        &self,
        _destination_parent: &Path,
        _stream: Vec<u8>,
    ) -> impl Future<Output = core::result::Result<Option<SubvolumeMeta>, SubvolumeError>> {
        async { Ok(None) }
    }
}

/// Default non-btrfs [`SubvolumeBackend`] that triggers the read-only directory fallback.
#[derive(Clone, Copy, Debug, Default)]
pub struct DirectoryBackend;

impl SubvolumeBackend for DirectoryBackend {
    async fn create_subvolume(
        &self,
        path: &Path,
    ) -> core::result::Result<SubvolumeMeta, SubvolumeError> {
        Err(SubvolumeError::NotBtrfs {
            path: path.to_path_buf(),
        })
    }

    async fn snapshot_subvolume(
        &self,
        _source: &Path,
        destination: &Path,
        _read_only: bool,
    ) -> core::result::Result<SubvolumeMeta, SubvolumeError> {
        Err(SubvolumeError::NotBtrfs {
            path: destination.to_path_buf(),
        })
    }

    async fn set_subvolume_read_only(
        &self,
        path: &Path,
        _read_only: bool,
    ) -> core::result::Result<(), SubvolumeError> {
        Err(SubvolumeError::NotBtrfs {
            path: path.to_path_buf(),
        })
    }

    async fn delete_subvolume(&self, path: &Path) -> core::result::Result<(), SubvolumeError> {
        Err(SubvolumeError::NotBtrfs {
            path: path.to_path_buf(),
        })
    }

    async fn subvolume_info(
        &self,
        path: &Path,
    ) -> core::result::Result<Option<SubvolumeMeta>, SubvolumeError> {
        Err(SubvolumeError::NotBtrfs {
            path: path.to_path_buf(),
        })
    }
}

/// A pulled and materialized OCI image ready for Linux containers or VMs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PulledImage {
    pub reference: ImageReference,
    pub manifest_digest: Digest,
    pub arch: Arch,
    pub config: ImageConfig,
    /// Ordered list of materialized `chain-id`s (base layer -> top layer).
    pub layer_chain_ids: Vec<Digest>,
    /// Path to the read-only top-layer rootfs (btrfs subvolume or read-only directory).
    pub rootfs_path: PathBuf,
    /// Whether the materialized rootfs is backed by a read-only btrfs subvolume.
    pub btrfs_backed: bool,
}

impl PulledImage {
    /// Read-only materialized rootfs path.
    #[must_use]
    pub fn rootfs_path(&self) -> &Path {
        &self.rootfs_path
    }

    /// Top-layer `chain-id` (if the image has at least one layer).
    #[must_use]
    pub fn top_chain_id(&self) -> Option<&Digest> {
        self.layer_chain_ids.last()
    }
}

#[derive(Clone, Copy)]
struct LayerMaterializeParams<'a> {
    blob_path: &'a Path,
    compressed_digest: &'a Digest,
    expected_diff_id: &'a Digest,
    chain_id: &'a Digest,
    parent_chain: Option<&'a Digest>,
    parent_meta: Option<&'a BTreeMap<String, EntryUnixMetadata>>,
    compression: LayerCompression,
}

/// Content-addressed user-space OCI image store.
///
/// Layout under `root`:
/// - `layers/<chain-id-hex>/` — materialized read-only btrfs subvolume or directory
/// - `layers/<chain-id-hex>.meta.json` — persisted Unix metadata & layer provenance
/// - `staging/` — atomic download & unpack scratch directory
/// - `images/<ref-hash>.json` — [`PulledImage`] index records
/// - `user-default-images.json` — per-user shell default image preferences
pub struct ImageStore<B: SubvolumeBackend = DirectoryBackend> {
    root: PathBuf,
    backend: B,
}

impl ImageStore<DirectoryBackend> {
    /// Open an [`ImageStore`] using the read-only directory backend (no btrfs disk).
    pub fn open_directory(root: impl Into<PathBuf>) -> Result<Self> {
        Self::open(root, DirectoryBackend)
    }
}

impl<B: SubvolumeBackend> ImageStore<B> {
    /// Open or initialize an [`ImageStore`] at `root` backed by `backend`.
    pub fn open(root: impl Into<PathBuf>, backend: B) -> Result<Self> {
        let root = root.into();
        for sub in ["layers", "staging", "images"] {
            let dir = root.join(sub);
            fs::create_dir_all(&dir).map_err(|source| OciError::Io {
                operation: "initialize OCI store directory",
                path: dir,
                source,
            })?;
        }
        Ok(Self { root, backend })
    }

    /// Store root directory.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Reference to the underlying [`SubvolumeBackend`].
    #[must_use]
    pub const fn backend(&self) -> &B {
        &self.backend
    }

    /// Open the per-user default Linux image preferences store inside this store root.
    pub fn default_image_store(&self) -> Result<DefaultImageStore> {
        DefaultImageStore::load(DefaultImageStore::path_in_store(&self.root))
    }

    /// Path of the materialized read-only rootfs for `chain_id`.
    #[must_use]
    pub fn layer_path(&self, chain_id: &Digest) -> PathBuf {
        self.root.join("layers").join(chain_id.hex())
    }

    /// Path of the persisted [`LayerMetadataIndex`] for `chain_id`.
    #[must_use]
    pub fn layer_meta_path(&self, chain_id: &Digest) -> PathBuf {
        self.root
            .join("layers")
            .join(format!("{}.meta.json", chain_id.hex()))
    }

    /// Load the persisted [`LayerMetadataIndex`] for a materialized `chain_id`, if present.
    pub fn load_layer_metadata(&self, chain_id: &Digest) -> Result<Option<LayerMetadataIndex>> {
        let path = self.layer_meta_path(chain_id);
        match fs::read_to_string(&path) {
            Ok(raw) => serde_json::from_str(&raw)
                .map(Some)
                .map_err(|source| OciError::Json {
                    subject: "layer metadata",
                    source,
                }),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(source) => Err(OciError::Io {
                operation: "read layer metadata",
                path,
                source,
            }),
        }
    }

    /// Load a previously pulled image record by reference, if present in the local store.
    pub fn get_image(&self, reference: &ImageReference) -> Result<Option<PulledImage>> {
        let path = self.image_record_path(reference);
        match fs::read_to_string(&path) {
            Ok(raw) => serde_json::from_str(&raw)
                .map(Some)
                .map_err(|source| OciError::Json {
                    subject: "pulled image record",
                    source,
                }),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(source) => Err(OciError::Io {
                operation: "read pulled image record",
                path,
                source,
            }),
        }
    }

    /// Pull `reference` for `arch` using `client`, caching every layer by `chain-id`.
    ///
    /// Layers whose `chain-id` is already materialized in the store are reused without
    /// downloading or unpacking them again.
    pub async fn pull<C: Client>(
        &self,
        client: &mut RegistryClient<C>,
        reference: &ImageReference,
        arch: Arch,
    ) -> Result<PulledImage> {
        let resolved = client.fetch_manifest(reference, arch).await?;
        let config = client
            .fetch_config(reference, &resolved.manifest.config)
            .await?;

        let layers = &resolved.manifest.layers;
        let diff_ids = &config.rootfs.diff_ids;
        if layers.len() != diff_ids.len() {
            return Err(OciError::LayerCountMismatch {
                manifest_layers: layers.len(),
                config_diff_ids: diff_ids.len(),
            });
        }

        let mut layer_chain_ids = Vec::with_capacity(layers.len());
        let mut parent_chain: Option<Digest> = None;
        let mut parent_meta: Option<BTreeMap<String, EntryUnixMetadata>> = None;
        let mut btrfs_backed = false;

        for (index, (layer_desc, expected_diff_id)) in
            layers.iter().zip(diff_ids.iter()).enumerate()
        {
            let chain_id = Digest::chain_id(parent_chain.as_ref(), expected_diff_id);
            let layer_dir = self.layer_path(&chain_id);

            if let Some(cached) = self.load_layer_metadata(&chain_id)?
                && layer_dir.is_dir()
            {
                debug!(
                    layer_index = index,
                    chain_id = %chain_id,
                    btrfs_backed = cached.btrfs_backed,
                    "reusing cached OCI layer by chain-id"
                );
                btrfs_backed = cached.btrfs_backed;
                parent_meta = Some(cached.entries);
                parent_chain = Some(chain_id.clone());
                layer_chain_ids.push(chain_id);
                continue;
            }

            let compression = LayerCompression::from_media_type(&layer_desc.media_type)?;
            let staged_blob = self
                .root
                .join("staging")
                .join(format!("{}.blob", chain_id.hex()));
            {
                let mut blob_file = File::create(&staged_blob).map_err(|source| OciError::Io {
                    operation: "create staging blob file",
                    path: staged_blob.clone(),
                    source,
                })?;
                if let Err(err) = client
                    .stream_verified_blob(reference, &layer_desc.digest, &mut blob_file)
                    .await
                {
                    let _ = fs::remove_file(&staged_blob);
                    return Err(err);
                }
            }

            let materialize_res = self
                .materialize_layer_from_blob(LayerMaterializeParams {
                    blob_path: &staged_blob,
                    compressed_digest: &layer_desc.digest,
                    expected_diff_id,
                    chain_id: &chain_id,
                    parent_chain: parent_chain.as_ref(),
                    parent_meta: parent_meta.as_ref(),
                    compression,
                })
                .await;
            let _ = fs::remove_file(&staged_blob);

            let meta_index = materialize_res?;
            btrfs_backed = meta_index.btrfs_backed;
            parent_meta = Some(meta_index.entries);
            parent_chain = Some(chain_id.clone());
            layer_chain_ids.push(chain_id);
        }

        let rootfs_path = match layer_chain_ids.last() {
            Some(top) => self.layer_path(top),
            None => {
                // Scratch image with zero layers: materialize an empty read-only directory/subvolume.
                let empty_id = Digest::sha256(b"empty-oci-scratch-layer");
                let empty_dir = self.layer_path(&empty_id);
                if !empty_dir.is_dir() {
                    let is_btrfs = match self.backend.create_subvolume(&empty_dir).await {
                        Ok(_) => {
                            self.backend
                                .set_subvolume_read_only(&empty_dir, true)
                                .await?;
                            true
                        }
                        Err(SubvolumeError::NotBtrfs { .. }) => {
                            fs::create_dir_all(&empty_dir).map_err(|source| OciError::Io {
                                operation: "create empty scratch rootfs",
                                path: empty_dir.clone(),
                                source,
                            })?;
                            mark_tree_read_only(&empty_dir);
                            false
                        }
                        Err(err) => return Err(OciError::Subvolume(err)),
                    };
                    btrfs_backed = is_btrfs;
                }
                empty_dir
            }
        };

        let pulled = PulledImage {
            reference: reference.clone(),
            manifest_digest: resolved.digest,
            arch,
            config,
            layer_chain_ids,
            rootfs_path,
            btrfs_backed,
        };
        self.save_image_record(&pulled)?;
        info!(
            reference = %pulled.reference,
            arch = %pulled.arch,
            layers = pulled.layer_chain_ids.len(),
            btrfs_backed = pulled.btrfs_backed,
            "pulled and materialized OCI image"
        );
        Ok(pulled)
    }

    async fn materialize_layer_from_blob(
        &self,
        params: LayerMaterializeParams<'_>,
    ) -> Result<LayerMetadataIndex> {
        let LayerMaterializeParams {
            blob_path,
            compressed_digest,
            expected_diff_id,
            chain_id,
            parent_chain,
            parent_meta,
            compression,
        } = params;
        let final_dir = self.layer_path(chain_id);
        // Clean any partial leftover from an interrupted prior run.
        if final_dir.exists() {
            let _ = self.backend.delete_subvolume(&final_dir).await;
            let _ = remove_path_recursive(&final_dir);
        }

        // First try atomic btrfs send/receive when the backend supports `receive_subvolume`
        // (preserves full Unix uid/gid/mode/suid/sgid/xattr directly inside Helios btrfs from WASI).
        let parent_subvol_ref = match parent_chain {
            Some(parent_id) => match self
                .backend
                .subvolume_info(&self.layer_path(parent_id))
                .await
            {
                Ok(Some(info)) => Some(ParentSubvolumeRef {
                    uuid: info.received_uuid.unwrap_or(info.uuid),
                    ctransid: info.ctransid,
                }),
                Ok(None)
                | Err(SubvolumeError::NotBtrfs { .. } | SubvolumeError::NotSubvolume { .. }) => {
                    None
                }
                Err(err) => return Err(OciError::Subvolume(err)),
            },
            None => None,
        };

        // Probe whether btrfs `create_subvolume` / `snapshot_subvolume` is available or if
        // we should use `receive_subvolume` or fall back to read-only directories.
        if let Some(index) = self
            .try_receive_subvolume(params, parent_subvol_ref)
            .await?
        {
            self.write_layer_metadata(&index)?;
            return Ok(index);
        }

        // Standard subvolume path: create_subvolume / snapshot_subvolume -> unpack -> set_subvolume_read_only,
        // transparently falling back to read-only directories when `SubvolumeError::NotBtrfs`.
        let btrfs_backed = match parent_chain {
            None => match self.backend.create_subvolume(&final_dir).await {
                Ok(_) => true,
                Err(SubvolumeError::NotBtrfs { .. }) => {
                    fs::create_dir_all(&final_dir).map_err(|source| OciError::Io {
                        operation: "create fallback layer directory",
                        path: final_dir.clone(),
                        source,
                    })?;
                    false
                }
                Err(err) => return Err(OciError::Subvolume(err)),
            },
            Some(parent_id) => {
                let parent_dir = self.layer_path(parent_id);
                match self
                    .backend
                    .snapshot_subvolume(&parent_dir, &final_dir, false)
                    .await
                {
                    Ok(_) => true,
                    Err(SubvolumeError::NotBtrfs { .. }) => {
                        copy_tree_recursive(&parent_dir, &final_dir)?;
                        false
                    }
                    Err(err) => return Err(OciError::Subvolume(err)),
                }
            }
        };

        let unpack_result = (|| -> Result<BTreeMap<String, EntryUnixMetadata>> {
            let file = File::open(blob_path).map_err(|source| OciError::Io {
                operation: "open staged blob for unpacking",
                path: blob_path.to_path_buf(),
                source,
            })?;
            let decoder = LayerDecoder::new(BufReader::new(file), compression);
            let mut hashing = HashingReader::new(decoder);
            let entries = unpack_layer_into_dir(
                &mut hashing,
                &final_dir,
                &compressed_digest.as_str(),
                parent_meta,
            )?;
            hashing.drain_to_eof().map_err(|err| OciError::Decompress {
                compression: compression.as_str(),
                digest: compressed_digest.as_str(),
                detail: err.to_string(),
            })?;
            let (actual_diff_id, _) = hashing.finalize();
            if &actual_diff_id != expected_diff_id {
                return Err(OciError::DigestMismatch {
                    subject: format!("uncompressed layer diff_id for `{compressed_digest}`"),
                    expected: expected_diff_id.as_str(),
                    actual: actual_diff_id.as_str(),
                });
            }
            Ok(entries)
        })();

        let entries = match unpack_result {
            Ok(entries) => entries,
            Err(err) => {
                if btrfs_backed {
                    let _ = self.backend.delete_subvolume(&final_dir).await;
                }
                let _ = remove_path_recursive(&final_dir);
                return Err(err);
            }
        };

        if btrfs_backed {
            self.backend
                .set_subvolume_read_only(&final_dir, true)
                .await?;
        } else {
            mark_tree_read_only(&final_dir);
        }

        let index = LayerMetadataIndex {
            chain_id: chain_id.clone(),
            diff_id: expected_diff_id.clone(),
            parent_chain_id: parent_chain.cloned(),
            btrfs_backed,
            entries,
        };
        self.write_layer_metadata(&index)?;
        Ok(index)
    }

    async fn try_receive_subvolume(
        &self,
        params: LayerMaterializeParams<'_>,
        parent_subvol_ref: Option<ParentSubvolumeRef>,
    ) -> Result<Option<LayerMetadataIndex>> {
        let LayerMaterializeParams {
            blob_path,
            compressed_digest,
            expected_diff_id,
            chain_id,
            parent_chain,
            parent_meta,
            compression,
        } = params;
        // Only build a send stream when either this is a base layer or the parent is a real subvolume.
        if parent_chain.is_some() && parent_subvol_ref.is_none() {
            return Ok(None);
        }
        let layers_dir = self.root.join("layers");
        // Probe if backend is btrfs via subvolume_info on layers_dir before buffering a send stream.
        // `layers_dir` is a regular directory on a btrfs mount, so `NotSubvolume` confirms btrfs
        // is active and `receive_subvolume` should proceed; only `NotBtrfs` opts out.
        match self.backend.subvolume_info(&layers_dir).await {
            Err(SubvolumeError::NotBtrfs { .. }) => return Ok(None),
            Ok(_) | Err(SubvolumeError::NotFound { .. } | SubvolumeError::NotSubvolume { .. }) => {}
            Err(err) => return Err(OciError::Subvolume(err)),
        }

        let file = File::open(blob_path).map_err(|source| OciError::Io {
            operation: "open staged blob for btrfs send",
            path: blob_path.to_path_buf(),
            source,
        })?;
        let decoder = LayerDecoder::new(BufReader::new(file), compression);
        let mut hashing = HashingReader::new(decoder);
        let (stream, entries) = encode_layer_as_btrfs_send(
            &mut hashing,
            chain_id.hex(),
            chain_id.to_uuid_bytes(),
            1,
            parent_subvol_ref,
            &compressed_digest.as_str(),
            parent_meta,
        )?;
        hashing.drain_to_eof().map_err(|err| OciError::Decompress {
            compression: compression.as_str(),
            digest: compressed_digest.as_str(),
            detail: err.to_string(),
        })?;
        let (actual_diff_id, _) = hashing.finalize();
        if &actual_diff_id != expected_diff_id {
            return Err(OciError::DigestMismatch {
                subject: format!("uncompressed layer diff_id for `{compressed_digest}`"),
                expected: expected_diff_id.as_str(),
                actual: actual_diff_id.as_str(),
            });
        }

        match self.backend.receive_subvolume(&layers_dir, stream).await {
            Ok(Some(_info)) => Ok(Some(LayerMetadataIndex {
                chain_id: chain_id.clone(),
                diff_id: expected_diff_id.clone(),
                parent_chain_id: parent_chain.cloned(),
                btrfs_backed: true,
                entries,
            })),
            Ok(None) | Err(SubvolumeError::NotBtrfs { .. }) => Ok(None),
            Err(err) => Err(OciError::Subvolume(err)),
        }
    }

    fn write_layer_metadata(&self, index: &LayerMetadataIndex) -> Result<()> {
        let path = self.layer_meta_path(&index.chain_id);
        let payload = serde_json::to_vec_pretty(index).map_err(|source| OciError::Json {
            subject: "layer metadata",
            source,
        })?;
        let tmp = path.with_extension("json.tmp");
        fs::write(&tmp, payload).map_err(|source| OciError::Io {
            operation: "write temporary layer metadata",
            path: tmp.clone(),
            source,
        })?;
        fs::rename(&tmp, &path).map_err(|source| OciError::Io {
            operation: "commit layer metadata",
            path,
            source,
        })
    }

    fn image_record_path(&self, reference: &ImageReference) -> PathBuf {
        self.root
            .join("images")
            .join(format!("{}.json", reference.storage_key()))
    }

    fn save_image_record(&self, image: &PulledImage) -> Result<()> {
        let path = self.image_record_path(&image.reference);
        let payload = serde_json::to_vec_pretty(image).map_err(|source| OciError::Json {
            subject: "pulled image record",
            source,
        })?;
        let tmp = path.with_extension("json.tmp");
        fs::write(&tmp, payload).map_err(|source| OciError::Io {
            operation: "write temporary image record",
            path: tmp.clone(),
            source,
        })?;
        fs::rename(&tmp, &path).map_err(|source| OciError::Io {
            operation: "commit image record",
            path,
            source,
        })
    }
}
