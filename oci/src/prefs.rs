//! Per-user persistent shell default Linux image preferences keyed by authenticated login identity.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{OciError, Result};
use crate::spec::ResolvedUser;
use crate::store::PulledImage;

/// Persisted default Linux image preference for one authenticated login identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserDefaultImage {
    /// Canonical OCI image reference string.
    pub image_ref: String,
    /// Materialized read-only rootfs path (btrfs subvolume or read-only directory).
    pub rootfs_path: String,
    /// Base environment defaults derived from the OCI image config.
    #[serde(default)]
    pub env: Vec<(String, String)>,
    /// Default Linux credentials for direct Linux launches.
    #[serde(default)]
    pub credentials: ResolvedUser,
}

impl UserDefaultImage {
    /// Build a [`UserDefaultImage`] preference from a materialized [`PulledImage`].
    pub fn from_pulled_image(image: &PulledImage) -> Result<Self> {
        let credentials = image.config.config.resolve_user(Some(&image.rootfs_path))?;
        Ok(Self {
            image_ref: image.reference.canonical(),
            rootfs_path: image.rootfs_path.to_string_lossy().into_owned(),
            env: image.config.config.env_pairs(),
            credentials,
        })
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct PreferencesDocument {
    /// Map from authenticated login principal -> default image preference.
    #[serde(default)]
    users: BTreeMap<String, UserDefaultImage>,
}

/// Persistent store of per-user default Linux image preferences keyed by authenticated login identity.
#[derive(Clone, Debug)]
pub struct DefaultImageStore {
    path: PathBuf,
    doc: PreferencesDocument,
}

impl DefaultImageStore {
    /// Default preferences file path inside an OCI store root directory.
    #[must_use]
    pub fn path_in_store(store_root: &Path) -> PathBuf {
        store_root.join("user-default-images.json")
    }

    /// Load preferences from `path` (returning an empty store if the file does not exist yet).
    pub fn load(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let doc = match fs::read_to_string(&path) {
            Ok(raw) => serde_json::from_str::<PreferencesDocument>(&raw).map_err(|source| {
                OciError::Json {
                    subject: "user default images store",
                    source,
                }
            })?,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                PreferencesDocument::default()
            }
            Err(source) => {
                return Err(OciError::Io {
                    operation: "read user default images",
                    path,
                    source,
                });
            }
        };
        Ok(Self { path, doc })
    }

    /// Path of the backing JSON file.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Look up the persistent default Linux image for `principal`.
    pub fn get(&self, principal: &str) -> Result<Option<&UserDefaultImage>> {
        let key = validate_principal(principal)?;
        Ok(self.doc.users.get(key))
    }

    /// Set and persist the default Linux image for `principal`.
    pub fn set(&mut self, principal: &str, image: UserDefaultImage) -> Result<()> {
        let key = validate_principal(principal)?.to_owned();
        self.doc.users.insert(key, image);
        self.save()
    }

    /// Clear and persist removal of the default Linux image for `principal`.
    pub fn clear(&mut self, principal: &str) -> Result<Option<UserDefaultImage>> {
        let key = validate_principal(principal)?;
        let removed = self.doc.users.remove(key);
        self.save()?;
        Ok(removed)
    }

    /// Return all stored `(principal, preference)` pairs.
    #[must_use]
    pub fn entries(&self) -> &BTreeMap<String, UserDefaultImage> {
        &self.doc.users
    }

    /// Atomically write the preferences document to disk.
    pub fn save(&self) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).map_err(|source| OciError::Io {
                operation: "create parent directory for user default images",
                path: parent.to_path_buf(),
                source,
            })?;
        }
        let payload = serde_json::to_vec_pretty(&self.doc).map_err(|source| OciError::Json {
            subject: "user default images store",
            source,
        })?;
        let tmp_path = self.path.with_extension("json.tmp");
        fs::write(&tmp_path, &payload).map_err(|source| OciError::Io {
            operation: "write temporary user default images",
            path: tmp_path.clone(),
            source,
        })?;
        fs::rename(&tmp_path, &self.path).map_err(|source| OciError::Io {
            operation: "commit user default images",
            path: self.path.clone(),
            source,
        })?;
        Ok(())
    }
}

fn validate_principal(principal: &str) -> Result<&str> {
    let trimmed = principal.trim();
    if trimmed.is_empty() {
        return Err(OciError::InvalidPrincipal {
            principal: principal.to_owned(),
            reason: "authenticated login principal must not be empty",
        });
    }
    if trimmed.contains('\0') || trimmed.contains('\n') || trimmed.contains('\r') {
        return Err(OciError::InvalidPrincipal {
            principal: principal.to_owned(),
            reason: "authenticated login principal must not contain control characters",
        });
    }
    Ok(trimmed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn persists_per_user_default_images_by_principal() {
        let dir = TempDir::new().unwrap();
        let path = DefaultImageStore::path_in_store(dir.path());

        let mut store = DefaultImageStore::load(&path).unwrap();
        assert!(store.get("alice@helios.internal").unwrap().is_none());

        let alice_img = UserDefaultImage {
            image_ref: "registry-1.docker.io/library/alpine:3.20".to_owned(),
            rootfs_path: "/oci/layers/aaa".to_owned(),
            env: vec![("PATH".to_owned(), "/bin:/usr/bin".to_owned())],
            credentials: ResolvedUser {
                uid: 0,
                gid: 0,
                supplementary_groups: Vec::new(),
            },
        };
        let bob_img = UserDefaultImage {
            image_ref: "registry-1.docker.io/library/ubuntu:24.04".to_owned(),
            rootfs_path: "/oci/layers/bbb".to_owned(),
            env: vec![("LANG".to_owned(), "C.UTF-8".to_owned())],
            credentials: ResolvedUser {
                uid: 1000,
                gid: 1000,
                supplementary_groups: vec![27],
            },
        };

        store
            .set("alice@helios.internal", alice_img.clone())
            .unwrap();
        store.set("bob@helios.internal", bob_img.clone()).unwrap();

        let reloaded = DefaultImageStore::load(&path).unwrap();
        assert_eq!(
            reloaded.get("alice@helios.internal").unwrap(),
            Some(&alice_img)
        );
        assert_eq!(reloaded.get("bob@helios.internal").unwrap(), Some(&bob_img));

        let mut store = reloaded;
        assert_eq!(
            store.clear("alice@helios.internal").unwrap(),
            Some(alice_img)
        );
        let reloaded = DefaultImageStore::load(&path).unwrap();
        assert!(reloaded.get("alice@helios.internal").unwrap().is_none());
        assert_eq!(reloaded.get("bob@helios.internal").unwrap(), Some(&bob_img));
    }
}
