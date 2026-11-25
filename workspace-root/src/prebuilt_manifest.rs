//! Shared metadata schema and artifact naming for prebuilt CI artifacts (#1218).
//!
//! Three tiers of prebuilt artifacts are uploaded on demand by CI and consumed
//! by `helios-cli` and `helios-inspector`:
//! - `userspace`: architecture-independent guest wasm (`helios-wasm-{profile}`)
//! - `kernel`: built kernel ELF and embedded root public key (`helios-kernel-{arch}-{profile}`)
//! - `image`: full bootable bundle — kernel ELF, signed `helios-bootfs`,
//!   root public key, optional Limine UEFI disk image, and optional compiler
//!   plugin wasm (`helios-image-{arch}-{profile}`).
//!
//! Every tier carries a `manifest.json` written with `serde_json` so producers
//! and consumers agree on file names, profile labels, architecture and included
//! programs without ad-hoc parsing.

use std::collections::BTreeSet;
use std::fmt::{self, Write as _};
use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::root_key::{INSPECTOR_CLIENT_SECRET_FILE, ROOT_SECRET_FILE};

/// File name of the manifest stored inside every prebuilt artifact directory.
pub const PREBUILT_MANIFEST_FILE: &str = "manifest.json";

/// Schema version spoken by this crate.
pub const PREBUILT_SCHEMA_VERSION: u32 = 1;

/// Canonical file name of the kernel ELF inside `kernel` and `image` bundles.
pub const KERNEL_IMAGE_FILE: &str = "helios";

/// Canonical file name of the signed `helios-bootfs` payload inside `image` bundles.
pub const BOOTFS_IMAGE_FILE: &str = "helios-bootfs";

/// Canonical file name of the prebuilt Limine UEFI disk image inside `image` bundles.
pub const UEFI_DISK_IMAGE_FILE: &str = "kernel.uefi.img";

/// Canonical file name of the compiler plugin wasm module inside `image` bundles.
pub const COMPILER_PLUGIN_FILE: &str = "compiler_plugin.wasm";

/// Which tier of prebuilt artifact a directory or CI bundle holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PrebuiltArtifactKind {
    Userspace,
    Kernel,
    Image,
}

impl PrebuiltArtifactKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Userspace => "userspace",
            Self::Kernel => "kernel",
            Self::Image => "image",
        }
    }
}

impl fmt::Display for PrebuiltArtifactKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Which guest programs a `userspace` or `image` bundle carries.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PrebuiltPrograms {
    All,
    Subset(Vec<String>),
}

impl PrebuiltPrograms {
    /// Whether `program` is present in this bundle.
    #[must_use]
    pub fn includes(&self, program: &str) -> bool {
        match self {
            Self::All => true,
            Self::Subset(list) => list.iter().any(|item| item == program),
        }
    }

    /// Returns the requested programs that this bundle does not contain.
    #[must_use]
    pub fn missing<'a>(&self, required: &'a [String]) -> Vec<&'a str> {
        match self {
            Self::All => Vec::new(),
            Self::Subset(_) => required
                .iter()
                .filter(|program| !self.includes(program))
                .map(String::as_str)
                .collect(),
        }
    }
}

/// Typed `manifest.json` written into every prebuilt artifact directory.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrebuiltManifest {
    pub schema_version: u32,
    pub kind: PrebuiltArtifactKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arch: Option<String>,
    pub profile: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub kernel_features: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub programs: Option<PrebuiltPrograms>,
    #[serde(default)]
    pub files: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_public_key_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub baud: Option<u32>,
}

/// Why a prebuilt artifact manifest or directory could not be read, written or validated.
#[derive(Debug, Error)]
pub enum PrebuiltManifestError {
    #[error("failed to read {path}: {source}")]
    Read {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("failed to write {path}: {source}")]
    Write {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("failed to decode {path}: {source}")]
    Decode {
        path: String,
        #[source]
        source: serde_json::Error,
    },
    #[error("failed to encode {path}: {source}")]
    Encode {
        path: String,
        #[source]
        source: serde_json::Error,
    },
    #[error(
        "{path} declares schema_version {found}; this tool only supports schema_version {PREBUILT_SCHEMA_VERSION}"
    )]
    UnsupportedSchemaVersion { path: String, found: u32 },
    #[error(
        "{path} lists unsafe file path {entry:?}; manifest entries must be relative paths inside the artifact directory"
    )]
    UnsafeFilePath { path: String, entry: String },
    #[error("{path} lists {entry:?}, which does not exist as a file at {expected}")]
    MissingDeclaredFile {
        path: String,
        entry: String,
        expected: String,
    },
    #[error(
        "refusing prebuilt artifact {dir}: secret key file {ROOT_SECRET_FILE} must never appear in a prebuilt artifact"
    )]
    SecretKeyPresent { dir: String },
    #[error(
        "prebuilt {kind} artifact requires an architecture (`x86-64`, `aarch64`, or `riscv64`)"
    )]
    MissingArch { kind: PrebuiltArtifactKind },
    #[error("prebuilt userspace artifact is architecture-independent; do not pass --arch {arch}")]
    UnexpectedArchForUserspace { arch: String },
    #[error("{path} must hold a 32-byte Ed25519 root public key, found {len} bytes")]
    InvalidRootPublicKeyLength { path: String, len: usize },
}

/// Canonical GitHub Actions artifact name for a `userspace` bundle.
#[must_use]
pub fn userspace_artifact_name(profile: &str) -> String {
    format!("helios-wasm-{profile}")
}

/// Canonical GitHub Actions artifact name for a `kernel` bundle.
#[must_use]
pub fn kernel_artifact_name(arch: &str, profile: &str) -> String {
    format!("helios-kernel-{arch}-{profile}")
}

/// Canonical GitHub Actions artifact name for a full bootable `image` bundle.
#[must_use]
pub fn image_artifact_name(arch: &str, profile: &str) -> String {
    format!("helios-image-{arch}-{profile}")
}

/// Resolves the canonical CI artifact name for `(kind, arch, profile)`.
pub fn artifact_name(
    kind: PrebuiltArtifactKind,
    arch: Option<&str>,
    profile: &str,
) -> Result<String, PrebuiltManifestError> {
    match kind {
        PrebuiltArtifactKind::Userspace => {
            if let Some(arch) = arch {
                return Err(PrebuiltManifestError::UnexpectedArchForUserspace {
                    arch: arch.to_owned(),
                });
            }
            Ok(userspace_artifact_name(profile))
        }
        PrebuiltArtifactKind::Kernel => {
            let arch = arch.ok_or(PrebuiltManifestError::MissingArch { kind })?;
            Ok(kernel_artifact_name(arch, profile))
        }
        PrebuiltArtifactKind::Image => {
            let arch = arch.ok_or(PrebuiltManifestError::MissingArch { kind })?;
            Ok(image_artifact_name(arch, profile))
        }
    }
}

/// Builds a deterministic artifact profile label from the base profile
/// (`debug` or `release`), sorted unique kernel features, and an optional suffix
/// (such as `cfi`).
#[must_use]
pub fn artifact_profile_label(
    base_profile: &str,
    kernel_features: &[String],
    extra_suffix: Option<&str>,
) -> String {
    let mut parts = vec![base_profile.to_owned()];
    let unique_features: BTreeSet<&str> = kernel_features.iter().map(String::as_str).collect();
    parts.extend(unique_features.into_iter().map(str::to_owned));
    if let Some(suffix) = extra_suffix.filter(|suffix| !suffix.is_empty()) {
        parts.push(suffix.to_owned());
    }
    parts.join("-")
}

/// Lowercase hex SHA-256 digest of `bytes`.
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

/// Reads a 32-byte Ed25519 root public key from `path`.
pub fn read_root_public_key(path: &Path) -> Result<[u8; 32], PrebuiltManifestError> {
    let bytes = fs::read(path).map_err(|source| PrebuiltManifestError::Read {
        path: path.display().to_string(),
        source,
    })?;
    let len = bytes.len();
    bytes
        .try_into()
        .map_err(|_| PrebuiltManifestError::InvalidRootPublicKeyLength {
            path: path.display().to_string(),
            len,
        })
}

/// Serializes `manifest` as pretty JSON into `<dir>/manifest.json`.
pub fn write_manifest(
    dir: &Path,
    manifest: &PrebuiltManifest,
) -> Result<PathBuf, PrebuiltManifestError> {
    let allow_inspector_client_key = manifest.kind == PrebuiltArtifactKind::Image;
    if dir.join(ROOT_SECRET_FILE).exists()
        || (!allow_inspector_client_key && dir.join(INSPECTOR_CLIENT_SECRET_FILE).exists())
        || manifest.files.iter().any(|file| {
            let name = Path::new(file).file_name();
            name == Some(ROOT_SECRET_FILE.as_ref())
                || (!allow_inspector_client_key
                    && name == Some(INSPECTOR_CLIENT_SECRET_FILE.as_ref()))
        })
    {
        return Err(PrebuiltManifestError::SecretKeyPresent {
            dir: dir.display().to_string(),
        });
    }
    let path = dir.join(PREBUILT_MANIFEST_FILE);
    let mut encoded =
        serde_json::to_string_pretty(manifest).map_err(|source| PrebuiltManifestError::Encode {
            path: path.display().to_string(),
            source,
        })?;
    encoded.push('\n');
    fs::write(&path, encoded).map_err(|source| PrebuiltManifestError::Write {
        path: path.display().to_string(),
        source,
    })?;
    Ok(path)
}

/// Reads and validates `<dir>/manifest.json`, verifying its schema version,
/// checking that no root secret key is present, and confirming every declared
/// file exists under `dir`.
pub fn read_manifest(dir: &Path) -> Result<PrebuiltManifest, PrebuiltManifestError> {
    if dir.join(ROOT_SECRET_FILE).exists() {
        return Err(PrebuiltManifestError::SecretKeyPresent {
            dir: dir.display().to_string(),
        });
    }
    let path = dir.join(PREBUILT_MANIFEST_FILE);
    let raw = fs::read_to_string(&path).map_err(|source| PrebuiltManifestError::Read {
        path: path.display().to_string(),
        source,
    })?;
    let manifest: PrebuiltManifest =
        serde_json::from_str(&raw).map_err(|source| PrebuiltManifestError::Decode {
            path: path.display().to_string(),
            source,
        })?;
    if manifest.schema_version != PREBUILT_SCHEMA_VERSION {
        return Err(PrebuiltManifestError::UnsupportedSchemaVersion {
            path: path.display().to_string(),
            found: manifest.schema_version,
        });
    }
    let allow_inspector_client_key = manifest.kind == PrebuiltArtifactKind::Image;
    if !allow_inspector_client_key && dir.join(INSPECTOR_CLIENT_SECRET_FILE).exists() {
        return Err(PrebuiltManifestError::SecretKeyPresent {
            dir: dir.display().to_string(),
        });
    }
    for entry in &manifest.files {
        validate_relative_entry(&path, entry)?;
        let file_name = Path::new(entry).file_name();
        if file_name == Some(ROOT_SECRET_FILE.as_ref())
            || (!allow_inspector_client_key
                && file_name == Some(INSPECTOR_CLIENT_SECRET_FILE.as_ref()))
        {
            return Err(PrebuiltManifestError::SecretKeyPresent {
                dir: dir.display().to_string(),
            });
        }
        let expected = dir.join(entry);
        if !expected.is_file() {
            return Err(PrebuiltManifestError::MissingDeclaredFile {
                path: path.display().to_string(),
                entry: entry.clone(),
                expected: expected.display().to_string(),
            });
        }
    }
    Ok(manifest)
}

fn validate_relative_entry(manifest_path: &Path, entry: &str) -> Result<(), PrebuiltManifestError> {
    let rel = Path::new(entry);
    if entry.is_empty() || rel.is_absolute() {
        return Err(PrebuiltManifestError::UnsafeFilePath {
            path: manifest_path.display().to_string(),
            entry: entry.to_owned(),
        });
    }
    for component in rel.components() {
        if !matches!(component, Component::Normal(_)) {
            return Err(PrebuiltManifestError::UnsafeFilePath {
                path: manifest_path.display().to_string(),
                entry: entry.to_owned(),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::root_key::ROOT_PUBLIC_FILE;
    use tempfile::TempDir;

    fn sample_image_manifest() -> PrebuiltManifest {
        PrebuiltManifest {
            schema_version: PREBUILT_SCHEMA_VERSION,
            kind: PrebuiltArtifactKind::Image,
            commit: Some("0123456789abcdef0123456789abcdef01234567".to_owned()),
            arch: Some("x86-64".to_owned()),
            profile: "release-linux".to_owned(),
            kernel_features: vec!["linux".to_owned()],
            programs: Some(PrebuiltPrograms::Subset(vec![
                "init".to_owned(),
                "inspector-host".to_owned(),
                "inspector-tls".to_owned(),
                "inspector-worker".to_owned(),
            ])),
            files: vec![
                KERNEL_IMAGE_FILE.to_owned(),
                BOOTFS_IMAGE_FILE.to_owned(),
                ROOT_PUBLIC_FILE.to_owned(),
            ],
            root_public_key_sha256: Some(sha256_hex(&[7_u8; 32])),
            baud: Some(115_200),
        }
    }

    #[test]
    fn manifest_round_trips_and_validates_files() {
        let dir = TempDir::new().expect("temp dir");
        fs::write(dir.path().join(KERNEL_IMAGE_FILE), b"elf").expect("write kernel");
        fs::write(dir.path().join(BOOTFS_IMAGE_FILE), b"bootfs").expect("write bootfs");
        fs::write(dir.path().join(ROOT_PUBLIC_FILE), [7_u8; 32]).expect("write pubkey");

        let manifest = sample_image_manifest();
        write_manifest(dir.path(), &manifest).expect("write manifest");
        let loaded = read_manifest(dir.path()).expect("read manifest");
        assert_eq!(loaded, manifest);
    }

    #[test]
    fn read_manifest_rejects_missing_declared_file() {
        let dir = TempDir::new().expect("temp dir");
        fs::write(dir.path().join(KERNEL_IMAGE_FILE), b"elf").expect("write kernel");
        let manifest = sample_image_manifest();
        write_manifest(dir.path(), &manifest).expect("write manifest");
        let error = read_manifest(dir.path()).expect_err("missing bootfs must fail");
        assert!(matches!(
            error,
            PrebuiltManifestError::MissingDeclaredFile { .. }
        ));
    }

    #[test]
    fn read_manifest_rejects_secret_key_and_path_traversal() {
        let dir = TempDir::new().expect("temp dir");
        let mut manifest = sample_image_manifest();
        manifest.files = vec!["../escape".to_owned()];
        write_manifest(dir.path(), &manifest).expect("write manifest");
        let traversal = read_manifest(dir.path()).expect_err("path traversal must fail");
        assert!(matches!(
            traversal,
            PrebuiltManifestError::UnsafeFilePath { .. }
        ));

        fs::write(dir.path().join(ROOT_SECRET_FILE), [1_u8; 32]).expect("write secret");
        let secret = read_manifest(dir.path()).expect_err("secret key must be refused");
        assert!(matches!(
            secret,
            PrebuiltManifestError::SecretKeyPresent { .. }
        ));
    }

    #[test]
    fn artifact_naming_and_profile_labels_are_canonical() {
        assert_eq!(
            artifact_name(PrebuiltArtifactKind::Userspace, None, "debug").expect("userspace name"),
            "helios-wasm-debug"
        );
        assert!(artifact_name(PrebuiltArtifactKind::Userspace, Some("x86-64"), "debug").is_err());
        assert_eq!(
            artifact_name(
                PrebuiltArtifactKind::Kernel,
                Some("x86-64"),
                "release-linux"
            )
            .expect("kernel name"),
            "helios-kernel-x86-64-release-linux"
        );
        assert_eq!(
            artifact_name(PrebuiltArtifactKind::Image, Some("aarch64"), "release")
                .expect("image name"),
            "helios-image-aarch64-release"
        );
        assert!(artifact_name(PrebuiltArtifactKind::Image, None, "release").is_err());
        assert_eq!(
            artifact_profile_label("release", &["linux".to_owned(), "linux".to_owned()], None),
            "release-linux"
        );
        assert_eq!(
            artifact_profile_label("debug", &[], Some("cfi")),
            "debug-cfi"
        );
    }

    #[test]
    fn programs_subset_reports_missing_entries() {
        let all = PrebuiltPrograms::All;
        assert!(
            all.missing(&["dash".to_owned(), "cpu".to_owned()])
                .is_empty()
        );

        let subset = PrebuiltPrograms::Subset(vec!["inspector-host".to_owned(), "init".to_owned()]);
        assert_eq!(
            subset.missing(&["inspector-host".to_owned(), "cpu".to_owned()]),
            vec!["cpu"]
        );
    }
}
