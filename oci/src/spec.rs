//! OCI Image Specification and Distribution Specification data structures.

use core::fmt;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::{OciError, Result};
use crate::reference::Digest;

/// Media type constants defined by the OCI Image Spec and Docker Registry v2.2.
pub mod media_type {
    pub const OCI_INDEX: &str = "application/vnd.oci.image.index.v1+json";
    pub const OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
    pub const OCI_CONFIG: &str = "application/vnd.oci.image.config.v1+json";
    pub const OCI_LAYER_TAR: &str = "application/vnd.oci.image.layer.v1.tar";
    pub const OCI_LAYER_TAR_GZIP: &str = "application/vnd.oci.image.layer.v1.tar+gzip";
    pub const OCI_LAYER_TAR_ZSTD: &str = "application/vnd.oci.image.layer.v1.tar+zstd";
    pub const OCI_LAYER_NONDIST_TAR: &str =
        "application/vnd.oci.image.layer.nondistributable.v1.tar";
    pub const OCI_LAYER_NONDIST_TAR_GZIP: &str =
        "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip";
    pub const OCI_LAYER_NONDIST_TAR_ZSTD: &str =
        "application/vnd.oci.image.layer.nondistributable.v1.tar+zstd";

    pub const DOCKER_MANIFEST_LIST: &str =
        "application/vnd.docker.distribution.manifest.list.v2+json";
    pub const DOCKER_MANIFEST_V2: &str = "application/vnd.docker.distribution.manifest.v2+json";
    pub const DOCKER_CONFIG: &str = "application/vnd.docker.container.image.v1+json";
    pub const DOCKER_LAYER_TAR_GZIP: &str = "application/vnd.docker.image.rootfs.diff.tar.gzip";
    pub const DOCKER_LAYER_TAR_ZSTD: &str = "application/vnd.docker.image.rootfs.diff.tar.zstd";
    pub const DOCKER_LAYER_TAR: &str = "application/vnd.docker.image.rootfs.diff.tar";

    /// `Accept` header sent when requesting an OCI manifest or manifest index.
    pub const MANIFEST_ACCEPT_HEADER: &str = "application/vnd.oci.image.index.v1+json, \
         application/vnd.docker.distribution.manifest.list.v2+json, \
         application/vnd.oci.image.manifest.v1+json, \
         application/vnd.docker.distribution.manifest.v2+json";
}

/// Target Linux CPU architecture supported by Helios containers and VMs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Arch {
    #[serde(rename = "amd64", alias = "x86_64")]
    X86_64,
    #[serde(rename = "arm64", alias = "aarch64")]
    Aarch64,
}

impl Arch {
    /// OCI `platform.architecture` value (`"amd64"` or `"arm64"`).
    #[must_use]
    pub const fn oci_arch(self) -> &'static str {
        match self {
            Self::X86_64 => "amd64",
            Self::Aarch64 => "arm64",
        }
    }

    /// Rust / Linux uname architecture name (`"x86_64"` or `"aarch64"`).
    #[must_use]
    pub const fn rust_arch(self) -> &'static str {
        match self {
            Self::X86_64 => "x86_64",
            Self::Aarch64 => "aarch64",
        }
    }

    /// Parse `"x86_64"`, `"amd64"`, `"aarch64"`, or `"arm64"`.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "x86_64" | "amd64" => Some(Self::X86_64),
            "aarch64" | "arm64" => Some(Self::Aarch64),
            _ => None,
        }
    }

    /// Host compile-time architecture (defaults to `X86_64` on wasm32 targets where
    /// the caller should select the guest Linux architecture explicitly).
    #[must_use]
    pub const fn host_default() -> Self {
        #[cfg(target_arch = "aarch64")]
        {
            Self::Aarch64
        }
        #[cfg(not(target_arch = "aarch64"))]
        {
            Self::X86_64
        }
    }
}

impl fmt::Display for Arch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.oci_arch())
    }
}

/// Layer archive compression format inferred from an OCI descriptor media type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LayerCompression {
    None,
    Gzip,
    Zstd,
}

impl LayerCompression {
    /// Infer compression from a layer descriptor's `mediaType`.
    pub fn from_media_type(media_type: &str) -> Result<Self> {
        match media_type {
            media_type::OCI_LAYER_TAR
            | media_type::OCI_LAYER_NONDIST_TAR
            | media_type::DOCKER_LAYER_TAR => Ok(Self::None),
            media_type::OCI_LAYER_TAR_GZIP
            | media_type::OCI_LAYER_NONDIST_TAR_GZIP
            | media_type::DOCKER_LAYER_TAR_GZIP => Ok(Self::Gzip),
            media_type::OCI_LAYER_TAR_ZSTD
            | media_type::OCI_LAYER_NONDIST_TAR_ZSTD
            | media_type::DOCKER_LAYER_TAR_ZSTD => Ok(Self::Zstd),
            other => Err(OciError::UnsupportedMediaType {
                subject: "image layer",
                media_type: other.to_owned(),
            }),
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "uncompressed",
            Self::Gzip => "gzip",
            Self::Zstd => "zstd",
        }
    }
}

/// Platform selector on an OCI manifest descriptor.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Platform {
    pub os: String,
    pub architecture: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub variant: Option<String>,
}

/// OCI content descriptor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Descriptor {
    #[serde(rename = "mediaType")]
    pub media_type: String,
    pub digest: Digest,
    pub size: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub urls: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub annotations: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<Platform>,
}

/// Multi-architecture OCI Image Index / Docker Manifest List.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageIndex {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u32,
    #[serde(rename = "mediaType", default, skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
    pub manifests: Vec<Descriptor>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub annotations: BTreeMap<String, String>,
}

impl ImageIndex {
    /// Select the manifest descriptor matching `os == "linux"` and `arch`.
    ///
    /// On `Aarch64`, prefers an entry with `variant == Some("v8")` or `variant == None`,
    /// and skips attestation/unknown-platform descriptors.
    #[must_use]
    pub fn select_linux(&self, arch: Arch) -> Option<&Descriptor> {
        let want_arch = arch.oci_arch();
        let mut fallback = None;
        for desc in &self.manifests {
            let Some(platform) = &desc.platform else {
                continue;
            };
            if platform.os != "linux" || platform.architecture != want_arch {
                continue;
            }
            if desc
                .annotations
                .get("vnd.docker.reference.type")
                .is_some_and(|v| v == "attestation-manifest")
            {
                continue;
            }
            match arch {
                Arch::Aarch64 => {
                    if matches!(platform.variant.as_deref(), None | Some("") | Some("v8")) {
                        return Some(desc);
                    }
                    fallback.get_or_insert(desc);
                }
                Arch::X86_64 => return Some(desc),
            }
        }
        fallback
    }
}

/// Single-platform OCI Image Manifest / Docker Manifest v2.2.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageManifest {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u32,
    #[serde(rename = "mediaType", default, skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
    pub config: Descriptor,
    pub layers: Vec<Descriptor>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub annotations: BTreeMap<String, String>,
}

/// Parsed response from `/v2/<repo>/manifests/<ref>`: either an index or a single manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ManifestDocument {
    Index(ImageIndex),
    Manifest(ImageManifest),
}

impl ManifestDocument {
    /// Parse a manifest response using the HTTP `Content-Type` header and JSON payload.
    pub fn parse(content_type: Option<&str>, bytes: &[u8]) -> Result<Self> {
        let ct = content_type
            .map(|v| v.split(';').next().unwrap_or("").trim())
            .unwrap_or("");
        if matches!(ct, media_type::OCI_INDEX | media_type::DOCKER_MANIFEST_LIST) {
            let index: ImageIndex =
                serde_json::from_slice(bytes).map_err(|source| OciError::Json {
                    subject: "image index",
                    source,
                })?;
            return Ok(Self::Index(index));
        }
        if matches!(
            ct,
            media_type::OCI_MANIFEST | media_type::DOCKER_MANIFEST_V2
        ) {
            let manifest: ImageManifest =
                serde_json::from_slice(bytes).map_err(|source| OciError::Json {
                    subject: "image manifest",
                    source,
                })?;
            return Ok(Self::Manifest(manifest));
        }

        // Fall back to inspecting the JSON object's `mediaType` / top-level keys.
        let value: serde_json::Value =
            serde_json::from_slice(bytes).map_err(|source| OciError::Json {
                subject: "manifest document",
                source,
            })?;
        let embedded_mt = value.get("mediaType").and_then(serde_json::Value::as_str);
        if embedded_mt == Some(media_type::OCI_INDEX)
            || embedded_mt == Some(media_type::DOCKER_MANIFEST_LIST)
            || value.get("manifests").is_some()
        {
            let index: ImageIndex =
                serde_json::from_value(value).map_err(|source| OciError::Json {
                    subject: "image index",
                    source,
                })?;
            Ok(Self::Index(index))
        } else if embedded_mt == Some(media_type::OCI_MANIFEST)
            || embedded_mt == Some(media_type::DOCKER_MANIFEST_V2)
            || (value.get("config").is_some() && value.get("layers").is_some())
        {
            let manifest: ImageManifest =
                serde_json::from_value(value).map_err(|source| OciError::Json {
                    subject: "image manifest",
                    source,
                })?;
            Ok(Self::Manifest(manifest))
        } else {
            Err(OciError::UnsupportedMediaType {
                subject: "manifest",
                media_type: embedded_mt.unwrap_or(ct).to_owned(),
            })
        }
    }
}

/// `rootfs` section of an OCI Image Config JSON.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootFs {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub diff_ids: Vec<Digest>,
}

/// Execution parameters embedded in an OCI Image Config (`config` object).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageRuntimeConfig {
    #[serde(rename = "User", default)]
    pub user: Option<String>,
    #[serde(rename = "Env", default)]
    pub env: Vec<String>,
    #[serde(rename = "Entrypoint", default)]
    pub entrypoint: Vec<String>,
    #[serde(rename = "Cmd", default)]
    pub cmd: Vec<String>,
    #[serde(rename = "WorkingDir", default)]
    pub working_dir: Option<String>,
    #[serde(rename = "Labels", default)]
    pub labels: BTreeMap<String, String>,
    #[serde(rename = "StopSignal", default)]
    pub stop_signal: Option<String>,
}

/// Resolved Unix credentials parsed from OCI `config.User`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedUser {
    pub uid: u32,
    pub gid: u32,
    pub supplementary_groups: Vec<u32>,
}

impl ImageRuntimeConfig {
    /// Parse `Env` entries (`"KEY=VALUE"`) into `(key, value)` pairs.
    #[must_use]
    pub fn env_pairs(&self) -> Vec<(String, String)> {
        self.env
            .iter()
            .filter_map(|entry| match entry.split_once('=') {
                Some((k, v)) if !k.is_empty() => Some((k.to_owned(), v.to_owned())),
                _ => None,
            })
            .collect()
    }

    /// Resolve the effective `(executable_path, argv_tail)` by combining OCI
    /// `Entrypoint` and `Cmd` (with optional caller command override).
    ///
    /// Follows OCI Image Spec semantics:
    /// - If `override_args` is `Some(args)`:
    ///   - If `Entrypoint` is non-empty, runs `Entrypoint` followed by `args`.
    ///   - Otherwise runs `args` directly.
    /// - If `override_args` is `None`, runs `Entrypoint` followed by `Cmd`.
    #[must_use]
    pub fn resolve_command(
        &self,
        override_args: Option<&[String]>,
    ) -> Option<(String, Vec<String>)> {
        let mut full = Vec::new();
        if !self.entrypoint.is_empty() {
            full.extend(self.entrypoint.iter().cloned());
            match override_args {
                Some(extra) => full.extend(extra.iter().cloned()),
                None => full.extend(self.cmd.iter().cloned()),
            }
        } else {
            match override_args {
                Some(extra) => full.extend(extra.iter().cloned()),
                None => full.extend(self.cmd.iter().cloned()),
            }
        }
        let mut iter = full.into_iter();
        let program = iter.next()?;
        Some((program, iter.collect()))
    }

    /// Normalized working directory, or `None` when unset / empty.
    #[must_use]
    pub fn effective_working_dir(&self) -> Option<&str> {
        self.working_dir
            .as_deref()
            .map(str::trim)
            .filter(|dir| !dir.is_empty())
    }

    /// Resolve OCI `config.User` (`""`, `"uid"`, `"uid:gid"`, `"user"`, `"user:group"`)
    /// using `<rootfs>/etc/passwd` and `<rootfs>/etc/group` when symbolic names are given.
    pub fn resolve_user(&self, rootfs: Option<&Path>) -> Result<ResolvedUser> {
        let Some(raw) = self
            .user
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        else {
            return Ok(ResolvedUser::default());
        };
        let (user_part, group_part) = match raw.split_once(':') {
            Some((u, g)) => (u.trim(), Some(g.trim())),
            None => (raw, None),
        };
        if user_part.is_empty() {
            return Err(OciError::InvalidUser {
                spec: raw.to_owned(),
                reason: "user component must not be empty".to_owned(),
            });
        }

        let (uid, passwd_gid) = if let Ok(uid) = user_part.parse::<u32>() {
            (uid, None)
        } else {
            let Some(root) = rootfs else {
                return Err(OciError::InvalidUser {
                    spec: raw.to_owned(),
                    reason: "symbolic username requires a materialized rootfs with /etc/passwd"
                        .to_owned(),
                });
            };
            lookup_passwd(root, user_part, raw)?
        };

        let gid = match group_part {
            Some(g) if !g.is_empty() => {
                if let Ok(gid) = g.parse::<u32>() {
                    gid
                } else {
                    let Some(root) = rootfs else {
                        return Err(OciError::InvalidUser {
                            spec: raw.to_owned(),
                            reason:
                                "symbolic group name requires a materialized rootfs with /etc/group"
                                    .to_owned(),
                        });
                    };
                    lookup_group(root, g, raw)?
                }
            }
            _ => passwd_gid.unwrap_or(0),
        };

        Ok(ResolvedUser {
            uid,
            gid,
            supplementary_groups: Vec::new(),
        })
    }
}

fn lookup_passwd(rootfs: &Path, username: &str, spec: &str) -> Result<(u32, Option<u32>)> {
    let path = rootfs.join("etc/passwd");
    let content = fs::read_to_string(&path).map_err(|err| OciError::InvalidUser {
        spec: spec.to_owned(),
        reason: format!("cannot read `{}`: {err}", path.display()),
    })?;
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.split(':');
        let Some(name) = fields.next() else {
            continue;
        };
        if name == username {
            let _pw = fields.next();
            let uid = fields
                .next()
                .and_then(|v| v.parse::<u32>().ok())
                .ok_or_else(|| OciError::InvalidUser {
                    spec: spec.to_owned(),
                    reason: format!("malformed uid in /etc/passwd for `{username}`"),
                })?;
            let gid = fields.next().and_then(|v| v.parse::<u32>().ok());
            return Ok((uid, gid));
        }
    }
    Err(OciError::InvalidUser {
        spec: spec.to_owned(),
        reason: format!("user `{username}` not found in /etc/passwd"),
    })
}

fn lookup_group(rootfs: &Path, groupname: &str, spec: &str) -> Result<u32> {
    let path = rootfs.join("etc/group");
    let content = fs::read_to_string(&path).map_err(|err| OciError::InvalidUser {
        spec: spec.to_owned(),
        reason: format!("cannot read `{}`: {err}", path.display()),
    })?;
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.split(':');
        let Some(name) = fields.next() else {
            continue;
        };
        if name == groupname {
            let _pw = fields.next();
            let gid = fields
                .next()
                .and_then(|v| v.parse::<u32>().ok())
                .ok_or_else(|| OciError::InvalidUser {
                    spec: spec.to_owned(),
                    reason: format!("malformed gid in /etc/group for `{groupname}`"),
                })?;
            return Ok(gid);
        }
    }
    Err(OciError::InvalidUser {
        spec: spec.to_owned(),
        reason: format!("group `{groupname}` not found in /etc/group"),
    })
}

/// Top-level OCI Image Config JSON document.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageConfig {
    #[serde(default)]
    pub architecture: String,
    #[serde(default)]
    pub os: String,
    #[serde(default)]
    pub config: ImageRuntimeConfig,
    #[serde(default)]
    pub rootfs: RootFs,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn resolves_entrypoint_cmd_env_and_user() {
        let dir = TempDir::new().unwrap();
        fs::create_dir_all(dir.path().join("etc")).unwrap();
        fs::write(
            dir.path().join("etc/passwd"),
            "root:x:0:0:root:/root:/bin/sh\nnobody:x:65534:65534:nobody:/:/sbin/nologin\n",
        )
        .unwrap();
        fs::write(
            dir.path().join("etc/group"),
            "root:x:0:\nnogroup:x:65534:\nwww-data:x:33:\n",
        )
        .unwrap();

        let cfg = ImageRuntimeConfig {
            user: Some("nobody:www-data".to_owned()),
            env: vec![
                "PATH=/usr/local/sbin:/usr/local/bin:/usr/bin:/bin".to_owned(),
                "APP_DSN=postgres://a=b&c=d".to_owned(),
            ],
            entrypoint: vec!["/usr/bin/env".to_owned()],
            cmd: vec!["sh".to_owned(), "-c".to_owned(), "echo hi".to_owned()],
            working_dir: Some("/app".to_owned()),
            labels: BTreeMap::new(),
            stop_signal: Some("SIGTERM".to_owned()),
        };

        assert_eq!(
            cfg.resolve_command(None),
            Some((
                "/usr/bin/env".to_owned(),
                vec!["sh".to_owned(), "-c".to_owned(), "echo hi".to_owned()]
            ))
        );
        assert_eq!(
            cfg.resolve_command(Some(&["id".to_owned()])),
            Some(("/usr/bin/env".to_owned(), vec!["id".to_owned()]))
        );
        assert_eq!(
            cfg.env_pairs(),
            vec![
                (
                    "PATH".to_owned(),
                    "/usr/local/sbin:/usr/local/bin:/usr/bin:/bin".to_owned()
                ),
                ("APP_DSN".to_owned(), "postgres://a=b&c=d".to_owned()),
            ]
        );
        let user = cfg.resolve_user(Some(dir.path())).unwrap();
        assert_eq!(
            user,
            ResolvedUser {
                uid: 65534,
                gid: 33,
                supplementary_groups: Vec::new(),
            }
        );
    }

    #[test]
    fn selects_matching_platform_from_multi_arch_index() {
        let amd64_digest = Digest::sha256(b"amd64");
        let arm64_digest = Digest::sha256(b"arm64");
        let index = ImageIndex {
            schema_version: 2,
            media_type: Some(media_type::OCI_INDEX.to_owned()),
            manifests: vec![
                Descriptor {
                    media_type: media_type::OCI_MANIFEST.to_owned(),
                    digest: amd64_digest.clone(),
                    size: 512,
                    urls: Vec::new(),
                    annotations: BTreeMap::new(),
                    platform: Some(Platform {
                        os: "linux".to_owned(),
                        architecture: "amd64".to_owned(),
                        variant: None,
                    }),
                },
                Descriptor {
                    media_type: media_type::OCI_MANIFEST.to_owned(),
                    digest: arm64_digest.clone(),
                    size: 520,
                    urls: Vec::new(),
                    annotations: BTreeMap::new(),
                    platform: Some(Platform {
                        os: "linux".to_owned(),
                        architecture: "arm64".to_owned(),
                        variant: Some("v8".to_owned()),
                    }),
                },
            ],
            annotations: BTreeMap::new(),
        };
        assert_eq!(
            index.select_linux(Arch::X86_64).unwrap().digest,
            amd64_digest
        );
        assert_eq!(
            index.select_linux(Arch::Aarch64).unwrap().digest,
            arm64_digest
        );
    }
}
