//! OCI image references (`registry/repository[:tag|@digest]`) and SHA-256 digests.

use core::fmt;
use serde::{Deserialize, Serialize};
use sha2::{Digest as Sha2Digest, Sha256};

use crate::error::{OciError, Result};

/// Default Docker Hub registry host.
pub const DEFAULT_REGISTRY: &str = "registry-1.docker.io";

/// A validated OCI content digest (`sha256:<64-lowercase-hex>`).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Digest {
    algorithm: String,
    hex: String,
}

impl Digest {
    /// Parse and validate an OCI digest string (currently requires `sha256:<64 hex>`).
    pub fn parse(raw: &str) -> Result<Self> {
        let trimmed = raw.trim();
        let Some((alg, hex)) = trimmed.split_once(':') else {
            return Err(OciError::InvalidDigest {
                digest: raw.to_owned(),
                reason: "expected `<algorithm>:<hex>`",
            });
        };
        if alg != "sha256" {
            return Err(OciError::InvalidDigest {
                digest: raw.to_owned(),
                reason: "only `sha256` digests are supported",
            });
        }
        if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(OciError::InvalidDigest {
                digest: raw.to_owned(),
                reason: "sha256 digest must be 64 hexadecimal characters",
            });
        }
        Ok(Self {
            algorithm: alg.to_owned(),
            hex: hex.to_ascii_lowercase(),
        })
    }

    /// Compute the `sha256:<hex>` digest of `bytes`.
    #[must_use]
    pub fn sha256(bytes: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        Self::from_sha256_bytes(hasher.finalize().into())
    }

    /// Construct a `sha256:<hex>` digest from 32 raw hash bytes.
    #[must_use]
    pub fn from_sha256_bytes(bytes: [u8; 32]) -> Self {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(64);
        for b in bytes {
            out.push(HEX[usize::from(b >> 4)] as char);
            out.push(HEX[usize::from(b & 0x0f)] as char);
        }
        Self {
            algorithm: "sha256".to_owned(),
            hex: out,
        }
    }

    /// Compute the OCI Image Spec `ChainID` for a layer given its optional parent `ChainID`
    /// and its uncompressed `DiffID`:
    /// - Base layer: `ChainID(L0) = DiffID(L0)`
    /// - Child layer: `ChainID(Ln) = sha256(ChainID(Ln-1) + " " + DiffID(Ln))`
    #[must_use]
    pub fn chain_id(parent: Option<&Self>, diff_id: &Self) -> Self {
        match parent {
            None => diff_id.clone(),
            Some(parent_chain) => {
                let mut hasher = Sha256::new();
                hasher.update(parent_chain.as_str().as_bytes());
                hasher.update(b" ");
                hasher.update(diff_id.as_str().as_bytes());
                Self::from_sha256_bytes(hasher.finalize().into())
            }
        }
    }

    /// Algorithm prefix (e.g. `"sha256"`).
    #[must_use]
    pub fn algorithm(&self) -> &str {
        &self.algorithm
    }

    /// Lowercase hexadecimal digest body (64 chars for SHA-256).
    #[must_use]
    pub fn hex(&self) -> &str {
        &self.hex
    }

    /// Full canonical `algorithm:hex` representation.
    #[must_use]
    pub fn as_str(&self) -> String {
        format!("{}:{}", self.algorithm, self.hex)
    }

    /// Derive a deterministic 16-byte UUID from this digest (useful for btrfs send streams).
    #[must_use]
    pub fn to_uuid_bytes(&self) -> [u8; 16] {
        let mut uuid = [0u8; 16];
        let hex_bytes = self.hex.as_bytes();
        for (i, slot) in uuid.iter_mut().enumerate() {
            let hi = hex_nibble(hex_bytes[i * 2]);
            let lo = hex_nibble(hex_bytes[i * 2 + 1]);
            *slot = (hi << 4) | lo;
        }
        // RFC 4122 version 5 / variant 1 layout bits so UUID is always non-zero and valid.
        uuid[6] = (uuid[6] & 0x0f) | 0x50;
        uuid[8] = (uuid[8] & 0x3f) | 0x80;
        uuid
    }
}

fn hex_nibble(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => 0,
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.algorithm, self.hex)
    }
}

impl TryFrom<String> for Digest {
    type Error = OciError;

    fn try_from(value: String) -> Result<Self> {
        Self::parse(&value)
    }
}

impl From<Digest> for String {
    fn from(value: Digest) -> Self {
        value.as_str()
    }
}

/// Tag or immutable digest selector on an [`ImageReference`].
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ReferenceSelector {
    Tag(String),
    Digest(Digest),
}

impl ReferenceSelector {
    /// Reference string placed in `/v2/<repo>/manifests/<reference>`.
    #[must_use]
    pub fn manifest_ref(&self) -> String {
        match self {
            Self::Tag(tag) => tag.clone(),
            Self::Digest(digest) => digest.as_str(),
        }
    }
}

/// Parsed OCI image reference (`[http://|https://][registry/]repository[:tag|@digest]`).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ImageReference {
    pub registry: String,
    pub repository: String,
    pub selector: ReferenceSelector,
    /// When `true`, contact the registry over plain HTTP (for loopback/dev registries).
    pub insecure_http: bool,
}

impl ImageReference {
    /// Parse an OCI/Docker image reference string.
    ///
    /// Rules match the OCI Distribution & Docker Hub conventions:
    /// - Optional `http://` (sets `insecure_http = true`) or `https://` prefix.
    /// - Bare names like `"alpine"` or `"alpine:3.20"` normalize to
    ///   `registry-1.docker.io/library/alpine:latest` / `:3.20`.
    /// - `docker.io/...` normalizes to `registry-1.docker.io/...` (adding `library/` if single-segment).
    /// - Registries are recognized when the first `/`-separated component contains `.`, `:`,
    ///   or equals `"localhost"`.
    pub fn parse(raw: &str) -> Result<Self> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(OciError::InvalidReference {
                reference: raw.to_owned(),
                reason: "reference must not be empty",
            });
        }

        let (rest, insecure_http) = if let Some(stripped) = trimmed.strip_prefix("http://") {
            (stripped, true)
        } else if let Some(stripped) = trimmed.strip_prefix("https://") {
            (stripped, false)
        } else {
            (trimmed, false)
        };

        let (name_part, selector) = if let Some((before_at, digest_str)) = rest.split_once('@') {
            let digest = Digest::parse(digest_str)?;
            // Strip optional tag before `@sha256:...` (e.g. `repo:tag@sha256:...`).
            let cleaned_name = strip_tag_suffix(before_at);
            (cleaned_name, ReferenceSelector::Digest(digest))
        } else {
            let last_slash = rest.rfind('/');
            let last_colon = rest.rfind(':');
            match (last_slash, last_colon) {
                (Some(s), Some(c)) if c > s => {
                    let tag = &rest[c + 1..];
                    validate_tag(raw, tag)?;
                    (&rest[..c], ReferenceSelector::Tag(tag.to_owned()))
                }
                (None, Some(c)) => {
                    let tag = &rest[c + 1..];
                    validate_tag(raw, tag)?;
                    (&rest[..c], ReferenceSelector::Tag(tag.to_owned()))
                }
                _ => (rest, ReferenceSelector::Tag("latest".to_owned())),
            }
        };

        if name_part.is_empty() {
            return Err(OciError::InvalidReference {
                reference: raw.to_owned(),
                reason: "missing repository name",
            });
        }

        let (registry, repository) = match name_part.split_once('/') {
            Some((first, remainder))
                if first.contains('.') || first.contains(':') || first == "localhost" =>
            {
                if remainder.is_empty() {
                    return Err(OciError::InvalidReference {
                        reference: raw.to_owned(),
                        reason: "missing repository path after registry host",
                    });
                }
                if first == "docker.io" || first == "index.docker.io" || first == DEFAULT_REGISTRY {
                    let repo = if remainder.contains('/') {
                        remainder.to_owned()
                    } else {
                        format!("library/{remainder}")
                    };
                    (DEFAULT_REGISTRY.to_owned(), repo)
                } else {
                    (first.to_owned(), remainder.to_owned())
                }
            }
            Some(_) => (DEFAULT_REGISTRY.to_owned(), name_part.to_owned()),
            None => (DEFAULT_REGISTRY.to_owned(), format!("library/{name_part}")),
        };

        validate_repository(raw, &repository)?;

        Ok(Self {
            registry,
            repository,
            selector,
            insecure_http,
        })
    }

    /// Force plain HTTP (`true`) or HTTPS (`false`) for this reference.
    #[must_use]
    pub const fn with_insecure_http(mut self, insecure: bool) -> Self {
        self.insecure_http = insecure;
        self
    }

    /// Base registry URL (`http://host` or `https://host`).
    #[must_use]
    pub fn base_url(&self) -> String {
        let scheme = if self.insecure_http { "http" } else { "https" };
        format!("{scheme}://{}", self.registry)
    }

    /// URL for fetching this reference's manifest or manifest index.
    #[must_use]
    pub fn manifest_url(&self) -> String {
        format!(
            "{}/v2/{}/manifests/{}",
            self.base_url(),
            self.repository,
            self.selector.manifest_ref()
        )
    }

    /// URL for fetching a specific manifest digest in this repository.
    #[must_use]
    pub fn manifest_digest_url(&self, digest: &Digest) -> String {
        format!(
            "{}/v2/{}/manifests/{}",
            self.base_url(),
            self.repository,
            digest
        )
    }

    /// URL for fetching a blob by digest in this repository.
    #[must_use]
    pub fn blob_url(&self, digest: &Digest) -> String {
        format!(
            "{}/v2/{}/blobs/{}",
            self.base_url(),
            self.repository,
            digest
        )
    }

    /// Canonical string form `<registry>/<repository>[:tag|@digest]`.
    #[must_use]
    pub fn canonical(&self) -> String {
        match &self.selector {
            ReferenceSelector::Tag(tag) => format!("{}/{}:{tag}", self.registry, self.repository),
            ReferenceSelector::Digest(digest) => {
                format!("{}/{}@{digest}", self.registry, self.repository)
            }
        }
    }

    /// Filesystem-safe cache filename stem derived from the canonical reference.
    #[must_use]
    pub fn storage_key(&self) -> String {
        let digest = Digest::sha256(self.canonical().as_bytes());
        digest.hex().to_owned()
    }
}

impl fmt::Display for ImageReference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.canonical())
    }
}

fn strip_tag_suffix(name: &str) -> &str {
    let last_slash = name.rfind('/');
    let last_colon = name.rfind(':');
    match (last_slash, last_colon) {
        (Some(s), Some(c)) if c > s => &name[..c],
        (None, Some(c)) => &name[..c],
        _ => name,
    }
}

fn validate_tag(raw: &str, tag: &str) -> Result<()> {
    if tag.is_empty() || tag.len() > 128 {
        return Err(OciError::InvalidReference {
            reference: raw.to_owned(),
            reason: "tag must be 1..=128 characters",
        });
    }
    if tag.starts_with('.') || tag.starts_with('-') {
        return Err(OciError::InvalidReference {
            reference: raw.to_owned(),
            reason: "tag must not start with '.' or '-'",
        });
    }
    if !tag
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
    {
        return Err(OciError::InvalidReference {
            reference: raw.to_owned(),
            reason: "tag contains invalid characters",
        });
    }
    Ok(())
}

fn validate_repository(raw: &str, repo: &str) -> Result<()> {
    if repo.is_empty() || repo.starts_with('/') || repo.ends_with('/') {
        return Err(OciError::InvalidReference {
            reference: raw.to_owned(),
            reason: "repository path is empty or has leading/trailing slash",
        });
    }
    for segment in repo.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err(OciError::InvalidReference {
                reference: raw.to_owned(),
                reason: "repository path contains invalid segment",
            });
        }
        if !segment.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
        }) {
            return Err(OciError::InvalidReference {
                reference: raw.to_owned(),
                reason: "repository segment must be lowercase ASCII alphanumeric or [._-]",
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_standard_and_local_image_references() {
        let alpine = ImageReference::parse("alpine").unwrap();
        assert_eq!(alpine.registry, DEFAULT_REGISTRY);
        assert_eq!(alpine.repository, "library/alpine");
        assert_eq!(alpine.selector, ReferenceSelector::Tag("latest".to_owned()));
        assert!(!alpine.insecure_http);

        let ubuntu = ImageReference::parse("docker.io/ubuntu:24.04").unwrap();
        assert_eq!(ubuntu.registry, DEFAULT_REGISTRY);
        assert_eq!(ubuntu.repository, "library/ubuntu");
        assert_eq!(ubuntu.selector, ReferenceSelector::Tag("24.04".to_owned()));

        let ghcr = ImageReference::parse("ghcr.io/lexoliu/helios-demo:v1.2").unwrap();
        assert_eq!(ghcr.registry, "ghcr.io");
        assert_eq!(ghcr.repository, "lexoliu/helios-demo");
        assert_eq!(ghcr.selector, ReferenceSelector::Tag("v1.2".to_owned()));

        let local = ImageReference::parse("http://127.0.0.1:5000/test/app:dev").unwrap();
        assert_eq!(local.registry, "127.0.0.1:5000");
        assert_eq!(local.repository, "test/app");
        assert!(local.insecure_http);
        assert_eq!(
            local.manifest_url(),
            "http://127.0.0.1:5000/v2/test/app/manifests/dev"
        );

        let digest_hex = "a".repeat(64);
        let pinned = ImageReference::parse(&format!(
            "localhost:5000/my-svc:ignored@sha256:{digest_hex}"
        ))
        .unwrap();
        assert_eq!(pinned.registry, "localhost:5000");
        assert_eq!(pinned.repository, "my-svc");
        assert_eq!(
            pinned.selector,
            ReferenceSelector::Digest(Digest::parse(&format!("sha256:{digest_hex}")).unwrap())
        );
    }

    #[test]
    fn computes_oci_chain_id() {
        let d0 = Digest::sha256(b"layer-0");
        let d1 = Digest::sha256(b"layer-1");
        let c0 = Digest::chain_id(None, &d0);
        assert_eq!(c0, d0);
        let c1 = Digest::chain_id(Some(&c0), &d1);
        let expected = Digest::sha256(format!("{c0} {d1}").as_bytes());
        assert_eq!(c1, expected);
    }
}
