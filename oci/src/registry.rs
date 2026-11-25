//! Async OCI Distribution Spec v2 HTTP client over [`zenwave`].
//!
//! Zero `block_on`: compiles cleanly for both `wasm32-wasip3` (`wasi-backend`) and
//! host `std` (`hyper-rustls`), verifying SHA-256 digests while streaming blobs.

use std::io::Write;

use futures_lite::StreamExt as _;
use sha2::{Digest as Sha2Digest, Sha256};
use tracing::debug;
use zenwave::{Client, DefaultClient, ResponseExt as _, StatusCode, Transport};

use crate::auth::{AuthChallenge, RegistryAuth, TokenResponse, parse_www_authenticate};
use crate::error::{OciError, Result};
use crate::reference::{Digest, ImageReference, ReferenceSelector};
use crate::spec::{Arch, Descriptor, ImageConfig, ImageManifest, ManifestDocument, media_type};

/// Manifest resolved for a target Linux [`Arch`], along with its verified SHA-256 digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedManifest {
    pub digest: Digest,
    pub manifest: ImageManifest,
    pub arch: Arch,
}

/// Async OCI Distribution Spec registry client backed by [`zenwave`].
pub struct RegistryClient<C: Client = DefaultClient> {
    client: C,
    auth: RegistryAuth,
    cached_bearer: Option<String>,
}

impl RegistryClient<DefaultClient> {
    /// Construct a registry client using [`zenwave::DefaultClient`] and anonymous auth.
    #[must_use]
    pub fn new() -> Self {
        Self::with_auth(RegistryAuth::Anonymous)
    }

    /// Construct a registry client using [`zenwave::DefaultClient`] and explicit credentials.
    #[must_use]
    pub fn with_auth(auth: RegistryAuth) -> Self {
        Self::with_client(DefaultClient::new(Transport::system()), auth)
    }
}

impl Default for RegistryClient<DefaultClient> {
    fn default() -> Self {
        Self::new()
    }
}

impl<C: Client> RegistryClient<C> {
    /// Construct a registry client over a custom [`zenwave::Client`].
    #[must_use]
    pub fn with_client(client: C, auth: RegistryAuth) -> Self {
        let cached_bearer = match &auth {
            RegistryAuth::Bearer(tok) => Some(tok.clone()),
            _ => None,
        };
        Self {
            client,
            auth,
            cached_bearer,
        }
    }

    /// Fetch and resolve the [`ImageManifest`] for `reference` and `arch`.
    ///
    /// Automatically resolves multi-arch OCI Image Indexes / Docker Manifest Lists
    /// to the matching `linux/<arch>` manifest and verifies every fetched digest.
    pub async fn fetch_manifest(
        &mut self,
        reference: &ImageReference,
        arch: Arch,
    ) -> Result<ResolvedManifest> {
        let url = reference.manifest_url();
        let (content_type, bytes) = self
            .get_bytes(&url, Some(media_type::MANIFEST_ACCEPT_HEADER))
            .await?;

        let actual_digest = Digest::sha256(&bytes);
        if let ReferenceSelector::Digest(expected) = &reference.selector
            && &actual_digest != expected
        {
            return Err(OciError::DigestMismatch {
                subject: format!("manifest for `{reference}`"),
                expected: expected.as_str(),
                actual: actual_digest.as_str(),
            });
        }

        match ManifestDocument::parse(content_type.as_deref(), &bytes)? {
            ManifestDocument::Manifest(manifest) => Ok(ResolvedManifest {
                digest: actual_digest,
                manifest,
                arch,
            }),
            ManifestDocument::Index(index) => {
                let selected =
                    index
                        .select_linux(arch)
                        .ok_or_else(|| OciError::UnsupportedArchitecture {
                            reference: reference.canonical(),
                            arch: arch.oci_arch().to_owned(),
                        })?;
                let child_url = reference.manifest_digest_url(&selected.digest);
                debug!(
                    reference = %reference,
                    arch = %arch,
                    manifest_digest = %selected.digest,
                    "resolved multi-arch OCI index entry"
                );
                let (child_ct, child_bytes) = self
                    .get_bytes(&child_url, Some(media_type::MANIFEST_ACCEPT_HEADER))
                    .await?;
                let child_actual = Digest::sha256(&child_bytes);
                if child_actual != selected.digest {
                    return Err(OciError::DigestMismatch {
                        subject: format!("arch manifest `{}` for `{reference}`", selected.digest),
                        expected: selected.digest.as_str(),
                        actual: child_actual.as_str(),
                    });
                }
                match ManifestDocument::parse(child_ct.as_deref(), &child_bytes)? {
                    ManifestDocument::Manifest(manifest) => Ok(ResolvedManifest {
                        digest: child_actual,
                        manifest,
                        arch,
                    }),
                    ManifestDocument::Index(_) => Err(OciError::UnsupportedMediaType {
                        subject: "child manifest",
                        media_type: child_ct.unwrap_or_else(|| media_type::OCI_INDEX.to_owned()),
                    }),
                }
            }
        }
    }

    /// Fetch and SHA-256-verify the OCI [`ImageConfig`] blob referenced by `descriptor`.
    pub async fn fetch_config(
        &mut self,
        reference: &ImageReference,
        descriptor: &Descriptor,
    ) -> Result<ImageConfig> {
        let url = reference.blob_url(&descriptor.digest);
        let (_, bytes) = self.get_bytes(&url, None).await?;
        let actual = Digest::sha256(&bytes);
        if actual != descriptor.digest {
            return Err(OciError::DigestMismatch {
                subject: format!("image config `{}`", descriptor.digest),
                expected: descriptor.digest.as_str(),
                actual: actual.as_str(),
            });
        }
        serde_json::from_slice(&bytes).map_err(|source| OciError::Json {
            subject: "image config",
            source,
        })
    }

    /// Stream a blob from the registry into `writer` while computing and verifying its SHA-256.
    pub async fn stream_verified_blob<W: Write>(
        &mut self,
        reference: &ImageReference,
        expected_digest: &Digest,
        writer: &mut W,
    ) -> Result<u64> {
        let url = reference.blob_url(expected_digest);
        let response = self.send_authed_get(&url, None).await?;
        let mut stream = response.into_body().into_data_stream();
        let mut hasher = Sha256::new();
        let mut total = 0u64;

        while let Some(chunk_res) = stream.next().await {
            let chunk = chunk_res.map_err(|err| OciError::Http {
                method: "GET",
                url: url.clone(),
                detail: err.to_string(),
            })?;
            if !chunk.is_empty() {
                hasher.update(&chunk);
                writer.write_all(&chunk).map_err(|source| OciError::Io {
                    operation: "write streamed blob chunk",
                    path: std::path::PathBuf::from(expected_digest.as_str()),
                    source,
                })?;
                total = total.saturating_add(chunk.len() as u64);
            }
        }
        writer.flush().map_err(|source| OciError::Io {
            operation: "flush streamed blob",
            path: std::path::PathBuf::from(expected_digest.as_str()),
            source,
        })?;

        let actual = Digest::from_sha256_bytes(hasher.finalize().into());
        if &actual != expected_digest {
            return Err(OciError::DigestMismatch {
                subject: format!("blob `{expected_digest}`"),
                expected: expected_digest.as_str(),
                actual: actual.as_str(),
            });
        }
        Ok(total)
    }

    async fn get_bytes(
        &mut self,
        url: &str,
        accept: Option<&str>,
    ) -> Result<(Option<String>, Vec<u8>)> {
        let response = self.send_authed_get(url, accept).await?;
        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .map(ToOwned::to_owned);
        let bytes = response
            .into_bytes()
            .await
            .map_err(|err| OciError::Http {
                method: "GET",
                url: url.to_owned(),
                detail: err.to_string(),
            })?
            .to_vec();
        Ok((content_type, bytes))
    }

    async fn send_authed_get(
        &mut self,
        url: &str,
        accept: Option<&str>,
    ) -> Result<zenwave::Response> {
        let initial_auth = self.initial_auth_header();
        let response = self.raw_get(url, accept, initial_auth.as_deref()).await?;

        if response.status() != StatusCode::UNAUTHORIZED {
            return check_status("GET", url, response).await;
        }

        let challenge_header = response
            .headers()
            .get("www-authenticate")
            .and_then(|v| v.to_str().ok())
            .map(ToOwned::to_owned)
            .ok_or_else(|| OciError::Auth {
                url: url.to_owned(),
                detail: "HTTP 401 response missing WWW-Authenticate header".to_owned(),
            })?;

        let challenge = parse_www_authenticate(&challenge_header, url)?;
        let retry_auth = match challenge {
            AuthChallenge::Basic { .. } => {
                self.auth.basic_header_value().ok_or_else(|| OciError::Auth {
                    url: url.to_owned(),
                    detail: "registry requested Basic authentication, but no Basic credentials were supplied".to_owned(),
                })?
            }
            AuthChallenge::Bearer(bearer) => {
                let token_url = bearer.token_url();
                let token_auth = self.auth.basic_header_value();
                debug!(token_url = %token_url, "exchanging OCI Bearer token");
                let token_resp = self
                    .raw_get(&token_url, Some("application/json"), token_auth.as_deref())
                    .await?;
                let token_resp = check_status("GET", &token_url, token_resp).await?;
                let token_bytes = token_resp.into_bytes().await.map_err(|err| OciError::Http {
                    method: "GET",
                    url: token_url.clone(),
                    detail: err.to_string(),
                })?;
                let parsed: TokenResponse =
                    serde_json::from_slice(&token_bytes).map_err(|source| OciError::Json {
                        subject: "Bearer token response",
                        source,
                    })?;
                let token = parsed.extract_token(&token_url)?;
                self.cached_bearer = Some(token.clone());
                format!("Bearer {token}")
            }
        };

        let retry = self.raw_get(url, accept, Some(&retry_auth)).await?;
        check_status("GET", url, retry).await
    }

    fn initial_auth_header(&self) -> Option<String> {
        if let Some(tok) = &self.cached_bearer {
            return Some(format!("Bearer {tok}"));
        }
        self.auth.basic_header_value()
    }

    async fn raw_get(
        &mut self,
        url: &str,
        accept: Option<&str>,
        authorization: Option<&str>,
    ) -> Result<zenwave::Response> {
        let mut req = self.client.get(url).map_err(|err| OciError::Http {
            method: "GET",
            url: url.to_owned(),
            detail: err.to_string(),
        })?;
        if let Some(accept_val) = accept {
            req = req
                .header("accept", accept_val)
                .map_err(|err| OciError::Http {
                    method: "GET",
                    url: url.to_owned(),
                    detail: err.to_string(),
                })?;
        }
        if let Some(auth_val) = authorization {
            req = req
                .header("authorization", auth_val)
                .map_err(|err| OciError::Http {
                    method: "GET",
                    url: url.to_owned(),
                    detail: err.to_string(),
                })?;
        }
        req.await.map_err(|err| OciError::Http {
            method: "GET",
            url: url.to_owned(),
            detail: err.to_string(),
        })
    }
}

async fn check_status(
    method: &'static str,
    url: &str,
    response: zenwave::Response,
) -> Result<zenwave::Response> {
    let status = response.status();
    if status.is_success() {
        return Ok(response);
    }
    let code = status.as_u16();
    let body = response
        .into_bytes()
        .await
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .unwrap_or_default();
    Err(OciError::RegistryStatus {
        method,
        url: url.to_owned(),
        status: code,
        body,
    })
}
