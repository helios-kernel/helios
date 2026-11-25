//! OCI Distribution Spec `WWW-Authenticate` challenge parsing and Bearer/Basic auth.

use std::collections::BTreeMap;

use base64::Engine as _;
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use serde::Deserialize;

use crate::error::{OciError, Result};

/// Registry credentials configured by the caller.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum RegistryAuth {
    /// Anonymous access (still supports anonymous Bearer token exchange on registries like Docker Hub/GHCR).
    #[default]
    Anonymous,
    /// HTTP Basic credentials (`username` / `password`), used either directly for `Basic`
    /// challenges or to authenticate against a `Bearer` token endpoint.
    Basic { username: String, password: String },
    /// Pre-issued Bearer token.
    Bearer(String),
}

impl RegistryAuth {
    /// Encode `Basic <base64(user:pass)>` header value when credentials are [`Self::Basic`].
    #[must_use]
    pub fn basic_header_value(&self) -> Option<String> {
        match self {
            Self::Basic { username, password } => {
                let raw = format!("{username}:{password}");
                let encoded = base64::engine::general_purpose::STANDARD.encode(raw.as_bytes());
                Some(format!("Basic {encoded}"))
            }
            _ => None,
        }
    }
}

/// Parsed HTTP `WWW-Authenticate` challenge.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthChallenge {
    Bearer(BearerChallenge),
    Basic { realm: Option<String> },
}

/// Parameters of a `WWW-Authenticate: Bearer ...` challenge.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BearerChallenge {
    pub realm: String,
    pub service: Option<String>,
    pub scope: Option<String>,
}

impl BearerChallenge {
    /// Construct the token endpoint URL with percent-encoded `service` and `scope` query params.
    #[must_use]
    pub fn token_url(&self) -> String {
        let mut url = self.realm.clone();
        let mut sep = if url.contains('?') { '&' } else { '?' };
        if let Some(service) = &self.service {
            let enc = utf8_percent_encode(service, NON_ALPHANUMERIC);
            url.push(sep);
            url.push_str("service=");
            url.push_str(&enc.to_string());
            sep = '&';
        }
        if let Some(scope) = &self.scope {
            let enc = utf8_percent_encode(scope, NON_ALPHANUMERIC);
            url.push(sep);
            url.push_str("scope=");
            url.push_str(&enc.to_string());
        }
        url
    }
}

/// JSON body returned by an OCI/Docker Bearer token service.
#[derive(Debug, Deserialize)]
pub(crate) struct TokenResponse {
    #[serde(default)]
    pub token: Option<String>,
    #[serde(default)]
    pub access_token: Option<String>,
}

impl TokenResponse {
    pub(crate) fn extract_token(self, url: &str) -> Result<String> {
        self.token
            .filter(|t| !t.is_empty())
            .or_else(|| self.access_token.filter(|t| !t.is_empty()))
            .ok_or_else(|| OciError::Auth {
                url: url.to_owned(),
                detail: "token response contained neither `token` nor `access_token`".to_owned(),
            })
    }
}

/// Parse an HTTP `WWW-Authenticate` header value into a typed [`AuthChallenge`].
///
/// Supports `Bearer realm="...",service="...",scope="..."` and `Basic realm="..."`
/// (case-insensitive scheme and parameter names, RFC 7235 quoted-string escaping).
pub fn parse_www_authenticate(header: &str, request_url: &str) -> Result<AuthChallenge> {
    let trimmed = header.trim();
    if trimmed.is_empty() {
        return Err(OciError::Auth {
            url: request_url.to_owned(),
            detail: "empty WWW-Authenticate header".to_owned(),
        });
    }

    let (scheme, rest) = match trimmed.find(|c: char| c.is_ascii_whitespace()) {
        Some(idx) => (&trimmed[..idx], trimmed[idx..].trim_start()),
        None => (trimmed, ""),
    };

    let params = parse_auth_params(rest, request_url)?;
    if scheme.eq_ignore_ascii_case("bearer") {
        let realm = params
            .get("realm")
            .cloned()
            .filter(|r| !r.is_empty())
            .ok_or_else(|| OciError::Auth {
                url: request_url.to_owned(),
                detail: "Bearer challenge missing required `realm` parameter".to_owned(),
            })?;
        Ok(AuthChallenge::Bearer(BearerChallenge {
            realm,
            service: params.get("service").cloned().filter(|s| !s.is_empty()),
            scope: params.get("scope").cloned().filter(|s| !s.is_empty()),
        }))
    } else if scheme.eq_ignore_ascii_case("basic") {
        Ok(AuthChallenge::Basic {
            realm: params.get("realm").cloned(),
        })
    } else {
        Err(OciError::Auth {
            url: request_url.to_owned(),
            detail: format!("unsupported WWW-Authenticate scheme `{scheme}`"),
        })
    }
}

fn parse_auth_params(input: &str, request_url: &str) -> Result<BTreeMap<String, String>> {
    let mut map = BTreeMap::new();
    let bytes = input.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        while i < bytes.len() && (bytes[i].is_ascii_whitespace() || bytes[i] == b',') {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        let key_start = i;
        while i < bytes.len() && bytes[i] != b'=' && !bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        let key = input[key_start..i].to_ascii_lowercase();
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() || bytes[i] != b'=' {
            return Err(OciError::Auth {
                url: request_url.to_owned(),
                detail: format!("malformed WWW-Authenticate parameter `{key}`"),
            });
        }
        i += 1; // skip '='
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() {
            return Err(OciError::Auth {
                url: request_url.to_owned(),
                detail: format!("missing value for WWW-Authenticate parameter `{key}`"),
            });
        }
        let value = if bytes[i] == b'"' {
            i += 1;
            let mut out = String::new();
            let mut closed = false;
            while i < bytes.len() {
                if bytes[i] == b'\\' && i + 1 < bytes.len() {
                    out.push(bytes[i + 1] as char);
                    i += 2;
                } else if bytes[i] == b'"' {
                    i += 1;
                    closed = true;
                    break;
                } else {
                    let ch = input[i..].chars().next().ok_or_else(|| OciError::Auth {
                        url: request_url.to_owned(),
                        detail: "unterminated quoted string in WWW-Authenticate".to_owned(),
                    })?;
                    out.push(ch);
                    i += ch.len_utf8();
                }
            }
            if !closed {
                return Err(OciError::Auth {
                    url: request_url.to_owned(),
                    detail: "unterminated quoted string in WWW-Authenticate".to_owned(),
                });
            }
            out
        } else {
            let val_start = i;
            while i < bytes.len() && bytes[i] != b',' && !bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            input[val_start..i].to_owned()
        };
        map.insert(key, value);
    }

    Ok(map)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_bearer_and_basic_challenges() {
        let bearer = parse_www_authenticate(
            r#"Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/alpine:pull""#,
            "https://registry-1.docker.io/v2/",
        )
        .unwrap();
        assert_eq!(
            bearer,
            AuthChallenge::Bearer(BearerChallenge {
                realm: "https://auth.docker.io/token".to_owned(),
                service: Some("registry.docker.io".to_owned()),
                scope: Some("repository:library/alpine:pull".to_owned()),
            })
        );
        if let AuthChallenge::Bearer(b) = bearer {
            assert_eq!(
                b.token_url(),
                "https://auth.docker.io/token?service=registry%2Edocker%2Eio&scope=repository%3Alibrary%2Falpine%3Apull"
            );
        }

        let basic = parse_www_authenticate(
            r#"Basic realm="Helios Registry""#,
            "http://127.0.0.1:5000/v2/",
        )
        .unwrap();
        assert_eq!(
            basic,
            AuthChallenge::Basic {
                realm: Some("Helios Registry".to_owned())
            }
        );
    }
}
