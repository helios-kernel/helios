//! Target URIs, `targets.toml` store, operator identity, capability certificates,
//! and fine-grained capability / subtree attenuation.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use directories::ProjectDirs;
use helios_inspector_protocol::VSOCK_RPC_PORT;
use serde::{Deserialize, Serialize};

use crate::error::{AuthError, TargetError};

/// Default TCP port for `helios://` remote inspection endpoints.
pub const DEFAULT_HELIOS_PORT: u16 = 9443;

/// Default serial baud rate for `serial://` TTY transports.
pub const DEFAULT_SERIAL_BAUD: u32 = 115_200;

/// Parsed endpoint URI for a Helios node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetUri {
    /// Local serial TTY or Unix domain socket (`serial:///path/to/dev[?baud=115200]`).
    Serial { path: String, baud: u32 },
    /// Linux AF_VSOCK guest endpoint (`vsock://<cid>[:<port>]`).
    Vsock { cid: u32, port: u32 },
    /// Network endpoint (`helios://<host>[:<port>]` or `tcp://<host>[:<port>]`).
    Helios {
        host: String,
        port: u16,
        /// Whether TLS + Ed25519 `CapabilityCert` negotiation is requested (`helios://`).
        tls: bool,
    },
}

impl TargetUri {
    /// Parse a target URI string (`serial://`, `vsock://`, `helios://`, or `tcp://`).
    pub fn parse(raw: &str) -> Result<Self, TargetError> {
        let trimmed = raw.trim();
        if let Some(rest) = trimmed.strip_prefix("serial://") {
            let (path_part, query) = match rest.split_once('?') {
                Some((p, q)) => (p, Some(q)),
                None => (rest, None),
            };
            if path_part.is_empty() {
                return Err(TargetError::InvalidUri {
                    uri: raw.to_owned(),
                    reason: "serial:// URI requires a device or socket path".to_owned(),
                });
            }
            let mut baud = DEFAULT_SERIAL_BAUD;
            if let Some(q) = query {
                for pair in q.split('&').filter(|p| !p.is_empty()) {
                    if let Some((k, v)) = pair.split_once('=')
                        && k == "baud"
                    {
                        baud = v.parse::<u32>().map_err(|_| TargetError::InvalidUri {
                            uri: raw.to_owned(),
                            reason: format!("invalid baud rate `{v}`"),
                        })?;
                    }
                }
            }
            return Ok(Self::Serial {
                path: path_part.to_owned(),
                baud,
            });
        }

        if let Some(rest) = trimmed.strip_prefix("vsock://") {
            let (cid_str, port) = match rest.split_once(':') {
                Some((c, p)) => {
                    let port = p.parse::<u32>().map_err(|_| TargetError::InvalidUri {
                        uri: raw.to_owned(),
                        reason: format!("invalid vsock port `{p}`"),
                    })?;
                    (c, port)
                }
                None => (rest, VSOCK_RPC_PORT),
            };
            let cid = cid_str
                .parse::<u32>()
                .map_err(|_| TargetError::InvalidUri {
                    uri: raw.to_owned(),
                    reason: format!("invalid vsock CID `{cid_str}`"),
                })?;
            return Ok(Self::Vsock { cid, port });
        }

        if let Some(rest) = trimmed.strip_prefix("helios://") {
            return parse_host_port(raw, rest, true);
        }

        if let Some(rest) = trimmed.strip_prefix("tcp://") {
            return parse_host_port(raw, rest, false);
        }

        Err(TargetError::InvalidUri {
            uri: raw.to_owned(),
            reason: "expected scheme `helios://`, `tcp://`, `vsock://`, or `serial://`".to_owned(),
        })
    }

    /// Format this URI in canonical string form.
    #[must_use]
    pub fn to_uri_string(&self) -> String {
        match self {
            Self::Serial { path, baud } if *baud == DEFAULT_SERIAL_BAUD => {
                format!("serial://{path}")
            }
            Self::Serial { path, baud } => format!("serial://{path}?baud={baud}"),
            Self::Vsock { cid, port } if *port == VSOCK_RPC_PORT => format!("vsock://{cid}"),
            Self::Vsock { cid, port } => format!("vsock://{cid}:{port}"),
            Self::Helios { host, port, tls } => {
                let scheme = if *tls { "helios" } else { "tcp" };
                format!("{scheme}://{host}:{port}")
            }
        }
    }
}

fn parse_host_port(raw: &str, rest: &str, tls: bool) -> Result<TargetUri, TargetError> {
    let authority = rest.split('/').next().unwrap_or(rest);
    if authority.is_empty() {
        return Err(TargetError::InvalidUri {
            uri: raw.to_owned(),
            reason: "missing host".to_owned(),
        });
    }
    let (host, port) = if let Some(bracketed) = authority.strip_prefix('[') {
        let Some((ipv6, suffix)) = bracketed.split_once(']') else {
            return Err(TargetError::InvalidUri {
                uri: raw.to_owned(),
                reason: "unclosed IPv6 literal bracket".to_owned(),
            });
        };
        let port = if let Some(p) = suffix.strip_prefix(':') {
            p.parse::<u16>().map_err(|_| TargetError::InvalidUri {
                uri: raw.to_owned(),
                reason: format!("invalid TCP port `{p}`"),
            })?
        } else if suffix.is_empty() {
            DEFAULT_HELIOS_PORT
        } else {
            return Err(TargetError::InvalidUri {
                uri: raw.to_owned(),
                reason: format!("unexpected trailing authority `{suffix}`"),
            });
        };
        (ipv6.to_owned(), port)
    } else if let Some((h, p)) = authority.rsplit_once(':') {
        let port = p.parse::<u16>().map_err(|_| TargetError::InvalidUri {
            uri: raw.to_owned(),
            reason: format!("invalid TCP port `{p}`"),
        })?;
        (h.to_owned(), port)
    } else {
        (authority.to_owned(), DEFAULT_HELIOS_PORT)
    };

    if host.is_empty() {
        return Err(TargetError::InvalidUri {
            uri: raw.to_owned(),
            reason: "missing host".to_owned(),
        });
    }

    Ok(TargetUri::Helios { host, port, tls })
}

/// Named Helios target entry persisted in `targets.toml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Target {
    pub name: String,
    pub uri: String,
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_scope: Option<String>,
}

impl Target {
    /// Construct an ad-hoc target directly from a URI string.
    pub fn from_uri(uri: impl Into<String>) -> Result<Self, TargetError> {
        let uri_str = uri.into();
        let parsed = TargetUri::parse(&uri_str)?;
        Ok(Self {
            name: parsed.to_uri_string(),
            uri: parsed.to_uri_string(),
            labels: BTreeMap::new(),
            identity: None,
            default_scope: None,
        })
    }

    /// Construct a named target with a validated URI.
    pub fn new(name: impl Into<String>, uri: impl Into<String>) -> Result<Self, TargetError> {
        let uri_str = uri.into();
        let parsed = TargetUri::parse(&uri_str)?;
        Ok(Self {
            name: name.into(),
            uri: parsed.to_uri_string(),
            labels: BTreeMap::new(),
            identity: None,
            default_scope: None,
        })
    }

    /// Parse this target's URI into a typed [`TargetUri`].
    pub fn parsed_uri(&self) -> Result<TargetUri, TargetError> {
        TargetUri::parse(&self.uri)
    }

    /// Check whether this target matches every `(key, value)` label filter.
    #[must_use]
    pub fn matches_labels(&self, filters: &[(String, String)]) -> bool {
        filters
            .iter()
            .all(|(k, v)| self.labels.get(k).is_some_and(|val| val == v))
    }
}

/// On-disk schema of `targets.toml`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct TargetsFile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    default_target: Option<String>,
    #[serde(default)]
    targets: Vec<Target>,
}

/// Persistent target inventory stored in `targets.toml`.
#[derive(Debug, Clone)]
pub struct TargetStore {
    path: PathBuf,
    data: TargetsFile,
}

impl TargetStore {
    /// Default XDG configuration directory for `helios` (`targets.toml`, identities, history).
    #[must_use]
    pub fn default_config_dir() -> PathBuf {
        ProjectDirs::from("cool", "lexo", "helios").map_or_else(
            || PathBuf::from(".helios"),
            |dirs| dirs.config_dir().to_path_buf(),
        )
    }

    /// Default path to `targets.toml`.
    #[must_use]
    pub fn default_path() -> PathBuf {
        Self::default_config_dir().join("targets.toml")
    }

    /// Load `targets.toml` from `path` (returning an empty store if the file does not exist yet).
    pub fn load(path: impl Into<PathBuf>) -> Result<Self, TargetError> {
        let path = path.into();
        let data = match fs::read_to_string(&path) {
            Ok(content) => toml::from_str::<TargetsFile>(&content).map_err(|source| {
                TargetError::ParseStore {
                    path: path.clone(),
                    source,
                }
            })?,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => TargetsFile::default(),
            Err(source) => {
                return Err(TargetError::ReadStore { path, source });
            }
        };
        Ok(Self { path, data })
    }

    /// Load `targets.toml` from [`Self::default_path`].
    pub fn load_default() -> Result<Self, TargetError> {
        Self::load(Self::default_path())
    }

    /// Persist this target store atomically to disk.
    pub fn save(&self) -> Result<(), TargetError> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).map_err(|source| TargetError::WriteStore {
                path: self.path.clone(),
                source,
            })?;
        }
        let encoded = toml::to_string_pretty(&self.data)
            .map_err(|source| TargetError::SerializeStore { source })?;
        fs::write(&self.path, encoded).map_err(|source| TargetError::WriteStore {
            path: self.path.clone(),
            source,
        })
    }

    /// Path of the backing `targets.toml` file.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// All configured targets.
    #[must_use]
    pub fn list(&self) -> &[Target] {
        &self.data.targets
    }

    /// Currently active default target name, if any.
    #[must_use]
    pub fn default_target_name(&self) -> Option<&str> {
        self.data.default_target.as_deref()
    }

    /// Insert or replace a target by name. If this is the first target, it becomes default.
    pub fn upsert(&mut self, target: Target) {
        if let Some(existing) = self.data.targets.iter_mut().find(|t| t.name == target.name) {
            *existing = target;
        } else {
            let name = target.name.clone();
            self.data.targets.push(target);
            if self.data.default_target.is_none() {
                self.data.default_target = Some(name);
            }
        }
    }

    /// Mark `name` as the default target.
    pub fn set_default(&mut self, name: &str) -> Result<(), TargetError> {
        if !self.data.targets.iter().any(|t| t.name == name) {
            return Err(TargetError::NotFound {
                name: name.to_owned(),
                store_path: self.path.clone(),
            });
        }
        self.data.default_target = Some(name.to_owned());
        Ok(())
    }

    /// Remove a target by name. Clears `default_target` if it matched.
    pub fn remove(&mut self, name: &str) -> Result<Target, TargetError> {
        let Some(idx) = self.data.targets.iter().position(|t| t.name == name) else {
            return Err(TargetError::NotFound {
                name: name.to_owned(),
                store_path: self.path.clone(),
            });
        };
        let removed = self.data.targets.remove(idx);
        if self.data.default_target.as_deref() == Some(name) {
            self.data.default_target = self.data.targets.first().map(|t| t.name.clone());
        }
        Ok(removed)
    }

    /// Resolve a CLI `-t/--target` argument: either a direct URI or a stored target name,
    /// falling back to the store's default target when `spec` is `None`.
    pub fn resolve(&self, spec: Option<&str>) -> Result<Target, TargetError> {
        match spec {
            Some(raw) if raw.contains("://") => Target::from_uri(raw),
            Some(name) => self
                .data
                .targets
                .iter()
                .find(|t| t.name == name)
                .cloned()
                .ok_or_else(|| TargetError::NotFound {
                    name: name.to_owned(),
                    store_path: self.path.clone(),
                }),
            None => {
                let default_name = self.data.default_target.as_deref().ok_or_else(|| {
                    TargetError::NoDefaultTarget {
                        store_path: self.path.clone(),
                    }
                })?;
                self.data
                    .targets
                    .iter()
                    .find(|t| t.name == default_name)
                    .cloned()
                    .ok_or_else(|| TargetError::NotFound {
                        name: default_name.to_owned(),
                        store_path: self.path.clone(),
                    })
            }
        }
    }

    /// Select all targets matching every `key=value` label filter.
    pub fn select_by_labels(&self, raw_filters: &[String]) -> Result<Vec<Target>, TargetError> {
        let parsed = parse_label_filters(raw_filters)?;
        let matched: Vec<Target> = self
            .data
            .targets
            .iter()
            .filter(|target| target.matches_labels(&parsed))
            .cloned()
            .collect();
        if matched.is_empty() {
            return Err(TargetError::NoMatchingLabels {
                selector: raw_filters.join(","),
            });
        }
        Ok(matched)
    }
}

/// Parse repeatable `k=v` label filter arguments.
pub fn parse_label_filters(raw_filters: &[String]) -> Result<Vec<(String, String)>, TargetError> {
    let mut parsed = Vec::with_capacity(raw_filters.len());
    for raw in raw_filters {
        let Some((k, v)) = raw.split_once('=') else {
            return Err(TargetError::InvalidLabelFilter { raw: raw.clone() });
        };
        if k.is_empty() {
            return Err(TargetError::InvalidLabelFilter { raw: raw.clone() });
        }
        parsed.push((k.to_owned(), v.to_owned()));
    }
    Ok(parsed)
}

/// Fine-grained capability rights attenuated per session (no coarse `Role` enum).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GrantRight {
    Inspect,
    Trace,
    Profile,
    InstanceRead,
    InstanceControl,
    Exec,
    FilesystemRead,
    FilesystemWrite,
    Snapshot,
    Processors,
    Net,
    Http,
    Virtualize,
}

impl GrantRight {
    /// Parse a CLI `--only` capability name.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "inspect" => Some(Self::Inspect),
            "trace" | "tracing" => Some(Self::Trace),
            "profile" | "profiling" => Some(Self::Profile),
            "ps" | "instances" | "instance-read" => Some(Self::InstanceRead),
            "kill" | "instance-control" => Some(Self::InstanceControl),
            "exec" | "spawn" | "programs" => Some(Self::Exec),
            "fs-read" | "filesystem-read" | "read" => Some(Self::FilesystemRead),
            "fs-write" | "filesystem-write" | "write" => Some(Self::FilesystemWrite),
            "snapshot" => Some(Self::Snapshot),
            "processors" | "cpu" => Some(Self::Processors),
            "net" | "network" => Some(Self::Net),
            "http" => Some(Self::Http),
            "virtualize" | "vm" => Some(Self::Virtualize),
            _ => None,
        }
    }

    /// Canonical kebab-case capability name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Inspect => "inspect",
            Self::Trace => "trace",
            Self::Profile => "profile",
            Self::InstanceRead => "instance-read",
            Self::InstanceControl => "instance-control",
            Self::Exec => "exec",
            Self::FilesystemRead => "filesystem-read",
            Self::FilesystemWrite => "filesystem-write",
            Self::Snapshot => "snapshot",
            Self::Processors => "processors",
            Self::Net => "net",
            Self::Http => "http",
            Self::Virtualize => "virtualize",
        }
    }
}

/// Structured capability grants attached to an attenuated session or child launch.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Grants {
    /// Explicit set of allowed rights. When empty, inherits the certificate/session ceiling.
    pub rights: BTreeSet<GrantRight>,
    /// Explicit granted VFS directory prefixes (e.g. `"/etc"`, `"/tmp"`).
    pub directories: Vec<String>,
}

/// Per-session capability and subtree scope attenuation (`--scope`, `--only`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attenuation {
    /// Moniker subtree prefix (e.g. `"/core/http"`). `None` means machine root `"/"`.
    pub scope: Option<String>,
    /// Optional explicit capability ceiling narrowing the session's certificate rights.
    pub only: BTreeSet<GrantRight>,
}

impl Attenuation {
    /// Returns `true` if `right` is permitted under this attenuation.
    #[must_use]
    pub fn allows(&self, right: GrantRight) -> bool {
        self.only.is_empty() || self.only.contains(&right)
    }

    /// Effective scope moniker string.
    #[must_use]
    pub fn effective_scope(&self) -> &str {
        self.scope.as_deref().unwrap_or("/")
    }
}

/// Ed25519-backed capability certificate exchanged via `helios login` and presented
/// during the #1190 TLS+Ed25519 handshake on `helios://` connections.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityCert {
    pub principal: String,
    pub issuer: String,
    pub public_key_hex: String,
    pub scope: String,
    pub rights: Vec<GrantRight>,
    pub expires_at_unix: u64,
    pub signature_hex: String,
}

/// Persisted operator identity profile (`~/.config/helios/identities/<name>.toml`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityProfile {
    pub name: String,
    pub principal: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert: Option<CapabilityCert>,
}

impl IdentityProfile {
    /// Default path for the named identity profile.
    #[must_use]
    pub fn path_for(name: &str) -> PathBuf {
        TargetStore::default_config_dir()
            .join("identities")
            .join(format!("{name}.toml"))
    }

    /// Load an identity profile from a file path or profile name.
    pub fn load(name_or_path: &str) -> Result<Self, AuthError> {
        let path = if Path::new(name_or_path).exists() {
            PathBuf::from(name_or_path)
        } else {
            Self::path_for(name_or_path)
        };
        let content = fs::read_to_string(&path).map_err(|source| AuthError::ReadIdentity {
            path: path.clone(),
            source,
        })?;
        toml::from_str(&content).map_err(|source| AuthError::ParseIdentity { path, source })
    }

    /// Persist this identity profile to disk.
    pub fn save(&self) -> Result<PathBuf, AuthError> {
        let path = Self::path_for(&self.name);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|source| AuthError::WriteIdentity {
                path: path.clone(),
                source,
            })?;
        }
        let encoded = toml::to_string_pretty(self)
            .map_err(|source| AuthError::SerializeIdentity { source })?;
        fs::write(&path, encoded).map_err(|source| AuthError::WriteIdentity {
            path: path.clone(),
            source,
        })?;
        Ok(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn parses_all_target_uri_schemes() {
        assert_eq!(
            TargetUri::parse("serial:///tmp/helios.sock").expect("serial uri"),
            TargetUri::Serial {
                path: "/tmp/helios.sock".to_owned(),
                baud: DEFAULT_SERIAL_BAUD,
            }
        );
        assert_eq!(
            TargetUri::parse("serial:///dev/ttyUSB0?baud=921600").expect("serial baud uri"),
            TargetUri::Serial {
                path: "/dev/ttyUSB0".to_owned(),
                baud: 921600,
            }
        );
        assert_eq!(
            TargetUri::parse("vsock://42").expect("vsock default port"),
            TargetUri::Vsock {
                cid: 42,
                port: VSOCK_RPC_PORT,
            }
        );
        assert_eq!(
            TargetUri::parse("vsock://7:2048").expect("vsock custom port"),
            TargetUri::Vsock { cid: 7, port: 2048 }
        );
        assert_eq!(
            TargetUri::parse("helios://node1.internal").expect("helios default port"),
            TargetUri::Helios {
                host: "node1.internal".to_owned(),
                port: DEFAULT_HELIOS_PORT,
                tls: true,
            }
        );
        assert_eq!(
            TargetUri::parse("tcp://127.0.0.1:9500").expect("tcp port"),
            TargetUri::Helios {
                host: "127.0.0.1".to_owned(),
                port: 9500,
                tls: false,
            }
        );
    }

    #[test]
    fn target_store_round_trip_and_label_selection() {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("targets.toml");
        let mut store = TargetStore::load(&path).expect("empty load");

        let mut t1 = Target::new("prod-1", "helios://10.0.0.1:9443").expect("t1");
        t1.labels.insert("env".to_owned(), "prod".to_owned());
        t1.labels.insert("rack".to_owned(), "a".to_owned());
        store.upsert(t1);

        let mut t2 = Target::new("staging-1", "tcp://10.0.1.2:9443").expect("t2");
        t2.labels.insert("env".to_owned(), "staging".to_owned());
        store.upsert(t2);

        store.set_default("staging-1").expect("set default");
        store.save().expect("save");

        let reloaded = TargetStore::load(&path).expect("reload");
        assert_eq!(reloaded.default_target_name(), Some("staging-1"));
        assert_eq!(reloaded.resolve(None).expect("default").name, "staging-1");
        assert_eq!(
            reloaded.resolve(Some("prod-1")).expect("named").name,
            "prod-1"
        );
        let prod = reloaded
            .select_by_labels(&["env=prod".to_owned()])
            .expect("label match");
        assert_eq!(prod.len(), 1);
        assert_eq!(prod[0].name, "prod-1");
    }
}
