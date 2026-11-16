//! A content-addressed cache of the artifacts `wasm-build` and
//! `kernel-prebuild` produce, so a run takes what an earlier run already
//! built instead of building it again (#1022).
//!
//! Two kinds of entry live in one flat directory, each one file named by the
//! digest of what determines it:
//!
//! - `wasm-<digest>`: a guest `.wasm` that cargo built. Its lookup key is the
//!   digest of the build's own description (manifest, profile, target,
//!   build environment, toolchain, lockfile), the way sccache's direct mode
//!   keys a compilation. The entry also lists the files the build read,
//!   each with its digest, because the build description does not say what
//!   the sources contain: the ones cargo's dep-info named for the artifact,
//!   and every file of every workspace package the program depends on,
//!   which also covers what a build script reads. A lookup is a hit only
//!   when every listed file is still there and still hashes the same.
//! - `cwasm-<digest>`: the bytes `precompile_artifact` returned. Its key
//!   covers the input component, the running executable (which carries the
//!   compiler), the target level and the compile hint, so it needs no file
//!   list.
//!
//! A hit sets the entry's modification time to now, and so does a store.
//! [`prune`] deletes the entries untouched since a cutoff, which a job
//! takes before it starts, so the cache it saves holds what that job used
//! and does not grow with every revision. The modification time is the
//! only record of use, so it works across the processes of one job.

use std::collections::BTreeSet;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::SystemTime;

use helios_artifact::CwasmTarget;
use helios_compiler_support::{AotCompileHint, CompileError, precompile_artifact};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;
use walkdir::WalkDir;

/// Prefix of the file a store is written to before it is renamed into
/// place; a name that never matches an entry.
const TEMP_PREFIX: &str = ".tmp-";
/// Width of the manifest length every entry file starts with.
const LENGTH_BYTES: usize = size_of::<u64>();

/// Why a cache could not be read, written or pruned.
#[derive(Debug, thiserror::Error)]
pub enum CacheError {
    #[error("failed to create the artifact cache directory {path}: {source}")]
    CreateDir {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("failed to read {path}: {source}")]
    Read {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("failed to write the cache entry {path}: {source}")]
    Write {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("failed to remove {path}: {source}")]
    Remove {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("failed to resolve {path}: {source}")]
    Resolve {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("failed to find the running helios-cli executable: {source}")]
    CurrentExecutable {
        #[source]
        source: io::Error,
    },
    #[error("the cache entry {path} is cut short: {reason}")]
    Truncated { path: String, reason: &'static str },
    #[error("the cache entry {path} holds a payload that does not match its recorded digest")]
    PayloadMismatch { path: String },
    #[error("the cache entry {path} has an unreadable manifest: {source}")]
    DecodeManifest {
        path: String,
        #[source]
        source: serde_json::Error,
    },
    #[error("failed to encode the manifest of the cache entry {path}: {source}")]
    EncodeManifest {
        path: String,
        #[source]
        source: serde_json::Error,
    },
    #[error("the dep-info file {path} is not a make rule: {reason}")]
    MalformedDepInfo { path: String, reason: &'static str },
    #[error("the dep-info file {path} names the relative path {dependency}")]
    RelativeDependency { path: String, dependency: String },
    #[error("failed to set the modification time of {path}: {source}")]
    Touch {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("failed to list the files of {path}: {source}")]
    Walk {
        path: String,
        #[source]
        source: walkdir::Error,
    },
    #[error("failed to run `cargo metadata` for {manifest}: {source}")]
    SpawnMetadata {
        manifest: String,
        #[source]
        source: io::Error,
    },
    #[error("`cargo metadata` for {manifest} failed with status {status}: {stderr}")]
    MetadataFailed {
        manifest: String,
        status: ExitStatus,
        stderr: String,
    },
    #[error("the `cargo metadata` output for {manifest} is not the expected JSON: {source}")]
    DecodeMetadata {
        manifest: String,
        #[source]
        source: serde_json::Error,
    },
    #[error(
        "`cargo metadata` for {manifest} resolved no root package, or a package it names is missing"
    )]
    MetadataShape { manifest: String },
}

/// Why a precompile through the cache did not produce bytes.
#[derive(Debug, thiserror::Error)]
pub enum PrecompileError {
    #[error("{0}")]
    Compile(#[from] CompileError),
    #[error("{0}")]
    Cache(#[from] CacheError),
}

/// Which family of entry a key addresses; it names the entry's file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryKind {
    Wasm,
    Cwasm,
}

impl EntryKind {
    const fn prefix(self) -> &'static str {
        match self {
            Self::Wasm => "wasm",
            Self::Cwasm => "cwasm",
        }
    }
}

/// The digest an entry is stored under.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Key {
    file_name: String,
}

/// Hashes the fields that determine an entry into its [`Key`].
///
/// Every field is length-prefixed, so two different field lists never hash
/// the same bytes.
pub struct KeyBuilder {
    kind: EntryKind,
    digest: Sha256,
}

impl KeyBuilder {
    pub fn new(kind: EntryKind) -> Self {
        Self {
            kind,
            digest: Sha256::new(),
        }
    }

    #[must_use]
    pub fn field(mut self, bytes: impl AsRef<[u8]>) -> Self {
        let bytes = bytes.as_ref();
        self.digest.update((bytes.len() as u64).to_le_bytes());
        self.digest.update(bytes);
        self
    }

    pub fn finish(self) -> Key {
        Key {
            file_name: format!("{}-{:x}", self.kind.prefix(), self.digest.finalize()),
        }
    }
}

/// How many lookups this process answered from the cache and how many it
/// did not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CacheStats {
    pub hits: usize,
    pub misses: usize,
}

impl std::fmt::Display for CacheStats {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{} hits, {} misses", self.hits, self.misses)
    }
}

/// One source file an entry was built from, and what it contained.
#[derive(Debug, Serialize, Deserialize)]
struct InputDigest {
    /// Relative to the workspace root.
    path: PathBuf,
    sha256: String,
}

/// The part of an entry file that describes its payload.
#[derive(Debug, Serialize, Deserialize)]
struct Manifest {
    inputs: Vec<InputDigest>,
    payload_len: u64,
    payload_sha256: String,
}

/// A directory of cache entries, shared by the threads of one process.
pub struct ArtifactCache {
    dir: PathBuf,
    hits: AtomicUsize,
    misses: AtomicUsize,
}

impl ArtifactCache {
    /// Opens the cache at `dir`, creating the directory when it is not
    /// there yet.
    pub fn open(dir: &Path) -> Result<Self, CacheError> {
        fs::create_dir_all(dir).map_err(|source| CacheError::CreateDir {
            path: dir.display().to_string(),
            source,
        })?;
        Ok(Self {
            dir: dir.to_path_buf(),
            hits: AtomicUsize::new(0),
            misses: AtomicUsize::new(0),
        })
    }

    pub fn stats(&self) -> CacheStats {
        CacheStats {
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
        }
    }

    /// The payload stored under `key` when every source file the entry
    /// lists, resolved against `workspace_root`, still exists and hashes
    /// as it did when the entry was stored.
    pub fn lookup_wasm(
        &self,
        key: &Key,
        workspace_root: &Path,
    ) -> Result<Option<Vec<u8>>, CacheError> {
        let Some((manifest, payload)) = self.read_entry(key)? else {
            return Ok(self.miss());
        };
        for input in &manifest.inputs {
            let path = workspace_root.join(&input.path);
            match fs::read(&path) {
                Ok(bytes) if sha256_hex(&bytes) == input.sha256 => {}
                Ok(_) => return Ok(self.miss()),
                Err(source) if source.kind() == io::ErrorKind::NotFound => {
                    return Ok(self.miss());
                }
                Err(source) => {
                    return Err(CacheError::Read {
                        path: path.display().to_string(),
                        source,
                    });
                }
            }
        }
        self.hit(key, payload).map(Some)
    }

    /// Stores a built wasm under `key` with the workspace-relative source
    /// files it was built from, as [`workspace_inputs`] lists them.
    pub fn store_wasm(
        &self,
        key: &Key,
        workspace_root: &Path,
        inputs: &[PathBuf],
        wasm: &[u8],
    ) -> Result<(), CacheError> {
        let mut digests = Vec::with_capacity(inputs.len());
        for input in inputs {
            let path = workspace_root.join(input);
            let bytes = fs::read(&path).map_err(|source| CacheError::Read {
                path: path.display().to_string(),
                source,
            })?;
            digests.push(InputDigest {
                path: input.clone(),
                sha256: sha256_hex(&bytes),
            });
        }
        self.write_entry(key, digests, wasm)
    }

    /// The payload stored under `key`, for an entry the key alone
    /// determines.
    pub fn lookup_payload(&self, key: &Key) -> Result<Option<Vec<u8>>, CacheError> {
        match self.read_entry(key)? {
            Some((_, payload)) => self.hit(key, payload).map(Some),
            None => Ok(self.miss()),
        }
    }

    pub fn store_payload(&self, key: &Key, payload: &[u8]) -> Result<(), CacheError> {
        self.write_entry(key, Vec::new(), payload)
    }

    /// Counts a hit and marks the entry used by setting its modification
    /// time to now.
    fn hit(&self, key: &Key, payload: Vec<u8>) -> Result<Vec<u8>, CacheError> {
        let path = self.dir.join(&key.file_name);
        fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .and_then(|file| file.set_modified(SystemTime::now()))
            .map_err(|source| CacheError::Touch {
                path: path.display().to_string(),
                source,
            })?;
        self.hits.fetch_add(1, Ordering::Relaxed);
        Ok(payload)
    }

    fn miss<T>(&self) -> Option<T> {
        self.misses.fetch_add(1, Ordering::Relaxed);
        None
    }

    fn read_entry(&self, key: &Key) -> Result<Option<(Manifest, Vec<u8>)>, CacheError> {
        let path = self.dir.join(&key.file_name);
        let display = || path.display().to_string();
        let mut bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(source) => {
                return Err(CacheError::Read {
                    path: display(),
                    source,
                });
            }
        };
        let length = bytes
            .first_chunk::<LENGTH_BYTES>()
            .map(|length| u64::from_le_bytes(*length))
            .ok_or_else(|| CacheError::Truncated {
                path: display(),
                reason: "no manifest length",
            })?;
        let payload_start = usize::try_from(length)
            .ok()
            .and_then(|length| length.checked_add(LENGTH_BYTES))
            .filter(|end| *end <= bytes.len())
            .ok_or_else(|| CacheError::Truncated {
                path: display(),
                reason: "the manifest runs past the end of the file",
            })?;
        let manifest: Manifest = serde_json::from_slice(&bytes[LENGTH_BYTES..payload_start])
            .map_err(|source| CacheError::DecodeManifest {
                path: display(),
                source,
            })?;
        bytes.drain(..payload_start);
        if bytes.len() as u64 != manifest.payload_len {
            return Err(CacheError::Truncated {
                path: display(),
                reason: "the payload is not the recorded length",
            });
        }
        if sha256_hex(&bytes) != manifest.payload_sha256 {
            return Err(CacheError::PayloadMismatch { path: display() });
        }
        Ok(Some((manifest, bytes)))
    }

    /// Writes the entry to a temporary file beside it and renames that
    /// into place, so no reader ever sees a half-written entry and two
    /// processes storing one key leave one complete file.
    fn write_entry(
        &self,
        key: &Key,
        inputs: Vec<InputDigest>,
        payload: &[u8],
    ) -> Result<(), CacheError> {
        let path = self.dir.join(&key.file_name);
        let write_error = |source| CacheError::Write {
            path: path.display().to_string(),
            source,
        };
        let manifest = serde_json::to_vec(&Manifest {
            inputs,
            payload_len: payload.len() as u64,
            payload_sha256: sha256_hex(payload),
        })
        .map_err(|source| CacheError::EncodeManifest {
            path: path.display().to_string(),
            source,
        })?;
        let mut file =
            NamedTempFile::with_prefix_in(TEMP_PREFIX, &self.dir).map_err(write_error)?;
        file.write_all(&(manifest.len() as u64).to_le_bytes())
            .and_then(|()| file.write_all(&manifest))
            .and_then(|()| file.write_all(payload))
            .map_err(write_error)?;
        // The file is new, so its modification time is now: stored is used.
        file.persist(&path)
            .map_err(|error| write_error(error.error))?;
        Ok(())
    }
}

/// Deletes the entries of the cache at `dir` that were last hit or stored
/// before `older_than`, and any store a killed process left half-written
/// before then. Returns how many files it removed.
///
/// A file in `dir` that is not an entry is left alone.
pub fn prune(dir: &Path, older_than: SystemTime) -> Result<usize, CacheError> {
    let read_error = |path: &Path, source| CacheError::Read {
        path: path.display().to_string(),
        source,
    };
    let mut removed = 0;
    for entry in fs::read_dir(dir).map_err(|source| read_error(dir, source))? {
        let entry = entry.map_err(|source| read_error(dir, source))?;
        let path = entry.path();
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let is_entry = [EntryKind::Wasm, EntryKind::Cwasm]
            .iter()
            .any(|kind| name.starts_with(&format!("{}-", kind.prefix())));
        if !is_entry && !name.starts_with(TEMP_PREFIX) {
            continue;
        }
        let modified = entry
            .metadata()
            .and_then(|metadata| metadata.modified())
            .map_err(|source| read_error(&path, source))?;
        if modified < older_than {
            fs::remove_file(&path).map_err(|source| CacheError::Remove {
                path: path.display().to_string(),
                source,
            })?;
            removed += 1;
        }
    }
    Ok(removed)
}

/// The files a wasm entry depends on, relative to `workspace_root` and
/// sorted: the source files cargo's dep-info `dep_info` names, every file of
/// every package in `package_dirs`, and the root manifest.
///
/// Files outside the workspace (registry and git checkouts, the sysroot)
/// are left out because the lockfile and the toolchain are part of the
/// entry's key; so is everything under `excluded`, the target directory the
/// build writes into, and every `target` directory of a package. The
/// packages add what dep-info does not list but a build reads: manifests,
/// which hold the features and dependencies, and whatever a build script
/// takes in.
pub fn workspace_inputs(
    dep_info: &Path,
    workspace_root: &Path,
    excluded: &Path,
    package_dirs: &[PathBuf],
) -> Result<Vec<PathBuf>, CacheError> {
    let text = fs::read_to_string(dep_info).map_err(|source| CacheError::Read {
        path: dep_info.display().to_string(),
        source,
    })?;
    let mut inputs = BTreeSet::from([PathBuf::from(MANIFEST)]);
    for dependency in parse_dep_info(dep_info, &text)? {
        let dependency_path = Path::new(&dependency);
        if !dependency_path.is_absolute() {
            return Err(CacheError::RelativeDependency {
                path: dep_info.display().to_string(),
                dependency,
            });
        }
        let resolved = fs::canonicalize(dependency_path).map_err(|source| CacheError::Resolve {
            path: dependency.clone(),
            source,
        })?;
        if resolved.starts_with(excluded) {
            continue;
        }
        if let Ok(relative) = resolved.strip_prefix(workspace_root) {
            inputs.insert(relative.to_path_buf());
        }
    }
    for package_dir in package_dirs {
        let resolved = fs::canonicalize(package_dir).map_err(|source| CacheError::Resolve {
            path: package_dir.display().to_string(),
            source,
        })?;
        if !resolved.starts_with(workspace_root) {
            continue;
        }
        let files = WalkDir::new(&resolved)
            .into_iter()
            .filter_entry(|entry| entry.depth() == 0 || entry.file_name() != "target");
        for entry in files {
            let entry = entry.map_err(|source| CacheError::Walk {
                path: resolved.display().to_string(),
                source,
            })?;
            if entry.file_type().is_file()
                && let Ok(relative) = entry.path().strip_prefix(workspace_root)
            {
                inputs.insert(relative.to_path_buf());
            }
        }
    }
    Ok(inputs.into_iter().collect())
}

/// The file name of a cargo manifest.
const MANIFEST: &str = "Cargo.toml";

/// The directories of the workspace path packages the program with
/// `manifest_path` depends on for `target_triple`, itself included.
///
/// A path package is one `cargo metadata` gives no `source`. The
/// dependencies are the program's whole closure in the resolve graph,
/// build-dependencies included and dev-dependencies left out.
pub fn package_directories(
    cargo: &Path,
    manifest_path: &Path,
    target_triple: &str,
) -> Result<Vec<PathBuf>, CacheError> {
    let manifest = manifest_path.display().to_string();
    let output = Command::new(cargo)
        .args(["metadata", "--format-version", "1", "--filter-platform"])
        .arg(target_triple)
        .arg("--manifest-path")
        .arg(manifest_path)
        .output()
        .map_err(|source| CacheError::SpawnMetadata {
            manifest: manifest.clone(),
            source,
        })?;
    if !output.status.success() {
        return Err(CacheError::MetadataFailed {
            manifest,
            status: output.status,
            stderr: String::from_utf8_lossy(&output.stderr)
                .trim_end()
                .to_owned(),
        });
    }
    let metadata: Metadata =
        serde_json::from_slice(&output.stdout).map_err(|source| CacheError::DecodeMetadata {
            manifest: manifest.clone(),
            source,
        })?;
    let shape = || CacheError::MetadataShape {
        manifest: manifest.clone(),
    };
    let resolve = metadata.resolve.ok_or_else(shape)?;
    let nodes = resolve
        .nodes
        .iter()
        .map(|node| (node.id.as_str(), node))
        .collect::<std::collections::BTreeMap<_, _>>();
    let mut closure = BTreeSet::new();
    let mut pending = vec![resolve.root.as_deref().ok_or_else(shape)?];
    while let Some(id) = pending.pop() {
        if !closure.insert(id) {
            continue;
        }
        let node = nodes.get(id).ok_or_else(shape)?;
        for dependency in &node.deps {
            let only_dev = !dependency.dep_kinds.is_empty()
                && dependency
                    .dep_kinds
                    .iter()
                    .all(|kind| kind.kind.as_deref() == Some("dev"));
            if !only_dev {
                pending.push(&dependency.pkg);
            }
        }
    }
    let mut directories = BTreeSet::new();
    for package in &metadata.packages {
        if package.source.is_none()
            && closure.contains(package.id.as_str())
            && let Some(directory) = package.manifest_path.parent()
        {
            directories.insert(directory.to_path_buf());
        }
    }
    Ok(directories.into_iter().collect())
}

/// The parts of `cargo metadata --format-version 1` the closure needs.
#[derive(Deserialize)]
struct Metadata {
    packages: Vec<MetadataPackage>,
    resolve: Option<MetadataResolve>,
}

#[derive(Deserialize)]
struct MetadataPackage {
    id: String,
    manifest_path: PathBuf,
    /// Absent for a path package.
    source: Option<String>,
}

#[derive(Deserialize)]
struct MetadataResolve {
    /// The package whose manifest was named.
    root: Option<String>,
    nodes: Vec<MetadataNode>,
}

#[derive(Deserialize)]
struct MetadataNode {
    id: String,
    deps: Vec<MetadataDependency>,
}

#[derive(Deserialize)]
struct MetadataDependency {
    pkg: String,
    dep_kinds: Vec<MetadataDependencyKind>,
}

#[derive(Deserialize)]
struct MetadataDependencyKind {
    /// `null` for a normal dependency, else `"dev"` or `"build"`.
    kind: Option<String>,
}

/// The dependencies of the first rule of a make-style dep-info file.
///
/// rustc escapes only the space in a name, as a backslash and the space,
/// and writes the rule on one line; the lines after it are empty rules
/// for the same files.
fn parse_dep_info(path: &Path, text: &str) -> Result<Vec<String>, CacheError> {
    let malformed = |reason| CacheError::MalformedDepInfo {
        path: path.display().to_string(),
        reason,
    };
    let rule = text
        .lines()
        .find(|line| !line.trim().is_empty())
        .ok_or_else(|| malformed("it has no rule"))?;
    let mut words = Vec::new();
    let mut word = String::new();
    let mut characters = rule.chars().peekable();
    while let Some(character) = characters.next() {
        match character {
            '\\' if characters.peek() == Some(&' ') => {
                word.push(' ');
                characters.next();
            }
            character if character.is_whitespace() => {
                if !word.is_empty() {
                    words.push(std::mem::take(&mut word));
                }
            }
            character => word.push(character),
        }
    }
    if !word.is_empty() {
        words.push(word);
    }
    let mut words = words.into_iter();
    match words.next() {
        Some(target) if target.ends_with(':') => Ok(words.collect()),
        _ => Err(malformed(
            "its first word is not a target ending in a colon",
        )),
    }
}

/// Lowercase hex SHA-256 of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// Precompiles through a cache of `cwasm` entries.
pub struct PrecompileCache<'a> {
    cache: &'a ArtifactCache,
    /// Digest of the running executable: it carries the compiler, so a
    /// rebuilt `helios-cli` addresses different entries.
    executable: String,
}

impl<'a> PrecompileCache<'a> {
    pub fn new(cache: &'a ArtifactCache) -> Result<Self, CacheError> {
        let path =
            std::env::current_exe().map_err(|source| CacheError::CurrentExecutable { source })?;
        let bytes = fs::read(&path).map_err(|source| CacheError::Read {
            path: path.display().to_string(),
            source,
        })?;
        Ok(Self {
            cache,
            executable: sha256_hex(&bytes),
        })
    }

    fn key(&self, bytes: &[u8], target: &CwasmTarget<'_>, hint: AotCompileHint) -> Key {
        KeyBuilder::new(EntryKind::Cwasm)
            .field(bytes)
            .field(&self.executable)
            .field(target.triple())
            .field(target.level().name())
            .field(format!("{hint:?}"))
            .finish()
    }
}

/// The bytes `precompile_artifact` returns for `bytes`, taken from `cache`
/// when it holds them and stored there when it does not.
pub fn precompile(
    cache: Option<&PrecompileCache<'_>>,
    bytes: &[u8],
    target: &CwasmTarget<'_>,
    hint: AotCompileHint,
) -> Result<Vec<u8>, PrecompileError> {
    let Some(cache) = cache else {
        return Ok(precompile_artifact(bytes, target, hint)?.bytes);
    };
    let key = cache.key(bytes, target, hint);
    if let Some(payload) = cache.cache.lookup_payload(&key)? {
        return Ok(payload);
    }
    let payload = precompile_artifact(bytes, target, hint)?.bytes;
    cache.cache.store_payload(&key, &payload)?;
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    /// A workspace with one program whose dep-info lists its source, a
    /// path dependency's source, a file in the target directory and a file
    /// outside the workspace.
    struct Fixture {
        root: tempfile::TempDir,
        outside: tempfile::TempDir,
        cache_dir: tempfile::TempDir,
    }

    impl Fixture {
        fn new() -> Self {
            let fixture = Self {
                root: tempfile::tempdir().expect("a workspace directory"),
                outside: tempfile::tempdir().expect("a directory outside the workspace"),
                cache_dir: tempfile::tempdir().expect("a cache directory"),
            };
            let root = fixture.workspace();
            for (path, contents) in [
                ("Cargo.toml", "[workspace]\n"),
                ("programs/date/Cargo.toml", "[package]\n"),
                ("programs/date/src/main.rs", "fn main() {}\n"),
                ("api/Cargo.toml", "[package]\n"),
                ("api/src/lib.rs", "pub fn api() {}\n"),
                // Read by a build script, so dep-info does not list it.
                ("api/protocol.txt", "protocol 1\n"),
                ("programs/date/target/ignored.o", "// output\n"),
                ("target/generated.rs", "// output\n"),
            ] {
                let path = root.join(path);
                fs::create_dir_all(path.parent().expect("a parent")).expect("a directory");
                fs::write(path, contents).expect("a file");
            }
            fs::write(fixture.outside.path().join("registry.rs"), "// registry\n").expect("a file");
            let listed = [
                root.join("programs/date/src/main.rs"),
                root.join("api/src/lib.rs"),
                root.join("target/generated.rs"),
                fixture.outside.path().join("registry.rs"),
            ]
            .map(|path| path.display().to_string())
            .join(" ");
            fs::write(
                fixture.dep_info(),
                format!(
                    "{root}/target/date.wasm: {listed}\n\n{root}/api/src/lib.rs:\n",
                    root = root.display()
                ),
            )
            .expect("a dep-info file");
            fixture
        }

        fn workspace(&self) -> PathBuf {
            fs::canonicalize(self.root.path()).expect("the workspace resolves")
        }

        fn dep_info(&self) -> PathBuf {
            self.root.path().join("date.d")
        }

        fn cache(&self) -> ArtifactCache {
            ArtifactCache::open(self.cache_dir.path()).expect("the cache opens")
        }

        fn inputs(&self) -> Vec<PathBuf> {
            workspace_inputs(
                &self.dep_info(),
                &self.workspace(),
                &self.workspace().join("target"),
                &[
                    self.workspace().join("programs/date"),
                    self.workspace().join("api"),
                ],
            )
            .expect("the dep-info is read")
        }
    }

    fn key(rustc: &str) -> Key {
        KeyBuilder::new(EntryKind::Wasm)
            .field("programs/date/Cargo.toml")
            .field(rustc)
            .finish()
    }

    #[test]
    fn the_inputs_are_the_listed_sources_and_every_file_of_the_packages() {
        let fixture = Fixture::new();
        let expected = [
            "Cargo.toml",
            "api/Cargo.toml",
            "api/protocol.txt",
            "api/src/lib.rs",
            "programs/date/Cargo.toml",
            "programs/date/src/main.rs",
        ]
        .map(PathBuf::from);
        assert_eq!(fixture.inputs(), expected);
    }

    #[test]
    fn a_name_with_a_space_stays_one_word() {
        let words = parse_dep_info(
            Path::new("date.d"),
            "/a b/date.wasm: /a\\ b/src/main.rs /c.rs\n\n/c.rs:\n",
        );
        // The target holds an unescaped space, which splits it: the rule
        // is then not a target followed by its files.
        assert!(matches!(words, Err(CacheError::MalformedDepInfo { .. })));
        let words = parse_dep_info(
            Path::new("date.d"),
            "/a\\ b/date.wasm: /a\\ b/src/main.rs /c.rs\n\n/c.rs:\n",
        )
        .expect("a rule with escaped spaces");
        assert_eq!(words, ["/a b/src/main.rs", "/c.rs"]);
    }

    #[test]
    fn nothing_changed_is_a_hit() {
        let fixture = Fixture::new();
        let cache = fixture.cache();
        let key = key("rustc 1");
        cache
            .store_wasm(
                &key,
                &fixture.workspace(),
                &fixture.inputs(),
                b"\0asm built",
            )
            .expect("the store succeeds");

        let hit = cache
            .lookup_wasm(&key, &fixture.workspace())
            .expect("the lookup succeeds");
        assert_eq!(hit.as_deref(), Some(&b"\0asm built"[..]));
        assert_eq!(cache.stats(), CacheStats { hits: 1, misses: 0 });
    }

    #[test]
    fn a_changed_listed_input_is_a_miss() {
        let fixture = Fixture::new();
        let cache = fixture.cache();
        let key = key("rustc 1");
        cache
            .store_wasm(&key, &fixture.workspace(), &fixture.inputs(), b"built")
            .expect("the store succeeds");

        fs::write(
            fixture.workspace().join("api/src/lib.rs"),
            "pub fn changed() {}\n",
        )
        .expect("an edit");
        assert_eq!(
            cache
                .lookup_wasm(&key, &fixture.workspace())
                .expect("the lookup succeeds"),
            None
        );

        // A changed manifest is as good as a changed source.
        fs::write(
            fixture.workspace().join("api/src/lib.rs"),
            "pub fn api() {}\n",
        )
        .expect("a revert");
        fs::write(
            fixture.workspace().join("api/Cargo.toml"),
            "[package]\n# features\n",
        )
        .expect("an edit");
        assert_eq!(
            cache
                .lookup_wasm(&key, &fixture.workspace())
                .expect("the lookup succeeds"),
            None
        );
        assert_eq!(cache.stats(), CacheStats { hits: 0, misses: 2 });
    }

    #[test]
    fn a_removed_listed_input_is_a_miss() {
        let fixture = Fixture::new();
        let cache = fixture.cache();
        let key = key("rustc 1");
        cache
            .store_wasm(&key, &fixture.workspace(), &fixture.inputs(), b"built")
            .expect("the store succeeds");

        fs::remove_file(fixture.workspace().join("programs/date/src/main.rs")).expect("a removal");
        assert_eq!(
            cache
                .lookup_wasm(&key, &fixture.workspace())
                .expect("the lookup succeeds"),
            None
        );
    }

    #[test]
    fn different_key_inputs_are_a_miss() {
        let fixture = Fixture::new();
        let cache = fixture.cache();
        cache
            .store_wasm(
                &key("rustc 1"),
                &fixture.workspace(),
                &fixture.inputs(),
                b"built",
            )
            .expect("the store succeeds");

        assert_eq!(
            cache
                .lookup_wasm(&key("rustc 2"), &fixture.workspace())
                .expect("the lookup succeeds"),
            None
        );
        // Fields are length-prefixed: moving a byte between two never
        // reproduces a key.
        assert_ne!(
            KeyBuilder::new(EntryKind::Wasm)
                .field("ab")
                .field("c")
                .finish(),
            KeyBuilder::new(EntryKind::Wasm)
                .field("a")
                .field("bc")
                .finish()
        );
        // The family of entry is part of the key.
        assert_ne!(
            KeyBuilder::new(EntryKind::Wasm).field("a").finish(),
            KeyBuilder::new(EntryKind::Cwasm).field("a").finish()
        );
    }

    #[test]
    fn a_store_leaves_one_complete_entry_and_no_temporary_file() {
        let fixture = Fixture::new();
        let cache = fixture.cache();
        let key = key("rustc 1");
        cache
            .store_payload(&key, b"first")
            .expect("the first store succeeds");
        cache
            .store_payload(&key, b"second, longer")
            .expect("a replacing store succeeds");

        let names = fs::read_dir(fixture.cache_dir.path())
            .expect("the cache lists")
            .map(|entry| entry.expect("an entry").file_name())
            .collect::<Vec<_>>();
        assert_eq!(names, [std::ffi::OsString::from(&key.file_name)]);
        assert_eq!(
            cache
                .lookup_payload(&key)
                .expect("the lookup succeeds")
                .as_deref(),
            Some(&b"second, longer"[..])
        );
    }

    #[test]
    fn a_corrupt_entry_is_an_error_naming_its_file() {
        let fixture = Fixture::new();
        let cache = fixture.cache();
        let key = key("rustc 1");
        cache.store_payload(&key, b"payload").expect("a store");
        let path = fixture.cache_dir.path().join(&key.file_name);
        let mut bytes = fs::read(&path).expect("the entry reads");
        *bytes.last_mut().expect("a payload") ^= 0xff;
        fs::write(&path, &bytes).expect("a corruption");

        let error = cache.lookup_payload(&key).expect_err("a corrupt entry");
        assert!(
            matches!(&error, CacheError::PayloadMismatch { path } if path.ends_with(&key.file_name)),
            "{error}"
        );

        fs::write(&path, b"abc").expect("a truncation");
        let error = cache.lookup_payload(&key).expect_err("a truncated entry");
        assert!(
            matches!(&error, CacheError::Truncated { path, .. } if path.ends_with(&key.file_name)),
            "{error}"
        );
    }

    #[test]
    fn prune_removes_only_the_entries_untouched_since_the_cutoff() {
        let fixture = Fixture::new();
        let used = key("used");
        let kept = key("stored");
        let unused = key("unused");
        let earlier = fixture.cache();
        for key in [&used, &kept, &unused] {
            earlier.store_payload(key, b"payload").expect("a store");
        }
        fs::write(fixture.cache_dir.path().join(".tmp-killed"), b"half").expect("a leftover");
        fs::write(fixture.cache_dir.path().join("README"), b"not an entry").expect("a file");
        // What a restored cache looks like: everything last used an hour
        // ago, the job having started half an hour ago.
        let hour_ago = SystemTime::now() - Duration::from_secs(3600);
        let cutoff = SystemTime::now() - Duration::from_secs(1800);
        for entry in fs::read_dir(fixture.cache_dir.path()).expect("the cache lists") {
            fs::File::options()
                .write(true)
                .open(entry.expect("an entry").path())
                .expect("an entry opens")
                .set_modified(hour_ago)
                .expect("an age");
        }

        // The job hits one entry and stores another; the third is what
        // it did not need. A second process of the job does the same.
        let run = fixture.cache();
        assert!(run.lookup_payload(&used).expect("a hit").is_some());
        run.store_payload(&kept, b"payload").expect("a store");
        let removed = prune(fixture.cache_dir.path(), cutoff).expect("the prune succeeds");

        let mut names = fs::read_dir(fixture.cache_dir.path())
            .expect("the cache lists")
            .map(|entry| {
                entry
                    .expect("an entry")
                    .file_name()
                    .into_string()
                    .expect("utf-8")
            })
            .collect::<Vec<_>>();
        names.sort();
        let mut expected = vec![
            "README".to_owned(),
            used.file_name.clone(),
            kept.file_name.clone(),
        ];
        expected.sort();
        assert_eq!(names, expected);
        assert_eq!(
            removed, 2,
            "the unused entry and the leftover temporary file"
        );
    }

    #[test]
    fn a_changed_file_of_a_build_dependency_package_is_a_miss() {
        let root = tempfile::tempdir().expect("a workspace directory");
        let workspace = fs::canonicalize(root.path()).expect("the workspace resolves");
        for (path, contents) in [
            (
                "Cargo.toml",
                "[workspace]\nmembers = [\"program\", \"generator\", \"tester\"]\nresolver = \"2\"\n",
            ),
            (
                "program/Cargo.toml",
                "[package]\nname = \"program\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\
                 [build-dependencies]\ngenerator = { path = \"../generator\" }\n\
                 [dev-dependencies]\ntester = { path = \"../tester\" }\n",
            ),
            ("program/src/main.rs", "fn main() {}\n"),
            ("program/build.rs", "fn main() {}\n"),
            (
                "generator/Cargo.toml",
                "[package]\nname = \"generator\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            ),
            ("generator/src/lib.rs", "pub fn generate() {}\n"),
            // What the generator reads at build time: no dep-info names it.
            ("generator/protocol.txt", "protocol 1\n"),
            (
                "tester/Cargo.toml",
                "[package]\nname = \"tester\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            ),
            ("tester/src/lib.rs", "pub fn test() {}\n"),
        ] {
            let path = workspace.join(path);
            fs::create_dir_all(path.parent().expect("a parent")).expect("a directory");
            fs::write(path, contents).expect("a file");
        }
        // The dep-info of the program itself: its own source and nothing else.
        let dep_info = workspace.join("program.d");
        fs::write(
            &dep_info,
            format!(
                "{root}/target/program: {root}/program/src/main.rs\n",
                root = workspace.display()
            ),
        )
        .expect("a dep-info file");

        let cargo = std::env::var_os("CARGO").expect("cargo runs the tests");
        let directories = package_directories(
            Path::new(&cargo),
            &workspace.join("program/Cargo.toml"),
            "wasm32-wasip2",
        )
        .expect("the closure resolves");
        let directories = directories
            .iter()
            .map(|directory| {
                directory
                    .strip_prefix(&workspace)
                    .expect("inside the workspace")
                    .to_owned()
            })
            .collect::<Vec<_>>();
        assert_eq!(
            directories,
            [PathBuf::from("generator"), PathBuf::from("program")],
            "the build-dependency is in the closure and the dev-dependency is not"
        );

        let inputs = workspace_inputs(
            &dep_info,
            &workspace,
            &workspace.join("target"),
            &directories
                .iter()
                .map(|directory| workspace.join(directory))
                .collect::<Vec<_>>(),
        )
        .expect("the inputs are listed");
        let cache_dir = tempfile::tempdir().expect("a cache directory");
        let cache = ArtifactCache::open(cache_dir.path()).expect("the cache opens");
        let key = key("rustc 1");
        cache
            .store_wasm(&key, &workspace, &inputs, b"built")
            .expect("the store succeeds");
        assert!(
            cache
                .lookup_wasm(&key, &workspace)
                .expect("the lookup succeeds")
                .is_some()
        );

        fs::write(workspace.join("generator/protocol.txt"), "protocol 2\n").expect("an edit");
        assert_eq!(
            cache
                .lookup_wasm(&key, &workspace)
                .expect("the lookup succeeds"),
            None
        );
    }
}
