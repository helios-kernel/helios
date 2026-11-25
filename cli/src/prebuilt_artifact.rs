//! Staging and fetching the three tiers of prebuilt CI artifacts (#1218).
//!
//! - `artifact-stage`: assembles a `kernel` (`helios-kernel-{arch}-{profile}`)
//!   or `image` (`helios-image-{arch}-{profile}`) bundle with a typed
//!   `manifest.json`, verifying that no root secret key is included and that a
//!   staged `helios-bootfs` verifies under the staged `helios-root-public.key`.
//! - `artifact-fetch`: resolves and downloads a `userspace`, `kernel`, or
//!   `image` artifact from GitHub Actions into a shared user cache (or explicit
//!   `--out-dir`), preferring `release` over `debug` when no profile override
//!   is named, rejecting zip path traversal, and validating `manifest.json`.

use std::collections::BTreeSet;
use std::fs;
use std::io::{self, Cursor};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

use clap::{Parser, ValueEnum};
use directories::ProjectDirs;
use ed25519_dalek::{SigningKey, VerifyingKey};
use helios_artifact::bootfs::{self, BootfsError, Fingerprint};
use helios_workspace_root::prebuilt_manifest::{
    BOOTFS_IMAGE_FILE, COMPILER_PLUGIN_FILE, KERNEL_IMAGE_FILE, PREBUILT_SCHEMA_VERSION,
    PrebuiltArtifactKind, PrebuiltManifest, PrebuiltManifestError, PrebuiltPrograms,
    UEFI_DISK_IMAGE_FILE, artifact_name, artifact_profile_label, read_manifest,
    read_root_public_key, sha256_hex, write_manifest,
};
use helios_workspace_root::root_key::{
    INSPECTOR_CLIENT_SECRET_FILE, ROOT_PUBLIC_FILE, ROOT_SECRET_FILE, SECRET_KEY_MODE,
};
use serde::{Deserialize, Serialize};
use tempfile::TempDir;
use thiserror::Error;

use crate::{
    ARTIFACT_PAGE, GITHUB_API, GithubArtifact, GithubArtifacts, LimineEfiArch, LimineError,
    LimineToolchain, ProfileFetchError, RELEASE_REPOSITORY, build_limine_uefi_image, decode,
    default_branch, github_get, github_redirect,
};

/// Environment variable overriding the local prebuilt artifact cache root.
pub(crate) const PREBUILT_CACHE_DIR_ENV: &str = "HELIOS_PREBUILT_CACHE_DIR";

/// Which tier `artifact-stage` produces. `userspace` is staged directly by
/// `wasm-build`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum StageKind {
    Kernel,
    Image,
}

impl From<StageKind> for PrebuiltArtifactKind {
    fn from(value: StageKind) -> Self {
        match value {
            StageKind::Kernel => Self::Kernel,
            StageKind::Image => Self::Image,
        }
    }
}

/// Which tier `artifact-fetch` downloads.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum FetchKind {
    Userspace,
    Kernel,
    Image,
}

impl From<FetchKind> for PrebuiltArtifactKind {
    fn from(value: FetchKind) -> Self {
        match value {
            FetchKind::Userspace => Self::Userspace,
            FetchKind::Kernel => Self::Kernel,
            FetchKind::Image => Self::Image,
        }
    }
}

/// Stage a `kernel` or full bootable `image` prebuilt artifact directory with
/// its typed `manifest.json`.
#[derive(Parser)]
pub(crate) struct ArtifactStageCommand {
    /// Which artifact tier to stage (`kernel` or `image`).
    #[arg(long, value_enum)]
    pub(crate) kind: StageKind,
    /// Target architecture (`x86-64`, `aarch64`, or `riscv64`).
    #[arg(long, value_parser = ["x86-64", "aarch64", "riscv64"])]
    pub(crate) arch: String,
    /// Profile label (e.g. `release`, `debug`, `release-linux`, `debug-cfi`).
    #[arg(long)]
    pub(crate) profile: String,
    /// Output directory to populate with the staged files and `manifest.json`.
    #[arg(long)]
    pub(crate) out_dir: PathBuf,
    /// Built kernel ELF binary.
    #[arg(long)]
    pub(crate) kernel: PathBuf,
    /// 32-byte Ed25519 root public key embedded in the kernel (`helios-root-public.key`).
    #[arg(long)]
    pub(crate) root_public_key: PathBuf,
    /// Signed `helios-bootfs` payload (required for `--kind image`).
    #[arg(long)]
    pub(crate) bootfs: Option<PathBuf>,
    /// Existing Limine UEFI disk image (`kernel.uefi.img`) to copy into `--out-dir`.
    #[arg(long, conflicts_with = "build_uefi_image")]
    pub(crate) uefi_image: Option<PathBuf>,
    /// Build `kernel.uefi.img` directly into `--out-dir` via Limine (`x86-64` and `aarch64` image bundles only).
    #[arg(long, default_value_t = false)]
    pub(crate) build_uefi_image: bool,
    /// Serial baud rate baked into `kernel.uefi.img`.
    #[arg(long, default_value_t = 115_200)]
    pub(crate) baud: u32,
    /// Optional `compiler_plugin.wasm` to include in `--kind image`.
    #[arg(long)]
    pub(crate) compiler_plugin: Option<PathBuf>,
    /// Optional 32-byte Ed25519 inspector client key (`helios-inspector-client-secret.key`)
    /// to stage into `--kind image` so CI shards and `helios vm --prebuilt image` can authenticate.
    #[arg(long)]
    pub(crate) inspector_client_key: Option<PathBuf>,
    /// Kernel features enabled in this build (repeatable).
    #[arg(long = "kernel-feature")]
    pub(crate) kernel_features: Vec<String>,
    /// Boot programs included in `helios-bootfs` (repeatable). Omit when all programs are included.
    #[arg(long = "program")]
    pub(crate) programs: Vec<String>,
    /// Explicit git commit SHA to record in `manifest.json` (defaults to `GITHUB_SHA` or `git rev-parse HEAD`).
    #[arg(long)]
    pub(crate) commit: Option<String>,
}

/// Download a prebuilt CI artifact (`userspace`, `kernel`, or `image`) into
/// the user cache (or `--out-dir`) and validate its `manifest.json`.
#[derive(Parser)]
pub(crate) struct ArtifactFetchCommand {
    /// Which artifact tier to fetch (`userspace`, `kernel`, or `image`).
    #[arg(long, value_enum)]
    pub(crate) kind: FetchKind,
    /// Target architecture (`x86-64`, `aarch64`, or `riscv64`). Required for `kernel` and `image`.
    #[arg(long, value_parser = ["x86-64", "aarch64", "riscv64"])]
    pub(crate) arch: Option<String>,
    /// Explicit profile label (e.g. `release`, `debug`, `release-linux`, `debug-cfi`).
    ///
    /// When omitted, `release` is preferred over `debug` whenever a matching
    /// `release` artifact exists, falling back to `debug` only if none is found.
    #[arg(long)]
    pub(crate) profile: Option<String>,
    /// Kernel features appended to the implicit profile label when `--profile` is omitted.
    #[arg(long = "kernel-feature")]
    pub(crate) kernel_features: Vec<String>,
    /// Fetch from a specific GitHub Actions workflow run ID.
    #[arg(long, value_name = "RUN_ID", conflicts_with = "git_ref")]
    pub(crate) run: Option<u64>,
    /// Fetch from the latest green CI run matching this commit SHA or branch name.
    #[arg(long = "ref", value_name = "REF")]
    pub(crate) git_ref: Option<String>,
    /// `owner/name` of the GitHub repository carrying the CI artifacts.
    #[arg(long, value_name = "REPOSITORY", default_value = RELEASE_REPOSITORY)]
    pub(crate) repo: String,
    /// Extract into this directory instead of the shared user cache directory.
    #[arg(long, value_name = "DIR")]
    pub(crate) out_dir: Option<PathBuf>,
    /// Emit a structured JSON summary of the fetched artifact to stdout.
    #[arg(long, default_value_t = false)]
    pub(crate) json: bool,
}

/// Structured output emitted by `artifact-fetch --json` and parsed by
/// `helios-inspector vm --prebuilt`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct FetchedArtifactReport {
    pub(crate) dir: PathBuf,
    pub(crate) artifact_name: String,
    pub(crate) artifact_id: u64,
    pub(crate) run_id: u64,
    pub(crate) repo: String,
    pub(crate) head_branch: String,
    pub(crate) head_sha: String,
    pub(crate) cache_hit: bool,
    pub(crate) manifest: PrebuiltManifest,
}

#[derive(Debug, Error)]
pub(crate) enum ArtifactStageError {
    #[error("{0}")]
    Manifest(#[from] PrebuiltManifestError),
    #[error("{0}")]
    Limine(#[from] LimineError),
    #[error("failed to create staging directory {path}: {source}")]
    CreateDir {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("failed to copy {from} to {to}: {source}")]
    Copy {
        from: String,
        to: String,
        #[source]
        source: io::Error,
    },
    #[error("failed to read {path}: {source}")]
    Read {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error(
        "refusing {path}: secret key files ({ROOT_SECRET_FILE}) must never be staged into a prebuilt artifact"
    )]
    SecretKeyInput { path: String },
    #[error("--root-public-key {path} is not a valid Ed25519 verifying key")]
    InvalidRootPublicKey { path: String },
    #[error(
        "--inspector-client-key {path} must hold a 32-byte Ed25519 secret seed, found {len} bytes"
    )]
    InvalidInspectorClientKey { path: String, len: usize },
    #[error("failed to set permissions on {path}: {source}")]
    SetPermissions {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("--kind image requires --bootfs")]
    MissingBootfs,
    #[error("--kind kernel must not include image-only option {option}")]
    UnexpectedOptionForKernel { option: &'static str },
    #[error("--build-uefi-image is only supported for x86-64 and aarch64, not {arch}")]
    UefiUnsupportedArch { arch: String },
    #[error("failed to verify bootfs {path}: {source}")]
    BootfsVerify {
        path: String,
        #[source]
        source: BootfsError,
    },
    #[error(
        "bootfs {bootfs} was signed by root key {bootfs_signer}, which does not match --root-public-key {root_public_key} ({kernel_key})"
    )]
    BootfsRootKeyMismatch {
        bootfs: String,
        bootfs_signer: Fingerprint,
        root_public_key: String,
        kernel_key: Fingerprint,
    },
    #[error("input file does not exist: {path}")]
    InputMissing { path: String },
}

#[derive(Debug, Error)]
pub(crate) enum ArtifactFetchError {
    #[error("{0}")]
    Manifest(#[from] PrebuiltManifestError),
    #[error("{0}")]
    Http(#[from] ProfileFetchError),
    #[error(
        "no unexpired {candidates} artifact found in {repo} for {target}; ensure a green CI run uploaded it"
    )]
    NotFound {
        repo: String,
        candidates: String,
        target: String,
    },
    #[error("cannot determine a local cache directory; set {PREBUILT_CACHE_DIR_ENV} or --out-dir")]
    NoCacheDir,
    #[error("failed to create cache directory {path}: {source}")]
    CreateDir {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("failed to create temporary extraction directory in {parent}: {source}")]
    CreateTempDir {
        parent: String,
        #[source]
        source: io::Error,
    },
    #[error("artifact {artifact} is not a readable zip archive: {source}")]
    Archive {
        artifact: u64,
        #[source]
        source: zip::result::ZipError,
    },
    #[error("artifact {artifact} contains unsafe zip entry {entry:?}")]
    UnsafeZipEntry { artifact: u64, entry: String },
    #[error("artifact {artifact} contains a symlink entry {entry:?}, which is refused")]
    SymlinkZipEntry { artifact: u64, entry: String },
    #[error("artifact {artifact} contains {ROOT_SECRET_FILE}, which is refused")]
    SecretKeyInArchive { artifact: u64 },
    #[error("failed to extract {entry:?} from artifact {artifact}: {source}")]
    ExtractEntry {
        artifact: u64,
        entry: String,
        #[source]
        source: io::Error,
    },
    #[error("artifact {artifact} manifest kind is {found}, expected {expected}")]
    KindMismatch {
        artifact: u64,
        expected: PrebuiltArtifactKind,
        found: PrebuiltArtifactKind,
    },
    #[error("artifact {artifact} manifest profile is {found:?}, expected {expected:?}")]
    ProfileMismatch {
        artifact: u64,
        expected: String,
        found: String,
    },
    #[error("artifact {artifact} manifest arch is {found:?}, expected {expected:?}")]
    ArchMismatch {
        artifact: u64,
        expected: Option<String>,
        found: Option<String>,
    },
    #[error("failed to publish extracted artifact into {dest}: {source}")]
    PublishDir {
        dest: String,
        #[source]
        source: io::Error,
    },
    #[error("failed to encode fetch report as JSON: {source}")]
    EncodeReport {
        #[source]
        source: serde_json::Error,
    },
}

/// The parts of a GitHub workflow run response read to verify it is green.
#[derive(Debug, Deserialize)]
struct GithubRunStatus {
    status: String,
    conclusion: Option<String>,
}

impl GithubRunStatus {
    fn is_green(&self) -> bool {
        self.status == "completed" && self.conclusion.as_deref() == Some("success")
    }
}

/// Resolves the current checkout's commit SHA (`GITHUB_SHA` first, then `git rev-parse HEAD`).
pub(crate) fn current_git_commit(cwd: Option<&Path>) -> Option<String> {
    if let Ok(sha) = std::env::var("GITHUB_SHA") {
        let trimmed = sha.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_owned());
        }
    }
    let mut git = Command::new("git");
    if let Some(dir) = cwd {
        git.current_dir(dir);
    }
    let output = git.args(["rev-parse", "HEAD"]).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let sha = String::from_utf8(output.stdout).ok()?;
    let trimmed = sha.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_owned())
}

pub(crate) fn run_stage(
    command: ArtifactStageCommand,
    workspace_root: Option<&Path>,
) -> Result<(), ArtifactStageError> {
    if command.root_public_key.file_name() == Some(ROOT_SECRET_FILE.as_ref()) {
        return Err(ArtifactStageError::SecretKeyInput {
            path: command.root_public_key.display().to_string(),
        });
    }
    if !command.kernel.is_file() {
        return Err(ArtifactStageError::InputMissing {
            path: command.kernel.display().to_string(),
        });
    }
    let root_public_bytes = read_root_public_key(&command.root_public_key)?;
    VerifyingKey::from_bytes(&root_public_bytes).map_err(|_| {
        ArtifactStageError::InvalidRootPublicKey {
            path: command.root_public_key.display().to_string(),
        }
    })?;

    if command.kind == StageKind::Kernel {
        if command.bootfs.is_some() {
            return Err(ArtifactStageError::UnexpectedOptionForKernel { option: "--bootfs" });
        }
        if command.uefi_image.is_some() {
            return Err(ArtifactStageError::UnexpectedOptionForKernel {
                option: "--uefi-image",
            });
        }
        if command.build_uefi_image {
            return Err(ArtifactStageError::UnexpectedOptionForKernel {
                option: "--build-uefi-image",
            });
        }
        if command.compiler_plugin.is_some() {
            return Err(ArtifactStageError::UnexpectedOptionForKernel {
                option: "--compiler-plugin",
            });
        }
        if command.inspector_client_key.is_some() {
            return Err(ArtifactStageError::UnexpectedOptionForKernel {
                option: "--inspector-client-key",
            });
        }
    }

    fs::create_dir_all(&command.out_dir).map_err(|source| ArtifactStageError::CreateDir {
        path: command.out_dir.display().to_string(),
        source,
    })?;

    let mut files = BTreeSet::new();
    copy_into(&command.kernel, &command.out_dir.join(KERNEL_IMAGE_FILE))?;
    files.insert(KERNEL_IMAGE_FILE.to_owned());

    copy_into(
        &command.root_public_key,
        &command.out_dir.join(ROOT_PUBLIC_FILE),
    )?;
    files.insert(ROOT_PUBLIC_FILE.to_owned());

    let mut baud = None;
    let programs = match command.kind {
        StageKind::Kernel => None,
        StageKind::Image => {
            let bootfs = command
                .bootfs
                .as_deref()
                .ok_or(ArtifactStageError::MissingBootfs)?;
            if !bootfs.is_file() {
                return Err(ArtifactStageError::InputMissing {
                    path: bootfs.display().to_string(),
                });
            }
            let bootfs_bytes = fs::read(bootfs).map_err(|source| ArtifactStageError::Read {
                path: bootfs.display().to_string(),
                source,
            })?;
            let signer = bootfs::verified_signer(&bootfs_bytes).map_err(|source| {
                ArtifactStageError::BootfsVerify {
                    path: bootfs.display().to_string(),
                    source,
                }
            })?;
            if signer != root_public_bytes {
                return Err(ArtifactStageError::BootfsRootKeyMismatch {
                    bootfs: bootfs.display().to_string(),
                    bootfs_signer: Fingerprint::of(&signer),
                    root_public_key: command.root_public_key.display().to_string(),
                    kernel_key: Fingerprint::of(&root_public_bytes),
                });
            }
            let staged_bootfs = command.out_dir.join(BOOTFS_IMAGE_FILE);
            copy_into(bootfs, &staged_bootfs)?;
            files.insert(BOOTFS_IMAGE_FILE.to_owned());

            if let Some(uefi) = &command.uefi_image {
                if !uefi.is_file() {
                    return Err(ArtifactStageError::InputMissing {
                        path: uefi.display().to_string(),
                    });
                }
                copy_into(uefi, &command.out_dir.join(UEFI_DISK_IMAGE_FILE))?;
                files.insert(UEFI_DISK_IMAGE_FILE.to_owned());
                baud = Some(command.baud);
            } else if command.build_uefi_image {
                let efi_arch = match command.arch.as_str() {
                    "x86-64" => LimineEfiArch::X86_64,
                    "aarch64" => LimineEfiArch::Aarch64,
                    other => {
                        return Err(ArtifactStageError::UefiUnsupportedArch {
                            arch: other.to_owned(),
                        });
                    }
                };
                let limine = LimineToolchain::discover(efi_arch)?;
                let staged_kernel = command.out_dir.join(KERNEL_IMAGE_FILE);
                let staged_uefi = command.out_dir.join(UEFI_DISK_IMAGE_FILE);
                build_limine_uefi_image(
                    &limine,
                    &staged_kernel,
                    &staged_bootfs,
                    &staged_uefi,
                    command.baud,
                )?;
                files.insert(UEFI_DISK_IMAGE_FILE.to_owned());
                baud = Some(command.baud);
            }

            if let Some(plugin) = &command.compiler_plugin {
                if !plugin.is_file() {
                    return Err(ArtifactStageError::InputMissing {
                        path: plugin.display().to_string(),
                    });
                }
                copy_into(plugin, &command.out_dir.join(COMPILER_PLUGIN_FILE))?;
                files.insert(COMPILER_PLUGIN_FILE.to_owned());
            }

            if let Some(client_key) = &command.inspector_client_key {
                if client_key.file_name() == Some(ROOT_SECRET_FILE.as_ref()) {
                    return Err(ArtifactStageError::SecretKeyInput {
                        path: client_key.display().to_string(),
                    });
                }
                if !client_key.is_file() {
                    return Err(ArtifactStageError::InputMissing {
                        path: client_key.display().to_string(),
                    });
                }
                let raw = fs::read(client_key).map_err(|source| ArtifactStageError::Read {
                    path: client_key.display().to_string(),
                    source,
                })?;
                let seed: [u8; 32] = raw.as_slice().try_into().map_err(|_| {
                    ArtifactStageError::InvalidInspectorClientKey {
                        path: client_key.display().to_string(),
                        len: raw.len(),
                    }
                })?;
                // Validate that the seed constructs a signing key cleanly.
                let _ = SigningKey::from_bytes(&seed);
                let staged_key = command.out_dir.join(INSPECTOR_CLIENT_SECRET_FILE);
                copy_into(client_key, &staged_key)?;
                #[cfg(unix)]
                fs::set_permissions(&staged_key, fs::Permissions::from_mode(SECRET_KEY_MODE))
                    .map_err(|source| ArtifactStageError::SetPermissions {
                        path: staged_key.display().to_string(),
                        source,
                    })?;
                files.insert(INSPECTOR_CLIENT_SECRET_FILE.to_owned());
            }

            Some(if command.programs.is_empty() {
                PrebuiltPrograms::All
            } else {
                let sorted: Vec<String> = command
                    .programs
                    .iter()
                    .cloned()
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect();
                PrebuiltPrograms::Subset(sorted)
            })
        }
    };

    let kernel_features: Vec<String> = command
        .kernel_features
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();

    let manifest = PrebuiltManifest {
        schema_version: PREBUILT_SCHEMA_VERSION,
        kind: command.kind.into(),
        commit: command
            .commit
            .or_else(|| current_git_commit(workspace_root)),
        arch: Some(command.arch),
        profile: command.profile,
        kernel_features,
        programs,
        files: files.into_iter().collect(),
        root_public_key_sha256: Some(sha256_hex(&root_public_bytes)),
        baud,
    };
    write_manifest(&command.out_dir, &manifest)?;
    // Re-read to guarantee the staged directory satisfies every consumer invariant.
    let _ = read_manifest(&command.out_dir)?;
    Ok(())
}

fn copy_into(from: &Path, to: &Path) -> Result<(), ArtifactStageError> {
    fs::copy(from, to).map_err(|source| ArtifactStageError::Copy {
        from: from.display().to_string(),
        to: to.display().to_string(),
        source,
    })?;
    Ok(())
}

/// Resolves candidate profile labels in priority order.
///
/// When an explicit `--profile` was passed, only that profile is tried.
/// Otherwise `release` is always preferred over `debug`, with any requested
/// `--kernel-feature` suffixes attached deterministically.
fn candidate_profiles(explicit: Option<&str>, kernel_features: &[String]) -> Vec<String> {
    if let Some(profile) = explicit {
        return vec![profile.to_owned()];
    }
    vec![
        artifact_profile_label("release", kernel_features, None),
        artifact_profile_label("debug", kernel_features, None),
    ]
}

/// Filter predicates for matching a workflow artifact against a caller's target.
#[derive(Clone, Debug, PartialEq, Eq)]
enum RefMatcher {
    Commit(String),
    Branch(String),
    CommitOrBranch {
        ref_name: String,
        resolved_sha: Option<String>,
    },
}

impl RefMatcher {
    fn matches(&self, artifact: &GithubArtifact) -> bool {
        match self {
            Self::Commit(sha) => sha_matches(&artifact.workflow_run.head_sha, sha),
            Self::Branch(branch) => artifact.workflow_run.head_branch == *branch,
            Self::CommitOrBranch {
                ref_name,
                resolved_sha,
            } => {
                artifact.workflow_run.head_branch == *ref_name
                    || sha_matches(&artifact.workflow_run.head_sha, ref_name)
                    || resolved_sha
                        .as_deref()
                        .is_some_and(|sha| sha_matches(&artifact.workflow_run.head_sha, sha))
            }
        }
    }
}

fn sha_matches(full_sha: &str, needle: &str) -> bool {
    if needle.len() < 7 || needle.len() > 40 || !needle.bytes().all(|b| b.is_ascii_hexdigit()) {
        return false;
    }
    full_sha
        .get(..needle.len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(needle))
}

fn resolve_local_ref_sha(cwd: Option<&Path>, reference: &str) -> Option<String> {
    let mut git = Command::new("git");
    if let Some(dir) = cwd {
        git.current_dir(dir);
    }
    let output = git
        .args(["rev-parse", "--verify", &format!("{reference}^{{commit}}")])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let sha = String::from_utf8(output.stdout).ok()?;
    let trimmed = sha.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_owned())
}

/// Picks the newest unexpired artifact from `artifacts` whose name matches
/// `expected_name`, whose run matches `matcher` (if any), and whose run is
/// green according to `is_run_green`.
fn select_matching_artifact<F>(
    artifacts: Vec<GithubArtifact>,
    expected_name: &str,
    matcher: Option<&RefMatcher>,
    mut is_run_green: F,
) -> Result<Option<GithubArtifact>, ArtifactFetchError>
where
    F: FnMut(u64) -> Result<bool, ArtifactFetchError>,
{
    for artifact in artifacts {
        if artifact.expired || artifact.name != expected_name {
            continue;
        }
        if let Some(matcher) = matcher
            && !matcher.matches(&artifact)
        {
            continue;
        }
        if is_run_green(artifact.workflow_run.id)? {
            return Ok(Some(artifact));
        }
    }
    Ok(None)
}

pub(crate) fn run_fetch(
    command: ArtifactFetchCommand,
    workspace_root: Option<&Path>,
) -> Result<(), ArtifactFetchError> {
    let kind: PrebuiltArtifactKind = command.kind.into();
    let profiles = candidate_profiles(command.profile.as_deref(), &command.kernel_features);
    let candidate_names: Vec<(String, String)> = profiles
        .into_iter()
        .map(|profile| {
            let name = artifact_name(kind, command.arch.as_deref(), &profile)?;
            Ok((profile, name))
        })
        .collect::<Result<Vec<_>, PrebuiltManifestError>>()?;

    let (selected_profile, selected_artifact) =
        resolve_artifact(&command, workspace_root, &candidate_names)?;

    let (dest_dir, cache_hit) = match &command.out_dir {
        Some(out_dir) => {
            download_and_extract(
                &selected_artifact,
                kind,
                command.arch.as_deref(),
                &selected_profile,
                out_dir,
                true,
            )?;
            (out_dir.clone(), false)
        }
        None => {
            let cache_entry = cache_entry_dir(
                &command.repo,
                &selected_artifact.name,
                selected_artifact.workflow_run.id,
                selected_artifact.id,
            )?;
            let hit = validate_cached_dir(
                &cache_entry,
                kind,
                command.arch.as_deref(),
                &selected_profile,
            )
            .is_ok();
            if !hit {
                download_and_extract(
                    &selected_artifact,
                    kind,
                    command.arch.as_deref(),
                    &selected_profile,
                    &cache_entry,
                    false,
                )?;
            }
            (cache_entry, hit)
        }
    };

    let manifest = read_manifest(&dest_dir)?;
    let report = FetchedArtifactReport {
        dir: dest_dir,
        artifact_name: selected_artifact.name,
        artifact_id: selected_artifact.id,
        run_id: selected_artifact.workflow_run.id,
        repo: command.repo,
        head_branch: selected_artifact.workflow_run.head_branch,
        head_sha: selected_artifact.workflow_run.head_sha,
        cache_hit,
        manifest,
    };

    if command.json {
        let encoded = serde_json::to_string(&report)
            .map_err(|source| ArtifactFetchError::EncodeReport { source })?;
        println!("{encoded}");
    } else {
        let source_state = if report.cache_hit {
            "cached"
        } else {
            "fetched"
        };
        println!(
            "{} {} (run {}, sha {}) -> {}",
            source_state,
            report.artifact_name,
            report.run_id,
            &report.head_sha[..report.head_sha.len().min(12)],
            report.dir.display(),
        );
    }
    Ok(())
}

fn resolve_artifact(
    command: &ArtifactFetchCommand,
    workspace_root: Option<&Path>,
    candidate_names: &[(String, String)],
) -> Result<(String, GithubArtifact), ArtifactFetchError> {
    let repo = &command.repo;
    if let Some(run_id) = command.run {
        for (profile, name) in candidate_names {
            let url = format!(
                "{GITHUB_API}/repos/{repo}/actions/runs/{run_id}/artifacts\
                 ?name={name}&per_page={ARTIFACT_PAGE}"
            );
            let doc = github_get(&url, true)?;
            let listing: GithubArtifacts = decode(&url, "a GitHub run artifact listing", &doc)?;
            if let Some(artifact) =
                select_matching_artifact(listing.artifacts, name, None, |_| Ok(true))?
            {
                return Ok((profile.clone(), artifact));
            }
        }
        return Err(ArtifactFetchError::NotFound {
            repo: repo.clone(),
            candidates: format_candidates(candidate_names),
            target: format!("workflow run {run_id}"),
        });
    }

    let mut run_status_cache = std::collections::BTreeMap::<u64, bool>::new();
    let mut is_green = |run_id: u64| -> Result<bool, ArtifactFetchError> {
        if let Some(&cached) = run_status_cache.get(&run_id) {
            return Ok(cached);
        }
        let url = format!("{GITHUB_API}/repos/{repo}/actions/runs/{run_id}");
        let doc = github_get(&url, true)?;
        let status: GithubRunStatus = decode(&url, "a GitHub workflow run", &doc)?;
        let green = status.is_green();
        run_status_cache.insert(run_id, green);
        Ok(green)
    };

    if let Some(git_ref) = &command.git_ref {
        let matcher = RefMatcher::CommitOrBranch {
            ref_name: git_ref.clone(),
            resolved_sha: resolve_local_ref_sha(workspace_root, git_ref),
        };
        for (profile, name) in candidate_names {
            let listing = fetch_repo_artifacts(repo, name)?;
            if let Some(artifact) =
                select_matching_artifact(listing, name, Some(&matcher), &mut is_green)?
            {
                return Ok((profile.clone(), artifact));
            }
        }
        return Err(ArtifactFetchError::NotFound {
            repo: repo.clone(),
            candidates: format_candidates(candidate_names),
            target: format!("ref {git_ref:?}"),
        });
    }

    // Default lookup: try current HEAD commit first (across preferred profiles:
    // release before debug), then fall back to the repository's default branch
    // (again preferring release before debug).
    let head_sha = current_git_commit(workspace_root);
    let mut listings = Vec::with_capacity(candidate_names.len());
    for (profile, name) in candidate_names {
        let artifacts = fetch_repo_artifacts(repo, name)?;
        if let Some(sha) = &head_sha {
            let matcher = RefMatcher::Commit(sha.clone());
            if let Some(artifact) =
                select_matching_artifact(artifacts.clone(), name, Some(&matcher), &mut is_green)?
            {
                return Ok((profile.clone(), artifact));
            }
        }
        listings.push((profile.clone(), name.clone(), artifacts));
    }

    let branch = default_branch(repo)?;
    let branch_matcher = RefMatcher::Branch(branch.clone());
    for (profile, name, artifacts) in listings {
        if let Some(artifact) =
            select_matching_artifact(artifacts, &name, Some(&branch_matcher), &mut is_green)?
        {
            return Ok((profile, artifact));
        }
    }

    let target = match head_sha {
        Some(sha) => format!(
            "HEAD ({}) or default branch {branch:?}",
            &sha[..sha.len().min(12)]
        ),
        None => format!("default branch {branch:?}"),
    };
    Err(ArtifactFetchError::NotFound {
        repo: repo.clone(),
        candidates: format_candidates(candidate_names),
        target,
    })
}

fn fetch_repo_artifacts(
    repo: &str,
    artifact_name: &str,
) -> Result<Vec<GithubArtifact>, ArtifactFetchError> {
    let url = format!(
        "{GITHUB_API}/repos/{repo}/actions/artifacts\
         ?name={artifact_name}&per_page={ARTIFACT_PAGE}"
    );
    let doc = github_get(&url, true)?;
    let listing: GithubArtifacts = decode(&url, "a GitHub artifact listing", &doc)?;
    Ok(listing.artifacts)
}

fn format_candidates(candidates: &[(String, String)]) -> String {
    candidates
        .iter()
        .map(|(_, name)| name.as_str())
        .collect::<Vec<_>>()
        .join(" or ")
}

fn cache_entry_dir(
    repo: &str,
    artifact_name: &str,
    run_id: u64,
    artifact_id: u64,
) -> Result<PathBuf, ArtifactFetchError> {
    let root = match std::env::var_os(PREBUILT_CACHE_DIR_ENV) {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ => ProjectDirs::from("", "", "helios")
            .ok_or(ArtifactFetchError::NoCacheDir)?
            .cache_dir()
            .join("prebuilt"),
    };
    let safe_repo = repo.replace('/', "__");
    Ok(root
        .join(safe_repo)
        .join(artifact_name)
        .join(format!("run-{run_id}-artifact-{artifact_id}")))
}

fn download_and_extract(
    artifact: &GithubArtifact,
    expected_kind: PrebuiltArtifactKind,
    expected_arch: Option<&str>,
    expected_profile: &str,
    dest: &Path,
    replace_existing: bool,
) -> Result<(), ArtifactFetchError> {
    let location = github_redirect(&artifact.archive_download_url)?;
    let archive_bytes = github_get(&location, false)?;

    let parent = dest
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|source| ArtifactFetchError::CreateDir {
        path: parent.display().to_string(),
        source,
    })?;
    let staging = TempDir::new_in(parent).map_err(|source| ArtifactFetchError::CreateTempDir {
        parent: parent.display().to_string(),
        source,
    })?;

    extract_zip_safely(artifact.id, &archive_bytes, staging.path())?;
    validate_extracted_manifest(
        artifact.id,
        staging.path(),
        expected_kind,
        expected_arch,
        expected_profile,
    )?;

    if replace_existing && dest.exists() {
        fs::remove_dir_all(dest).map_err(|source| ArtifactFetchError::PublishDir {
            dest: dest.display().to_string(),
            source,
        })?;
    }

    let staged_path = staging.keep();
    match fs::rename(&staged_path, dest) {
        Ok(()) => Ok(()),
        Err(source) => {
            // Another process may have populated the same cache entry concurrently.
            let _ = fs::remove_dir_all(&staged_path);
            if !replace_existing
                && validate_cached_dir(dest, expected_kind, expected_arch, expected_profile).is_ok()
            {
                return Ok(());
            }
            Err(ArtifactFetchError::PublishDir {
                dest: dest.display().to_string(),
                source,
            })
        }
    }
}

fn validate_cached_dir(
    dir: &Path,
    expected_kind: PrebuiltArtifactKind,
    expected_arch: Option<&str>,
    expected_profile: &str,
) -> Result<PrebuiltManifest, ArtifactFetchError> {
    validate_extracted_manifest(0, dir, expected_kind, expected_arch, expected_profile)
}

fn validate_extracted_manifest(
    artifact_id: u64,
    dir: &Path,
    expected_kind: PrebuiltArtifactKind,
    expected_arch: Option<&str>,
    expected_profile: &str,
) -> Result<PrebuiltManifest, ArtifactFetchError> {
    let manifest = read_manifest(dir)?;
    if manifest.kind != expected_kind {
        return Err(ArtifactFetchError::KindMismatch {
            artifact: artifact_id,
            expected: expected_kind,
            found: manifest.kind,
        });
    }
    if manifest.profile != expected_profile {
        return Err(ArtifactFetchError::ProfileMismatch {
            artifact: artifact_id,
            expected: expected_profile.to_owned(),
            found: manifest.profile,
        });
    }
    if manifest.arch.as_deref() != expected_arch {
        return Err(ArtifactFetchError::ArchMismatch {
            artifact: artifact_id,
            expected: expected_arch.map(str::to_owned),
            found: manifest.arch,
        });
    }
    Ok(manifest)
}

/// Extracts a GitHub Actions zip archive into `dest`, refusing path traversal,
/// absolute paths, symlinks, and any secret key file.
fn extract_zip_safely(
    artifact_id: u64,
    archive_bytes: &[u8],
    dest: &Path,
) -> Result<(), ArtifactFetchError> {
    let mut archive = zip::ZipArchive::new(Cursor::new(archive_bytes)).map_err(|source| {
        ArtifactFetchError::Archive {
            artifact: artifact_id,
            source,
        }
    })?;
    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .map_err(|source| ArtifactFetchError::Archive {
                artifact: artifact_id,
                source,
            })?;
        let raw_name = entry.name().to_owned();
        if entry.is_symlink() {
            return Err(ArtifactFetchError::SymlinkZipEntry {
                artifact: artifact_id,
                entry: raw_name,
            });
        }
        let rel = safe_zip_relative_path(artifact_id, &raw_name)?;
        if rel.file_name() == Some(ROOT_SECRET_FILE.as_ref()) {
            return Err(ArtifactFetchError::SecretKeyInArchive {
                artifact: artifact_id,
            });
        }
        let target = dest.join(&rel);
        if entry.is_dir() {
            fs::create_dir_all(&target).map_err(|source| ArtifactFetchError::ExtractEntry {
                artifact: artifact_id,
                entry: raw_name,
                source,
            })?;
            continue;
        }
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).map_err(|source| ArtifactFetchError::ExtractEntry {
                artifact: artifact_id,
                entry: raw_name.clone(),
                source,
            })?;
        }
        let mut out =
            fs::File::create(&target).map_err(|source| ArtifactFetchError::ExtractEntry {
                artifact: artifact_id,
                entry: raw_name.clone(),
                source,
            })?;
        io::copy(&mut entry, &mut out).map_err(|source| ArtifactFetchError::ExtractEntry {
            artifact: artifact_id,
            entry: raw_name.clone(),
            source,
        })?;
        #[cfg(unix)]
        if rel.file_name() == Some(INSPECTOR_CLIENT_SECRET_FILE.as_ref()) {
            fs::set_permissions(&target, fs::Permissions::from_mode(SECRET_KEY_MODE)).map_err(
                |source| ArtifactFetchError::ExtractEntry {
                    artifact: artifact_id,
                    entry: raw_name,
                    source,
                },
            )?;
        }
    }
    Ok(())
}

fn safe_zip_relative_path(artifact_id: u64, raw_name: &str) -> Result<PathBuf, ArtifactFetchError> {
    let stripped = raw_name.trim_end_matches('/');
    if stripped.is_empty() || stripped.contains('\\') {
        return Err(ArtifactFetchError::UnsafeZipEntry {
            artifact: artifact_id,
            entry: raw_name.to_owned(),
        });
    }
    let path = Path::new(stripped);
    if path.is_absolute() {
        return Err(ArtifactFetchError::UnsafeZipEntry {
            artifact: artifact_id,
            entry: raw_name.to_owned(),
        });
    }
    let mut clean = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => clean.push(part),
            _ => {
                return Err(ArtifactFetchError::UnsafeZipEntry {
                    artifact: artifact_id,
                    entry: raw_name.to_owned(),
                });
            }
        }
    }
    if clean.as_os_str().is_empty() {
        return Err(ArtifactFetchError::UnsafeZipEntry {
            artifact: artifact_id,
            entry: raw_name.to_owned(),
        });
    }
    Ok(clean)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::GithubWorkflowRun;
    use helios_artifact::bootfs::{EntryKind, WriteEntry, sign_image, write_image};
    use helios_workspace_root::prebuilt_manifest::PREBUILT_MANIFEST_FILE;
    use std::io::Write;
    use zip::write::SimpleFileOptions;

    fn make_signed_bootfs(secret: &[u8; 32]) -> (Vec<u8>, [u8; 32]) {
        let signing_key = SigningKey::from_bytes(secret);
        let public_key = VerifyingKey::from(&signing_key).to_bytes();
        let body = write_image(&[
            WriteEntry {
                kind: EntryKind::InitComponent,
                path: "bin/init",
                data: b"fake-init",
                modified_nanos: 0,
            },
            WriteEntry {
                kind: EntryKind::InitArgv0,
                path: "/bin/init",
                data: &[],
                modified_nanos: 0,
            },
        ]);
        (sign_image(body, &signing_key), public_key)
    }

    fn make_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut cursor = Cursor::new(Vec::new());
        {
            let mut writer = zip::ZipWriter::new(&mut cursor);
            let options = SimpleFileOptions::default();
            for (name, bytes) in entries {
                writer.start_file(*name, options).expect("start zip file");
                writer.write_all(bytes).expect("write zip bytes");
            }
            writer.finish().expect("finish zip");
        }
        cursor.into_inner()
    }

    fn sample_artifact(
        id: u64,
        name: &str,
        run_id: u64,
        branch: &str,
        sha: &str,
    ) -> GithubArtifact {
        GithubArtifact {
            id,
            name: name.to_owned(),
            expired: false,
            archive_download_url: format!("https://example.invalid/artifacts/{id}/zip"),
            workflow_run: GithubWorkflowRun {
                id: run_id,
                head_branch: branch.to_owned(),
                head_sha: sha.to_owned(),
            },
        }
    }

    #[test]
    fn candidate_profiles_prefer_release_over_debug_unless_explicit() {
        assert_eq!(
            candidate_profiles(None, &[]),
            vec!["release".to_owned(), "debug".to_owned()]
        );
        assert_eq!(
            candidate_profiles(None, &["linux".to_owned()]),
            vec!["release-linux".to_owned(), "debug-linux".to_owned()]
        );
        assert_eq!(
            candidate_profiles(Some("debug-cfi"), &["linux".to_owned()]),
            vec!["debug-cfi".to_owned()]
        );
    }

    #[test]
    fn artifact_selection_skips_failed_and_expired_runs() {
        let mut expired =
            sample_artifact(1, "helios-image-x86-64-release", 10, "main", "aaaaaaa111");
        expired.expired = true;
        let failed = sample_artifact(2, "helios-image-x86-64-release", 11, "main", "bbbbbbb222");
        let green = sample_artifact(3, "helios-image-x86-64-release", 12, "main", "ccccccc333");
        let other_branch =
            sample_artifact(4, "helios-image-x86-64-release", 13, "feat", "ddddddd444");

        let matcher = RefMatcher::Branch("main".to_owned());
        let picked = select_matching_artifact(
            vec![expired, other_branch, failed, green.clone()],
            "helios-image-x86-64-release",
            Some(&matcher),
            |run_id| Ok(run_id == 12),
        )
        .expect("selection succeeds")
        .expect("green main artifact must be picked");
        assert_eq!(picked.id, green.id);
    }

    #[test]
    fn zip_extraction_rejects_path_traversal_and_secret_key() {
        let dest = TempDir::new().expect("temp dir");
        let traversal = make_zip(&[("../evil.txt", b"boom")]);
        let err =
            extract_zip_safely(99, &traversal, dest.path()).expect_err("path traversal must fail");
        assert!(matches!(err, ArtifactFetchError::UnsafeZipEntry { .. }));

        let secret = make_zip(&[(ROOT_SECRET_FILE, &[1_u8; 32])]);
        let err = extract_zip_safely(100, &secret, dest.path())
            .expect_err("secret key in archive must fail");
        assert!(matches!(err, ArtifactFetchError::SecretKeyInArchive { .. }));
    }

    #[test]
    fn artifact_stage_validates_image_signature_and_refuses_mismatch() {
        let src = TempDir::new().expect("src dir");
        let out = TempDir::new().expect("out dir");
        let kernel = src.path().join("helios");
        fs::write(&kernel, b"elf-bytes").expect("write kernel");

        let (bootfs_bytes, pub_a) = make_signed_bootfs(&[11_u8; 32]);
        let (_, pub_b) = make_signed_bootfs(&[22_u8; 32]);
        let bootfs_path = src.path().join("helios-bootfs");
        fs::write(&bootfs_path, bootfs_bytes).expect("write bootfs");
        let pub_a_path = src.path().join("helios-root-public.key");
        let pub_b_path = src.path().join("other-public.key");
        fs::write(&pub_a_path, pub_a).expect("write pub a");
        fs::write(&pub_b_path, pub_b).expect("write pub b");

        // Mismatched root public key must fail fast.
        let mismatch = run_stage(
            ArtifactStageCommand {
                kind: StageKind::Image,
                arch: "x86-64".to_owned(),
                profile: "release-linux".to_owned(),
                out_dir: out.path().join("bad"),
                kernel: kernel.clone(),
                root_public_key: pub_b_path,
                bootfs: Some(bootfs_path.clone()),
                uefi_image: None,
                build_uefi_image: false,
                baud: 115_200,
                compiler_plugin: None,
                inspector_client_key: None,
                kernel_features: vec!["linux".to_owned()],
                programs: vec!["debugger".to_owned(), "init".to_owned()],
                commit: Some("deadbeef".to_owned()),
            },
            None,
        )
        .expect_err("mismatched signer must fail");
        assert!(matches!(
            mismatch,
            ArtifactStageError::BootfsRootKeyMismatch { .. }
        ));

        // Matching root public key stages cleanly and produces a valid manifest.
        let good_dir = out.path().join("good");
        run_stage(
            ArtifactStageCommand {
                kind: StageKind::Image,
                arch: "x86-64".to_owned(),
                profile: "release-linux".to_owned(),
                out_dir: good_dir.clone(),
                kernel,
                root_public_key: pub_a_path,
                bootfs: Some(bootfs_path),
                uefi_image: None,
                build_uefi_image: false,
                baud: 115_200,
                compiler_plugin: None,
                inspector_client_key: None,
                kernel_features: vec!["linux".to_owned()],
                programs: vec!["debugger".to_owned(), "init".to_owned()],
                commit: Some("deadbeef".to_owned()),
            },
            None,
        )
        .expect("matching image stages cleanly");

        let manifest = read_manifest(&good_dir).expect("staged manifest must validate");
        assert_eq!(manifest.kind, PrebuiltArtifactKind::Image);
        assert_eq!(manifest.arch.as_deref(), Some("x86-64"));
        assert_eq!(manifest.profile, "release-linux");
        assert_eq!(manifest.kernel_features, vec!["linux".to_owned()]);
        assert_eq!(
            manifest.programs,
            Some(PrebuiltPrograms::Subset(vec![
                "debugger".to_owned(),
                "init".to_owned(),
            ]))
        );
        assert_eq!(manifest.root_public_key_sha256, Some(sha256_hex(&pub_a)));
        assert!(good_dir.join(PREBUILT_MANIFEST_FILE).is_file());
    }

    #[test]
    fn artifact_stage_refuses_secret_key_filename() {
        let src = TempDir::new().expect("src dir");
        let out = TempDir::new().expect("out dir");
        let kernel = src.path().join("helios");
        fs::write(&kernel, b"elf").expect("write kernel");
        let secret_path = src.path().join(ROOT_SECRET_FILE);
        fs::write(&secret_path, [9_u8; 32]).expect("write secret");

        let err = run_stage(
            ArtifactStageCommand {
                kind: StageKind::Kernel,
                arch: "riscv64".to_owned(),
                profile: "release".to_owned(),
                out_dir: out.path().to_path_buf(),
                kernel,
                root_public_key: secret_path,
                bootfs: None,
                uefi_image: None,
                build_uefi_image: false,
                baud: 115_200,
                compiler_plugin: None,
                inspector_client_key: None,
                kernel_features: Vec::new(),
                programs: Vec::new(),
                commit: Some("abc1234".to_owned()),
            },
            None,
        )
        .expect_err("secret key input must be refused");
        assert!(matches!(err, ArtifactStageError::SecretKeyInput { .. }));
    }

    #[test]
    fn cli_parses_artifact_fetch_and_stage_subcommands() {
        let cli = crate::Cli::try_parse_from([
            "helios-cli",
            "artifact-fetch",
            "--kind",
            "image",
            "--arch",
            "x86-64",
            "--json",
        ])
        .expect("artifact-fetch parses without --profile");
        let crate::Commands::ArtifactFetch(fetch) = cli.command else {
            panic!("expected ArtifactFetch");
        };
        assert_eq!(fetch.kind, FetchKind::Image);
        assert_eq!(fetch.arch.as_deref(), Some("x86-64"));
        assert!(fetch.profile.is_none());
        assert!(fetch.json);
    }

    #[test]
    fn artifact_stage_image_with_inspector_client_key_stages_0600_and_validates_manifest() {
        let src = TempDir::new().expect("src dir");
        let out = TempDir::new().expect("out dir");
        let kernel = src.path().join("helios");
        fs::write(&kernel, b"elf-bytes").expect("write kernel");

        let (bootfs_bytes, pub_a) = make_signed_bootfs(&[11_u8; 32]);
        let bootfs_path = src.path().join("helios-bootfs");
        fs::write(&bootfs_path, bootfs_bytes).expect("write bootfs");
        let pub_a_path = src.path().join("helios-root-public.key");
        fs::write(&pub_a_path, pub_a).expect("write pub a");
        let client_key_path = src.path().join(INSPECTOR_CLIENT_SECRET_FILE);
        fs::write(&client_key_path, [0x42_u8; 32]).expect("write inspector client key");

        let staged_dir = out.path().join("image-with-key");
        run_stage(
            ArtifactStageCommand {
                kind: StageKind::Image,
                arch: "x86-64".to_owned(),
                profile: "release-linux".to_owned(),
                out_dir: staged_dir.clone(),
                kernel,
                root_public_key: pub_a_path,
                bootfs: Some(bootfs_path),
                uefi_image: None,
                build_uefi_image: false,
                baud: 115_200,
                compiler_plugin: None,
                inspector_client_key: Some(client_key_path),
                kernel_features: vec!["linux".to_owned()],
                programs: vec!["init".to_owned(), "inspector-host".to_owned()],
                commit: Some("deadbeef".to_owned()),
            },
            None,
        )
        .expect("image with inspector client key must stage cleanly");

        let staged_key = staged_dir.join(INSPECTOR_CLIENT_SECRET_FILE);
        assert!(staged_key.is_file());
        assert_eq!(
            fs::read(&staged_key).expect("read staged key"),
            [0x42_u8; 32]
        );
        #[cfg(unix)]
        {
            let mode = fs::metadata(&staged_key)
                .expect("staged key metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, SECRET_KEY_MODE);
        }

        let manifest = read_manifest(&staged_dir).expect("read_manifest must succeed");
        assert!(
            manifest
                .files
                .iter()
                .any(|f| f == INSPECTOR_CLIENT_SECRET_FILE),
            "manifest.json must list {INSPECTOR_CLIENT_SECRET_FILE}"
        );
    }

    #[test]
    fn artifact_stage_kernel_rejects_inspector_client_key() {
        let src = TempDir::new().expect("src dir");
        let out = TempDir::new().expect("out dir");
        let kernel = src.path().join("helios");
        fs::write(&kernel, b"elf").expect("write kernel");
        let (_, pub_a) = make_signed_bootfs(&[11_u8; 32]);
        let pub_a_path = src.path().join("helios-root-public.key");
        fs::write(&pub_a_path, pub_a).expect("write pub a");
        let client_key_path = src.path().join(INSPECTOR_CLIENT_SECRET_FILE);
        fs::write(&client_key_path, [0x42_u8; 32]).expect("write client key");

        let err = run_stage(
            ArtifactStageCommand {
                kind: StageKind::Kernel,
                arch: "x86-64".to_owned(),
                profile: "release-linux".to_owned(),
                out_dir: out.path().join("kernel"),
                kernel,
                root_public_key: pub_a_path,
                bootfs: None,
                uefi_image: None,
                build_uefi_image: false,
                baud: 115_200,
                compiler_plugin: None,
                inspector_client_key: Some(client_key_path),
                kernel_features: Vec::new(),
                programs: Vec::new(),
                commit: Some("abc1234".to_owned()),
            },
            None,
        )
        .expect_err("kernel stage must reject --inspector-client-key");
        assert!(matches!(
            err,
            ArtifactStageError::UnexpectedOptionForKernel {
                option: "--inspector-client-key"
            }
        ));
    }

    #[test]
    fn artifact_stage_inspector_client_key_rejects_root_secret_and_invalid_length() {
        let src = TempDir::new().expect("src dir");
        let out = TempDir::new().expect("out dir");
        let kernel = src.path().join("helios");
        fs::write(&kernel, b"elf").expect("write kernel");
        let (bootfs_bytes, pub_a) = make_signed_bootfs(&[11_u8; 32]);
        let bootfs_path = src.path().join("helios-bootfs");
        fs::write(&bootfs_path, bootfs_bytes).expect("write bootfs");
        let pub_a_path = src.path().join("helios-root-public.key");
        fs::write(&pub_a_path, pub_a).expect("write pub a");

        // Passing helios-root-secret.key as --inspector-client-key must be rejected.
        let root_secret = src.path().join(ROOT_SECRET_FILE);
        fs::write(&root_secret, [0x99_u8; 32]).expect("write root secret");
        let err = run_stage(
            ArtifactStageCommand {
                kind: StageKind::Image,
                arch: "x86-64".to_owned(),
                profile: "release-linux".to_owned(),
                out_dir: out.path().join("reject-root-secret"),
                kernel: kernel.clone(),
                root_public_key: pub_a_path.clone(),
                bootfs: Some(bootfs_path.clone()),
                uefi_image: None,
                build_uefi_image: false,
                baud: 115_200,
                compiler_plugin: None,
                inspector_client_key: Some(root_secret),
                kernel_features: Vec::new(),
                programs: Vec::new(),
                commit: Some("abc1234".to_owned()),
            },
            None,
        )
        .expect_err("root secret key passed to --inspector-client-key must fail");
        assert!(matches!(err, ArtifactStageError::SecretKeyInput { .. }));

        // Invalid length seed file must be rejected.
        let bad_key = src.path().join("bad-client.key");
        fs::write(&bad_key, [0x11_u8; 16]).expect("write short key");
        let err = run_stage(
            ArtifactStageCommand {
                kind: StageKind::Image,
                arch: "x86-64".to_owned(),
                profile: "release-linux".to_owned(),
                out_dir: out.path().join("reject-bad-len"),
                kernel,
                root_public_key: pub_a_path,
                bootfs: Some(bootfs_path),
                uefi_image: None,
                build_uefi_image: false,
                baud: 115_200,
                compiler_plugin: None,
                inspector_client_key: Some(bad_key),
                kernel_features: Vec::new(),
                programs: Vec::new(),
                commit: Some("abc1234".to_owned()),
            },
            None,
        )
        .expect_err("non-32-byte inspector client key must fail");
        assert!(matches!(
            err,
            ArtifactStageError::InvalidInspectorClientKey { len: 16, .. }
        ));
    }
}
