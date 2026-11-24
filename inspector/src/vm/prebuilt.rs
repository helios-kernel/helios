//! Prebuilt CI artifact resolution and validation for `helios-inspector vm` (#1218).
//!
//! Supports three tiers selected via `--prebuilt [image|kernel|userspace]`:
//! - `image`: reuses a prebuilt kernel ELF, signed `helios-bootfs`, and optional
//!   Limine UEFI disk image with zero local compilation.
//! - `userspace`: reuses prebuilt guest wasm (`helios-wasm-{profile}`) via
//!   `kernel-prebuild --prebuilt-wasm`, compiling only the local kernel and
//!   bootfs.
//! - `kernel`: reuses a prebuilt kernel ELF while verifying root-key
//!   compatibility fail-fast against either a supplied `--bootfs` or the secret
//!   key that will sign a locally built bootfs.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

use clap::ValueEnum;
use ed25519_dalek::{SigningKey, VerifyingKey};
use helios_artifact::bootfs::{self, BootfsError, Fingerprint};
use helios_workspace_root::prebuilt_manifest::{
    BOOTFS_IMAGE_FILE, KERNEL_IMAGE_FILE, PrebuiltArtifactKind, PrebuiltManifest,
    PrebuiltManifestError, UEFI_DISK_IMAGE_FILE, artifact_profile_label, read_manifest,
    read_root_public_key, sha256_hex,
};
use helios_workspace_root::root_key::{
    ROOT_PUBLIC_FILE, ROOT_SECRET_FILE, RootSecretReadError, read_root_secret_seed,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::{
    DEFAULT_BAUD, GuestProgramsProfile, KernelBuildProfile, ToolDiscoveryError, VmArch,
    discover_helios_cli,
};

/// Canonical hyphenated architecture label used in prebuilt artifact names and
/// `manifest.json` (`x86-64`, `aarch64`, `riscv64`).
fn artifact_arch(arch: VmArch) -> &'static str {
    match arch {
        VmArch::X86_64 => "x86-64",
        VmArch::Aarch64 => "aarch64",
        VmArch::Riscv64 => "riscv64",
    }
}

/// Which prebuilt artifact tier `helios-inspector vm --prebuilt` consumes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum VmPrebuiltMode {
    /// Full bootable image (`helios-image-{arch}-{profile}`): kernel + signed
    /// bootfs + optional Limine UEFI disk image. Skips all local builds.
    Image,
    /// Prebuilt kernel ELF (`helios-kernel-{arch}-{profile}`) + root public
    /// key. Requires a matching `--bootfs` or matching `--root-secret-key`.
    Kernel,
    /// Prebuilt architecture-independent guest wasm (`helios-wasm-{profile}`).
    /// Feeds `--prebuilt-wasm` to `kernel-prebuild` while building the kernel
    /// locally.
    Userspace,
}

impl From<VmPrebuiltMode> for PrebuiltArtifactKind {
    fn from(value: VmPrebuiltMode) -> Self {
        match value {
            VmPrebuiltMode::Image => Self::Image,
            VmPrebuiltMode::Kernel => Self::Kernel,
            VmPrebuiltMode::Userspace => Self::Userspace,
        }
    }
}

/// How the caller specified the prebuilt artifact source.
#[derive(Debug, Clone)]
pub(crate) struct PrebuiltRequest<'a> {
    pub(crate) mode: VmPrebuiltMode,
    pub(crate) arch: VmArch,
    /// Explicit base profile (`"release"` or `"debug"`) when the caller passed
    /// `--release`, `--debug`, `--kernel-debug`, or `--guest-programs-profile`.
    /// `None` lets `helios-cli artifact-fetch` prefer `release` over `debug`.
    pub(crate) explicit_profile: Option<&'a str>,
    pub(crate) kernel_features: &'a [String],
    pub(crate) boot_programs: &'a [String],
    pub(crate) baud: u32,
    pub(crate) run_id: Option<u64>,
    pub(crate) git_ref: Option<&'a str>,
    pub(crate) dir: Option<&'a Path>,
    pub(crate) host_build_kind: KernelBuildProfile,
}

/// Validated prebuilt artifact paths ready to wire into `ResolvedVmCommand`.
#[derive(Debug, Clone)]
pub(crate) enum ResolvedPrebuilt {
    Image {
        kernel: PathBuf,
        bootfs: PathBuf,
        uefi_image: Option<PathBuf>,
    },
    Kernel {
        kernel: PathBuf,
        root_public_key: [u8; 32],
    },
    Userspace {
        dir: PathBuf,
        guest_profile: GuestProgramsProfile,
    },
}

/// Output of `helios-cli artifact-fetch --json`.
#[derive(Debug, Deserialize)]
struct FetchedArtifactReport {
    dir: PathBuf,
}

#[derive(Debug, Error)]
pub(crate) enum PrebuiltError {
    #[error("{0}")]
    Manifest(#[from] PrebuiltManifestError),
    #[error("{0}")]
    Tool(#[from] ToolDiscoveryError),
    #[error("failed to spawn `helios-cli artifact-fetch`: {source}")]
    SpawnFetch {
        #[source]
        source: io::Error,
    },
    #[error("`helios-cli artifact-fetch` failed ({status}): {stderr}")]
    FetchFailed { status: String, stderr: String },
    #[error("failed to decode `helios-cli artifact-fetch --json` output: {source}")]
    DecodeFetchReport {
        #[source]
        source: serde_json::Error,
    },
    #[error("prebuilt directory {dir} holds a {found} artifact, expected {expected}")]
    KindMismatch {
        dir: String,
        expected: PrebuiltArtifactKind,
        found: PrebuiltArtifactKind,
    },
    #[error(
        "prebuilt {kind} artifact in {dir} targets architecture {found:?}, expected {expected:?}"
    )]
    ArchMismatch {
        kind: PrebuiltArtifactKind,
        dir: String,
        expected: String,
        found: Option<String>,
    },
    #[error("prebuilt {kind} artifact in {dir} has profile {found:?}, expected {expected:?}")]
    ProfileMismatch {
        kind: PrebuiltArtifactKind,
        dir: String,
        expected: String,
        found: String,
    },
    #[error(
        "prebuilt {kind} artifact in {dir} is missing required kernel feature(s): {missing} \
         (manifest features: {present})"
    )]
    MissingKernelFeatures {
        kind: PrebuiltArtifactKind,
        dir: String,
        missing: String,
        present: String,
    },
    #[error("prebuilt image in {dir} does not include requested --boot-program(s): {missing}")]
    MissingBootPrograms { dir: String, missing: String },
    #[error("prebuilt {kind} artifact in {dir} is missing required file {file}")]
    MissingRequiredFile {
        kind: PrebuiltArtifactKind,
        dir: String,
        file: String,
    },
    #[error("prebuilt userspace artifact in {dir} has unsupported profile {profile:?}")]
    UnsupportedUserspaceProfile { dir: String, profile: String },
    #[error(
        "prebuilt {kind} artifact in {dir} has root public key SHA-256 {actual}, \
         which disagrees with manifest.json ({expected})"
    )]
    RootPublicKeyDigestMismatch {
        kind: PrebuiltArtifactKind,
        dir: String,
        expected: String,
        actual: String,
    },
    #[error("--prebuilt {mode} cannot be combined with --profile-generate or --profile-use")]
    ConflictsWithPgo { mode: &'static str },
    #[error("--prebuilt {mode} cannot be combined with explicit {flag}")]
    ConflictsWithExplicitPath {
        mode: &'static str,
        flag: &'static str,
    },
    #[error("failed to read bootfs {path}: {source}")]
    ReadBootfs {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("supplied --bootfs {path} failed signature verification: {source}")]
    BootfsSignatureInvalid {
        path: String,
        #[source]
        source: BootfsError,
    },
    #[error(
        "supplied --bootfs {bootfs} was signed by root key {bootfs_signer}, but the prebuilt \
         kernel embeds root key {kernel_key}; pass a matching --bootfs or use `--prebuilt image`"
    )]
    BootfsRootKeyMismatch {
        bootfs: String,
        bootfs_signer: Fingerprint,
        kernel_key: Fingerprint,
    },
    #[error("failed to read root secret key {path}: {source}")]
    ReadRootSecretKey {
        path: String,
        #[source]
        source: RootSecretReadError,
    },
    #[error(
        "--root-secret-key {path} derives public key {secret_public}, which does not match the \
         prebuilt kernel's embedded root key {kernel_key}; pass the matching --root-secret-key, \
         a matching --bootfs, or use `--prebuilt image`"
    )]
    RootSecretKeyMismatch {
        path: String,
        secret_public: Fingerprint,
        kernel_key: Fingerprint,
    },
    #[error(
        "prebuilt kernel embeds root public key {kernel_key}, which a locally generated \
         development key cannot match; pass `--root-secret-key <PATH>` matching {kernel_key}, \
         pass a matching `--bootfs <PATH>`, or use `--prebuilt image` to boot the matching \
         prebuilt kernel and bootfs together"
    )]
    KernelRootKeyUnavailable { kernel_key: Fingerprint },
}

/// Resolves and validates the requested prebuilt artifact directory.
pub(crate) fn resolve_prebuilt(
    request: &PrebuiltRequest<'_>,
) -> Result<ResolvedPrebuilt, PrebuiltError> {
    let dir = match request.dir {
        Some(dir) => dir.to_path_buf(),
        None => fetch_via_cli(request)?,
    };
    validate_prebuilt_dir(&dir, request)
}

fn fetch_via_cli(request: &PrebuiltRequest<'_>) -> Result<PathBuf, PrebuiltError> {
    let cli = discover_helios_cli(request.host_build_kind)?;
    let kind: PrebuiltArtifactKind = request.mode.into();
    let mut cmd = Command::new(&cli);
    cmd.arg("artifact-fetch")
        .arg("--kind")
        .arg(kind.as_str())
        .arg("--json");

    match request.mode {
        VmPrebuiltMode::Image | VmPrebuiltMode::Kernel => {
            cmd.arg("--arch").arg(artifact_arch(request.arch));
            if let Some(base) = request.explicit_profile {
                let label = artifact_profile_label(base, request.kernel_features, None);
                cmd.arg("--profile").arg(label);
            } else {
                for feature in request.kernel_features {
                    cmd.arg("--kernel-feature").arg(feature);
                }
            }
        }
        VmPrebuiltMode::Userspace => {
            if let Some(profile) = request.explicit_profile {
                cmd.arg("--profile").arg(profile);
            }
        }
    }

    if let Some(run_id) = request.run_id {
        cmd.arg("--run").arg(run_id.to_string());
    }
    if let Some(git_ref) = request.git_ref {
        cmd.arg("--ref").arg(git_ref);
    }

    let output = cmd
        .output()
        .map_err(|source| PrebuiltError::SpawnFetch { source })?;
    if !output.status.success() {
        return Err(PrebuiltError::FetchFailed {
            status: output.status.to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        });
    }
    let report: FetchedArtifactReport = serde_json::from_slice(&output.stdout)
        .map_err(|source| PrebuiltError::DecodeFetchReport { source })?;
    Ok(report.dir)
}

/// Validates an already-materialized prebuilt artifact directory against the
/// caller's requested tier, architecture, profile, kernel features and boot
/// programs.
pub(crate) fn validate_prebuilt_dir(
    dir: &Path,
    request: &PrebuiltRequest<'_>,
) -> Result<ResolvedPrebuilt, PrebuiltError> {
    let manifest = read_manifest(dir)?;
    let expected_kind: PrebuiltArtifactKind = request.mode.into();
    if manifest.kind != expected_kind {
        return Err(PrebuiltError::KindMismatch {
            dir: dir.display().to_string(),
            expected: expected_kind,
            found: manifest.kind,
        });
    }

    match request.mode {
        VmPrebuiltMode::Image => {
            validate_arch_profile_features(dir, &manifest, request)?;
            if !request.boot_programs.is_empty()
                && let Some(programs) = &manifest.programs
            {
                let missing = programs.missing(request.boot_programs);
                if !missing.is_empty() {
                    return Err(PrebuiltError::MissingBootPrograms {
                        dir: dir.display().to_string(),
                        missing: missing.join(", "),
                    });
                }
            }
            let kernel = require_file(dir, expected_kind, KERNEL_IMAGE_FILE)?;
            let bootfs = require_file(dir, expected_kind, BOOTFS_IMAGE_FILE)?;
            let uefi_path = dir.join(UEFI_DISK_IMAGE_FILE);
            let uefi_image = (uefi_path.is_file()
                && manifest.baud.unwrap_or(DEFAULT_BAUD) == request.baud)
                .then_some(uefi_path);
            Ok(ResolvedPrebuilt::Image {
                kernel,
                bootfs,
                uefi_image,
            })
        }
        VmPrebuiltMode::Kernel => {
            validate_arch_profile_features(dir, &manifest, request)?;
            let kernel = require_file(dir, expected_kind, KERNEL_IMAGE_FILE)?;
            let pubkey_path = require_file(dir, expected_kind, ROOT_PUBLIC_FILE)?;
            let root_public_key = read_root_public_key(&pubkey_path)?;
            if let Some(expected_digest) = &manifest.root_public_key_sha256 {
                let actual = sha256_hex(&root_public_key);
                if &actual != expected_digest {
                    return Err(PrebuiltError::RootPublicKeyDigestMismatch {
                        kind: expected_kind,
                        dir: dir.display().to_string(),
                        expected: expected_digest.clone(),
                        actual,
                    });
                }
            }
            Ok(ResolvedPrebuilt::Kernel {
                kernel,
                root_public_key,
            })
        }
        VmPrebuiltMode::Userspace => {
            if let Some(expected) = request.explicit_profile
                && manifest.profile != expected
            {
                return Err(PrebuiltError::ProfileMismatch {
                    kind: expected_kind,
                    dir: dir.display().to_string(),
                    expected: expected.to_owned(),
                    found: manifest.profile,
                });
            }
            let guest_profile = match manifest.profile.as_str() {
                "debug" => GuestProgramsProfile::Debug,
                "release" => GuestProgramsProfile::Release,
                other => {
                    return Err(PrebuiltError::UnsupportedUserspaceProfile {
                        dir: dir.display().to_string(),
                        profile: other.to_owned(),
                    });
                }
            };
            Ok(ResolvedPrebuilt::Userspace {
                dir: dir.to_path_buf(),
                guest_profile,
            })
        }
    }
}

fn validate_arch_profile_features(
    dir: &Path,
    manifest: &PrebuiltManifest,
    request: &PrebuiltRequest<'_>,
) -> Result<(), PrebuiltError> {
    let expected_arch = artifact_arch(request.arch);
    if manifest.arch.as_deref() != Some(expected_arch) {
        return Err(PrebuiltError::ArchMismatch {
            kind: manifest.kind,
            dir: dir.display().to_string(),
            expected: expected_arch.to_owned(),
            found: manifest.arch.clone(),
        });
    }
    let missing_features: Vec<&str> = request
        .kernel_features
        .iter()
        .filter(|feature| !manifest.kernel_features.iter().any(|item| item == *feature))
        .map(String::as_str)
        .collect();
    if !missing_features.is_empty() {
        return Err(PrebuiltError::MissingKernelFeatures {
            kind: manifest.kind,
            dir: dir.display().to_string(),
            missing: missing_features.join(", "),
            present: if manifest.kernel_features.is_empty() {
                "(none)".to_owned()
            } else {
                manifest.kernel_features.join(", ")
            },
        });
    }
    if let Some(base) = request.explicit_profile {
        let expected_profile = artifact_profile_label(base, request.kernel_features, None);
        if manifest.profile != expected_profile {
            return Err(PrebuiltError::ProfileMismatch {
                kind: manifest.kind,
                dir: dir.display().to_string(),
                expected: expected_profile,
                found: manifest.profile.clone(),
            });
        }
    }
    Ok(())
}

fn require_file(
    dir: &Path,
    kind: PrebuiltArtifactKind,
    name: &str,
) -> Result<PathBuf, PrebuiltError> {
    let path = dir.join(name);
    if path.is_file() {
        Ok(path)
    } else {
        Err(PrebuiltError::MissingRequiredFile {
            kind,
            dir: dir.display().to_string(),
            file: name.to_owned(),
        })
    }
}

/// Checks root-key compatibility for `--prebuilt kernel` BEFORE building or
/// booting QEMU.
///
/// Returns `true` when an explicit `--bootfs` matches the prebuilt kernel's
/// embedded root public key (so nothing needs to be built at all), or `false`
/// when a matching root secret key is available to sign a fresh local bootfs.
pub(crate) fn verify_kernel_root_key_compatibility(
    kernel_root_public_key: &[u8; 32],
    explicit_bootfs: Option<&Path>,
    explicit_root_secret_key: Option<&Path>,
    default_prebuild_dir: Option<&Path>,
) -> Result<bool, PrebuiltError> {
    let kernel_fp = Fingerprint::of(kernel_root_public_key);
    if let Some(bootfs) = explicit_bootfs {
        let bytes = fs::read(bootfs).map_err(|source| PrebuiltError::ReadBootfs {
            path: bootfs.display().to_string(),
            source,
        })?;
        let signer = bootfs::verified_signer(&bytes).map_err(|source| {
            PrebuiltError::BootfsSignatureInvalid {
                path: bootfs.display().to_string(),
                source,
            }
        })?;
        if &signer != kernel_root_public_key {
            return Err(PrebuiltError::BootfsRootKeyMismatch {
                bootfs: bootfs.display().to_string(),
                bootfs_signer: Fingerprint::of(&signer),
                kernel_key: kernel_fp,
            });
        }
        return Ok(true);
    }

    if let Some(secret_path) = explicit_root_secret_key {
        let seed = read_root_secret_seed(secret_path).map_err(|source| {
            PrebuiltError::ReadRootSecretKey {
                path: secret_path.display().to_string(),
                source,
            }
        })?;
        let derived = VerifyingKey::from(&SigningKey::from_bytes(&seed)).to_bytes();
        if &derived != kernel_root_public_key {
            return Err(PrebuiltError::RootSecretKeyMismatch {
                path: secret_path.display().to_string(),
                secret_public: Fingerprint::of(&derived),
                kernel_key: kernel_fp,
            });
        }
        return Ok(false);
    }

    if let Some(prebuild_dir) = default_prebuild_dir {
        let local_secret = prebuild_dir.join(ROOT_SECRET_FILE);
        if local_secret.is_file()
            && let Ok(seed) = read_root_secret_seed(&local_secret)
        {
            let derived = VerifyingKey::from(&SigningKey::from_bytes(&seed)).to_bytes();
            if &derived == kernel_root_public_key {
                return Ok(false);
            }
        }
    }

    Err(PrebuiltError::KernelRootKeyUnavailable {
        kernel_key: kernel_fp,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use helios_artifact::bootfs::{EntryKind, WriteEntry, sign_image, write_image};
    use helios_workspace_root::prebuilt_manifest::{
        PREBUILT_SCHEMA_VERSION, PrebuiltPrograms, write_manifest,
    };
    use helios_workspace_root::root_key::SECRET_KEY_MODE;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    fn make_keypair(seed: [u8; 32]) -> ([u8; 32], [u8; 32]) {
        let signing = SigningKey::from_bytes(&seed);
        let public = VerifyingKey::from(&signing).to_bytes();
        (seed, public)
    }

    fn write_secret_file(path: &Path, seed: &[u8; 32]) {
        fs::write(path, seed).expect("write secret");
        fs::set_permissions(path, fs::Permissions::from_mode(SECRET_KEY_MODE)).expect("chmod 600");
    }

    fn make_signed_bootfs(seed: &[u8; 32]) -> Vec<u8> {
        let signing = SigningKey::from_bytes(seed);
        let body = write_image(&[
            WriteEntry {
                kind: EntryKind::InitComponent,
                path: "bin/init",
                data: b"init",
                modified_nanos: 0,
            },
            WriteEntry {
                kind: EntryKind::InitArgv0,
                path: "/bin/init",
                data: &[],
                modified_nanos: 0,
            },
        ]);
        sign_image(body, &signing)
    }

    fn write_image_dir(dir: &Path, include_uefi: bool, programs: PrebuiltPrograms) {
        let (_, pubkey) = make_keypair([5_u8; 32]);
        fs::write(dir.join(KERNEL_IMAGE_FILE), b"elf").expect("write kernel");
        fs::write(dir.join(BOOTFS_IMAGE_FILE), make_signed_bootfs(&[5_u8; 32]))
            .expect("write bootfs");
        fs::write(dir.join(ROOT_PUBLIC_FILE), pubkey).expect("write pubkey");
        let mut files = vec![
            KERNEL_IMAGE_FILE.to_owned(),
            BOOTFS_IMAGE_FILE.to_owned(),
            ROOT_PUBLIC_FILE.to_owned(),
        ];
        if include_uefi {
            fs::write(dir.join(UEFI_DISK_IMAGE_FILE), b"uefi").expect("write uefi");
            files.push(UEFI_DISK_IMAGE_FILE.to_owned());
        }
        write_manifest(
            dir,
            &PrebuiltManifest {
                schema_version: PREBUILT_SCHEMA_VERSION,
                kind: PrebuiltArtifactKind::Image,
                commit: Some("0123456789abcdef".to_owned()),
                arch: Some("x86-64".to_owned()),
                profile: "release-linux".to_owned(),
                kernel_features: vec!["linux".to_owned()],
                programs: Some(programs),
                files,
                root_public_key_sha256: Some(sha256_hex(&pubkey)),
                baud: include_uefi.then_some(DEFAULT_BAUD),
            },
        )
        .expect("write manifest");
    }

    #[test]
    fn image_validation_resolves_paths_and_rejects_missing_program_or_feature() {
        let dir = TempDir::new().expect("temp dir");
        write_image_dir(
            dir.path(),
            true,
            PrebuiltPrograms::Subset(vec!["debugger".to_owned(), "init".to_owned()]),
        );

        let features = vec!["linux".to_owned()];
        let programs = vec!["debugger".to_owned()];
        let request = PrebuiltRequest {
            mode: VmPrebuiltMode::Image,
            arch: VmArch::X86_64,
            explicit_profile: Some("release"),
            kernel_features: &features,
            boot_programs: &programs,
            baud: DEFAULT_BAUD,
            run_id: None,
            git_ref: None,
            dir: Some(dir.path()),
            host_build_kind: KernelBuildProfile::Release,
        };
        let resolved = validate_prebuilt_dir(dir.path(), &request).expect("valid image");
        let ResolvedPrebuilt::Image {
            kernel,
            bootfs,
            uefi_image,
        } = resolved
        else {
            panic!("expected Image");
        };
        assert_eq!(kernel, dir.path().join(KERNEL_IMAGE_FILE));
        assert_eq!(bootfs, dir.path().join(BOOTFS_IMAGE_FILE));
        assert_eq!(uefi_image, Some(dir.path().join(UEFI_DISK_IMAGE_FILE)));

        // Different baud skips the prebuilt UEFI disk image so Limine rebuilds with the new baud.
        let mut custom_baud = request.clone();
        custom_baud.baud = 9600;
        let ResolvedPrebuilt::Image { uefi_image, .. } =
            validate_prebuilt_dir(dir.path(), &custom_baud).expect("custom baud valid")
        else {
            panic!("expected Image");
        };
        assert!(uefi_image.is_none());

        // Requesting a boot program not in the subset fails fast.
        let missing_prog = vec!["cpu".to_owned()];
        let mut bad_prog = request.clone();
        bad_prog.boot_programs = &missing_prog;
        let err = validate_prebuilt_dir(dir.path(), &bad_prog).expect_err("missing program fails");
        assert!(matches!(err, PrebuiltError::MissingBootPrograms { .. }));

        // Wrong arch fails fast.
        let mut bad_arch = request;
        bad_arch.arch = VmArch::Aarch64;
        let err = validate_prebuilt_dir(dir.path(), &bad_arch).expect_err("wrong arch fails");
        assert!(matches!(err, PrebuiltError::ArchMismatch { .. }));
    }

    #[test]
    fn kernel_root_key_compatibility_enforces_match_before_boot() {
        let dir = TempDir::new().expect("temp dir");
        let (seed_a, pub_a) = make_keypair([1_u8; 32]);
        let (seed_b, _) = make_keypair([2_u8; 32]);

        let bootfs_a = dir.path().join("bootfs-a");
        let bootfs_b = dir.path().join("bootfs-b");
        fs::write(&bootfs_a, make_signed_bootfs(&seed_a)).expect("write bootfs a");
        fs::write(&bootfs_b, make_signed_bootfs(&seed_b)).expect("write bootfs b");

        let secret_a = dir.path().join("secret-a.key");
        let secret_b = dir.path().join("secret-b.key");
        write_secret_file(&secret_a, &seed_a);
        write_secret_file(&secret_b, &seed_b);

        // Matching bootfs -> no build needed (true).
        assert!(
            verify_kernel_root_key_compatibility(&pub_a, Some(&bootfs_a), None, None)
                .expect("matching bootfs succeeds")
        );

        // Mismatched bootfs -> fail fast.
        let err = verify_kernel_root_key_compatibility(&pub_a, Some(&bootfs_b), None, None)
            .expect_err("mismatched bootfs fails");
        assert!(matches!(err, PrebuiltError::BootfsRootKeyMismatch { .. }));

        // Matching root secret key -> local bootfs build allowed (false).
        assert!(
            !verify_kernel_root_key_compatibility(&pub_a, None, Some(&secret_a), None)
                .expect("matching secret key succeeds")
        );

        // Mismatched root secret key -> fail fast.
        let err = verify_kernel_root_key_compatibility(&pub_a, None, Some(&secret_b), None)
            .expect_err("mismatched secret key fails");
        assert!(matches!(err, PrebuiltError::RootSecretKeyMismatch { .. }));

        // Neither bootfs nor matching secret key -> fail fast explaining alternatives.
        let err = verify_kernel_root_key_compatibility(&pub_a, None, None, Some(dir.path()))
            .expect_err("missing key fails fast");
        assert!(matches!(
            err,
            PrebuiltError::KernelRootKeyUnavailable { .. }
        ));
    }
}
