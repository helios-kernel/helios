//! The kernel image a build links, kept in the artifact cache (#1023).
//!
//! `helios-cli` owns the cache: it addresses an entry by what the build is
//! and checks every file the build read before it hands an image back. This
//! module says what the build is. The cargo command line, the environment
//! that reaches cargo and the profile a profile-use build reads are the
//! fields it names; the trusted public key the image embeds is a file the
//! cache reads. A job without `HELIOS_ARTIFACT_CACHE` links every image
//! itself.
//!
//! An image is stored only after the root-secret scan passed, so the cache
//! never holds an image that carries the secret.

use std::ffi::OsStr;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

use helios_profdata::ProfileUseError;

/// The environment variable that names the cache directory, the one
/// `helios-cli` reads.
const CACHE_DIR_ENV: &str = "HELIOS_ARTIFACT_CACHE";

/// What `helios-cli kernel-image-restore` prints when it wrote the image.
const HIT: &str = "hit";
/// What it prints when the build has to link the image.
const MISS: &str = "miss";

/// The environment variables cargo and the kernel's build script read that
/// change the image: cargo's profile and build configuration, the target's
/// rustflags, the compiler wrapper and the watchdog self-test switches.
const ENVIRONMENT_PREFIXES: [&str; 3] = ["CARGO_PROFILE_", "CARGO_BUILD_", "CARGO_TARGET_"];
const ENVIRONMENT_NAMES: [&str; 8] = [
    "CARGO_ENCODED_RUSTFLAGS",
    "RUSTFLAGS",
    "RUSTC",
    "RUSTC_WRAPPER",
    "RUSTC_WORKSPACE_WRAPPER",
    "HELIOS_BUILD_TARGET",
    "HELIOS_WATCHDOG_SELF_TEST",
    "HELIOS_WATCHDOG_SELF_TEST_DELAY_MS",
];

/// The variable of the kernel build that names the public key file by a
/// path, which is a field of its own: its content is what matters.
const PUBLIC_KEY_ENV: &str = "HELIOS_KERNEL_ROOT_PUBLIC_KEY";

#[derive(Debug, thiserror::Error)]
pub(crate) enum KernelImageCacheError {
    #[error("failed to run helios-cli {subcommand}: {source}")]
    Spawn {
        subcommand: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("helios-cli {subcommand} exited with status {status}")]
    Exited {
        subcommand: &'static str,
        status: ExitStatus,
    },
    #[error("helios-cli {subcommand} answered `{answer}`, not `{HIT}` or `{MISS}`")]
    Answer {
        subcommand: &'static str,
        answer: String,
    },
    #[error("{0}")]
    Profile(#[from] ProfileUseError),
}

/// One kernel build's entry in the cache.
pub(crate) struct KernelImageCache {
    cli: PathBuf,
    repo_root: PathBuf,
    fields: Vec<String>,
    public_key: PathBuf,
    image: PathBuf,
    target: &'static str,
    target_dir: PathBuf,
}

/// What names a build's entry, besides the cargo command itself.
pub(crate) struct KernelImageBuild<'a> {
    /// The `helios-cli` that owns the cache.
    pub cli: PathBuf,
    pub repo_root: &'a Path,
    /// The cargo invocation that links the image, as it will run.
    pub cargo: &'a Command,
    /// The profile a profile-use build reads.
    pub profile: Option<&'a Path>,
    /// The public key file the image embeds.
    pub public_key: PathBuf,
    pub image: PathBuf,
    pub target: &'static str,
    /// The cargo target directory the build writes into.
    pub target_dir: PathBuf,
}

impl KernelImageCache {
    /// The entry for `build`, or `None` when this job keeps no cache.
    pub(crate) fn open(build: KernelImageBuild<'_>) -> Result<Option<Self>, KernelImageCacheError> {
        if std::env::var_os(CACHE_DIR_ENV).is_none() {
            return Ok(None);
        }
        let mut fields = vec![build.cargo.get_program().to_string_lossy().into_owned()];
        fields.extend(build.cargo.get_args().map(lossy));
        for (name, value) in build.cargo.get_envs() {
            if name != OsStr::new(PUBLIC_KEY_ENV) {
                fields.push(format!(
                    "{}={}",
                    lossy(name),
                    value.map_or_else(String::new, lossy)
                ));
            }
        }
        let mut inherited = std::env::vars_os()
            .filter_map(|(name, value)| Some((name.into_string().ok()?, value.into_string().ok()?)))
            .filter(|(name, _)| is_build_environment(name))
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>();
        inherited.sort();
        fields.extend(inherited);
        // What the profile holds, not where it lies: a profile-use build
        // is the same build wherever the profile was fetched to.
        if let Some(profile) = build.profile {
            fields.push(format!(
                "profile={}",
                helios_profdata::digest(profile)?.as_str()
            ));
        }
        Ok(Some(Self {
            cli: build.cli,
            repo_root: build.repo_root.to_path_buf(),
            fields,
            public_key: build.public_key,
            image: build.image,
            target: build.target,
            target_dir: build.target_dir,
        }))
    }

    /// Writes the image the cache holds for this build to its place and
    /// reports whether it held one.
    pub(crate) fn restore(&self) -> Result<bool, KernelImageCacheError> {
        let subcommand = "kernel-image-restore";
        let output = self
            .command(subcommand)
            .output()
            .map_err(|source| KernelImageCacheError::Spawn { subcommand, source })?;
        if !output.status.success() {
            eprint!("{}", String::from_utf8_lossy(&output.stderr));
            return Err(KernelImageCacheError::Exited {
                subcommand,
                status: output.status,
            });
        }
        match String::from_utf8_lossy(&output.stdout).trim() {
            HIT => Ok(true),
            MISS => Ok(false),
            answer => Err(KernelImageCacheError::Answer {
                subcommand,
                answer: answer.to_owned(),
            }),
        }
    }

    /// Stores the image the build linked, with the files it read.
    pub(crate) fn store(&self) -> Result<(), KernelImageCacheError> {
        let subcommand = "kernel-image-store";
        let artifact_dir = self
            .image
            .parent()
            .expect("a kernel image lies in its profile's directory");
        let status = self
            .command(subcommand)
            .arg("--target")
            .arg(self.target)
            .arg("--artifact-dir")
            .arg(artifact_dir)
            .arg("--target-dir")
            .arg(&self.target_dir)
            .status()
            .map_err(|source| KernelImageCacheError::Spawn { subcommand, source })?;
        if status.success() {
            Ok(())
        } else {
            Err(KernelImageCacheError::Exited { subcommand, status })
        }
    }

    fn command(&self, subcommand: &'static str) -> Command {
        let mut command = Command::new(&self.cli);
        command
            .current_dir(&self.repo_root)
            .arg(subcommand)
            .arg("--public-key")
            .arg(&self.public_key)
            .arg("--image")
            .arg(&self.image);
        for field in &self.fields {
            command.arg("--field").arg(field);
        }
        command
    }
}

fn lossy(value: impl AsRef<OsStr>) -> String {
    value.as_ref().to_string_lossy().into_owned()
}

fn is_build_environment(name: &str) -> bool {
    ENVIRONMENT_NAMES.contains(&name)
        || ENVIRONMENT_PREFIXES
            .iter()
            .any(|prefix| name.starts_with(prefix))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_variables_that_change_an_image_are_part_of_its_build() {
        for name in [
            "RUSTFLAGS",
            "CARGO_ENCODED_RUSTFLAGS",
            "CARGO_PROFILE_KERNEL_RELEASE_LTO",
            "CARGO_TARGET_X86_64_UNKNOWN_NONE_RUSTFLAGS",
            "HELIOS_WATCHDOG_SELF_TEST",
            "HELIOS_WATCHDOG_SELF_TEST_DELAY_MS",
        ] {
            assert!(is_build_environment(name), "{name}");
        }
        for name in ["PATH", "HOME", "GITHUB_TOKEN", "HELIOS_ARTIFACT_CACHE"] {
            assert!(!is_build_environment(name), "{name}");
        }
    }

    #[test]
    fn a_job_without_a_cache_directory_keeps_no_entry() {
        let cargo = Command::new("cargo");
        // The variable is the job's, set before any test runs; a test that
        // sets it would race the others, so it is only read here.
        if std::env::var_os(CACHE_DIR_ENV).is_some() {
            return;
        }
        let entry = KernelImageCache::open(KernelImageBuild {
            cli: PathBuf::from("helios-cli"),
            repo_root: Path::new("."),
            cargo: &cargo,
            profile: None,
            public_key: PathBuf::from("helios-root-public.key"),
            image: PathBuf::from("helios-kernel"),
            target: "x86_64-unknown-none",
            target_dir: PathBuf::from("target"),
        })
        .expect("no profile to read");
        assert!(entry.is_none());
    }
}
