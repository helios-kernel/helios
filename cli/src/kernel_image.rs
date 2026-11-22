//! The kernel images cargo linked, kept in the artifact cache so a run
//! whose kernel inputs did not change links none (#1023).
//!
//! An entry is addressed like a cached wasm (`artifact_cache`): its key is
//! what the build is, and the entry lists every file the build read with
//! its digest, which a lookup checks. The key covers the fields the
//! inspector names (the cargo command line and the environment that
//! reaches it, the profile a profile-use build reads), the trusted public
//! key the image embeds, the toolchain, cargo's configuration and the
//! lockfile entries the kernel package resolves through. The file list is
//! what cargo's dep-info files name for every unit of the build, and every
//! file of the path packages the kernel depends on, the sibling Wasmtime
//! checkout's included.
//!
//! The secret half of the root key is never an input and never stored: an
//! image carries the public key alone.

use std::collections::BTreeSet;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

use clap::Parser;
use tempfile::NamedTempFile;
use walkdir::WalkDir;

use crate::CacheArgs;
use crate::artifact_cache::{
    CacheError, EntryKind, FeatureSet, Key, KeyBuilder, lock_closure_digest, package_directories,
    package_name, workspace_inputs,
};

/// The package whose build links the kernel image: the root crate.
const KERNEL_PACKAGE_MANIFEST: &str = "Cargo.toml";

/// Why a kernel image could not be taken from the cache or stored in it.
#[derive(Debug, thiserror::Error)]
pub enum KernelImageError {
    #[error("{0}")]
    Cache(#[from] CacheError),
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
    #[error("Cargo.lock is not UTF-8: {source}")]
    LockNotUtf8 {
        #[source]
        source: std::str::Utf8Error,
    },
    #[error("failed to run `rustc -vV`: {source}")]
    SpawnRustc {
        #[source]
        source: io::Error,
    },
    #[error("`rustc -vV` failed with status {status}")]
    RustcFailed { status: ExitStatus },
    #[error("failed to list the dep-info files in {path}: {source}")]
    ListDepInfo {
        path: String,
        #[source]
        source: walkdir::Error,
    },
    #[error("{path} holds no dep-info file: the build did not run there")]
    NoDepInfo { path: String },
}

/// What addresses a kernel image in the cache.
#[derive(Parser)]
pub struct KernelImageKey {
    /// One field of the build's description, in order. The inspector
    /// names the cargo command line and the environment that reaches it.
    #[arg(long = "field", value_name = "TEXT", required = true)]
    fields: Vec<String>,
    /// The trusted root public key file the kernel build embeds.
    #[arg(long, value_name = "FILE")]
    public_key: PathBuf,
    /// The kernel image: the file a restore writes and a store reads.
    #[arg(long, value_name = "FILE")]
    image: PathBuf,
    #[command(flatten)]
    cache: CacheArgs,
}

/// Take the kernel image the cache holds for a build, when every file the
/// build read is unchanged, and write it to `--image`.
///
/// Prints `hit` when the image was written and `miss` when the build has to
/// link it; a run without a cache directory always prints `miss`.
#[derive(Parser)]
pub struct KernelImageRestore {
    #[command(flatten)]
    key: KernelImageKey,
}

/// Store the kernel image a build linked, with the files the build read.
#[derive(Parser)]
pub struct KernelImageStore {
    #[command(flatten)]
    key: KernelImageKey,
    /// The cargo target triple the image was built for.
    #[arg(long)]
    target: String,
    /// The directory cargo wrote the build into, `<target dir>/<triple>/
    /// <profile>`: it holds the dep-info file of every unit.
    #[arg(long, value_name = "DIR")]
    artifact_dir: PathBuf,
    /// The cargo target directory, whose files are outputs and never inputs.
    #[arg(long, value_name = "DIR")]
    target_dir: PathBuf,
}

pub fn restore(
    command: &KernelImageRestore,
    workspace_root: &Path,
) -> Result<(), KernelImageError> {
    let Some(cache) = command.key.cache.open()? else {
        println!("miss");
        return Ok(());
    };
    let key = key(&command.key, workspace_root)?;
    let Some(image) = cache.lookup_inputs(&key, workspace_root)? else {
        println!("miss");
        return Ok(());
    };
    write_image(&command.key.image, &image)?;
    println!("hit");
    Ok(())
}

pub fn store(command: &KernelImageStore, workspace_root: &Path) -> Result<(), KernelImageError> {
    let Some(cache) = command.key.cache.open()? else {
        return Ok(());
    };
    let key = key(&command.key, workspace_root)?;
    let image = read(&command.key.image)?;
    // Where cargo keeps a unit's dep-info depends on its build-directory
    // layout (`deps/` or `build/<package>/<hash>/out/`), so every one the
    // build wrote is found by its extension.
    let mut dep_infos = Vec::new();
    for entry in WalkDir::new(&command.artifact_dir) {
        let entry = entry.map_err(|source| KernelImageError::ListDepInfo {
            path: command.artifact_dir.display().to_string(),
            source,
        })?;
        if entry.file_type().is_file()
            && entry
                .path()
                .extension()
                .is_some_and(|extension| extension == "d")
        {
            dep_infos.push(entry.into_path());
        }
    }
    if dep_infos.is_empty() {
        return Err(KernelImageError::NoDepInfo {
            path: command.artifact_dir.display().to_string(),
        });
    }
    let excluded =
        fs::canonicalize(&command.target_dir).map_err(|source| KernelImageError::Read {
            path: command.target_dir.display().to_string(),
            source,
        })?;
    // A target directory that outlives a checkout or a toolchain holds the
    // dep-info of units this build did not run, and those name files that
    // are gone; such a unit is no input of the image.
    let mut inputs = BTreeSet::new();
    for dep_info in &dep_infos {
        match workspace_inputs(
            std::slice::from_ref(dep_info),
            workspace_root,
            &excluded,
            &[],
        ) {
            Ok(files) => inputs.extend(files),
            Err(CacheError::Resolve { .. }) => {}
            Err(error) => return Err(error.into()),
        }
    }
    inputs.extend(workspace_inputs(
        &[],
        workspace_root,
        &excluded,
        &package_directories(
            Path::new("cargo"),
            &workspace_root.join(KERNEL_PACKAGE_MANIFEST),
            &command.target,
            FeatureSet::All,
        )?,
    )?);
    let inputs = inputs.into_iter().collect::<Vec<_>>();
    cache.store_inputs(&key, workspace_root, &inputs, &image)?;
    Ok(())
}

fn key(key: &KernelImageKey, workspace_root: &Path) -> Result<Key, KernelImageError> {
    let optional = |path: PathBuf| {
        if path.is_file() {
            read(&path)
        } else {
            Ok(Vec::new())
        }
    };
    let mut builder = KeyBuilder::new(EntryKind::Kernel);
    for field in &key.fields {
        builder = builder.field(field);
    }
    let lock = read(&workspace_root.join("Cargo.lock"))?;
    let lock =
        std::str::from_utf8(&lock).map_err(|source| KernelImageError::LockNotUtf8 { source })?;
    let package = package_name(&workspace_root.join(KERNEL_PACKAGE_MANIFEST))?;
    Ok(builder
        .field(read(&key.public_key)?)
        .field(rustc_version()?)
        // Cargo reads these for every build in the workspace, and an
        // absent one is an empty one.
        .field(optional(workspace_root.join(".cargo/config.toml"))?)
        .field(optional(workspace_root.join("rust-toolchain.toml"))?)
        .field(lock_closure_digest(lock, &package)?)
        .finish())
}

fn rustc_version() -> Result<Vec<u8>, KernelImageError> {
    let output = Command::new("rustc")
        .arg("-vV")
        .output()
        .map_err(|source| KernelImageError::SpawnRustc { source })?;
    if !output.status.success() {
        return Err(KernelImageError::RustcFailed {
            status: output.status,
        });
    }
    Ok(output.stdout)
}

fn read(path: &Path) -> Result<Vec<u8>, KernelImageError> {
    fs::read(path).map_err(|source| KernelImageError::Read {
        path: path.display().to_string(),
        source,
    })
}

/// Writes `image` to `path` through a file beside it, renamed into place,
/// and leaves a file that already holds it alone.
fn write_image(path: &Path, image: &[u8]) -> Result<(), KernelImageError> {
    if fs::read(path).ok().as_deref() == Some(image) {
        return Ok(());
    }
    let write_error = |source| KernelImageError::Write {
        path: path.display().to_string(),
        source,
    };
    let directory = path.parent().unwrap_or(Path::new("."));
    fs::create_dir_all(directory).map_err(write_error)?;
    let mut file = NamedTempFile::new_in(directory).map_err(write_error)?;
    file.write_all(image).map_err(write_error)?;
    file.persist(path)
        .map_err(|error| write_error(error.error))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_image_already_in_place_is_left_alone() {
        let directory = tempfile::tempdir().expect("a directory");
        let path = directory.path().join("helios-kernel");
        write_image(&path, b"image").expect("the image is written");
        let modified = fs::metadata(&path)
            .and_then(|m| m.modified())
            .expect("an mtime");
        write_image(&path, b"image").expect("the same image is accepted");
        assert_eq!(
            fs::metadata(&path)
                .and_then(|m| m.modified())
                .expect("an mtime"),
            modified
        );
        write_image(&path, b"other").expect("another image replaces it");
        assert_eq!(fs::read(&path).expect("the image"), b"other");
    }
}
