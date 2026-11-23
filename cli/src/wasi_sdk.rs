//! Pinned `wasi-sdk` download, verification, and BoringSSL cross-compilation
//! environment for `wasm32-wasip3` guest programs (`[package.metadata.helios]
//! boringssl = true`).
//!
//! Honors an existing `WASI_SDK_PATH` after verifying its required toolchain
//! and sysroot files; otherwise fetches and SHA-256-verifies the pinned
//! official `WebAssembly/wasi-sdk` release tarball into
//! `<workspace_root>/target/wasi-sdk-34`.

use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};

/// The pinned upstream `WebAssembly/wasi-sdk` release tag.
pub const WASI_SDK_TAG: &str = "wasi-sdk-34";

/// Environment variable overriding the `wasi-sdk` installation directory.
pub const WASI_SDK_PATH_ENV: &str = "WASI_SDK_PATH";

/// Embedded CMake toolchain file for cross-compiling BoringSSL to
/// single-threaded WASI.
pub const BORINGSSL_TOOLCHAIN_CMAKE: &str = include_str!("wasi-boringssl.cmake");

/// File name materialized inside a target directory for CMake.
const TOOLCHAIN_FILE_NAME: &str = "wasi-boringssl.cmake";

/// Stamp written inside the managed `wasi-sdk` directory once extraction and
/// SHA-256 verification succeed.
const STAMP_FILE_NAME: &str = ".wasi-sdk-sha256";

const RELEASE_BASE_URL: &str =
    "https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-34";

/// Single-threaded WASI BoringSSL preprocessor definitions passed to `bindgen`.
const BORINGSSL_BINDGEN_DEFS: &str = "-fvisibility=default -DOPENSSL_NO_ASM -DOPENSSL_NO_SOCK \
     -DOPENSSL_NO_POSIX_IO -DOPENSSL_NO_THREADS_CORRUPT_MEMORY_AND_LEAK_SECRETS_IF_THREADED";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct HostArchive {
    filename: &'static str,
    sha256: &'static str,
}

impl HostArchive {
    fn url(self) -> String {
        format!("{RELEASE_BASE_URL}/{}", self.filename)
    }
}

/// Official `wasi-sdk-34` release archive and SHA-256 for `(os, arch)`.
fn host_archive(os: &str, arch: &str) -> Result<HostArchive, WasiSdkError> {
    match (os, arch) {
        ("linux", "x86_64") => Ok(HostArchive {
            filename: "wasi-sdk-34.0-x86_64-linux.tar.gz",
            sha256: "b761e3a0721dbae9c09a0059e5fdb2bf917d1b4a8a7b430fb3b5aafb0984b2c4",
        }),
        ("linux", "aarch64") => Ok(HostArchive {
            filename: "wasi-sdk-34.0-arm64-linux.tar.gz",
            sha256: "f7e243dff54d60bcc576e94d6166b69f410f2500ae4a9ceef34315be10e77971",
        }),
        ("macos", "aarch64") => Ok(HostArchive {
            filename: "wasi-sdk-34.0-arm64-macos.tar.gz",
            sha256: "9c59398106b417f8f14913380fdf0097a8cc0ff4af9eb3ce0065a859e88d49e9",
        }),
        _ => Err(WasiSdkError::UnsupportedHost {
            os: os.to_owned(),
            arch: arch.to_owned(),
        }),
    }
}

/// Why a `wasi-sdk` toolchain could not be prepared for BoringSSL compilation.
#[derive(Debug, thiserror::Error)]
pub enum WasiSdkError {
    #[error(
        "no pinned {WASI_SDK_TAG} archive for host {os}/{arch}; set {WASI_SDK_PATH_ENV} to a \
         local {WASI_SDK_TAG}+ installation"
    )]
    UnsupportedHost { os: String, arch: String },
    #[error(
        "wasi-sdk installation at {path} is missing required path {missing} ({WASI_SDK_TAG}+ \
         required)"
    )]
    Incomplete { path: PathBuf, missing: PathBuf },
    #[error("failed to run curl for {url}: {source}")]
    Curl {
        url: String,
        #[source]
        source: io::Error,
    },
    #[error("curl did not fetch {url}: it exited {status} and said {stderr}")]
    CurlExited {
        url: String,
        status: String,
        stderr: String,
    },
    #[error(
        "{url} answered an archive with SHA-256 {actual}, but {WASI_SDK_TAG} pins {expected}; \
         nothing was installed"
    )]
    HashMismatch {
        url: String,
        expected: String,
        actual: String,
    },
    #[error("failed to run tar to extract {archive}: {source}")]
    Tar {
        archive: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("tar failed to extract {archive}: it exited {status} and said {stderr}")]
    TarExited {
        archive: PathBuf,
        status: String,
        stderr: String,
    },
    #[error("failed to {action} {path}: {source}")]
    Io {
        action: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

/// Ensures a verified `wasi-sdk-34` installation exists and returns its
/// canonicalized root directory.
pub fn ensure(workspace_root: &Path, target_triple: &str) -> Result<PathBuf, WasiSdkError> {
    let override_path = std::env::var_os(WASI_SDK_PATH_ENV)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from);
    ensure_with_override(workspace_root, target_triple, override_path.as_deref())
}

fn ensure_with_override(
    workspace_root: &Path,
    target_triple: &str,
    override_path: Option<&Path>,
) -> Result<PathBuf, WasiSdkError> {
    if let Some(sdk_root) = override_path {
        validate_installation(sdk_root, target_triple)?;
        return canonicalize(sdk_root);
    }

    let archive = host_archive(std::env::consts::OS, std::env::consts::ARCH)?;
    let install_dir = default_install_dir(workspace_root);
    if is_verified_install(&install_dir, target_triple, archive.sha256) {
        return canonicalize(&install_dir);
    }

    install_from_release(&install_dir, target_triple, archive)?;
    canonicalize(&install_dir)
}

/// Default managed installation directory inside `workspace_root`.
pub fn default_install_dir(workspace_root: &Path) -> PathBuf {
    workspace_root.join("target").join(WASI_SDK_TAG)
}

/// Materializes `wasi-boringssl.cmake` inside `target_dir` and returns its
/// canonicalized path. Leaves the file untouched when its contents already
/// match so incremental CMake builds do not reconfigure unnecessarily.
pub fn materialize_toolchain_cmake(target_dir: &Path) -> Result<PathBuf, WasiSdkError> {
    fs::create_dir_all(target_dir).map_err(|source| WasiSdkError::Io {
        action: "create",
        path: target_dir.to_owned(),
        source,
    })?;
    let canonical_dir = canonicalize(target_dir)?;
    let path = canonical_dir.join(TOOLCHAIN_FILE_NAME);
    if fs::read(&path).ok().as_deref() != Some(BORINGSSL_TOOLCHAIN_CMAKE.as_bytes()) {
        fs::write(&path, BORINGSSL_TOOLCHAIN_CMAKE).map_err(|source| WasiSdkError::Io {
            action: "write",
            path: path.clone(),
            source,
        })?;
    }
    Ok(path)
}

/// Returns the cross-compilation environment variables required to build
/// BoringSSL (`boring-sys` / `quiche`) for `target_triple` using `sdk_root`
/// and `toolchain_file`.
pub fn boringssl_env(
    sdk_root: &Path,
    target_triple: &str,
    toolchain_file: &Path,
) -> Vec<(String, String)> {
    let target_env = target_triple.replace('-', "_");
    let sdk = sdk_root.display();
    let bindgen_args = format!("--sysroot={sdk}/share/wasi-sysroot {BORINGSSL_BINDGEN_DEFS}");
    vec![
        (WASI_SDK_PATH_ENV.to_owned(), sdk.to_string()),
        ("LIBCLANG_PATH".to_owned(), format!("{sdk}/lib")),
        (format!("CC_{target_env}"), format!("{sdk}/bin/clang")),
        (format!("AR_{target_env}"), format!("{sdk}/bin/llvm-ar")),
        (
            format!("RANLIB_{target_env}"),
            format!("{sdk}/bin/llvm-ranlib"),
        ),
        ("CMAKE_GENERATOR".to_owned(), "Ninja".to_owned()),
        (
            format!("CMAKE_TOOLCHAIN_FILE_{target_env}"),
            toolchain_file.display().to_string(),
        ),
        (
            format!("BORING_BSSL_RUST_CPPLIB_{target_env}"),
            "c++".to_owned(),
        ),
        (
            format!("BINDGEN_EXTRA_CLANG_ARGS_{target_env}"),
            bindgen_args,
        ),
    ]
}

fn required_paths(sdk_root: &Path, target_triple: &str) -> Vec<PathBuf> {
    let sysroot = sdk_root.join("share/wasi-sysroot");
    vec![
        sdk_root.join("bin/clang"),
        sdk_root.join("bin/clang++"),
        sdk_root.join("bin/llvm-ar"),
        sdk_root.join("bin/llvm-ranlib"),
        sdk_root.join("lib"),
        sysroot.join("include").join(target_triple),
        sysroot
            .join("lib")
            .join(target_triple)
            .join("noeh/libc++.a"),
        sysroot
            .join("lib")
            .join(target_triple)
            .join("noeh/libc++abi.a"),
    ]
}

fn validate_installation(sdk_root: &Path, target_triple: &str) -> Result<(), WasiSdkError> {
    for required in required_paths(sdk_root, target_triple) {
        if !required.exists() {
            return Err(WasiSdkError::Incomplete {
                path: sdk_root.to_owned(),
                missing: required,
            });
        }
    }
    Ok(())
}

fn is_verified_install(sdk_root: &Path, target_triple: &str, expected_sha256: &str) -> bool {
    let stamp = fs::read_to_string(sdk_root.join(STAMP_FILE_NAME))
        .ok()
        .map(|text| text.trim().to_owned());
    stamp.as_deref() == Some(expected_sha256)
        && validate_installation(sdk_root, target_triple).is_ok()
}

fn install_from_release(
    install_dir: &Path,
    target_triple: &str,
    archive: HostArchive,
) -> Result<(), WasiSdkError> {
    let parent = install_dir
        .parent()
        .expect("managed wasi-sdk install dir has a parent directory");
    fs::create_dir_all(parent).map_err(|source| WasiSdkError::Io {
        action: "create",
        path: parent.to_owned(),
        source,
    })?;

    let work_dir = tempfile::Builder::new()
        .prefix(".wasi-sdk-fetch-")
        .tempdir_in(parent)
        .map_err(|source| WasiSdkError::Io {
            action: "create temporary staging directory in",
            path: parent.to_owned(),
            source,
        })?;
    let tarball = work_dir.path().join(archive.filename);
    let url = archive.url();
    let output = Command::new("curl")
        .args([
            "--fail",
            "--silent",
            "--show-error",
            "--location",
            "--retry",
            "3",
            "--output",
        ])
        .arg(&tarball)
        .arg(&url)
        .output()
        .map_err(|source| WasiSdkError::Curl {
            url: url.clone(),
            source,
        })?;
    if !output.status.success() {
        return Err(WasiSdkError::CurlExited {
            url,
            status: output.status.to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        });
    }

    let actual = sha256_file(&tarball)?;
    if actual != archive.sha256 {
        return Err(WasiSdkError::HashMismatch {
            url,
            expected: archive.sha256.to_owned(),
            actual,
        });
    }

    let staging = work_dir.path().join("sdk");
    fs::create_dir_all(&staging).map_err(|source| WasiSdkError::Io {
        action: "create",
        path: staging.clone(),
        source,
    })?;
    let tar_output = Command::new("tar")
        .arg("-C")
        .arg(&staging)
        .arg("--strip-components=1")
        .arg("-xzf")
        .arg(&tarball)
        .output()
        .map_err(|source| WasiSdkError::Tar {
            archive: tarball.clone(),
            source,
        })?;
    if !tar_output.status.success() {
        return Err(WasiSdkError::TarExited {
            archive: tarball,
            status: tar_output.status.to_string(),
            stderr: String::from_utf8_lossy(&tar_output.stderr)
                .trim()
                .to_owned(),
        });
    }

    validate_installation(&staging, target_triple)?;
    let stamp = staging.join(STAMP_FILE_NAME);
    fs::write(&stamp, format!("{}\n", archive.sha256)).map_err(|source| WasiSdkError::Io {
        action: "write",
        path: stamp,
        source,
    })?;

    if install_dir.exists() {
        fs::remove_dir_all(install_dir).map_err(|source| WasiSdkError::Io {
            action: "remove stale",
            path: install_dir.to_owned(),
            source,
        })?;
    }
    fs::rename(&staging, install_dir).map_err(|source| WasiSdkError::Io {
        action: "install",
        path: install_dir.to_owned(),
        source,
    })?;
    Ok(())
}

fn sha256_file(path: &Path) -> Result<String, WasiSdkError> {
    let mut file = File::open(path).map_err(|source| WasiSdkError::Io {
        action: "open",
        path: path.to_owned(),
        source,
    })?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buf).map_err(|source| WasiSdkError::Io {
            action: "read",
            path: path.to_owned(),
            source,
        })?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn canonicalize(path: &Path) -> Result<PathBuf, WasiSdkError> {
    fs::canonicalize(path).map_err(|source| WasiSdkError::Io {
        action: "resolve",
        path: path.to_owned(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_fake_sdk(root: &Path, target_triple: &str) {
        for dir in [
            root.join("bin"),
            root.join("lib"),
            root.join("share/wasi-sysroot/include").join(target_triple),
            root.join("share/wasi-sysroot/lib")
                .join(target_triple)
                .join("noeh"),
        ] {
            fs::create_dir_all(dir).expect("create fake sdk dir");
        }
        for file in [
            root.join("bin/clang"),
            root.join("bin/clang++"),
            root.join("bin/llvm-ar"),
            root.join("bin/llvm-ranlib"),
            root.join("share/wasi-sysroot/lib")
                .join(target_triple)
                .join("noeh/libc++.a"),
            root.join("share/wasi-sysroot/lib")
                .join(target_triple)
                .join("noeh/libc++abi.a"),
        ] {
            fs::write(file, b"").expect("write fake sdk file");
        }
    }

    #[test]
    fn host_archive_pins_supported_hosts_and_refuses_intel_macos() {
        let linux_x86 = host_archive("linux", "x86_64").expect("linux x86_64 supported");
        assert_eq!(linux_x86.filename, "wasi-sdk-34.0-x86_64-linux.tar.gz");
        assert_eq!(
            linux_x86.sha256,
            "b761e3a0721dbae9c09a0059e5fdb2bf917d1b4a8a7b430fb3b5aafb0984b2c4"
        );

        let linux_arm = host_archive("linux", "aarch64").expect("linux aarch64 supported");
        assert_eq!(linux_arm.filename, "wasi-sdk-34.0-arm64-linux.tar.gz");
        assert_eq!(
            linux_arm.sha256,
            "f7e243dff54d60bcc576e94d6166b69f410f2500ae4a9ceef34315be10e77971"
        );

        let macos_arm = host_archive("macos", "aarch64").expect("macos aarch64 supported");
        assert_eq!(macos_arm.filename, "wasi-sdk-34.0-arm64-macos.tar.gz");
        assert_eq!(
            macos_arm.sha256,
            "9c59398106b417f8f14913380fdf0097a8cc0ff4af9eb3ce0065a859e88d49e9"
        );

        assert!(matches!(
            host_archive("macos", "x86_64"),
            Err(WasiSdkError::UnsupportedHost { os, arch }) if os == "macos" && arch == "x86_64"
        ));
    }

    #[test]
    fn override_path_is_validated_and_accepted_when_complete() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sdk = dir.path().join("custom-sdk");
        create_fake_sdk(&sdk, "wasm32-wasip3");

        let resolved = ensure_with_override(dir.path(), "wasm32-wasip3", Some(&sdk))
            .expect("complete override sdk passes");
        assert_eq!(resolved, fs::canonicalize(&sdk).expect("canonical sdk"));

        fs::remove_file(sdk.join("bin/clang")).expect("remove clang");
        let error = ensure_with_override(dir.path(), "wasm32-wasip3", Some(&sdk))
            .expect_err("incomplete override sdk fails fast");
        assert!(
            matches!(error, WasiSdkError::Incomplete { ref missing, .. } if missing.ends_with("bin/clang")),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn boringssl_env_and_toolchain_materialization_match_target_triple() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sdk = dir.path().join("wasi-sdk-34");
        let target_dir = dir.path().join("target-dir");
        let toolchain = materialize_toolchain_cmake(&target_dir).expect("materialize cmake");
        assert_eq!(
            fs::read_to_string(&toolchain).expect("read cmake"),
            BORINGSSL_TOOLCHAIN_CMAKE
        );

        let env = boringssl_env(&sdk, "wasm32-wasip3", &toolchain);
        let lookup = |key: &str| {
            env.iter()
                .find(|(name, _)| name == key)
                .map(|(_, value)| value.as_str())
        };
        assert_eq!(lookup("WASI_SDK_PATH"), Some(sdk.to_str().unwrap()));
        assert_eq!(
            lookup("LIBCLANG_PATH"),
            Some(sdk.join("lib").to_str().unwrap())
        );
        assert_eq!(
            lookup("CC_wasm32_wasip3"),
            Some(sdk.join("bin/clang").to_str().unwrap())
        );
        assert_eq!(
            lookup("AR_wasm32_wasip3"),
            Some(sdk.join("bin/llvm-ar").to_str().unwrap())
        );
        assert_eq!(
            lookup("RANLIB_wasm32_wasip3"),
            Some(sdk.join("bin/llvm-ranlib").to_str().unwrap())
        );
        assert_eq!(lookup("CMAKE_GENERATOR"), Some("Ninja"));
        assert_eq!(
            lookup("CMAKE_TOOLCHAIN_FILE_wasm32_wasip3"),
            Some(toolchain.to_str().unwrap())
        );
        assert_eq!(lookup("BORING_BSSL_RUST_CPPLIB_wasm32_wasip3"), Some("c++"));
        let bindgen = lookup("BINDGEN_EXTRA_CLANG_ARGS_wasm32_wasip3").expect("bindgen args");
        assert!(bindgen.contains(&format!("--sysroot={}/share/wasi-sysroot", sdk.display())));
        assert!(bindgen.contains("-DOPENSSL_NO_ASM"));
        assert!(bindgen.contains("-DOPENSSL_NO_SOCK"));
        assert!(bindgen.contains("-DOPENSSL_NO_POSIX_IO"));
        assert!(
            bindgen.contains("-DOPENSSL_NO_THREADS_CORRUPT_MEMORY_AND_LEAK_SECRETS_IF_THREADED")
        );
    }
}
