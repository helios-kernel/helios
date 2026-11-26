//! Compile-time `component.toml` -> native Rust codegen (`askama`) and
//! three-part system image packaging (`helios-kernel`, signed
//! `component-manager.cwasm`, and signed user-space components payload).

use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

use askama::Template;
use clap::Parser;
use helios_artifact::bootfs;
use helios_artifact::{
    CwasmTarget, TrailerError, cwasm_target_isa_levels, sign_payload_with_key,
    verify_signed_payload,
};
use helios_component_manager::{
    AuthorityScopeSpec, ComponentNode, ComponentTopology, ContainerMountSharingSpec, Criticality,
    EscalationAction, IpAddrSpec, LifecycleKind, ManifestError, MountSharingSpec, MountSourceSpec,
    NameCeiling, OomTier, PortCeiling, ProviderSlot, RestartPolicy, RunnerSpec,
    SocketActivationSpec, StartupPolicy, WasmSharding, load_tree_from_dir,
};
use helios_workspace_root::prebuilt_manifest::sha256_hex;
use helios_workspace_root::{WorkspaceRoot, WorkspaceRootError};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::artifact_cache::{PrecompileCache, precompile};
use crate::{
    BOOTFS_IMAGE_FILE, BootAsset, BootAssetKind, BootBuild, CacheArgs, ComponentBuildProfile,
    DEFAULT_BOOT_ARTIFACTS_MANIFEST, DEFAULT_INIT_ARGV0, Hint, INIT_COMMAND, INIT_WASM,
    PrebuildError, PreparedRootKey, WasmBuildError, WasmBuilder, WasmSource,
    build_boot_program_assets, build_compiler_plugin_asset, encode_component, prepare_root_key,
    resolve_bootfs_source, selected_boot_programs, validate_external_boot_artifact_sources,
    write_bootfs_image,
};

/// File name of the standalone signed root `component-manager` artifact (Part 2).
pub const COMPONENT_MANAGER_ARTIFACT_FILE: &str = "component-manager.cwasm";
/// File name of the signed user-space components payload artifact (Part 3).
pub const USERSPACE_PAYLOAD_ARTIFACT_FILE: &str = "userspace-components.bootfs";
/// File name of the staged kernel image artifact (Part 1).
pub const KERNEL_ARTIFACT_FILE: &str = "helios-kernel";
/// File name of the typed three-part image manifest written beside the artifacts.
pub const THREE_PART_MANIFEST_FILE: &str = "image-manifest.json";
/// Schema version of [`ThreePartImageManifest`].
pub const THREE_PART_MANIFEST_SCHEMA_VERSION: u32 = 1;

/// Why parsing, validating, and rendering a `component.toml` tree into Rust failed.
#[derive(Debug, Error)]
pub enum TopologyCodegenError {
    #[error(transparent)]
    Manifest(#[from] ManifestError),
    #[error("failed to render component topology template: {source}")]
    RenderTemplate {
        #[source]
        source: askama::Error,
    },
    #[error("failed to create directory `{path}`: {source}")]
    CreateDir {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("failed to write `{path}`: {source}")]
    Write {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("failed to resolve `{path}`: {source}")]
    Resolve {
        path: String,
        #[source]
        source: io::Error,
    },
}

/// Parses, statically validates, and renders a `component.toml` directory tree into
/// `out_path`, returning the canonicalized output path.
pub(crate) fn render_components_dir_to_file(
    workspace_root: &WorkspaceRoot,
    components_dir: &Path,
    out_path: &Path,
) -> Result<PathBuf, TopologyCodegenError> {
    let resolved_dir = resolve_path(workspace_root, components_dir);
    let topology = load_tree_from_dir(&resolved_dir)?;
    let rendered = render_topology_rust(&topology)?;
    if let Some(parent) = out_path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent).map_err(|source| TopologyCodegenError::CreateDir {
            path: parent.display().to_string(),
            source,
        })?;
    }
    fs::write(out_path, rendered).map_err(|source| TopologyCodegenError::Write {
        path: out_path.display().to_string(),
        source,
    })?;
    fs::canonicalize(out_path).map_err(|source| TopologyCodegenError::Resolve {
        path: out_path.display().to_string(),
        source,
    })
}

/// Why component codegen or three-part image packaging failed.
#[derive(Debug, Error)]
pub enum ComponentBuildError {
    #[error(transparent)]
    WorkspaceRoot(#[from] WorkspaceRootError),
    #[error(transparent)]
    Manifest(#[from] ManifestError),
    #[error(transparent)]
    Codegen(#[from] TopologyCodegenError),
    #[error(transparent)]
    Prebuild(#[from] PrebuildError),
    #[error(transparent)]
    WasmBuild(#[from] WasmBuildError),
    #[error("failed to read `{path}`: {source}")]
    Read {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("failed to write `{path}`: {source}")]
    Write {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("failed to create directory `{path}`: {source}")]
    CreateDir {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error(
        "generated topology differs from `{expected}`; regenerate with `helios-cli component-codegen`"
    )]
    DriftDetected { expected: String },
    #[error("failed to sign `{path}`: {source}")]
    SignArtifact {
        path: String,
        #[source]
        source: TrailerError,
    },
    #[error("failed to verify signed artifact `{path}`: {source}")]
    VerifyArtifact {
        path: String,
        #[source]
        source: TrailerError,
    },
    #[error("failed to verify signed bootfs `{path}`: {source}")]
    VerifyBootfs {
        path: String,
        #[source]
        source: bootfs::BootfsError,
    },
    #[error("kernel image `{path}` does not exist")]
    KernelMissing { path: String },
    #[error("failed to encode `{path}`: {source}")]
    EncodeJson {
        path: String,
        #[source]
        source: serde_json::Error,
    },
    #[error("failed to detect host rust target via `rustc -vV`: {detail}")]
    HostTarget { detail: String },
}

/// Generate static native Rust routing tables, capability ceilings, and supervisor
/// state definitions from a directory tree of `component.toml` manifests.
#[derive(Parser)]
pub(crate) struct ComponentCodegenCommand {
    /// Root directory of the `component.toml` hierarchy (defaults to `components`).
    #[arg(long, default_value = "components")]
    pub(crate) components: PathBuf,
    /// Output `.rs` file path to write the generated topology module to.
    #[arg(long)]
    pub(crate) out: PathBuf,
    /// Optional existing `.rs` file to check for exact parity (fails on drift).
    #[arg(long)]
    pub(crate) verify_matches: Option<PathBuf>,
}

/// Build and package a three-part Helios system image:
/// (1) `helios-kernel`, (2) compiled & signed `component-manager.cwasm`, and
/// (3) signed user-space components payload (`userspace-components.bootfs` / `helios-bootfs`).
#[derive(Parser)]
pub(crate) struct ImageBuildCommand {
    /// Root directory of the `component.toml` hierarchy (defaults to `components`).
    #[arg(long, default_value = "components")]
    pub(crate) components: PathBuf,
    /// Directory receiving the three-part artifacts and `image-manifest.json`.
    #[arg(long)]
    pub(crate) out_dir: PathBuf,
    /// Target triple for precompiled `cwasm` artifacts (defaults to the host triple).
    #[arg(long)]
    pub(crate) target: Option<String>,
    /// Build profile (`debug` or `release`).
    #[arg(long, default_value = "debug", value_parser = ["debug", "release"])]
    pub(crate) profile: String,
    /// Cargo binary path.
    #[arg(long, default_value = "cargo")]
    pub(crate) cargo: PathBuf,
    /// Opt-in: compile runtime TOML parsing and bounded dynamic subtree mounting
    /// (`--features dynamic-components`) into `component-manager`. Off by default.
    #[arg(long, default_value_t = false)]
    pub(crate) dynamic_components: bool,
    /// Optional built `helios-kernel` ELF binary to stage as Part 1 of the three-part bundle.
    #[arg(long)]
    pub(crate) kernel: Option<PathBuf>,
    /// Root filesystem template overlaid into the signed bootfs payload.
    #[arg(long, default_value = "programs/init/bootfs")]
    pub(crate) bootfs_root: PathBuf,
    /// `argv[0]` passed to the root `component-manager` component.
    #[arg(long, default_value = DEFAULT_INIT_ARGV0)]
    pub(crate) init_argv0: String,
    /// Optional subset of boot programs to package into the user-space payload.
    #[arg(long = "boot-program")]
    pub(crate) boot_programs: Vec<String>,
    /// External WASI boot artifacts manifest.
    #[arg(long, default_value = DEFAULT_BOOT_ARTIFACTS_MANIFEST)]
    pub(crate) boot_artifacts_manifest: PathBuf,
    /// Skip building the in-kernel compiler plugin.
    #[arg(long = "no-compiler-plugin", default_value_t = false)]
    pub(crate) no_compiler_plugin: bool,
    /// Optional prebuilt userspace wasm directory for non-root programs.
    #[arg(long, value_name = "DIR", env = "HELIOS_PREBUILT_WASM")]
    pub(crate) prebuilt_wasm: Option<PathBuf>,
    /// Sign artifacts with this 32-byte Ed25519 secret key instead of generating one in `--out-dir`.
    #[arg(long, value_name = "PATH", env = "HELIOS_ROOT_SECRET_KEY")]
    pub(crate) root_secret_key: Option<PathBuf>,
    #[command(flatten)]
    pub(crate) cache: CacheArgs,
}

/// File name and SHA-256 digest of one packaged artifact.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactFileDigest {
    pub file: String,
    pub bytes: u64,
    pub sha256: String,
}

/// Typed `image-manifest.json` describing a three-part Helios system image bundle.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreePartImageManifest {
    pub schema_version: u32,
    pub target: String,
    pub profile: String,
    pub dynamic_components: bool,
    pub root_public_key: String,
    pub root_public_key_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kernel: Option<ArtifactFileDigest>,
    pub component_manager: ArtifactFileDigest,
    pub userspace_payload: ArtifactFileDigest,
    pub generated_topology: String,
    pub components: Vec<String>,
}

/// Runs `helios-cli component-codegen`.
pub(crate) fn run_component_codegen(
    command: &ComponentCodegenCommand,
    explicit_workspace_root: Option<&Path>,
) -> Result<(), ComponentBuildError> {
    let workspace_root = WorkspaceRoot::resolve(explicit_workspace_root)?;
    let components_dir = resolve_path(&workspace_root, &command.components);
    let topology = load_tree_from_dir(&components_dir)?;
    let rendered = render_topology_rust(&topology)?;

    if let Some(expected_path) = &command.verify_matches {
        let resolved_expected = resolve_path(&workspace_root, expected_path);
        let existing =
            fs::read_to_string(&resolved_expected).map_err(|source| ComponentBuildError::Read {
                path: resolved_expected.display().to_string(),
                source,
            })?;
        if existing != rendered {
            return Err(ComponentBuildError::DriftDetected {
                expected: resolved_expected.display().to_string(),
            });
        }
    }

    if let Some(parent) = command.out.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent).map_err(|source| ComponentBuildError::CreateDir {
            path: parent.display().to_string(),
            source,
        })?;
    }
    fs::write(&command.out, rendered).map_err(|source| ComponentBuildError::Write {
        path: command.out.display().to_string(),
        source,
    })?;
    Ok(())
}

/// Runs `helios-cli image-build`, producing the three-part system image bundle.
pub(crate) fn run_image_build(
    command: ImageBuildCommand,
    explicit_workspace_root: Option<&Path>,
) -> Result<ThreePartImageManifest, ComponentBuildError> {
    let workspace_root = WorkspaceRoot::resolve(explicit_workspace_root)?;
    let target_triple = match command.target {
        Some(target) => target,
        None => detect_host_target()?,
    };

    fs::create_dir_all(&command.out_dir).map_err(|source| ComponentBuildError::CreateDir {
        path: command.out_dir.display().to_string(),
        source,
    })?;

    // 1. Parse, statically validate, and render the `component.toml` directory tree via `askama`.
    let components_dir = resolve_path(&workspace_root, &command.components);
    let topology = load_tree_from_dir(&components_dir)?;
    let rendered = render_topology_rust(&topology)?;
    let generated_topology_path = command.out_dir.join("generated_topology.rs");
    fs::write(&generated_topology_path, &rendered).map_err(|source| {
        ComponentBuildError::Write {
            path: generated_topology_path.display().to_string(),
            source,
        }
    })?;
    let generated_topology_abs =
        fs::canonicalize(&generated_topology_path).map_err(|source| ComponentBuildError::Read {
            path: generated_topology_path.display().to_string(),
            source,
        })?;

    // 2. Prepare root signing keys (never leaking secret keys into the manifest).
    let PreparedRootKey {
        root_public_path,
        root_secret_path: _,
        root_signing_key,
    } = prepare_root_key(&command.out_dir, command.root_secret_key.as_deref())?;
    let root_public_bytes =
        fs::read(&root_public_path).map_err(|source| ComponentBuildError::Read {
            path: root_public_path.display().to_string(),
            source,
        })?;
    let root_public_key_array: [u8; 32] = root_public_bytes
        .as_slice()
        .try_into()
        .expect("prepared root public key is 32 bytes");

    let cache = command.cache.open().map_err(PrebuildError::from)?;
    let precompile_cache = cache
        .as_ref()
        .map(PrecompileCache::new)
        .transpose()
        .map_err(PrebuildError::from)?;
    let floor = cwasm_target_isa_levels(&target_triple).floor();
    let cwasm_target =
        CwasmTarget::new(&target_triple, floor.name()).map_err(PrebuildError::from)?;

    // 3. Compile `component-manager` (`programs/init`) with the generated static topology
    //    (and `--features dynamic-components` ONLY when explicitly requested!).
    let init_manifest = workspace_root.join(Path::new("programs/init/Cargo.toml"));
    let manager_builder = WasmBuilder {
        cargo: &command.cargo,
        profile: &command.profile,
        out_dir: &command.out_dir,
        workspace_root: &workspace_root,
        cache: None,
    };
    let extra_features: &[&str] = if command.dynamic_components {
        &["dynamic-components"]
    } else {
        &[]
    };
    let manager_wasm = manager_builder.component_with_options(
        &init_manifest,
        INIT_WASM,
        ComponentBuildProfile {
            extra_features,
            generated_topology_rs: Some(&generated_topology_abs),
        },
    )?;
    let manager_component_bytes = encode_component(&manager_wasm)?;
    let manager_cwasm_unsigned = precompile(
        precompile_cache.as_ref(),
        &manager_component_bytes,
        &cwasm_target,
        Hint::Performance.into(),
    )
    .map_err(PrebuildError::from)?;

    // Part 2: Standalone signed `component-manager.cwasm` (`SystemComponent`).
    let manager_cwasm_signed = sign_payload_with_key(&manager_cwasm_unsigned, &root_signing_key)
        .map_err(|source| ComponentBuildError::SignArtifact {
            path: COMPONENT_MANAGER_ARTIFACT_FILE.to_owned(),
            source,
        })?;
    let manager_signed_path = command.out_dir.join(COMPONENT_MANAGER_ARTIFACT_FILE);
    fs::write(&manager_signed_path, &manager_cwasm_signed).map_err(|source| {
        ComponentBuildError::Write {
            path: manager_signed_path.display().to_string(),
            source,
        }
    })?;
    verify_signed_payload(&manager_cwasm_signed, &[root_public_key_array]).map_err(|source| {
        ComponentBuildError::VerifyArtifact {
            path: manager_signed_path.display().to_string(),
            source,
        }
    })?;

    // Unsigned `init_component.cwasm` placed inside the signed `helios-bootfs` envelope.
    let init_cwasm_path = command.out_dir.join("init_component.cwasm");
    fs::write(&init_cwasm_path, &manager_cwasm_unsigned).map_err(|source| {
        ComponentBuildError::Write {
            path: init_cwasm_path.display().to_string(),
            source,
        }
    })?;

    // 4. Part 3: Signed user-space components payload (`userspace-components.bootfs` + `helios-bootfs`).
    let bootfs_root = resolve_path(&workspace_root, &command.bootfs_root);
    let selected_programs =
        selected_boot_programs(command.boot_programs).map_err(PrebuildError::from)?;
    let boot_artifacts_manifest = resolve_path(&workspace_root, &command.boot_artifacts_manifest);
    validate_external_boot_artifact_sources(
        &boot_artifacts_manifest,
        &target_triple,
        &selected_programs,
        &workspace_root,
    )
    .map_err(PrebuildError::from)?;

    let wasm_source = match command.prebuilt_wasm.as_deref() {
        Some(dir) => WasmSource::prebuilt(workspace_root.join(dir), &command.profile)?,
        None => WasmSource::Build(WasmBuilder {
            cargo: &command.cargo,
            profile: &command.profile,
            out_dir: &command.out_dir,
            workspace_root: &workspace_root,
            cache: cache.as_ref(),
        }),
    };
    let build = BootBuild {
        wasm: &wasm_source,
        out_dir: &command.out_dir,
        target: &cwasm_target,
        workspace_root: &workspace_root,
        precompile: precompile_cache.as_ref(),
    };
    let mut bootfs_assets = Vec::new();
    if !command.no_compiler_plugin {
        bootfs_assets.push(build_compiler_plugin_asset(&build).map_err(PrebuildError::from)?);
    }
    bootfs_assets.extend(
        build_boot_program_assets(&build, &selected_programs, &boot_artifacts_manifest)
            .map_err(PrebuildError::from)?,
    );
    if selected_programs
        .as_ref()
        .is_none_or(|selected| selected.contains(INIT_COMMAND))
    {
        bootfs_assets.push(BootAsset {
            path: format!("bin/{INIT_COMMAND}"),
            source: resolve_bootfs_source(&init_cwasm_path).map_err(PrebuildError::from)?,
            kind: BootAssetKind::File,
        });
    }
    let prepared_inspector = crate::prepare_inspector_auth(&command.out_dir, None, None)?;
    bootfs_assets.push(BootAsset {
        path: helios_inspector_protocol::auth::INSPECTOR_POLICY_PATH
            .trim_start_matches('/')
            .to_owned(),
        source: resolve_bootfs_source(&prepared_inspector.policy_path)
            .map_err(PrebuildError::from)?,
        kind: BootAssetKind::File,
    });

    let userspace_payload_path = command.out_dir.join(USERSPACE_PAYLOAD_ARTIFACT_FILE);
    write_bootfs_image(
        &userspace_payload_path,
        &bootfs_root,
        &bootfs_assets,
        &init_cwasm_path,
        &command.init_argv0,
        &root_signing_key,
    )?;
    let userspace_bytes =
        fs::read(&userspace_payload_path).map_err(|source| ComponentBuildError::Read {
            path: userspace_payload_path.display().to_string(),
            source,
        })?;
    let verified_signer = bootfs::verified_signer(&userspace_bytes).map_err(|source| {
        ComponentBuildError::VerifyBootfs {
            path: userspace_payload_path.display().to_string(),
            source,
        }
    })?;
    if verified_signer != root_public_key_array {
        return Err(ComponentBuildError::VerifyBootfs {
            path: userspace_payload_path.display().to_string(),
            source: bootfs::BootfsError::SignatureMismatch,
        });
    }

    // Write `helios-bootfs` beside `userspace-components.bootfs` for direct kernel/VM boot.
    let bootfs_compat_path = command.out_dir.join(BOOTFS_IMAGE_FILE);
    fs::write(&bootfs_compat_path, &userspace_bytes).map_err(|source| {
        ComponentBuildError::Write {
            path: bootfs_compat_path.display().to_string(),
            source,
        }
    })?;

    // 5. Part 1: Optional staged `helios-kernel`.
    let kernel_digest = match command.kernel {
        Some(kernel_src) => {
            if !kernel_src.is_file() {
                return Err(ComponentBuildError::KernelMissing {
                    path: kernel_src.display().to_string(),
                });
            }
            let kernel_bytes =
                fs::read(&kernel_src).map_err(|source| ComponentBuildError::Read {
                    path: kernel_src.display().to_string(),
                    source,
                })?;
            let staged_kernel = command.out_dir.join(KERNEL_ARTIFACT_FILE);
            fs::write(&staged_kernel, &kernel_bytes).map_err(|source| {
                ComponentBuildError::Write {
                    path: staged_kernel.display().to_string(),
                    source,
                }
            })?;
            Some(ArtifactFileDigest {
                file: KERNEL_ARTIFACT_FILE.to_owned(),
                bytes: kernel_bytes.len() as u64,
                sha256: sha256_hex(&kernel_bytes),
            })
        }
        None => None,
    };

    let manifest = ThreePartImageManifest {
        schema_version: THREE_PART_MANIFEST_SCHEMA_VERSION,
        target: target_triple,
        profile: command.profile,
        dynamic_components: command.dynamic_components,
        root_public_key: root_public_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("helios-root-public.key")
            .to_owned(),
        root_public_key_sha256: sha256_hex(&root_public_bytes),
        kernel: kernel_digest,
        component_manager: ArtifactFileDigest {
            file: COMPONENT_MANAGER_ARTIFACT_FILE.to_owned(),
            bytes: manager_cwasm_signed.len() as u64,
            sha256: sha256_hex(&manager_cwasm_signed),
        },
        userspace_payload: ArtifactFileDigest {
            file: USERSPACE_PAYLOAD_ARTIFACT_FILE.to_owned(),
            bytes: userspace_bytes.len() as u64,
            sha256: sha256_hex(&userspace_bytes),
        },
        generated_topology: "generated_topology.rs".to_owned(),
        components: topology
            .nodes
            .iter()
            .map(|n| n.moniker.to_string())
            .collect(),
    };

    let manifest_path = command.out_dir.join(THREE_PART_MANIFEST_FILE);
    let mut encoded = serde_json::to_string_pretty(&manifest).map_err(|source| {
        ComponentBuildError::EncodeJson {
            path: manifest_path.display().to_string(),
            source,
        }
    })?;
    encoded.push('\n');
    fs::write(&manifest_path, encoded).map_err(|source| ComponentBuildError::Write {
        path: manifest_path.display().to_string(),
        source,
    })?;

    CacheArgs::report(cache.as_ref());
    Ok(manifest)
}

/// Renders a validated [`ComponentTopology`] into static native Rust source code
/// through the compile-time `askama` template (`cli/templates/component_topology.rs.askama`).
pub fn render_topology_rust(topology: &ComponentTopology) -> Result<String, TopologyCodegenError> {
    let template = ComponentTopologyTemplate {
        nodes: topology.nodes.as_ref(),
    };
    let mut rendered = template
        .render()
        .map_err(|source| TopologyCodegenError::RenderTemplate { source })?;
    if !rendered.ends_with('\n') {
        rendered.push('\n');
    }
    Ok(rendered)
}

fn resolve_path(workspace_root: &WorkspaceRoot, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        workspace_root.join(path)
    }
}

fn detect_host_target() -> Result<String, ComponentBuildError> {
    let output = Command::new("rustc").arg("-vV").output().map_err(|error| {
        ComponentBuildError::HostTarget {
            detail: error.to_string(),
        }
    })?;
    if !output.status.success() {
        return Err(ComponentBuildError::HostTarget {
            detail: format!("rustc -vV exited with {}", output.status),
        });
    }
    let text = String::from_utf8_lossy(&output.stdout);
    text.lines()
        .find_map(|line| line.strip_prefix("host: "))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| ComponentBuildError::HostTarget {
            detail: "missing `host:` line in `rustc -vV`".to_owned(),
        })
}

/// Zero-allocation wrapper that renders `&str` as an escaped Rust string literal.
struct RustStrLit<'a>(&'a str);

impl fmt::Display for RustStrLit<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self.0, f)
    }
}

#[derive(Template)]
#[template(path = "component_topology.rs.askama", escape = "none")]
struct ComponentTopologyTemplate<'a> {
    nodes: &'a [ComponentNode],
}

impl ComponentTopologyTemplate<'_> {
    const fn str_lit(s: &str) -> RustStrLit<'_> {
        RustStrLit(s)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;
    use std::process::Command;

    use ed25519_dalek::{SigningKey, VerifyingKey};
    use helios_artifact::bootfs;
    use helios_artifact::{sign_payload_with_key, verify_signed_payload};
    use helios_component_manager::{ManifestError, ValidationError, load_tree_from_dir};
    use helios_workspace_root::prebuilt_manifest::sha256_hex;

    use super::{
        ArtifactFileDigest, COMPONENT_MANAGER_ARTIFACT_FILE, KERNEL_ARTIFACT_FILE,
        THREE_PART_MANIFEST_SCHEMA_VERSION, ThreePartImageManifest,
        USERSPACE_PAYLOAD_ARTIFACT_FILE, render_topology_rust,
    };

    fn repo_root() -> &'static Path {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("cli lives under workspace root")
    }

    #[test]
    fn default_components_tree_codegen_matches_checked_in_default_topology() {
        let root = repo_root();
        let topology =
            load_tree_from_dir(&root.join("components")).expect("default components tree loads");
        let rendered = render_topology_rust(&topology).expect("askama template renders");
        let checked_in = fs::read_to_string(root.join("programs/init/src/default_topology.rs"))
            .expect("read checked-in default_topology.rs");
        assert_eq!(
            rendered, checked_in,
            "programs/init/src/default_topology.rs drifted from components/; regenerate via \
             `helios-cli component-codegen --components components --out programs/init/src/default_topology.rs`"
        );
    }

    #[test]
    fn codegen_rejects_escalation_cycles_and_unknown_fields_in_directory_tree() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::write(
            dir.path().join("component.toml"),
            r#"
runner = "realm"
oom_tier = "plugin"
[capabilities]
network = ["tcp"]
tcp_ports = [8080]
"#,
        )
        .unwrap();

        // Child escalates network + oom_tier -> rejected.
        let child_dir = dir.path().join("app");
        fs::create_dir_all(&child_dir).unwrap();
        fs::write(
            child_dir.join("component.toml"),
            r#"
runner = "wasm"
program = "/bin/app"
oom_tier = "protected"
[capabilities]
network = ["tcp", "admin"]
"#,
        )
        .unwrap();
        let err = load_tree_from_dir(dir.path()).expect_err("escalation must fail");
        assert!(matches!(
            err,
            ManifestError::Validation(ValidationError::CapabilityEscalation { .. })
        ));

        // Unknown field -> rejected.
        fs::write(
            child_dir.join("component.toml"),
            r#"
runner = "wasm"
program = "/bin/app"
nonexistent_flag = 42
"#,
        )
        .unwrap();
        let err = load_tree_from_dir(dir.path()).expect_err("unknown field must fail");
        assert!(matches!(err, ManifestError::Parse { .. }));
    }

    #[test]
    fn default_component_manager_links_zero_toml_crates_and_dynamic_opt_in_enables_toml() {
        let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
        let root = repo_root();

        for pkg in ["helios-component-manager", "helios-init"] {
            let default_tree = Command::new(&cargo)
                .current_dir(root)
                .args(["tree", "-p", pkg, "--prefix", "none"])
                .output()
                .expect("run cargo tree (default)");
            assert!(
                default_tree.status.success(),
                "cargo tree -p {pkg} failed: {}",
                String::from_utf8_lossy(&default_tree.stderr)
            );
            let stdout = String::from_utf8_lossy(&default_tree.stdout);
            assert!(
                !stdout.lines().any(|line| {
                    let name = line.split_whitespace().next().unwrap_or("");
                    name == "toml" || name == "toml_edit"
                }),
                "default build of {pkg} MUST NOT depend on any `toml` crate, got:\n{stdout}"
            );

            let dynamic_tree = Command::new(&cargo)
                .current_dir(root)
                .args([
                    "tree",
                    "-p",
                    pkg,
                    "--features",
                    "dynamic-components",
                    "--prefix",
                    "none",
                ])
                .output()
                .expect("run cargo tree (--features dynamic-components)");
            assert!(
                dynamic_tree.status.success(),
                "cargo tree -p {pkg} --features dynamic-components failed: {}",
                String::from_utf8_lossy(&dynamic_tree.stderr)
            );
            let dyn_stdout = String::from_utf8_lossy(&dynamic_tree.stdout);
            assert!(
                dyn_stdout
                    .lines()
                    .any(|line| line.split_whitespace().next() == Some("toml")),
                "{pkg} --features dynamic-components must include `toml` parser, got:\n{dyn_stdout}"
            );
        }
    }

    #[test]
    fn three_part_image_packaging_round_trips_and_verifies_signatures() {
        let dir = tempfile::tempdir().expect("tempdir");
        let signing_key = SigningKey::from_bytes(&[0x5a; 32]);
        let verifying_key = VerifyingKey::from(&signing_key).to_bytes();

        // Part 1: helios-kernel
        let kernel_bytes = b"\x7fELF-synthetic-helios-kernel";
        fs::write(dir.path().join(KERNEL_ARTIFACT_FILE), kernel_bytes).unwrap();

        // Part 2: signed component-manager.cwasm
        let manager_unsigned = b"synthetic-component-manager-cwasm";
        let manager_signed =
            sign_payload_with_key(manager_unsigned, &signing_key).expect("sign manager");
        fs::write(
            dir.path().join(COMPONENT_MANAGER_ARTIFACT_FILE),
            &manager_signed,
        )
        .unwrap();

        // Part 3: signed userspace-components.bootfs
        let bootfs_body = bootfs::write_image(&[
            bootfs::WriteEntry {
                kind: bootfs::EntryKind::InitComponent,
                path: "init_component.cwasm",
                data: manager_unsigned,
                modified_nanos: 0,
            },
            bootfs::WriteEntry {
                kind: bootfs::EntryKind::InitArgv0,
                path: "/init.wasm",
                data: b"",
                modified_nanos: 0,
            },
            bootfs::WriteEntry {
                kind: bootfs::EntryKind::File,
                path: "bin/inspector-host",
                data: b"synthetic-inspector-host",
                modified_nanos: 0,
            },
        ]);
        let bootfs_signed = bootfs::sign_image(bootfs_body, &signing_key);
        fs::write(
            dir.path().join(USERSPACE_PAYLOAD_ARTIFACT_FILE),
            &bootfs_signed,
        )
        .unwrap();

        let manifest = ThreePartImageManifest {
            schema_version: THREE_PART_MANIFEST_SCHEMA_VERSION,
            target: "x86_64-unknown-none".to_owned(),
            profile: "release".to_owned(),
            dynamic_components: false,
            root_public_key: "helios-root-public.key".to_owned(),
            root_public_key_sha256: sha256_hex(&verifying_key),
            kernel: Some(ArtifactFileDigest {
                file: KERNEL_ARTIFACT_FILE.to_owned(),
                bytes: kernel_bytes.len() as u64,
                sha256: sha256_hex(kernel_bytes),
            }),
            component_manager: ArtifactFileDigest {
                file: COMPONENT_MANAGER_ARTIFACT_FILE.to_owned(),
                bytes: manager_signed.len() as u64,
                sha256: sha256_hex(&manager_signed),
            },
            userspace_payload: ArtifactFileDigest {
                file: USERSPACE_PAYLOAD_ARTIFACT_FILE.to_owned(),
                bytes: bootfs_signed.len() as u64,
                sha256: sha256_hex(&bootfs_signed),
            },
            generated_topology: "generated_topology.rs".to_owned(),
            components: vec![
                "/".to_owned(),
                "/plugins".to_owned(),
                "/plugins/compiler".to_owned(),
                "/plugins/http-client".to_owned(),
                "/plugins/compositor".to_owned(),
                "/inspector".to_owned(),
                "/inspector/tls".to_owned(),
                "/inspector/worker".to_owned(),
            ],
        };

        let json = serde_json::to_string_pretty(&manifest).expect("serialize manifest");
        let parsed: ThreePartImageManifest =
            serde_json::from_str(&json).expect("round-trip manifest");
        assert_eq!(parsed, manifest);

        // Verify Part 2 signed component-manager payload and reject tampering.
        let verified_mgr = verify_signed_payload(&manager_signed, &[verifying_key])
            .expect("component-manager signature verifies");
        assert_eq!(verified_mgr.payload(), manager_unsigned);
        let mut tampered_mgr = manager_signed.clone();
        tampered_mgr[0] ^= 0xff;
        assert!(verify_signed_payload(&tampered_mgr, &[verifying_key]).is_err());

        // Verify Part 3 signed user-space payload and reject tampering.
        let leaked_bootfs: &'static [u8] = Box::leak(bootfs_signed.clone().into_boxed_slice());
        let verified_bootfs = bootfs::Image::parse_signed(leaked_bootfs, &[verifying_key])
            .expect("userspace bootfs signature verifies");
        assert_eq!(verified_bootfs.signer, verifying_key);
        let mut tampered_bootfs = bootfs_signed;
        tampered_bootfs[0] ^= 0xff;
        assert!(bootfs::verified_signer(&tampered_bootfs).is_err());
    }

    #[test]
    fn structured_askama_template_renders_mounts_sockets_and_all_runners() {
        use helios_component_manager::{
            AuthorityScopeSpec, CapabilityCeiling, ComponentNode, ComponentTopology,
            ContainerMountSharingSpec, ContainerMountSpec, Criticality, DirectoryGrantSpec,
            EnvVarSpec, EscalationAction, ExecRunnerSpec, FsRights, HardwarePredicates, IpAddrSpec,
            LifecycleKind, MachineRights, MountRights, MountSharingSpec, MountSourceSpec,
            MountSpec, NetRights, OciRunnerSpec, OomTier, PortCeiling, RestartPolicy, RunnerSpec,
            SocketActivationSpec, StartupPolicy, VmRunnerSpec, VmShareSpec,
        };
        use std::borrow::Cow;

        let mut root = ComponentNode {
            moniker: Cow::Borrowed("/"),
            instance_name: Cow::Borrowed("root"),
            parent_index: None,
            children_indices: Cow::Borrowed(&[1, 2, 3]),
            runner: RunnerSpec::Realm,
            startup: StartupPolicy::Lazy,
            lifecycle: LifecycleKind::Service,
            requires: HardwarePredicates::NONE,
            after: Cow::Borrowed(&[]),
            mounts: Cow::Owned(vec![
                MountSpec {
                    source: MountSourceSpec::Memory,
                    path: Cow::Borrowed("/tmp"),
                    sharing: MountSharingSpec::Shared,
                    read_only: false,
                    compress: None,
                    commit: None,
                    max_inline: None,
                },
                MountSpec {
                    source: MountSourceSpec::Btrfs(Cow::Borrowed("vol-0")),
                    path: Cow::Borrowed("/data"),
                    sharing: MountSharingSpec::Private,
                    read_only: false,
                    compress: Some(Cow::Borrowed("zstd:3")),
                    commit: Some(30),
                    max_inline: Some(4096),
                },
                MountSpec {
                    source: MountSourceSpec::Disk(Cow::Borrowed("disk-0")),
                    path: Cow::Borrowed("/mnt/raw"),
                    sharing: MountSharingSpec::Shared,
                    read_only: true,
                    compress: None,
                    commit: None,
                    max_inline: None,
                },
            ]),
            restart: RestartPolicy::Never,
            restart_backoff_ms: 250,
            restart_backoff_max_ms: 30_000,
            burst_limit: 5,
            burst_window_ms: 60_000,
            stop_timeout_ms: 5_000,
            critical: Criticality::None,
            escalation: EscalationAction::Halt,
            oom_tier: OomTier::Protected,
            dynamic_mount: false,
            capabilities: CapabilityCeiling {
                directories: Cow::Owned(vec![DirectoryGrantSpec {
                    source: Cow::Borrowed("/"),
                    guest: Cow::Borrowed("/"),
                    rights: FsRights::ALL,
                }]),
                network: NetRights::ALL,
                tcp_ports: PortCeiling::Any,
                vsock_ports: PortCeiling::Any,
                mount: MountRights::ALL,
                machine: MachineRights::ALL,
                inspect_read: AuthorityScopeSpec::Machine,
                ..CapabilityCeiling::EMPTY
            },
            exposes: Cow::Borrowed(&[]),
            routes: Cow::Borrowed(&[]),
            sockets: Cow::Borrowed(&[]),
        };
        let mut oci = root.clone();
        oci.moniker = Cow::Borrowed("/oci");
        oci.instance_name = Cow::Borrowed("oci");
        oci.parent_index = Some(0);
        oci.children_indices = Cow::Borrowed(&[]);
        oci.mounts = Cow::Borrowed(&[]);
        oci.oom_tier = OomTier::User;
        oci.runner = RunnerSpec::Oci(OciRunnerSpec {
            image: Some(Cow::Borrowed("alpine:3.20")),
            rootfs: None,
            store: Some(Cow::Borrowed("/var/lib/oci")),
            hostname: Cow::Borrowed("oci"),
            uid: 1000,
            gid: 1000,
            entrypoint: Cow::Borrowed(&[Cow::Borrowed("/bin/sh")]),
            cmd: Cow::Borrowed(&[Cow::Borrowed("-c"), Cow::Borrowed("echo hi")]),
            env: Cow::Owned(vec![EnvVarSpec {
                key: Cow::Borrowed("K"),
                value: Cow::Borrowed("V"),
            }]),
            cwd: Some(Cow::Borrowed("/app")),
            mounts: Cow::Owned(vec![ContainerMountSpec {
                source: Cow::Borrowed("/data"),
                target: Cow::Borrowed("/data"),
                sharing: ContainerMountSharingSpec::EphemeralOverlay,
                rights: FsRights::READ,
            }]),
        });
        oci.sockets = Cow::Owned(vec![
            SocketActivationSpec::Tcp {
                address: IpAddrSpec::V4([127, 0, 0, 1]),
                port: 8080,
                backlog: 64,
            },
            SocketActivationSpec::Tcp {
                address: IpAddrSpec::V6([0, 0, 0, 0, 0, 0, 0, 1]),
                port: 8443,
                backlog: 32,
            },
            SocketActivationSpec::Vsock {
                port: 5000,
                backlog: 16,
            },
        ]);

        let mut exec = oci.clone();
        exec.moniker = Cow::Borrowed("/exec");
        exec.instance_name = Cow::Borrowed("exec");
        exec.sockets = Cow::Borrowed(&[]);
        exec.runner = RunnerSpec::Exec(ExecRunnerSpec {
            program: Cow::Borrowed("/bin/tool"),
            args: Cow::Borrowed(&[Cow::Borrowed("--flag")]),
            env: Cow::Borrowed(&[]),
            cwd: None,
            optional: true,
        });

        let mut vm = exec.clone();
        vm.moniker = Cow::Borrowed("/vm");
        vm.instance_name = Cow::Borrowed("vm");
        vm.runner = RunnerSpec::Vm(VmRunnerSpec {
            kernel: Cow::Borrowed("/boot/Image"),
            initramfs: Some(Cow::Borrowed("/boot/initrd")),
            disk: Some(Cow::Borrowed("/vm/disk.raw")),
            memory_mib: 256,
            cpus: 2,
            cmdline: Some(Cow::Borrowed("console=hvc0")),
            rootfs_dir: Some(Cow::Borrowed("/vm/rootfs")),
            share_dirs: Cow::Owned(vec![VmShareSpec {
                tag: Cow::Borrowed("work"),
                host_path: Cow::Borrowed("/vm/work"),
            }]),
        });
        root.children_indices = Cow::Borrowed(&[1, 2, 3]);

        let topology = ComponentTopology {
            nodes: Cow::Owned(vec![root, oci, exec, vm]),
        };
        helios_component_manager::validate_topology(&topology).expect("topology validates");
        let rendered = render_topology_rust(&topology).expect("template renders");
        assert!(rendered.contains("parent_index: None,"));
        assert!(rendered.contains("parent_index: Some(0),"));
        assert!(rendered.contains("MountSourceSpec::Btrfs(Cow::Borrowed(\"vol-0\"))"));
        assert!(rendered.contains("MountSourceSpec::Disk(Cow::Borrowed(\"disk-0\"))"));
        assert!(rendered.contains("commit: Some(30),"));
        assert!(rendered.contains("max_inline: Some(4096),"));
        assert!(rendered.contains("IpAddrSpec::V4([127, 0, 0, 1]), port: 8080, backlog: 64"));
        assert!(
            rendered.contains("IpAddrSpec::V6([0, 0, 0, 0, 0, 0, 0, 1]), port: 8443, backlog: 32")
        );
        assert!(rendered.contains("SocketActivationSpec::Vsock { port: 5000, backlog: 16 }"));
        assert!(rendered.contains("ContainerMountSharingSpec::EphemeralOverlay"));
        assert!(rendered.contains("RunnerSpec::Exec(ExecRunnerSpec"));
        assert!(rendered.contains("RunnerSpec::Vm(VmRunnerSpec"));
    }
}
