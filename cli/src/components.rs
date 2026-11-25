//! Compile-time `component.toml` -> native Rust codegen (`askama`) and
//! three-part system image packaging (`helios-kernel`, signed
//! `component-manager.cwasm`, and signed user-space components payload).

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
    EscalationAction, HardwarePredicates, IpAddrSpec, LifecycleKind, ManifestError,
    MountSharingSpec, MountSourceSpec, NameCeiling, OomTier, PortCeiling, ProviderSlot,
    RestartPolicy, RunnerSpec, SocketActivationSpec, StartupPolicy, WasmSharding,
    load_tree_from_dir,
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

/// Why component codegen or three-part image packaging failed.
#[derive(Debug, Error)]
pub enum ComponentBuildError {
    #[error(transparent)]
    WorkspaceRoot(#[from] WorkspaceRootError),
    #[error(transparent)]
    Manifest(#[from] ManifestError),
    #[error(transparent)]
    Prebuild(#[from] PrebuildError),
    #[error(transparent)]
    WasmBuild(#[from] WasmBuildError),
    #[error("failed to render component topology template: {source}")]
    RenderTemplate {
        #[source]
        source: askama::Error,
    },
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
pub fn render_topology_rust(topology: &ComponentTopology) -> Result<String, ComponentBuildError> {
    let nodes = topology.nodes.iter().map(NodeView::from_node).collect();
    let template = ComponentTopologyTemplate { nodes };
    let mut rendered = template
        .render()
        .map_err(|source| ComponentBuildError::RenderTemplate { source })?;
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

fn rust_lit(s: &str) -> String {
    format!("{s:?}")
}

#[derive(Template)]
#[template(path = "component_topology.rs.askama", escape = "none")]
struct ComponentTopologyTemplate {
    nodes: Vec<NodeView>,
}

struct NodeView {
    moniker: String,
    instance_name: String,
    parent_index: String,
    children_indices: Vec<usize>,
    runner: RunnerView,
    startup: &'static str,
    lifecycle: &'static str,
    requires: HardwarePredicates,
    after: Vec<usize>,
    mounts: Vec<MountView>,
    restart: &'static str,
    restart_backoff_ms: u64,
    restart_backoff_max_ms: u64,
    burst_limit: u32,
    burst_window_ms: u64,
    stop_timeout_ms: u64,
    critical: &'static str,
    escalation: &'static str,
    oom_tier: &'static str,
    dynamic_mount: bool,
    capabilities: CapabilitiesView,
    exposes: Vec<ExposeView>,
    routes: Vec<RouteView>,
    sockets: Vec<SocketView>,
}

enum RunnerView {
    Realm,
    Wasm(WasmRunnerView),
    Oci(OciRunnerView),
    Exec(ExecRunnerView),
    Vm(VmRunnerView),
}

struct WasmRunnerView {
    program: String,
    sharding: &'static str,
    provider: &'static str,
    args: Vec<String>,
    env: Vec<EnvVarView>,
    cwd: Option<String>,
    optional: bool,
}

struct OciRunnerView {
    image: Option<String>,
    rootfs: Option<String>,
    store: Option<String>,
    hostname: String,
    uid: u32,
    gid: u32,
    entrypoint: Vec<String>,
    cmd: Vec<String>,
    env: Vec<EnvVarView>,
    cwd: Option<String>,
    mounts: Vec<ContainerMountView>,
}

struct ContainerMountView {
    source: String,
    target: String,
    sharing: &'static str,
    rights_bits: u8,
}

struct ExecRunnerView {
    program: String,
    args: Vec<String>,
    env: Vec<EnvVarView>,
    cwd: Option<String>,
    optional: bool,
}

struct VmRunnerView {
    kernel: String,
    initramfs: Option<String>,
    disk: Option<String>,
    memory_mib: u64,
    cpus: u32,
    cmdline: Option<String>,
    rootfs_dir: Option<String>,
    share_dirs: Vec<VmShareView>,
}

struct VmShareView {
    tag: String,
    host_path: String,
}

struct EnvVarView {
    key: String,
    value: String,
}

struct MountView {
    source_expr: String,
    path: String,
    sharing: &'static str,
    read_only: bool,
    compress: Option<String>,
    commit: String,
    max_inline: String,
}

struct DirectoryView {
    source: String,
    guest: String,
    rights_bits: u8,
}

enum PortCeilingView {
    Any,
    Set(Vec<u16>),
}

enum VsockCeilingView {
    Any,
    Set(Vec<u32>),
}

enum NameCeilingView {
    Any,
    Set(Vec<String>),
}

struct CapabilitiesView {
    directories: Vec<DirectoryView>,
    network_bits: u8,
    tcp_ports: PortCeilingView,
    vsock_ports: VsockCeilingView,
    clock_bits: u8,
    terminal_bits: u8,
    process_bits: u8,
    link_bits: u8,
    mount_bits: u8,
    devices_bits: u8,
    named_devices: NameCeilingView,
    inspect_read: &'static str,
    trace_read: &'static str,
    profile_read: &'static str,
    diagnostics_control: bool,
    instance_control: &'static str,
    settings_write: bool,
    machine_bits: u8,
    wit_interfaces: NameCeilingView,
}

struct ExposeView {
    interface: String,
    channel: String,
}

struct RouteView {
    interface: String,
    provider_index: usize,
    provider_moniker: String,
    provider_channel: String,
    consumer_channel: String,
}

struct SocketView {
    expr: String,
}

impl NodeView {
    fn from_node(node: &ComponentNode) -> Self {
        let parent_index = match node.parent_index {
            Some(idx) => format!("Some({idx})"),
            None => "None".to_owned(),
        };
        let runner = match &node.runner {
            RunnerSpec::Realm => RunnerView::Realm,
            RunnerSpec::Wasm(w) => RunnerView::Wasm(WasmRunnerView {
                program: rust_lit(w.program.as_ref()),
                sharding: match w.sharding {
                    WasmSharding::Singleton => "WasmSharding::Singleton",
                    WasmSharding::PerProcessor => "WasmSharding::PerProcessor",
                },
                provider: match w.provider {
                    None => "None",
                    Some(ProviderSlot::Compiler) => "Some(ProviderSlot::Compiler)",
                    Some(ProviderSlot::HttpClient) => "Some(ProviderSlot::HttpClient)",
                    Some(ProviderSlot::Surface) => "Some(ProviderSlot::Surface)",
                },
                args: w.args.iter().map(|s| rust_lit(s.as_ref())).collect(),
                env: w
                    .env
                    .iter()
                    .map(|e| EnvVarView {
                        key: rust_lit(e.key.as_ref()),
                        value: rust_lit(e.value.as_ref()),
                    })
                    .collect(),
                cwd: w.cwd.as_deref().map(rust_lit),
                optional: w.optional,
            }),
            RunnerSpec::Oci(o) => RunnerView::Oci(OciRunnerView {
                image: o.image.as_deref().map(rust_lit),
                rootfs: o.rootfs.as_deref().map(rust_lit),
                store: o.store.as_deref().map(rust_lit),
                hostname: rust_lit(o.hostname.as_ref()),
                uid: o.uid,
                gid: o.gid,
                entrypoint: o.entrypoint.iter().map(|s| rust_lit(s.as_ref())).collect(),
                cmd: o.cmd.iter().map(|s| rust_lit(s.as_ref())).collect(),
                env: o
                    .env
                    .iter()
                    .map(|e| EnvVarView {
                        key: rust_lit(e.key.as_ref()),
                        value: rust_lit(e.value.as_ref()),
                    })
                    .collect(),
                cwd: o.cwd.as_deref().map(rust_lit),
                mounts: o
                    .mounts
                    .iter()
                    .map(|m| ContainerMountView {
                        source: rust_lit(m.source.as_ref()),
                        target: rust_lit(m.target.as_ref()),
                        sharing: match m.sharing {
                            ContainerMountSharingSpec::Private => {
                                "ContainerMountSharingSpec::Private"
                            }
                            ContainerMountSharingSpec::Shared => {
                                "ContainerMountSharingSpec::Shared"
                            }
                            ContainerMountSharingSpec::EphemeralOverlay => {
                                "ContainerMountSharingSpec::EphemeralOverlay"
                            }
                        },
                        rights_bits: m.rights.bits(),
                    })
                    .collect(),
            }),
            RunnerSpec::Exec(x) => RunnerView::Exec(ExecRunnerView {
                program: rust_lit(x.program.as_ref()),
                args: x.args.iter().map(|s| rust_lit(s.as_ref())).collect(),
                env: x
                    .env
                    .iter()
                    .map(|e| EnvVarView {
                        key: rust_lit(e.key.as_ref()),
                        value: rust_lit(e.value.as_ref()),
                    })
                    .collect(),
                cwd: x.cwd.as_deref().map(rust_lit),
                optional: x.optional,
            }),
            RunnerSpec::Vm(v) => RunnerView::Vm(VmRunnerView {
                kernel: rust_lit(v.kernel.as_ref()),
                initramfs: v.initramfs.as_deref().map(rust_lit),
                disk: v.disk.as_deref().map(rust_lit),
                memory_mib: v.memory_mib,
                cpus: v.cpus,
                cmdline: v.cmdline.as_deref().map(rust_lit),
                rootfs_dir: v.rootfs_dir.as_deref().map(rust_lit),
                share_dirs: v
                    .share_dirs
                    .iter()
                    .map(|s| VmShareView {
                        tag: rust_lit(s.tag.as_ref()),
                        host_path: rust_lit(s.host_path.as_ref()),
                    })
                    .collect(),
            }),
        };

        let mounts = node
            .mounts
            .iter()
            .map(|m| {
                let source_expr = match &m.source {
                    MountSourceSpec::Memory => "MountSourceSpec::Memory".to_owned(),
                    MountSourceSpec::BootImage => "MountSourceSpec::BootImage".to_owned(),
                    MountSourceSpec::HostShare => "MountSourceSpec::HostShare".to_owned(),
                    MountSourceSpec::Disk(s) => {
                        format!("MountSourceSpec::Disk(Cow::Borrowed({}))", rust_lit(s))
                    }
                    MountSourceSpec::Btrfs(s) => {
                        format!("MountSourceSpec::Btrfs(Cow::Borrowed({}))", rust_lit(s))
                    }
                };
                MountView {
                    source_expr,
                    path: rust_lit(m.path.as_ref()),
                    sharing: match m.sharing {
                        MountSharingSpec::Private => "MountSharingSpec::Private",
                        MountSharingSpec::Shared => "MountSharingSpec::Shared",
                    },
                    read_only: m.read_only,
                    compress: m.compress.as_deref().map(rust_lit),
                    commit: match m.commit {
                        Some(v) => format!("Some({v})"),
                        None => "None".to_owned(),
                    },
                    max_inline: match m.max_inline {
                        Some(v) => format!("Some({v})"),
                        None => "None".to_owned(),
                    },
                }
            })
            .collect();

        let cap = &node.capabilities;
        let capabilities = CapabilitiesView {
            directories: cap
                .directories
                .iter()
                .map(|d| DirectoryView {
                    source: rust_lit(d.source.as_ref()),
                    guest: rust_lit(d.guest.as_ref()),
                    rights_bits: d.rights.bits(),
                })
                .collect(),
            network_bits: cap.network.bits(),
            tcp_ports: match &cap.tcp_ports {
                PortCeiling::Any => PortCeilingView::Any,
                PortCeiling::Set(ports) => PortCeilingView::Set(ports.to_vec()),
            },
            vsock_ports: match &cap.vsock_ports {
                PortCeiling::Any => VsockCeilingView::Any,
                PortCeiling::Set(ports) => VsockCeilingView::Set(ports.to_vec()),
            },
            clock_bits: cap.clock.bits(),
            terminal_bits: cap.terminal.bits(),
            process_bits: cap.process.bits(),
            link_bits: cap.link.bits(),
            mount_bits: cap.mount.bits(),
            devices_bits: cap.devices.bits(),
            named_devices: match &cap.named_devices {
                NameCeiling::Any => NameCeilingView::Any,
                NameCeiling::Set(items) => {
                    NameCeilingView::Set(items.iter().map(|s| rust_lit(s.as_ref())).collect())
                }
            },
            inspect_read: scope_expr(cap.inspect_read),
            trace_read: scope_expr(cap.trace_read),
            profile_read: scope_expr(cap.profile_read),
            diagnostics_control: cap.diagnostics_control,
            instance_control: scope_expr(cap.instance_control),
            settings_write: cap.settings_write,
            machine_bits: cap.machine.bits(),
            wit_interfaces: match &cap.wit_interfaces {
                NameCeiling::Any => NameCeilingView::Any,
                NameCeiling::Set(items) => {
                    NameCeilingView::Set(items.iter().map(|s| rust_lit(s.as_ref())).collect())
                }
            },
        };

        let exposes = node
            .exposes
            .iter()
            .map(|e| ExposeView {
                interface: rust_lit(e.interface.as_ref()),
                channel: rust_lit(e.channel.as_ref()),
            })
            .collect();

        let routes = node
            .routes
            .iter()
            .map(|r| RouteView {
                interface: rust_lit(r.interface.as_ref()),
                provider_index: r.provider_index,
                provider_moniker: rust_lit(r.provider_moniker.as_ref()),
                provider_channel: rust_lit(r.provider_channel.as_ref()),
                consumer_channel: rust_lit(r.consumer_channel.as_ref()),
            })
            .collect();

        let sockets = node
            .sockets
            .iter()
            .map(|s| {
                let expr = match *s {
                    SocketActivationSpec::Tcp {
                        address,
                        port,
                        backlog,
                    } => {
                        let addr = match address {
                            IpAddrSpec::V4(octets) => format!("IpAddrSpec::V4({octets:?})"),
                            IpAddrSpec::V6(segs) => format!("IpAddrSpec::V6({segs:?})"),
                        };
                        format!(
                            "SocketActivationSpec::Tcp {{ address: {addr}, port: {port}, backlog: {backlog} }}"
                        )
                    }
                    SocketActivationSpec::Vsock { port, backlog } => {
                        format!(
                            "SocketActivationSpec::Vsock {{ port: {port}, backlog: {backlog} }}"
                        )
                    }
                };
                SocketView { expr }
            })
            .collect();

        Self {
            moniker: rust_lit(node.moniker.as_ref()),
            instance_name: rust_lit(node.instance_name.as_ref()),
            parent_index,
            children_indices: node.children_indices.to_vec(),
            runner,
            startup: match node.startup {
                StartupPolicy::Lazy => "StartupPolicy::Lazy",
                StartupPolicy::Eager => "StartupPolicy::Eager",
            },
            lifecycle: match node.lifecycle {
                LifecycleKind::Service => "LifecycleKind::Service",
                LifecycleKind::Oneshot => "LifecycleKind::Oneshot",
            },
            requires: node.requires,
            after: node.after.to_vec(),
            mounts,
            restart: match node.restart {
                RestartPolicy::Never => "RestartPolicy::Never",
                RestartPolicy::OnFailure => "RestartPolicy::OnFailure",
                RestartPolicy::Always => "RestartPolicy::Always",
            },
            restart_backoff_ms: node.restart_backoff_ms,
            restart_backoff_max_ms: node.restart_backoff_max_ms,
            burst_limit: node.burst_limit,
            burst_window_ms: node.burst_window_ms,
            stop_timeout_ms: node.stop_timeout_ms,
            critical: match node.critical {
                Criticality::None => "Criticality::None",
                Criticality::Parent => "Criticality::Parent",
                Criticality::System => "Criticality::System",
            },
            escalation: match node.escalation {
                EscalationAction::Halt => "EscalationAction::Halt",
                EscalationAction::Reboot => "EscalationAction::Reboot",
            },
            oom_tier: match node.oom_tier {
                OomTier::User => "OomTier::User",
                OomTier::Plugin => "OomTier::Plugin",
                OomTier::Protected => "OomTier::Protected",
            },
            dynamic_mount: node.dynamic_mount,
            capabilities,
            exposes,
            routes,
            sockets,
        }
    }
}

const fn scope_expr(scope: AuthorityScopeSpec) -> &'static str {
    match scope {
        AuthorityScopeSpec::None => "AuthorityScopeSpec::None",
        AuthorityScopeSpec::Own => "AuthorityScopeSpec::Own",
        AuthorityScopeSpec::Subtree => "AuthorityScopeSpec::Subtree",
        AuthorityScopeSpec::Machine => "AuthorityScopeSpec::Machine",
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
                path: "bin/debugger",
                data: b"synthetic-debugger",
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
                "/debugger".to_owned(),
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
}
