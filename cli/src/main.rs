use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::time::{Duration, UNIX_EPOCH};

use artifact_cache::{
    ArtifactCache, CacheError, EntryKind, FeatureSet, KeyBuilder, PrecompileCache, PrecompileError,
    lock_closure_digest, package_directories, package_name, precompile, prune, workspace_inputs,
    workspace_manifest_digest,
};
use askama::Template;
use clap::{Parser, Subcommand, ValueEnum};
use ed25519_dalek::{SecretKey, SigningKey, VerifyingKey};
use fatfs::{FatType, FileSystem, FormatVolumeOptions, FsOptions};
use helios_artifact::bootfs::{self, WriteEntry};
use helios_artifact::{
    CwasmTarget, IsaLevelError, cwasm_target_isa_levels, cwasm_target_supports_wasm_simd,
};
use helios_compiler_support::AotCompileHint;
use helios_inspector_protocol::auth::{AuthError, AuthPolicy, INSPECTOR_POLICY_PATH};
use helios_profdata::{
    FetchedProfile, KERNEL_PROFILE_ARTIFACT, KERNEL_PROFILE_ASSET, KERNEL_PROFILE_WORKFLOW,
    KernelProfileStore, KernelProfileStoreError, ProfileUseError, RELEASE_REPOSITORY,
};
use helios_workspace_root::prebuilt_manifest::{
    PREBUILT_MANIFEST_FILE, PREBUILT_SCHEMA_VERSION, PrebuiltArtifactKind, PrebuiltManifest,
    PrebuiltManifestError, PrebuiltPrograms, read_manifest, write_manifest,
};
use helios_workspace_root::root_key::{
    INSPECTOR_CLIENT_SECRET_FILE, INSPECTOR_POLICY_FILE, ROOT_PUBLIC_FILE, ROOT_SECRET_FILE,
    RootSecretReadError, SECRET_KEY_MODE, read_root_secret_seed,
};
use helios_workspace_root::{WorkspaceRoot, WorkspaceRootError};
use mbrman::{BOOT_ACTIVE, CHS, MBR, MBRPartitionEntry};
use rand::{TryRng, rngs::SysRng};
use serde::{Deserialize, Serialize};
use toml::Value;
use walkdir::WalkDir;
use wasmparser::Parser as WasmParser;
use wit_component::ComponentEncoder;

mod artifact_cache;
mod boot_kernel;
mod components;
mod kernel_image;
mod prebuilt_artifact;
mod venus_fetch;
mod wasi_sdk;

/// Why a `helios-cli` invocation did not do what it was asked.
///
/// One variant per subcommand: each owns the typed error of the work it
/// drives, so a failure names the command that produced it before it
/// names the step.
#[derive(Debug, thiserror::Error)]
enum CliError {
    #[error("{0}")]
    ArtifactCachePrune(#[from] CacheError),
    #[error("{0}")]
    ArtifactFetch(#[from] prebuilt_artifact::ArtifactFetchError),
    #[error("{0}")]
    ArtifactStage(#[from] prebuilt_artifact::ArtifactStageError),
    #[error("{0}")]
    ComponentBuild(#[from] components::ComponentBuildError),
    #[error("{0}")]
    KernelImage(#[from] kernel_image::KernelImageError),
    #[error("{0}")]
    KernelPrebuild(#[from] PrebuildError),
    #[error("{0}")]
    LimineUefiImage(#[from] LimineError),
    #[error("{0}")]
    ProfileFetch(#[from] ProfileFetchError),
    #[error("{0}")]
    VenusProtocolFetch(#[from] venus_fetch::VenusFetchError),
    #[error("{0}")]
    WasmBuild(#[from] WasmProgramsError),
    #[error("{0}")]
    WorkspaceRoot(#[from] WorkspaceRootError),
}

/// Why the guest wasm directory `wasm-build` writes could not be produced.
#[derive(Debug, thiserror::Error)]
enum WasmProgramsError {
    #[error("{0}")]
    WorkspaceRoot(#[from] WorkspaceRootError),
    #[error("{0}")]
    BootPrograms(#[from] BootProgramError),
    #[error("{0}")]
    WasmBuild(#[from] WasmBuildError),
    #[error("{0}")]
    Cache(#[from] CacheError),
    #[error("the host does not report its available parallelism: {source}")]
    Parallelism {
        #[source]
        source: io::Error,
    },
    #[error("failed to create {path}: {source}")]
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
    #[error(
        "{first} and {second} both build {artifact}; a prebuilt directory is keyed by artifact name"
    )]
    DuplicateArtifact {
        artifact: String,
        first: String,
        second: String,
    },
    #[error("unknown guest program(s): {unknown}")]
    UnknownPrograms { unknown: String },
    #[error("{0}")]
    Manifest(#[from] PrebuiltManifestError),
}

/// Why the root signing keypair could not be read or written.
#[derive(Debug, thiserror::Error)]
enum KeyError {
    #[error("{0}")]
    Read(#[from] RootSecretReadError),
    #[error("failed to write {path}: {source}")]
    Write {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("the operating system refused to supply entropy for a new root key: {source}")]
    Entropy {
        #[source]
        source: rand::rngs::SysError,
    },
    #[error(
        "--root-secret-key {path} is not a file; the key a release signs with is never generated"
    )]
    SuppliedKeyMissing { path: String },
}

/// Why the kernel-prebuild manifest and the bootfs it describes could
/// not be produced.
#[derive(Debug, thiserror::Error)]
pub(crate) enum PrebuildError {
    #[error("{0}")]
    WorkspaceRoot(#[from] WorkspaceRootError),
    #[error("{0}")]
    Key(#[from] KeyError),
    #[error("{0}")]
    BootPrograms(#[from] BootProgramError),
    #[error("{0}")]
    BootArtifacts(#[from] BootArtifactsError),
    #[error("{0}")]
    WasmBuild(#[from] WasmBuildError),
    #[error("{0}")]
    Bootfs(#[from] BootfsError),
    #[error("{0}")]
    IsaLevel(#[from] IsaLevelError),
    #[error("{0}")]
    Precompile(#[from] PrecompileError),
    #[error("{0}")]
    Cache(#[from] CacheError),
    #[error("failed to create {path}: {source}")]
    CreateOutDir {
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
    #[error("failed to resolve {path}: {source}")]
    Resolve {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("failed to encode the kernel-prebuild manifest: {source}")]
    EncodeManifest {
        #[source]
        source: serde_json::Error,
    },
    #[error("failed to read inspector auth policy {path}: {source}")]
    ReadInspectorPolicy {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("invalid inspector auth policy {path}: {source}")]
    InvalidInspectorPolicy {
        path: String,
        #[source]
        source: AuthError,
    },
    #[error("failed to encode inspector auth policy: {source}")]
    EncodeInspectorPolicy {
        #[source]
        source: AuthError,
    },
}

/// Why one wasm program could not be built into an artifact.
#[derive(Debug, thiserror::Error)]
pub(crate) enum WasmBuildError {
    #[error("failed to parse wasm build settings in {path}: {source}")]
    ManifestSettings {
        path: String,
        #[source]
        source: toml::de::Error,
    },
    #[error(transparent)]
    VenusInputs(#[from] venus_fetch::VenusFetchError),
    #[error(transparent)]
    WasiSdk(#[from] wasi_sdk::WasiSdkError),
    #[error(transparent)]
    Workspace(#[from] WorkspaceRootError),
    #[error("crate manifest {path} is missing")]
    ManifestMissing { path: String },
    #[error("failed to invoke cargo for {path}: {source}")]
    SpawnCargo {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("wasm build for {path} target {target} failed with status {status}")]
    BuildFailed {
        path: String,
        target: String,
        status: std::process::ExitStatus,
    },
    #[error("failed to resolve generated artifact {artifact}: {source}")]
    ResolveArtifact {
        artifact: String,
        #[source]
        source: io::Error,
    },
    #[error("failed to read {path}: {source}")]
    Read {
        path: String,
        #[source]
        source: io::Error,
    },
    /// wit-component reports through `anyhow`, which keeps no type to
    /// carry here, so its own report travels as the text it renders —
    /// the whole chain, not just its outermost line.
    #[error("failed to load core module {path}: {report}")]
    LoadCoreModule { path: String, report: String },
    #[error("failed to encode component {path}: {report}")]
    EncodeComponent { path: String, report: String },
    /// wac-types reports through `anyhow`; its chain travels as text.
    #[error("failed to load {name} into the composition graph: {report}")]
    LoadComposed { name: String, report: String },
    #[error("failed to register {name} in the composition graph: {source}")]
    RegisterComposed {
        name: String,
        #[source]
        source: wac_graph::RegisterPackageError,
    },
    /// `PlugError` carries an `anyhow` source, so the rendered chain is
    /// kept beside the variant.
    #[error("failed to plug {plugs} into {command}: {report}")]
    Plug {
        command: String,
        plugs: String,
        report: String,
    },
    #[error("failed to encode the composition of {command}: {source}")]
    EncodeComposition {
        command: String,
        #[source]
        source: wac_graph::EncodeError,
    },
    #[error("failed to run `rustc {query}`: {source}")]
    SpawnRustc {
        query: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("`rustc {query}` failed with status {status}")]
    RustcFailed {
        query: &'static str,
        status: std::process::ExitStatus,
    },
    #[error(
        "the toolchain has no llvm-ar at {path}; rust-toolchain.toml lists the \
         llvm-tools component that ships it"
    )]
    LlvmArMissing { path: String },
    #[error(
        "prebuilt wasm {path} is missing; `helios-cli wasm-build --profile {profile}` \
         writes the directory --prebuilt-wasm names"
    )]
    PrebuiltMissing { path: String, profile: String },
    #[error("invalid prebuilt userspace manifest in {dir}: {source}")]
    PrebuiltManifest {
        dir: String,
        #[source]
        source: PrebuiltManifestError,
    },
    #[error("prebuilt userspace directory {dir} holds a {found} artifact, expected userspace")]
    PrebuiltWrongKind {
        dir: String,
        found: PrebuiltArtifactKind,
    },
    #[error(
        "prebuilt userspace directory {dir} was built for profile {found:?}, expected {expected:?}"
    )]
    PrebuiltProfileMismatch {
        dir: String,
        expected: String,
        found: String,
    },
    #[error("{0}")]
    Cache(#[from] CacheError),
    #[error("crate manifest {manifest} is outside the workspace {root}, so no cache key names it")]
    ManifestOutsideWorkspace { manifest: String, root: String },
    #[error("Cargo.lock is not UTF-8: {source}")]
    LockNotUtf8 {
        #[source]
        source: std::str::Utf8Error,
    },
    #[error("failed to write the cached artifact {path}: {source}")]
    WriteCached {
        path: String,
        #[source]
        source: io::Error,
    },
}

/// Why the set of boot programs could not be resolved from the
/// workspace and the selection the caller made.
#[derive(Debug, thiserror::Error)]
enum BootProgramError {
    #[error("--boot-program must name at least one boot program")]
    EmptyFlagSelection,
    #[error("HELIOS_BOOT_PROGRAMS must name at least one boot program")]
    EmptyEnvSelection,
    #[error("HELIOS_BOOT_PROGRAMS referenced unknown program(s): {missing}")]
    UnknownPrograms { missing: String },
    #[error(
        "program {command} plugs {plug}, which is no library component under programs/ \
         (package.metadata.helios.library)"
    )]
    UnknownPlug { command: String, plug: String },
    #[error("a library component cannot plug others: {command} names {plugs}")]
    LibraryPlugs { command: String, plugs: String },
    #[error("failed to read {path}: {source}")]
    ReadProgramsRoot {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("failed to read programs directory entry: {source}")]
    ReadProgramsEntry {
        #[source]
        source: io::Error,
    },
    #[error("program directory {path} has no valid UTF-8 name")]
    ProgramNameNotUtf8 { path: String },
    #[error("default program crate manifest {path} is missing")]
    ManifestMissing { path: String },
    #[error("failed to read {path}: {source}")]
    ReadManifest {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("failed to parse {path}: {source}")]
    ParseManifest {
        path: String,
        #[source]
        source: toml::de::Error,
    },
    #[error("{path} is missing package.name or lib.name")]
    ManifestHasNoName { path: String },
    #[error("{path} specifies invalid package.metadata.helios.command `{command}`")]
    InvalidCommandName { path: String, command: String },
}

/// Why the external boot-artifacts manifest does not describe artifacts
/// this build can use.
#[derive(Debug, thiserror::Error)]
enum BootArtifactsError {
    #[error("boot artifacts manifest {path} is missing")]
    ManifestMissing { path: String },
    #[error("failed to read boot artifacts manifest {path}: {source}")]
    ReadManifest {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("failed to parse boot artifacts manifest {path}: {source}")]
    ParseManifest {
        path: String,
        #[source]
        source: toml::de::Error,
    },
    #[error("boot artifact in {path} has an empty command")]
    EmptyCommand { path: String },
    #[error("boot artifact {command} in {path} has an empty {field}")]
    EmptyField {
        command: String,
        path: String,
        /// The manifest key that was empty, spelled the way the message
        /// reads it.
        field: &'static str,
    },
    #[error("boot artifact {command} must install under bin/")]
    BootfsPathNotUnderBin { command: String },
    #[error("boot artifact {command} source must be workspace-relative")]
    SourceNotRelative { command: String },
    #[error("boot artifact {command} support root must be workspace-relative")]
    SupportRootNotRelative { command: String },
    #[error(
        "boot artifact {command} support_root and support_bootfs_prefix must be specified together"
    )]
    SupportPairMismatch { command: String },
    #[error("boot artifact {command} support bootfs prefix must be relative")]
    SupportPrefixNotRelative { command: String },
    #[error("boot artifact {command} declares an empty target")]
    EmptyTarget { command: String },
    #[error("boot artifact support root {path} is missing")]
    SupportRootMissing { path: String },
    #[error("boot program command {command} is declared more than once")]
    DuplicateCommand { command: String },
    #[error("boot program(s) are not available for target {target}: {mismatches}")]
    TargetMismatch { target: String, mismatches: String },
}

/// Why one bootfs asset could not be produced.
#[derive(Debug, thiserror::Error)]
enum BootfsError {
    #[error("{0}")]
    WasmBuild(#[from] WasmBuildError),
    #[error("{0}")]
    Precompile(#[from] PrecompileError),
    #[error("{0}")]
    BootArtifacts(#[from] BootArtifactsError),
    #[error("{0}")]
    BootPrograms(#[from] BootProgramError),
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
    #[error("failed to resolve {path}: {source}")]
    Resolve {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("failed to walk support root {path}: {source}")]
    WalkSupportRoot {
        path: String,
        #[source]
        source: walkdir::Error,
    },
    #[error("failed to strip support root {root} from {source_path}: {source}")]
    StripSupportRoot {
        root: String,
        source_path: String,
        #[source]
        source: std::path::StripPrefixError,
    },
    #[error("{path} is not valid UTF-8")]
    PathNotUtf8 { path: String },
    #[error("failed to walk bootfs root {path}: {source}")]
    WalkBootfsRoot {
        path: String,
        #[source]
        source: walkdir::Error,
    },
    #[error("modification time of {path} is not representable as nanoseconds since the epoch")]
    ModifiedBeforeEpoch { path: String },
    #[error("failed to read directory {path}: {source}")]
    ReadDir {
        path: String,
        #[source]
        source: io::Error,
    },
}

/// Why the Limine UEFI disk image could not be built.
#[derive(Debug, thiserror::Error)]
pub(crate) enum LimineError {
    #[error("failed to canonicalize kernel {path}: {source}")]
    CanonicalizeKernel {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("failed to canonicalize bootfs payload {path}: {source}")]
    CanonicalizeBootfs {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("failed to find Limine; install `limine` or set HELIOS_LIMINE_BIN")]
    ToolchainMissing,
    #[error("failed to locate Limine shared files; set HELIOS_LIMINE_SHARE")]
    ShareDirMissing,
    #[error("Limine EFI bootloader is missing: {path}")]
    BootloaderMissing { path: String },
    #[error("failed to inspect {path}: {source}")]
    Inspect {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("failed to create image directory {path}: {source}")]
    CreateImageDir {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("failed to create Limine image {path}: {source}")]
    CreateImage {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("failed to size Limine image {path}: {source}")]
    SizeImage {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("failed to create Limine image MBR: {source}")]
    CreateMbr {
        #[source]
        source: mbrman::Error,
    },
    #[error("Limine UEFI image is too large for an MBR partition table: {source}")]
    ImageTooLarge {
        #[source]
        source: std::num::TryFromIntError,
    },
    #[error("Limine UEFI image is too small for the FAT partition")]
    ImageTooSmall,
    #[error("failed to write Limine image MBR: {source}")]
    WriteMbr {
        #[source]
        source: mbrman::Error,
    },
    #[error("Limine partition offset exceeds image size")]
    PartitionOffsetTooLarge,
    #[error("failed to format Limine FAT32 partition: {source}")]
    FormatPartition {
        #[source]
        source: io::Error,
    },
    #[error("failed to {step}: {source}")]
    Partition {
        /// The partition operation that failed, spelled the way the
        /// message reads it.
        step: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("failed to create {path}: {source}")]
    CreateFatEntry {
        /// The path inside the image, which is fixed by the layout.
        path: &'static str,
        #[source]
        source: io::Error,
    },
    #[error(transparent)]
    BootKernel(#[from] boot_kernel::BootKernelError),
    #[error("failed to write {path}: {source}")]
    WriteFatEntry {
        path: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("failed to render Limine configuration: {source}")]
    RenderConfig {
        #[source]
        source: askama::Error,
    },
    #[error("failed to open source file {path}: {source}")]
    OpenSource {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("failed to create FAT file {name}: {source}")]
    CreateFatFile {
        name: String,
        #[source]
        source: io::Error,
    },
    #[error("failed to copy {path} into FAT file {name}: {source}")]
    CopyIntoFat {
        path: String,
        name: String,
        #[source]
        source: io::Error,
    },
}

const PREBUILD_MANIFEST_FILE: &str = "kernel-prebuild.json";
/// The payload `kernel-prebuild` writes beside the manifest: the whole
/// user payload the kernel used to link in, delivered as a boot module.
pub(crate) const BOOTFS_IMAGE_FILE: &str = "helios-bootfs";
pub(crate) const DEFAULT_INIT_ARGV0: &str = "/init.wasm";
/// The boot-program name `programs/init` answers to, published at
/// `bin/init` like every other boot program.
pub(crate) const INIT_COMMAND: &str = "init";
pub(crate) const DEFAULT_BOOT_ARTIFACTS_MANIFEST: &str = "tools/wasi-apps/boot-artifacts.toml";
/// Why the kernel profile did not reach the store.
///
/// A fetch either leaves a profile this toolchain can build against in
/// the store or fails saying which step did not answer: a release build
/// reads the store and nothing downstream can tell an empty store from a
/// half-written one.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ProfileFetchError {
    #[error("{0}")]
    WorkspaceRoot(#[from] WorkspaceRootError),
    #[error(
        "{variable} holds characters a GitHub token does not: a token is printable ASCII \
         without quotes or backslashes, and this one would be passed to curl as a header"
    )]
    Token { variable: &'static str },
    #[error("failed to run curl for {url}: {source}; the fetch downloads over HTTPS with curl")]
    Curl {
        url: String,
        #[source]
        source: io::Error,
    },
    #[error("failed to hand curl its configuration for {url}: {source}")]
    CurlConfig {
        url: String,
        #[source]
        source: io::Error,
    },
    #[error("curl did not answer {url}: it exited {status} and said {stderr}")]
    CurlExited {
        url: String,
        status: String,
        stderr: String,
    },
    #[error("{url} answered 404: no such repository, release or artifact")]
    NotFound { url: String },
    #[error(
        "{repository} has no release tagged {tag}. Every release carries {KERNEL_PROFILE_ASSET} \
         from release.yml's kernel-profile job (docs/pgo.md); a release cut before that job \
         existed gets its assets by dispatching that workflow with its tag"
    )]
    NoRelease { repository: String, tag: String },
    #[error(
        "no unexpired {KERNEL_PROFILE_ARTIFACT} artifact from a run on {branch} of {repository} \
         among the newest {ARTIFACT_PAGE}; dispatch {KERNEL_PROFILE_WORKFLOW} on that branch \
         (docs/pgo.md). GitHub keeps an artifact ninety days"
    )]
    NoCollection { repository: String, branch: String },
    #[error(
        "no unexpired {KERNEL_PROFILE_ARTIFACT} artifact from run {run} of {repository} among \
         the newest {ARTIFACT_PAGE}; the run's own {KERNEL_PROFILE_WORKFLOW} collection has \
         to have uploaded it first"
    )]
    NoRunCollection { repository: String, run: u64 },
    #[error(
        "{url} answered HTTP {status} without a redirect; GitHub answers an artifact download \
         with a redirect to its object store"
    )]
    NoRedirect { url: String, status: String },
    #[error("artifact {artifact} is not a zip archive this tool can read: {source}")]
    Archive {
        artifact: u64,
        #[source]
        source: zip::result::ZipError,
    },
    #[error(
        "artifact {artifact} holds no {KERNEL_PROFILE_ASSET}; {KERNEL_PROFILE_WORKFLOW} uploads \
         exactly that file"
    )]
    NoProfileInArchive { artifact: u64 },
    #[error("failed to read {KERNEL_PROFILE_ASSET} out of artifact {artifact}: {source}")]
    ReadArchive {
        artifact: u64,
        #[source]
        source: io::Error,
    },
    #[error("{url} answered HTTP {status}: {body}")]
    HttpStatus {
        url: String,
        status: String,
        body: String,
    },
    #[error("curl wrote no HTTP status for {url}; it answered {len} bytes")]
    NoHttpStatus { url: String, len: usize },
    #[error("{url} did not answer with {what}: {source}")]
    Decode {
        url: String,
        what: &'static str,
        #[source]
        source: serde_json::Error,
    },
    #[error(
        "release {tag} of {repository} carries no {KERNEL_PROFILE_ASSET} asset; release.yml's \
         kernel-profile job attaches one to every release that carries a kernel \
         (docs/pgo.md), and an older release gets it by dispatching that workflow with \
         this tag"
    )]
    NoProfileAsset { repository: String, tag: String },
    #[error("failed to create {path}: {source}")]
    CreateDirectory {
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
    #[error("{0}")]
    Profile(#[from] ProfileUseError),
    #[error("{0}")]
    Store(#[from] KernelProfileStoreError),
}

const COMPILER_PLUGIN_BOOTFS_PATH: &str = "bin/compiler.cwasm";
/// The program name `wasm-build --program` uses for the in-kernel compiler plugin.
const COMPILER_PLUGIN_NAME: &str = "compiler-plugin";
const COMPILER_PLUGIN_MANIFEST: &str = "compiler-plugin/Cargo.toml";
const COMPILER_PLUGIN_TARGET_DIR: &str = "compiler-plugin-target";
const COMPILER_PLUGIN_TRIPLE: &str = "wasm32-wasip1-threads";
/// The file the compiler plugin's `cdylib` builds to.
const COMPILER_PLUGIN_WASM: &str = "helios_compiler_plugin.wasm";
/// The file `programs/init` builds to.
pub(crate) const INIT_WASM: &str = "helios_init.wasm";
const COMPILER_PLUGIN_SHARED_MEMORY_MAX_BYTES: usize = 512 * 1024 * 1024;
const LIMINE_IMAGE_BYTES: u64 = 768 * 1024 * 1024;
const LIMINE_PARTITION_START_LBA: u32 = 2048;
const LIMINE_SECTOR_BYTES: u64 = 512;
const LIMINE_EFI_SYSTEM_PARTITION_TYPE: u8 = 0xef;
const LIMINE_DISK_SIGNATURE: [u8; 4] = *b"HELO";

#[derive(Template)]
#[template(path = "limine.conf", escape = "none")]
struct LimineConfigTemplate {
    baud: u32,
}

#[derive(Parser)]
#[command(name = "helios-cli")]
struct Cli {
    /// Directory holding the Cargo workspace manifest that repository-relative
    /// paths resolve against.
    ///
    /// Defaults to the nearest workspace root at or above the current
    /// directory, so the tool operates on the checkout it is run in rather
    /// than the one it was built in.
    #[arg(long, global = true, value_name = "PATH")]
    workspace_root: Option<PathBuf>,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    ArtifactCachePrune(ArtifactCachePruneCommand),
    /// Download a prebuilt CI artifact (`userspace`, `kernel`, or `image`)
    /// into the local user cache or an explicit directory.
    ArtifactFetch(prebuilt_artifact::ArtifactFetchCommand),
    /// Stage a `kernel` or full bootable `image` artifact directory with its
    /// typed `manifest.json`.
    ArtifactStage(prebuilt_artifact::ArtifactStageCommand),
    /// Parse and statically validate a `component.toml` directory tree and emit
    /// static native Rust routing tables and supervisor definitions.
    ComponentCodegen(components::ComponentCodegenCommand),
    /// Validate a `component.toml` directory tree, compile/sign `component-manager`,
    /// and package the three-part system image (`helios-kernel`, `component-manager.cwasm`,
    /// and `userspace-components.bootfs`).
    ImageBuild(components::ImageBuildCommand),
    /// Prepare the root keypair that compile and lint checks read,
    /// without building a boot payload.
    KernelKeys {
        #[arg(long)]
        out_dir: PathBuf,
    },
    KernelImageRestore(kernel_image::KernelImageRestore),
    KernelImageStore(kernel_image::KernelImageStore),
    KernelPrebuild(KernelPrebuildCommand),
    LimineUefiImage(LimineUefiImageCommand),
    ProfileFetch(ProfileFetchCommand),
    /// Build the architecture-independent guest wasm once: the compiler
    /// plugin and every program under `programs/`. `kernel-prebuild
    /// --prebuilt-wasm` then precompiles it for a target without
    /// building it again.
    WasmBuild(WasmBuildCommand),
    /// Download the venus-protocol files `venus/protocol-inputs.toml` pins,
    /// which the `helios-venus` build reads.
    VenusProtocolFetch,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub(crate) enum Hint {
    Balanced,
    Performance,
}

impl From<Hint> for AotCompileHint {
    fn from(value: Hint) -> Self {
        match value {
            Hint::Balanced => Self::Balanced,
            Hint::Performance => Self::Performance,
        }
    }
}

#[derive(Parser)]
struct KernelPrebuildCommand {
    #[arg(long)]
    out_dir: PathBuf,
    #[arg(long)]
    target: String,
    #[arg(long)]
    profile: String,
    #[arg(long)]
    cargo: PathBuf,
    #[arg(long, default_value = "programs/init/Cargo.toml")]
    init_manifest: PathBuf,
    #[arg(long, default_value = "programs/init/bootfs")]
    bootfs_root: PathBuf,
    #[arg(long, default_value = DEFAULT_INIT_ARGV0)]
    init_argv0: String,
    #[arg(long = "boot-program")]
    boot_programs: Vec<String>,
    #[arg(long, default_value = DEFAULT_BOOT_ARTIFACTS_MANIFEST)]
    boot_artifacts_manifest: PathBuf,
    #[arg(long = "no-compiler-plugin", default_value_t = false)]
    no_compiler_plugin: bool,
    /// Take the guest wasm from this directory, as `wasm-build` wrote it,
    /// instead of building it.
    ///
    /// The wasm is read from `<DIR>/<profile>/`; a file that is not there
    /// fails the prebuild, which never builds it instead. The init
    /// program is the one `programs/init` builds, so `--init-manifest`
    /// cannot be combined with it. A relative path is relative to the
    /// workspace root.
    #[arg(
        long,
        value_name = "DIR",
        env = "HELIOS_PREBUILT_WASM",
        conflicts_with = "init_manifest"
    )]
    prebuilt_wasm: Option<PathBuf>,
    /// Sign the payload with the 32-byte Ed25519 secret in this file
    /// instead of the key generated in `--out-dir`.
    ///
    /// The file is read in place and nothing secret is written to
    /// `--out-dir`; a release build names the key its workflow
    /// installed, and CI names its signing key through the environment.
    #[arg(long, value_name = "PATH", env = "HELIOS_ROOT_SECRET_KEY")]
    root_secret_key: Option<PathBuf>,
    /// Authorize the Ed25519 public key derived from this 32-byte client
    /// secret key file in `/etc/inspector/policy.postcard`.
    ///
    /// When neither this nor `--inspector-policy` is supplied, a mode-0600
    /// development client key is generated in `--out-dir`
    /// (`helios-inspector-client-secret.key`) and only its public key is
    /// staged into bootfs.
    #[arg(
        long,
        value_name = "PATH",
        env = "HELIOS_INSPECTOR_CLIENT_KEY",
        conflicts_with = "inspector_policy"
    )]
    inspector_client_key: Option<PathBuf>,
    /// Stage this pre-encoded postcard `AuthPolicy` at
    /// `etc/inspector/policy.postcard` instead of generating a local policy.
    #[arg(
        long,
        value_name = "PATH",
        env = "HELIOS_INSPECTOR_POLICY",
        conflicts_with = "inspector_client_key"
    )]
    inspector_policy: Option<PathBuf>,
    #[command(flatten)]
    cache: CacheArgs,
}

#[derive(Parser)]
struct WasmBuildCommand {
    /// Directory the wasm lands in, under `<DIR>/<profile>/`.
    #[arg(long)]
    out_dir: PathBuf,
    #[arg(long, value_parser = ["release", "debug"])]
    profile: String,
    #[arg(long)]
    cargo: PathBuf,
    /// Restrict the build to the named guest programs (`compiler-plugin` or
    /// directory names under `programs/`). Repeat for multiple programs. When
    /// omitted, the compiler plugin and every program under `programs/` are
    /// built. Library components plugged by a selected program are included
    /// automatically.
    #[arg(long = "program", value_name = "NAME")]
    programs: Vec<String>,
    #[command(flatten)]
    cache: CacheArgs,
}

/// The artifact cache a build reads and fills (#1022).
#[derive(Parser)]
struct CacheArgs {
    /// Take the wasm and the precompiled `cwasm` this directory holds
    /// instead of building them, and store what is built there.
    ///
    /// Without it nothing is read or kept between runs. A wasm entry is a
    /// hit only while every source file cargo listed for it is unchanged;
    /// a `cwasm` entry is addressed by its input, this executable, the
    /// target level and the compile hint. A relative path is relative to
    /// the current directory. `artifact-cache-prune` empties what a job
    /// did not use.
    #[arg(long, value_name = "DIR", env = "HELIOS_ARTIFACT_CACHE")]
    cache_dir: Option<PathBuf>,
}

impl CacheArgs {
    fn open(&self) -> Result<Option<ArtifactCache>, CacheError> {
        self.cache_dir
            .as_deref()
            .map(ArtifactCache::open)
            .transpose()
    }

    /// Reports what the run took from the cache.
    fn report(cache: Option<&ArtifactCache>) {
        if let Some(cache) = cache {
            eprintln!("helios-cli: artifact cache: {}", cache.stats());
        }
    }
}

/// Delete the entries of an artifact cache that nothing has used since a
/// point in time (#1022).
///
/// A hit and a store both set an entry's modification time to now, so a job
/// that notes when it started and runs this last leaves a cache holding
/// what the job used, whichever processes of it used it.
#[derive(Parser)]
struct ArtifactCachePruneCommand {
    #[arg(long, value_name = "DIR", env = "HELIOS_ARTIFACT_CACHE")]
    cache_dir: PathBuf,
    /// Delete the entries last used before this many whole seconds since
    /// the unix epoch: what `date +%s` printed when the job started.
    #[arg(long, value_name = "UNIX_SECONDS")]
    older_than: u64,
}

#[derive(Parser)]
struct LimineUefiImageCommand {
    #[arg(long)]
    kernel: PathBuf,
    /// The `helios-bootfs` payload `kernel-prebuild` wrote; it lands at
    /// `/boot/helios-bootfs` and the entry names it as a Limine module.
    #[arg(long)]
    bootfs: PathBuf,
    #[arg(long)]
    output: PathBuf,
    #[arg(long)]
    baud: u32,
    #[arg(long, value_enum)]
    efi_arch: LimineEfiArch,
}

/// Download a kernel profile, so that a `--release` x86-64 kernel has one
/// to read (`docs/pgo.md`, #226, #313).
#[derive(Parser)]
struct ProfileFetchCommand {
    /// Release to take the profile from: the asset `release.yml` attached
    /// to it. Without it, the newest artifact a `kernel-profile.yml` run
    /// on the default branch uploaded.
    #[arg(long, value_name = "TAG", conflicts_with_all = ["branch", "run"])]
    tag: Option<String>,
    /// Branch whose newest collection to take, instead of the default
    /// branch's.
    #[arg(long, value_name = "BRANCH", conflicts_with = "run")]
    branch: Option<String>,
    /// Workflow run whose collection to take: the artifact that run
    /// itself uploaded, for a lane that collected its own profile.
    #[arg(long, value_name = "RUN_ID")]
    run: Option<u64>,
    /// `owner/name` of the repository whose collections and releases carry
    /// the profile.
    #[arg(long, value_name = "REPOSITORY", default_value = RELEASE_REPOSITORY)]
    repository: String,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub(crate) enum LimineEfiArch {
    X86_64,
    Aarch64,
}

impl LimineEfiArch {
    /// Removable-media boot path the UEFI firmware looks for on this
    /// architecture, which is both what Limine installs and what the
    /// share directory is recognised by.
    fn efi_bootloader_name(self) -> &'static str {
        match self {
            Self::X86_64 => "BOOTX64.EFI",
            Self::Aarch64 => "BOOTAA64.EFI",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PrebuildManifest {
    target: String,
    init_component: PathBuf,
    init_argv0: String,
    bootfs_root: PathBuf,
    bootfs: PathBuf,
    root_public_key: PathBuf,
    root_secret_key: PathBuf,
    inspector_policy: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    inspector_client_secret_key: Option<PathBuf>,
    bootfs_assets: Vec<BootAsset>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct BootAsset {
    pub(crate) path: String,
    pub(crate) source: PathBuf,
    pub(crate) kind: BootAssetKind,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum BootAssetKind {
    Directory,
    File,
}

#[derive(Clone, Debug, Deserialize)]
struct BootArtifactsManifest {
    #[serde(default)]
    artifact: Vec<ExternalBootArtifact>,
}

#[derive(Clone, Debug, Deserialize)]
struct ExternalBootArtifact {
    command: String,
    package: String,
    version: String,
    source_url: String,
    #[serde(default)]
    targets: Vec<String>,
    #[serde(default)]
    requires_wasm_simd: bool,
    bootfs_path: String,
    source: PathBuf,
    support_root: Option<PathBuf>,
    support_bootfs_prefix: Option<String>,
}

/// The inputs every bootfs asset build shares.
///
/// They travel together because each asset is compiled by the same cargo, for
/// the same profile and target, and resolved against the same checkout.
pub(crate) struct BootBuild<'a> {
    pub(crate) wasm: &'a WasmSource<'a>,
    pub(crate) out_dir: &'a Path,
    /// The level every boot artifact is compiled for: the target's floor.
    pub(crate) target: &'a CwasmTarget<'a>,
    pub(crate) workspace_root: &'a WorkspaceRoot,
    /// Where a precompiled artifact is taken from and kept, when a cache
    /// directory was named.
    pub(crate) precompile: Option<&'a PrecompileCache<'a>>,
}

/// Where the architecture-independent guest wasm of a boot payload comes
/// from: compiled by this run, or read from the directory `wasm-build`
/// wrote. Only the precompile to a target is the payload's own work.
pub(crate) enum WasmSource<'a> {
    Build(WasmBuilder<'a>),
    Prebuilt {
        /// The profile's own directory of the prebuilt tree.
        dir: PathBuf,
        profile: &'a str,
    },
}

/// What one `cargo build` of a guest program needs besides the program.
pub(crate) struct WasmBuilder<'a> {
    pub(crate) cargo: &'a Path,
    pub(crate) profile: &'a str,
    /// Where cargo's target directories go.
    pub(crate) out_dir: &'a Path,
    pub(crate) workspace_root: &'a WorkspaceRoot,
    /// Where a built wasm is taken from and kept, when a cache directory
    /// was named.
    pub(crate) cache: Option<&'a ArtifactCache>,
}

/// Extra options passed when compiling `component-manager` (`programs/init`)
/// from a validated `component.toml` directory tree.
#[derive(Clone, Copy, Default)]
pub(crate) struct ComponentBuildProfile<'a> {
    pub(crate) extra_features: &'a [&'a str],
    pub(crate) generated_topology_rs: Option<&'a Path>,
}

impl<'a> WasmSource<'a> {
    fn prebuilt(root: PathBuf, profile: &'a str) -> Result<Self, WasmBuildError> {
        let profile_dir = profile_dir_name(profile);
        let nested = root.join(profile_dir);
        let dir = if nested.is_dir() {
            nested
        } else if root.join(PREBUILT_MANIFEST_FILE).is_file() {
            root
        } else {
            nested
        };
        if dir.join(PREBUILT_MANIFEST_FILE).is_file() {
            let manifest =
                read_manifest(&dir).map_err(|source| WasmBuildError::PrebuiltManifest {
                    dir: dir.display().to_string(),
                    source,
                })?;
            if manifest.kind != PrebuiltArtifactKind::Userspace {
                return Err(WasmBuildError::PrebuiltWrongKind {
                    dir: dir.display().to_string(),
                    found: manifest.kind,
                });
            }
            if manifest.profile != profile_dir {
                return Err(WasmBuildError::PrebuiltProfileMismatch {
                    dir: dir.display().to_string(),
                    expected: profile_dir.to_owned(),
                    found: manifest.profile,
                });
            }
        }
        Ok(Self::Prebuilt { dir, profile })
    }

    /// The `wasm32-wasip3` core module or component `manifest_path`
    /// builds, whose file is named `artifact_name`.
    fn component(
        &self,
        manifest_path: &Path,
        artifact_name: &str,
    ) -> Result<PathBuf, WasmBuildError> {
        match self {
            Self::Build(builder) => builder.component(manifest_path, artifact_name),
            Self::Prebuilt { dir, profile } => prebuilt_wasm(dir, profile, artifact_name),
        }
    }

    /// The in-kernel compiler's `wasm32-wasip1-threads` module.
    fn compiler_plugin(&self) -> Result<PathBuf, WasmBuildError> {
        match self {
            Self::Build(builder) => builder.compiler_plugin(),
            Self::Prebuilt { dir, profile } => prebuilt_wasm(dir, profile, COMPILER_PLUGIN_WASM),
        }
    }
}

/// The subdirectory of a `wasm-build` tree a cargo profile's wasm lives
/// in: the two profiles the guest programs build with.
fn profile_dir_name(profile: &str) -> &'static str {
    if profile == "release" {
        "release"
    } else {
        "debug"
    }
}

fn prebuilt_wasm(
    dir: &Path,
    profile: &str,
    artifact_name: &str,
) -> Result<PathBuf, WasmBuildError> {
    let path = dir.join(artifact_name);
    if path.is_file() {
        Ok(path)
    } else {
        Err(WasmBuildError::PrebuiltMissing {
            path: path.display().to_string(),
            profile: profile.to_owned(),
        })
    }
}

#[derive(Clone, Debug)]
struct ProgramManifest {
    command: String,
    manifest_path: PathBuf,
    artifact_name: String,
    role: ProgramRole,
}

/// What `package.metadata.helios` says a directory under `programs/` is.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct ProgramRole {
    /// A library component: it is plugged into the programs that import
    /// what it exports and is never installed as a command.
    #[serde(default)]
    library: bool,
    /// The library components, by directory name, whose exports satisfy
    /// this program's imports.
    #[serde(default)]
    plugs: Vec<String>,
    /// Override the installed `bin/<command>` name (defaults to the directory
    /// name under `programs/`).
    #[serde(default)]
    command: Option<String>,
}

/// Every command's failure is a typed error whose message names what was
/// checked and what fixes it; the process boundary prints that message,
/// not the `Debug` form a `Result` returned from `main` would.
fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("helios-cli: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<(), CliError> {
    match cli.command {
        Commands::ArtifactCachePrune(command) => {
            let removed = prune(
                &command.cache_dir,
                UNIX_EPOCH + Duration::from_secs(command.older_than),
            )?;
            eprintln!(
                "helios-cli: artifact cache: pruned {removed} entries from {}",
                command.cache_dir.display()
            );
            Ok(())
        }
        Commands::ArtifactFetch(command) => {
            let root = WorkspaceRoot::resolve(cli.workspace_root.as_deref()).ok();
            Ok(prebuilt_artifact::run_fetch(
                command,
                root.as_ref().map(WorkspaceRoot::path),
            )?)
        }
        Commands::ArtifactStage(command) => {
            let root = WorkspaceRoot::resolve(cli.workspace_root.as_deref()).ok();
            Ok(prebuilt_artifact::run_stage(
                command,
                root.as_ref().map(WorkspaceRoot::path),
            )?)
        }
        Commands::ComponentCodegen(command) => Ok(components::run_component_codegen(
            &command,
            cli.workspace_root.as_deref(),
        )?),
        Commands::ImageBuild(command) => {
            let _ = components::run_image_build(command, cli.workspace_root.as_deref())?;
            Ok(())
        }
        Commands::KernelKeys { out_dir } => {
            prepare_root_key(&out_dir, None)?;
            Ok(())
        }
        Commands::KernelImageRestore(command) => Ok(kernel_image::restore(
            &command,
            WorkspaceRoot::resolve(cli.workspace_root.as_deref())?.path(),
        )?),
        Commands::KernelImageStore(command) => Ok(kernel_image::store(
            &command,
            WorkspaceRoot::resolve(cli.workspace_root.as_deref())?.path(),
        )?),
        Commands::KernelPrebuild(command) => {
            Ok(run_kernel_prebuild(command, cli.workspace_root.as_deref())?)
        }
        Commands::LimineUefiImage(command) => Ok(run_limine_uefi_image(command)?),
        Commands::WasmBuild(command) => Ok(run_wasm_build(
            &command,
            &WorkspaceRoot::resolve(cli.workspace_root.as_deref())?,
        )?),
        Commands::ProfileFetch(command) => {
            Ok(run_profile_fetch(command, cli.workspace_root.as_deref())?)
        }
        Commands::VenusProtocolFetch => {
            let workspace_root = WorkspaceRoot::resolve(cli.workspace_root.as_deref())?;
            Ok(venus_fetch::run(workspace_root.path())?)
        }
    }
}

fn run_kernel_prebuild(
    command: KernelPrebuildCommand,
    explicit_workspace_root: Option<&Path>,
) -> Result<(), PrebuildError> {
    let workspace_root = WorkspaceRoot::resolve(explicit_workspace_root)?;
    let PreparedRootKey {
        root_public_path,
        root_secret_path,
        root_signing_key,
    } = prepare_root_key(&command.out_dir, command.root_secret_key.as_deref())?;

    let init_manifest = workspace_root.join(&command.init_manifest);
    let bootfs_root = workspace_root.join(&command.bootfs_root);

    let selected_programs = selected_boot_programs(command.boot_programs)?;
    let boot_artifacts_manifest = workspace_root.join(&command.boot_artifacts_manifest);
    validate_external_boot_artifact_sources(
        &boot_artifacts_manifest,
        &command.target,
        &selected_programs,
        &workspace_root,
    )?;

    let cache = command.cache.open()?;
    let wasm = match command.prebuilt_wasm.as_deref() {
        Some(dir) => WasmSource::prebuilt(workspace_root.join(dir), &command.profile)?,
        None => WasmSource::Build(WasmBuilder {
            cargo: &command.cargo,
            profile: &command.profile,
            out_dir: &command.out_dir,
            workspace_root: &workspace_root,
            cache: cache.as_ref(),
        }),
    };
    let precompile_cache = cache.as_ref().map(PrecompileCache::new).transpose()?;
    let init_component = wasm.component(&init_manifest, INIT_WASM)?;
    let init_cwasm = command.out_dir.join("init_component.cwasm");
    let init_component_bytes = encode_component(&init_component)?;
    // The boot payload stays at the floor level: every processor the target
    // supports satisfies it. Only the in-kernel compiler follows the
    // processor's own level.
    let floor = cwasm_target_isa_levels(&command.target).floor();
    let target = CwasmTarget::new(&command.target, floor.name())?;
    let init_payload = precompile(
        precompile_cache.as_ref(),
        &init_component_bytes,
        &target,
        Hint::Performance.into(),
    )?;
    fs::write(&init_cwasm, init_payload).map_err(|source| PrebuildError::Write {
        path: init_cwasm.display().to_string(),
        source,
    })?;

    let build = BootBuild {
        wasm: &wasm,
        out_dir: &command.out_dir,
        target: &target,
        workspace_root: &workspace_root,
        precompile: precompile_cache.as_ref(),
    };
    let mut bootfs_assets = Vec::new();
    if !command.no_compiler_plugin {
        bootfs_assets.push(build_compiler_plugin_asset(&build)?);
    }
    bootfs_assets.extend(build_boot_program_assets(
        &build,
        &selected_programs,
        &boot_artifacts_manifest,
    )?);
    if selected_programs
        .as_ref()
        .is_none_or(|selected| selected.contains(INIT_COMMAND))
    {
        bootfs_assets.push(BootAsset {
            path: format!("bin/{INIT_COMMAND}"),
            source: resolve_bootfs_source(&init_cwasm)?,
            kind: BootAssetKind::File,
        });
    }

    let prepared_inspector = prepare_inspector_auth(
        &command.out_dir,
        command.inspector_client_key.as_deref(),
        command.inspector_policy.as_deref(),
    )?;
    bootfs_assets.push(BootAsset {
        path: INSPECTOR_POLICY_PATH.trim_start_matches('/').to_owned(),
        source: resolve_bootfs_source(&prepared_inspector.policy_path)?,
        kind: BootAssetKind::File,
    });

    let bootfs_path = command.out_dir.join(BOOTFS_IMAGE_FILE);
    write_bootfs_image(
        &bootfs_path,
        &bootfs_root,
        &bootfs_assets,
        &init_cwasm,
        &command.init_argv0,
        &root_signing_key,
    )?;

    let resolve = |path: &Path| {
        fs::canonicalize(path).map_err(|source| PrebuildError::Resolve {
            path: path.display().to_string(),
            source,
        })
    };
    let manifest = PrebuildManifest {
        target: command.target,
        init_component: resolve(&init_cwasm)?,
        init_argv0: command.init_argv0,
        bootfs_root: resolve(&bootfs_root)?,
        bootfs: resolve(&bootfs_path)?,
        root_public_key: resolve(&root_public_path)?,
        root_secret_key: resolve(&root_secret_path)?,
        inspector_policy: resolve(&prepared_inspector.policy_path)?,
        inspector_client_secret_key: prepared_inspector
            .client_secret_path
            .as_deref()
            .map(resolve)
            .transpose()?,
        bootfs_assets,
    };
    let manifest_path = command.out_dir.join(PREBUILD_MANIFEST_FILE);
    let encoded = serde_json::to_vec_pretty(&manifest)
        .map_err(|source| PrebuildError::EncodeManifest { source })?;
    fs::write(&manifest_path, encoded).map_err(|source| PrebuildError::Write {
        path: manifest_path.display().to_string(),
        source,
    })?;
    CacheArgs::report(cache.as_ref());
    Ok(())
}

/// Serialises the bootfs the kernel used to embed into one
/// `helios-bootfs` image at `image_path`.
///
/// The entry set is the one the manifest lists: every file under
/// `bootfs_root`, every built asset, and the two distinguished entries —
/// the init component and its `argv0`. Only empty directories get an
/// entry; a directory holding a file exists implicitly, which is the
/// same rule the kernel's bootfs view has always applied.
pub(crate) fn write_bootfs_image(
    image_path: &Path,
    bootfs_root: &Path,
    assets: &[BootAsset],
    init_component: &Path,
    init_argv0: &str,
    signing_key: &SigningKey,
) -> Result<(), PrebuildError> {
    let mut directories = Vec::new();
    let mut files = Vec::new();
    for entry in WalkDir::new(bootfs_root).sort_by_file_name() {
        let entry = entry.map_err(|source| BootfsError::WalkBootfsRoot {
            path: bootfs_root.display().to_string(),
            source,
        })?;
        let path = entry.path();
        if path == bootfs_root {
            continue;
        }
        let relative = path
            .strip_prefix(bootfs_root)
            .map_err(|_| BootfsError::PathNotUtf8 {
                path: path.display().to_string(),
            })?
            .to_str()
            .ok_or_else(|| BootfsError::PathNotUtf8 {
                path: path.display().to_string(),
            })?
            .replace('\\', "/");
        if path.is_dir() {
            if !is_empty_directory(path)? {
                continue;
            }
            directories.push((relative, file_modified_nanos(path)?));
        } else if path.is_file() {
            files.push((relative, path.to_path_buf(), file_modified_nanos(path)?));
        }
    }
    for asset in assets {
        match asset.kind {
            BootAssetKind::Directory => {
                directories.push((asset.path.clone(), file_modified_nanos(&asset.source)?));
            }
            BootAssetKind::File => {
                files.push((
                    asset.path.clone(),
                    asset.source.clone(),
                    file_modified_nanos(&asset.source)?,
                ));
            }
        }
    }
    directories.sort_by(|left, right| left.0.cmp(&right.0));
    files.sort_by(|left, right| left.0.cmp(&right.0));

    let init_name = init_component
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| BootfsError::PathNotUtf8 {
            path: init_component.display().to_string(),
        })?
        .to_owned();
    let read = |path: &Path| {
        fs::read(path).map_err(|source| BootfsError::Read {
            path: path.display().to_string(),
            source,
        })
    };
    let init_bytes = read(init_component)?;

    // Entry payloads are read into memory here rather than streamed:
    // the writer needs each blob's length before it lays the image out,
    // and bootfs files are small signed artifacts.
    let mut contents = Vec::with_capacity(files.len());
    for (_, source, _) in &files {
        contents.push(read(source)?);
    }

    let mut entries = Vec::with_capacity(directories.len() + files.len() + 2);
    for (path, modified_nanos) in &directories {
        entries.push(WriteEntry {
            kind: bootfs::EntryKind::Directory,
            path,
            data: b"",
            modified_nanos: *modified_nanos,
        });
    }
    for ((path, _, modified_nanos), data) in files.iter().zip(&contents) {
        entries.push(WriteEntry {
            kind: bootfs::EntryKind::File,
            path,
            data,
            modified_nanos: *modified_nanos,
        });
    }
    entries.push(WriteEntry {
        kind: bootfs::EntryKind::InitComponent,
        path: &init_name,
        data: &init_bytes,
        modified_nanos: file_modified_nanos(init_component)?,
    });
    entries.push(WriteEntry {
        kind: bootfs::EntryKind::InitArgv0,
        path: init_argv0,
        data: b"",
        modified_nanos: 0,
    });

    let signed = bootfs::sign_image(bootfs::write_image(&entries), signing_key);
    fs::write(image_path, signed).map_err(|source| PrebuildError::Write {
        path: image_path.display().to_string(),
        source,
    })
}

/// Modification time of `path` in nanoseconds since the Unix epoch, the
/// timestamp a bootfs entry carries.
fn file_modified_nanos(path: &Path) -> Result<u64, BootfsError> {
    let modified = fs::metadata(path)
        .and_then(|metadata| metadata.modified())
        .map_err(|source| BootfsError::Read {
            path: path.display().to_string(),
            source,
        })?;
    let duration =
        modified
            .duration_since(UNIX_EPOCH)
            .map_err(|_| BootfsError::ModifiedBeforeEpoch {
                path: path.display().to_string(),
            })?;
    duration
        .as_secs()
        .checked_mul(1_000_000_000)
        .and_then(|seconds| seconds.checked_add(u64::from(duration.subsec_nanos())))
        .ok_or_else(|| BootfsError::ModifiedBeforeEpoch {
            path: path.display().to_string(),
        })
}

fn run_limine_uefi_image(command: LimineUefiImageCommand) -> Result<(), LimineError> {
    let kernel =
        fs::canonicalize(&command.kernel).map_err(|source| LimineError::CanonicalizeKernel {
            path: command.kernel.display().to_string(),
            source,
        })?;
    let bootfs =
        fs::canonicalize(&command.bootfs).map_err(|source| LimineError::CanonicalizeBootfs {
            path: command.bootfs.display().to_string(),
            source,
        })?;
    let limine = LimineToolchain::discover(command.efi_arch)?;
    build_limine_uefi_image(&limine, &kernel, &bootfs, &command.output, command.baud)
}

pub(crate) struct LimineToolchain {
    efi_bootloader: PathBuf,
    efi_bootloader_name: &'static str,
}

impl LimineToolchain {
    pub(crate) fn discover(efi_arch: LimineEfiArch) -> Result<Self, LimineError> {
        let executable = std::env::var_os("HELIOS_LIMINE_BIN")
            .map(PathBuf::from)
            .or_else(|| find_executable_in_path("limine"))
            .ok_or(LimineError::ToolchainMissing)?;
        let share_dir = std::env::var_os("HELIOS_LIMINE_SHARE")
            .map(PathBuf::from)
            .or_else(|| limine_datadir(&executable))
            .or_else(|| infer_limine_share_dir(&executable, efi_arch))
            .ok_or(LimineError::ShareDirMissing)?;
        let efi_bootloader_name = efi_arch.efi_bootloader_name();
        let efi_bootloader = share_dir.join(efi_bootloader_name);
        if !efi_bootloader.is_file() {
            return Err(LimineError::BootloaderMissing {
                path: efi_bootloader.display().to_string(),
            });
        }
        Ok(Self {
            efi_bootloader,
            efi_bootloader_name,
        })
    }
}

/// Asks the Limine executable where its shared files live.
///
/// Every failure means the same thing to the caller — this executable
/// cannot say — and [`LimineToolchain::discover`] goes on to the next
/// way of finding the directory, so the reason is not carried further.
fn limine_datadir(executable: &Path) -> Option<PathBuf> {
    let output = Command::new(executable)
        .arg("--print-datadir")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let path = String::from_utf8(output.stdout).ok()?;
    Some(PathBuf::from(path.trim()))
}

pub(crate) fn build_limine_uefi_image(
    limine: &LimineToolchain,
    kernel: &Path,
    bootfs: &Path,
    image: &Path,
    baud: u32,
) -> Result<(), LimineError> {
    // The disk carries the image without its DWARF; the host keeps the
    // full file to symbolize against (`boot_kernel`).
    let kernel = boot_kernel::without_debuginfo(kernel)?;
    let image_bytes = limine_image_bytes(&kernel, bootfs, &limine.efi_bootloader)?;
    if let Some(parent) = image.parent().filter(|path| !path.as_os_str().is_empty()) {
        fs::create_dir_all(parent).map_err(|source| LimineError::CreateImageDir {
            path: parent.display().to_string(),
            source,
        })?;
    }
    let mut image_file = fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .read(true)
        .write(true)
        .open(image)
        .map_err(|source| LimineError::CreateImage {
            path: image.display().to_string(),
            source,
        })?;
    image_file
        .set_len(image_bytes)
        .map_err(|source| LimineError::SizeImage {
            path: image.display().to_string(),
            source,
        })?;
    write_limine_mbr(&mut image_file, image_bytes)?;
    write_limine_fat_volume(&mut image_file, image_bytes, &kernel, bootfs, limine, baud)
}

fn limine_image_bytes(
    kernel: &[u8],
    bootfs: &Path,
    efi_bootloader: &Path,
) -> Result<u64, LimineError> {
    let inspect = |path: &Path| {
        fs::metadata(path)
            .map(|metadata| metadata.len())
            .map_err(|source| LimineError::Inspect {
                path: path.display().to_string(),
                source,
            })
    };
    let kernel = u64::try_from(kernel.len()).expect("a kernel image held in memory fits u64");
    let payload_bytes = kernel + inspect(bootfs)? + inspect(efi_bootloader)?;
    Ok(LIMINE_IMAGE_BYTES.max(payload_bytes + 128 * 1024 * 1024))
}

fn write_limine_mbr(image: &mut fs::File, image_bytes: u64) -> Result<(), LimineError> {
    let mut mbr = MBR::new_from(image, LIMINE_SECTOR_BYTES as u32, LIMINE_DISK_SIGNATURE)
        .map_err(|source| LimineError::CreateMbr { source })?;
    let total_sectors = u32::try_from(image_bytes / LIMINE_SECTOR_BYTES)
        .map_err(|source| LimineError::ImageTooLarge { source })?;
    let partition_sectors = total_sectors
        .checked_sub(LIMINE_PARTITION_START_LBA)
        .ok_or(LimineError::ImageTooSmall)?;
    mbr[1] = MBRPartitionEntry {
        boot: BOOT_ACTIVE,
        first_chs: CHS::empty(),
        sys: LIMINE_EFI_SYSTEM_PARTITION_TYPE,
        last_chs: CHS::empty(),
        starting_lba: LIMINE_PARTITION_START_LBA,
        sectors: partition_sectors,
    };
    mbr.write_into(image)
        .map_err(|source| LimineError::WriteMbr { source })
}

fn write_limine_fat_volume(
    image: &mut fs::File,
    image_bytes: u64,
    kernel: &[u8],
    bootfs: &Path,
    limine: &LimineToolchain,
    baud: u32,
) -> Result<(), LimineError> {
    let partition_offset = u64::from(LIMINE_PARTITION_START_LBA) * LIMINE_SECTOR_BYTES;
    let partition_len = image_bytes
        .checked_sub(partition_offset)
        .ok_or(LimineError::PartitionOffsetTooLarge)?;
    let mut partition = FileSlice::new(image, partition_offset, partition_len);
    fatfs::format_volume(
        &mut partition,
        FormatVolumeOptions::new()
            .fat_type(FatType::Fat32)
            .volume_label(*b"HELIOS     "),
    )
    .map_err(|source| LimineError::FormatPartition { source })?;
    write_fat32_hidden_sectors(&mut partition, LIMINE_PARTITION_START_LBA)?;
    partition
        .seek(SeekFrom::Start(0))
        .map_err(|source| LimineError::Partition {
            step: "rewind Limine FAT32 partition",
            source,
        })?;
    let fs =
        FileSystem::new(partition, FsOptions::new()).map_err(|source| LimineError::Partition {
            step: "open Limine FAT32 partition",
            source,
        })?;
    let root = fs.root_dir();
    fn create_dir<'a, IO: fatfs::ReadWriteSeek>(
        parent: &fatfs::Dir<'a, IO>,
        name: &str,
        path: &'static str,
    ) -> Result<fatfs::Dir<'a, IO>, LimineError> {
        parent
            .create_dir(name)
            .map_err(|source| LimineError::CreateFatEntry { path, source })
    }
    let boot = create_dir(&root, "boot", "/boot")?;
    let efi = create_dir(&root, "EFI", "/EFI")?;
    let efi_boot = create_dir(&efi, "BOOT", "/EFI/BOOT")?;
    let limine_dir = create_dir(&boot, "limine", "/boot/limine")?;
    write_file_to_fat(
        &efi_boot,
        limine.efi_bootloader_name,
        &limine.efi_bootloader,
    )?;
    let config = LimineConfigTemplate { baud }
        .render()
        .map_err(|source| LimineError::RenderConfig { source })?;
    for (directory, path) in [
        (&limine_dir, "/boot/limine/limine.conf"),
        (&efi_boot, "/EFI/BOOT/limine.conf"),
    ] {
        let mut file = directory
            .create_file("limine.conf")
            .map_err(|source| LimineError::CreateFatEntry { path, source })?;
        file.write_all(config.as_bytes())
            .map_err(|source| LimineError::WriteFatEntry { path, source })?;
    }
    let path = "/boot/helios";
    let mut file = boot
        .create_file("helios")
        .map_err(|source| LimineError::CreateFatEntry { path, source })?;
    file.write_all(kernel)
        .map_err(|source| LimineError::WriteFatEntry { path, source })?;
    // The user payload, handed to the kernel as a Limine module — the
    // entry's `module_path` names this path.
    write_file_to_fat(&boot, "helios-bootfs", bootfs)?;
    Ok(())
}

fn write_fat32_hidden_sectors(
    partition: &mut FileSlice<'_>,
    hidden_sectors: u32,
) -> Result<(), LimineError> {
    const BPB_HIDDEN_SECTORS_OFFSET: u64 = 0x1c;
    const FAT32_BACKUP_BOOT_SECTOR: u64 = 6 * LIMINE_SECTOR_BYTES;
    for boot_sector in [0, FAT32_BACKUP_BOOT_SECTOR] {
        partition
            .seek(SeekFrom::Start(boot_sector + BPB_HIDDEN_SECTORS_OFFSET))
            .map_err(|source| LimineError::Partition {
                step: "seek to FAT32 hidden-sectors field",
                source,
            })?;
        partition
            .write_all(&hidden_sectors.to_le_bytes())
            .map_err(|source| LimineError::Partition {
                step: "write FAT32 hidden-sectors field",
                source,
            })?;
    }
    Ok(())
}

fn write_file_to_fat<IO>(
    root: &fatfs::Dir<'_, IO>,
    name: &str,
    source: &Path,
) -> Result<(), LimineError>
where
    IO: fatfs::ReadWriteSeek,
{
    let mut input = fs::File::open(source).map_err(|error| LimineError::OpenSource {
        path: source.display().to_string(),
        source: error,
    })?;
    let mut output = root
        .create_file(name)
        .map_err(|error| LimineError::CreateFatFile {
            name: name.to_owned(),
            source: io::Error::other(error),
        })?;
    std::io::copy(&mut input, &mut output).map_err(|error| LimineError::CopyIntoFat {
        path: source.display().to_string(),
        name: name.to_owned(),
        source: error,
    })?;
    Ok(())
}

fn find_executable_in_path(name: &str) -> Option<PathBuf> {
    let paths = std::env::var_os("PATH")?;
    std::env::split_paths(&paths)
        .map(|path| path.join(name))
        .find(|candidate| candidate.is_file())
}

fn infer_limine_share_dir(executable: &Path, efi_arch: LimineEfiArch) -> Option<PathBuf> {
    let bin_dir = executable.parent()?;
    let prefix_dir = bin_dir.parent()?;
    let efi_bootloader_name = efi_arch.efi_bootloader_name();
    [
        prefix_dir.join("share").join("limine"),
        prefix_dir.join("share"),
    ]
    .into_iter()
    .find(|path| path.join(efi_bootloader_name).is_file())
}

struct FileSlice<'a> {
    file: &'a mut fs::File,
    offset: u64,
    len: u64,
    position: u64,
}

impl<'a> FileSlice<'a> {
    fn new(file: &'a mut fs::File, offset: u64, len: u64) -> Self {
        Self {
            file,
            offset,
            len,
            position: 0,
        }
    }
}

impl Read for FileSlice<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.position >= self.len {
            return Ok(0);
        }
        let remaining = self.len - self.position;
        let count = remaining.min(buf.len() as u64) as usize;
        self.file.seek(SeekFrom::Start(
            self.offset
                .checked_add(self.position)
                .ok_or_else(|| std::io::Error::other("file slice position overflow"))?,
        ))?;
        let read = self.file.read(&mut buf[..count])?;
        self.position += read as u64;
        Ok(read)
    }
}

impl Write for FileSlice<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.position >= self.len {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "file slice write exceeds partition bounds",
            ));
        }
        let remaining = self.len - self.position;
        let count = remaining.min(buf.len() as u64) as usize;
        self.file.seek(SeekFrom::Start(
            self.offset
                .checked_add(self.position)
                .ok_or_else(|| std::io::Error::other("file slice position overflow"))?,
        ))?;
        let written = self.file.write(&buf[..count])?;
        self.position += written as u64;
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

impl Seek for FileSlice<'_> {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        let next = match pos {
            SeekFrom::Start(position) => i128::from(position),
            SeekFrom::End(delta) => i128::from(self.len) + i128::from(delta),
            SeekFrom::Current(delta) => i128::from(self.position) + i128::from(delta),
        };
        if !(0..=i128::from(self.len)).contains(&next) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "file slice seek is outside partition bounds",
            ));
        }
        self.position = next as u64;
        Ok(self.position)
    }
}

pub(crate) fn build_compiler_plugin_asset(build: &BootBuild<'_>) -> Result<BootAsset, BootfsError> {
    let wasm_path = build.wasm.compiler_plugin()?;
    let wasm = fs::read(&wasm_path).map_err(|source| BootfsError::Read {
        path: wasm_path.display().to_string(),
        source,
    })?;
    let payload = precompile(
        build.precompile,
        &wasm,
        build.target,
        Hint::Performance.into(),
    )?;
    // The exact module this run precompiled into the bootfs, at a path that
    // does not depend on cargo's target-directory layout: the bench's Linux
    // + Wasmtime column runs this file under `helios-compiler-host`, so both
    // columns run one plugin build.
    let wasm_output_path = build.out_dir.join("compiler_plugin.wasm");
    fs::write(&wasm_output_path, &wasm).map_err(|source| BootfsError::Write {
        path: wasm_output_path.display().to_string(),
        source,
    })?;
    let output_path = build.out_dir.join("compiler_plugin.cwasm");
    write_bootfs_artifact(&output_path, payload)?;

    Ok(BootAsset {
        path: COMPILER_PLUGIN_BOOTFS_PATH.to_owned(),
        source: resolve_bootfs_source(&output_path)?,
        kind: BootAssetKind::File,
    })
}

/// Writes one bare Wasmtime bootfs artifact to `path`; the image's own
/// footer is what signs it.
fn write_bootfs_artifact(path: &Path, bytes: Vec<u8>) -> Result<(), BootfsError> {
    fs::write(path, bytes).map_err(|source| BootfsError::Write {
        path: path.display().to_string(),
        source,
    })
}

/// The absolute path the manifest records for one bootfs asset.
pub(crate) fn resolve_bootfs_source(path: &Path) -> Result<PathBuf, BootfsError> {
    fs::canonicalize(path).map_err(|source| BootfsError::Resolve {
        path: path.display().to_string(),
        source,
    })
}

pub(crate) fn selected_boot_programs(
    boot_programs: Vec<String>,
) -> Result<Option<BTreeSet<String>>, BootProgramError> {
    if !boot_programs.is_empty() {
        let selected = boot_programs.into_iter().collect::<BTreeSet<_>>();
        if selected.is_empty() {
            return Err(BootProgramError::EmptyFlagSelection);
        }
        return Ok(Some(selected));
    }

    let Some(raw) = std::env::var_os("HELIOS_BOOT_PROGRAMS") else {
        return Ok(None);
    };
    let selected = raw
        .to_string_lossy()
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    if selected.is_empty() {
        return Err(BootProgramError::EmptyEnvSelection);
    }
    Ok(Some(selected))
}

pub(crate) fn build_boot_program_assets(
    build: &BootBuild<'_>,
    selected_programs: &Option<BTreeSet<String>>,
    boot_artifacts_manifest: &Path,
) -> Result<Vec<BootAsset>, BootfsError> {
    let programs_root = build.workspace_root.join(Path::new("programs"));
    let mut available_programs = BTreeSet::new();
    let mut manifests = Vec::new();
    let mut libraries = BTreeMap::new();
    let mut external_artifacts = read_external_boot_artifacts(boot_artifacts_manifest)?;

    for (dir_name, path) in program_dirs(&programs_root)? {
        // Init is built once, as the payload's init component; the
        // prebuild publishes that same artifact at `bin/init`.
        if dir_name == INIT_COMMAND {
            available_programs.insert(dir_name);
            continue;
        }
        let manifest = read_program_manifest(&dir_name, &path.join("Cargo.toml"))?;
        if manifest.role.library {
            libraries.insert(dir_name, manifest);
            continue;
        }
        let command = manifest.command.clone();
        available_programs.insert(command.clone());
        if selected_programs
            .as_ref()
            .is_some_and(|selected| !selected.contains(&command))
        {
            continue;
        }
        manifests.push(manifest);
    }
    for artifact in &external_artifacts {
        if !available_programs.insert(artifact.command.clone()) {
            return Err(BootArtifactsError::DuplicateCommand {
                command: artifact.command.clone(),
            }
            .into());
        }
    }
    reject_selected_target_mismatches(
        &external_artifacts,
        build.target.triple(),
        selected_programs,
    )?;
    external_artifacts.retain(|artifact| {
        artifact.supports_target(build.target.triple())
            && selected_programs
                .as_ref()
                .is_none_or(|selected| selected.contains(&artifact.command))
    });

    if let Some(selected_programs) = selected_programs {
        let missing_programs = selected_programs
            .iter()
            .filter(|command| !available_programs.contains(*command))
            .cloned()
            .collect::<Vec<_>>();
        if !missing_programs.is_empty() {
            return Err(BootProgramError::UnknownPrograms {
                missing: missing_programs.join(", "),
            }
            .into());
        }
    }

    manifests.sort_by(|left, right| left.command.cmp(&right.command));
    external_artifacts.sort_by(|left, right| left.command.cmp(&right.command));
    let mut assets = manifests
        .into_iter()
        .map(|manifest| build_boot_program_asset(build, manifest, &libraries))
        .collect::<Result<Vec<_>, BootfsError>>()?;
    for artifact in external_artifacts {
        assets.extend(build_external_boot_artifact_assets(build, artifact)?);
    }
    Ok(assets)
}

/// Every program directory under `programs_root`, as its command name and
/// path.
fn program_dirs(programs_root: &Path) -> Result<Vec<(String, PathBuf)>, BootProgramError> {
    let mut dirs = Vec::new();
    for entry in
        fs::read_dir(programs_root).map_err(|source| BootProgramError::ReadProgramsRoot {
            path: programs_root.display().to_string(),
            source,
        })?
    {
        let entry = entry.map_err(|source| BootProgramError::ReadProgramsEntry { source })?;
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let Some(command) = path.file_name().and_then(|name| name.to_str()) else {
            return Err(BootProgramError::ProgramNameNotUtf8 {
                path: path.display().to_string(),
            });
        };
        dirs.push((command.to_owned(), path));
    }
    Ok(dirs)
}

/// Guest wasm build targets chosen by `wasm-build`.
struct SelectedWasmBuild {
    compiler_plugin: bool,
    programs: Vec<ProgramManifest>,
}

/// Resolves `--program` filters against `programs/` and `compiler-plugin`.
///
/// An empty request builds the compiler plugin and every program under
/// `programs/`. A non-empty request rejects unknown names up front and
/// automatically pulls in any library component a selected program plugs.
fn select_wasm_programs(
    requested: &[String],
    available: Vec<ProgramManifest>,
) -> Result<SelectedWasmBuild, WasmProgramsError> {
    if requested.is_empty() {
        return Ok(SelectedWasmBuild {
            compiler_plugin: true,
            programs: available,
        });
    }

    let by_name: BTreeMap<String, ProgramManifest> = available
        .into_iter()
        .map(|manifest| (manifest.command.clone(), manifest))
        .collect();
    let requested_set: BTreeSet<&str> = requested.iter().map(String::as_str).collect();
    let unknown: Vec<&str> = requested_set
        .iter()
        .copied()
        .filter(|name| *name != COMPILER_PLUGIN_NAME && !by_name.contains_key(*name))
        .collect();
    if !unknown.is_empty() {
        return Err(WasmProgramsError::UnknownPrograms {
            unknown: unknown.join(", "),
        });
    }

    let compiler_plugin = requested_set.contains(COMPILER_PLUGIN_NAME);
    let mut expanded: BTreeSet<String> = requested_set
        .iter()
        .filter(|name| **name != COMPILER_PLUGIN_NAME)
        .map(|name| (*name).to_owned())
        .collect();

    let mut plugs_to_add = Vec::new();
    for name in &expanded {
        let manifest = &by_name[name];
        for plug in &manifest.role.plugs {
            let Some(library) = by_name.get(plug) else {
                return Err(BootProgramError::UnknownPlug {
                    command: manifest.command.clone(),
                    plug: plug.clone(),
                }
                .into());
            };
            if !library.role.library {
                return Err(BootProgramError::UnknownPlug {
                    command: manifest.command.clone(),
                    plug: plug.clone(),
                }
                .into());
            }
            plugs_to_add.push(plug.clone());
        }
    }
    expanded.extend(plugs_to_add);

    let programs = by_name
        .into_iter()
        .filter(|(name, _)| expanded.contains(name))
        .map(|(_, manifest)| manifest)
        .collect();
    Ok(SelectedWasmBuild {
        compiler_plugin,
        programs,
    })
}

/// Builds the compiler plugin and programs under `programs/` (or the subset
/// named by `--program`) into `<out-dir>/<profile>/`, one file per artifact
/// name: the wasm every target's boot payload is precompiled from.
fn run_wasm_build(
    command: &WasmBuildCommand,
    workspace_root: &WorkspaceRoot,
) -> Result<(), WasmProgramsError> {
    let mut program_entries = program_dirs(&workspace_root.join(Path::new("programs")))?;
    program_entries.sort();
    let available = program_entries
        .into_iter()
        .map(|(command_name, path)| read_program_manifest(&command_name, &path.join("Cargo.toml")))
        .collect::<Result<Vec<_>, _>>()?;
    let selection = select_wasm_programs(&command.programs, available)?;

    let dest = command.out_dir.join(profile_dir_name(&command.profile));
    fs::create_dir_all(&dest).map_err(|source| WasmProgramsError::CreateDir {
        path: dest.display().to_string(),
        source,
    })?;
    // Cargo's target directories sit beside the result, never in it, so
    // what is uploaded or handed to `--prebuilt-wasm` is the wasm alone.
    let scratch = command
        .out_dir
        .join(format!("{}-target", profile_dir_name(&command.profile)));
    let cache = command.cache.open()?;
    let builder = WasmBuilder {
        cargo: &command.cargo,
        profile: &command.profile,
        out_dir: &scratch,
        workspace_root,
        cache: cache.as_ref(),
    };

    // The compiler plugin builds first and longest, so it takes the first
    // worker when selected; every target directory's programs follow.
    let mut selected_program_names = BTreeSet::new();
    if selection.compiler_plugin {
        selected_program_names.insert(COMPILER_PLUGIN_NAME.to_owned());
    }
    for manifest in &selection.programs {
        selected_program_names.insert(manifest.command.clone());
    }

    let mut groups = BTreeMap::<String, Vec<(usize, ProgramManifest)>>::new();
    let mut venus_protocol = false;
    let mut boringssl = false;
    for (index, manifest) in selection.programs.into_iter().enumerate() {
        let requirements = read_wasm_requirements(&manifest.manifest_path)?;
        venus_protocol |= requirements.venus_protocol;
        boringssl |= requirements.boringssl;
        groups
            .entry(component_target_dir(&requirements))
            .or_default()
            .push((index + 1, manifest));
    }
    // Fetched once before the groups start, so that groups building at the
    // same time only ever find the pinned files in place and never write
    // the cache directory together.
    if venus_protocol {
        venus_fetch::run(workspace_root.path()).map_err(WasmBuildError::from)?;
    }
    if boringssl {
        wasi_sdk::ensure(workspace_root.path(), COMPONENT_TRIPLE).map_err(WasmBuildError::from)?;
    }
    let jobs = selection
        .compiler_plugin
        .then_some(WasmJob::CompilerPlugin)
        .into_iter()
        .chain(groups.into_values().map(WasmJob::Programs))
        .collect::<Vec<_>>();
    let mut built = run_wasm_jobs(&builder, &jobs)?;
    built.sort_by_key(|built| built.order);
    let built = built
        .into_iter()
        .map(|built| (built.manifest, built.artifact))
        .collect::<Vec<_>>();

    let mut names = BTreeSet::new();
    for (source_manifest, artifact) in &built {
        let name = artifact
            .file_name()
            .expect("a built artifact is a file, which has a name");
        if !names.insert(name.to_owned()) {
            let first = built
                .iter()
                .find(|(_, other)| other.file_name() == Some(name))
                .map_or_else(String::new, |(manifest, _)| manifest.clone());
            return Err(WasmProgramsError::DuplicateArtifact {
                artifact: name.to_string_lossy().into_owned(),
                first,
                second: source_manifest.clone(),
            });
        }
        let to = dest.join(name);
        fs::copy(artifact, &to).map_err(|source| WasmProgramsError::Copy {
            from: artifact.display().to_string(),
            to: to.display().to_string(),
            source,
        })?;
    }
    let manifest = PrebuiltManifest {
        schema_version: PREBUILT_SCHEMA_VERSION,
        kind: PrebuiltArtifactKind::Userspace,
        commit: prebuilt_artifact::current_git_commit(Some(workspace_root.path())),
        arch: None,
        profile: profile_dir_name(&command.profile).to_owned(),
        kernel_features: Vec::new(),
        programs: Some(if command.programs.is_empty() {
            PrebuiltPrograms::All
        } else {
            PrebuiltPrograms::Subset(selected_program_names.into_iter().collect())
        }),
        files: names
            .into_iter()
            .map(|name| name.to_string_lossy().into_owned())
            .collect(),
        root_public_key_sha256: None,
        baud: None,
    };
    write_manifest(&dest, &manifest)?;
    CacheArgs::report(cache.as_ref());
    Ok(())
}

/// One unit of work `wasm-build` runs beside the others.
enum WasmJob {
    CompilerPlugin,
    /// The programs that build into one target directory, each with its
    /// place in the output order. Cargo locks a target directory, so they
    /// build one after another.
    Programs(Vec<(usize, ProgramManifest)>),
}

/// A wasm one job built.
struct BuiltWasm {
    order: usize,
    /// The manifest it came from.
    manifest: String,
    artifact: PathBuf,
}

impl WasmJob {
    fn run(&self, builder: &WasmBuilder<'_>) -> Result<Vec<BuiltWasm>, WasmBuildError> {
        match self {
            Self::CompilerPlugin => Ok(vec![BuiltWasm {
                order: 0,
                manifest: COMPILER_PLUGIN_MANIFEST.to_owned(),
                artifact: builder.compiler_plugin()?,
            }]),
            Self::Programs(programs) => programs
                .iter()
                .map(|(order, manifest)| {
                    Ok(BuiltWasm {
                        order: *order,
                        manifest: manifest.manifest_path.display().to_string(),
                        artifact: builder
                            .component(&manifest.manifest_path, &manifest.artifact_name)?,
                    })
                })
                .collect(),
        }
    }
}

/// Runs `jobs`, as many at once as the host has parallelism for.
///
/// Workers take jobs in order until none is left or one has failed. The
/// first failure to arrive is the one returned, after the builds already
/// running have finished.
fn run_wasm_jobs(
    builder: &WasmBuilder<'_>,
    jobs: &[WasmJob],
) -> Result<Vec<BuiltWasm>, WasmProgramsError> {
    let workers = std::thread::available_parallelism()
        .map_err(|source| WasmProgramsError::Parallelism { source })?
        .get()
        .min(jobs.len());
    let next = &AtomicUsize::new(0);
    let failed = &AtomicBool::new(false);
    let (results, outcomes) = mpsc::channel();
    std::thread::scope(|scope| {
        for _ in 0..workers {
            let results = results.clone();
            scope.spawn(move || {
                while !failed.load(Ordering::Relaxed) {
                    let Some(job) = jobs.get(next.fetch_add(1, Ordering::Relaxed)) else {
                        break;
                    };
                    let outcome = job.run(builder);
                    if outcome.is_err() {
                        failed.store(true, Ordering::Relaxed);
                    }
                    results
                        .send(outcome)
                        .expect("the receiver outlives the scope that sends to it");
                }
            });
        }
    });
    drop(results);
    let mut built = Vec::new();
    for outcome in outcomes {
        built.extend(outcome?);
    }
    Ok(built)
}

fn read_external_boot_artifacts(
    path: &Path,
) -> Result<Vec<ExternalBootArtifact>, BootArtifactsError> {
    if !path.is_file() {
        return Err(BootArtifactsError::ManifestMissing {
            path: path.display().to_string(),
        });
    }
    let manifest = fs::read_to_string(path).map_err(|source| BootArtifactsError::ReadManifest {
        path: path.display().to_string(),
        source,
    })?;
    let manifest = toml::from_str::<BootArtifactsManifest>(&manifest).map_err(|source| {
        BootArtifactsError::ParseManifest {
            path: path.display().to_string(),
            source,
        }
    })?;
    for artifact in &manifest.artifact {
        if artifact.command.is_empty() {
            return Err(BootArtifactsError::EmptyCommand {
                path: path.display().to_string(),
            });
        }
        let empty = |field| BootArtifactsError::EmptyField {
            command: artifact.command.clone(),
            path: path.display().to_string(),
            field,
        };
        for (value, field) in [
            (&artifact.package, "package"),
            (&artifact.version, "version"),
            (&artifact.source_url, "source URL"),
            (&artifact.bootfs_path, "bootfs path"),
        ] {
            if value.is_empty() {
                return Err(empty(field));
            }
        }
        if !artifact.bootfs_path.starts_with("bin/") {
            return Err(BootArtifactsError::BootfsPathNotUnderBin {
                command: artifact.command.clone(),
            });
        }
        if !artifact.source.is_relative() {
            return Err(BootArtifactsError::SourceNotRelative {
                command: artifact.command.clone(),
            });
        }
        if let Some(support_root) = &artifact.support_root
            && !support_root.is_relative()
        {
            return Err(BootArtifactsError::SupportRootNotRelative {
                command: artifact.command.clone(),
            });
        }
        if artifact.support_root.is_some() != artifact.support_bootfs_prefix.is_some() {
            return Err(BootArtifactsError::SupportPairMismatch {
                command: artifact.command.clone(),
            });
        }
        if let Some(prefix) = &artifact.support_bootfs_prefix
            && (prefix.is_empty() || prefix.starts_with('/'))
        {
            return Err(BootArtifactsError::SupportPrefixNotRelative {
                command: artifact.command.clone(),
            });
        }
        if artifact.targets.iter().any(String::is_empty) {
            return Err(BootArtifactsError::EmptyTarget {
                command: artifact.command.clone(),
            });
        }
    }
    Ok(manifest.artifact)
}

pub(crate) fn validate_external_boot_artifact_sources(
    path: &Path,
    target: &str,
    selected_programs: &Option<BTreeSet<String>>,
    workspace_root: &WorkspaceRoot,
) -> Result<(), BootArtifactsError> {
    for artifact in read_external_boot_artifacts(path)? {
        if !artifact.supports_target(target) {
            continue;
        }
        if selected_programs
            .as_ref()
            .is_some_and(|selected| !selected.contains(&artifact.command))
        {
            continue;
        }
        if let Some(support_root) = &artifact.support_root {
            let support_root = workspace_root.join(support_root);
            if !support_root.is_dir() {
                return Err(BootArtifactsError::SupportRootMissing {
                    path: support_root.display().to_string(),
                });
            }
        }
    }
    Ok(())
}

fn reject_selected_target_mismatches(
    artifacts: &[ExternalBootArtifact],
    target: &str,
    selected_programs: &Option<BTreeSet<String>>,
) -> Result<(), BootArtifactsError> {
    let Some(selected_programs) = selected_programs else {
        return Ok(());
    };
    let mismatches = artifacts
        .iter()
        .filter(|artifact| selected_programs.contains(&artifact.command))
        .filter(|artifact| !artifact.supports_target(target))
        .map(|artifact| format!("{} {}", artifact.command, artifact.target_constraints()))
        .collect::<Vec<_>>();
    if !mismatches.is_empty() {
        return Err(BootArtifactsError::TargetMismatch {
            target: target.to_owned(),
            mismatches: mismatches.join("; "),
        });
    }
    Ok(())
}

impl ExternalBootArtifact {
    fn supports_target(&self, target: &str) -> bool {
        let target_allowed =
            self.targets.is_empty() || self.targets.iter().any(|candidate| candidate == target);
        let simd_satisfied = !self.requires_wasm_simd || cwasm_target_supports_wasm_simd(target);
        target_allowed && simd_satisfied
    }

    fn target_constraints(&self) -> String {
        let mut constraints = Vec::new();
        if !self.targets.is_empty() {
            constraints.push(format!("supports {}", self.targets.join(", ")));
        }
        if self.requires_wasm_simd {
            constraints.push("requires wasm SIMD".to_owned());
        }
        constraints.join(" and ")
    }
}

fn build_boot_program_asset(
    build: &BootBuild<'_>,
    manifest: ProgramManifest,
    libraries: &BTreeMap<String, ProgramManifest>,
) -> Result<BootAsset, BootfsError> {
    let wasm_path = build
        .wasm
        .component(&manifest.manifest_path, &manifest.artifact_name)?;
    let mut component_bytes = encode_component(&wasm_path)?;
    if !manifest.role.plugs.is_empty() {
        let plugs = manifest
            .role
            .plugs
            .iter()
            .map(|plug| {
                let library = libraries
                    .get(plug)
                    .ok_or_else(|| BootProgramError::UnknownPlug {
                        command: manifest.command.clone(),
                        plug: plug.clone(),
                    })?;
                let path = build
                    .wasm
                    .component(&library.manifest_path, &library.artifact_name)?;
                Ok((plug.clone(), encode_component(&path)?))
            })
            .collect::<Result<Vec<_>, BootfsError>>()?;
        component_bytes = compose(&manifest.command, component_bytes, plugs)?;
    }
    let payload = precompile(
        build.precompile,
        &component_bytes,
        build.target,
        Hint::Performance.into(),
    )?;
    let output_path = build
        .out_dir
        .join(format!("{}_bootfs_component.cwasm", manifest.command));
    write_bootfs_artifact(&output_path, payload)?;

    Ok(BootAsset {
        path: format!("bin/{}", manifest.command),
        source: resolve_bootfs_source(&output_path)?,
        kind: BootAssetKind::File,
    })
}

fn build_external_boot_artifact_assets(
    build: &BootBuild<'_>,
    artifact: ExternalBootArtifact,
) -> Result<Vec<BootAsset>, BootfsError> {
    let source = build.workspace_root.join(&artifact.source);
    let wasm = fs::read(&source).map_err(|error| BootfsError::Read {
        path: source.display().to_string(),
        source: error,
    })?;
    let payload = precompile(
        build.precompile,
        &wasm,
        build.target,
        Hint::Performance.into(),
    )?;
    let output_path = build
        .out_dir
        .join(format!("{}_bootfs_component.cwasm", artifact.command));
    write_bootfs_artifact(&output_path, payload)?;

    let mut assets = vec![BootAsset {
        path: artifact.bootfs_path,
        source: resolve_bootfs_source(&output_path)?,
        kind: BootAssetKind::File,
    }];
    if let (Some(support_root), Some(prefix)) =
        (&artifact.support_root, &artifact.support_bootfs_prefix)
    {
        assets.extend(build_external_support_assets(
            &build.workspace_root.join(support_root),
            prefix,
        )?);
    }
    Ok(assets)
}

fn build_external_support_assets(
    root: &Path,
    bootfs_prefix: &str,
) -> Result<Vec<BootAsset>, BootfsError> {
    if !root.is_dir() {
        return Err(BootArtifactsError::SupportRootMissing {
            path: root.display().to_string(),
        }
        .into());
    }
    let mut assets = Vec::new();
    for entry in WalkDir::new(root).sort_by_file_name() {
        let entry = entry.map_err(|source| BootfsError::WalkSupportRoot {
            path: root.display().to_string(),
            source,
        })?;
        if entry.path() == root {
            continue;
        }
        let source = entry.into_path();
        let relative = source
            .strip_prefix(root)
            .map_err(|error| BootfsError::StripSupportRoot {
                root: root.display().to_string(),
                source_path: source.display().to_string(),
                source: error,
            })?
            .to_str()
            .ok_or_else(|| BootfsError::PathNotUtf8 {
                path: source.display().to_string(),
            })?
            .replace('\\', "/");
        let kind = if source.is_dir() {
            if !is_empty_directory(&source)? {
                continue;
            }
            BootAssetKind::Directory
        } else if source.is_file() {
            BootAssetKind::File
        } else {
            continue;
        };
        assets.push(BootAsset {
            path: format!("{}/{}", bootfs_prefix.trim_end_matches('/'), relative),
            source: resolve_bootfs_source(&source)?,
            kind,
        });
    }
    Ok(assets)
}

fn is_empty_directory(path: &Path) -> Result<bool, BootfsError> {
    Ok(fs::read_dir(path)
        .map_err(|source| BootfsError::ReadDir {
            path: path.display().to_string(),
            source,
        })?
        .next()
        .is_none())
}

fn read_program_manifest(
    command: &str,
    manifest_path: &Path,
) -> Result<ProgramManifest, BootProgramError> {
    if !manifest_path.is_file() {
        return Err(BootProgramError::ManifestMissing {
            path: manifest_path.display().to_string(),
        });
    }
    let manifest =
        fs::read_to_string(manifest_path).map_err(|source| BootProgramError::ReadManifest {
            path: manifest_path.display().to_string(),
            source,
        })?;
    let manifest = manifest
        .parse::<Value>()
        .map_err(|source| BootProgramError::ParseManifest {
            path: manifest_path.display().to_string(),
            source,
        })?;
    let artifact_stem = manifest
        .get("lib")
        .and_then(|lib| lib.get("name"))
        .and_then(Value::as_str)
        .map(str::to_owned)
        .or_else(|| {
            manifest
                .get("package")
                .and_then(|package| package.get("name"))
                .and_then(Value::as_str)
                .map(|name| name.replace('-', "_"))
        })
        .ok_or_else(|| BootProgramError::ManifestHasNoName {
            path: manifest_path.display().to_string(),
        })?;
    let role = manifest
        .get("package")
        .and_then(|package| package.get("metadata"))
        .and_then(|metadata| metadata.get("helios"))
        .cloned()
        .map(Value::try_into::<ProgramRole>)
        .transpose()
        .map_err(|source| BootProgramError::ParseManifest {
            path: manifest_path.display().to_string(),
            source,
        })?
        .unwrap_or_default();
    if role.library && !role.plugs.is_empty() {
        return Err(BootProgramError::LibraryPlugs {
            command: command.to_owned(),
            plugs: role.plugs.join(", "),
        });
    }
    let installed_command = match &role.command {
        Some(explicit) => {
            if explicit.is_empty() || explicit.contains('/') || explicit == "." || explicit == ".."
            {
                return Err(BootProgramError::InvalidCommandName {
                    path: manifest_path.display().to_string(),
                    command: explicit.clone(),
                });
            }
            explicit.clone()
        }
        None => command.to_owned(),
    };
    Ok(ProgramManifest {
        command: installed_command,
        manifest_path: manifest_path.to_path_buf(),
        artifact_name: format!("{artifact_stem}.wasm"),
        role,
    })
}

/// Plugs each library's exports into the imports of `command`'s component
/// that they satisfy; what the libraries import stays imported by the
/// result, beside the program's own imports.
fn compose(
    command: &str,
    socket: Vec<u8>,
    plugs: Vec<(String, Vec<u8>)>,
) -> Result<Vec<u8>, WasmBuildError> {
    let mut graph = wac_graph::CompositionGraph::new();
    let mut register = |name: &str, bytes: Vec<u8>| {
        // A package name in the graph is a `namespace:name` pair.
        let package_name = format!("helios:{name}");
        let package =
            wac_graph::types::Package::from_bytes(&package_name, None, bytes, graph.types_mut())
                .map_err(|error| WasmBuildError::LoadComposed {
                    name: name.to_owned(),
                    report: format!("{error:#}"),
                })?;
        graph
            .register_package(package)
            .map_err(|source| WasmBuildError::RegisterComposed {
                name: name.to_owned(),
                source,
            })
    };
    let socket = register(command, socket)?;
    let plug_names = plugs
        .iter()
        .map(|(name, _)| name.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    let plugs = plugs
        .into_iter()
        .map(|(name, bytes)| register(&name, bytes))
        .collect::<Result<Vec<_>, _>>()?;
    wac_graph::plug(&mut graph, plugs, socket).map_err(|error| WasmBuildError::Plug {
        command: command.to_owned(),
        plugs: plug_names,
        report: error_chain(&error),
    })?;
    graph
        .encode(wac_graph::EncodeOptions::default())
        .map_err(|source| WasmBuildError::EncodeComposition {
            command: command.to_owned(),
            source,
        })
}

/// An error and every source under it, outermost first.
fn error_chain(error: &dyn std::error::Error) -> String {
    let mut report = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        report.push_str(": ");
        report.push_str(&cause.to_string());
        source = cause.source();
    }
    report
}

/// The target directory every `wasm32-wasip3` component program builds
/// into. The programs are workspace members built with one profile
/// environment and one `RUSTFLAGS`, so their shared dependencies compile
/// once; each program is still its own `cargo build`, so its feature
/// resolution and its `.wasm` are what a private directory would produce.
const COMPONENT_PROGRAMS_TARGET_DIR: &str = "component-programs-target";

/// The target the component programs build for.
const COMPONENT_TRIPLE: &str = "wasm32-wasip3";

/// The target directory, by name, a component program with these
/// requirements builds into.
///
/// Programs that name the same directory build one after another, because
/// cargo locks a target directory; programs that name different ones build
/// at the same time. Programs with extra target features compile every
/// crate, std included, with other flags, so they get a directory of their
/// own rather than invalidating the shared one on every switch.
fn component_target_dir(requirements: &WasmRequirements) -> String {
    let mut dir = COMPONENT_PROGRAMS_TARGET_DIR.to_owned();
    if !requirements.target_features.is_empty() {
        dir.push('-');
        dir.push_str(&requirements.target_features.join("-"));
    }
    if requirements.boringssl {
        dir.push_str("-boringssl");
    }
    dir
}

/// What `package.metadata.helios` asks of the wasm build of the crate at
/// `manifest_path`.
fn read_wasm_requirements(manifest_path: &Path) -> Result<WasmRequirements, WasmBuildError> {
    if !manifest_path.is_file() {
        return Err(WasmBuildError::ManifestMissing {
            path: manifest_path.display().to_string(),
        });
    }
    let manifest_text =
        fs::read_to_string(manifest_path).map_err(|source| WasmBuildError::Read {
            path: manifest_path.display().to_string(),
            source,
        })?;
    let settings: WasmBuildSettings =
        toml::from_str(&manifest_text).map_err(|source| WasmBuildError::ManifestSettings {
            path: manifest_path.display().to_string(),
            source,
        })?;
    Ok(settings.package.metadata.helios)
}

#[derive(Default, Deserialize)]
struct WasmBuildSettings {
    #[serde(default)]
    package: WasmPackageSettings,
}

#[derive(Default, Deserialize)]
struct WasmPackageSettings {
    #[serde(default)]
    metadata: WasmMetadata,
}

#[derive(Default, Deserialize)]
struct WasmMetadata {
    #[serde(default)]
    helios: WasmRequirements,
}

#[derive(Clone, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct WasmRequirements {
    #[serde(default)]
    venus_protocol: bool,
    #[serde(default)]
    boringssl: bool,
    #[serde(default)]
    target_features: Vec<String>,
}

/// The environment variables a guest build sets, in a fixed order.
///
/// They decide what the build produces, so they are also part of its
/// cache key. The target features are among them, in the rustflags, and
/// they alone decide whether std is rebuilt with them, so the key covers
/// that too.
fn build_environment(
    profile: &str,
    target_triple: &str,
    requirements: &WasmRequirements,
) -> Vec<(&'static str, String)> {
    let mut environment = Vec::new();
    if profile == "release" {
        if target_triple == COMPILER_PLUGIN_TRIPLE {
            environment.push(("CARGO_PROFILE_RELEASE_LTO", "fat".to_owned()));
            environment.push(("CARGO_PROFILE_RELEASE_CODEGEN_UNITS", "1".to_owned()));
        }
    } else {
        environment.push(("CARGO_PROFILE_DEV_OPT_LEVEL", "1".to_owned()));
        environment.push(("CARGO_PROFILE_DEV_DEBUG", "0".to_owned()));
        environment.push(("CARGO_PROFILE_DEV_PANIC", "abort".to_owned()));
    }
    // The flags carry link arguments with spaces in them, so they go as
    // the separator-joined list cargo reads verbatim.
    environment.push((
        "CARGO_ENCODED_RUSTFLAGS",
        wasm_rustflags(target_triple, &requirements.target_features).join("\x1f"),
    ));
    environment
}

impl WasmBuilder<'_> {
    /// The `wasm32-wasip3` core module or component `manifest_path`
    /// builds, whose file is named `artifact_name`.
    fn component(
        &self,
        manifest_path: &Path,
        artifact_name: &str,
    ) -> Result<PathBuf, WasmBuildError> {
        self.component_with_options(
            manifest_path,
            artifact_name,
            ComponentBuildProfile::default(),
        )
    }

    /// Builds a `wasm32-wasip3` component with optional extra Cargo features and
    /// generated topology file override (`HELIOS_COMPONENT_TOPOLOGY_RS`).
    pub(crate) fn component_with_options(
        &self,
        manifest_path: &Path,
        artifact_name: &str,
        options: ComponentBuildProfile<'_>,
    ) -> Result<PathBuf, WasmBuildError> {
        let requirements = read_wasm_requirements(manifest_path)?;
        let mut target_dir_name = component_target_dir(&requirements);
        if !options.extra_features.is_empty() {
            target_dir_name.push('-');
            target_dir_name.push_str(&options.extra_features.join("-"));
        }
        self.build_with_options(
            manifest_path,
            &target_dir_name,
            COMPONENT_TRIPLE,
            artifact_name,
            &requirements,
            options,
        )
    }

    /// The in-kernel compiler's `wasm32-wasip1-threads` module.
    fn compiler_plugin(&self) -> Result<PathBuf, WasmBuildError> {
        let manifest_path = self
            .workspace_root
            .join(Path::new(COMPILER_PLUGIN_MANIFEST));
        let requirements = read_wasm_requirements(&manifest_path)?;
        self.build_with_options(
            &manifest_path,
            COMPILER_PLUGIN_TARGET_DIR,
            COMPILER_PLUGIN_TRIPLE,
            COMPILER_PLUGIN_WASM,
            &requirements,
            ComponentBuildProfile::default(),
        )
    }

    /// Builds `manifest_path` for `target_triple` into the target
    /// directory `target_dir_name`, or takes the wasm from the cache when
    /// every input of an earlier build is unchanged. Either way the wasm
    /// is at the path cargo would have left it.
    fn build_with_options(
        &self,
        manifest_path: &Path,
        target_dir_name: &str,
        target_triple: &str,
        artifact_name: &str,
        requirements: &WasmRequirements,
        options: ComponentBuildProfile<'_>,
    ) -> Result<PathBuf, WasmBuildError> {
        let target_dir = self.out_dir.join(target_dir_name);
        let artifact = target_dir
            .join(target_triple)
            .join(profile_dir_name(self.profile))
            .join(artifact_name);
        let environment = build_environment(self.profile, target_triple, requirements);
        let cache = match self.cache {
            Some(cache) => {
                let package_dirs = package_directories(
                    self.cargo,
                    manifest_path,
                    target_triple,
                    FeatureSet::Default,
                )?;
                let key = self.cache_key(
                    manifest_path,
                    target_triple,
                    &environment,
                    requirements,
                    &package_dirs,
                )?;
                Some((cache, key, package_dirs))
            }
            None => None,
        };
        let resolve = || {
            fs::canonicalize(&artifact).map_err(|source| WasmBuildError::ResolveArtifact {
                artifact: artifact_name.to_owned(),
                source,
            })
        };
        if let Some((cache, key, _)) = &cache
            && let Some(wasm) = cache.lookup_inputs(key, self.workspace_root.path())?
        {
            let write_cached = |source| WasmBuildError::WriteCached {
                path: artifact.display().to_string(),
                source,
            };
            if let Some(parent) = artifact.parent() {
                fs::create_dir_all(parent).map_err(write_cached)?;
            }
            fs::write(&artifact, wasm).map_err(write_cached)?;
            return resolve();
        }

        // The protocol inputs are pinned by a file in `venus/`, which the
        // cache key's package closure covers; they are fetched only for a
        // build that will read them.
        if requirements.venus_protocol {
            venus_fetch::run(self.workspace_root.path())?;
        }
        let mut command = Command::new(self.cargo);
        if !requirements.target_features.is_empty() {
            // Wasm atomics change TLS relocations. Every Rust object,
            // including std, must use the same target features.
            command.arg("-Zbuild-std=std,panic_abort");
        }
        command
            .arg("build")
            .arg("--manifest-path")
            .arg(manifest_path)
            .arg("--target")
            .arg(target_triple)
            .arg("--target-dir")
            .arg(&target_dir);
        if self.profile == "release" {
            command.arg("--release");
        }
        if !options.extra_features.is_empty() {
            command
                .arg("--features")
                .arg(options.extra_features.join(","));
        }
        command.envs(environment);
        if let Some(topology_path) = options.generated_topology_rs {
            command.env("HELIOS_COMPONENT_TOPOLOGY_RS", topology_path);
        }
        command.env_remove("RUSTFLAGS");
        if requirements.boringssl {
            let sdk = wasi_sdk::ensure(self.workspace_root.path(), target_triple)?;
            let toolchain = wasi_sdk::materialize_toolchain_cmake(&target_dir)?;
            command.envs(wasi_sdk::boringssl_env(&sdk, target_triple, &toolchain));
        } else {
            // C code a program links (ring's, for one) is archived by `cc`, which
            // falls back to the host's `ar` for a wasm target; that archive carries
            // no symbol index wasm-ld can read, and the link then misses every C
            // symbol. The toolchain's own llvm-ar writes one. Its path follows the
            // toolchain, which `rustc -vV` in the cache key already names.
            command.env(
                format!("AR_{}", target_triple.replace('-', "_")),
                toolchain_llvm_ar()?,
            );
        }
        let status = command
            .status()
            .map_err(|source| WasmBuildError::SpawnCargo {
                path: manifest_path.display().to_string(),
                source,
            })?;
        if !status.success() {
            return Err(WasmBuildError::BuildFailed {
                path: manifest_path.display().to_string(),
                target: target_triple.to_owned(),
                status,
            });
        }
        let resolved = resolve()?;

        if let Some((cache, key, package_dirs)) = &cache {
            let wasm = fs::read(&resolved).map_err(|source| WasmBuildError::Read {
                path: resolved.display().to_string(),
                source,
            })?;
            // Cargo leaves the dep-info of the artifact beside it.
            let excluded = fs::canonicalize(&target_dir).map_err(|source| {
                WasmBuildError::ResolveArtifact {
                    artifact: target_dir.display().to_string(),
                    source,
                }
            })?;
            let inputs = workspace_inputs(
                &[artifact.with_extension("d")],
                self.workspace_root.path(),
                &excluded,
                package_dirs,
            )?;
            cache.store_inputs(key, self.workspace_root.path(), &inputs, &wasm)?;
        }
        Ok(resolved)
    }

    /// The key an earlier build of the same program is found by: what
    /// the build is, not what its sources hold, which the entry's own file
    /// list checks.
    fn cache_key(
        &self,
        manifest_path: &Path,
        target_triple: &str,
        environment: &[(&'static str, String)],
        requirements: &WasmRequirements,
        package_dirs: &[PathBuf],
    ) -> Result<artifact_cache::Key, WasmBuildError> {
        let root = self.workspace_root.path();
        let relative = manifest_path.strip_prefix(root).map_err(|_| {
            WasmBuildError::ManifestOutsideWorkspace {
                manifest: manifest_path.display().to_string(),
                root: root.display().to_string(),
            }
        })?;
        let read = |path: PathBuf| {
            fs::read(&path).map_err(|source| WasmBuildError::Read {
                path: path.display().to_string(),
                source,
            })
        };
        // Cargo reads this file for every build in the workspace, and an
        // absent one is an empty one.
        let config_path = root.join(".cargo/config.toml");
        let config = if config_path.is_file() {
            read(config_path)?
        } else {
            Vec::new()
        };
        let mut key = KeyBuilder::new(EntryKind::Wasm)
            .field(relative.as_os_str().as_encoded_bytes())
            .field(self.profile)
            .field(target_triple);
        for (name, value) in environment {
            key = key.field(name).field(value);
        }
        if requirements.boringssl {
            key = key
                .field("boringssl")
                .field(wasi_sdk::WASI_SDK_TAG)
                .field(wasi_sdk::BORINGSSL_TOOLCHAIN_CMAKE);
        }
        // Only the lockfile entries the program resolves through: a line
        // about the kernel's dependencies must not rebuild every program.
        let lock = String::from_utf8(read(root.join("Cargo.lock"))?).map_err(|source| {
            WasmBuildError::LockNotUtf8 {
                source: source.utf8_error(),
            }
        })?;
        let lock_closure = lock_closure_digest(&lock, &package_name(manifest_path)?)?;
        let manifest_digest = workspace_manifest_digest(root, package_dirs)?;
        Ok(key
            .field(rustc_print("-vV")?)
            .field(config)
            .field(lock_closure)
            .field(manifest_digest)
            .finish())
    }
}

/// The llvm-ar the toolchain's llvm-tools component installs beside
/// rust-lld, in the host's directory of the sysroot.
fn toolchain_llvm_ar() -> Result<PathBuf, WasmBuildError> {
    let sysroot = rustc_print("--print=sysroot")?;
    let host = rustc_print("--print=host-tuple")?;
    let path = PathBuf::from(sysroot)
        .join("lib/rustlib")
        .join(host)
        .join("bin/llvm-ar");
    if path.is_file() {
        Ok(path)
    } else {
        Err(WasmBuildError::LlvmArMissing {
            path: path.display().to_string(),
        })
    }
}

/// What `rustc <query>` prints, without its trailing newline.
fn rustc_print(query: &'static str) -> Result<String, WasmBuildError> {
    let output = Command::new("rustc")
        .arg(query)
        .output()
        .map_err(|source| WasmBuildError::SpawnRustc { query, source })?;
    if !output.status.success() {
        return Err(WasmBuildError::RustcFailed {
            query,
            status: output.status,
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .trim_end()
        .to_owned())
}

fn wasm_rustflags(target_triple: &str, features: &[String]) -> Vec<String> {
    let mut flags = vec!["-C".to_owned(), "debuginfo=0".to_owned(), "-C".to_owned()];
    if target_triple == "wasm32-wasip1-threads" {
        flags.push("strip=symbols".to_owned());
        for argument in [
            "--no-entry".to_owned(),
            "--export=__tls_base".to_owned(),
            format!("--max-memory={COMPILER_PLUGIN_SHARED_MEMORY_MAX_BYTES}"),
        ] {
            flags.extend(["-C".to_owned(), format!("link-arg={argument}")]);
        }
    } else {
        flags.push("strip=debuginfo".to_owned());
    }
    if !features.is_empty() {
        let features: Vec<_> = features
            .iter()
            .map(|feature| format!("+{feature}"))
            .collect();
        flags.extend([
            "-C".to_owned(),
            format!("target-feature={}", features.join(",")),
        ]);
    }
    flags
}

/// Encodes one core module as a component, or passes a component through.
///
/// `wit-component` reports through `anyhow`, which leaves no error type
/// to keep, so its report is captured as the whole chain it renders and
/// carried in the variant that names the step — the alternative would be
/// to lose everything the encoder said about why the module was refused.
pub(crate) fn encode_component(path: &Path) -> Result<Vec<u8>, WasmBuildError> {
    let wasm = fs::read(path).map_err(|source| WasmBuildError::Read {
        path: path.display().to_string(),
        source,
    })?;
    if WasmParser::is_component(&wasm) {
        return Ok(wasm);
    }
    ComponentEncoder::default()
        .module(&wasm)
        .map_err(|error| WasmBuildError::LoadCoreModule {
            path: path.display().to_string(),
            report: format!("{error:#}"),
        })?
        .validate(true)
        .encode()
        .map_err(|error| WasmBuildError::EncodeComponent {
            path: path.display().to_string(),
            report: format!("{error:#}"),
        })
}

pub(crate) struct PreparedRootKey {
    pub(crate) root_public_path: PathBuf,
    pub(crate) root_secret_path: PathBuf,
    pub(crate) root_signing_key: SigningKey,
}

pub(crate) fn prepare_root_key(
    out_dir: &Path,
    supplied: Option<&Path>,
) -> Result<PreparedRootKey, PrebuildError> {
    fs::create_dir_all(out_dir).map_err(|source| PrebuildError::CreateOutDir {
        path: out_dir.display().to_string(),
        source,
    })?;

    let root_public_path = out_dir.join(ROOT_PUBLIC_FILE);
    let (root_secret_path, root_signing_key) = match supplied {
        Some(supplied) => (
            supplied.to_path_buf(),
            supplied_root_keypair(supplied, &root_public_path)?,
        ),
        None => {
            let generated = out_dir.join(ROOT_SECRET_FILE);
            let key = ensure_root_keypair(&generated, &root_public_path)?;
            (generated, key)
        }
    };

    Ok(PreparedRootKey {
        root_public_path,
        root_secret_path,
        root_signing_key,
    })
}

fn ensure_root_keypair(
    root_secret_path: &Path,
    root_public_path: &Path,
) -> Result<SigningKey, KeyError> {
    let signing_key = if root_secret_path.is_file() {
        read_signing_key(root_secret_path)?
    } else {
        let mut secret = SecretKey::default();
        SysRng
            .try_fill_bytes(&mut secret)
            .map_err(|source| KeyError::Entropy { source })?;
        let signing_key = SigningKey::from_bytes(&secret);
        // The mode is set by the call that creates the file, so the secret
        // is never on disk under the process umask.
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(SECRET_KEY_MODE)
            .open(root_secret_path)
            .and_then(|mut file| file.write_all(&signing_key.to_bytes()))
            .map_err(|source| KeyError::Write {
                path: root_secret_path.display().to_string(),
                source,
            })?;
        signing_key
    };
    write_root_public_key(&signing_key, root_public_path)?;
    Ok(signing_key)
}

/// The root key a release names: read in place, never generated and never
/// copied, so the only file holding the secret is the one the caller owns.
fn supplied_root_keypair(
    root_secret_path: &Path,
    root_public_path: &Path,
) -> Result<SigningKey, KeyError> {
    if !root_secret_path.is_file() {
        return Err(KeyError::SuppliedKeyMissing {
            path: root_secret_path.display().to_string(),
        });
    }
    let signing_key = read_signing_key(root_secret_path)?;
    write_root_public_key(&signing_key, root_public_path)?;
    Ok(signing_key)
}

/// The public key always lands in the prebuild directory: it is the copy
/// the kernel verifies against, and a secret that outlived its public half
/// would otherwise sign artifacts nothing can check. The write is
/// skipped when the bytes already match — a kernel build tracks the
/// file through `cargo:rerun-if-changed`, and an untouched mtime is
/// what keeps a payload-only prebuild from recompiling it.
fn write_root_public_key(
    signing_key: &SigningKey,
    root_public_path: &Path,
) -> Result<(), KeyError> {
    let public_bytes = VerifyingKey::from(signing_key).to_bytes();
    if fs::read(root_public_path).ok().as_deref() != Some(public_bytes.as_slice()) {
        fs::write(root_public_path, public_bytes).map_err(|source| KeyError::Write {
            path: root_public_path.display().to_string(),
            source,
        })?;
    }
    Ok(())
}

pub(crate) struct PreparedInspectorAuth {
    pub(crate) policy_path: PathBuf,
    pub(crate) client_secret_path: Option<PathBuf>,
}

/// Prepares the public inspector `AuthPolicy` staged at
/// `etc/inspector/policy.postcard` and (unless `--inspector-policy` was passed)
/// the owner-only development client key in `out_dir`.
///
/// Only the public key ever lands in `inspector-policy.postcard` and bootfs.
pub(crate) fn prepare_inspector_auth(
    out_dir: &Path,
    supplied_client_key: Option<&Path>,
    supplied_policy: Option<&Path>,
) -> Result<PreparedInspectorAuth, PrebuildError> {
    fs::create_dir_all(out_dir).map_err(|source| PrebuildError::CreateOutDir {
        path: out_dir.display().to_string(),
        source,
    })?;
    let policy_path = out_dir.join(INSPECTOR_POLICY_FILE);

    if let Some(explicit_policy) = supplied_policy {
        let raw =
            fs::read(explicit_policy).map_err(|source| PrebuildError::ReadInspectorPolicy {
                path: explicit_policy.display().to_string(),
                source,
            })?;
        AuthPolicy::decode_postcard(&raw).map_err(|source| {
            PrebuildError::InvalidInspectorPolicy {
                path: explicit_policy.display().to_string(),
                source,
            }
        })?;
        write_if_changed(&policy_path, &raw)?;
        return Ok(PreparedInspectorAuth {
            policy_path,
            client_secret_path: None,
        });
    }

    let (client_secret_path, client_signing_key) = match supplied_client_key {
        Some(path) => {
            if !path.is_file() {
                return Err(KeyError::SuppliedKeyMissing {
                    path: path.display().to_string(),
                }
                .into());
            }
            (path.to_path_buf(), read_signing_key(path)?)
        }
        None => {
            let generated = out_dir.join(INSPECTOR_CLIENT_SECRET_FILE);
            let key = ensure_secret_signing_key(&generated)?;
            (generated, key)
        }
    };

    let public_bytes = VerifyingKey::from(&client_signing_key).to_bytes();
    let policy = AuthPolicy::single_static_key("local-dev", public_bytes);
    let encoded = policy
        .encode_postcard()
        .map_err(|source| PrebuildError::EncodeInspectorPolicy { source })?;
    write_if_changed(&policy_path, &encoded)?;

    Ok(PreparedInspectorAuth {
        policy_path,
        client_secret_path: Some(client_secret_path),
    })
}

fn ensure_secret_signing_key(secret_path: &Path) -> Result<SigningKey, KeyError> {
    if secret_path.is_file() {
        return read_signing_key(secret_path);
    }
    let mut secret = SecretKey::default();
    SysRng
        .try_fill_bytes(&mut secret)
        .map_err(|source| KeyError::Entropy { source })?;
    let signing_key = SigningKey::from_bytes(&secret);
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(SECRET_KEY_MODE)
        .open(secret_path)
        .and_then(|mut file| file.write_all(&signing_key.to_bytes()))
        .map_err(|source| KeyError::Write {
            path: secret_path.display().to_string(),
            source,
        })?;
    Ok(signing_key)
}

fn write_if_changed(path: &Path, bytes: &[u8]) -> Result<(), PrebuildError> {
    if fs::read(path).ok().as_deref() != Some(bytes) {
        fs::write(path, bytes).map_err(|source| PrebuildError::Write {
            path: path.display().to_string(),
            source,
        })?;
    }
    Ok(())
}

fn read_signing_key(path: &Path) -> Result<SigningKey, KeyError> {
    Ok(SigningKey::from_bytes(&read_root_secret_seed(path)?))
}

/// GitHub's REST API, where a release's tag and its assets are read from.
pub(crate) const GITHUB_API: &str = "https://api.github.com";

/// Environment variables a GitHub token is read from, in order: the first
/// is what a GitHub Actions runner sets, the second what `gh auth` sets.
///
/// The API answers a public repository without one, at sixty requests an
/// hour per address, which a busy shared runner can be a long way into.
const GITHUB_TOKEN_VARIABLES: [&str; 2] = ["GITHUB_TOKEN", "GH_TOKEN"];

/// Digits of the HTTP status curl is asked to write after the body.
const HTTP_STATUS_DIGITS: usize = 3;

/// Bytes of an unexpected answer an error carries: enough to read
/// GitHub's own `{"message": ...}`, not enough to bury the message.
const ERROR_BODY_BYTES: usize = 512;

/// The parts of a GitHub release this fetch reads.
#[derive(Debug, Deserialize)]
struct GithubRelease {
    tag_name: String,
    #[serde(default)]
    assets: Vec<GithubReleaseAsset>,
}

/// One asset of a release.
#[derive(Debug, Deserialize)]
struct GithubReleaseAsset {
    name: String,
    browser_download_url: String,
}

/// The part of a GitHub repository this fetch reads.
#[derive(Debug, Deserialize)]
struct GithubRepository {
    default_branch: String,
}

/// Artifacts the listing endpoint asks for at once. GitHub lists newest
/// first, so the newest collection on a branch is within the first page
/// unless that many newer runs on other branches uploaded one since; the
/// refusal says so.
pub(crate) const ARTIFACT_PAGE: usize = 100;

/// One page of a repository's artifact listing.
#[derive(Debug, Deserialize)]
pub(crate) struct GithubArtifacts {
    pub(crate) artifacts: Vec<GithubArtifact>,
}

/// The parts of a workflow artifact this fetch reads.
#[derive(Clone, Debug, Deserialize)]
pub(crate) struct GithubArtifact {
    pub(crate) id: u64,
    pub(crate) name: String,
    pub(crate) expired: bool,
    pub(crate) archive_download_url: String,
    pub(crate) workflow_run: GithubWorkflowRun,
}

/// The run that uploaded an artifact.
#[derive(Clone, Debug, Deserialize)]
pub(crate) struct GithubWorkflowRun {
    pub(crate) id: u64,
    pub(crate) head_branch: String,
    pub(crate) head_sha: String,
}

/// What curl answered: the status, the redirect it did not follow, and
/// the body.
struct HttpAnswer {
    status: String,
    redirect: String,
    body: Vec<u8>,
}

/// Downloads a kernel profile into the store.
///
/// The store is what `helios-inspector vm --release` reads to build an
/// x86-64 kernel the way the lanes and a release build it
/// (`docs/pgo.md`), so this is the one entry point that puts a profile
/// there: everything else names a profile it was given. Without `--tag`
/// the profile is the newest `helios-kernel-profdata` artifact a run on
/// the default branch uploaded (#313); with it, the asset a release
/// carries (#226).
fn run_profile_fetch(
    command: ProfileFetchCommand,
    explicit_workspace_root: Option<&Path>,
) -> Result<(), ProfileFetchError> {
    let workspace_root = WorkspaceRoot::resolve(explicit_workspace_root)?;
    let store = KernelProfileStore::new(workspace_root.path());
    let repository = &command.repository;
    let (fetched, profile) = match &command.tag {
        Some(tag) => fetch_release_asset(repository, tag)?,
        None => fetch_collection_artifact(repository, command.branch.as_deref(), command.run)?,
    };
    let path = store.profile_path(&fetched.key())?;
    let directory = path.parent().expect("a profile path names its key");
    fs::create_dir_all(directory).map_err(|source| ProfileFetchError::CreateDirectory {
        path: directory.display().to_string(),
        source,
    })?;
    fs::write(&path, profile).map_err(|source| ProfileFetchError::Write {
        path: path.display().to_string(),
        source,
    })?;
    // The header check before the record: a record names a profile a
    // build can read, or there is no record.
    helios_profdata::validate(&path)?;
    store.publish(&fetched)?;
    println!("{} {} {}", fetched.label(), repository, path.display());
    Ok(())
}

/// The profile asset of the release tagged `tag`, and the record naming it.
fn fetch_release_asset(
    repository: &str,
    tag: &str,
) -> Result<(FetchedProfile, Vec<u8>), ProfileFetchError> {
    let url = format!("{GITHUB_API}/repos/{repository}/releases/tags/{tag}");
    let document = match github_get(&url, true) {
        Err(ProfileFetchError::NotFound { .. }) => {
            return Err(ProfileFetchError::NoRelease {
                repository: repository.to_owned(),
                tag: tag.to_owned(),
            });
        }
        answer => answer?,
    };
    let release: GithubRelease = decode(&url, "a GitHub release", &document)?;
    let asset = release
        .assets
        .iter()
        .find(|asset| asset.name == KERNEL_PROFILE_ASSET)
        .ok_or_else(|| ProfileFetchError::NoProfileAsset {
            repository: repository.to_owned(),
            tag: release.tag_name.clone(),
        })?;
    // The download carries no token: GitHub redirects an asset to its own
    // object store, and an Authorization header follows the redirect
    // there.
    let profile = github_get(&asset.browser_download_url, false)?;
    Ok((
        FetchedProfile::Release {
            repository: repository.to_owned(),
            tag: release.tag_name,
        },
        profile,
    ))
}

/// The profile inside the newest unexpired collection artifact a run on
/// `branch` uploaded, the default branch when none is named, and the
/// record naming that run. With `run` it is that run's artifact instead,
/// whatever branch it was on.
fn fetch_collection_artifact(
    repository: &str,
    branch: Option<&str>,
    run: Option<u64>,
) -> Result<(FetchedProfile, Vec<u8>), ProfileFetchError> {
    let branch = match (branch, run) {
        (Some(branch), _) => branch.to_owned(),
        (None, Some(_)) => String::new(),
        (None, None) => default_branch(repository)?,
    };
    let url = format!(
        "{GITHUB_API}/repos/{repository}/actions/artifacts\
         ?name={KERNEL_PROFILE_ARTIFACT}&per_page={ARTIFACT_PAGE}"
    );
    let document = github_get(&url, true)?;
    let listing: GithubArtifacts = decode(&url, "a GitHub artifact listing", &document)?;
    let artifact = listing
        .artifacts
        .into_iter()
        .find(|artifact| {
            !artifact.expired
                && artifact.name == KERNEL_PROFILE_ARTIFACT
                && match run {
                    Some(run) => artifact.workflow_run.id == run,
                    None => artifact.workflow_run.head_branch == branch,
                }
        })
        .ok_or_else(|| match run {
            Some(run) => ProfileFetchError::NoRunCollection {
                repository: repository.to_owned(),
                run,
            },
            None => ProfileFetchError::NoCollection {
                repository: repository.to_owned(),
                branch: branch.clone(),
            },
        })?;
    // The archive endpoint answers with a redirect to GitHub's object
    // store, whose signed URL refuses the token the API wanted, so the
    // redirect is read with the token and followed without it.
    let location = github_redirect(&artifact.archive_download_url)?;
    let archive = github_get(&location, false)?;
    let profile = profile_in_archive(artifact.id, archive)?;
    Ok((
        FetchedProfile::Collection {
            repository: repository.to_owned(),
            run_id: artifact.workflow_run.id,
            head_branch: artifact.workflow_run.head_branch,
            head_sha: artifact.workflow_run.head_sha,
        },
        profile,
    ))
}

/// The repository's default branch, which is where the collection runs
/// every lane reads from.
pub(crate) fn default_branch(repository: &str) -> Result<String, ProfileFetchError> {
    let url = format!("{GITHUB_API}/repos/{repository}");
    let document = github_get(&url, true)?;
    let repository: GithubRepository = decode(&url, "a GitHub repository", &document)?;
    Ok(repository.default_branch)
}

/// The profile file out of an artifact archive. An artifact downloads
/// as a zip archive of the files the run uploaded, and the collection
/// uploads exactly one.
fn profile_in_archive(artifact: u64, archive: Vec<u8>) -> Result<Vec<u8>, ProfileFetchError> {
    let mut archive = zip::ZipArchive::new(io::Cursor::new(archive))
        .map_err(|source| ProfileFetchError::Archive { artifact, source })?;
    let mut entry = match archive.by_name(KERNEL_PROFILE_ASSET) {
        Ok(entry) => entry,
        Err(zip::result::ZipError::FileNotFound) => {
            return Err(ProfileFetchError::NoProfileInArchive { artifact });
        }
        Err(source) => return Err(ProfileFetchError::Archive { artifact, source }),
    };
    let mut profile = Vec::with_capacity(usize::try_from(entry.size()).unwrap_or(0));
    entry
        .read_to_end(&mut profile)
        .map_err(|source| ProfileFetchError::ReadArchive { artifact, source })?;
    Ok(profile)
}

/// One JSON answer decoded, naming the endpoint and what it was expected
/// to be when it is not.
pub(crate) fn decode<T: serde::de::DeserializeOwned>(
    url: &str,
    what: &'static str,
    document: &[u8],
) -> Result<T, ProfileFetchError> {
    serde_json::from_slice(document).map_err(|source| ProfileFetchError::Decode {
        url: url.to_owned(),
        what,
        source,
    })
}

/// One HTTPS GET through curl, following redirects, returning the body
/// of a 200.
pub(crate) fn github_get(url: &str, authenticated: bool) -> Result<Vec<u8>, ProfileFetchError> {
    let answer = curl_get(url, authenticated, true)?;
    match answer.status.as_str() {
        "200" => Ok(answer.body),
        "404" => Err(ProfileFetchError::NotFound {
            url: url.to_owned(),
        }),
        _ => Err(ProfileFetchError::HttpStatus {
            url: url.to_owned(),
            status: answer.status,
            body: String::from_utf8_lossy(&answer.body[..answer.body.len().min(ERROR_BODY_BYTES)])
                .trim()
                .to_owned(),
        }),
    }
}

/// Where an authenticated GET of `url` redirects to, without following it.
pub(crate) fn github_redirect(url: &str) -> Result<String, ProfileFetchError> {
    let answer = curl_get(url, true, false)?;
    if answer.status == "404" {
        return Err(ProfileFetchError::NotFound {
            url: url.to_owned(),
        });
    }
    if !answer.status.starts_with('3') || answer.redirect.is_empty() {
        return Err(ProfileFetchError::NoRedirect {
            url: url.to_owned(),
            status: answer.status,
        });
    }
    Ok(answer.redirect)
}

/// One HTTPS GET through curl.
///
/// curl is the HTTP client this repository already downloads its pinned
/// artifacts with (`tools/wasi-apps/build.sh`). The status is asked for
/// explicitly rather than through `--fail`, because a 404 on a release is
/// the answer that has something to say and `--fail` throws the body away.
/// The redirect curl did not follow is written after the body as well, on
/// a line of its own, so the answer is parsed from its end: the status,
/// the newline before it, and the redirect back to the newline before that.
fn curl_get(url: &str, authenticated: bool, follow: bool) -> Result<HttpAnswer, ProfileFetchError> {
    let config = if authenticated {
        github_token_header()?
    } else {
        String::new()
    };
    let mut command = Command::new("curl");
    command.args([
        "--silent",
        "--show-error",
        "--proto",
        "=https",
        "--tlsv1.2",
        "--write-out",
        "\n%{redirect_url}\n%{http_code}",
        "--config",
        "-",
    ]);
    if follow {
        command.arg("--location");
    }
    let mut child = command
        .arg(url)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|source| ProfileFetchError::Curl {
            url: url.to_owned(),
            source,
        })?;
    child
        .stdin
        .take()
        .expect("curl was spawned with a piped stdin")
        .write_all(config.as_bytes())
        .map_err(|source| ProfileFetchError::CurlConfig {
            url: url.to_owned(),
            source,
        })?;
    let output = child
        .wait_with_output()
        .map_err(|source| ProfileFetchError::Curl {
            url: url.to_owned(),
            source,
        })?;
    if !output.status.success() {
        return Err(ProfileFetchError::CurlExited {
            url: url.to_owned(),
            status: output.status.to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        });
    }
    parse_answer(url, output.stdout)
}

/// Splits curl's output into the body, the redirect and the status.
fn parse_answer(url: &str, mut body: Vec<u8>) -> Result<HttpAnswer, ProfileFetchError> {
    let short = || ProfileFetchError::NoHttpStatus {
        url: url.to_owned(),
        len: body.len(),
    };
    let status_at = body
        .len()
        .checked_sub(HTTP_STATUS_DIGITS)
        .ok_or_else(short)?;
    let newline_at = status_at.checked_sub(1).ok_or_else(short)?;
    if body[newline_at] != b'\n' {
        return Err(short());
    }
    let redirect_at = body[..newline_at]
        .iter()
        .rposition(|byte| *byte == b'\n')
        .ok_or_else(short)?;
    let status = String::from_utf8_lossy(&body[status_at..]).into_owned();
    let redirect = String::from_utf8_lossy(&body[redirect_at + 1..newline_at]).into_owned();
    body.truncate(redirect_at);
    Ok(HttpAnswer {
        status,
        redirect,
        body,
    })
}

/// The curl configuration carrying the GitHub token, or nothing.
///
/// The token reaches curl on its standard input rather than in an
/// argument, because arguments are readable to every process on the
/// machine. A value that is not a token is refused rather than quoted
/// into a configuration line.
fn github_token_header() -> Result<String, ProfileFetchError> {
    for variable in GITHUB_TOKEN_VARIABLES {
        let Ok(token) = std::env::var(variable) else {
            continue;
        };
        if token.is_empty() {
            continue;
        }
        return bearer_header(variable, &token);
    }
    Ok(String::new())
}

/// The curl configuration line carrying `token`.
///
/// The value lands inside a quoted `header = "…"` line, so what is
/// refused is what would end or escape that line or the line after it:
/// anything outside printable ASCII, a quote, or a backslash. GitHub's
/// tokens have worn several shapes (`ghp_…`, `ghs_…`, `github_pat_…`,
/// the older `v1.<hex>`) and this admits all of them without listing them.
fn bearer_header(variable: &'static str, token: &str) -> Result<String, ProfileFetchError> {
    if !token
        .bytes()
        .all(|byte| byte.is_ascii_graphic() && byte != b'"' && byte != b'\\')
    {
        return Err(ProfileFetchError::Token { variable });
    }
    Ok(format!("header = \"Authorization: Bearer {token}\"\n"))
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    #[test]
    fn gpu_test_requests_protocol_inputs_and_ordinary_programs_do_not() {
        let gpu: WasmBuildSettings =
            toml::from_str(include_str!("../../programs/gpu-test/Cargo.toml")).unwrap();
        assert!(gpu.package.metadata.helios.venus_protocol);
        assert!(!gpu.package.metadata.helios.boringssl);
        assert_eq!(gpu.package.metadata.helios.target_features, ["atomics"]);
        let http_client: WasmBuildSettings =
            toml::from_str(include_str!("../../programs/http-client/Cargo.toml")).unwrap();
        assert!(!http_client.package.metadata.helios.venus_protocol);
        assert!(http_client.package.metadata.helios.boringssl);
        assert_eq!(
            component_target_dir(&http_client.package.metadata.helios),
            format!("{COMPONENT_PROGRAMS_TARGET_DIR}-boringssl")
        );
        let init: WasmBuildSettings =
            toml::from_str(include_str!("../../programs/init/Cargo.toml")).unwrap();
        assert!(!init.package.metadata.helios.venus_protocol);
        assert!(!init.package.metadata.helios.boringssl);
        assert_eq!(init.package.metadata.helios.target_features, ["atomics"]);
        assert_eq!(
            component_target_dir(&init.package.metadata.helios),
            format!("{COMPONENT_PROGRAMS_TARGET_DIR}-atomics")
        );
        let date: WasmBuildSettings =
            toml::from_str(include_str!("../../programs/date/Cargo.toml")).unwrap();
        assert!(!date.package.metadata.helios.venus_protocol);
        assert!(!date.package.metadata.helios.boringssl);
        assert!(date.package.metadata.helios.target_features.is_empty());
        assert_eq!(
            component_target_dir(&date.package.metadata.helios),
            COMPONENT_PROGRAMS_TARGET_DIR
        );
    }

    #[test]
    fn boringssl_changes_wasm_cache_key_independently_of_output_path() {
        let workspace_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("cli crate lives under the workspace root");
        let root = WorkspaceRoot::resolve(Some(workspace_dir)).expect("resolve workspace root");
        let manifest = root.join(Path::new("programs/http-client/Cargo.toml"));
        let plain = WasmRequirements::default();
        let boring = WasmRequirements {
            boringssl: true,
            ..WasmRequirements::default()
        };
        let env_plain = build_environment("debug", COMPONENT_TRIPLE, &plain);
        let env_boring = build_environment("debug", COMPONENT_TRIPLE, &boring);

        let dir_a = tempfile::tempdir().expect("tempdir a");
        let dir_b = tempfile::tempdir().expect("tempdir b");
        let builder_a = WasmBuilder {
            cargo: Path::new("cargo"),
            profile: "debug",
            out_dir: dir_a.path(),
            workspace_root: &root,
            cache: None,
        };
        let builder_b = WasmBuilder {
            cargo: Path::new("cargo"),
            profile: "debug",
            out_dir: dir_b.path(),
            workspace_root: &root,
            cache: None,
        };

        let cargo = std::env::var_os("CARGO")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("cargo"));
        let package_dirs =
            package_directories(&cargo, &manifest, COMPONENT_TRIPLE, FeatureSet::Default)
                .expect("package directories resolve");

        let key_plain = builder_a
            .cache_key(
                &manifest,
                COMPONENT_TRIPLE,
                &env_plain,
                &plain,
                &package_dirs,
            )
            .expect("plain key");
        let key_boring_a = builder_a
            .cache_key(
                &manifest,
                COMPONENT_TRIPLE,
                &env_boring,
                &boring,
                &package_dirs,
            )
            .expect("boring key a");
        let key_boring_b = builder_b
            .cache_key(
                &manifest,
                COMPONENT_TRIPLE,
                &env_boring,
                &boring,
                &package_dirs,
            )
            .expect("boring key b");
        assert_ne!(
            key_plain, key_boring_a,
            "boringssl requirement must change wasm cache key"
        );
        assert_eq!(
            key_boring_a, key_boring_b,
            "boringssl wasm cache key must be portable across runner paths"
        );
    }

    #[test]
    fn wasm_target_features_are_explicit_and_do_not_replace_threaded_link_arguments() {
        let ordinary = wasm_rustflags("wasm32-wasip3", &[]);
        assert!(
            !ordinary
                .iter()
                .any(|flag| flag.starts_with("target-feature="))
        );
        let gpu = wasm_rustflags("wasm32-wasip3", &["atomics".to_owned()]);
        assert!(gpu.iter().any(|flag| flag == "target-feature=+atomics"));
        let threaded = wasm_rustflags("wasm32-wasip1-threads", &[]);
        assert!(
            threaded
                .iter()
                .any(|flag| flag == "link-arg=--export=__tls_base")
        );
        assert!(threaded.iter().any(|flag| flag
            == &format!("link-arg=--max-memory={COMPILER_PLUGIN_SHARED_MEMORY_MAX_BYTES}")));
    }

    #[test]
    fn a_prebuilt_tree_is_read_from_its_profile_directory() {
        let root = tempfile::tempdir().expect("a temporary directory");
        let release = root.path().join("release");
        fs::create_dir(&release).expect("a profile directory");
        fs::write(release.join(INIT_WASM), b"\0asm").expect("a wasm file");
        let source = WasmSource::prebuilt(root.path().to_path_buf(), "release")
            .expect("prebuilt source resolves");
        let found = source
            .component(Path::new("unused/Cargo.toml"), INIT_WASM)
            .expect("the prebuilt file is found");
        assert_eq!(found, release.join(INIT_WASM));
    }

    #[test]
    fn a_flat_prebuilt_userspace_artifact_with_manifest_is_accepted_and_validated() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        fs::write(dir.path().join(INIT_WASM), b"\0asm").expect("a wasm file");
        write_manifest(
            dir.path(),
            &PrebuiltManifest {
                schema_version: PREBUILT_SCHEMA_VERSION,
                kind: PrebuiltArtifactKind::Userspace,
                commit: None,
                arch: None,
                profile: "release".to_owned(),
                kernel_features: Vec::new(),
                programs: Some(PrebuiltPrograms::All),
                files: vec![INIT_WASM.to_owned()],
                root_public_key_sha256: None,
                baud: None,
            },
        )
        .expect("manifest writes");

        let source = WasmSource::prebuilt(dir.path().to_path_buf(), "release")
            .expect("flat userspace dir resolves for matching profile");
        let found = source
            .component(Path::new("unused/Cargo.toml"), INIT_WASM)
            .expect("init wasm found in flat dir");
        assert_eq!(found, dir.path().join(INIT_WASM));

        let err = match WasmSource::prebuilt(dir.path().to_path_buf(), "debug") {
            Ok(_) => panic!("mismatched profile must fail fast"),
            Err(error) => error,
        };
        assert!(matches!(
            err,
            WasmBuildError::PrebuiltProfileMismatch { .. }
        ));
    }

    #[test]
    fn a_missing_prebuilt_file_is_refused_and_never_built() {
        let root = tempfile::tempdir().expect("a temporary directory");
        // Only the release tree exists, so a debug prebuild finds nothing.
        fs::create_dir(root.path().join("release")).expect("a profile directory");
        let source = WasmSource::prebuilt(root.path().to_path_buf(), "debug")
            .expect("prebuilt source resolves");
        let Err(error) = source.component(Path::new("unused/Cargo.toml"), INIT_WASM) else {
            panic!("a file that is not there is refused");
        };
        assert!(
            matches!(&error, WasmBuildError::PrebuiltMissing { path, profile }
                if path.ends_with("debug/helios_init.wasm") && profile == "debug"),
            "{error}"
        );
    }

    #[test]
    fn kernel_keys_prepares_only_a_stable_keypair() {
        let root = tempfile::tempdir().expect("a temporary directory");
        let out_dir = root.path().join("keys");
        let prepare = || {
            let cli = Cli::try_parse_from([
                "helios-cli",
                "kernel-keys",
                "--out-dir",
                out_dir.to_str().expect("a UTF-8 test path"),
            ])
            .expect("the keys command parses");
            run(cli).expect("the keys are prepared without a payload");
        };
        prepare();
        let secret = fs::read(out_dir.join(ROOT_SECRET_FILE)).unwrap();
        let public = fs::read(out_dir.join(ROOT_PUBLIC_FILE)).unwrap();
        let key = read_signing_key(&out_dir.join(ROOT_SECRET_FILE)).unwrap();
        assert_eq!(public, key.verifying_key().to_bytes());
        assert_eq!(fs::read_dir(&out_dir).unwrap().count(), 2);
        prepare();
        assert_eq!(fs::read(out_dir.join(ROOT_SECRET_FILE)).unwrap(), secret);
        assert_eq!(fs::read(out_dir.join(ROOT_PUBLIC_FILE)).unwrap(), public);
    }

    #[test]
    fn a_new_root_secret_is_readable_by_its_owner_alone() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let secret = dir.path().join(ROOT_SECRET_FILE);
        ensure_root_keypair(&secret, &dir.path().join("root.pub")).expect("a new keypair");
        let mode = fs::metadata(&secret)
            .expect("the secret was written")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, SECRET_KEY_MODE);
    }

    #[test]
    fn a_root_secret_others_can_read_is_refused_with_its_mode() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let secret = dir.path().join(ROOT_SECRET_FILE);
        fs::write(&secret, [7_u8; 32]).expect("a key file");
        fs::set_permissions(&secret, fs::Permissions::from_mode(0o644)).expect("a wider mode");
        let error = ensure_root_keypair(&secret, &dir.path().join("root.pub"))
            .expect_err("a world-readable secret is refused");
        assert!(
            matches!(
                error,
                KeyError::Read(RootSecretReadError::SecretKeyExposed { mode: 0o644, .. })
            ),
            "{error}"
        );
    }

    #[test]
    fn a_supplied_root_secret_signs_and_nothing_secret_is_written_beside_the_public_key() {
        let keys = tempfile::tempdir().expect("a directory for the release key");
        let out_dir = tempfile::tempdir().expect("a prebuild directory");
        let supplied = keys.path().join("release.key");
        fs::write(&supplied, [7_u8; 32]).expect("a key file");
        fs::set_permissions(&supplied, fs::Permissions::from_mode(SECRET_KEY_MODE))
            .expect("an owner-only mode");
        let public = out_dir.path().join(ROOT_PUBLIC_FILE);

        let key = supplied_root_keypair(&supplied, &public).expect("the supplied key is read");

        let expected = VerifyingKey::from(&SigningKey::from_bytes(&[7_u8; 32])).to_bytes();
        assert_eq!(fs::read(&public).expect("the public half"), expected);
        let signed = bootfs::sign_image(bootfs::write_image(&[]), &key);
        let footer_start = signed.len() - bootfs::SIGNATURE_FOOTER_BYTES;
        // Magic, footer version and algorithm precede the signer's key.
        let signer_offset = footer_start + 8 + 4 + 4;
        assert_eq!(
            &signed[signer_offset..signer_offset + 32],
            expected.as_slice()
        );
        let written: Vec<_> = fs::read_dir(out_dir.path())
            .expect("the prebuild directory")
            .map(|entry| entry.expect("an entry").file_name())
            .collect();
        assert_eq!(written, [std::ffi::OsString::from(ROOT_PUBLIC_FILE)]);
    }

    #[test]
    fn a_missing_supplied_root_secret_is_refused_naming_its_path() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let supplied = dir.path().join("absent.key");
        let error = supplied_root_keypair(&supplied, &dir.path().join("root.pub"))
            .expect_err("a key that is not there is never generated");
        assert!(
            matches!(&error, KeyError::SuppliedKeyMissing { path } if path == &supplied.display().to_string()),
            "{error}"
        );
        assert!(!supplied.exists(), "nothing was generated at the path");
    }

    #[test]
    fn a_supplied_root_secret_others_can_read_is_refused_with_its_mode() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let supplied = dir.path().join("release.key");
        fs::write(&supplied, [7_u8; 32]).expect("a key file");
        fs::set_permissions(&supplied, fs::Permissions::from_mode(0o640)).expect("a wider mode");
        let public = dir.path().join("root.pub");
        let error =
            supplied_root_keypair(&supplied, &public).expect_err("a group-readable key is refused");
        assert!(
            matches!(
                error,
                KeyError::Read(RootSecretReadError::SecretKeyExposed { mode: 0o640, .. })
            ),
            "{error}"
        );
        assert!(
            !public.exists(),
            "no public half is written for a refused key"
        );
    }

    #[test]
    fn every_shape_of_github_token_makes_a_header_line() {
        for token in [
            "ghs_0123456789abcdefghijklmnopqrstuvwxyzAB",
            "github_pat_11AAAAAAA0_abcdefghijklmnopqrstuvwxyz",
            "v1.1f699f1069f60c4d3e2b8a7c5d4e3f2a1b0c9d8e7f",
        ] {
            let line = bearer_header("GITHUB_TOKEN", token).expect("a token curl can carry");
            assert_eq!(
                line,
                format!("header = \"Authorization: Bearer {token}\"\n")
            );
        }
    }

    #[test]
    fn a_value_that_would_escape_the_header_line_is_refused() {
        for value in [
            "ghs_abc\"",
            "ghs_abc\\",
            "ghs_abc\nurl = evil",
            "ghs_ab c",
            "ghs_ab\u{e9}",
        ] {
            let error = bearer_header("GH_TOKEN", value)
                .expect_err("a value that could end or escape the config line is not a token");
            assert!(
                matches!(
                    error,
                    ProfileFetchError::Token {
                        variable: "GH_TOKEN"
                    }
                ),
                "{error}"
            );
        }
    }

    #[test]
    fn selected_target_mismatches_fail_fast() {
        let mut artifact = test_artifact(
            "simd-lanes",
            "helios-wasix-conformance",
            "0.1.0",
            "tools/wasi-apps/wasix-tests",
            Path::new("simd-lanes.wasm"),
        );
        artifact.targets.push("aarch64-unknown-none".to_owned());
        let selected = Some(BTreeSet::from(["simd-lanes".to_owned()]));

        let error =
            reject_selected_target_mismatches(&[artifact], "riscv64gc-unknown-none-elf", &selected)
                .expect_err("target-specific artifact must reject unsupported selected target");
        assert!(
            error.to_string().contains("simd-lanes supports"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn wasm_simd_requirement_gates_targets() {
        let mut artifact = test_artifact(
            "quickjs",
            "quickjs-ng/quickjs",
            "v0.14.0",
            "https://github.com/quickjs-ng/quickjs",
            Path::new("qjs.wasm"),
        );
        artifact.requires_wasm_simd = true;

        assert!(artifact.supports_target("aarch64-unknown-none"));
        assert!(artifact.supports_target("x86_64-unknown-none"));
        assert!(artifact.supports_target("aarch64-apple-darwin"));
        assert!(!artifact.supports_target("riscv64gc-unknown-none-elf"));

        let selected = Some(BTreeSet::from(["quickjs".to_owned()]));
        let error =
            reject_selected_target_mismatches(&[artifact], "riscv64gc-unknown-none-elf", &selected)
                .expect_err("simd-requiring artifact must reject riscv64 selection");
        assert!(
            error.to_string().contains("quickjs requires wasm SIMD"),
            "unexpected error: {error}"
        );
    }

    fn test_program_manifest(command: &str, role: ProgramRole) -> ProgramManifest {
        ProgramManifest {
            command: command.to_owned(),
            manifest_path: PathBuf::from(format!("programs/{command}/Cargo.toml")),
            artifact_name: format!("helios_{}.wasm", command.replace('-', "_")),
            role,
        }
    }

    fn sample_program_manifests() -> Vec<ProgramManifest> {
        vec![
            test_program_manifest("compositor", ProgramRole::default()),
            test_program_manifest("init", ProgramRole::default()),
            test_program_manifest("inspector-host", ProgramRole::default()),
            test_program_manifest(
                "pride-flag",
                ProgramRole {
                    library: false,
                    plugs: vec!["webgpu".to_owned()],
                    ..ProgramRole::default()
                },
            ),
            test_program_manifest(
                "webgpu",
                ProgramRole {
                    library: true,
                    plugs: Vec::new(),
                    ..ProgramRole::default()
                },
            ),
        ]
    }

    #[test]
    fn wasm_build_without_programs_selects_compiler_plugin_and_all_programs() {
        let selected = select_wasm_programs(&[], sample_program_manifests())
            .expect("empty selection selects all");
        assert!(selected.compiler_plugin);
        let names: Vec<_> = selected
            .programs
            .iter()
            .map(|m| m.command.as_str())
            .collect();
        assert_eq!(
            names,
            [
                "compositor",
                "init",
                "inspector-host",
                "pride-flag",
                "webgpu"
            ]
        );
    }

    #[test]
    fn wasm_build_subset_selects_only_named_programs_and_deduplicates() {
        let requested = vec![
            "inspector-host".to_owned(),
            "init".to_owned(),
            "inspector-host".to_owned(),
        ];
        let selected = select_wasm_programs(&requested, sample_program_manifests())
            .expect("valid subset resolves");
        assert!(!selected.compiler_plugin);
        let names: Vec<_> = selected
            .programs
            .iter()
            .map(|m| m.command.as_str())
            .collect();
        assert_eq!(names, ["init", "inspector-host"]);
    }

    #[test]
    fn wasm_build_subset_includes_plugged_library_components() {
        let requested = vec!["pride-flag".to_owned()];
        let selected = select_wasm_programs(&requested, sample_program_manifests())
            .expect("plugged libraries are included automatically");
        assert!(!selected.compiler_plugin);
        let names: Vec<_> = selected
            .programs
            .iter()
            .map(|m| m.command.as_str())
            .collect();
        assert_eq!(names, ["pride-flag", "webgpu"]);
    }

    #[test]
    fn wasm_build_subset_can_select_compiler_plugin_alone() {
        let requested = vec![COMPILER_PLUGIN_NAME.to_owned()];
        let selected = select_wasm_programs(&requested, sample_program_manifests())
            .expect("compiler-plugin alone is valid");
        assert!(selected.compiler_plugin);
        assert!(selected.programs.is_empty());
    }

    #[test]
    fn wasm_build_rejects_unknown_program_names() {
        let requested = vec![
            "init".to_owned(),
            "missing-b".to_owned(),
            "missing-a".to_owned(),
        ];
        let error = select_wasm_programs(&requested, sample_program_manifests())
            .err()
            .expect("unknown program names must fail fast");
        assert!(
            matches!(
                &error,
                WasmProgramsError::UnknownPrograms { unknown } if unknown == "missing-a, missing-b"
            ),
            "{error}"
        );
    }

    #[test]
    fn wasm_build_cli_parses_repeatable_program_flags() {
        let parsed = Cli::try_parse_from([
            "helios-cli",
            "wasm-build",
            "--out-dir",
            "/tmp/out",
            "--profile",
            "debug",
            "--cargo",
            "cargo",
            "--program",
            "init",
            "--program",
            "inspector-host",
            "--program",
            "compiler-plugin",
        ])
        .expect("repeatable --program flags parse");
        let Commands::WasmBuild(command) = parsed.command else {
            panic!("expected WasmBuild command");
        };
        assert_eq!(
            command.programs,
            ["init", "inspector-host", "compiler-plugin"]
        );
    }

    fn test_artifact(
        command: &str,
        package: &str,
        version: &str,
        source_url: &str,
        source: &Path,
    ) -> ExternalBootArtifact {
        ExternalBootArtifact {
            command: command.to_owned(),
            package: package.to_owned(),
            version: version.to_owned(),
            source_url: source_url.to_owned(),
            targets: Vec::new(),
            requires_wasm_simd: false,
            bootfs_path: format!("bin/{command}"),
            source: source.to_owned(),
            support_root: None,
            support_bootfs_prefix: None,
        }
    }
}
