//! Unified `helios` CLI operations subcommands backed by `helios-ops` and
//! `helios-inspector-shell` (`nu`, `python`, `login`, `whoami`, `target`,
//! `inspect`, `ps`, `kill`, `trace`, `profile`, `spawn`, `bundle`, `bridge`).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use clap::{Args as ClapArgs, Subcommand, ValueEnum};
use helios_inspector_protocol::auth::{
    CapabilityCert as ProtocolCapabilityCert, ClientIdentity, DEFAULT_FIDO2_APPLICATION, random_32,
};
use helios_inspector_shell::{HostEnv, OutputFormat as ShellOutputFormat, ReplError};
use helios_ops::account::{
    AccountAuthenticatorChoice, AccountStore, AuthenticatorSpec, CreateAccountRequest,
    OperatorAccount, encode_hex as account_encode_hex, session_grants_from_attenuation,
};
use helios_ops::helios_oci::{Arch as OciArch, PulledImage};
use helios_ops::linux::{ContainerBuilder, ContainerMount, ContainerMountSharing};
use helios_ops::{
    AccountError, Attenuation, CapabilityCert, DEFAULT_FLEET_CONCURRENCY, DiagnosticBundle, Fleet,
    GrantRight, IdentityProfile, OpsError, PullOptions, Session, SessionOptions, SpawnRequest,
    Target, TargetError, TargetStore, TargetUri, http,
};
use helios_wit_rpc::inspector::helios::system::{
    component_control::ComponentStatus,
    inspect as proto_inspect,
    profiling::{Filter as ProfileFilter, MetricFilter},
    programs::{CapabilityGrant, ExecRequest, FilesystemRight},
    tracing as proto_tracing,
};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;

/// Global CLI operations flags accepted on `helios` and every subcommand.
#[derive(Debug, Clone, Default, ClapArgs)]
pub(crate) struct GlobalOpsFlags {
    /// Target name from `targets.toml` or direct URI (`helios://`, `tcp://`, `vsock://`, `serial://`).
    #[arg(short = 't', long = "target", global = true, value_name = "NAME|URI")]
    pub target: Option<String>,

    /// Select fleet targets matching `key=value` labels (repeatable).
    #[arg(short = 'l', long = "label", global = true, value_name = "K=V")]
    pub labels: Vec<String>,

    /// Maximum concurrent node operations during fleet fan-out.
    #[arg(
        long = "concurrency",
        global = true,
        default_value_t = DEFAULT_FLEET_CONCURRENCY
    )]
    pub concurrency: usize,

    /// Identity profile name or path to load credentials from.
    #[arg(long = "identity", global = true, value_name = "NAME|PATH")]
    pub identity: Option<String>,

    /// Attenuate session authority to this component moniker subtree (e.g. `/core/http`).
    #[arg(long = "scope", global = true, value_name = "MONIKER")]
    pub scope: Option<String>,

    /// Restrict session capabilities to only these rights (comma-separated or repeatable).
    #[arg(
        long = "only",
        global = true,
        value_delimiter = ',',
        value_name = "CAP"
    )]
    pub only: Vec<String>,

    /// Structured output format (`table`, `json`, `jsonl`, `nuon`).
    #[arg(
        short = 'o',
        long = "output",
        global = true,
        value_enum,
        default_value_t = CliOutputFormat::Table
    )]
    pub output: CliOutputFormat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum)]
pub(crate) enum CliOutputFormat {
    #[default]
    Table,
    Json,
    Jsonl,
    Nuon,
}

impl From<CliOutputFormat> for ShellOutputFormat {
    fn from(value: CliOutputFormat) -> Self {
        match value {
            CliOutputFormat::Table => Self::Table,
            CliOutputFormat::Json => Self::Json,
            CliOutputFormat::Jsonl => Self::Jsonl,
            CliOutputFormat::Nuon => Self::Nuon,
        }
    }
}

/// Interactive Nushell REPL (`helios nu` / `helios repl`), inline pipeline (`-c`), or script runner.
#[derive(Debug, Clone, Default, ClapArgs)]
pub(crate) struct NuCommand {
    /// Evaluate an inline Nushell pipeline and exit.
    #[arg(short = 'c', long = "command", conflicts_with = "script")]
    pub command: Option<String>,

    /// Path to a local `.nu` script file to execute against the connected target(s).
    #[arg(conflicts_with = "command")]
    pub script: Option<PathBuf>,

    /// Positional arguments forwarded to `<script.nu>` via `$env.HELIOS_ARGS`.
    #[arg(trailing_var_arg = true)]
    pub args: Vec<String>,
}

/// Symmetric Python entrypoint (`helios python`) delegating to `python3 -m helios._cli_entry`.
#[derive(Debug, Clone, Default, ClapArgs)]
pub(crate) struct PythonCommand {
    /// Inline Python async snippet passed to `python -m helios._cli_entry -c`.
    #[arg(short = 'c', long = "command", conflicts_with = "script")]
    pub command: Option<String>,

    /// Path to a Python script to execute with resolved target context.
    #[arg(conflicts_with = "command")]
    pub script: Option<PathBuf>,

    /// Additional arguments forwarded to `helios._cli_entry`.
    #[arg(trailing_var_arg = true)]
    pub args: Vec<String>,
}

/// Authenticate against an Authority CA via `zenwave` or save a local identity profile.
#[derive(Debug, Clone, ClapArgs)]
pub(crate) struct LoginCommand {
    /// Authority CA base URL (e.g. `https://ca.helios.internal`).
    #[arg(long = "authority", value_name = "URL")]
    pub authority: Option<String>,

    /// Profile name under `~/.config/helios/identities/<name>.toml`.
    #[arg(long = "name", default_value = "default")]
    pub name: String,

    /// Principal identifier (e.g. `lexo@helios.local`).
    #[arg(long = "principal")]
    pub principal: Option<String>,

    /// Optional bearer token presented to the Authority CA `/v1/issue` endpoint.
    #[arg(long = "token", env = "HELIOS_AUTH_TOKEN")]
    pub token: Option<String>,
}

/// Manage Touch ID, FIDO2, and software operator accounts (`account`).
#[derive(Debug, Clone, Subcommand)]
pub(crate) enum AccountCommand {
    /// Enroll a new operator account under `~/.config/helios/accounts/<username>.toml`.
    Create {
        /// POSIX-safe operator username (`[a-z_][a-z0-9_-]{0,31}`).
        username: String,
        /// Enroll a macOS Touch ID account (LocalAuthentication + Keychain-sealed P-256 key).
        #[arg(long = "touch-id", conflicts_with_all = ["fido2", "p256", "ed25519"])]
        touch_id: bool,
        /// Enroll a FIDO2 hardware security key via OpenSSH (`ed25519-sk` / `ecdsa-sk`).
        #[arg(long = "fido2", conflicts_with_all = ["touch_id", "p256", "ed25519"])]
        fido2: bool,
        /// Enroll a software NIST P-256 account (stored with `0600` permissions).
        #[arg(long = "p256", conflicts_with_all = ["touch_id", "fido2", "ed25519"])]
        p256: bool,
        /// Enroll a software Ed25519 account (stored with `0600` permissions).
        #[arg(long = "ed25519", conflicts_with_all = ["touch_id", "fido2", "p256"])]
        ed25519: bool,
        /// Require FIDO2 User Verification (PIN or biometric on the hardware token).
        #[arg(long = "require-uv")]
        require_uv: bool,
        /// Custom FIDO2 application string (defaults to `ssh:helios`).
        #[arg(long = "application", default_value = DEFAULT_FIDO2_APPLICATION)]
        application: String,
    },
    /// List enrolled operator accounts.
    Ls,
    /// Show detailed public-key and capability metadata for one operator account.
    Inspect { username: String },
    /// Run a local challenge-response verification test against an operator account.
    Verify { username: String },
    /// Remove an operator account and clean up its Keychain / FIDO2 key handle.
    Rm { username: String },
}

/// Manage named Helios targets in `targets.toml`.
#[derive(Debug, Clone, Subcommand)]
pub(crate) enum TargetCommand {
    /// Add or update a named target in `targets.toml`.
    Add {
        name: String,
        uri: String,
        /// Attach `key=value` labels (repeatable).
        #[arg(short = 'l', long = "label", value_name = "K=V")]
        labels: Vec<String>,
        /// Default identity profile for this target.
        #[arg(long = "identity")]
        identity: Option<String>,
        /// Default capability subtree scope for this target.
        #[arg(long = "scope")]
        scope: Option<String>,
    },
    /// List configured targets in `targets.toml`.
    Ls,
    /// Set the default target in `targets.toml`.
    Use { name: String },
    /// Remove a target from `targets.toml`.
    Rm { name: String },
}

/// Query `/kernel/*` and component inspect state.
#[derive(Debug, Clone, Default, ClapArgs)]
pub(crate) struct InspectCommand {
    /// Inspect key/moniker prefixes to query (empty returns all visible entries).
    pub prefixes: Vec<String>,

    /// Maximum entries to return (`0` means unbounded).
    #[arg(long, default_value_t = 0)]
    pub limit: u32,

    /// Continuously poll inspect state until `Ctrl+C`.
    #[arg(long)]
    pub watch: bool,

    /// Show only keys that were added, removed, or changed between consecutive polls.
    #[arg(long)]
    pub diff: bool,

    /// Poll interval in milliseconds when `--watch` is active.
    #[arg(long, default_value_t = 1000)]
    pub interval_ms: u64,
}

/// List running instances / components (`ps`).
#[derive(Debug, Clone, Default, ClapArgs)]
pub(crate) struct PsCommand {
    /// Display instances as a moniker/hierarchy tree.
    #[arg(long)]
    pub tree: bool,

    /// Include extended uptime and raw byte metrics.
    #[arg(short = 'l', long)]
    pub long: bool,
}

/// Terminate an instance by ID or name (`kill`).
#[derive(Debug, Clone, ClapArgs)]
pub(crate) struct KillCommand {
    /// Instance ID or instance name.
    pub target: String,

    /// Treat `<target>` as an instance name rather than numeric ID.
    #[arg(long)]
    pub name: bool,

    /// Forceful stop indicator.
    #[arg(short = 'f', long)]
    pub force: bool,
}

/// Fetch or stream guest tracing events (`trace`).
#[derive(Debug, Clone, Default, ClapArgs)]
pub(crate) struct TraceCommand {
    /// Maximum number of recent events per poll.
    #[arg(long, default_value_t = 64)]
    pub limit: u32,

    /// Lowest severity (`none`, `error`, `warn`, `info`, `debug`, `trace`).
    #[arg(long)]
    pub min_level: Option<String>,

    /// Only include events whose target starts with one of these prefixes.
    #[arg(long)]
    pub target_prefix: Vec<String>,

    /// Enable a named kernel diagnostic target before fetching/streaming.
    #[arg(long = "enable-target", value_name = "TARGET")]
    pub enable_target: Vec<String>,

    /// Continuously stream events until `Ctrl+C`.
    #[arg(short = 'f', long)]
    pub follow: bool,
}

/// Profiling inspection & collection (`profile`).
#[derive(Debug, Clone, Subcommand)]
pub(crate) enum ProfileOpsCommand {
    /// Capture kernel instruction samples for a duration (ms) and print summary (or symbolized folded output).
    Instructions {
        /// Sampling duration in milliseconds (0 reads existing samples without toggling).
        #[arg(long, default_value_t = 500)]
        duration_ms: u64,
        /// Optional kernel ELF image for ELF/DWARF symbolization.
        #[arg(long = "kernel", value_name = "ELF")]
        kernel: Option<PathBuf>,
        /// Optional output path for flamegraph folded stacks (requires `--kernel`).
        #[arg(long = "out", value_name = "PATH")]
        out: Option<PathBuf>,
    },
    /// Fetch folded stack samples.
    Folded {
        #[arg(long, default_value_t = 256)]
        limit: u32,
        #[arg(long)]
        stack_prefix: Vec<String>,
    },
    /// Fetch kernel and component metric samples.
    Metrics {
        #[arg(long, default_value_t = 256)]
        limit: u32,
        #[arg(long)]
        prefix: Vec<String>,
    },
    /// Collect LLVM raw profile bytes to a local file.
    LlvmRaw {
        /// Destination `.profraw` path.
        #[arg(long = "out", value_name = "PATH")]
        out: PathBuf,
    },
}

/// Spawn a remote Wasm/Linux binary with streaming stdio (`spawn`).
#[derive(Debug, Clone, ClapArgs)]
pub(crate) struct SpawnCommand {
    /// Remote executable path (e.g. `/bin/ping`).
    pub path: String,

    /// Arguments passed to the remote program.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub args: Vec<String>,

    /// Explicit environment entries `KEY=VAL` (repeatable).
    #[arg(short = 'e', long = "env", value_name = "K=V")]
    pub env: Vec<String>,

    /// Optional working directory for the remote process.
    #[arg(long = "cwd", value_name = "DIR")]
    pub cwd: Option<String>,

    /// Explicit capability grant specs (repeatable).
    #[arg(long = "grant", value_name = "SPEC")]
    pub grants: Vec<String>,
}

/// Execute a remote Wasm/Linux binary to completion (`exec`).
#[derive(Debug, Clone, ClapArgs)]
pub(crate) struct ExecCommand {
    /// Remote executable path (e.g. `/bin/ping` or `/bin/echo`).
    pub path: String,

    /// Arguments passed to the remote program.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub args: Vec<String>,

    /// Explicit environment entries `KEY=VAL` (repeatable).
    #[arg(short = 'e', long = "env", value_name = "K=V")]
    pub env: Vec<String>,

    /// Optional working directory for the remote process.
    #[arg(long = "cwd", value_name = "DIR")]
    pub cwd: Option<String>,

    /// Explicit capability grant specs (repeatable).
    #[arg(long = "grant", value_name = "SPEC")]
    pub grants: Vec<String>,

    /// Optional UTF-8 text piped to the program's stdin.
    #[arg(long = "stdin", value_name = "TEXT")]
    pub stdin: Option<String>,
}

/// Component-topology lifecycle commands (`component`).
#[derive(Debug, Clone, Subcommand)]
pub(crate) enum ComponentCommand {
    /// List configured and live components.
    Ls,
    /// Show the status of one component by moniker.
    Status { moniker: String },
    /// Start a configured component by moniker.
    Start { moniker: String },
    /// Stop a running component by moniker.
    Stop { moniker: String },
    /// Restart a configured component by moniker.
    Restart { moniker: String },
    /// Mount a dynamic component subtree under an opted-in parent realm.
    MountDynamic {
        /// Parent realm moniker (e.g. `/apps`).
        parent_moniker: String,
        /// Guest directory holding a `component.toml` subtree to mount.
        #[arg(
            long = "guest-dir",
            value_name = "GUEST_DIR",
            conflicts_with = "manifest_dir"
        )]
        guest_dir: Option<String>,
        /// Subtree name under `parent_moniker` (defaults to `--guest-dir` basename).
        #[arg(long = "name", value_name = "SUBTREE")]
        subtree_name: Option<String>,
        /// Host directory containing `component.toml` manifests to upload inline.
        #[arg(
            long = "manifest-dir",
            value_name = "HOST_DIR",
            conflicts_with = "guest_dir"
        )]
        manifest_dir: Option<PathBuf>,
    },
    /// Gracefully stop and unmount a previously mounted dynamic subtree.
    UnmountDynamic {
        /// Mounted dynamic subtree moniker (e.g. `/apps/worker`).
        moniker: String,
    },
}

/// Remote OCI image store commands (`oci`).
#[derive(Debug, Clone, Subcommand)]
pub(crate) enum OciCommand {
    /// Pull an OCI image into the remote guest store.
    Pull {
        /// OCI image reference (e.g. `alpine:latest` or `ghcr.io/org/app:v1`).
        reference: String,
        /// Target architecture (`x86-64` / `aarch64`); inferred from guest if omitted.
        #[arg(long, value_parser = ["x86_64", "x86-64", "amd64", "aarch64", "arm64"])]
        arch: Option<String>,
        /// Custom guest OCI store root path.
        #[arg(long = "store-root", value_name = "DIR")]
        store_root: Option<String>,
    },
    /// List pulled OCI images in the remote guest store.
    Ls {
        /// Custom guest OCI store root path.
        #[arg(long = "store-root", value_name = "DIR")]
        store_root: Option<String>,
    },
    /// Inspect a pulled OCI image in the remote guest store.
    Inspect {
        /// OCI image reference.
        reference: String,
        /// Custom guest OCI store root path.
        #[arg(long = "store-root", value_name = "DIR")]
        store_root: Option<String>,
    },
    /// Remove a pulled OCI image from the remote guest store.
    Rm {
        /// OCI image reference.
        reference: String,
        /// Custom guest OCI store root path.
        #[arg(long = "store-root", value_name = "DIR")]
        store_root: Option<String>,
    },
}

/// Shared Linux container creation options for `helios container {create, exec, spawn}`.
#[derive(Debug, Clone, Default, ClapArgs)]
pub(crate) struct ContainerTargetArgs {
    /// Pulled OCI image reference to use as the ephemeral overlay rootfs.
    #[arg(long, conflicts_with = "root")]
    pub image: Option<String>,

    /// Remote directory path to use as the ephemeral overlay rootfs.
    #[arg(long, conflicts_with = "image")]
    pub root: Option<String>,

    /// Custom guest OCI store root path (used with `--image`).
    #[arg(long = "store-root", value_name = "DIR")]
    pub store_root: Option<String>,

    /// Container UTS hostname.
    #[arg(long)]
    pub hostname: Option<String>,

    /// Container UTS domainname.
    #[arg(long)]
    pub domainname: Option<String>,

    /// Bind mount specs (`SRC:DST[:ro|rx|rw|rwx][:shared|private|overlay]`, repeatable).
    #[arg(short = 'm', long = "mount", value_name = "SPEC")]
    pub mounts: Vec<String>,

    /// Non-filesystem capability grant specs (repeatable).
    #[arg(long = "grant", value_name = "SPEC")]
    pub grants: Vec<String>,

    /// Explicit environment entries `KEY=VAL` (repeatable).
    #[arg(short = 'e', long = "env", value_name = "K=V")]
    pub env: Vec<String>,

    /// Working directory inside the container.
    #[arg(long = "cwd", value_name = "DIR")]
    pub cwd: Option<String>,
}

/// Linux container lifecycle commands (`container`).
#[derive(Debug, Clone, Subcommand)]
pub(crate) enum ContainerCommand {
    /// Create a Linux container (optionally running a command or holding until Ctrl+C).
    Create {
        #[command(flatten)]
        config: ContainerTargetArgs,
        /// Hold the container resource open until Ctrl+C when no command is provided.
        #[arg(long, default_value_t = false)]
        hold: bool,
        /// Optional command and arguments to run inside the newly created container.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
    /// List live Linux containers reported by `/kernel/containers/*`.
    Ls,
    /// Execute a Linux command to completion inside a container.
    Exec {
        #[command(flatten)]
        config: ContainerTargetArgs,
        /// Executable path inside the container.
        path: String,
        /// Arguments passed to the executable.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Spawn a streaming Linux command inside a container.
    Spawn {
        #[command(flatten)]
        config: ContainerTargetArgs,
        /// Executable path inside the container.
        path: String,
        /// Arguments passed to the executable.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Remove / stop a live Linux container by numeric ID.
    Rm {
        /// Container ID from `helios container ls`.
        id: u64,
    },
}

/// Collect a `.tar.zst` diagnostic bundle (`bundle`).
#[derive(Debug, Clone, ClapArgs)]
pub(crate) struct BundleCommand {
    /// Output `.tar.zst` archive path.
    pub output: PathBuf,
}

/// Export live inspect telemetry as Prometheus `/metrics` and/or OTLP/HTTP via `zenwave` (`bridge`).
#[derive(Debug, Clone, ClapArgs)]
pub(crate) struct BridgeCommand {
    /// Listen address for Prometheus HTTP `/metrics` scrape endpoint (e.g. `127.0.0.1:9095`).
    #[arg(long = "prometheus-listen", value_name = "ADDR")]
    pub prometheus_listen: Option<String>,

    /// OTLP/HTTP JSON metrics ingest endpoint (e.g. `http://127.0.0.1:4318/v1/metrics`).
    #[arg(long = "otlp-endpoint", value_name = "URL")]
    pub otlp_endpoint: Option<String>,

    /// Push interval in seconds for `--otlp-endpoint`.
    #[arg(long = "interval", default_value_t = 10)]
    pub interval_secs: u64,
}

/// Errors returned by `helios` CLI ops commands.
#[derive(Debug, thiserror::Error)]
pub(crate) enum OpsCliError {
    #[error("{0}")]
    Ops(#[from] OpsError),
    #[error("{0}")]
    Target(#[from] TargetError),
    #[error("{0}")]
    Account(#[from] AccountError),
    #[error("{0}")]
    Repl(#[from] ReplError),
    #[error("{0}")]
    Terminal(#[from] crate::tui::TerminalError),
    #[error("unknown capability `{raw}` in `--only`")]
    UnknownCapability { raw: String },
    #[error("invalid environment variable `{raw}`; expected `KEY=VALUE`")]
    InvalidEnvVar { raw: String },
    #[error("invalid mount specification `{raw}`: {reason}")]
    InvalidMountSpec { raw: String, reason: String },
    #[error("container requires either `--image <ref>` or `--root <path>`")]
    ContainerNeedsRoot,
    #[error("no live Linux container with id {id}")]
    ContainerNotFound { id: u64 },
    #[error("{0}")]
    InvalidArgument(String),
    #[error("invalid tracing level `{level}`")]
    UnknownTraceLevel { level: String },
    #[error("failed to locate Python interpreter (`HELIOS_PYTHON`, active venv, or `python3`)")]
    PythonNotFound,
    #[error("failed to launch `{program}`: {source}")]
    SpawnLocal {
        program: String,
        #[source]
        source: std::io::Error,
    },
    #[error("python process exited with code {code}")]
    PythonExited { code: i32 },
    #[error("remote program exited with code {code}")]
    RemoteExited { code: u32 },
    #[error("bridge requires at least one of `--prometheus-listen` or `--otlp-endpoint`")]
    BridgeNeedsSink,
    #[error("failed to bind Prometheus listener on `{addr}`: {source}")]
    BindPrometheus {
        addr: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to write output: {source}")]
    Io {
        #[from]
        source: std::io::Error,
    },
    #[error("failed to encode JSON output: {source}")]
    Json {
        #[from]
        source: serde_json::Error,
    },
}

/// Build [`SessionOptions`] from global CLI flags (`--identity`, `--scope`, `--only`).
pub(crate) fn build_session_options(flags: &GlobalOpsFlags) -> Result<SessionOptions, OpsCliError> {
    build_session_options_for_target(flags, None, true)
}

fn build_session_options_for_target(
    flags: &GlobalOpsFlags,
    target_identity: Option<&str>,
    allow_ambient_auth: bool,
) -> Result<SessionOptions, OpsCliError> {
    let mut only = BTreeSet::new();
    for raw in &flags.only {
        if raw.trim().is_empty() {
            continue;
        }
        let right = GrantRight::parse(raw)
            .ok_or_else(|| OpsCliError::UnknownCapability { raw: raw.clone() })?;
        only.insert(right);
    }
    let identity_arg = flags.identity.as_deref().or(target_identity);
    let (identity, security) = SessionOptions::resolve_security(identity_arg, allow_ambient_auth)?;
    Ok(SessionOptions {
        attenuation: Attenuation {
            scope: flags.scope.clone(),
            only,
        },
        identity,
        security,
        ..SessionOptions::default()
    })
}

fn allows_ambient_auth(target: &Target) -> bool {
    !matches!(
        target.parsed_uri(),
        Ok(TargetUri::Helios { tls: false, .. })
    )
}

/// Resolve a connected [`Session`] (and optional [`Fleet`]) from global CLI flags or `--device`.
pub(crate) async fn connect_from_flags(
    flags: &GlobalOpsFlags,
    legacy_device: Option<&str>,
    legacy_baud: u32,
) -> Result<(Session, Option<Fleet>), OpsCliError> {
    if !flags.labels.is_empty() {
        let store = TargetStore::load_default()?;
        let targets = store.select_by_labels(&flags.labels)?;
        let primary = targets[0].clone();
        let options = build_session_options_for_target(
            flags,
            primary.identity.as_deref(),
            allows_ambient_auth(&primary),
        )?;
        let fleet = Fleet::new(targets, flags.concurrency, options.clone());
        let session = Session::connect(&primary, options).await?;
        return Ok((session, Some(fleet)));
    }
    if let Some(dev) = legacy_device {
        let uri = format!("serial://{dev}?baud={legacy_baud}");
        let target = Target::from_uri(uri)?;
        let options = build_session_options_for_target(flags, None, true)?;
        let session = Session::connect(&target, options).await?;
        return Ok((session, None));
    }
    let store = TargetStore::load_default()?;
    let target = store.resolve(flags.target.as_deref())?;
    let options = build_session_options_for_target(
        flags,
        target.identity.as_deref(),
        allows_ambient_auth(&target),
    )?;
    let session = Session::connect(&target, options).await?;
    Ok((session, None))
}

/// Run `helios nu` (REPL, `-c`, or `<script.nu>`) against a connected [`Session`].
pub(crate) async fn run_nu_with_session(
    session: Session,
    fleet: Option<Fleet>,
    cmd: &NuCommand,
    output: CliOutputFormat,
) -> Result<(), OpsCliError> {
    let env = HostEnv::new(session, fleet);
    let format = ShellOutputFormat::from(output);
    if let Some(inline) = &cmd.command {
        let rendered = helios_inspector_shell::eval_command(env, inline, format).await?;
        if !rendered.is_empty() {
            println!("{rendered}");
        }
        return Ok(());
    }
    if let Some(script_path) = &cmd.script {
        let rendered =
            helios_inspector_shell::eval_script(env, script_path, &cmd.args, format).await?;
        if !rendered.is_empty() {
            println!("{rendered}");
        }
        return Ok(());
    }
    helios_inspector_shell::run_repl(env, format).await?;
    Ok(())
}

/// Resolve the Python interpreter (`HELIOS_PYTHON` -> `$VIRTUAL_ENV/bin/python` -> `python3`)
/// without linking `libpython` into `helios`.
pub(crate) fn resolve_python_executable() -> Result<PathBuf, OpsCliError> {
    if let Ok(explicit) = std::env::var("HELIOS_PYTHON")
        && !explicit.trim().is_empty()
    {
        return Ok(PathBuf::from(explicit));
    }
    if let Ok(venv) = std::env::var("VIRTUAL_ENV") {
        let candidate = PathBuf::from(venv).join("bin").join("python");
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    for name in ["python3", "python"] {
        if let Ok(path_var) = std::env::var("PATH") {
            for dir in std::env::split_paths(&path_var) {
                let candidate = dir.join(name);
                if candidate.is_file() {
                    return Ok(candidate);
                }
            }
        }
    }
    Err(OpsCliError::PythonNotFound)
}

/// Run `helios python` by delegating to `<python> -m helios._cli_entry`.
pub(crate) fn run_python_command(
    flags: &GlobalOpsFlags,
    cmd: &PythonCommand,
    override_target_uri: Option<&str>,
) -> Result<(), OpsCliError> {
    let python = resolve_python_executable()?;
    let mut proc_cmd = Command::new(&python);
    proc_cmd.arg("-m").arg("helios._cli_entry");
    if let Some(inline) = &cmd.command {
        proc_cmd.arg("-c").arg(inline);
    } else if let Some(script) = &cmd.script {
        proc_cmd.arg(script);
    }
    proc_cmd.args(&cmd.args);

    if let Some(uri) = override_target_uri {
        proc_cmd.env("HELIOS_TARGET", uri);
    } else if let Some(target) = &flags.target {
        proc_cmd.env("HELIOS_TARGET", target);
    }
    if !flags.labels.is_empty() {
        proc_cmd.env("HELIOS_LABELS", flags.labels.join(","));
    }
    proc_cmd.env("HELIOS_CONCURRENCY", flags.concurrency.to_string());
    if let Some(identity) = &flags.identity {
        proc_cmd.env("HELIOS_IDENTITY", identity);
    }
    if let Some(scope) = &flags.scope {
        proc_cmd.env("HELIOS_SCOPE", scope);
    }
    if !flags.only.is_empty() {
        proc_cmd.env("HELIOS_ONLY", flags.only.join(","));
    }

    let status = proc_cmd
        .status()
        .map_err(|source| OpsCliError::SpawnLocal {
            program: python.display().to_string(),
            source,
        })?;
    if !status.success() {
        return Err(OpsCliError::PythonExited {
            code: status.code().unwrap_or(1),
        });
    }
    Ok(())
}

/// Run `helios login`.
pub(crate) async fn run_login(cmd: &LoginCommand) -> Result<(), OpsCliError> {
    let principal = cmd
        .principal
        .clone()
        .or_else(|| std::env::var("USER").ok())
        .unwrap_or_else(|| "operator".to_owned());

    let seed = random_32().map_err(|err| {
        OpsError::Auth(helios_ops::AuthError::InvalidIdentity {
            name: cmd.name.clone(),
            detail: err.to_string(),
        })
    })?;
    let client_identity = ClientIdentity::from_static_seed(seed);
    let public_key_hex = encode_hex(&client_identity.public_key());
    let secret_key_hex = encode_hex(&seed);

    let mut cert: Option<CapabilityCert> = None;
    let mut capability_cert_postcard_hex: Option<String> = None;
    let mut expected_machine_public_key_hex: Option<String> = None;

    if let Some(authority) = &cmd.authority {
        let endpoint = format!("{}/v1/issue", authority.trim_end_matches('/'));
        let req_body = serde_json::json!({
            "principal": principal,
            "profile": cmd.name,
            "public_key_hex": public_key_hex,
        });
        let mut headers = Vec::new();
        let auth_header;
        if let Some(token) = &cmd.token {
            auth_header = format!("Bearer {token}");
            headers.push(("authorization", auth_header.as_str()));
        }
        let (_status, bytes) = http::post_json(
            &endpoint,
            &req_body,
            &headers,
            Some(Duration::from_secs(15)),
        )
        .await
        .map_err(OpsError::from)?;
        let parsed = parse_issued_credentials(&bytes, &cmd.name)?;
        cert = parsed.cert;
        capability_cert_postcard_hex = parsed.capability_cert_postcard_hex;
        expected_machine_public_key_hex = parsed.expected_machine_public_key_hex;
    }

    let profile = IdentityProfile {
        name: cmd.name.clone(),
        principal: principal.clone(),
        authority_url: cmd.authority.clone(),
        cert,
        secret_key_hex: Some(secret_key_hex),
        capability_cert_postcard_hex,
        expected_machine_public_key_hex,
        account: None,
    };
    let saved_path = profile.save().map_err(OpsError::from)?;
    println!(
        "saved identity `{}` (principal `{}`, public key `{}`) to {}",
        profile.name,
        principal,
        public_key_hex,
        saved_path.display()
    );
    Ok(())
}

struct IssuedCredentials {
    cert: Option<CapabilityCert>,
    capability_cert_postcard_hex: Option<String>,
    expected_machine_public_key_hex: Option<String>,
}

fn parse_issued_credentials(
    bytes: &[u8],
    profile_name: &str,
) -> Result<IssuedCredentials, OpsCliError> {
    let raw: serde_json::Value = serde_json::from_slice(bytes)?;
    if let Some(obj) = raw.as_object()
        && (obj.contains_key("capability_cert_postcard_hex")
            || obj.contains_key("capability_cert")
            || obj.contains_key("cert")
            || obj.contains_key("expected_machine_public_key_hex"))
    {
        let cert = obj
            .get("cert")
            .map(|v| serde_json::from_value::<CapabilityCert>(v.clone()))
            .transpose()?;
        let capability_cert_postcard_hex = if let Some(hex_val) = obj
            .get("capability_cert_postcard_hex")
            .and_then(|v| v.as_str())
        {
            Some(hex_val.to_owned())
        } else if let Some(proto_val) = obj.get("capability_cert") {
            let proto: ProtocolCapabilityCert = serde_json::from_value(proto_val.clone())?;
            Some(encode_protocol_cert(&proto, profile_name)?)
        } else {
            None
        };
        let expected_machine_public_key_hex = obj
            .get("expected_machine_public_key_hex")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        return Ok(IssuedCredentials {
            cert,
            capability_cert_postcard_hex,
            expected_machine_public_key_hex,
        });
    }

    if let Ok(proto) = serde_json::from_value::<ProtocolCapabilityCert>(raw.clone()) {
        return Ok(IssuedCredentials {
            cert: None,
            capability_cert_postcard_hex: Some(encode_protocol_cert(&proto, profile_name)?),
            expected_machine_public_key_hex: None,
        });
    }

    let cert: CapabilityCert = serde_json::from_value(raw)?;
    Ok(IssuedCredentials {
        cert: Some(cert),
        capability_cert_postcard_hex: None,
        expected_machine_public_key_hex: None,
    })
}

fn encode_protocol_cert(
    cert: &ProtocolCapabilityCert,
    profile_name: &str,
) -> Result<String, OpsCliError> {
    let encoded = cert.encode_postcard().map_err(|err| {
        OpsError::Auth(helios_ops::AuthError::InvalidIdentity {
            name: profile_name.to_owned(),
            detail: format!("failed to encode issued capability certificate: {err}"),
        })
    })?;
    Ok(encode_hex(&encoded))
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

/// Run `helios whoami`.
pub(crate) fn run_whoami(flags: &GlobalOpsFlags) -> Result<(), OpsCliError> {
    let options = build_session_options(flags)?;
    let store = TargetStore::load_default()?;
    let target = store
        .resolve(flags.target.as_deref())
        .ok()
        .map(|t| format!("{} ({})", t.name, t.uri));
    let principal = options
        .identity
        .as_ref()
        .map_or_else(|| "local".to_owned(), |id| id.principal.clone());
    let caps: Vec<&str> = options
        .attenuation
        .only
        .iter()
        .map(|r| r.as_str())
        .collect();
    match flags.output {
        CliOutputFormat::Json | CliOutputFormat::Jsonl | CliOutputFormat::Nuon => {
            let doc = serde_json::json!({
                "principal": principal,
                "target": target,
                "scope": options.attenuation.effective_scope(),
                "only": caps,
            });
            println!("{}", serde_json::to_string_pretty(&doc)?);
        }
        CliOutputFormat::Table => {
            println!("principal : {principal}");
            println!(
                "target    : {}",
                target.unwrap_or_else(|| "<none>".to_owned())
            );
            println!("scope     : {}", options.attenuation.effective_scope());
            println!(
                "only      : {}",
                if caps.is_empty() {
                    "all".to_owned()
                } else {
                    caps.join(", ")
                }
            );
        }
    }
    Ok(())
}

/// Run `helios account {create, ls, inspect, verify, rm}`.
pub(crate) fn run_account_command(
    cmd: &AccountCommand,
    flags: &GlobalOpsFlags,
) -> Result<(), OpsCliError> {
    let store = AccountStore::default_store();
    run_account_command_in(&store, cmd, flags)
}

fn run_account_command_in(
    store: &AccountStore,
    cmd: &AccountCommand,
    flags: &GlobalOpsFlags,
) -> Result<(), OpsCliError> {
    match cmd {
        AccountCommand::Create {
            username,
            touch_id,
            fido2,
            p256,
            ed25519,
            require_uv,
            application,
        } => {
            let authenticator = if *touch_id {
                AccountAuthenticatorChoice::TouchId
            } else if *fido2 {
                AccountAuthenticatorChoice::Fido2
            } else if *p256 {
                AccountAuthenticatorChoice::SoftwareP256
            } else if *ed25519 {
                AccountAuthenticatorChoice::SoftwareEd25519
            } else {
                AccountAuthenticatorChoice::platform_default()
            };

            let mut only = BTreeSet::new();
            for raw in &flags.only {
                if raw.trim().is_empty() {
                    continue;
                }
                let right = GrantRight::parse(raw)
                    .ok_or_else(|| OpsCliError::UnknownCapability { raw: raw.clone() })?;
                only.insert(right);
            }
            let grants = session_grants_from_attenuation(&Attenuation {
                scope: flags.scope.clone(),
                only,
            })?;

            eprintln!(
                "enrolling operator account `{username}` with authenticator `{}`...",
                authenticator.label()
            );
            let mut req = CreateAccountRequest::new(username.clone(), authenticator);
            req.require_uv = *require_uv;
            req.application = application.clone();
            req.grants = grants;
            let account = store.create(req)?;
            let summary = account_summary_json(&account)?;
            match flags.output {
                CliOutputFormat::Json | CliOutputFormat::Nuon => {
                    println!("{}", serde_json::to_string_pretty(&summary)?);
                }
                CliOutputFormat::Jsonl => {
                    println!("{}", serde_json::to_string(&summary)?);
                }
                CliOutputFormat::Table => {
                    let pub_key = account.public_key()?;
                    println!(
                        "created account `{}` ({}, {}, fingerprint {}) at {}",
                        account.username,
                        account.authenticator.kind_label(),
                        pub_key.algorithm_name(),
                        account_encode_hex(&pub_key.fingerprint_sha256()),
                        store.path_for(&account.username).display()
                    );
                }
            }
        }
        AccountCommand::Ls => {
            let accounts = store.list()?;
            match flags.output {
                CliOutputFormat::Json | CliOutputFormat::Nuon => {
                    let rows: Vec<serde_json::Value> = accounts
                        .iter()
                        .map(account_summary_json)
                        .collect::<Result<_, _>>()?;
                    println!("{}", serde_json::to_string_pretty(&rows)?);
                }
                CliOutputFormat::Jsonl => {
                    for acct in &accounts {
                        println!("{}", serde_json::to_string(&account_summary_json(acct)?)?);
                    }
                }
                CliOutputFormat::Table => {
                    if accounts.is_empty() {
                        println!("no accounts configured ({})", store.dir().display());
                    } else {
                        for acct in &accounts {
                            let pub_key = acct.public_key()?;
                            let fp = account_encode_hex(&pub_key.fingerprint_sha256());
                            println!(
                                "{:<20} {:<10} {:<15} {}",
                                acct.username,
                                acct.authenticator.kind_label(),
                                pub_key.algorithm_name(),
                                &fp[..16],
                            );
                        }
                    }
                }
            }
        }
        AccountCommand::Inspect { username } => {
            let account = store.load(username)?;
            let pub_key = account.public_key()?;
            let summary = account_summary_json(&account)?;
            match flags.output {
                CliOutputFormat::Json | CliOutputFormat::Nuon => {
                    println!("{}", serde_json::to_string_pretty(&summary)?);
                }
                CliOutputFormat::Jsonl => {
                    println!("{}", serde_json::to_string(&summary)?);
                }
                CliOutputFormat::Table => {
                    println!("username      : {}", account.username);
                    println!("authenticator : {}", account.authenticator.kind_label());
                    println!("algorithm     : {}", pub_key.algorithm_name());
                    println!(
                        "public_key    : {}",
                        account_encode_hex(pub_key.raw_key_bytes())
                    );
                    println!(
                        "fingerprint   : {}",
                        account_encode_hex(&pub_key.fingerprint_sha256())
                    );
                    println!("created_at    : {}", account.created_at_unix);
                    match &account.authenticator {
                        AuthenticatorSpec::TouchId {
                            keychain_service,
                            keychain_account,
                            ..
                        } => {
                            println!("keychain      : {keychain_service} / {keychain_account}");
                        }
                        AuthenticatorSpec::Fido2 {
                            application,
                            require_uv,
                            key_handle_path,
                            ..
                        } => {
                            println!("application   : {application}");
                            println!("require_uv    : {require_uv}");
                            println!("key_handle    : {}", key_handle_path.display());
                        }
                        AuthenticatorSpec::SoftwareP256 { .. }
                        | AuthenticatorSpec::SoftwareEd25519 { .. } => {}
                    }
                    println!(
                        "path          : {}",
                        store.path_for(&account.username).display()
                    );
                }
            }
        }
        AccountCommand::Verify { username } => {
            let account = store.load(username)?;
            let verified = account.verify_self()?;
            let fp = account_encode_hex(&verified.public_key.fingerprint_sha256());
            match flags.output {
                CliOutputFormat::Json | CliOutputFormat::Nuon => {
                    let doc = serde_json::json!({
                        "verified": true,
                        "username": verified.username,
                        "algorithm": verified.public_key.algorithm_name(),
                        "fingerprint_sha256": fp,
                    });
                    println!("{}", serde_json::to_string_pretty(&doc)?);
                }
                CliOutputFormat::Jsonl => {
                    let doc = serde_json::json!({
                        "verified": true,
                        "username": verified.username,
                        "algorithm": verified.public_key.algorithm_name(),
                        "fingerprint_sha256": fp,
                    });
                    println!("{}", serde_json::to_string(&doc)?);
                }
                CliOutputFormat::Table => {
                    println!(
                        "verified account `{}` ({}, fingerprint {})",
                        verified.username,
                        verified.public_key.algorithm_name(),
                        fp
                    );
                }
            }
        }
        AccountCommand::Rm { username } => {
            let removed = store.remove(username)?;
            println!(
                "removed account `{}` ({})",
                removed.username,
                removed.authenticator.kind_label()
            );
        }
    }
    Ok(())
}

fn account_summary_json(account: &OperatorAccount) -> Result<serde_json::Value, OpsCliError> {
    let pub_key = account.public_key()?;
    let (application, require_uv, key_handle_path, keychain_service) = match &account.authenticator
    {
        AuthenticatorSpec::TouchId {
            keychain_service, ..
        } => (None, None, None, Some(keychain_service.as_str())),
        AuthenticatorSpec::Fido2 {
            application,
            require_uv,
            key_handle_path,
            ..
        } => (
            Some(application.as_str()),
            Some(*require_uv),
            Some(key_handle_path.display().to_string()),
            None,
        ),
        AuthenticatorSpec::SoftwareP256 { .. } | AuthenticatorSpec::SoftwareEd25519 { .. } => {
            (None, None, None, None)
        }
    };
    Ok(serde_json::json!({
        "username": account.username,
        "authenticator": account.authenticator.kind_label(),
        "algorithm": pub_key.algorithm_name(),
        "public_key_hex": account_encode_hex(pub_key.raw_key_bytes()),
        "fingerprint_sha256": account_encode_hex(&pub_key.fingerprint_sha256()),
        "created_at_unix": account.created_at_unix,
        "application": application,
        "require_uv": require_uv,
        "key_handle_path": key_handle_path,
        "keychain_service": keychain_service,
    }))
}

/// Run `helios target {add, ls, use, rm}`.
pub(crate) fn run_target_command(
    cmd: &TargetCommand,
    output: CliOutputFormat,
) -> Result<(), OpsCliError> {
    let mut store = TargetStore::load_default()?;
    match cmd {
        TargetCommand::Add {
            name,
            uri,
            labels,
            identity,
            scope,
        } => {
            let mut target = Target::new(name, uri)?;
            for (k, v) in helios_ops::target::parse_label_filters(labels)? {
                target.labels.insert(k, v);
            }
            target.identity = identity.clone();
            target.default_scope = scope.clone();
            store.upsert(target);
            store.save()?;
            println!("added target `{name}` -> {uri}");
        }
        TargetCommand::Ls => {
            let default_name = store.default_target_name().map(ToOwned::to_owned);
            match output {
                CliOutputFormat::Json | CliOutputFormat::Nuon => {
                    println!("{}", serde_json::to_string_pretty(store.list())?);
                }
                CliOutputFormat::Jsonl => {
                    for t in store.list() {
                        println!("{}", serde_json::to_string(t)?);
                    }
                }
                CliOutputFormat::Table => {
                    if store.list().is_empty() {
                        println!("no targets configured ({})", store.path().display());
                    } else {
                        for t in store.list() {
                            let mark = if default_name.as_deref() == Some(t.name.as_str()) {
                                "*"
                            } else {
                                " "
                            };
                            let labels = helios_inspector_shell::env::format_labels(&t.labels);
                            println!("{mark} {:<20} {:<36} {labels}", t.name, t.uri);
                        }
                    }
                }
            }
        }
        TargetCommand::Use { name } => {
            store.set_default(name)?;
            store.save()?;
            println!("default target set to `{name}`");
        }
        TargetCommand::Rm { name } => {
            store.remove(name)?;
            store.save()?;
            println!("removed target `{name}`");
        }
    }
    Ok(())
}

/// Run `helios inspect` (one-shot, `--watch`, and `--diff`).
pub(crate) async fn run_inspect(
    session: &Session,
    cmd: &InspectCommand,
    output: CliOutputFormat,
) -> Result<(), OpsCliError> {
    let prefixes: Vec<&str> = cmd.prefixes.iter().map(String::as_str).collect();
    let mut previous: Option<BTreeMap<String, String>> = None;

    loop {
        let snapshot = session.inspect(&prefixes, cmd.limit).await?;
        let current: BTreeMap<String, String> = snapshot
            .entries
            .iter()
            .map(|e| (e.path.clone(), render_inspect_value(&e.value)))
            .collect();

        if cmd.diff
            && let Some(prev) = &previous
        {
            for (path, val) in &current {
                match prev.get(path) {
                    None => println!("+ {path} = {val}"),
                    Some(old) if old != val => println!("~ {path}: {old} -> {val}"),
                    _ => {}
                }
            }
            for (path, old) in prev {
                if !current.contains_key(path) {
                    println!("- {path} = {old}");
                }
            }
        } else {
            render_inspect_entries(&snapshot.entries, output)?;
        }

        previous = Some(current);
        if !cmd.watch {
            break;
        }
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            _ = tokio::time::sleep(Duration::from_millis(cmd.interval_ms.max(50))) => {}
        }
    }
    Ok(())
}

fn render_inspect_entries(
    entries: &[proto_inspect::Entry],
    output: CliOutputFormat,
) -> Result<(), OpsCliError> {
    match output {
        CliOutputFormat::Json | CliOutputFormat::Nuon => {
            let rows: Vec<serde_json::Value> = entries
                .iter()
                .map(|e| {
                    serde_json::json!({
                        "path": e.path,
                        "value": inspect_value_json(&e.value),
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&rows)?);
        }
        CliOutputFormat::Jsonl => {
            for e in entries {
                let row = serde_json::json!({
                    "path": e.path,
                    "value": inspect_value_json(&e.value),
                });
                println!("{}", serde_json::to_string(&row)?);
            }
        }
        CliOutputFormat::Table => {
            for e in entries {
                println!("{:<56} {}", e.path, render_inspect_value(&e.value));
            }
        }
    }
    Ok(())
}

/// Run `helios ps` (with `--tree` and `-o` formatting).
pub(crate) async fn run_ps(
    session: &Session,
    cmd: &PsCommand,
    output: CliOutputFormat,
) -> Result<(), OpsCliError> {
    let instances = session.ps().await?;
    match output {
        CliOutputFormat::Json | CliOutputFormat::Nuon => {
            let rows: Vec<serde_json::Value> = instances
                .iter()
                .map(|inst| {
                    serde_json::json!({
                        "id": inst.id,
                        "name": inst.name,
                        "uptime_ms": inst.uptime / 1_000_000,
                        "memory_bytes": inst.memory_bytes,
                        "cpu_permille": inst.cpu_busy,
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&rows)?);
        }
        CliOutputFormat::Jsonl => {
            for inst in &instances {
                let row = serde_json::json!({
                    "id": inst.id,
                    "name": inst.name,
                    "uptime_ms": inst.uptime / 1_000_000,
                    "memory_bytes": inst.memory_bytes,
                    "cpu_permille": inst.cpu_busy,
                });
                println!("{}", serde_json::to_string(&row)?);
            }
        }
        CliOutputFormat::Table => {
            if cmd.tree {
                println!("/ (helios)");
                for (idx, inst) in instances.iter().enumerate() {
                    let branch = if idx + 1 == instances.len() {
                        "└─"
                    } else {
                        "├─"
                    };
                    println!(
                        "{branch} [{}] {} ({} KiB, {:.1}% cpu)",
                        inst.id,
                        inst.name,
                        inst.memory_bytes / 1024,
                        f64::from(inst.cpu_busy) / 10.0,
                    );
                }
            } else {
                for inst in &instances {
                    if cmd.long {
                        println!(
                            "{:>6}  {:<28} up {:>8} ms  {:>10} B  {:>5.1}% cpu",
                            inst.id,
                            inst.name,
                            inst.uptime / 1_000_000,
                            inst.memory_bytes,
                            f64::from(inst.cpu_busy) / 10.0,
                        );
                    } else {
                        println!(
                            "{:>6}  {:<24} up {:>8} ms  {:>9} KiB  {:>4}‰ cpu",
                            inst.id,
                            inst.name,
                            inst.uptime / 1_000_000,
                            inst.memory_bytes / 1024,
                            inst.cpu_busy,
                        );
                    }
                }
            }
        }
    }
    Ok(())
}

/// Run `helios kill`.
pub(crate) async fn run_kill(session: &Session, cmd: &KillCommand) -> Result<(), OpsCliError> {
    let _ = cmd.force;
    if !cmd.name
        && let Ok(id) = cmd.target.parse::<u64>()
    {
        session.kill(id).await?;
        println!("killed instance {id}");
        return Ok(());
    }
    let id = session.kill_by_name(&cmd.target).await?;
    println!("killed instance {id} (`{}`)", cmd.target);
    Ok(())
}

/// Run `helios trace` (one-shot or `--follow`).
pub(crate) async fn run_trace(
    session: &Session,
    cmd: &TraceCommand,
    output: CliOutputFormat,
) -> Result<(), OpsCliError> {
    for target in &cmd.enable_target {
        session.set_trace_target_enabled(target, true).await?;
    }
    let min_level = match cmd.min_level.as_deref() {
        None => Some(proto_tracing::Level::Info),
        Some("none") => None,
        Some("error") => Some(proto_tracing::Level::Error),
        Some("warn") => Some(proto_tracing::Level::Warn),
        Some("info") => Some(proto_tracing::Level::Info),
        Some("debug") => Some(proto_tracing::Level::Debug),
        Some("trace") => Some(proto_tracing::Level::Trace),
        Some(other) => {
            return Err(OpsCliError::UnknownTraceLevel {
                level: other.to_owned(),
            });
        }
    };
    let filter = proto_tracing::Filter {
        min_level,
        target_prefixes: cmd.target_prefix.clone(),
    };

    let mut seen = BTreeSet::new();
    loop {
        let events = session.trace_recent(&filter, cmd.limit).await?;
        for ev in events {
            let key = (ev.timestamp, ev.target.clone(), ev.fields.len());
            if !seen.insert(key) {
                continue;
            }
            match output {
                CliOutputFormat::Json | CliOutputFormat::Jsonl | CliOutputFormat::Nuon => {
                    let row = serde_json::json!({
                        "timestamp": ev.timestamp,
                        "level": format!("{:?}", ev.level),
                        "target": ev.target,
                        "fields": ev.fields.iter().map(|f| (f.key.clone(), format!("{:?}", f.value))).collect::<BTreeMap<_, _>>(),
                    });
                    println!("{}", serde_json::to_string(&row)?);
                }
                CliOutputFormat::Table => {
                    let rendered = crate::system::render_tracing_event(&ev)
                        .unwrap_or_else(|_| format!("{:?} {}", ev.level, ev.target));
                    println!("{rendered}");
                }
            }
        }
        if !cmd.follow {
            break;
        }
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            _ = tokio::time::sleep(Duration::from_millis(250)) => {}
        }
    }
    Ok(())
}

/// Run `helios profile {instructions, folded, metrics, llvm-raw}`.
pub(crate) async fn run_profile(
    session: &Session,
    cmd: &ProfileOpsCommand,
    output: CliOutputFormat,
) -> Result<(), OpsCliError> {
    match cmd {
        ProfileOpsCommand::Instructions {
            duration_ms,
            kernel,
            out,
        } => {
            let profile = if *duration_ms > 0 {
                let guard = session.start_instruction_sampling().await?;
                tokio::time::sleep(Duration::from_millis(*duration_ms)).await;
                guard.stop_and_collect().await?
            } else {
                session.profile_instruction_samples().await?
            };
            if let Some(kernel_path) = kernel {
                let symbolized = helios_ops::symbolize_instruction_profile(profile, kernel_path)
                    .await
                    .map_err(OpsError::from)?;
                if let Some(out_path) = out {
                    let folded = helios_ops::symbolize::render_folded_samples(&symbolized.samples);
                    tokio::fs::write(out_path, folded).await?;
                }
                match output {
                    CliOutputFormat::Json | CliOutputFormat::Nuon => {
                        println!("{}", serde_json::to_string_pretty(&symbolized)?);
                    }
                    CliOutputFormat::Jsonl => {
                        for sample in &symbolized.samples {
                            println!("{}", serde_json::to_string(sample)?);
                        }
                    }
                    CliOutputFormat::Table => {
                        for sample in &symbolized.samples {
                            println!("{} {}", sample.stack, sample.count);
                        }
                    }
                }
                return Ok(());
            }
            let sample_count: u64 = profile.samples.iter().map(|s| s.count).sum();
            let doc = serde_json::json!({
                "period_nanos": profile.period_nanos,
                "kernel_image_base": format!("{:#x}", profile.kernel_image_base),
                "sample_count": sample_count,
                "unique_pcs": profile.samples.len(),
                "dropped": profile.dropped,
            });
            println!("{}", serde_json::to_string_pretty(&doc)?);
        }
        ProfileOpsCommand::Folded {
            limit,
            stack_prefix,
        } => {
            let filter = ProfileFilter {
                scope: None,
                stack_prefixes: stack_prefix.clone(),
            };
            let samples = session.profile_folded(&filter, *limit).await?;
            match output {
                CliOutputFormat::Json | CliOutputFormat::Nuon => {
                    let rows: Vec<serde_json::Value> = samples
                        .iter()
                        .map(|s| {
                            serde_json::json!({
                                "scope": format!("{:?}", s.scope),
                                "stack": s.stack,
                                "weight": s.weight,
                            })
                        })
                        .collect();
                    println!("{}", serde_json::to_string_pretty(&rows)?);
                }
                CliOutputFormat::Jsonl => {
                    for s in samples {
                        let row = serde_json::json!({
                            "scope": format!("{:?}", s.scope),
                            "stack": s.stack,
                            "weight": s.weight,
                        });
                        println!("{}", serde_json::to_string(&row)?);
                    }
                }
                CliOutputFormat::Table => {
                    for s in samples {
                        println!("{} {}", s.stack, s.weight);
                    }
                }
            }
        }
        ProfileOpsCommand::Metrics { limit, prefix } => {
            let filter = MetricFilter {
                name_prefixes: prefix.clone(),
            };
            let metrics = session.profile_metrics(&filter, *limit).await?;
            match output {
                CliOutputFormat::Json | CliOutputFormat::Nuon => {
                    let rows: Vec<serde_json::Value> = metrics
                        .iter()
                        .map(|m| {
                            serde_json::json!({
                                "scope": format!("{:?}", m.scope),
                                "name": m.name,
                                "count": m.count,
                                "total_events": m.total_events,
                                "total_nanos": m.total_nanos,
                                "min_nanos": m.min_nanos,
                                "max_nanos": m.max_nanos,
                            })
                        })
                        .collect();
                    println!("{}", serde_json::to_string_pretty(&rows)?);
                }
                CliOutputFormat::Jsonl => {
                    for m in metrics {
                        let row = serde_json::json!({
                            "scope": format!("{:?}", m.scope),
                            "name": m.name,
                            "count": m.count,
                            "total_events": m.total_events,
                            "total_nanos": m.total_nanos,
                            "min_nanos": m.min_nanos,
                            "max_nanos": m.max_nanos,
                        });
                        println!("{}", serde_json::to_string(&row)?);
                    }
                }
                CliOutputFormat::Table => {
                    for m in metrics {
                        println!(
                            "{:<40} count={:<8} total_ns={:<12} min_ns={:<10} max_ns={}",
                            m.name, m.count, m.total_nanos, m.min_nanos, m.max_nanos
                        );
                    }
                }
            }
        }
        ProfileOpsCommand::LlvmRaw { out } => {
            let bytes = session.profile_raw_collect().await?;
            tokio::fs::write(out, &bytes).await?;
            println!("wrote {} bytes to {}", bytes.len(), out.display());
        }
    }
    Ok(())
}

/// Run `helios spawn`.
pub(crate) async fn run_spawn(session: &Session, cmd: &SpawnCommand) -> Result<(), OpsCliError> {
    let env = parse_env_pairs(&cmd.env)?;
    let capability_grants = parse_cli_grants(&cmd.grants)?;
    let child = session
        .spawn(SpawnRequest {
            path: cmd.path.clone(),
            args: cmd.args.clone(),
            env,
            cwd: cmd.cwd.clone(),
            stdin: Vec::new(),
            capability_grants,
        })
        .await?;
    stream_child_to_stdio(child).await
}

/// Run `helios exec`.
pub(crate) async fn run_exec(
    session: &Session,
    fleet: Option<&Fleet>,
    cmd: &ExecCommand,
    output: CliOutputFormat,
) -> Result<(), OpsCliError> {
    let env = parse_env_pairs(&cmd.env)?;
    let capability_grants = parse_cli_grants(&cmd.grants)?;
    let stdin = cmd
        .stdin
        .as_deref()
        .map_or_else(Vec::new, |s| s.as_bytes().to_vec());

    if let Some(fleet) = fleet
        && env.is_empty()
        && cmd.cwd.is_none()
        && capability_grants.is_empty()
        && stdin.is_empty()
    {
        let outcomes = fleet.exec(cmd.path.clone(), cmd.args.clone()).await;
        for outcome in outcomes {
            match outcome.result {
                Ok(res) => match output {
                    CliOutputFormat::Json | CliOutputFormat::Jsonl | CliOutputFormat::Nuon => {
                        let row = serde_json::json!({
                            "target": outcome.target.name,
                            "exit_code": res.exit_code,
                            "stdout": String::from_utf8_lossy(&res.output.stdout),
                            "stderr": String::from_utf8_lossy(&res.output.stderr),
                        });
                        println!("{}", serde_json::to_string(&row)?);
                    }
                    CliOutputFormat::Table => {
                        println!("[{}] exit={}", outcome.target.name, res.exit_code);
                        std::io::stdout().write_all(&res.output.stdout)?;
                        std::io::stderr().write_all(&res.output.stderr)?;
                    }
                },
                Err(err) => {
                    eprintln!("[{}] error: {err}", outcome.target.name);
                }
            }
        }
        return Ok(());
    }

    let normalized = helios_ops::session::normalize_absolute_path(&cmd.path)?;
    let result = session
        .exec_request(ExecRequest {
            name: normalized.clone(),
            args: cmd.args.clone(),
            env,
            path: normalized,
            cwd: cmd.cwd.clone(),
            stdin,
            hint: None,
            capability_grants,
        })
        .await?;
    std::io::stdout().write_all(&result.output.stdout)?;
    std::io::stderr().write_all(&result.output.stderr)?;
    if result.exit_code != 0 {
        return Err(OpsCliError::RemoteExited {
            code: result.exit_code,
        });
    }
    Ok(())
}

/// Run `helios component {ls, status, start, stop, restart}`.
pub(crate) async fn run_component(
    session: &Session,
    fleet: Option<&Fleet>,
    cmd: &ComponentCommand,
    output: CliOutputFormat,
) -> Result<(), OpsCliError> {
    if let Some(fleet) = fleet {
        let fc = fleet.components();
        match cmd {
            ComponentCommand::Ls => {
                for outcome in fc.list().await {
                    match outcome.result {
                        Ok(list) => {
                            println!("=== {} ===", outcome.target.name);
                            render_components(&list, output)?;
                        }
                        Err(err) => eprintln!("[{}] error: {err}", outcome.target.name),
                    }
                }
            }
            ComponentCommand::Status { moniker } => {
                for outcome in fc.status(moniker.clone()).await {
                    match outcome.result {
                        Ok(st) => {
                            println!("=== {} ===", outcome.target.name);
                            render_components(&[st], output)?;
                        }
                        Err(err) => eprintln!("[{}] error: {err}", outcome.target.name),
                    }
                }
            }
            ComponentCommand::Start { moniker } => {
                for outcome in fc.start(moniker.clone()).await {
                    match outcome.result {
                        Ok(st) => {
                            println!("=== {} ===", outcome.target.name);
                            render_components(&[st], output)?;
                        }
                        Err(err) => eprintln!("[{}] error: {err}", outcome.target.name),
                    }
                }
            }
            ComponentCommand::Stop { moniker } => {
                for outcome in fc.stop(moniker.clone()).await {
                    match outcome.result {
                        Ok(()) => println!("[{}] stopped {moniker}", outcome.target.name),
                        Err(err) => eprintln!("[{}] error: {err}", outcome.target.name),
                    }
                }
            }
            ComponentCommand::Restart { moniker } => {
                for outcome in fc.restart(moniker.clone()).await {
                    match outcome.result {
                        Ok(st) => {
                            println!("=== {} ===", outcome.target.name);
                            render_components(&[st], output)?;
                        }
                        Err(err) => eprintln!("[{}] error: {err}", outcome.target.name),
                    }
                }
            }
            ComponentCommand::MountDynamic {
                parent_moniker,
                guest_dir,
                subtree_name,
                manifest_dir,
            } => {
                let source = build_dynamic_subtree_source(
                    guest_dir.as_deref(),
                    subtree_name.as_deref(),
                    manifest_dir.as_deref(),
                )?;
                for outcome in fc.mount_dynamic(parent_moniker.clone(), source).await {
                    match outcome.result {
                        Ok(mounted) => println!("[{}] mounted {mounted}", outcome.target.name),
                        Err(err) => eprintln!("[{}] error: {err}", outcome.target.name),
                    }
                }
            }
            ComponentCommand::UnmountDynamic { moniker } => {
                for outcome in fc.unmount_dynamic(moniker.clone()).await {
                    match outcome.result {
                        Ok(()) => println!("[{}] unmounted {moniker}", outcome.target.name),
                        Err(err) => eprintln!("[{}] error: {err}", outcome.target.name),
                    }
                }
            }
        }
        return Ok(());
    }

    let components = session.components();
    match cmd {
        ComponentCommand::Ls => {
            let list = components.list().await?;
            render_components(&list, output)?;
        }
        ComponentCommand::Status { moniker } => {
            let st = components.status(moniker).await?;
            render_components(&[st], output)?;
        }
        ComponentCommand::Start { moniker } => {
            let st = components.start(moniker).await?;
            render_components(&[st], output)?;
        }
        ComponentCommand::Stop { moniker } => {
            components.stop(moniker).await?;
            println!("stopped component `{moniker}`");
        }
        ComponentCommand::Restart { moniker } => {
            let st = components.restart(moniker).await?;
            render_components(&[st], output)?;
        }
        ComponentCommand::MountDynamic {
            parent_moniker,
            guest_dir,
            subtree_name,
            manifest_dir,
        } => {
            let source = build_dynamic_subtree_source(
                guest_dir.as_deref(),
                subtree_name.as_deref(),
                manifest_dir.as_deref(),
            )?;
            let mounted = components.mount_dynamic(parent_moniker, source).await?;
            match output {
                CliOutputFormat::Json | CliOutputFormat::Nuon | CliOutputFormat::Jsonl => {
                    println!("{}", serde_json::json!({ "moniker": mounted }));
                }
                CliOutputFormat::Table => println!("mounted dynamic subtree `{mounted}`"),
            }
        }
        ComponentCommand::UnmountDynamic { moniker } => {
            components.unmount_dynamic(moniker).await?;
            println!("unmounted dynamic subtree `{moniker}`");
        }
    }
    Ok(())
}

fn build_dynamic_subtree_source(
    guest_dir: Option<&str>,
    subtree_name: Option<&str>,
    manifest_dir: Option<&Path>,
) -> Result<helios_ops::DynamicSubtreeSource, OpsCliError> {
    match (guest_dir, manifest_dir) {
        (Some(path), None) => {
            let name = match subtree_name {
                Some(explicit) if !explicit.trim().is_empty() => explicit.trim().to_owned(),
                _ => Path::new(path)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .filter(|s| !s.is_empty())
                    .ok_or_else(|| {
                        OpsCliError::InvalidArgument(format!(
                            "cannot infer subtree name from `--guest-dir {path}`; pass `--name`"
                        ))
                    })?
                    .to_owned(),
            };
            Ok(helios_ops::DynamicSubtreeSource::GuestDir(
                helios_ops::DynamicDirSource {
                    subtree_name: name,
                    path: path.to_owned(),
                },
            ))
        }
        (None, Some(root)) => {
            let mut manifests = Vec::new();
            collect_dynamic_manifests(root, root, &mut manifests)?;
            if manifests.is_empty() {
                return Err(OpsCliError::InvalidArgument(format!(
                    "no `component.toml` files found under `{}`",
                    root.display()
                )));
            }
            manifests.sort_by(|a, b| a.0.cmp(&b.0));
            Ok(helios_ops::DynamicSubtreeSource::Manifests(manifests))
        }
        _ => Err(OpsCliError::InvalidArgument(
            "component mount-dynamic requires either `--guest-dir <GUEST_DIR>` or `--manifest-dir <HOST_DIR>`"
                .to_owned(),
        )),
    }
}

fn collect_dynamic_manifests(
    root: &Path,
    dir: &Path,
    out: &mut Vec<(String, String)>,
) -> Result<(), OpsCliError> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            collect_dynamic_manifests(root, &path, out)?;
        } else if file_type.is_file() && entry.file_name() == "component.toml" {
            let rel = path
                .strip_prefix(root)
                .map_err(|err| OpsCliError::InvalidArgument(err.to_string()))?;
            let rel_posix = rel
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/");
            let content = std::fs::read_to_string(&path)?;
            out.push((rel_posix, content));
        }
    }
    Ok(())
}

fn render_components(
    components: &[ComponentStatus],
    output: CliOutputFormat,
) -> Result<(), OpsCliError> {
    let to_json = |c: &ComponentStatus| {
        serde_json::json!({
            "moniker": c.moniker,
            "program": c.program,
            "state": c.state,
            "instance_id": c.instance_id,
            "restarts": c.restarts,
        })
    };
    match output {
        CliOutputFormat::Json | CliOutputFormat::Nuon => {
            let rows: Vec<serde_json::Value> = components.iter().map(to_json).collect();
            println!("{}", serde_json::to_string_pretty(&rows)?);
        }
        CliOutputFormat::Jsonl => {
            for c in components {
                println!("{}", serde_json::to_string(&to_json(c))?);
            }
        }
        CliOutputFormat::Table => {
            for c in components {
                let id = c
                    .instance_id
                    .map_or_else(|| "-".to_owned(), |id| id.to_string());
                println!(
                    "{:<28} {:<12} id={:<8} restarts={:<4} {}",
                    c.moniker, c.state, id, c.restarts, c.program
                );
            }
        }
    }
    Ok(())
}

/// Run `helios oci {pull, ls, inspect, rm}`.
pub(crate) async fn run_oci(
    session: &Session,
    fleet: Option<&Fleet>,
    cmd: &OciCommand,
    output: CliOutputFormat,
) -> Result<(), OpsCliError> {
    let parse_arch = |raw: Option<&str>| -> Option<OciArch> {
        match raw {
            Some("x86_64" | "x86-64" | "amd64") => Some(OciArch::X86_64),
            Some("aarch64" | "arm64") => Some(OciArch::Aarch64),
            _ => None,
        }
    };

    if let Some(fleet) = fleet {
        let oci_for = |store_root: &Option<String>| {
            let base = fleet.oci();
            match store_root {
                Some(root) => base.with_store_root(root),
                None => base,
            }
        };
        match cmd {
            OciCommand::Pull {
                reference,
                arch,
                store_root,
            } => {
                let opts = PullOptions {
                    arch: parse_arch(arch.as_deref()),
                    ..PullOptions::default()
                };
                for outcome in oci_for(store_root)
                    .pull_with_options(reference.clone(), opts)
                    .await
                {
                    match outcome.result {
                        Ok(img) => {
                            println!("=== {} ===", outcome.target.name);
                            render_oci_images(&[img], output)?;
                        }
                        Err(err) => eprintln!("[{}] error: {err}", outcome.target.name),
                    }
                }
            }
            OciCommand::Ls { store_root } => {
                for outcome in oci_for(store_root).list().await {
                    match outcome.result {
                        Ok(imgs) => {
                            println!("=== {} ===", outcome.target.name);
                            render_oci_images(&imgs, output)?;
                        }
                        Err(err) => eprintln!("[{}] error: {err}", outcome.target.name),
                    }
                }
            }
            OciCommand::Inspect {
                reference,
                store_root,
            } => {
                for outcome in oci_for(store_root).inspect(reference.clone()).await {
                    match outcome.result {
                        Ok(img) => {
                            println!("=== {} ===", outcome.target.name);
                            println!("{}", serde_json::to_string_pretty(&img)?);
                        }
                        Err(err) => eprintln!("[{}] error: {err}", outcome.target.name),
                    }
                }
            }
            OciCommand::Rm {
                reference,
                store_root,
            } => {
                for outcome in oci_for(store_root).remove(reference.clone()).await {
                    match outcome.result {
                        Ok(img) => println!("[{}] removed {}", outcome.target.name, img.reference),
                        Err(err) => eprintln!("[{}] error: {err}", outcome.target.name),
                    }
                }
            }
        }
        return Ok(());
    }

    let make_client = |store_root: &Option<String>| -> Result<helios_ops::OciClient, OpsCliError> {
        match store_root {
            Some(root) => Ok(session.oci_with_store_root(root)?),
            None => Ok(session.oci()),
        }
    };

    match cmd {
        OciCommand::Pull {
            reference,
            arch,
            store_root,
        } => {
            let client = make_client(store_root)?;
            let img = client
                .pull_with_options(
                    reference,
                    PullOptions {
                        arch: parse_arch(arch.as_deref()),
                        ..PullOptions::default()
                    },
                )
                .await?;
            render_oci_images(&[img], output)?;
        }
        OciCommand::Ls { store_root } => {
            let imgs = make_client(store_root)?.list().await?;
            render_oci_images(&imgs, output)?;
        }
        OciCommand::Inspect {
            reference,
            store_root,
        } => {
            let img = make_client(store_root)?.inspect(reference).await?;
            println!("{}", serde_json::to_string_pretty(&img)?);
        }
        OciCommand::Rm {
            reference,
            store_root,
        } => {
            let removed = make_client(store_root)?.remove(reference).await?;
            println!("removed image `{}`", removed.reference);
        }
    }
    Ok(())
}

fn render_oci_images(images: &[PulledImage], output: CliOutputFormat) -> Result<(), OpsCliError> {
    match output {
        CliOutputFormat::Json | CliOutputFormat::Nuon => {
            println!("{}", serde_json::to_string_pretty(images)?);
        }
        CliOutputFormat::Jsonl => {
            for img in images {
                println!("{}", serde_json::to_string(img)?);
            }
        }
        CliOutputFormat::Table => {
            for img in images {
                println!(
                    "{:<36} {:<8} layers={:<3} btrfs={:<5} {}",
                    img.reference.to_string(),
                    img.arch.oci_arch(),
                    img.layer_chain_ids.len(),
                    img.btrfs_backed,
                    img.rootfs_path.display()
                );
            }
        }
    }
    Ok(())
}

/// Run `helios container {create, ls, exec, spawn, rm}`.
pub(crate) async fn run_container(
    session: &Session,
    cmd: &ContainerCommand,
    output: CliOutputFormat,
) -> Result<(), OpsCliError> {
    match cmd {
        ContainerCommand::Ls => {
            let snap = session.kernel_snapshot().await?;
            let to_json = |c: &helios_wit_rpc::inspector_snapshot::LinuxContainer| {
                serde_json::json!({
                    "id": c.id,
                    "hostname": c.hostname,
                    "domainname": c.domainname,
                    "live_processes": c.live_processes,
                    "allocated_pids": c.allocated_pids,
                    "live_threads": c.live_threads,
                    "overlay_pages": c.overlay_pages,
                    "mounts": c.mounts.len(),
                })
            };
            match output {
                CliOutputFormat::Json | CliOutputFormat::Nuon => {
                    let rows: Vec<serde_json::Value> =
                        snap.containers.iter().map(to_json).collect();
                    println!("{}", serde_json::to_string_pretty(&rows)?);
                }
                CliOutputFormat::Jsonl => {
                    for c in &snap.containers {
                        println!("{}", serde_json::to_string(&to_json(c))?);
                    }
                }
                CliOutputFormat::Table => {
                    for c in &snap.containers {
                        println!(
                            "{:>6}  {:<20} procs={:<4} threads={:<4} overlay_pages={:<6} mounts={}",
                            c.id,
                            c.hostname,
                            c.live_processes,
                            c.live_threads,
                            c.overlay_pages,
                            c.mounts.len()
                        );
                    }
                }
            }
        }
        ContainerCommand::Create {
            config,
            hold,
            command,
        } => {
            let builder = build_container_from_args(session, config).await?;
            let container = builder.create(session.clone()).await?;
            if let Some((prog, args)) = command.split_first() {
                let res = container
                    .exec_with_options(prog, args, &[], config.cwd.as_deref(), Vec::new())
                    .await?;
                std::io::stdout().write_all(&res.output.stdout)?;
                std::io::stderr().write_all(&res.output.stderr)?;
                if res.exit_code != 0 {
                    return Err(OpsCliError::RemoteExited {
                        code: res.exit_code,
                    });
                }
            } else {
                let info = serde_json::json!({
                    "hostname": container.config().hostname,
                    "root": container.config().root.source_path,
                    "mounts": container.config().mounts.len(),
                });
                match output {
                    CliOutputFormat::Json | CliOutputFormat::Jsonl | CliOutputFormat::Nuon => {
                        println!("{}", serde_json::to_string_pretty(&info)?);
                    }
                    CliOutputFormat::Table => {
                        println!(
                            "created container `{}` (root={})",
                            container.config().hostname,
                            container.config().root.source_path
                        );
                    }
                }
                if *hold {
                    let _ = tokio::signal::ctrl_c().await;
                }
            }
            container.close();
        }
        ContainerCommand::Exec { config, path, args } => {
            let builder = build_container_from_args(session, config).await?;
            let container = builder.create(session.clone()).await?;
            let res = container
                .exec_with_options(path, args, &[], config.cwd.as_deref(), Vec::new())
                .await?;
            std::io::stdout().write_all(&res.output.stdout)?;
            std::io::stderr().write_all(&res.output.stderr)?;
            container.close();
            if res.exit_code != 0 {
                return Err(OpsCliError::RemoteExited {
                    code: res.exit_code,
                });
            }
        }
        ContainerCommand::Spawn { config, path, args } => {
            let builder = build_container_from_args(session, config).await?;
            let container = builder.create(session.clone()).await?;
            let child = container
                .spawn_with_options(path, args, &[], config.cwd.as_deref(), Vec::new())
                .await?;
            let status = stream_child_to_stdio(child).await;
            container.close();
            status?;
        }
        ContainerCommand::Rm { id } => {
            let snap = session.kernel_snapshot().await?;
            let Some(ctr) = snap.containers.iter().find(|c| c.id == *id) else {
                return Err(OpsCliError::ContainerNotFound { id: *id });
            };
            let live = session.ps().await?;
            let mut killed = 0usize;
            for inst in live {
                if inst.id == *id || (!ctr.hostname.is_empty() && inst.name.contains(&ctr.hostname))
                {
                    let _ = session.kill(inst.id).await;
                    killed += 1;
                }
            }
            println!("removed container {id} (stopped {killed} instance(s))");
        }
    }
    Ok(())
}

async fn build_container_from_args(
    session: &Session,
    args: &ContainerTargetArgs,
) -> Result<ContainerBuilder, OpsCliError> {
    let mut builder = if let Some(image_ref) = &args.image {
        let oci = match &args.store_root {
            Some(root) => session.oci_with_store_root(root)?,
            None => session.oci(),
        };
        let pulled = oci.inspect(image_ref).await?;
        ContainerBuilder::from_image(&pulled).map_err(OpsError::from)?
    } else if let Some(root) = &args.root {
        ContainerBuilder::ephemeral(root)
    } else {
        return Err(OpsCliError::ContainerNeedsRoot);
    };

    if let Some(hostname) = &args.hostname {
        builder = builder.hostname(hostname);
    }
    if let Some(domainname) = &args.domainname {
        builder = builder.domainname(domainname);
    }
    if let Some(cwd) = &args.cwd {
        builder = builder.working_dir(cwd);
    }
    for (k, v) in parse_env_pairs(&args.env)? {
        builder = builder.env(k, v);
    }
    for spec in &args.mounts {
        builder = builder.mount(parse_container_mount_spec(spec)?);
    }
    let mut non_fs = helios_ops::NonFsGrants::new();
    for spec in &args.grants {
        let parsed = helios_ops::session::parse_capability_grant(spec)?;
        match parsed {
            CapabilityGrant::Directory(_) => {
                return Err(OpsError::InvalidGrant {
                    spec: spec.clone(),
                    reason: "directory grants are not allowed on containers; use `--mount`"
                        .to_owned(),
                }
                .into());
            }
            CapabilityGrant::Network(g) => {
                non_fs = non_fs.grant(helios_ops::NonFsGrant::Network(g))
            }
            CapabilityGrant::Clock(g) => non_fs = non_fs.grant(helios_ops::NonFsGrant::Clock(g)),
            CapabilityGrant::Terminal(g) => {
                non_fs = non_fs.grant(helios_ops::NonFsGrant::Terminal(g))
            }
            CapabilityGrant::Process(g) => {
                non_fs = non_fs.grant(helios_ops::NonFsGrant::Process(g))
            }
            CapabilityGrant::Link(g) => non_fs = non_fs.grant(helios_ops::NonFsGrant::Link(g)),
            CapabilityGrant::Mount(g) => non_fs = non_fs.grant(helios_ops::NonFsGrant::Mount(g)),
            CapabilityGrant::Device(g) => non_fs = non_fs.grant(helios_ops::NonFsGrant::Device(g)),
            CapabilityGrant::Diagnostics(g) => {
                non_fs = non_fs.grant(helios_ops::NonFsGrant::Diagnostics(g))
            }
            CapabilityGrant::InstanceControl(s) => {
                non_fs = non_fs.grant(helios_ops::NonFsGrant::InstanceControl(s))
            }
            CapabilityGrant::Settings(g) => {
                non_fs = non_fs.grant(helios_ops::NonFsGrant::Settings(g))
            }
            CapabilityGrant::Machine(g) => {
                non_fs = non_fs.grant(helios_ops::NonFsGrant::Machine(g))
            }
            CapabilityGrant::Ipc(_) => {
                return Err(OpsError::InvalidGrant {
                    spec: spec.clone(),
                    reason: "IPC endpoint grants cannot be parsed from CLI strings".to_owned(),
                }
                .into());
            }
        }
    }
    builder = builder.grants(non_fs);
    Ok(builder)
}

fn parse_container_mount_spec(raw: &str) -> Result<ContainerMount, OpsCliError> {
    let parts: Vec<&str> = raw.split(':').collect();
    if parts.len() < 2 || parts.len() > 4 {
        return Err(OpsCliError::InvalidMountSpec {
            raw: raw.to_owned(),
            reason: "expected `SRC:DST[:ro|rx|rw|rwx][:shared|private|overlay]`".to_owned(),
        });
    }
    let source_path = helios_ops::session::normalize_absolute_path(parts[0])?;
    let target_path = helios_ops::session::normalize_absolute_path(parts[1])?;
    let rights = match parts.get(2).copied().unwrap_or("ro") {
        "ro" | "r" => vec![FilesystemRight::Read],
        "rx" => vec![FilesystemRight::Read, FilesystemRight::Execute],
        "rw" => vec![
            FilesystemRight::Read,
            FilesystemRight::Write,
            FilesystemRight::MutateDirectory,
        ],
        "rwx" => vec![
            FilesystemRight::Read,
            FilesystemRight::Write,
            FilesystemRight::MutateDirectory,
            FilesystemRight::Execute,
        ],
        other => {
            return Err(OpsCliError::InvalidMountSpec {
                raw: raw.to_owned(),
                reason: format!("unknown mode `{other}`; expected ro|rx|rw|rwx"),
            });
        }
    };
    let sharing = match parts.get(3).copied().unwrap_or("shared") {
        "shared" => ContainerMountSharing::Shared,
        "private" => ContainerMountSharing::Private,
        "overlay" | "ephemeral-overlay" => ContainerMountSharing::EphemeralOverlay,
        other => {
            return Err(OpsCliError::InvalidMountSpec {
                raw: raw.to_owned(),
                reason: format!("unknown sharing `{other}`; expected shared|private|overlay"),
            });
        }
    };
    Ok(ContainerMount {
        source_path,
        target_path,
        rights,
        sharing,
    })
}

fn parse_env_pairs(raw: &[String]) -> Result<Vec<(String, String)>, OpsCliError> {
    let mut env = Vec::with_capacity(raw.len());
    for pair in raw {
        let Some((k, v)) = pair.split_once('=') else {
            return Err(OpsCliError::InvalidEnvVar { raw: pair.clone() });
        };
        env.push((k.to_owned(), v.to_owned()));
    }
    Ok(env)
}

fn parse_cli_grants(
    raw: &[String],
) -> Result<
    Vec<CapabilityGrant<helios_wit_rpc::inspector::helios::system::ipc::Endpoint>>,
    OpsCliError,
> {
    let mut grants = Vec::with_capacity(raw.len());
    for spec in raw {
        grants.push(helios_ops::session::parse_capability_grant(spec)?);
    }
    Ok(grants)
}

async fn stream_child_to_stdio(child: helios_ops::Child) -> Result<(), OpsCliError> {
    let stdout_rx = child.stdout.clone();
    let stderr_rx = child.stderr.clone();
    let out_task = tokio::spawn(async move {
        while let Ok(chunk) = stdout_rx.recv().await {
            if let Ok(bytes) = chunk {
                let mut stdout = std::io::stdout().lock();
                let _ = stdout.write_all(&bytes);
                let _ = stdout.flush();
            }
        }
    });
    let err_task = tokio::spawn(async move {
        while let Ok(chunk) = stderr_rx.recv().await {
            if let Ok(bytes) = chunk {
                let mut stderr = std::io::stderr().lock();
                let _ = stderr.write_all(&bytes);
                let _ = stderr.flush();
            }
        }
    });

    let result = child.wait().await?;
    let _ = tokio::join!(out_task, err_task);
    if result.exit_code != 0 {
        return Err(OpsCliError::RemoteExited {
            code: result.exit_code,
        });
    }
    Ok(())
}

/// Run `helios bundle`.
pub(crate) async fn run_bundle(session: &Session, cmd: &BundleCommand) -> Result<(), OpsCliError> {
    let bundle = DiagnosticBundle::collect(session).await?;
    let written = bundle
        .write_tar_zst(&cmd.output)
        .await
        .map_err(OpsError::from)?;
    println!(
        "wrote diagnostic bundle ({} entries) to {}",
        bundle.entries.len() + 1,
        written.display()
    );
    Ok(())
}

/// Run `helios bridge` (Prometheus scrape HTTP endpoint and/or OTLP/HTTP JSON export via `zenwave`).
pub(crate) async fn run_bridge(session: &Session, cmd: &BridgeCommand) -> Result<(), OpsCliError> {
    if cmd.prometheus_listen.is_none() && cmd.otlp_endpoint.is_none() {
        return Err(OpsCliError::BridgeNeedsSink);
    }

    let prom_task = if let Some(addr) = &cmd.prometheus_listen {
        let listener =
            TcpListener::bind(addr)
                .await
                .map_err(|source| OpsCliError::BindPrometheus {
                    addr: addr.clone(),
                    source,
                })?;
        println!("Prometheus metrics endpoint listening on http://{addr}/metrics");
        let prom_session = session.clone();
        Some(tokio::spawn(async move {
            loop {
                let Ok((mut stream, _peer)) = listener.accept().await else {
                    break;
                };
                let s = prom_session.clone();
                tokio::spawn(async move {
                    let mut req_buf = [0_u8; 2048];
                    let n = stream.read(&mut req_buf).await.unwrap_or(0);
                    let request_line = std::str::from_utf8(&req_buf[..n])
                        .ok()
                        .and_then(|s| s.lines().next())
                        .unwrap_or("");
                    let (method, raw_path) = parse_http_request_line(request_line);
                    let (status_line, content_type, body) = match (method, raw_path) {
                        ("GET", "/metrics" | "/") => match s.inspect(&["/kernel/"], 0).await {
                            Ok(snap) => (
                                "HTTP/1.1 200 OK",
                                "text/plain; version=0.0.4; charset=utf-8",
                                render_prometheus(&snap.entries),
                            ),
                            Err(err) => (
                                "HTTP/1.1 503 Service Unavailable",
                                "text/plain; charset=utf-8",
                                format!("inspect query failed: {err}\n"),
                            ),
                        },
                        ("GET", _) => (
                            "HTTP/1.1 404 Not Found",
                            "text/plain; charset=utf-8",
                            "not found; try /metrics\n".to_owned(),
                        ),
                        _ => (
                            "HTTP/1.1 405 Method Not Allowed",
                            "text/plain; charset=utf-8",
                            "method not allowed\n".to_owned(),
                        ),
                    };
                    let header = format!(
                        "{status_line}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = stream.write_all(header.as_bytes()).await;
                    let _ = stream.write_all(body.as_bytes()).await;
                    let _ = stream.shutdown().await;
                });
            }
        }))
    } else {
        None
    };

    let otlp_task = if let Some(endpoint) = &cmd.otlp_endpoint {
        println!(
            "OTLP/HTTP exporter pushing every {}s to {endpoint} via zenwave",
            cmd.interval_secs
        );
        let otlp_session = session.clone();
        let url = endpoint.clone();
        let interval = Duration::from_secs(cmd.interval_secs.max(1));
        Some(tokio::spawn(async move {
            loop {
                if let Ok(snap) = otlp_session.inspect(&["/kernel/"], 0).await {
                    let payload = encode_otlp_payload(&otlp_session.target().name, &snap);
                    if let Err(err) =
                        http::post_json(&url, &payload, &[], Some(Duration::from_secs(10))).await
                    {
                        tracing::warn!("OTLP export to `{url}` failed: {err}");
                    }
                }
                tokio::time::sleep(interval).await;
            }
        }))
    } else {
        None
    };

    let _ = tokio::signal::ctrl_c().await;
    if let Some(h) = prom_task {
        h.abort();
    }
    if let Some(h) = otlp_task {
        h.abort();
    }
    Ok(())
}

fn parse_http_request_line(line: &str) -> (&str, &str) {
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let raw_target = parts.next().unwrap_or("");
    let path = raw_target.split('?').next().unwrap_or(raw_target);
    (method, path)
}

fn sanitize_prometheus_metric_name(path: &str) -> Option<String> {
    let trimmed = path.trim_start_matches('/');
    if trimmed.is_empty() {
        return None;
    }
    let mut name = String::with_capacity("helios_".len() + trimmed.len());
    name.push_str("helios_");
    for ch in trimmed.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' || ch == ':' {
            name.push(ch);
        } else {
            name.push('_');
        }
    }
    Some(name)
}

fn write_prometheus_escaped_label(out: &mut String, value: &str) {
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            other => out.push(other),
        }
    }
}

fn render_prometheus(entries: &[proto_inspect::Entry]) -> String {
    let mut out = String::new();
    for entry in entries {
        let Some(metric_name) = sanitize_prometheus_metric_name(&entry.path) else {
            continue;
        };
        let mut rendered_value = String::new();
        match entry.value {
            proto_inspect::Value::Unsigned64(v) => {
                let _ = write!(&mut rendered_value, "{v}");
            }
            proto_inspect::Value::Signed64(v) => {
                let _ = write!(&mut rendered_value, "{v}");
            }
            proto_inspect::Value::Float64(v) => {
                if v.is_nan() {
                    rendered_value.push_str("NaN");
                } else if v.is_infinite() {
                    rendered_value.push_str(if v.is_sign_positive() { "+Inf" } else { "-Inf" });
                } else {
                    let _ = write!(&mut rendered_value, "{v}");
                }
            }
            proto_inspect::Value::Boolean(b) => {
                rendered_value.push(if b { '1' } else { '0' });
            }
            _ => continue,
        }
        let _ = write!(&mut out, "{metric_name}{{path=\"");
        write_prometheus_escaped_label(&mut out, &entry.path);
        let _ = writeln!(&mut out, "\"}} {rendered_value}");
    }
    out
}

fn encode_otlp_payload(
    target_name: &str,
    snapshot: &proto_inspect::SnapshotResult,
) -> serde_json::Value {
    let metrics: Vec<serde_json::Value> = snapshot
        .entries
        .iter()
        .filter_map(|entry| {
            let dp = match entry.value {
                proto_inspect::Value::Unsigned64(v) => serde_json::json!({
                    "timeUnixNano": snapshot.timestamp.to_string(),
                    "asInt": v.to_string(),
                }),
                proto_inspect::Value::Signed64(v) => serde_json::json!({
                    "timeUnixNano": snapshot.timestamp.to_string(),
                    "asInt": v.to_string(),
                }),
                proto_inspect::Value::Float64(v) => serde_json::json!({
                    "timeUnixNano": snapshot.timestamp.to_string(),
                    "asDouble": v,
                }),
                _ => return None,
            };
            Some(serde_json::json!({
                "name": entry.path,
                "gauge": { "dataPoints": [dp] }
            }))
        })
        .collect();
    serde_json::json!({
        "resourceMetrics": [{
            "resource": {
                "attributes": [{
                    "key": "service.name",
                    "value": { "stringValue": target_name }
                }]
            },
            "scopeMetrics": [{
                "scope": { "name": "helios-ops" },
                "metrics": metrics
            }]
        }]
    })
}

fn render_inspect_value(value: &proto_inspect::Value) -> String {
    match value {
        proto_inspect::Value::Boolean(v) => v.to_string(),
        proto_inspect::Value::Signed64(v) => v.to_string(),
        proto_inspect::Value::Unsigned64(v) => v.to_string(),
        proto_inspect::Value::Float64(v) => v.to_string(),
        proto_inspect::Value::Text(v) => v.clone(),
        proto_inspect::Value::Blob(v) => format!("{} bytes", v.len()),
    }
}

fn inspect_value_json(value: &proto_inspect::Value) -> serde_json::Value {
    match value {
        proto_inspect::Value::Boolean(v) => serde_json::Value::Bool(*v),
        proto_inspect::Value::Signed64(v) => serde_json::json!(v),
        proto_inspect::Value::Unsigned64(v) => serde_json::json!(v),
        proto_inspect::Value::Float64(v) => serde_json::json!(v),
        proto_inspect::Value::Text(v) => serde_json::Value::String(v.clone()),
        proto_inspect::Value::Blob(v) => serde_json::json!(v),
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use helios_inspector_protocol::auth::{
        AUTH_PROTOCOL_VERSION, CapabilityCert as ProtoCert, CapabilityCertPayload, SessionGrants,
        TransportMask,
    };

    use super::*;

    #[test]
    fn parse_issued_credentials_handles_protocol_and_legacy_cert_formats() {
        let ca_key = SigningKey::from_bytes(&[0x12_u8; 32]);
        let client_pub = ClientIdentity::from_static_seed([0x34_u8; 32]).public_key();
        let proto_cert = ProtoCert::issue(
            &ca_key,
            CapabilityCertPayload {
                version: AUTH_PROTOCOL_VERSION,
                principal: "alice".to_owned(),
                subject_public_key: client_pub,
                node_public_key: None,
                not_before_unix: 0,
                expires_at_unix: u64::MAX,
                grants: SessionGrants::full_worker_ceiling(),
                allowed_transports: TransportMask::ALL,
            },
        )
        .expect("issue");
        let proto_json = serde_json::to_vec(&proto_cert).expect("serialize");
        let parsed = parse_issued_credentials(&proto_json, "op").expect("parse proto cert");
        assert!(parsed.cert.is_none());
        let decoded_bytes = decode_hex_for_test(
            parsed
                .capability_cert_postcard_hex
                .as_deref()
                .expect("postcard hex present"),
        );
        assert_eq!(
            ProtoCert::decode_postcard(&decoded_bytes).expect("decode postcard"),
            proto_cert
        );

        let legacy = CapabilityCert {
            principal: "bob".to_owned(),
            issuer: "ca".to_owned(),
            public_key_hex: "00".repeat(32),
            scope: "/".to_owned(),
            rights: vec![GrantRight::Inspect],
            expires_at_unix: 9999,
            signature_hex: "11".repeat(64),
        };
        let legacy_json = serde_json::to_vec(&legacy).expect("serialize legacy");
        let parsed_legacy = parse_issued_credentials(&legacy_json, "op").expect("parse legacy");
        assert_eq!(parsed_legacy.cert, Some(legacy));
    }

    #[test]
    fn render_prometheus_sanitizes_metric_names_escapes_labels_and_formats_floats() {
        let entries = vec![
            proto_inspect::Entry {
                path: "/kernel/processors/online".to_owned(),
                value: proto_inspect::Value::Unsigned64(4),
            },
            proto_inspect::Entry {
                path: "/core/http-client/bad\"path\\line\n1".to_owned(),
                value: proto_inspect::Value::Float64(f64::NAN),
            },
            proto_inspect::Entry {
                path: "/core/inf".to_owned(),
                value: proto_inspect::Value::Float64(f64::INFINITY),
            },
            proto_inspect::Entry {
                path: "/core/text".to_owned(),
                value: proto_inspect::Value::Text("ignored".to_owned()),
            },
        ];
        let rendered = render_prometheus(&entries);
        assert!(
            rendered.contains(
                "helios_kernel_processors_online{path=\"/kernel/processors/online\"} 4\n"
            )
        );
        assert!(rendered.contains(
            "helios_core_http_client_bad_path_line_1{path=\"/core/http-client/bad\\\"path\\\\line\\n1\"} NaN\n"
        ));
        assert!(rendered.contains("helios_core_inf{path=\"/core/inf\"} +Inf\n"));
        assert!(!rendered.contains("ignored"));
    }

    #[test]
    fn parse_http_request_line_strips_query_and_extracts_method_and_path() {
        assert_eq!(
            parse_http_request_line("GET /metrics?format=prom HTTP/1.1"),
            ("GET", "/metrics")
        );
        assert_eq!(parse_http_request_line("POST / HTTP/1.1"), ("POST", "/"));
    }

    #[test]
    fn run_account_command_in_covers_create_ls_inspect_verify_and_rm() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let store = AccountStore::new(dir.path().join("accounts"));
        let flags = GlobalOpsFlags {
            scope: Some("/core/http".to_owned()),
            only: vec!["inspect".to_owned(), "trace".to_owned()],
            output: CliOutputFormat::Json,
            ..GlobalOpsFlags::default()
        };

        run_account_command_in(
            &store,
            &AccountCommand::Create {
                username: "ci_operator".to_owned(),
                touch_id: false,
                fido2: false,
                p256: true,
                ed25519: false,
                require_uv: false,
                application: DEFAULT_FIDO2_APPLICATION.to_owned(),
            },
            &flags,
        )
        .expect("create account");
        run_account_command_in(&store, &AccountCommand::Ls, &flags).expect("ls accounts");
        run_account_command_in(
            &store,
            &AccountCommand::Inspect {
                username: "ci_operator".to_owned(),
            },
            &flags,
        )
        .expect("inspect account");
        run_account_command_in(
            &store,
            &AccountCommand::Verify {
                username: "ci_operator".to_owned(),
            },
            &flags,
        )
        .expect("verify account");
        run_account_command_in(
            &store,
            &AccountCommand::Rm {
                username: "ci_operator".to_owned(),
            },
            &flags,
        )
        .expect("rm account");
        assert!(store.list().expect("list after rm").is_empty());
    }

    fn decode_hex_for_test(raw: &str) -> Vec<u8> {
        raw.as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| {
                u8::from_str_radix(std::str::from_utf8(pair).expect("utf8"), 16).expect("hex")
            })
            .collect()
    }
}
