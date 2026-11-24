//! Unified `helios` CLI operations subcommands backed by `helios-ops` and
//! `helios-inspector-shell` (`nu`, `python`, `login`, `whoami`, `target`,
//! `inspect`, `ps`, `kill`, `trace`, `profile`, `spawn`, `bundle`, `bridge`).

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write as _;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use clap::{Args as ClapArgs, Subcommand, ValueEnum};
use helios_inspector_protocol::system::{
    inspect as proto_inspect,
    profiling::{Filter as ProfileFilter, MetricFilter},
    tracing as proto_tracing,
};
use helios_inspector_shell::{HostEnv, OutputFormat as ShellOutputFormat, ReplError};
use helios_ops::{
    Attenuation, CapabilityCert, DEFAULT_FLEET_CONCURRENCY, DiagnosticBundle, Fleet, GrantRight,
    IdentityProfile, OpsError, Session, SessionOptions, SpawnRequest, Target, TargetError,
    TargetStore, http,
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
    /// Capture kernel instruction samples for a duration (ms) and print summary.
    Instructions {
        /// Sampling duration in milliseconds (0 reads existing samples without toggling).
        #[arg(long, default_value_t = 500)]
        duration_ms: u64,
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

/// Spawn or execute a remote Wasm/Linux binary (`spawn`).
#[derive(Debug, Clone, ClapArgs)]
pub(crate) struct SpawnCommand {
    /// Remote executable path (e.g. `/bin/ping`).
    pub path: String,

    /// Arguments passed to the remote program.
    #[arg(trailing_var_arg = true)]
    pub args: Vec<String>,

    /// Explicit environment entries `KEY=VAL` (repeatable).
    #[arg(short = 'e', long = "env", value_name = "K=V")]
    pub env: Vec<String>,

    /// Explicit capability grant specs (repeatable).
    #[arg(long = "grant", value_name = "SPEC")]
    pub grants: Vec<String>,
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
    Repl(#[from] ReplError),
    #[error("{0}")]
    Terminal(#[from] crate::tui::TerminalError),
    #[error("unknown capability `{raw}` in `--only`")]
    UnknownCapability { raw: String },
    #[error("invalid environment variable `{raw}`; expected `KEY=VALUE`")]
    InvalidEnvVar { raw: String },
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
    let mut only = BTreeSet::new();
    for raw in &flags.only {
        if raw.trim().is_empty() {
            continue;
        }
        let right = GrantRight::parse(raw)
            .ok_or_else(|| OpsCliError::UnknownCapability { raw: raw.clone() })?;
        only.insert(right);
    }
    let identity = match &flags.identity {
        Some(name_or_path) => Some(IdentityProfile::load(name_or_path).map_err(OpsError::from)?),
        None => IdentityProfile::load("default").ok(),
    };
    let security = match identity.as_ref().and_then(|id| id.cert.clone()) {
        Some(cert) => helios_ops::SecurityMode::CapabilityTls { cert: Some(cert) },
        None => helios_ops::SecurityMode::Plain,
    };
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

/// Resolve a connected [`Session`] (and optional [`Fleet`]) from global CLI flags or `--device`.
pub(crate) async fn connect_from_flags(
    flags: &GlobalOpsFlags,
    legacy_device: Option<&str>,
    legacy_baud: u32,
) -> Result<(Session, Option<Fleet>), OpsCliError> {
    let options = build_session_options(flags)?;
    if !flags.labels.is_empty() {
        let store = TargetStore::load_default()?;
        let targets = store.select_by_labels(&flags.labels)?;
        let primary = targets[0].clone();
        let fleet = Fleet::new(targets, flags.concurrency, options.clone());
        let session = Session::connect(&primary, options).await?;
        return Ok((session, Some(fleet)));
    }
    if let Some(dev) = legacy_device {
        let uri = format!("serial://{dev}?baud={legacy_baud}");
        let target = Target::from_uri(uri)?;
        let session = Session::connect(&target, options).await?;
        return Ok((session, None));
    }
    let store = TargetStore::load_default()?;
    let target = store.resolve(flags.target.as_deref())?;
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

    let cert = if let Some(authority) = &cmd.authority {
        let endpoint = format!("{}/v1/issue", authority.trim_end_matches('/'));
        let req_body = serde_json::json!({
            "principal": principal,
            "profile": cmd.name,
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
        let cert: CapabilityCert = serde_json::from_slice(&bytes)?;
        Some(cert)
    } else {
        None
    };

    let profile = IdentityProfile {
        name: cmd.name.clone(),
        principal: principal.clone(),
        authority_url: cmd.authority.clone(),
        cert,
    };
    let saved_path = profile.save().map_err(OpsError::from)?;
    println!(
        "saved identity `{}` (principal `{}`) to {}",
        profile.name,
        principal,
        saved_path.display()
    );
    Ok(())
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
        CliOutputFormat::Json | CliOutputFormat::Jsonl => {
            let doc = serde_json::json!({
                "principal": principal,
                "target": target,
                "scope": options.attenuation.effective_scope(),
                "only": caps,
            });
            println!("{}", serde_json::to_string_pretty(&doc)?);
        }
        CliOutputFormat::Table | CliOutputFormat::Nuon => {
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
                CliOutputFormat::Json => {
                    println!("{}", serde_json::to_string_pretty(store.list())?);
                }
                CliOutputFormat::Jsonl => {
                    for t in store.list() {
                        println!("{}", serde_json::to_string(t)?);
                    }
                }
                CliOutputFormat::Table | CliOutputFormat::Nuon => {
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
        CliOutputFormat::Json => {
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
        CliOutputFormat::Table | CliOutputFormat::Nuon => {
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
        CliOutputFormat::Json => {
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
        CliOutputFormat::Table | CliOutputFormat::Nuon => {
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
                CliOutputFormat::Json | CliOutputFormat::Jsonl => {
                    let row = serde_json::json!({
                        "timestamp": ev.timestamp,
                        "level": format!("{:?}", ev.level),
                        "target": ev.target,
                        "fields": ev.fields.iter().map(|f| (f.key.clone(), format!("{:?}", f.value))).collect::<BTreeMap<_, _>>(),
                    });
                    println!("{}", serde_json::to_string(&row)?);
                }
                CliOutputFormat::Table | CliOutputFormat::Nuon => {
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
        ProfileOpsCommand::Instructions { duration_ms } => {
            if *duration_ms > 0 {
                session.profile_set_instruction_sampling(true).await?;
                tokio::time::sleep(Duration::from_millis(*duration_ms)).await;
            }
            let profile = session.profile_instruction_samples().await?;
            if *duration_ms > 0 {
                let _ = session.profile_set_instruction_sampling(false).await;
            }
            let doc = serde_json::json!({
                "period_nanos": profile.period_nanos,
                "kernel_image_base": format!("{:#x}", profile.kernel_image_base),
                "sample_count": profile.samples.len(),
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
                CliOutputFormat::Json => {
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
                CliOutputFormat::Jsonl | CliOutputFormat::Table | CliOutputFormat::Nuon => {
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
                CliOutputFormat::Json => {
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
                CliOutputFormat::Jsonl | CliOutputFormat::Table | CliOutputFormat::Nuon => {
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
    let mut env = Vec::with_capacity(cmd.env.len());
    for pair in &cmd.env {
        let Some((k, v)) = pair.split_once('=') else {
            return Err(OpsCliError::InvalidEnvVar { raw: pair.clone() });
        };
        env.push((k.to_owned(), v.to_owned()));
    }
    let mut capability_grants = Vec::with_capacity(cmd.grants.len());
    for spec in &cmd.grants {
        capability_grants.push(helios_ops::session::parse_capability_grant(spec)?);
    }
    let child = session
        .spawn(SpawnRequest {
            path: cmd.path.clone(),
            args: cmd.args.clone(),
            env,
            stdin: Vec::new(),
            capability_grants,
        })
        .await?;

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
                    let mut req_buf = [0_u8; 1024];
                    let _ = stream.read(&mut req_buf).await;
                    let body = match s.inspect(&["/kernel/"], 0).await {
                        Ok(snap) => render_prometheus(&snap.entries),
                        Err(err) => format!("# error fetching inspect metrics: {err}\n"),
                    };
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
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

fn render_prometheus(entries: &[proto_inspect::Entry]) -> String {
    let mut out = String::new();
    for entry in entries {
        let numeric = match entry.value {
            proto_inspect::Value::Unsigned64(v) => Some(v.to_string()),
            proto_inspect::Value::Signed64(v) => Some(v.to_string()),
            proto_inspect::Value::Float64(v) => Some(v.to_string()),
            proto_inspect::Value::Boolean(b) => Some(if b { "1" } else { "0" }.to_owned()),
            _ => None,
        };
        if let Some(num) = numeric {
            let metric_name: String = entry
                .path
                .trim_start_matches('/')
                .chars()
                .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
                .collect();
            out.push_str(&format!("helios_{metric_name} {num}\n"));
        }
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
