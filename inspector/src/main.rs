mod frame_reader;
mod linux_suite;
mod ops_cli;
mod programs;
mod ready;
mod remote;
mod repl;
mod runtime;
mod serial;
mod stats_tui;
mod system;
mod tui;
mod vm;
mod vsock;
mod workload_bench;

use clap::{Args as ClapArgs, Parser, Subcommand};
use std::io::Write as _;
use std::path::PathBuf;

use crate::ops_cli::{
    BridgeCommand, BundleCommand, GlobalOpsFlags, InspectCommand, KillCommand, LoginCommand,
    NuCommand, OpsCliError, ProfileOpsCommand, PsCommand, PythonCommand, SpawnCommand,
    TargetCommand, TraceCommand,
};
use crate::ready::BootError;
use crate::repl::ShellScriptError;
use crate::serial::SerialError;
use crate::system::SystemError;
use crate::tui::TerminalError;

/// Why a `helios` run ended other than by doing what it was asked.
#[derive(Debug, thiserror::Error)]
enum InspectorError {
    #[error(
        "a target is required (`-t/--target`, `--device`, a default in `targets.toml`, or `helios vm`)"
    )]
    MissingTarget,
    #[error("{0}")]
    Vm(#[from] vm::VmError),
    #[error("{0}")]
    Connect(#[from] ConnectError),
    #[error("{0}")]
    Session(#[from] SessionError),
    #[error("{0}")]
    Ops(#[from] OpsCliError),
    #[error("failed to initialize async runtime: {source}")]
    Runtime {
        #[source]
        source: std::io::Error,
    },
}

/// Why the inspector could not reach the guest debugger.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ConnectError {
    #[error("failed to start the RPC connection driver: {source}")]
    Driver {
        #[from]
        source: std::io::Error,
    },
    #[error("{0}")]
    Transport(#[from] SerialError),
    #[error("{0}")]
    Boot(#[from] BootError),
}

/// Why the session that ran over an open transport failed.
#[derive(Debug, thiserror::Error)]
pub(crate) enum SessionError {
    #[error("failed to prime the guest tracing capture: {source}")]
    PrimeCapture {
        #[source]
        source: SystemError,
    },
    #[error("failed to drain the guest tracing capture: {source}")]
    DrainCapture {
        #[source]
        source: SystemError,
    },
    #[error("failed to create the guest trace log at {path}: {source}")]
    CreateTraceLog {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to write the guest trace log at {path}: {source}")]
    WriteTraceLog {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("{0}")]
    Shell(#[from] ShellScriptError),
    #[error("failed to write the remote shell output: {source}")]
    WriteShellOutput {
        #[source]
        source: std::io::Error,
    },
    #[error("remote shell exited with code {exit_code}")]
    RemoteShellExited { exit_code: u32 },
    #[error("{0}")]
    Tracing(#[from] SystemError),
    #[error("{0}")]
    Stats(#[from] TerminalError),
    #[error("{0}")]
    Ops(#[from] OpsCliError),
    #[error("failed to initialize async runtime: {source}")]
    Runtime {
        #[source]
        source: std::io::Error,
    },
    #[error("{0}")]
    Interrupt(#[from] InterruptError),
}

/// The inspector could not arm the Ctrl+C handler a cancellable command
/// runs under.
#[derive(Debug, thiserror::Error)]
#[error("failed to listen for Ctrl+C during inspector command execution: {source}")]
pub(crate) struct InterruptError {
    #[source]
    source: std::io::Error,
}

#[derive(Debug, Parser)]
#[command(
    name = "helios",
    version,
    about = "Inspect, operate, and orchestrate Helios nodes and local VMs",
    long_about = "Connects to Helios nodes over helios://, vsock://, or serial:// \
                  (or boots a local VM with `helios vm`) and provides the async \
                  Nushell REPL (`helios nu`), Python entrypoint (`helios python`), \
                  structured inspection, fleet fan-out, diagnostic bundles, and \
                  telemetry bridges."
)]
struct Args {
    #[command(flatten)]
    ops: GlobalOpsFlags,

    #[command(flatten)]
    serial: SerialOptions,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, ClapArgs)]
struct SerialOptions {
    /// Legacy serial device or Unix socket path used as the inspector transport.
    #[arg(long)]
    device: Option<String>,

    /// Baud rate for the serial inspector transport.
    #[arg(long, default_value_t = 115_200)]
    baud: u32,

    #[arg(long, hide = true)]
    boot_sync: bool,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Start the interactive host Nushell REPL (with live <Tab> completion), run `-c`, or execute `<script.nu>`.
    #[command(visible_alias = "repl")]
    Nu(NuCommand),
    /// Run the symmetric Python operations REPL or script via `python3 -m helios._cli_entry`.
    Python(PythonCommand),
    /// Authenticate with an Authority CA or store a local operator identity.
    Login(LoginCommand),
    /// Display the active principal, resolved target, scope, and capability attenuation.
    Whoami,
    /// Manage named targets in `targets.toml`.
    #[command(subcommand)]
    Target(TargetCommand),
    /// Query `/kernel/*` and component inspect state (`--watch`, `--diff`).
    Inspect(InspectCommand),
    /// Open the live system monitor TUI.
    Stats,
    /// List running instances / components (`--tree`).
    Ps(PsCommand),
    /// Stop a live instance by ID or name.
    Kill(KillCommand),
    /// Fetch or stream (`--follow`) guest tracing events.
    Trace(TraceCommand),
    /// Inspect or collect profiling data (`instructions`, `folded`, `metrics`, `llvm-raw`).
    #[command(subcommand)]
    Profile(ProfileOpsCommand),
    /// Spawn or execute a remote program with streaming stdio.
    Spawn(SpawnCommand),
    /// Collect a `.tar.zst` diagnostic bundle.
    Bundle(BundleCommand),
    /// Export inspect metrics to Prometheus (`/metrics`) and/or OTLP/HTTP via `zenwave`.
    Bridge(BridgeCommand),
    /// Execute a script inside the remote guest shell (`/bin/dash`).
    Shell(ShellCommand),
    /// Stream tracing events until interrupted (legacy compatibility surface).
    Tracing(TracingCommand),
    /// List the live program instances, and optionally stop one (legacy compatibility surface).
    Instances(InstancesCommand),
    /// Launch a local QEMU VM, wait for the debugger, and connect `helios`.
    ///
    /// Boxed: the VM options dwarf every other subcommand's, and the
    /// parsed command is moved around by value.
    Vm(Box<vm::VmCommand>),
}

#[derive(Debug, Clone, Subcommand)]
pub(crate) enum SessionCommand {
    /// Start the interactive host Nushell REPL (with live <Tab> completion), run `-c`, or execute `<script.nu>`.
    #[command(visible_alias = "repl")]
    Nu(NuCommand),
    /// Launch the symmetric Python entrypoint against this connected target.
    Python(PythonCommand),
    /// Query `/kernel/*` and component inspect state (`--watch`, `--diff`).
    Inspect(InspectCommand),
    /// Open the live system monitor TUI.
    Stats,
    /// List running instances / components (`--tree`).
    Ps(PsCommand),
    /// Stop a live instance by ID or name.
    Kill(KillCommand),
    /// Fetch or stream (`--follow`) guest tracing events.
    Trace(TraceCommand),
    /// Spawn or execute a remote program with streaming stdio.
    Spawn(SpawnCommand),
    /// Collect a `.tar.zst` diagnostic bundle.
    Bundle(BundleCommand),
    /// Export inspect metrics to Prometheus and/or OTLP/HTTP via `zenwave`.
    Bridge(BridgeCommand),
    /// Execute a shell script inside the remote guest shell program (`/bin/dash`).
    Shell(ShellCommand),
    /// Stream tracing events until interrupted.
    Tracing(TracingCommand),
    /// List the live program instances, and optionally stop one.
    Instances(InstancesCommand),
}

#[derive(Debug, Clone, ClapArgs)]
pub(crate) struct ShellCommand {
    /// Inline script passed to `/bin/dash -c`.
    #[arg(short = 'c', long = "command", conflicts_with = "script")]
    command: Option<String>,

    /// Path to a local script file whose contents are executed remotely by the guest shell.
    #[arg(conflicts_with = "command")]
    script: Option<String>,

    /// Guest shell binary to invoke (defaults to `/bin/dash`; pass `/bin/nu` for Nushell).
    #[arg(long = "shell", value_name = "PATH")]
    shell: Option<String>,

    /// Write the guest tracing events the script produced to this file.
    #[arg(long = "trace-log", value_name = "PATH")]
    trace_log: Option<PathBuf>,

    /// Lowest severity to capture into `--trace-log`.
    #[arg(
        long = "trace-log-level",
        value_name = "LEVEL",
        default_value = "trace"
    )]
    trace_log_level: String,

    /// Number of recent guest events each `--trace-log` poll retrieves.
    #[arg(long = "trace-log-limit", value_name = "COUNT", default_value_t = 512)]
    trace_log_limit: u32,
}

/// Which live instances there are, and which of them to stop.
#[derive(Debug, Clone, ClapArgs)]
pub(crate) struct InstancesCommand {
    /// Stop the instance carrying this identifier.
    #[arg(long = "kill", value_name = "ID", conflicts_with = "kill_name")]
    kill: Option<u64>,

    /// Stop the instance registered under this name.
    #[arg(long = "kill-name", value_name = "NAME", conflicts_with = "kill")]
    kill_name: Option<String>,
}

#[derive(Debug, Clone, ClapArgs)]
pub(crate) struct TracingCommand {
    /// Maximum number of recent events kept in the incremental polling window.
    #[arg(long, default_value_t = 64)]
    limit: u32,

    /// Lowest severity to stream (trace, debug, info, warn, or error).
    #[arg(long)]
    min_level: Option<String>,

    /// Only stream events whose target starts with one of these prefixes;
    /// repeat the flag to allow several prefixes.
    #[arg(long)]
    target_prefix: Vec<String>,

    /// Enable a kernel diagnostic target the kernel holds off by name,
    /// for the rest of this boot; repeat to enable several.
    #[arg(long = "enable-target", value_name = "TARGET")]
    enable_target: Vec<String>,
}

fn main() -> Result<(), InspectorError> {
    let args = Args::parse();
    match args.command {
        Some(Command::Vm(command)) => Ok(vm::run(*command, args.ops)?),
        Some(Command::Python(cmd)) => Ok(ops_cli::run_python_command(&args.ops, &cmd, None)?),
        Some(Command::Whoami) => Ok(ops_cli::run_whoami(&args.ops)?),
        Some(Command::Target(cmd)) => Ok(ops_cli::run_target_command(&cmd, args.ops.output)?),
        Some(Command::Login(cmd)) => {
            let rt = tokio::runtime::Runtime::new()
                .map_err(|source| InspectorError::Runtime { source })?;
            Ok(rt.block_on(ops_cli::run_login(&cmd))?)
        }
        Some(Command::Profile(cmd)) => {
            let rt = tokio::runtime::Runtime::new()
                .map_err(|source| InspectorError::Runtime { source })?;
            Ok(rt.block_on(async {
                let (session, _fleet) = ops_cli::connect_from_flags(
                    &args.ops,
                    args.serial.device.as_deref(),
                    args.serial.baud,
                )
                .await?;
                ops_cli::run_profile(&session, &cmd, args.ops.output).await
            })?)
        }
        other => {
            let session_cmd = match other {
                Some(Command::Nu(cmd)) => SessionCommand::Nu(cmd),
                Some(Command::Inspect(cmd)) => SessionCommand::Inspect(cmd),
                Some(Command::Stats) => SessionCommand::Stats,
                Some(Command::Ps(cmd)) => SessionCommand::Ps(cmd),
                Some(Command::Kill(cmd)) => SessionCommand::Kill(cmd),
                Some(Command::Trace(cmd)) => SessionCommand::Trace(cmd),
                Some(Command::Spawn(cmd)) => SessionCommand::Spawn(cmd),
                Some(Command::Bundle(cmd)) => SessionCommand::Bundle(cmd),
                Some(Command::Bridge(cmd)) => SessionCommand::Bridge(cmd),
                Some(Command::Shell(cmd)) => SessionCommand::Shell(cmd),
                Some(Command::Tracing(cmd)) => SessionCommand::Tracing(cmd),
                Some(Command::Instances(cmd)) => SessionCommand::Instances(cmd),
                None => SessionCommand::Nu(NuCommand::default()),
                Some(
                    Command::Vm(_)
                    | Command::Python(_)
                    | Command::Login(_)
                    | Command::Whoami
                    | Command::Target(_)
                    | Command::Profile(_),
                ) => unreachable!("handled above"),
            };

            // Legacy serial `--device` path (supports `--boot-sync` and `stats` TUI directly).
            if let Some(device) = args.serial.device.as_deref() {
                let client = connect_client(device, args.serial.baud, args.serial.boot_sync)?;
                let target_uri = format!("serial://{device}?baud={}", args.serial.baud);
                return Ok(run_connected(
                    client,
                    Some(session_cmd),
                    &args.ops,
                    Some(&target_uri),
                )?);
            }

            // Unified `helios-ops` target resolution (`-t/--target`, `-l/--label`, or default in `targets.toml`).
            if args.ops.target.is_none()
                && args.ops.labels.is_empty()
                && helios_ops::TargetStore::load_default()
                    .ok()
                    .and_then(|s| s.default_target_name().map(ToOwned::to_owned))
                    .is_none()
            {
                return Err(InspectorError::MissingTarget);
            }

            let rt = tokio::runtime::Runtime::new()
                .map_err(|source| InspectorError::Runtime { source })?;
            Ok(rt.block_on(async {
                let (session, fleet) =
                    ops_cli::connect_from_flags(&args.ops, None, args.serial.baud).await?;
                run_ops_session_command(session, fleet, &session_cmd, &args.ops).await
            })?)
        }
    }
}

async fn run_ops_session_command(
    session: helios_ops::Session,
    fleet: Option<helios_ops::Fleet>,
    command: &SessionCommand,
    ops: &GlobalOpsFlags,
) -> Result<(), OpsCliError> {
    match command {
        SessionCommand::Nu(cmd) => {
            ops_cli::run_nu_with_session(session, fleet, cmd, ops.output).await
        }
        SessionCommand::Python(cmd) => {
            let uri = session.target().uri.clone();
            ops_cli::run_python_command(ops, cmd, Some(&uri))
        }
        SessionCommand::Inspect(cmd) => ops_cli::run_inspect(&session, cmd, ops.output).await,
        SessionCommand::Ps(cmd) => ops_cli::run_ps(&session, cmd, ops.output).await,
        SessionCommand::Kill(cmd) => ops_cli::run_kill(&session, cmd).await,
        SessionCommand::Trace(cmd) => ops_cli::run_trace(&session, cmd, ops.output).await,
        SessionCommand::Spawn(cmd) => ops_cli::run_spawn(&session, cmd).await,
        SessionCommand::Bundle(cmd) => ops_cli::run_bundle(&session, cmd).await,
        SessionCommand::Bridge(cmd) => ops_cli::run_bridge(&session, cmd).await,
        SessionCommand::Shell(cmd) => {
            let script = match (&cmd.command, &cmd.script) {
                (Some(c), None) => c.clone(),
                (None, Some(path)) => std::fs::read_to_string(path)?,
                _ => String::new(),
            };
            let shell_path = cmd.shell.as_deref().unwrap_or(programs::REMOTE_SHELL_PATH);
            let res = session.exec(shell_path, &["-c".to_owned(), script]).await?;
            std::io::stdout().write_all(&res.output.stdout)?;
            std::io::stderr().write_all(&res.output.stderr)?;
            if res.exit_code != 0 {
                return Err(OpsCliError::RemoteExited {
                    code: res.exit_code,
                });
            }
            Ok(())
        }
        SessionCommand::Tracing(cmd) => {
            let trace_cmd = TraceCommand {
                limit: cmd.limit,
                min_level: cmd.min_level.clone(),
                target_prefix: cmd.target_prefix.clone(),
                enable_target: cmd.enable_target.clone(),
                follow: true,
            };
            ops_cli::run_trace(&session, &trace_cmd, ops.output).await
        }
        SessionCommand::Instances(cmd) => {
            ops_cli::run_ps(&session, &PsCommand::default(), ops.output).await?;
            if let Some(id) = cmd.kill {
                ops_cli::run_kill(
                    &session,
                    &KillCommand {
                        target: id.to_string(),
                        name: false,
                        force: false,
                    },
                )
                .await?;
            } else if let Some(name) = &cmd.kill_name {
                ops_cli::run_kill(
                    &session,
                    &KillCommand {
                        target: name.clone(),
                        name: true,
                        force: false,
                    },
                )
                .await?;
            }
            Ok(())
        }
        SessionCommand::Stats => {
            for right in [
                helios_ops::GrantRight::Inspect,
                helios_ops::GrantRight::InstanceRead,
            ] {
                if !session.options().attenuation.allows(right) {
                    return Err(helios_ops::OpsError::AttenuationDenied {
                        capability: right.as_str().to_owned(),
                        scope: session.options().attenuation.effective_scope().to_owned(),
                    }
                    .into());
                }
            }
            let active_scope = helios_ops::target::normalize_scope(
                session.options().attenuation.effective_scope(),
            );
            if !helios_ops::target::scope_contains(&active_scope, "/kernel") {
                return Err(helios_ops::OpsError::AttenuationDenied {
                    capability: helios_ops::GrantRight::Inspect.as_str().to_owned(),
                    scope: active_scope,
                }
                .into());
            }
            let client = session.protocol_client();
            let previous_echo = client.set_remote_serial_echo(false);
            let run_result = stats_tui::run(client).await;
            client.set_remote_serial_echo(previous_echo);
            run_result?;
            Ok(())
        }
    }
}

pub(crate) fn connect_client(
    device: &str,
    baud: u32,
    boot_sync: bool,
) -> Result<serial::RpcClient, ConnectError> {
    runtime::block_on(async move {
        let io = serial::open(device, baud).await?;
        if boot_sync {
            Ok(ready::connect_after_boot(io).await?)
        } else {
            let mut client = io.into_client()?;
            ready::wait_until_ready(&mut client).await?;
            Ok(client)
        }
    })
}

pub(crate) fn run_connected(
    client: serial::RpcClient,
    command: Option<SessionCommand>,
    ops: &GlobalOpsFlags,
    target_uri: Option<&str>,
) -> Result<(), SessionError> {
    let command = command.unwrap_or_else(|| SessionCommand::Nu(NuCommand::default()));
    match command {
        SessionCommand::Nu(cmd) => {
            let session = wrap_vm_session(&client, ops, target_uri)?;
            let rt = tokio::runtime::Runtime::new()
                .map_err(|source| SessionError::Runtime { source })?;
            Ok(rt.block_on(ops_cli::run_nu_with_session(
                session, None, &cmd, ops.output,
            ))?)
        }
        SessionCommand::Python(cmd) => {
            drop(client);
            Ok(ops_cli::run_python_command(ops, &cmd, target_uri)?)
        }
        SessionCommand::Inspect(cmd) => {
            let session = wrap_vm_session(&client, ops, target_uri)?;
            let rt = tokio::runtime::Runtime::new()
                .map_err(|source| SessionError::Runtime { source })?;
            Ok(rt.block_on(ops_cli::run_inspect(&session, &cmd, ops.output))?)
        }
        SessionCommand::Ps(cmd) => {
            let session = wrap_vm_session(&client, ops, target_uri)?;
            let rt = tokio::runtime::Runtime::new()
                .map_err(|source| SessionError::Runtime { source })?;
            Ok(rt.block_on(ops_cli::run_ps(&session, &cmd, ops.output))?)
        }
        SessionCommand::Kill(cmd) => {
            let session = wrap_vm_session(&client, ops, target_uri)?;
            let rt = tokio::runtime::Runtime::new()
                .map_err(|source| SessionError::Runtime { source })?;
            Ok(rt.block_on(ops_cli::run_kill(&session, &cmd))?)
        }
        SessionCommand::Trace(cmd) => {
            let session = wrap_vm_session(&client, ops, target_uri)?;
            let rt = tokio::runtime::Runtime::new()
                .map_err(|source| SessionError::Runtime { source })?;
            Ok(rt.block_on(ops_cli::run_trace(&session, &cmd, ops.output))?)
        }
        SessionCommand::Spawn(cmd) => {
            let session = wrap_vm_session(&client, ops, target_uri)?;
            let rt = tokio::runtime::Runtime::new()
                .map_err(|source| SessionError::Runtime { source })?;
            Ok(rt.block_on(ops_cli::run_spawn(&session, &cmd))?)
        }
        SessionCommand::Bundle(cmd) => {
            let session = wrap_vm_session(&client, ops, target_uri)?;
            let rt = tokio::runtime::Runtime::new()
                .map_err(|source| SessionError::Runtime { source })?;
            Ok(rt.block_on(ops_cli::run_bundle(&session, &cmd))?)
        }
        SessionCommand::Bridge(cmd) => {
            let session = wrap_vm_session(&client, ops, target_uri)?;
            let rt = tokio::runtime::Runtime::new()
                .map_err(|source| SessionError::Runtime { source })?;
            Ok(rt.block_on(ops_cli::run_bridge(&session, &cmd))?)
        }
        SessionCommand::Shell(command) => run_interruptible(async move {
            let mut client = client;
            let mut capture = match command.trace_log.as_ref() {
                Some(_) => Some(
                    system::TracingCapture::start(
                        &mut client,
                        system::tracing_config(
                            command.trace_log_limit,
                            Some(command.trace_log_level.as_str()),
                            Vec::new(),
                        )?,
                    )
                    .await
                    .map_err(|source| SessionError::PrimeCapture { source })?,
                ),
                None => None,
            };
            let result = repl::run_shell_command(&mut client, &command).await;
            if let (Some(capture), Some(path)) = (capture.as_mut(), command.trace_log.as_ref()) {
                write_trace_log(&mut client, capture, path).await?;
            }
            let output = result?;
            std::io::stdout()
                .write_all(&output.output.stdout)
                .and_then(|()| std::io::stderr().write_all(&output.output.stderr))
                .map_err(|source| SessionError::WriteShellOutput { source })?;
            if output.exit_code != 0 {
                return Err(SessionError::RemoteShellExited {
                    exit_code: output.exit_code,
                });
            }
            Ok(())
        }),
        SessionCommand::Tracing(command) => {
            Ok(runtime::block_on(system::run_tracing(client, &command))?)
        }
        SessionCommand::Stats => {
            run_interruptible(async move { Ok(stats_tui::run(&client).await?) })
        }
        SessionCommand::Instances(command) => run_interruptible(async move {
            Ok(system::run_instances(&client, command.kill, command.kill_name.as_deref()).await?)
        }),
    }
}

fn wrap_vm_session(
    client: &serial::RpcClient,
    ops: &GlobalOpsFlags,
    target_uri: Option<&str>,
) -> Result<helios_ops::Session, SessionError> {
    let uri = target_uri.unwrap_or("serial://vm");
    let target = helios_ops::Target {
        name: "vm".to_owned(),
        uri: uri.to_owned(),
        labels: std::collections::BTreeMap::new(),
        identity: ops.identity.clone(),
        default_scope: ops.scope.clone(),
    };
    let options = ops_cli::build_session_options(ops)?;
    Ok(helios_ops::Session::from_connection(
        target,
        client.to_ops_connection(),
        options,
    ))
}

/// Writes what the guest traced during the shell command to `path`.
async fn write_trace_log(
    client: &mut serial::RpcClient,
    capture: &mut system::TracingCapture,
    path: &PathBuf,
) -> Result<(), SessionError> {
    let lines = capture
        .drain(client)
        .await
        .map_err(|source| SessionError::DrainCapture { source })?;
    let mut log = std::fs::File::create(path).map_err(|source| SessionError::CreateTraceLog {
        path: path.display().to_string(),
        source,
    })?;
    for line in lines {
        writeln!(log, "{line}").map_err(|source| SessionError::WriteTraceLog {
            path: path.display().to_string(),
            source,
        })?;
    }
    Ok(())
}

fn run_interruptible<E>(command: impl std::future::Future<Output = Result<(), E>>) -> Result<(), E>
where
    E: From<InterruptError>,
{
    match runtime::block_on(runtime::interruptible(command))
        .map_err(|source| InterruptError { source })?
    {
        runtime::CommandRun::Completed(result) => result,
        runtime::CommandRun::Interrupted => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::{Args, Command};
    use crate::ops_cli::CliOutputFormat;
    use clap::Parser;

    #[test]
    fn parses_nu_and_repl_alias_with_inline_and_script() {
        let nu_repl =
            Args::try_parse_from(["helios", "-t", "node1", "nu"]).expect("`helios nu` must parse");
        assert_eq!(nu_repl.ops.target.as_deref(), Some("node1"));
        assert!(matches!(nu_repl.command, Some(Command::Nu(_))));

        let repl_alias = Args::try_parse_from(["helios", "repl", "-c", "ps | length"])
            .expect("`helios repl -c` alias must parse");
        match repl_alias.command {
            Some(Command::Nu(cmd)) => assert_eq!(cmd.command.as_deref(), Some("ps | length")),
            other => panic!("expected Nu command via repl alias, got {other:?}"),
        }

        let script = Args::try_parse_from([
            "helios",
            "-o",
            "json",
            "-l",
            "env=prod",
            "--concurrency",
            "8",
            "--scope",
            "/core/http",
            "--only",
            "inspect,ps",
            "nu",
            "check.nu",
            "arg1",
        ])
        .expect("global ops flags + `nu <script>` must parse");
        assert_eq!(script.ops.output, CliOutputFormat::Json);
        assert_eq!(script.ops.labels, vec!["env=prod"]);
        assert_eq!(script.ops.concurrency, 8);
        assert_eq!(script.ops.scope.as_deref(), Some("/core/http"));
        assert_eq!(script.ops.only, vec!["inspect", "ps"]);
    }

    #[test]
    fn parses_python_and_ops_subcommands() {
        let py = Args::try_parse_from(["helios", "python", "-c", "print(1)"])
            .expect("`helios python -c` must parse");
        assert!(matches!(py.command, Some(Command::Python(_))));

        let inspect = Args::try_parse_from(["helios", "inspect", "/kernel/", "--watch", "--diff"])
            .expect("`helios inspect --watch --diff` must parse");
        assert!(matches!(inspect.command, Some(Command::Inspect(_))));

        let ps = Args::try_parse_from(["helios", "ps", "--tree"]).expect("`helios ps --tree`");
        assert!(matches!(ps.command, Some(Command::Ps(_))));

        let bridge = Args::try_parse_from([
            "helios",
            "bridge",
            "--prometheus-listen",
            "127.0.0.1:9095",
            "--otlp-endpoint",
            "http://127.0.0.1:4318/v1/metrics",
        ])
        .expect("`helios bridge` must parse");
        assert!(matches!(bridge.command, Some(Command::Bridge(_))));
    }

    #[test]
    fn parses_shell_subcommand() {
        let args = Args::try_parse_from(["helios", "shell", "-c", "echo hi"])
            .expect("shell subcommand must parse");
        match args.command.expect("subcommand must be present") {
            Command::Shell(cmd) => assert_eq!(cmd.shell, None),
            _ => panic!("expected shell subcommand"),
        }
    }

    #[test]
    fn parses_shell_explicit_shell_flag_and_repl_alias() {
        let shell_args =
            Args::try_parse_from(["helios", "shell", "--shell", "/bin/nu", "-c", "true"])
                .expect("shell --shell must parse");
        match shell_args.command.expect("subcommand must be present") {
            Command::Shell(cmd) => assert_eq!(cmd.shell.as_deref(), Some("/bin/nu")),
            _ => panic!("expected shell subcommand"),
        }

        let repl_args =
            Args::try_parse_from(["helios", "repl"]).expect("repl alias for nu must parse");
        assert!(matches!(repl_args.command, Some(Command::Nu(_))));
    }

    #[test]
    fn rejects_legacy_dash_subcommand() {
        let result = Args::try_parse_from(["helios", "dash", "-c", "echo hi"]);
        assert!(result.is_err(), "legacy dash subcommand must stay removed");
    }

    #[test]
    fn parses_vm_nu_and_vm_repl_subcommands() {
        let vm_nu = Args::try_parse_from(["helios", "vm", "--arch", "aarch64", "--no-build", "nu"])
            .expect("`helios vm ... nu` must parse");
        assert!(matches!(vm_nu.command, Some(Command::Vm(_))));

        let vm_nu_inline = Args::try_parse_from([
            "helios",
            "vm",
            "--arch",
            "aarch64",
            "--no-build",
            "nu",
            "-c",
            "inspect /kernel/ | length",
        ])
        .expect("`helios vm ... nu -c` must parse");
        assert!(matches!(vm_nu_inline.command, Some(Command::Vm(_))));

        let vm_python = Args::try_parse_from([
            "helios",
            "vm",
            "--arch",
            "x86-64",
            "--no-build",
            "python",
            "-c",
            "print('ok')",
        ])
        .expect("`helios vm ... python` must parse");
        assert!(matches!(vm_python.command, Some(Command::Vm(_))));
    }

    #[test]
    fn parses_vm_shell_subcommand() {
        let args = Args::try_parse_from([
            "helios",
            "vm",
            "--arch",
            "riscv64",
            "--no-build",
            "shell",
            "-c",
            "echo hi",
        ])
        .expect("vm shell subcommand must parse");
        match args.command.expect("subcommand must be present") {
            Command::Vm(_) => {}
            _ => panic!("expected vm command"),
        }
    }

    #[test]
    fn parses_vm_release_flag() {
        let args = Args::try_parse_from(["helios", "vm", "--arch", "x86-64", "--release", "repl"])
            .expect("vm release flag must parse");
        match args.command.expect("subcommand must be present") {
            Command::Vm(_) => {}
            _ => panic!("expected vm command"),
        }
    }

    #[test]
    fn parses_vm_debug_diagnostics_flags() {
        let args = Args::try_parse_from([
            "helios",
            "vm",
            "--arch",
            "x86-64",
            "--debug",
            "--cpu",
            "max",
            "--accel",
            "tcg,thread=multi",
            "--qemu-trace",
            "int,exec",
            "--qemu-arg",
            "-no-reboot",
            "repl",
        ])
        .expect("vm debug diagnostics flags must parse");
        match args.command.expect("subcommand must be present") {
            Command::Vm(_) => {}
            _ => panic!("expected vm command"),
        }
    }
}
