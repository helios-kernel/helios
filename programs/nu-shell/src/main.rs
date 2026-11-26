//! `/bin/nu`: Helios guest shell component powered by `helios-nu`.
//!
//! Supports:
//! - `nu -c <script>` / `nu --commands <script>`: evaluate one Nushell script and exit.
//! - `nu <file> [args...]`: evaluate a Nushell script file (such as `/etc/rc.nu`).
//! - `nu` (no arguments): interactive REPL reading incrementally from `wasi:cli/stdin`
//!   so terminals such as `programs/compositor` receive immediate responses per line.

mod control;
mod env;

use helios_api::bindings::wasi::cli::{environment, exit, stdin};
use helios_api::io as helios_io;
use helios_nu::{AsyncPipelineData, HeliosEnv, NuError, ShellSession};
use nu_protocol::{ShellError, Span, Value};
use thiserror::Error;

use crate::env::GuestHeliosEnv;

const DEFAULT_PROMPT: &str = "helios> ";
const STDIN_CHUNK_BYTES: usize = 4096;

#[derive(Debug, Error)]
enum NuShellError {
    #[error("missing script argument for `{0}`")]
    MissingScriptFlag(&'static str),
    #[error("failed to read script `{path}`: {detail}")]
    ReadScript { path: String, detail: String },
    #[error("failed to write shell output: {0}")]
    Io(#[from] std::io::Error),
}

enum LaunchMode {
    Command(String),
    Script { path: String },
    Interactive,
    Version,
}

fn parse_args(args: &[String]) -> Result<LaunchMode, NuShellError> {
    let mut iter = args.iter().skip(1);
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-c" | "--commands" => {
                let script = iter
                    .next()
                    .ok_or(NuShellError::MissingScriptFlag("-c"))?
                    .clone();
                return Ok(LaunchMode::Command(script));
            }
            "-v" | "--version" => return Ok(LaunchMode::Version),
            "--" => {
                if let Some(path) = iter.next() {
                    return Ok(LaunchMode::Script { path: path.clone() });
                }
                return Ok(LaunchMode::Interactive);
            }
            flag if flag.starts_with('-') => {
                // Ignore unknown launcher flags such as `-l`/`-i` for login/interactive.
            }
            path => {
                return Ok(LaunchMode::Script {
                    path: path.to_owned(),
                });
            }
        }
    }
    Ok(LaunchMode::Interactive)
}

#[helios_api::main]
async fn main() -> Result<(), NuShellError> {
    let args = environment::get_arguments();
    let mode = parse_args(&args)?;

    if matches!(mode, LaunchMode::Version) {
        helios_io::stdout().writeln("helios-nu 0.117.0").await?;
        return Ok(());
    }

    let raw_env = environment::get_environment();
    let initial_cwd = environment::get_initial_cwd().unwrap_or_else(|| String::from("/"));

    let guest_env = GuestHeliosEnv::new(initial_cwd);
    let mut session = ShellSession::new(guest_env).await;
    seed_session_env(&mut session, &raw_env);

    let exit_code =
        match mode {
            LaunchMode::Command(script) => eval_and_output(&mut session, &script, None).await?,
            LaunchMode::Script { path } => {
                let bytes = session.env().read_file(&path).await.map_err(|err| {
                    NuShellError::ReadScript {
                        path: path.clone(),
                        detail: err.to_string(),
                    }
                })?;
                let script = String::from_utf8(bytes).map_err(|err| NuShellError::ReadScript {
                    path: path.clone(),
                    detail: format!("invalid UTF-8: {err}"),
                })?;
                eval_and_output(&mut session, &script, Some(&path)).await?
            }
            LaunchMode::Interactive => run_interactive(&mut session).await?,
            LaunchMode::Version => 0,
        };

    if exit_code != 0 {
        let code = u8::try_from(exit_code.clamp(1, 255)).unwrap_or(1);
        exit::exit_with_code(code);
    }

    Ok(())
}

fn seed_session_env(session: &mut ShellSession<GuestHeliosEnv>, raw_env: &[(String, String)]) {
    let span = Span::unknown();
    let mut has_home = false;
    let mut has_path = false;
    for (key, value) in raw_env {
        if key == "HOME" {
            has_home = true;
        }
        if key == "PATH" {
            has_path = true;
            let entries: Vec<Value> = value
                .split(':')
                .filter(|s| !s.is_empty())
                .map(|s| Value::string(s, span))
                .collect();
            if !entries.is_empty() {
                session
                    .stack_mut()
                    .add_env_var(key.clone(), Value::list(entries, span));
                continue;
            }
        }
        session
            .stack_mut()
            .add_env_var(key.clone(), Value::string(value, span));
    }
    if !has_home {
        session
            .stack_mut()
            .add_env_var(String::from("HOME"), Value::string("/", span));
    }
    if !has_path {
        session.stack_mut().add_env_var(
            String::from("PATH"),
            Value::list(vec![Value::string("/bin", span)], span),
        );
    }
}

fn current_prompt(session: &ShellSession<GuestHeliosEnv>) -> String {
    session
        .stack()
        .get_env_var(session.engine_state(), "PS1")
        .and_then(|val| val.as_str().ok())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| String::from(DEFAULT_PROMPT))
}

async fn run_interactive(session: &mut ShellSession<GuestHeliosEnv>) -> Result<i32, NuShellError> {
    let stdout = helios_io::stdout();
    let (mut stream, done) = stdin::read_via_stream();
    let mut pending = Vec::<u8>::new();
    let mut last_status = 0_i32;

    let prompt = current_prompt(session);
    stdout.write_str(&prompt).await?;

    loop {
        let (status, chunk) = stream.read(Vec::with_capacity(STDIN_CHUNK_BYTES)).await;
        if !chunk.is_empty() {
            pending.extend_from_slice(&chunk);
            while let Some(newline_pos) = pending.iter().position(|&b| b == b'\n') {
                let mut line_bytes: Vec<u8> = pending.drain(..=newline_pos).collect();
                if line_bytes.ends_with(b"\n") {
                    line_bytes.pop();
                }
                if line_bytes.ends_with(b"\r") {
                    line_bytes.pop();
                }
                let line = String::from_utf8_lossy(&line_bytes);
                let trimmed = line.trim();
                if trimmed == "exit" || trimmed == "quit" {
                    drop(stream);
                    let _ = core::future::IntoFuture::into_future(done).await;
                    return Ok(last_status);
                }
                if !trimmed.is_empty() {
                    match eval_interactive_line(session, trimmed).await? {
                        LineOutcome::Continue(code) => last_status = code,
                        LineOutcome::Exit(code) => {
                            drop(stream);
                            let _ = core::future::IntoFuture::into_future(done).await;
                            return Ok(code);
                        }
                    }
                }
                let prompt = current_prompt(session);
                stdout.write_str(&prompt).await?;
            }
        }

        if helios_api::stream_closed(status) {
            if !pending.is_empty() {
                let tail = String::from_utf8_lossy(&pending);
                let trimmed = tail.trim();
                if !trimmed.is_empty() && trimmed != "exit" && trimmed != "quit" {
                    match eval_interactive_line(session, trimmed).await? {
                        LineOutcome::Continue(code) | LineOutcome::Exit(code) => {
                            last_status = code;
                        }
                    }
                }
            }
            break;
        }
    }

    let _ = core::future::IntoFuture::into_future(done).await;
    Ok(last_status)
}

enum LineOutcome {
    Continue(i32),
    Exit(i32),
}

async fn eval_interactive_line(
    session: &mut ShellSession<GuestHeliosEnv>,
    source: &str,
) -> Result<LineOutcome, NuShellError> {
    match session
        .eval_pipeline_with_file(source, None, AsyncPipelineData::Empty)
        .await
    {
        Ok(pipeline) => {
            let code = render_pipeline_output(session, pipeline).await?;
            Ok(LineOutcome::Continue(code))
        }
        Err(NuError::Eval(err)) => match *err {
            ShellError::Exit { code, .. } => Ok(LineOutcome::Exit(code)),
            ShellError::NonZeroExitCode { exit_code, .. } => {
                Ok(LineOutcome::Continue(exit_code.get()))
            }
            other => {
                helios_io::stderr().writeln(&format!("nu: {other}")).await?;
                Ok(LineOutcome::Continue(1))
            }
        },
        Err(other) => {
            helios_io::stderr().writeln(&format!("nu: {other}")).await?;
            Ok(LineOutcome::Continue(1))
        }
    }
}

async fn eval_and_output(
    session: &mut ShellSession<GuestHeliosEnv>,
    source: &str,
    file_name: Option<&str>,
) -> Result<i32, NuShellError> {
    match session
        .eval_pipeline_with_file(source, file_name, AsyncPipelineData::Empty)
        .await
    {
        Ok(pipeline) => render_pipeline_output(session, pipeline).await,
        Err(NuError::Eval(err)) => match *err {
            ShellError::Exit { code, .. } => Ok(code),
            ShellError::NonZeroExitCode { exit_code, .. } => Ok(exit_code.get()),
            other => {
                helios_io::stderr().writeln(&format!("nu: {other}")).await?;
                Ok(1)
            }
        },
        Err(other) => {
            helios_io::stderr().writeln(&format!("nu: {other}")).await?;
            Ok(1)
        }
    }
}

async fn render_pipeline_output(
    session: &ShellSession<GuestHeliosEnv>,
    pipeline: AsyncPipelineData,
) -> Result<i32, NuShellError> {
    let stdout = helios_io::stdout();
    let stderr = helios_io::stderr();

    match pipeline {
        AsyncPipelineData::Empty => Ok(0),
        AsyncPipelineData::ByteStream {
            stream,
            stderr: err_rx,
            exit_code,
            upstream_exits,
            merge_stderr,
            ..
        } => {
            let out_task = async move {
                while let Ok(chunk) = stream.recv().await {
                    if let Ok(bytes) = chunk
                        && !bytes.is_empty()
                    {
                        let _ = stdout.write_all(&bytes).await;
                    }
                }
            };
            let err_task = async move {
                if let Some(rx) = err_rx {
                    while let Ok(chunk) = rx.recv().await {
                        if let Ok(bytes) = chunk
                            && !bytes.is_empty()
                        {
                            if merge_stderr {
                                let _ = stdout.write_all(&bytes).await;
                            } else {
                                let _ = stderr.write_all(&bytes).await;
                            }
                        }
                    }
                }
            };
            let ((), ()) = futures_lite::future::zip(out_task, err_task).await;

            let mut upstream_non_zero = None;
            for upstream in upstream_exits {
                if let Ok(code) = upstream.exit_code.recv().await {
                    match code {
                        Ok(status) if status != 0 && upstream_non_zero.is_none() => {
                            upstream_non_zero = Some(status);
                        }
                        Ok(_) => {}
                        Err(err) => {
                            stderr.writeln(&format!("nu: {err}")).await?;
                            return Ok(1);
                        }
                    }
                }
            }
            if let Some(code_rx) = exit_code
                && let Ok(code) = code_rx.recv().await
            {
                return match code {
                    Ok(status) => Ok(if status != 0 {
                        status
                    } else {
                        upstream_non_zero.unwrap_or(0)
                    }),
                    Err(err) => {
                        stderr.writeln(&format!("nu: {err}")).await?;
                        Ok(1)
                    }
                };
            }
            Ok(upstream_non_zero.unwrap_or(0))
        }
        other => match other.into_value_async(Span::unknown()).await {
            Ok(val) => {
                write_value_to_stdout(session, &val).await?;
                Ok(0)
            }
            Err(ShellError::Exit { code, .. }) => Ok(code),
            Err(ShellError::NonZeroExitCode { exit_code, .. }) => Ok(exit_code.get()),
            Err(err) => {
                stderr.writeln(&format!("nu: {err}")).await?;
                Ok(1)
            }
        },
    }
}

async fn write_value_to_stdout(
    session: &ShellSession<GuestHeliosEnv>,
    value: &Value,
) -> Result<(), NuShellError> {
    let stdout = helios_io::stdout();
    match value {
        Value::Nothing { .. } => Ok(()),
        Value::Binary { val, .. } => {
            stdout.write_all(val).await?;
            Ok(())
        }
        Value::String { val, .. } => {
            if val.ends_with('\n') {
                stdout.write_str(val).await?;
            } else {
                stdout.writeln(val).await?;
            }
            Ok(())
        }
        other => {
            let config = session.stack().get_config(session.engine_state());
            let formatted = other.to_expanded_string("\n", &config);
            if !formatted.is_empty() {
                stdout.writeln(&formatted).await?;
            }
            Ok(())
        }
    }
}
