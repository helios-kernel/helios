//! Async host Nushell REPL (over `reedline 0.53.0` + `crossterm::event::EventStream`),
//! inline `-c` pipeline evaluation, script file execution, and structured output rendering.

use std::borrow::Cow;
use std::io::{IsTerminal as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use crossterm::event::{Event, EventStream, KeyCode, KeyEvent, KeyModifiers};
use crossterm::terminal;
use futures_lite::StreamExt as _;
use helios_nu::{AsyncPipelineData, HeliosEnv, ShellSession};
use helios_ops::TargetStore;
use nu_ansi_term::{Color, Style};
use nu_protocol::engine::{EngineState, Stack};
use nu_protocol::{Signals, Span, Value};
use reedline::{
    ColumnarMenu, DefaultHinter, Emacs, FileBackedHistory, KeyCode as ReedKeyCode,
    KeyModifiers as ReedKeyModifiers, MenuBuilder as _, Prompt, PromptEditMode,
    PromptHistorySearch, PromptHistorySearchStatus, Reedline, ReedlineEvent, ReedlineMenu,
    Signal as ReedlineSignal, default_emacs_keybindings,
};
use tokio::sync::RwLock;

use crate::completer::{
    AsyncReedlineCompleter, CompletionSnapshot, NuSyntaxHighlighter, NuValidator,
    spawn_completion_worker,
};
use crate::env::HostEnv;
use crate::error::ReplError;

/// Poll cadence for `reedline`'s async completion settle loop.
const REEDLINE_POLL_INTERVAL: Duration = Duration::from_millis(10);

/// Maximum persisted history entries in `~/.config/helios/nu_history.txt`.
const HISTORY_CAPACITY: usize = 5_000;

/// Output format for non-interactive commands and `helios nu -c` / script execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OutputFormat {
    #[default]
    Table,
    Json,
    Jsonl,
    Nuon,
}

/// RAII guard ensuring raw terminal mode is always disabled on scope exit, error, or panic.
struct RawModeGuard {
    active: bool,
}

impl RawModeGuard {
    fn enter() -> Result<Self, ReplError> {
        if std::io::stdin().is_terminal() {
            terminal::enable_raw_mode().map_err(|source| ReplError::Terminal { source })?;
            Ok(Self { active: true })
        } else {
            Ok(Self { active: false })
        }
    }

    fn ensure_disabled(&mut self) {
        if self.active {
            let _ = terminal::disable_raw_mode();
            self.active = false;
        }
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        self.ensure_disabled();
    }
}

/// Styled prompt displaying the connected target name and current remote VFS working directory.
struct HeliosPrompt {
    target: String,
    cwd: String,
    scope: Option<String>,
}

impl Prompt for HeliosPrompt {
    fn render_prompt_left(&self) -> Cow<'_, str> {
        let prefix = Style::new().fg(Color::Green).bold().paint("helios");
        let target = Style::new().fg(Color::Cyan).paint(&self.target);
        let cwd = Style::new().fg(Color::Blue).paint(&self.cwd);
        Cow::Owned(format!("{prefix}[{target}:{cwd}]"))
    }

    fn render_prompt_right(&self) -> Cow<'_, str> {
        match &self.scope {
            Some(scope) => Cow::Owned(
                Style::new()
                    .fg(Color::Fixed(244))
                    .paint(format!("scope:{scope}"))
                    .to_string(),
            ),
            None => Cow::Borrowed(""),
        }
    }

    fn render_prompt_indicator(&self, _edit_mode: PromptEditMode) -> Cow<'_, str> {
        Cow::Owned(Style::new().fg(Color::Fixed(244)).paint("> ").to_string())
    }

    fn render_prompt_multiline_indicator(&self) -> Cow<'_, str> {
        Cow::Owned(Style::new().fg(Color::Fixed(244)).paint("::: ").to_string())
    }

    fn render_prompt_history_search_indicator(
        &self,
        history_search: PromptHistorySearch,
    ) -> Cow<'_, str> {
        let status = match history_search.status {
            PromptHistorySearchStatus::Passing => "",
            PromptHistorySearchStatus::Failing => "failing ",
        };
        Cow::Owned(format!("({status}search: {}) ", history_search.term))
    }
}

/// Evaluate a single inline Nushell pipeline (`helios nu -c '<pipeline>'`) asynchronously.
pub async fn eval_command(
    env: HostEnv,
    source: &str,
    format: OutputFormat,
) -> Result<String, ReplError> {
    let mut session = Box::pin(ShellSession::new(env)).await;
    let value = Box::pin(session.eval(source)).await?;
    format_value(session.engine_state(), session.stack(), &value, format).await
}

/// Execute a local `.nu` script file (`helios nu <script.nu> [args...]`) asynchronously.
pub async fn eval_script(
    env: HostEnv,
    script_path: &Path,
    args: &[String],
    format: OutputFormat,
) -> Result<String, ReplError> {
    let source = tokio::fs::read_to_string(script_path)
        .await
        .map_err(|source| ReplError::ReadScript {
            path: script_path.to_path_buf(),
            source,
        })?;
    let mut session = Box::pin(ShellSession::new(env)).await;
    let arg_values: Vec<Value> = args
        .iter()
        .map(|arg| Value::string(arg.clone(), Span::unknown()))
        .collect();
    session.stack_mut().add_env_var(
        "HELIOS_ARGS".to_owned(),
        Value::list(arg_values, Span::unknown()),
    );
    let file_name = script_path.display().to_string();
    let out =
        Box::pin(session.eval_source(&source, Some(&file_name), AsyncPipelineData::Empty)).await?;
    let value = out
        .into_value_async(Span::unknown())
        .await
        .map_err(helios_nu::NuError::from)?;
    format_value(session.engine_state(), session.stack(), &value, format).await
}

/// Run the interactive host Nushell REPL backed by `reedline 0.53.0` (with
/// `bashisms`, `system_clipboard`, live `<Tab>` completion over
/// [`helios_nu::complete_async`], raw-mode RAII teardown, and `Ctrl+C`
/// per-invocation cancellation via [`crossterm::event::EventStream`] + `SIGINT`).
pub async fn run_repl(env: HostEnv, format: OutputFormat) -> Result<(), ReplError> {
    let completion_env = env.for_completion();
    let target_name = env.session().target().name.clone();
    let scope = env.session().options().attenuation.scope.clone();

    let mut session = ShellSession::new(env).await;
    let interrupt_flag = Arc::new(AtomicBool::new(false));
    session
        .engine_state_mut()
        .set_signals(Signals::new(Arc::clone(&interrupt_flag)));

    let snapshot = Arc::new(RwLock::new(CompletionSnapshot {
        engine_state: session.engine_state().clone(),
        stack: session.stack().clone(),
    }));

    let (completer, req_rx, resp_tx) = AsyncReedlineCompleter::channel_pair();

    let completion_menu = Box::new(
        ColumnarMenu::default()
            .with_name("completion_menu")
            .with_columns(4)
            .with_column_padding(2),
    );

    let mut keybindings = default_emacs_keybindings();
    keybindings.add_binding(
        ReedKeyModifiers::NONE,
        ReedKeyCode::Tab,
        ReedlineEvent::UntilFound(vec![
            ReedlineEvent::Menu("completion_menu".to_owned()),
            ReedlineEvent::MenuNext,
        ]),
    );
    keybindings.add_binding(
        ReedKeyModifiers::SHIFT,
        ReedKeyCode::BackTab,
        ReedlineEvent::MenuPrevious,
    );

    let history_path = history_file_path();
    if let Some(parent) = history_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    let mut editor = Reedline::create()
        .with_completer(Box::new(completer))
        .with_menu(ReedlineMenu::EngineCompleter(completion_menu))
        .with_edit_mode(Box::new(Emacs::new(keybindings)))
        .with_highlighter(Box::new(NuSyntaxHighlighter::new(
            session.engine_state().clone(),
        )))
        .with_hinter(Box::new(
            DefaultHinter::default().with_style(Style::new().italic().fg(Color::Fixed(244))),
        ))
        .with_validator(Box::new(NuValidator::new(session.engine_state().clone())))
        .with_quick_completions(true)
        .with_partial_completions(true)
        .with_poll_interval(REEDLINE_POLL_INTERVAL);

    if let Ok(history) = FileBackedHistory::with_file(HISTORY_CAPACITY, history_path.clone()) {
        editor = editor.with_history(Box::new(history));
    }

    let repaint = editor.repaint_signal();
    let worker = spawn_completion_worker(
        completion_env,
        Arc::clone(&snapshot),
        req_rx,
        resp_tx,
        Some(repaint),
    );

    writeln_stdout(&format!(
        "Helios Nushell REPL connected to `{target_name}`. Press <Tab> for live completions, `exit` or Ctrl+D to quit."
    ))?;

    let mut editor_opt = Some(editor);
    let repl_result = loop {
        let cwd = session
            .env()
            .cwd()
            .await
            .unwrap_or_else(|_| String::from("/"));
        {
            let mut snap = snapshot.write().await;
            snap.engine_state = session.engine_state().clone();
            snap.stack = session.stack().clone();
        }

        let prompt = HeliosPrompt {
            target: target_name.clone(),
            cwd,
            scope: scope.clone(),
        };

        let mut ed = editor_opt
            .take()
            .expect("editor is always returned from spawn_blocking");
        let (ed, read_res) = tokio::task::spawn_blocking(move || {
            let res = ed.read_line(&prompt);
            // Guarantee raw mode is disabled even if reedline exited early on an I/O error.
            let _ = terminal::disable_raw_mode();
            (ed, res)
        })
        .await
        .map_err(|err| ReplError::EditorTask {
            detail: err.to_string(),
        })?;
        editor_opt = Some(ed);

        let line = match read_res {
            Ok(ReedlineSignal::Success(buffer)) => buffer,
            Ok(ReedlineSignal::CtrlC(_)) => continue,
            Ok(ReedlineSignal::CtrlD) => break Ok(()),
            Ok(ReedlineSignal::ExternalBreak(_)) => break Ok(()),
            Ok(_) => continue,
            Err(source) => break Err(ReplError::Terminal { source }),
        };

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if matches!(trimmed, "exit" | "quit") {
            break Ok(());
        }

        interrupt_flag.store(false, std::sync::atomic::Ordering::Release);
        match eval_interruptible(&mut session, trimmed, &interrupt_flag).await {
            EvalOutcome::Completed(Ok(value)) => {
                if !value.is_nothing() {
                    let rendered =
                        format_value(session.engine_state(), session.stack(), &value, format)
                            .await?;
                    if !rendered.is_empty() {
                        writeln_stdout(&rendered)?;
                    }
                }
            }
            EvalOutcome::Completed(Err(err)) => {
                writeln_stderr(&format!("error: {err}"))?;
            }
            EvalOutcome::Interrupted => {
                writeln_stderr("^C interrupted")?;
            }
        }
    };

    worker.abort();
    let _ = terminal::disable_raw_mode();
    repl_result
}

enum EvalOutcome {
    Completed(Result<Value, helios_nu::NuError>),
    Interrupted,
}

/// Evaluate one REPL command with `Ctrl+C` per-invocation cancellation driven by
/// [`crossterm::event::EventStream`] (in raw mode when stdin is a TTY) and `SIGINT`.
async fn eval_interruptible(
    session: &mut ShellSession<HostEnv>,
    source: &str,
    interrupt_flag: &AtomicBool,
) -> EvalOutcome {
    let mut raw_guard = RawModeGuard::enter().ok();
    let mut event_stream = raw_guard
        .as_ref()
        .filter(|g| g.active)
        .map(|_| EventStream::new());

    let cancel_fut = async {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = wait_for_ctrl_c_key(&mut event_stream) => {}
        }
    };

    let outcome = tokio::select! {
        res = Box::pin(session.eval(source)) => EvalOutcome::Completed(res),
        _ = cancel_fut => {
            interrupt_flag.store(true, std::sync::atomic::Ordering::Release);
            EvalOutcome::Interrupted
        }
    };

    drop(event_stream);
    if let Some(guard) = raw_guard.as_mut() {
        guard.ensure_disabled();
    }
    outcome
}

async fn wait_for_ctrl_c_key(stream: &mut Option<EventStream>) {
    let Some(events) = stream.as_mut() else {
        std::future::pending::<()>().await;
        return;
    };
    while let Some(ev) = events.next().await {
        if let Ok(Event::Key(KeyEvent {
            code: KeyCode::Char('c'),
            modifiers,
            ..
        })) = ev
            && modifiers.contains(KeyModifiers::CONTROL)
        {
            return;
        }
    }
    std::future::pending::<()>().await;
}

/// Render a Nushell [`Value`] in the requested [`OutputFormat`].
pub async fn format_value(
    engine_state: &EngineState,
    stack: &Stack,
    value: &Value,
    format: OutputFormat,
) -> Result<String, ReplError> {
    if value.is_nothing() {
        return Ok(String::new());
    }
    match format {
        OutputFormat::Table => Ok(render_table(engine_state, stack, value)),
        OutputFormat::Json => {
            let json = nu_value_to_json(value);
            serde_json::to_string_pretty(&json).map_err(|source| ReplError::EncodeJson { source })
        }
        OutputFormat::Jsonl => match value {
            Value::List { vals, .. } => {
                let mut lines = Vec::with_capacity(vals.len());
                for item in vals {
                    let line = serde_json::to_string(&nu_value_to_json(item))
                        .map_err(|source| ReplError::EncodeJson { source })?;
                    lines.push(line);
                }
                Ok(lines.join("\n"))
            }
            other => serde_json::to_string(&nu_value_to_json(other))
                .map_err(|source| ReplError::EncodeJson { source }),
        },
        OutputFormat::Nuon => Ok(render_via_decl(engine_state, stack, value, "to nuon")
            .unwrap_or_else(|| value.to_abbreviated_string(&nu_protocol::Config::default()))),
    }
}

fn render_table(engine_state: &EngineState, stack: &Stack, value: &Value) -> String {
    if let Value::String { val, .. } = value {
        return val.clone();
    }
    render_via_decl(engine_state, stack, value, "table")
        .unwrap_or_else(|| value.to_abbreviated_string(&nu_protocol::Config::default()))
}

fn render_via_decl(
    engine_state: &EngineState,
    stack: &Stack,
    value: &Value,
    decl_name: &str,
) -> Option<String> {
    let decl_id = engine_state.find_decl(decl_name.as_bytes(), &[])?;
    let decl = engine_state.get_decl(decl_id);
    let call = nu_protocol::ir::Call::build(decl_id, Span::unknown()).finish();
    let mut local_stack = stack.clone();
    let out = decl
        .run(
            engine_state,
            &mut local_stack,
            &(&call).into(),
            nu_protocol::PipelineData::value(value.clone(), None),
        )
        .ok()?;
    let val = out.into_value(Span::unknown()).ok()?;
    match val {
        Value::String { val, .. } => Some(val),
        other => Some(other.to_abbreviated_string(&nu_protocol::Config::default())),
    }
}

fn nu_value_to_json(value: &Value) -> serde_json::Value {
    match value {
        Value::Nothing { .. } => serde_json::Value::Null,
        Value::Bool { val, .. } => serde_json::Value::Bool(*val),
        Value::Int { val, .. } => serde_json::json!(val),
        Value::Float { val, .. } => serde_json::Number::from_f64(*val)
            .map_or(serde_json::Value::Null, serde_json::Value::Number),
        Value::Filesize { val, .. } => serde_json::json!(val.get()),
        Value::Duration { val, .. } => serde_json::json!(val),
        Value::String { val, .. } | Value::Glob { val, .. } => {
            serde_json::Value::String(val.clone())
        }
        Value::Binary { val, .. } => {
            serde_json::Value::Array(val.iter().map(|b| serde_json::json!(b)).collect())
        }
        Value::List { vals, .. } => {
            serde_json::Value::Array(vals.iter().map(nu_value_to_json).collect())
        }
        Value::Record { val, .. } => {
            let mut map = serde_json::Map::new();
            for (k, v) in val.iter() {
                map.insert(k.clone(), nu_value_to_json(v));
            }
            serde_json::Value::Object(map)
        }
        other => {
            serde_json::Value::String(other.to_abbreviated_string(&nu_protocol::Config::default()))
        }
    }
}

fn history_file_path() -> PathBuf {
    TargetStore::default_config_dir().join("nu_history.txt")
}

fn writeln_stdout(text: &str) -> Result<(), ReplError> {
    let mut out = std::io::stdout().lock();
    writeln!(out, "{text}")
        .and_then(|()| out.flush())
        .map_err(|source| ReplError::Terminal { source })
}

fn writeln_stderr(text: &str) -> Result<(), ReplError> {
    let mut err = std::io::stderr().lock();
    writeln!(err, "{text}")
        .and_then(|()| err.flush())
        .map_err(|source| ReplError::Terminal { source })
}
