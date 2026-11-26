//! Process, inspection, identity, timing, scope, snapshot, and profiling commands:
//! `inspect`, `ps`, `kill`, `whoami`, `sleep`, `clear`, `with-scope`,
//! `with-snapshot`, and `with-instruction-profile`.

use core::time::Duration;

use nu_engine::CallExt;
use nu_protocol::engine::Closure;
use nu_protocol::{Category, Record, ShellError, Signature, Span, SyntaxShape, Type, Value};

use crate::command::{AsyncCommand, AsyncCommandContext};
use crate::env::{HeliosEnv, InspectValue};
use crate::error::generic_error;
use crate::eval::eval_closure_async;
use crate::pipeline::AsyncPipelineData;

/// `inspect`: query lock-free component and kernel state via `helios:system/inspect`.
#[derive(Debug, Clone, Copy)]
pub struct HeliosInspect;

impl<E: HeliosEnv> AsyncCommand<E> for HeliosInspect {
    fn name(&self) -> &str {
        "inspect"
    }

    fn description(&self) -> &str {
        "Query Helios component and kernel inspection state."
    }

    fn search_terms(&self) -> Vec<&str> {
        vec!["telemetry", "diagnostics", "state", "moniker"]
    }

    fn signature(&self) -> Signature {
        Signature::build("inspect")
            .input_output_types(vec![(
                Type::Nothing,
                Type::Table(
                    vec![
                        ("path".into(), Type::String),
                        ("moniker".into(), Type::String),
                        ("value".into(), Type::Any),
                    ]
                    .into(),
                ),
            )])
            .optional(
                "path",
                SyntaxShape::String,
                "Optional inspect key or moniker prefix to filter.",
            )
            .category(Category::System)
    }

    async fn run_async<'a>(
        &'a self,
        ctx: &'a mut AsyncCommandContext<'_, E>,
        _input: AsyncPipelineData,
    ) -> Result<AsyncPipelineData, ShellError> {
        let head = ctx.call.head;
        let path: Option<String> = ctx.call.opt(ctx.engine_state, ctx.stack, 0)?;
        let entries = ctx
            .env
            .inspect(path.as_deref())
            .await
            .map_err(|e| e.into_shell_error("inspect failed", head))?;

        let rows = entries
            .into_iter()
            .map(|entry| {
                let mut rec = Record::new();
                rec.push("path", Value::string(entry.path, head));
                rec.push("moniker", Value::string(entry.moniker, head));
                rec.push("value", inspect_value_to_nu(entry.value, head));
                Value::record(rec, head)
            })
            .collect();

        Ok(AsyncPipelineData::value(Value::list(rows, head), None))
    }
}

/// `ps`: list running Helios components and processes.
#[derive(Debug, Clone, Copy)]
pub struct Ps;

impl<E: HeliosEnv> AsyncCommand<E> for Ps {
    fn name(&self) -> &str {
        "ps"
    }

    fn description(&self) -> &str {
        "View information about running Helios components and processes."
    }

    fn signature(&self) -> Signature {
        Signature::build("ps")
            .switch("long", "Include extended columns.", Some('l'))
            .input_output_types(vec![(
                Type::Nothing,
                Type::Table(
                    vec![
                        ("pid".into(), Type::Int),
                        ("ppid".into(), Type::Int),
                        ("moniker".into(), Type::String),
                        ("name".into(), Type::String),
                        ("status".into(), Type::String),
                        ("cpu".into(), Type::Float),
                        ("mem".into(), Type::Filesize),
                        ("virtual".into(), Type::Filesize),
                    ]
                    .into(),
                ),
            )])
            .category(Category::System)
    }

    async fn run_async<'a>(
        &'a self,
        ctx: &'a mut AsyncCommandContext<'_, E>,
        _input: AsyncPipelineData,
    ) -> Result<AsyncPipelineData, ShellError> {
        let head = ctx.call.head;
        let long = ctx.call.has_flag(ctx.engine_state, ctx.stack, "long")?;
        let procs = ctx
            .env
            .list_processes()
            .await
            .map_err(|e| e.into_shell_error("ps failed", head))?;

        let rows = procs
            .into_iter()
            .map(|proc| {
                let mut rec = Record::new();
                rec.push(
                    "pid",
                    Value::int(i64::try_from(proc.pid).unwrap_or(i64::MAX), head),
                );
                rec.push(
                    "ppid",
                    Value::int(i64::try_from(proc.ppid).unwrap_or(i64::MAX), head),
                );
                rec.push("moniker", Value::string(proc.moniker, head));
                rec.push("name", Value::string(proc.name, head));
                rec.push("status", Value::string(proc.status, head));
                rec.push("cpu", Value::float(proc.cpu, head));
                rec.push(
                    "mem",
                    Value::filesize(i64::try_from(proc.mem).unwrap_or(i64::MAX), head),
                );
                rec.push(
                    "virtual",
                    Value::filesize(i64::try_from(proc.virtual_mem).unwrap_or(i64::MAX), head),
                );
                if long {
                    rec.push("command", Value::string(proc.command, head));
                }
                Value::record(rec, head)
            })
            .collect();

        Ok(AsyncPipelineData::value(Value::list(rows, head), None))
    }
}

/// `kill`: send a signal or terminate one or more processes.
#[derive(Debug, Clone, Copy)]
pub struct Kill;

impl<E: HeliosEnv> AsyncCommand<E> for Kill {
    fn name(&self) -> &str {
        "kill"
    }

    fn description(&self) -> &str {
        "Send a signal to or stop Helios processes by PID."
    }

    fn signature(&self) -> Signature {
        Signature::build("kill")
            .input_output_types(vec![(Type::Nothing, Type::Nothing)])
            .switch("force", "Forcefully terminate the process.", Some('f'))
            .named(
                "signal",
                SyntaxShape::String,
                "Signal name or number (e.g. INT, TERM, KILL).",
                Some('s'),
            )
            .required("pid", SyntaxShape::Int, "Process ID to signal.")
            .rest(
                "rest",
                SyntaxShape::Int,
                "Additional process IDs to signal.",
            )
            .category(Category::System)
    }

    async fn run_async<'a>(
        &'a self,
        ctx: &'a mut AsyncCommandContext<'_, E>,
        _input: AsyncPipelineData,
    ) -> Result<AsyncPipelineData, ShellError> {
        let head = ctx.call.head;
        let force = ctx.call.has_flag(ctx.engine_state, ctx.stack, "force")?;
        let signal: Option<String> = ctx.call.get_flag(ctx.engine_state, ctx.stack, "signal")?;
        let first: i64 = ctx.call.req(ctx.engine_state, ctx.stack, 0)?;
        let rest: Vec<i64> = ctx.call.rest(ctx.engine_state, ctx.stack, 1)?;

        for pid in std::iter::once(first).chain(rest) {
            let pid = u64::try_from(pid).map_err(|_| {
                generic_error(
                    "invalid pid",
                    format!("pid must be non-negative: {pid}"),
                    head,
                )
            })?;
            ctx.env
                .kill_process(pid, signal.as_deref(), force)
                .await
                .map_err(|e| e.into_shell_error("kill failed", head))?;
        }
        Ok(AsyncPipelineData::Empty)
    }
}

/// `whoami`: report the current capability principal.
#[derive(Debug, Clone, Copy)]
pub struct Whoami;

impl<E: HeliosEnv> AsyncCommand<E> for Whoami {
    fn name(&self) -> &str {
        "whoami"
    }

    fn description(&self) -> &str {
        "Get the current Helios principal identity."
    }

    fn signature(&self) -> Signature {
        Signature::build("whoami")
            .input_output_types(vec![(Type::Nothing, Type::String)])
            .category(Category::Platform)
    }

    async fn run_async<'a>(
        &'a self,
        ctx: &'a mut AsyncCommandContext<'_, E>,
        _input: AsyncPipelineData,
    ) -> Result<AsyncPipelineData, ShellError> {
        let head = ctx.call.head;
        let name = ctx
            .env
            .whoami()
            .await
            .map_err(|e| e.into_shell_error("whoami failed", head))?;
        Ok(AsyncPipelineData::value(Value::string(name, head), None))
    }
}

/// `sleep`: asynchronous monotonic sleep.
#[derive(Debug, Clone, Copy)]
pub struct Sleep;

impl<E: HeliosEnv> AsyncCommand<E> for Sleep {
    fn name(&self) -> &str {
        "sleep"
    }

    fn description(&self) -> &str {
        "Delay execution for the specified duration asynchronously."
    }

    fn signature(&self) -> Signature {
        Signature::build("sleep")
            .input_output_types(vec![(Type::Nothing, Type::Nothing)])
            .required("duration", SyntaxShape::Duration, "Duration to sleep.")
            .rest(
                "rest",
                SyntaxShape::Duration,
                "Additional durations to add.",
            )
            .category(Category::Platform)
    }

    async fn run_async<'a>(
        &'a self,
        ctx: &'a mut AsyncCommandContext<'_, E>,
        _input: AsyncPipelineData,
    ) -> Result<AsyncPipelineData, ShellError> {
        let head = ctx.call.head;
        let first: i64 = ctx.call.req(ctx.engine_state, ctx.stack, 0)?;
        let rest: Vec<i64> = ctx.call.rest(ctx.engine_state, ctx.stack, 1)?;

        let mut total_nanos = 0_u64;
        for ns in std::iter::once(first).chain(rest) {
            if ns < 0 {
                return Err(generic_error(
                    "invalid sleep duration",
                    "sleep duration must be non-negative",
                    head,
                ));
            }
            total_nanos = total_nanos.saturating_add(ns.cast_unsigned());
        }
        ctx.env
            .sleep(Duration::from_nanos(total_nanos))
            .await
            .map_err(|e| e.into_shell_error("sleep failed", head))?;
        Ok(AsyncPipelineData::Empty)
    }
}

/// `clear`: clear the active terminal.
#[derive(Debug, Clone, Copy)]
pub struct Clear;

impl<E: HeliosEnv> AsyncCommand<E> for Clear {
    fn name(&self) -> &str {
        "clear"
    }

    fn description(&self) -> &str {
        "Clear the terminal screen."
    }

    fn signature(&self) -> Signature {
        Signature::build("clear")
            .input_output_types(vec![(Type::Nothing, Type::Nothing)])
            .category(Category::Platform)
    }

    async fn run_async<'a>(
        &'a self,
        ctx: &'a mut AsyncCommandContext<'_, E>,
        _input: AsyncPipelineData,
    ) -> Result<AsyncPipelineData, ShellError> {
        let head = ctx.call.head;
        ctx.env
            .clear()
            .await
            .map_err(|e| e.into_shell_error("clear failed", head))?;
        Ok(AsyncPipelineData::Empty)
    }
}

/// `with-scope`: execute a closure inside a named Helios capability subtree scope.
#[derive(Debug, Clone, Copy)]
pub struct WithScope;

impl<E: HeliosEnv> AsyncCommand<E> for WithScope {
    fn name(&self) -> &str {
        "with-scope"
    }

    fn description(&self) -> &str {
        "Execute a closure within a named Helios capability subtree scope."
    }

    fn signature(&self) -> Signature {
        Signature::build("with-scope")
            .input_output_types(vec![(Type::Any, Type::Any)])
            .required(
                "scope",
                SyntaxShape::String,
                "Subtree moniker or scope name.",
            )
            .required("block", SyntaxShape::Closure(None), "Closure to execute.")
            .category(Category::System)
    }

    async fn run_async<'a>(
        &'a self,
        ctx: &'a mut AsyncCommandContext<'_, E>,
        input: AsyncPipelineData,
    ) -> Result<AsyncPipelineData, ShellError> {
        let head = ctx.call.head;
        let scope: String = ctx.call.req(ctx.engine_state, ctx.stack, 0)?;
        let closure: Closure = ctx.call.req(ctx.engine_state, ctx.stack, 1)?;

        let active = ctx
            .env
            .enter_scope(&scope)
            .await
            .map_err(|e| e.into_shell_error("with-scope enter failed", head))?;
        let mut child_scope = ctx.runtime_scope.clone();
        child_scope.scope_frames.push(active.clone());

        let mut rt = crate::command::EvalRuntime {
            env: ctx.env,
            registry: ctx.registry,
            runtime_scope: &mut child_scope,
        };
        let result = eval_closure_async(
            ctx.engine_state,
            ctx.stack,
            &closure,
            Vec::new(),
            input,
            &mut rt,
            head,
        )
        .await;

        let leave_res = ctx.env.leave_scope(&active).await;
        if let Err(err) = leave_res
            && result.is_ok()
        {
            return Err(err.into_shell_error("with-scope leave failed", head));
        }
        result
    }
}

/// `with-snapshot`: capture a snapshot and execute a closure with its descriptor.
#[derive(Debug, Clone, Copy)]
pub struct WithSnapshot;

impl<E: HeliosEnv> AsyncCommand<E> for WithSnapshot {
    fn name(&self) -> &str {
        "with-snapshot"
    }

    fn description(&self) -> &str {
        "Capture a Helios snapshot and run a closure against it."
    }

    fn signature(&self) -> Signature {
        Signature::build("with-snapshot")
            .input_output_types(vec![(Type::Any, Type::Any)])
            .required("name", SyntaxShape::String, "Snapshot name.")
            .named(
                "moniker",
                SyntaxShape::String,
                "Optional component moniker to snapshot.",
                Some('m'),
            )
            .required(
                "block",
                SyntaxShape::Closure(None),
                "Closure receiving the snapshot record.",
            )
            .category(Category::System)
    }

    async fn run_async<'a>(
        &'a self,
        ctx: &'a mut AsyncCommandContext<'_, E>,
        input: AsyncPipelineData,
    ) -> Result<AsyncPipelineData, ShellError> {
        let head = ctx.call.head;
        let name: String = ctx.call.req(ctx.engine_state, ctx.stack, 0)?;
        let moniker: Option<String> = ctx.call.get_flag(ctx.engine_state, ctx.stack, "moniker")?;
        let closure: Closure = ctx.call.req(ctx.engine_state, ctx.stack, 1)?;

        let info = ctx
            .env
            .take_snapshot(&name, moniker.as_deref())
            .await
            .map_err(|e| e.into_shell_error("with-snapshot failed", head))?;

        let snap_id = info.id.clone();
        let mut snap_rec = Record::new();
        snap_rec.push("id", Value::string(info.id, head));
        snap_rec.push("name", Value::string(info.name, head));
        snap_rec.push(
            "moniker",
            info.moniker
                .map_or_else(|| Value::nothing(head), |m| Value::string(m, head)),
        );
        let snap_val = Value::record(snap_rec, head);

        let mut rt = crate::command::EvalRuntime {
            env: ctx.env,
            registry: ctx.registry,
            runtime_scope: ctx.runtime_scope,
        };
        let eval_result = eval_closure_async(
            ctx.engine_state,
            ctx.stack,
            &closure,
            vec![snap_val],
            input,
            &mut rt,
            head,
        )
        .await;

        let release_res = ctx.env.release_snapshot(&snap_id).await;
        if let Err(err) = release_res
            && eval_result.is_ok()
        {
            return Err(err.into_shell_error("with-snapshot release failed", head));
        }
        eval_result
    }
}

/// `with-instruction-profile`: profile a closure's execution via `helios:system/profiling`.
#[derive(Debug, Clone, Copy)]
pub struct WithInstructionProfile;

impl<E: HeliosEnv> AsyncCommand<E> for WithInstructionProfile {
    fn name(&self) -> &str {
        "with-instruction-profile"
    }

    fn description(&self) -> &str {
        "Execute a closure under instruction profiling and return the result with profile stats."
    }

    fn signature(&self) -> Signature {
        Signature::build("with-instruction-profile")
            .input_output_types(vec![(
                Type::Any,
                Type::Record(
                    vec![
                        ("result".into(), Type::Any),
                        ("target".into(), Type::String),
                        ("instructions".into(), Type::Int),
                        ("cycles".into(), Type::Int),
                        ("samples".into(), Type::Int),
                        ("elapsed".into(), Type::Duration),
                    ]
                    .into(),
                ),
            )])
            .named(
                "target",
                SyntaxShape::String,
                "Optional diagnostic or component target to profile.",
                Some('t'),
            )
            .required("block", SyntaxShape::Closure(None), "Closure to profile.")
            .category(Category::System)
    }

    async fn run_async<'a>(
        &'a self,
        ctx: &'a mut AsyncCommandContext<'_, E>,
        input: AsyncPipelineData,
    ) -> Result<AsyncPipelineData, ShellError> {
        let head = ctx.call.head;
        let target: Option<String> = ctx.call.get_flag(ctx.engine_state, ctx.stack, "target")?;
        let closure: Closure = ctx.call.req(ctx.engine_state, ctx.stack, 0)?;

        let handle = ctx
            .env
            .begin_instruction_profile(target.as_deref())
            .await
            .map_err(|e| e.into_shell_error("failed to start instruction profile", head))?;

        let mut rt = crate::command::EvalRuntime {
            env: ctx.env,
            registry: ctx.registry,
            runtime_scope: ctx.runtime_scope,
        };
        let eval_result = eval_closure_async(
            ctx.engine_state,
            ctx.stack,
            &closure,
            Vec::new(),
            input,
            &mut rt,
            head,
        )
        .await;

        let summary_res = ctx.env.end_instruction_profile(&handle).await;
        let output_value = match eval_result {
            Ok(data) => data.into_value_async(head).await?,
            Err(err) => return Err(err),
        };
        let summary = summary_res
            .map_err(|e| e.into_shell_error("failed to finish instruction profile", head))?;

        let mut rec = Record::new();
        rec.push("result", output_value);
        rec.push("target", Value::string(summary.target, head));
        rec.push(
            "instructions",
            Value::int(
                i64::try_from(summary.instructions).unwrap_or(i64::MAX),
                head,
            ),
        );
        rec.push(
            "cycles",
            Value::int(i64::try_from(summary.cycles).unwrap_or(i64::MAX), head),
        );
        rec.push(
            "samples",
            Value::int(i64::try_from(summary.samples).unwrap_or(i64::MAX), head),
        );
        rec.push(
            "elapsed",
            Value::duration(
                i64::try_from(summary.elapsed.as_nanos()).unwrap_or(i64::MAX),
                head,
            ),
        );

        Ok(AsyncPipelineData::value(Value::record(rec, head), None))
    }
}

fn inspect_value_to_nu(val: InspectValue, span: Span) -> Value {
    match val {
        InspectValue::Null => Value::nothing(span),
        InspectValue::Bool(b) => Value::bool(b, span),
        InspectValue::Int(i) => Value::int(i, span),
        InspectValue::Uint(u) => Value::int(i64::try_from(u).unwrap_or(i64::MAX), span),
        InspectValue::Float(f) => Value::float(f, span),
        InspectValue::String(s) => Value::string(s, span),
        InspectValue::Bytes(b) => Value::binary(b, span),
        InspectValue::List(items) => Value::list(
            items
                .into_iter()
                .map(|v| inspect_value_to_nu(v, span))
                .collect(),
            span,
        ),
        InspectValue::Map(entries) => {
            let mut rec = Record::new();
            for (k, v) in entries {
                rec.push(k, inspect_value_to_nu(v, span));
            }
            Value::record(rec, span)
        }
    }
}
