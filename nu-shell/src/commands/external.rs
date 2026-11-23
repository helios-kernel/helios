//! External process execution (`run-external`), capability scoping (`with-grants`),
//! and executable resolution (`which`).

use std::collections::BTreeMap;

use nu_engine::CallExt;
use nu_protocol::engine::{Closure, EngineState, Stack};
use nu_protocol::{
    ByteStreamType, Category, Record, ShellError, Signature, Span, SyntaxShape, Type, Value,
};

use crate::command::{AsyncCommand, AsyncCommandContext};
use crate::env::{ExternalSpawnRequest, GrantSpec, HeliosEnv};
use crate::error::generic_error;
use crate::eval::{current_cwd_async, eval_closure_async};
use crate::pipeline::AsyncPipelineData;

/// `run-external`: launch an external program with streaming stdin/stdout and
/// explicit capability grants (`--grants` plus active `with-grants` frames).
#[derive(Debug, Clone, Copy)]
pub struct RunExternal;

impl<E: HeliosEnv> AsyncCommand<E> for RunExternal {
    fn name(&self) -> &str {
        "run-external"
    }

    fn description(&self) -> &str {
        "Runs an external program with streaming stdio and explicit Helios capability grants."
    }

    fn search_terms(&self) -> Vec<&str> {
        vec!["exec", "spawn", "external", "process"]
    }

    fn signature(&self) -> Signature {
        Signature::build("run-external")
            .input_output_types(vec![(Type::Any, Type::Any)])
            .named(
                "grants",
                SyntaxShape::Any,
                "Explicit capability grants (string, list of strings, or list of grant records).",
                Some('g'),
            )
            .rest(
                "command",
                SyntaxShape::OneOf(vec![SyntaxShape::GlobPattern, SyntaxShape::Any]),
                "External command to run, with arguments.",
            )
            .category(Category::System)
    }

    async fn run_async<'a>(
        &'a self,
        ctx: &'a mut AsyncCommandContext<'_, E>,
        input: AsyncPipelineData,
    ) -> Result<AsyncPipelineData, ShellError> {
        let head = ctx.call.head;
        let explicit_grants_val: Option<Value> =
            ctx.call.get_flag(ctx.engine_state, ctx.stack, "grants")?;
        let rest: Vec<Value> = ctx.call.rest(ctx.engine_state, ctx.stack, 0)?;

        let Some((first, tail)) = rest.split_first() else {
            return Err(ShellError::MissingParameter {
                param_name: "command".to_owned(),
                span: head,
            });
        };

        let mut args = Vec::new();
        let program = match first {
            Value::List { vals, .. } => {
                let Some((prog, more)) = vals.split_first() else {
                    return Err(ShellError::MissingParameter {
                        param_name: "command".to_owned(),
                        span: head,
                    });
                };
                for item in more {
                    args.push(value_to_arg(item)?);
                }
                value_to_arg(prog)?
            }
            other => value_to_arg(other)?,
        };
        for item in tail {
            args.push(value_to_arg(item)?);
        }

        let mut grants = ctx.runtime_scope.active_grants();
        if let Some(val) = explicit_grants_val {
            grants.extend(parse_grants(&val, head)?);
        }

        let cwd = current_cwd_async(ctx.engine_state, ctx.stack, ctx.env).await;
        let env_map = collect_env_strings(ctx.engine_state, ctx.stack);
        let scope = ctx.runtime_scope.current_scope().map(ToOwned::to_owned);
        let stdin = input.into_byte_receiver_async(head).await?;

        let process = ctx
            .env
            .spawn_external(ExternalSpawnRequest {
                program: program.clone(),
                args,
                cwd,
                env: env_map,
                grants,
                scope,
                stdin,
                capture_stdout: true,
                capture_stderr: true,
            })
            .await
            .map_err(|err| err.into_shell_error(&format!("failed to spawn `{program}`"), head))?;

        let stdout = match process.stdout {
            Some(rx) => rx,
            None => {
                let (_, rx) = async_channel::bounded(1);
                rx
            }
        };

        Ok(AsyncPipelineData::ByteStream {
            stream: stdout,
            stderr: process.stderr,
            exit_code: Some(process.exit_code),
            span: head,
            stream_type: ByteStreamType::Unknown,
            metadata: None,
        })
    }
}

/// `with-grants`: push explicit capability grants for all external launches
/// executed inside a closure.
#[derive(Debug, Clone, Copy)]
pub struct WithGrants;

impl<E: HeliosEnv> AsyncCommand<E> for WithGrants {
    fn name(&self) -> &str {
        "with-grants"
    }

    fn description(&self) -> &str {
        "Run a closure with additional explicit capability grants for external launches."
    }

    fn signature(&self) -> Signature {
        Signature::build("with-grants")
            .input_output_types(vec![(Type::Any, Type::Any)])
            .required(
                "grants",
                SyntaxShape::Any,
                "Grant specification (string, list of strings, or list of `{kind, target, mode?}` records).",
            )
            .required(
                "block",
                SyntaxShape::Closure(None),
                "Closure to execute with the grants active.",
            )
            .category(Category::System)
    }

    async fn run_async<'a>(
        &'a self,
        ctx: &'a mut AsyncCommandContext<'_, E>,
        input: AsyncPipelineData,
    ) -> Result<AsyncPipelineData, ShellError> {
        let head = ctx.call.head;
        let grants_val: Value = ctx.call.req(ctx.engine_state, ctx.stack, 0)?;
        let closure: Closure = ctx.call.req(ctx.engine_state, ctx.stack, 1)?;
        let parsed = parse_grants(&grants_val, head)?;

        ctx.runtime_scope.grant_frames.push(parsed);
        let mut rt = crate::command::EvalRuntime {
            env: ctx.env,
            registry: ctx.registry,
            runtime_scope: ctx.runtime_scope,
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
        ctx.runtime_scope.grant_frames.pop();
        result
    }
}

/// `which`: find commands (built-ins, custom commands, aliases, and granted external programs).
#[derive(Debug, Clone, Copy)]
pub struct Which;

impl<E: HeliosEnv> AsyncCommand<E> for Which {
    fn name(&self) -> &str {
        "which"
    }

    fn description(&self) -> &str {
        "Finds a program or Nushell command by name."
    }

    fn signature(&self) -> Signature {
        Signature::build("which")
            .input_output_types(vec![(
                Type::Nothing,
                Type::Table(
                    vec![
                        ("command".into(), Type::String),
                        ("path".into(), Type::String),
                        ("type".into(), Type::String),
                    ]
                    .into(),
                ),
            )])
            .switch("all", "List all executables", Some('a'))
            .rest(
                "applications",
                SyntaxShape::String,
                "Application(s) to find.",
            )
            .category(Category::System)
    }

    async fn run_async<'a>(
        &'a self,
        ctx: &'a mut AsyncCommandContext<'_, E>,
        _input: AsyncPipelineData,
    ) -> Result<AsyncPipelineData, ShellError> {
        let head = ctx.call.head;
        let all = ctx.call.has_flag(ctx.engine_state, ctx.stack, "all")?;
        let apps: Vec<String> = ctx.call.rest(ctx.engine_state, ctx.stack, 0)?;
        let path_env = extract_path_list(ctx.engine_state, ctx.stack);

        let mut rows = Vec::new();
        for app in apps {
            let mut found = false;
            if let Some(decl_id) = ctx.engine_state.find_decl(app.as_bytes(), &[]) {
                let decl = ctx.engine_state.get_decl(decl_id);
                let kind = if decl.is_alias() {
                    "alias"
                } else if decl.is_custom() {
                    "custom"
                } else if decl.is_keyword() {
                    "keyword"
                } else {
                    "built-in"
                };
                let mut rec = Record::new();
                rec.push("command", Value::string(&app, head));
                rec.push("path", Value::string(String::new(), head));
                rec.push("type", Value::string(kind, head));
                rows.push(Value::record(rec, head));
                found = true;
            }

            if (!found || all)
                && let Some(ext) = ctx
                    .env
                    .resolve_executable(&app, &path_env)
                    .await
                    .map_err(|err| err.into_shell_error("failed to resolve executable", head))?
            {
                let mut rec = Record::new();
                rec.push("command", Value::string(ext.command, head));
                rec.push("path", Value::string(ext.path, head));
                rec.push("type", Value::string("external", head));
                rows.push(Value::record(rec, head));
            }
        }

        Ok(AsyncPipelineData::value(Value::list(rows, head), None))
    }
}

/// Parse grant specifications from a string (`"dir:/data:rw"` or `"virtualize"`),
/// a record (`{kind: "dir", target: "/data", mode: "rw"}`), or a list of those.
pub(crate) fn parse_grants(val: &Value, span: Span) -> Result<Vec<GrantSpec>, ShellError> {
    match val {
        Value::Nothing { .. } => Ok(Vec::new()),
        Value::String { val, .. } => Ok(vec![parse_grant_str(val)]),
        Value::Record { val, .. } => Ok(vec![parse_grant_record(val, span)?]),
        Value::List { vals, .. } => {
            let mut out = Vec::with_capacity(vals.len());
            for item in vals {
                match item {
                    Value::String { val, .. } => out.push(parse_grant_str(val)),
                    Value::Record { val, .. } => out.push(parse_grant_record(val, span)?),
                    other => {
                        return Err(generic_error(
                            "invalid grant entry",
                            format!("expected string or record, found {}", other.get_type()),
                            other.span(),
                        ));
                    }
                }
            }
            Ok(out)
        }
        other => Err(generic_error(
            "invalid grants argument",
            format!(
                "expected string, record, or list, found {}",
                other.get_type()
            ),
            span,
        )),
    }
}

fn parse_grant_str(raw: &str) -> GrantSpec {
    let mut parts = raw.splitn(3, ':');
    let kind = parts.next().unwrap_or_default().to_owned();
    let target = parts.next().unwrap_or_default().to_owned();
    let mode = parts.next().map(ToOwned::to_owned);
    GrantSpec { kind, target, mode }
}

fn parse_grant_record(rec: &Record, span: Span) -> Result<GrantSpec, ShellError> {
    let kind = rec
        .get("kind")
        .ok_or_else(|| generic_error("invalid grant record", "missing `kind` field", span))?
        .coerce_str()?
        .into_owned();
    let target = match rec.get("target") {
        Some(v) => v.coerce_str()?.into_owned(),
        None => String::new(),
    };
    let mode = match rec.get("mode") {
        Some(Value::Nothing { .. }) | None => None,
        Some(v) => Some(v.coerce_str()?.into_owned()),
    };
    Ok(GrantSpec { kind, target, mode })
}

fn value_to_arg(val: &Value) -> Result<String, ShellError> {
    match val {
        Value::String { val, .. } | Value::Glob { val, .. } => Ok(val.clone()),
        Value::Int { val, .. } => Ok(val.to_string()),
        Value::Float { val, .. } => Ok(val.to_string()),
        Value::Bool { val, .. } => Ok(val.to_string()),
        other => Ok(other.clone().coerce_into_string()?),
    }
}

fn collect_env_strings(engine_state: &EngineState, stack: &Stack) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for (k, v) in stack.get_env_vars(engine_state) {
        if let Ok(s) = v.coerce_str() {
            map.insert(k.to_string(), s.into_owned());
        } else if let Value::List { vals, .. } = &v {
            let joined: Vec<String> = vals
                .iter()
                .filter_map(|item| item.coerce_str().ok().map(|s| s.into_owned()))
                .collect();
            map.insert(k.to_string(), joined.join(":"));
        }
    }
    map
}

fn extract_path_list(engine_state: &EngineState, stack: &Stack) -> Vec<String> {
    let Some(val) = stack.get_env_var(engine_state, "PATH") else {
        return vec![String::from("/bin")];
    };
    match val {
        Value::List { vals, .. } => vals
            .iter()
            .filter_map(|v| v.coerce_str().ok().map(|s| s.into_owned()))
            .collect(),
        Value::String { val, .. } => val
            .split(':')
            .filter(|s| !s.is_empty())
            .map(ToOwned::to_owned)
            .collect(),
        _ => vec![String::from("/bin")],
    }
}
