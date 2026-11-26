//! Linux container lifecycle and scoped execution commands:
//! `container {create, ls, exec, spawn, rm}` and `with-container <handle> { ... }`.

use std::collections::BTreeMap;

use nu_engine::CallExt;
use nu_protocol::engine::Closure;
use nu_protocol::{
    ByteStreamType, Category, OutDest, Record, ShellError, Signature, Span, SyntaxShape, Type,
    Value,
};

use crate::command::{AsyncCommand, AsyncCommandContext};
use crate::commands::external::parse_grants;
use crate::env::{
    ContainerCreateRequest, ContainerExecRequest, ContainerInfo, ContainerMountSharingSpec,
    ContainerMountSpec, ContainerSpawnRequest, HeliosEnv,
};
use crate::error::generic_error;
use crate::eval::{current_cwd_async, eval_closure_async, resolve_vfs_path};
use crate::pipeline::AsyncPipelineData;

fn container_columns() -> Vec<(String, Type)> {
    vec![
        ("handle".into(), Type::String),
        ("image".into(), Type::Any),
        ("rootfs_path".into(), Type::String),
        ("hostname".into(), Type::String),
        ("cwd".into(), Type::Any),
        ("uid".into(), Type::Int),
        ("gid".into(), Type::Int),
    ]
}

fn container_to_value(info: ContainerInfo, span: Span) -> Value {
    let mut rec = Record::new();
    rec.push("handle", Value::string(info.handle, span));
    rec.push(
        "image",
        info.image
            .map_or_else(|| Value::nothing(span), |i| Value::string(i, span)),
    );
    rec.push("rootfs_path", Value::string(info.rootfs_path, span));
    rec.push("hostname", Value::string(info.hostname, span));
    rec.push(
        "cwd",
        info.cwd
            .map_or_else(|| Value::nothing(span), |c| Value::string(c, span)),
    );
    rec.push("uid", Value::int(i64::from(info.uid), span));
    rec.push("gid", Value::int(i64::from(info.gid), span));
    Value::record(rec, span)
}

/// `container`: parent namespace (lists active containers when invoked directly).
#[derive(Debug, Clone, Copy)]
pub struct Container;

impl<E: HeliosEnv> AsyncCommand<E> for Container {
    fn name(&self) -> &str {
        "container"
    }

    fn description(&self) -> &str {
        "Create, list, inspect, execute in, and destroy Linux containers."
    }

    fn signature(&self) -> Signature {
        Signature::build("container")
            .input_output_types(vec![(
                Type::Nothing,
                Type::Table(container_columns().into()),
            )])
            .category(Category::System)
    }

    async fn run_async<'a>(
        &'a self,
        ctx: &'a mut AsyncCommandContext<'_, E>,
        input: AsyncPipelineData,
    ) -> Result<AsyncPipelineData, ShellError> {
        ContainerLs.run_async(ctx, input).await
    }
}

/// `container create`: create a persistent Linux container handle.
#[derive(Debug, Clone, Copy)]
pub struct ContainerCreate;

impl<E: HeliosEnv> AsyncCommand<E> for ContainerCreate {
    fn name(&self) -> &str {
        "container create"
    }

    fn description(&self) -> &str {
        "Create a live Linux container from an OCI image or rootfs path."
    }

    fn signature(&self) -> Signature {
        Signature::build("container create")
            .input_output_types(vec![(
                Type::Nothing,
                Type::Record(container_columns().into()),
            )])
            .optional(
                "image",
                SyntaxShape::String,
                "Optional positional OCI image reference (e.g. alpine).",
            )
            .named(
                "image",
                SyntaxShape::String,
                "OCI image reference to materialize as an ephemeral overlay root.",
                Some('i'),
            )
            .named(
                "rootfs",
                SyntaxShape::Filepath,
                "Explicit read-only lower rootfs path in the guest VFS.",
                Some('r'),
            )
            .named(
                "mount",
                SyntaxShape::Any,
                "Additional mount(s): `source:target[:mode[:sharing]]`, record, or list.",
                Some('m'),
            )
            .named(
                "grants",
                SyntaxShape::Any,
                "Non-filesystem capability grants for the container.",
                Some('g'),
            )
            .named(
                "hostname",
                SyntaxShape::String,
                "Container UTS hostname.",
                None,
            )
            .named(
                "domainname",
                SyntaxShape::String,
                "Container UTS domain name.",
                None,
            )
            .named(
                "user",
                SyntaxShape::String,
                "Numeric credentials `uid` or `uid:gid`.",
                Some('u'),
            )
            .named(
                "env",
                SyntaxShape::Record(vec![].into()),
                "Default environment variables for commands inside the container.",
                Some('e'),
            )
            .named(
                "cwd",
                SyntaxShape::String,
                "Default working directory inside the container.",
                None,
            )
            .category(Category::System)
    }

    async fn run_async<'a>(
        &'a self,
        ctx: &'a mut AsyncCommandContext<'_, E>,
        _input: AsyncPipelineData,
    ) -> Result<AsyncPipelineData, ShellError> {
        let head = ctx.call.head;
        let pos_image: Option<String> = ctx.call.opt(ctx.engine_state, ctx.stack, 0)?;
        let flag_image: Option<String> = ctx.call.get_flag(ctx.engine_state, ctx.stack, "image")?;
        let rootfs_raw: Option<String> =
            ctx.call.get_flag(ctx.engine_state, ctx.stack, "rootfs")?;
        let mount_val: Option<Value> = ctx.call.get_flag(ctx.engine_state, ctx.stack, "mount")?;
        let grants_val: Option<Value> = ctx.call.get_flag(ctx.engine_state, ctx.stack, "grants")?;
        let hostname: Option<String> =
            ctx.call.get_flag(ctx.engine_state, ctx.stack, "hostname")?;
        let domainname: Option<String> =
            ctx.call
                .get_flag(ctx.engine_state, ctx.stack, "domainname")?;
        let user_raw: Option<String> = ctx.call.get_flag(ctx.engine_state, ctx.stack, "user")?;
        let env_rec: Option<Record> = ctx.call.get_flag(ctx.engine_state, ctx.stack, "env")?;
        let cwd: Option<String> = ctx.call.get_flag(ctx.engine_state, ctx.stack, "cwd")?;

        let image = flag_image.or(pos_image);
        if image.is_some() && rootfs_raw.is_some() {
            return Err(generic_error(
                "conflicting container root",
                "specify either an OCI image or `--rootfs`, not both",
                head,
            ));
        }
        if image.is_none() && rootfs_raw.is_none() {
            return Err(generic_error(
                "missing container root",
                "specify an OCI image reference or `--rootfs <path>`",
                head,
            ));
        }

        let shell_cwd = current_cwd_async(ctx.engine_state, ctx.stack, ctx.env).await;
        let rootfs =
            rootfs_raw.map(|p| resolve_vfs_path(ctx.engine_state, ctx.stack, &shell_cwd, &p, true));

        let mounts = match mount_val {
            Some(val) => parse_container_mounts(&val, &shell_cwd, head)?,
            None => Vec::new(),
        };
        let grants = match grants_val {
            Some(val) => parse_grants(&val, head)?,
            None => Vec::new(),
        };
        let (uid, gid) = match user_raw {
            Some(spec) => parse_uid_gid(&spec, head)?,
            None => (None, None),
        };
        let env = parse_env_record(env_rec)?;

        let info = ctx
            .env
            .container_create(ContainerCreateRequest {
                image,
                rootfs,
                mounts,
                grants,
                hostname,
                domainname,
                uid,
                gid,
                env,
                cwd,
            })
            .await
            .map_err(|e| e.into_shell_error("container create failed", head))?;

        Ok(AsyncPipelineData::value(
            container_to_value(info, head),
            None,
        ))
    }
}

/// `container ls`: list live Linux containers owned by this shell session.
#[derive(Debug, Clone, Copy)]
pub struct ContainerLs;

impl<E: HeliosEnv> AsyncCommand<E> for ContainerLs {
    fn name(&self) -> &str {
        "container ls"
    }

    fn description(&self) -> &str {
        "List active Linux containers in this shell session."
    }

    fn signature(&self) -> Signature {
        Signature::build("container ls")
            .input_output_types(vec![(
                Type::Nothing,
                Type::Table(container_columns().into()),
            )])
            .category(Category::System)
    }

    async fn run_async<'a>(
        &'a self,
        ctx: &'a mut AsyncCommandContext<'_, E>,
        _input: AsyncPipelineData,
    ) -> Result<AsyncPipelineData, ShellError> {
        let head = ctx.call.head;
        let items = ctx
            .env
            .container_list()
            .await
            .map_err(|e| e.into_shell_error("container ls failed", head))?;
        let rows = items
            .into_iter()
            .map(|c| container_to_value(c, head))
            .collect();
        Ok(AsyncPipelineData::value(Value::list(rows, head), None))
    }
}

/// `container exec <handle> <program> [args...]`: run a command to completion inside a container.
#[derive(Debug, Clone, Copy)]
pub struct ContainerExec;

impl<E: HeliosEnv> AsyncCommand<E> for ContainerExec {
    fn name(&self) -> &str {
        "container exec"
    }

    fn description(&self) -> &str {
        "Execute a command to completion inside a live Linux container."
    }

    fn signature(&self) -> Signature {
        Signature::build("container exec")
            .input_output_types(vec![(
                Type::Any,
                Type::Record(
                    vec![
                        ("instance_id".into(), Type::Int),
                        ("exit_code".into(), Type::Int),
                        ("stdout".into(), Type::String),
                        ("stderr".into(), Type::String),
                    ]
                    .into(),
                ),
            )])
            .named(
                "cwd",
                SyntaxShape::String,
                "Working directory override inside the container.",
                None,
            )
            .named(
                "env",
                SyntaxShape::Record(vec![].into()),
                "Additional environment variables for this command.",
                Some('e'),
            )
            .named(
                "stdin",
                SyntaxShape::Any,
                "Explicit stdin bytes or string (overrides pipeline input).",
                None,
            )
            .required(
                "handle",
                SyntaxShape::Any,
                "Container handle string or record returned by `container create`.",
            )
            .required(
                "program",
                SyntaxShape::String,
                "Program path inside container.",
            )
            .rest(
                "args",
                SyntaxShape::Any,
                "Arguments to pass to the program.",
            )
            .category(Category::System)
    }

    async fn run_async<'a>(
        &'a self,
        ctx: &'a mut AsyncCommandContext<'_, E>,
        input: AsyncPipelineData,
    ) -> Result<AsyncPipelineData, ShellError> {
        let head = ctx.call.head;
        let cwd: Option<String> = ctx.call.get_flag(ctx.engine_state, ctx.stack, "cwd")?;
        let env_rec: Option<Record> = ctx.call.get_flag(ctx.engine_state, ctx.stack, "env")?;
        let stdin_flag: Option<Value> = ctx.call.get_flag(ctx.engine_state, ctx.stack, "stdin")?;
        let handle_val: Value = ctx.call.req(ctx.engine_state, ctx.stack, 0)?;
        let program: String = ctx.call.req(ctx.engine_state, ctx.stack, 1)?;
        let raw_args: Vec<Value> = ctx.call.rest(ctx.engine_state, ctx.stack, 2)?;

        let handle = extract_container_handle(&handle_val, head)?;
        let mut args = Vec::with_capacity(raw_args.len());
        for arg in raw_args {
            args.push(arg.coerce_into_string()?);
        }
        let env = parse_env_record(env_rec)?;
        let stdin = match stdin_flag {
            Some(val) => crate::pipeline::value_to_bytes(&val, head)?,
            None if !input.is_empty_or_nothing() => input.into_bytes_async(head).await?,
            None => Vec::new(),
        };

        let out = ctx
            .env
            .container_exec(
                &handle,
                ContainerExecRequest {
                    program,
                    args,
                    env,
                    cwd,
                    stdin,
                },
            )
            .await
            .map_err(|e| e.into_shell_error("container exec failed", head))?;

        ctx.stack.set_last_exit_code(out.exit_code, head);
        let mut rec = Record::new();
        rec.push(
            "instance_id",
            Value::int(i64::try_from(out.instance_id).unwrap_or(i64::MAX), head),
        );
        rec.push("exit_code", Value::int(i64::from(out.exit_code), head));
        rec.push(
            "stdout",
            Value::string(String::from_utf8_lossy(&out.stdout).into_owned(), head),
        );
        rec.push(
            "stderr",
            Value::string(String::from_utf8_lossy(&out.stderr).into_owned(), head),
        );
        Ok(AsyncPipelineData::value(Value::record(rec, head), None))
    }
}

/// `container spawn <handle> <program> [args...]`: stream a command inside a container.
#[derive(Debug, Clone, Copy)]
pub struct ContainerSpawn;

impl<E: HeliosEnv> AsyncCommand<E> for ContainerSpawn {
    fn name(&self) -> &str {
        "container spawn"
    }

    fn description(&self) -> &str {
        "Spawn a streaming command inside a live Linux container."
    }

    fn signature(&self) -> Signature {
        Signature::build("container spawn")
            .input_output_types(vec![(Type::Any, Type::Any)])
            .named(
                "cwd",
                SyntaxShape::String,
                "Working directory override inside the container.",
                None,
            )
            .named(
                "env",
                SyntaxShape::Record(vec![].into()),
                "Additional environment variables for this command.",
                Some('e'),
            )
            .required(
                "handle",
                SyntaxShape::Any,
                "Container handle string or record returned by `container create`.",
            )
            .required(
                "program",
                SyntaxShape::String,
                "Program path inside container.",
            )
            .rest(
                "args",
                SyntaxShape::Any,
                "Arguments to pass to the program.",
            )
            .category(Category::System)
    }

    async fn run_async<'a>(
        &'a self,
        ctx: &'a mut AsyncCommandContext<'_, E>,
        input: AsyncPipelineData,
    ) -> Result<AsyncPipelineData, ShellError> {
        let head = ctx.call.head;
        let cwd: Option<String> = ctx.call.get_flag(ctx.engine_state, ctx.stack, "cwd")?;
        let env_rec: Option<Record> = ctx.call.get_flag(ctx.engine_state, ctx.stack, "env")?;
        let handle_val: Value = ctx.call.req(ctx.engine_state, ctx.stack, 0)?;
        let program: String = ctx.call.req(ctx.engine_state, ctx.stack, 1)?;
        let raw_args: Vec<Value> = ctx.call.rest(ctx.engine_state, ctx.stack, 2)?;

        let handle = extract_container_handle(&handle_val, head)?;
        let mut args = Vec::with_capacity(raw_args.len());
        for arg in raw_args {
            args.push(arg.coerce_into_string()?);
        }
        let env = parse_env_record(env_rec)?;
        let (stdin, upstream_exits) = input.into_external_stdin_async(head).await?;

        let stderr_piped_alone = matches!(ctx.stack.stderr(), OutDest::Pipe)
            && matches!(
                ctx.stack.stdout(),
                OutDest::Inherit | OutDest::Print | OutDest::Null
            );
        let capture_stdout = !stderr_piped_alone
            && (ctx.runtime_scope.capture_inherited_stdout
                || !matches!(ctx.stack.stdout(), OutDest::Inherit | OutDest::Print));
        let capture_stderr = !matches!(ctx.stack.stderr(), OutDest::Inherit | OutDest::Print);

        let process = ctx
            .env
            .container_spawn(
                &handle,
                ContainerSpawnRequest {
                    program: program.clone(),
                    args,
                    env,
                    cwd,
                    stdin,
                    capture_stdout,
                    capture_stderr,
                },
            )
            .await
            .map_err(|e| {
                e.into_shell_error(
                    &format!("failed to spawn `{program}` in container `{handle}`"),
                    head,
                )
            })?;

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
            upstream_exits,
            is_external: true,
            merge_stderr: false,
            span: head,
            stream_type: ByteStreamType::Unknown,
            metadata: None,
        })
    }
}

/// `container rm <handle>`: destroy a live container handle and release its overlay.
#[derive(Debug, Clone, Copy)]
pub struct ContainerRm;

impl<E: HeliosEnv> AsyncCommand<E> for ContainerRm {
    fn name(&self) -> &str {
        "container rm"
    }

    fn description(&self) -> &str {
        "Destroy a live Linux container and release its ephemeral overlay."
    }

    fn signature(&self) -> Signature {
        Signature::build("container rm")
            .input_output_types(vec![(Type::Nothing, Type::Nothing)])
            .required(
                "handle",
                SyntaxShape::Any,
                "Container handle string or record returned by `container create`.",
            )
            .category(Category::System)
    }

    async fn run_async<'a>(
        &'a self,
        ctx: &'a mut AsyncCommandContext<'_, E>,
        _input: AsyncPipelineData,
    ) -> Result<AsyncPipelineData, ShellError> {
        let head = ctx.call.head;
        let handle_val: Value = ctx.call.req(ctx.engine_state, ctx.stack, 0)?;
        let handle = extract_container_handle(&handle_val, head)?;
        ctx.env
            .container_remove(&handle)
            .await
            .map_err(|e| e.into_shell_error("container rm failed", head))?;
        Ok(AsyncPipelineData::Empty)
    }
}

/// `with-container <handle> { ... }`: route external commands inside a closure into a live container.
#[derive(Debug, Clone, Copy)]
pub struct WithContainer;

impl<E: HeliosEnv> AsyncCommand<E> for WithContainer {
    fn name(&self) -> &str {
        "with-container"
    }

    fn description(&self) -> &str {
        "Run a closure with external commands routed into a live Linux container."
    }

    fn signature(&self) -> Signature {
        Signature::build("with-container")
            .input_output_types(vec![(Type::Any, Type::Any)])
            .required(
                "handle",
                SyntaxShape::Any,
                "Container handle string or record returned by `container create`.",
            )
            .required(
                "block",
                SyntaxShape::Closure(None),
                "Closure to execute inside the container context.",
            )
            .category(Category::System)
    }

    async fn run_async<'a>(
        &'a self,
        ctx: &'a mut AsyncCommandContext<'_, E>,
        input: AsyncPipelineData,
    ) -> Result<AsyncPipelineData, ShellError> {
        let head = ctx.call.head;
        let handle_val: Value = ctx.call.req(ctx.engine_state, ctx.stack, 0)?;
        let closure: Closure = ctx.call.req(ctx.engine_state, ctx.stack, 1)?;
        let handle = extract_container_handle(&handle_val, head)?;

        let active = ctx
            .env
            .container_list()
            .await
            .map_err(|e| e.into_shell_error("with-container lookup failed", head))?;
        if !active.iter().any(|c| c.handle == handle) {
            return Err(generic_error(
                "unknown container handle",
                format!("no active container with handle `{handle}`"),
                head,
            ));
        }

        let mut child_scope = ctx.runtime_scope.clone();
        child_scope.container_frames.push(handle);
        let mut rt = crate::command::EvalRuntime {
            env: ctx.env,
            registry: ctx.registry,
            runtime_scope: &mut child_scope,
        };
        eval_closure_async(
            ctx.engine_state,
            ctx.stack,
            &closure,
            Vec::new(),
            input,
            &mut rt,
            head,
        )
        .await
    }
}

fn extract_container_handle(val: &Value, span: Span) -> Result<String, ShellError> {
    match val {
        Value::String { val, .. } if !val.is_empty() => Ok(val.clone()),
        Value::Record { val, .. } => val
            .get("handle")
            .ok_or_else(|| {
                generic_error(
                    "invalid container record",
                    "container record is missing `handle` field",
                    span,
                )
            })?
            .coerce_str()
            .map(std::borrow::Cow::into_owned),
        other => Err(generic_error(
            "invalid container handle",
            format!(
                "expected container handle string or record, found {}",
                other.get_type()
            ),
            span,
        )),
    }
}

fn parse_uid_gid(spec: &str, span: Span) -> Result<(Option<u32>, Option<u32>), ShellError> {
    let trimmed = spec.trim();
    if trimmed.is_empty() {
        return Ok((None, None));
    }
    match trimmed.split_once(':') {
        Some((u, g)) => {
            let uid = u.trim().parse::<u32>().map_err(|_| {
                generic_error("invalid `--user`", format!("invalid uid `{u}`"), span)
            })?;
            let gid = g.trim().parse::<u32>().map_err(|_| {
                generic_error("invalid `--user`", format!("invalid gid `{g}`"), span)
            })?;
            Ok((Some(uid), Some(gid)))
        }
        None => {
            let uid = trimmed.parse::<u32>().map_err(|_| {
                generic_error("invalid `--user`", format!("invalid uid `{trimmed}`"), span)
            })?;
            Ok((Some(uid), None))
        }
    }
}

fn parse_env_record(rec: Option<Record>) -> Result<BTreeMap<String, String>, ShellError> {
    let mut env = BTreeMap::new();
    if let Some(record) = rec {
        for (k, v) in record {
            env.insert(k, v.coerce_into_string()?);
        }
    }
    Ok(env)
}

fn parse_container_mounts(
    val: &Value,
    shell_cwd: &str,
    span: Span,
) -> Result<Vec<ContainerMountSpec>, ShellError> {
    match val {
        Value::Nothing { .. } => Ok(Vec::new()),
        Value::String { val, .. } => Ok(vec![parse_mount_spec_str(val, shell_cwd, span)?]),
        Value::Record { val, .. } => Ok(vec![parse_mount_spec_record(val, shell_cwd, span)?]),
        Value::List { vals, .. } => {
            let mut out = Vec::with_capacity(vals.len());
            for item in vals {
                match item {
                    Value::String { val, .. } => {
                        out.push(parse_mount_spec_str(val, shell_cwd, item.span())?);
                    }
                    Value::Record { val, .. } => {
                        out.push(parse_mount_spec_record(val, shell_cwd, item.span())?);
                    }
                    other => {
                        return Err(generic_error(
                            "invalid container mount entry",
                            format!("expected string or record, found {}", other.get_type()),
                            other.span(),
                        ));
                    }
                }
            }
            Ok(out)
        }
        other => Err(generic_error(
            "invalid `--mount` argument",
            format!(
                "expected string, record, or list, found {}",
                other.get_type()
            ),
            span,
        )),
    }
}

fn parse_mount_spec_str(
    raw: &str,
    shell_cwd: &str,
    span: Span,
) -> Result<ContainerMountSpec, ShellError> {
    let parts: Vec<&str> = raw.split(':').collect();
    if parts.len() < 2 || parts.len() > 4 || parts[0].is_empty() || parts[1].is_empty() {
        return Err(generic_error(
            "invalid container mount spec",
            format!("expected `source:target[:mode[:sharing]]`, got `{raw}`"),
            span,
        ));
    }
    let source_path = crate::env::normalize_vfs_path(shell_cwd, parts[0]);
    let target_path = parts[1].to_owned();
    let mode = parts.get(2).copied().unwrap_or("rw").to_owned();
    let sharing = parse_sharing(parts.get(3).copied().unwrap_or("shared"), span)?;
    Ok(ContainerMountSpec {
        source_path,
        target_path,
        mode,
        sharing,
    })
}

fn parse_mount_spec_record(
    rec: &Record,
    shell_cwd: &str,
    span: Span,
) -> Result<ContainerMountSpec, ShellError> {
    let source_raw = rec
        .get("source")
        .ok_or_else(|| generic_error("invalid mount record", "missing `source` field", span))?
        .coerce_str()?
        .into_owned();
    let target_path = rec
        .get("target")
        .ok_or_else(|| generic_error("invalid mount record", "missing `target` field", span))?
        .coerce_str()?
        .into_owned();
    let mode = match rec.get("mode") {
        Some(v) => v.coerce_str()?.into_owned(),
        None => String::from("rw"),
    };
    let sharing = match rec.get("sharing") {
        Some(v) => parse_sharing(&v.coerce_str()?, span)?,
        None => ContainerMountSharingSpec::Shared,
    };
    Ok(ContainerMountSpec {
        source_path: crate::env::normalize_vfs_path(shell_cwd, &source_raw),
        target_path,
        mode,
        sharing,
    })
}

fn parse_sharing(raw: &str, span: Span) -> Result<ContainerMountSharingSpec, ShellError> {
    match raw {
        "shared" => Ok(ContainerMountSharingSpec::Shared),
        "private" => Ok(ContainerMountSharingSpec::Private),
        "ephemeral" | "ephemeral-overlay" | "overlay" => {
            Ok(ContainerMountSharingSpec::EphemeralOverlay)
        }
        other => Err(generic_error(
            "invalid mount sharing mode",
            format!("expected `shared`, `private`, or `ephemeral-overlay`, got `{other}`"),
            span,
        )),
    }
}
