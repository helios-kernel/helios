//! Dynamic component topology management commands:
//! `component {ls, status, start, stop, restart, add, rm}`.

use nu_engine::CallExt;
use nu_protocol::{Category, Record, ShellError, Signature, Span, SyntaxShape, Type, Value};

use crate::command::{AsyncCommand, AsyncCommandContext};
use crate::env::{ComponentAddRequest, ComponentInfo, ComponentSubtreeSource, HeliosEnv};
use crate::error::generic_error;
use crate::eval::{current_cwd_async, resolve_vfs_path};
use crate::pipeline::AsyncPipelineData;

fn component_columns() -> Vec<(String, Type)> {
    vec![
        ("moniker".into(), Type::String),
        ("program".into(), Type::String),
        ("state".into(), Type::String),
        ("instance_id".into(), Type::Any),
        ("restarts".into(), Type::Int),
    ]
}

fn component_to_value(info: ComponentInfo, span: Span) -> Value {
    let mut rec = Record::new();
    rec.push("moniker", Value::string(info.moniker, span));
    rec.push("program", Value::string(info.program, span));
    rec.push("state", Value::string(info.state, span));
    rec.push(
        "instance_id",
        info.instance_id.map_or_else(
            || Value::nothing(span),
            |id| Value::int(i64::try_from(id).unwrap_or(i64::MAX), span),
        ),
    );
    rec.push(
        "restarts",
        Value::int(i64::try_from(info.restarts).unwrap_or(i64::MAX), span),
    );
    Value::record(rec, span)
}

/// `component`: parent namespace (lists components when invoked directly).
#[derive(Debug, Clone, Copy)]
pub struct Component;

impl<E: HeliosEnv> AsyncCommand<E> for Component {
    fn name(&self) -> &str {
        "component"
    }

    fn description(&self) -> &str {
        "Manage Helios component topology and dynamic subtrees."
    }

    fn signature(&self) -> Signature {
        Signature::build("component")
            .input_output_types(vec![(
                Type::Nothing,
                Type::Table(component_columns().into()),
            )])
            .category(Category::System)
    }

    async fn run_async<'a>(
        &'a self,
        ctx: &'a mut AsyncCommandContext<'_, E>,
        input: AsyncPipelineData,
    ) -> Result<AsyncPipelineData, ShellError> {
        ComponentLs.run_async(ctx, input).await
    }
}

/// `component ls`: list configured and running components under the caller's scope.
#[derive(Debug, Clone, Copy)]
pub struct ComponentLs;

impl<E: HeliosEnv> AsyncCommand<E> for ComponentLs {
    fn name(&self) -> &str {
        "component ls"
    }

    fn description(&self) -> &str {
        "List configured and live Helios components under the authorized scope."
    }

    fn signature(&self) -> Signature {
        Signature::build("component ls")
            .input_output_types(vec![(
                Type::Nothing,
                Type::Table(component_columns().into()),
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
            .component_list()
            .await
            .map_err(|e| e.into_shell_error("component ls failed", head))?;
        let rows = items
            .into_iter()
            .map(|c| component_to_value(c, head))
            .collect();
        Ok(AsyncPipelineData::value(Value::list(rows, head), None))
    }
}

/// `component status <moniker>`: show detailed status for a single component.
#[derive(Debug, Clone, Copy)]
pub struct ComponentStatus;

impl<E: HeliosEnv> AsyncCommand<E> for ComponentStatus {
    fn name(&self) -> &str {
        "component status"
    }

    fn description(&self) -> &str {
        "Inspect the status of a Helios component by moniker."
    }

    fn signature(&self) -> Signature {
        Signature::build("component status")
            .input_output_types(vec![(
                Type::Nothing,
                Type::Record(component_columns().into()),
            )])
            .required("moniker", SyntaxShape::String, "Component moniker.")
            .category(Category::System)
    }

    async fn run_async<'a>(
        &'a self,
        ctx: &'a mut AsyncCommandContext<'_, E>,
        _input: AsyncPipelineData,
    ) -> Result<AsyncPipelineData, ShellError> {
        let head = ctx.call.head;
        let moniker: String = ctx.call.req(ctx.engine_state, ctx.stack, 0)?;
        let info = ctx
            .env
            .component_status(&moniker)
            .await
            .map_err(|e| e.into_shell_error("component status failed", head))?;
        Ok(AsyncPipelineData::value(
            component_to_value(info, head),
            None,
        ))
    }
}

/// `component start <moniker>`: start a configured component.
#[derive(Debug, Clone, Copy)]
pub struct ComponentStart;

impl<E: HeliosEnv> AsyncCommand<E> for ComponentStart {
    fn name(&self) -> &str {
        "component start"
    }

    fn description(&self) -> &str {
        "Start a configured Helios component by moniker."
    }

    fn signature(&self) -> Signature {
        Signature::build("component start")
            .input_output_types(vec![(
                Type::Nothing,
                Type::Record(component_columns().into()),
            )])
            .required("moniker", SyntaxShape::String, "Component moniker.")
            .category(Category::System)
    }

    async fn run_async<'a>(
        &'a self,
        ctx: &'a mut AsyncCommandContext<'_, E>,
        _input: AsyncPipelineData,
    ) -> Result<AsyncPipelineData, ShellError> {
        let head = ctx.call.head;
        let moniker: String = ctx.call.req(ctx.engine_state, ctx.stack, 0)?;
        let info = ctx
            .env
            .component_start(&moniker)
            .await
            .map_err(|e| e.into_shell_error("component start failed", head))?;
        Ok(AsyncPipelineData::value(
            component_to_value(info, head),
            None,
        ))
    }
}

/// `component stop <moniker>`: stop a running component.
#[derive(Debug, Clone, Copy)]
pub struct ComponentStop;

impl<E: HeliosEnv> AsyncCommand<E> for ComponentStop {
    fn name(&self) -> &str {
        "component stop"
    }

    fn description(&self) -> &str {
        "Stop a running Helios component by moniker."
    }

    fn signature(&self) -> Signature {
        Signature::build("component stop")
            .input_output_types(vec![(Type::Nothing, Type::Nothing)])
            .required("moniker", SyntaxShape::String, "Component moniker.")
            .category(Category::System)
    }

    async fn run_async<'a>(
        &'a self,
        ctx: &'a mut AsyncCommandContext<'_, E>,
        _input: AsyncPipelineData,
    ) -> Result<AsyncPipelineData, ShellError> {
        let head = ctx.call.head;
        let moniker: String = ctx.call.req(ctx.engine_state, ctx.stack, 0)?;
        ctx.env
            .component_stop(&moniker)
            .await
            .map_err(|e| e.into_shell_error("component stop failed", head))?;
        Ok(AsyncPipelineData::Empty)
    }
}

/// `component restart <moniker>`: restart a managed component.
#[derive(Debug, Clone, Copy)]
pub struct ComponentRestart;

impl<E: HeliosEnv> AsyncCommand<E> for ComponentRestart {
    fn name(&self) -> &str {
        "component restart"
    }

    fn description(&self) -> &str {
        "Restart a Helios component by moniker."
    }

    fn signature(&self) -> Signature {
        Signature::build("component restart")
            .input_output_types(vec![(
                Type::Nothing,
                Type::Record(component_columns().into()),
            )])
            .required("moniker", SyntaxShape::String, "Component moniker.")
            .category(Category::System)
    }

    async fn run_async<'a>(
        &'a self,
        ctx: &'a mut AsyncCommandContext<'_, E>,
        _input: AsyncPipelineData,
    ) -> Result<AsyncPipelineData, ShellError> {
        let head = ctx.call.head;
        let moniker: String = ctx.call.req(ctx.engine_state, ctx.stack, 0)?;
        let info = ctx
            .env
            .component_restart(&moniker)
            .await
            .map_err(|e| e.into_shell_error("component restart failed", head))?;
        Ok(AsyncPipelineData::value(
            component_to_value(info, head),
            None,
        ))
    }
}

/// `component add`: dynamically mount a component subtree from a guest directory or inline manifests.
#[derive(Debug, Clone, Copy)]
pub struct ComponentAdd;

impl<E: HeliosEnv> AsyncCommand<E> for ComponentAdd {
    fn name(&self) -> &str {
        "component add"
    }

    fn description(&self) -> &str {
        "Mount a dynamic component subtree under a parent moniker."
    }

    fn signature(&self) -> Signature {
        Signature::build("component add")
            .input_output_types(vec![(
                Type::Nothing,
                Type::Record(
                    vec![
                        ("moniker".into(), Type::String),
                        ("parent".into(), Type::String),
                    ]
                    .into(),
                ),
            )])
            .required(
                "parent",
                SyntaxShape::String,
                "Parent moniker where the dynamic subtree is mounted (e.g. `/services`).",
            )
            .optional(
                "path",
                SyntaxShape::Filepath,
                "Guest directory containing component manifests.",
            )
            .named(
                "dir",
                SyntaxShape::Filepath,
                "Guest directory containing component manifests (alternative to positional path).",
                Some('d'),
            )
            .named(
                "name",
                SyntaxShape::String,
                "Subtree root name under parent (defaults to the directory basename).",
                Some('n'),
            )
            .named(
                "manifests",
                SyntaxShape::Record(vec![].into()),
                "Inline record mapping relative manifest paths to TOML source strings.",
                Some('m'),
            )
            .category(Category::System)
    }

    async fn run_async<'a>(
        &'a self,
        ctx: &'a mut AsyncCommandContext<'_, E>,
        _input: AsyncPipelineData,
    ) -> Result<AsyncPipelineData, ShellError> {
        let head = ctx.call.head;
        let parent_moniker: String = ctx.call.req(ctx.engine_state, ctx.stack, 0)?;
        let pos_path: Option<String> = ctx.call.opt(ctx.engine_state, ctx.stack, 1)?;
        let dir_flag: Option<String> = ctx.call.get_flag(ctx.engine_state, ctx.stack, "dir")?;
        let name_flag: Option<String> = ctx.call.get_flag(ctx.engine_state, ctx.stack, "name")?;
        let manifests_flag: Option<Record> =
            ctx.call
                .get_flag(ctx.engine_state, ctx.stack, "manifests")?;

        let dir_raw = dir_flag.or(pos_path);
        let source = match (dir_raw, manifests_flag) {
            (Some(_), Some(_)) => {
                return Err(generic_error(
                    "conflicting component add sources",
                    "specify either a guest directory path or `--manifests`, not both",
                    head,
                ));
            }
            (None, None) => {
                return Err(generic_error(
                    "missing component add source",
                    "provide a guest directory path or `--manifests` record",
                    head,
                ));
            }
            (Some(raw_path), None) => {
                let cwd = current_cwd_async(ctx.engine_state, ctx.stack, ctx.env).await;
                let resolved = resolve_vfs_path(ctx.engine_state, ctx.stack, &cwd, &raw_path, true);
                let subtree_name = match name_flag {
                    Some(name) if !name.is_empty() => name,
                    _ => resolved
                        .rsplit('/')
                        .find(|seg| !seg.is_empty())
                        .ok_or_else(|| {
                            generic_error(
                                "missing subtree name",
                                "provide `--name` when mounting from `/`",
                                head,
                            )
                        })?
                        .to_owned(),
                };
                ComponentSubtreeSource::GuestDir {
                    subtree_name,
                    path: resolved,
                }
            }
            (None, Some(rec)) => {
                let mut pairs = Vec::with_capacity(rec.len());
                for (path, val) in rec {
                    let body = val.coerce_into_string()?;
                    pairs.push((path, body));
                }
                if pairs.is_empty() {
                    return Err(generic_error(
                        "empty manifests record",
                        "`--manifests` must contain at least one manifest entry",
                        head,
                    ));
                }
                ComponentSubtreeSource::Manifests(pairs)
            }
        };

        let mounted = ctx
            .env
            .component_add(ComponentAddRequest {
                parent_moniker: parent_moniker.clone(),
                source,
            })
            .await
            .map_err(|e| e.into_shell_error("component add failed", head))?;

        let mut rec = Record::new();
        rec.push("moniker", Value::string(mounted, head));
        rec.push("parent", Value::string(parent_moniker, head));
        Ok(AsyncPipelineData::value(Value::record(rec, head), None))
    }
}

/// `component rm <moniker>`: unmount and stop a dynamically mounted component subtree.
#[derive(Debug, Clone, Copy)]
pub struct ComponentRm;

impl<E: HeliosEnv> AsyncCommand<E> for ComponentRm {
    fn name(&self) -> &str {
        "component rm"
    }

    fn description(&self) -> &str {
        "Unmount a dynamically added Helios component subtree."
    }

    fn signature(&self) -> Signature {
        Signature::build("component rm")
            .input_output_types(vec![(Type::Nothing, Type::Nothing)])
            .required("moniker", SyntaxShape::String, "Mounted subtree moniker.")
            .category(Category::System)
    }

    async fn run_async<'a>(
        &'a self,
        ctx: &'a mut AsyncCommandContext<'_, E>,
        _input: AsyncPipelineData,
    ) -> Result<AsyncPipelineData, ShellError> {
        let head = ctx.call.head;
        let moniker: String = ctx.call.req(ctx.engine_state, ctx.stack, 0)?;
        ctx.env
            .component_remove(&moniker)
            .await
            .map_err(|e| e.into_shell_error("component rm failed", head))?;
        Ok(AsyncPipelineData::Empty)
    }
}
