//! OCI image management commands: `oci {pull, ls, inspect, rm}`.

use nu_engine::CallExt;
use nu_protocol::{Category, Record, ShellError, Signature, Span, SyntaxShape, Type, Value};

use crate::command::{AsyncCommand, AsyncCommandContext};
use crate::env::{HeliosEnv, OciImageInspect, OciImageSummary};
use crate::pipeline::AsyncPipelineData;

fn oci_summary_columns() -> Vec<(String, Type)> {
    vec![
        ("reference".into(), Type::String),
        ("digest".into(), Type::String),
        ("arch".into(), Type::String),
        ("layers".into(), Type::Int),
        ("rootfs_path".into(), Type::String),
        ("btrfs_backed".into(), Type::Bool),
    ]
}

fn oci_summary_to_value(summary: OciImageSummary, span: Span) -> Value {
    let mut rec = Record::new();
    rec.push("reference", Value::string(summary.reference, span));
    rec.push("digest", Value::string(summary.digest, span));
    rec.push("arch", Value::string(summary.arch, span));
    rec.push(
        "layers",
        Value::int(i64::try_from(summary.layers).unwrap_or(i64::MAX), span),
    );
    rec.push("rootfs_path", Value::string(summary.rootfs_path, span));
    rec.push("btrfs_backed", Value::bool(summary.btrfs_backed, span));
    Value::record(rec, span)
}

fn oci_inspect_to_value(info: OciImageInspect, span: Span) -> Value {
    let mut env_rec = Record::new();
    for (k, v) in info.env {
        env_rec.push(k, Value::string(v, span));
    }
    let mut labels_rec = Record::new();
    for (k, v) in info.labels {
        labels_rec.push(k, Value::string(v, span));
    }
    let chain_ids: Vec<Value> = info
        .layer_chain_ids
        .into_iter()
        .map(|id| Value::string(id, span))
        .collect();
    let entrypoint: Vec<Value> = info
        .entrypoint
        .into_iter()
        .map(|s| Value::string(s, span))
        .collect();
    let cmd: Vec<Value> = info
        .cmd
        .into_iter()
        .map(|s| Value::string(s, span))
        .collect();

    let mut rec = Record::new();
    rec.push("reference", Value::string(info.reference, span));
    rec.push("digest", Value::string(info.digest, span));
    rec.push("arch", Value::string(info.arch, span));
    rec.push("os", Value::string(info.os, span));
    rec.push(
        "layers",
        Value::int(i64::try_from(chain_ids.len()).unwrap_or(i64::MAX), span),
    );
    rec.push("layer_chain_ids", Value::list(chain_ids, span));
    rec.push("rootfs_path", Value::string(info.rootfs_path, span));
    rec.push("btrfs_backed", Value::bool(info.btrfs_backed, span));
    rec.push(
        "user",
        info.user
            .map_or_else(|| Value::nothing(span), |u| Value::string(u, span)),
    );
    rec.push(
        "working_dir",
        info.working_dir
            .map_or_else(|| Value::nothing(span), |d| Value::string(d, span)),
    );
    rec.push("entrypoint", Value::list(entrypoint, span));
    rec.push("cmd", Value::list(cmd, span));
    rec.push("env", Value::record(env_rec, span));
    rec.push("labels", Value::record(labels_rec, span));
    Value::record(rec, span)
}

/// `oci`: parent namespace (lists local OCI images when invoked directly).
#[derive(Debug, Clone, Copy)]
pub struct Oci;

impl<E: HeliosEnv> AsyncCommand<E> for Oci {
    fn name(&self) -> &str {
        "oci"
    }

    fn description(&self) -> &str {
        "Pull, list, inspect, and remove OCI images in the Helios image store."
    }

    fn signature(&self) -> Signature {
        Signature::build("oci")
            .input_output_types(vec![(
                Type::Nothing,
                Type::Table(oci_summary_columns().into()),
            )])
            .category(Category::System)
    }

    async fn run_async<'a>(
        &'a self,
        ctx: &'a mut AsyncCommandContext<'_, E>,
        input: AsyncPipelineData,
    ) -> Result<AsyncPipelineData, ShellError> {
        OciLs.run_async(ctx, input).await
    }
}

/// `oci pull <ref>`: pull and materialize an OCI image into the image store.
#[derive(Debug, Clone, Copy)]
pub struct OciPull;

impl<E: HeliosEnv> AsyncCommand<E> for OciPull {
    fn name(&self) -> &str {
        "oci pull"
    }

    fn description(&self) -> &str {
        "Pull an OCI image from a registry into the Helios image store."
    }

    fn signature(&self) -> Signature {
        Signature::build("oci pull")
            .input_output_types(vec![(
                Type::Nothing,
                Type::Record(oci_summary_columns().into()),
            )])
            .named(
                "arch",
                SyntaxShape::String,
                "Target Linux architecture (amd64/x86_64 or arm64/aarch64).",
                Some('a'),
            )
            .required("ref", SyntaxShape::String, "OCI image reference.")
            .category(Category::System)
    }

    async fn run_async<'a>(
        &'a self,
        ctx: &'a mut AsyncCommandContext<'_, E>,
        _input: AsyncPipelineData,
    ) -> Result<AsyncPipelineData, ShellError> {
        let head = ctx.call.head;
        let arch: Option<String> = ctx.call.get_flag(ctx.engine_state, ctx.stack, "arch")?;
        let reference: String = ctx.call.req(ctx.engine_state, ctx.stack, 0)?;

        let summary = ctx
            .env
            .oci_pull(&reference, arch.as_deref())
            .await
            .map_err(|e| e.into_shell_error("oci pull failed", head))?;
        Ok(AsyncPipelineData::value(
            oci_summary_to_value(summary, head),
            None,
        ))
    }
}

/// `oci ls`: list pulled OCI images in the image store.
#[derive(Debug, Clone, Copy)]
pub struct OciLs;

impl<E: HeliosEnv> AsyncCommand<E> for OciLs {
    fn name(&self) -> &str {
        "oci ls"
    }

    fn description(&self) -> &str {
        "List OCI images materialized in the Helios image store."
    }

    fn signature(&self) -> Signature {
        Signature::build("oci ls")
            .input_output_types(vec![(
                Type::Nothing,
                Type::Table(oci_summary_columns().into()),
            )])
            .category(Category::System)
    }

    async fn run_async<'a>(
        &'a self,
        ctx: &'a mut AsyncCommandContext<'_, E>,
        _input: AsyncPipelineData,
    ) -> Result<AsyncPipelineData, ShellError> {
        let head = ctx.call.head;
        let images = ctx
            .env
            .oci_list()
            .await
            .map_err(|e| e.into_shell_error("oci ls failed", head))?;
        let rows = images
            .into_iter()
            .map(|img| oci_summary_to_value(img, head))
            .collect();
        Ok(AsyncPipelineData::value(Value::list(rows, head), None))
    }
}

/// `oci inspect <ref>`: inspect configuration and layers of a pulled OCI image.
#[derive(Debug, Clone, Copy)]
pub struct OciInspect;

impl<E: HeliosEnv> AsyncCommand<E> for OciInspect {
    fn name(&self) -> &str {
        "oci inspect"
    }

    fn description(&self) -> &str {
        "Inspect metadata, layers, and runtime config for a pulled OCI image."
    }

    fn signature(&self) -> Signature {
        Signature::build("oci inspect")
            .input_output_types(vec![(
                Type::Nothing,
                Type::Record(
                    vec![
                        ("reference".into(), Type::String),
                        ("digest".into(), Type::String),
                        ("arch".into(), Type::String),
                        ("os".into(), Type::String),
                        ("layers".into(), Type::Int),
                        ("layer_chain_ids".into(), Type::list(Type::String)),
                        ("rootfs_path".into(), Type::String),
                        ("btrfs_backed".into(), Type::Bool),
                        ("user".into(), Type::Any),
                        ("working_dir".into(), Type::Any),
                        ("entrypoint".into(), Type::list(Type::String)),
                        ("cmd".into(), Type::list(Type::String)),
                        ("env".into(), Type::Record(vec![].into())),
                        ("labels".into(), Type::Record(vec![].into())),
                    ]
                    .into(),
                ),
            )])
            .required("ref", SyntaxShape::String, "OCI image reference.")
            .category(Category::System)
    }

    async fn run_async<'a>(
        &'a self,
        ctx: &'a mut AsyncCommandContext<'_, E>,
        _input: AsyncPipelineData,
    ) -> Result<AsyncPipelineData, ShellError> {
        let head = ctx.call.head;
        let reference: String = ctx.call.req(ctx.engine_state, ctx.stack, 0)?;
        let info = ctx
            .env
            .oci_inspect(&reference)
            .await
            .map_err(|e| e.into_shell_error("oci inspect failed", head))?;
        Ok(AsyncPipelineData::value(
            oci_inspect_to_value(info, head),
            None,
        ))
    }
}

/// `oci rm <ref>`: remove a pulled OCI image from the image store.
#[derive(Debug, Clone, Copy)]
pub struct OciRm;

impl<E: HeliosEnv> AsyncCommand<E> for OciRm {
    fn name(&self) -> &str {
        "oci rm"
    }

    fn description(&self) -> &str {
        "Remove a pulled OCI image from the Helios image store."
    }

    fn signature(&self) -> Signature {
        Signature::build("oci rm")
            .input_output_types(vec![(Type::Nothing, Type::Nothing)])
            .required("ref", SyntaxShape::String, "OCI image reference.")
            .category(Category::System)
    }

    async fn run_async<'a>(
        &'a self,
        ctx: &'a mut AsyncCommandContext<'_, E>,
        _input: AsyncPipelineData,
    ) -> Result<AsyncPipelineData, ShellError> {
        let head = ctx.call.head;
        let reference: String = ctx.call.req(ctx.engine_state, ctx.stack, 0)?;
        ctx.env
            .oci_remove(&reference)
            .await
            .map_err(|e| e.into_shell_error("oci rm failed", head))?;
        Ok(AsyncPipelineData::Empty)
    }
}
