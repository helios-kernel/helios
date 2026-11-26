//! Linux distribution default image commands:
//! `linux`, `linux image`, `linux image get`, `linux image set <ref>`, `linux image clear`.

use nu_engine::CallExt;
use nu_protocol::{Category, Record, ShellError, Signature, Span, SyntaxShape, Type, Value};

use crate::command::{AsyncCommand, AsyncCommandContext};
use crate::env::{HeliosEnv, LinuxImageInfo};
use crate::pipeline::AsyncPipelineData;

fn linux_image_record_type() -> Type {
    Type::Record(
        vec![
            ("principal".into(), Type::String),
            ("image_ref".into(), Type::Any),
            ("default_ref".into(), Type::String),
            ("rootfs_path".into(), Type::Any),
            ("active".into(), Type::Bool),
            ("persisted".into(), Type::Bool),
            ("env".into(), Type::Record(vec![].into())),
            ("uid".into(), Type::Any),
            ("gid".into(), Type::Any),
        ]
        .into(),
    )
}

fn linux_image_to_value(info: LinuxImageInfo, span: Span) -> Value {
    let mut env_rec = Record::new();
    for (k, v) in info.env {
        env_rec.push(k, Value::string(v, span));
    }

    let mut rec = Record::new();
    rec.push("principal", Value::string(info.principal, span));
    rec.push(
        "image_ref",
        info.image_ref
            .map_or_else(|| Value::nothing(span), |r| Value::string(r, span)),
    );
    rec.push("default_ref", Value::string(info.default_ref, span));
    rec.push(
        "rootfs_path",
        info.rootfs_path
            .map_or_else(|| Value::nothing(span), |p| Value::string(p, span)),
    );
    rec.push("active", Value::bool(info.active, span));
    rec.push("persisted", Value::bool(info.persisted, span));
    rec.push("env", Value::record(env_rec, span));
    rec.push(
        "uid",
        info.uid
            .map_or_else(|| Value::nothing(span), |u| Value::int(i64::from(u), span)),
    );
    rec.push(
        "gid",
        info.gid
            .map_or_else(|| Value::nothing(span), |g| Value::int(i64::from(g), span)),
    );
    Value::record(rec, span)
}

/// `linux`: parent namespace for Linux subsystem commands.
#[derive(Debug, Clone, Copy)]
pub struct Linux;

impl<E: HeliosEnv> AsyncCommand<E> for Linux {
    fn name(&self) -> &str {
        "linux"
    }

    fn description(&self) -> &str {
        "Manage Helios Linux subsystem settings and default distribution images."
    }

    fn signature(&self) -> Signature {
        Signature::build("linux")
            .input_output_types(vec![(Type::Nothing, Type::Record(vec![].into()))])
            .category(Category::System)
    }

    async fn run_async<'a>(
        &'a self,
        ctx: &'a mut AsyncCommandContext<'_, E>,
        _input: AsyncPipelineData,
    ) -> Result<AsyncPipelineData, ShellError> {
        let head = ctx.call.head;
        let info = ctx
            .env
            .linux_image_get()
            .await
            .map_err(|e| e.into_shell_error("linux failed", head))?;
        let mut rec = Record::new();
        rec.push("image", linux_image_to_value(info, head));
        Ok(AsyncPipelineData::value(Value::record(rec, head), None))
    }
}

/// `linux image`: inspect or manage the per-user default Linux root image.
#[derive(Debug, Clone, Copy)]
pub struct LinuxImage;

impl<E: HeliosEnv> AsyncCommand<E> for LinuxImage {
    fn name(&self) -> &str {
        "linux image"
    }

    fn description(&self) -> &str {
        "Inspect or configure the current user's default Linux root image."
    }

    fn signature(&self) -> Signature {
        Signature::build("linux image")
            .input_output_types(vec![(Type::Nothing, linux_image_record_type())])
            .category(Category::System)
    }

    async fn run_async<'a>(
        &'a self,
        ctx: &'a mut AsyncCommandContext<'_, E>,
        _input: AsyncPipelineData,
    ) -> Result<AsyncPipelineData, ShellError> {
        let head = ctx.call.head;
        let info = ctx
            .env
            .linux_image_get()
            .await
            .map_err(|e| e.into_shell_error("linux image failed", head))?;
        Ok(AsyncPipelineData::value(
            linux_image_to_value(info, head),
            None,
        ))
    }
}

/// `linux image get`: return the current user's default Linux root image.
#[derive(Debug, Clone, Copy)]
pub struct LinuxImageGet;

impl<E: HeliosEnv> AsyncCommand<E> for LinuxImageGet {
    fn name(&self) -> &str {
        "linux image get"
    }

    fn description(&self) -> &str {
        "Get the current login identity's active and persisted default Linux image."
    }

    fn signature(&self) -> Signature {
        Signature::build("linux image get")
            .input_output_types(vec![(Type::Nothing, linux_image_record_type())])
            .category(Category::System)
    }

    async fn run_async<'a>(
        &'a self,
        ctx: &'a mut AsyncCommandContext<'_, E>,
        _input: AsyncPipelineData,
    ) -> Result<AsyncPipelineData, ShellError> {
        let head = ctx.call.head;
        let info = ctx
            .env
            .linux_image_get()
            .await
            .map_err(|e| e.into_shell_error("linux image get failed", head))?;
        Ok(AsyncPipelineData::value(
            linux_image_to_value(info, head),
            None,
        ))
    }
}

/// `linux image set <ref>`: pull (if needed), persist per login identity, and activate a default Linux image.
#[derive(Debug, Clone, Copy)]
pub struct LinuxImageSet;

impl<E: HeliosEnv> AsyncCommand<E> for LinuxImageSet {
    fn name(&self) -> &str {
        "linux image set"
    }

    fn description(&self) -> &str {
        "Set, persist, and activate the default Linux OCI image for the current user."
    }

    fn signature(&self) -> Signature {
        Signature::build("linux image set")
            .input_output_types(vec![(Type::Nothing, linux_image_record_type())])
            .named(
                "arch",
                SyntaxShape::String,
                "Target Linux architecture (amd64/x86_64 or arm64/aarch64).",
                Some('a'),
            )
            .required(
                "ref",
                SyntaxShape::String,
                "OCI image reference (e.g. alpine, ubuntu:24.04).",
            )
            .category(Category::System)
    }

    async fn run_async<'a>(
        &'a self,
        ctx: &'a mut AsyncCommandContext<'_, E>,
        _input: AsyncPipelineData,
    ) -> Result<AsyncPipelineData, ShellError> {
        let head = ctx.call.head;
        let arch: Option<String> = ctx.call.get_flag(ctx.engine_state, ctx.stack, "arch")?;
        let image_ref: String = ctx.call.req(ctx.engine_state, ctx.stack, 0)?;

        let info = ctx
            .env
            .linux_image_set(&image_ref, arch.as_deref())
            .await
            .map_err(|e| e.into_shell_error("linux image set failed", head))?;
        Ok(AsyncPipelineData::value(
            linux_image_to_value(info, head),
            None,
        ))
    }
}

/// `linux image clear`: clear the persisted and active default Linux image.
#[derive(Debug, Clone, Copy)]
pub struct LinuxImageClear;

impl<E: HeliosEnv> AsyncCommand<E> for LinuxImageClear {
    fn name(&self) -> &str {
        "linux image clear"
    }

    fn description(&self) -> &str {
        "Clear the current login identity's persisted and active default Linux image."
    }

    fn signature(&self) -> Signature {
        Signature::build("linux image clear")
            .input_output_types(vec![(
                Type::Nothing,
                Type::Record(
                    vec![
                        ("principal".into(), Type::String),
                        ("cleared".into(), Type::Bool),
                        ("previous_ref".into(), Type::Any),
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
        let res = ctx
            .env
            .linux_image_clear()
            .await
            .map_err(|e| e.into_shell_error("linux image clear failed", head))?;
        let mut rec = Record::new();
        rec.push("principal", Value::string(res.principal, head));
        rec.push("cleared", Value::bool(res.cleared, head));
        rec.push(
            "previous_ref",
            res.previous_ref
                .map_or_else(|| Value::nothing(head), |r| Value::string(r, head)),
        );
        Ok(AsyncPipelineData::value(Value::record(rec, head), None))
    }
}
