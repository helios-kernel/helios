//! Micro-VM management commands: `vm`, `vm run [--oci <ref>]`, `vm ls`.

use nu_engine::CallExt;
use nu_protocol::{Category, Record, ShellError, Signature, Span, SyntaxShape, Type, Value};

use crate::command::{AsyncCommand, AsyncCommandContext};
use crate::env::{HeliosEnv, VmInfo, VmRunRequest, VmShareSpec, normalize_vfs_path};
use crate::error::generic_error;
use crate::eval::{current_cwd_async, resolve_vfs_path};
use crate::pipeline::AsyncPipelineData;

fn vm_columns() -> Vec<(String, Type)> {
    vec![
        ("id".into(), Type::String),
        ("name".into(), Type::String),
        ("state".into(), Type::String),
        ("cpus".into(), Type::Int),
        ("memory_mib".into(), Type::Int),
        ("oci_ref".into(), Type::Any),
        ("kernel".into(), Type::Any),
        ("exit_reason".into(), Type::Any),
    ]
}

fn vm_to_value(info: VmInfo, span: Span) -> Value {
    let mut rec = Record::new();
    rec.push("id", Value::string(info.id, span));
    rec.push("name", Value::string(info.name, span));
    rec.push("state", Value::string(info.state, span));
    rec.push("cpus", Value::int(i64::from(info.cpus), span));
    rec.push(
        "memory_mib",
        Value::int(i64::try_from(info.memory_mib).unwrap_or(i64::MAX), span),
    );
    rec.push(
        "oci_ref",
        info.oci_ref
            .map_or_else(|| Value::nothing(span), |r| Value::string(r, span)),
    );
    rec.push(
        "kernel",
        info.kernel
            .map_or_else(|| Value::nothing(span), |k| Value::string(k, span)),
    );
    rec.push(
        "exit_reason",
        info.exit_reason
            .map_or_else(|| Value::nothing(span), |r| Value::string(r, span)),
    );
    Value::record(rec, span)
}

/// `vm`: parent namespace (lists VMs when invoked directly).
#[derive(Debug, Clone, Copy)]
pub struct Vm;

impl<E: HeliosEnv> AsyncCommand<E> for Vm {
    fn name(&self) -> &str {
        "vm"
    }

    fn description(&self) -> &str {
        "Launch and list hardware-virtualized Helios micro-VMs."
    }

    fn signature(&self) -> Signature {
        Signature::build("vm")
            .input_output_types(vec![(Type::Nothing, Type::Table(vm_columns().into()))])
            .category(Category::System)
    }

    async fn run_async<'a>(
        &'a self,
        ctx: &'a mut AsyncCommandContext<'_, E>,
        input: AsyncPipelineData,
    ) -> Result<AsyncPipelineData, ShellError> {
        VmLs.run_async(ctx, input).await
    }
}

/// `vm run`: launch a micro-VM, optionally backed by an ephemeral OCI image rootfs over `virtio-fs`.
#[derive(Debug, Clone, Copy)]
pub struct VmRun;

impl<E: HeliosEnv> AsyncCommand<E> for VmRun {
    fn name(&self) -> &str {
        "vm run"
    }

    fn description(&self) -> &str {
        "Boot a hardware-virtualized micro-VM with an optional OCI image rootfs."
    }

    fn signature(&self) -> Signature {
        Signature::build("vm run")
            .input_output_types(vec![(Type::Nothing, Type::Record(vm_columns().into()))])
            .named(
                "oci",
                SyntaxShape::String,
                "OCI image reference mounted as an ephemeral writable virtio-fs rootfs.",
                None,
            )
            .named(
                "kernel",
                SyntaxShape::Filepath,
                "Path to the guest Linux kernel image.",
                Some('k'),
            )
            .named(
                "initramfs",
                SyntaxShape::Filepath,
                "Optional path to an initramfs archive.",
                None,
            )
            .named(
                "disk",
                SyntaxShape::Filepath,
                "Optional raw block disk image path.",
                None,
            )
            .named(
                "rootfs-dir",
                SyntaxShape::Filepath,
                "Explicit directory mounted as virtio-fs rootfs.",
                None,
            )
            .named(
                "share-dir",
                SyntaxShape::Any,
                "Pass-through virtio-fs share(s): `tag:path[:ro]` or list of strings/records.",
                None,
            )
            .named(
                "cpus",
                SyntaxShape::Int,
                "Number of vCPUs (default 1).",
                Some('c'),
            )
            .named(
                "memory-mib",
                SyntaxShape::Int,
                "Guest RAM size in MiB (default 128).",
                Some('m'),
            )
            .named(
                "cmdline",
                SyntaxShape::String,
                "Kernel command line override.",
                None,
            )
            .named(
                "name",
                SyntaxShape::String,
                "Display name for the VM.",
                Some('n'),
            )
            .switch(
                "detach",
                "Run the VM in the background instead of awaiting exit.",
                Some('d'),
            )
            .category(Category::System)
    }

    async fn run_async<'a>(
        &'a self,
        ctx: &'a mut AsyncCommandContext<'_, E>,
        _input: AsyncPipelineData,
    ) -> Result<AsyncPipelineData, ShellError> {
        let head = ctx.call.head;
        let oci_ref: Option<String> = ctx.call.get_flag(ctx.engine_state, ctx.stack, "oci")?;
        let kernel_raw: Option<String> =
            ctx.call.get_flag(ctx.engine_state, ctx.stack, "kernel")?;
        let initramfs_raw: Option<String> =
            ctx.call
                .get_flag(ctx.engine_state, ctx.stack, "initramfs")?;
        let disk_raw: Option<String> = ctx.call.get_flag(ctx.engine_state, ctx.stack, "disk")?;
        let rootfs_raw: Option<String> =
            ctx.call
                .get_flag(ctx.engine_state, ctx.stack, "rootfs-dir")?;
        let shares_val: Option<Value> =
            ctx.call
                .get_flag(ctx.engine_state, ctx.stack, "share-dir")?;
        let cpus_i64: Option<i64> = ctx.call.get_flag(ctx.engine_state, ctx.stack, "cpus")?;
        let mem_i64: Option<i64> = ctx
            .call
            .get_flag(ctx.engine_state, ctx.stack, "memory-mib")?;
        let cmdline: Option<String> = ctx.call.get_flag(ctx.engine_state, ctx.stack, "cmdline")?;
        let name: Option<String> = ctx.call.get_flag(ctx.engine_state, ctx.stack, "name")?;
        let detach = ctx.call.has_flag(ctx.engine_state, ctx.stack, "detach")?;

        if oci_ref.is_some() && rootfs_raw.is_some() {
            return Err(generic_error(
                "conflicting VM rootfs",
                "specify either `--oci` or `--rootfs-dir`, not both",
                head,
            ));
        }

        let cpus = match cpus_i64 {
            Some(v) if v >= 1 => u32::try_from(v).map_err(|_| {
                generic_error("invalid `--cpus`", format!("invalid vCPU count {v}"), head)
            })?,
            Some(v) => {
                return Err(generic_error(
                    "invalid `--cpus`",
                    format!("vCPU count must be at least 1, got {v}"),
                    head,
                ));
            }
            None => 1,
        };
        let memory_mib = match mem_i64 {
            Some(v) if v >= 1 => u64::try_from(v).map_err(|_| {
                generic_error(
                    "invalid `--memory-mib`",
                    format!("invalid memory size {v}"),
                    head,
                )
            })?,
            Some(v) => {
                return Err(generic_error(
                    "invalid `--memory-mib`",
                    format!("memory size must be positive, got {v}"),
                    head,
                ));
            }
            None => 128,
        };

        let cwd = current_cwd_async(ctx.engine_state, ctx.stack, ctx.env).await;
        let kernel =
            kernel_raw.map(|p| resolve_vfs_path(ctx.engine_state, ctx.stack, &cwd, &p, true));
        let initramfs =
            initramfs_raw.map(|p| resolve_vfs_path(ctx.engine_state, ctx.stack, &cwd, &p, true));
        let disk = disk_raw.map(|p| resolve_vfs_path(ctx.engine_state, ctx.stack, &cwd, &p, true));
        let rootfs_dir =
            rootfs_raw.map(|p| resolve_vfs_path(ctx.engine_state, ctx.stack, &cwd, &p, true));
        let shares = match shares_val {
            Some(val) => parse_vm_shares(&val, &cwd, head)?,
            None => Vec::new(),
        };

        let info = ctx
            .env
            .vm_run(VmRunRequest {
                name,
                oci_ref,
                kernel,
                initramfs,
                disk,
                rootfs_dir,
                shares,
                cpus,
                memory_mib,
                cmdline,
                detach,
            })
            .await
            .map_err(|e| e.into_shell_error("vm run failed", head))?;

        Ok(AsyncPipelineData::value(vm_to_value(info, head), None))
    }
}

/// `vm ls`: list running and tracked micro-VMs.
#[derive(Debug, Clone, Copy)]
pub struct VmLs;

impl<E: HeliosEnv> AsyncCommand<E> for VmLs {
    fn name(&self) -> &str {
        "vm ls"
    }

    fn description(&self) -> &str {
        "List running and tracked Helios micro-VMs."
    }

    fn signature(&self) -> Signature {
        Signature::build("vm ls")
            .input_output_types(vec![(Type::Nothing, Type::Table(vm_columns().into()))])
            .category(Category::System)
    }

    async fn run_async<'a>(
        &'a self,
        ctx: &'a mut AsyncCommandContext<'_, E>,
        _input: AsyncPipelineData,
    ) -> Result<AsyncPipelineData, ShellError> {
        let head = ctx.call.head;
        let vms = ctx
            .env
            .vm_list()
            .await
            .map_err(|e| e.into_shell_error("vm ls failed", head))?;
        let rows = vms.into_iter().map(|v| vm_to_value(v, head)).collect();
        Ok(AsyncPipelineData::value(Value::list(rows, head), None))
    }
}

fn parse_vm_shares(val: &Value, cwd: &str, span: Span) -> Result<Vec<VmShareSpec>, ShellError> {
    match val {
        Value::Nothing { .. } => Ok(Vec::new()),
        Value::String { val, .. } => Ok(vec![parse_share_str(val, cwd, span)?]),
        Value::Record { val, .. } => Ok(vec![parse_share_record(val, cwd, span)?]),
        Value::List { vals, .. } => {
            let mut out = Vec::with_capacity(vals.len());
            for item in vals {
                match item {
                    Value::String { val, .. } => out.push(parse_share_str(val, cwd, item.span())?),
                    Value::Record { val, .. } => {
                        out.push(parse_share_record(val, cwd, item.span())?);
                    }
                    other => {
                        return Err(generic_error(
                            "invalid `--share-dir` entry",
                            format!("expected string or record, found {}", other.get_type()),
                            other.span(),
                        ));
                    }
                }
            }
            Ok(out)
        }
        other => Err(generic_error(
            "invalid `--share-dir` argument",
            format!(
                "expected string, record, or list, found {}",
                other.get_type()
            ),
            span,
        )),
    }
}

fn parse_share_str(raw: &str, cwd: &str, span: Span) -> Result<VmShareSpec, ShellError> {
    let parts: Vec<&str> = raw.split(':').collect();
    if parts.len() < 2 || parts.len() > 3 || parts[0].is_empty() || parts[1].is_empty() {
        return Err(generic_error(
            "invalid `--share-dir` spec",
            format!("expected `<tag>:<path>[:ro|rw]`, got `{raw}`"),
            span,
        ));
    }
    let read_only = match parts.get(2).copied() {
        None | Some("rw") => false,
        Some("ro") => true,
        Some(other) => {
            return Err(generic_error(
                "invalid `--share-dir` mode",
                format!("expected `ro` or `rw`, got `{other}`"),
                span,
            ));
        }
    };
    Ok(VmShareSpec {
        tag: parts[0].to_owned(),
        host_path: normalize_vfs_path(cwd, parts[1]),
        read_only,
    })
}

fn parse_share_record(rec: &Record, cwd: &str, span: Span) -> Result<VmShareSpec, ShellError> {
    let tag = rec
        .get("tag")
        .ok_or_else(|| generic_error("invalid share record", "missing `tag` field", span))?
        .coerce_str()?
        .into_owned();
    let host_raw = rec
        .get("path")
        .or_else(|| rec.get("host_path"))
        .ok_or_else(|| generic_error("invalid share record", "missing `path` field", span))?
        .coerce_str()?
        .into_owned();
    let read_only = match rec.get("read_only") {
        Some(v) => v.as_bool()?,
        None => false,
    };
    Ok(VmShareSpec {
        tag,
        host_path: normalize_vfs_path(cwd, &host_raw),
        read_only,
    })
}
