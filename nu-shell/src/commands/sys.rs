//! System telemetry commands (`sys`, `sys cpu`, `sys mem`, `sys net`, `sys disks`, `sys host`).

use nu_engine::CallExt;
use nu_protocol::{Category, Record, ShellError, Signature, Span, Type, Value};

use crate::command::{AsyncCommand, AsyncCommandContext};
use crate::env::{HeliosEnv, SysCpuInfo, SysDiskInfo, SysHostInfo, SysMemInfo, SysNetInfo};
use crate::pipeline::AsyncPipelineData;

/// `sys`: combined system telemetry record.
#[derive(Debug, Clone, Copy)]
pub struct Sys;

impl<E: HeliosEnv> AsyncCommand<E> for Sys {
    fn name(&self) -> &str {
        "sys"
    }

    fn description(&self) -> &str {
        "View information about the Helios system."
    }

    fn signature(&self) -> Signature {
        Signature::build("sys")
            .input_output_types(vec![(
                Type::Nothing,
                Type::Record(
                    vec![
                        ("host".into(), Type::record()),
                        ("cpu".into(), Type::table()),
                        ("mem".into(), Type::record()),
                        ("net".into(), Type::table()),
                        ("disks".into(), Type::table()),
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
        let ((host, cpus), (mem, (net, disks))) = futures_lite::future::zip(
            futures_lite::future::zip(ctx.env.sys_host(), ctx.env.sys_cpu(false)),
            futures_lite::future::zip(
                ctx.env.sys_mem(),
                futures_lite::future::zip(ctx.env.sys_net(), ctx.env.sys_disks()),
            ),
        )
        .await;
        let host = host.map_err(|e| e.into_shell_error("sys host failed", head))?;
        let cpus = cpus.map_err(|e| e.into_shell_error("sys cpu failed", head))?;
        let mem = mem.map_err(|e| e.into_shell_error("sys mem failed", head))?;
        let (net, disks) = (
            net.map_err(|e| e.into_shell_error("sys net failed", head))?,
            disks.map_err(|e| e.into_shell_error("sys disks failed", head))?,
        );

        let mut rec = Record::new();
        rec.push("host", host_to_value(host, head));
        rec.push("cpu", cpus_to_value(cpus, false, head));
        rec.push("mem", mem_to_value(mem, head));
        rec.push("net", net_to_value(net, head));
        rec.push("disks", disks_to_value(disks, head));
        Ok(AsyncPipelineData::value(Value::record(rec, head), None))
    }
}

/// `sys cpu`: per-CPU telemetry table.
#[derive(Debug, Clone, Copy)]
pub struct SysCpu;

impl<E: HeliosEnv> AsyncCommand<E> for SysCpu {
    fn name(&self) -> &str {
        "sys cpu"
    }

    fn description(&self) -> &str {
        "View information about the system CPUs."
    }

    fn signature(&self) -> Signature {
        Signature::build("sys cpu")
            .switch("long", "Include sampled CPU usage.", Some('l'))
            .input_output_types(vec![(
                Type::Nothing,
                Type::Table(
                    vec![
                        ("name".into(), Type::String),
                        ("brand".into(), Type::String),
                        ("vendor_id".into(), Type::String),
                        ("freq".into(), Type::Int),
                        ("load_average".into(), Type::String),
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
        let cpus = ctx
            .env
            .sys_cpu(long)
            .await
            .map_err(|e| e.into_shell_error("sys cpu failed", head))?;
        Ok(AsyncPipelineData::value(
            cpus_to_value(cpus, long, head),
            None,
        ))
    }
}

/// `sys mem`: memory telemetry record.
#[derive(Debug, Clone, Copy)]
pub struct SysMem;

impl<E: HeliosEnv> AsyncCommand<E> for SysMem {
    fn name(&self) -> &str {
        "sys mem"
    }

    fn description(&self) -> &str {
        "View information about the system memory."
    }

    fn signature(&self) -> Signature {
        Signature::build("sys mem")
            .input_output_types(vec![(
                Type::Nothing,
                Type::Record(
                    vec![
                        ("total".into(), Type::Filesize),
                        ("free".into(), Type::Filesize),
                        ("used".into(), Type::Filesize),
                        ("available".into(), Type::Filesize),
                        ("swap total".into(), Type::Filesize),
                        ("swap free".into(), Type::Filesize),
                        ("swap used".into(), Type::Filesize),
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
        let mem = ctx
            .env
            .sys_mem()
            .await
            .map_err(|e| e.into_shell_error("sys mem failed", head))?;
        Ok(AsyncPipelineData::value(mem_to_value(mem, head), None))
    }
}

/// `sys net`: network interface telemetry table.
#[derive(Debug, Clone, Copy)]
pub struct SysNet;

impl<E: HeliosEnv> AsyncCommand<E> for SysNet {
    fn name(&self) -> &str {
        "sys net"
    }

    fn description(&self) -> &str {
        "View information about the system network interfaces."
    }

    fn signature(&self) -> Signature {
        Signature::build("sys net")
            .input_output_types(vec![(
                Type::Nothing,
                Type::Table(
                    vec![
                        ("name".into(), Type::String),
                        ("mac".into(), Type::String),
                        ("ip".into(), Type::list(Type::String)),
                        ("sent".into(), Type::Filesize),
                        ("recv".into(), Type::Filesize),
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
        let net = ctx
            .env
            .sys_net()
            .await
            .map_err(|e| e.into_shell_error("sys net failed", head))?;
        Ok(AsyncPipelineData::value(net_to_value(net, head), None))
    }
}

/// `sys disks`: disk and mount telemetry table.
#[derive(Debug, Clone, Copy)]
pub struct SysDisks;

impl<E: HeliosEnv> AsyncCommand<E> for SysDisks {
    fn name(&self) -> &str {
        "sys disks"
    }

    fn description(&self) -> &str {
        "View information about the system disks and mounts."
    }

    fn signature(&self) -> Signature {
        Signature::build("sys disks")
            .input_output_types(vec![(
                Type::Nothing,
                Type::Table(
                    vec![
                        ("device".into(), Type::String),
                        ("type".into(), Type::String),
                        ("mount".into(), Type::String),
                        ("total".into(), Type::Filesize),
                        ("free".into(), Type::Filesize),
                        ("removable".into(), Type::Bool),
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
        let disks = ctx
            .env
            .sys_disks()
            .await
            .map_err(|e| e.into_shell_error("sys disks failed", head))?;
        Ok(AsyncPipelineData::value(disks_to_value(disks, head), None))
    }
}

/// `sys host`: host identity and uptime record.
#[derive(Debug, Clone, Copy)]
pub struct SysHost;

impl<E: HeliosEnv> AsyncCommand<E> for SysHost {
    fn name(&self) -> &str {
        "sys host"
    }

    fn description(&self) -> &str {
        "View information about the system host."
    }

    fn signature(&self) -> Signature {
        Signature::build("sys host")
            .input_output_types(vec![(
                Type::Nothing,
                Type::Record(
                    vec![
                        ("name".into(), Type::String),
                        ("os_version".into(), Type::String),
                        ("long_os_version".into(), Type::String),
                        ("kernel_version".into(), Type::String),
                        ("hostname".into(), Type::String),
                        ("uptime".into(), Type::Duration),
                        ("boot_time".into(), Type::Date),
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
        let host = ctx
            .env
            .sys_host()
            .await
            .map_err(|e| e.into_shell_error("sys host failed", head))?;
        Ok(AsyncPipelineData::value(host_to_value(host, head), None))
    }
}

fn cpus_to_value(cpus: Vec<SysCpuInfo>, long: bool, span: Span) -> Value {
    let rows = cpus
        .into_iter()
        .map(|cpu| {
            let mut rec = Record::new();
            rec.push("name", Value::string(cpu.name, span));
            rec.push("brand", Value::string(cpu.brand, span));
            rec.push("vendor_id", Value::string(cpu.vendor_id, span));
            rec.push(
                "freq",
                Value::int(i64::try_from(cpu.freq_mhz).unwrap_or(i64::MAX), span),
            );
            rec.push("load_average", Value::string(cpu.load_average, span));
            if long {
                let usage = cpu.cpu_usage.map_or_else(
                    || Value::nothing(span),
                    |u| Value::float((u * 10.0).round() / 10.0, span),
                );
                rec.push("cpu_usage", usage);
            }
            Value::record(rec, span)
        })
        .collect();
    Value::list(rows, span)
}

fn mem_to_value(mem: SysMemInfo, span: Span) -> Value {
    let to_fs = |v: u64| Value::filesize(i64::try_from(v).unwrap_or(i64::MAX), span);
    let mut rec = Record::new();
    rec.push("total", to_fs(mem.total));
    rec.push("free", to_fs(mem.free));
    rec.push("used", to_fs(mem.used));
    rec.push("available", to_fs(mem.available));
    rec.push("swap total", to_fs(mem.swap_total));
    rec.push("swap free", to_fs(mem.swap_free));
    rec.push("swap used", to_fs(mem.swap_used));
    Value::record(rec, span)
}

fn net_to_value(net: Vec<SysNetInfo>, span: Span) -> Value {
    let to_fs = |v: u64| Value::filesize(i64::try_from(v).unwrap_or(i64::MAX), span);
    let rows = net
        .into_iter()
        .map(|iface| {
            let mut rec = Record::new();
            rec.push("name", Value::string(iface.name, span));
            rec.push("mac", Value::string(iface.mac, span));
            rec.push(
                "ip",
                Value::list(
                    iface
                        .ip
                        .into_iter()
                        .map(|addr| Value::string(addr, span))
                        .collect(),
                    span,
                ),
            );
            rec.push("sent", to_fs(iface.sent));
            rec.push("recv", to_fs(iface.recv));
            Value::record(rec, span)
        })
        .collect();
    Value::list(rows, span)
}

fn disks_to_value(disks: Vec<SysDiskInfo>, span: Span) -> Value {
    let to_fs = |v: u64| Value::filesize(i64::try_from(v).unwrap_or(i64::MAX), span);
    let rows = disks
        .into_iter()
        .map(|disk| {
            let mut rec = Record::new();
            rec.push("device", Value::string(disk.device, span));
            rec.push("type", Value::string(disk.kind, span));
            rec.push("mount", Value::string(disk.mount, span));
            rec.push("total", to_fs(disk.total));
            rec.push("free", to_fs(disk.free));
            rec.push("removable", Value::bool(disk.removable, span));
            Value::record(rec, span)
        })
        .collect();
    Value::list(rows, span)
}

fn host_to_value(host: SysHostInfo, span: Span) -> Value {
    let mut rec = Record::new();
    rec.push("name", Value::string(host.name, span));
    rec.push("os_version", Value::string(host.os_version, span));
    rec.push("long_os_version", Value::string(host.long_os_version, span));
    rec.push("kernel_version", Value::string(host.kernel_version, span));
    rec.push("hostname", Value::string(host.hostname, span));
    rec.push(
        "uptime",
        Value::duration(
            i64::try_from(host.uptime.as_nanos()).unwrap_or(i64::MAX),
            span,
        ),
    );
    rec.push(
        "boot_time",
        host.boot_time
            .map_or_else(|| Value::nothing(span), |dt| Value::date(dt, span)),
    );
    Value::record(rec, span)
}
