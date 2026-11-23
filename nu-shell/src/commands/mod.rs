//! Helios-native async commands and async-aware Nushell combinators.

pub mod external;
pub mod fs;
pub mod http;
pub mod process;
pub mod random;
pub mod sys;

use nu_engine::CallExt;
use nu_protocol::engine::{Closure, StateWorkingSet};
use nu_protocol::{Category, Record, ShellError, Signature, SyntaxShape, Type, Value};

use crate::command::{AsyncCommand, AsyncCommandContext, AsyncCommandRegistry};
use crate::env::HeliosEnv;
use crate::eval::eval_closure_async;
use crate::pipeline::{AsyncPipelineData, collect_byte_receiver};

/// Concrete dispatch enum of every built-in Helios async command (no dynamic dispatch).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AsyncBuiltin {
    // External execution & grants
    RunExternal,
    WithGrants,
    Which,
    // System telemetry
    Sys,
    SysCpu,
    SysMem,
    SysNet,
    SysDisks,
    SysHost,
    // Processes, inspection, scopes, snapshots, profiling
    Inspect,
    Ps,
    Kill,
    Whoami,
    Sleep,
    Clear,
    WithScope,
    WithSnapshot,
    WithInstructionProfile,
    // Capability-bounded VFS
    Cd,
    Ls,
    Open,
    Save,
    Mkdir,
    Rm,
    Cp,
    Mv,
    Touch,
    Glob,
    Watch,
    // HTTP (zenwave)
    Http,
    HttpGet,
    HttpPost,
    HttpPut,
    HttpPatch,
    HttpDelete,
    HttpHead,
    HttpOptions,
    // CSPRNG random
    Random,
    RandomInt,
    RandomFloat,
    RandomBool,
    RandomChars,
    RandomBinary,
    RandomUuid,
    // Async-capable combinators so closures can call async commands without block_on
    Do,
    Each,
    ParEach,
    Where,
    WithEnv,
    Complete,
    Print,
}

impl AsyncBuiltin {
    /// All built-in async commands registered into a Helios Nushell [`EngineState`].
    pub const ALL: &'static [Self] = &[
        Self::RunExternal,
        Self::WithGrants,
        Self::Which,
        Self::Sys,
        Self::SysCpu,
        Self::SysMem,
        Self::SysNet,
        Self::SysDisks,
        Self::SysHost,
        Self::Inspect,
        Self::Ps,
        Self::Kill,
        Self::Whoami,
        Self::Sleep,
        Self::Clear,
        Self::WithScope,
        Self::WithSnapshot,
        Self::WithInstructionProfile,
        Self::Cd,
        Self::Ls,
        Self::Open,
        Self::Save,
        Self::Mkdir,
        Self::Rm,
        Self::Cp,
        Self::Mv,
        Self::Touch,
        Self::Glob,
        Self::Watch,
        Self::Http,
        Self::HttpGet,
        Self::HttpPost,
        Self::HttpPut,
        Self::HttpPatch,
        Self::HttpDelete,
        Self::HttpHead,
        Self::HttpOptions,
        Self::Random,
        Self::RandomInt,
        Self::RandomFloat,
        Self::RandomBool,
        Self::RandomChars,
        Self::RandomBinary,
        Self::RandomUuid,
        Self::Do,
        Self::Each,
        Self::ParEach,
        Self::Where,
        Self::WithEnv,
        Self::Complete,
        Self::Print,
    ];

    /// Command name as registered in Nushell.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::RunExternal => "run-external",
            Self::WithGrants => "with-grants",
            Self::Which => "which",
            Self::Sys => "sys",
            Self::SysCpu => "sys cpu",
            Self::SysMem => "sys mem",
            Self::SysNet => "sys net",
            Self::SysDisks => "sys disks",
            Self::SysHost => "sys host",
            Self::Inspect => "inspect",
            Self::Ps => "ps",
            Self::Kill => "kill",
            Self::Whoami => "whoami",
            Self::Sleep => "sleep",
            Self::Clear => "clear",
            Self::WithScope => "with-scope",
            Self::WithSnapshot => "with-snapshot",
            Self::WithInstructionProfile => "with-instruction-profile",
            Self::Cd => "cd",
            Self::Ls => "ls",
            Self::Open => "open",
            Self::Save => "save",
            Self::Mkdir => "mkdir",
            Self::Rm => "rm",
            Self::Cp => "cp",
            Self::Mv => "mv",
            Self::Touch => "touch",
            Self::Glob => "glob",
            Self::Watch => "watch",
            Self::Http => "http",
            Self::HttpGet => "http get",
            Self::HttpPost => "http post",
            Self::HttpPut => "http put",
            Self::HttpPatch => "http patch",
            Self::HttpDelete => "http delete",
            Self::HttpHead => "http head",
            Self::HttpOptions => "http options",
            Self::Random => "random",
            Self::RandomInt => "random int",
            Self::RandomFloat => "random float",
            Self::RandomBool => "random bool",
            Self::RandomChars => "random chars",
            Self::RandomBinary => "random binary",
            Self::RandomUuid => "random uuid",
            Self::Do => "do",
            Self::Each => "each",
            Self::ParEach => "par-each",
            Self::Where => "where",
            Self::WithEnv => "with-env",
            Self::Complete => "complete",
            Self::Print => "print",
        }
    }

    /// Signature of this built-in command.
    #[must_use]
    pub fn signature(self) -> Signature {
        // Dispatch via a zero-sized marker env type because signatures are env-independent.
        self.signature_for::<SignatureOnlyEnv>()
    }

    fn signature_for<E: HeliosEnv>(self) -> Signature {
        match self {
            Self::RunExternal => {
                <external::RunExternal as AsyncCommand<E>>::signature(&external::RunExternal)
            }
            Self::WithGrants => {
                <external::WithGrants as AsyncCommand<E>>::signature(&external::WithGrants)
            }
            Self::Which => <external::Which as AsyncCommand<E>>::signature(&external::Which),
            Self::Sys => <sys::Sys as AsyncCommand<E>>::signature(&sys::Sys),
            Self::SysCpu => <sys::SysCpu as AsyncCommand<E>>::signature(&sys::SysCpu),
            Self::SysMem => <sys::SysMem as AsyncCommand<E>>::signature(&sys::SysMem),
            Self::SysNet => <sys::SysNet as AsyncCommand<E>>::signature(&sys::SysNet),
            Self::SysDisks => <sys::SysDisks as AsyncCommand<E>>::signature(&sys::SysDisks),
            Self::SysHost => <sys::SysHost as AsyncCommand<E>>::signature(&sys::SysHost),
            Self::Inspect => {
                <process::HeliosInspect as AsyncCommand<E>>::signature(&process::HeliosInspect)
            }
            Self::Ps => <process::Ps as AsyncCommand<E>>::signature(&process::Ps),
            Self::Kill => <process::Kill as AsyncCommand<E>>::signature(&process::Kill),
            Self::Whoami => <process::Whoami as AsyncCommand<E>>::signature(&process::Whoami),
            Self::Sleep => <process::Sleep as AsyncCommand<E>>::signature(&process::Sleep),
            Self::Clear => <process::Clear as AsyncCommand<E>>::signature(&process::Clear),
            Self::WithScope => {
                <process::WithScope as AsyncCommand<E>>::signature(&process::WithScope)
            }
            Self::WithSnapshot => {
                <process::WithSnapshot as AsyncCommand<E>>::signature(&process::WithSnapshot)
            }
            Self::WithInstructionProfile => {
                <process::WithInstructionProfile as AsyncCommand<E>>::signature(
                    &process::WithInstructionProfile,
                )
            }
            Self::Cd => <fs::Cd as AsyncCommand<E>>::signature(&fs::Cd),
            Self::Ls => <fs::Ls as AsyncCommand<E>>::signature(&fs::Ls),
            Self::Open => <fs::Open as AsyncCommand<E>>::signature(&fs::Open),
            Self::Save => <fs::Save as AsyncCommand<E>>::signature(&fs::Save),
            Self::Mkdir => <fs::Mkdir as AsyncCommand<E>>::signature(&fs::Mkdir),
            Self::Rm => <fs::Rm as AsyncCommand<E>>::signature(&fs::Rm),
            Self::Cp => <fs::Cp as AsyncCommand<E>>::signature(&fs::Cp),
            Self::Mv => <fs::Mv as AsyncCommand<E>>::signature(&fs::Mv),
            Self::Touch => <fs::Touch as AsyncCommand<E>>::signature(&fs::Touch),
            Self::Glob => <fs::Glob as AsyncCommand<E>>::signature(&fs::Glob),
            Self::Watch => <fs::Watch as AsyncCommand<E>>::signature(&fs::Watch),
            Self::Http => <http::Http as AsyncCommand<E>>::signature(&http::Http),
            Self::HttpGet => <http::HttpGet as AsyncCommand<E>>::signature(&http::HttpGet),
            Self::HttpPost => <http::HttpPost as AsyncCommand<E>>::signature(&http::HttpPost),
            Self::HttpPut => <http::HttpPut as AsyncCommand<E>>::signature(&http::HttpPut),
            Self::HttpPatch => <http::HttpPatch as AsyncCommand<E>>::signature(&http::HttpPatch),
            Self::HttpDelete => <http::HttpDelete as AsyncCommand<E>>::signature(&http::HttpDelete),
            Self::HttpHead => <http::HttpHead as AsyncCommand<E>>::signature(&http::HttpHead),
            Self::HttpOptions => {
                <http::HttpOptions as AsyncCommand<E>>::signature(&http::HttpOptions)
            }
            Self::Random => <random::Random as AsyncCommand<E>>::signature(&random::Random),
            Self::RandomInt => {
                <random::RandomInt as AsyncCommand<E>>::signature(&random::RandomInt)
            }
            Self::RandomFloat => {
                <random::RandomFloat as AsyncCommand<E>>::signature(&random::RandomFloat)
            }
            Self::RandomBool => {
                <random::RandomBool as AsyncCommand<E>>::signature(&random::RandomBool)
            }
            Self::RandomChars => {
                <random::RandomChars as AsyncCommand<E>>::signature(&random::RandomChars)
            }
            Self::RandomBinary => {
                <random::RandomBinary as AsyncCommand<E>>::signature(&random::RandomBinary)
            }
            Self::RandomUuid => {
                <random::RandomUuid as AsyncCommand<E>>::signature(&random::RandomUuid)
            }
            Self::Do => <AsyncDo as AsyncCommand<E>>::signature(&AsyncDo),
            Self::Each => <AsyncEach as AsyncCommand<E>>::signature(&AsyncEach),
            Self::ParEach => <AsyncParEach as AsyncCommand<E>>::signature(&AsyncParEach),
            Self::Where => <AsyncWhere as AsyncCommand<E>>::signature(&AsyncWhere),
            Self::WithEnv => <AsyncWithEnv as AsyncCommand<E>>::signature(&AsyncWithEnv),
            Self::Complete => <AsyncComplete as AsyncCommand<E>>::signature(&AsyncComplete),
            Self::Print => <AsyncPrint as AsyncCommand<E>>::signature(&AsyncPrint),
        }
    }

    #[must_use]
    pub fn description(self) -> &'static str {
        self.description_for::<SignatureOnlyEnv>()
    }

    fn description_for<E: HeliosEnv>(self) -> &'static str {
        match self {
            Self::RunExternal => {
                <external::RunExternal as AsyncCommand<E>>::description(&external::RunExternal)
            }
            Self::WithGrants => {
                <external::WithGrants as AsyncCommand<E>>::description(&external::WithGrants)
            }
            Self::Which => <external::Which as AsyncCommand<E>>::description(&external::Which),
            Self::Sys => <sys::Sys as AsyncCommand<E>>::description(&sys::Sys),
            Self::SysCpu => <sys::SysCpu as AsyncCommand<E>>::description(&sys::SysCpu),
            Self::SysMem => <sys::SysMem as AsyncCommand<E>>::description(&sys::SysMem),
            Self::SysNet => <sys::SysNet as AsyncCommand<E>>::description(&sys::SysNet),
            Self::SysDisks => <sys::SysDisks as AsyncCommand<E>>::description(&sys::SysDisks),
            Self::SysHost => <sys::SysHost as AsyncCommand<E>>::description(&sys::SysHost),
            Self::Inspect => {
                <process::HeliosInspect as AsyncCommand<E>>::description(&process::HeliosInspect)
            }
            Self::Ps => <process::Ps as AsyncCommand<E>>::description(&process::Ps),
            Self::Kill => <process::Kill as AsyncCommand<E>>::description(&process::Kill),
            Self::Whoami => <process::Whoami as AsyncCommand<E>>::description(&process::Whoami),
            Self::Sleep => <process::Sleep as AsyncCommand<E>>::description(&process::Sleep),
            Self::Clear => <process::Clear as AsyncCommand<E>>::description(&process::Clear),
            Self::WithScope => {
                <process::WithScope as AsyncCommand<E>>::description(&process::WithScope)
            }
            Self::WithSnapshot => {
                <process::WithSnapshot as AsyncCommand<E>>::description(&process::WithSnapshot)
            }
            Self::WithInstructionProfile => {
                <process::WithInstructionProfile as AsyncCommand<E>>::description(
                    &process::WithInstructionProfile,
                )
            }
            Self::Cd => <fs::Cd as AsyncCommand<E>>::description(&fs::Cd),
            Self::Ls => <fs::Ls as AsyncCommand<E>>::description(&fs::Ls),
            Self::Open => <fs::Open as AsyncCommand<E>>::description(&fs::Open),
            Self::Save => <fs::Save as AsyncCommand<E>>::description(&fs::Save),
            Self::Mkdir => <fs::Mkdir as AsyncCommand<E>>::description(&fs::Mkdir),
            Self::Rm => <fs::Rm as AsyncCommand<E>>::description(&fs::Rm),
            Self::Cp => <fs::Cp as AsyncCommand<E>>::description(&fs::Cp),
            Self::Mv => <fs::Mv as AsyncCommand<E>>::description(&fs::Mv),
            Self::Touch => <fs::Touch as AsyncCommand<E>>::description(&fs::Touch),
            Self::Glob => <fs::Glob as AsyncCommand<E>>::description(&fs::Glob),
            Self::Watch => <fs::Watch as AsyncCommand<E>>::description(&fs::Watch),
            Self::Http => <http::Http as AsyncCommand<E>>::description(&http::Http),
            Self::HttpGet => <http::HttpGet as AsyncCommand<E>>::description(&http::HttpGet),
            Self::HttpPost => <http::HttpPost as AsyncCommand<E>>::description(&http::HttpPost),
            Self::HttpPut => <http::HttpPut as AsyncCommand<E>>::description(&http::HttpPut),
            Self::HttpPatch => <http::HttpPatch as AsyncCommand<E>>::description(&http::HttpPatch),
            Self::HttpDelete => {
                <http::HttpDelete as AsyncCommand<E>>::description(&http::HttpDelete)
            }
            Self::HttpHead => <http::HttpHead as AsyncCommand<E>>::description(&http::HttpHead),
            Self::HttpOptions => {
                <http::HttpOptions as AsyncCommand<E>>::description(&http::HttpOptions)
            }
            Self::Random => <random::Random as AsyncCommand<E>>::description(&random::Random),
            Self::RandomInt => {
                <random::RandomInt as AsyncCommand<E>>::description(&random::RandomInt)
            }
            Self::RandomFloat => {
                <random::RandomFloat as AsyncCommand<E>>::description(&random::RandomFloat)
            }
            Self::RandomBool => {
                <random::RandomBool as AsyncCommand<E>>::description(&random::RandomBool)
            }
            Self::RandomChars => {
                <random::RandomChars as AsyncCommand<E>>::description(&random::RandomChars)
            }
            Self::RandomBinary => {
                <random::RandomBinary as AsyncCommand<E>>::description(&random::RandomBinary)
            }
            Self::RandomUuid => {
                <random::RandomUuid as AsyncCommand<E>>::description(&random::RandomUuid)
            }
            Self::Do => <AsyncDo as AsyncCommand<E>>::description(&AsyncDo),
            Self::Each => <AsyncEach as AsyncCommand<E>>::description(&AsyncEach),
            Self::ParEach => <AsyncParEach as AsyncCommand<E>>::description(&AsyncParEach),
            Self::Where => <AsyncWhere as AsyncCommand<E>>::description(&AsyncWhere),
            Self::WithEnv => <AsyncWithEnv as AsyncCommand<E>>::description(&AsyncWithEnv),
            Self::Complete => <AsyncComplete as AsyncCommand<E>>::description(&AsyncComplete),
            Self::Print => <AsyncPrint as AsyncCommand<E>>::description(&AsyncPrint),
        }
    }

    #[must_use]
    pub fn extra_description(self) -> &'static str {
        ""
    }

    #[must_use]
    pub fn search_terms(self) -> Vec<&'static str> {
        match self {
            Self::RunExternal => vec!["exec", "spawn", "external", "process"],
            Self::Inspect => vec!["telemetry", "diagnostics", "state", "moniker"],
            Self::Open => vec!["load", "read", "cat"],
            Self::HttpGet
            | Self::HttpPost
            | Self::HttpPut
            | Self::HttpPatch
            | Self::HttpDelete
            | Self::HttpHead
            | Self::HttpOptions => vec!["network", "http", "zenwave", "request"],
            _ => Vec::new(),
        }
    }

    /// Execute this command asynchronously against `ctx`.
    pub async fn run_async<E: HeliosEnv>(
        self,
        ctx: &mut AsyncCommandContext<'_, E>,
        input: AsyncPipelineData,
    ) -> Result<AsyncPipelineData, ShellError> {
        match self {
            Self::RunExternal => external::RunExternal.run_async(ctx, input).await,
            Self::WithGrants => external::WithGrants.run_async(ctx, input).await,
            Self::Which => external::Which.run_async(ctx, input).await,
            Self::Sys => sys::Sys.run_async(ctx, input).await,
            Self::SysCpu => sys::SysCpu.run_async(ctx, input).await,
            Self::SysMem => sys::SysMem.run_async(ctx, input).await,
            Self::SysNet => sys::SysNet.run_async(ctx, input).await,
            Self::SysDisks => sys::SysDisks.run_async(ctx, input).await,
            Self::SysHost => sys::SysHost.run_async(ctx, input).await,
            Self::Inspect => process::HeliosInspect.run_async(ctx, input).await,
            Self::Ps => process::Ps.run_async(ctx, input).await,
            Self::Kill => process::Kill.run_async(ctx, input).await,
            Self::Whoami => process::Whoami.run_async(ctx, input).await,
            Self::Sleep => process::Sleep.run_async(ctx, input).await,
            Self::Clear => process::Clear.run_async(ctx, input).await,
            Self::WithScope => process::WithScope.run_async(ctx, input).await,
            Self::WithSnapshot => process::WithSnapshot.run_async(ctx, input).await,
            Self::WithInstructionProfile => {
                process::WithInstructionProfile.run_async(ctx, input).await
            }
            Self::Cd => fs::Cd.run_async(ctx, input).await,
            Self::Ls => fs::Ls.run_async(ctx, input).await,
            Self::Open => fs::Open.run_async(ctx, input).await,
            Self::Save => fs::Save.run_async(ctx, input).await,
            Self::Mkdir => fs::Mkdir.run_async(ctx, input).await,
            Self::Rm => fs::Rm.run_async(ctx, input).await,
            Self::Cp => fs::Cp.run_async(ctx, input).await,
            Self::Mv => fs::Mv.run_async(ctx, input).await,
            Self::Touch => fs::Touch.run_async(ctx, input).await,
            Self::Glob => fs::Glob.run_async(ctx, input).await,
            Self::Watch => fs::Watch.run_async(ctx, input).await,
            Self::Http => http::Http.run_async(ctx, input).await,
            Self::HttpGet => http::HttpGet.run_async(ctx, input).await,
            Self::HttpPost => http::HttpPost.run_async(ctx, input).await,
            Self::HttpPut => http::HttpPut.run_async(ctx, input).await,
            Self::HttpPatch => http::HttpPatch.run_async(ctx, input).await,
            Self::HttpDelete => http::HttpDelete.run_async(ctx, input).await,
            Self::HttpHead => http::HttpHead.run_async(ctx, input).await,
            Self::HttpOptions => http::HttpOptions.run_async(ctx, input).await,
            Self::Random => random::Random.run_async(ctx, input).await,
            Self::RandomInt => random::RandomInt.run_async(ctx, input).await,
            Self::RandomFloat => random::RandomFloat.run_async(ctx, input).await,
            Self::RandomBool => random::RandomBool.run_async(ctx, input).await,
            Self::RandomChars => random::RandomChars.run_async(ctx, input).await,
            Self::RandomBinary => random::RandomBinary.run_async(ctx, input).await,
            Self::RandomUuid => random::RandomUuid.run_async(ctx, input).await,
            Self::Do => AsyncDo.run_async(ctx, input).await,
            Self::Each => AsyncEach.run_async(ctx, input).await,
            Self::ParEach => AsyncParEach.run_async(ctx, input).await,
            Self::Where => AsyncWhere.run_async(ctx, input).await,
            Self::WithEnv => AsyncWithEnv.run_async(ctx, input).await,
            Self::Complete => AsyncComplete.run_async(ctx, input).await,
            Self::Print => AsyncPrint.run_async(ctx, input).await,
        }
    }
}

/// Register every Helios async command into `working_set` and `registry`.
pub fn register_helios_commands(
    working_set: &mut StateWorkingSet<'_>,
    registry: &mut AsyncCommandRegistry,
) {
    for &cmd in AsyncBuiltin::ALL {
        registry.register(working_set, cmd);
    }
}

/// Async-aware `do` command so closures containing async Helios calls execute without `block_on`.
#[derive(Debug, Clone, Copy)]
pub struct AsyncDo;

impl<E: HeliosEnv> AsyncCommand<E> for AsyncDo {
    fn name(&self) -> &str {
        "do"
    }

    fn description(&self) -> &str {
        "Run a closure asynchronously."
    }

    fn signature(&self) -> Signature {
        Signature::build("do")
            .input_output_types(vec![(Type::Any, Type::Any)])
            .switch(
                "ignore-errors",
                "Ignore errors produced by the closure.",
                Some('i'),
            )
            .switch(
                "env",
                "Keep environment changes made by the closure.",
                Some('c'),
            )
            .required("block", SyntaxShape::Closure(None), "The closure to run.")
            .rest(
                "rest",
                SyntaxShape::Any,
                "Arguments to pass to the closure.",
            )
            .category(Category::Core)
    }

    async fn run_async<'a>(
        &'a self,
        ctx: &'a mut AsyncCommandContext<'_, E>,
        input: AsyncPipelineData,
    ) -> Result<AsyncPipelineData, ShellError> {
        let head = ctx.call.head;
        let ignore_errors = ctx
            .call
            .has_flag(ctx.engine_state, ctx.stack, "ignore-errors")?;
        let capture_env = ctx.call.has_flag(ctx.engine_state, ctx.stack, "env")?;
        let closure: Closure = ctx.call.req(ctx.engine_state, ctx.stack, 0)?;
        let args: Vec<Value> = ctx.call.rest(ctx.engine_state, ctx.stack, 1)?;

        let mut rt = crate::command::EvalRuntime {
            env: ctx.env,
            registry: ctx.registry,
            runtime_scope: ctx.runtime_scope,
        };
        let result = if capture_env {
            crate::eval::eval_closure_redirect_env_async(
                ctx.engine_state,
                ctx.stack,
                &closure,
                args,
                input,
                &mut rt,
                head,
            )
            .await
        } else {
            eval_closure_async(
                ctx.engine_state,
                ctx.stack,
                &closure,
                args,
                input,
                &mut rt,
                head,
            )
            .await
        };

        match result {
            Ok(out) => Ok(out),
            Err(_) if ignore_errors => Ok(AsyncPipelineData::Empty),
            Err(err) => Err(err),
        }
    }
}

/// Async-aware `each` command supporting streaming async pipelines and async closures.
#[derive(Debug, Clone, Copy)]
pub struct AsyncEach;

impl<E: HeliosEnv> AsyncCommand<E> for AsyncEach {
    fn name(&self) -> &str {
        "each"
    }

    fn description(&self) -> &str {
        "Run a closure on each row of the input list or stream asynchronously."
    }

    fn signature(&self) -> Signature {
        Signature::build("each")
            .input_output_types(vec![
                (Type::list(Type::Any), Type::list(Type::Any)),
                (Type::table(), Type::list(Type::Any)),
                (Type::Any, Type::Any),
            ])
            .switch(
                "keep-empty",
                "Keep empty/null results in output.",
                Some('k'),
            )
            .switch("flatten", "Flatten nested list outputs.", Some('f'))
            .required(
                "closure",
                SyntaxShape::Closure(Some(vec![SyntaxShape::Any])),
                "The closure to run on each element.",
            )
            .category(Category::Filters)
    }

    async fn run_async<'a>(
        &'a self,
        ctx: &'a mut AsyncCommandContext<'_, E>,
        input: AsyncPipelineData,
    ) -> Result<AsyncPipelineData, ShellError> {
        let head = ctx.call.head;
        let keep_empty = ctx
            .call
            .has_flag(ctx.engine_state, ctx.stack, "keep-empty")?;
        let flatten = ctx.call.has_flag(ctx.engine_state, ctx.stack, "flatten")?;
        let closure: Closure = ctx.call.req(ctx.engine_state, ctx.stack, 0)?;

        let (rx, span, metadata) = input.into_list_stream_receiver(head).await?;
        let mut results = Vec::new();
        while let Ok(item) = rx.recv().await {
            if let Value::Error { error, .. } = item {
                return Err(*error);
            }
            let mut rt = crate::command::EvalRuntime {
                env: ctx.env,
                registry: ctx.registry,
                runtime_scope: ctx.runtime_scope,
            };
            let out = eval_closure_async(
                ctx.engine_state,
                ctx.stack,
                &closure,
                vec![item.clone()],
                AsyncPipelineData::value(item, None),
                &mut rt,
                head,
            )
            .await?;
            let val = out.into_value_async(head).await?;
            if val.is_nothing() && !keep_empty {
                continue;
            }
            if flatten {
                if let Value::List { vals, .. } = val {
                    results.extend(vals);
                } else {
                    results.push(val);
                }
            } else {
                results.push(val);
            }
        }

        Ok(AsyncPipelineData::value(
            Value::list(results, span),
            metadata,
        ))
    }
}

/// Async-native `par-each` command executing closures concurrently on the
/// active async executor without spawning OS threads (works on single-threaded
/// `wasm32-wasip3` as well as host targets).
#[derive(Debug, Clone, Copy)]
pub struct AsyncParEach;

impl<E: HeliosEnv> AsyncCommand<E> for AsyncParEach {
    fn name(&self) -> &str {
        "par-each"
    }

    fn description(&self) -> &str {
        "Run a closure on each row of the input list concurrently via async tasks."
    }

    fn signature(&self) -> Signature {
        Signature::build("par-each")
            .input_output_types(vec![
                (Type::list(Type::Any), Type::list(Type::Any)),
                (Type::table(), Type::list(Type::Any)),
                (Type::Any, Type::Any),
            ])
            .switch(
                "keep-order",
                "Keep sequence of output same as the order of input.",
                Some('k'),
            )
            .named(
                "threads",
                SyntaxShape::Int,
                "Maximum number of concurrent tasks (advisory).",
                Some('t'),
            )
            .required(
                "closure",
                SyntaxShape::Closure(Some(vec![SyntaxShape::Any])),
                "The closure to run on each element.",
            )
            .category(Category::Filters)
    }

    async fn run_async<'a>(
        &'a self,
        ctx: &'a mut AsyncCommandContext<'_, E>,
        input: AsyncPipelineData,
    ) -> Result<AsyncPipelineData, ShellError> {
        use core::future::Future;
        use core::pin::Pin;
        use core::task::Poll;

        let head = ctx.call.head;
        let _keep_order = ctx
            .call
            .has_flag(ctx.engine_state, ctx.stack, "keep-order")?;
        let max_concurrency: Option<i64> =
            ctx.call.get_flag(ctx.engine_state, ctx.stack, "threads")?;
        let closure: Closure = ctx.call.req(ctx.engine_state, ctx.stack, 0)?;

        let (rx, span, metadata) = input.into_list_stream_receiver(head).await?;
        let mut items = Vec::new();
        while let Ok(item) = rx.recv().await {
            if let Value::Error { error, .. } = item {
                return Err(*error);
            }
            items.push(item);
        }

        if items.is_empty() {
            return Ok(AsyncPipelineData::value(
                Value::list(Vec::new(), span),
                metadata,
            ));
        }

        let engine_state = ctx.engine_state;
        let env = ctx.env;
        let registry = ctx.registry;
        let base_stack = ctx.stack.clone();
        let base_scope = ctx.runtime_scope.clone();
        let limit = max_concurrency
            .and_then(|n| usize::try_from(n).ok())
            .filter(|&n| n > 0)
            .unwrap_or(items.len());

        let total = items.len();
        let mut pending_items = items.into_iter().enumerate();
        let mut results: Vec<Option<Value>> = vec![None; total];
        type TaskFuture<'b> = Pin<Box<dyn Future<Output = Result<Value, ShellError>> + Send + 'b>>;
        let mut active: Vec<(usize, TaskFuture<'_>)> = Vec::with_capacity(limit.min(total));

        let spawn_next = |idx: usize, item: Value| -> (usize, TaskFuture<'_>) {
            let mut task_stack = base_stack.clone();
            let mut task_scope = base_scope.clone();
            let closure = closure.clone();
            let fut: TaskFuture<'_> = Box::pin(async move {
                let mut rt = crate::command::EvalRuntime {
                    env,
                    registry,
                    runtime_scope: &mut task_scope,
                };
                let out = eval_closure_async(
                    engine_state,
                    &mut task_stack,
                    &closure,
                    vec![item.clone()],
                    AsyncPipelineData::value(item, None),
                    &mut rt,
                    head,
                )
                .await?;
                out.into_value_async(head).await
            });
            (idx, fut)
        };

        for _ in 0..limit {
            if let Some((idx, item)) = pending_items.next() {
                active.push(spawn_next(idx, item));
            }
        }

        futures_lite::future::poll_fn(|cx| {
            let mut i = 0;
            while i < active.len() {
                match active[i].1.as_mut().poll(cx) {
                    Poll::Ready(Ok(val)) => {
                        let (idx, _) = active.swap_remove(i);
                        results[idx] = Some(val);
                        if let Some((next_idx, next_item)) = pending_items.next() {
                            active.push(spawn_next(next_idx, next_item));
                        }
                    }
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                    Poll::Pending => i += 1,
                }
            }
            if active.is_empty() {
                Poll::Ready(Ok(()))
            } else {
                Poll::Pending
            }
        })
        .await?;

        let collected: Vec<Value> = results
            .into_iter()
            .flatten()
            .filter(|val| !val.is_nothing())
            .collect();
        Ok(AsyncPipelineData::value(
            Value::list(collected, span),
            metadata,
        ))
    }
}

/// Async-aware `where` command supporting both row conditions (`where size > 10b`)
/// and async closures (`where { |r| (open $r.name) == "ok" }`).
#[derive(Debug, Clone, Copy)]
pub struct AsyncWhere;

impl<E: HeliosEnv> AsyncCommand<E> for AsyncWhere {
    fn name(&self) -> &str {
        "where"
    }

    fn description(&self) -> &str {
        "Filter values based on a row condition or closure asynchronously."
    }

    fn signature(&self) -> Signature {
        Signature::build("where")
            .input_output_types(vec![
                (Type::list(Type::Any), Type::list(Type::Any)),
                (Type::table(), Type::table()),
            ])
            .required(
                "cond",
                SyntaxShape::OneOf(vec![
                    SyntaxShape::RowCondition,
                    SyntaxShape::Closure(Some(vec![SyntaxShape::Any])),
                ]),
                "Condition or closure returning a boolean.",
            )
            .category(Category::Filters)
    }

    async fn run_async<'a>(
        &'a self,
        ctx: &'a mut AsyncCommandContext<'_, E>,
        input: AsyncPipelineData,
    ) -> Result<AsyncPipelineData, ShellError> {
        let head = ctx.call.head;
        let closure: Closure = ctx.call.req(ctx.engine_state, ctx.stack, 0)?;

        let (rx, span, metadata) = input.into_list_stream_receiver(head).await?;
        let mut kept = Vec::new();
        while let Ok(item) = rx.recv().await {
            if let Value::Error { error, .. } = item {
                return Err(*error);
            }
            let mut rt = crate::command::EvalRuntime {
                env: ctx.env,
                registry: ctx.registry,
                runtime_scope: ctx.runtime_scope,
            };
            let out = eval_closure_async(
                ctx.engine_state,
                ctx.stack,
                &closure,
                vec![item.clone()],
                AsyncPipelineData::value(item.clone(), None),
                &mut rt,
                head,
            )
            .await?;
            let cond_val = out.into_value_async(head).await?;
            if cond_val.is_true() {
                kept.push(item);
            }
        }

        Ok(AsyncPipelineData::value(Value::list(kept, span), metadata))
    }
}

/// Async-aware `with-env` command.
#[derive(Debug, Clone, Copy)]
pub struct AsyncWithEnv;

impl<E: HeliosEnv> AsyncCommand<E> for AsyncWithEnv {
    fn name(&self) -> &str {
        "with-env"
    }

    fn description(&self) -> &str {
        "Runs a closure with temporary environment variables set."
    }

    fn signature(&self) -> Signature {
        Signature::build("with-env")
            .input_output_types(vec![(Type::Any, Type::Any)])
            .required(
                "assignment",
                SyntaxShape::Record(vec![].into()),
                "Record of environment variable names and values.",
            )
            .required("block", SyntaxShape::Closure(None), "The closure to run.")
            .category(Category::Env)
    }

    async fn run_async<'a>(
        &'a self,
        ctx: &'a mut AsyncCommandContext<'_, E>,
        input: AsyncPipelineData,
    ) -> Result<AsyncPipelineData, ShellError> {
        let env_rec: Record = ctx.call.req(ctx.engine_state, ctx.stack, 0)?;
        let closure: Closure = ctx.call.req(ctx.engine_state, ctx.stack, 1)?;

        let mut scoped_stack = ctx
            .stack
            .captures_to_stack_preserve_out_dest(closure.captures.clone());
        for (k, v) in env_rec {
            if v.is_nothing() {
                scoped_stack.hide_env_var(ctx.engine_state, &k);
            } else {
                scoped_stack.add_env_var(k, v);
            }
        }

        let block = ctx.engine_state.get_block(closure.block_id);
        let mut rt = crate::command::EvalRuntime {
            env: ctx.env,
            registry: ctx.registry,
            runtime_scope: ctx.runtime_scope,
        };
        crate::eval::eval_block_async(ctx.engine_state, &mut scoped_stack, block, input, &mut rt)
            .await
            .map(|exec| exec.body)
    }
}

/// Async-aware `complete` command: captures stdout, stderr, and exit_code from
/// an external command stream into a structured record.
#[derive(Debug, Clone, Copy)]
pub struct AsyncComplete;

impl<E: HeliosEnv> AsyncCommand<E> for AsyncComplete {
    fn name(&self) -> &str {
        "complete"
    }

    fn description(&self) -> &str {
        "Capture the stdout, stderr, and exit code of an external command."
    }

    fn signature(&self) -> Signature {
        Signature::build("complete")
            .input_output_types(vec![(
                Type::Any,
                Type::Record(
                    vec![
                        ("stdout".into(), Type::String),
                        ("stderr".into(), Type::String),
                        ("exit_code".into(), Type::Int),
                    ]
                    .into(),
                ),
            )])
            .category(Category::System)
    }

    async fn run_async<'a>(
        &'a self,
        ctx: &'a mut AsyncCommandContext<'_, E>,
        input: AsyncPipelineData,
    ) -> Result<AsyncPipelineData, ShellError> {
        let head = ctx.call.head;
        let (stdout, stderr, exit_code) = match input {
            AsyncPipelineData::ByteStream {
                stream,
                stderr,
                exit_code,
                ..
            } => {
                let (out_res, err_res) =
                    futures_lite::future::zip(collect_byte_receiver(stream), async move {
                        match stderr {
                            Some(rx) => collect_byte_receiver(rx).await,
                            None => Ok(Vec::new()),
                        }
                    })
                    .await;
                let out_bytes = out_res?;
                let err_bytes = err_res?;
                let code = match exit_code {
                    Some(rx) => match rx.recv().await {
                        Ok(Ok(code)) => code,
                        Ok(Err(err)) => {
                            return Err(err.into_shell_error("external command failed", head));
                        }
                        Err(_) => 0,
                    },
                    None => 0,
                };
                (
                    String::from_utf8_lossy(&out_bytes).into_owned(),
                    String::from_utf8_lossy(&err_bytes).into_owned(),
                    code,
                )
            }
            other => {
                let bytes = other.into_bytes_async(head).await?;
                (
                    String::from_utf8_lossy(&bytes).into_owned(),
                    String::new(),
                    0,
                )
            }
        };

        ctx.stack.set_last_exit_code(exit_code, head);
        let mut rec = Record::new();
        rec.push("stdout", Value::string(stdout, head));
        rec.push("stderr", Value::string(stderr, head));
        rec.push("exit_code", Value::int(i64::from(exit_code), head));
        Ok(AsyncPipelineData::value(Value::record(rec, head), None))
    }
}

/// Async-native `print` command writing formatted values to stdout or stderr
/// through [`HeliosEnv::write_stdout`] / [`HeliosEnv::write_stderr`].
#[derive(Debug, Clone, Copy)]
pub struct AsyncPrint;

impl<E: HeliosEnv> AsyncCommand<E> for AsyncPrint {
    fn name(&self) -> &str {
        "print"
    }

    fn description(&self) -> &str {
        "Print the given values to stdout (or stderr with -e)."
    }

    fn signature(&self) -> Signature {
        Signature::build("print")
            .input_output_types(vec![(Type::Any, Type::Nothing)])
            .switch("no-newline", "Print without a trailing newline.", Some('n'))
            .switch("stderr", "Print to stderr instead of stdout.", Some('e'))
            .switch(
                "raw",
                "Print raw string/binary bytes without formatting.",
                Some('r'),
            )
            .rest("rest", SyntaxShape::Any, "The values to print.")
            .category(Category::Strings)
    }

    async fn run_async<'a>(
        &'a self,
        ctx: &'a mut AsyncCommandContext<'_, E>,
        input: AsyncPipelineData,
    ) -> Result<AsyncPipelineData, ShellError> {
        let head = ctx.call.head;
        let no_newline = ctx
            .call
            .has_flag(ctx.engine_state, ctx.stack, "no-newline")?;
        let to_stderr = ctx.call.has_flag(ctx.engine_state, ctx.stack, "stderr")?;
        let _raw = ctx.call.has_flag(ctx.engine_state, ctx.stack, "raw")?;
        let args: Vec<Value> = ctx.call.rest(ctx.engine_state, ctx.stack, 0)?;

        let config = ctx.stack.get_config(ctx.engine_state);
        let mut payload = Vec::new();
        if args.is_empty() {
            if !input.is_empty_or_nothing() {
                let val = input.into_value_async(head).await?;
                append_printable(&mut payload, &val, &config);
                if !no_newline {
                    payload.push(b'\n');
                }
            } else if !no_newline {
                payload.push(b'\n');
            }
        } else {
            for (idx, val) in args.iter().enumerate() {
                if idx > 0 {
                    payload.push(b'\n');
                }
                append_printable(&mut payload, val, &config);
            }
            if !no_newline {
                payload.push(b'\n');
            }
        }

        if !payload.is_empty() {
            let res = if to_stderr {
                ctx.env.write_stderr(&payload).await
            } else {
                ctx.env.write_stdout(&payload).await
            };
            res.map_err(|err| err.into_shell_error("print failed", head))?;
        }

        Ok(AsyncPipelineData::Empty)
    }
}

fn append_printable(out: &mut Vec<u8>, value: &Value, config: &nu_protocol::Config) {
    match value {
        Value::Nothing { .. } => {}
        Value::String { val, .. } => out.extend_from_slice(val.as_bytes()),
        Value::Binary { val, .. } => out.extend_from_slice(val),
        other => out.extend_from_slice(other.to_expanded_string("\n", config).as_bytes()),
    }
}

/// Zero-sized marker type used solely to query env-independent signatures and
/// descriptions from [`AsyncCommand<E>`] implementations.
struct SignatureOnlyEnv;

impl HeliosEnv for SignatureOnlyEnv {
    async fn cwd(&self) -> Result<String, crate::error::EnvError> {
        unreachable!("SignatureOnlyEnv is never executed")
    }
    async fn set_cwd(&self, _: &str) -> Result<String, crate::error::EnvError> {
        unreachable!("SignatureOnlyEnv is never executed")
    }
    async fn spawn_external(
        &self,
        _: crate::env::ExternalSpawnRequest,
    ) -> Result<crate::env::ExternalProcess, crate::error::EnvError> {
        unreachable!("SignatureOnlyEnv is never executed")
    }
    async fn resolve_executable(
        &self,
        _: &str,
        _: &[String],
    ) -> Result<Option<crate::env::ExecutableMatch>, crate::error::EnvError> {
        unreachable!("SignatureOnlyEnv is never executed")
    }
    async fn sys_cpu(
        &self,
        _: bool,
    ) -> Result<Vec<crate::env::SysCpuInfo>, crate::error::EnvError> {
        unreachable!("SignatureOnlyEnv is never executed")
    }
    async fn sys_mem(&self) -> Result<crate::env::SysMemInfo, crate::error::EnvError> {
        unreachable!("SignatureOnlyEnv is never executed")
    }
    async fn sys_net(&self) -> Result<Vec<crate::env::SysNetInfo>, crate::error::EnvError> {
        unreachable!("SignatureOnlyEnv is never executed")
    }
    async fn sys_disks(&self) -> Result<Vec<crate::env::SysDiskInfo>, crate::error::EnvError> {
        unreachable!("SignatureOnlyEnv is never executed")
    }
    async fn sys_host(&self) -> Result<crate::env::SysHostInfo, crate::error::EnvError> {
        unreachable!("SignatureOnlyEnv is never executed")
    }
    async fn inspect(
        &self,
        _: Option<&str>,
    ) -> Result<Vec<crate::env::InspectEntry>, crate::error::EnvError> {
        unreachable!("SignatureOnlyEnv is never executed")
    }
    async fn list_processes(&self) -> Result<Vec<crate::env::ProcessInfo>, crate::error::EnvError> {
        unreachable!("SignatureOnlyEnv is never executed")
    }
    async fn kill_process(
        &self,
        _: u64,
        _: Option<&str>,
        _: bool,
    ) -> Result<(), crate::error::EnvError> {
        unreachable!("SignatureOnlyEnv is never executed")
    }
    async fn whoami(&self) -> Result<String, crate::error::EnvError> {
        unreachable!("SignatureOnlyEnv is never executed")
    }
    async fn sleep(&self, _: core::time::Duration) -> Result<(), crate::error::EnvError> {
        unreachable!("SignatureOnlyEnv is never executed")
    }
    async fn clear(&self) -> Result<(), crate::error::EnvError> {
        unreachable!("SignatureOnlyEnv is never executed")
    }
    async fn enter_scope(&self, _: &str) -> Result<String, crate::error::EnvError> {
        unreachable!("SignatureOnlyEnv is never executed")
    }
    async fn leave_scope(&self, _: &str) -> Result<(), crate::error::EnvError> {
        unreachable!("SignatureOnlyEnv is never executed")
    }
    async fn take_snapshot(
        &self,
        _: &str,
        _: Option<&str>,
    ) -> Result<crate::env::SnapshotInfo, crate::error::EnvError> {
        unreachable!("SignatureOnlyEnv is never executed")
    }
    async fn begin_instruction_profile(
        &self,
        _: Option<&str>,
    ) -> Result<String, crate::error::EnvError> {
        unreachable!("SignatureOnlyEnv is never executed")
    }
    async fn end_instruction_profile(
        &self,
        _: &str,
    ) -> Result<crate::env::InstructionProfileSummary, crate::error::EnvError> {
        unreachable!("SignatureOnlyEnv is never executed")
    }
    async fn list_dir(
        &self,
        _: &str,
    ) -> Result<Vec<crate::env::FileMetadata>, crate::error::EnvError> {
        unreachable!("SignatureOnlyEnv is never executed")
    }
    async fn stat(&self, _: &str) -> Result<crate::env::FileMetadata, crate::error::EnvError> {
        unreachable!("SignatureOnlyEnv is never executed")
    }
    async fn read_file(&self, _: &str) -> Result<Vec<u8>, crate::error::EnvError> {
        unreachable!("SignatureOnlyEnv is never executed")
    }
    async fn write_file(
        &self,
        _: &str,
        _: &[u8],
        _: bool,
        _: bool,
    ) -> Result<(), crate::error::EnvError> {
        unreachable!("SignatureOnlyEnv is never executed")
    }
    async fn mkdir(&self, _: &str) -> Result<(), crate::error::EnvError> {
        unreachable!("SignatureOnlyEnv is never executed")
    }
    async fn remove(&self, _: &str, _: bool, _: bool) -> Result<(), crate::error::EnvError> {
        unreachable!("SignatureOnlyEnv is never executed")
    }
    async fn copy(&self, _: &str, _: &str, _: bool, _: bool) -> Result<(), crate::error::EnvError> {
        unreachable!("SignatureOnlyEnv is never executed")
    }
    async fn rename(&self, _: &str, _: &str, _: bool) -> Result<(), crate::error::EnvError> {
        unreachable!("SignatureOnlyEnv is never executed")
    }
    async fn touch(&self, _: &str, _: bool) -> Result<(), crate::error::EnvError> {
        unreachable!("SignatureOnlyEnv is never executed")
    }
    async fn watch(
        &self,
        _: &str,
    ) -> Result<async_channel::Receiver<crate::env::WatchEvent>, crate::error::EnvError> {
        unreachable!("SignatureOnlyEnv is never executed")
    }
}
