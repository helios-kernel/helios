//! `helios-nu`: async-first Nushell `0.117` `IrBlock` evaluator, Helios-native
//! capability commands, and shared AST completion core.
//!
//! Compiles cleanly on both host targets and `wasm32-wasip3` with zero
//! `block_on` in production code.

pub mod command;
pub mod commands;
pub mod completion;
pub mod env;
pub mod error;
pub mod eval;
pub mod pipeline;

#[cfg(any(test, feature = "test-support"))]
pub mod test_env;

pub use command::{
    AsyncCommand, AsyncCommandContext, AsyncCommandRegistry, EvalRuntime, RuntimeScope,
};
pub use commands::AsyncBuiltin;
pub use completion::{CompletionItem, CompletionKind, complete_async};
pub use env::{
    AsyncByteReceiver, AsyncByteSender, ExecutableMatch, ExternalProcess, ExternalSpawnRequest,
    FileMetadata, FileType, GrantSpec, HeliosEnv, HttpRedirectMode, HttpRequest, HttpResponse,
    InspectEntry, InspectValue, InstructionProfileSummary, ProcessInfo, STREAM_CHANNEL_CAPACITY,
    SnapshotInfo, SysCpuInfo, SysDiskInfo, SysHostInfo, SysMemInfo, SysNetInfo, WatchEvent,
    normalize_vfs_path,
};
pub use error::{EnvError, NuError};
pub use eval::{eval_block_async, eval_call_by_name_async, eval_closure_async, eval_ir_async};
pub use pipeline::{AsyncExecutionData, AsyncPipelineData};

use nu_protocol::Value;
use nu_protocol::engine::{EngineState, Stack, StateWorkingSet};

/// Build a fresh Helios Nushell [`EngineState`] and matching [`AsyncCommandRegistry`].
///
/// Registers:
/// 1. Core language declarations from `nu-cmd-lang` (`default-features = false`).
/// 2. All ~200 pure in-memory operators from `nu-command` (`default-features = false`).
/// 3. Helios-native async commands over [`HeliosEnv`] and [`zenwave`].
#[must_use]
pub fn create_helios_context() -> (EngineState, AsyncCommandRegistry) {
    let engine_state = nu_cmd_lang::create_default_context();
    let mut engine_state = nu_command::add_shell_command_context(engine_state);

    let mut registry = AsyncCommandRegistry::new();
    let delta = {
        let mut working_set = StateWorkingSet::new(&engine_state);
        commands::register_helios_commands(&mut working_set, &mut registry);
        working_set.render()
    };

    if let Err(err) = engine_state.merge_delta(delta) {
        tracing::error!("failed to merge helios async command delta: {err}");
    }

    // Ensure `table` decl id remains cached for viewers.
    engine_state.table_decl_id = engine_state.find_decl(b"table", &[]);

    (engine_state, registry)
}

/// Parse, compile to `IrBlock`, and evaluate Nushell source text asynchronously.
pub async fn eval_source_async<E: HeliosEnv>(
    engine_state: &mut EngineState,
    stack: &mut Stack,
    rt: &mut EvalRuntime<'_, E>,
    source: &str,
    file_name: Option<&str>,
    input: AsyncPipelineData,
) -> Result<AsyncPipelineData, NuError> {
    let mut working_set = StateWorkingSet::new(engine_state);
    let block = nu_parser::parse(&mut working_set, file_name, source.as_bytes(), false);

    if !working_set.parse_errors.is_empty() {
        let errors = working_set.parse_errors.clone();
        let message = errors
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("; ");
        return Err(NuError::Parse { message, errors });
    }

    if !working_set.compile_errors.is_empty() {
        let err = working_set.compile_errors[0].clone();
        return Err(NuError::Compile(Box::new(err)));
    }

    let delta = working_set.render();
    engine_state.merge_delta(delta)?;

    let exec = eval_block_async(engine_state, stack, &block, input, rt).await?;

    Ok(exec.body)
}

/// Stateful asynchronous Nushell session owning [`EngineState`], [`Stack`],
/// [`AsyncCommandRegistry`], and [`RuntimeScope`].
pub struct ShellSession<E: HeliosEnv> {
    engine_state: EngineState,
    stack: Stack,
    registry: AsyncCommandRegistry,
    runtime_scope: RuntimeScope,
    env: E,
}

impl<E: HeliosEnv> ShellSession<E> {
    /// Construct a new session backed by `env`, initializing `$env.PWD` from `env.cwd()`.
    pub async fn new(env: E) -> Self {
        let (engine_state, registry) = create_helios_context();
        let mut stack = Stack::new();
        let cwd = env.cwd().await.unwrap_or_else(|_| String::from("/"));
        stack.add_env_var(
            "PWD".to_owned(),
            Value::string(cwd, nu_protocol::Span::unknown()),
        );
        stack.add_env_var(
            "PATH".to_owned(),
            Value::list(
                vec![Value::string("/bin", nu_protocol::Span::unknown())],
                nu_protocol::Span::unknown(),
            ),
        );
        Self {
            engine_state,
            stack,
            registry,
            runtime_scope: RuntimeScope::default(),
            env,
        }
    }

    /// Evaluate Nushell source text and return the raw [`AsyncPipelineData`].
    pub async fn eval_pipeline(
        &mut self,
        source: &str,
        input: AsyncPipelineData,
    ) -> Result<AsyncPipelineData, NuError> {
        self.eval_pipeline_with_file(source, None, input).await
    }

    /// Evaluate Nushell source text with an optional file name for diagnostics
    /// and return the raw [`AsyncPipelineData`].
    pub async fn eval_pipeline_with_file(
        &mut self,
        source: &str,
        file_name: Option<&str>,
        input: AsyncPipelineData,
    ) -> Result<AsyncPipelineData, NuError> {
        let mut rt = EvalRuntime {
            env: &self.env,
            registry: &self.registry,
            runtime_scope: &mut self.runtime_scope,
        };
        eval_source_async(
            &mut self.engine_state,
            &mut self.stack,
            &mut rt,
            source,
            file_name,
            input,
        )
        .await
    }

    /// Evaluate Nushell source text and collect its output into a [`Value`].
    pub async fn eval(&mut self, source: &str) -> Result<Value, NuError> {
        let mut child_scope = self.runtime_scope.clone();
        child_scope.capture_inherited_stdout = true;
        let mut rt = EvalRuntime {
            env: &self.env,
            registry: &self.registry,
            runtime_scope: &mut child_scope,
        };
        let out = eval_source_async(
            &mut self.engine_state,
            &mut self.stack,
            &mut rt,
            source,
            None,
            AsyncPipelineData::Empty,
        )
        .await?;
        Ok(out.into_value_async(nu_protocol::Span::unknown()).await?)
    }

    /// Compute AST-driven completions for `input` at byte offset `cursor`.
    pub async fn complete(&self, input: &str, cursor: usize) -> Vec<CompletionItem> {
        complete_async(&self.engine_state, &self.stack, &self.env, input, cursor).await
    }

    #[must_use]
    pub const fn env(&self) -> &E {
        &self.env
    }

    #[must_use]
    pub const fn engine_state(&self) -> &EngineState {
        &self.engine_state
    }

    #[must_use]
    pub const fn stack(&self) -> &Stack {
        &self.stack
    }

    pub fn stack_mut(&mut self) -> &mut Stack {
        &mut self.stack
    }

    #[must_use]
    pub const fn runtime_scope(&self) -> &RuntimeScope {
        &self.runtime_scope
    }
}
