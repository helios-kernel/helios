//! Async command trait and Nushell declaration bridge.
//!
//! Each Helios-native command implements [`AsyncCommand<E>`] and is registered
//! in [`EngineState`] via [`AsyncCommandDescriptor`] so `nu-parser`,
//! `nu-engine::compile`, `help`, and AST completion see its exact [`Signature`]
//! and metadata. During evaluation, [`crate::eval_ir_async`] dispatches those
//! declarations directly to [`AsyncCommand::run_async`] with zero `block_on`.

use core::future::Future;
use std::collections::HashMap;

use nu_protocol::engine::{Call, Command, CommandType, EngineState, Stack, StateWorkingSet};
use nu_protocol::{DeclId, Example, PipelineData, ShellError, Signature};

use crate::commands::AsyncBuiltin;
use crate::env::{GrantSpec, HeliosEnv};
use crate::error::generic_error;
use crate::pipeline::AsyncPipelineData;

/// Scoped runtime state carried across async command invocations (explicit
/// grants, active subtree scope, cancellation/signal context).
#[derive(Debug, Default, Clone)]
pub struct RuntimeScope {
    /// Stack of explicit grant frames pushed by `with-grants`.
    pub grant_frames: Vec<Vec<GrantSpec>>,
    /// Stack of active subtree scopes pushed by `with-scope`.
    pub scope_frames: Vec<String>,
    /// When `true`, external commands capture stdout even when `stack.stdout()`
    /// is `OutDest::Inherit`/`OutDest::Print` (used by `ShellSession::eval` so
    /// the caller receives the final expression as a [`nu_protocol::Value`]).
    pub capture_inherited_stdout: bool,
}

impl RuntimeScope {
    /// Flattened active grants visible to an external command invocation.
    #[must_use]
    pub fn active_grants(&self) -> Vec<GrantSpec> {
        let mut grants = Vec::new();
        for frame in &self.grant_frames {
            grants.extend(frame.iter().cloned());
        }
        grants
    }

    /// Innermost active subtree scope, if any.
    #[must_use]
    pub fn current_scope(&self) -> Option<&str> {
        self.scope_frames.last().map(String::as_str)
    }
}

/// Mutable runtime handles shared across async IR evaluation and command calls.
pub struct EvalRuntime<'a, E: HeliosEnv> {
    pub env: &'a E,
    pub registry: &'a AsyncCommandRegistry,
    pub runtime_scope: &'a mut RuntimeScope,
}

/// Mutable execution context handed to every [`AsyncCommand::run_async`].
pub struct AsyncCommandContext<'a, E: HeliosEnv> {
    pub engine_state: &'a EngineState,
    pub stack: &'a mut Stack,
    pub call: &'a Call<'a>,
    pub env: &'a E,
    pub registry: &'a AsyncCommandRegistry,
    pub runtime_scope: &'a mut RuntimeScope,
}

impl<E: HeliosEnv> AsyncCommandContext<'_, E> {
    /// Borrow runtime handles as an [`EvalRuntime`] for nested async evaluation.
    pub fn runtime(&mut self) -> EvalRuntime<'_, E> {
        EvalRuntime {
            env: self.env,
            registry: self.registry,
            runtime_scope: self.runtime_scope,
        }
    }
}

/// Asynchronous command implemented against [`HeliosEnv`].
///
/// Trait method spells out its `impl Future + Send` return type explicitly per
/// `AGENTS.md §3.2`.
pub trait AsyncCommand<E: HeliosEnv>: Send + Sync {
    fn name(&self) -> &str;

    fn signature(&self) -> Signature;

    fn description(&self) -> &str;

    fn extra_description(&self) -> &str {
        ""
    }

    fn search_terms(&self) -> Vec<&str> {
        Vec::new()
    }

    fn run_async<'a>(
        &'a self,
        ctx: &'a mut AsyncCommandContext<'_, E>,
        input: AsyncPipelineData,
    ) -> impl Future<Output = Result<AsyncPipelineData, ShellError>> + Send + 'a;
}

/// Registry mapping Nushell [`DeclId`]s to Helios [`AsyncBuiltin`] commands.
#[derive(Debug, Default, Clone)]
pub struct AsyncCommandRegistry {
    by_decl: HashMap<DeclId, AsyncBuiltin>,
}

impl AsyncCommandRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self {
            by_decl: HashMap::new(),
        }
    }

    /// Register `command` in `working_set` and record its [`DeclId`] for async
    /// dispatch during [`crate::eval_ir_async`].
    pub fn register(
        &mut self,
        working_set: &mut StateWorkingSet<'_>,
        command: AsyncBuiltin,
    ) -> DeclId {
        let descriptor = AsyncCommandDescriptor {
            name: command.name().to_owned(),
            signature: command.signature(),
            description: command.description().to_owned(),
            extra_description: command.extra_description().to_owned(),
            search_terms: command
                .search_terms()
                .into_iter()
                .map(ToOwned::to_owned)
                .collect(),
        };
        let decl_id = working_set.add_decl(Box::new(descriptor));
        self.by_decl.insert(decl_id, command);
        decl_id
    }

    /// Look up the async implementation for `decl_id`, if registered.
    #[must_use]
    pub fn get(&self, decl_id: DeclId) -> Option<AsyncBuiltin> {
        self.by_decl.get(&decl_id).copied()
    }
}

/// Synchronous `nu-protocol` [`Command`] metadata descriptor for an
/// [`AsyncCommand`].
///
/// Gives `nu-parser`, `nu-engine::compile`, `help`, and AST completion the exact
/// signature without ever exposing a synchronous `block_on` fallback.
#[derive(Clone)]
struct AsyncCommandDescriptor {
    name: String,
    signature: Signature,
    description: String,
    extra_description: String,
    search_terms: Vec<String>,
}

impl Command for AsyncCommandDescriptor {
    fn name(&self) -> &str {
        &self.name
    }

    fn signature(&self) -> Signature {
        self.signature.clone()
    }

    fn description(&self) -> &str {
        &self.description
    }

    fn extra_description(&self) -> &str {
        &self.extra_description
    }

    fn search_terms(&self) -> Vec<&str> {
        self.search_terms.iter().map(String::as_str).collect()
    }

    fn examples(&self) -> Vec<Example<'_>> {
        Vec::new()
    }

    fn command_type(&self) -> CommandType {
        CommandType::Builtin
    }

    fn run(
        &self,
        _engine_state: &EngineState,
        _stack: &mut Stack,
        call: &Call,
        _input: PipelineData,
    ) -> Result<PipelineData, ShellError> {
        Err(generic_error(
            "async command invoked synchronously",
            format!(
                "`{}` requires helios-nu's async evaluator (`eval_ir_async`); synchronous invocation is not supported",
                self.name
            ),
            call.head,
        ))
    }
}
