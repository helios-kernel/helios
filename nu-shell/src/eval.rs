//! Async-first Nushell `IrBlock` evaluator (`eval_ir_async`).
//!
//! Executes compiled `nu_protocol::ir::IrBlock` instructions asynchronously
//! with zero `block_on`, concurrent `AsyncPipelineData` stream stages,
//! capability-bounded VFS redirections via [`HeliosEnv`], and dual command
//! dispatch:
//! - Custom Nushell commands (`decl.block_id()`) execute recursively via
//!   [`eval_block_async`].
//! - Helios-native [`AsyncCommand`](crate::command::AsyncCommand) declarations
//!   execute asynchronously against [`HeliosEnv`].
//! - Pure in-memory `nu-command` / `nu-cmd-lang` operators receive
//!   materialized [`PipelineData`] and run synchronously in memory.

use core::future::Future;
use core::pin::Pin;
use std::sync::Arc;

use nu_engine::env::{is_automatic_env_var, var};
use nu_engine::{convert_env_vars, eval_ir_call};
use nu_path::dots::expand_ndots_safe;
use nu_protocol::ast::{Bits, Block, Boolean, CellPath, Comparison, Math, Operator, PathMember};
use nu_protocol::engine::named_flags::{
    list_spread_before_required_error, normalize_engine_arguments,
};
use nu_protocol::engine::{
    Argument, Closure, EngineState, EnvName, ErrorHandler, Matcher, Redirection, Stack,
    StateWorkingSet, TryHandler, env_var_eq,
};
use nu_protocol::ir::{Call, DataSlice, Instruction, IrBlock, Literal, RedirectMode};
use nu_protocol::shell_error::generic::GenericError;
use nu_protocol::{
    CompareTypes, DeclId, ENV_VARIABLE_ID, Flag, IntoSpanned, LabeledError, OutDest, PipelineData,
    PositionalArg, Range, Record, RegId, ShellError, Signature, Span, Spanned, Type, Value, VarId,
    combined_type_string,
};

use crate::command::{AsyncCommandContext, AsyncCommandRegistry, EvalRuntime, RuntimeScope};
use crate::env::{HeliosEnv, normalize_vfs_path};
use crate::pipeline::{AsyncExecutionData, AsyncPipelineData, collect_byte_receiver};

/// Open redirection file slot backed by [`HeliosEnv`] rather than ambient host `std::fs`.
#[derive(Debug, Clone)]
struct RedirectFile {
    path: String,
    append: bool,
    written: bool,
}

/// Evaluate a compiled Nushell [`Block`] asynchronously against `rt`.
pub fn eval_block_async<'a, E: HeliosEnv>(
    engine_state: &'a EngineState,
    stack: &'a mut Stack,
    block: &'a Block,
    input: AsyncPipelineData,
    rt: &'a mut EvalRuntime<'_, E>,
) -> Pin<Box<dyn Future<Output = Result<AsyncExecutionData, ShellError>> + Send + 'a>> {
    Box::pin(async move {
        let config = stack.config.as_deref().unwrap_or(&engine_state.config);
        let maximum_call_stack_depth = config.recursion_limit.max(0).cast_unsigned();
        if stack.recursion_count > maximum_call_stack_depth {
            return Err(ShellError::RecursionLimitReached {
                recursion_limit: maximum_call_stack_depth,
                span: block.span,
            });
        }

        let pushed_scope = if let Some(bindings) = &block.scope_bindings {
            stack.push_scope_bindings(bindings.clone());
            true
        } else {
            false
        };

        let saved_regions = std::mem::take(&mut stack.ir_scope_regions);
        let saved_pc = stack.ir_instruction_index.take();

        let result = eval_ir_block_inner(engine_state, stack, block, input, rt).await;

        stack.ir_scope_regions = saved_regions;
        stack.ir_instruction_index = saved_pc;
        if pushed_scope {
            stack.pop_scope_bindings();
        }
        result
    })
}

/// Evaluate a Nushell [`IrBlock`] directly with async dual dispatch.
pub async fn eval_ir_async<E: HeliosEnv>(
    engine_state: &EngineState,
    stack: &mut Stack,
    ir_block: &IrBlock,
    block_span: Option<Span>,
    input: AsyncPipelineData,
    rt: &mut EvalRuntime<'_, E>,
) -> Result<AsyncExecutionData, ShellError> {
    stack.ir_scope_regions = ir_block.scope_regions.clone();
    stack.ir_instruction_index = None;

    let args_base = stack.arguments.get_base();
    let error_handler_base = stack.error_handlers.get_base();

    let mut registers = Vec::with_capacity(ir_block.register_count as usize);
    for _ in 0..ir_block.register_count {
        registers.push(AsyncExecutionData::empty());
    }
    let mut files = vec![None; ir_block.file_count as usize];
    let mut record_items = vec![Vec::new(); ir_block.register_count as usize];

    let mut ctx = AsyncEvalContext {
        engine_state,
        stack,
        env: rt.env,
        registry: rt.registry,
        runtime_scope: rt.runtime_scope,
        data: &ir_block.data,
        block_span: &block_span,
        args_base,
        error_handler_base,
        finally_resumes: Vec::new(),
        redirect_out: None,
        redirect_err: None,
        redirect_out_file: None,
        redirect_err_file: None,
        matches: Vec::new(),
        registers: &mut registers[..],
        files: &mut files[..],
        record_items: &mut record_items[..],
    };

    let result = eval_ir_loop(&mut ctx, ir_block, input).await;

    ctx.stack.error_handlers.leave_frame(error_handler_base);
    ctx.stack.arguments.leave_frame(args_base);
    ctx.stack.ir_instruction_index = None;

    result
}

/// Evaluate a Nushell [`Closure`] asynchronously with positional arguments and pipeline input.
pub async fn eval_closure_async<E: HeliosEnv>(
    engine_state: &EngineState,
    caller_stack: &mut Stack,
    closure: &Closure,
    args: Vec<Value>,
    input: AsyncPipelineData,
    rt: &mut EvalRuntime<'_, E>,
    call_span: Span,
) -> Result<AsyncPipelineData, ShellError> {
    eval_closure_inner(
        engine_state,
        caller_stack,
        closure,
        (args, input),
        rt,
        call_span,
        false,
    )
    .await
}

/// Evaluate a Nushell [`Closure`] asynchronously and propagate environment
/// variable mutations back into `caller_stack` (used by `do --env`).
pub async fn eval_closure_redirect_env_async<E: HeliosEnv>(
    engine_state: &EngineState,
    caller_stack: &mut Stack,
    closure: &Closure,
    args: Vec<Value>,
    input: AsyncPipelineData,
    rt: &mut EvalRuntime<'_, E>,
    call_span: Span,
) -> Result<AsyncPipelineData, ShellError> {
    eval_closure_inner(
        engine_state,
        caller_stack,
        closure,
        (args, input),
        rt,
        call_span,
        true,
    )
    .await
}

async fn eval_closure_inner<E: HeliosEnv>(
    engine_state: &EngineState,
    caller_stack: &mut Stack,
    closure: &Closure,
    (args, input): (Vec<Value>, AsyncPipelineData),
    rt: &mut EvalRuntime<'_, E>,
    call_span: Span,
    force_redirect_env: bool,
) -> Result<AsyncPipelineData, ShellError> {
    let block = engine_state.get_block(closure.block_id);
    let mut callee_stack = caller_stack
        .captures_to_stack(closure.captures.clone())
        .with_invocation_stdout(caller_stack.stdout().clone());
    callee_stack.recursion_count = caller_stack.recursion_count + 1;

    // Bind closure positional arguments (required + optional + rest).
    let mut arg_iter = args.into_iter();
    for param in block
        .signature
        .required_positional
        .iter()
        .chain(block.signature.optional_positional.iter())
    {
        if let Some(var_id) = param.var_id {
            let val = match arg_iter.next() {
                Some(v) => v,
                None => param
                    .default_value
                    .clone()
                    .unwrap_or_else(|| Value::nothing(call_span)),
            };
            callee_stack.add_var(var_id, val);
        }
    }
    if let Some(rest_param) = &block.signature.rest_positional
        && let Some(var_id) = rest_param.var_id
    {
        let rest: Vec<Value> = arg_iter.collect();
        callee_stack.add_var(var_id, Value::list(rest, call_span));
    }

    let result = eval_block_async(engine_state, &mut callee_stack, block, input, rt)
        .await
        .map(|exec| exec.body);

    if force_redirect_env || block.redirect_env {
        redirect_env(engine_state, caller_stack, &callee_stack);
    }
    result
}

/// Invoke a named Nushell declaration (such as `from json` or `to toml`) asynchronously.
pub fn eval_call_by_name_async<'a, E: HeliosEnv>(
    engine_state: &'a EngineState,
    stack: &'a mut Stack,
    name: &'a str,
    head: Span,
    input: AsyncPipelineData,
    rt: &'a mut EvalRuntime<'_, E>,
) -> Pin<Box<dyn Future<Output = Result<Option<AsyncPipelineData>, ShellError>> + Send + 'a>> {
    Box::pin(async move {
        let Some(decl_id) = engine_state.find_decl(name.as_bytes(), &[]) else {
            return Ok(None);
        };

        if let Some(async_cmd) = rt.registry.get(decl_id) {
            let call = Call::build(decl_id, head).finish();
            let engine_call = (&call).into();
            let mut cmd_ctx = AsyncCommandContext {
                engine_state,
                stack,
                call: &engine_call,
                env: rt.env,
                registry: rt.registry,
                runtime_scope: rt.runtime_scope,
            };
            let output = async_cmd.run_async(&mut cmd_ctx, input).await?;
            return Ok(Some(output));
        }

        let decl = engine_state.get_decl(decl_id);
        if let Some(block_id) = decl.block_id() {
            let block = engine_state.get_block(block_id);
            let mut callee_stack = stack.gather_captures(engine_state, &block.captures);
            callee_stack.recursion_count = stack.recursion_count + 1;
            let out = eval_block_async(engine_state, &mut callee_stack, block, input, rt)
                .await?
                .body;
            if block.redirect_env {
                redirect_env(engine_state, stack, &callee_stack);
            }
            return Ok(Some(out));
        }

        let sync_input = input.into_sync_pipeline_data(head).await?;
        let call = Call::build(decl_id, head).finish();
        let output = eval_ir_call(engine_state, stack, &call, sync_input)?;
        call.leave(stack);
        Ok(Some(AsyncPipelineData::from(output)))
    })
}

async fn eval_ir_block_inner<E: HeliosEnv>(
    engine_state: &EngineState,
    stack: &mut Stack,
    block: &Block,
    input: AsyncPipelineData,
    rt: &mut EvalRuntime<'_, E>,
) -> Result<AsyncExecutionData, ShellError> {
    let Some(ir_block) = &block.ir_block else {
        let error = if let Some(span) = block.span {
            ShellError::Generic(
                GenericError::new(
                    "Can't evaluate block in IR mode",
                    "block is missing compiled representation",
                    span,
                )
                .with_help("the IrBlock is probably missing due to a compilation error"),
            )
        } else {
            ShellError::Generic(
                GenericError::new_internal(
                    "Can't evaluate block in IR mode",
                    "block is missing compiled representation",
                )
                .with_help("the IrBlock is probably missing due to a compilation error"),
            )
        };
        return Err(error);
    };

    eval_ir_async(engine_state, stack, ir_block, block.span, input, rt).await
}

#[derive(Clone, Copy)]
struct RecordLiteralItem {
    end: usize,
    span: Span,
    is_spread: bool,
}

struct AsyncEvalContext<'a, E: HeliosEnv> {
    engine_state: &'a EngineState,
    stack: &'a mut Stack,
    env: &'a E,
    registry: &'a AsyncCommandRegistry,
    runtime_scope: &'a mut RuntimeScope,
    data: &'a Arc<[u8]>,
    block_span: &'a Option<Span>,
    args_base: usize,
    error_handler_base: usize,
    finally_resumes: Vec<Option<Unwind>>,
    redirect_out: Option<Redirection>,
    redirect_err: Option<Redirection>,
    redirect_out_file: Option<u32>,
    redirect_err_file: Option<u32>,
    matches: Vec<(VarId, Value)>,
    registers: &'a mut [AsyncExecutionData],
    files: &'a mut [Option<RedirectFile>],
    record_items: &'a mut [Vec<RecordLiteralItem>],
}

impl<'a, E: HeliosEnv> AsyncEvalContext<'a, E> {
    fn record_item_of_key(
        &self,
        reg: RegId,
        record: &Record,
        key: &str,
    ) -> Option<RecordLiteralItem> {
        let index = record.index_of(key)?;
        let items = &self.record_items[reg.get() as usize];
        items
            .get(items.partition_point(|item| item.end <= index))
            .copied()
    }

    fn push_record_item(&mut self, reg: RegId, end: usize, span: Span, is_spread: bool) {
        self.record_items[reg.get() as usize].push(RecordLiteralItem {
            end,
            span,
            is_spread,
        });
    }

    #[inline]
    fn put_reg(&mut self, reg_id: RegId, new_value: AsyncExecutionData) {
        self.registers[reg_id.get() as usize] = new_value;
    }

    #[inline]
    fn borrow_reg(&self, reg_id: RegId) -> &AsyncPipelineData {
        &self.registers[reg_id.get() as usize].body
    }

    #[inline]
    fn take_reg(&mut self, reg_id: RegId) -> AsyncExecutionData {
        std::mem::replace(
            &mut self.registers[reg_id.get() as usize],
            AsyncExecutionData::empty(),
        )
    }

    fn clone_reg(
        &mut self,
        reg_id: RegId,
        error_span: Span,
    ) -> Result<AsyncPipelineData, ShellError> {
        match &self.registers[reg_id.get() as usize].body {
            AsyncPipelineData::Empty => Ok(AsyncPipelineData::Empty),
            AsyncPipelineData::Value(val, meta) => {
                Ok(AsyncPipelineData::Value(val.clone(), meta.clone()))
            }
            AsyncPipelineData::Sync(PipelineData::Empty) => Ok(AsyncPipelineData::Empty),
            AsyncPipelineData::Sync(PipelineData::Value(val, meta)) => {
                Ok(AsyncPipelineData::Value(val.clone(), meta.clone()))
            }
            _ => Err(ShellError::IrEvalError {
                msg: "Must collect to value before using instruction that clones from a register"
                    .into(),
                span: Some(error_span),
            }),
        }
    }

    fn clone_reg_value(&mut self, reg_id: RegId, fallback_span: Span) -> Result<Value, ShellError> {
        match self.clone_reg(reg_id, fallback_span)? {
            AsyncPipelineData::Empty => Ok(Value::nothing(fallback_span)),
            AsyncPipelineData::Value(val, _) => Ok(val),
            _ => Err(ShellError::IrEvalError {
                msg: "clone_reg returned non-value stream data".into(),
                span: Some(fallback_span),
            }),
        }
    }

    async fn collect_reg(
        &mut self,
        reg_id: RegId,
        fallback_span: Span,
    ) -> Result<Value, ShellError> {
        let data = self.take_reg(reg_id);
        let span = data.span().unwrap_or(fallback_span);
        data.body.into_value_async(span).await
    }

    fn get_str(&self, slice: DataSlice, error_span: Span) -> Result<&'a str, ShellError> {
        std::str::from_utf8(&self.data[slice]).map_err(|_| ShellError::IrEvalError {
            msg: format!("data slice does not refer to valid UTF-8: {slice:?}"),
            span: Some(error_span),
        })
    }
}

#[derive(Debug)]
enum Unwind {
    Error(Spanned<ShellError>),
    Return(AsyncExecutionData),
    Jump { index: usize, handlers: usize },
}

enum Unwound {
    Branch(usize),
    Return(Box<Result<AsyncExecutionData, ShellError>>),
}

#[derive(Debug)]
enum InstructionResult {
    Continue,
    Branch(usize),
    Return(RegId),
    ReturnEarly(RegId),
    UnwindJump { index: usize, handlers: usize },
    EndFinally,
}

async fn eval_ir_loop<E: HeliosEnv>(
    ctx: &mut AsyncEvalContext<'_, E>,
    ir_block: &IrBlock,
    input: AsyncPipelineData,
) -> Result<AsyncExecutionData, ShellError> {
    if !ctx.registers.is_empty() {
        ctx.registers[0] = AsyncExecutionData::from_body(input);
    }

    let mut pc = 0;
    let need_backtrace = ctx.engine_state.get_env_var("NU_BACKTRACE").is_some();

    while pc < ir_block.instructions.len() {
        let instruction = &ir_block.instructions[pc];
        let span = &ir_block.spans[pc];

        ctx.stack.ir_instruction_index = Some(pc);

        let result = eval_instruction_async(ctx, instruction, span, need_backtrace).await;

        let unwind = match result {
            Ok(InstructionResult::Continue) => {
                pc += 1;
                continue;
            }
            Ok(InstructionResult::Branch(next_pc)) => {
                pc = next_pc;
                continue;
            }
            Ok(InstructionResult::Return(reg_id)) => return Ok(ctx.take_reg(reg_id)),
            Ok(InstructionResult::ReturnEarly(reg_id)) => {
                Unwind::Return(ctx.take_reg(reg_id).with_early_return())
            }
            Ok(InstructionResult::UnwindJump { index, handlers }) => {
                Unwind::Jump { index, handlers }
            }
            Ok(InstructionResult::EndFinally) => {
                match ctx.stack.error_handlers.pop(ctx.error_handler_base) {
                    Some(TryHandler::RunningFinally) => {}
                    handler => {
                        return Err(ShellError::IrEvalError {
                            msg: format!(
                                "end-finally expected a running finally handler, found {handler:?}"
                            ),
                            span: Some(*span),
                        });
                    }
                }
                match ctx.finally_resumes.pop() {
                    Some(None) => {
                        pc += 1;
                        continue;
                    }
                    Some(Some(unwind)) => unwind,
                    None => {
                        return Err(ShellError::IrEvalError {
                            msg: "end-finally without a matching begin-finally".into(),
                            span: Some(*span),
                        });
                    }
                }
            }
            Err(err @ (ShellError::Continue { .. } | ShellError::Break { .. })) => {
                return Err(err);
            }
            Err(err @ ShellError::Exit { abort: true, .. }) => return Err(err),
            Err(err) => Unwind::Error(err.into_spanned(*span)),
        };

        match unwind_through_handlers_async(ctx, unwind, *span, need_backtrace).await {
            Unwound::Branch(next_pc) => pc = next_pc,
            Unwound::Return(result) => return *result,
        }
    }

    Err(ShellError::IrEvalError {
        msg: format!(
            "Program counter out of range (pc={pc}, len={len})",
            len = ir_block.instructions.len(),
        ),
        span: *ctx.block_span,
    })
}

async fn unwind_through_handlers_async<E: HeliosEnv>(
    ctx: &mut AsyncEvalContext<'_, E>,
    mut unwind: Unwind,
    span: Span,
    need_backtrace: bool,
) -> Unwound {
    loop {
        if let Unwind::Jump { index, handlers: 0 } = unwind {
            return Unwound::Branch(index);
        }

        let Some(handler) = ctx.stack.error_handlers.pop(ctx.error_handler_base) else {
            return Unwound::Return(Box::new(match unwind {
                Unwind::Error(err) if need_backtrace => {
                    Err(ShellError::into_chained(err.item, err.span))
                }
                Unwind::Error(err) => Err(err.item),
                Unwind::Return(data) => Ok(data),
                Unwind::Jump { .. } => Err(ShellError::IrEvalError {
                    msg: "unwind-jump ran out of handlers before reaching its target".into(),
                    span: Some(span),
                }),
            }));
        };

        if let Unwind::Jump { handlers, .. } = &mut unwind {
            *handlers -= 1;
        }

        match handler {
            TryHandler::Catch(handler) => match unwind {
                Unwind::Error(err) if !matches!(err.item, ShellError::Exit { .. }) => {
                    reset_signals_if_interrupted(ctx, &err.item);
                    prepare_error_handler(ctx, handler, Some(err));
                    return Unwound::Branch(handler.handler_index);
                }
                _ => {}
            },
            TryHandler::Finally(handler) => {
                if let Unwind::Return(data) = unwind {
                    let collected = collect_async(data, span).await;
                    unwind = match collected {
                        Ok(body) => {
                            Unwind::Return(AsyncExecutionData::from_body(body).with_early_return())
                        }
                        Err(err) => Unwind::Error(err.into_spanned(span)),
                    };
                }
                let error = match &unwind {
                    Unwind::Error(err) if !matches!(err.item, ShellError::Exit { .. }) => {
                        reset_signals_if_interrupted(ctx, &err.item);
                        Some(err.clone())
                    }
                    _ => None,
                };
                prepare_error_handler(ctx, handler, error);
                ctx.stack.error_handlers.push(TryHandler::RunningFinally);
                ctx.finally_resumes.push(Some(unwind));
                return Unwound::Branch(handler.handler_index);
            }
            TryHandler::RunningFinally => {
                ctx.finally_resumes.pop();
            }
        }
    }
}

fn reset_signals_if_interrupted<E: HeliosEnv>(ctx: &AsyncEvalContext<'_, E>, err: &ShellError) {
    if err.is_interrupt() {
        ctx.engine_state.signals().reset();
    }
}

fn prepare_error_handler<E: HeliosEnv>(
    ctx: &mut AsyncEvalContext<'_, E>,
    error_handler: ErrorHandler,
    error: Option<Spanned<ShellError>>,
) {
    if let Some(reg_id) = error_handler.error_register {
        if let Some(error) = error {
            ctx.stack.set_last_error(&error.item);
            let value = error.item.into_full_value(
                &StateWorkingSet::new(ctx.engine_state),
                ctx.stack,
                error.span,
            );
            ctx.put_reg(
                reg_id,
                AsyncExecutionData::from_body(AsyncPipelineData::value(value, None)),
            );
        } else {
            ctx.put_reg(reg_id, AsyncExecutionData::empty());
        }
    }
}

async fn eval_instruction_async<E: HeliosEnv>(
    ctx: &mut AsyncEvalContext<'_, E>,
    instruction: &Instruction,
    span: &Span,
    need_backtrace: bool,
) -> Result<InstructionResult, ShellError> {
    use InstructionResult::{Branch, Continue, EndFinally, Return, ReturnEarly, UnwindJump};

    instruction.check_interrupt(ctx.engine_state, span)?;

    match instruction {
        Instruction::Unreachable => Err(ShellError::IrEvalError {
            msg: "Reached unreachable code".into(),
            span: Some(*span),
        }),
        Instruction::LoadLiteral { dst, lit } => load_literal_async(ctx, *dst, lit, *span).await,
        Instruction::LoadValue { dst, val } => {
            ctx.put_reg(
                *dst,
                AsyncExecutionData::from_body(AsyncPipelineData::value(Value::clone(val), None)),
            );
            Ok(Continue)
        }
        Instruction::Move { dst, src } => {
            let val = ctx.take_reg(*src);
            ctx.put_reg(*dst, val);
            Ok(Continue)
        }
        Instruction::Clone { dst, src } => {
            let data = ctx.clone_reg(*src, *span)?;
            ctx.put_reg(*dst, AsyncExecutionData::from_body(data));
            Ok(Continue)
        }
        Instruction::Collect { src_dst } | Instruction::TryCollect { src_dst } => {
            let data = ctx.take_reg(*src_dst);
            let value = collect_async(data, *span).await?;
            ctx.put_reg(*src_dst, AsyncExecutionData::from_body(value));
            Ok(Continue)
        }
        Instruction::Span { src_dst } => {
            let mut data = ctx.take_reg(*src_dst);
            data.body = data.body.with_span(*span);
            ctx.put_reg(*src_dst, data);
            Ok(Continue)
        }
        Instruction::Drop { src } => {
            let _ = ctx.take_reg(*src);
            Ok(Continue)
        }
        Instruction::Drain { src } => {
            let data = ctx.take_reg(*src);
            let span_val = data.span().unwrap_or(*span);
            match data.body.drain_async().await {
                Ok(Some(code)) => {
                    ctx.stack.set_last_exit_code(code, span_val);
                    if let Some(non_zero) = core::num::NonZeroI32::new(code) {
                        let err = ShellError::NonZeroExitCode {
                            exit_code: non_zero,
                            span: span_val,
                        };
                        ctx.stack.set_last_error(&err);
                        return Err(err);
                    }
                    Ok(Continue)
                }
                Ok(None) => Ok(Continue),
                Err(err) => {
                    ctx.stack.set_last_error(&err);
                    Err(err)
                }
            }
        }
        Instruction::DrainIfEnd { src } => {
            let data = ctx.take_reg(*src);
            let collected = collect_async(data, *span).await?;
            ctx.put_reg(*src, AsyncExecutionData::from_body(collected));
            Ok(Continue)
        }
        Instruction::LoadVariable {
            dst,
            var_id,
            preserve_origin,
        } => {
            let data = if *var_id == nu_protocol::LAST_VARIABLE_ID {
                ctx.stack.defer_last_result_truncation_warning();
                AsyncPipelineData::from(ctx.stack.last_result_pipeline_data(*span))
            } else if *preserve_origin {
                let value = ctx
                    .stack
                    .get_var_with_origin(*var_id, *span)
                    .or_else(|err| ctx.engine_state.get_constant(*var_id).cloned().ok_or(err))?;
                AsyncPipelineData::value(value, None)
            } else {
                let value = get_var(ctx, *var_id, *span)?;
                AsyncPipelineData::value(value, None)
            };
            ctx.put_reg(*dst, AsyncExecutionData::from_body(data));
            Ok(Continue)
        }
        Instruction::StoreVariable { var_id, src } => {
            let value = ctx.collect_reg(*src, *span).await?;
            if nu_experimental::ENFORCE_RUNTIME_ANNOTATIONS.get() {
                let variable = ctx.engine_state.get_var(*var_id);
                let converted = check_assignment_type(value, &variable.ty, *span)?;
                ctx.stack.add_var(*var_id, converted);
            } else {
                ctx.stack.add_var(*var_id, value);
            }
            Ok(Continue)
        }
        Instruction::DropVariable { var_id } => {
            ctx.stack.remove_var(*var_id);
            Ok(Continue)
        }
        Instruction::LoadEnv { dst, key } => {
            let key = ctx.get_str(*key, *span)?;
            if let Some(value) = get_env_var(ctx, key) {
                let cloned = value.clone();
                ctx.put_reg(
                    *dst,
                    AsyncExecutionData::from_body(AsyncPipelineData::value(cloned, None)),
                );
                Ok(Continue)
            } else {
                Err(ShellError::CantFindColumn {
                    col_name: key.into(),
                    span: Some(*span),
                    src_span: *span,
                })
            }
        }
        Instruction::LoadEnvOpt { dst, key } => {
            let key = ctx.get_str(*key, *span)?;
            let value = get_env_var(ctx, key)
                .cloned()
                .unwrap_or_else(|| Value::nothing(*span));
            ctx.put_reg(
                *dst,
                AsyncExecutionData::from_body(AsyncPipelineData::value(value, None)),
            );
            Ok(Continue)
        }
        Instruction::StoreEnv { key, src } => {
            let key = ctx.get_str(*key, *span)?;
            let value = ctx.collect_reg(*src, *span).await?;
            let key = ctx.stack.get_env_var_name(ctx.engine_state, key);

            if !is_automatic_env_var(&key) {
                let is_config = env_var_eq(&key, var::CONFIG);
                let update_conversions = env_var_eq(&key, var::ENV_CONVERSIONS);

                ctx.stack.add_env_var(key.into_owned(), value.clone());

                if is_config {
                    ctx.stack.update_config(ctx.engine_state)?;
                }
                if update_conversions {
                    convert_env_vars(ctx.stack, ctx.engine_state, &value)?;
                }
                Ok(Continue)
            } else {
                Err(ShellError::AutomaticEnvVarSetManually {
                    envvar_name: key.into(),
                    span: *span,
                })
            }
        }
        Instruction::PushPositional { src } => {
            let val = ctx.collect_reg(*src, *span).await?;
            ctx.stack
                .arguments
                .push(Argument::Positional { span: *span, val });
            Ok(Continue)
        }
        Instruction::AppendRest { src } => {
            let vals = ctx.collect_reg(*src, *span).await?;
            ctx.stack
                .arguments
                .push(Argument::Spread { span: *span, vals });
            Ok(Continue)
        }
        Instruction::PushFlag { name } => {
            let data = ctx.data.clone();
            ctx.stack.arguments.push(Argument::Flag {
                data,
                name: *name,
                short: DataSlice::empty(),
                span: *span,
            });
            Ok(Continue)
        }
        Instruction::PushShortFlag { short } => {
            let data = ctx.data.clone();
            ctx.stack.arguments.push(Argument::Flag {
                data,
                name: DataSlice::empty(),
                short: *short,
                span: *span,
            });
            Ok(Continue)
        }
        Instruction::PushNamed { name, src } => {
            let val = ctx.collect_reg(*src, *span).await?.with_span(*span);
            let data = ctx.data.clone();
            ctx.stack.arguments.push(Argument::Named {
                data,
                name: *name,
                short: DataSlice::empty(),
                span: *span,
                val,
            });
            Ok(Continue)
        }
        Instruction::PushShortNamed { short, src } => {
            let val = ctx.collect_reg(*src, *span).await?.with_span(*span);
            let data = ctx.data.clone();
            ctx.stack.arguments.push(Argument::Named {
                data,
                name: DataSlice::empty(),
                short: *short,
                span: *span,
                val,
            });
            Ok(Continue)
        }
        Instruction::PushParserInfo { name, info } => {
            let data = ctx.data.clone();
            ctx.stack.arguments.push(Argument::ParserInfo {
                data,
                name: *name,
                info: info.clone(),
            });
            Ok(Continue)
        }
        Instruction::RedirectOut { mode } => {
            let (redir, file) = eval_redirection(ctx, mode, *span, RedirectionStream::Out)?;
            ctx.redirect_out = redir;
            ctx.redirect_out_file = file;
            Ok(Continue)
        }
        Instruction::RedirectErr { mode } => {
            let (redir, file) = eval_redirection(ctx, mode, *span, RedirectionStream::Err)?;
            ctx.redirect_err = redir;
            ctx.redirect_err_file = file;
            Ok(Continue)
        }
        Instruction::CheckErrRedirected { src } => match ctx.borrow_reg(*src) {
            AsyncPipelineData::ByteStream {
                stderr: Some(_), ..
            } => Ok(Continue),
            _ => Err(ShellError::Generic(GenericError::new(
                "Can't redirect stderr of internal command output",
                "piping stderr only works on external commands",
                *span,
            ))),
        },
        Instruction::OpenFile {
            file_num,
            path,
            append,
        } => {
            let path_val = ctx.collect_reg(*path, *span).await?;
            let raw = path_val.as_str()?;
            let cwd = current_cwd_async(ctx.engine_state, ctx.stack, ctx.env).await;
            let resolved = normalize_vfs_path(&cwd, raw);
            ctx.files[*file_num as usize] = Some(RedirectFile {
                path: resolved,
                append: *append,
                written: false,
            });
            Ok(Continue)
        }
        Instruction::WriteFile {
            file_num,
            src: src_reg,
        } => {
            let src = ctx.take_reg(*src_reg);
            let already_written = ctx
                .files
                .get(*file_num as usize)
                .and_then(Option::as_ref)
                .ok_or_else(|| ShellError::IrEvalError {
                    msg: format!("Tried to write to file #{file_num}, but it is not open"),
                    span: Some(*span),
                })?
                .written;
            if matches!(src.body, AsyncPipelineData::Empty) && already_written {
                ctx.put_reg(*src_reg, AsyncExecutionData::empty());
                return Ok(Continue);
            }
            let bytes = src.body.into_bytes_async(*span).await?;
            write_redirect_slot(ctx, *file_num, &bytes, *span).await?;
            ctx.put_reg(*src_reg, AsyncExecutionData::empty());
            Ok(Continue)
        }
        Instruction::CloseFile { file_num } => {
            if let Some(file) = ctx.files[*file_num as usize].take() {
                if !file.written {
                    ctx.env
                        .write_file(&file.path, &[], file.append, true)
                        .await
                        .map_err(|err| {
                            err.into_shell_error("failed to create redirection file", *span)
                        })?;
                }
                Ok(Continue)
            } else {
                Err(ShellError::IrEvalError {
                    msg: format!("Tried to close file #{file_num}, but it is not open"),
                    span: Some(*span),
                })
            }
        }
        Instruction::Call { decl_id, src_dst } => {
            let input = ctx.take_reg(*src_dst);
            let mut result = eval_call_async(ctx, *decl_id, *span, input.body).await?;
            if need_backtrace && let AsyncPipelineData::Sync(sync_data) = &mut result {
                match sync_data {
                    PipelineData::ByteStream(s, ..) => s.push_caller_span(*span),
                    PipelineData::ListStream(s, ..) => s.push_caller_span(*span),
                    _ => (),
                }
            }
            ctx.put_reg(*src_dst, AsyncExecutionData::from_body(result));
            Ok(Continue)
        }
        Instruction::StringAppend { src_dst, val } => {
            let string_value = ctx.collect_reg(*src_dst, *span).await?;
            let operand_value = ctx.collect_reg(*val, *span).await?;
            let string_span = string_value.span();

            let mut string = string_value.into_string()?;
            let operand = if let Value::String { val, .. } = operand_value {
                val
            } else {
                operand_value.to_expanded_string(", ", &ctx.stack.get_config(ctx.engine_state))
            };
            string.push_str(&operand);

            ctx.put_reg(
                *src_dst,
                AsyncExecutionData::from_body(AsyncPipelineData::value(
                    Value::string(string, string_span),
                    None,
                )),
            );
            Ok(Continue)
        }
        Instruction::GlobFrom { src_dst, no_expand } => {
            let string_value = ctx.collect_reg(*src_dst, *span).await?;
            let glob_value = if matches!(string_value, Value::Glob { .. }) {
                string_value
            } else {
                let string = string_value.into_string()?;
                Value::glob(string, *no_expand, *span)
            };
            ctx.put_reg(
                *src_dst,
                AsyncExecutionData::from_body(AsyncPipelineData::value(glob_value, None)),
            );
            Ok(Continue)
        }
        Instruction::ListPush { src_dst, item } => {
            let list_value = ctx.collect_reg(*src_dst, *span).await?;
            let item = ctx.collect_reg(*item, *span).await?;
            let list_span = list_value.span();
            let mut list = list_value.into_list()?;
            list.push(item);
            ctx.put_reg(
                *src_dst,
                AsyncExecutionData::from_body(AsyncPipelineData::value(
                    Value::list(list, list_span),
                    None,
                )),
            );
            Ok(Continue)
        }
        Instruction::ListSpread { src_dst, items } => {
            let list_value = ctx.collect_reg(*src_dst, *span).await?;
            let items = ctx.collect_reg(*items, *span).await?;
            let list_span = list_value.span();
            let items_span = items.span();
            let items = match items {
                Value::List { vals, .. } => vals.into_owned(),
                Value::Nothing { .. } => Vec::new(),
                _ => return Err(ShellError::CannotSpreadAsList { span: items_span }),
            };
            let mut list = list_value.into_list()?;
            list.extend(items);
            ctx.put_reg(
                *src_dst,
                AsyncExecutionData::from_body(AsyncPipelineData::value(
                    Value::list(list, list_span),
                    None,
                )),
            );
            Ok(Continue)
        }
        Instruction::RecordInsert { src_dst, key, val } => {
            let record_value = ctx.collect_reg(*src_dst, *span).await?;
            let key = ctx.collect_reg(*key, *span).await?;
            let val = ctx.collect_reg(*val, *span).await?;
            let record_span = record_value.span();
            let mut record = record_value.into_record()?;

            let key = key.coerce_into_string()?;
            if let Some(old_value) = record.insert(&key, val) {
                let first_item = ctx.record_item_of_key(*src_dst, &record, &key);
                return Err(ShellError::ColumnDefinedTwice {
                    col_name: key,
                    second_use: *span,
                    first_use: first_item.map_or_else(|| old_value.span(), |item| item.span),
                    help: first_item
                        .filter(|item| item.is_spread)
                        .map(|_| ShellError::RECORD_SPREAD_DUPLICATE_HELP.into()),
                });
            }
            ctx.push_record_item(*src_dst, record.len(), *span, false);
            ctx.put_reg(
                *src_dst,
                AsyncExecutionData::from_body(AsyncPipelineData::value(
                    Value::record(record, record_span),
                    None,
                )),
            );
            Ok(Continue)
        }
        Instruction::RecordSpread { src_dst, items } => {
            let record_value = ctx.collect_reg(*src_dst, *span).await?;
            let items = ctx.collect_reg(*items, *span).await?;
            let record_span = record_value.span();
            let items_span = items.span();
            let mut record = record_value.into_record()?;
            let items = match items {
                Value::Record { val, .. } => val.into_owned(),
                Value::Nothing { .. } => Record::new(),
                _ => return Err(ShellError::CannotSpreadAsRecord { span: items_span }),
            };
            for (key, val) in items {
                if let Some(first_value) = record.insert(&key, val) {
                    let first_use = ctx
                        .record_item_of_key(*src_dst, &record, &key)
                        .map_or_else(|| first_value.span(), |item| item.span);
                    return Err(ShellError::ColumnDefinedTwice {
                        col_name: key,
                        second_use: *span,
                        first_use,
                        help: Some(ShellError::RECORD_SPREAD_DUPLICATE_HELP.into()),
                    });
                }
            }
            ctx.push_record_item(*src_dst, record.len(), *span, true);
            ctx.put_reg(
                *src_dst,
                AsyncExecutionData::from_body(AsyncPipelineData::value(
                    Value::record(record, record_span),
                    None,
                )),
            );
            Ok(Continue)
        }
        Instruction::Not { src_dst } => {
            let bool_val = ctx.collect_reg(*src_dst, *span).await?;
            let negated = !bool_val.as_bool()?;
            ctx.put_reg(
                *src_dst,
                AsyncExecutionData::from_body(AsyncPipelineData::value(
                    Value::bool(negated, bool_val.span()),
                    None,
                )),
            );
            Ok(Continue)
        }
        Instruction::BinaryOp { lhs_dst, op, rhs } => {
            binary_op_async(ctx, *lhs_dst, op, *rhs, *span).await
        }
        Instruction::FollowCellPath { src_dst, path } => {
            let data = ctx.take_reg(*src_dst);
            let path = ctx.take_reg(*path);
            let path_val = path.body.into_value_async(*span).await?;
            match path_val {
                Value::CellPath { val: path, .. } => {
                    let from_ans = data.body.metadata_ref().is_some_and(|m| {
                        m.custom.get(Stack::ANS_LAST_RESULT_METADATA_KEY).is_some()
                    });
                    let is_ans_last = from_ans
                        && path.members.len() == 1
                        && matches!(
                            &path.members[0],
                            PathMember::String { val, .. } if val == "last"
                        );
                    let src_meta = data.body.metadata_ref().cloned();
                    let sync_body = data.body.into_sync_pipeline_data(*span).await?;
                    let value = sync_body.follow_cell_path(&path.members, *span)?;
                    let metadata = if is_ans_last {
                        src_meta.map(|mut m| {
                            m.custom.remove(Stack::ANS_LAST_RESULT_METADATA_KEY);
                            m
                        })
                    } else {
                        None
                    };
                    ctx.put_reg(
                        *src_dst,
                        AsyncExecutionData::from_body(AsyncPipelineData::value(value, metadata)),
                    );
                    Ok(Continue)
                }
                Value::Error { error, .. } => Err(*error),
                other => Err(ShellError::TypeMismatch {
                    err_message: "expected cell path".into(),
                    span: other.span(),
                }),
            }
        }
        Instruction::CloneCellPath { dst, src, path } => {
            let value = ctx.clone_reg_value(*src, *span)?;
            let path = ctx.take_reg(*path);
            let path_val = path.body.into_value_async(*span).await?;
            match path_val {
                Value::CellPath { val: path, .. } => {
                    let value = value.follow_cell_path(&path.members)?;
                    ctx.put_reg(
                        *dst,
                        AsyncExecutionData::from_body(AsyncPipelineData::value(
                            value.into_owned(),
                            None,
                        )),
                    );
                    Ok(Continue)
                }
                Value::Error { error, .. } => Err(*error),
                other => Err(ShellError::TypeMismatch {
                    err_message: "expected cell path".into(),
                    span: other.span(),
                }),
            }
        }
        Instruction::UpsertCellPath {
            src_dst,
            path,
            new_value,
        } => {
            let mut data = ctx.take_reg(*src_dst).body;
            let metadata = data.take_metadata();
            let mut value = data.into_value_async(*span).await?;
            let path_val = ctx.take_reg(*path).body.into_value_async(*span).await?;
            let new_value = ctx.collect_reg(*new_value, *span).await?;
            match path_val {
                Value::CellPath { val: path, .. } => {
                    value.upsert_data_at_cell_path(&path.members, new_value)?;
                    ctx.put_reg(
                        *src_dst,
                        AsyncExecutionData::from_body(AsyncPipelineData::value(value, metadata)),
                    );
                    Ok(Continue)
                }
                Value::Error { error, .. } => Err(*error),
                other => Err(ShellError::TypeMismatch {
                    err_message: "expected cell path".into(),
                    span: other.span(),
                }),
            }
        }
        Instruction::UpdateVarCellPath {
            var_id,
            cell_path,
            new_value,
        } => {
            let new_val = ctx.collect_reg(*new_value, *span).await?;
            let path_val = ctx
                .take_reg(*cell_path)
                .body
                .into_value_async(*span)
                .await?;
            match path_val {
                Value::CellPath { val: path, .. } => {
                    let new_val = if nu_experimental::ENFORCE_RUNTIME_ANNOTATIONS.get() {
                        let variable = ctx.engine_state.get_var(*var_id);
                        if let Some(expected_ty) = variable.ty.follow_cell_path(&path.members) {
                            check_assignment_type(new_val, &expected_ty, *span)?
                        } else {
                            new_val
                        }
                    } else {
                        new_val
                    };
                    ctx.stack
                        .upsert_var_cell_path(*var_id, &path.members, new_val, *span)?;
                    Ok(Continue)
                }
                Value::Error { error, .. } => Err(*error),
                other => Err(ShellError::TypeMismatch {
                    err_message: "expected cell path".into(),
                    span: other.span(),
                }),
            }
        }
        Instruction::Jump { index } => Ok(Branch(*index)),
        Instruction::BranchIf { cond, index } => {
            let val = ctx.collect_reg(*cond, *span).await?;
            let flag = match val {
                Value::Bool { val, .. } => val,
                Value::Error { error, .. } => return Err(*error),
                other => {
                    return Err(ShellError::TypeMismatch {
                        err_message: "expected bool".into(),
                        span: other.span(),
                    });
                }
            };
            if flag {
                Ok(Branch(*index))
            } else {
                Ok(Continue)
            }
        }
        Instruction::BranchIfEmpty { src, index } => {
            if ctx.borrow_reg(*src).is_empty_or_nothing() {
                Ok(Branch(*index))
            } else {
                Ok(Continue)
            }
        }
        Instruction::Match {
            pattern,
            src,
            index,
        } => {
            let value = ctx.clone_reg_value(*src, *span)?;
            ctx.matches.clear();
            if pattern.match_value(&value, &mut ctx.matches) {
                for (var_id, match_value) in ctx.matches.drain(..) {
                    ctx.stack.add_var(var_id, match_value);
                }
                Ok(Branch(*index))
            } else {
                ctx.matches.clear();
                Ok(Continue)
            }
        }
        Instruction::CheckMatchGuard { src } => {
            if matches!(
                ctx.borrow_reg(*src),
                AsyncPipelineData::Value(Value::Bool { .. }, _)
                    | AsyncPipelineData::Sync(PipelineData::Value(Value::Bool { .. }, _))
            ) {
                Ok(Continue)
            } else {
                Err(ShellError::MatchGuardNotBool { span: *span })
            }
        }
        Instruction::Iterate {
            dst,
            stream,
            end_index,
        } => eval_iterate_async(ctx, *dst, *stream, *end_index, *span).await,
        Instruction::UnwindJump { index, handlers } => Ok(UnwindJump {
            index: *index,
            handlers: *handlers,
        }),
        Instruction::OnError { index } => {
            ctx.stack
                .error_handlers
                .push(TryHandler::Catch(ErrorHandler {
                    handler_index: *index,
                    error_register: None,
                }));
            Ok(Continue)
        }
        Instruction::OnErrorInto { index, dst } => {
            ctx.stack
                .error_handlers
                .push(TryHandler::Catch(ErrorHandler {
                    handler_index: *index,
                    error_register: Some(*dst),
                }));
            Ok(Continue)
        }
        Instruction::FinallyInto { index, dst } => {
            ctx.stack
                .error_handlers
                .push(TryHandler::Finally(ErrorHandler {
                    handler_index: *index,
                    error_register: Some(*dst),
                }));
            Ok(Continue)
        }
        Instruction::PopErrorHandler => {
            match ctx.stack.error_handlers.pop(ctx.error_handler_base) {
                Some(TryHandler::Catch(_)) => Ok(Continue),
                handler => Err(ShellError::IrEvalError {
                    msg: format!("pop-error-handler expected a catch handler, found {handler:?}"),
                    span: Some(*span),
                }),
            }
        }
        Instruction::BeginFinally => match ctx.stack.error_handlers.pop(ctx.error_handler_base) {
            Some(TryHandler::Finally(_)) => {
                ctx.stack.error_handlers.push(TryHandler::RunningFinally);
                ctx.finally_resumes.push(None);
                Ok(Continue)
            }
            handler => Err(ShellError::IrEvalError {
                msg: format!("begin-finally expected a finally handler, found {handler:?}"),
                span: Some(*span),
            }),
        },
        Instruction::EndFinally => Ok(EndFinally),
        Instruction::ReturnEarly { src } => Ok(ReturnEarly(*src)),
        Instruction::Return { src } => Ok(Return(*src)),
    }
}

async fn load_literal_async<E: HeliosEnv>(
    ctx: &mut AsyncEvalContext<'_, E>,
    dst: RegId,
    lit: &Literal,
    span: Span,
) -> Result<InstructionResult, ShellError> {
    if matches!(lit, Literal::Record { .. }) {
        ctx.record_items[dst.get() as usize].clear();
    }
    if matches!(lit, Literal::Empty) {
        ctx.put_reg(dst, AsyncExecutionData::empty());
    } else {
        let value = literal_value_async(ctx, lit, span).await?;
        ctx.put_reg(
            dst,
            AsyncExecutionData::from_body(AsyncPipelineData::value(value, None)),
        );
    }
    Ok(InstructionResult::Continue)
}

async fn literal_value_async<E: HeliosEnv>(
    ctx: &mut AsyncEvalContext<'_, E>,
    lit: &Literal,
    span: Span,
) -> Result<Value, ShellError> {
    Ok(match lit {
        Literal::Bool(b) => Value::bool(*b, span),
        Literal::Int(i) => Value::int(*i, span),
        Literal::Float(f) => Value::float(*f, span),
        Literal::Filesize(q) => Value::filesize(*q, span),
        Literal::Duration(q) => Value::duration(*q, span),
        Literal::Binary(bin) => Value::binary(&ctx.data[*bin], span),
        Literal::Block(block_id) | Literal::RowCondition(block_id) | Literal::Closure(block_id) => {
            let block = ctx.engine_state.get_block(*block_id);
            let captures = block
                .captures
                .iter()
                .map(|(var_id, cap_span)| {
                    get_var(ctx, *var_id, *cap_span).map(|val| (*var_id, val))
                })
                .collect::<Result<Vec<_>, ShellError>>()?;
            Value::closure(
                Closure {
                    block_id: *block_id,
                    captures,
                },
                span,
            )
        }
        Literal::Range {
            start,
            step,
            end,
            inclusion,
        } => {
            let start = ctx.collect_reg(*start, span).await?;
            let step = ctx.collect_reg(*step, span).await?;
            let end = ctx.collect_reg(*end, span).await?;
            let range = Range::new(start, step, end, *inclusion, span)?;
            Value::range(range, span)
        }
        Literal::List { capacity } => Value::list(Vec::with_capacity(*capacity), span),
        Literal::Record { capacity } => Value::record(Record::with_capacity(*capacity), span),
        Literal::Filepath {
            val: path,
            no_expand,
        } => {
            let path = ctx.get_str(*path, span)?;
            if *no_expand {
                Value::string(path, span)
            } else {
                let home = stack_home_dir(ctx.engine_state, ctx.stack);
                Value::string(expand_vfs_tilde_and_ndots(path, home.as_deref()), span)
            }
        }
        Literal::Directory {
            val: path,
            no_expand,
        } => {
            let path = ctx.get_str(*path, span)?;
            if path == "-" {
                Value::string("-", span)
            } else if *no_expand {
                Value::string(path, span)
            } else {
                let home = stack_home_dir(ctx.engine_state, ctx.stack);
                Value::string(expand_vfs_tilde_and_ndots(path, home.as_deref()), span)
            }
        }
        Literal::GlobPattern { val, no_expand } => {
            Value::glob(ctx.get_str(*val, span)?, *no_expand, span)
        }
        Literal::String(s) | Literal::RawString(s) => Value::string(ctx.get_str(*s, span)?, span),
        Literal::CellPath(path) => Value::cell_path(CellPath::clone(path), span),
        Literal::Date(dt) => Value::date(**dt, span),
        Literal::Nothing | Literal::Empty => Value::nothing(span),
    })
}

async fn binary_op_async<E: HeliosEnv>(
    ctx: &mut AsyncEvalContext<'_, E>,
    lhs_dst: RegId,
    op: &Operator,
    rhs: RegId,
    span: Span,
) -> Result<InstructionResult, ShellError> {
    let lhs_val = ctx.collect_reg(lhs_dst, span).await?;
    let rhs_val = ctx.collect_reg(rhs, span).await?;

    if let Value::Error { error, .. } = lhs_val {
        return Err(*error);
    }
    if let Value::Error { error, .. } = rhs_val {
        return Err(*error);
    }

    let op_span = span;
    let result = match op {
        Operator::Comparison(cmp) => match cmp {
            Comparison::Equal => lhs_val.eq(op_span, &rhs_val, span)?,
            Comparison::NotEqual => lhs_val.ne(op_span, &rhs_val, span)?,
            Comparison::LessThan => lhs_val.lt(op_span, &rhs_val, span)?,
            Comparison::GreaterThan => lhs_val.gt(op_span, &rhs_val, span)?,
            Comparison::LessThanOrEqual => lhs_val.lte(op_span, &rhs_val, span)?,
            Comparison::GreaterThanOrEqual => lhs_val.gte(op_span, &rhs_val, span)?,
            Comparison::RegexMatch => {
                lhs_val.regex_match(ctx.engine_state, op_span, &rhs_val, false, span)?
            }
            Comparison::NotRegexMatch => {
                lhs_val.regex_match(ctx.engine_state, op_span, &rhs_val, true, span)?
            }
            Comparison::In => lhs_val.r#in(op_span, &rhs_val, span)?,
            Comparison::NotIn => lhs_val.not_in(op_span, &rhs_val, span)?,
            Comparison::Has => lhs_val.has(op_span, &rhs_val, span)?,
            Comparison::NotHas => lhs_val.not_has(op_span, &rhs_val, span)?,
            Comparison::StartsWith => lhs_val.starts_with(op_span, &rhs_val, span)?,
            Comparison::NotStartsWith => lhs_val.not_starts_with(op_span, &rhs_val, span)?,
            Comparison::EndsWith => lhs_val.ends_with(op_span, &rhs_val, span)?,
            Comparison::NotEndsWith => lhs_val.not_ends_with(op_span, &rhs_val, span)?,
            Comparison::OlderThan => lhs_val.older_than(op_span, &rhs_val, span)?,
            Comparison::NewerThan => lhs_val.newer_than(op_span, &rhs_val, span)?,
        },
        Operator::Math(mat) => match mat {
            Math::Add => lhs_val.add(op_span, &rhs_val, span)?,
            Math::Subtract => lhs_val.sub(op_span, &rhs_val, span)?,
            Math::Multiply => lhs_val.mul(op_span, &rhs_val, span)?,
            Math::Divide => lhs_val.div(op_span, &rhs_val, span)?,
            Math::FloorDivide => lhs_val.floor_div(op_span, &rhs_val, span)?,
            Math::Modulo => lhs_val.modulo(op_span, &rhs_val, span)?,
            Math::Pow => lhs_val.pow(op_span, &rhs_val, span)?,
            Math::Concatenate => lhs_val.concat(op_span, &rhs_val, span)?,
        },
        Operator::Boolean(bl) => match bl {
            Boolean::Or => lhs_val.or(op_span, &rhs_val, span)?,
            Boolean::Xor => lhs_val.xor(op_span, &rhs_val, span)?,
            Boolean::And => lhs_val.and(op_span, &rhs_val, span)?,
        },
        Operator::Bits(bit) => match bit {
            Bits::BitOr => lhs_val.bit_or(op_span, &rhs_val, span)?,
            Bits::BitXor => lhs_val.bit_xor(op_span, &rhs_val, span)?,
            Bits::BitAnd => lhs_val.bit_and(op_span, &rhs_val, span)?,
            Bits::ShiftLeft => lhs_val.bit_shl(op_span, &rhs_val, span)?,
            Bits::ShiftRight => lhs_val.bit_shr(op_span, &rhs_val, span)?,
        },
        Operator::Assignment(_) => {
            return Err(ShellError::IrEvalError {
                msg: "can't eval assignment with the `binary-op` instruction".into(),
                span: Some(span),
            });
        }
    };

    ctx.put_reg(
        lhs_dst,
        AsyncExecutionData::from_body(AsyncPipelineData::value(result, None)),
    );
    Ok(InstructionResult::Continue)
}

async fn eval_call_async<E: HeliosEnv>(
    ctx: &mut AsyncEvalContext<'_, E>,
    decl_id: DeclId,
    head: Span,
    input: AsyncPipelineData,
) -> Result<AsyncPipelineData, ShellError> {
    let args_base = ctx.args_base;
    let args_len = ctx.stack.arguments.get_len(args_base);
    let stderr_pipe_separate = matches!(
        ctx.redirect_err.as_ref(),
        Some(Redirection::Pipe(OutDest::PipeSeparate))
    );
    let redir_out = ctx.redirect_out.take();
    let redir_err = ctx.redirect_err.take();
    let out_file_num = ctx.redirect_out_file.take();
    let err_file_num = ctx.redirect_err_file.take();

    let result = {
        let mut caller_stack = ctx.stack.push_redirection(redir_out, redir_err);
        let mut rt = EvalRuntime {
            env: ctx.env,
            registry: ctx.registry,
            runtime_scope: ctx.runtime_scope,
        };
        eval_call_frame_async(
            ctx.engine_state,
            &mut caller_stack,
            &mut rt,
            decl_id,
            head,
            (args_base, args_len),
            input,
        )
        .await
    };

    ctx.stack.arguments.leave_frame(args_base);
    ctx.redirect_out = None;
    ctx.redirect_err = None;

    let result = match result {
        Err(err) if stderr_pipe_separate => {
            Ok(AsyncPipelineData::value(Value::error(err, head), None))
        }
        other => other,
    }?;

    // Handle file redirections (`o>`, `o>>`, `e>`, `e>>`, `o+e>`, `o+e>>`) through HeliosEnv.
    match (out_file_num, err_file_num) {
        (Some(out_num), Some(err_num)) if out_num == err_num => {
            if let AsyncPipelineData::ByteStream {
                stream,
                stderr,
                exit_code,
                ..
            } = result
            {
                let (out_res, err_res) =
                    futures_lite::future::zip(collect_byte_receiver(stream), async move {
                        match stderr {
                            Some(rx) => collect_byte_receiver(rx).await,
                            None => Ok(Vec::new()),
                        }
                    })
                    .await;
                let mut combined = out_res?;
                combined.extend_from_slice(&err_res?);
                if let Some(exit_rx) = exit_code {
                    let _ = exit_rx.recv().await;
                }
                write_redirect_slot(ctx, out_num, &combined, head).await?;
                return Ok(AsyncPipelineData::Empty);
            }
            let bytes = result.into_bytes_async(head).await?;
            write_redirect_slot(ctx, out_num, &bytes, head).await?;
            Ok(AsyncPipelineData::Empty)
        }
        (out_opt, Some(err_num)) => {
            if let AsyncPipelineData::ByteStream {
                stream,
                stderr,
                exit_code,
                span,
                stream_type,
                metadata,
            } = result
            {
                if let Some(out_num) = out_opt {
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
                    if let Some(exit_rx) = exit_code {
                        let _ = exit_rx.recv().await;
                    }
                    write_redirect_slot(ctx, out_num, &out_bytes, head).await?;
                    write_redirect_slot(ctx, err_num, &err_bytes, head).await?;
                    return Ok(AsyncPipelineData::Empty);
                }

                if let Some(err_rx) = stderr {
                    // Drain stdout and stderr concurrently so a child writing more than
                    // `STREAM_CHANNEL_CAPACITY` stdout chunks before closing stderr cannot
                    // backpressure-deadlock.
                    let (out_res, err_res) = futures_lite::future::zip(
                        collect_byte_receiver(stream),
                        collect_byte_receiver(err_rx),
                    )
                    .await;
                    let out_bytes = out_res?;
                    let err_bytes = err_res?;
                    write_redirect_slot(ctx, err_num, &err_bytes, head).await?;
                    let (out_tx, out_rx) = async_channel::bounded(1);
                    if !out_bytes.is_empty() {
                        let _ = out_tx.send(Ok(out_bytes)).await;
                    }
                    drop(out_tx);
                    return Ok(AsyncPipelineData::ByteStream {
                        stream: out_rx,
                        stderr: None,
                        exit_code,
                        span,
                        stream_type,
                        metadata,
                    });
                }
                return Ok(AsyncPipelineData::ByteStream {
                    stream,
                    stderr: None,
                    exit_code,
                    span,
                    stream_type,
                    metadata,
                });
            }

            if let Some(out_num) = out_opt {
                let bytes = result.into_bytes_async(head).await?;
                write_redirect_slot(ctx, out_num, &bytes, head).await?;
                return Ok(AsyncPipelineData::Empty);
            }
            Ok(result)
        }
        (Some(out_num), None) => {
            let bytes = result.into_bytes_async(head).await?;
            write_redirect_slot(ctx, out_num, &bytes, head).await?;
            Ok(AsyncPipelineData::Empty)
        }
        (None, None) => Ok(result),
    }
}

async fn write_redirect_slot<E: HeliosEnv>(
    ctx: &mut AsyncEvalContext<'_, E>,
    file_num: u32,
    bytes: &[u8],
    span: Span,
) -> Result<(), ShellError> {
    let (path, append) = {
        let slot = ctx
            .files
            .get(file_num as usize)
            .and_then(Option::as_ref)
            .ok_or_else(|| ShellError::IrEvalError {
                msg: format!("Tried to write to file #{file_num}, but it is not open"),
                span: Some(span),
            })?;
        (slot.path.clone(), slot.append || slot.written)
    };
    ctx.env
        .write_file(&path, bytes, append, true)
        .await
        .map_err(|err| err.into_shell_error("failed to write redirection file", span))?;
    if let Some(slot) = ctx
        .files
        .get_mut(file_num as usize)
        .and_then(Option::as_mut)
    {
        slot.written = true;
    }
    Ok(())
}

async fn eval_call_frame_async<E: HeliosEnv>(
    engine_state: &EngineState,
    caller_stack: &mut Stack,
    rt: &mut EvalRuntime<'_, E>,
    decl_id: DeclId,
    head: Span,
    (args_base, args_len): (usize, usize),
    input: AsyncPipelineData,
) -> Result<AsyncPipelineData, ShellError> {
    let decl = engine_state.get_decl(decl_id);
    if let Some(block_id) = decl.block_id() {
        let block = engine_state.get_block(block_id);
        check_async_input_types(&input, &block.signature, head)?;
        let args_len =
            normalize_call_arguments(&block.signature, caller_stack, args_base, args_len)?;
        let mut callee_stack = caller_stack.gather_captures(engine_state, &block.captures);
        gather_arguments(
            engine_state,
            block,
            caller_stack,
            &mut callee_stack,
            args_base,
            args_len,
            head,
        )?;
        let mut callee_stack = callee_stack.with_invocation_stdout(caller_stack.stdout().clone());
        callee_stack.recursion_count += 1;

        let result = eval_block_async(engine_state, &mut callee_stack, block, input, rt)
            .await
            .map(|exec| exec.body);

        if block.redirect_env {
            redirect_env(engine_state, caller_stack, &callee_stack);
        }
        return result;
    }

    let signature = engine_state.get_signature_cached(decl_id);
    let allow_error_input = matches!(
        input,
        AsyncPipelineData::Value(Value::Error { .. }, ..)
            | AsyncPipelineData::Sync(PipelineData::Value(Value::Error { .. }, ..))
    ) && engine_state
        .find_decl(b"ignore", &[])
        .is_some_and(|ignore_decl_id| ignore_decl_id == decl_id);
    if !allow_error_input {
        check_async_input_types(&input, &signature, head)?;
    }

    let args_len = normalize_call_arguments(&signature, caller_stack, args_base, args_len)?;
    let span = Span::merge_many(
        std::iter::once(head).chain(
            caller_stack
                .arguments
                .get_args(args_base, args_len)
                .iter()
                .flat_map(|arg| arg.span()),
        ),
    );
    let call = Call {
        decl_id,
        head,
        span,
        args_base,
        args_len,
    };

    if let Some(async_cmd) = rt.registry.get(decl_id) {
        let engine_call = (&call).into();
        let mut cmd_ctx = AsyncCommandContext {
            engine_state,
            stack: caller_stack,
            call: &engine_call,
            env: rt.env,
            registry: rt.registry,
            runtime_scope: rt.runtime_scope,
        };
        return async_cmd.run_async(&mut cmd_ctx, input).await;
    }

    // Pure in-memory synchronous Nushell command (`nu-command` / `nu-cmd-lang`).
    let mut sync_input = input.into_sync_pipeline_data(head).await?;
    if let PipelineData::Value(v, ..) = &mut sync_input {
        v.inject_signals(engine_state);
    }
    let output = decl.run(engine_state, caller_stack, &(&call).into(), sync_input)?;
    Ok(AsyncPipelineData::from(output))
}

async fn eval_iterate_async<E: HeliosEnv>(
    ctx: &mut AsyncEvalContext<'_, E>,
    dst: RegId,
    stream: RegId,
    end_index: usize,
    span: Span,
) -> Result<InstructionResult, ShellError> {
    let mut data = ctx.take_reg(stream);
    if let AsyncPipelineData::ListStream {
        stream: rx,
        span: _,
        metadata: _,
    } = &mut data.body
    {
        if let Ok(val) = rx.recv().await {
            if let Value::Error { error, .. } = val {
                return Err(*error);
            }
            ctx.put_reg(
                dst,
                AsyncExecutionData::from_body(AsyncPipelineData::value(val, None)),
            );
            ctx.put_reg(stream, data);
            Ok(InstructionResult::Continue)
        } else {
            ctx.put_reg(dst, AsyncExecutionData::empty());
            Ok(InstructionResult::Branch(end_index))
        }
    } else {
        let (rx, stream_span, metadata) = data.body.into_list_stream_receiver(span).await?;
        if let Ok(val) = rx.recv().await {
            if let Value::Error { error, .. } = val {
                return Err(*error);
            }
            ctx.put_reg(
                dst,
                AsyncExecutionData::from_body(AsyncPipelineData::value(val, None)),
            );
            ctx.put_reg(
                stream,
                AsyncExecutionData::from_body(AsyncPipelineData::ListStream {
                    stream: rx,
                    span: stream_span,
                    metadata,
                }),
            );
            Ok(InstructionResult::Continue)
        } else {
            ctx.put_reg(dst, AsyncExecutionData::empty());
            Ok(InstructionResult::Branch(end_index))
        }
    }
}

async fn collect_async(
    pipe: AsyncExecutionData,
    fallback_span: Span,
) -> Result<AsyncPipelineData, ShellError> {
    let mut data = pipe.body;
    let span = data.span().unwrap_or(fallback_span);
    let metadata = data.take_metadata().and_then(|m| m.for_collect());
    let value = data.into_value_async(span).await?;
    Ok(AsyncPipelineData::value(value, metadata))
}

pub(crate) async fn current_cwd_async<E: HeliosEnv>(
    engine_state: &EngineState,
    stack: &Stack,
    env: &E,
) -> String {
    if let Some(pwd) = stack
        .get_env_var(engine_state, "PWD")
        .and_then(|v| v.as_str().ok())
    {
        return pwd.to_owned();
    }
    env.cwd().await.unwrap_or_else(|_| String::from("/"))
}

enum RedirectionStream {
    Out,
    Err,
}

fn eval_redirection<E: HeliosEnv>(
    ctx: &AsyncEvalContext<'_, E>,
    mode: &RedirectMode,
    span: Span,
    which: RedirectionStream,
) -> Result<(Option<Redirection>, Option<u32>), ShellError> {
    match mode {
        RedirectMode::Pipe => Ok((Some(Redirection::Pipe(OutDest::Pipe)), None)),
        RedirectMode::PipeRaw => Ok((Some(Redirection::Pipe(OutDest::PipeRaw)), None)),
        RedirectMode::PipeSeparate => Ok((Some(Redirection::Pipe(OutDest::PipeSeparate)), None)),
        RedirectMode::Value => Ok((Some(Redirection::Pipe(OutDest::Value)), None)),
        RedirectMode::Null => Ok((Some(Redirection::Pipe(OutDest::Null)), None)),
        RedirectMode::Inherit => Ok((Some(Redirection::Pipe(OutDest::Inherit)), None)),
        RedirectMode::Print => Ok((Some(Redirection::Pipe(OutDest::Print)), None)),
        RedirectMode::File { file_num } => {
            if ctx
                .files
                .get(*file_num as usize)
                .and_then(Option::as_ref)
                .is_none()
            {
                return Err(ShellError::IrEvalError {
                    msg: format!("Tried to redirect to file #{file_num}, but it is not open"),
                    span: Some(span),
                });
            }
            Ok((Some(Redirection::Pipe(OutDest::Pipe)), Some(*file_num)))
        }
        RedirectMode::Caller => Ok((
            match which {
                RedirectionStream::Out => ctx.stack.pipe_stdout().cloned().map(Redirection::Pipe),
                RedirectionStream::Err => ctx.stack.pipe_stderr().cloned().map(Redirection::Pipe),
            },
            None,
        )),
    }
}

pub(crate) fn stack_home_dir(engine_state: &EngineState, stack: &Stack) -> Option<String> {
    stack
        .get_env_var(engine_state, "HOME")
        .and_then(|val| val.as_str().ok())
        .map(ToOwned::to_owned)
}

/// Expand leading `~` strictly from Helios's `$env.HOME` (never host OS `HOME`/passwd)
/// and normalize Nushell `...` ndots segments.
pub(crate) fn expand_vfs_tilde_and_ndots(raw: &str, home: Option<&str>) -> String {
    let tilde_expanded = if raw == "~" {
        home.unwrap_or("/").to_owned()
    } else if let Some(rest) = raw.strip_prefix("~/") {
        let base = home.unwrap_or("/");
        if base == "/" {
            format!("/{rest}")
        } else {
            format!("{}/{rest}", base.trim_end_matches('/'))
        }
    } else {
        raw.to_owned()
    };
    expand_ndots_safe(tilde_expanded)
        .to_string_lossy()
        .into_owned()
}

/// Resolve a user-supplied VFS path against `cwd`, expanding leading `~` from
/// `$env.HOME` (never ambient host OS `HOME`) when `expand` is `true`.
pub(crate) fn resolve_vfs_path(
    engine_state: &EngineState,
    stack: &Stack,
    cwd: &str,
    raw: &str,
    expand: bool,
) -> String {
    if expand {
        let home = stack_home_dir(engine_state, stack);
        let expanded = expand_vfs_tilde_and_ndots(raw, home.as_deref());
        normalize_vfs_path(cwd, &expanded)
    } else {
        normalize_vfs_path(cwd, raw)
    }
}

fn expand_external_glob_arg(val: Value, home: Option<&str>) -> Value {
    if let Value::Glob {
        val: ref s,
        no_expand,
        internal_span,
        ..
    } = val
        && !no_expand
        && !nu_glob::is_glob(s)
    {
        return Value::string(expand_vfs_tilde_and_ndots(s, home), internal_span);
    }
    val
}

fn find_named_var_id(
    sig: &Signature,
    name: &[u8],
    short: &[u8],
    span: Span,
) -> Result<VarId, ShellError> {
    sig.named
        .iter()
        .find(|n| match (n.long_name(), n.short) {
            (Some(long), _) => long.as_bytes() == name,
            (None, Some(s)) => s.encode_utf8(&mut [0; 4]).as_bytes() == short,
            (None, None) => false,
        })
        .ok_or_else(|| ShellError::IrEvalError {
            msg: format!(
                "block does not have an argument named `{}`",
                String::from_utf8_lossy(name)
            ),
            span: Some(span),
        })
        .and_then(|flag| expect_named_var_id(flag, span))
}

fn expect_named_var_id(arg: &Flag, span: Span) -> Result<VarId, ShellError> {
    arg.var_id.ok_or_else(|| ShellError::IrEvalError {
        msg: format!(
            "block signature is missing var id for named arg `{}`",
            arg.long
        ),
        span: Some(span),
    })
}

fn expect_positional_var_id(arg: &PositionalArg, span: Span) -> Result<VarId, ShellError> {
    arg.var_id.ok_or_else(|| ShellError::IrEvalError {
        msg: format!(
            "block signature is missing var id for positional arg `{}`",
            arg.name
        ),
        span: Some(span),
    })
}

fn normalize_call_arguments(
    signature: &Signature,
    stack: &mut Stack,
    args_base: usize,
    args_len: usize,
) -> Result<usize, ShellError> {
    let raw: Vec<Argument> = stack.arguments.drain_args(args_base, args_len).collect();
    let expanded = normalize_engine_arguments(signature, raw)?;
    let new_len = expanded.len();
    for arg in expanded {
        stack.arguments.push(arg);
    }
    Ok(new_len)
}

fn gather_arguments(
    engine_state: &EngineState,
    block: &Block,
    caller_stack: &mut Stack,
    callee_stack: &mut Stack,
    args_base: usize,
    args_len: usize,
    call_head: Span,
) -> Result<(), ShellError> {
    let mut positional_iter = block
        .signature
        .required_positional
        .iter()
        .map(|p| (p, true))
        .chain(
            block
                .signature
                .optional_positional
                .iter()
                .map(|p| (p, false)),
        );

    let mut rest = Vec::new();
    let mut rest_span: Option<Span> = None;
    let expand_glob_args = block.signature.allows_unknown_args;
    let home = expand_glob_args
        .then(|| stack_home_dir(engine_state, caller_stack))
        .flatten();
    let mut always_spread = false;
    let mut remaining_required = block.signature.required_positional.len();

    for arg in caller_stack.arguments.drain_args(args_base, args_len) {
        match arg {
            Argument::Positional { span, val, .. } => {
                let next = (!always_spread).then(|| positional_iter.next()).flatten();
                if let Some((positional_arg, required)) = next {
                    let var_id = expect_positional_var_id(positional_arg, span)?;
                    if required {
                        let variable = engine_state.get_var(var_id);
                        check_type(&val, &variable.ty)?;
                        remaining_required = remaining_required.saturating_sub(1);
                    }
                    callee_stack.add_var(var_id, val);
                } else {
                    rest_span = Some(rest_span.map_or(span, |s| s.append(span)));
                    let val = if expand_glob_args {
                        expand_external_glob_arg(val, home.as_deref())
                    } else {
                        val
                    };
                    rest.push(val);
                }
            }
            Argument::Spread {
                vals,
                span: spread_span,
                ..
            } => match vals {
                Value::List { vals, .. } => {
                    if remaining_required > 0 && !always_spread {
                        return Err(list_spread_before_required_error(spread_span));
                    }
                    rest.extend(vals);
                    rest_span = Some(rest_span.map_or(spread_span, |s| s.append(spread_span)));
                    always_spread = true;
                }
                Value::Nothing { .. } => {
                    if remaining_required > 0 && !always_spread {
                        return Err(list_spread_before_required_error(spread_span));
                    }
                    rest_span = Some(rest_span.map_or(spread_span, |s| s.append(spread_span)));
                    always_spread = true;
                }
                Value::Record { .. } => {
                    return Err(ShellError::IrEvalError {
                        msg: "internal error: unexpanded record spread in gather_arguments".into(),
                        span: Some(spread_span),
                    });
                }
                Value::Error { error, .. } => return Err(*error),
                _ => return Err(ShellError::CannotSpreadAsList { span: vals.span() }),
            },
            Argument::Flag {
                data,
                name,
                short,
                span,
            } => {
                let var_id = find_named_var_id(&block.signature, &data[name], &data[short], span)?;
                callee_stack.add_var(var_id, Value::bool(true, span));
            }
            Argument::Named {
                data,
                name,
                short,
                span,
                val,
                ..
            } => {
                let var_id = find_named_var_id(&block.signature, &data[name], &data[short], span)?;
                callee_stack.add_var(var_id, val);
            }
            Argument::ParserInfo { .. } => {}
        }
    }

    if let Some(rest_arg) = &block.signature.rest_positional {
        let rest_span = rest_span.unwrap_or(call_head);
        let var_id = expect_positional_var_id(rest_arg, rest_span)?;
        callee_stack.add_var(var_id, Value::list(rest, rest_span));
    }

    for (positional_arg, _) in positional_iter {
        let var_id = expect_positional_var_id(positional_arg, call_head)?;
        callee_stack.add_var(
            var_id,
            positional_arg
                .default_value
                .clone()
                .unwrap_or_else(|| Value::nothing(call_head)),
        );
    }

    for named_arg in &block.signature.named {
        if let Some(var_id) = named_arg.var_id
            && !callee_stack.vars.iter().any(|(id, _)| *id == var_id)
        {
            let val = if named_arg.arg.is_none() {
                Value::bool(false, call_head)
            } else if let Some(value) = &named_arg.default_value {
                value.clone()
            } else {
                Value::nothing(call_head)
            };
            callee_stack.add_var(var_id, val);
        }
    }

    Ok(())
}

fn check_type(val: &Value, ty: &Type) -> Result<(), ShellError> {
    match val {
        Value::Error { error, .. } => Err(*error.clone()),
        _ if val.is_assignable_to(ty) => Ok(()),
        _ => Err(ShellError::CantConvert {
            to_type: ty.to_string(),
            from_type: val.get_type().to_string(),
            span: val.span(),
            help: None,
        }),
    }
}

fn check_assignment_type(
    val: Value,
    target_ty: &Type,
    assignment_span: Span,
) -> Result<Value, ShellError> {
    match val {
        Value::Error { error, .. } => Err(*error),
        _ if val.is_assignable_to(target_ty) => Ok(val),
        _ => {
            let expected = target_ty.to_string();
            let actual = val.get_type().to_string();
            let mut err = LabeledError::new("Type mismatch.").with_code("nu::shell::type_mismatch");
            if !(val.span() == Span::unknown() || val.span() == Span::test_data()) {
                err = err.with_label(format!("the value is a {actual}"), val.span());
            }
            err = err.with_label(
                format!("expected {expected}, got {actual}"),
                assignment_span,
            );
            Err(ShellError::LabeledError(err.into()))
        }
    }
}

fn check_async_input_types(
    input: &AsyncPipelineData,
    signature: &Signature,
    head: Span,
) -> Result<(), ShellError> {
    let io_types = &signature.input_output_types;
    if io_types.is_empty() || io_types.iter().all(|(in_ty, _)| in_ty == &Type::Nothing) {
        return Ok(());
    }

    if let AsyncPipelineData::Value(Value::Error { error, .. }, ..)
    | AsyncPipelineData::Sync(PipelineData::Value(Value::Error { error, .. }, ..)) = input
    {
        return Err(*error.clone());
    }

    let input_type = input.get_type();
    if io_types.iter().any(|(cmd_ty, _)| {
        input_type.is_subtype_of(cmd_ty)
            || matches!(
                (input, cmd_ty),
                (
                    AsyncPipelineData::ByteStream { .. },
                    Type::String | Type::Binary | Type::Any
                ) | (
                    AsyncPipelineData::ListStream { .. },
                    Type::List(_) | Type::Table(_) | Type::Any
                )
            )
            || match input {
                AsyncPipelineData::Value(v, _) => v.is_assignable_to(cmd_ty),
                AsyncPipelineData::Sync(p) => p.is_assignable_to(cmd_ty),
                _ => false,
            }
    }) {
        return Ok(());
    }

    let input_types: Vec<Type> = io_types.iter().map(|(in_ty, _)| in_ty.clone()).collect();
    let expected_string = combined_type_string(&input_types, "and");
    match (input, expected_string) {
        (AsyncPipelineData::Empty, _) => Err(ShellError::PipelineEmpty { dst_span: head }),
        (_, Some(expected_string)) => Err(ShellError::OnlySupportsThisInputType {
            exp_input_type: expected_string,
            wrong_type: input.get_type().to_string(),
            dst_span: head,
            src_span: input.span().unwrap_or(head),
        }),
        (_, None) => Err(ShellError::NushellFailed {
            msg: "Command input type strings is empty, despite being non-zero earlier".to_owned(),
        }),
    }
}

fn get_var<E: HeliosEnv>(
    ctx: &mut AsyncEvalContext<'_, E>,
    var_id: VarId,
    span: Span,
) -> Result<Value, ShellError> {
    match var_id {
        ENV_VARIABLE_ID => {
            let env_vars = ctx.stack.get_env_vars(ctx.engine_state);
            let mut pairs: Vec<(String, Value)> = env_vars
                .iter()
                .map(|(k, v)| (k.to_string(), v.clone()))
                .collect();
            pairs.sort_by(|a, b| a.0.cmp(&b.0));
            Ok(Value::record(pairs.into_iter().collect(), span))
        }
        id if id == nu_protocol::LAST_VARIABLE_ID => {
            ctx.stack.defer_last_result_truncation_warning();
            ctx.stack.get_var(var_id, span)
        }
        _ => ctx.stack.get_var(var_id, span).or_else(|err| {
            ctx.engine_state
                .get_constant(var_id)
                .cloned()
                .map(|v| v.with_span(span))
                .ok_or(err)
        }),
    }
}

fn get_env_var<'a, E: HeliosEnv>(ctx: &'a AsyncEvalContext<'_, E>, key: &str) -> Option<&'a Value> {
    for overlays in ctx
        .stack
        .env_vars
        .iter()
        .rev()
        .chain(std::iter::once(&ctx.engine_state.env_vars))
    {
        for overlay_name in ctx.stack.active_overlays.iter().rev() {
            let Some(map) = overlays.get(overlay_name) else {
                continue;
            };
            let hidden = ctx.stack.env_hidden.get(overlay_name);
            let env_key = EnvName::from(key);
            if hidden.is_some_and(|h| h.contains(&env_key)) {
                continue;
            }
            if let Some(val) = map.get(&env_key) {
                return Some(val);
            }
        }
    }
    None
}

pub(crate) fn redirect_env(
    engine_state: &EngineState,
    caller_stack: &mut Stack,
    callee_stack: &Stack,
) {
    let caller_env_vars = caller_stack.get_env_var_names(engine_state);
    for var in &caller_env_vars {
        if !callee_stack.has_env_var(engine_state, var) {
            caller_stack.hide_env_var(engine_state, var);
        }
    }
    for (var, value) in callee_stack.get_stack_env_vars() {
        caller_stack.add_env_var(var, value);
    }
    caller_stack.config.clone_from(&callee_stack.config);
}
