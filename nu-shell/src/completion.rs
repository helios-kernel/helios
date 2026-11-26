//! Shared AST-driven completion core for `helios-nu`.
//!
//! Resolves completions from the parsed Nushell AST plus live [`HeliosEnv`]
//! capabilities:
//! - Command names (built-ins, custom commands, aliases, granted externals)
//! - Command flags (`--long`, `-s`) from [`Signature`]
//! - Downstream pipeline `Type::Table` / `Type::Record` column names
//! - Helios Monikers, Inspect keys, diagnostic targets, OCI image refs
//! - Granted directory entries (capability-bounded via [`HeliosEnv::list_dir`])

use std::collections::BTreeSet;

use nu_protocol::ast::{Argument as AstArg, Block, Call as AstCall, Expr, Expression, Pipeline};
use nu_protocol::engine::{EngineState, Stack, StateWorkingSet};
use nu_protocol::{Span, SyntaxShape, Type, Value};

use crate::env::{FileType, HeliosEnv, normalize_vfs_path};
use crate::eval::current_cwd_async;

/// Semantic kind of a completion candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompletionKind {
    Command,
    Flag,
    Column,
    Moniker,
    InspectKey,
    DiagnosticTarget,
    OciRef,
    ContainerHandle,
    Path,
    Variable,
}

/// A single completion candidate returned by [`complete_async`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompletionItem {
    pub value: String,
    pub description: String,
    pub kind: CompletionKind,
    /// Byte span in the input line to replace when inserting `value`.
    pub replace_start: usize,
    pub replace_end: usize,
}

/// Byte range in the input line that a completion replaces.
#[derive(Debug, Clone, Copy)]
struct ReplaceSpan {
    start: usize,
    end: usize,
}

/// Read-only context for completion helpers.
struct CompletionCtx<'a, E: HeliosEnv> {
    engine_state: &'a EngineState,
    stack: &'a Stack,
    env: &'a E,
    span: ReplaceSpan,
    abs_token_start: usize,
}
/// Compute context-sensitive completions for `input` at byte offset `cursor`.
pub async fn complete_async<E: HeliosEnv>(
    engine_state: &EngineState,
    stack: &Stack,
    env: &E,
    input: &str,
    cursor: usize,
) -> Vec<CompletionItem> {
    let cursor = cursor.min(input.len());
    let prefix_slice = &input[..cursor];

    let mut working_set = StateWorkingSet::new(engine_state);
    let offset = working_set.next_span_start();
    let block = nu_parser::parse(&mut working_set, None, prefix_slice.as_bytes(), false);
    let abs_cursor = offset + cursor;

    let (token_start, token) = current_token(prefix_slice);
    let replace_start = token_start;
    let replace_end = cursor;
    let abs_token_start = offset + token_start;
    let ctx = CompletionCtx {
        engine_state,
        stack,
        env,
        span: ReplaceSpan {
            start: replace_start,
            end: replace_end,
        },
        abs_token_start,
    };

    // Variable / cell-path completion (`$var.col...`)
    if let Some(after_dollar) = token.strip_prefix('$') {
        if let Some((var_name, field_prefix)) = after_dollar.rsplit_once('.') {
            let var_items = complete_variable_cell_path(
                engine_state,
                stack,
                var_name,
                field_prefix,
                replace_start + 1 + var_name.len() + 1,
                replace_end,
            );
            if !var_items.is_empty() {
                return var_items;
            }
        } else {
            return complete_variables(
                engine_state,
                stack,
                after_dollar,
                replace_start,
                replace_end,
            );
        }
    }

    // Locate the active pipeline and element containing the cursor.
    if let Some((pipeline, elem_idx)) = find_active_pipeline(&block, abs_cursor) {
        let active_elem = &pipeline.elements[elem_idx];
        let upstream_type =
            infer_upstream_type(&working_set, engine_state, stack, pipeline, elem_idx);

        if let Expr::Call(call) = &active_elem.expr.expr {
            let decl = working_set.get_decl(call.decl_id);
            let cmd_name = decl.name().to_owned();
            let sig = decl.signature();
            let head_end = call.head.end.saturating_sub(offset);

            // Still typing the command head itself (or subcommand continuation).
            if cursor <= head_end && !prefix_slice.ends_with(' ') {
                return complete_commands(engine_state, env, token, replace_start, replace_end)
                    .await;
            }

            // Flag completion (`-` or `--`).
            if token.starts_with('-') {
                return complete_flags(&sig, token, replace_start, replace_end);
            }

            // Determine whether the previous token is a named flag expecting a value.
            if let Some(flag_name) = previous_flag_name(prefix_slice, token_start)
                && let Some(items) = complete_flag_value(&ctx, &cmd_name, flag_name, token).await
            {
                return items;
            }

            // Downstream pipeline column completion for table/record-consuming commands.
            if is_column_command(&cmd_name)
                && let Some(ty) = &upstream_type
            {
                let cols = extract_columns_from_type(ty);
                if !cols.is_empty() {
                    return filter_column_completions(&cols, token, replace_start, replace_end);
                }
            }

            // Helios domain-specific positional completions.
            if let Some(items) = complete_domain_positional(&ctx, &cmd_name, call, token).await {
                return items;
            }

            // Subcommand completion when user typed a parent command like `sys `,
            // `linux image `, or `btrfs subvolume ` (before any prior positional args).
            if prior_positional_count(call, abs_token_start) == 0 {
                let sub_prefix = format!("{cmd_name} {token}");
                let subcommands = complete_subcommands(
                    engine_state,
                    &cmd_name,
                    &sub_prefix,
                    replace_start,
                    replace_end,
                );
                if !subcommands.is_empty() {
                    return subcommands;
                }
            }

            // Generic signature-driven path completion.
            if signature_expects_path(&sig, call, abs_token_start) {
                return complete_vfs_paths(
                    engine_state,
                    stack,
                    env,
                    token,
                    replace_start,
                    replace_end,
                )
                .await;
            }

            // Fallback: if upstream has known columns (e.g. inside `where <col>`), offer them.
            if let Some(ty) = &upstream_type {
                let cols = extract_columns_from_type(ty);
                if !cols.is_empty() {
                    return filter_column_completions(&cols, token, replace_start, replace_end);
                }
            }
        }
    }

    // Check if the cursor sits right after a pipe or at the start of a command.
    let trimmed_before = prefix_slice[..token_start].trim_end();
    if trimmed_before.is_empty()
        || trimmed_before.ends_with('|')
        || trimmed_before.ends_with(';')
        || trimmed_before.ends_with('(')
        || trimmed_before.ends_with('{')
    {
        return complete_commands(engine_state, env, token, replace_start, replace_end).await;
    }

    // Fallback: offer subcommands / commands matching prefix.
    complete_commands(engine_state, env, token, replace_start, replace_end).await
}

fn current_token(prefix: &str) -> (usize, &str) {
    let mut start = prefix.len();
    for (idx, ch) in prefix.char_indices().rev() {
        if ch.is_whitespace() || matches!(ch, '|' | ';' | '(' | '{' | '[') {
            break;
        }
        start = idx;
    }
    (start, &prefix[start..])
}

fn previous_flag_name(prefix: &str, token_start: usize) -> Option<&str> {
    let before = prefix[..token_start].trim_end();
    let last = before.split_whitespace().last()?;
    if let Some(long) = last.strip_prefix("--")
        && !long.is_empty()
    {
        return Some(long);
    }
    if let Some(short) = last.strip_prefix('-')
        && short.len() == 1
    {
        return Some(short);
    }
    None
}

fn find_active_pipeline(block: &Block, abs_cursor: usize) -> Option<(&Pipeline, usize)> {
    let mut best: Option<(&Pipeline, usize)> = None;
    for pipeline in &block.pipelines {
        for (idx, elem) in pipeline.elements.iter().enumerate() {
            let span = elem.expr.span;
            if span.start <= abs_cursor {
                best = Some((pipeline, idx));
            }
        }
    }
    best
}

fn infer_upstream_type(
    working_set: &StateWorkingSet<'_>,
    engine_state: &EngineState,
    stack: &Stack,
    pipeline: &Pipeline,
    elem_idx: usize,
) -> Option<Type> {
    if elem_idx == 0 {
        return None;
    }
    // Walk backward from the immediately preceding stage until a known structured type is found.
    for prev in pipeline.elements[..elem_idx].iter().rev() {
        if let Some(ty) = infer_expr_type(working_set, engine_state, stack, &prev.expr) {
            match &ty {
                Type::Table(cols) if !cols.is_empty() => return Some(ty),
                Type::Record(cols) if !cols.is_empty() => return Some(ty),
                _ => {}
            }
        }
    }
    None
}

fn infer_expr_type(
    working_set: &StateWorkingSet<'_>,
    engine_state: &EngineState,
    stack: &Stack,
    expr: &Expression,
) -> Option<Type> {
    match &expr.expr {
        Expr::Call(call) => {
            let decl = working_set.get_decl(call.decl_id);
            let sig = decl.signature();
            for (_, out_ty) in &sig.input_output_types {
                if matches!(out_ty, Type::Table(c) | Type::Record(c) if !c.is_empty()) {
                    return Some(out_ty.clone());
                }
            }
            None
        }
        Expr::Var(var_id) => stack
            .get_var(*var_id, Span::unknown())
            .ok()
            .or_else(|| engine_state.get_constant(*var_id).cloned())
            .map(|val| value_schema_type(&val)),
        Expr::Record(items) => {
            let mut cols = Vec::new();
            for item in items {
                if let nu_protocol::ast::RecordItem::Pair(k, v) = item
                    && let Expr::String(name) = &k.expr
                {
                    cols.push((name.clone(), v.ty.clone()));
                }
            }
            Some(Type::Record(cols.into()))
        }
        Expr::Table(table) => {
            let cols = table
                .columns
                .iter()
                .filter_map(|c| match &c.expr {
                    Expr::String(name) => Some((name.clone(), Type::Any)),
                    _ => None,
                })
                .collect::<Vec<_>>();
            Some(Type::Table(cols.into()))
        }
        _ => Some(expr.ty.clone()),
    }
}

fn value_schema_type(val: &Value) -> Type {
    match val {
        Value::Record { val, .. } => {
            let cols = val
                .iter()
                .map(|(k, v)| (k.clone(), v.get_type()))
                .collect::<Vec<_>>();
            Type::Record(cols.into())
        }
        Value::List { vals, .. } => {
            if let Some(Value::Record { val, .. }) = vals.first() {
                let cols = val
                    .iter()
                    .map(|(k, v)| (k.clone(), v.get_type()))
                    .collect::<Vec<_>>();
                Type::Table(cols.into())
            } else {
                val.get_type()
            }
        }
        other => other.get_type(),
    }
}

fn extract_columns_from_type(ty: &Type) -> Vec<(String, Type)> {
    match ty {
        Type::Table(cols) | Type::Record(cols) => cols.iter().cloned().collect(),
        _ => Vec::new(),
    }
}

fn is_column_command(name: &str) -> bool {
    matches!(
        name,
        "get"
            | "select"
            | "reject"
            | "sort-by"
            | "group-by"
            | "where"
            | "update"
            | "upsert"
            | "rename"
            | "move"
            | "compact"
            | "drop column"
            | "uniq-by"
    )
}

fn filter_column_completions(
    cols: &[(String, Type)],
    prefix: &str,
    replace_start: usize,
    replace_end: usize,
) -> Vec<CompletionItem> {
    cols.iter()
        .filter(|(name, _)| name.starts_with(prefix))
        .map(|(name, ty)| CompletionItem {
            value: name.clone(),
            description: format!("column ({ty})"),
            kind: CompletionKind::Column,
            replace_start,
            replace_end,
        })
        .collect()
}

async fn complete_commands<E: HeliosEnv>(
    engine_state: &EngineState,
    env: &E,
    prefix: &str,
    replace_start: usize,
    replace_end: usize,
) -> Vec<CompletionItem> {
    let mut seen = BTreeSet::new();
    let mut items = Vec::new();

    for (name_bytes, decl_id) in engine_state.get_decls_sorted(false) {
        let Ok(name) = std::str::from_utf8(&name_bytes) else {
            continue;
        };
        if !name.starts_with(prefix) || name.contains(' ') {
            continue;
        }
        if seen.insert(name.to_owned()) {
            let desc = engine_state.get_decl(decl_id).description().to_owned();
            items.push(CompletionItem {
                value: name.to_owned(),
                description: desc,
                kind: CompletionKind::Command,
                replace_start,
                replace_end,
            });
        }
    }

    if let Ok(externals) = env.list_executables().await {
        for ext in externals {
            if ext.starts_with(prefix) && seen.insert(ext.clone()) {
                items.push(CompletionItem {
                    value: ext,
                    description: String::from("external program"),
                    kind: CompletionKind::Command,
                    replace_start,
                    replace_end,
                });
            }
        }
    }

    items.sort_by(|a, b| a.value.cmp(&b.value));
    items
}

fn complete_subcommands(
    engine_state: &EngineState,
    parent: &str,
    full_prefix: &str,
    replace_start: usize,
    replace_end: usize,
) -> Vec<CompletionItem> {
    let parent_space = format!("{parent} ");
    let mut items = Vec::new();
    for (name_bytes, decl_id) in engine_state.get_decls_sorted(false) {
        let Ok(name) = std::str::from_utf8(&name_bytes) else {
            continue;
        };
        if let Some(sub) = name.strip_prefix(&parent_space)
            && name.starts_with(full_prefix)
            && !sub.contains(' ')
        {
            items.push(CompletionItem {
                value: sub.to_owned(),
                description: engine_state.get_decl(decl_id).description().to_owned(),
                kind: CompletionKind::Command,
                replace_start,
                replace_end,
            });
        }
    }
    items.sort_by(|a, b| a.value.cmp(&b.value));
    items
}

fn complete_flags(
    sig: &nu_protocol::Signature,
    prefix: &str,
    replace_start: usize,
    replace_end: usize,
) -> Vec<CompletionItem> {
    let mut items = Vec::new();
    for flag in &sig.named {
        if !flag.long.is_empty() {
            let long = format!("--{}", flag.long);
            if long.starts_with(prefix) {
                items.push(CompletionItem {
                    value: long,
                    description: flag.desc.clone(),
                    kind: CompletionKind::Flag,
                    replace_start,
                    replace_end,
                });
            }
        }
        if let Some(short_ch) = flag.short {
            let short = format!("-{short_ch}");
            if short.starts_with(prefix) && !prefix.starts_with("--") {
                items.push(CompletionItem {
                    value: short,
                    description: flag.desc.clone(),
                    kind: CompletionKind::Flag,
                    replace_start,
                    replace_end,
                });
            }
        }
    }
    items.sort_by(|a, b| a.value.cmp(&b.value));
    items
}

async fn complete_flag_value<E: HeliosEnv>(
    ctx: &CompletionCtx<'_, E>,
    cmd_name: &str,
    flag_name: &str,
    prefix: &str,
) -> Option<Vec<CompletionItem>> {
    let replace_start = ctx.span.start;
    let replace_end = ctx.span.end;
    match (cmd_name, flag_name) {
        ("with-instruction-profile", "target" | "t") => {
            let targets = ctx.env.complete_diagnostic_targets().await.ok()?;
            Some(
                targets
                    .into_iter()
                    .filter(|t| t.starts_with(prefix))
                    .map(|value| CompletionItem {
                        value,
                        description: String::from("diagnostic target"),
                        kind: CompletionKind::DiagnosticTarget,
                        replace_start,
                        replace_end,
                    })
                    .collect(),
            )
        }
        ("with-snapshot", "moniker" | "m") => {
            let monikers = ctx.env.complete_monikers().await.ok()?;
            Some(
                monikers
                    .into_iter()
                    .filter(|m| m.starts_with(prefix))
                    .map(|value| CompletionItem {
                        value,
                        description: String::from("component moniker"),
                        kind: CompletionKind::Moniker,
                        replace_start,
                        replace_end,
                    })
                    .collect(),
            )
        }
        (_, "oci") | ("container create", "image" | "i") => {
            let refs = ctx.env.complete_oci_refs().await.ok()?;
            Some(
                refs.into_iter()
                    .filter(|r| r.starts_with(prefix))
                    .map(|value| CompletionItem {
                        value,
                        description: String::from("OCI image reference"),
                        kind: CompletionKind::OciRef,
                        replace_start,
                        replace_end,
                    })
                    .collect(),
            )
        }
        ("vm run", "kernel" | "k" | "initramfs" | "disk" | "rootfs-dir")
        | ("container create", "rootfs" | "r")
        | ("component add", "dir" | "d")
        | ("btrfs subvolume send", "parent" | "p")
        | ("btrfs subvolume receive", "file" | "f") => Some(
            complete_vfs_paths(
                ctx.engine_state,
                ctx.stack,
                ctx.env,
                prefix,
                replace_start,
                replace_end,
            )
            .await,
        ),
        (
            "http get" | "http post" | "http put" | "http patch" | "http delete" | "http head"
            | "http options",
            "redirect-mode" | "R",
        ) => {
            let modes = ["follow", "manual", "error"];
            Some(
                modes
                    .into_iter()
                    .filter(|m| m.starts_with(prefix))
                    .map(|m| CompletionItem {
                        value: m.to_owned(),
                        description: String::from("HTTP redirect mode"),
                        kind: CompletionKind::Flag,
                        replace_start,
                        replace_end,
                    })
                    .collect(),
            )
        }
        ("save", "stderr" | "e") => Some(
            complete_vfs_paths(
                ctx.engine_state,
                ctx.stack,
                ctx.env,
                prefix,
                replace_start,
                replace_end,
            )
            .await,
        ),
        _ => None,
    }
}

async fn complete_domain_positional<E: HeliosEnv>(
    ctx: &CompletionCtx<'_, E>,
    cmd_name: &str,
    _call: &AstCall,
    prefix: &str,
) -> Option<Vec<CompletionItem>> {
    let replace_start = ctx.span.start;
    let replace_end = ctx.span.end;
    match cmd_name {
        "inspect" => {
            let keys = ctx.env.complete_inspect_keys(prefix).await.ok()?;
            Some(
                keys.into_iter()
                    .map(|value| CompletionItem {
                        value,
                        description: String::from("inspect key"),
                        kind: CompletionKind::InspectKey,
                        replace_start,
                        replace_end,
                    })
                    .collect(),
            )
        }
        "with-scope" | "component status" | "component start" | "component stop"
        | "component restart" | "component rm" => {
            let monikers = ctx.env.complete_monikers().await.ok()?;
            Some(
                monikers
                    .into_iter()
                    .filter(|m| m.starts_with(prefix))
                    .map(|value| CompletionItem {
                        value,
                        description: String::from("component moniker"),
                        kind: CompletionKind::Moniker,
                        replace_start,
                        replace_end,
                    })
                    .collect(),
            )
        }
        "component add" => {
            if prior_positional_count(_call, ctx.abs_token_start) == 0 {
                let monikers = ctx.env.complete_monikers().await.ok()?;
                Some(
                    monikers
                        .into_iter()
                        .filter(|m| m.starts_with(prefix))
                        .map(|value| CompletionItem {
                            value,
                            description: String::from("component moniker"),
                            kind: CompletionKind::Moniker,
                            replace_start,
                            replace_end,
                        })
                        .collect(),
                )
            } else {
                Some(
                    complete_vfs_paths(
                        ctx.engine_state,
                        ctx.stack,
                        ctx.env,
                        prefix,
                        replace_start,
                        replace_end,
                    )
                    .await,
                )
            }
        }
        "linux image set" | "oci inspect" | "oci rm" | "container create" => {
            let refs = ctx.env.complete_oci_refs().await.ok()?;
            Some(
                refs.into_iter()
                    .filter(|r| r.starts_with(prefix))
                    .map(|value| CompletionItem {
                        value,
                        description: String::from("OCI image reference"),
                        kind: CompletionKind::OciRef,
                        replace_start,
                        replace_end,
                    })
                    .collect(),
            )
        }
        "container exec" | "container spawn" | "container rm" | "with-container" => {
            if prior_positional_count(_call, ctx.abs_token_start) == 0 {
                let handles = ctx.env.complete_containers().await.ok()?;
                Some(
                    handles
                        .into_iter()
                        .filter(|h| h.starts_with(prefix))
                        .map(|value| CompletionItem {
                            value,
                            description: String::from("container handle"),
                            kind: CompletionKind::ContainerHandle,
                            replace_start,
                            replace_end,
                        })
                        .collect(),
                )
            } else {
                None
            }
        }
        "cd"
        | "ls"
        | "open"
        | "save"
        | "mkdir"
        | "rm"
        | "cp"
        | "mv"
        | "touch"
        | "watch"
        | "umount"
        | "btrfs subvolume create"
        | "btrfs subvolume delete"
        | "btrfs subvolume snapshot"
        | "btrfs subvolume list"
        | "btrfs subvolume show"
        | "btrfs subvolume set-ro"
        | "btrfs subvolume send"
        | "btrfs subvolume receive" => Some(
            complete_vfs_paths(
                ctx.engine_state,
                ctx.stack,
                ctx.env,
                prefix,
                replace_start,
                replace_end,
            )
            .await,
        ),
        "mount" => {
            if prior_positional_count(_call, ctx.abs_token_start) >= 1 {
                Some(
                    complete_vfs_paths(
                        ctx.engine_state,
                        ctx.stack,
                        ctx.env,
                        prefix,
                        replace_start,
                        replace_end,
                    )
                    .await,
                )
            } else {
                None
            }
        }
        _ => None,
    }
}

fn prior_positional_count(call: &AstCall, abs_token_start: usize) -> usize {
    call.arguments
        .iter()
        .filter(|arg| {
            matches!(
                arg,
                AstArg::Positional(expr) | AstArg::Unknown(expr)
                    if expr.span.end <= abs_token_start
            )
        })
        .count()
}

fn signature_expects_path(
    sig: &nu_protocol::Signature,
    call: &AstCall,
    abs_token_start: usize,
) -> bool {
    let pos_count = prior_positional_count(call, abs_token_start);

    let shape = sig
        .required_positional
        .get(pos_count)
        .or_else(|| {
            sig.optional_positional
                .get(pos_count.saturating_sub(sig.required_positional.len()))
        })
        .or(sig.rest_positional.as_ref())
        .map(|arg| &arg.shape);

    matches!(
        shape,
        Some(SyntaxShape::Filepath | SyntaxShape::Directory | SyntaxShape::GlobPattern)
    )
}

async fn complete_vfs_paths<E: HeliosEnv>(
    engine_state: &EngineState,
    stack: &Stack,
    env: &E,
    prefix: &str,
    replace_start: usize,
    replace_end: usize,
) -> Vec<CompletionItem> {
    let cwd = current_cwd_async(engine_state, stack, env).await;
    let (dir_prefix, name_prefix) = match prefix.rsplit_once('/') {
        Some((dir, name)) => (format!("{dir}/"), name),
        None => (String::new(), prefix),
    };

    let lookup_dir = if dir_prefix.is_empty() {
        cwd
    } else {
        normalize_vfs_path(&cwd, &dir_prefix)
    };

    let Ok(entries) = env.list_dir(&lookup_dir).await else {
        return Vec::new();
    };

    let mut items: Vec<CompletionItem> = entries
        .into_iter()
        .filter(|entry| entry.name.starts_with(name_prefix))
        .map(|entry| {
            let suffix = if entry.file_type == FileType::Dir {
                "/"
            } else {
                ""
            };
            CompletionItem {
                value: format!("{dir_prefix}{}{suffix}", entry.name),
                description: entry.file_type.as_str().to_owned(),
                kind: CompletionKind::Path,
                replace_start,
                replace_end,
            }
        })
        .collect();
    items.sort_by(|a, b| a.value.cmp(&b.value));
    items
}

fn complete_variables(
    engine_state: &EngineState,
    stack: &Stack,
    prefix: &str,
    replace_start: usize,
    replace_end: usize,
) -> Vec<CompletionItem> {
    let mut items = Vec::new();
    let mut seen = BTreeSet::new();
    for (var_id, _) in &stack.vars {
        let var = engine_state.get_var(*var_id);
        let name = format!("${}", var.ty);
        let _ = name;
    }
    if "env".starts_with(prefix) && seen.insert("env") {
        items.push(CompletionItem {
            value: String::from("$env"),
            description: String::from("environment record"),
            kind: CompletionKind::Variable,
            replace_start,
            replace_end,
        });
    }
    if "nu".starts_with(prefix) && seen.insert("nu") {
        items.push(CompletionItem {
            value: String::from("$nu"),
            description: String::from("nushell metadata record"),
            kind: CompletionKind::Variable,
            replace_start,
            replace_end,
        });
    }
    if "in".starts_with(prefix) && seen.insert("in") {
        items.push(CompletionItem {
            value: String::from("$in"),
            description: String::from("pipeline input value"),
            kind: CompletionKind::Variable,
            replace_start,
            replace_end,
        });
    }
    items
}

fn complete_variable_cell_path(
    engine_state: &EngineState,
    stack: &Stack,
    var_name: &str,
    field_prefix: &str,
    replace_start: usize,
    replace_end: usize,
) -> Vec<CompletionItem> {
    if var_name == "env" {
        let mut items: Vec<CompletionItem> = stack
            .get_env_vars(engine_state)
            .keys()
            .filter(|k| k.starts_with(field_prefix))
            .map(|k| CompletionItem {
                value: k.to_string(),
                description: String::from("environment variable"),
                kind: CompletionKind::Column,
                replace_start,
                replace_end,
            })
            .collect();
        items.sort_by(|a, b| a.value.cmp(&b.value));
        return items;
    }
    Vec::new()
}
