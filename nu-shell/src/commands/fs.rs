//! Capability-bounded VFS commands (`cd`, `ls`, `open`, `save`, `mkdir`,
//! `rm`, `cp`, `mv`, `touch`, `glob`, `watch`) backed by [`HeliosEnv`].

use std::collections::VecDeque;

use nu_engine::CallExt;
use nu_glob::Pattern;
use nu_protocol::engine::Closure;
use nu_protocol::{
    Category, DataSource, NuGlob, PipelineMetadata, Record, ShellError, Signature, Span, Spanned,
    SyntaxShape, Type, Value,
};

use crate::command::{AsyncCommand, AsyncCommandContext};
use crate::env::{FileMetadata, FileType, HeliosEnv, normalize_vfs_path};
use crate::error::generic_error;
use crate::eval::{current_cwd_async, eval_call_by_name_async, eval_closure_async};
use crate::pipeline::AsyncPipelineData;

/// `cd`: change current working directory through [`HeliosEnv::set_cwd`].
#[derive(Debug, Clone, Copy)]
pub struct Cd;

impl<E: HeliosEnv> AsyncCommand<E> for Cd {
    fn name(&self) -> &str {
        "cd"
    }

    fn description(&self) -> &str {
        "Change the current working directory."
    }

    fn signature(&self) -> Signature {
        Signature::build("cd")
            .input_output_types(vec![(Type::Nothing, Type::Nothing)])
            .optional("path", SyntaxShape::Directory, "The path to change to.")
            .category(Category::FileSystem)
    }

    async fn run_async<'a>(
        &'a self,
        ctx: &'a mut AsyncCommandContext<'_, E>,
        _input: AsyncPipelineData,
    ) -> Result<AsyncPipelineData, ShellError> {
        let head = ctx.call.head;
        let target: Option<String> = ctx.call.opt(ctx.engine_state, ctx.stack, 0)?;
        let current = current_cwd_async(ctx.engine_state, ctx.stack, ctx.env).await;

        let desired = match target.as_deref() {
            None => ctx
                .stack
                .get_env_var(ctx.engine_state, "HOME")
                .and_then(|v| v.as_str().ok())
                .map_or_else(|| String::from("/"), ToOwned::to_owned),
            Some("-") => ctx
                .stack
                .get_env_var(ctx.engine_state, "OLDPWD")
                .and_then(|v| v.as_str().ok())
                .map_or_else(|| current.clone(), ToOwned::to_owned),
            Some(path) => normalize_vfs_path(&current, path),
        };

        let next = ctx
            .env
            .set_cwd(&desired)
            .await
            .map_err(|e| e.into_shell_error("cd failed", head))?;

        ctx.stack
            .add_env_var("OLDPWD".to_owned(), Value::string(current, head));
        ctx.stack
            .add_env_var("PWD".to_owned(), Value::string(next, head));
        Ok(AsyncPipelineData::Empty)
    }
}

/// `ls`: list files and directories under granted VFS paths.
#[derive(Debug, Clone, Copy)]
pub struct Ls;

impl<E: HeliosEnv> AsyncCommand<E> for Ls {
    fn name(&self) -> &str {
        "ls"
    }

    fn description(&self) -> &str {
        "List filenames, sizes, and modification times."
    }

    fn signature(&self) -> Signature {
        Signature::build("ls")
            .input_output_types(vec![(
                Type::Nothing,
                Type::Table(
                    vec![
                        ("name".into(), Type::String),
                        ("type".into(), Type::String),
                        ("size".into(), Type::Filesize),
                        ("modified".into(), Type::Date),
                    ]
                    .into(),
                ),
            )])
            .switch("all", "Show hidden files.", Some('a'))
            .switch(
                "long",
                "Get all available columns for each entry.",
                Some('l'),
            )
            .switch(
                "short-names",
                "Only print file names, not paths.",
                Some('s'),
            )
            .switch("full-paths", "Display paths as absolute paths.", Some('f'))
            .optional(
                "pattern",
                SyntaxShape::OneOf(vec![SyntaxShape::GlobPattern, SyntaxShape::String]),
                "The glob pattern or directory path to list.",
            )
            .category(Category::FileSystem)
    }

    async fn run_async<'a>(
        &'a self,
        ctx: &'a mut AsyncCommandContext<'_, E>,
        _input: AsyncPipelineData,
    ) -> Result<AsyncPipelineData, ShellError> {
        let head = ctx.call.head;
        let all = ctx.call.has_flag(ctx.engine_state, ctx.stack, "all")?;
        let long = ctx.call.has_flag(ctx.engine_state, ctx.stack, "long")?;
        let short_names = ctx
            .call
            .has_flag(ctx.engine_state, ctx.stack, "short-names")?;
        let full_paths = ctx
            .call
            .has_flag(ctx.engine_state, ctx.stack, "full-paths")?;
        let pattern: Option<Spanned<NuGlob>> = ctx.call.opt(ctx.engine_state, ctx.stack, 0)?;

        let cwd = current_cwd_async(ctx.engine_state, ctx.stack, ctx.env).await;
        let entries = match pattern {
            None => ctx
                .env
                .list_dir(&cwd)
                .await
                .map_err(|e| e.into_shell_error("ls failed", head))?,
            Some(glob_arg) => {
                let raw = glob_arg.item.as_ref().to_owned();
                let is_glob = glob_arg.item.is_expand() && nu_glob::is_glob(&raw);
                if is_glob {
                    let full_pat = normalize_vfs_path(&cwd, &raw);
                    glob_walk(ctx.env, &cwd, &full_pat, None, head).await?
                } else {
                    let target = normalize_vfs_path(&cwd, &raw);
                    let meta = ctx
                        .env
                        .stat(&target)
                        .await
                        .map_err(|e| e.into_shell_error("ls failed", glob_arg.span))?;
                    if meta.file_type == FileType::Dir {
                        ctx.env
                            .list_dir(&target)
                            .await
                            .map_err(|e| e.into_shell_error("ls failed", glob_arg.span))?
                    } else {
                        vec![meta]
                    }
                }
            }
        };

        let mut rows = Vec::new();
        for entry in entries {
            if !all && entry.name.starts_with('.') {
                continue;
            }
            let display_name = if short_names {
                entry.name.clone()
            } else if full_paths {
                entry.path.clone()
            } else {
                display_relative(&cwd, &entry.path)
            };

            let mut rec = Record::new();
            rec.push("name", Value::string(display_name, head));
            rec.push("type", Value::string(entry.file_type.as_str(), head));
            rec.push(
                "size",
                Value::filesize(i64::try_from(entry.size).unwrap_or(i64::MAX), head),
            );
            rec.push(
                "modified",
                entry
                    .modified
                    .map_or_else(|| Value::nothing(head), |dt| Value::date(dt, head)),
            );
            if long {
                rec.push("readonly", Value::bool(entry.readonly, head));
                rec.push(
                    "target",
                    entry
                        .target
                        .map_or_else(|| Value::nothing(head), |t| Value::string(t, head)),
                );
            }
            rows.push(Value::record(rec, head));
        }

        Ok(AsyncPipelineData::value(Value::list(rows, head), None))
    }
}

/// `open`: read files through [`HeliosEnv::read_file`], preserving extension-based
/// format decoding via `from <ext>` (and `from dotenv` for `.env*` files).
#[derive(Debug, Clone, Copy)]
pub struct Open;

impl<E: HeliosEnv> AsyncCommand<E> for Open {
    fn name(&self) -> &str {
        "open"
    }

    fn description(&self) -> &str {
        "Load a file into a value, decoding structured formats by extension (avoid with `--raw`)."
    }

    fn search_terms(&self) -> Vec<&str> {
        vec!["load", "read", "cat", "load_file", "read_file"]
    }

    fn signature(&self) -> Signature {
        Signature::build("open")
            .input_output_types(vec![
                (Type::Nothing, Type::Any),
                (Type::String, Type::Any),
                (Type::Any, Type::Any),
            ])
            .rest(
                "files",
                SyntaxShape::OneOf(vec![SyntaxShape::GlobPattern, SyntaxShape::String]),
                "The file(s) to open.",
            )
            .switch(
                "raw",
                "Open file as raw text or binary without format decoding.",
                Some('r'),
            )
            .category(Category::FileSystem)
    }

    async fn run_async<'a>(
        &'a self,
        ctx: &'a mut AsyncCommandContext<'_, E>,
        input: AsyncPipelineData,
    ) -> Result<AsyncPipelineData, ShellError> {
        let head = ctx.call.head;
        let raw_flag = ctx.call.has_flag(ctx.engine_state, ctx.stack, "raw")?;
        let mut paths: Vec<Spanned<NuGlob>> = ctx.call.rest(ctx.engine_state, ctx.stack, 0)?;

        if paths.is_empty() && !ctx.call.has_positional_args(ctx.stack, 0) {
            let val = input.into_value_async(head).await?;
            if val.is_nothing() {
                return Err(ShellError::MissingParameter {
                    param_name: "files".to_owned(),
                    span: head,
                });
            }
            let span = val.span();
            paths.push(Spanned {
                item: NuGlob::Expand(val.coerce_into_string()?),
                span,
            });
        }

        let cwd = current_cwd_async(ctx.engine_state, ctx.stack, ctx.env).await;
        let mut resolved_paths = Vec::new();
        for p in paths {
            let raw_str = p.item.as_ref().to_owned();
            if p.item.is_expand() && nu_glob::is_glob(&raw_str) {
                let full_pat = normalize_vfs_path(&cwd, &raw_str);
                let matched = glob_walk(ctx.env, &cwd, &full_pat, None, p.span).await?;
                if matched.is_empty() {
                    return Err(generic_error(
                        "file not found",
                        format!("glob `{raw_str}` matched no files"),
                        p.span,
                    ));
                }
                for m in matched {
                    resolved_paths.push((m.path, p.span));
                }
            } else {
                resolved_paths.push((normalize_vfs_path(&cwd, &raw_str), p.span));
            }
        }

        let mut outputs = Vec::with_capacity(resolved_paths.len());
        for (path, span) in resolved_paths {
            let bytes = ctx
                .env
                .read_file(&path)
                .await
                .map_err(|e| e.into_shell_error(&format!("failed to open `{path}`"), span))?;

            let metadata = Some(PipelineMetadata {
                data_source: DataSource::FilePath(path.clone().into()),
                ..PipelineMetadata::default()
            });

            if raw_flag {
                let val = match String::from_utf8(bytes) {
                    Ok(s) => Value::string(s, span),
                    Err(err) => Value::binary(err.into_bytes(), span),
                };
                outputs.push(AsyncPipelineData::value(val, metadata));
                continue;
            }

            if let Some(converter) = format_converter_for_path(&path, "from") {
                let input_val = match String::from_utf8(bytes.clone()) {
                    Ok(s) => Value::string(s, span),
                    Err(_) => Value::binary(bytes.clone(), span),
                };
                if let Some(decoded) = eval_call_by_name_async(
                    ctx.engine_state,
                    ctx.stack,
                    &converter,
                    span,
                    AsyncPipelineData::value(input_val, metadata.clone()),
                    &mut crate::command::EvalRuntime {
                        env: ctx.env,
                        registry: ctx.registry,
                        runtime_scope: ctx.runtime_scope,
                    },
                )
                .await?
                {
                    outputs.push(decoded);
                    continue;
                }
            }

            let val = match String::from_utf8(bytes) {
                Ok(s) => Value::string(s, span),
                Err(err) => Value::binary(err.into_bytes(), span),
            };
            outputs.push(AsyncPipelineData::value(val, metadata));
        }

        if outputs.len() == 1 {
            Ok(outputs.pop().unwrap_or(AsyncPipelineData::Empty))
        } else {
            let mut list = Vec::with_capacity(outputs.len());
            for item in outputs {
                list.push(item.into_value_async(head).await?);
            }
            Ok(AsyncPipelineData::value(Value::list(list, head), None))
        }
    }
}

/// `save`: write pipeline data to a file through [`HeliosEnv::write_file`],
/// encoding structured values via `to <ext>` unless `--raw` is specified.
#[derive(Debug, Clone, Copy)]
pub struct Save;

impl<E: HeliosEnv> AsyncCommand<E> for Save {
    fn name(&self) -> &str {
        "save"
    }

    fn description(&self) -> &str {
        "Save pipeline data to a file."
    }

    fn signature(&self) -> Signature {
        Signature::build("save")
            .input_output_types(vec![(Type::Any, Type::Nothing)])
            .required(
                "filename",
                SyntaxShape::Filepath,
                "The destination file path.",
            )
            .switch("raw", "Save input without format conversion.", Some('r'))
            .switch(
                "append",
                "Append to the file instead of overwriting.",
                Some('a'),
            )
            .switch("force", "Overwrite an existing file.", Some('f'))
            .category(Category::FileSystem)
    }

    async fn run_async<'a>(
        &'a self,
        ctx: &'a mut AsyncCommandContext<'_, E>,
        input: AsyncPipelineData,
    ) -> Result<AsyncPipelineData, ShellError> {
        let head = ctx.call.head;
        let raw_flag = ctx.call.has_flag(ctx.engine_state, ctx.stack, "raw")?;
        let append = ctx.call.has_flag(ctx.engine_state, ctx.stack, "append")?;
        let force = ctx.call.has_flag(ctx.engine_state, ctx.stack, "force")?;
        let filename: String = ctx.call.req(ctx.engine_state, ctx.stack, 0)?;

        let cwd = current_cwd_async(ctx.engine_state, ctx.stack, ctx.env).await;
        let resolved = normalize_vfs_path(&cwd, &filename);

        let prepared = if !raw_flag
            && let Some(converter) = format_converter_for_path(&resolved, "to")
            && !matches!(
                &input,
                AsyncPipelineData::Value(Value::String { .. } | Value::Binary { .. }, _)
                    | AsyncPipelineData::ByteStream { .. }
            ) {
            if let Some(encoded) = eval_call_by_name_async(
                ctx.engine_state,
                ctx.stack,
                &converter,
                head,
                input,
                &mut crate::command::EvalRuntime {
                    env: ctx.env,
                    registry: ctx.registry,
                    runtime_scope: ctx.runtime_scope,
                },
            )
            .await?
            {
                encoded
            } else {
                AsyncPipelineData::Empty
            }
        } else {
            input
        };

        let bytes = prepared.into_bytes_async(head).await?;
        ctx.env
            .write_file(&resolved, &bytes, append, force)
            .await
            .map_err(|e| e.into_shell_error(&format!("failed to save `{resolved}`"), head))?;
        Ok(AsyncPipelineData::Empty)
    }
}

/// `mkdir`: create one or more directories via [`HeliosEnv::mkdir`].
#[derive(Debug, Clone, Copy)]
pub struct Mkdir;

impl<E: HeliosEnv> AsyncCommand<E> for Mkdir {
    fn name(&self) -> &str {
        "mkdir"
    }

    fn description(&self) -> &str {
        "Create directories, creating parent directories as needed."
    }

    fn signature(&self) -> Signature {
        Signature::build("mkdir")
            .input_output_types(vec![(Type::Nothing, Type::Nothing)])
            .rest("rest", SyntaxShape::Directory, "Directory paths to create.")
            .category(Category::FileSystem)
    }

    async fn run_async<'a>(
        &'a self,
        ctx: &'a mut AsyncCommandContext<'_, E>,
        _input: AsyncPipelineData,
    ) -> Result<AsyncPipelineData, ShellError> {
        let head = ctx.call.head;
        let dirs: Vec<String> = ctx.call.rest(ctx.engine_state, ctx.stack, 0)?;
        if dirs.is_empty() {
            return Err(ShellError::MissingParameter {
                param_name: "rest".to_owned(),
                span: head,
            });
        }
        let cwd = current_cwd_async(ctx.engine_state, ctx.stack, ctx.env).await;
        for dir in dirs {
            let resolved = normalize_vfs_path(&cwd, &dir);
            ctx.env
                .mkdir(&resolved)
                .await
                .map_err(|e| e.into_shell_error(&format!("mkdir `{resolved}` failed"), head))?;
        }
        Ok(AsyncPipelineData::Empty)
    }
}

/// `rm`: remove files or directories via [`HeliosEnv::remove`].
#[derive(Debug, Clone, Copy)]
pub struct Rm;

impl<E: HeliosEnv> AsyncCommand<E> for Rm {
    fn name(&self) -> &str {
        "rm"
    }

    fn description(&self) -> &str {
        "Remove files and directories."
    }

    fn signature(&self) -> Signature {
        Signature::build("rm")
            .input_output_types(vec![(Type::Nothing, Type::Nothing)])
            .switch("recursive", "Delete subdirectories recursively.", Some('r'))
            .switch("force", "Ignore missing files.", Some('f'))
            .rest(
                "rest",
                SyntaxShape::OneOf(vec![SyntaxShape::GlobPattern, SyntaxShape::Filepath]),
                "Paths to remove.",
            )
            .category(Category::FileSystem)
    }

    async fn run_async<'a>(
        &'a self,
        ctx: &'a mut AsyncCommandContext<'_, E>,
        _input: AsyncPipelineData,
    ) -> Result<AsyncPipelineData, ShellError> {
        let head = ctx.call.head;
        let recursive = ctx
            .call
            .has_flag(ctx.engine_state, ctx.stack, "recursive")?;
        let force = ctx.call.has_flag(ctx.engine_state, ctx.stack, "force")?;
        let targets: Vec<Spanned<NuGlob>> = ctx.call.rest(ctx.engine_state, ctx.stack, 0)?;
        if targets.is_empty() {
            return Err(ShellError::MissingParameter {
                param_name: "rest".to_owned(),
                span: head,
            });
        }

        let cwd = current_cwd_async(ctx.engine_state, ctx.stack, ctx.env).await;
        for target in targets {
            let raw = target.item.as_ref().to_owned();
            if target.item.is_expand() && nu_glob::is_glob(&raw) {
                let full_pat = normalize_vfs_path(&cwd, &raw);
                let matched = glob_walk(ctx.env, &cwd, &full_pat, None, target.span).await?;
                for entry in matched {
                    ctx.env
                        .remove(&entry.path, recursive, force)
                        .await
                        .map_err(|e| e.into_shell_error("rm failed", target.span))?;
                }
            } else {
                let resolved = normalize_vfs_path(&cwd, &raw);
                ctx.env
                    .remove(&resolved, recursive, force)
                    .await
                    .map_err(|e| e.into_shell_error("rm failed", target.span))?;
            }
        }
        Ok(AsyncPipelineData::Empty)
    }
}

/// `cp`: copy files or directories via [`HeliosEnv::copy`].
#[derive(Debug, Clone, Copy)]
pub struct Cp;

impl<E: HeliosEnv> AsyncCommand<E> for Cp {
    fn name(&self) -> &str {
        "cp"
    }

    fn description(&self) -> &str {
        "Copy files or directories."
    }

    fn signature(&self) -> Signature {
        Signature::build("cp")
            .input_output_types(vec![(Type::Nothing, Type::Nothing)])
            .switch("recursive", "Copy directories recursively.", Some('r'))
            .switch("force", "Overwrite existing destination files.", Some('f'))
            .required("source", SyntaxShape::Filepath, "Source file or directory.")
            .required(
                "destination",
                SyntaxShape::Filepath,
                "Destination file or directory.",
            )
            .category(Category::FileSystem)
    }

    async fn run_async<'a>(
        &'a self,
        ctx: &'a mut AsyncCommandContext<'_, E>,
        _input: AsyncPipelineData,
    ) -> Result<AsyncPipelineData, ShellError> {
        let head = ctx.call.head;
        let recursive = ctx
            .call
            .has_flag(ctx.engine_state, ctx.stack, "recursive")?;
        let force = ctx.call.has_flag(ctx.engine_state, ctx.stack, "force")?;
        let src: String = ctx.call.req(ctx.engine_state, ctx.stack, 0)?;
        let dst: String = ctx.call.req(ctx.engine_state, ctx.stack, 1)?;
        let cwd = current_cwd_async(ctx.engine_state, ctx.stack, ctx.env).await;
        let from = normalize_vfs_path(&cwd, &src);
        let to = normalize_vfs_path(&cwd, &dst);

        ctx.env
            .copy(&from, &to, recursive, force)
            .await
            .map_err(|e| e.into_shell_error("cp failed", head))?;
        Ok(AsyncPipelineData::Empty)
    }
}

/// `mv`: move or rename files and directories via [`HeliosEnv::rename`].
#[derive(Debug, Clone, Copy)]
pub struct Mv;

impl<E: HeliosEnv> AsyncCommand<E> for Mv {
    fn name(&self) -> &str {
        "mv"
    }

    fn description(&self) -> &str {
        "Move or rename files or directories."
    }

    fn signature(&self) -> Signature {
        Signature::build("mv")
            .input_output_types(vec![(Type::Nothing, Type::Nothing)])
            .switch("force", "Overwrite an existing destination.", Some('f'))
            .required("source", SyntaxShape::Filepath, "Source path.")
            .required("destination", SyntaxShape::Filepath, "Destination path.")
            .category(Category::FileSystem)
    }

    async fn run_async<'a>(
        &'a self,
        ctx: &'a mut AsyncCommandContext<'_, E>,
        _input: AsyncPipelineData,
    ) -> Result<AsyncPipelineData, ShellError> {
        let head = ctx.call.head;
        let force = ctx.call.has_flag(ctx.engine_state, ctx.stack, "force")?;
        let src: String = ctx.call.req(ctx.engine_state, ctx.stack, 0)?;
        let dst: String = ctx.call.req(ctx.engine_state, ctx.stack, 1)?;
        let cwd = current_cwd_async(ctx.engine_state, ctx.stack, ctx.env).await;
        let from = normalize_vfs_path(&cwd, &src);
        let to = normalize_vfs_path(&cwd, &dst);

        ctx.env
            .rename(&from, &to, force)
            .await
            .map_err(|e| e.into_shell_error("mv failed", head))?;
        Ok(AsyncPipelineData::Empty)
    }
}

/// `touch`: create empty files or update modification timestamps via [`HeliosEnv::touch`].
#[derive(Debug, Clone, Copy)]
pub struct Touch;

impl<E: HeliosEnv> AsyncCommand<E> for Touch {
    fn name(&self) -> &str {
        "touch"
    }

    fn description(&self) -> &str {
        "Create files or update their modification timestamps."
    }

    fn signature(&self) -> Signature {
        Signature::build("touch")
            .input_output_types(vec![(Type::Nothing, Type::Nothing)])
            .switch(
                "no-create",
                "Do not create files that do not exist.",
                Some('c'),
            )
            .required("filename", SyntaxShape::Filepath, "Path of the file.")
            .rest("rest", SyntaxShape::Filepath, "Additional files to touch.")
            .category(Category::FileSystem)
    }

    async fn run_async<'a>(
        &'a self,
        ctx: &'a mut AsyncCommandContext<'_, E>,
        _input: AsyncPipelineData,
    ) -> Result<AsyncPipelineData, ShellError> {
        let head = ctx.call.head;
        let no_create = ctx
            .call
            .has_flag(ctx.engine_state, ctx.stack, "no-create")?;
        let first: String = ctx.call.req(ctx.engine_state, ctx.stack, 0)?;
        let rest: Vec<String> = ctx.call.rest(ctx.engine_state, ctx.stack, 1)?;
        let cwd = current_cwd_async(ctx.engine_state, ctx.stack, ctx.env).await;

        for file in std::iter::once(first).chain(rest) {
            let resolved = normalize_vfs_path(&cwd, &file);
            ctx.env
                .touch(&resolved, no_create)
                .await
                .map_err(|e| e.into_shell_error("touch failed", head))?;
        }
        Ok(AsyncPipelineData::Empty)
    }
}

/// `glob`: capability-bounded glob matching over [`HeliosEnv::list_dir`].
#[derive(Debug, Clone, Copy)]
pub struct Glob;

impl<E: HeliosEnv> AsyncCommand<E> for Glob {
    fn name(&self) -> &str {
        "glob"
    }

    fn description(&self) -> &str {
        "Create a list of files and/or folders using a glob pattern over granted directories."
    }

    fn signature(&self) -> Signature {
        Signature::build("glob")
            .input_output_types(vec![(Type::Nothing, Type::list(Type::String))])
            .required("glob", SyntaxShape::String, "The glob expression.")
            .named(
                "depth",
                SyntaxShape::Int,
                "Maximum directory traversal depth.",
                Some('d'),
            )
            .switch("no-dir", "Exclude directories from the output.", Some('D'))
            .switch(
                "no-file",
                "Exclude regular files from the output.",
                Some('F'),
            )
            .named(
                "exclude",
                SyntaxShape::List(Box::new(SyntaxShape::String)),
                "Patterns to exclude.",
                Some('e'),
            )
            .category(Category::FileSystem)
    }

    async fn run_async<'a>(
        &'a self,
        ctx: &'a mut AsyncCommandContext<'_, E>,
        _input: AsyncPipelineData,
    ) -> Result<AsyncPipelineData, ShellError> {
        let head = ctx.call.head;
        let pat_raw: String = ctx.call.req(ctx.engine_state, ctx.stack, 0)?;
        let depth: Option<i64> = ctx.call.get_flag(ctx.engine_state, ctx.stack, "depth")?;
        let no_dir = ctx.call.has_flag(ctx.engine_state, ctx.stack, "no-dir")?;
        let no_file = ctx.call.has_flag(ctx.engine_state, ctx.stack, "no-file")?;
        let exclude: Option<Vec<String>> =
            ctx.call.get_flag(ctx.engine_state, ctx.stack, "exclude")?;

        let max_depth = match depth {
            Some(d) if d < 0 => {
                return Err(generic_error(
                    "invalid depth",
                    "depth must be non-negative",
                    head,
                ));
            }
            Some(d) => Some(usize::try_from(d).unwrap_or(usize::MAX)),
            None => None,
        };

        let exclude_patterns: Vec<Pattern> = exclude
            .unwrap_or_default()
            .into_iter()
            .map(|p| {
                Pattern::new(&p)
                    .map_err(|err| generic_error("invalid exclude glob", err.to_string(), head))
            })
            .collect::<Result<_, _>>()?;

        let cwd = current_cwd_async(ctx.engine_state, ctx.stack, ctx.env).await;
        let full_pat = normalize_vfs_path(&cwd, &pat_raw);
        let matched = glob_walk(ctx.env, &cwd, &full_pat, max_depth, head).await?;

        let values: Vec<Value> = matched
            .into_iter()
            .filter(|entry| {
                if no_dir && entry.file_type == FileType::Dir {
                    return false;
                }
                if no_file && entry.file_type == FileType::File {
                    return false;
                }
                if exclude_patterns
                    .iter()
                    .any(|ex| ex.matches(&entry.path) || ex.matches(&entry.name))
                {
                    return false;
                }
                true
            })
            .map(|entry| Value::string(entry.path, head))
            .collect();

        Ok(AsyncPipelineData::value(Value::list(values, head), None))
    }
}

/// `watch`: asynchronously watch a VFS path via [`HeliosEnv::watch`] and run a
/// closure on every matching event.
#[derive(Debug, Clone, Copy)]
pub struct Watch;

impl<E: HeliosEnv> AsyncCommand<E> for Watch {
    fn name(&self) -> &str {
        "watch"
    }

    fn description(&self) -> &str {
        "Watch for file changes asynchronously and invoke a closure for each event."
    }

    fn signature(&self) -> Signature {
        Signature::build("watch")
            .input_output_types(vec![(Type::Nothing, Type::Any)])
            .required("path", SyntaxShape::Filepath, "The path to watch.")
            .required(
                "block",
                SyntaxShape::Closure(Some(vec![
                    SyntaxShape::String,
                    SyntaxShape::String,
                    SyntaxShape::String,
                ])),
                "Closure invoked with `(operation, path, new_path)` for each event.",
            )
            .named(
                "glob",
                SyntaxShape::String,
                "Only report events whose path matches this glob.",
                Some('g'),
            )
            .named(
                "max-events",
                SyntaxShape::Int,
                "Stop watching after handling this many matching events.",
                Some('n'),
            )
            .category(Category::FileSystem)
    }

    async fn run_async<'a>(
        &'a self,
        ctx: &'a mut AsyncCommandContext<'_, E>,
        _input: AsyncPipelineData,
    ) -> Result<AsyncPipelineData, ShellError> {
        let head = ctx.call.head;
        let path_arg: String = ctx.call.req(ctx.engine_state, ctx.stack, 0)?;
        let closure: Closure = ctx.call.req(ctx.engine_state, ctx.stack, 1)?;
        let glob_filter: Option<String> = ctx.call.get_flag(ctx.engine_state, ctx.stack, "glob")?;
        let max_events: Option<i64> =
            ctx.call
                .get_flag(ctx.engine_state, ctx.stack, "max-events")?;

        let filter_pat = match glob_filter {
            Some(pat) => Some(
                Pattern::new(&pat)
                    .map_err(|e| generic_error("invalid watch glob", e.to_string(), head))?,
            ),
            None => None,
        };
        let limit = max_events.and_then(|n| usize::try_from(n).ok());

        let cwd = current_cwd_async(ctx.engine_state, ctx.stack, ctx.env).await;
        let resolved = normalize_vfs_path(&cwd, &path_arg);
        let rx = ctx
            .env
            .watch(&resolved)
            .await
            .map_err(|e| e.into_shell_error("watch failed", head))?;

        let mut handled = 0_usize;
        let mut results = Vec::new();
        while let Ok(event) = rx.recv().await {
            if ctx.engine_state.signals().interrupted() {
                break;
            }
            if let Some(pat) = &filter_pat
                && !pat.matches(&event.path)
            {
                continue;
            }

            let args = vec![
                Value::string(event.operation, head),
                Value::string(event.path, head),
                event
                    .new_path
                    .map_or_else(|| Value::nothing(head), |p| Value::string(p, head)),
            ];
            let mut rt = crate::command::EvalRuntime {
                env: ctx.env,
                registry: ctx.registry,
                runtime_scope: ctx.runtime_scope,
            };
            let out = eval_closure_async(
                ctx.engine_state,
                ctx.stack,
                &closure,
                args,
                AsyncPipelineData::Empty,
                &mut rt,
                head,
            )
            .await?;
            let val = out.into_value_async(head).await?;
            if !val.is_nothing() {
                results.push(val);
            }

            handled += 1;
            if limit.is_some_and(|max| handled >= max) {
                break;
            }
        }

        if results.is_empty() {
            Ok(AsyncPipelineData::Empty)
        } else {
            Ok(AsyncPipelineData::value(Value::list(results, head), None))
        }
    }
}

/// Walk granted VFS directories breadth-first and match entries against `full_pattern`.
async fn glob_walk<E: HeliosEnv>(
    env: &E,
    cwd: &str,
    full_pattern: &str,
    max_depth: Option<usize>,
    span: Span,
) -> Result<Vec<FileMetadata>, ShellError> {
    let pattern = Pattern::new(full_pattern)
        .map_err(|err| generic_error("invalid glob pattern", err.to_string(), span))?;

    let root = glob_static_root(full_pattern, cwd);
    let mut queue = VecDeque::new();
    queue.push_back((root, 0_usize));

    let mut matches = Vec::new();
    while let Some((dir, depth)) = queue.pop_front() {
        let Ok(entries) = env.list_dir(&dir).await else {
            continue;
        };
        for entry in entries {
            if pattern.matches(&entry.path) {
                matches.push(entry.clone());
            }
            if entry.file_type == FileType::Dir && max_depth.is_none_or(|limit| depth < limit) {
                queue.push_back((entry.path, depth + 1));
            }
        }
    }
    matches.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(matches)
}

/// Extract the longest non-glob directory prefix from a normalized absolute glob pattern.
fn glob_static_root(pattern: &str, fallback_cwd: &str) -> String {
    let mut prefix_parts = Vec::new();
    for seg in pattern.split('/').filter(|s| !s.is_empty()) {
        if nu_glob::is_glob(seg) {
            break;
        }
        prefix_parts.push(seg);
    }
    if prefix_parts.is_empty() {
        if pattern.starts_with('/') {
            String::from("/")
        } else {
            fallback_cwd.to_owned()
        }
    } else {
        format!("/{}", prefix_parts.join("/"))
    }
}

fn display_relative(cwd: &str, abs_path: &str) -> String {
    if cwd == "/" {
        abs_path.strip_prefix('/').unwrap_or(abs_path).to_owned()
    } else if let Some(rest) = abs_path.strip_prefix(cwd).and_then(|s| s.strip_prefix('/')) {
        rest.to_owned()
    } else {
        abs_path.to_owned()
    }
}

/// Map a file path's extension (or `.env*` basename) to its Nushell `from <ext>` / `to <ext>` command.
fn format_converter_for_path(path: &str, verb: &str) -> Option<String> {
    let file_name = path.rsplit('/').next().unwrap_or(path);
    if file_name == ".env" || file_name.starts_with(".env.") || file_name.ends_with(".env") {
        return Some(format!("{verb} dotenv"));
    }
    let (_, ext) = file_name.rsplit_once('.')?;
    let ext = ext.to_ascii_lowercase();
    if ext.is_empty() {
        return None;
    }
    Some(format!("{verb} {ext}"))
}
