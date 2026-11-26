//! Storage and filesystem management commands:
//! `mount`, `umount`, and `btrfs subvolume {create, delete, snapshot, list, show, set-ro, send, receive}`.

use nu_engine::CallExt;
use nu_protocol::{Category, Record, ShellError, Signature, Span, SyntaxShape, Type, Value};

use crate::command::{AsyncCommand, AsyncCommandContext};
use crate::env::{
    BtrfsSubvolumeInfo, HeliosEnv, MountEntryInfo, MountRequestSpec, MountSharingSpec,
    MountSourceSpec,
};
use crate::error::generic_error;
use crate::eval::{current_cwd_async, resolve_vfs_path};
use crate::pipeline::AsyncPipelineData;

fn mount_columns() -> Vec<(String, Type)> {
    vec![
        ("path".into(), Type::String),
        ("source".into(), Type::String),
        ("kind".into(), Type::String),
        ("read_only".into(), Type::Bool),
        ("sharing".into(), Type::String),
    ]
}

fn mount_entry_to_value(entry: MountEntryInfo, span: Span) -> Value {
    let mut rec = Record::new();
    rec.push("path", Value::string(entry.path, span));
    rec.push("source", Value::string(entry.source, span));
    rec.push("kind", Value::string(entry.kind, span));
    rec.push("read_only", Value::bool(entry.read_only, span));
    rec.push("sharing", Value::string(entry.sharing, span));
    Value::record(rec, span)
}

fn subvolume_columns() -> Vec<(String, Type)> {
    vec![
        ("id".into(), Type::Int),
        ("parent_id".into(), Type::Any),
        ("path".into(), Type::String),
        ("uuid".into(), Type::String),
        ("parent_uuid".into(), Type::Any),
        ("received_uuid".into(), Type::Any),
        ("generation".into(), Type::Int),
        ("ctransid".into(), Type::Int),
        ("otransid".into(), Type::Int),
        ("stransid".into(), Type::Int),
        ("rtransid".into(), Type::Int),
        ("read_only".into(), Type::Bool),
    ]
}

fn subvolume_to_value(info: BtrfsSubvolumeInfo, span: Span) -> Value {
    let mut rec = Record::new();
    rec.push(
        "id",
        Value::int(i64::try_from(info.id).unwrap_or(i64::MAX), span),
    );
    rec.push(
        "parent_id",
        info.parent_id.map_or_else(
            || Value::nothing(span),
            |id| Value::int(i64::try_from(id).unwrap_or(i64::MAX), span),
        ),
    );
    rec.push("path", Value::string(info.path, span));
    rec.push("uuid", Value::string(info.uuid, span));
    rec.push(
        "parent_uuid",
        info.parent_uuid
            .map_or_else(|| Value::nothing(span), |u| Value::string(u, span)),
    );
    rec.push(
        "received_uuid",
        info.received_uuid
            .map_or_else(|| Value::nothing(span), |u| Value::string(u, span)),
    );
    rec.push(
        "generation",
        Value::int(i64::try_from(info.generation).unwrap_or(i64::MAX), span),
    );
    rec.push(
        "ctransid",
        Value::int(i64::try_from(info.ctransid).unwrap_or(i64::MAX), span),
    );
    rec.push(
        "otransid",
        Value::int(i64::try_from(info.otransid).unwrap_or(i64::MAX), span),
    );
    rec.push(
        "stransid",
        Value::int(i64::try_from(info.stransid).unwrap_or(i64::MAX), span),
    );
    rec.push(
        "rtransid",
        Value::int(i64::try_from(info.rtransid).unwrap_or(i64::MAX), span),
    );
    rec.push("read_only", Value::bool(info.read_only, span));
    Value::record(rec, span)
}

/// `mount`: list active mounts (no arguments) or attach a filesystem at a mount point.
#[derive(Debug, Clone, Copy)]
pub struct Mount;

impl<E: HeliosEnv> AsyncCommand<E> for Mount {
    fn name(&self) -> &str {
        "mount"
    }

    fn description(&self) -> &str {
        "List mounted filesystems or attach a filesystem to the guest path tree."
    }

    fn signature(&self) -> Signature {
        Signature::build("mount")
            .input_output_types(vec![
                (Type::Nothing, Type::Table(mount_columns().into())),
                (Type::Nothing, Type::Nothing),
            ])
            .optional(
                "source",
                SyntaxShape::String,
                "Mount source (`memory`, `boot-image`, `host-share`, `disk:<serial>`, `btrfs:<serial>`).",
            )
            .optional(
                "path",
                SyntaxShape::Filepath,
                "Directory path to mount at.",
            )
            .switch("ro", "Attach the filesystem read-only.", Some('r'))
            .switch("private", "Attach as a container-private mount.", None)
            .switch("shared", "Attach as a shared mount (default).", None)
            .named(
                "compress",
                SyntaxShape::String,
                "Writable btrfs compression option (e.g. `zstd:3`, `zlib`, `lzo`, `no`).",
                None,
            )
            .named(
                "commit",
                SyntaxShape::Int,
                "Writable btrfs commit interval in seconds.",
                None,
            )
            .named(
                "max-inline",
                SyntaxShape::Int,
                "Writable btrfs maximum inline file extent size in bytes.",
                None,
            )
            .category(Category::System)
    }

    async fn run_async<'a>(
        &'a self,
        ctx: &'a mut AsyncCommandContext<'_, E>,
        _input: AsyncPipelineData,
    ) -> Result<AsyncPipelineData, ShellError> {
        let head = ctx.call.head;
        let source_raw: Option<String> = ctx.call.opt(ctx.engine_state, ctx.stack, 0)?;
        let path_raw: Option<String> = ctx.call.opt(ctx.engine_state, ctx.stack, 1)?;

        match (source_raw, path_raw) {
            (None, None) => {
                let entries = ctx
                    .env
                    .list_mounts()
                    .await
                    .map_err(|e| e.into_shell_error("mount list failed", head))?;
                let rows = entries
                    .into_iter()
                    .map(|e| mount_entry_to_value(e, head))
                    .collect();
                Ok(AsyncPipelineData::value(Value::list(rows, head), None))
            }
            (Some(_), None) => Err(generic_error(
                "missing mount path",
                "provide both `<source>` and `<path>`, or neither to list mounts",
                head,
            )),
            (None, Some(_)) => Err(generic_error(
                "missing mount source",
                "provide both `<source>` and `<path>`",
                head,
            )),
            (Some(src), Some(raw_path)) => {
                let read_only = ctx.call.has_flag(ctx.engine_state, ctx.stack, "ro")?;
                let private = ctx.call.has_flag(ctx.engine_state, ctx.stack, "private")?;
                let shared = ctx.call.has_flag(ctx.engine_state, ctx.stack, "shared")?;
                if private && shared {
                    return Err(generic_error(
                        "conflicting mount flags",
                        "`--private` and `--shared` are mutually exclusive",
                        head,
                    ));
                }
                let sharing = if private {
                    MountSharingSpec::Private
                } else {
                    MountSharingSpec::Shared
                };
                let compress: Option<String> =
                    ctx.call.get_flag(ctx.engine_state, ctx.stack, "compress")?;
                let commit_i64: Option<i64> =
                    ctx.call.get_flag(ctx.engine_state, ctx.stack, "commit")?;
                let max_inline_i64: Option<i64> =
                    ctx.call
                        .get_flag(ctx.engine_state, ctx.stack, "max-inline")?;

                let commit = match commit_i64 {
                    Some(v) => Some(u32::try_from(v).map_err(|_| {
                        generic_error(
                            "invalid `--commit`",
                            format!("commit interval must be a non-negative u32, got {v}"),
                            head,
                        )
                    })?),
                    None => None,
                };
                let max_inline = match max_inline_i64 {
                    Some(v) => Some(u64::try_from(v).map_err(|_| {
                        generic_error(
                            "invalid `--max-inline`",
                            format!("max-inline must be non-negative, got {v}"),
                            head,
                        )
                    })?),
                    None => None,
                };

                let source = parse_mount_source(&src, head)?;
                let cwd = current_cwd_async(ctx.engine_state, ctx.stack, ctx.env).await;
                let path = resolve_vfs_path(ctx.engine_state, ctx.stack, &cwd, &raw_path, true);

                ctx.env
                    .mount(MountRequestSpec {
                        source,
                        path,
                        read_only,
                        sharing,
                        compress,
                        commit,
                        max_inline,
                    })
                    .await
                    .map_err(|e| e.into_shell_error("mount failed", head))?;

                Ok(AsyncPipelineData::Empty)
            }
        }
    }
}

/// `umount <path>`: detach a mounted filesystem.
#[derive(Debug, Clone, Copy)]
pub struct Umount;

impl<E: HeliosEnv> AsyncCommand<E> for Umount {
    fn name(&self) -> &str {
        "umount"
    }

    fn description(&self) -> &str {
        "Detach the filesystem mounted at the given path."
    }

    fn signature(&self) -> Signature {
        Signature::build("umount")
            .input_output_types(vec![(Type::Nothing, Type::Nothing)])
            .required("path", SyntaxShape::Filepath, "Mounted directory path.")
            .category(Category::System)
    }

    async fn run_async<'a>(
        &'a self,
        ctx: &'a mut AsyncCommandContext<'_, E>,
        _input: AsyncPipelineData,
    ) -> Result<AsyncPipelineData, ShellError> {
        let head = ctx.call.head;
        let raw_path: String = ctx.call.req(ctx.engine_state, ctx.stack, 0)?;
        let cwd = current_cwd_async(ctx.engine_state, ctx.stack, ctx.env).await;
        let path = resolve_vfs_path(ctx.engine_state, ctx.stack, &cwd, &raw_path, true);
        ctx.env
            .umount(&path)
            .await
            .map_err(|e| e.into_shell_error("umount failed", head))?;
        Ok(AsyncPipelineData::Empty)
    }
}

/// `btrfs`: parent namespace for btrfs volume commands.
#[derive(Debug, Clone, Copy)]
pub struct Btrfs;

impl<E: HeliosEnv> AsyncCommand<E> for Btrfs {
    fn name(&self) -> &str {
        "btrfs"
    }

    fn description(&self) -> &str {
        "Manage mounted btrfs copy-on-write filesystems and subvolumes."
    }

    fn signature(&self) -> Signature {
        Signature::build("btrfs")
            .input_output_types(vec![(
                Type::Nothing,
                Type::Table(subvolume_columns().into()),
            )])
            .optional(
                "mount_point",
                SyntaxShape::Filepath,
                "Optional btrfs mount point (defaults to `/`).",
            )
            .category(Category::System)
    }

    async fn run_async<'a>(
        &'a self,
        ctx: &'a mut AsyncCommandContext<'_, E>,
        input: AsyncPipelineData,
    ) -> Result<AsyncPipelineData, ShellError> {
        BtrfsSubvolumeList.run_async(ctx, input).await
    }
}

/// `btrfs subvolume`: parent namespace for subvolume operations.
#[derive(Debug, Clone, Copy)]
pub struct BtrfsSubvolume;

impl<E: HeliosEnv> AsyncCommand<E> for BtrfsSubvolume {
    fn name(&self) -> &str {
        "btrfs subvolume"
    }

    fn description(&self) -> &str {
        "Create, snapshot, list, inspect, send, receive, and delete btrfs subvolumes."
    }

    fn signature(&self) -> Signature {
        Signature::build("btrfs subvolume")
            .input_output_types(vec![(
                Type::Nothing,
                Type::Table(subvolume_columns().into()),
            )])
            .optional(
                "mount_point",
                SyntaxShape::Filepath,
                "Optional btrfs mount point (defaults to `/`).",
            )
            .category(Category::System)
    }

    async fn run_async<'a>(
        &'a self,
        ctx: &'a mut AsyncCommandContext<'_, E>,
        input: AsyncPipelineData,
    ) -> Result<AsyncPipelineData, ShellError> {
        BtrfsSubvolumeList.run_async(ctx, input).await
    }
}

/// `btrfs subvolume create <path>`.
#[derive(Debug, Clone, Copy)]
pub struct BtrfsSubvolumeCreate;

impl<E: HeliosEnv> AsyncCommand<E> for BtrfsSubvolumeCreate {
    fn name(&self) -> &str {
        "btrfs subvolume create"
    }

    fn description(&self) -> &str {
        "Create a new empty btrfs subvolume at the specified path."
    }

    fn signature(&self) -> Signature {
        Signature::build("btrfs subvolume create")
            .input_output_types(vec![(
                Type::Nothing,
                Type::Record(subvolume_columns().into()),
            )])
            .required("path", SyntaxShape::Filepath, "Destination subvolume path.")
            .category(Category::System)
    }

    async fn run_async<'a>(
        &'a self,
        ctx: &'a mut AsyncCommandContext<'_, E>,
        _input: AsyncPipelineData,
    ) -> Result<AsyncPipelineData, ShellError> {
        let head = ctx.call.head;
        let raw_path: String = ctx.call.req(ctx.engine_state, ctx.stack, 0)?;
        let cwd = current_cwd_async(ctx.engine_state, ctx.stack, ctx.env).await;
        let path = resolve_vfs_path(ctx.engine_state, ctx.stack, &cwd, &raw_path, true);
        let info = ctx
            .env
            .btrfs_subvolume_create(&path)
            .await
            .map_err(|e| e.into_shell_error("btrfs subvolume create failed", head))?;
        Ok(AsyncPipelineData::value(
            subvolume_to_value(info, head),
            None,
        ))
    }
}

/// `btrfs subvolume delete <path>`.
#[derive(Debug, Clone, Copy)]
pub struct BtrfsSubvolumeDelete;

impl<E: HeliosEnv> AsyncCommand<E> for BtrfsSubvolumeDelete {
    fn name(&self) -> &str {
        "btrfs subvolume delete"
    }

    fn description(&self) -> &str {
        "Delete the btrfs subvolume rooted at the specified path."
    }

    fn signature(&self) -> Signature {
        Signature::build("btrfs subvolume delete")
            .input_output_types(vec![(Type::Nothing, Type::Nothing)])
            .required("path", SyntaxShape::Filepath, "Subvolume path to delete.")
            .category(Category::System)
    }

    async fn run_async<'a>(
        &'a self,
        ctx: &'a mut AsyncCommandContext<'_, E>,
        _input: AsyncPipelineData,
    ) -> Result<AsyncPipelineData, ShellError> {
        let head = ctx.call.head;
        let raw_path: String = ctx.call.req(ctx.engine_state, ctx.stack, 0)?;
        let cwd = current_cwd_async(ctx.engine_state, ctx.stack, ctx.env).await;
        let path = resolve_vfs_path(ctx.engine_state, ctx.stack, &cwd, &raw_path, true);
        ctx.env
            .btrfs_subvolume_delete(&path)
            .await
            .map_err(|e| e.into_shell_error("btrfs subvolume delete failed", head))?;
        Ok(AsyncPipelineData::Empty)
    }
}

/// `btrfs subvolume snapshot <source> <destination> [--read-only]`.
#[derive(Debug, Clone, Copy)]
pub struct BtrfsSubvolumeSnapshot;

impl<E: HeliosEnv> AsyncCommand<E> for BtrfsSubvolumeSnapshot {
    fn name(&self) -> &str {
        "btrfs subvolume snapshot"
    }

    fn description(&self) -> &str {
        "Create a copy-on-write snapshot of a btrfs subvolume."
    }

    fn signature(&self) -> Signature {
        Signature::build("btrfs subvolume snapshot")
            .input_output_types(vec![(
                Type::Nothing,
                Type::Record(subvolume_columns().into()),
            )])
            .switch("read-only", "Create a read-only snapshot.", Some('r'))
            .required("source", SyntaxShape::Filepath, "Source subvolume path.")
            .required(
                "destination",
                SyntaxShape::Filepath,
                "Destination snapshot path.",
            )
            .category(Category::System)
    }

    async fn run_async<'a>(
        &'a self,
        ctx: &'a mut AsyncCommandContext<'_, E>,
        _input: AsyncPipelineData,
    ) -> Result<AsyncPipelineData, ShellError> {
        let head = ctx.call.head;
        let read_only = ctx
            .call
            .has_flag(ctx.engine_state, ctx.stack, "read-only")?;
        let src_raw: String = ctx.call.req(ctx.engine_state, ctx.stack, 0)?;
        let dst_raw: String = ctx.call.req(ctx.engine_state, ctx.stack, 1)?;
        let cwd = current_cwd_async(ctx.engine_state, ctx.stack, ctx.env).await;
        let source = resolve_vfs_path(ctx.engine_state, ctx.stack, &cwd, &src_raw, true);
        let destination = resolve_vfs_path(ctx.engine_state, ctx.stack, &cwd, &dst_raw, true);

        let info = ctx
            .env
            .btrfs_subvolume_snapshot(&source, &destination, read_only)
            .await
            .map_err(|e| e.into_shell_error("btrfs subvolume snapshot failed", head))?;
        Ok(AsyncPipelineData::value(
            subvolume_to_value(info, head),
            None,
        ))
    }
}

/// `btrfs subvolume list [mount_point]`.
#[derive(Debug, Clone, Copy)]
pub struct BtrfsSubvolumeList;

impl<E: HeliosEnv> AsyncCommand<E> for BtrfsSubvolumeList {
    fn name(&self) -> &str {
        "btrfs subvolume list"
    }

    fn description(&self) -> &str {
        "List subvolumes on a mounted btrfs filesystem."
    }

    fn signature(&self) -> Signature {
        Signature::build("btrfs subvolume list")
            .input_output_types(vec![(
                Type::Nothing,
                Type::Table(subvolume_columns().into()),
            )])
            .optional(
                "mount_point",
                SyntaxShape::Filepath,
                "Btrfs mount point (defaults to `/`).",
            )
            .category(Category::System)
    }

    async fn run_async<'a>(
        &'a self,
        ctx: &'a mut AsyncCommandContext<'_, E>,
        _input: AsyncPipelineData,
    ) -> Result<AsyncPipelineData, ShellError> {
        let head = ctx.call.head;
        let raw_mp: Option<String> = ctx.call.opt(ctx.engine_state, ctx.stack, 0)?;
        let mount_point = match raw_mp {
            Some(mp) => {
                let cwd = current_cwd_async(ctx.engine_state, ctx.stack, ctx.env).await;
                resolve_vfs_path(ctx.engine_state, ctx.stack, &cwd, &mp, true)
            }
            None => String::from("/"),
        };
        let list = ctx
            .env
            .btrfs_subvolume_list(&mount_point)
            .await
            .map_err(|e| e.into_shell_error("btrfs subvolume list failed", head))?;
        let rows = list
            .into_iter()
            .map(|info| subvolume_to_value(info, head))
            .collect();
        Ok(AsyncPipelineData::value(Value::list(rows, head), None))
    }
}

/// `btrfs subvolume show <path>`.
#[derive(Debug, Clone, Copy)]
pub struct BtrfsSubvolumeShow;

impl<E: HeliosEnv> AsyncCommand<E> for BtrfsSubvolumeShow {
    fn name(&self) -> &str {
        "btrfs subvolume show"
    }

    fn description(&self) -> &str {
        "Show detailed metadata for a btrfs subvolume."
    }

    fn signature(&self) -> Signature {
        Signature::build("btrfs subvolume show")
            .input_output_types(vec![(
                Type::Nothing,
                Type::Record(subvolume_columns().into()),
            )])
            .required("path", SyntaxShape::Filepath, "Subvolume path.")
            .category(Category::System)
    }

    async fn run_async<'a>(
        &'a self,
        ctx: &'a mut AsyncCommandContext<'_, E>,
        _input: AsyncPipelineData,
    ) -> Result<AsyncPipelineData, ShellError> {
        let head = ctx.call.head;
        let raw_path: String = ctx.call.req(ctx.engine_state, ctx.stack, 0)?;
        let cwd = current_cwd_async(ctx.engine_state, ctx.stack, ctx.env).await;
        let path = resolve_vfs_path(ctx.engine_state, ctx.stack, &cwd, &raw_path, true);
        let info = ctx
            .env
            .btrfs_subvolume_info(&path)
            .await
            .map_err(|e| e.into_shell_error("btrfs subvolume show failed", head))?;
        Ok(AsyncPipelineData::value(
            subvolume_to_value(info, head),
            None,
        ))
    }
}

/// `btrfs subvolume set-ro <path> <read_only>`.
#[derive(Debug, Clone, Copy)]
pub struct BtrfsSubvolumeSetRo;

impl<E: HeliosEnv> AsyncCommand<E> for BtrfsSubvolumeSetRo {
    fn name(&self) -> &str {
        "btrfs subvolume set-ro"
    }

    fn description(&self) -> &str {
        "Set or clear the read-only flag on a btrfs subvolume."
    }

    fn signature(&self) -> Signature {
        Signature::build("btrfs subvolume set-ro")
            .input_output_types(vec![(Type::Nothing, Type::Nothing)])
            .required("path", SyntaxShape::Filepath, "Subvolume path.")
            .required(
                "read_only",
                SyntaxShape::Boolean,
                "Whether the subvolume should be read-only.",
            )
            .category(Category::System)
    }

    async fn run_async<'a>(
        &'a self,
        ctx: &'a mut AsyncCommandContext<'_, E>,
        _input: AsyncPipelineData,
    ) -> Result<AsyncPipelineData, ShellError> {
        let head = ctx.call.head;
        let raw_path: String = ctx.call.req(ctx.engine_state, ctx.stack, 0)?;
        let read_only: bool = ctx.call.req(ctx.engine_state, ctx.stack, 1)?;
        let cwd = current_cwd_async(ctx.engine_state, ctx.stack, ctx.env).await;
        let path = resolve_vfs_path(ctx.engine_state, ctx.stack, &cwd, &raw_path, true);
        ctx.env
            .btrfs_subvolume_set_ro(&path, read_only)
            .await
            .map_err(|e| e.into_shell_error("btrfs subvolume set-ro failed", head))?;
        Ok(AsyncPipelineData::Empty)
    }
}

/// `btrfs subvolume send <subvolume> [--parent <path>] [--clone-source <list>]`.
#[derive(Debug, Clone, Copy)]
pub struct BtrfsSubvolumeSend;

impl<E: HeliosEnv> AsyncCommand<E> for BtrfsSubvolumeSend {
    fn name(&self) -> &str {
        "btrfs subvolume send"
    }

    fn description(&self) -> &str {
        "Emit a btrfs v1 send stream for a read-only subvolume as binary data."
    }

    fn signature(&self) -> Signature {
        Signature::build("btrfs subvolume send")
            .input_output_types(vec![(Type::Nothing, Type::Binary)])
            .named(
                "parent",
                SyntaxShape::Filepath,
                "Optional parent read-only snapshot for incremental send.",
                Some('p'),
            )
            .named(
                "clone-source",
                SyntaxShape::List(Box::new(SyntaxShape::Filepath)),
                "Optional clone source subvolumes.",
                Some('c'),
            )
            .required(
                "subvolume",
                SyntaxShape::Filepath,
                "Read-only subvolume path.",
            )
            .category(Category::System)
    }

    async fn run_async<'a>(
        &'a self,
        ctx: &'a mut AsyncCommandContext<'_, E>,
        _input: AsyncPipelineData,
    ) -> Result<AsyncPipelineData, ShellError> {
        let head = ctx.call.head;
        let parent_raw: Option<String> =
            ctx.call.get_flag(ctx.engine_state, ctx.stack, "parent")?;
        let clone_raw: Option<Vec<String>> =
            ctx.call
                .get_flag(ctx.engine_state, ctx.stack, "clone-source")?;
        let subvol_raw: String = ctx.call.req(ctx.engine_state, ctx.stack, 0)?;

        let cwd = current_cwd_async(ctx.engine_state, ctx.stack, ctx.env).await;
        let subvol = resolve_vfs_path(ctx.engine_state, ctx.stack, &cwd, &subvol_raw, true);
        let parent =
            parent_raw.map(|p| resolve_vfs_path(ctx.engine_state, ctx.stack, &cwd, &p, true));
        let clone_sources: Vec<String> = clone_raw
            .unwrap_or_default()
            .into_iter()
            .map(|p| resolve_vfs_path(ctx.engine_state, ctx.stack, &cwd, &p, true))
            .collect();

        let bytes = ctx
            .env
            .btrfs_subvolume_send(&subvol, parent.as_deref(), &clone_sources)
            .await
            .map_err(|e| e.into_shell_error("btrfs subvolume send failed", head))?;

        Ok(AsyncPipelineData::value(Value::binary(bytes, head), None))
    }
}

/// `btrfs subvolume receive <destination> [--file <path>]`.
#[derive(Debug, Clone, Copy)]
pub struct BtrfsSubvolumeReceive;

impl<E: HeliosEnv> AsyncCommand<E> for BtrfsSubvolumeReceive {
    fn name(&self) -> &str {
        "btrfs subvolume receive"
    }

    fn description(&self) -> &str {
        "Receive a btrfs v1 send stream from pipeline input (or `--file`) into a destination directory."
    }

    fn signature(&self) -> Signature {
        Signature::build("btrfs subvolume receive")
            .input_output_types(vec![(Type::Any, Type::Record(subvolume_columns().into()))])
            .named(
                "file",
                SyntaxShape::Filepath,
                "Read the send stream from a VFS file instead of pipeline input.",
                Some('f'),
            )
            .required(
                "destination",
                SyntaxShape::Filepath,
                "Destination directory on a mounted btrfs filesystem.",
            )
            .category(Category::System)
    }

    async fn run_async<'a>(
        &'a self,
        ctx: &'a mut AsyncCommandContext<'_, E>,
        input: AsyncPipelineData,
    ) -> Result<AsyncPipelineData, ShellError> {
        let head = ctx.call.head;
        let file_raw: Option<String> = ctx.call.get_flag(ctx.engine_state, ctx.stack, "file")?;
        let dst_raw: String = ctx.call.req(ctx.engine_state, ctx.stack, 0)?;

        let cwd = current_cwd_async(ctx.engine_state, ctx.stack, ctx.env).await;
        let destination = resolve_vfs_path(ctx.engine_state, ctx.stack, &cwd, &dst_raw, true);

        let payload = match file_raw {
            Some(raw_file) => {
                let resolved = resolve_vfs_path(ctx.engine_state, ctx.stack, &cwd, &raw_file, true);
                ctx.env
                    .read_file(&resolved)
                    .await
                    .map_err(|e| e.into_shell_error("failed to read btrfs stream file", head))?
            }
            None => input.into_bytes_async(head).await?,
        };

        let info = ctx
            .env
            .btrfs_subvolume_receive(&destination, payload)
            .await
            .map_err(|e| e.into_shell_error("btrfs subvolume receive failed", head))?;

        Ok(AsyncPipelineData::value(
            subvolume_to_value(info, head),
            None,
        ))
    }
}

fn parse_mount_source(raw: &str, span: Span) -> Result<MountSourceSpec, ShellError> {
    match raw {
        "memory" | "tmpfs" => Ok(MountSourceSpec::Memory),
        "boot-image" | "bootfs" => Ok(MountSourceSpec::BootImage),
        "host-share" | "9p" | "virtio-fs" => Ok(MountSourceSpec::HostShare),
        other => {
            if let Some(serial) = other
                .strip_prefix("disk:")
                .or_else(|| other.strip_prefix("erofs:"))
                && !serial.is_empty()
            {
                return Ok(MountSourceSpec::Disk(serial.to_owned()));
            }
            if let Some(serial) = other.strip_prefix("btrfs:")
                && !serial.is_empty()
            {
                return Ok(MountSourceSpec::Btrfs(serial.to_owned()));
            }
            Err(generic_error(
                "invalid mount source",
                format!(
                    "expected `memory`, `boot-image`, `host-share`, `disk:<serial>`, or `btrfs:<serial>`, got `{other}`"
                ),
                span,
            ))
        }
    }
}
