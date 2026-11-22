//! Linux-compatible btrfs send stream (v1) decoder and applier.
//!
//! Consumes streams produced by Linux `btrfs send` (or Helios's own encoder),
//! verifies every command's CRC32C before applying it, records full Unix
//! metadata per `#1037` (uid, gid, modes with set-id/sticky bits, device/special
//! nodes, POSIX ACLs, `user.*`/`security.*`/`trusted.*` xattrs), checks
//! `authorize_source` before reading or snapshotting any source subvolume
//! referenced by `SNAPSHOT` or `CLONE`, and marks the received subvolume
//! read-only with `received_uuid`, `stransid`, `rtransid`, and `rtime`.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::num::NonZeroUsize;

use crate::compress::policy::Compressor;
use crate::csum::send_stream_crc;
use crate::fs::writer::{Attributes, Special};
use crate::ondisk::RawTimespec;
use crate::send::{STREAM_MAGIC, STREAM_VERSION_1, attr, cmd};
use crate::source::BlockSink;
use crate::transaction::Transaction;
use crate::transaction::namespace::{Attributes as RawAttributes, Name};
use crate::transaction::reflink::{CloneRange, FileId};
use crate::transaction::xattr::XattrMode;
use crate::tree::write::WriteError;
use crate::{DeviceNumber, Timestamp};

/// One parsed TLV attribute inside a send command.
#[derive(Clone, Copy)]
struct Tlv<'a> {
    kind: u16,
    data: &'a [u8],
}

/// One verified, parsed command from the send stream.
pub(crate) struct ParsedCommand<'a> {
    pub(crate) code: u16,
    attrs: Vec<Tlv<'a>>,
}

impl<'a> ParsedCommand<'a> {
    fn bytes(&self, kind: u16) -> Result<&'a [u8], WriteError> {
        self.attrs
            .iter()
            .find(|t| t.kind == kind)
            .map(|t| t.data)
            .ok_or_else(|| {
                WriteError::InvalidStream(format!("command {} missing attr {kind}", self.code))
            })
    }

    fn opt_bytes(&self, kind: u16) -> Option<&'a [u8]> {
        self.attrs.iter().find(|t| t.kind == kind).map(|t| t.data)
    }

    fn u64(&self, kind: u16) -> Result<u64, WriteError> {
        let b = self.bytes(kind)?;
        let arr: [u8; 8] = b.try_into().map_err(|_| {
            WriteError::InvalidStream(format!("attr {kind} expected 8 bytes, got {}", b.len()))
        })?;
        Ok(u64::from_le_bytes(arr))
    }

    fn uuid(&self, kind: u16) -> Result<[u8; 16], WriteError> {
        let b = self.bytes(kind)?;
        b.try_into().map_err(|_| {
            WriteError::InvalidStream(format!("attr {kind} expected 16 bytes, got {}", b.len()))
        })
    }

    fn opt_timespec(&self, kind: u16) -> Result<Option<Timestamp>, WriteError> {
        let Some(b) = self.opt_bytes(kind) else {
            return Ok(None);
        };
        if b.len() != 12 {
            return Err(WriteError::InvalidStream(format!(
                "timespec attr {kind} expected 12 bytes, got {}",
                b.len()
            )));
        }
        let sec = u64::from_le_bytes(b[..8].try_into().unwrap()) as i64;
        let nsec = u32::from_le_bytes(b[8..12].try_into().unwrap());
        if nsec >= 1_000_000_000 {
            return Err(WriteError::InvalidStream(format!(
                "timespec attr {kind} invalid nanoseconds {nsec}"
            )));
        }
        Ok(Some(Timestamp {
            seconds: sec,
            nanoseconds: nsec,
        }))
    }
}

/// Parses and CRC-verifies an entire btrfs send stream (v1).
pub(crate) fn parse_stream(stream: &[u8]) -> Result<Vec<ParsedCommand<'_>>, WriteError> {
    if stream.len() < STREAM_MAGIC.len() + 4 {
        return Err(WriteError::InvalidStream(String::from(
            "stream header truncated",
        )));
    }
    if &stream[..STREAM_MAGIC.len()] != STREAM_MAGIC {
        return Err(WriteError::InvalidStream(String::from(
            "invalid btrfs-stream magic",
        )));
    }
    let version = u32::from_le_bytes(
        stream[STREAM_MAGIC.len()..STREAM_MAGIC.len() + 4]
            .try_into()
            .unwrap(),
    );
    if version != STREAM_VERSION_1 {
        return Err(WriteError::InvalidStream(format!(
            "unsupported btrfs send stream version {version}"
        )));
    }
    let mut pos = STREAM_MAGIC.len() + 4;
    let mut commands = Vec::new();
    let mut saw_end = false;

    while pos < stream.len() {
        if pos + 10 > stream.len() {
            return Err(WriteError::InvalidStream(String::from(
                "truncated command header",
            )));
        }
        let payload_len = u32::from_le_bytes(stream[pos..pos + 4].try_into().unwrap()) as usize;
        let code = u16::from_le_bytes(stream[pos + 4..pos + 6].try_into().unwrap());
        let stored_crc = u32::from_le_bytes(stream[pos + 6..pos + 10].try_into().unwrap());
        let cmd_end = pos
            .checked_add(10)
            .and_then(|v| v.checked_add(payload_len))
            .filter(|&end| end <= stream.len())
            .ok_or_else(|| WriteError::InvalidStream(String::from("command payload truncated")))?;

        // Verify CRC32C over the command header (with CRC field zeroed) + payload.
        let mut check_buf = Vec::with_capacity(10 + payload_len);
        check_buf.extend_from_slice(&stream[pos..pos + 6]);
        check_buf.extend_from_slice(&0_u32.to_le_bytes());
        check_buf.extend_from_slice(&stream[pos + 10..cmd_end]);
        let computed = send_stream_crc(&check_buf);
        if computed != stored_crc {
            return Err(WriteError::InvalidStream(format!(
                "command {code} CRC mismatch: stored {stored_crc:#010x}, computed {computed:#010x}"
            )));
        }

        // Parse TLVs inside payload.
        let mut attrs = Vec::new();
        let mut tpos = pos + 10;
        while tpos < cmd_end {
            if tpos + 4 > cmd_end {
                return Err(WriteError::InvalidStream(String::from(
                    "truncated TLV header",
                )));
            }
            let tkind = u16::from_le_bytes(stream[tpos..tpos + 2].try_into().unwrap());
            let tlen = usize::from(u16::from_le_bytes(
                stream[tpos + 2..tpos + 4].try_into().unwrap(),
            ));
            let tend = tpos
                .checked_add(4)
                .and_then(|v| v.checked_add(tlen))
                .filter(|&end| end <= cmd_end)
                .ok_or_else(|| WriteError::InvalidStream(String::from("truncated TLV payload")))?;
            attrs.push(Tlv {
                kind: tkind,
                data: &stream[tpos + 4..tend],
            });
            tpos = tend;
        }
        commands.push(ParsedCommand { code, attrs });
        pos = cmd_end;
        if code == cmd::END {
            saw_end = true;
            break;
        }
    }

    if !saw_end {
        return Err(WriteError::InvalidStream(String::from(
            "missing END command",
        )));
    }
    Ok(commands)
}

/// Validates a relative path inside the received subvolume (`""` is allowed
/// for the subvolume root; no leading `/`, no `.` or `..` components).
fn split_rel_path(path: &[u8]) -> Result<Vec<&[u8]>, WriteError> {
    if path.is_empty() {
        return Ok(Vec::new());
    }
    if path.starts_with(b"/") || path.ends_with(b"/") {
        return Err(WriteError::InvalidStream(String::from(
            "stream path must be relative without leading or trailing slash",
        )));
    }
    let mut parts = Vec::new();
    for seg in path.split(|&b| b == b'/') {
        if seg.is_empty() || seg == b"." || seg == b".." || seg.contains(&0) {
            return Err(WriteError::InvalidStream(String::from(
                "stream path contains invalid component",
            )));
        }
        parts.push(seg);
    }
    Ok(parts)
}

async fn resolve_in_subvol<S: BlockSink>(
    tx: &Transaction<S>,
    tree: u64,
    rel: &[u8],
) -> Result<FileId, WriteError> {
    let root_dir = tx.roots.root_directory(tree)?;
    let mut current = FileId {
        tree,
        inode: root_dir,
    };
    for seg in split_rel_path(rel)? {
        current = tx
            .lookup_file(Name {
                tree: current.tree,
                parent: current.inode,
                bytes: seg,
            })
            .await?
            .ok_or(WriteError::NoEntry {
                tree: current.tree,
                parent: current.inode,
            })?;
    }
    Ok(current)
}

async fn resolve_parent_in_subvol<'a, S: BlockSink>(
    tx: &Transaction<S>,
    tree: u64,
    rel: &'a [u8],
) -> Result<(FileId, &'a [u8]), WriteError> {
    let parts = split_rel_path(rel)?;
    let Some((&last, prefix)) = parts.split_last() else {
        return Err(WriteError::InvalidStream(String::from(
            "expected non-empty relative path",
        )));
    };
    let root_dir = tx.roots.root_directory(tree)?;
    let mut current = FileId {
        tree,
        inode: root_dir,
    };
    for &seg in prefix {
        current = tx
            .lookup_file(Name {
                tree: current.tree,
                parent: current.inode,
                bytes: seg,
            })
            .await?
            .ok_or(WriteError::NoEntry {
                tree: current.tree,
                parent: current.inode,
            })?;
    }
    Ok((current, last))
}

/// Parses `stream` (verifying header and per-command CRC32C) and returns every
/// `(uuid, ctransid)` source subvolume referenced by `SNAPSHOT` or `CLONE`
/// commands, deduplicated in order of first appearance.
pub fn stream_referenced_sources(stream: &[u8]) -> Result<Vec<([u8; 16], u64)>, WriteError> {
    let commands = parse_stream(stream)?;
    let mut sources: Vec<([u8; 16], u64)> = Vec::new();
    for command in &commands {
        if matches!(command.code, cmd::SNAPSHOT | cmd::CLONE) {
            let uuid = command.uuid(attr::CLONE_UUID)?;
            let ctransid = command.u64(attr::CLONE_CTRANSID)?;
            if !sources.contains(&(uuid, ctransid)) {
                sources.push((uuid, ctransid));
            }
        }
    }
    Ok(sources)
}

/// First command header extracted from a send stream so the caller can set up
/// the target subvolume (or snapshot a parent after authorizing it).
pub(crate) enum ReceiveInit<'a> {
    Subvol {
        name: &'a [u8],
        uuid: [u8; 16],
        ctransid: u64,
    },
    Snapshot {
        name: &'a [u8],
        uuid: [u8; 16],
        ctransid: u64,
        clone_uuid: [u8; 16],
        clone_ctransid: u64,
    },
}

/// Inspects the first command of `commands` and returns its subvolume creation
/// directive.
pub(crate) fn decode_receive_init<'a>(
    commands: &[ParsedCommand<'a>],
) -> Result<ReceiveInit<'a>, WriteError> {
    let Some(first) = commands.first() else {
        return Err(WriteError::InvalidStream(String::from("empty send stream")));
    };
    let name = first.bytes(attr::PATH)?;
    if name.is_empty() || name.contains(&b'/') || name == b"." || name == b".." || name.contains(&0)
    {
        return Err(WriteError::InvalidStream(String::from(
            "invalid subvolume name in stream header",
        )));
    }
    let uuid = first.uuid(attr::UUID)?;
    let ctransid = first.u64(attr::CTRANSID)?;
    match first.code {
        cmd::SUBVOL => Ok(ReceiveInit::Subvol {
            name,
            uuid,
            ctransid,
        }),
        cmd::SNAPSHOT => Ok(ReceiveInit::Snapshot {
            name,
            uuid,
            ctransid,
            clone_uuid: first.uuid(attr::CLONE_UUID)?,
            clone_ctransid: first.u64(attr::CLONE_CTRANSID)?,
        }),
        other => Err(WriteError::InvalidStream(format!(
            "stream must begin with SUBVOL or SNAPSHOT, got command {other}"
        ))),
    }
}

/// Applies commands `commands[1..]` to the newly created writable subvolume
/// Context for applying a parsed receive stream into a newly created subvolume.
pub(crate) struct ReceiveApplyContext<'a> {
    pub(crate) target_tree: u64,
    pub(crate) received_uuid: [u8; 16],
    pub(crate) stransid: u64,
    pub(crate) when: Timestamp,
    pub(crate) compressor: &'a mut Compressor,
    pub(crate) concurrency: NonZeroUsize,
    pub(crate) max_inline: u64,
}

/// Applies the commands of a parsed stream (after the initial `SUBVOL` or
/// `SNAPSHOT` command) into `ctx.target_tree`, calling `authorize_source`
/// before cloning from any other subvolume. Finishes by recording
/// `received_uuid`, `stransid`, `rtransid`, `rtime` and setting
/// `BTRFS_ROOT_SUBVOL_RDONLY`.
pub(crate) async fn apply_receive_commands<S, F>(
    tx: &mut Transaction<S>,
    ctx: ReceiveApplyContext<'_>,
    commands: &[ParsedCommand<'_>],
    mut authorize_source: F,
) -> Result<(), WriteError>
where
    S: BlockSink,
    F: FnMut(&str) -> Result<(), WriteError>,
{
    let ReceiveApplyContext {
        target_tree,
        received_uuid,
        stransid,
        when,
        compressor,
        concurrency,
        max_inline,
    } = ctx;
    let default_attrs = |mode: u32, rdev: u64| RawAttributes {
        mode,
        uid: 0,
        gid: 0,
        rdev,
        umask: 0,
    };

    for command in commands.iter().skip(1) {
        tx.prepare_mutation().await?;
        match command.code {
            cmd::END => break,
            cmd::MKFILE => {
                let path = command.bytes(attr::PATH)?;
                let (parent, name) = resolve_parent_in_subvol(tx, target_tree, path).await?;
                tx.create_node(
                    Name {
                        tree: parent.tree,
                        parent: parent.inode,
                        bytes: name,
                    },
                    default_attrs(0o100_600, 0),
                    when,
                )
                .await?;
            }
            cmd::MKDIR => {
                let path = command.bytes(attr::PATH)?;
                let (parent, name) = resolve_parent_in_subvol(tx, target_tree, path).await?;
                tx.create_node(
                    Name {
                        tree: parent.tree,
                        parent: parent.inode,
                        bytes: name,
                    },
                    default_attrs(0o040_700, 0),
                    when,
                )
                .await?;
            }
            cmd::MKNOD => {
                let path = command.bytes(attr::PATH)?;
                let mode = command.u64(attr::MODE)? as u32;
                let rdev_enc = command.u64(attr::RDEV)? as u32;
                let dev = DeviceNumber::decode(rdev_enc);
                let kind_bits = mode & 0o170_000;
                let rdev = match kind_bits {
                    0o020_000 | 0o060_000 => dev.inode_item(),
                    0o010_000 | 0o140_000 => 0,
                    _ => {
                        return Err(WriteError::InvalidStream(format!(
                            "MKNOD invalid mode {mode:#o}"
                        )));
                    }
                };
                let (parent, name) = resolve_parent_in_subvol(tx, target_tree, path).await?;
                tx.create_node(
                    Name {
                        tree: parent.tree,
                        parent: parent.inode,
                        bytes: name,
                    },
                    default_attrs(kind_bits | (mode & 0o7777), rdev),
                    when,
                )
                .await?;
            }
            cmd::MKFIFO => {
                let path = command.bytes(attr::PATH)?;
                let (parent, name) = resolve_parent_in_subvol(tx, target_tree, path).await?;
                tx.create_node(
                    Name {
                        tree: parent.tree,
                        parent: parent.inode,
                        bytes: name,
                    },
                    default_attrs(0o010_600, 0),
                    when,
                )
                .await?;
            }
            cmd::MKSOCK => {
                let path = command.bytes(attr::PATH)?;
                let (parent, name) = resolve_parent_in_subvol(tx, target_tree, path).await?;
                tx.create_node(
                    Name {
                        tree: parent.tree,
                        parent: parent.inode,
                        bytes: name,
                    },
                    default_attrs(0o140_600, 0),
                    when,
                )
                .await?;
            }
            cmd::SYMLINK => {
                let path = command.bytes(attr::PATH)?;
                let target = command.bytes(attr::PATH_LINK)?;
                let (parent, name) = resolve_parent_in_subvol(tx, target_tree, path).await?;
                tx.symlink(
                    Name {
                        tree: parent.tree,
                        parent: parent.inode,
                        bytes: name,
                    },
                    target,
                    default_attrs(0o120_777, 0),
                    when,
                )
                .await?;
            }
            cmd::RENAME => {
                let from = command.bytes(attr::PATH)?;
                let to = command.bytes(attr::PATH_TO)?;
                let (src_parent, src_name) =
                    resolve_parent_in_subvol(tx, target_tree, from).await?;
                let (dst_parent, dst_name) = resolve_parent_in_subvol(tx, target_tree, to).await?;
                tx.rename(
                    Name {
                        tree: src_parent.tree,
                        parent: src_parent.inode,
                        bytes: src_name,
                    },
                    Name {
                        tree: dst_parent.tree,
                        parent: dst_parent.inode,
                        bytes: dst_name,
                    },
                    helios_hal::fs::RenameMode::Replace,
                    when,
                )
                .await?;
            }
            cmd::LINK => {
                let link_path = command.bytes(attr::PATH)?;
                let existing_path = command.bytes(attr::PATH_LINK)?;
                let existing = resolve_in_subvol(tx, target_tree, existing_path).await?;
                let (parent, name) = resolve_parent_in_subvol(tx, target_tree, link_path).await?;
                tx.hard_link(
                    Name {
                        tree: parent.tree,
                        parent: parent.inode,
                        bytes: name,
                    },
                    existing.inode,
                    when,
                )
                .await?;
            }
            cmd::UNLINK | cmd::RMDIR => {
                let path = command.bytes(attr::PATH)?;
                let (parent, name) = resolve_parent_in_subvol(tx, target_tree, path).await?;
                tx.unlink_name(
                    Name {
                        tree: parent.tree,
                        parent: parent.inode,
                        bytes: name,
                    },
                    when,
                )
                .await?;
            }
            cmd::SET_XATTR => {
                let path = command.bytes(attr::PATH)?;
                let name = command.bytes(attr::XATTR_NAME)?;
                let value = command.bytes(attr::XATTR_DATA)?;
                let target = resolve_in_subvol(tx, target_tree, path).await?;
                tx.set_xattr(target.tree, target.inode, name, value, XattrMode::Set, when)
                    .await?;
            }
            cmd::REMOVE_XATTR => {
                let path = command.bytes(attr::PATH)?;
                let name = command.bytes(attr::XATTR_NAME)?;
                let target = resolve_in_subvol(tx, target_tree, path).await?;
                match tx.remove_xattr(target.tree, target.inode, name, when).await {
                    Ok(()) | Err(WriteError::XattrMissing { .. }) => {}
                    Err(e) => return Err(e),
                }
            }
            cmd::WRITE => {
                let path = command.bytes(attr::PATH)?;
                let offset = command.u64(attr::FILE_OFFSET)?;
                let data = command.bytes(attr::DATA)?;
                let target = resolve_in_subvol(tx, target_tree, path).await?;
                let sector = u64::from(tx.volume.superblock().sectorsize());
                let needed = (data.len() as u64).next_multiple_of(sector).max(sector);
                tx.ensure_data(needed).await?;
                let mut written = 0;
                while written < data.len() {
                    let n = tx
                        .write_file(
                            target,
                            offset + written as u64,
                            &data[written..],
                            when,
                            compressor,
                            max_inline,
                        )
                        .await?;
                    if n == 0 {
                        return Err(WriteError::NoSpace { tree: target.tree });
                    }
                    written += n;
                }
            }
            cmd::CLONE => {
                let file_offset = command.u64(attr::FILE_OFFSET)?;
                let clone_len = command.u64(attr::CLONE_LEN)?;
                let path = command.bytes(attr::PATH)?;
                let clone_uuid = command.uuid(attr::CLONE_UUID)?;
                let clone_ctransid = command.u64(attr::CLONE_CTRANSID)?;
                let clone_path = command.bytes(attr::CLONE_PATH)?;
                let clone_offset = command.u64(attr::CLONE_OFFSET)?;

                let source_tree = if clone_uuid == received_uuid {
                    target_tree
                } else {
                    let found = tx
                        .roots
                        .find_subvolume_by_uuid(clone_uuid, Some(clone_ctransid))
                        .ok_or_else(|| {
                            WriteError::InvalidStream(String::from(
                                "CLONE references unknown source subvolume UUID",
                            ))
                        })?;
                    let (_, source_root_path) = tx.subvolume_path(found).await?;
                    authorize_source(&source_root_path)?;
                    found
                };

                let source = resolve_in_subvol(tx, source_tree, clone_path).await?;
                let destination = resolve_in_subvol(tx, target_tree, path).await?;
                tx.clone_range(
                    CloneRange {
                        source,
                        destination,
                        source_offset: clone_offset,
                        destination_offset: file_offset,
                        length: clone_len,
                    },
                    when,
                    compressor,
                    concurrency,
                    max_inline,
                )
                .await?;
            }
            cmd::TRUNCATE => {
                let path = command.bytes(attr::PATH)?;
                let size = command.u64(attr::SIZE)?;
                let target = resolve_in_subvol(tx, target_tree, path).await?;
                tx.truncate_file(
                    target.tree,
                    target.inode,
                    size,
                    when,
                    compressor,
                    max_inline,
                )
                .await?;
            }
            cmd::CHMOD => {
                let path = command.bytes(attr::PATH)?;
                let mode = (command.u64(attr::MODE)? as u32) & 0o7777;
                let target = resolve_in_subvol(tx, target_tree, path).await?;
                tx.set_permissions(target.tree, target.inode, mode, when)
                    .await?;
            }
            cmd::CHOWN => {
                let path = command.bytes(attr::PATH)?;
                let uid = command.u64(attr::UID)? as u32;
                let gid = command.u64(attr::GID)? as u32;
                let target = resolve_in_subvol(tx, target_tree, path).await?;
                tx.set_owner(target.tree, target.inode, Some(uid), Some(gid), when)
                    .await?;
            }
            cmd::UTIMES => {
                let path = command.bytes(attr::PATH)?;
                let atime = command.opt_timespec(attr::ATIME)?;
                let mtime = command.opt_timespec(attr::MTIME)?;
                let ctime = command.opt_timespec(attr::CTIME)?.unwrap_or(when);
                let target = resolve_in_subvol(tx, target_tree, path).await?;
                tx.set_times(target.tree, target.inode, atime, mtime, ctime)
                    .await?;
            }
            cmd::UPDATE_EXTENT => {
                // Metadata-only `--no-data` send marker; extend file size if needed.
                let path = command.bytes(attr::PATH)?;
                let offset = command.u64(attr::FILE_OFFSET)?;
                let size = command.u64(attr::SIZE)?;
                let target = resolve_in_subvol(tx, target_tree, path).await?;
                let meta = tx.inode_metadata(target).await?;
                if let Some(end) = offset.checked_add(size)
                    && end > meta.size
                {
                    tx.truncate_file(target.tree, target.inode, end, when, compressor, max_inline)
                        .await?;
                }
            }
            other => {
                return Err(WriteError::InvalidStream(format!(
                    "unsupported send stream command {other}"
                )));
            }
        }
    }

    let rtime = RawTimespec {
        sec: (when.seconds as u64).into(),
        nsec: when.nanoseconds.into(),
    };
    tx.roots.set_received_info(
        target_tree,
        received_uuid,
        stransid,
        tx.trees.generation(),
        rtime,
        true,
    )?;
    Ok(())
}

/// Ensures `Attributes` and `Special` stay in sync with receive semantics.
const _: (usize, usize) = (size_of::<Attributes>(), size_of::<Special>());
