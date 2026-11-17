//! One task owns transactions. A bounded queue admits requests from all CPUs;
//! each drained batch publishes once, before replying. Readers clone the last
//! published snapshot under a short lock and never hold that lock across I/O.

use alloc::string::String;
use alloc::vec::Vec;
use core::num::NonZeroUsize;

use futures::channel::oneshot;
use helios_btrfs::write::{
    Attributes, ChunkError, Compressor, InodeHandle, Name, SpaceError, WriteError,
    WriteTransaction, Writer,
};
use helios_btrfs::{BlockSink, Error, FileKind, Timestamp};
use helios_hal::fs::{
    BlockDevice, FsError, FsResult, Landed, OpenFlags, RenameMode, WritePosition,
};
use triomphe::Arc;

use super::{Image, Snapshot};
use crate::component::{ProviderReceiver, ProviderSender, provider_channel};
use crate::{BlockPages, RootEntropyHandle};

pub(super) enum Response {
    Done,
    Written(Landed),
    Opened {
        inode: InodeHandle,
        metadata: helios_btrfs::Metadata,
    },
}

pub(super) enum Operation {
    Write {
        inode: InodeHandle,
        position: WritePosition,
        bytes: bytes::Bytes,
    },
    Open {
        flags: OpenFlags,
    },
    CreateDirectory,
    Remove {
        directory: bool,
    },
    Truncate {
        size: u64,
    },
    Times {
        access: Option<u64>,
        modified: Option<u64>,
    },
    Rename {
        destination: String,
        mode: RenameMode,
    },
    Link {
        destination: String,
    },
    Symlink {
        target: String,
    },
    Sync,
}

pub(super) struct Request {
    path: String,
    when: u64,
    operation: Operation,
    reply: oneshot::Sender<FsResult<Response>>,
}

pub(super) struct Client {
    sender: ProviderSender<Request>,
}

impl Drop for Client {
    fn drop(&mut self) {
        self.sender.close();
    }
}

impl Client {
    pub(super) async fn execute(
        &self,
        path: &str,
        when: u64,
        operation: Operation,
    ) -> FsResult<Response> {
        let (reply, result) = oneshot::channel();
        self.sender
            .send(Request {
                path: String::from(path),
                when,
                operation,
                reply,
            })
            .await
            .map_err(|_| FsError::Io)?;
        result.await.map_err(|_| FsError::Io)?
    }
}

pub(super) fn channel(capacity: NonZeroUsize) -> (Client, ProviderReceiver<Request>) {
    let (sender, receiver) = provider_channel(capacity.get());
    (Client { sender }, receiver)
}

/// The kernel task owning one writable mount. Dropping the mount closes its
/// queue; the task drains already accepted work and then terminates.
pub struct BtrfsService<Device: BlockDevice<Buffer = BlockPages>> {
    pub(super) writer: Writer<Image<Device>>,
    pub(super) receiver: ProviderReceiver<Request>,
    pub(super) published: Arc<spin::Mutex<Snapshot<Device>>>,
    pub(super) entropy: RootEntropyHandle,
    pub(super) concurrency: NonZeroUsize,
    pub(super) compressor: Compressor,
}

impl<Device: BlockDevice<Buffer = BlockPages>> BtrfsService<Device> {
    pub async fn run(self) {
        serve(
            self.writer,
            self.receiver,
            self.published,
            self.entropy,
            self.concurrency,
            self.compressor,
        )
        .await;
    }
}

pub(super) async fn serve<Device: BlockDevice<Buffer = BlockPages>>(
    mut writer: Writer<Image<Device>>,
    receiver: ProviderReceiver<Request>,
    published: Arc<spin::Mutex<Snapshot<Device>>>,
    entropy: RootEntropyHandle,
    concurrency: NonZeroUsize,
    mut compressor: Compressor,
) {
    while let Some(first) = receiver.recv().await {
        let mut requests = Vec::with_capacity(concurrency.get());
        requests.push(first);
        // A continuous producer cannot postpone durability indefinitely.
        while requests.len() < concurrency.get() {
            match receiver.try_recv() {
                Ok(request) => requests.push(request),
                Err(_) => break,
            }
        }
        let mut transaction = match writer.begin().await {
            Ok(transaction) => transaction,
            Err(error) => {
                let error = fs_error(error);
                for request in requests {
                    let _ = request.reply.send(Err(error));
                }
                return;
            }
        };
        let mut replies = Vec::with_capacity(requests.len());
        let mut dirty = false;
        for request in requests {
            if request.reply.is_canceled() {
                continue;
            }
            let mutates = match &request.operation {
                Operation::Open { flags } => {
                    flags.intersects(OpenFlags::CREATE | OpenFlags::TRUNCATE)
                }
                Operation::Sync => false,
                _ => true,
            };
            let result = apply(
                &mut transaction,
                &request.path,
                request.when,
                request.operation,
                concurrency,
                &mut compressor,
            )
            .await;
            dirty |= mutates && result.is_ok();
            replies.push((request.reply, result));
        }
        if !dirty {
            drop(transaction);
            for (reply, result) in replies {
                let _ = reply.send(result);
            }
            continue;
        }
        let committed = transaction
            .commit(
                || {
                    let mut uuid = [0; 16];
                    entropy.fill(&mut uuid);
                    // RFC 9562, version 4 and the RFC variant.
                    uuid[6] = (uuid[6] & 0x0f) | 0x40;
                    uuid[8] = (uuid[8] & 0x3f) | 0x80;
                    uuid
                },
                concurrency,
            )
            .await
            .map_err(fs_error);
        if committed.is_ok() {
            match writer.snapshot() {
                Ok(snapshot) => *published.lock() = snapshot,
                Err(error) => {
                    let error = fs_error(error);
                    for (reply, _) in replies {
                        let _ = reply.send(Err(error));
                    }
                    return;
                }
            }
        }
        for (reply, result) in replies {
            let _ = reply.send(result.and_then(|value| committed.map(|()| value)));
        }
        if committed.is_err() {
            return;
        }
    }
}

async fn inode<S: BlockSink>(
    transaction: &WriteTransaction<'_, S>,
    path: &str,
) -> FsResult<InodeHandle> {
    let mut inode = transaction.root().await.map_err(fs_error)?;
    if !path.is_empty() {
        for name in path.split('/') {
            inode = transaction
                .lookup(&inode, name.as_bytes())
                .await
                .map_err(fs_error)?
                .ok_or(FsError::NoEntry)?;
        }
    }
    Ok(inode)
}

async fn parent<'a, S: BlockSink>(
    transaction: &WriteTransaction<'_, S>,
    path: &'a str,
) -> FsResult<(InodeHandle, &'a [u8])> {
    if path.is_empty() {
        return Err(FsError::Busy);
    }
    let (directory, name) = path.rsplit_once('/').unwrap_or(("", path));
    Ok((inode(transaction, directory).await?, name.as_bytes()))
}

fn timestamp(nanos: u64) -> Timestamp {
    Timestamp {
        seconds: (nanos / 1_000_000_000) as i64,
        nanoseconds: (nanos % 1_000_000_000) as u32,
    }
}

async fn apply<S: BlockSink>(
    transaction: &mut WriteTransaction<'_, S>,
    path: &str,
    now: u64,
    operation: Operation,
    concurrency: NonZeroUsize,
    compressor: &mut Compressor,
) -> FsResult<Response> {
    let when = timestamp(now);
    match operation {
        Operation::Write {
            inode,
            position,
            bytes,
        } => {
            let metadata = transaction.metadata(&inode).await.map_err(fs_error)?;
            let offset = match position {
                WritePosition::At(offset) => offset,
                WritePosition::End => metadata.size,
            };
            offset
                .checked_add(bytes.len() as u64)
                .ok_or(FsError::Overflow)?;
            let written = transaction
                .write_file_with_policy(&inode, offset, &bytes, when, concurrency, compressor)
                .await
                .map_err(fs_error)?;
            // A device with no more free sectors stores a prefix, which the
            // transaction keeps and the caller learns the length of.
            if written != bytes.len() {
                tracing::warn!(
                    written,
                    requested = bytes.len(),
                    "btrfs write ran out of space"
                );
            }
            return Ok(Response::Written(Landed {
                offset,
                len: written,
            }));
        }
        Operation::Open { flags } => {
            let file = match inode(transaction, path).await {
                Ok(file) => {
                    if flags.contains(OpenFlags::CREATE | OpenFlags::EXCLUSIVE) {
                        return Err(FsError::Exists);
                    }
                    file
                }
                Err(FsError::NoEntry) if flags.contains(OpenFlags::CREATE) => {
                    if flags.contains(OpenFlags::DIRECTORY) {
                        return Err(FsError::NotDirectory);
                    }
                    let (parent, bytes) = parent(transaction, path).await?;
                    transaction
                        .create_file(
                            Name {
                                parent: &parent,
                                bytes,
                            },
                            Attributes {
                                permissions: 0o644,
                                uid: 0,
                                gid: 0,
                            },
                            when,
                        )
                        .await
                        .map_err(fs_error)?
                }
                Err(error) => return Err(error),
            };
            let metadata = transaction.metadata(&file).await.map_err(fs_error)?;
            if flags.contains(OpenFlags::DIRECTORY) && metadata.kind != FileKind::Directory {
                return Err(FsError::NotDirectory);
            }
            if flags.contains(OpenFlags::TRUNCATE) {
                transaction
                    .truncate_file(&file, 0, when, concurrency)
                    .await
                    .map_err(fs_error)?;
            }
            let metadata = transaction.metadata(&file).await.map_err(fs_error)?;
            return Ok(Response::Opened {
                inode: file,
                metadata,
            });
        }
        Operation::CreateDirectory | Operation::Symlink { .. } => {
            let (parent, bytes) = parent(transaction, path).await?;
            let name = Name {
                parent: &parent,
                bytes,
            };
            // The VFS has no ownership/mode input yet; use its existing new-node
            // defaults, with the inode type supplied by the operation.
            let attributes = Attributes {
                permissions: 0o755,
                uid: 0,
                gid: 0,
            };
            match operation {
                Operation::Symlink { target } => {
                    transaction
                        .symlink(
                            name,
                            target.as_bytes(),
                            Attributes {
                                permissions: 0o777,
                                ..attributes
                            },
                            when,
                        )
                        .await
                }
                _ => transaction.create_directory(name, attributes, when).await,
            }
            .map_err(fs_error)?;
        }
        Operation::Rename { destination, mode } => {
            let (source, source_name) = parent(transaction, path).await?;
            let (destination, destination_name) = parent(transaction, &destination).await?;
            transaction
                .rename(
                    Name {
                        parent: &source,
                        bytes: source_name,
                    },
                    Name {
                        parent: &destination,
                        bytes: destination_name,
                    },
                    mode,
                    when,
                )
                .await
                .map_err(fs_error)?;
        }
        Operation::Link { destination } => {
            let file = inode(transaction, path).await?;
            let (parent, bytes) = parent(transaction, &destination).await?;
            transaction
                .hard_link(
                    Name {
                        parent: &parent,
                        bytes,
                    },
                    &file,
                    when,
                )
                .await
                .map_err(fs_error)?;
        }
        Operation::Remove { directory } => {
            let file = inode(transaction, path).await?;
            let kind = transaction.metadata(&file).await.map_err(fs_error)?.kind;
            if directory && kind != FileKind::Directory {
                return Err(FsError::NotDirectory);
            }
            if !directory && kind == FileKind::Directory {
                return Err(FsError::IsDirectory);
            }
            let (parent, bytes) = parent(transaction, path).await?;
            transaction
                .unlink_name(
                    Name {
                        parent: &parent,
                        bytes,
                    },
                    when,
                )
                .await
                .map_err(fs_error)?;
        }
        Operation::Truncate { size } => {
            let file = inode(transaction, path).await?;
            transaction
                .truncate_file(&file, size, when, concurrency)
                .await
                .map_err(fs_error)?;
        }
        Operation::Times { access, modified } => {
            let file = inode(transaction, path).await?;
            transaction
                .set_times(&file, access.map(timestamp), modified.map(timestamp), when)
                .await
                .map_err(fs_error)?;
        }
        Operation::Sync => {
            inode(transaction, path).await?;
        }
    }
    Ok(Response::Done)
}

pub(super) fn fs_error(error: WriteError) -> FsError {
    match error {
        WriteError::NoEntry { .. }
        | WriteError::StaleHandle { .. }
        | WriteError::Read(Error::NotFound { .. }) => FsError::NoEntry,
        WriteError::Exists { .. } => FsError::Exists,
        WriteError::NotEmpty { .. } => FsError::NotEmpty,
        WriteError::ReadOnlySubvolume { .. } => FsError::ReadOnly,
        WriteError::InodeFlags { .. } | WriteError::SetId { .. } | WriteError::DirectoryLink => {
            FsError::NotPermitted
        }
        WriteError::CrossSubvolume => FsError::CrossDevice,
        WriteError::InvalidName | WriteError::DirectoryCycle | WriteError::SymlinkTarget { .. } => {
            FsError::Invalid
        }
        WriteError::FileOverflow => FsError::Overflow,
        WriteError::NoSpace { .. }
        | WriteError::IdentifierExhausted { .. }
        | WriteError::Chunk(
            ChunkError::NoDeviceSpace { .. } | ChunkError::SystemArrayFull { .. },
        )
        | WriteError::Space(SpaceError::Exhausted { .. }) => FsError::NoSpace,
        WriteError::Read(Error::WrongKind {
            expected: FileKind::Directory,
            ..
        }) => FsError::NotDirectory,
        WriteError::Read(Error::WrongKind {
            found: FileKind::Directory,
            ..
        }) => FsError::IsDirectory,
        error => {
            tracing::warn!(%error, "btrfs transaction failed");
            FsError::Io
        }
    }
}
