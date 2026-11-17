//! Extended attributes: `XATTR_ITEM`s keyed by the CRC32C of the attribute
//! name, each holding every attribute whose name hashes to that key as
//! `btrfs_dir_item` records (name, then value), the layout `fs/btrfs/xattr.c`
//! and `fs/btrfs/dir-item.c` (`btrfs_insert_xattr_item`) maintain.
//!
//! Limits and errors follow Linux's VFS entry points (`fs/xattr.c`:
//! `setxattr_copy`, `xattr_permission`, `xattr_resolve_name`) and
//! `btrfs_setxattr` / `btrfs_getxattr` / `btrfs_listxattr`:
//!
//! - a name of zero or more than `XATTR_NAME_MAX` bytes is `ERANGE`, a
//!   handler prefix with nothing after it `EINVAL`;
//! - a value longer than `XATTR_SIZE_MAX` is `E2BIG`;
//! - name plus value beyond `BTRFS_MAX_XATTR_SIZE` (the leaf's item capacity
//!   less one `btrfs_dir_item`), or a hash-sharing item that outgrows one
//!   leaf, is `ENOSPC`;
//! - `user.*` on anything but a regular file or directory is `EPERM` to
//!   write and `ENODATA` to read;
//! - removal is a replace with no value: `ENODATA` when absent.
//!
//! Only `user.*` is writable. Whatever namespace is on disk reads back.

use alloc::vec::Vec;
use core::ops::Range;
use zerocopy::{FromZeros, IntoBytes};

use super::Transaction;
use super::namespace::{check_flags, time};
use crate::csum::name_hash;
use crate::items::{INODE_APPEND, INODE_IMMUTABLE, RecordKind, dir_records};
use crate::ondisk::{NAME_MAX, RawDirItem, RawHeader, RawItem, RawKey, item_type};
use crate::source::BlockSink;
use crate::tree::write::WriteError;
use crate::{Error, FileKind, Key, Timestamp};

/// `XATTR_SIZE_MAX` in `linux/limits.h`: the longest value the VFS passes on.
const VALUE_MAX: usize = 65536;

/// `BTRFS_XATTR_ENTRY_TYPE`, the dir-item type of an xattr record.
const ENTRY_TYPE_XATTR: u8 = 8;

/// The name `cap_inode_killpriv` (security/commoncap.c) removes.
const CAPABILITY: &[u8] = b"security.capability";

const USER: &[u8] = b"user.";
/// Handler prefixes of `btrfs_xattr_handlers` (fs/btrfs/xattr.c).
const PREFIXES: [&[u8]; 4] = [USER, b"security.", b"trusted.", b"btrfs."];
const POSIX_ACLS: [&[u8]; 2] = [b"system.posix_acl_access", b"system.posix_acl_default"];

/// How a set treats an attribute that exists or does not: the `flags` of
/// `setxattr(2)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum XattrMode {
    /// Create the attribute or replace its value.
    Set,
    /// `XATTR_CREATE`: fail if the attribute exists.
    Create,
    /// `XATTR_REPLACE`: fail if the attribute does not exist.
    Replace,
}

/// The handler a written name resolves to, `xattr_resolve_name` in
/// `fs/xattr.c`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Namespace {
    User,
    /// `security.*`, `trusted.*` and the POSIX ACL names: handlers Linux has
    /// and this writer refuses (lexoliu/helios#1037).
    Refused,
    /// No handler: `EOPNOTSUPP`.
    Unsupported,
}

fn check_name(name: &[u8]) -> Result<(), WriteError> {
    if name.is_empty() || name.len() > NAME_MAX {
        return Err(WriteError::XattrNameLength { length: name.len() });
    }
    Ok(())
}

fn resolve(name: &[u8]) -> Result<Namespace, WriteError> {
    check_name(name)?;
    if PREFIXES.contains(&name) {
        return Err(WriteError::XattrName);
    }
    Ok(if name.starts_with(USER) {
        Namespace::User
    } else if name.starts_with(b"security.")
        || name.starts_with(b"trusted.")
        || POSIX_ACLS.contains(&name)
    {
        Namespace::Refused
    } else {
        Namespace::Unsupported
    })
}

/// `user.*` exists only on regular files and directories
/// (`xattr_permission`).
fn user_applies(kind: FileKind) -> bool {
    matches!(kind, FileKind::Regular | FileKind::Directory)
}

/// Where one record sits in an xattr item.
struct Located {
    /// The whole record, header included.
    record: Range<usize>,
    /// The value inside it.
    value: Range<usize>,
}

fn locate(tree: u64, key: Key, item: &[u8], name: &[u8]) -> Result<Option<Located>, WriteError> {
    let header = size_of::<RawDirItem>();
    let mut position = 0;
    for record in dir_records(item, RecordKind::Xattr) {
        let record = record.map_err(|defect| Error::Item { tree, key, defect })?;
        let end = position + header + record.name.len() + record.data.len();
        if record.name == name {
            return Ok(Some(Located {
                record: position..end,
                value: end - record.data.len()..end,
            }));
        }
        position = end;
    }
    Ok(None)
}

impl<S: BlockSink> Transaction<S> {
    /// `BTRFS_MAX_ITEM_SIZE`: what one item may hold in a leaf.
    fn max_item(&self) -> usize {
        self.volume.superblock().nodesize() as usize - size_of::<RawHeader>() - size_of::<RawItem>()
    }

    async fn xattr_item(
        &self,
        tree: u64,
        inode: u64,
        name: &[u8],
    ) -> Result<(Key, Option<Vec<u8>>), WriteError> {
        let key = Key::new(inode, item_type::XATTR_ITEM, name_hash(name));
        let root = self.roots.get(tree)?;
        Ok((key, self.trees.get(&self.volume, root, key).await?))
    }

    async fn put_xattr_item(
        &mut self,
        tree: u64,
        key: Key,
        item: Option<&[u8]>,
    ) -> Result<(), WriteError> {
        let root = self.roots.get(tree)?;
        let root = self
            .trees
            .apply(&self.volume, root, key, item, &mut self.space)
            .await?;
        self.roots.set(root)
    }

    /// `getxattr(2)`: the value's length, copied to `buffer` when that is not
    /// empty. A nonempty buffer shorter than the value is `ERANGE`.
    pub(crate) async fn xattr(
        &self,
        tree: u64,
        inode: u64,
        name: &[u8],
        buffer: &mut [u8],
    ) -> Result<usize, WriteError> {
        check_name(name)?;
        let missing = WriteError::XattrMissing { tree, inode };
        let (_, metadata) = self.inode_item(tree, inode).await?;
        if name.starts_with(USER) && !user_applies(metadata.kind) {
            return Err(missing);
        }
        let (key, item) = self.xattr_item(tree, inode, name).await?;
        let Some(item) = item else {
            return Err(missing);
        };
        let Some(found) = locate(tree, key, &item, name)? else {
            return Err(missing);
        };
        let value = &item[found.value];
        if !buffer.is_empty() {
            if value.len() > buffer.len() {
                return Err(WriteError::XattrBuffer {
                    needed: value.len(),
                    provided: buffer.len(),
                });
            }
            buffer[..value.len()].copy_from_slice(value);
        }
        Ok(value.len())
    }

    /// `listxattr(2)`: the name of every attribute on disk, each followed by
    /// a NUL, in key order. Returns their total length, written to `buffer`
    /// when it is not empty; a nonempty buffer that is too short is `ERANGE`.
    pub(crate) async fn list_xattrs(
        &self,
        tree: u64,
        inode: u64,
        buffer: &mut [u8],
    ) -> Result<usize, WriteError> {
        self.inode_item(tree, inode).await?;
        let root = self.roots.get(tree)?;
        let mut names = Vec::new();
        let mut next = Key::new(inode, item_type::XATTR_ITEM, 0);
        while let Some((key, item)) = self.trees.ceiling(&self.volume, root, next).await? {
            if !key.is(inode, item_type::XATTR_ITEM) {
                break;
            }
            for record in dir_records(&item, RecordKind::Xattr) {
                let record = record.map_err(|defect| Error::Item { tree, key, defect })?;
                names.extend_from_slice(record.name);
                names.push(0);
            }
            let Some(offset) = key.offset.checked_add(1) else {
                break;
            };
            next = Key::new(inode, item_type::XATTR_ITEM, offset);
        }
        if !buffer.is_empty() {
            if names.len() > buffer.len() {
                return Err(WriteError::XattrBuffer {
                    needed: names.len(),
                    provided: buffer.len(),
                });
            }
            buffer[..names.len()].copy_from_slice(&names);
        }
        Ok(names.len())
    }

    /// `setxattr(2)` of a `user.*` attribute, `btrfs_setxattr`: `mode` says
    /// whether it may create or replace; the inode's ctime, transid and
    /// sequence advance.
    pub(crate) async fn set_xattr(
        &mut self,
        tree: u64,
        inode: u64,
        name: &[u8],
        value: &[u8],
        mode: XattrMode,
        when: Timestamp,
    ) -> Result<(), WriteError> {
        let namespace = resolve(name)?;
        if value.len() > VALUE_MAX {
            return Err(WriteError::XattrValueTooBig {
                length: value.len(),
                maximum: VALUE_MAX,
            });
        }
        self.check_xattr_write(tree, inode, namespace).await?;
        let maximum = self.max_item() - size_of::<RawDirItem>();
        if name.len() + value.len() > maximum {
            return Err(WriteError::XattrNoSpace {
                bytes: name.len() + value.len(),
                maximum,
            });
        }
        let (key, item) = self.xattr_item(tree, inode, name).await?;
        let mut item = item.unwrap_or_default();
        let existing = locate(tree, key, &item, name)?;
        match (mode, &existing) {
            (XattrMode::Create, Some(_)) => return Err(WriteError::XattrExists { tree, inode }),
            (XattrMode::Replace, None) => return Err(WriteError::XattrMissing { tree, inode }),
            _ => {}
        }
        let record = RawDirItem {
            location: RawKey::new_zeroed(),
            transid: self.trees.generation().into(),
            data_len: (value.len() as u16).into(),
            name_len: (name.len() as u16).into(),
            entry_type: ENTRY_TYPE_XATTR,
        };
        let mut bytes = Vec::from(record.as_bytes());
        bytes.extend_from_slice(name);
        bytes.extend_from_slice(value);
        match existing {
            Some(found) => {
                item.splice(found.record, bytes);
            }
            None => item.extend_from_slice(&bytes),
        }
        if item.len() > self.max_item() {
            return Err(WriteError::XattrNoSpace {
                bytes: item.len(),
                maximum: self.max_item(),
            });
        }
        self.put_xattr_item(tree, key, Some(&item)).await?;
        self.touch(tree, inode, when).await
    }

    /// `removexattr(2)` of a `user.*` attribute: `ENODATA` when absent.
    pub(crate) async fn remove_xattr(
        &mut self,
        tree: u64,
        inode: u64,
        name: &[u8],
        when: Timestamp,
    ) -> Result<(), WriteError> {
        let namespace = resolve(name)?;
        self.check_xattr_write(tree, inode, namespace).await?;
        if !self.drop_xattr(tree, inode, name).await? {
            return Err(WriteError::XattrMissing { tree, inode });
        }
        self.touch(tree, inode, when).await
    }

    /// `ATTR_KILL_PRIV` on an owner change (`notify_change`, then
    /// `cap_inode_killpriv` in security/commoncap.c, which removes
    /// `security.capability` and ignores its absence): drops the file
    /// capability of a non-directory. Only the item changes; the owner change
    /// writes the inode, ctime included.
    pub(crate) async fn kill_privileges(
        &mut self,
        tree: u64,
        inode: u64,
    ) -> Result<(), WriteError> {
        let (_, metadata) = self.inode_item(tree, inode).await?;
        if metadata.kind != FileKind::Directory {
            self.drop_xattr(tree, inode, CAPABILITY).await?;
        }
        Ok(())
    }

    /// The checks every write makes before touching the item: immutable and
    /// append-only inodes (`xattr_permission`), then the handler.
    async fn check_xattr_write(
        &self,
        tree: u64,
        inode: u64,
        namespace: Namespace,
    ) -> Result<(), WriteError> {
        let (_, metadata) = self.inode_item(tree, inode).await?;
        check_flags(tree, inode, metadata.flags, INODE_IMMUTABLE | INODE_APPEND)?;
        match namespace {
            Namespace::User if user_applies(metadata.kind) => Ok(()),
            Namespace::User | Namespace::Refused => {
                Err(WriteError::XattrNotPermitted { tree, inode })
            }
            Namespace::Unsupported => Err(WriteError::XattrNamespace),
        }
    }

    /// Removes the record of `name`, and its item when it was the last one.
    async fn drop_xattr(&mut self, tree: u64, inode: u64, name: &[u8]) -> Result<bool, WriteError> {
        let (key, item) = self.xattr_item(tree, inode, name).await?;
        let Some(mut item) = item else {
            return Ok(false);
        };
        let Some(found) = locate(tree, key, &item, name)? else {
            return Ok(false);
        };
        item.drain(found.record);
        self.put_xattr_item(tree, key, (!item.is_empty()).then_some(item.as_slice()))
            .await?;
        Ok(true)
    }

    /// An inode change: ctime, transid and sequence, as `btrfs_update_inode`
    /// after `inode_set_ctime_current` and `inode_inc_iversion`.
    async fn touch(&mut self, tree: u64, inode: u64, when: Timestamp) -> Result<(), WriteError> {
        let changed = time(tree, inode, when)?;
        let (mut raw, _) = self.inode_item(tree, inode).await?;
        raw.ctime = changed;
        raw.transid.set(self.trees.generation());
        raw.sequence.set(raw.sequence.get().wrapping_add(1));
        self.put_inode(tree, inode, raw).await
    }
}
