//! Changing an inode's permission bits and its owner, stored as Linux's
//! btrfs stores them. The set-id and sticky bits are kept on every kind of
//! inode: what they mean is decided by the mount a caller reaches the
//! filesystem through, never by the storage (lexoliu/helios#1037).

use super::Transaction;
use super::namespace::{check_flags, time};
use crate::items::{INODE_APPEND, INODE_IMMUTABLE};
use crate::source::BlockSink;
use crate::tree::write::WriteError;
use crate::{FileKind, Timestamp};

/// The file type bits of an inode's mode.
pub(crate) const S_IFMT: u32 = 0o170_000;
pub(crate) const S_IFDIR: u32 = 0o040_000;
pub(crate) const S_IFLNK: u32 = 0o120_000;
/// Every bit `chmod` sets: permissions, sticky and the two set-id bits.
const S_IALLUGO: u32 = 0o7777;
const S_ISUID: u32 = 0o4000;
pub(crate) const S_ISGID: u32 = 0o2000;

impl<S: BlockSink> Transaction<S> {
    /// Replaces the permission bits, keeping the file type, as `chmod`
    /// (`chmod_common` in `fs/open.c` stores `(mode & S_IALLUGO) |
    /// (inode->i_mode & ~S_IALLUGO)`), then sets an access ACL's base
    /// entries to them as `btrfs_setattr` does with `posix_acl_chmod`. The
    /// set-id bits are stored on a non-directory as on a directory, as
    /// `btrfs_setattr` stores whatever `notify_change` hands it.
    pub(crate) async fn set_permissions(
        &mut self,
        tree: u64,
        inode: u64,
        permissions: u32,
        changed: Timestamp,
    ) -> Result<(), WriteError> {
        if permissions & !S_IALLUGO != 0 {
            return Err(WriteError::InvalidPermissions { permissions });
        }
        let (mut raw, metadata) = self.inode_item(tree, inode).await?;
        check_flags(tree, inode, metadata.flags, INODE_IMMUTABLE | INODE_APPEND)?;
        let mode = (raw.mode.get() & !S_IALLUGO) | permissions;
        let changed_at = changed;
        let changed = time(tree, inode, changed)?;
        raw.mode.set(mode);
        raw.ctime = changed;
        raw.transid.set(self.trees.generation());
        raw.sequence.set(raw.sequence.get().wrapping_add(1));
        self.put_inode(tree, inode, raw).await?;
        // `btrfs_setattr` carries the mode into the access ACL.
        self.chmod_acl(tree, inode, mode, changed_at).await
    }

    /// Sets the owner and/or the group, each left alone when `None` as
    /// `fchownat` leaves an id of -1.
    ///
    /// On a non-directory the set-id bits go, as `chown_common` in
    /// `fs/open.c` of torvalds/linux requests with
    /// `ATTR_KILL_SUID | setattr_should_drop_sgid()`, which `notify_change`
    /// in `fs/attr.c` turns into a mode with `S_ISUID` and `S_ISGID` removed.
    /// Linux drops `S_ISGID` unconditionally when `S_IXGRP` is set and
    /// otherwise only when the caller is neither in the group nor holds
    /// `CAP_FSETID`; the writer has no caller, so the bit goes in both cases,
    /// as it would for an unprivileged caller. A directory keeps both bits.
    ///
    /// `chown_common` asks for `ATTR_KILL_PRIV` on a non-directory as well,
    /// which `notify_change` carries to `security_inode_killpriv` and
    /// `cap_inode_killpriv` (security/commoncap.c): `security.capability`
    /// goes with the old owner ([`Self::kill_privileges`]).
    pub(crate) async fn set_owner(
        &mut self,
        tree: u64,
        inode: u64,
        uid: Option<u32>,
        gid: Option<u32>,
        changed: Timestamp,
    ) -> Result<(), WriteError> {
        let (mut raw, metadata) = self.inode_item(tree, inode).await?;
        check_flags(tree, inode, metadata.flags, INODE_IMMUTABLE | INODE_APPEND)?;
        let changed = time(tree, inode, changed)?;
        self.kill_privileges(tree, inode).await?;
        if let Some(uid) = uid {
            raw.uid.set(uid);
        }
        if let Some(gid) = gid {
            raw.gid.set(gid);
        }
        if metadata.kind != FileKind::Directory {
            raw.mode.set(raw.mode.get() & !(S_ISUID | S_ISGID));
        }
        raw.ctime = changed;
        raw.transid.set(self.trees.generation());
        raw.sequence.set(raw.sequence.get().wrapping_add(1));
        self.put_inode(tree, inode, raw).await
    }
}
