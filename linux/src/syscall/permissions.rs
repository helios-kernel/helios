//! Linux v6.12 discretionary access control, POSIX ACL evaluation, set-id and
//! sticky bit rules, privileged xattr namespace checks, `mknod` checks, and
//! `execve` credential transitions.
//!
//! Every function here is pure `#![no_std]` policy shared by the syscall layer
//! and the kernel's container filesystem (`kernel/src/linux_container.rs`).
//! Linux's permission model only narrows a container's mount rights and
//! `ProcessAuthority`, never widens them.

use super::fs::{FsOpError, TimeUpdate};
use super::system::{
    CAP_CHOWN, CAP_DAC_OVERRIDE, CAP_DAC_READ_SEARCH, CAP_FOWNER, CAP_FSETID, CAP_FULL_SET,
    CAP_MKNOD, CAP_SETFCAP, CAP_SYS_ADMIN, Credentials,
};
use helios_hal::fs::{FsError, NodeKind};

// Mode bit constants (`include/uapi/linux/stat.h`, Linux v6.12).
pub const S_IFMT: u32 = 0o170_000;
pub const S_IFIFO: u32 = 0o010_000;
pub const S_IFCHR: u32 = 0o020_000;
pub const S_IFDIR: u32 = 0o040_000;
pub const S_IFBLK: u32 = 0o060_000;
pub const S_IFREG: u32 = 0o100_000;
pub const S_IFLNK: u32 = 0o120_000;
pub const S_IFSOCK: u32 = 0o140_000;

pub const S_ISUID: u32 = 0o4000;
pub const S_ISGID: u32 = 0o2000;
pub const S_ISVTX: u32 = 0o1000;
pub const S_IXGRP: u32 = 0o0010;
pub const S_IXUGO: u32 = 0o0111;
pub const S_IALLUGO: u32 = 0o7777;

// Permission mask bits (`include/linux/fs.h`, Linux v6.12).
pub const MAY_EXEC: u32 = 1;
pub const MAY_WRITE: u32 = 2;
pub const MAY_READ: u32 = 4;

// Xattr limits (`include/uapi/linux/limits.h`, Linux v6.12).
pub const XATTR_NAME_MAX: usize = 255;
pub const XATTR_SIZE_MAX: usize = 65_536;
pub const XATTR_LIST_MAX: usize = 65_536;

pub const XATTR_SECURITY_CAPABILITY: &str = "security.capability";
pub const XATTR_POSIX_ACL_ACCESS: &str = "system.posix_acl_access";
pub const XATTR_POSIX_ACL_DEFAULT: &str = "system.posix_acl_default";

// POSIX ACL xattr binary format (`include/uapi/linux/posix_acl_xattr.h`).
const POSIX_ACL_XATTR_VERSION: u32 = 0x0002;
const ACL_USER_OBJ: u16 = 0x01;
const ACL_USER: u16 = 0x02;
const ACL_GROUP_OBJ: u16 = 0x04;
const ACL_GROUP: u16 = 0x08;
const ACL_MASK: u16 = 0x10;
const ACL_OTHER: u16 = 0x20;

// File capability xattr format (`include/uapi/linux/capability.h`).
const VFS_CAP_REVISION_MASK: u32 = 0xff00_0000;
const VFS_CAP_FLAGS_MASK: u32 = !VFS_CAP_REVISION_MASK;
const VFS_CAP_FLAGS_EFFECTIVE: u32 = 0x0000_0001;
const VFS_CAP_REVISION_1: u32 = 0x0100_0000;
const VFS_CAP_REVISION_2: u32 = 0x0200_0000;
const VFS_CAP_REVISION_3: u32 = 0x0300_0000;

/// Metadata of a private-mount inode relevant to permission checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InodeMeta {
    pub kind: NodeKind,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
}

/// Whether `creds` owns `inode_uid` or holds `CAP_FOWNER`
/// (`fs/inode.c` `inode_owner_or_capable`, Linux v6.12).
pub fn inode_owner_or_capable(creds: &Credentials, inode_uid: u32) -> bool {
    creds.user.effective == inode_uid || creds.capabilities.has_effective(CAP_FOWNER)
}

/// Evaluates a Linux `system.posix_acl_access` binary payload against `creds`
/// (`fs/posix_acl.c` `posix_acl_permission`, Linux v6.12).
///
/// Returns `Some(true)` if the ACL grants all bits in `want`, `Some(false)` if
/// it denies them, or `None` if `acl_bytes` is malformed/empty so the caller
/// falls back to the inode's mode bits.
pub fn posix_acl_permission(
    creds: &Credentials,
    inode_uid: u32,
    inode_gid: u32,
    acl_bytes: &[u8],
    want: u32,
) -> Option<bool> {
    if acl_bytes.len() < 4 || !(acl_bytes.len() - 4).is_multiple_of(8) {
        return None;
    }
    let version = u32::from_le_bytes(acl_bytes[0..4].try_into().ok()?);
    if version != POSIX_ACL_XATTR_VERSION {
        return None;
    }
    let body = &acl_bytes[4..];
    if body.is_empty() {
        return None;
    }
    let mut mask: Option<u32> = None;
    for chunk in body.as_chunks::<8>().0 {
        let tag = u16::from_le_bytes(chunk[0..2].try_into().ok()?);
        let perm = u16::from_le_bytes(chunk[2..4].try_into().ok()?);
        if tag == ACL_MASK {
            mask = Some(u32::from(perm & 7));
        }
    }

    let mut found_group = false;
    for chunk in body.as_chunks::<8>().0 {
        let tag = u16::from_le_bytes(chunk[0..2].try_into().ok()?);
        let perm = u32::from(u16::from_le_bytes(chunk[2..4].try_into().ok()?) & 7);
        let id = u32::from_le_bytes(chunk[4..8].try_into().ok()?);
        match tag {
            ACL_USER_OBJ => {
                if creds.user.effective == inode_uid {
                    return Some((perm & want) == want);
                }
            }
            ACL_USER => {
                if creds.user.effective == id {
                    let effective = perm & mask.unwrap_or(7);
                    return Some((effective & want) == want);
                }
            }
            ACL_GROUP_OBJ => {
                if creds.in_group(inode_gid) {
                    found_group = true;
                    let effective = perm & mask.unwrap_or(7);
                    if (effective & want) == want {
                        return Some(true);
                    }
                }
            }
            ACL_GROUP => {
                if creds.in_group(id) {
                    found_group = true;
                    let effective = perm & mask.unwrap_or(7);
                    if (effective & want) == want {
                        return Some(true);
                    }
                }
            }
            ACL_MASK => {}
            ACL_OTHER => {
                if found_group {
                    return Some(false);
                }
                return Some((perm & want) == want);
            }
            _ => return None,
        }
    }
    if found_group { Some(false) } else { None }
}

/// Checks DAC + POSIX ACL + `CAP_DAC_OVERRIDE`/`CAP_DAC_READ_SEARCH`
/// (`fs/namei.c` `generic_permission` and `acl_permission_check`, Linux v6.12).
pub fn generic_permission(
    creds: &Credentials,
    inode: InodeMeta,
    access_acl: Option<&[u8]>,
    want: u32,
) -> Result<(), FsOpError> {
    let want = want & (MAY_READ | MAY_WRITE | MAY_EXEC);
    if want == 0 {
        return Ok(());
    }

    let acl_ok = if creds.user.effective == inode.uid {
        let owner_bits = (inode.mode >> 6) & 7;
        (owner_bits & want) == want
    } else if let Some(bytes) = access_acl
        && let Some(allowed) = posix_acl_permission(creds, inode.uid, inode.gid, bytes, want)
    {
        allowed
    } else if creds.in_group(inode.gid) {
        let group_bits = (inode.mode >> 3) & 7;
        (group_bits & want) == want
    } else {
        let other_bits = inode.mode & 7;
        (other_bits & want) == want
    };

    if acl_ok {
        return Ok(());
    }

    // Capability overrides (`fs/namei.c` `generic_permission`).
    if inode.kind == NodeKind::Directory {
        if creds.capabilities.has_effective(CAP_DAC_OVERRIDE) {
            return Ok(());
        }
        if (want & MAY_WRITE) == 0 && creds.capabilities.has_effective(CAP_DAC_READ_SEARCH) {
            return Ok(());
        }
        return Err(FsOpError::Fs(FsError::NotPermitted));
    }

    // Non-directory: CAP_DAC_OVERRIDE grants read/write unconditionally, and
    // exec only if at least one execute bit (`S_IXUGO`) is set on the file.
    if ((want & MAY_EXEC) == 0 || (inode.mode & S_IXUGO) != 0)
        && creds.capabilities.has_effective(CAP_DAC_OVERRIDE)
    {
        return Ok(());
    }

    // CAP_DAC_READ_SEARCH grants pure read on non-directories.
    if want == MAY_READ && creds.capabilities.has_effective(CAP_DAC_READ_SEARCH) {
        return Ok(());
    }

    Err(FsOpError::Fs(FsError::NotPermitted))
}

/// Sticky-bit check on unlink/rmdir/rename (`fs/namei.c` `check_sticky`,
/// Linux v6.12). Fails with `EPERM`.
pub fn check_sticky(
    creds: &Credentials,
    parent: InodeMeta,
    child_uid: u32,
) -> Result<(), FsOpError> {
    if (parent.mode & S_ISVTX) == 0 {
        return Ok(());
    }
    if creds.user.effective == child_uid
        || creds.user.effective == parent.uid
        || creds.capabilities.has_effective(CAP_FOWNER)
    {
        return Ok(());
    }
    Err(FsOpError::PermissionDenied)
}

/// Validates `chmod`/`fchmod`/`fchmodat`/`fchmodat2` (`fs/attr.c`
/// `setattr_prepare` + `fs/open.c` `chmod_common`, Linux v6.12) and returns
/// the effective 12-bit permission mode to store (stripping `S_ISGID` when the
/// caller is neither in `inode.gid` nor holds `CAP_FSETID`).
pub fn check_chmod(
    creds: &Credentials,
    inode: InodeMeta,
    requested_mode: u32,
) -> Result<u32, FsOpError> {
    if inode.kind == NodeKind::Symlink {
        return Err(FsOpError::Fs(FsError::Unsupported));
    }
    if !inode_owner_or_capable(creds, inode.uid) {
        return Err(FsOpError::PermissionDenied);
    }
    let mut mode = requested_mode & S_IALLUGO;
    if !creds.in_group(inode.gid) && !creds.capabilities.has_effective(CAP_FSETID) {
        mode &= !S_ISGID;
    }
    Ok(mode)
}

/// Result of validating `chown`/`fchown`/`lchown`/`fchownat`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChownPlan {
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    /// Whether `S_ISUID`/`S_ISGID` and `security.capability` must be cleared.
    pub kill_privs: bool,
}

/// Validates `chown`/`fchown`/`lchown`/`fchownat` (`fs/attr.c` `chown_ok`,
/// `chgrp_ok`, `fs/open.c` `chown_common`, Linux v6.12).
pub fn check_chown(
    creds: &Credentials,
    inode: InodeMeta,
    new_uid: Option<u32>,
    new_gid: Option<u32>,
) -> Result<ChownPlan, FsOpError> {
    if let Some(uid) = new_uid {
        let ok = creds.capabilities.has_effective(CAP_CHOWN)
            || (creds.user.effective == inode.uid && uid == inode.uid);
        if !ok {
            return Err(FsOpError::PermissionDenied);
        }
    }
    if let Some(gid) = new_gid {
        let ok = creds.capabilities.has_effective(CAP_CHOWN)
            || (creds.user.effective == inode.uid && (gid == inode.gid || creds.in_group(gid)));
        if !ok {
            return Err(FsOpError::PermissionDenied);
        }
    }
    let kill_privs = inode.kind != NodeKind::Directory && (new_uid.is_some() || new_gid.is_some());
    Ok(ChownPlan {
        uid: new_uid,
        gid: new_gid,
        kill_privs,
    })
}

/// Validates `utimensat` timestamp updates (`fs/utimes.c` `utimes_common`,
/// Linux v6.12).
pub fn check_utimens(
    creds: &Credentials,
    inode: InodeMeta,
    access_acl: Option<&[u8]>,
    access: TimeUpdate,
    modified: TimeUpdate,
) -> Result<(), FsOpError> {
    if access == TimeUpdate::Omit && modified == TimeUpdate::Omit {
        return Ok(());
    }
    let explicit = matches!(access, TimeUpdate::Set(_)) || matches!(modified, TimeUpdate::Set(_));
    if explicit {
        if inode_owner_or_capable(creds, inode.uid) {
            Ok(())
        } else {
            Err(FsOpError::PermissionDenied)
        }
    } else if inode_owner_or_capable(creds, inode.uid)
        || generic_permission(creds, inode, access_acl, MAY_WRITE).is_ok()
    {
        Ok(())
    } else {
        Err(FsOpError::Fs(FsError::NotPermitted))
    }
}

/// Mode bits to clear on `write`/`truncate`/`O_TRUNC` of a regular file
/// (`fs/inode.c` `setattr_should_drop_suidgid` / `file_remove_privs`,
/// Linux v6.12).
///
/// Returns `Some(new_permissions)` if the inode's mode must be updated.
/// Callers must additionally remove `security.capability` on every write or
/// truncate of a regular file regardless of `CAP_FSETID`.
pub fn stripped_mode_on_write(creds: &Credentials, inode: InodeMeta) -> Option<u32> {
    if inode.kind != NodeKind::File {
        return None;
    }
    if creds.capabilities.has_effective(CAP_FSETID) {
        return None;
    }
    let mut clear = 0u32;
    if (inode.mode & S_ISUID) != 0 {
        clear |= S_ISUID;
    }
    if (inode.mode & S_ISGID) != 0 && (inode.mode & S_IXGRP) != 0 {
        clear |= S_ISGID;
    }
    if clear == 0 {
        None
    } else {
        Some((inode.mode & S_IALLUGO) & !clear)
    }
}

/// Validates `mknod`/`mknodat` (`fs/namei.c` `may_mknod` + `do_mknodat`, Linux
/// v6.12) and returns the `NodeKind` to create.
pub fn check_mknod(creds: &Credentials, mode: u32) -> Result<NodeKind, FsOpError> {
    let kind = match mode & S_IFMT {
        0 | S_IFREG => NodeKind::File,
        S_IFIFO => NodeKind::Fifo,
        S_IFSOCK => NodeKind::Socket,
        S_IFCHR => NodeKind::CharacterDevice,
        S_IFBLK => NodeKind::BlockDevice,
        S_IFDIR => return Err(FsOpError::PermissionDenied),
        _ => return Err(FsOpError::Fs(FsError::Invalid)),
    };
    if matches!(kind, NodeKind::CharacterDevice | NodeKind::BlockDevice)
        && !creds.capabilities.has_effective(CAP_MKNOD)
    {
        return Err(FsOpError::PermissionDenied);
    }
    Ok(kind)
}

/// Classified extended attribute namespace.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum XattrNamespace {
    User,
    Trusted,
    SecurityCapability,
    SecurityOther,
    PosixAclAccess,
    PosixAclDefault,
}

/// Validates the xattr name syntax and classifies its namespace (`fs/xattr.c`).
pub fn classify_xattr_name(name: &str) -> Result<XattrNamespace, FsOpError> {
    if name.is_empty() || name.len() > XATTR_NAME_MAX {
        return Err(FsOpError::Range);
    }
    if name == XATTR_SECURITY_CAPABILITY {
        return Ok(XattrNamespace::SecurityCapability);
    }
    if name == XATTR_POSIX_ACL_ACCESS {
        return Ok(XattrNamespace::PosixAclAccess);
    }
    if name == XATTR_POSIX_ACL_DEFAULT {
        return Ok(XattrNamespace::PosixAclDefault);
    }
    if let Some(rest) = name.strip_prefix("user.") {
        return if rest.is_empty() {
            Err(FsOpError::Fs(FsError::Invalid))
        } else {
            Ok(XattrNamespace::User)
        };
    }
    if let Some(rest) = name.strip_prefix("trusted.") {
        return if rest.is_empty() {
            Err(FsOpError::Fs(FsError::Invalid))
        } else {
            Ok(XattrNamespace::Trusted)
        };
    }
    if let Some(rest) = name.strip_prefix("security.") {
        return if rest.is_empty() {
            Err(FsOpError::Fs(FsError::Invalid))
        } else {
            Ok(XattrNamespace::SecurityOther)
        };
    }
    Err(FsOpError::Fs(FsError::Unsupported))
}

/// Checks permission for `getxattr` (`write = false`) or `setxattr`/
/// `removexattr` (`write = true`) (`fs/xattr.c` `xattr_permission`,
/// `security/commoncap.c` `cap_inode_setxattr`, `fs/posix_acl.c`, Linux v6.12).
pub fn check_xattr_permission(
    creds: &Credentials,
    inode: InodeMeta,
    access_acl: Option<&[u8]>,
    name: &str,
    write: bool,
) -> Result<XattrNamespace, FsOpError> {
    let ns = classify_xattr_name(name)?;
    match ns {
        XattrNamespace::Trusted => {
            if !creds.capabilities.has_effective(CAP_SYS_ADMIN) {
                return Err(if write {
                    FsOpError::PermissionDenied
                } else {
                    FsOpError::NoData
                });
            }
        }
        XattrNamespace::SecurityCapability => {
            if write && !creds.capabilities.has_effective(CAP_SETFCAP) {
                return Err(FsOpError::PermissionDenied);
            }
        }
        XattrNamespace::SecurityOther => {
            if write && !creds.capabilities.has_effective(CAP_SYS_ADMIN) {
                return Err(FsOpError::PermissionDenied);
            }
        }
        XattrNamespace::PosixAclAccess | XattrNamespace::PosixAclDefault => {
            if write {
                if inode.kind == NodeKind::Symlink {
                    return Err(FsOpError::Fs(FsError::Unsupported));
                }
                if !inode_owner_or_capable(creds, inode.uid) {
                    return Err(FsOpError::PermissionDenied);
                }
            }
        }
        XattrNamespace::User => {
            if !matches!(inode.kind, NodeKind::File | NodeKind::Directory) {
                return Err(if write {
                    FsOpError::PermissionDenied
                } else {
                    FsOpError::NoData
                });
            }
            if write
                && inode.kind == NodeKind::Directory
                && (inode.mode & S_ISVTX) != 0
                && !inode_owner_or_capable(creds, inode.uid)
            {
                return Err(FsOpError::PermissionDenied);
            }
            let mask = if write { MAY_WRITE } else { MAY_READ };
            generic_permission(creds, inode, access_acl, mask)?;
        }
    }
    Ok(ns)
}

/// Whether `listxattr` should include `name` for `creds` (`fs/xattr.c` /
/// `fs/btrfs/xattr.c`: `trusted.*` is omitted without `CAP_SYS_ADMIN`).
pub fn xattr_visible_in_list(creds: &Credentials, name: &str) -> bool {
    if name.starts_with("trusted.") {
        creds.capabilities.has_effective(CAP_SYS_ADMIN)
    } else {
        true
    }
}

/// Decoded Linux `security.capability` VFS capability record
/// (`include/uapi/linux/capability.h`, `security/commoncap.c`
/// `get_vfs_caps_from_disk`, Linux v6.12).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VfsCapData {
    pub effective: bool,
    pub permitted: u64,
    pub inheritable: u64,
    /// `rootid` for v3 capabilities (`0` for v1/v2).
    pub rootid: u32,
}

/// Parses and validates a Linux `security.capability` xattr payload (v1, v2,
/// or v3; `security/commoncap.c` `cap_convert_nscap` /
/// `get_vfs_caps_from_disk`, Linux v6.12).
pub fn parse_vfs_cap_data(bytes: &[u8]) -> Result<VfsCapData, FsOpError> {
    if bytes.len() < 4 {
        return Err(FsOpError::Fs(FsError::Invalid));
    }
    let magic_etc = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    let revision = magic_etc & VFS_CAP_REVISION_MASK;
    let flags = magic_etc & VFS_CAP_FLAGS_MASK;
    if (flags & !VFS_CAP_FLAGS_EFFECTIVE) != 0 {
        return Err(FsOpError::Fs(FsError::Invalid));
    }
    let effective = (flags & VFS_CAP_FLAGS_EFFECTIVE) != 0;
    let read_u32 = |off: usize| u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap());
    match (revision, bytes.len()) {
        (VFS_CAP_REVISION_1, 12) => Ok(VfsCapData {
            effective,
            permitted: u64::from(read_u32(4)) & CAP_FULL_SET,
            inheritable: u64::from(read_u32(8)) & CAP_FULL_SET,
            rootid: 0,
        }),
        (VFS_CAP_REVISION_2, 20) => Ok(VfsCapData {
            effective,
            permitted: (u64::from(read_u32(4)) | (u64::from(read_u32(12)) << 32)) & CAP_FULL_SET,
            inheritable: (u64::from(read_u32(8)) | (u64::from(read_u32(16)) << 32)) & CAP_FULL_SET,
            rootid: 0,
        }),
        (VFS_CAP_REVISION_3, 24) => Ok(VfsCapData {
            effective,
            permitted: (u64::from(read_u32(4)) | (u64::from(read_u32(12)) << 32)) & CAP_FULL_SET,
            inheritable: (u64::from(read_u32(8)) | (u64::from(read_u32(16)) << 32)) & CAP_FULL_SET,
            rootid: read_u32(20),
        }),
        _ => Err(FsOpError::Fs(FsError::Invalid)),
    }
}

/// Computes the post-`execve` [`Credentials`] for executing `inode` with
/// optional raw `security.capability` xattr bytes (`fs/exec.c`
/// `bprm_fill_uid` + `security/commoncap.c` `cap_bprm_creds_from_file`,
/// Linux v6.12).
///
/// - When `honours_exec_privileges` is `false` (a shared or `NO_SUID` mount),
///   or when `current.no_new_privs` (`PR_SET_NO_NEW_PRIVS`) is set, set-id
///   bits and file capabilities are ignored and no capability outside
///   `current.capabilities.permitted` can be gained.
/// - `authority_cap_ceiling` caps every resulting capability set so a
///   container's processes never exceed the container's granted authority, even
///   as `uid 0` or via setuid/file capabilities.
pub fn apply_exec_credentials(
    current: &Credentials,
    inode: InodeMeta,
    file_cap_bytes: Option<&[u8]>,
    honours_exec_privileges: bool,
    authority_cap_ceiling: u64,
) -> Credentials {
    let mut new = current.clone();
    let ceiling = authority_cap_ceiling & CAP_FULL_SET;
    let grant_privs = honours_exec_privileges && !current.no_new_privs;

    if grant_privs {
        if (inode.mode & S_ISUID) != 0 {
            new.user.effective = inode.uid;
        }
        if (inode.mode & S_ISGID) != 0 && (inode.mode & S_IXGRP) != 0 {
            new.group.effective = inode.gid;
        }
    }
    new.user.saved = new.user.effective;
    new.group.saved = new.group.effective;

    let file_caps = if grant_privs {
        file_cap_bytes
            .and_then(|raw| parse_vfs_cap_data(raw).ok())
            .filter(|caps| caps.rootid == 0)
    } else {
        None
    };

    let is_setid =
        new.user.effective != current.user.real || new.group.effective != current.group.real;
    if is_setid || file_caps.is_some() {
        new.capabilities.ambient = 0;
    }

    let (mut permitted, mut effective) = if let Some(fcaps) = file_caps {
        let p = ((current.capabilities.inheritable & fcaps.inheritable)
            | (fcaps.permitted & current.capabilities.bounding)
            | new.capabilities.ambient)
            & CAP_FULL_SET;
        let e = if fcaps.effective {
            p
        } else {
            new.capabilities.ambient
        };
        (p, e)
    } else if new.user.effective == 0 || new.user.real == 0 {
        // `security/commoncap.c` `handle_privileged_root`.
        let p = (current.capabilities.inheritable | current.capabilities.bounding) & CAP_FULL_SET;
        let e = if new.user.effective == 0 { p } else { 0 };
        (p, e)
    } else {
        let a = new.capabilities.ambient & CAP_FULL_SET;
        (a, a)
    };

    if current.no_new_privs {
        // `security/commoncap.c` `cap_bprm_creds_from_file`: `PR_SET_NO_NEW_PRIVS`
        // prevents gaining any capability outside the caller's permitted set.
        permitted &= current.capabilities.permitted;
        effective &= permitted;
    }

    new.capabilities.bounding &= ceiling;
    new.capabilities.permitted = permitted & ceiling;
    new.capabilities.effective = effective & ceiling;
    new.capabilities.inheritable &= ceiling;
    new.capabilities.ambient &= ceiling;
    new
}

/// Whether an `execve` credential transition from `old` to `new` sets
/// `AT_SECURE = 1` (`security/commoncap.c` `cap_bprm_creds_from_file`,
/// Linux v6.12).
pub fn exec_is_secure(old: &Credentials, new: &Credentials) -> bool {
    new.user.effective != old.user.real
        || new.group.effective != old.group.real
        || (new.capabilities.permitted & !old.capabilities.permitted) != 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;

    fn encode_acl(entries: &[(u16, u16, u32)]) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + entries.len() * 8);
        out.extend_from_slice(&POSIX_ACL_XATTR_VERSION.to_le_bytes());
        for &(tag, perm, id) in entries {
            out.extend_from_slice(&tag.to_le_bytes());
            out.extend_from_slice(&perm.to_le_bytes());
            out.extend_from_slice(&id.to_le_bytes());
        }
        out
    }

    fn encode_vfs_cap_v2(effective: bool, permitted: u64, inheritable: u64) -> [u8; 20] {
        let mut out = [0u8; 20];
        let magic = VFS_CAP_REVISION_2
            | if effective {
                VFS_CAP_FLAGS_EFFECTIVE
            } else {
                0
            };
        out[0..4].copy_from_slice(&magic.to_le_bytes());
        out[4..8].copy_from_slice(&(permitted as u32).to_le_bytes());
        out[8..12].copy_from_slice(&(inheritable as u32).to_le_bytes());
        out[12..16].copy_from_slice(&((permitted >> 32) as u32).to_le_bytes());
        out[16..20].copy_from_slice(&((inheritable >> 32) as u32).to_le_bytes());
        out
    }

    #[test]
    fn generic_permission_owner_does_not_fall_through_to_group_or_other() {
        let owner = Credentials::for_ids(1000, 100, vec![]);
        let inode = InodeMeta {
            kind: NodeKind::File,
            mode: 0o077,
            uid: 1000,
            gid: 100,
        };
        assert_eq!(
            generic_permission(&owner, inode, None, MAY_READ),
            Err(FsOpError::Fs(FsError::NotPermitted))
        );
        let group_member = Credentials::for_ids(2000, 200, vec![100]);
        assert_eq!(
            generic_permission(&group_member, inode, None, MAY_READ | MAY_WRITE),
            Ok(())
        );
    }

    #[test]
    fn generic_permission_cap_dac_override_exec_requires_one_exec_bit() {
        let root = Credentials::root();
        let non_exec = InodeMeta {
            kind: NodeKind::File,
            mode: 0o644,
            uid: 1000,
            gid: 1000,
        };
        assert_eq!(
            generic_permission(&root, non_exec, None, MAY_READ | MAY_WRITE),
            Ok(())
        );
        assert_eq!(
            generic_permission(&root, non_exec, None, MAY_EXEC),
            Err(FsOpError::Fs(FsError::NotPermitted))
        );
        let one_exec = InodeMeta {
            mode: 0o001,
            ..non_exec
        };
        assert_eq!(generic_permission(&root, one_exec, None, MAY_EXEC), Ok(()));
        let dir = InodeMeta {
            kind: NodeKind::Directory,
            mode: 0o000,
            uid: 1000,
            gid: 1000,
        };
        assert_eq!(
            generic_permission(&root, dir, None, MAY_EXEC | MAY_READ | MAY_WRITE),
            Ok(())
        );
    }

    #[test]
    fn posix_acl_named_user_and_group_masking() {
        let acl = encode_acl(&[
            (ACL_USER_OBJ, 6, u32::MAX),
            (ACL_USER, 7, 1001),
            (ACL_GROUP_OBJ, 0, u32::MAX),
            (ACL_GROUP, 6, 200),
            (ACL_MASK, 4, u32::MAX),
            (ACL_OTHER, 7, u32::MAX),
        ]);
        let inode = InodeMeta {
            kind: NodeKind::File,
            mode: 0o647,
            uid: 1000,
            gid: 100,
        };
        let u1001 = Credentials::for_ids(1001, 500, vec![]);
        assert_eq!(
            generic_permission(&u1001, inode, Some(&acl), MAY_READ),
            Ok(())
        );
        assert_eq!(
            generic_permission(&u1001, inode, Some(&acl), MAY_WRITE),
            Err(FsOpError::Fs(FsError::NotPermitted))
        );
        // Member of both group 100 (0) and 200 (6 & mask 4 = 4) gets read,
        // denied write, and does NOT fall through to ACL_OTHER (7).
        let gmember = Credentials::for_ids(1002, 100, vec![200]);
        assert_eq!(
            generic_permission(&gmember, inode, Some(&acl), MAY_READ),
            Ok(())
        );
        assert_eq!(
            generic_permission(&gmember, inode, Some(&acl), MAY_WRITE),
            Err(FsOpError::Fs(FsError::NotPermitted))
        );
        // Other user gets ACL_OTHER (7).
        let other = Credentials::for_ids(1003, 999, vec![]);
        assert_eq!(
            generic_permission(&other, inode, Some(&acl), MAY_READ | MAY_WRITE | MAY_EXEC),
            Ok(())
        );
    }

    #[test]
    fn sticky_chmod_chown_and_write_priv_rules() {
        let parent = InodeMeta {
            kind: NodeKind::Directory,
            mode: 0o1777,
            uid: 0,
            gid: 0,
        };
        let u1 = Credentials::for_ids(1000, 1000, vec![]);
        let u2 = Credentials::for_ids(2000, 2000, vec![]);
        assert_eq!(check_sticky(&u1, parent, 1000), Ok(()));
        assert_eq!(
            check_sticky(&u2, parent, 1000),
            Err(FsOpError::PermissionDenied)
        );
        assert_eq!(check_sticky(&Credentials::root(), parent, 1000), Ok(()));

        // chmod strips S_ISGID when caller not in group and no CAP_FSETID.
        let file = InodeMeta {
            kind: NodeKind::File,
            mode: 0o644,
            uid: 1000,
            gid: 500,
        };
        assert_eq!(check_chmod(&u1, file, 0o6755), Ok(0o4755));
        let in_grp = Credentials::for_ids(1000, 1000, vec![500]);
        assert_eq!(check_chmod(&in_grp, file, 0o6755), Ok(0o6755));
        assert_eq!(
            check_chmod(&u2, file, 0o644),
            Err(FsOpError::PermissionDenied)
        );

        // chown rules.
        assert_eq!(
            check_chown(&in_grp, file, None, Some(500)),
            Ok(ChownPlan {
                uid: None,
                gid: Some(500),
                kill_privs: true,
            })
        );
        assert_eq!(
            check_chown(&u1, file, None, Some(500)),
            Ok(ChownPlan {
                uid: None,
                gid: Some(500),
                kill_privs: true,
            })
        );
        assert_eq!(
            check_chown(&u1, file, None, Some(999)),
            Err(FsOpError::PermissionDenied)
        );
        assert_eq!(
            check_chown(&u1, file, Some(2000), None),
            Err(FsOpError::PermissionDenied)
        );

        // Write strips S_ISUID and S_ISGID (when S_IXGRP set) without CAP_FSETID.
        let suid_file = InodeMeta {
            mode: 0o6755,
            ..file
        };
        assert_eq!(stripped_mode_on_write(&u1, suid_file), Some(0o0755));
        let mand_lock = InodeMeta {
            mode: 0o2644,
            ..file
        };
        assert_eq!(stripped_mode_on_write(&u1, mand_lock), None);
        assert_eq!(
            stripped_mode_on_write(&Credentials::root(), suid_file),
            None
        );
    }

    #[test]
    fn xattr_and_exec_capability_rules() {
        let user = Credentials::for_ids(1000, 1000, vec![]);
        let root = Credentials::root();
        let file = InodeMeta {
            kind: NodeKind::File,
            mode: 0o644,
            uid: 1000,
            gid: 1000,
        };
        assert_eq!(
            check_xattr_permission(&user, file, None, "trusted.x", false),
            Err(FsOpError::NoData)
        );
        assert_eq!(
            check_xattr_permission(&user, file, None, "trusted.x", true),
            Err(FsOpError::PermissionDenied)
        );
        assert_eq!(
            check_xattr_permission(&root, file, None, "trusted.x", true),
            Ok(XattrNamespace::Trusted)
        );
        assert_eq!(
            check_xattr_permission(&user, file, None, XATTR_SECURITY_CAPABILITY, true),
            Err(FsOpError::PermissionDenied)
        );
        assert_eq!(
            check_xattr_permission(&user, file, None, XATTR_SECURITY_CAPABILITY, false),
            Ok(XattrNamespace::SecurityCapability)
        );

        // File capabilities honoured on private mount, ignored on shared/nosuid mount,
        // and bounded by container authority ceiling.
        let raw_cap = encode_vfs_cap_v2(
            true,
            (1u64 << CAP_NET_BIND_SERVICE) | (1u64 << CAP_SYS_ADMIN),
            0,
        );
        let exec_file = InodeMeta {
            kind: NodeKind::File,
            mode: 0o4755,
            uid: 0,
            gid: 0,
        };
        let ceiling = (1u64 << CAP_NET_BIND_SERVICE) | (1u64 << CAP_CHOWN);
        let priv_creds = apply_exec_credentials(&user, exec_file, Some(&raw_cap), true, ceiling);
        assert_eq!(priv_creds.user.effective, 0);
        assert!(priv_creds.capabilities.has_effective(CAP_NET_BIND_SERVICE));
        assert!(!priv_creds.capabilities.has_effective(CAP_SYS_ADMIN));
        assert!(exec_is_secure(&user, &priv_creds));

        let shared_creds =
            apply_exec_credentials(&user, exec_file, Some(&raw_cap), false, CAP_FULL_SET);
        assert_eq!(shared_creds.user.effective, 1000);
        assert_eq!(shared_creds.capabilities.effective, 0);
        assert!(!exec_is_secure(&user, &shared_creds));

        // PR_SET_NO_NEW_PRIVS suppresses both set-id and file capabilities.
        let mut nnp_user = user.clone();
        nnp_user.no_new_privs = true;
        let nnp_creds = apply_exec_credentials(&nnp_user, exec_file, Some(&raw_cap), true, ceiling);
        assert_eq!(nnp_creds.user.effective, 1000);
        assert_eq!(nnp_creds.group.effective, 1000);
        assert_eq!(nnp_creds.capabilities.permitted, 0);
        assert_eq!(nnp_creds.capabilities.effective, 0);
        assert!(nnp_creds.no_new_privs);
        assert!(!exec_is_secure(&nnp_user, &nnp_creds));
    }

    use super::super::system::CAP_NET_BIND_SERVICE;
}
