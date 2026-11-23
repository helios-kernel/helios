//! Parsing Linux `/proc/self/mountinfo` entries for active mounts.

use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
use std::path::{Path, PathBuf};

use crate::options::{AtimeMode, MountOptions, SyncMode};

/// The topmost mount entry at a mountpoint in `/proc/self/mountinfo`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MountEntry {
    pub mount_point: PathBuf,
    pub fs_type: String,
    pub source: String,
    pub vfs_options: MountOptions,
}

/// Finds the topmost (last) mount entry whose mountpoint equals `target`.
pub fn find_mount(contents: &str, target: &Path) -> Option<MountEntry> {
    let mut found = None;
    for line in contents.lines() {
        if let Some(entry) = parse_line(line)
            && entry.mount_point == target
        {
            found = Some(entry);
        }
    }
    found
}

fn parse_line(line: &str) -> Option<MountEntry> {
    let fields: Vec<&str> = line.split(' ').collect();
    // `proc_pid_mountinfo(5)`: id, parent, major:minor, root, mount_point,
    // mount_options, optional fields..., "-", fs_type, source, super_options.
    if fields.len() < 10 {
        return None;
    }
    let sep = fields.iter().skip(6).position(|&field| field == "-")? + 6;
    if sep + 3 >= fields.len() {
        return None;
    }
    let mount_point = PathBuf::from(unescape_mountinfo(fields[4]));
    let mount_options = fields[5];
    let fs_type = fields[sep + 1].to_owned();
    let source = unescape_mountinfo(fields[sep + 2])
        .to_string_lossy()
        .into_owned();
    let super_options = fields[sep + 3];
    let vfs_options = parse_vfs_options(mount_options, super_options);
    Some(MountEntry {
        mount_point,
        fs_type,
        source,
        vfs_options,
    })
}

/// Extracts only VFS mount/super flags from `/proc/self/mountinfo`, ignoring
/// FUSE-specific super options (`user_id`, `group_id`, `default_permissions`,
/// `allow_other`, etc.). Positive defaults (`suid`, `dev`, `exec`, `diratime`,
/// `async`) are filled in explicitly so rollback and `mount_setattr` clear
/// negative flags reliably.
fn parse_vfs_options(mount_options: &str, super_options: &str) -> MountOptions {
    let mut opts = MountOptions {
        remount: false,
        read_only: Some(false),
        suid: Some(true),
        dev: Some(true),
        exec: Some(true),
        atime: None,
        diratime: Some(true),
        sync: Some(SyncMode::Async),
        dirsync: false,
        lazytime: None,
        iversion: None,
    };
    let mut saw_ro = false;
    for token in mount_options.split(',').chain(super_options.split(',')) {
        match token {
            "ro" => saw_ro = true,
            "rw" => {}
            "nosuid" => opts.suid = Some(false),
            "nodev" => opts.dev = Some(false),
            "noexec" => opts.exec = Some(false),
            "noatime" => opts.atime = Some(AtimeMode::NoAtime),
            "relatime" => opts.atime = Some(AtimeMode::Relatime),
            "strictatime" => opts.atime = Some(AtimeMode::StrictAtime),
            "nodiratime" => opts.diratime = Some(false),
            "sync" => opts.sync = Some(SyncMode::Sync),
            "dirsync" => opts.dirsync = true,
            "lazytime" => opts.lazytime = Some(true),
            "iversion" => opts.iversion = Some(true),
            _ => {}
        }
    }
    opts.read_only = Some(saw_ro);
    opts
}

/// Reverses `mangle_path` octal escapes (`\040`, `\011`, `\012`, `\134`) from
/// `/proc/self/mountinfo`.
fn unescape_mountinfo(input: &str) -> OsString {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\'
            && i + 3 < bytes.len()
            && bytes[i + 1..i + 4]
                .iter()
                .all(|b| (b'0'..=b'7').contains(b))
        {
            let value =
                ((bytes[i + 1] - b'0') << 6) | ((bytes[i + 2] - b'0') << 3) | (bytes[i + 3] - b'0');
            out.push(value);
            i += 4;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    OsString::from_vec(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw,errors=remount-ro
120 22 0:54 / /mnt/helios-fstests/scratch rw,nosuid,nodev,relatime shared:60 - fuse /dev/loop0 rw,user_id=0,group_id=0,default_permissions,allow_other
121 22 0:55 / /mnt/helios-fstests/scratch ro,nosuid,nodev,noexec,noatime shared:61 - fuse /dev/loop1 ro,user_id=0,group_id=0,default_permissions,allow_other
122 22 0:56 / /mnt/with\\040space rw,relatime - fuse /dev/loop2 rw,sync,dirsync,user_id=0
";

    #[test]
    fn finds_topmost_mount_and_strips_fuse_super_options() {
        let entry = find_mount(SAMPLE, Path::new("/mnt/helios-fstests/scratch")).unwrap();
        assert_eq!(entry.fs_type, "fuse");
        assert_eq!(entry.source, "/dev/loop1");
        assert_eq!(entry.vfs_options.read_only, Some(true));
        assert_eq!(entry.vfs_options.suid, Some(false));
        assert_eq!(entry.vfs_options.dev, Some(false));
        assert_eq!(entry.vfs_options.exec, Some(false));
        assert_eq!(entry.vfs_options.atime, Some(AtimeMode::NoAtime));
        assert_eq!(
            entry.vfs_options.to_remount_option_string(),
            "remount,ro,nosuid,nodev,noexec,noatime,diratime,async"
        );
    }

    #[test]
    fn unescapes_octal_mount_paths_and_reads_super_vfs_flags() {
        let entry = find_mount(SAMPLE, Path::new("/mnt/with space")).unwrap();
        assert_eq!(entry.source, "/dev/loop2");
        assert_eq!(entry.vfs_options.read_only, Some(false));
        assert_eq!(entry.vfs_options.suid, Some(true));
        assert_eq!(entry.vfs_options.dev, Some(true));
        assert_eq!(entry.vfs_options.exec, Some(true));
        assert_eq!(entry.vfs_options.sync, Some(SyncMode::Sync));
        assert!(entry.vfs_options.dirsync);
    }

    #[test]
    fn returns_none_when_mountpoint_absent() {
        assert!(find_mount(SAMPLE, Path::new("/mnt/missing")).is_none());
    }
}
