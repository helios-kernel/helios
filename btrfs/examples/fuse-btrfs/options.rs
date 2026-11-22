//! Mount option parsing and VFS flag merging for `fuse-btrfs`.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AtimeMode {
    Atime,
    NoAtime,
    Relatime,
    NoRelatime,
    StrictAtime,
    NoStrictAtime,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyncMode {
    Sync,
    Async,
}

/// Parsed `-o` options from a `mount(8)` invocation or `/proc/self/mountinfo`.
///
/// Conflicting pairs (`ro`/`rw`, `suid`/`nosuid`, `dev`/`nodev`, `exec`/`noexec`,
/// `atime`/`noatime`/..., `sync`/`async`) follow `mount(8)` semantics: the last
/// occurrence wins.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MountOptions {
    pub remount: bool,
    pub read_only: Option<bool>,
    pub suid: Option<bool>,
    pub dev: Option<bool>,
    pub exec: Option<bool>,
    pub atime: Option<AtimeMode>,
    pub diratime: Option<bool>,
    pub sync: Option<SyncMode>,
    pub dirsync: bool,
    pub lazytime: Option<bool>,
    pub iversion: Option<bool>,
}

impl MountOptions {
    /// Parses a comma-separated `-o` option list. Returns the first unsupported
    /// option name on error.
    ///
    /// Initial mounts accept only the VFS options that `fuser` applies at mount
    /// time; remounts (`remount` present in the list) accept all standard VFS
    /// flags that `mount -i -o remount,...` applies.
    pub fn parse(raw: Option<&str>) -> Result<Self, String> {
        let mut parsed = Self::default();
        let Some(raw) = raw else {
            return Ok(parsed);
        };
        if raw.is_empty() {
            return Ok(parsed);
        }
        let tokens: Vec<&str> = raw.split(',').collect();
        let is_remount = tokens.contains(&"remount");
        for option in tokens {
            match option {
                "defaults" => {}
                "remount" => parsed.remount = true,
                "ro" => parsed.read_only = Some(true),
                "rw" => parsed.read_only = Some(false),
                "suid" => parsed.suid = Some(true),
                "nosuid" => parsed.suid = Some(false),
                "dev" => parsed.dev = Some(true),
                "nodev" => parsed.dev = Some(false),
                "exec" => parsed.exec = Some(true),
                "noexec" => parsed.exec = Some(false),
                "atime" => parsed.atime = Some(AtimeMode::Atime),
                "noatime" => parsed.atime = Some(AtimeMode::NoAtime),
                "sync" => parsed.sync = Some(SyncMode::Sync),
                "async" => parsed.sync = Some(SyncMode::Async),
                "dirsync" => parsed.dirsync = true,
                "relatime" if is_remount => parsed.atime = Some(AtimeMode::Relatime),
                "norelatime" if is_remount => parsed.atime = Some(AtimeMode::NoRelatime),
                "strictatime" if is_remount => parsed.atime = Some(AtimeMode::StrictAtime),
                "nostrictatime" if is_remount => parsed.atime = Some(AtimeMode::NoStrictAtime),
                "diratime" if is_remount => parsed.diratime = Some(true),
                "nodiratime" if is_remount => parsed.diratime = Some(false),
                "lazytime" if is_remount => parsed.lazytime = Some(true),
                "nolazytime" if is_remount => parsed.lazytime = Some(false),
                "iversion" if is_remount => parsed.iversion = Some(true),
                "noiversion" if is_remount => parsed.iversion = Some(false),
                other => return Err(other.to_owned()),
            }
        }
        Ok(parsed)
    }

    /// Applies `requested` remount overrides onto `self` (the mount's current
    /// VFS flags from `/proc/self/mountinfo`), preserving every flag not
    /// overridden.
    pub fn apply(&self, requested: &Self) -> Self {
        Self {
            remount: true,
            read_only: requested.read_only.or(self.read_only),
            suid: requested.suid.or(self.suid),
            dev: requested.dev.or(self.dev),
            exec: requested.exec.or(self.exec),
            atime: requested.atime.or(self.atime),
            diratime: requested.diratime.or(self.diratime),
            sync: requested.sync.or(self.sync),
            dirsync: requested.dirsync || self.dirsync,
            lazytime: requested.lazytime.or(self.lazytime),
            iversion: requested.iversion.or(self.iversion),
        }
    }

    /// Formats the VFS options as a `-o` argument for `mount -i -o remount,...`.
    /// Never includes FUSE-specific super options (`user_id`, `allow_other`,
    /// `default_permissions`), which Linux's `fuse_parse_param` rejects during
    /// `FS_CONTEXT_FOR_RECONFIGURE` under the new mount API.
    pub fn to_remount_option_string(&self) -> String {
        let mut parts = vec!["remount"];
        if let Some(ro) = self.read_only {
            parts.push(if ro { "ro" } else { "rw" });
        }
        if let Some(suid) = self.suid {
            parts.push(if suid { "suid" } else { "nosuid" });
        }
        if let Some(dev) = self.dev {
            parts.push(if dev { "dev" } else { "nodev" });
        }
        if let Some(exec) = self.exec {
            parts.push(if exec { "exec" } else { "noexec" });
        }
        if let Some(atime) = self.atime {
            parts.push(match atime {
                AtimeMode::Atime => "atime",
                AtimeMode::NoAtime => "noatime",
                AtimeMode::Relatime => "relatime",
                AtimeMode::NoRelatime => "norelatime",
                AtimeMode::StrictAtime => "strictatime",
                AtimeMode::NoStrictAtime => "nostrictatime",
            });
        }
        if let Some(diratime) = self.diratime {
            parts.push(if diratime { "diratime" } else { "nodiratime" });
        }
        if let Some(sync) = self.sync {
            parts.push(match sync {
                SyncMode::Sync => "sync",
                SyncMode::Async => "async",
            });
        }
        if self.dirsync {
            parts.push("dirsync");
        }
        if let Some(lazytime) = self.lazytime {
            parts.push(if lazytime { "lazytime" } else { "nolazytime" });
        }
        if let Some(iversion) = self.iversion {
            parts.push(if iversion { "iversion" } else { "noiversion" });
        }
        parts.join(",")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn last_conflicting_option_wins() {
        let opts = MountOptions::parse(Some("ro,rw,nosuid,suid,nodev,dev,noexec,exec")).unwrap();
        assert!(!opts.remount);
        assert_eq!(opts.read_only, Some(false));
        assert_eq!(opts.suid, Some(true));
        assert_eq!(opts.dev, Some(true));
        assert_eq!(opts.exec, Some(true));

        let opts = MountOptions::parse(Some("rw,remount,ro")).unwrap();
        assert!(opts.remount);
        assert_eq!(opts.read_only, Some(true));
    }

    #[test]
    fn initial_mount_rejects_unsupported_options() {
        assert_eq!(MountOptions::parse(Some("dax")), Err("dax".to_owned()));
        assert_eq!(
            MountOptions::parse(Some("ro,norecovery")),
            Err("norecovery".to_owned())
        );
        assert_eq!(
            MountOptions::parse(Some("relatime")),
            Err("relatime".to_owned())
        );
    }

    #[test]
    fn remount_accepts_vfs_flags_and_rejects_fs_specific_options() {
        let opts = MountOptions::parse(Some("rw,relatime,remount,ro,noexec,nodiratime")).unwrap();
        assert!(opts.remount);
        assert_eq!(opts.read_only, Some(true));
        assert_eq!(opts.exec, Some(false));
        assert_eq!(opts.atime, Some(AtimeMode::Relatime));
        assert_eq!(opts.diratime, Some(false));

        assert_eq!(
            MountOptions::parse(Some("remount,dax")),
            Err("dax".to_owned())
        );
        assert_eq!(
            MountOptions::parse(Some("remount,allow_other")),
            Err("allow_other".to_owned())
        );
    }

    #[test]
    fn apply_preserves_unspecified_flags_and_overrides_specified_ones() {
        let current = MountOptions {
            remount: false,
            read_only: Some(false),
            suid: Some(false),
            dev: Some(false),
            exec: Some(true),
            atime: Some(AtimeMode::Relatime),
            diratime: Some(true),
            sync: Some(SyncMode::Async),
            dirsync: false,
            lazytime: None,
            iversion: None,
        };
        let requested = MountOptions::parse(Some("remount,ro,noexec")).unwrap();
        let merged = current.apply(&requested);
        assert_eq!(
            merged.to_remount_option_string(),
            "remount,ro,nosuid,nodev,noexec,relatime,diratime,async"
        );

        let keep_ro = MountOptions::parse(Some("remount,suid")).unwrap();
        let merged_again = merged.apply(&keep_ro);
        assert_eq!(
            merged_again.to_remount_option_string(),
            "remount,ro,suid,nodev,noexec,relatime,diratime,async"
        );
    }
}
