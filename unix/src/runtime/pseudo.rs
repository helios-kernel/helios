//! Pseudo character devices (`/dev/null`, `/dev/zero`, `/dev/full`,
//! `/dev/random`, `/dev/urandom`, `/dev/tty`, `/dev/console`).
//!
//! Device numbers follow Linux's `Documentation/admin-guide/devices.txt` and
//! `include/linux/kdev_t.h` `new_encode_dev` encoding.

/// Character device major number for memory pseudo-devices (`null`, `zero`,
/// `full`, `random`, `urandom`).
pub const CHAR_MAJOR_MEM: u32 = 1;
/// Character device major number for TTY/console/ptmx devices.
pub const CHAR_MAJOR_TTY: u32 = 5;
/// First character device major number for UNIX98 PTY slaves (`/dev/pts/*`).
pub const CHAR_MAJOR_UNIX98_PTY_SLAVE: u32 = 136;

/// Encodes `(major, minor)` using Linux `new_encode_dev` (`include/linux/kdev_t.h`).
pub const fn encode_dev(major: u32, minor: u32) -> u64 {
    ((minor & 0xff) as u64)
        | (((major & 0xfff) as u64) << 8)
        | (((minor & !0xff) as u64) << 12)
        | (((major & !0xfff) as u64) << 32)
}

/// Which kernel pseudo character device an open descriptor refers to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PseudoDeviceKind {
    /// `1:3` `/dev/null`
    Null,
    /// `1:5` `/dev/zero`
    Zero,
    /// `1:7` `/dev/full`
    Full,
    /// `1:8` `/dev/random`
    Random,
    /// `1:9` `/dev/urandom`
    Urandom,
    /// `5:0` `/dev/tty` (bound to container stdio terminal when no PTY is attached)
    Tty,
    /// `5:1` `/dev/console` (bound to container stdio terminal)
    Console,
}

impl PseudoDeviceKind {
    /// Returns the Linux `(major, minor)` device number pair for this pseudo device.
    pub const fn major_minor(self) -> (u32, u32) {
        match self {
            Self::Null => (CHAR_MAJOR_MEM, 3),
            Self::Zero => (CHAR_MAJOR_MEM, 5),
            Self::Full => (CHAR_MAJOR_MEM, 7),
            Self::Random => (CHAR_MAJOR_MEM, 8),
            Self::Urandom => (CHAR_MAJOR_MEM, 9),
            Self::Tty => (CHAR_MAJOR_TTY, 0),
            Self::Console => (CHAR_MAJOR_TTY, 1),
        }
    }

    /// Returns the Linux `new_encode_dev` device number for this pseudo device.
    pub const fn default_rdev(self) -> u64 {
        let (major, minor) = self.major_minor();
        encode_dev(major, minor)
    }

    /// Default path name for `/proc/<pid>/fd/<n>` links.
    pub const fn default_path(self) -> &'static str {
        match self {
            Self::Null => "/dev/null",
            Self::Zero => "/dev/zero",
            Self::Full => "/dev/full",
            Self::Random => "/dev/random",
            Self::Urandom => "/dev/urandom",
            Self::Tty => "/dev/tty",
            Self::Console => "/dev/console",
        }
    }

    /// Whether `epoll_ctl` refuses monitoring this device with `EPERM`
    /// (`drivers/char/mem.c`: `null`, `zero`, `full` have no `poll` op so
    /// `epoll_ctl` returns `EPERM`, while `poll(2)` reports `POLLIN | POLLOUT`).
    pub const fn refuses_epoll(self) -> bool {
        matches!(self, Self::Null | Self::Zero | Self::Full)
    }
}

/// An open descriptor referring to a pseudo character device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PseudoDevice {
    pub kind: PseudoDeviceKind,
    pub readable: bool,
    pub writable: bool,
    pub dev: u64,
    pub ino: u64,
    pub rdev: u64,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
}

impl PseudoDevice {
    pub const fn new(kind: PseudoDeviceKind, readable: bool, writable: bool) -> Self {
        Self {
            kind,
            readable,
            writable,
            dev: 1,
            ino: 1,
            rdev: kind.default_rdev(),
            uid: 0,
            gid: 0,
            mode: 0o666,
        }
    }
}
