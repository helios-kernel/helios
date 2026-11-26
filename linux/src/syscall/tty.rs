//! Terminal and generic descriptor `ioctl` system calls: `TCGETS`, `TCSETS*`,
//! `TIOCGWINSZ`, `TIOCSWINSZ`, `FIONBIO`, `FIOCLEX`, `FIONCLEX`, and `FIONREAD`.
//!
//! Layout and request numbers follow Linux v6.12 `include/uapi/asm-generic/termbits.h`,
//! `termios.h`, and `ioctls.h` (identical on x86-64 and aarch64).

use super::*;
use helios_unix::{FDFLAG_NONBLOCK, PtyTermios, PtyWinsize};

// include/uapi/asm-generic/ioctls.h
pub const TCGETS: u32 = 0x5401;
pub const TCSETS: u32 = 0x5402;
pub const TCSETSW: u32 = 0x5403;
pub const TCSETSF: u32 = 0x5404;
pub const TIOCSCTTY: u32 = 0x540E;
pub const TIOCGPGRP: u32 = 0x540F;
pub const TIOCSPGRP: u32 = 0x5410;
pub const TIOCGWINSZ: u32 = 0x5413;
pub const TIOCSWINSZ: u32 = 0x5414;
pub const FIONREAD: u32 = 0x541B;
pub const FIONBIO: u32 = 0x5421;
pub const TIOCNOTTY: u32 = 0x5422;
pub const TIOCGSID: u32 = 0x5429;
pub const FIONCLEX: u32 = 0x5450;
pub const FIOCLEX: u32 = 0x5451;
/// `_IOR('T', 0x30, unsigned int)`: get UNIX98 PTY number.
pub const TIOCGPTN: u32 = 0x8004_5430;
/// `_IOW('T', 0x31, int)`: lock/unlock UNIX98 PTY slave.
pub const TIOCSPTLCK: u32 = 0x4004_5431;
/// `_IOR('T', 0x39, int)`: query UNIX98 PTY slave lock state.
pub const TIOCGPTLCK: u32 = 0x8004_5439;

// include/uapi/asm-generic/termbits-common.h and termbits.h
pub const ICRNL: u32 = 0x0100;
pub const IXON: u32 = 0x0400;
pub const OPOST: u32 = 0x0001;
pub const ONLCR: u32 = 0x0004;
pub const B38400: u32 = 0x000f;
pub const CS8: u32 = 0x0030;
pub const CREAD: u32 = 0x0080;
pub const ISIG: u32 = 0x0001;
pub const ICANON: u32 = 0x0002;
pub const ECHO: u32 = 0x0008;
pub const ECHOE: u32 = 0x0010;
pub const ECHOK: u32 = 0x0020;

const NCCS: usize = 19;
const TERMIOS_SIZE: usize = 36;
const WINSIZE_SIZE: usize = 8;

/// Which standard stream a terminal `ioctl` targets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TtyStream {
    Stdin,
    Stdout,
    Stderr,
}

/// Which `TCSETS*` variant the caller requested.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TermiosAction {
    /// `TCSETS`: apply immediately.
    Now,
    /// `TCSETSW`: drain output before applying.
    Drain,
    /// `TCSETSF`: drain output and discard unread input before applying.
    Flush,
}

/// Linux `struct termios` (36 bytes on both x86-64 and aarch64).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Termios {
    pub iflag: u32,
    pub oflag: u32,
    pub cflag: u32,
    pub lflag: u32,
    pub line: u8,
    pub cc: [u8; NCCS],
}

impl Termios {
    /// Default Linux terminal configuration aligned with WASIX `tty_get`/`tty_set`
    /// flags (`echo`, `line_buffered`, `line_feeds`).
    pub const fn from_flags(echo: bool, line_buffered: bool, line_feeds: bool) -> Self {
        let oflag = OPOST | if line_feeds { ONLCR } else { 0 };
        let lflag = ISIG
            | ECHOE
            | ECHOK
            | if line_buffered { ICANON } else { 0 }
            | if echo { ECHO } else { 0 };
        // Default control characters from Linux `include/asm-generic/termios.h` `INIT_C_CC`.
        let cc = [
            3,   // VINTR  (^C)
            28,  // VQUIT  (^\)
            127, // VERASE (DEL)
            21,  // VKILL  (^U)
            4,   // VEOF   (^D)
            0,   // VTIME
            1,   // VMIN
            0,   // VSWTC
            17,  // VSTART (^Q)
            19,  // VSTOP  (^S)
            26,  // VSUSP  (^Z)
            0,   // VEOL
            18,  // VREPRINT (^R)
            15,  // VDISCARD (^O)
            23,  // VWERASE  (^W)
            22,  // VLNEXT   (^V)
            0,   // VEOL2
            0,   // spare
            0,   // spare
        ];
        Self {
            iflag: ICRNL | IXON,
            oflag,
            cflag: B38400 | CS8 | CREAD,
            lflag,
            line: 0,
            cc,
        }
    }

    pub const fn echo(&self) -> bool {
        self.lflag & ECHO != 0
    }

    pub const fn line_buffered(&self) -> bool {
        self.lflag & ICANON != 0
    }

    pub const fn line_feeds(&self) -> bool {
        self.oflag & ONLCR != 0
    }

    pub fn to_bytes(self) -> [u8; TERMIOS_SIZE] {
        let mut out = [0u8; TERMIOS_SIZE];
        out[0..4].copy_from_slice(&self.iflag.to_le_bytes());
        out[4..8].copy_from_slice(&self.oflag.to_le_bytes());
        out[8..12].copy_from_slice(&self.cflag.to_le_bytes());
        out[12..16].copy_from_slice(&self.lflag.to_le_bytes());
        out[16] = self.line;
        out[17..36].copy_from_slice(&self.cc);
        out
    }

    pub fn from_bytes(bytes: &[u8; TERMIOS_SIZE]) -> Self {
        let mut cc = [0u8; NCCS];
        cc.copy_from_slice(&bytes[17..36]);
        Self {
            iflag: u32::from_le_bytes(bytes[0..4].try_into().unwrap()),
            oflag: u32::from_le_bytes(bytes[4..8].try_into().unwrap()),
            cflag: u32::from_le_bytes(bytes[8..12].try_into().unwrap()),
            lflag: u32::from_le_bytes(bytes[12..16].try_into().unwrap()),
            line: bytes[16],
            cc,
        }
    }

    pub const fn from_pty(pty: PtyTermios) -> Self {
        Self {
            iflag: pty.iflag,
            oflag: pty.oflag,
            cflag: pty.cflag,
            lflag: pty.lflag,
            line: pty.line,
            cc: pty.cc,
        }
    }

    pub const fn into_pty(self) -> PtyTermios {
        PtyTermios {
            iflag: self.iflag,
            oflag: self.oflag,
            cflag: self.cflag,
            lflag: self.lflag,
            line: self.line,
            cc: self.cc,
        }
    }
}

/// Linux `struct winsize` (8 bytes on both x86-64 and aarch64).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Winsize {
    pub rows: u16,
    pub cols: u16,
    pub xpixel: u16,
    pub ypixel: u16,
}

impl Winsize {
    pub const DEFAULT: Self = Self {
        rows: 24,
        cols: 80,
        xpixel: 0,
        ypixel: 0,
    };

    pub fn to_bytes(self) -> [u8; WINSIZE_SIZE] {
        let mut out = [0u8; WINSIZE_SIZE];
        out[0..2].copy_from_slice(&self.rows.to_le_bytes());
        out[2..4].copy_from_slice(&self.cols.to_le_bytes());
        out[4..6].copy_from_slice(&self.xpixel.to_le_bytes());
        out[6..8].copy_from_slice(&self.ypixel.to_le_bytes());
        out
    }

    pub fn from_bytes(bytes: &[u8; WINSIZE_SIZE]) -> Self {
        Self {
            rows: u16::from_le_bytes(bytes[0..2].try_into().unwrap()),
            cols: u16::from_le_bytes(bytes[2..4].try_into().unwrap()),
            xpixel: u16::from_le_bytes(bytes[4..6].try_into().unwrap()),
            ypixel: u16::from_le_bytes(bytes[6..8].try_into().unwrap()),
        }
    }

    pub const fn from_pty(pty: PtyWinsize) -> Self {
        Self {
            rows: pty.rows,
            cols: pty.cols,
            xpixel: pty.xpixel,
            ypixel: pty.ypixel,
        }
    }

    pub const fn into_pty(self) -> PtyWinsize {
        PtyWinsize {
            rows: self.rows,
            cols: self.cols,
            xpixel: self.xpixel,
            ypixel: self.ypixel,
        }
    }
}

/// Why a terminal `ioctl` was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum TtyError {
    #[error("descriptor is not a terminal")]
    NotTty,
    #[error("container authority does not grant terminal control")]
    Denied,
}

/// Host terminal state for `TCGETS`/`TCSETS*`/`TIOCGWINSZ`/`TIOCSWINSZ`.
pub trait Tty {
    fn is_tty(&self, _stream: TtyStream) -> bool {
        false
    }

    fn get_termios(&self, _stream: TtyStream) -> Result<Termios, TtyError> {
        Err(TtyError::NotTty)
    }

    fn set_termios(
        &mut self,
        _stream: TtyStream,
        _termios: Termios,
        _action: TermiosAction,
    ) -> Result<(), TtyError> {
        Err(TtyError::NotTty)
    }

    fn get_winsize(&self, _stream: TtyStream) -> Result<Winsize, TtyError> {
        Err(TtyError::NotTty)
    }

    fn set_winsize(&mut self, _stream: TtyStream, _winsize: Winsize) -> Result<(), TtyError> {
        Err(TtyError::NotTty)
    }

    fn controlling_pty(&self) -> Option<helios_unix::PtySlave> {
        None
    }

    fn set_controlling_pty(&mut self, _pty: Option<helios_unix::PtySlave>) {}
}

fn tty_errno(error: TtyError) -> u64 {
    errno(match error {
        TtyError::NotTty => ENOTTY,
        TtyError::Denied => EPERM,
    })
}

pub(super) async fn ioctl<R: Resources, M: UserMemory, T: Tty>(
    process: &Process<R>,
    args: [u64; 6],
    memory: &mut M,
    tty: &mut T,
) -> u64 {
    let fd = args[0] as u32 as i32;
    let request = args[1] as u32;
    let arg = args[2];

    let entry = {
        let mut table = process.shared.descriptors.lock();
        match request {
            FIOCLEX => {
                return match table.get_entry_mut(fd) {
                    Some(entry) => {
                        entry.close_on_exec = true;
                        0
                    }
                    None => errno(EBADF),
                };
            }
            FIONCLEX => {
                return match table.get_entry_mut(fd) {
                    Some(entry) => {
                        entry.close_on_exec = false;
                        0
                    }
                    None => errno(EBADF),
                };
            }
            _ => match table.get_entry(fd).cloned() {
                Some(entry) => entry,
                None => return errno(EBADF),
            },
        }
    };

    if entry.fdflags() & helios_unix::FDFLAG_PATH != 0 {
        return errno(EBADF);
    }

    if request == FIONBIO {
        let mut raw = [0u8; 4];
        if memory.read(arg, &mut raw).await.is_err() {
            return errno(EFAULT);
        }
        let enable = i32::from_le_bytes(raw) != 0;
        let current = entry.fdflags();
        let next = if enable {
            current | FDFLAG_NONBLOCK
        } else {
            current & !FDFLAG_NONBLOCK
        };
        entry.set_fdflags(next);
        if let FileDescriptor::Socket(sock) = &entry.descriptor {
            sock.set_nonblocking(enable);
        }
        return 0;
    }

    if request == FIONREAD {
        let available = match &entry.descriptor {
            FileDescriptor::PtyMaster(master) => Some(master.readable_bytes()),
            FileDescriptor::PtySlave(slave) => Some(slave.readable_bytes()),
            FileDescriptor::FifoRead(reader) => Some(reader.buffered_bytes()),
            FileDescriptor::FifoReadWrite(rw) => Some(rw.buffered_bytes()),
            FileDescriptor::PipeRead { .. } => Some(0),
            FileDescriptor::Stdin { .. } => Some(process.shared.stdin_carry.lock().len()),
            _ => None,
        };
        if let Some(bytes) = available {
            let count = i32::try_from(bytes).unwrap_or(i32::MAX);
            return match memory.write(arg, &count.to_le_bytes()).await {
                Ok(()) => 0,
                Err(_) => errno(EFAULT),
            };
        }
        return errno(ENOTTY);
    }

    if let FileDescriptor::PtyMaster(master) = &entry.descriptor {
        return match request {
            TIOCGPTN => match memory.write(arg, &master.index().to_le_bytes()).await {
                Ok(()) => 0,
                Err(_) => errno(EFAULT),
            },
            TIOCSPTLCK => {
                let mut raw = [0u8; 4];
                if memory.read(arg, &mut raw).await.is_err() {
                    return errno(EFAULT);
                }
                master.set_locked(i32::from_le_bytes(raw) != 0);
                0
            }
            TIOCGPTLCK => {
                let locked = i32::from(master.is_locked());
                match memory.write(arg, &locked.to_le_bytes()).await {
                    Ok(()) => 0,
                    Err(_) => errno(EFAULT),
                }
            }
            TCGETS => {
                let termios = Termios::from_pty(master.termios());
                match memory.write(arg, &termios.to_bytes()).await {
                    Ok(()) => 0,
                    Err(_) => errno(EFAULT),
                }
            }
            TCSETS | TCSETSW | TCSETSF => {
                let mut raw = [0u8; TERMIOS_SIZE];
                if memory.read(arg, &mut raw).await.is_err() {
                    return errno(EFAULT);
                }
                master.set_termios(Termios::from_bytes(&raw).into_pty(), request == TCSETSF);
                0
            }
            TIOCGWINSZ => {
                let ws = Winsize::from_pty(master.winsize());
                match memory.write(arg, &ws.to_bytes()).await {
                    Ok(()) => 0,
                    Err(_) => errno(EFAULT),
                }
            }
            TIOCSWINSZ => {
                let mut raw = [0u8; WINSIZE_SIZE];
                if memory.read(arg, &mut raw).await.is_err() {
                    return errno(EFAULT);
                }
                master.set_winsize(Winsize::from_bytes(&raw).into_pty());
                0
            }
            TIOCGPGRP => {
                let pgrp = master.fg_pgrp() as i32;
                match memory.write(arg, &pgrp.to_le_bytes()).await {
                    Ok(()) => 0,
                    Err(_) => errno(EFAULT),
                }
            }
            TIOCSPGRP => {
                let mut raw = [0u8; 4];
                if memory.read(arg, &mut raw).await.is_err() {
                    return errno(EFAULT);
                }
                let pgrp = i32::from_le_bytes(raw);
                if pgrp <= 0 {
                    return errno(EINVAL);
                }
                master.set_fg_pgrp(pgrp as u32);
                0
            }
            TIOCGSID => match master.session_id() {
                Some(sid) => match memory.write(arg, &(sid as i32).to_le_bytes()).await {
                    Ok(()) => 0,
                    Err(_) => errno(EFAULT),
                },
                None => errno(ENOTTY),
            },
            _ => errno(ENOTTY),
        };
    }

    if let FileDescriptor::PtySlave(slave) = &entry.descriptor {
        return match request {
            TCGETS => {
                let termios = Termios::from_pty(slave.termios());
                match memory.write(arg, &termios.to_bytes()).await {
                    Ok(()) => 0,
                    Err(_) => errno(EFAULT),
                }
            }
            TCSETS | TCSETSW | TCSETSF => {
                let mut raw = [0u8; TERMIOS_SIZE];
                if memory.read(arg, &mut raw).await.is_err() {
                    return errno(EFAULT);
                }
                slave.set_termios(Termios::from_bytes(&raw).into_pty(), request == TCSETSF);
                0
            }
            TIOCGWINSZ => {
                let ws = Winsize::from_pty(slave.winsize());
                match memory.write(arg, &ws.to_bytes()).await {
                    Ok(()) => 0,
                    Err(_) => errno(EFAULT),
                }
            }
            TIOCSWINSZ => {
                let mut raw = [0u8; WINSIZE_SIZE];
                if memory.read(arg, &mut raw).await.is_err() {
                    return errno(EFAULT);
                }
                slave.set_winsize(Winsize::from_bytes(&raw).into_pty());
                0
            }
            TIOCSCTTY => {
                let pid = process.pid().get();
                let sid = process
                    .shared
                    .pids
                    .sid(pid)
                    .map_or(pid, core::num::NonZeroU32::get);
                let pgid = process.shared.signals.pgid();
                if let Some(current_ctty) = tty.controlling_pty()
                    && current_ctty.same_pty(slave)
                {
                    return 0;
                }
                if pid != sid || tty.controlling_pty().is_some() {
                    return errno(EPERM);
                }
                if let Some(owner_sid) = slave.session_id()
                    && owner_sid != sid
                {
                    let steal = arg == 1
                        && process
                            .credentials
                            .lock()
                            .capabilities
                            .has_effective(CAP_SYS_ADMIN);
                    if !steal {
                        return errno(EPERM);
                    }
                }
                slave.set_session_id(Some(sid));
                slave.set_fg_pgrp(pgid);
                tty.set_controlling_pty(Some(slave.clone()));
                0
            }
            TIOCNOTTY => {
                let pid = process.pid().get();
                let sid = process
                    .shared
                    .pids
                    .sid(pid)
                    .map_or(pid, core::num::NonZeroU32::get);
                if let Some(current_ctty) = tty.controlling_pty()
                    && current_ctty.same_pty(slave)
                {
                    if slave.session_id() == Some(sid) {
                        slave.set_session_id(None);
                    }
                    tty.set_controlling_pty(None);
                    0
                } else {
                    errno(ENOTTY)
                }
            }
            TIOCGPGRP => {
                let pgrp = slave.fg_pgrp();
                let reported = if pgrp != 0 {
                    pgrp as i32
                } else {
                    process.shared.signals.pgid() as i32
                };
                match memory.write(arg, &reported.to_le_bytes()).await {
                    Ok(()) => 0,
                    Err(_) => errno(EFAULT),
                }
            }
            TIOCSPGRP => {
                let mut raw = [0u8; 4];
                if memory.read(arg, &mut raw).await.is_err() {
                    return errno(EFAULT);
                }
                let pgrp = i32::from_le_bytes(raw);
                if pgrp <= 0 {
                    return errno(EINVAL);
                }
                slave.set_fg_pgrp(pgrp as u32);
                0
            }
            TIOCGSID => match slave.session_id() {
                Some(sid) => match memory.write(arg, &(sid as i32).to_le_bytes()).await {
                    Ok(()) => 0,
                    Err(_) => errno(EFAULT),
                },
                None => errno(ENOTTY),
            },
            _ => errno(ENOTTY),
        };
    }

    let stream = match &entry.descriptor {
        FileDescriptor::Stdin { .. } => TtyStream::Stdin,
        FileDescriptor::Stdout => TtyStream::Stdout,
        FileDescriptor::Stderr => TtyStream::Stderr,
        FileDescriptor::PseudoDevice(dev)
            if matches!(
                dev.kind,
                helios_unix::PseudoDeviceKind::Tty | helios_unix::PseudoDeviceKind::Console
            ) =>
        {
            TtyStream::Stdin
        }
        _ => return errno(ENOTTY),
    };

    match request {
        TIOCGPGRP => {
            if !tty.is_tty(stream) {
                return errno(ENOTTY);
            }
            let pgrp = process.shared.signals.pgid() as i32;
            match memory.write(arg, &pgrp.to_le_bytes()).await {
                Ok(()) => 0,
                Err(_) => errno(EFAULT),
            }
        }
        TIOCSPGRP => {
            if !tty.is_tty(stream) {
                return errno(ENOTTY);
            }
            let mut raw = [0u8; 4];
            if memory.read(arg, &mut raw).await.is_err() {
                return errno(EFAULT);
            }
            if i32::from_le_bytes(raw) <= 0 {
                return errno(EINVAL);
            }
            0
        }
        TCGETS => match tty.get_termios(stream) {
            Ok(termios) => match memory.write(arg, &termios.to_bytes()).await {
                Ok(()) => 0,
                Err(_) => errno(EFAULT),
            },
            Err(error) => tty_errno(error),
        },
        TCSETS | TCSETSW | TCSETSF => {
            if !tty.is_tty(stream) {
                return errno(ENOTTY);
            }
            let mut raw = [0u8; TERMIOS_SIZE];
            if memory.read(arg, &mut raw).await.is_err() {
                return errno(EFAULT);
            }
            let action = match request {
                TCSETS => TermiosAction::Now,
                TCSETSW => TermiosAction::Drain,
                TCSETSF => TermiosAction::Flush,
                _ => unreachable!(),
            };
            match tty.set_termios(stream, Termios::from_bytes(&raw), action) {
                Ok(()) => {
                    if action == TermiosAction::Flush {
                        process.shared.stdin_carry.lock().clear();
                    }
                    0
                }
                Err(error) => tty_errno(error),
            }
        }
        TIOCGWINSZ => match tty.get_winsize(stream) {
            Ok(winsize) => match memory.write(arg, &winsize.to_bytes()).await {
                Ok(()) => 0,
                Err(_) => errno(EFAULT),
            },
            Err(error) => tty_errno(error),
        },
        TIOCSWINSZ => {
            if !tty.is_tty(stream) {
                return errno(ENOTTY);
            }
            let mut raw = [0u8; WINSIZE_SIZE];
            if memory.read(arg, &mut raw).await.is_err() {
                return errno(EFAULT);
            }
            match tty.set_winsize(stream, Winsize::from_bytes(&raw)) {
                Ok(()) => 0,
                Err(error) => tty_errno(error),
            }
        }
        _ => errno(ENOTTY),
    }
}
