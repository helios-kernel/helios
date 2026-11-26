//! UNIX98 pseudo-terminal (`ptmx` master / `/dev/pts/<n>` slave) pair state
//! and `n_tty` line discipline (`drivers/tty/pty.c`, `drivers/tty/n_tty.c`).
//!
//! # Concurrency contract
//!
//! Every mutable field lives under one short synchronous `spin::Mutex`, never
//! held across an `.await`. Blocking reads arm a [`NotifyWaiter`] before
//! testing the buffer or close state so no wake-up can be lost.

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use core::future::poll_fn;
use core::task::{Context, Poll};

use bytes::Bytes;
use helios_sync::{Notify, NotifyWaiter};

use crate::Signal;

// Linux `include/uapi/asm-generic/termbits.h` flags used by the line discipline.
const ICRNL: u32 = 0x0100;
const IXON: u32 = 0x0400;
const OPOST: u32 = 0x0001;
const ONLCR: u32 = 0x0004;
const B38400: u32 = 0x000f;
const CS8: u32 = 0x0030;
const CREAD: u32 = 0x0080;
const ISIG: u32 = 0x0001;
const ICANON: u32 = 0x0002;
const ECHO: u32 = 0x0008;
const ECHOE: u32 = 0x0010;
const ECHOK: u32 = 0x0020;

// Control-character indices (`include/uapi/asm-generic/termbits-common.h`).
const VINTR: usize = 0;
const VQUIT: usize = 1;
const VERASE: usize = 2;
const VKILL: usize = 3;
const VEOF: usize = 4;
const VEOL: usize = 11;
const VSUSP: usize = 10;

/// Number of `c_cc` entries in Linux `struct termios` (x86-64 and aarch64).
pub const PTY_NCCS: usize = 19;

/// Raw Linux `struct termios` fields stored on a PTY pair.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PtyTermios {
    pub iflag: u32,
    pub oflag: u32,
    pub cflag: u32,
    pub lflag: u32,
    pub line: u8,
    pub cc: [u8; PTY_NCCS],
}

impl Default for PtyTermios {
    fn default() -> Self {
        Self {
            iflag: ICRNL | IXON,
            oflag: OPOST | ONLCR,
            cflag: B38400 | CS8 | CREAD,
            lflag: ISIG | ICANON | ECHO | ECHOE | ECHOK,
            line: 0,
            // Linux `include/asm-generic/termios.h` `INIT_C_CC`.
            cc: [
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
            ],
        }
    }
}

/// Linux `struct winsize` stored on a PTY pair.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PtyWinsize {
    pub rows: u16,
    pub cols: u16,
    pub xpixel: u16,
    pub ypixel: u16,
}

impl Default for PtyWinsize {
    fn default() -> Self {
        Self {
            rows: 24,
            cols: 80,
            xpixel: 0,
            ypixel: 0,
        }
    }
}

/// Errors produced by PTY operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PtyError {
    #[error("operation would block")]
    WouldBlock,
    #[error("pseudo-terminal peer is closed")]
    Closed,
    #[error("pseudo-terminal slave is locked")]
    Locked,
}

/// Outcome of a non-blocking PTY read.
#[derive(Debug, PartialEq, Eq)]
pub enum PtyTryRead {
    Ready(Bytes),
    Eof,
    Closed,
    WouldBlock,
}

struct PtyState {
    /// UNIX98 slave lock (`TIOCSPTLCK`); starts locked per Linux `ptmx_open`.
    locked: bool,
    master_closed: bool,
    slave_opens: usize,
    /// Set once the last open slave closes; cleared again if another slave opens.
    slave_hung_up: bool,
    termios: PtyTermios,
    winsize: PtyWinsize,
    /// Foreground process group (`TIOCGPGRP` / `TIOCSPGRP`), 0 if unset.
    fg_pgrp: u32,
    /// Controlling session ID (`TIOCSCTTY`), `None` if detached.
    session_id: Option<u32>,
    uid: u32,
    gid: u32,
    mode: u32,
    /// Canonical line edit buffer (master -> slave input before newline/EOF).
    canon_line: alloc::vec::Vec<u8>,
    /// Committed bytes waiting for slave `read(2)`.
    slave_rx: VecDeque<u8>,
    /// Pending zero-byte canonical `VEOF` barriers for slave `read(2)`.
    slave_eof_markers: usize,
    /// Bytes waiting for master `read(2)` (slave output + canonical echo).
    master_rx: VecDeque<u8>,
}

struct PtyInner {
    index: u32,
    state: spin::Mutex<PtyState>,
    master_notify: Notify,
    slave_notify: Notify,
}

impl PtyInner {
    fn new(index: u32, uid: u32, gid: u32) -> Self {
        Self {
            index,
            state: spin::Mutex::new(PtyState {
                locked: true,
                master_closed: false,
                slave_opens: 0,
                slave_hung_up: false,
                termios: PtyTermios::default(),
                winsize: PtyWinsize::default(),
                fg_pgrp: 0,
                session_id: None,
                uid,
                gid,
                mode: 0o620,
                canon_line: alloc::vec::Vec::new(),
                slave_rx: VecDeque::new(),
                slave_eof_markers: 0,
                master_rx: VecDeque::new(),
            }),
            master_notify: Notify::new(),
            slave_notify: Notify::new(),
        }
    }

    fn echo_output(state: &mut PtyState, bytes: &[u8]) {
        if state.termios.oflag & (OPOST | ONLCR) == (OPOST | ONLCR) {
            for &b in bytes {
                if b == b'\n' {
                    state.master_rx.push_back(b'\r');
                }
                state.master_rx.push_back(b);
            }
        } else {
            state.master_rx.extend(bytes);
        }
    }
}

/// Registry handle for a live UNIX98 PTY pair (`/dev/pts/<index>`).
///
/// Holding a `PtyPair` does not count as an open master or slave descriptor.
#[derive(Clone)]
pub struct PtyPair {
    inner: Arc<PtyInner>,
}

impl PtyPair {
    /// Allocates a new UNIX98 PTY pair with `index`, returning `(master, pair)`.
    pub fn create(index: u32, uid: u32, gid: u32) -> (PtyMaster, Self) {
        let inner = Arc::new(PtyInner::new(index, uid, gid));
        let master = PtyMaster(Arc::new(PtyMasterGuard(inner.clone())));
        let pair = Self { inner };
        (master, pair)
    }

    pub fn index(&self) -> u32 {
        self.inner.index
    }

    pub fn is_alive(&self) -> bool {
        !self.inner.state.lock().master_closed
    }

    pub fn is_locked(&self) -> bool {
        self.inner.state.lock().locked
    }

    pub fn attrs(&self) -> (u32, u32, u32) {
        let state = self.inner.state.lock();
        (state.uid, state.gid, state.mode)
    }

    pub fn set_mode(&self, mode: u32) {
        self.inner.state.lock().mode = mode & 0o7777;
    }

    pub fn set_owner(&self, uid: Option<u32>, gid: Option<u32>) {
        let mut state = self.inner.state.lock();
        if let Some(uid) = uid {
            state.uid = uid;
        }
        if let Some(gid) = gid {
            state.gid = gid;
        }
    }

    /// Opens the slave end (`/dev/pts/<index>`). Fails with [`PtyError::Locked`]
    /// until the master unlocks it via `TIOCSPTLCK(0)`, or [`PtyError::Closed`]
    /// if the master has already closed.
    pub fn open_slave(&self) -> Result<PtySlave, PtyError> {
        {
            let mut state = self.inner.state.lock();
            if state.master_closed {
                return Err(PtyError::Closed);
            }
            if state.locked {
                return Err(PtyError::Locked);
            }
            state.slave_opens += 1;
            state.slave_hung_up = false;
        }
        self.inner.master_notify.notify_all();
        Ok(PtySlave(Arc::new(PtySlaveGuard(self.inner.clone()))))
    }
}

struct PtyMasterGuard(Arc<PtyInner>);

impl Drop for PtyMasterGuard {
    fn drop(&mut self) {
        self.0.state.lock().master_closed = true;
        self.0.master_notify.notify_all();
        self.0.slave_notify.notify_all();
    }
}

struct PtySlaveGuard(Arc<PtyInner>);

impl Drop for PtySlaveGuard {
    fn drop(&mut self) {
        let hung_up = {
            let mut state = self.0.state.lock();
            state.slave_opens = state.slave_opens.saturating_sub(1);
            if state.slave_opens == 0 {
                state.slave_hung_up = true;
                true
            } else {
                false
            }
        };
        if hung_up {
            self.0.master_notify.notify_all();
            self.0.slave_notify.notify_all();
        }
    }
}

/// Master side of a UNIX98 PTY (`/dev/ptmx` open description).
#[derive(Clone)]
pub struct PtyMaster(Arc<PtyMasterGuard>);

/// Slave side of a UNIX98 PTY (`/dev/pts/<n>` open description).
#[derive(Clone)]
pub struct PtySlave(Arc<PtySlaveGuard>);

impl PtyMaster {
    pub fn index(&self) -> u32 {
        self.0.0.index
    }

    pub fn is_locked(&self) -> bool {
        self.0.0.state.lock().locked
    }

    pub fn set_locked(&self, locked: bool) {
        self.0.0.state.lock().locked = locked;
    }

    pub fn termios(&self) -> PtyTermios {
        self.0.0.state.lock().termios
    }

    pub fn set_termios(&self, termios: PtyTermios, flush_input: bool) {
        let mut state = self.0.0.state.lock();
        let was_canon = state.termios.lflag & ICANON != 0;
        let now_canon = termios.lflag & ICANON != 0;
        state.termios = termios;
        if flush_input {
            state.canon_line.clear();
            state.slave_rx.clear();
            state.slave_eof_markers = 0;
        } else if was_canon && !now_canon && !state.canon_line.is_empty() {
            // Switching from canonical to raw flushes any partial edited line
            // to the slave read queue.
            let pending = core::mem::take(&mut state.canon_line);
            state.slave_rx.extend(pending);
            drop(state);
            self.0.0.slave_notify.notify_all();
        }
    }

    pub fn winsize(&self) -> PtyWinsize {
        self.0.0.state.lock().winsize
    }

    pub fn set_winsize(&self, winsize: PtyWinsize) {
        self.0.0.state.lock().winsize = winsize;
    }

    pub fn fg_pgrp(&self) -> u32 {
        self.0.0.state.lock().fg_pgrp
    }

    pub fn set_fg_pgrp(&self, pgid: u32) {
        self.0.0.state.lock().fg_pgrp = pgid;
    }

    pub fn session_id(&self) -> Option<u32> {
        self.0.0.state.lock().session_id
    }

    pub fn attrs(&self) -> (u32, u32, u32) {
        let state = self.0.0.state.lock();
        (state.uid, state.gid, state.mode)
    }

    /// Writes `data` from the master into the PTY line discipline, returning
    /// `(written_bytes, optional_signal_for_fg_pgrp)`.
    pub fn write(&self, data: &[u8]) -> (usize, Option<(u32, Signal)>) {
        let mut state = self.0.0.state.lock();
        let mut echoed = false;
        let mut delivered = false;
        let mut signal_to_send = None;

        let icrnl = state.termios.iflag & ICRNL != 0;
        let icanon = state.termios.lflag & ICANON != 0;
        let echo = state.termios.lflag & ECHO != 0;
        let echoe = state.termios.lflag & ECHOE != 0;
        let echok = state.termios.lflag & ECHOK != 0;
        let isig = state.termios.lflag & ISIG != 0;
        let cc = state.termios.cc;

        for &raw in data {
            let byte = if icrnl && raw == b'\r' { b'\n' } else { raw };
            if isig && byte != 0 {
                let sig = if byte == cc[VINTR] {
                    Some(Signal::SIGINT)
                } else if byte == cc[VQUIT] {
                    Some(Signal::SIGQUIT)
                } else if byte == cc[VSUSP] {
                    Some(Signal::SIGTSTP)
                } else {
                    None
                };
                if let Some(sig) = sig {
                    state.canon_line.clear();
                    if state.fg_pgrp != 0 {
                        signal_to_send = Some((state.fg_pgrp, sig));
                    }
                    continue;
                }
            }
            if icanon {
                if byte == cc[VERASE] && byte != 0 {
                    if state.canon_line.pop().is_some() && echo && echoe {
                        state.master_rx.extend(b"\x08 \x08");
                        echoed = true;
                    }
                    continue;
                }
                if byte == cc[VKILL] && byte != 0 {
                    state.canon_line.clear();
                    if echo && echok {
                        PtyInner::echo_output(&mut state, b"\n");
                        echoed = true;
                    }
                    continue;
                }
                if byte == cc[VEOF] && byte != 0 {
                    if state.canon_line.is_empty() {
                        state.slave_eof_markers += 1;
                    } else {
                        let line = core::mem::take(&mut state.canon_line);
                        state.slave_rx.extend(line);
                    }
                    delivered = true;
                    continue;
                }
                state.canon_line.push(byte);
                if echo {
                    PtyInner::echo_output(&mut state, &[byte]);
                    echoed = true;
                }
                if byte == b'\n' || (cc[VEOL] != 0 && byte == cc[VEOL]) {
                    let line = core::mem::take(&mut state.canon_line);
                    state.slave_rx.extend(line);
                    delivered = true;
                }
            } else {
                state.slave_rx.push_back(byte);
                delivered = true;
                if echo {
                    PtyInner::echo_output(&mut state, &[byte]);
                    echoed = true;
                }
            }
        }
        drop(state);
        if delivered {
            self.0.0.slave_notify.notify_all();
        }
        if echoed {
            self.0.0.master_notify.notify_all();
        }
        (data.len(), signal_to_send)
    }

    pub fn try_read(&self, limit: usize) -> PtyTryRead {
        let mut state = self.0.0.state.lock();
        if !state.master_rx.is_empty() {
            let take = limit.min(state.master_rx.len());
            let mut out = alloc::vec![0u8; take];
            for slot in &mut out {
                *slot = state.master_rx.pop_front().expect("checked length");
            }
            return PtyTryRead::Ready(Bytes::from(out));
        }
        if state.slave_hung_up {
            PtyTryRead::Closed
        } else {
            PtyTryRead::WouldBlock
        }
    }

    pub async fn read(&self, limit: usize) -> Result<Bytes, PtyError> {
        if limit == 0 {
            return Ok(Bytes::new());
        }
        loop {
            let mut wait = self.0.0.master_notify.waiter();
            match self.try_read(limit) {
                PtyTryRead::Ready(bytes) => return Ok(bytes),
                PtyTryRead::Eof => return Ok(Bytes::new()),
                PtyTryRead::Closed => return Err(PtyError::Closed),
                PtyTryRead::WouldBlock => {
                    poll_fn(|cx| self.0.0.master_notify.poll_notified(cx, &mut wait)).await;
                }
            }
        }
    }

    pub fn readable_bytes(&self) -> usize {
        self.0.0.state.lock().master_rx.len()
    }

    pub fn is_slave_hung_up(&self) -> bool {
        self.0.0.state.lock().slave_hung_up
    }

    pub fn wait_state(&self) -> NotifyWaiter {
        self.0.0.master_notify.waiter()
    }

    pub fn poll_changed(&self, cx: &mut Context<'_>, wait: &mut NotifyWaiter) -> Poll<()> {
        self.0.0.master_notify.poll_notified(cx, wait)
    }
}

impl PtySlave {
    pub fn index(&self) -> u32 {
        self.0.0.index
    }

    pub fn same_pty(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0.0, &other.0.0)
    }

    pub fn termios(&self) -> PtyTermios {
        self.0.0.state.lock().termios
    }

    pub fn set_termios(&self, termios: PtyTermios, flush_input: bool) {
        let mut state = self.0.0.state.lock();
        let was_canon = state.termios.lflag & ICANON != 0;
        let now_canon = termios.lflag & ICANON != 0;
        state.termios = termios;
        if flush_input {
            state.canon_line.clear();
            state.slave_rx.clear();
            state.slave_eof_markers = 0;
        } else if was_canon && !now_canon && !state.canon_line.is_empty() {
            let pending = core::mem::take(&mut state.canon_line);
            state.slave_rx.extend(pending);
            drop(state);
            self.0.0.slave_notify.notify_all();
        }
    }

    pub fn winsize(&self) -> PtyWinsize {
        self.0.0.state.lock().winsize
    }

    pub fn set_winsize(&self, winsize: PtyWinsize) {
        self.0.0.state.lock().winsize = winsize;
    }

    pub fn fg_pgrp(&self) -> u32 {
        self.0.0.state.lock().fg_pgrp
    }

    pub fn set_fg_pgrp(&self, pgid: u32) {
        self.0.0.state.lock().fg_pgrp = pgid;
    }

    pub fn session_id(&self) -> Option<u32> {
        self.0.0.state.lock().session_id
    }

    pub fn set_session_id(&self, sid: Option<u32>) {
        self.0.0.state.lock().session_id = sid;
    }

    pub fn attrs(&self) -> (u32, u32, u32) {
        let state = self.0.0.state.lock();
        (state.uid, state.gid, state.mode)
    }

    pub fn set_mode(&self, mode: u32) {
        self.0.0.state.lock().mode = mode & 0o7777;
    }

    pub fn set_owner(&self, uid: Option<u32>, gid: Option<u32>) {
        let mut state = self.0.0.state.lock();
        if let Some(uid) = uid {
            state.uid = uid;
        }
        if let Some(gid) = gid {
            state.gid = gid;
        }
    }

    pub fn write(&self, data: &[u8]) -> Result<usize, PtyError> {
        let mut state = self.0.0.state.lock();
        if state.master_closed {
            return Err(PtyError::Closed);
        }
        PtyInner::echo_output(&mut state, data);
        drop(state);
        self.0.0.master_notify.notify_all();
        Ok(data.len())
    }

    pub fn try_read(&self, limit: usize) -> PtyTryRead {
        let mut state = self.0.0.state.lock();
        if !state.slave_rx.is_empty() {
            let take = limit.min(state.slave_rx.len());
            let mut out = alloc::vec![0u8; take];
            for slot in &mut out {
                *slot = state.slave_rx.pop_front().expect("checked length");
            }
            return PtyTryRead::Ready(Bytes::from(out));
        }
        if state.slave_eof_markers > 0 {
            state.slave_eof_markers -= 1;
            return PtyTryRead::Eof;
        }
        if state.master_closed {
            PtyTryRead::Eof
        } else {
            PtyTryRead::WouldBlock
        }
    }

    pub async fn read(&self, limit: usize) -> Bytes {
        if limit == 0 {
            return Bytes::new();
        }
        loop {
            let mut wait = self.0.0.slave_notify.waiter();
            match self.try_read(limit) {
                PtyTryRead::Ready(bytes) => return bytes,
                PtyTryRead::Eof | PtyTryRead::Closed => return Bytes::new(),
                PtyTryRead::WouldBlock => {
                    poll_fn(|cx| self.0.0.slave_notify.poll_notified(cx, &mut wait)).await;
                }
            }
        }
    }

    pub fn readable_bytes(&self) -> usize {
        self.0.0.state.lock().slave_rx.len()
    }

    pub fn is_master_closed(&self) -> bool {
        self.0.0.state.lock().master_closed
    }

    pub fn wait_state(&self) -> NotifyWaiter {
        self.0.0.slave_notify.waiter()
    }

    pub fn poll_changed(&self, cx: &mut Context<'_>, wait: &mut NotifyWaiter) -> Poll<()> {
        self.0.0.slave_notify.poll_notified(cx, wait)
    }
}
