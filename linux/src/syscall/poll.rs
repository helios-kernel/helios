//! Readiness multiplexing system calls: `poll`, `ppoll`, `select`, `pselect6`,
//! and the shared readiness/wait machinery also used by `epoll_wait`.

use super::signal::ThreadSignalSlot;
use super::*;
use alloc::vec::Vec;
use core::future::{Future, poll_fn};
use core::task::{Context, Poll};
use helios_sync::{ByteReadWait, ByteReader, ByteWriteWait, ByteWriter, NotifyWaiter};
use helios_unix::{Epoll, EventFd, SignalSet};

// Linux UAPI `include/uapi/asm-generic/poll.h` and `eventpoll.h`.
pub(super) const POLLIN: u32 = 0x0001;
pub(super) const POLLPRI: u32 = 0x0002;
pub(super) const POLLOUT: u32 = 0x0004;
pub(super) const POLLERR: u32 = 0x0008;
pub(super) const POLLHUP: u32 = 0x0010;
pub(super) const POLLNVAL: u32 = 0x0020;
pub(super) const POLLRDNORM: u32 = 0x0040;
pub(super) const POLLWRNORM: u32 = 0x0100;

// Linux `fs/select.c` readiness masks for `select`/`pselect6`.
const SELECT_IN_SET: u32 = POLLIN | POLLRDNORM | POLLHUP | POLLERR;
const SELECT_OUT_SET: u32 = POLLOUT | POLLWRNORM | POLLERR;
const SELECT_EX_SET: u32 = POLLPRI;

const NANOS_PER_SECOND: u64 = 1_000_000_000;
const MICROS_PER_SECOND: u64 = 1_000_000;

pub(super) enum Wait {
    Event(EventFd, NotifyWaiter),
    Read(ByteReader, ByteReadWait),
    Write(ByteWriter, ByteWriteWait),
}

impl Wait {
    pub(super) fn arm<R: Resources>(entry: &Entry<R>, events: u32) -> Option<Self> {
        match &entry.descriptor {
            FileDescriptor::Event(event) => Some(Self::Event(event.clone(), event.wait_state())),
            FileDescriptor::PipeRead { reader } if events & (POLLIN | POLLRDNORM) != 0 => {
                Some(Self::Read(reader.clone(), reader.wait_state()))
            }
            FileDescriptor::PipeWrite { writer } if events & (POLLOUT | POLLWRNORM) != 0 => {
                Some(Self::Write(writer.clone(), writer.wait_state()))
            }
            _ => None,
        }
    }

    pub(super) fn poll(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        match self {
            Self::Event(event, wait) => event.poll_changed(cx, wait),
            Self::Read(reader, wait) => reader.poll_readable(cx, wait),
            Self::Write(writer, wait) => writer.poll_writable(cx, wait),
        }
    }
}

pub(super) fn ready_mask<R: Resources, O: Stdio>(
    process: &Process<R>,
    entry: &Entry<R>,
    table: &Descriptors<R>,
    stdio: &O,
    for_epoll: bool,
) -> u32 {
    match &entry.descriptor {
        FileDescriptor::Event(event) => {
            (if event.is_readable() {
                POLLIN | POLLRDNORM
            } else {
                0
            }) | (if event.is_writable() {
                POLLOUT | POLLWRNORM
            } else {
                0
            })
        }
        FileDescriptor::PipeRead { reader } => {
            (if reader.has_buffered_data() {
                POLLIN | POLLRDNORM
            } else {
                0
            }) | (if reader.is_writer_closed() {
                POLLHUP
            } else {
                0
            })
        }
        FileDescriptor::PipeWrite { writer } => {
            if writer.is_reader_closed() {
                POLLERR
            } else if writer.is_writable() {
                POLLOUT | POLLWRNORM
            } else {
                0
            }
        }
        FileDescriptor::Stdin { .. } => {
            let mut mask = if !process.shared.stdin_carry.lock().is_empty() {
                POLLIN
            } else {
                0
            };
            mask |= stdio.stdin_ready_mask();
            if mask & POLLIN != 0 {
                mask |= POLLRDNORM;
            }
            mask
        }
        FileDescriptor::Stdout => {
            let mut mask = stdio.stdout_ready_mask(Stream::Stdout);
            if mask & POLLOUT != 0 {
                mask |= POLLWRNORM;
            }
            mask
        }
        FileDescriptor::Stderr => {
            let mut mask = stdio.stdout_ready_mask(Stream::Stderr);
            if mask & POLLOUT != 0 {
                mask |= POLLWRNORM;
            }
            mask
        }
        FileDescriptor::Epoll(epoll) => {
            if epoll.interests().iter().any(|interest| {
                table.get_entry(interest.fd).is_some_and(|child| {
                    ready_mask::<R, O>(process, child, table, stdio, true)
                        & (interest.events | POLLERR | POLLHUP)
                        != 0
                })
            }) {
                POLLIN | POLLRDNORM
            } else {
                0
            }
        }
        FileDescriptor::File(_) | FileDescriptor::Preopen { .. } | FileDescriptor::NullDevice => {
            if for_epoll {
                0
            } else {
                POLLIN | POLLRDNORM | POLLOUT | POLLWRNORM
            }
        }
        FileDescriptor::Socket(_) => 0,
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn arm_entry_wait<R: Resources, O: Stdio>(
    process: &Process<R>,
    entry: &Entry<R>,
    events: u32,
    table: &Descriptors<R>,
    stdio: &O,
    waits: &mut Vec<Wait>,
    watch_stdin: &mut bool,
    repoll: &mut bool,
) {
    match &entry.descriptor {
        FileDescriptor::Epoll(child) if events & (POLLIN | POLLRDNORM) != 0 => {
            arm_epoll_waits::<R, O>(process, child, table, stdio, waits, watch_stdin, repoll);
        }
        FileDescriptor::Stdin { .. } => {
            // Only arm stdin wait when stdin is currently quiet; if data or EOF
            // is already present, `wait_stdin_ready` would return immediately
            // even if the caller only asked for `POLLOUT`.
            let current = ready_mask::<R, O>(process, entry, table, stdio, false);
            if current & (POLLIN | POLLHUP | POLLERR) == 0 {
                *watch_stdin = true;
            }
        }
        FileDescriptor::Socket(sock) => {
            if let Some((reader, carry_len)) = sock.pair_read_probe() {
                if events & (POLLIN | POLLRDNORM) != 0 && carry_len == 0 {
                    waits.push(Wait::Read(reader.clone(), reader.wait_state()));
                }
                if events & (POLLOUT | POLLWRNORM) != 0
                    && let Some(writer) = sock.pair_writer()
                    && !writer.is_writable()
                {
                    waits.push(Wait::Write(writer.clone(), writer.wait_state()));
                }
            } else if sock.handle().is_some() {
                *repoll = true;
            }
        }
        _ => {
            if let Some(wait) = Wait::arm::<R>(entry, events) {
                waits.push(wait);
            }
        }
    }
}

pub(super) fn arm_epoll_waits<R: Resources, O: Stdio>(
    process: &Process<R>,
    epoll: &Epoll<R::Data>,
    table: &Descriptors<R>,
    stdio: &O,
    waits: &mut Vec<Wait>,
    watch_stdin: &mut bool,
    repoll: &mut bool,
) {
    for interest in epoll.interests() {
        if let Some(entry) = table.get_entry(interest.fd) {
            arm_entry_wait::<R, O>(
                process,
                entry,
                interest.events,
                table,
                stdio,
                waits,
                watch_stdin,
                repoll,
            );
        }
    }
}

/// Waits until the deadline expires, stdin or one of `waits` becomes ready, or
/// a deliverable signal arrives. Returns `true` when interrupted by a signal.
pub(super) async fn wait_once<O: Stdio + Clock>(
    signals: &ThreadSignalSlot,
    deadline: Option<u64>,
    waits: &mut [Wait],
    watch_stdin: bool,
    io: &O,
) -> bool {
    let timer = async {
        match deadline {
            Some(end) => io.sleep_until(end).await,
            None => core::future::pending().await,
        }
    };
    let stdin_wait = async {
        if watch_stdin {
            io.wait_stdin_ready().await;
        } else {
            core::future::pending().await
        }
    };
    let mut timer = core::pin::pin!(timer);
    let mut stdin_wait = core::pin::pin!(stdin_wait);
    let mut sig = core::pin::pin!(signals.wait_deliverable());
    poll_fn(|cx| {
        let mut ready = timer.as_mut().poll(cx).is_ready();
        ready |= stdin_wait.as_mut().poll(cx).is_ready();
        for wait in waits.iter_mut() {
            ready |= wait.poll(cx).is_ready();
        }
        if ready {
            return Poll::Ready(false);
        }
        if sig.as_mut().poll(cx).is_ready() {
            return Poll::Ready(true);
        }
        Poll::Pending
    })
    .await
}

fn read_timespec_timeout<M: UserMemory, C: Clock>(
    memory: &M,
    ptr: u64,
    clock: &C,
) -> Result<Option<u64>, u64> {
    if ptr == 0 {
        return Ok(None);
    }
    let mut raw = [0u8; 16];
    if memory.read(ptr, &mut raw).is_err() {
        return Err(errno(EFAULT));
    }
    let sec = i64::from_le_bytes(raw[0..8].try_into().unwrap());
    let nsec = i64::from_le_bytes(raw[8..16].try_into().unwrap());
    if sec < 0 || !(0..NANOS_PER_SECOND as i64).contains(&nsec) {
        return Err(errno(EINVAL));
    }
    let delta = (sec as u64)
        .saturating_mul(NANOS_PER_SECOND)
        .saturating_add(nsec as u64);
    Ok(Some(clock.now_nanos().saturating_add(delta)))
}

fn read_sigmask<M: UserMemory>(
    memory: &M,
    ptr: u64,
    sigsetsize: u64,
) -> Result<Option<SignalSet>, u64> {
    if ptr == 0 {
        return Ok(None);
    }
    if sigsetsize != 8 {
        return Err(errno(EINVAL));
    }
    let mut mask = [0u8; 8];
    if memory.read(ptr, &mut mask).is_err() {
        return Err(errno(EFAULT));
    }
    Ok(Some(SignalSet::from_bits(u64::from_le_bytes(mask))))
}

const NETWORK_REPOLL_NANOS: u64 = 1_000_000;

pub(super) async fn poll<
    R: Resources,
    M: UserMemory,
    O: Stdio + Clock + socket::Network<R::Network>,
>(
    process: &Process<R>,
    args: [u64; 6],
    memory: &mut M,
    io: &O,
) -> SyscallOutcome {
    let timeout_ms = args[2] as i32;
    let deadline =
        (timeout_ms >= 0).then(|| io.now_nanos().saturating_add(timeout_ms as u64 * 1_000_000));
    poll_common(process, args[0], args[1], deadline, None, memory, io).await
}

pub(super) async fn ppoll<
    R: Resources,
    M: UserMemory,
    O: Stdio + Clock + socket::Network<R::Network>,
>(
    process: &Process<R>,
    args: [u64; 6],
    memory: &mut M,
    io: &O,
) -> SyscallOutcome {
    let temp_mask = match read_sigmask(memory, args[3], args[4]) {
        Ok(m) => m,
        Err(err) => return SyscallOutcome::Return(err),
    };
    let deadline = match read_timespec_timeout(memory, args[2], io) {
        Ok(d) => d,
        Err(err) => return SyscallOutcome::Return(err),
    };
    poll_common(process, args[0], args[1], deadline, temp_mask, memory, io).await
}

async fn poll_common<
    R: Resources,
    M: UserMemory,
    O: Stdio + Clock + socket::Network<R::Network>,
>(
    process: &Process<R>,
    fds_ptr: u64,
    nfds: u64,
    deadline: Option<u64>,
    temp_mask: Option<SignalSet>,
    memory: &mut M,
    io: &O,
) -> SyscallOutcome {
    let limit = process.shared.descriptors.lock().limit.get().max(1024) as u64;
    if nfds > limit {
        return SyscallOutcome::Return(errno(EINVAL));
    }
    let count = nfds as usize;
    let mut requests = Vec::with_capacity(count);
    let mut raw = [0u8; 8];
    for idx in 0..count {
        let addr = match fds_ptr.checked_add((idx as u64) * 8) {
            Some(a) => a,
            None => return SyscallOutcome::Return(errno(EFAULT)),
        };
        if memory.read(addr, &mut raw).is_err() {
            return SyscallOutcome::Return(errno(EFAULT));
        }
        let fd = i32::from_le_bytes(raw[0..4].try_into().unwrap());
        let events = u16::from_le_bytes(raw[4..6].try_into().unwrap());
        requests.push((fd, events));
    }

    let installed_mask = if let Some(mask) = temp_mask {
        process.signals.push_temp_mask(mask);
        true
    } else {
        false
    };

    let mut revents = alloc::vec![0u16; count];
    loop {
        let mut waits = Vec::new();
        let mut watch_stdin = false;
        let mut repoll = false;
        let mut ready_count = 0u64;
        let mut pending_sockets = Vec::new();
        {
            let table = process.shared.descriptors.lock();
            for (idx, &(fd, events)) in requests.iter().enumerate() {
                if fd < 0 {
                    revents[idx] = 0;
                    continue;
                }
                let Some(entry) = table.get_entry(fd) else {
                    revents[idx] = POLLNVAL as u16;
                    ready_count += 1;
                    continue;
                };
                let wanted =
                    u32::from(events) & (POLLIN | POLLPRI | POLLOUT | POLLRDNORM | POLLWRNORM);
                if matches!(entry.descriptor, FileDescriptor::Socket(_)) {
                    revents[idx] = 0;
                    arm_entry_wait::<R, O>(
                        process,
                        entry,
                        wanted,
                        &table,
                        io,
                        &mut waits,
                        &mut watch_stdin,
                        &mut repoll,
                    );
                    pending_sockets.push((idx, entry.clone(), wanted));
                    continue;
                }
                let mask = ready_mask::<R, O>(process, entry, &table, io, false);
                let rev = mask & (wanted | POLLERR | POLLHUP);
                revents[idx] = rev as u16;
                if rev != 0 {
                    ready_count += 1;
                } else {
                    arm_entry_wait::<R, O>(
                        process,
                        entry,
                        wanted,
                        &table,
                        io,
                        &mut waits,
                        &mut watch_stdin,
                        &mut repoll,
                    );
                }
            }
        }
        for (idx, entry, wanted) in pending_sockets {
            if let FileDescriptor::Socket(sock) = &entry.descriptor {
                let rev = socket::socket_epoll_ready(sock, wanted, io).await;
                revents[idx] = rev as u16;
                if rev != 0 {
                    ready_count += 1;
                }
            }
        }
        let now = io.now_nanos();
        if ready_count != 0 || deadline.is_some_and(|end| now >= end) {
            if installed_mask {
                process.signals.restore_temp_mask();
            }
            for (idx, &rev) in revents.iter().enumerate() {
                let addr = fds_ptr + (idx as u64) * 8 + 6;
                if memory.write(addr, &rev.to_le_bytes()).is_err() {
                    return SyscallOutcome::Return(errno(EFAULT));
                }
            }
            return SyscallOutcome::Return(ready_count);
        }
        let wake_at = match (deadline, repoll) {
            (Some(end), true) => Some(end.min(now.saturating_add(NETWORK_REPOLL_NANOS))),
            (Some(end), false) => Some(end),
            (None, true) => Some(now.saturating_add(NETWORK_REPOLL_NANOS)),
            (None, false) => None,
        };
        if wait_once(&process.signals, wake_at, &mut waits, watch_stdin, io).await {
            // Leave `saved_mask` active (`TIF_RESTORE_SIGMASK`) so signal
            // delivery writes the original mask into `uc_sigmask`.
            return SyscallOutcome::RestartNoHand;
        }
    }
}

fn read_fd_set<M: UserMemory>(memory: &M, ptr: u64, byte_len: usize) -> Result<Vec<u8>, u64> {
    if ptr == 0 || byte_len == 0 {
        return Ok(Vec::new());
    }
    let mut buf = alloc::vec![0u8; byte_len];
    if memory.read(ptr, &mut buf).is_err() {
        return Err(errno(EFAULT));
    }
    Ok(buf)
}

fn bit_is_set(bits: &[u8], fd: usize) -> bool {
    let byte = fd / 8;
    byte < bits.len() && (bits[byte] & (1 << (fd % 8))) != 0
}

fn set_bit(bits: &mut [u8], fd: usize) {
    let byte = fd / 8;
    if byte < bits.len() {
        bits[byte] |= 1 << (fd % 8);
    }
}

pub(super) async fn select<
    R: Resources,
    M: UserMemory,
    O: Stdio + Clock + socket::Network<R::Network>,
>(
    process: &Process<R>,
    args: [u64; 6],
    memory: &mut M,
    io: &O,
) -> SyscallOutcome {
    let timeout_ptr = args[4];
    let deadline = if timeout_ptr == 0 {
        None
    } else {
        let mut raw = [0u8; 16];
        if memory.read(timeout_ptr, &mut raw).is_err() {
            return SyscallOutcome::Return(errno(EFAULT));
        }
        let sec = i64::from_le_bytes(raw[0..8].try_into().unwrap());
        let usec = i64::from_le_bytes(raw[8..16].try_into().unwrap());
        if sec < 0 || usec < 0 {
            return SyscallOutcome::Return(errno(EINVAL));
        }
        let extra_sec = (usec as u64) / MICROS_PER_SECOND;
        let rem_usec = (usec as u64) % MICROS_PER_SECOND;
        let delta = (sec as u64)
            .saturating_add(extra_sec)
            .saturating_mul(NANOS_PER_SECOND)
            .saturating_add(rem_usec.saturating_mul(1_000));
        Some(io.now_nanos().saturating_add(delta))
    };
    let outcome = select_common(
        process,
        args[0] as i32,
        args[1],
        args[2],
        args[3],
        deadline,
        None,
        memory,
        io,
    )
    .await;
    if matches!(outcome, SyscallOutcome::Return(result) if (result as i64) >= 0)
        && timeout_ptr != 0
        && let Some(end) = deadline
    {
        let rem_nanos = end.saturating_sub(io.now_nanos());
        let sec = (rem_nanos / NANOS_PER_SECOND) as i64;
        let usec = ((rem_nanos % NANOS_PER_SECOND) / 1_000) as i64;
        let mut out = [0u8; 16];
        out[0..8].copy_from_slice(&sec.to_le_bytes());
        out[8..16].copy_from_slice(&usec.to_le_bytes());
        if memory.write(timeout_ptr, &out).is_err() {
            return SyscallOutcome::Return(errno(EFAULT));
        }
    }
    outcome
}

pub(super) async fn pselect6<
    R: Resources,
    M: UserMemory,
    O: Stdio + Clock + socket::Network<R::Network>,
>(
    process: &Process<R>,
    args: [u64; 6],
    memory: &mut M,
    io: &O,
) -> SyscallOutcome {
    let sig_arg = args[5];
    let temp_mask = if sig_arg != 0 {
        let mut raw = [0u8; 16];
        if memory.read(sig_arg, &mut raw).is_err() {
            return SyscallOutcome::Return(errno(EFAULT));
        }
        let sig_ptr = u64::from_le_bytes(raw[0..8].try_into().unwrap());
        let sig_len = u64::from_le_bytes(raw[8..16].try_into().unwrap());
        match read_sigmask(memory, sig_ptr, sig_len) {
            Ok(m) => m,
            Err(err) => return SyscallOutcome::Return(err),
        }
    } else {
        None
    };
    let deadline = match read_timespec_timeout(memory, args[4], io) {
        Ok(d) => d,
        Err(err) => return SyscallOutcome::Return(err),
    };
    select_common(
        process,
        args[0] as i32,
        args[1],
        args[2],
        args[3],
        deadline,
        temp_mask,
        memory,
        io,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn select_common<
    R: Resources,
    M: UserMemory,
    O: Stdio + Clock + socket::Network<R::Network>,
>(
    process: &Process<R>,
    nfds: i32,
    read_ptr: u64,
    write_ptr: u64,
    except_ptr: u64,
    deadline: Option<u64>,
    temp_mask: Option<SignalSet>,
    memory: &mut M,
    io: &O,
) -> SyscallOutcome {
    if nfds < 0 {
        return SyscallOutcome::Return(errno(EINVAL));
    }
    // Linux caps `n` at `fdt->max_fds` or `1024` only when above current limit,
    // after rounding up to `unsigned long` (8-byte) word count.
    let nfds_usize = nfds as usize;
    let max_limit = process.shared.descriptors.lock().limit.get().max(1024);
    if nfds_usize > max_limit.saturating_mul(8) {
        return SyscallOutcome::Return(errno(EINVAL));
    }
    let byte_len = nfds_usize.div_ceil(64) * 8;
    let in_read = match read_fd_set(memory, read_ptr, byte_len) {
        Ok(v) => v,
        Err(err) => return SyscallOutcome::Return(err),
    };
    let in_write = match read_fd_set(memory, write_ptr, byte_len) {
        Ok(v) => v,
        Err(err) => return SyscallOutcome::Return(err),
    };
    let in_except = match read_fd_set(memory, except_ptr, byte_len) {
        Ok(v) => v,
        Err(err) => return SyscallOutcome::Return(err),
    };

    let installed_mask = if let Some(mask) = temp_mask {
        process.signals.push_temp_mask(mask);
        true
    } else {
        false
    };

    loop {
        let mut out_read = if read_ptr != 0 {
            alloc::vec![0u8; byte_len]
        } else {
            Vec::new()
        };
        let mut out_write = if write_ptr != 0 {
            alloc::vec![0u8; byte_len]
        } else {
            Vec::new()
        };
        let mut out_except = if except_ptr != 0 {
            alloc::vec![0u8; byte_len]
        } else {
            Vec::new()
        };

        let mut waits = Vec::new();
        let mut watch_stdin = false;
        let mut repoll = false;
        let mut ready_bits = 0u64;
        let mut pending_sockets = Vec::new();
        {
            let table = process.shared.descriptors.lock();
            for fd in 0..nfds_usize {
                let want_r = bit_is_set(&in_read, fd);
                let want_w = bit_is_set(&in_write, fd);
                let want_x = bit_is_set(&in_except, fd);
                if !(want_r || want_w || want_x) {
                    continue;
                }
                let Some(entry) = table.get_entry(fd as i32) else {
                    if installed_mask {
                        process.signals.restore_temp_mask();
                    }
                    return SyscallOutcome::Return(errno(EBADF));
                };
                let mut events = 0u32;
                if want_r {
                    events |= POLLIN | POLLRDNORM;
                }
                if want_w {
                    events |= POLLOUT | POLLWRNORM;
                }
                if want_x {
                    events |= POLLPRI;
                }
                if matches!(entry.descriptor, FileDescriptor::Socket(_)) {
                    arm_entry_wait::<R, O>(
                        process,
                        entry,
                        events,
                        &table,
                        io,
                        &mut waits,
                        &mut watch_stdin,
                        &mut repoll,
                    );
                    pending_sockets.push((fd, entry.clone(), want_r, want_w, want_x, events));
                    continue;
                }
                let mask = ready_mask::<R, O>(process, entry, &table, io, false);
                let mut hit = false;
                if want_r && (mask & SELECT_IN_SET) != 0 {
                    set_bit(&mut out_read, fd);
                    ready_bits += 1;
                    hit = true;
                }
                if want_w && (mask & SELECT_OUT_SET) != 0 {
                    set_bit(&mut out_write, fd);
                    ready_bits += 1;
                    hit = true;
                }
                if want_x && (mask & SELECT_EX_SET) != 0 {
                    set_bit(&mut out_except, fd);
                    ready_bits += 1;
                    hit = true;
                }
                if !hit {
                    arm_entry_wait::<R, O>(
                        process,
                        entry,
                        events,
                        &table,
                        io,
                        &mut waits,
                        &mut watch_stdin,
                        &mut repoll,
                    );
                }
            }
        }
        for (fd, entry, want_r, want_w, want_x, events) in pending_sockets {
            if let FileDescriptor::Socket(sock) = &entry.descriptor {
                let mask = socket::socket_epoll_ready(sock, events, io).await;
                if want_r && (mask & SELECT_IN_SET) != 0 {
                    set_bit(&mut out_read, fd);
                    ready_bits += 1;
                }
                if want_w && (mask & SELECT_OUT_SET) != 0 {
                    set_bit(&mut out_write, fd);
                    ready_bits += 1;
                }
                if want_x && (mask & SELECT_EX_SET) != 0 {
                    set_bit(&mut out_except, fd);
                    ready_bits += 1;
                }
            }
        }

        let now = io.now_nanos();
        if ready_bits != 0 || deadline.is_some_and(|end| now >= end) {
            if installed_mask {
                process.signals.restore_temp_mask();
            }
            if read_ptr != 0 && !out_read.is_empty() && memory.write(read_ptr, &out_read).is_err() {
                return SyscallOutcome::Return(errno(EFAULT));
            }
            if write_ptr != 0
                && !out_write.is_empty()
                && memory.write(write_ptr, &out_write).is_err()
            {
                return SyscallOutcome::Return(errno(EFAULT));
            }
            if except_ptr != 0
                && !out_except.is_empty()
                && memory.write(except_ptr, &out_except).is_err()
            {
                return SyscallOutcome::Return(errno(EFAULT));
            }
            return SyscallOutcome::Return(ready_bits);
        }
        let wake_at = match (deadline, repoll) {
            (Some(end), true) => Some(end.min(now.saturating_add(NETWORK_REPOLL_NANOS))),
            (Some(end), false) => Some(end),
            (None, true) => Some(now.saturating_add(NETWORK_REPOLL_NANOS)),
            (None, false) => None,
        };
        if wait_once(&process.signals, wake_at, &mut waits, watch_stdin, io).await {
            return SyscallOutcome::RestartNoHand;
        }
    }
}
