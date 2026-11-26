//! Shared POSIX named-FIFO (`S_IFIFO`) pipe ring with Linux `fifo_open`
//! rendezvous semantics (`fs/pipe.c`).
//!
//! # Concurrency contract
//!
//! Internal state is guarded by a short synchronous `spin::Mutex`, never held
//! across an `.await`. Every async waiter arms its [`NotifyWaiter`] before
//! testing the condition so no wake-up between the check and the park is lost.

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use core::future::poll_fn;
use core::task::{Context, Poll};

use bytes::Bytes;
use helios_sync::{Notify, NotifyWaiter};
use thiserror::Error;

use crate::PipeInode;

/// Default Linux pipe buffer capacity (64 KiB, `PIPE_DEF_BUFFERS * PAGE_SIZE`).
pub const FIFO_CAPACITY: usize = 65_536;

/// Errors returned by named FIFO operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum FifoError {
    /// `open(O_WRONLY | O_NONBLOCK)` attempted when no reader is open (`ENXIO`).
    #[error("no reader open on FIFO")]
    NoReader,
    /// Write attempted when no reader remains open (`EPIPE`).
    #[error("broken FIFO pipe")]
    BrokenPipe,
}

/// Outcome of a non-blocking FIFO read.
#[derive(Debug, PartialEq, Eq)]
pub enum FifoTryRead {
    Ready(Bytes),
    Eof,
    WouldBlock,
}

/// Outcome of a non-blocking FIFO write.
#[derive(Debug, PartialEq, Eq)]
pub enum FifoTryWrite {
    Written(usize),
    WouldBlock,
    BrokenPipe,
}

struct FifoState {
    buf: VecDeque<u8>,
    readers: usize,
    writers: usize,
    /// Monotonic count of reader opens (`fs/pipe.c` `pipe_inode_info::r_counter`),
    /// so a blocked `open(O_WRONLY)` wakes even if the reader opens and closes
    /// before the writer is re-polled.
    r_counter: u64,
    /// Monotonic count of writer opens (`fs/pipe.c` `pipe_inode_info::w_counter`),
    /// so a blocked `open(O_RDONLY)` wakes even if the writer opens, writes,
    /// and closes before the reader is re-polled.
    w_counter: u64,
}

struct FifoInner {
    state: spin::Mutex<FifoState>,
    /// Broadcast whenever readers/writers counts or readable/writable status change.
    changed: Notify,
    inode: PipeInode,
}

impl FifoInner {
    fn new(inode: PipeInode) -> Self {
        Self {
            state: spin::Mutex::new(FifoState {
                buf: VecDeque::new(),
                readers: 0,
                writers: 0,
                r_counter: 0,
                w_counter: 0,
            }),
            changed: Notify::new(),
            inode,
        }
    }

    fn try_read(&self, limit: usize) -> FifoTryRead {
        let mut state = self.state.lock();
        if !state.buf.is_empty() {
            let take = limit.min(state.buf.len());
            let mut out = alloc::vec![0u8; take];
            for slot in &mut out {
                *slot = state.buf.pop_front().expect("checked buffer length");
            }
            drop(state);
            self.changed.notify_all();
            return FifoTryRead::Ready(Bytes::from(out));
        }
        if state.writers == 0 {
            FifoTryRead::Eof
        } else {
            FifoTryRead::WouldBlock
        }
    }

    async fn read(&self, limit: usize) -> Bytes {
        if limit == 0 {
            return Bytes::new();
        }
        loop {
            let mut wait = self.changed.waiter();
            match self.try_read(limit) {
                FifoTryRead::Ready(bytes) => return bytes,
                FifoTryRead::Eof => return Bytes::new(),
                FifoTryRead::WouldBlock => {
                    poll_fn(|cx| self.changed.poll_notified(cx, &mut wait)).await;
                }
            }
        }
    }

    fn try_write(&self, data: &[u8]) -> FifoTryWrite {
        let mut state = self.state.lock();
        if state.readers == 0 {
            return FifoTryWrite::BrokenPipe;
        }
        if data.is_empty() {
            return FifoTryWrite::Written(0);
        }
        let free = FIFO_CAPACITY.saturating_sub(state.buf.len());
        if free == 0 {
            return FifoTryWrite::WouldBlock;
        }
        let take = data.len().min(free);
        state.buf.extend(&data[..take]);
        drop(state);
        self.changed.notify_all();
        FifoTryWrite::Written(take)
    }

    async fn write(&self, data: &[u8]) -> Result<usize, FifoError> {
        if data.is_empty() {
            let state = self.state.lock();
            return if state.readers == 0 {
                Err(FifoError::BrokenPipe)
            } else {
                Ok(0)
            };
        }
        loop {
            let mut wait = self.changed.waiter();
            match self.try_write(data) {
                FifoTryWrite::Written(n) => return Ok(n),
                FifoTryWrite::BrokenPipe => return Err(FifoError::BrokenPipe),
                FifoTryWrite::WouldBlock => {
                    poll_fn(|cx| self.changed.poll_notified(cx, &mut wait)).await;
                }
            }
        }
    }

    fn buffered_bytes(&self) -> usize {
        self.state.lock().buf.len()
    }

    fn reader_count(&self) -> usize {
        self.state.lock().readers
    }

    fn writer_count(&self) -> usize {
        self.state.lock().writers
    }

    fn is_writable(&self) -> bool {
        let state = self.state.lock();
        state.readers > 0 && state.buf.len() < FIFO_CAPACITY
    }

    fn wait_state(&self) -> NotifyWaiter {
        self.changed.waiter()
    }

    fn poll_changed(&self, cx: &mut Context<'_>, wait: &mut NotifyWaiter) -> Poll<()> {
        self.changed.poll_notified(cx, wait)
    }
}

/// Shared backing pipe for a named FIFO node in a container's FIFO registry.
#[derive(Clone)]
pub struct FifoPipe {
    inner: Arc<FifoInner>,
}

impl FifoPipe {
    pub fn new(inode: PipeInode) -> Self {
        Self {
            inner: Arc::new(FifoInner::new(inode)),
        }
    }

    pub fn inode(&self) -> &PipeInode {
        &self.inner.inode
    }

    /// Whether no reader or writer currently holds this FIFO open.
    pub fn is_idle(&self) -> bool {
        let state = self.inner.state.lock();
        state.readers == 0 && state.writers == 0 && state.buf.is_empty()
    }

    /// `open(O_RDONLY | O_NONBLOCK)`: succeeds immediately even with no writer.
    pub fn open_read_nonblock(&self) -> FifoReader {
        {
            let mut state = self.inner.state.lock();
            state.readers += 1;
            state.r_counter = state.r_counter.wrapping_add(1);
        }
        self.inner.changed.notify_all();
        FifoReader(Arc::new(FifoReaderGuard(self.inner.clone())))
    }

    /// `open(O_RDONLY)`: increments reader count and awaits at least one writer
    /// (matching Linux `fs/pipe.c` `fifo_open` `w_counter` rendezvous so a
    /// short-lived writer that opens, writes, and closes before the reader is
    /// re-polled still completes the open).
    /// Dropping the future before completion (e.g. signal interruption) decrements
    /// the reader count cleanly.
    pub async fn open_read_blocking(&self) -> FifoReader {
        let guard = FifoReader(Arc::new(FifoReaderGuard(self.inner.clone())));
        let w_counter_before = {
            let mut state = self.inner.state.lock();
            state.readers += 1;
            state.r_counter = state.r_counter.wrapping_add(1);
            state.w_counter
        };
        self.inner.changed.notify_all();
        loop {
            let mut wait = self.inner.changed.waiter();
            {
                let state = self.inner.state.lock();
                if state.writers > 0 || state.w_counter != w_counter_before {
                    return guard;
                }
            }
            poll_fn(|cx| self.inner.changed.poll_notified(cx, &mut wait)).await;
        }
    }

    /// `open(O_WRONLY | O_NONBLOCK)`: fails with [`FifoError::NoReader`] (`ENXIO`)
    /// when no reader is currently open.
    pub fn open_write_nonblock(&self) -> Result<FifoWriter, FifoError> {
        {
            let mut state = self.inner.state.lock();
            if state.readers == 0 {
                return Err(FifoError::NoReader);
            }
            state.writers += 1;
            state.w_counter = state.w_counter.wrapping_add(1);
        }
        self.inner.changed.notify_all();
        Ok(FifoWriter(Arc::new(FifoWriterGuard(self.inner.clone()))))
    }

    /// `open(O_WRONLY)`: increments writer count and awaits at least one reader
    /// (matching Linux `fs/pipe.c` `fifo_open` `r_counter` rendezvous).
    /// Dropping the future before completion decrements the writer count cleanly.
    pub async fn open_write_blocking(&self) -> FifoWriter {
        let guard = FifoWriter(Arc::new(FifoWriterGuard(self.inner.clone())));
        let r_counter_before = {
            let mut state = self.inner.state.lock();
            state.writers += 1;
            state.w_counter = state.w_counter.wrapping_add(1);
            state.r_counter
        };
        self.inner.changed.notify_all();
        loop {
            let mut wait = self.inner.changed.waiter();
            {
                let state = self.inner.state.lock();
                if state.readers > 0 || state.r_counter != r_counter_before {
                    return guard;
                }
            }
            poll_fn(|cx| self.inner.changed.poll_notified(cx, &mut wait)).await;
        }
    }

    /// `open(O_RDWR)`: never blocks, holds both a reader and a writer reference
    /// so reads never observe EOF and writes never fail with `EPIPE`.
    pub fn open_rdwr(&self) -> FifoReadWrite {
        {
            let mut state = self.inner.state.lock();
            state.readers += 1;
            state.writers += 1;
            state.r_counter = state.r_counter.wrapping_add(1);
            state.w_counter = state.w_counter.wrapping_add(1);
        }
        self.inner.changed.notify_all();
        FifoReadWrite(Arc::new(FifoReadWriteGuard(self.inner.clone())))
    }
}

struct FifoReaderGuard(Arc<FifoInner>);

impl Drop for FifoReaderGuard {
    fn drop(&mut self) {
        {
            let mut state = self.0.state.lock();
            state.readers = state.readers.saturating_sub(1);
            if state.readers == 0 && state.writers == 0 {
                state.buf.clear();
            }
        }
        self.0.changed.notify_all();
    }
}

struct FifoWriterGuard(Arc<FifoInner>);

impl Drop for FifoWriterGuard {
    fn drop(&mut self) {
        {
            let mut state = self.0.state.lock();
            state.writers = state.writers.saturating_sub(1);
            if state.readers == 0 && state.writers == 0 {
                state.buf.clear();
            }
        }
        self.0.changed.notify_all();
    }
}

struct FifoReadWriteGuard(Arc<FifoInner>);

impl Drop for FifoReadWriteGuard {
    fn drop(&mut self) {
        {
            let mut state = self.0.state.lock();
            state.readers = state.readers.saturating_sub(1);
            state.writers = state.writers.saturating_sub(1);
            if state.readers == 0 && state.writers == 0 {
                state.buf.clear();
            }
        }
        self.0.changed.notify_all();
    }
}

/// Read-only open file description for a named FIFO (`O_RDONLY`).
#[derive(Clone)]
pub struct FifoReader(Arc<FifoReaderGuard>);

impl FifoReader {
    pub fn inode(&self) -> &PipeInode {
        &self.0.0.inode
    }

    pub fn try_read(&self, limit: usize) -> FifoTryRead {
        self.0.0.try_read(limit)
    }

    pub async fn read(&self, limit: usize) -> Bytes {
        self.0.0.read(limit).await
    }

    pub fn has_buffered_data(&self) -> bool {
        self.0.0.buffered_bytes() > 0
    }

    pub fn buffered_bytes(&self) -> usize {
        self.0.0.buffered_bytes()
    }

    pub fn is_writer_closed(&self) -> bool {
        self.0.0.writer_count() == 0
    }

    pub fn wait_state(&self) -> NotifyWaiter {
        self.0.0.wait_state()
    }

    pub fn poll_changed(&self, cx: &mut Context<'_>, wait: &mut NotifyWaiter) -> Poll<()> {
        self.0.0.poll_changed(cx, wait)
    }
}

/// Write-only open file description for a named FIFO (`O_WRONLY`).
#[derive(Clone)]
pub struct FifoWriter(Arc<FifoWriterGuard>);

impl FifoWriter {
    pub fn inode(&self) -> &PipeInode {
        &self.0.0.inode
    }

    pub fn try_write(&self, data: &[u8]) -> FifoTryWrite {
        self.0.0.try_write(data)
    }

    pub async fn write(&self, data: &[u8]) -> Result<usize, FifoError> {
        self.0.0.write(data).await
    }

    pub fn is_reader_closed(&self) -> bool {
        self.0.0.reader_count() == 0
    }

    pub fn is_writable(&self) -> bool {
        self.0.0.is_writable()
    }

    pub fn wait_state(&self) -> NotifyWaiter {
        self.0.0.wait_state()
    }

    pub fn poll_changed(&self, cx: &mut Context<'_>, wait: &mut NotifyWaiter) -> Poll<()> {
        self.0.0.poll_changed(cx, wait)
    }
}

/// Read-write open file description for a named FIFO (`O_RDWR`).
#[derive(Clone)]
pub struct FifoReadWrite(Arc<FifoReadWriteGuard>);

impl FifoReadWrite {
    pub fn inode(&self) -> &PipeInode {
        &self.0.0.inode
    }

    pub fn try_read(&self, limit: usize) -> FifoTryRead {
        self.0.0.try_read(limit)
    }

    pub async fn read(&self, limit: usize) -> Bytes {
        self.0.0.read(limit).await
    }

    pub fn try_write(&self, data: &[u8]) -> FifoTryWrite {
        self.0.0.try_write(data)
    }

    pub async fn write(&self, data: &[u8]) -> Result<usize, FifoError> {
        self.0.0.write(data).await
    }

    pub fn has_buffered_data(&self) -> bool {
        self.0.0.buffered_bytes() > 0
    }

    pub fn buffered_bytes(&self) -> usize {
        self.0.0.buffered_bytes()
    }

    pub fn is_writable(&self) -> bool {
        self.0.0.is_writable()
    }

    pub fn wait_state(&self) -> NotifyWaiter {
        self.0.0.wait_state()
    }

    pub fn poll_changed(&self, cx: &mut Context<'_>, wait: &mut NotifyWaiter) -> Poll<()> {
        self.0.0.poll_changed(cx, wait)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::future::Future;
    use core::pin::pin;
    use core::task::{Context, Poll, Waker};
    use futures_lite::future::block_on;

    #[test]
    fn open_read_blocking_wakes_when_writer_writes_and_closes_before_reader_polls() {
        let fifo = FifoPipe::new(PipeInode::new(0, 0));
        let mut reader_open = pin!(fifo.open_read_blocking());
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);

        // Reader enters blocking open and parks before any writer arrives.
        assert!(matches!(reader_open.as_mut().poll(&mut cx), Poll::Pending));

        // Short-lived writer opens, writes payload, and drops before reader is re-polled.
        let writer = block_on(fifo.open_write_blocking());
        assert_eq!(block_on(writer.write(b"locked\n")).unwrap(), 7);
        drop(writer);

        // Reader must still complete `open_read_blocking` via `w_counter` and read
        // the buffered payload followed by EOF.
        let reader = match reader_open.as_mut().poll(&mut cx) {
            Poll::Ready(r) => r,
            Poll::Pending => panic!("reader stayed parked after writer opened and closed"),
        };
        assert_eq!(&block_on(reader.read(64))[..], b"locked\n");
        assert!(block_on(reader.read(64)).is_empty());
    }

    #[test]
    fn open_write_blocking_wakes_when_reader_opens_and_closes_before_writer_polls() {
        let fifo = FifoPipe::new(PipeInode::new(0, 0));
        let mut writer_open = pin!(fifo.open_write_blocking());
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);

        assert!(matches!(writer_open.as_mut().poll(&mut cx), Poll::Pending));

        let reader = block_on(fifo.open_read_blocking());
        drop(reader);

        assert!(
            matches!(writer_open.as_mut().poll(&mut cx), Poll::Ready(_)),
            "writer stayed parked after reader opened and closed"
        );
    }
}
