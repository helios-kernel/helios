//! Symmetric peer-to-peer multiplexed RPC framing engine.
//!
//! Built directly on [`crate::wire`]'s `(invocation, path)` frame format,
//! supporting concurrent bidirectional invocations, multi-path `stream<T>`
//! and `future<T>` sub-channels with explicit per-stream credit flow control,
//! caller drop cancellation (root `Frame::Close`), connection-local
//! `Frame::ResourceDrop`, and typed [`WireError`] fault propagation across any
//! `futures_io::AsyncRead + futures_io::AsyncWrite` byte stream on both host
//! (`std`) and `wasm32-wasip3` guest targets.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::future::Future;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Weak};
use std::task::Poll;

use async_channel::{Receiver, Sender};
use async_lock::Mutex;
use bytes::Bytes;
use futures_io::{AsyncRead, AsyncWrite};
use futures_util::stream::{FuturesUnordered, StreamExt as _};

use crate::error::{TransportError, WireError};
use crate::transport::{
    Fault, MAX_INBOUND_PATHS, MAX_UNDELIVERED_BYTES, Progress, RAW_UPLOAD_CHUNK_BYTES,
};
#[cfg(not(feature = "host"))]
use crate::wire::read_frame;
#[cfg(feature = "host")]
use crate::wire::read_frame_with_echo;
use crate::wire::{Frame, write_frame};

/// Default per-stream item credit window granted to a remote `stream<T>`
/// producer.
pub const DEFAULT_STREAM_CREDIT_WINDOW: u32 = 8;

/// Default maximum concurrent inbound invocations accepted on one mux
/// connection before excess `Frame::Open` requests are rejected.
pub const DEFAULT_MAX_CONCURRENT_INBOUND_CALLS: usize = 64;

/// Default maximum queued control/reply frames buffered in `drive_mux`'s
/// priority outbox before polling further inbound frames pauses to apply
/// transport backpressure.
pub const DEFAULT_MAX_PRIORITY_OUTBOX_FRAMES: usize = 256;

/// Direction tags placed at `path[0]` so two symmetric peers may open the same
/// numeric `invocation` ID concurrently without any path ambiguity.
const DIR_CALLER_TO_CALLEE: u32 = 0;
const DIR_CALLEE_TO_CALLER: u32 = 1;
const DIR_CALLER_STOP_READING: u32 = 2;
const DIR_CALLEE_STOP_READING: u32 = 3;

/// Configuration for a symmetric multiplexed RPC connection.
#[derive(Debug, Clone, Copy)]
pub struct MuxConfig {
    pub stream_credit_window: u32,
    pub max_inbound_paths: usize,
    pub max_undelivered_bytes: usize,
    pub max_concurrent_inbound_calls: usize,
    pub max_priority_outbox_frames: usize,
}

impl Default for MuxConfig {
    fn default() -> Self {
        Self {
            stream_credit_window: DEFAULT_STREAM_CREDIT_WINDOW,
            max_inbound_paths: MAX_INBOUND_PATHS,
            max_undelivered_bytes: MAX_UNDELIVERED_BYTES,
            max_concurrent_inbound_calls: DEFAULT_MAX_CONCURRENT_INBOUND_CALLS,
            max_priority_outbox_frames: DEFAULT_MAX_PRIORITY_OUTBOX_FRAMES,
        }
    }
}

/// Thread-safety marker equivalent to `Send` on multi-threaded host targets
/// and unconditional on single-threaded `wasm32` guests where `wit-bindgen`
/// component resources and host-call futures are `!Send`.
#[cfg(not(target_arch = "wasm32"))]
pub trait MaybeSend: Send {}
#[cfg(not(target_arch = "wasm32"))]
impl<T: Send + ?Sized> MaybeSend for T {}

/// Single-threaded `wasm32` guest relaxation of [`MaybeSend`].
#[cfg(target_arch = "wasm32")]
pub trait MaybeSend {}
#[cfg(target_arch = "wasm32")]
impl<T: ?Sized> MaybeSend for T {}

/// Thread-safety marker equivalent to `Sync` on multi-threaded host targets
/// and unconditional on single-threaded `wasm32` guests.
#[cfg(not(target_arch = "wasm32"))]
pub trait MaybeSync: Sync {}
#[cfg(not(target_arch = "wasm32"))]
impl<T: Sync + ?Sized> MaybeSync for T {}

/// Single-threaded `wasm32` guest relaxation of [`MaybeSync`].
#[cfg(target_arch = "wasm32")]
pub trait MaybeSync {}
#[cfg(target_arch = "wasm32")]
impl<T: ?Sized> MaybeSync for T {}

/// Service handler contract driven by [`drive_mux`].
pub trait MuxDispatcher: MaybeSend + MaybeSync + 'static {
    /// Whether this peer serves `(instance, func)`.
    fn supports(&self, instance: &str, func: &str) -> bool;

    /// Handles an accepted incoming invocation. Returning `Err(WireError)`
    /// reports a structured [`Frame::Fault`] for that invocation without
    /// tearing down the connection.
    fn dispatch(
        &self,
        call: InboundCall,
        instance: String,
        func: String,
    ) -> impl Future<Output = Result<(), WireError>> + MaybeSend + '_;

    /// Drops a connection-local exported resource when the peer emits
    /// [`Frame::ResourceDrop`].
    fn drop_resource(
        &self,
        handle: u32,
    ) -> impl Future<Output = Result<(), WireError>> + MaybeSend + '_;

    /// Releases every remaining connection-scoped resource when the transport
    /// disconnects.
    fn on_disconnect(&self) -> impl Future<Output = ()> + MaybeSend + '_;
}

/// Cloneable, concrete connection handle for initiating outbound invocations
/// and dropping remote resource handles from any task.
#[derive(Clone)]
pub struct PeerHandle {
    state: Arc<MuxShared>,
    outgoing_tx: Sender<QueuedFrame>,
    control_tx: Sender<ControlEvent>,
}

impl std::fmt::Debug for PeerHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerHandle")
            .field("closed", &self.is_closed())
            .finish()
    }
}

struct MuxShared {
    config: MuxConfig,
    closed: AtomicBool,
    shutdown: AtomicBool,
    #[cfg(feature = "host")]
    echo_remote_serial: AtomicBool,
    next_invocation: AtomicU32,
    outbound: Mutex<HashMap<u32, Weak<CallCore>>>,
    /// Keeps `CallCore` alive while pre-buffered outbound streams/futures
    /// (`FutureReader::ready`, `StreamReader::from_vec`) wait for peer credit.
    buffered_keepalive: Mutex<HashMap<(CallSide, u32, u32), Arc<CallCore>>>,
    disconnect_reason: Mutex<Option<String>>,
    guest_panic: Mutex<Option<String>>,
    progress: Progress,
}

struct QueuedFrame {
    frame: Frame,
    ack: Sender<io::Result<()>>,
}

enum ControlEvent {
    Frame(Frame),
    LocalDropSubpath { core: Arc<CallCore>, path: Vec<u32> },
    Shutdown,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum CallSide {
    Caller,
    Callee,
}

impl CallSide {
    fn out_data_dir(self) -> u32 {
        match self {
            Self::Caller => DIR_CALLER_TO_CALLEE,
            Self::Callee => DIR_CALLEE_TO_CALLER,
        }
    }

    fn in_data_dir(self) -> u32 {
        match self {
            Self::Caller => DIR_CALLEE_TO_CALLER,
            Self::Callee => DIR_CALLER_TO_CALLEE,
        }
    }

    fn out_stop_dir(self) -> u32 {
        match self {
            Self::Caller => DIR_CALLER_STOP_READING,
            Self::Callee => DIR_CALLEE_STOP_READING,
        }
    }
}

enum OpenReply {
    Accept,
    Reject(String),
    Fault(WireError),
}

#[derive(Default)]
struct ActivePath {
    chunks: VecDeque<Bytes>,
    peer_closed: bool,
    credits: Option<u32>,
}

#[derive(Default)]
struct InboundPathTable {
    active: HashMap<Vec<u32>, ActivePath>,
    /// Compact tombstones for locally-finished/dropped sub-paths awaiting the
    /// peer's `Frame::Close`. Maps `path -> remaining_granted_credits` so late
    /// legitimately credited frames are discarded without leaking
    /// `undelivered_bytes` while excess frames still fail with
    /// `StreamCreditExceeded`.
    draining: HashMap<Vec<u32>, u32>,
    draining_order: VecDeque<Vec<u32>>,
    undelivered_bytes: usize,
    error: Option<Fault>,
}

impl InboundPathTable {
    fn admits_active_path(&self, path: &[u32], max_paths: usize) -> bool {
        self.active.contains_key(path) || self.active.len() < max_paths
    }

    fn insert_draining(&mut self, path: Vec<u32>, remaining_credits: u32, max_paths: usize) {
        let cap = max_paths.saturating_mul(4).max(64);
        if let Some(existing) = self.draining.get_mut(&path) {
            *existing = remaining_credits;
            return;
        }
        while self.draining.len() >= cap {
            let Some(oldest) = self.draining_order.pop_front() else {
                break;
            };
            self.draining.remove(&oldest);
        }
        self.draining.insert(path.clone(), remaining_credits);
        self.draining_order.push_back(path);
        if self.draining_order.len() > cap.saturating_mul(2) {
            self.draining_order
                .retain(|queued| self.draining.contains_key(queued));
        }
    }

    fn remove_draining(&mut self, path: &[u32]) -> bool {
        self.draining.remove(path).is_some()
    }

    /// Reclaims buffered chunks and active path slot immediately when a local
    /// `SubpathReader` is dropped before peer EOF.
    fn local_drop_subpath(&mut self, path: &[u32], max_paths: usize) {
        let Some(entry) = self.active.remove(path) else {
            return;
        };
        let released: usize = entry.chunks.iter().map(Bytes::len).sum();
        self.undelivered_bytes = self.undelivered_bytes.saturating_sub(released);
        if !entry.peer_closed {
            let remaining = entry.credits.unwrap_or(0);
            self.insert_draining(path.to_vec(), remaining, max_paths);
        }
    }

    fn fail_wire(&mut self, error: WireError) {
        if self.error.is_none() {
            self.error = Some(Fault::Wire(error));
        }
        self.active.clear();
        self.draining.clear();
        self.draining_order.clear();
        self.undelivered_bytes = 0;
    }
}

struct WriterSlot {
    credits: AtomicU32,
    peer_stopped: AtomicBool,
    progress: Progress,
}

impl WriterSlot {
    fn new() -> Self {
        Self {
            credits: AtomicU32::new(0),
            peer_stopped: AtomicBool::new(false),
            progress: Progress::new(),
        }
    }
}

struct CallCore {
    invocation: u32,
    side: CallSide,
    shared: Arc<MuxShared>,
    outgoing_tx: Sender<QueuedFrame>,
    control_tx: Sender<ControlEvent>,
    next_subpath: AtomicU32,
    accepted: AtomicBool,
    cancelled: AtomicBool,
    reply: Mutex<Option<OpenReply>>,
    inbound: Mutex<InboundPathTable>,
    writers: Mutex<BTreeMap<u32, Arc<WriterSlot>>>,
    prebuffered_streams: Mutex<BTreeMap<u32, VecDeque<Vec<u8>>>>,
    progress: Progress,
}

impl CallCore {
    fn new(
        invocation: u32,
        side: CallSide,
        shared: Arc<MuxShared>,
        outgoing_tx: Sender<QueuedFrame>,
        control_tx: Sender<ControlEvent>,
    ) -> Arc<Self> {
        Arc::new(Self {
            invocation,
            side,
            shared,
            outgoing_tx,
            control_tx,
            next_subpath: AtomicU32::new(1),
            accepted: AtomicBool::new(matches!(side, CallSide::Callee)),
            cancelled: AtomicBool::new(false),
            reply: Mutex::new(None),
            inbound: Mutex::new(InboundPathTable::default()),
            writers: Mutex::new(BTreeMap::new()),
            prebuffered_streams: Mutex::new(BTreeMap::new()),
            progress: Progress::new(),
        })
    }

    async fn send_frame(&self, frame: Frame) -> Result<(), TransportError> {
        send_queued_frame(&self.shared, &self.outgoing_tx, frame).await
    }

    fn send_control(&self, frame: Frame) {
        if !self.shared.closed.load(Ordering::Acquire) {
            let _ = self.control_tx.try_send(ControlEvent::Frame(frame));
        }
    }

    async fn send_control_async(&self, frame: Frame) {
        if !self.shared.closed.load(Ordering::Acquire) {
            let _ = self.control_tx.send(ControlEvent::Frame(frame)).await;
        }
    }

    async fn failure_error(&self) -> Option<TransportError> {
        self.inbound
            .lock()
            .await
            .error
            .as_ref()
            .map(Fault::to_transport)
    }

    async fn push_data(&self, path: Vec<u32>, payload: Bytes) -> Result<(), WireError> {
        let mut wire_fault = None;
        {
            let mut inbound = self.inbound.lock().await;
            if inbound.error.is_some() {
                return Ok(());
            }
            if path.len() >= 2
                && let Some(remaining) = inbound.draining.get_mut(&path)
            {
                // Local reader already dropped/completed before peer EOF:
                // discard legitimately credited late frames without buffering
                // or touching `undelivered_bytes`, while still rejecting any
                // frame sent past the granted credit window.
                if *remaining > 0 {
                    *remaining -= 1;
                    return Ok(());
                }
                let err = WireError::StreamCreditExceeded {
                    invocation: self.invocation,
                    path,
                };
                inbound.fail_wire(err.clone());
                wire_fault = Some(err);
            } else if !inbound.admits_active_path(&path, self.shared.config.max_inbound_paths) {
                let err = WireError::TooManyInboundPaths {
                    invocation: self.invocation,
                    max: self.shared.config.max_inbound_paths,
                };
                inbound.fail_wire(err.clone());
                wire_fault = Some(err);
            } else if path.len() >= 2 {
                let current_bytes = inbound.undelivered_bytes;
                let max_bytes = self.shared.config.max_undelivered_bytes;
                match inbound.active.get_mut(&path).and_then(|entry| {
                    let credits = entry.credits.as_mut()?;
                    Some((credits, &mut entry.chunks))
                }) {
                    Some((credits, chunks)) if *credits > 0 => {
                        if current_bytes + payload.len() > max_bytes {
                            let held = current_bytes + payload.len();
                            let err = WireError::InboundBacklogExceeded {
                                invocation: self.invocation,
                                held,
                                max: max_bytes,
                            };
                            inbound.fail_wire(err.clone());
                            wire_fault = Some(err);
                        } else {
                            *credits -= 1;
                            chunks.push_back(payload.clone());
                            inbound.undelivered_bytes += payload.len();
                        }
                    }
                    _ => {
                        let err = WireError::StreamCreditExceeded {
                            invocation: self.invocation,
                            path,
                        };
                        inbound.fail_wire(err.clone());
                        wire_fault = Some(err);
                    }
                }
            } else if inbound.undelivered_bytes + payload.len()
                > self.shared.config.max_undelivered_bytes
            {
                let held = inbound.undelivered_bytes + payload.len();
                let err = WireError::InboundBacklogExceeded {
                    invocation: self.invocation,
                    held,
                    max: self.shared.config.max_undelivered_bytes,
                };
                inbound.fail_wire(err.clone());
                wire_fault = Some(err);
            } else {
                inbound.undelivered_bytes += payload.len();
                inbound
                    .active
                    .entry(path)
                    .or_default()
                    .chunks
                    .push_back(payload);
            }
        }
        if wire_fault.is_some() {
            self.clear_prebuffered().await;
            self.wake_writers(false).await;
        }
        self.progress.signal();
        match wire_fault {
            Some(err) => Err(err),
            None => Ok(()),
        }
    }

    async fn push_close(&self, path: Vec<u32>) -> Result<(), WireError> {
        let mut wire_fault = None;
        {
            let mut inbound = self.inbound.lock().await;
            if inbound.error.is_some() {
                return Ok(());
            }
            if path.len() >= 2 && inbound.remove_draining(&path) {
                return Ok(());
            }
            if inbound.admits_active_path(&path, self.shared.config.max_inbound_paths) {
                inbound.active.entry(path).or_default().peer_closed = true;
            } else {
                let err = WireError::TooManyInboundPaths {
                    invocation: self.invocation,
                    max: self.shared.config.max_inbound_paths,
                };
                inbound.fail_wire(err.clone());
                wire_fault = Some(err);
            }
        }
        if wire_fault.is_some() {
            self.clear_prebuffered().await;
            self.wake_writers(false).await;
        }
        self.progress.signal();
        match wire_fault {
            Some(err) => Err(err),
            None => Ok(()),
        }
    }

    async fn notify_peer_stopped(&self, sub_id: u32) {
        self.prebuffered_streams.lock().await.remove(&sub_id);
        self.shared
            .buffered_keepalive
            .lock()
            .await
            .remove(&(self.side, self.invocation, sub_id));
        let slot = self.writers.lock().await.get(&sub_id).cloned();
        if let Some(slot) = slot {
            slot.peer_stopped.store(true, Ordering::Release);
            slot.progress.signal();
        }
    }

    async fn grant_credit(
        &self,
        path: Vec<u32>,
        sub_id: u32,
        credits: u32,
    ) -> Result<Vec<Frame>, WireError> {
        if credits == 0 {
            let err = WireError::CreditOverflow {
                invocation: self.invocation,
                path,
                credits,
            };
            self.inbound.lock().await.fail_wire(err.clone());
            self.progress.signal();
            return Err(err);
        }

        let buffered_action = {
            let mut buffered = self.prebuffered_streams.lock().await;
            if let Some(queue) = buffered.get_mut(&sub_id) {
                let mut to_send = Vec::new();
                for _ in 0..credits {
                    if let Some(payload) = queue.pop_front() {
                        to_send.push(payload);
                    } else {
                        break;
                    }
                }
                let finished = queue.is_empty();
                if finished {
                    buffered.remove(&sub_id);
                }
                Some((to_send, finished))
            } else {
                None
            }
        };

        if let Some((payloads, finished)) = buffered_action {
            let out_path = vec![self.side.out_data_dir(), sub_id];
            let mut frames = Vec::with_capacity(payloads.len() + usize::from(finished));
            for payload in payloads {
                frames.push(Frame::Data {
                    invocation: self.invocation,
                    path: out_path.clone(),
                    payload,
                });
            }
            if finished {
                frames.push(Frame::Close {
                    invocation: self.invocation,
                    path: out_path,
                });
                self.shared.buffered_keepalive.lock().await.remove(&(
                    self.side,
                    self.invocation,
                    sub_id,
                ));
            }
            return Ok(frames);
        }

        let slot = self.writers.lock().await.get(&sub_id).cloned();
        if let Some(slot) = slot {
            let mut current = slot.credits.load(Ordering::Acquire);
            loop {
                let Some(next) = current.checked_add(credits) else {
                    let err = WireError::CreditOverflow {
                        invocation: self.invocation,
                        path,
                        credits,
                    };
                    self.inbound.lock().await.fail_wire(err.clone());
                    self.progress.signal();
                    slot.progress.signal();
                    return Err(err);
                };
                match slot.credits.compare_exchange_weak(
                    current,
                    next,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => {
                        slot.progress.signal();
                        break;
                    }
                    Err(actual) => current = actual,
                }
            }
        }
        Ok(Vec::new())
    }

    async fn clear_prebuffered(&self) {
        let keys: Vec<u32> = {
            let mut prebuffered = self.prebuffered_streams.lock().await;
            std::mem::take(&mut *prebuffered).into_keys().collect()
        };
        if !keys.is_empty() {
            let mut keepalive = self.shared.buffered_keepalive.lock().await;
            for sub_id in keys {
                keepalive.remove(&(self.side, self.invocation, sub_id));
            }
        }
    }

    async fn wake_writers(&self, mark_stopped: bool) {
        let slots: Vec<Arc<WriterSlot>> = self.writers.lock().await.values().cloned().collect();
        for slot in slots {
            if mark_stopped {
                slot.peer_stopped.store(true, Ordering::Release);
            }
            slot.progress.signal();
        }
    }

    async fn cancel_from_peer(&self) {
        self.cancelled.store(true, Ordering::Release);
        {
            let mut inbound = self.inbound.lock().await;
            if inbound.error.is_none() {
                inbound.error = Some(Fault::Remote("invocation cancelled by caller".to_owned()));
            }
        }
        self.clear_prebuffered().await;
        self.wake_writers(true).await;
        self.progress.signal();
    }

    async fn fail_remote(&self, message: String) {
        {
            let mut inbound = self.inbound.lock().await;
            if inbound.error.is_none() {
                inbound.error = Some(Fault::Remote(message));
            }
        }
        self.clear_prebuffered().await;
        self.wake_writers(false).await;
        self.progress.signal();
    }

    async fn fail_guest_panic(&self, report: String) {
        {
            let mut inbound = self.inbound.lock().await;
            if inbound.error.is_none() {
                inbound.error = Some(Fault::GuestPanicked(report));
            }
        }
        self.clear_prebuffered().await;
        self.wake_writers(false).await;
        self.progress.signal();
    }

    async fn fail_wire(&self, error: WireError) {
        {
            let mut inbound = self.inbound.lock().await;
            inbound.fail_wire(error);
        }
        self.clear_prebuffered().await;
        self.wake_writers(false).await;
        self.progress.signal();
    }
}

/// Outbound (caller-side) invocation handle.
///
/// Dropping [`OutboundCall`] before [`Self::recv_root_response`] finishes
/// emits a root [`Frame::Close`] (`path: []`) so the callee cancels its
/// in-flight handler future.
pub struct OutboundCall {
    core: Arc<CallCore>,
    root_completed: bool,
}

impl Drop for OutboundCall {
    fn drop(&mut self) {
        if !self.root_completed {
            self.core.send_control(Frame::Close {
                invocation: self.core.invocation,
                path: Vec::new(),
            });
        }
    }
}

/// Inbound (callee-side) invocation handle handed to [`MuxDispatcher::dispatch`].
#[derive(Clone)]
pub struct InboundCall {
    core: Arc<CallCore>,
    peer: PeerHandle,
}

/// Lock-free watcher for whether a [`SubpathWriter`]'s remote consumer has
/// stopped reading, cancelled the invocation, or disconnected.
#[derive(Clone)]
pub struct SubpathStopWatch {
    core: Arc<CallCore>,
    slot: Arc<WriterSlot>,
}

impl SubpathStopWatch {
    pub fn is_peer_stopped(&self) -> bool {
        self.slot.peer_stopped.load(Ordering::Acquire)
            || self.core.cancelled.load(Ordering::Acquire)
            || self.core.shared.closed.load(Ordering::Acquire)
    }

    pub async fn wait_peer_stopped(&self) {
        loop {
            let slot_mark = self.slot.progress.mark();
            let call_mark = self.core.progress.mark();
            let conn_mark = self.core.shared.progress.mark();
            if self.is_peer_stopped() || self.core.failure_error().await.is_some() {
                return;
            }
            futures_lite::future::or(
                self.slot.progress.changed(slot_mark),
                futures_lite::future::or(
                    self.core.progress.changed(call_mark),
                    self.core.shared.progress.changed(conn_mark),
                ),
            )
            .await;
        }
    }
}

/// Credit-controlled sub-path writer backing `stream<T>` and `future<T>`.
pub struct SubpathWriter {
    core: Arc<CallCore>,
    sub_id: u32,
    slot: Arc<WriterSlot>,
    closed: bool,
}

impl Drop for SubpathWriter {
    fn drop(&mut self) {
        if let Some(mut writers) = self.core.writers.try_lock() {
            writers.remove(&self.sub_id);
        }
        if !self.closed {
            self.core.send_control(Frame::Close {
                invocation: self.core.invocation,
                path: vec![self.core.side.out_data_dir(), self.sub_id],
            });
        }
    }
}

/// Credit-granting sub-path reader backing `stream<T>` and `future<T>`.
pub struct SubpathReader {
    core: Arc<CallCore>,
    sub_id: u32,
    path: Vec<u32>,
    replenish_credits: bool,
    reached_eof: bool,
}

impl Drop for SubpathReader {
    fn drop(&mut self) {
        if !self.reached_eof {
            self.core.send_control(Frame::Close {
                invocation: self.core.invocation,
                path: vec![self.core.side.out_stop_dir(), self.sub_id],
            });
            if let Some(mut inbound) = self.core.inbound.try_lock() {
                inbound.local_drop_subpath(&self.path, self.core.shared.config.max_inbound_paths);
            } else if !self.core.shared.closed.load(Ordering::Acquire) {
                let _ = self
                    .core
                    .control_tx
                    .try_send(ControlEvent::LocalDropSubpath {
                        core: Arc::clone(&self.core),
                        path: std::mem::take(&mut self.path),
                    });
            }
        }
    }
}

/// Shared invocation context for allocating and opening sub-paths regardless
/// of whether the local peer is the caller or callee.
#[derive(Clone)]
pub struct CallHandle {
    core: Arc<CallCore>,
}

impl CallHandle {
    pub fn peer(&self) -> PeerHandle {
        PeerHandle {
            state: Arc::clone(&self.core.shared),
            outgoing_tx: self.core.outgoing_tx.clone(),
            control_tx: self.core.control_tx.clone(),
        }
    }

    pub fn alloc_subpath_id(&self) -> u32 {
        self.core.next_subpath.fetch_add(1, Ordering::Relaxed)
    }

    pub async fn register_writer(&self, sub_id: u32) -> SubpathWriter {
        let slot = Arc::new(WriterSlot::new());
        self.core
            .writers
            .lock()
            .await
            .insert(sub_id, Arc::clone(&slot));
        SubpathWriter {
            core: Arc::clone(&self.core),
            sub_id,
            slot,
            closed: false,
        }
    }

    pub fn register_empty(&self, sub_id: u32) {
        self.core.send_control(Frame::Close {
            invocation: self.core.invocation,
            path: vec![self.core.side.out_data_dir(), sub_id],
        });
    }

    pub async fn register_buffered(&self, sub_id: u32, frames: VecDeque<Vec<u8>>) {
        if frames.is_empty() {
            self.register_empty(sub_id);
        } else {
            self.core
                .prebuffered_streams
                .lock()
                .await
                .insert(sub_id, frames);
            self.core.shared.buffered_keepalive.lock().await.insert(
                (self.core.side, self.core.invocation, sub_id),
                Arc::clone(&self.core),
            );
        }
    }

    pub async fn open_reader(
        &self,
        sub_id: u32,
        credit_window: u32,
    ) -> Result<SubpathReader, TransportError> {
        open_reader(&self.core, sub_id, credit_window, true).await
    }

    pub async fn open_oneshot_reader(&self, sub_id: u32) -> Result<SubpathReader, TransportError> {
        open_reader(&self.core, sub_id, 1, false).await
    }
}

impl OutboundCall {
    pub fn invocation_id(&self) -> u32 {
        self.core.invocation
    }

    pub fn call_handle(&self) -> CallHandle {
        CallHandle {
            core: Arc::clone(&self.core),
        }
    }

    pub fn peer(&self) -> PeerHandle {
        PeerHandle {
            state: Arc::clone(&self.core.shared),
            outgoing_tx: self.core.outgoing_tx.clone(),
            control_tx: self.core.control_tx.clone(),
        }
    }

    pub async fn send_root_request(&self, payload: &[u8]) -> Result<(), TransportError> {
        send_chunked_root(&self.core, payload).await
    }

    pub async fn recv_root_response(&mut self) -> Result<Vec<u8>, TransportError> {
        let bytes = recv_root_all(&self.core).await?;
        self.root_completed = true;
        Ok(bytes)
    }
}

impl InboundCall {
    pub fn invocation_id(&self) -> u32 {
        self.core.invocation
    }

    pub fn call_handle(&self) -> CallHandle {
        CallHandle {
            core: Arc::clone(&self.core),
        }
    }

    pub fn peer(&self) -> &PeerHandle {
        &self.peer
    }

    pub fn is_cancelled(&self) -> bool {
        self.core.cancelled.load(Ordering::Acquire)
    }

    pub async fn recv_root_request(&self) -> Result<Vec<u8>, TransportError> {
        recv_root_all(&self.core).await
    }

    pub async fn send_root_response(&self, payload: &[u8]) -> Result<(), TransportError> {
        send_chunked_root(&self.core, payload).await
    }
}

impl SubpathWriter {
    pub fn call_handle(&self) -> CallHandle {
        CallHandle {
            core: Arc::clone(&self.core),
        }
    }

    pub fn peer(&self) -> PeerHandle {
        PeerHandle {
            state: Arc::clone(&self.core.shared),
            outgoing_tx: self.core.outgoing_tx.clone(),
            control_tx: self.core.control_tx.clone(),
        }
    }

    pub fn stop_watch(&self) -> SubpathStopWatch {
        SubpathStopWatch {
            core: Arc::clone(&self.core),
            slot: Arc::clone(&self.slot),
        }
    }

    pub fn is_peer_stopped(&self) -> bool {
        self.stop_watch().is_peer_stopped()
    }

    pub async fn wait_peer_stopped(&self) {
        self.stop_watch().wait_peer_stopped().await;
    }

    pub async fn send(&mut self, payload: Vec<u8>) -> Result<(), TransportError> {
        if self.closed {
            return Err(TransportError::Closed);
        }
        loop {
            let slot_mark = self.slot.progress.mark();
            let call_mark = self.core.progress.mark();
            let conn_mark = self.core.shared.progress.mark();

            if let Some(err) = self.core.failure_error().await {
                return Err(err);
            }
            if self.slot.peer_stopped.load(Ordering::Acquire)
                || self.core.cancelled.load(Ordering::Acquire)
                || self.core.shared.closed.load(Ordering::Acquire)
            {
                return Err(TransportError::Closed);
            }

            let available = self.slot.credits.load(Ordering::Acquire);
            if available > 0
                && self
                    .slot
                    .credits
                    .compare_exchange(
                        available,
                        available - 1,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    )
                    .is_ok()
            {
                break;
            }

            futures_lite::future::or(
                self.slot.progress.changed(slot_mark),
                futures_lite::future::or(
                    self.core.progress.changed(call_mark),
                    self.core.shared.progress.changed(conn_mark),
                ),
            )
            .await;
        }

        self.core
            .send_frame(Frame::Data {
                invocation: self.core.invocation,
                path: vec![self.core.side.out_data_dir(), self.sub_id],
                payload,
            })
            .await
    }

    pub async fn close(mut self) -> Result<(), TransportError> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        self.core.writers.lock().await.remove(&self.sub_id);
        self.core
            .send_frame(Frame::Close {
                invocation: self.core.invocation,
                path: vec![self.core.side.out_data_dir(), self.sub_id],
            })
            .await
    }
}

impl SubpathReader {
    pub fn call_handle(&self) -> CallHandle {
        CallHandle {
            core: Arc::clone(&self.core),
        }
    }

    pub fn peer(&self) -> PeerHandle {
        PeerHandle {
            state: Arc::clone(&self.core.shared),
            outgoing_tx: self.core.outgoing_tx.clone(),
            control_tx: self.core.control_tx.clone(),
        }
    }

    pub async fn recv(&mut self) -> Result<Option<Bytes>, TransportError> {
        if self.reached_eof {
            return Ok(None);
        }
        loop {
            let call_mark = self.core.progress.mark();
            let conn_mark = self.core.shared.progress.mark();

            let outcome = {
                let mut inbound = self.core.inbound.lock().await;
                let max_paths = self.core.shared.config.max_inbound_paths;
                if let Some(entry) = inbound.active.get_mut(&self.path)
                    && let Some(chunk) = entry.chunks.pop_front()
                {
                    let peer_closed = entry.peer_closed;
                    let replenish = if self.replenish_credits
                        && !peer_closed
                        && let Some(credits) = entry.credits.as_mut()
                    {
                        *credits = credits.saturating_add(1);
                        true
                    } else {
                        false
                    };
                    let chunk_len = chunk.len();
                    if !self.replenish_credits {
                        // Single-shot future sub-path completes after its one
                        // payload: reclaim the active slot immediately so
                        // sequential futures never accumulate in `active`. If
                        // the peer's trailing `Frame::Close` has not arrived
                        // yet, leave a 0-credit tombstone so that `Close` is
                        // absorbed cleanly while any duplicate `Data` fails
                        // with `StreamCreditExceeded`.
                        if let Some(removed) = inbound.active.remove(&self.path) {
                            let extra_bytes: usize = removed.chunks.iter().map(Bytes::len).sum();
                            inbound.undelivered_bytes = inbound
                                .undelivered_bytes
                                .saturating_sub(chunk_len + extra_bytes);
                            if !removed.peer_closed {
                                inbound.insert_draining(self.path.clone(), 0, max_paths);
                            }
                        } else {
                            inbound.undelivered_bytes =
                                inbound.undelivered_bytes.saturating_sub(chunk_len);
                        }
                    } else {
                        inbound.undelivered_bytes =
                            inbound.undelivered_bytes.saturating_sub(chunk_len);
                    }
                    Some(Ok(Some((chunk, replenish))))
                } else if inbound
                    .active
                    .get(&self.path)
                    .is_some_and(|entry| entry.peer_closed)
                {
                    // Peer EOF observed and all chunks drained: reclaim the
                    // sub-path slot completely.
                    inbound.active.remove(&self.path);
                    Some(Ok(None))
                } else {
                    inbound
                        .error
                        .as_ref()
                        .map(|fault| Err(fault.to_transport()))
                }
            };

            match outcome {
                Some(Ok(Some((chunk, replenish)))) => {
                    if replenish {
                        self.core
                            .send_control_async(Frame::Credit {
                                invocation: self.core.invocation,
                                path: self.path.clone(),
                                credits: 1,
                            })
                            .await;
                    } else if !self.replenish_credits {
                        // Single-shot future sub-paths never replenish credit
                        // and are complete after the single value frame; mark
                        // EOF so dropping the reader emits no spurious stop
                        // notification while leaving inbound credit at 0.
                        self.reached_eof = true;
                    }
                    return Ok(Some(chunk));
                }
                Some(Ok(None)) => {
                    self.reached_eof = true;
                    return Ok(None);
                }
                Some(Err(err)) => return Err(err),
                None => {}
            }

            if self.core.shared.closed.load(Ordering::Acquire) {
                return Err(TransportError::Closed);
            }

            futures_lite::future::or(
                self.core.progress.changed(call_mark),
                self.core.shared.progress.changed(conn_mark),
            )
            .await;
        }
    }
}

async fn open_reader(
    core: &Arc<CallCore>,
    sub_id: u32,
    credit_window: u32,
    replenish_credits: bool,
) -> Result<SubpathReader, TransportError> {
    let window = credit_window.max(1);
    let path = vec![core.side.in_data_dir(), sub_id];
    let send_credit = {
        let mut inbound = core.inbound.lock().await;
        if !inbound.admits_active_path(&path, core.shared.config.max_inbound_paths) {
            let err = WireError::TooManyInboundPaths {
                invocation: core.invocation,
                max: core.shared.config.max_inbound_paths,
            };
            inbound.fail_wire(err.clone());
            return Err(TransportError::Wire(err));
        }
        let entry = inbound.active.entry(path.clone()).or_default();
        if entry.peer_closed {
            entry.credits = Some(0);
            false
        } else {
            entry.credits = Some(window);
            true
        }
    };
    if send_credit {
        core.send_control_async(Frame::Credit {
            invocation: core.invocation,
            path: path.clone(),
            credits: window,
        })
        .await;
    }
    Ok(SubpathReader {
        core: Arc::clone(core),
        sub_id,
        path,
        replenish_credits,
        reached_eof: false,
    })
}

async fn send_chunked_root(core: &Arc<CallCore>, payload: &[u8]) -> Result<(), TransportError> {
    let path = vec![core.side.out_data_dir()];
    for chunk in payload.chunks(RAW_UPLOAD_CHUNK_BYTES) {
        core.send_frame(Frame::Data {
            invocation: core.invocation,
            path: path.clone(),
            payload: chunk.to_vec(),
        })
        .await?;
    }
    core.send_frame(Frame::Close {
        invocation: core.invocation,
        path,
    })
    .await
}

async fn recv_root_all(core: &Arc<CallCore>) -> Result<Vec<u8>, TransportError> {
    let path = vec![core.side.in_data_dir()];
    let mut output = Vec::new();
    loop {
        let call_mark = core.progress.mark();
        let conn_mark = core.shared.progress.mark();

        let step = {
            let mut inbound = core.inbound.lock().await;
            if let Some(entry) = inbound.active.get_mut(&path) {
                let mut drained = Vec::new();
                let mut released = 0usize;
                while let Some(chunk) = entry.chunks.pop_front() {
                    released += chunk.len();
                    drained.extend_from_slice(&chunk);
                }
                let done = entry.peer_closed;
                if done {
                    inbound.active.remove(&path);
                }
                inbound.undelivered_bytes = inbound.undelivered_bytes.saturating_sub(released);
                if !drained.is_empty() || done {
                    Some(Ok((drained, done)))
                } else {
                    inbound
                        .error
                        .as_ref()
                        .map(|fault| Err(fault.to_transport()))
                }
            } else {
                inbound
                    .error
                    .as_ref()
                    .map(|fault| Err(fault.to_transport()))
            }
        };

        match step {
            Some(Ok((bytes, done))) => {
                output.extend_from_slice(&bytes);
                if done {
                    return Ok(output);
                }
            }
            Some(Err(err)) => return Err(err),
            None => {}
        }

        if core.shared.closed.load(Ordering::Acquire) {
            return Err(TransportError::Closed);
        }

        futures_lite::future::or(
            core.progress.changed(call_mark),
            core.shared.progress.changed(conn_mark),
        )
        .await;
    }
}

async fn send_queued_frame(
    shared: &MuxShared,
    outgoing_tx: &Sender<QueuedFrame>,
    frame: Frame,
) -> Result<(), TransportError> {
    if shared.closed.load(Ordering::Acquire) {
        return Err(TransportError::Closed);
    }
    let (ack_tx, ack_rx) = async_channel::bounded(1);
    outgoing_tx
        .send(QueuedFrame { frame, ack: ack_tx })
        .await
        .map_err(|_| TransportError::Closed)?;
    let res = ack_rx.recv().await.map_err(|_| TransportError::Closed)?;
    res.map_err(|source| TransportError::io("write mux frame", source))
}

impl PeerHandle {
    pub fn is_closed(&self) -> bool {
        self.state.closed.load(Ordering::Acquire)
    }

    #[cfg(feature = "host")]
    pub fn set_remote_serial_echo(&self, echo: bool) -> bool {
        self.state.echo_remote_serial.swap(echo, Ordering::AcqRel)
    }

    pub async fn closed_error(&self) -> TransportError {
        if let Some(report) = self.state.guest_panic.lock().await.clone() {
            TransportError::GuestPanicked { report }
        } else {
            TransportError::Closed
        }
    }

    pub fn stream_credit_window(&self) -> u32 {
        self.state.config.stream_credit_window
    }

    pub fn close(&self) {
        self.state.shutdown.store(true, Ordering::Release);
        self.state.progress.signal();
        let _ = self.control_tx.try_send(ControlEvent::Shutdown);
    }

    pub fn drop_remote_resource(&self, handle: u32) {
        if !self.is_closed() {
            let _ = self
                .control_tx
                .try_send(ControlEvent::Frame(Frame::ResourceDrop { handle }));
        }
    }

    pub async fn open_call(
        &self,
        instance: &str,
        func: &str,
    ) -> Result<OutboundCall, TransportError> {
        if self.is_closed() {
            return Err(self.closed_error().await);
        }
        let id = self.state.next_invocation.fetch_add(1, Ordering::Relaxed);
        let core = CallCore::new(
            id,
            CallSide::Caller,
            Arc::clone(&self.state),
            self.outgoing_tx.clone(),
            self.control_tx.clone(),
        );
        {
            let mut outbound = self.state.outbound.lock().await;
            outbound.retain(|_, weak| weak.strong_count() > 0);
            outbound.insert(id, Arc::downgrade(&core));
        }

        send_queued_frame(
            &self.state,
            &self.outgoing_tx,
            Frame::Open {
                invocation: id,
                instance: instance.to_owned(),
                func: func.to_owned(),
            },
        )
        .await?;

        let mut call = OutboundCall {
            core: Arc::clone(&core),
            root_completed: false,
        };

        loop {
            let call_mark = core.progress.mark();
            let conn_mark = self.state.progress.mark();

            if let Some(reply) = core.reply.lock().await.take() {
                match reply {
                    OpenReply::Accept => return Ok(call),
                    OpenReply::Reject(message) => {
                        call.root_completed = true;
                        return Err(TransportError::Rejected(message));
                    }
                    OpenReply::Fault(error) => {
                        call.root_completed = true;
                        return Err(TransportError::Wire(error));
                    }
                }
            }
            if let Some(err) = core.failure_error().await {
                call.root_completed = true;
                return Err(err);
            }
            if self.is_closed() {
                call.root_completed = true;
                return Err(self.closed_error().await);
            }

            futures_lite::future::or(
                core.progress.changed(call_mark),
                self.state.progress.changed(conn_mark),
            )
            .await;
        }
    }
}

/// Creates a connected `(PeerHandle, MuxDriverChannels)` pair ready to be
/// driven by [`drive_mux`].
pub fn create_mux(config: MuxConfig) -> (PeerHandle, MuxDriverChannels) {
    let max_outbox = config.max_priority_outbox_frames.max(1);
    let control_cap = max_outbox.saturating_mul(2).max(64);
    let (outgoing_tx, outgoing_rx) = async_channel::bounded(8);
    let (control_tx, control_rx) = async_channel::bounded(control_cap);
    let shared = Arc::new(MuxShared {
        config,
        closed: AtomicBool::new(false),
        shutdown: AtomicBool::new(false),
        #[cfg(feature = "host")]
        echo_remote_serial: AtomicBool::new(true),
        next_invocation: AtomicU32::new(1),
        outbound: Mutex::new(HashMap::new()),
        buffered_keepalive: Mutex::new(HashMap::new()),
        disconnect_reason: Mutex::new(None),
        guest_panic: Mutex::new(None),
        progress: Progress::new(),
    });
    let handle = PeerHandle {
        state: Arc::clone(&shared),
        outgoing_tx,
        control_tx,
    };
    (
        handle.clone(),
        MuxDriverChannels {
            shared,
            peer: handle,
            outgoing_rx,
            control_rx,
        },
    )
}

/// Driver-side channels and state owned exclusively by [`drive_mux`].
pub struct MuxDriverChannels {
    shared: Arc<MuxShared>,
    peer: PeerHandle,
    outgoing_rx: Receiver<QueuedFrame>,
    control_rx: Receiver<ControlEvent>,
}

struct DriverClosedGuard(Arc<MuxShared>);

impl Drop for DriverClosedGuard {
    fn drop(&mut self) {
        self.0.closed.store(true, Ordering::Release);
        self.0.progress.signal();
    }
}

struct InboundLaunch {
    call: InboundCall,
    instance: String,
    func: String,
}

/// Drives symmetric peer-to-peer framing over `read` and `write` inside a
/// single future (`wasm32-wasip3`-safe, zero `spawn`, zero `block_on`, zero
/// `dyn` dispatch) until EOF, shutdown, or transport/protocol fault.
pub async fn drive_mux<R, W, D>(
    read: R,
    write: W,
    channels: MuxDriverChannels,
    dispatcher: &D,
) -> Result<(), TransportError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    D: MuxDispatcher,
{
    let MuxDriverChannels {
        shared,
        peer,
        outgoing_rx,
        control_rx,
    } = channels;
    let _closed_guard = DriverClosedGuard(Arc::clone(&shared));

    let mut inbound_calls: HashMap<u32, Weak<CallCore>> = HashMap::new();
    let mut server_tasks = FuturesUnordered::new();
    let mut priority_outbox: VecDeque<(Frame, Option<Sender<io::Result<()>>>)> = VecDeque::new();

    let mut read_fut = Box::pin(read_next_frame_owned(read, Arc::clone(&shared)));
    let mut writer_slot = Some(write);
    let mut write_fut = None;
    let mut shutdown_requested = false;
    let mut control_rx = std::pin::pin!(control_rx);
    let mut outgoing_rx = std::pin::pin!(outgoing_rx);

    let max_priority_outbox = shared.config.max_priority_outbox_frames.max(1);
    let loop_outcome: Result<(), TransportError> = async {
        enum Step<R> {
            FrameRead(R, io::Result<Option<Frame>>),
            Control(ControlEvent),
            Outgoing(QueuedFrame),
            ServerDone(Option<(u32, WireError)>),
            WriteDone,
            ShutdownSignalled,
        }

        loop {
            if shared.shutdown.load(Ordering::Acquire) {
                shutdown_requested = true;
            }
            while !shutdown_requested && priority_outbox.len() < max_priority_outbox {
                match control_rx.try_recv() {
                    Ok(ControlEvent::Frame(frame)) => priority_outbox.push_back((frame, None)),
                    Ok(ControlEvent::LocalDropSubpath { core, path }) => {
                        core.inbound
                            .lock()
                            .await
                            .local_drop_subpath(&path, shared.config.max_inbound_paths);
                    }
                    Ok(ControlEvent::Shutdown) => {
                        shutdown_requested = true;
                        break;
                    }
                    Err(_) => break,
                }
            }
            if shutdown_requested && write_fut.is_none() && priority_outbox.is_empty() {
                return Ok(());
            }

            while write_fut.is_none() {
                let next_to_send = if let Some(item) = priority_outbox.pop_front() {
                    Some(item)
                } else if !shutdown_requested && let Ok(queued) = outgoing_rx.try_recv() {
                    Some((queued.frame, Some(queued.ack)))
                } else {
                    None
                };

                let Some((frame, ack)) = next_to_send else {
                    break;
                };
                let w = writer_slot
                    .take()
                    .expect("mux writer must be present when write_fut is idle");
                write_fut = Some(Box::pin(write_next_frame_owned(w, frame, ack)));
            }

            if shutdown_requested && write_fut.is_none() && priority_outbox.is_empty() {
                return Ok(());
            }

            let outbox_has_room = priority_outbox.len() < max_priority_outbox;
            let shutdown_mark = shared.progress.mark();
            let mut shutdown_wait = std::pin::pin!(shared.progress.changed(shutdown_mark));

            let step = std::future::poll_fn(|cx| {
                if !shutdown_requested && shared.shutdown.load(Ordering::Acquire) {
                    return Poll::Ready(Ok(Step::ShutdownSignalled));
                }

                if let Some(active_write) = write_fut.as_mut()
                    && let Poll::Ready((w, ack, res)) = active_write.as_mut().poll(cx)
                {
                    write_fut = None;
                    writer_slot = Some(w);
                    match res {
                        Ok(()) => {
                            if let Some(ack) = ack {
                                let _ = ack.try_send(Ok(()));
                            }
                            return Poll::Ready(Ok(Step::WriteDone));
                        }
                        Err(err) => {
                            let msg = err.to_string();
                            if let Some(ack) = ack {
                                let _ = ack.try_send(Err(io::Error::other(msg)));
                            }
                            return Poll::Ready(Err(TransportError::io("write mux frame", err)));
                        }
                    }
                }

                if !server_tasks.is_empty()
                    && let Poll::Ready(Some(done)) = server_tasks.poll_next_unpin(cx)
                {
                    return Poll::Ready(Ok(Step::ServerDone(done)));
                }

                // Pause polling inbound frames whenever `priority_outbox` is at
                // its bound so TCP/IPC backpressure propagates to the peer
                // instead of growing server memory without bound.
                if !shutdown_requested
                    && outbox_has_room
                    && let Poll::Ready((r, frame_res)) = read_fut.as_mut().poll(cx)
                {
                    return Poll::Ready(Ok(Step::FrameRead(r, frame_res)));
                }

                if !shutdown_requested {
                    if outbox_has_room
                        && let Poll::Ready(Some(ctrl)) =
                            futures_core::Stream::poll_next(control_rx.as_mut(), cx)
                    {
                        return Poll::Ready(Ok(Step::Control(ctrl)));
                    }
                    if write_fut.is_none()
                        && outbox_has_room
                        && let Poll::Ready(Some(queued)) =
                            futures_core::Stream::poll_next(outgoing_rx.as_mut(), cx)
                    {
                        return Poll::Ready(Ok(Step::Outgoing(queued)));
                    }
                    if let Poll::Ready(()) = shutdown_wait.as_mut().poll(cx)
                        && shared.shutdown.load(Ordering::Acquire)
                    {
                        return Poll::Ready(Ok(Step::ShutdownSignalled));
                    }
                }

                Poll::Pending
            })
            .await?;

            match step {
                Step::WriteDone => {}
                Step::ShutdownSignalled => {
                    shutdown_requested = true;
                }
                Step::Control(ControlEvent::Frame(frame)) => {
                    priority_outbox.push_back((frame, None));
                }
                Step::Control(ControlEvent::LocalDropSubpath { core, path }) => {
                    core.inbound
                        .lock()
                        .await
                        .local_drop_subpath(&path, shared.config.max_inbound_paths);
                }
                Step::Control(ControlEvent::Shutdown) => {
                    shutdown_requested = true;
                }
                Step::Outgoing(queued) => {
                    priority_outbox.push_back((queued.frame, Some(queued.ack)));
                }
                Step::ServerDone(Some((invocation, wire_error))) => {
                    priority_outbox.push_back((
                        Frame::Fault {
                            invocation,
                            error: wire_error,
                        },
                        None,
                    ));
                }
                Step::ServerDone(None) => {}
                Step::FrameRead(reader_back, frame_res) => {
                    read_fut = Box::pin(read_next_frame_owned(reader_back, Arc::clone(&shared)));
                    let Some(frame) =
                        frame_res.map_err(|source| TransportError::io("read mux frame", source))?
                    else {
                        return Ok(());
                    };
                    if let Some(launch) = route_mux_frame(
                        &shared,
                        &peer,
                        dispatcher,
                        &mut inbound_calls,
                        &mut priority_outbox,
                        server_tasks.len(),
                        frame,
                    )
                    .await?
                    {
                        server_tasks.push(Box::pin(run_inbound_invocation(
                            dispatcher,
                            launch.call,
                            launch.instance,
                            launch.func,
                        )));
                    }
                }
            }
        }
    }
    .await;

    shared.closed.store(true, Ordering::Release);
    let panic_report = loop_outcome
        .as_ref()
        .err()
        .and_then(TransportError::guest_panic)
        .map(ToOwned::to_owned);
    if let Some(report) = &panic_report {
        *shared.guest_panic.lock().await = Some(report.clone());
    }
    let reason = match &loop_outcome {
        Ok(()) => "transport disconnected".to_owned(),
        Err(err) => err.to_string(),
    };
    *shared.disconnect_reason.lock().await = Some(reason.clone());

    let outbound_active: Vec<Arc<CallCore>> = shared
        .outbound
        .lock()
        .await
        .values()
        .filter_map(Weak::upgrade)
        .collect();
    shared.buffered_keepalive.lock().await.clear();
    for call in outbound_active {
        if let Some(report) = &panic_report {
            call.fail_guest_panic(report.clone()).await;
        } else {
            call.fail_remote(reason.clone()).await;
        }
    }
    let inbound_active: Vec<Arc<CallCore>> =
        inbound_calls.values().filter_map(Weak::upgrade).collect();
    for call in inbound_active {
        call.cancel_from_peer().await;
    }
    shared.progress.signal();

    // Drop in-flight server tasks first so active `ResourceBorrow`s release
    // before connection resources are torn down.
    drop(server_tasks);

    dispatcher.on_disconnect().await;

    loop_outcome
}

async fn read_next_frame_owned<R: AsyncRead + Unpin>(
    mut read: R,
    shared: Arc<MuxShared>,
) -> (R, io::Result<Option<Frame>>) {
    #[cfg(feature = "host")]
    let res = read_frame_with_echo(&mut read, &shared.echo_remote_serial).await;
    #[cfg(not(feature = "host"))]
    let res = {
        let _ = &shared;
        read_frame(&mut read).await
    };
    (read, res)
}

async fn write_next_frame_owned<W: AsyncWrite + Unpin>(
    mut write: W,
    frame: Frame,
    ack: Option<Sender<io::Result<()>>>,
) -> (W, Option<Sender<io::Result<()>>>, io::Result<()>) {
    let res = write_frame(&mut write, &frame).await;
    (write, ack, res)
}

async fn resolve_outbound(shared: &MuxShared, invocation: u32) -> Option<Arc<CallCore>> {
    let mut table = shared.outbound.lock().await;
    match table.get(&invocation).and_then(Weak::upgrade) {
        Some(core) => Some(core),
        None => {
            table.remove(&invocation);
            None
        }
    }
}

fn resolve_inbound(
    inbound_calls: &mut HashMap<u32, Weak<CallCore>>,
    invocation: u32,
) -> Option<Arc<CallCore>> {
    match inbound_calls.get(&invocation).and_then(Weak::upgrade) {
        Some(core) => Some(core),
        None => {
            inbound_calls.remove(&invocation);
            None
        }
    }
}

async fn run_inbound_invocation<D: MuxDispatcher>(
    dispatcher: &D,
    call: InboundCall,
    instance: String,
    func: String,
) -> Option<(u32, WireError)> {
    let invocation = call.invocation_id();
    let core = Arc::clone(&call.core);
    let dispatch_fut = dispatcher.dispatch(call, instance, func);
    let cancel_fut = async {
        loop {
            let call_mark = core.progress.mark();
            let conn_mark = core.shared.progress.mark();
            if core.cancelled.load(Ordering::Acquire) || core.shared.closed.load(Ordering::Acquire)
            {
                return;
            }
            futures_lite::future::or(
                core.progress.changed(call_mark),
                core.shared.progress.changed(conn_mark),
            )
            .await;
        }
    };

    let outcome = futures_lite::future::or(async move { Some(dispatch_fut.await) }, async move {
        cancel_fut.await;
        None
    })
    .await;

    match outcome {
        Some(Err(wire_error)) => Some((invocation, wire_error)),
        Some(Ok(())) | None => None,
    }
}

async fn route_mux_frame<D: MuxDispatcher>(
    shared: &Arc<MuxShared>,
    peer: &PeerHandle,
    dispatcher: &D,
    inbound_calls: &mut HashMap<u32, Weak<CallCore>>,
    priority_outbox: &mut VecDeque<(Frame, Option<Sender<io::Result<()>>>)>,
    active_server_tasks: usize,
    frame: Frame,
) -> Result<Option<InboundLaunch>, TransportError> {
    match frame {
        Frame::Open {
            invocation,
            instance,
            func,
        } => {
            if !dispatcher.supports(&instance, &func) {
                priority_outbox.push_back((
                    Frame::Reject {
                        invocation,
                        message: format!("no handler registered for {instance}.{func}"),
                    },
                    None,
                ));
                return Ok(None);
            }
            let max_concurrent = shared.config.max_concurrent_inbound_calls.max(1);
            if active_server_tasks >= max_concurrent {
                priority_outbox.push_back((
                    Frame::Reject {
                        invocation,
                        message: format!(
                            "concurrent inbound invocation limit ({max_concurrent}) reached"
                        ),
                    },
                    None,
                ));
                return Ok(None);
            }
            inbound_calls.retain(|_, weak| weak.strong_count() > 0);
            if resolve_inbound(inbound_calls, invocation).is_some() {
                return Err(TransportError::Wire(WireError::MalformedPayload {
                    context: "Frame::Open".to_owned(),
                    detail: format!("duplicate open for active invocation {invocation}"),
                }));
            }
            let core = CallCore::new(
                invocation,
                CallSide::Callee,
                Arc::clone(shared),
                peer.outgoing_tx.clone(),
                peer.control_tx.clone(),
            );
            inbound_calls.insert(invocation, Arc::downgrade(&core));
            priority_outbox.push_back((Frame::Accept { invocation }, None));
            Ok(Some(InboundLaunch {
                call: InboundCall {
                    core,
                    peer: peer.clone(),
                },
                instance,
                func,
            }))
        }
        Frame::Accept { invocation } => {
            if let Some(core) = resolve_outbound(shared, invocation).await {
                core.accepted.store(true, Ordering::Release);
                *core.reply.lock().await = Some(OpenReply::Accept);
                core.progress.signal();
            }
            Ok(None)
        }
        Frame::Reject {
            invocation,
            message,
        } => {
            if let Some(core) = resolve_outbound(shared, invocation).await {
                if core.accepted.load(Ordering::Acquire) {
                    core.fail_remote(message).await;
                } else {
                    *core.reply.lock().await = Some(OpenReply::Reject(message));
                    core.progress.signal();
                }
            }
            Ok(None)
        }
        Frame::Fault { invocation, error } => {
            if let Some(core) = resolve_outbound(shared, invocation).await {
                if core.accepted.load(Ordering::Acquire) {
                    core.fail_wire(error).await;
                } else {
                    *core.reply.lock().await = Some(OpenReply::Fault(error));
                    core.progress.signal();
                }
            }
            Ok(None)
        }
        Frame::Data {
            invocation,
            path,
            payload,
        } => {
            match path.first().copied() {
                Some(DIR_CALLER_TO_CALLEE) => {
                    if let Some(core) = resolve_inbound(inbound_calls, invocation)
                        && let Err(wire_err) = core.push_data(path, Bytes::from(payload)).await
                    {
                        core.cancel_from_peer().await;
                        priority_outbox.push_back((
                            Frame::Fault {
                                invocation,
                                error: wire_err,
                            },
                            None,
                        ));
                    }
                }
                Some(DIR_CALLEE_TO_CALLER) => {
                    if let Some(core) = resolve_outbound(shared, invocation).await {
                        let _ = core.push_data(path, Bytes::from(payload)).await;
                    }
                }
                _ => {
                    return Err(TransportError::Wire(WireError::MalformedPayload {
                        context: "Frame::Data".to_owned(),
                        detail: format!("invalid direction prefix in data path {path:?}"),
                    }));
                }
            }
            Ok(None)
        }
        Frame::Close { invocation, path } => {
            if path.is_empty() {
                if let Some(core) = resolve_inbound(inbound_calls, invocation) {
                    core.cancel_from_peer().await;
                }
                return Ok(None);
            }
            match path[0] {
                DIR_CALLER_TO_CALLEE => {
                    if let Some(core) = resolve_inbound(inbound_calls, invocation)
                        && let Err(wire_err) = core.push_close(path).await
                    {
                        core.cancel_from_peer().await;
                        priority_outbox.push_back((
                            Frame::Fault {
                                invocation,
                                error: wire_err,
                            },
                            None,
                        ));
                    }
                }
                DIR_CALLEE_TO_CALLER => {
                    if let Some(core) = resolve_outbound(shared, invocation).await {
                        let _ = core.push_close(path).await;
                    }
                }
                DIR_CALLER_STOP_READING if path.len() == 2 => {
                    if let Some(core) = resolve_inbound(inbound_calls, invocation) {
                        core.notify_peer_stopped(path[1]).await;
                    }
                }
                DIR_CALLEE_STOP_READING if path.len() == 2 => {
                    if let Some(core) = resolve_outbound(shared, invocation).await {
                        core.notify_peer_stopped(path[1]).await;
                    }
                }
                _ => {
                    return Err(TransportError::Wire(WireError::MalformedPayload {
                        context: "Frame::Close".to_owned(),
                        detail: format!("invalid close path {path:?}"),
                    }));
                }
            }
            Ok(None)
        }
        Frame::Credit {
            invocation,
            path,
            credits,
        } => {
            if path.len() != 2 {
                return Err(TransportError::Wire(WireError::MalformedPayload {
                    context: "Frame::Credit".to_owned(),
                    detail: format!("credit path {path:?} must have length 2"),
                }));
            }
            let sub_id = path[1];
            match path[0] {
                DIR_CALLER_TO_CALLEE => {
                    if let Some(core) = resolve_outbound(shared, invocation).await
                        && let Ok(frames) = core.grant_credit(path, sub_id, credits).await
                    {
                        for frame in frames {
                            priority_outbox.push_back((frame, None));
                        }
                    }
                }
                DIR_CALLEE_TO_CALLER => {
                    if let Some(core) = resolve_inbound(inbound_calls, invocation) {
                        match core.grant_credit(path, sub_id, credits).await {
                            Ok(frames) => {
                                for frame in frames {
                                    priority_outbox.push_back((frame, None));
                                }
                            }
                            Err(wire_err) => {
                                core.cancel_from_peer().await;
                                priority_outbox.push_back((
                                    Frame::Fault {
                                        invocation,
                                        error: wire_err,
                                    },
                                    None,
                                ));
                            }
                        }
                    }
                }
                _ => {
                    return Err(TransportError::Wire(WireError::MalformedPayload {
                        context: "Frame::Credit".to_owned(),
                        detail: format!("invalid credit direction in path {path:?}"),
                    }));
                }
            }
            Ok(None)
        }
        Frame::ResourceDrop { handle } => {
            dispatcher
                .drop_resource(handle)
                .await
                .map_err(TransportError::Wire)?;
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::pin::Pin;
    use std::task::Context;

    use super::*;

    struct PipeReader {
        rx: Pin<Box<Receiver<Vec<u8>>>>,
        buf: Vec<u8>,
        pos: usize,
        eof: bool,
    }

    type PipeSendFuture =
        Pin<Box<dyn Future<Output = Result<(), async_channel::SendError<Vec<u8>>>> + Send>>;

    struct PipeWriter {
        tx: Sender<Vec<u8>>,
        pending: Option<(usize, PipeSendFuture)>,
    }

    fn duplex_pipe(cap: usize) -> ((PipeReader, PipeWriter), (PipeReader, PipeWriter)) {
        let (a_tx, b_rx) = async_channel::bounded(cap);
        let (b_tx, a_rx) = async_channel::bounded(cap);
        (
            (
                PipeReader {
                    rx: Box::pin(a_rx),
                    buf: Vec::new(),
                    pos: 0,
                    eof: false,
                },
                PipeWriter {
                    tx: a_tx,
                    pending: None,
                },
            ),
            (
                PipeReader {
                    rx: Box::pin(b_rx),
                    buf: Vec::new(),
                    pos: 0,
                    eof: false,
                },
                PipeWriter {
                    tx: b_tx,
                    pending: None,
                },
            ),
        )
    }

    impl AsyncRead for PipeReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            out: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            if out.is_empty() || self.eof {
                return Poll::Ready(Ok(0));
            }
            loop {
                if self.pos < self.buf.len() {
                    let n = (self.buf.len() - self.pos).min(out.len());
                    out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
                    self.pos += n;
                    if self.pos == self.buf.len() {
                        self.buf.clear();
                        self.pos = 0;
                    }
                    return Poll::Ready(Ok(n));
                }
                match futures_core::Stream::poll_next(self.rx.as_mut(), cx) {
                    Poll::Ready(Some(chunk)) => {
                        if !chunk.is_empty() {
                            self.buf = chunk;
                            self.pos = 0;
                        }
                    }
                    Poll::Ready(None) => {
                        self.eof = true;
                        return Poll::Ready(Ok(0));
                    }
                    Poll::Pending => return Poll::Pending,
                }
            }
        }
    }

    impl AsyncWrite for PipeWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            if buf.is_empty() {
                return Poll::Ready(Ok(0));
            }
            if self.pending.is_none() {
                let tx = self.tx.clone();
                let data = buf.to_vec();
                let len = data.len();
                self.pending = Some((len, Box::pin(async move { tx.send(data).await })));
            }
            let (len, fut) = self.pending.as_mut().expect("pending write");
            match fut.as_mut().poll(cx) {
                Poll::Ready(Ok(())) => {
                    let written = *len;
                    self.pending = None;
                    Poll::Ready(Ok(written))
                }
                Poll::Ready(Err(_)) => {
                    self.pending = None;
                    Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "pipe closed",
                    )))
                }
                Poll::Pending => Poll::Pending,
            }
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.tx.close();
            Poll::Ready(Ok(()))
        }
    }

    struct NoopDispatcher;
    impl MuxDispatcher for NoopDispatcher {
        fn supports(&self, _instance: &str, _func: &str) -> bool {
            false
        }
        async fn dispatch(
            &self,
            _call: InboundCall,
            _instance: String,
            _func: String,
        ) -> Result<(), WireError> {
            Ok(())
        }
        async fn drop_resource(&self, _handle: u32) -> Result<(), WireError> {
            Ok(())
        }
        async fn on_disconnect(&self) {}
    }

    struct SequentialStreamsDispatcher {
        count: u32,
    }
    impl MuxDispatcher for SequentialStreamsDispatcher {
        fn supports(&self, instance: &str, func: &str) -> bool {
            instance == "test:mux" && func == "many-streams"
        }
        async fn dispatch(
            &self,
            call: InboundCall,
            _instance: String,
            _func: String,
        ) -> Result<(), WireError> {
            let _ = call.recv_root_request().await;
            let handle = call.call_handle();
            // Send 120 sequential sub-path streams on ONE invocation.
            call.send_root_response(&self.count.to_le_bytes())
                .await
                .map_err(|err| WireError::MalformedPayload {
                    context: "send_root_response".to_owned(),
                    detail: err.to_string(),
                })?;
            for sub_id in 1..=self.count {
                let mut writer = handle.register_writer(sub_id).await;
                let _ = writer.send(sub_id.to_le_bytes().to_vec()).await;
                let _ = writer.close().await;
            }
            Ok(())
        }
        async fn drop_resource(&self, _handle: u32) -> Result<(), WireError> {
            Ok(())
        }
        async fn on_disconnect(&self) {}
    }

    #[test]
    fn more_than_hundred_sequential_streams_in_one_invocation_reclaim_inbound_paths() {
        futures_lite::future::block_on(async {
            let ((c_r, c_w), (s_r, s_w)) = duplex_pipe(32);
            let config = MuxConfig {
                max_inbound_paths: 8,
                ..MuxConfig::default()
            };
            let (client_peer, client_ch) = create_mux(config);
            let (server_peer, server_ch) = create_mux(config);
            let server_disp = SequentialStreamsDispatcher { count: 120 };

            let client_task = async {
                let mut call = client_peer
                    .open_call("test:mux", "many-streams")
                    .await
                    .expect("open call");
                call.send_root_request(&[]).await.expect("send req");
                let resp = call.recv_root_response().await.expect("recv resp");
                let count = u32::from_le_bytes(resp.try_into().expect("u32 count"));
                assert_eq!(count, 120);
                let handle = call.call_handle();

                for sub_id in 1..=count {
                    let mut reader = handle.open_reader(sub_id, 2).await.expect("open stream");
                    let item = reader
                        .recv()
                        .await
                        .expect("recv item")
                        .expect("expected payload");
                    assert_eq!(item.as_ref(), &sub_id.to_le_bytes());
                    assert_eq!(reader.recv().await.expect("recv eof"), None);
                }
                assert_eq!(
                    call.core.inbound.lock().await.active.len(),
                    0,
                    "all completed stream paths must be reclaimed"
                );
                client_peer.close();
                server_peer.close();
            };

            let drivers = futures_lite::future::zip(
                drive_mux(c_r, c_w, client_ch, &NoopDispatcher),
                drive_mux(s_r, s_w, server_ch, &server_disp),
            );
            let ((), _) = futures_lite::future::zip(client_task, drivers).await;
        });
    }

    #[test]
    fn subpath_reader_drop_reclaims_buffered_bytes_and_discards_late_frames() {
        futures_lite::future::block_on(async {
            let config = MuxConfig {
                max_inbound_paths: 4,
                max_undelivered_bytes: 1024,
                ..MuxConfig::default()
            };
            let (peer, _channels) = create_mux(config);
            let core = CallCore::new(
                1,
                CallSide::Caller,
                Arc::clone(&peer.state),
                peer.outgoing_tx.clone(),
                peer.control_tx.clone(),
            );
            let handle = CallHandle {
                core: Arc::clone(&core),
            };
            let reader = handle.open_reader(1, 4).await.expect("open reader");
            let path = vec![DIR_CALLEE_TO_CALLER, 1];

            // Buffer 2 chunks totaling 600 bytes before dropping the reader.
            core.push_data(path.clone(), Bytes::from(vec![0xaa; 300]))
                .await
                .expect("push 1");
            core.push_data(path.clone(), Bytes::from(vec![0xbb; 300]))
                .await
                .expect("push 2");
            assert_eq!(core.inbound.lock().await.undelivered_bytes, 600);

            // Dropping the reader immediately releases buffered bytes and frees
            // the active path slot, moving remaining 2 credits into `draining`.
            drop(reader);
            {
                let inbound = core.inbound.lock().await;
                assert_eq!(inbound.undelivered_bytes, 0);
                assert!(!inbound.active.contains_key(&path));
                assert_eq!(inbound.draining.get(&path), Some(&2));
            }

            // Two legitimately credited in-flight frames are discarded safely
            // without accumulating `undelivered_bytes`.
            core.push_data(path.clone(), Bytes::from(vec![0xcc; 500]))
                .await
                .expect("late frame 1 discarded");
            core.push_data(path.clone(), Bytes::from(vec![0xdd; 500]))
                .await
                .expect("late frame 2 discarded");
            assert_eq!(core.inbound.lock().await.undelivered_bytes, 0);

            // Peer Close clears the draining tombstone completely.
            core.push_close(path.clone())
                .await
                .expect("late close absorbed");
            assert!(!core.inbound.lock().await.draining.contains_key(&path));
        });
    }

    #[test]
    fn concurrent_inbound_call_limit_rejects_excess_opens() {
        struct HoldDispatcher {
            release: Arc<Progress>,
        }
        impl MuxDispatcher for HoldDispatcher {
            fn supports(&self, instance: &str, func: &str) -> bool {
                instance == "test:limit" && func == "hold"
            }
            async fn dispatch(
                &self,
                call: InboundCall,
                _instance: String,
                _func: String,
            ) -> Result<(), WireError> {
                let mark = self.release.mark();
                self.release.changed(mark).await;
                let _ = call.send_root_response(b"ok").await;
                Ok(())
            }
            async fn drop_resource(&self, _handle: u32) -> Result<(), WireError> {
                Ok(())
            }
            async fn on_disconnect(&self) {}
        }

        futures_lite::future::block_on(async {
            let ((c_r, c_w), (s_r, s_w)) = duplex_pipe(32);
            let server_cfg = MuxConfig {
                max_concurrent_inbound_calls: 2,
                ..MuxConfig::default()
            };
            let (client_peer, client_ch) = create_mux(MuxConfig::default());
            let (server_peer, server_ch) = create_mux(server_cfg);
            let release = Arc::new(Progress::new());
            let disp = HoldDispatcher {
                release: Arc::clone(&release),
            };

            let test_fut = async {
                let mut call1 = client_peer
                    .open_call("test:limit", "hold")
                    .await
                    .expect("call 1 accepted");
                let mut call2 = client_peer
                    .open_call("test:limit", "hold")
                    .await
                    .expect("call 2 accepted");
                let err = client_peer
                    .open_call("test:limit", "hold")
                    .await
                    .err()
                    .expect("call 3 must be rejected at concurrent limit");
                assert!(
                    matches!(err, TransportError::Rejected(ref msg) if msg.contains("limit")),
                    "unexpected error: {err:?}"
                );
                release.signal();
                assert_eq!(call1.recv_root_response().await.expect("resp 1"), b"ok");
                assert_eq!(call2.recv_root_response().await.expect("resp 2"), b"ok");
                client_peer.close();
                server_peer.close();
            };

            let drivers = futures_lite::future::zip(
                drive_mux(c_r, c_w, client_ch, &NoopDispatcher),
                drive_mux(s_r, s_w, server_ch, &disp),
            );
            let ((), _) = futures_lite::future::zip(test_fut, drivers).await;
        });
    }
}
